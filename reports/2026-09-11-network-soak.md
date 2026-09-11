# 継続ネットワーク負荷・意味論テスト（2026-09-11）

専用LXC client/server間で継続負荷をかけ、動的rule更新、障害注入、統計、agentの終了処理を検証した。
アプリの終了処理に2件、テスト用TCX観測に1件の問題を再現・修正した。さらに起動失敗時のqdisc所有権も修正した。

## 発見と修正

1. **出力先の切断時にfqが残る可能性**: `EngineGuard::drop` が即SIGKILLしており、engineのqdisc終了処理が実行されなかった。SIGTERM後に最大2秒待ち、応答しない場合だけSIGKILLするよう修正。SIGTERM handlerの実行を確認するテストは修正前に失敗、修正後に成功した。
2. **stdoutが詰まるとstdin EOFで終了できない**: output転送がmain threadを塞ぎ、input転送threadの終了を監視していなかった。両方の終了を独立に監視し、EOF後は最終応答を読み切るための猶予を設け、詰まったconsumerは期限付きで終了する。4096 byte pipeを使う回帰テストで修正前のhangを再現。最終応答の保持も別テストで確認した。
3. **テスト用Pythonのメモリ破壊**: 最初の長時間runは約368秒でSIGSEGV終了。32 byteのBPF_PROG_QUERY構造体に対し、TCXはrevisionをoffset 56–63に書き込んでいた。128 byteのガード付き領域でこの書き込みを実測し、完全な64 byte ABIへ修正。修正後は1,000回の実kernel queryでガード領域が不変。残存engineはstdout保存先で所有を確認してSIGTERM回収した。これはアプリ本体のcrashではない。

前回テストで判明した16文字のveth名を `flt-client0` / `flt-server0` へ統一し、sudoを通過しても負荷設定を保持するtaskも整備した。Pythonキャッシュはgitignoreへ追加した。

## 16並列・各条件120秒

成功したapplication bytesを、最後の転送完了待ちを含む実時間で割った帯域。
通常/BPF passは1転送64 MiB、loss/bandwidthは1 MiB。ループは120秒間新規転送を開始し続ける。

| 条件 | 成功転送数 | 失敗 | 転送GB | 実効Mbit/s | 経過秒 |
|---|---:|---:|---:|---:|---:|
| baseline | 6636 | 0 | 445.334 | 29647.006 | 120.170 |
| bpf-pass | 8053 | 0 | 540.428 | 35989.234 | 120.131 |
| loss-1pct | 44558 | 0 | 46.722 | 3087.840 | 121.049 |
| bandwidth-100mbit | 1389 | 0 | 1.456 | 96.390 | 120.881 |

- 合計1,033,941,024,768 application bytes（約1.034 TB）。全4条件で失敗0。
- BPF pass: 58,469,240 skb処理、drop 0。
- 1% loss: 6,154,210 skb中61,523 drop、実測0.9996896%。
- 100 Mbit/s制限: 96.390 Mbit/s、pacing_dropped 0。
- JSONLの734 eventについてcounterの単調性、deltaと累計差分の一致、drop <= matchedを確認。
- 全条件でTC filter・TCX program数・root qdiscを実行前へ復元。障害解除後の100 requestは100成功。
- run全体は486.233秒、exit=0。初回の途中停止runは成功結果に算入していない。

## 通信中のruleset切替（120秒）

8並列uploadを継続し、同じdestinationに34件または上限1,024件のsource rulesを置いた。
clientの/32 allowとcatch-allの100% dropを同時に更新し、配列の順序も反転させた。

- 211,023,822,848 bytes転送中に1,504回のreplaceをack確認。
- 不正なduplicate IDを持つ151回の更新はerrorを返し、get_stateが直前の正常stateを保持。
- applied/get_stateのrulesetは送信したものと完全一致。
- catch-all drop ruleに誤って分類されたpacketは0。source最長prefix優先が世代切替中も維持された。
- malformed / no_rules / invalid_ruleは0、13,121 stats/diagnostics eventのcounterとdeltaは整合。
- 読み取らない16監視connectionを維持しても、制御応答の最大待ちは0.463秒。
- engineのFD数は36、thread数は5で一定。RSSは24,340→29,776 KiB、最後の20 sampleは29,776 KiBで一定だった。この120秒では継続的な増加は観測しなかった。
- 負荷完了後の100% lossでは20 requestがすべて失敗、復旧後は100 requestがすべて成功。最後のdrop counterは20。
- engineは正常終了し、TCX/fqとcontrol socketを解除。

## agent終了処理の実通信テスト

各経路で100 Mbit/sのbandwidth ruleを適用し、8並列uploadの途中で終了を発生させた。

| 終了経路 | 成功upload | 転送GB | 終了コード | TCX/fq復元 |
|---|---:|---:|---:|---|
| stdout-close | 3086 | 25.887 | 0 | OK |
| stdin-eof | 3262 | 27.364 | 0 | OK |
| blocked-stdout-eof | 1871 | 15.695 | 0 | OK |
| sigterm | 3307 | 27.741 | -15 | OK |

stdout詰まりのケースはpipe容量を4096 byteに縮め、出力を読まずに5秒経過後stdinを閉じた。
全upload成功。SIGTERMケースの-15は意図した終了で、子engineのPDEATHSIGによる後片付けも確認した。

## その他の検証

- `lab:pbt-long`: seed `0x7062745f67736f00`、生成case数10,000。IPv4/IPv6境界、GSO参照モデル、Gilbert–Elliott参照モデル、世代切替、16件超source、pass-throughの7テストすべて成功（193.955秒）。GSOは164,670 skb / 3,077,292 segment、GEは325,608 packet。
- `lab:unit-workspace`: 全ユーザー空間テスト成功。最終EOF-drain変更後にはagentの10テストを再実行してすべて成功。
- `cargo clippy -p faultline-agent --all-targets -- -D warnings`、Rust format、Python/shell/mise構文、diff whitespace検査を実施。
- `lab:experiment`: 最終agentでmanifest、所有traffic、baseline/outage/recovery、TUI描画を通すE2Eが成功。画面にmatched=83、dropped=8、TRAFFIC ok=19/fail=8を確認（意図したoutageを含む）。

## 再実行

同じlabを変更するtaskは順番に実行する。

```sh
LAB_LOAD_WORKERS=16 LAB_LOAD_SECONDS=120 mise run lab:load
mise run lab:soak
mise run lab:soak-agent  # agentだけ再検査する場合
mise run lab:pbt-long
mise run lab:down
```

通常のPython構造体回帰テスト: `python3 scripts/lab/test_load.py`。
rootかつlab起動中で実行するとガード付きkernel queryも実施する。

生データはgit管理対象外のローカルartifact:

- `target/network-load-96kd6xh0/`、`target/load-soak-fixed.log`
- `target/semantic-soak-kg_lt4n2/`、`target/semantic-soak.log`
- `target/semantic-soak-hgdi4_d5/`、`target/soak-agent-final.log`
- `target/soak-pbt.log`、`target/soak-unit-workspace-final.log`、`target/soak-experiment-final.log`

これはローカルveth/LXC経路の有限時間テストであり、物理NIC性能や無期限の耐久性を保証しない。
各runはホスト上の他の処理やcache状態の影響を受ける。baselineとpassの大小も変動したため、固定的なBPF overheadの推定には使わない。

後片付け: 最終 `lab:down` は exit=0。専用LXCを停止しbridgeを削除した（rootfsは保持）。


## 追加検証: ロード失敗時のqdisc復元

従来コードはverifier検証より先にclsactを追加し、追加エラーも無視していた。
`Attachment` にBPF linkと作成したclsactの所有を集め、次の順番に変更した。

1. BPF verifier/loadを先に完了させる。
2. Linux 6.6以降はTCXを選び、clsactを追加しない。
3. 6.6未満は従来TCを使う。新規作成したclsactだけを所有し、既存のものは借用する。
4. 失敗・終了時はBPF linkを先にdetachし、自分のclsactを回収する。他のfilterが追加されていた場合は保全する。
5. 起動途中でfqやcontrol socket設定が失敗しても、取得済みresourceはRAIIで戻す。

最低kernel要件（x86-64: 5.12、arm64: 5.18）は変更していない。
従来TC経路は現在のkernel上で明示選択して検査しており、古いkernelを起動した試験ではない。
clsactの回収にはtcを使い、他のfilterの有無を確認できない場合は削除を控えてwarningを出す。

`mise run lab:startup` は専用dummy interfaceで次の8条件を検証して成功した（exit=0）。

- 不正opcodeによる実verifier拒否でqdiscが変化しない。
- 存在しない親へのlegacy attach失敗で新規clsactを回収する。
- legacyの正常終了でも新規clsactを回収する。
- 元から存在したclsactとfilterは成功時・失敗時とも保持する。
- セッション中に追加された別のfilterを破壊しない。
- TCX attachではqdiscを変更せず、終了後にprogramが残らない。
- fq追加後にcontrol socketの起動を失敗させても、fqとattachを回収する。
- 元からあるroot fqはbandwidth設定失敗時にも保持する。

生ログ: `target/startup-cleanup.log`。

上記のattachment修正後、16 worker × 各30秒の4ケースを再実行した
（`target/network-load-4kdi_t0l/`、`target/load-after-startup-fix.log`）。
baseline/pass/1% loss/100 Mbit/s制限の全uploadが成功し、全ケースで終了後の
BPF・qdisc復元を確認した。lossはskb基準1.0093%、帯域制限時はapplication基準
97.60 Mbit/s、pacing dropは0。復旧確認も100/100成功した。
workspace unit tests、engine/agentのClippy、format検査も修正後に成功した。
agent終了の4ケースも修正後に再実行して全成功した
（`target/semantic-soak-7l_gz_82/`、`target/soak-agent-after-startup-fix.log`）。
