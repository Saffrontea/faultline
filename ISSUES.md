# Known issues

コードレビューで見つかった構造上の課題です。優先度順に並べています。
設計の全体像は[ARCHITECTURE.md](ARCHITECTURE.md)を参照してください。

各項目の`状態`は次の意味です。

- `確認済み`: コードを読んで動作が確定しているもの
- `要実測`: コードからは成立するが、実機で未確認のもの

---

## 1. 動的rule更新でpacingとdirectionが再評価されない

**優先度**: 高 / **状態**: 解決済み / **範囲**: control plane

`RULES`を`ArrayOfMaps`へ変更しました。`RuleStore`はdetached inner LPMを完成させてから
outer mapのslot 0を1回だけ更新するため、packetからは旧generationまたは新generationの
どちらかだけが見えます。

以下は変更前の分析です。

`PacingBackend::install`は起動時に一度だけ、`initial_rules`から計算した
`pacing_required`で呼ばれます。`validate_rule_direction`も初期ruleにしか適用されません。

- `faultline-engine/src/main.rs:350` — `validate_rule_direction(&options, &initial_rules)`
- `faultline-engine/src/main.rs:371-372` — `initial_rules.iter().any(rule_requires_pacing)`で
  `fq`の要否を決定し、以後再評価しない

一方で実行loopはattach後も`ControlCommand::ReplaceRules`を受け付け続けます
（`faultline-engine/src/main.rs:703`）。したがって、

- 初期ruleにdelay/jitter/reorder/bandwidthが無い状態で起動し、
  あとからそれらを含むruleを投入すると、**`fq`が無いので`skb->tstamp`を誰も解釈せず、
  障害が静かに効かない**
- ingressにattachした状態で、あとからEDT系のruleを投入しても弾かれない

現在はrule sourceがCLIとscenario fileだけで、どちらも起動時に確定するため表面化しません。
ただしcontrol planeの設計意図（file watcher / Unix socket adapterの追加）を踏まえると、
最初に踏む箇所です。

**対処の方向**: `RuleStore::apply`の成功時にpacingの要否とdirectionの妥当性を再評価する。
あるいは`--direction egress`では常に`fq`を張り、qdisc管理を起動時に確定させる。
前者を採る場合、`PacingGuard`のlifetimeを実行loopが持つ形へ変える必要があります。

---

## 2. ReplaceRulesはruleが一切マッチしない窓を必ず作る

**優先度**: 高 / **状態**: 解決済み / **範囲**: control plane

`RULES`を`ArrayOfMaps`へ変更し、`RuleStore`が新しいinner LPMを完成させてからouter mapの
slot 0を一度だけ差し替える構成へ変更しました。packet lookupからは旧世代または新世代の
完全なrule setだけが見え、更新途中の無障害区間は生じません。16を超えるsource ruleと
generation swapはkernel PBTで検証しています。

以下は変更前の分析です。

`RuleStore::replace`は、新しいruleを挿入する前に**既存prefixを全削除**します。

- `faultline-engine/src/rule_store.rs:120` — `for network in self.active_prefixes.drain(..)`（全削除）
- `faultline-engine/src/rule_store.rs:141` — `for (network, bucket_rules) in grouped`（挿入開始）

この2つのloopの間に通過したpacketは、どのruleにもマッチせず`TC_ACT_PIPE`で素通しされます。
これは「複数entryの更新が中途半端に見える」という非atomic性より強い性質で、
**更新のたびに必ず無障害の窓が生じる**ことを意味します。

特にoutage windowは`ControlCommand::ReplaceRules`で100% lossのruleへ差し替える実装のため
（`faultline-engine/src/control.rs:159-176`）、**障害を開始する瞬間と復帰する瞬間の両方で
一瞬完全に素通しになります**。

READMEは「複数ruleの一括更新は現在のLPM Mapでは非atomic」と記述していますが
（`README.md:161`）、実際の性質は上記のとおりで、記述より影響が大きいものです。

**対処の方向**: 短期的には、削除を挿入の後ろへ移し「新旧が重なる」側へ倒す
（同一prefixはinsertで上書きされるため、実際に削除が要るのは消えたprefixだけ）。
恒久的にはmap-in-mapによるgeneration単位のatomic切り替え。後者でも
`ControlCommand`のAPIは変わりません。

---

## 3. ingressでもskb->tstampを書き換えている

**優先度**: 中 / **状態**: 解決済み / **範囲**: data plane

`FaultRule::has_impairments`を追加し、loss判定を通過したあとにimpairmentが無ければ
`apply_impairments`を呼ばず`TC_ACT_PIPE`を返すfast pathへ変更しました。これにより
純粋なloss ruleとpass-through ruleは既存の`skb->tstamp`を保存します。
`BPF_PROG_TEST_RUN`で非zeroの入力timestampが不変であることも検証しています。

以下は変更前の分析です。

`apply_impairments`はdropしなかった全packetで実行されます
（`faultline-ebpf/src/main.rs:375`）。ruleにimpairmentが一つも設定されていない場合でも、

1. `delay = 0`、`bandwidth_bps = 0`なので`reserve_delivery_time`は`requested`をそのまま返す
2. `base = edt_base_ns(now, existing_tstamp)`は`now`（`faultline-ebpf/src/main.rs:391`）
3. `delivery > existing_tstamp`が成立し、`tstamp = now`が書かれる
   （`faultline-ebpf/src/main.rs:415-422`）

ingressの`skb->tstamp`は受信時刻であり、これを`bpf_ktime_get_ns()`で上書きすることになります。
純粋なloss ruleをingressへattachしただけで発生します。

`delayed`統計は`delivery > base`で判定しているため増えず、統計からは気づけません。

**未確認**: 実機でingress側の`skb->tstamp`が実際にどう消費されるか
（`SO_TIMESTAMPING`、後続のtc/netfilter、TCPのreceive path）は測定していません。
影響範囲の確定には実測が必要です。

**対処の方向**: ruleがimpairmentを一つも持たない場合は`apply_impairments`を呼ばず
早期returnする。この分岐はloss専用ruleのfast pathとしても有効です。

---

## 4. CLI経路とscenario経路でRuleSpecの組み立てが二重化している

**優先度**: 中 / **状態**: 解決済み / **範囲**: control plane

CLIとscenarioが共通の`RuleInput`へ変換し、その`compile`でpercentage、field間制約、
quantize、`RuleSpec::validate`を一度だけ行う構成へ変更しました。両経路で曖昧だった
`loss + burst_loss`と`random + burst_loss`が同じerrorになる回帰testも追加しています。

以下は変更前の分析です。

`parse_bandwidth` / `parse_duration` / `quantize_loss`は共有されていますが
（`faultline-engine/src/scenario.rs:12`）、**`RuleSpec`の構築本体**と
**percentage検証**が2箇所に複製されています。

- 構築: `faultline-engine/src/main.rs:595` `rule_from_options` / `faultline-engine/src/scenario.rs:100` `compile`
- 検証: `faultline-engine/src/main.rs:666,673` / `faultline-engine/src/scenario.rs:210`
- `ge_enabled`の判定式も両方に独立して存在

既に検証内容が乖離しています。CLI経路にあってscenario経路に無いもの:

| 検証 | CLI | scenario |
| --- | --- | --- |
| `--loss`と`--burst-loss`の同時指定をreject | あり（`main.rs:517`） | なし |
| random algorithmとburst lossの組み合わせをreject | あり（`main.rs:520`） | なし |

このため、scenario fileで`loss_algorithm: random`と`burst_loss`を同時に指定すると、
`ge_enabled`が真になって**randomの指定が黙ってGilbert-Elliottへ差し替わります**
（`faultline-engine/src/scenario.rs:174-183`）。CLIでは同じ組み合わせがerrorです。

**対処の方向**: 中間表現（各fieldを`Option`で持つ素の構造体）を一つ定義し、
CLIとscenarioの双方をそこへ変換したうえで、`RuleSpec`への compile と検証を一本化する。

---

## 5. random modeでもFLOW_STATEを更新している（ドキュメントとの不一致）

**優先度**: 低 / **状態**: 解決済み / **範囲**: data plane / documentation

`packet_index`が必要なのはhash loss、またはjitter / reorder / duplicate等のimpairmentを
持つruleだけにしました。純粋なrandom ruleは`FLOW_STATE`を作らず、純粋なGE ruleは
`ge_state`だけを更新します。READMEもこの条件付きの挙動に合わせています。

以下は変更前の分析です。

`next_packet_index`はloss algorithmに関係なく無条件に呼ばれます
（`faultline-ebpf/src/main.rs:194`）。READMEの
「`--loss-algorithm random`は`FLOW_STATE`を更新せず」（`README.md:120`）は不正確です。

コード側には理由があります。jitter / reorder / duplicateの選択は
loss algorithmと独立に`packet_index`を必要とするためです。したがって修正すべきは
第一にドキュメントの記述です。

あわせて、Gilbert-Elliott modeでは**1 packetあたり共有LRU mapへのatomic操作が2回**
走ります。

- `next_packet_index`の`atomic_xadd`（`faultline-ebpf/src/main.rs:514`）
- `next_gilbert_elliott_decision`のCAS loop（`faultline-ebpf/src/main.rs:550`）

しかもGE経路は`packet_index`を判定に使わず、自前の`ge_state`内のsequenceを使います。
impairmentが設定されていないGE ruleでは、前者は完全に無駄です。

**対処の方向**: READMEの記述を実装に合わせる。あわせて、impairmentもhash lossも
必要としない場合は`next_packet_index`をskipする（項目3の早期returnと同じ条件で括れます）。

---

## 6. pacing dropがinjected lossと同じcounterに混ざる

**優先度**: 低 / **状態**: 解決済み / **範囲**: observability

`pacing_dropped`を専用counterだけへ計上するよう変更し、injected lossの`dropped`と
`loss_percent`から分離しました。`PACE_STATE`も`(rule_id, generation)` keyのLRU mapへ
変更し、世代更新時に旧packetのclockをresetしない構成にしています。

以下は変更前の分析です。

`reserve_delivery_time`はbounded CAS loop（16回）に全て失敗した場合、
rate超過を避けるためpacketをdropします（`faultline-ebpf/src/main.rs:446-480`）。
この判断自体は安全側で妥当です。

ただし統計側では、pacing dropが`dropped`にも計上されます。

```rust
update_stats(rule.id, pacing_dropped, duplicated, reordered, delayed, pacing_dropped);
```

（`faultline-ebpf/src/main.rs:213-220`。第2引数が`dropped`、第6引数が`pacing_dropped`）

その結果、`StatsReporter`が算出する`loss_percent`（`faultline-engine/src/main.rs:114-121`）は
**「注入した損失」と「pacing clockの競合による溢れ」を合算した値**になります。
両者は原因も対処も異なるため、観測値としては分離されているべきです。

なお`PACE_STATE`はrule単位の単一clockなので（`faultline-ebpf/src/main.rs:100`）、
高pps環境では全CPUが1 wordを奪い合う構造的なcontention点でもあります。
集約帯域を表現するには正しい設計ですが、pacing dropの発生率は負荷に依存します。

**対処の方向**: `dropped`をinjected lossのみとし、`loss_percent`の分子から
pacing dropを除く。`pacing_dropped`は既に独立したcounterとして出力されているため、
消費側は両方を得られます。
