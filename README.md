# Faultline (`flt`)

アプリケーションエンジニアが、ローカルprocess、Docker、LXCを対象に再現可能な
ネットワーク障害実験を組み立て、実行し、観測するためのツールです。実験はvisual UIまたは
manifestで作成でき、同じmodelとorchestratorを非対話frontendからも利用できます。

利用者向けの主コマンドは`flt`です。Linux dataplaneを直接操作する低レベル実装は
`faultline-engine`、workload内でengineを所有する一時workerは`faultline-agent`です。

AyaとTC eBPFはLinux dataplaneの実装手段です。利用者が扱う中心概念はeBPF programではなく、
source workload、L3/L4 destination、fault profile、timeline、traffic、観測結果です。
プロダクトの方向性と非目標は[PRODUCT](PRODUCT.md)、内部境界は[ARCHITECTURE](ARCHITECTURE.md)を
参照してください。

IPv4/IPv6 Ethernet trafficを対象に、次の条件と実行環境を指定できます。

- local、Docker、LXCのsource workloadとinterface
- ingress/egress
- 宛先IPv4/IPv6 CIDRまたはsnapshot解決するhostname
- TCP、UDP、または全protocol
- TCP/UDP destination port
- loss、delay、jitter、duplication、reordering、bandwidth、burst、outage
- hash/random lossと再現用seed
- fault timeline、traffic generator、実行時間
- rule別packet/byte/action統計とresolved plan

## セットアップ

mise、eBPFをロードできる権限、およびx86-64ではLinux kernel 5.12以降、
arm64では5.18以降が必要です。flow counterはBPF ISA v3のreturn-value付きatomic
fetchを使用するため、eBPF crateだけを`-Ctarget-cpu=v3`でbuildします。
workspaceのrustc wrapperは既存の`sccache`等が設定されている場合もそれをchainします。

```console
mise install
mise run setup
mise run check
mise run test
mise run build
```

`setup`はstable/nightly Rust、`rust-src`、`bpf-linker`を導入します。

## テスト

純粋なdrop判定、seedの再現性、loss率、CLI validationは権限なしで実行できます。

```console
mise run test
```

TC programを実際にカーネルへロードし、合成packetを`BPF_PROG_TEST_RUN`へ渡す
統合テストは明示的に実行します。interfaceへattachしないため実通信は変更しません。

```console
mise run test-root
```

このテストにはrootまたは適切なBPF capabilityと、`BPF_PROG_TEST_RUN`対応kernelが
必要です。Rustのビルド自体は通常ユーザーで行い、生成されたtest binaryだけを
`sudo`で実行します。通常の`mise run test`ではignoredになります。

生成したGSO skb列をkernel dataplaneへ投入し、skb単位の参照モデルと比較するPBTは
別taskで実行します。結果にはskb、logical segment、byte基準のloss率が表示されます。

```bash
mise run lab:pbt
FAULTLINE_PBT_CASES=2000 mise run lab:pbt
mise run lab:pbt-long
FAULTLINE_PBT_SEED=0x1234 FAULTLINE_PBT_CASE=17 mise run lab:pbt
```

失敗時に表示されるseedとcaseを最後の形式へ渡すと、そのcaseだけを再実行できます。
このPBTはGSO skb列の参照モデル比較に加え、generation swapによるflow stateの分離と、
同一destinationへ17件以上のsource Ruleを置けることも実kernelで検証します。

## 使用例

`eth0`から`10.20.0.0/16`のTCP 443へ出ていくpacketの5%をdropします。

```console
sudo RUST_LOG=info ./target/release/faultline-engine \
  --interface eth0 \
  --source 192.0.2.0/24 \
  --direction egress \
  --destination 10.20.0.0/16 \
  --protocol tcp \
  --port 443 \
  --loss 5 \
  --loss-algorithm hash \
  --seed 42 \
  --duration 30s \
  --stats-interval 500ms \
  --stats-format text
```

`--source`を省略すると全sourceが対象です。指定するとdestination LPMで選ばれたruleへ
source CIDR filterを追加し、特定clientからの通信だけを壊せます。同じdestination prefix
には複数のsource ruleを登録でき、最も長いsource prefixが優先されます。sourceを
省略したruleを同じbucketへ置けばcatch-all policyになります。

表示されるstatsは`rule_id`ごとです。`matched`、`dropped`はTCが処理したskb単位です。
`matched_segments`、`dropped_segments`は`gso_segs`に基づく論理segment数、
`matched_bytes`、`dropped_bytes`は`wire_len`（0ならskb length）に基づくbyte数です。
GSO skbをdropした場合はその全segment・全byteをdropしたものとして計上しますが、skb内部を
segmentごとに判定しているわけではありません。`gso_skbs`は複数segmentを持つskbの数です。
`duplicated`、`reordered`、`delayed`を含む各counterは全CPUの累計で、対応する`*_delta`は
同じruleの前回出力からの増分です。
`pacing_dropped`はbandwidth clockをCAS競合中に予約できず、rate超過を避けるため明示的に
dropしたpacket数です。
`skb_loss_percent`、`segment_loss_percent`、`byte_loss_percent`は各単位の累計観測drop率です。
既存の`loss_percent`は`skb_loss_percent`の互換aliasです。終了はCtrl-C、SIGTERM、または
control sourceのcloseです。
`faultline-engine`が終了するとAyaがTC linkをdetachします。

`--duration`と`--stats-interval`は`ms`、`s`、`m`単位を受け付けます。
`--duration`を省略した場合はCtrl-Cまで動作します。
loss率は0.01 percentage point単位へ量子化され、起動logにはrequested値と実効値の両方を
表示します。0より大きい値が0へ丸められる場合はerrorにします。

複数ruleはJSON scenarioとして一括投入できます。interfaceとdirectionはattach単位なので
CLIで指定し、filterとimpairmentはfileへ記述します。

```console
sudo RUST_LOG=info ./target/release/faultline-engine \
  --interface eth0 \
  --direction egress \
  --scenario scenarios/example.yaml
```

scenarioはYAMLを標準例とし、`.yaml` / `.yml` / `.json`を受け付けます。top-levelの
`rules`配列に、各ruleの一意な`id`と`destination`が必要です。
`source`、`protocol`、`port`、`loss`、`loss_algorithm`、`seed`、burst loss系、
`delay`、`jitter`、`duplicate`、`reorder`、`bandwidth`をCLIと同じ単位で指定できます。
未知のfieldはtypoとしてrejectします。[example.yaml](scenarios/example.yaml)にはIPv4/IPv6を
混在させた例があります。

stats出力は次から選べます。

- `--stats-format text`（既定）: 人が読みやすいlog形式です。
- `--stats-format json`: 1回のreportでglobal diagnosticsと各rule statsをJSON objectとして
  stdoutへ出します。JSON Linesとしてfile保存や別processから逐次読み取りできます。
- `--stats-format msgpack`: stdoutへMessagePackを出します。各frameは4 byteのbig-endian
  payload長と、それに続くMessagePack mapで構成されます。streamやsocketでframe境界を
  復元できます。

rule別の`stats` eventは累計counterと`*_delta`に加え、直近intervalの観測値を含みます。

- `interval_ms`、`matched_pps`、`dropped_pps`
- `wire_mbps`、`dropped_mbps`
- skb・segment・byteの`*_loss_interval_percent`
- GSO、duplicate、reorder、delay、pacing dropの`*_interval_percent`

ruleへ到達しなかったpacketはglobalな`diagnostics` eventとして別に出します。rule IDがまだ
決まっていないmissを特定ruleへ誤帰属させないためです。`seen`、`non_ip`、`malformed`、
`no_rules`、destination/source/protocol/port miss、`fragment_port_miss`、`invalid_rule`、
`duplicate_bypass`と各`*_delta`を含みます。JSON/MessagePack consumerは`type`で
`stats`と`diagnostics`を判別できます。

TUIは累計lossに加え、直近intervalのpacket rate・wire throughput、impairment件数、
destination/source/protocol/port/parser missをOUTPUT METERSへ表示します。

TTYなしで実sessionの描画経路まで検査する`--snapshot-after-ms`もあります。通常と同じagent、
JSONL reader、App state、message handler、`draw`を通し、Ratatui `TestBackend`の画面をplain
textで出力します。mock statsではなく実trafficを使うE2Eは次で実行できます。

```bash
mise run lab:tui
```

このtaskはLXCから100 requestを流し、rendered screenの実効egress、非zero matched、packet rate、
wire throughput、diagnostics欄をassertし、session終了後のdetachも確認します。

実vethでのoffload差分は`mise run lab:offload`で観測できます。同じ8 MiB TCP uploadを
GSO/TSO/GROのoff/onで実行し、application bytes、BPF matched/drop数、pcap packet数、
interface RX packet/byte数を並べます。application bytesだけを不変条件として検証し、skb数の
差はkernelやdriverごとのsegmentation位置を調べるための観測値として残します。実行前の
offload設定は終了時に復元されます。`ethtool`と`tcpdump`がなければ`mise run lab:install`で
追加できます。

loss判定は次から選べます。

- `--loss-algorithm hash`（既定）: 5-tuple、flow内packet sequence、rule ID、seedから
  判定します。同じ条件を再現しやすい方式です。
- `--loss-algorithm random`: `bpf_get_prandom_u32()`をpacketごとに呼びます。
  impairmentを併用しない場合は`FLOW_STATE`を更新せず、seedは使用しません。
  jitter / reorder / duplicateを併用する場合は、それらの決定論的な選択に必要な
  packet sequenceだけを`FLOW_STATE`で管理します。
- `--burst-loss 1 --burst-recovery 25 --burst-bad-loss 100`: eBPF内の
  Gilbert–Elliott modelです。5-tupleとruleごとにgood/bad状態を保持し、seedから再現可能な
  遷移とloss判定を作ります。good stateのlossは`--burst-good-loss`、idle後にgoodへ戻す
  場合は`--burst-idle-reset 30s`で指定します。`--loss-algorithm gilbert-elliott`を明示する
  こともできます。

egress queueの障害は次のoptionを組み合わせられます。

- `--delay 100ms`: 固定delay
- `--delay 100ms --jitter 20ms`: seed付き一様分布のjitter
- `--duplicate 2`: 2%のpacket duplication
- `--delay 20ms --reorder 5`: queueされたpacketの5%をreorder
- `--bandwidth 10mbit`: bandwidth制限
- `--outage-after 10s --outage-duration 3s`: 指定CIDR/protocol/portだけを一時的に
  100% lossへ切り替え、その後元のloss ruleへ戻します。

loss、jitter、reorder、duplicateの選択は5-tuple、flow内packet sequence、rule ID、seedから
eBPF側で決定します。delay、jitter、reorder、bandwidthはeBPFが`skb->tstamp`へEarliest
Departure Timeを書き、`sch_fq`はその時刻までpacketを保持するだけです。netemの乱数や
gemodelには依存しません。duplicateは`bpf_clone_redirect`で生成します。

EDTを使うoptionは`--direction egress`専用で、既存root qdiscを上書きしません。終了時には
faultline-engineが追加した`fq` qdiscだけを削除します。burst lossとoutageはqdiscを必要とせず、
ingressでも使用できます。

既存のsocket/TCP pacingが設定したEDTは保持し、chaos delayはそのdeadlineより後ろへ
合成します。bandwidth clockはrule更新時に初期化されるため、同じrule IDへ新しいrateを
適用しても以前のqueue時刻を引き継ぎません。`fq`の既定horizon超過によるdropを避けるため、
faultline-engineが作るqdiscは24時間のhorizonとcap policyを明示します。total limitは100,000
packetを安全弁として残し、per-flow limitはu32最大値へ設定して、それだけが先にsilent
dropを発生させないようにします。duplicateされたcloneも独立したbandwidth slotを消費します。

### Control plane

CLI argumentは直接BPF Mapへ書き込まず、入力形式に依存しない`RuleSpec`へ変換され、
`ControlCommand::ReplaceRules`として実行loopへ渡されます。実行loopはattach後もcommand
channelを監視しており、rule更新時にBPF programを再attachする必要はありません。

Unix socket serverも同じcontrol channelへcommandを送ります。複数ruleの一括更新は
新しいinner LPMを構築してからmap-in-mapのactive slotを1回更新するため、generation単位で
atomicに切り替わります。

### Ephemeral agent、orchestrator、portable TUI

`faultline-orchestrator`はAyaやRatatuiへ依存しないlibrary crateです。workloadのprovision/start、
interface解決、concrete plan生成、target URIに応じた一時的な`faultline-agent`、timelineのack gate、
traffic ownershipを提供します。`faultline`はこのAPIを利用するfrontendであり、同じ機構を使う
非対話CLIやtest harnessをTUIへ依存せず作れます。常駐control planeやinline gatewayは必要ありません。
TUI終了またはstdio EOFでagent、engine、TC linkを順に終了します。

```bash
mise run build-tui
sudo ./target/release/flt local://eth0 --destination 10.20.0.0/16
sudo ./target/release/flt lxc://faultline-client/eth0 --destination 10.203.0.3/32
./target/release/flt docker://YOUR_RUNNING_CONTAINER/eth0 --destination 10.20.0.0/16
```

URIのcontainer名には起動中の実名を指定します。まず`flt --list-targets`で利用可能な
URIを確認してください。停止中または不可視のcontainerはTUIへ入る前にエラーになります。

UIを操作しながら継続的に通信を流す場合は、別terminalで次を実行します。各batchの成功数、
失敗数、経過時間が表示され、Ctrl-Cで終了します。

```bash
mise run lab:traffic
```

頻度などは`LAB_TRAFFIC_REQUESTS`、`LAB_TRAFFIC_INTERVAL_MS`、
`LAB_TRAFFIC_TIMEOUT_MS`で調整できます。

`auto://api/eth0`はrunning Docker/LXC containerから`api`を探し、片方だけに存在すればその
runtimeを選びます。target省略時も候補が1件だけなら自動選択し、複数なら明示を求めます。
`--list-targets`で`docker ps`とactive `lxc-ls`から候補URIを表示します。

Docker adapterは対象containerとnetwork namespaceを共有する一時containerを起動します。

```bash
mise run build-agent-image
faultline docker://api/eth0 --agent-image faultline-agent:latest
```

これは概念的に`docker run --rm -i --network container:api --cap-add NET_ADMIN --cap-add BPF`
であり、control portを公開しません。Docker Desktopでもagent/eBPFはLinux VM側で動きます。
LXC adapterは`lxc-attach`で対象container内のagentを起動します。agentと`faultline-engine` binaryは
containerから見えるpathへ配置し、必要なら`--agent`と`--engine`で指定します。

TUIの`--direction`既定値は`auto`で、targetをendpoint interfaceとしてegressへattachします。
client発のtrafficとdelay/duplicate/bandwidthをそのまま観測できます。containerの反対側にある
host vethへattachする場合だけ、`--direction ingress`を明示してください。画面上部には
`[egress]`または`[ingress]`として実効directionを表示します。

`↑`/`↓`でparameter、`←`/`→`で値を変更し、Shift併用は10倍stepです。`[`/`]`でrule、
`0`で選択parameterをzero、`r`で再同期、`q`でTUIだけを終了します。`x`はdaemon自体を
停止します。LOSS、DUPLICATE、REORDER、DELAY、JITTER、BANDWIDTHのknobと、skb・segment・
wire byte loss meter、ack/error logを表示します。automationではfull-screenへ入らない
`faultline TARGET --set-loss 25 --hold-seconds 10`も使えます。

### Profile、record、replay

profileは複数の完全なrulesetを時間軸に並べたversioned timelineです。各eventは
`replace_rules`を1回だけ送り、`applied`を待ってから次へ進むため、rule群はgeneration単位で
atomicに切り替わります。最後のeventは`duration_ms`まで有効です。

```bash
sudo flt local://faultline-client0 --profile profiles/brief-outage.yaml
mise run lab:profile
```

interactive操作を記録する場合は`--record`を指定します。初期`state`と、kernel map swap後に
acknowledgeされた異なる`applied` stateだけを記録するため、失敗した操作やstats eventは
replayへ混ざりません。

```bash
sudo flt local://eth0 --record session.json
sudo flt local://eth0 --replay session.json
```

recordにはtarget URIも保存されるため、同じtargetなら位置引数を省略できます。位置引数を
明示した場合は記録targetを上書きします。profile/replayはJSONまたはYAMLを受け付けます。
schema versionは現在`1`で、`at_ms`はsession開始からの絶対時刻です。rule値はreplayの
再現性を優先してprotocolと同じpermyriad、nanosecond、bit/second単位です。

既にlocal `faultline-engine`を起動しているdebug/embedding用途では、従来どおりmode 0600のUnix
socketへ直接接続できます。

```bash
sudo flt-engine --interface eth0 --destination 10.20.0.0/16 \
  --control-socket /tmp/faultline-engine.sock
flt --socket /tmp/faultline-engine.sock
```

protocol requestは`id`を持つ`ping`、`get_state`、`replace_rules`、`stop`です。responseは
`pong`、`state`、`applied`、`stopping`、`error`のいずれかで、`applied`はBPF mapのgeneration
swap成功後にだけ返ります。同じconnectionにはJSON stats eventもserverからpushされます。
socket pathに通常fileが存在する場合や、既にdaemonがlistenしている場合は上書きしません。

```json
{"type":"get_state","id":1}
{"type":"state","id":1,"state":{"rules":[...]}}
{"type":"replace_rules","id":2,"rules":[...]}
{"type":"applied","id":2,"state":{"rules":[...]}}
{"type":"stats","rule_id":0,"matched":120,"dropped":6,"skb_loss_percent":5.0}
```

## 標準LXC lab

標準の動作確認環境は、独立したLXC client/server間でTCP requestを送るlabです。
内部のbridgeやveth名はlabスクリプトが管理します。

初回だけDebianのLXC packageを導入します。

```console
mise run lab:install
```

baselineと50% packet-lossシナリオを順に実行できます。

```console
mise run lab:baseline
mise run lab:loss
mise run lab:loss-random
mise run lab:impairments
mise run lab:scenario
mise run lab:agent
mise run lab:agent-lxc
mise run lab:profile
mise run lab:tui
mise run lab:test
mise run lab:down
```

`lab:up`は`faultline-client`（`10.203.0.2`）と`faultline-server`
（`10.203.0.3:8080`）だけを作成します。初回はhost architectureに対応する
Debian trixie imageをダウンロードするため時間がかかります。
`lab:down`はcontainerを停止しますがrootfsを
残すので、次回はすぐ起動できます。

container自体も削除する場合だけ、明示的に次を実行します。

```console
mise run lab:clean
```

lossシナリオはclientのhost-side interfaceへTC ingress programをattachします。
`lab:loss`はhash方式、`lab:loss-random`はkernel pseudo-random方式を使います。
`lab:test`はbaseline、hash loss、random lossを順番に検証し、途中で失敗した場合も
delay、jitter、duplication、reordering、bandwidth、burst loss、outage windowを検証して、
最後にlabを停止します。lossシナリオはeBPF statsの最終値を読み、hashは30–55%、
randomは40–60%のpacket drop率に収まることも検証します。lab taskは最初のsudo認証を
controlling TTYで行い、別processがtask終了までcredentialを保持するため、同一task内で
passwordを再要求しません。
終了時にはtrapでfaultline-engineへSIGINTを送り、BPF linkをdetachします。

## 構成

- `faultline-common`: eBPF／ユーザー空間で共有する`#[repr(C)]`型
- `faultline-ebpf`: TC classifier、LPM rule lookup、CPU間で共有するatomic LRU flow state、
  per-CPU統計
- `faultline-engine`: eBPFのロード、rule投入、attach、統計表示
  - `control`: CLI/file/socketに依存しないcommand channel
  - `rule_store`: `ControlCommand`からAya Mapへの反映

eBPF mapは次の役割です。

- `RULES`: active generationのinner LPMを保持する`ArrayOfMaps`。family＋宛先CIDRから
  `destination_id`を引き、同じinner LPMを`destination_id`＋source CIDRで再検索
- `FLOW_STATE`: flow、rule、generationごとのpacket sequenceを持つ共有`LruHashMap`
- `PACE_STATE`: ruleとgenerationごとのaggregate bandwidth clockを持つ`LruHashMap`
- `STATS`: ruleごとの`PerCpuArray`
- `DIAGNOSTICS`: rule決定前のparser・CIDR・protocol・port missを持つglobal `PerCpuArray`

drop判定はflow、packet sequence、rule ID、seedから決定的に計算します。同じ通信が
完全に同じpacket分割・CPU配置になる保証はありませんが、単純な乱数より障害パターンを
再現しやすくしています。

## 現在の制限

- IPv4/IPv6に対応（IPv6 extension headerはHop-by-Hop、Routing、Fragment、Destination Options、AHを合計6段まで）
- inline VLANは802.1Q/802.1adの2段（QinQ）まで
- scenario file自体のwatchは未実装。実行中のrule全置換はcontrol socketで行える
- IPv4/IPv6 fragmentはfirst fragmentのportを30秒間のbounded LRU cacheで後続fragmentへ関連付ける。first fragmentより先に届いたfragmentはport ruleではpassする
- EDT pacingにはinterfaceのroot qdiscとして`sch_fq`を一時的に使用する

## 実験manifest

基本の実験modelでは、source workloadとL3 destinationを分離します。sourceにはlocal
interface、Docker container、LXC containerを指定できます。destinationにはIP address、
CIDR、hostnameを指定できます。hostnameは起動時に一度だけ解決され、有効なすべての
IPv4/IPv6 addressが解決済み実行planへ記録されます。

```bash
flt --experiment experiments/api-outage.yaml \
  --resolved-output /tmp/api-outage.resolved.json
```

manifestは持ち運び可能なartifactであり、YAMLを手書きする必要はありません。
validationとcompileは`faultline-runtime`、provisioning、interface解決、resource lifetimeは
`faultline-orchestrator::prepare_experiment`が担います。TUIも対話的に同じmodelを構築しますが、
これらのorchestration rule自体は保持しません。privileged agentはDocker、LXC、DNS、実験manifestを
意識せず、具体的なinterfaceとatomicなL3 ruleだけを受け取ります。
例は[`experiments/api-outage.yaml`](experiments/api-outage.yaml)を参照してください。

YAMLを書かずに新規作成できます。

```bash
flt --new-experiment experiments/my-experiment.yaml
```

引数なしで`faultline`を実行すると同じbuilderが開き、初期保存先には`experiment.yaml`が
使われます。target URIの直接指定とprofile/replay flagも、明示的なlow-level workflowとして
引き続き利用できます。

既存manifestもvisual editorで開けます。

```bash
flt --edit-experiment experiments/my-experiment.yaml
```

F2で組み込みのbrief-outage、lossy-link、slow-link templateを順に切り替えます。
visual editorは、extension、command traffic、Dockerのcommand/environment/cleanup設定、
高度なfault fieldなど、現在のformにないfieldも保持します。visual editorで表現できない
timelineは暗黙に単純化せず、エラーにします。

local sourceには、shellを介さないprocess定義（`program`、argument、environment、working
directory）も指定できます。builderではprogramを直接設定でき、詳細なargumentはmanifest編集で
保持できます。TUIはdataplaneへの接続前にこのprocessを起動し、cleanup時には自身が所有する
child processだけをkillして回収します。

LXCも同様に`distribution:release:architecture`形式のdownload templateからprovisionできます。
新規作成したLXCでは、TUIが起動前に現在のagentとengine binaryをrootfsへinstallします。
setupまたは起動に失敗した場合は新しいcontainerをrollbackします。cleanupで破棄するのは、
その実験が作成したLXCだけです。

builderでは`Source workload → L3 destination → Fault profile`の順に編集します。
Ctrl-Sで保存、Ctrl-Eで保存して実行します。builderで作成したDocker/LXC実験は
`lifecycle: session`を使用します。停止中のsourceはattach前に起動してcleanup後に停止しますが、
既に動作中だったcontainerは停止しません。`local` sourceのprocess ownershipがTUIへ移ることも
ありません。

builderはlocal network interfaceと、起動中・停止中のDocker/LXC containerを検出します。
source fieldでLeft/Rightを押して検出候補を選ぶか、名前を直接入力します。Docker imageを
指定するとsourceはprovision可能なworkloadになり、指定名のcontainerがなければ作成し、既定では
実験後に削除します。Docker daemonやpermissionのエラーをcontainer不在とはみなさないため、
その場合にprovisioningが始まることはありません。

実験はtraffic generatorも所有できます。visual builderでは任意のHTTP URLを指定でき、manifestでは
database clientなどHTTP以外のprotocol向けに、argumentを安全に渡せる`command` generatorも
使用できます。commandは選択したLocal/Docker/LXC source内でshellを介さずに実行され、設定した
intervalで繰り返されます。cleanup時にはkillして回収します。実行中のTUIでは
`Provision → Connect → Impair → Observe`、eBPF stats、generatorの成功・失敗件数を同じ画面に
表示します。

manifestのcompile、所有traffic、baseline/outage/recovery、live stats描画、cleanupを含む
LXCの全経路は、対話terminalなしで検証できます。

```bash
mise run lab:experiment
```
