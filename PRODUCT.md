# Product direction

## 一文での定義

アプリケーションエンジニアが、専用のnetwork applianceやcluster control planeを用意せず、
手元または検証環境のworkloadに対して再現可能なネットワーク障害実験を作成・実行・観測する。

## 主たる利用者と操作単位

主たる利用者はeBPFやtraffic controlの専門家ではなく、API、worker、databaseなどの障害時挙動を
検証したいアプリケーションエンジニアです。利用者が直接扱う単位は`ExperimentSpec`です。

- source workload: local process/interface、Docker container、LXC container
- destination: application名ではなく、実行時にsnapshotされるL3/L4 selector
- fault profile: loss、delay、jitter、duplication、reordering、bandwidth、burst、outage
- timeline: fault状態を切り替える時刻とatomic ruleset
- traffic: source workload内で実行する任意の観測用traffic
- result: concrete attach、解決済みnetwork、timeline、stats、traffic結果

UIはmanifestを手で書く難しさを解消する主frontendです。manifestは再実行、review、共有、自動化に
使うportable artifactです。`faultline-orchestrator`は両者を同じ意味論で実行し、将来のheadless CLI、
test framework adapter、IDE integrationがTUIを経由せず利用できる境界です。

## 「決定的」の範囲

再現可能にするものは、入力manifest、hostnameのsnapshot結果、concrete attach、rule generation、
seed付き判定列、timelineの順序、atomic map generation、実行後に保存するresolved planです。

実networkで観測されるpacket列そのものは、GSO/TSO/GRO、scheduler、driver、再送、並行trafficに
左右されます。そのため「常に同じ個数のapplication requestが失敗する」とは約束しません。
offload状態を含む実行条件を記録・比較し、kernel PBTと参照modelによってdataplaneの意味論を
説明可能にすることを目指します。

## Product principles

1. Authoringはapplication engineer向け、実行planはL3/L4の具体値にする。
2. UI、file、library APIでvalidationと実行意味論を共有する。
3. provision、attach、traffic、cleanupの所有権をsessionへ閉じ、既存workloadを暗黙に破壊しない。
4. 曖昧なruntime、interface、destinationは推測せず、候補またはresolved artifactを示す。
5. kernel固有の制約はengine/dataplaneへ隔離し、frontendへAyaやverifierの知識を要求しない。
6. statsとresolved planを、障害を「入れた」ことではなく「何が起きたか」を検証する材料にする。

## 非目標

- Kubernetes向けの常駐chaos control planeやChaos Meshの代替
- service名やapplication protocolを理解するservice mesh/proxy
- pfSenseのような常設router/firewall appliance
- 任意の物理network全体を中央管理するsystem
- offloadやtransport再送を無視したpacket/request結果の完全一致保証

## Naming

プロダクト名はFaultline、利用者向けのprimary commandは`flt`です。packageと内部componentは
次の役割を名前で区別します。

- primary command: experimentをbuild、run、observeする利用者向け入口
- engine: Linux TC/eBPFをloadしruleとstatsを扱う低レベル実装
- agent: workloadのnetwork namespace内でengineを所有する一時worker
- model/runtime: portable schema、validation、compile
- orchestrator: workload lifecycle、resolution、session、timeline、traffic

`faultline` packageが`flt`を提供し、`faultline-engine`と`faultline-agent`はそれぞれrole suffixを
持ちます。engineは低レベル実装であり、主たる利用者向けcontrollerではありません。
