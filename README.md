# 服务器网关防火墙（fwdd / fw）

一个用 **Go** 编写、基于 **Linux nftables** 的**网关型（路由器型）防火墙**：
部署在 Linux 服务器上，作为 LAN ↔ WAN ↔ DMZ 之间的转发网关，承担跨网段包转发、
访问控制、NAT 与抗 DDoS。

设计上把「你描述想要什么」与「内核里实际是什么」分开：所有变更都先落到**期望状态**，
由编译器翻译成一份后端无关的中间表示（IR），再原子下发到内核。因此规则可审阅、
可对账、可回滚，且**不会把管理员自己锁在门外**。

---

## 当前进度

本项目按里程碑推进，**M1 + M2 + M3 已完成，M4 进行中**（见下方「路线图」）：

| 能力 | 状态 |
| --- | --- |
| 声明式策略模型 + 静态校验 | ✅ |
| 编译器：策略 → IR → nft 规则集文本 | ✅ |
| nftables 后端：单事务原子替换、运行态读取、集合增删 | ✅ |
| mock 后端：无内核环境下的联调与单测 | ✅ |
| `fw` CLI / REST API / commit-confirm 自动回滚 / dry-run | ✅ |
| YAML 配置与策略基线 | ✅ |
| SQLite 持久化、重启恢复、审计日志 | ✅ |
| 规则 / 域 / NAT 的 CLI 与 REST CRUD | ✅ |
| 转发开关等内核网络参数管理与检查 | ✅ |
| 网络状态清点（接口 / 地址 / 路由 / 策略路由） | ✅ |
| 接口与路由的**写入**（最易自锁，需 commit-confirm 兜底） | ⏳ |
| 自动封禁引擎、GeoIP、Web UI | ⏳ M5–M7 |

> 驱动真实 `nft` 的测试在无 nft 或非 root 环境下自动跳过，因此 `go test ./...`
> 在 Windows/macOS 上也能跑；生成的规则集**尚未在真机校验过语法**，
> 请在 Linux 上执行 `sudo make verify-nft` 补上这一步。

---

## 快速开始

### 1. 离线体验（无需 root、无需 Linux）

`mock` 后端把规则存在内存里，不碰内核，适合先在开发机上把流程走通：

```bash
go build -o bin/ ./cmd/...

cat > dev.yaml <<'EOF'
listen: 127.0.0.1:18080
socket: ""
backend: mock
table: fw
family: inet
policy_file: configs/policy.example.yaml
log_level: info
EOF

./bin/fwdd -config dev.yaml &      # 启动守护进程（Windows 用 fwdd.exe）
./bin/fw -config dev.yaml status
./bin/fw -config dev.yaml ruleset  # 打印完整 nft 规则集
./bin/fw -config dev.yaml plan     # 预览将要下发的差异
```

### 2. 真实网关（Linux，需要 root）

```bash
# 前提：开启转发，否则策略不生效
sysctl -w net.ipv4.ip_forward=1
sysctl -w net.ipv6.conf.all.forwarding=1

sudo cp configs/config.example.yaml /etc/fwdd/config.yaml
sudo cp configs/policy.example.yaml /etc/fwdd/policy.yaml
sudo ./bin/fwdd -config /etc/fwdd/config.yaml
```

下发前先看一遍将要写入内核的规则（所见即所得）：

```bash
sudo ./bin/fwdd -config /etc/fwdd/config.yaml -dry-run
# 或对运行中的守护进程
./bin/fw -config /etc/fwdd/config.yaml apply --dry-run
```

**远程运维时务必开启 commit-confirm**，它会给你一个后悔的机会：

```bash
./bin/fw -config /etc/fwdd/config.yaml apply --confirm --timeout 60
#   规则已生效；若 60 秒内没有执行下面的命令，自动回滚到变更前的状态
./bin/fw -config /etc/fwdd/config.yaml confirm
```

---

## 持久化与重启恢复

状态存在 SQLite 里（`modernc.org/sqlite`，纯 Go，无 cgo），默认位于
`<data_dir>/fwdd.db`：

| 表 | 内容 |
| --- | --- |
| `policy` | 单行，完整期望状态 JSON。一次修改天然是一个事务，不会出现半截状态 |
| `ban_entries` | 封禁记录。写入频繁、需按到期时间清理，故单独建表 |
| `audit_log` | 只追加：谁在什么时候改了什么 |
| `kv` | 元数据，如上次成功下发的哈希（供重启后对账） |

**权威顺序**：数据库中的策略 > 策略文件。策略文件只是**首次启动**的初始值，
之后再改文件不会生效（避免一个陈旧的文件悄悄覆盖管理员的最新编辑）。
要强制用文件覆盖：

```bash
sudo ./bin/fwdd -config /etc/fwdd/config.yaml -import-policy
```

**封禁只有一份**，存在 `ban_entries` 表里。策略 JSON 中不含封禁 —— 两份副本
必然漂移。因此 `fw policy set` / `PUT /policy` **不会**清掉封禁（早期版本会，
表现为"解封了但重启后全部复活"）。启动时若数据库为空，策略文件里的 `bans:`
会被导入该表；已过期的条目在启动时直接清理，不会被重新注入。

演示或测试可以用 `-no-persist`（或配置 `disable_persist: true`）关掉持久化，
此时策略与封禁只存在于内存，重启即遗忘。

### 重启恢复顺序

```
打开数据库 → 清理过期封禁 → 从库读策略（无则用策略文件初始化）
  → 编译 → 单事务下发内核 → 重新注入封禁集合 → 启动 REST API
```

启动时的下发**不进入 commit-confirm 窗口**：本地策略文件是可信基线，
无人值守重启若还要等确认，超时回滚会把防火墙规则整个撤掉。

---

## 网络前提：转发开关

网关型防火墙依赖 `net.ipv4.ip_forward=1`。**这个开关没打开时，规则集看起来完全
正确、`nft` 也正常加载、所有校验都过，但跨网段流量根本不会到达 `forward` 钩子** ——
表现为"策略写了却不生效"，而且排查方向很容易跑偏。

所以 fwdd 启动时会检查它：

```bash
fw net                      # 网络状态；转发未开启时明确点出来
fw net sysctl show          # 内核参数当前值 vs 建议值
sudo fw net sysctl apply --dry-run   # 先看要改什么
sudo fw net sysctl apply             # 按基线写入
```

默认**只检查告警、不擅自改内核**。要让 fwdd 在启动时自动管理，在配置里打开
`manage_sysctls: true`，并可用 `sysctls:` 覆盖默认基线（默认基线为
`ip_forward=1`、`tcp_syncookies=1`、`rp_filter=0`）。

---

## 架构

```
┌──────────┐  Unix socket / HTTP(127.0.0.1:8080)
│ fw (CLI) │───┐
└──────────┘   │        ┌─────────────────────────────────────────┐
┌──────────┐   │        │                fwdd                     │
│ Web UI   │───┼───────▶│  REST API ──▶ engine ──▶ compiler ──▶ IR │
│ (M6)     │   │        │   (M6)      (期望/已应用/回滚)           │
└──────────┘   │        └──────────────────┬──────────────────────┘
               │                           │  Backend 接口
               │                           ▼
               │              ┌────────────┴────────────┐
               │              ▼                         ▼
               │        nftables 后端              mock 后端
               │        （nft -f -）             （内存，测试/演示）
               │              │
               │              ▼
               └────────  Linux 内核 netfilter
```

**写路径**：CLI/Web → 校验 → 写入期望状态 → 编译为 IR → 后端**单个事务**替换 →
成功才更新「已应用」状态。失败则内核与内存状态都不变。

**为什么走 `nft -f -` 而不是 netlink 库**：

1. `nft -f -` 把整个文件作为**一个 netlink 事务**下发，天然满足原子性；
2. dry-run 打印的文本就是实际下发的文本，不存在「渲染器与库不一致」；
3. 不耦合具体 nftables 库的 API 版本变化。

`Backend` 是接口，日后可另加一个基于 `github.com/google/nftables` 的实现，二者可互换。

---

## 策略模型

策略是一份 YAML（或等价的 JSON），是**唯一真相来源**。完整示例见
[`configs/policy.example.yaml`](configs/policy.example.yaml)。

```yaml
zones:                                  # 安全域：把接口/网段分组
  - name: lan
    interfaces: [eth1]
    trust: lan

rules:
  - id: ssh-from-lan                    # id 可省略，会自动分配
    priority: 300                       # 数字小的先匹配
    src_zone: lan
    dst_zone: local                     # local = 防火墙本机
    proto: tcp
    dst_port: ["22"]
    state: [new, established]
    action: accept                      # accept | drop | reject | log
    limit: {rate: 10, per: minute, burst: 20, per_ip: true}

nat_rules:
  - id: dmz-web
    kind: dnat                          # dnat | snat | masquerade
    proto: tcp
    src_zone: wan
    match_port: "8080"
    to_addr: 192.168.20.10
    to_port: "80"

default:
  input: drop
  forward: drop                         # 网关务必保持 drop
  output: accept
```

### 需要记住的三条语义

1. **`local` / `any` 是保留域名。**
   `local` 表示防火墙本机，含它的规则自动进入 `input` / `output` 链；其余进入 `forward` 链。
   `any`（或留空）表示该方向不加约束。

2. **域绑定接口时，网段不参与匹配。**
   域既有 `interfaces` 又有 `networks` 时，以**接口**为边界——再叠加网段会意外收窄匹配范围。
   只有未绑定接口的域才用 `networks` 做地址匹配。

3. **带地址族的规则会按族拆分。**
   一条规则里同时写了 IPv4 与 IPv6 地址时，编译器会展开为两条同义规则，
   因为它们必须分别落到 `ip saddr` 与 `ip6 saddr`。

### 编译器自动做的事

- 在 `input`/`forward`/`output` 链首注入 conntrack 快速通道
  （`ct state invalid drop` + `ct state {established,related} accept`）；
- 语义完全相同的规则自动去重（例如你手写的 established 放行与注入的快速通道）；
- 链尾由 `default` 策略兜底；
- 在 `prerouting` 链最早处用 `banned4`/`banned6` 集合丢弃被封禁的源地址。

### 封禁为什么不在编译产物里

封禁条目是**运行时状态**，元素带 `timeout` 由内核倒计时。若把"剩余时长"编译进
快照，规则集文本每秒都会变，对账哈希随之抖动、`apply` 会永远误报"有变化"。
因此：

- 编译产物只**声明**空的 `banned4`/`banned6` 集合，快照完全确定；
- 封禁由 `fw ban add` 立即注入内核集合，并在每次 `apply`/回滚之后重新注入
  （整表替换会连带重建集合）；
- 内核到点自动解封，进程崩溃也不会提前失效。

---

## CLI

```
fw status [-o json]                  守护进程与规则集状态
fw plan [-o json]                    预览差异（不下发）
fw ruleset                           打印完整 nft 规则集
fw apply [--dry-run] [--confirm] [--timeout 秒]
fw confirm / fw rollback / fw revisions
fw audit [-n 条数]                    操作审计日志
fw net                               网络状态：接口/地址/路由/转发开关
fw net sysctl show|apply [--dry-run]  查看 / 按基线写入内核网络参数
fw policy get|set -f 文件 [--apply]
fw zone list / fw rule list
fw ban add <ip> [--ttl 秒] [--reason 文本] | fw ban list | fw ban rm <ip>
```

全局参数 `-config` 与 `-o json` 可出现在任意位置。

---

## REST API

前缀 `/api/v1`，JSON。默认只监听回环；监听非回环地址时**强制要求** `token`
（`Authorization: Bearer <token>`）。经 Unix 套接字访问视为本机可信，免令牌。

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| GET | `/healthz` | 存活探测 |
| GET | `/status` | 状态汇总（含内核链/集合摘要与同步判定） |
| GET/PUT | `/policy` | 读取 / 替换期望状态（`?apply=true` 立即下发） |
| GET | `/plan` | 下发计划与差异 |
| GET | `/ruleset` | 渲染后的 nft 规则集文本 |
| POST | `/apply` | 下发（`?dry_run` `?confirm` `?timeout`） |
| POST | `/confirm` `/rollback` | 确认 / 回滚 |
| GET | `/revisions` | 下发历史 |
| GET | `/audit` | 操作审计日志（`?limit=`） |
| GET | `/net` | 网络状态与内核参数差异 |
| POST | `/net/sysctls` | 写入内核网络参数（`?dry_run`） |
| POST/PUT/DELETE | `/zones` `/rules` `/nat` | 策略对象增删改 |
| GET/POST | `/bans`，DELETE `/bans/{ip}` | 封禁管理 |
| GET | `/zones` `/rules` `/config` | 策略与配置查询 |

---

## 安全机制

- **commit-confirm**：下发后启动倒计时，窗口内未确认则自动回滚。
  若当时**还没有任何历史版本**，回滚是撤掉整张表（内核回到默认放行），
  而不是下发一份空策略——空策略会编译成 default drop 的链，等于把机器锁死。
  （例外：启动时从策略文件恢复不进入确认窗口，避免无人值守重启把规则撤掉。）
- **dry-run**：先看将要写入内核的文本，再决定是否下发。
- **下发前校验**：悬空域引用、重复 id、非法 CIDR/端口、协议与端口不匹配等
  都会在触碰内核之前被拒绝；失败的修改不会污染期望状态。
- **失败即回退**：后端下发失败时，内核与内存中的「已应用」状态都保持不变。
- **管理面令牌**：非回环监听必须配置 token，配置校验会直接拒绝不安全的组合。

---

## 目录结构

```
cmd/fwdd/            守护进程入口
cmd/fw/              CLI 客户端
internal/model/      声明式数据模型与静态校验（唯一真相）
internal/compiler/   策略 → IR（含地址族拆分、去重、默认策略）
internal/ir/         后端无关的中间表示与 nft 文本渲染器
internal/backend/    后端接口 + nftables 实现 + mock 实现
internal/engine/     期望/已应用状态机、commit-confirm、回滚、封禁
internal/api/        REST 接口与认证
internal/client/     CLI 用的 API 客户端（Unix 套接字优先）
internal/store/      SQLite 持久化（策略、封禁、审计、元数据）
internal/netcfg/     内核网络参数与接口/路由清点（Linux 实现 + 其他平台桩）
internal/config/     守护进程配置加载与校验
configs/             配置与策略示例
deploy/              验证脚本与 systemd 单元（M7 完善）
```

---

## 开发

```bash
make build         # 构建两个二进制到 bin/
make test          # 单元测试
make vet           # go vet
make cross         # 交叉编译 linux/amd64 与 linux/arm64
make verify-nft    # 用真实 nft -c 校验生成的规则集（需 Linux + root）
make netns         # 网络命名空间端到端测试（需 Linux + root）
```

在 Linux 上会遇到的两个环境限制，本仓库都做了处理：

- **驱动 nft 的测试会自动跳过**（见 `internal/backend/nftables/golden_test.go`）：
  没有 `nft` 或不是 root 时 `t.Skip`，因此 `go test ./...` 在 Windows/macOS 上也能跑。
- **`-race` 在 windows/386 上不可用**，请在 Linux CI 上执行 `go test -race ./...`。

---

## 路线图

- **M1 + M2（已完成）** 骨架、后端抽象、模型、编译器、原子下发、dry-run、
  commit-confirm、CLI 与 REST API。
- **M3（已完成）** SQLite 持久化与重启恢复、审计日志、过期封禁清理。
- **M4（进行中）** 策略对象 CRUD；转发开关等内核网络参数的管理与检查；
  接口/地址/路由/策略路由的只读清点。接口与路由的**写入**尚未实现 ——
  这是最容易把自己锁死的操作，需要先把它接进 commit-confirm 兜底。
- **M5** 限速与自动封禁引擎（conntrack 探测、日志解析、递增惩罚、白名单豁免）。
- **M6** 认证与审计完善、Prometheus 指标、SSE 实时连接与日志、内嵌 Web UI。
- **M7** GeoIP 国家拦截、大集合性能优化、systemd 打包、netns 端到端测试矩阵。

---

## 已知限制

- 网络配置目前只读：可以清点接口/地址/路由，可以管理内核参数，
  但**不能**写入接口地址或路由条目。
- 未与既有 iptables 规则做共存策略；同一钩子上二者会按 priority 排序，接管前请确认。
- GeoIP、连接数统计、日志流等读取类接口尚未实现。
