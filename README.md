# 服务器网关防火墙（fwdd / fw）

一个用 **Go** 编写、基于 **Linux nftables** 的**网关型（路由器型）防火墙**：
部署在 Linux 服务器上，作为 LAN ↔ WAN ↔ DMZ 之间的转发网关，承担跨网段包转发、
访问控制、NAT 与抗 DDoS。

设计上把「你描述想要什么」与「内核里实际是什么」分开：所有变更都先落到**期望状态**，
由编译器翻译成一份后端无关的中间表示（IR），再原子下发到内核。因此规则可审阅、
可对账、可回滚，且**不会把管理员自己锁在门外**。

---

## 当前进度

本项目按里程碑推进，**M1–M6 已完成**（见下方「路线图」）：

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
| 限速与抗 DDoS（令牌桶 + 单源并发连接数限制） | ✅ |
| 自动封禁引擎（conntrack + 日志检测、递进惩罚、白名单） | ✅ |
| 内嵌 Web 管理界面（零构建、可离线） | ✅ |
| Prometheus 指标与 SSE 实时事件流 | ✅ |
| 地址组（国家封锁 / 威胁情报列表 → nft 区间集合） | ✅ |
| GeoIP 国家拦截、打包与测试矩阵 | ⏳ M7 |

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

## 地址组（国家封锁、威胁情报列表）

几万条 CIDR 的列表**不能**写进规则里 —— 那会被内联成规则文本，规则集直接爆炸。
地址组把它们编译成 nft **区间集合**，查找 O(1)：

```yaml
addr_groups:
  # 每行一个 CIDR，`#` 起注释，裸 IP 会补成 /32 或 /128
  - name: cn
    file: /etc/fwdd/geoip/CN.cidr
  - name: threat-intel
    file: /etc/fwdd/lists/threat.cidr
  - name: small
    cidrs: [10.0.0.0/8, 192.168.0.0/16]   # 少量地址用内联

rules:
  - id: block-cn
    src_zone: wan
    dst_zone: any
    src_group: cn          # 也可以 dst_group
    action: drop
```

编译结果：

```
set grp_cn4 { type ipv4_addr; flags interval; elements = { 1.0.1.0/24, ... } }
set grp_cn6 { type ipv6_addr; flags interval; elements = { 2001:db8::/32 } }
...
iifname "eth0" ip saddr @grp_cn4 counter drop
iifname "eth0" ip6 saddr @grp_cn6 counter drop
```

**关于国家列表从哪来**：本工具只负责加载 CIDR 列表，不解析 GeoLite2 数据库
（那要引依赖，而且 MaxMind 的库有许可限制）。你可以从
[ipdeny.com](https://www.ipdeny.com/ipblocks/) 直接下载 `cn-aggregated.zone`
这类文件，或用 `mmdblookup` / 官方工具从 GeoLite2 导出。格式就是"每行一个 CIDR"。

```bash
fw groups                # 列出已加载的组：条目数、来源文件、被哪些规则引用
fw groups reload         # 重新读取文件（不自动下发）
```

**列表更新不该要求重启**：`fwdd` 每 30 分钟自动重读一次地址组文件；发现内容变化时
只更新期望状态并**标记为未同步**，由你决定什么时候 `apply` —— 与其余变更一致，
没有任何东西会背着你改动内核。

> 加载失败会让策略设置整个失败，而不是跳过那个组。少了地址的封锁是静默失效：
> 规则集看起来完全正常，只是那些地址根本没被匹配到，比启动报错难查得多。

---

## 限速与抗 DDoS

两道**独立**的防线，可以单独配，也可以一起配：

| 参数 | 拦什么 | nft 实现 |
| --- | --- | --- |
| `limit.rate` + `per_ip` | 连接**建得太快**（洪泛） | `add @set { ip saddr limit rate over N/unit }` |
| `limit.max_concurrent` | 连接**建得太多且不释放** | `add @set { ip saddr ct count over N }` |

```yaml
- id: wan-slowloris
  src_zone: wan
  dst_zone: dmz
  proto: tcp
  dst_port: ["80", "443"]
  state: [new]
  action: drop
  limit:
    rate: 30            # 每源每秒最多 30 个新连接
    per: second
    per_ip: true
    max_concurrent: 64  # 每源最多 64 个并发连接
```

为什么两个都要：**慢速攻击（slowloris 一类）每秒只建几个连接，速率限制完全看不出来**，
但并发连接数会一路涨上去。只配速率限制，挡不住这类攻击。

`per_ip` 决定速率是按每个源地址分别计数（动态集合）还是全局计数（令牌桶）——
抗洪泛要按源，限制某个服务的总吞吐则用全局。

SYN 洪泛另有一层防护，走内核参数：`net.ipv4.tcp_syncookies=1` 已在默认基线里，
用 `manage_sysctls: true` 或 `fw net sysctl apply` 打开。

> **注意**：`ct count` 只对 tcp/udp 有意义，配置校验会拒绝在 ICMP 上使用它。

---

## 自动封禁

检测可疑行为 → 滑动窗口累计加权 → 达阈值则封禁，且**越封越长**。

```
检测器                   判罚引擎                      执行
conntrack 采样  ─┐                                  ┌─ 写期望状态
日志特征匹配    ─┼─▶ 加权滑动窗口 ─▶ 达阈值 ─▶ 封禁 ─┼─ 落 SQLite
手工 / API      ─┘   递进惩罚 · 白名单 · 上限保护    └─ 注入 nftables 集合
```

**默认只观察不封禁**（`auto_ban.enabled: false`）。此时检测器照常工作、照常记录
达到阈值的地址，只是不真的封 —— 先跑一段时间看"封得准不准"，再打开开关。
误封一个有合法用途的地址（监控探针、NAT 出口、爬虫）比漏封更难收拾。

| 参数 | 默认 | 说明 |
| --- | --- | --- |
| `window` / `threshold` | 10m / 20 | 窗口内累计**权重**达标即封禁 |
| `base_ttl` | 10m | 首次封禁时长 |
| `multiplier` / `max_ttl` | 2 / 24h | 每多违规一次翻倍，有上限 |
| `strike_reset_after` | 24h | 安静这么久就清零惩罚计数 |
| `whitelist` | 回环 | 永不封禁；不配时至少护住本机 |

**检测器**

- **conntrack**：轮询 conntrack 表，用两次采样之差判断新建连接速率，
  并统计单源并发连接数。不依赖 `nf_conntrack_acct`，任何内核都能用。
- **日志**：跟踪文件（自动处理轮转），正则命中即计分。内置 sshd 认证失败、
  无效用户、认证次数超限，以及本工具自己打的 nft 限速日志（从 `SRC=` 取地址）。
  自定义特征的正则**必须恰好含一个捕获组**，捕获的就是要封的地址。

```bash
fw ban engine                  # 引擎状态：模式、阈值、跟踪与封禁计数
fw ban engine --enable         # 运行时打开（不必重启）
fw ban offenders               # 被跟踪的可疑地址，按可疑度倒序
fw ban list                    # 已封禁的（来源标记为 auto）
fw ban rm 203.0.113.9          # 手工解封
```

几个刻意的设计取舍：

- **封禁后清空窗口**。否则解封瞬间残留计数会立刻把它重新封上。
- **封禁期内不重复下发**。避免一条攻击打出一屏审计日志。
- **跟踪表有上限**（默认 10 万），被海量随机源地址扫描时丢弃新来源并计数，
  而不是无限吃内存。
- **手工解封会通知判罚引擎清窗口**，同样是为了避免"解了马上又被封"。

> 预置的限速/封禁只作用于**转发与本机入口**。想封自己的管理入口请用白名单护住，
> 别让自动封禁把你自己挡在门外。

---

## Web 管理界面

守护进程自带管理界面，打开 <http://127.0.0.1:8080/ui/> 即可（根路径会跳转过去）。

**零构建步骤**：界面是手写的 HTML/CSS/JS，用 `go:embed` 打进二进制。目标机上不需要
Node，交叉编译、单文件部署、离线环境全部照常工作。同样**没有引用任何外部字体或 CDN**
—— 防火墙常常跑在隔离网络里，界面必须能完全离线显示。测试里有一条断言专门盯着这点。

七个视图：**总览 / 规则 / 安全域 / NAT / 封禁 / 网络 / 审计**。

### 规则指纹

总览页的核心是一条「规则指纹」：每条链按求值顺序展开成一条色带，每格一条规则，
颜色就是它的裁决，链尾的斜纹是默认策略。

```
forward   ██ ███ ███ ███ ███ ░░░░ ░░▓    6
          drop └──── accept ────┘ log  ↖默认 drop
```

它替代了"数一数表格里有几行"：规则集的**形状**一眼可见 —— 放行在哪、丢弃在哪、
默认策略从哪开始接管。改了顺序或停用了某条规则，形状会立刻变。

### 认证

若配置了 `token`，界面会提示输入一次并存在浏览器本地（`localStorage`），
后续请求带 `Authorization: Bearer`。静态资源本身不需要认证 —— 否则用户连
"输入令牌"这个页面都打不开；数据接口仍然全部要过令牌。

也可以用 `?token=xxx` 打开，会自动存入本地并清掉 URL。

### 实时事件

界面通过 SSE 订阅 `/api/v1/events`，新事件直接插到表格顶部，不打乱你的阅读位置。
代理环境或隔离网络里 SSE 常会被缓冲甚至掐断，因此也可以 `?live=off` 关掉，
界面退化为 15 秒定时刷新，功能不受影响。

其余读数为按需拉取；页面不可见时不轮询，避免白白打扰服务端。

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
└──────────┘   │        ┌──────────────────────────────────────────────┐
┌──────────┐   │        │                   fwdd                       │
│  Web UI  │───┼───────▶│  REST API ──▶ engine ──▶ compiler ──▶ IR      │
│ (go:embed)│  │        │  SSE /metrics  (期望/已应用/回滚)             │
└──────────┘   │        └───────────────────┬──────────────────────────┘
               │                            │  Backend 接口
               │              ┌─────────────┴─────────────┐
               │              ▼                           ▼
               │        nftables 后端                mock 后端
               │        （nft -f -）               （内存，测试/演示）
               │              │
               │              ▼
               │        Linux 内核 netfilter
               │
               │        ┌──────────────────────────────────────────────┐
               └───────▶│ 自动封禁：conntrack / 日志检测器 ──▶ 判罚引擎 │
                        │            netcfg：转发开关与网络清点         │
                        └──────────────────────────────────────────────┘
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
fw ban engine [--enable|--disable]    自动封禁引擎状态与开关
fw ban offenders                     被跟踪的可疑地址
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
| GET/POST | `/ban/engine` | 自动封禁引擎状态与开关 |
| GET | `/ban/offenders` | 被跟踪的可疑地址 |
| GET | `/metrics` | Prometheus 指标 |
| GET | `/api/v1/events` | SSE 实时事件流 |
| GET | `/ui/` | Web 管理界面 |
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
internal/ban/        自动封禁：检测器（conntrack/日志）+ 判罚引擎
internal/addrgroup/  地址组加载（CIDR 列表 → 区间集合元素）
internal/obs/        Prometheus 指标与进程内事件总线
internal/webui/      Web 管理界面（go:embed 内嵌，无构建步骤）
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
- **M5（已完成）** 自动封禁：conntrack 与日志检测器、加权滑动窗口、
  递进惩罚、白名单、跟踪表上限、运行时开关。
- **M6（已完成）** 内嵌 Web 管理界面、SSE 实时事件流、Prometheus 指标。
- **M7** 大集合性能优化、打包与 netns 端到端测试矩阵。

---

## 已知限制

- 网络配置目前只读：可以清点接口/地址/路由，可以管理内核参数，
  但**不能**写入接口地址或路由条目。
- 未与既有 iptables 规则做共存策略；同一钩子上二者会按 priority 排序，接管前请确认。
- 不解析 GeoLite2 数据库；国家列表请自行导出为 CIDR 文本（见「地址组」一节）。
- conntrack 连接表浏览尚未实现。
- 自动封禁的 conntrack 检测器需要 Linux；日志检测器在任何平台都能用。
