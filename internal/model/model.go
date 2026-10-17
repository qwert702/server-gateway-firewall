// Package model 定义防火墙的声明式数据模型 —— 期望状态的唯一真相来源。
//
// 所有变更（CLI / REST API / Web UI）最终都表现为对 Policy 的修改；
// Policy 由 compiler 编译为后端无关的 ir.Snapshot，再交给 Backend 下发到内核。
package model

import (
	"net"
	"time"
)

// Trust 是安全域的信任级别，用于默认策略推导与审计提示。
type Trust string

const (
	TrustUntrusted Trust = "untrusted"
	TrustDMZ       Trust = "dmz"
	TrustLAN       Trust = "lan"
	TrustLocal     Trust = "local"
)

// 两个特殊域名的约定：
//
//	ZoneAny   —— 任意域，匹配时不施加接口/网段约束（空字符串等价）。
//	ZoneLocal —— 本机（防火墙自身），选路时进入 input / output 链而非 forward 链。
const (
	ZoneAny   = "any"
	ZoneLocal = "local"
)

// Zone 把接口与网段按信任级别分组。
type Zone struct {
	Name       string   `json:"name" yaml:"name"`
	Interfaces []string `json:"interfaces,omitempty" yaml:"interfaces,omitempty"`
	Networks   []string `json:"networks,omitempty" yaml:"networks,omitempty"`
	Trust      Trust    `json:"trust,omitempty" yaml:"trust,omitempty"`
	Comment    string   `json:"comment,omitempty" yaml:"comment,omitempty"`
}

// Proto 为四层协议。
type Proto string

const (
	ProtoAny    Proto = "any"
	ProtoTCP    Proto = "tcp"
	ProtoUDP    Proto = "udp"
	ProtoICMP   Proto = "icmp"
	ProtoICMPv6 Proto = "icmpv6"
	ProtoIGMP   Proto = "igmp"
	ProtoGRE    Proto = "gre"
	ProtoESP    Proto = "esp"
)

// Action 是规则命中后的裁决。
type Action string

const (
	ActionAccept Action = "accept"
	ActionDrop   Action = "drop"
	ActionReject Action = "reject"
	ActionLog    Action = "log" // 仅记录，不做裁决（继续匹配后续规则）
)

// RejectMode 指定 reject 的实现方式。
type RejectMode string

const (
	RejectDefault     RejectMode = ""
	RejectTCPReset    RejectMode = "tcp-reset"
	RejectICMPUnreach RejectMode = "icmp-port-unreachable"
)

// Rule 是一条转发/本机访问控制规则。
//
// 语义：SrcZone → DstZone 之间，满足全部匹配条件（AND）的流量执行 Action。
//   - SrcZone/DstZone 为 ZoneLocal 时表示本机，自动进入 input / output 链。
//   - SrcZone/DstZone 为 ZoneAny 或空时，不施加该方向的接口/网段约束。
type Rule struct {
	ID       string `json:"id" yaml:"id"`
	Priority int    `json:"priority" yaml:"priority"`
	// Enabled 缺省视为启用；显式 false 表示停用。
	Enabled *bool  `json:"enabled,omitempty" yaml:"enabled,omitempty"`
	SrcZone string `json:"src_zone,omitempty" yaml:"src_zone,omitempty"`
	DstZone string `json:"dst_zone,omitempty" yaml:"dst_zone,omitempty"`

	Proto   Proto    `json:"proto,omitempty" yaml:"proto,omitempty"`
	SrcAddr []string `json:"src_addr,omitempty" yaml:"src_addr,omitempty"`
	DstAddr []string `json:"dst_addr,omitempty" yaml:"dst_addr,omitempty"`
	SrcPort []string `json:"src_port,omitempty" yaml:"src_port,omitempty"`
	DstPort []string `json:"dst_port,omitempty" yaml:"dst_port,omitempty"`
	// State 为 conntrack 状态：new / established / related / invalid / untracked。
	State []string `json:"state,omitempty" yaml:"state,omitempty"`

	Action    Action     `json:"action" yaml:"action"`
	Reject    RejectMode `json:"reject,omitempty" yaml:"reject,omitempty"`
	Log       bool       `json:"log,omitempty" yaml:"log,omitempty"`
	LogPrefix string     `json:"log_prefix,omitempty" yaml:"log_prefix,omitempty"`
	Counter   *bool      `json:"counter,omitempty" yaml:"counter,omitempty"`
	Limit     *RateLimit `json:"limit,omitempty" yaml:"limit,omitempty"`

	// SrcGroup / DstGroup 引用命名地址组（见 AddrGroup）。
	//
	// 用途是承载"几万条 CIDR"这类列表：国家封锁、威胁情报订阅、大网段清单。
	// 这些地址**不能**写进规则的地址列表 —— 那会被内联进规则文本，几万条
	// 会让规则集爆炸；地址组编译成 nft 区间集合，查找是 O(1)。
	//
	// 每条规则最多引用一个源组与一个目的组（要匹配多个组就写多条规则），
	// 这样才不会有"组 × 组"的组合爆炸。
	SrcGroup string `json:"src_group,omitempty" yaml:"src_group,omitempty"`
	DstGroup string `json:"dst_group,omitempty" yaml:"dst_group,omitempty"`

	Comment string `json:"comment,omitempty" yaml:"comment,omitempty"`
}

// AddrGroup 是一个命名地址组。
//
// 地址来源二选一：文件（每行一个 CIDR，`#` 开头为注释）或内联列表。
// 文件形式是给"几万条"那种体量用的 —— 那不该出现在策略文件里。
type AddrGroup struct {
	Name string `json:"name" yaml:"name"`
	// File 为 CIDR 列表文件路径。
	File string `json:"file,omitempty" yaml:"file,omitempty"`
	// CIDRs 为内联地址列表，适合少量地址。
	CIDRs   []string `json:"cidrs,omitempty" yaml:"cidrs,omitempty"`
	Comment string   `json:"comment,omitempty" yaml:"comment,omitempty"`
}

// IsEnabled 缺省为启用。
func (r *Rule) IsEnabled() bool { return r.Enabled == nil || *r.Enabled }

// HasCounter 缺省为开启计数器（便于 stats 展示命中次数）。
func (r *Rule) HasCounter() bool { return r.Counter == nil || *r.Counter }

// RateLimit 描述限速参数，可用于单条规则或全局限速。
type RateLimit struct {
	Rate  int    `json:"rate,omitempty" yaml:"rate,omitempty"` // 单位时间内的包数
	Per   string `json:"per,omitempty" yaml:"per,omitempty"`   // second | minute | hour | day
	Burst int    `json:"burst,omitempty" yaml:"burst,omitempty"`
	// PerIP 为 true 时按源地址分别计数（nft 动态集合），否则全局计数。
	PerIP bool `json:"per_ip,omitempty" yaml:"per_ip,omitempty"`

	// MaxConcurrent 限制**单个源地址的并发连接数**（nft: ct count over N）。
	//
	// 与 Rate 是不同的防线：Rate 拦的是"连接建得太快"，MaxConcurrent 拦的是
	// "连接建得太多且不释放"。慢速攻击（slowloris 一类）每秒只建几个连接，
	// 速率限制看不出来，但并发数会一路涨上去。
	MaxConcurrent int `json:"max_concurrent,omitempty" yaml:"max_concurrent,omitempty"`
}

// Empty 报告该限速是否什么都没配。
func (r *RateLimit) Empty() bool {
	return r == nil || (r.Rate <= 0 && r.MaxConcurrent <= 0)
}

// NATKind 为 NAT 类型。
type NATKind string

const (
	NATSNAT       NATKind = "snat"
	NATMasquerade NATKind = "masquerade"
	NATDNAT       NATKind = "dnat"
)

// NATRule 描述一条地址转换规则。
//
//	dnat:       来自 SrcZone、目的为 MatchAddr:DstPort 的流量改写为 ToAddr:ToPort
//	snat:       出方向流量源地址改写为 ToAddr（可限 OutZone / DstAddr）
//	masquerade: 出 OutZone 的流量源地址伪装为出接口地址
type NATRule struct {
	ID        string   `json:"id" yaml:"id"`
	Priority  int      `json:"priority" yaml:"priority"`
	Enabled   *bool    `json:"enabled,omitempty" yaml:"enabled,omitempty"`
	Kind      NATKind  `json:"kind" yaml:"kind"`
	Proto     Proto    `json:"proto,omitempty" yaml:"proto,omitempty"`
	SrcZone   string   `json:"src_zone,omitempty" yaml:"src_zone,omitempty"`
	SrcAddr   []string `json:"src_addr,omitempty" yaml:"src_addr,omitempty"`
	MatchAddr []string `json:"match_addr,omitempty" yaml:"match_addr,omitempty"` // 被转换的目的地址
	MatchPort string   `json:"match_port,omitempty" yaml:"match_port,omitempty"`
	ToAddr    string   `json:"to_addr,omitempty" yaml:"to_addr,omitempty"`
	ToPort    string   `json:"to_port,omitempty" yaml:"to_port,omitempty"`
	OutZone   string   `json:"out_zone,omitempty" yaml:"out_zone,omitempty"`
	Comment   string   `json:"comment,omitempty" yaml:"comment,omitempty"`
}

// IsEnabled 缺省为启用。
func (n *NATRule) IsEnabled() bool { return n.Enabled == nil || *n.Enabled }

// BanSource 表示封禁来源。
type BanSource string

const (
	BanManual    BanSource = "manual"
	BanConntrack BanSource = "conntrack"
	BanLog       BanSource = "log"
	BanProbe     BanSource = "probe"
	BanRateLimit BanSource = "ratelimit"
	// BanAuto 由自动封禁引擎判定产生（具体检测源记在 reason 里）。
	BanAuto BanSource = "auto"
)

// BanEntry 是一条封禁记录。主存储在 SQLite，运行时镜像到 nftables 集合。
type BanEntry struct {
	IP        string    `json:"ip" yaml:"ip"`
	Reason    string    `json:"reason,omitempty" yaml:"reason,omitempty"`
	Source    BanSource `json:"source,omitempty" yaml:"source,omitempty"`
	AddedAt   time.Time `json:"added_at,omitempty" yaml:"added_at,omitempty"`
	ExpiresAt time.Time `json:"expires_at,omitempty" yaml:"expires_at,omitempty"`
}

// TTL 返回剩余封禁时长；零值 ExpiresAt 表示永久封禁。
func (b BanEntry) TTL(now time.Time) time.Duration {
	if b.ExpiresAt.IsZero() {
		return 0
	}
	d := b.ExpiresAt.Sub(now)
	if d < 0 {
		return 0
	}
	return d
}

// Expired 报告该封禁是否已到期。
func (b BanEntry) Expired(now time.Time) bool {
	return !b.ExpiresAt.IsZero() && !now.Before(b.ExpiresAt)
}

// DefaultPolicy 是各内置链的兜底策略。
type DefaultPolicy struct {
	Input   Action `json:"input,omitempty" yaml:"input,omitempty"`
	Forward Action `json:"forward,omitempty" yaml:"forward,omitempty"`
	Output  Action `json:"output,omitempty" yaml:"output,omitempty"`
}

// BanSettings 控制封禁集合的行为。
type BanSettings struct {
	// Timeout 为封禁集合的默认元素超时；内核到期自动解封。
	Timeout time.Duration `json:"timeout,omitempty" yaml:"timeout,omitempty"`
	// Whitelist 中的地址永不封禁。支持单个 IP 与 CIDR。
	Whitelist []string `json:"whitelist,omitempty" yaml:"whitelist,omitempty"`
}

// WhitelistContains 报告某个地址是否落在白名单内（支持 IP 与 CIDR 两种写法）。
func (b BanSettings) WhitelistContains(addr string) bool {
	ip := net.ParseIP(addr)
	if ip == nil {
		return false
	}
	for _, w := range b.Whitelist {
		if _, ipnet, err := net.ParseCIDR(w); err == nil {
			if ipnet.Contains(ip) {
				return true
			}
			continue
		}
		if other := net.ParseIP(w); other != nil && other.Equal(ip) {
			return true
		}
	}
	return false
}

// Policy 是完整的期望状态。
type Policy struct {
	Version    int               `json:"version" yaml:"version"`
	Zones      []Zone            `json:"zones" yaml:"zones"`
	AddrGroups []AddrGroup       `json:"addr_groups,omitempty" yaml:"addr_groups,omitempty"`
	Rules      []Rule            `json:"rules" yaml:"rules"`
	NATRules   []NATRule         `json:"nat_rules,omitempty" yaml:"nat_rules,omitempty"`
	Bans       []BanEntry        `json:"bans,omitempty" yaml:"bans,omitempty"`
	Default    DefaultPolicy     `json:"default" yaml:"default"`
	BanSet     BanSettings       `json:"ban_settings,omitempty" yaml:"ban_settings,omitempty"`
	Meta       map[string]string `json:"meta,omitempty" yaml:"meta,omitempty"`
}

// AddrGroupByName 按名称查找地址组；返回 nil 表示不存在。
func (p *Policy) AddrGroupByName(name string) *AddrGroup {
	if name == "" {
		return nil
	}
	for i := range p.AddrGroups {
		if p.AddrGroups[i].Name == name {
			return &p.AddrGroups[i]
		}
	}
	return nil
}

// ZoneByName 按名称查找域；返回 nil 表示不存在。
func (p *Policy) ZoneByName(name string) *Zone {
	if name == "" || name == ZoneAny || name == ZoneLocal {
		return nil
	}
	for i := range p.Zones {
		if p.Zones[i].Name == name {
			return &p.Zones[i]
		}
	}
	return nil
}

// RuleByID 按 ID 查找规则。
func (p *Policy) RuleByID(id string) *Rule {
	for i := range p.Rules {
		if p.Rules[i].ID == id {
			return &p.Rules[i]
		}
	}
	return nil
}
