// Package netcfg 管理系统级网络配置：转发开关、内核网络参数、
// 以及接口/地址/路由/策略路由的读取。
//
// 为什么把 sysctl 纳入防火墙工具：网关型防火墙依赖 net.ipv4.ip_forward=1。
// 这个开关没打开时，规则集看起来完全正确、nft 也正常加载，但**跨网段流量
// 根本不会到达 filter 钩子** —— 表现为"策略写了却不生效"，极难排查。
// 因此把它作为一等公民显式管理并在启动时校验。
//
// 接口地址与路由的写入是最容易把自己锁死的操作，本包先提供只读清单与
// 参数管理；变更类操作在设计上要求显式 dry-run 与 commit-confirm 兜底。
package netcfg

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// Sysctl 是一个内核网络参数。
type Sysctl struct {
	Key   string `json:"key" yaml:"key"`     // 如 net.ipv4.ip_forward
	Value string `json:"value" yaml:"value"` // 如 "1"
}

// Link 是接口的期望属性。
type Link struct {
	Name string `json:"name"`
	MTU  int    `json:"mtu,omitempty"`
	Up   *bool  `json:"up,omitempty"`
}

// LinkState 是接口的当前状态。
type LinkState struct {
	Name  string   `json:"name"`
	Index int      `json:"index"`
	MTU   int      `json:"mtu"`
	Up    bool     `json:"up"`
	Flags []string `json:"flags,omitempty"`
}

// Address 是一个接口地址。
type Address struct {
	Interface string `json:"interface"`
	CIDR      string `json:"cidr"`
	Family    string `json:"family,omitempty"` // inet | inet6（读取时填充）
}

// Route 是一条路由。
type Route struct {
	Dst    string `json:"dst"`
	Via    string `json:"via,omitempty"`
	Dev    string `json:"dev,omitempty"`
	Table  int    `json:"table,omitempty"`
	Metric int    `json:"metric,omitempty"`
	Proto  string `json:"proto,omitempty"`
}

// IPRule 是一条策略路由规则。
type IPRule struct {
	Priority int    `json:"priority"`
	From     string `json:"from,omitempty"`
	To       string `json:"to,omitempty"`
	Table    int    `json:"table,omitempty"`
	Mark     int    `json:"mark,omitempty"`
}

// State 是当前系统网络状态（只读快照）。
type State struct {
	Platform   string            `json:"platform"`
	Sysctls    map[string]string `json:"sysctls"`
	Links      []LinkState       `json:"links,omitempty"`
	Addresses  []Address         `json:"addresses,omitempty"`
	Routes     []Route           `json:"routes,omitempty"`
	IPRules    []IPRule          `json:"ip_rules,omitempty"`
	Forwarding bool              `json:"forwarding"`
	Note       string            `json:"note,omitempty"`
}

// Change 描述一次配置变更。
type Change struct {
	Kind   string `json:"kind"`   // sysctl | link | address | route | ip_rule
	Action string `json:"action"` // set | add | del | set_up | set_down | mtu
	Target string `json:"target"`
	From   string `json:"from,omitempty"`
	To     string `json:"to,omitempty"`
}

func (c Change) String() string {
	switch c.From {
	case "":
		return fmt.Sprintf("%s %s %s -> %s", c.Kind, c.Action, c.Target, c.To)
	default:
		return fmt.Sprintf("%s %s %s: %s -> %s", c.Kind, c.Action, c.Target, c.From, c.To)
	}
}

// Provider 是平台相关的实现。
type Provider interface {
	// Platform 返回平台标识，如 "linux"。
	Platform() string
	// Supported 报告本平台是否支持读取与修改。
	Supported() bool
	// Read 读取当前网络状态。
	Read(ctx context.Context) (*State, error)
	// SetSysctls 写入内核网络参数。
	SetSysctls(ctx context.Context, s []Sysctl) ([]Change, error)
}

// 常用参数：网关型防火墙的推荐基线。
const (
	KeyIPv4Forward = "net.ipv4.ip_forward"
	KeyIPv6Forward = "net.ipv6.conf.all.forwarding"
	KeyRPFilter    = "net.ipv4.conf.all.rp_filter"
	KeySyncookies  = "net.ipv4.tcp_syncookies"
	KeyConnMax     = "net.netfilter.nf_conntrack_max"
	KeyConnBucket  = "net.netfilter.nf_conntrack_buckets"
	KeySynRecvTO   = "net.netfilter.nf_conntrack_tcp_timeout_syn_recv"
)

// GatewayBaseline 返回网关场景的推荐参数（不覆盖调用方已显式给出的值）。
//
// 这些是"让规则生效"与"抗 SYN 洪泛"的最小集合，不含需要按机器调优的容量类参数。
func GatewayBaseline() []Sysctl {
	return []Sysctl{
		{Key: KeyIPv4Forward, Value: "1"},
		{Key: KeySyncookies, Value: "1"},
		{Key: KeyRPFilter, Value: "0"},
	}
}

// NormalizeKey 把 sysctl 的两种写法统一为点分格式。
//
// 内核与 sysctl(8) 接受 "net.ipv4.ip_forward" 与 "net/ipv4/ip_forward" 两种写法，
// 配置文件里两种都有人写，这里统一，避免同一个参数被当成两个。
func NormalizeKey(key string) string {
	key = strings.TrimSpace(key)
	key = strings.TrimPrefix(key, "/proc/sys/")
	return strings.Join(strings.Split(strings.Trim(key, "/"), "/"), ".")
}

// validateSysctl 校验键名与取值，避免把垃圾写进内核。
func validateSysctl(s Sysctl) error {
	if s.Key == "" {
		return fmt.Errorf("sysctl 键不能为空")
	}
	for _, part := range strings.Split(s.Key, ".") {
		if part == "" {
			return fmt.Errorf("sysctl 键 %q 含空段", s.Key)
		}
	}
	v := strings.TrimSpace(s.Value)
	if v == "" {
		return fmt.Errorf("sysctl %s 的取值不能为空", s.Key)
	}
	// 内核参数取值是整数或由空白分隔的整数列表（如 tcp_rmem）。
	for _, field := range strings.Fields(v) {
		if _, err := strconv.Atoi(field); err != nil {
			return fmt.Errorf("sysctl %s 的取值 %q 不是整数（内核参数只接受整数）", s.Key, field)
		}
	}
	return nil
}

// Normalize 校验并规范化一组参数，按键去重（后者覆盖前者）。
func Normalize(in []Sysctl) ([]Sysctl, error) {
	seen := map[string]int{}
	var out []Sysctl
	for _, s := range in {
		s.Key = NormalizeKey(s.Key)
		s.Value = strings.TrimSpace(s.Value)
		if err := validateSysctl(s); err != nil {
			return nil, err
		}
		if i, ok := seen[s.Key]; ok {
			out[i] = s
			continue
		}
		seen[s.Key] = len(out)
		out = append(out, s)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out, nil
}

// DiffSysctls 比较期望值与当前值，返回需要变更的项。
func DiffSysctls(desired []Sysctl, current map[string]string) []Change {
	var out []Change
	for _, s := range desired {
		cur, ok := current[s.Key]
		if ok && strings.TrimSpace(cur) == s.Value {
			continue
		}
		out = append(out, Change{Kind: "sysctl", Action: "set", Target: s.Key, From: cur, To: s.Value})
	}
	return out
}
