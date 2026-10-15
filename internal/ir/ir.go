// Package ir 定义后端无关的中间表示（IR）。
//
// compiler 把 model.Policy 编译为 Snapshot；Backend 负责把 Snapshot 翻译成
// 具体的防火墙实现（nftables / iptables / mock）。IR 同时可渲染为 nft 规则集文本，
// 供 dry-run 审阅与"期望状态 vs 已应用状态"的对账使用。
package ir

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// Family 是地址族（nft 的 family）。
type Family string

const (
	FamilyINet Family = "inet" // 同时处理 IPv4 / IPv6
	FamilyIP   Family = "ip"
	FamilyIP6  Family = "ip6"
)

// ChainType 是链类型。
type ChainType string

const (
	ChainFilter ChainType = "filter"
	ChainNAT    ChainType = "nat"
	ChainRoute  ChainType = "route"
)

// Hook 是基础链挂载点。
type Hook string

const (
	HookPrerouting  Hook = "prerouting"
	HookInput       Hook = "input"
	HookForward     Hook = "forward"
	HookOutput      Hook = "output"
	HookPostrouting Hook = "postrouting"
)

// nft 标准优先级。
const (
	PrioRaw      = -300
	PrioMangle   = -150
	PrioDstNAT   = -100
	PrioFilter   = 0
	PrioSecurity = 50
	PrioSrcNAT   = 100
)

// Snapshot 是一份完整的期望规则集。
type Snapshot struct {
	Tables []*Table `json:"tables"`
}

// Table 是一张 nft 表。
type Table struct {
	Family Family   `json:"family"`
	Name   string   `json:"name"`
	Sets   []*Set   `json:"sets,omitempty"`
	Chains []*Chain `json:"chains,omitempty"`
}

// Set 是命名集合（封禁表、GeoIP 库、限速动态集合等）。
type Set struct {
	Name string `json:"name"`
	// KeyType 为 nft 集合元素类型：ipv4_addr / ipv6_addr / inet_service / ether_addr。
	KeyType string `json:"key_type"`
	// Flags：interval（区间查找）、timeout（元素自动过期）、dynamic（运行时增删）。
	Flags    []string      `json:"flags,omitempty"`
	Timeout  time.Duration `json:"timeout,omitempty"`
	Elements []Element     `json:"elements,omitempty"`
	Comment  string        `json:"comment,omitempty"`
}

// Element 是集合元素。
type Element struct {
	Key     string        `json:"key"`
	Timeout time.Duration `json:"timeout,omitempty"`
	Comment string        `json:"comment,omitempty"`
}

// Chain 是链。Base 为 true 时是基础链，必须指定 Hook / Priority / Policy。
type Chain struct {
	Name     string    `json:"name"`
	Type     ChainType `json:"type"`
	Hook     Hook      `json:"hook,omitempty"`
	Priority int       `json:"priority,omitempty"`
	// Policy 仅对基础链有效：accept / drop；空表示不设（默认 accept）。
	Policy string  `json:"policy,omitempty"`
	Base   bool    `json:"base,omitempty"`
	Rules  []*Rule `json:"rules,omitempty"`
	// Comment 说明该链的用途（会渲染为 nft 注释）。
	Comment string `json:"comment,omitempty"`
}

// Rule 是一条规则：全部 Match 为 AND，随后按序执行 Statements。
type Rule struct {
	ID      string      `json:"id,omitempty"`
	Matches []Match     `json:"matches,omitempty"`
	Stmts   []Statement `json:"statements"`
	Comment string      `json:"comment,omitempty"`
	// Raw 非空时原样输出（用于承载无法结构化的既有规则）。
	Raw string `json:"raw,omitempty"`
}

// MatchOp 是匹配运算符。
type MatchOp string

const (
	OpEq    MatchOp = "=="
	OpNeq   MatchOp = "!="
	OpLt    MatchOp = "<"
	OpGt    MatchOp = ">"
	OpRange MatchOp = "range"
)

// Match 是一条匹配条件。
//
//	Set 非空时做集合查找（如 ip saddr @banned4）；否则对 Values 做等值/区间匹配。
type Match struct {
	Field  string   `json:"field"`
	Op     MatchOp  `json:"op,omitempty"`
	Values []string `json:"values,omitempty"`
	Set    string   `json:"set,omitempty"`
	Negate bool     `json:"negate,omitempty"`
}

// StmtKind 是语句种类。
type StmtKind string

const (
	StmtVerdict    StmtKind = "verdict" // accept / drop / reject / return
	StmtLog        StmtKind = "log"
	StmtCounter    StmtKind = "counter"
	StmtLimit      StmtKind = "limit"        // 全局令牌桶限速
	StmtLimitPerIP StmtKind = "limit_per_ip" // 按源地址限速（动态集合）
	StmtNAT        StmtKind = "nat"
	StmtJump       StmtKind = "jump"
	StmtGoto       StmtKind = "goto"
	StmtMeter      StmtKind = "meter" // 仅更新动态集合，不裁决
)

// Statement 是一条可渲染的 nft 语句。
type Statement struct {
	Kind StmtKind `json:"kind"`

	// Verdict:
	Verdict string `json:"verdict,omitempty"`
	Reject  string `json:"reject,omitempty"`
	// Log:
	Prefix string `json:"prefix,omitempty"`
	Level  string `json:"level,omitempty"`
	// Limit / LimitPerIP / Meter:
	Rate     int    `json:"rate,omitempty"`
	Per      string `json:"per,omitempty"`
	Burst    int    `json:"burst,omitempty"`
	KeyField string `json:"key_field,omitempty"` // 例如 "ip saddr"
	SetName  string `json:"set_name,omitempty"`  // 动态集合名
	Over     bool   `json:"over,omitempty"`      // limit rate over（超过即命中）
	// NAT:
	NATKind string `json:"nat_kind,omitempty"` // snat | dnat | masquerade | redirect
	Addr    string `json:"addr,omitempty"`
	Port    string `json:"port,omitempty"`
	// Jump / Goto:
	Target string `json:"target,omitempty"`
}

// ---- 便捷构造 ----

// Accept 返回一条无条件的 accept 规则。
func Accept(comment string) *Rule {
	return &Rule{Stmts: []Statement{{Kind: StmtVerdict, Verdict: "accept"}}, Comment: comment}
}

// Drop 返回一条无条件的 drop 规则。
func Drop(comment string) *Rule {
	return &Rule{Stmts: []Statement{{Kind: StmtVerdict, Verdict: "drop"}}, Comment: comment}
}

// CtState 构造 conntrack 状态匹配。
func CtState(states ...string) Match {
	return Match{Field: "ct state", Values: states}
}

// SortRules 按 ID 稳定排序（编译器保证输入顺序，这里仅用于展示/对账）。
func (c *Chain) SortRules() {
	sort.SliceStable(c.Rules, func(i, j int) bool { return c.Rules[i].ID < c.Rules[j].ID })
}

// Table 按名称查找表。
func (s *Snapshot) Table(family Family, name string) *Table {
	for _, t := range s.Tables {
		if t.Family == family && t.Name == name {
			return t
		}
	}
	return nil
}

// Chain 按名称查找链。
func (t *Table) Chain(name string) *Chain {
	for _, c := range t.Chains {
		if c.Name == name {
			return c
		}
	}
	return nil
}

// Set 按名称查找集合。
func (t *Table) Set(name string) *Set {
	for _, s := range t.Sets {
		if s.Name == name {
			return s
		}
	}
	return nil
}

// RuleCount 返回快照中的规则总数。
func (s *Snapshot) RuleCount() int {
	n := 0
	for _, t := range s.Tables {
		for _, c := range t.Chains {
			n += len(c.Rules)
		}
	}
	return n
}

// formatDuration 把 time.Duration 渲染为 nft 可接受的字面量（如 1h30m）。
func formatDuration(d time.Duration) string {
	if d <= 0 {
		return ""
	}
	if d%time.Hour == 0 {
		return fmt.Sprintf("%dh", d/time.Hour)
	}
	if d%time.Minute == 0 {
		return fmt.Sprintf("%dm", d/time.Minute)
	}
	if d%time.Second == 0 {
		return fmt.Sprintf("%ds", d/time.Second)
	}
	return fmt.Sprintf("%dms", d/time.Millisecond)
}

// quoteIfNeeded 对需要引号的标识符加引号。
func quoteIfNeeded(s string) string {
	if s == "" {
		return `""`
	}
	if strings.ContainsAny(s, " \t\"'{};#") || !isASCII(s) {
		return quote(s)
	}
	return s
}

// quote 无条件加引号（用于 comment / 接口名等）。
func quote(s string) string {
	return `"` + strings.ReplaceAll(s, `"`, `\"`) + `"`
}

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			return false
		}
	}
	return true
}
