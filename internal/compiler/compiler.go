// Package compiler 把声明式的 model.Policy 编译为后端无关的 ir.Snapshot。
//
// 编译流程：
//
//	Policy --Normalize--> Validate --> 选链（input/forward/output）--> 生成匹配/语句 --> Snapshot
//
// 关键语义：
//   - 含 ZoneLocal 的规则进入 input / output 链（本机流量）；其余进入 forward 链。
//   - 域 → 接口/网段约束；未指定域（any/空）则该方向不加约束。
//   - 规则内地址按地址族拆分为 IPv4 / IPv6 两条同义规则。
//   - 链首插入 conntrack 快速通道（established,related accept / invalid drop），
//     链尾由链策略兜底（默认 drop）。
package compiler

import (
	"errors"
	"fmt"
	"net"
	"sort"
	"strings"
	"time"

	"fwdd/internal/ir"
	"fwdd/internal/model"
)

// Options 控制编译产物的形态。
type Options struct {
	// TableName 为 nft 表名，默认 "fw"。
	TableName string
	// Family 默认 inet（同时覆盖 IPv4/IPv6）。
	Family ir.Family
	// BanSet4 / BanSet6 为封禁集合名；为空表示不生成封禁规则。
	BanSet4 string
	BanSet6 string
	// BanTimeout 为封禁集合元素默认超时。
	BanTimeout time.Duration
	// ConntrackFastPath 为 true 时在链首插入 conntrack 快速通道。
	ConntrackFastPath bool
	// Counters 为 true 时每条规则前插入计数器。
	Counters bool
	// LogPrefix 为日志前缀，默认 "fw: "。
	LogPrefix string
}

func (o Options) withDefaults() Options {
	if o.TableName == "" {
		o.TableName = "fw"
	}
	if o.Family == "" {
		o.Family = ir.FamilyINet
	}
	if o.LogPrefix == "" {
		o.LogPrefix = "fw: "
	}
	return o
}

// Result 是编译产物及其说明。
type Result struct {
	Snapshot *ir.Snapshot
	Warnings []model.Problem
	// Stats 摘要。
	ChainRules map[string]int
}

// Compile 编译策略。若存在 error 级校验问题则返回错误。
func Compile(p *model.Policy, opts Options) (*Result, error) {
	if p == nil {
		return nil, errors.New("策略为空，无法编译")
	}
	opts = opts.withDefaults()
	p.Normalize()

	problems := p.Validate()
	if errs := model.Errors(problems); len(errs) > 0 {
		return nil, &ValidationError{Problems: errs}
	}
	var warns []model.Problem
	for _, pr := range problems {
		if pr.Level == "warning" {
			warns = append(warns, pr)
		}
	}

	c := &compiler{policy: p, opts: opts}
	tbl := &ir.Table{Family: opts.Family, Name: opts.TableName}

	c.buildSets(tbl)
	c.buildChains(tbl)
	c.buildNAT(tbl)

	snap := &ir.Snapshot{Tables: []*ir.Table{tbl}}
	res := &Result{Snapshot: snap, Warnings: warns, ChainRules: map[string]int{}}
	for _, ch := range tbl.Chains {
		res.ChainRules[ch.Name] = len(ch.Rules)
	}
	return res, nil
}

// ValidationError 携带全部阻断性问题。
type ValidationError struct {
	Problems []model.Problem
}

func (e *ValidationError) Error() string {
	var b strings.Builder
	fmt.Fprintf(&b, "策略校验失败（%d 项）:", len(e.Problems))
	for _, p := range e.Problems {
		fmt.Fprintf(&b, "\n  - %s: %s", p.Where, p.Message)
	}
	return b.String()
}

type compiler struct {
	policy *model.Policy
	opts   Options
	chains map[string]*ir.Chain
}

// ---- 集合 ----

func (c *compiler) buildSets(t *ir.Table) {
	// 封禁集合只声明、不预置元素。
	//
	// 封禁是**运行时状态**：元素带 timeout，剩余时长随时间递减，若编译进快照会让
	// 规则集文本每秒都不同，破坏幂等性与对账哈希。因此改为由 engine 在下发之后
	// 通过 SetAdd 注入（语义等价，且快照保持确定性）。
	if c.opts.BanSet4 != "" {
		t.Sets = append(t.Sets, &ir.Set{
			Name:    c.opts.BanSet4,
			KeyType: "ipv4_addr",
			Flags:   []string{"timeout"},
			Timeout: c.opts.BanTimeout,
			Comment: "自动封禁（IPv4）",
		})
	}
	if c.opts.BanSet6 != "" {
		t.Sets = append(t.Sets, &ir.Set{
			Name:    c.opts.BanSet6,
			KeyType: "ipv6_addr",
			Flags:   []string{"timeout"},
			Timeout: c.opts.BanTimeout,
			Comment: "自动封禁（IPv6）",
		})
	}
	// 按源地址限速所需的动态集合。
	for _, name := range c.perIPLimitSets() {
		t.Sets = append(t.Sets, &ir.Set{
			Name:    name,
			KeyType: "ipv4_addr",
			Flags:   []string{"dynamic", "timeout"},
			Timeout: time.Minute,
			Comment: "按源地址限速的动态集合",
		})
	}
}

// BanSetFor 返回某个地址所属的封禁集合名（依据地址族）。
func BanSetFor(addr string, set4, set6 string) string {
	if isV6(addr) {
		return set6
	}
	return set4
}

func (c *compiler) perIPLimitSets() []string {
	seen := map[string]bool{}
	var out []string
	add := func(r *model.Rule) {
		if r.Limit == nil || !r.Limit.PerIP || !r.IsEnabled() {
			return
		}
		name := "limit_" + sanitize(r.ID)
		if name == "limit_" {
			return
		}
		if !seen[name] {
			seen[name] = true
			out = append(out, name)
		}
	}
	for i := range c.policy.Rules {
		add(&c.policy.Rules[i])
	}
	sort.Strings(out)
	return out
}

// ---- 链 ----

func (c *compiler) buildChains(t *ir.Table) {
	prerouting := &ir.Chain{Name: "prerouting", Type: ir.ChainNAT, Hook: ir.HookPrerouting, Priority: ir.PrioDstNAT, Base: true, Comment: "DNAT 与入口封禁"}
	input := &ir.Chain{Name: "input", Type: ir.ChainFilter, Hook: ir.HookInput, Priority: ir.PrioFilter, Base: true, Policy: policyStr(c.policy.Default.Input, model.ActionDrop), Comment: "发往本机"}
	forward := &ir.Chain{Name: "forward", Type: ir.ChainFilter, Hook: ir.HookForward, Priority: ir.PrioFilter, Base: true, Policy: policyStr(c.policy.Default.Forward, model.ActionDrop), Comment: "跨网段转发"}
	output := &ir.Chain{Name: "output", Type: ir.ChainFilter, Hook: ir.HookOutput, Priority: ir.PrioFilter, Base: true, Policy: policyStr(c.policy.Default.Output, model.ActionAccept), Comment: "本机发出"}
	postrouting := &ir.Chain{Name: "postrouting", Type: ir.ChainNAT, Hook: ir.HookPostrouting, Priority: ir.PrioSrcNAT, Base: true, Comment: "SNAT / masquerade"}

	c.chains = map[string]*ir.Chain{
		"prerouting":  prerouting,
		"input":       input,
		"forward":     forward,
		"output":      output,
		"postrouting": postrouting,
	}

	// 入口封禁：在 prerouting 里尽早丢弃被封禁的源地址。
	c.addBanRules(prerouting)

	if c.opts.ConntrackFastPath {
		for _, ch := range []*ir.Chain{input, forward, output} {
			var ctr []ir.Statement
			if c.opts.Counters {
				ctr = []ir.Statement{{Kind: ir.StmtCounter}}
			}
			ch.Rules = append(ch.Rules,
				&ir.Rule{ID: ch.Name + "-ct-invalid", Matches: []ir.Match{ir.CtState("invalid")},
					Stmts:   append(append([]ir.Statement(nil), ctr...), ir.Statement{Kind: ir.StmtVerdict, Verdict: "drop"}),
					Comment: "丢弃状态异常的连接"},
				&ir.Rule{ID: ch.Name + "-ct-established", Matches: []ir.Match{ir.CtState("established", "related")},
					Stmts:   append(append([]ir.Statement(nil), ctr...), ir.Statement{Kind: ir.StmtVerdict, Verdict: "accept"}),
					Comment: "已建立连接快速通道"},
			)
		}
	}

	// 用户规则按 Priority 稳定排序。
	rules := make([]model.Rule, 0, len(c.policy.Rules))
	for _, r := range c.policy.Rules {
		if r.IsEnabled() {
			rules = append(rules, r)
		}
	}
	sort.SliceStable(rules, func(i, j int) bool { return rules[i].Priority < rules[j].Priority })

	for _, r := range rules {
		chain := c.targetChain(&r)
		if chain == nil {
			continue
		}
		compiled := c.compileRule(chain.Name, &r)
		chain.Rules = append(chain.Rules, compiled...)
	}
	t.Chains = []*ir.Chain{prerouting, input, forward, output, postrouting}
	for _, ch := range t.Chains {
		dedupe(ch)
	}
}

// dedupe 删除同一链内语义完全相同的冗余规则（保留首条）。
//
// 典型的冗余来自用户显式书写的 established 放行与编译器注入的 conntrack 快速通道。
func dedupe(ch *ir.Chain) {
	seen := make(map[string]bool, len(ch.Rules))
	out := ch.Rules[:0]
	for _, r := range ch.Rules {
		key := ir.RuleBody(r)
		if key != "" && seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, r)
	}
	ch.Rules = out
}

// targetChain 决定规则落在哪条链。
//
//	本机相关（任一侧为 local）→ input / output；其余 → forward。
func (c *compiler) targetChain(r *model.Rule) *ir.Chain {
	srcLocal := isLocal(r.SrcZone)
	dstLocal := isLocal(r.DstZone)

	switch {
	case srcLocal && dstLocal:
		// 环回流量，归入 output（本机到本机）。
		return c.chains["output"]
	case dstLocal:
		return c.chains["input"]
	case srcLocal:
		return c.chains["output"]
	default:
		return c.chains["forward"]
	}
}

// ---- NAT ----

func (c *compiler) buildNAT(t *ir.Table) {
	dnat := c.chains["prerouting"]
	natOut := c.chains["postrouting"]

	rules := make([]model.NATRule, 0, len(c.policy.NATRules))
	for _, n := range c.policy.NATRules {
		if n.IsEnabled() {
			rules = append(rules, n)
		}
	}
	sort.SliceStable(rules, func(i, j int) bool { return rules[i].Priority < rules[j].Priority })

	for i := range rules {
		n := &rules[i]
		switch n.Kind {
		case model.NATDNAT:
			if r := c.compileDNAT(n); r != nil {
				dnat.Rules = append(dnat.Rules, r)
			}
		case model.NATSNAT, model.NATMasquerade:
			if r := c.compileSNAT(n); r != nil {
				natOut.Rules = append(natOut.Rules, r)
			}
		}
	}
}

func (c *compiler) compileDNAT(n *model.NATRule) *ir.Rule {
	var matches []ir.Match
	if z := c.policy.ZoneByName(n.SrcZone); z != nil {
		if m, ok := ifaceMatch("iifname", z.Interfaces); ok {
			matches = append(matches, m)
		}
	}
	if p := n.Proto; p != "" && p != model.ProtoAny {
		matches = append(matches, ir.Match{Field: "meta l4proto", Values: []string{string(p)}})
	}
	if len(n.SrcAddr) > 0 {
		matches = append(matches, ir.Match{Field: addrField(n.SrcAddr, "saddr"), Values: n.SrcAddr})
	}
	if len(n.MatchAddr) > 0 {
		matches = append(matches, ir.Match{Field: addrField(n.MatchAddr, "daddr"), Values: n.MatchAddr})
	}
	if n.MatchPort != "" {
		matches = append(matches, ir.Match{Field: portField(n.Proto, "dport"), Values: []string{n.MatchPort}})
	}
	return &ir.Rule{
		ID:      "dnat/" + n.ID,
		Matches: matches,
		Stmts: []ir.Statement{{
			Kind: ir.StmtCounter,
		}, {
			Kind: ir.StmtNAT, NATKind: "dnat", Addr: n.ToAddr, Port: n.ToPort,
		}},
		Comment: n.Comment,
	}
}

func (c *compiler) compileSNAT(n *model.NATRule) *ir.Rule {
	var matches []ir.Match
	if z := c.policy.ZoneByName(n.OutZone); z != nil {
		if m, ok := ifaceMatch("oifname", z.Interfaces); ok {
			matches = append(matches, m)
		}
	}
	if p := n.Proto; p != "" && p != model.ProtoAny {
		matches = append(matches, ir.Match{Field: "meta l4proto", Values: []string{string(p)}})
	}
	if len(n.SrcAddr) > 0 {
		matches = append(matches, ir.Match{Field: addrField(n.SrcAddr, "saddr"), Values: n.SrcAddr})
	}
	if len(n.MatchAddr) > 0 {
		matches = append(matches, ir.Match{Field: addrField(n.MatchAddr, "daddr"), Values: n.MatchAddr})
	}

	st := ir.Statement{Kind: ir.StmtNAT}
	if n.Kind == model.NATMasquerade {
		st.NATKind = "masquerade"
	} else {
		st.NATKind = "snat"
		st.Addr = n.ToAddr
		st.Port = n.ToPort
	}
	return &ir.Rule{
		ID:      string(n.Kind) + "/" + n.ID,
		Matches: matches,
		Stmts:   []ir.Statement{{Kind: ir.StmtCounter}, st},
		Comment: n.Comment,
	}
}

func (c *compiler) addBanRules(ch *ir.Chain) {
	if c.opts.BanSet4 != "" {
		ch.Rules = append(ch.Rules, &ir.Rule{
			ID:      "ban-v4",
			Matches: []ir.Match{{Field: "ip saddr", Set: c.opts.BanSet4}},
			Stmts: []ir.Statement{
				{Kind: ir.StmtCounter},
				{Kind: ir.StmtVerdict, Verdict: "drop"},
			},
			Comment: "封禁 IPv4 源地址",
		})
	}
	if c.opts.BanSet6 != "" {
		ch.Rules = append(ch.Rules, &ir.Rule{
			ID:      "ban-v6",
			Matches: []ir.Match{{Field: "ip6 saddr", Set: c.opts.BanSet6}},
			Stmts: []ir.Statement{
				{Kind: ir.StmtCounter},
				{Kind: ir.StmtVerdict, Verdict: "drop"},
			},
			Comment: "封禁 IPv6 源地址",
		})
	}
}

func policyStr(a model.Action, def model.Action) string {
	if a == "" {
		a = def
	}
	switch a {
	case model.ActionAccept:
		return "accept"
	case model.ActionDrop, "":
		return "drop"
	case model.ActionReject:
		// nft 基础链策略只支持 accept/drop；reject 用链尾规则实现。
		return "accept"
	}
	return "drop"
}

// ---- 规则编译 ----

// compileRule 把一条 model.Rule 展开为 1~N 条 ir.Rule（按地址族拆分）。
func (c *compiler) compileRule(chainName string, r *model.Rule) []*ir.Rule {
	variants := c.splitByFamily(r)
	var out []*ir.Rule
	for i, v := range variants {
		matches := c.ruleMatches(r, v)

		id := r.ID
		if len(variants) > 1 {
			id = fmt.Sprintf("%s#%d", r.ID, i)
		}

		var stmts []ir.Statement
		if r.HasCounter() {
			stmts = append(stmts, ir.Statement{Kind: ir.StmtCounter})
		}
		if r.Limit != nil {
			if r.Limit.PerIP {
				stmts = append(stmts, ir.Statement{
					Kind: ir.StmtMeter, SetName: "limit_" + sanitize(r.ID),
					KeyField: "ip saddr", Rate: r.Limit.Rate, Per: limitUnit(r.Limit.Per), Over: true,
				})
			} else {
				stmts = append(stmts, ir.Statement{
					Kind: ir.StmtLimit, Rate: r.Limit.Rate, Per: limitUnit(r.Limit.Per), Burst: r.Limit.Burst,
				})
			}
		}
		if r.Log || r.Action == model.ActionLog {
			stmts = append(stmts, ir.Statement{Kind: ir.StmtLog, Prefix: logPrefix(c.opts.LogPrefix, r)})
		}
		if r.Action != model.ActionLog {
			stmts = append(stmts, verdict(r))
		}

		out = append(out, &ir.Rule{
			ID:      chainName + "/" + id,
			Matches: matches,
			Stmts:   stmts,
			Comment: r.Comment,
		})
	}
	return out
}

// ruleMatches 按固定顺序组装匹配条件，便于阅读与对账：
//
//	入接口 → 出接口 → 源地址 → 目的地址 → 协议 → 端口 → conntrack 状态
//
// addrs 为当前地址族变体对应的地址匹配。
func (c *compiler) ruleMatches(r *model.Rule, addrs []ir.Match) []ir.Match {
	var out []ir.Match

	if z := c.policy.ZoneByName(r.SrcZone); z != nil {
		if m, ok := ifaceMatch("iifname", z.Interfaces); ok {
			out = append(out, m)
		}
	}
	if z := c.policy.ZoneByName(r.DstZone); z != nil {
		if m, ok := ifaceMatch("oifname", z.Interfaces); ok {
			out = append(out, m)
		}
	}

	out = append(out, addrs...)

	if p := r.Proto; p != "" && p != model.ProtoAny {
		switch p {
		case model.ProtoICMP:
			out = append(out, ir.Match{Field: "meta l4proto", Values: []string{"icmp"}})
		case model.ProtoICMPv6:
			out = append(out, ir.Match{Field: "meta l4proto", Values: []string{"ipv6-icmp"}})
		default:
			out = append(out, ir.Match{Field: "meta l4proto", Values: []string{string(p)}})
		}
	}

	if len(r.SrcPort) > 0 {
		out = append(out, ir.Match{Field: portField(r.Proto, "sport"), Values: normalizePorts(r.SrcPort)})
	}
	if len(r.DstPort) > 0 {
		out = append(out, ir.Match{Field: portField(r.Proto, "dport"), Values: normalizePorts(r.DstPort)})
	}
	if len(r.State) > 0 {
		out = append(out, ir.CtState(r.State...))
	}
	return out
}

// splitByFamily 把规则中的地址按族拆分，必要时产生多条 ir.Rule 模板。
// 返回的是"每一条变体需要追加的地址匹配"。
func (c *compiler) splitByFamily(r *model.Rule) [][]ir.Match {
	v4 := []ir.Match{}
	v6 := []ir.Match{}

	addAddrs := func(field4, field6 string, addrs []string) {
		var a4, a6 []string
		for _, a := range addrs {
			if isV6(a) {
				a6 = append(a6, a)
			} else {
				a4 = append(a4, a)
			}
		}
		if len(a4) > 0 {
			v4 = append(v4, ir.Match{Field: field4, Values: a4})
		}
		if len(a6) > 0 {
			v6 = append(v6, ir.Match{Field: field6, Values: a6})
		}
	}

	// 域的网段只在"该域未绑定接口"时才作为地址匹配使用：
	// 域绑定接口时，接口已经界定了边界，再叠加网段会意外收窄匹配范围。
	zoneAddrs := func(name string) []string {
		z := c.policy.ZoneByName(name)
		if z == nil || len(z.Interfaces) > 0 {
			return nil
		}
		return z.Networks
	}

	addAddrs("ip saddr", "ip6 saddr", append(append([]string(nil), r.SrcAddr...), zoneAddrs(r.SrcZone)...))
	addAddrs("ip daddr", "ip6 daddr", append(append([]string(nil), r.DstAddr...), zoneAddrs(r.DstZone)...))

	switch {
	case len(v4) > 0 && len(v6) > 0:
		return [][]ir.Match{v4, v6}
	case len(v6) > 0:
		return [][]ir.Match{v6}
	default:
		// 无地址约束：单条规则（inet 表天然同时覆盖 v4/v6）。
		return [][]ir.Match{v4}
	}
}

func verdict(r *model.Rule) ir.Statement {
	switch r.Action {
	case model.ActionAccept:
		return ir.Statement{Kind: ir.StmtVerdict, Verdict: "accept"}
	case model.ActionReject:
		rej := string(r.Reject)
		if rej == "" && r.Proto == model.ProtoTCP {
			rej = string(model.RejectTCPReset)
		}
		return ir.Statement{Kind: ir.StmtVerdict, Verdict: "reject", Reject: rej}
	default:
		return ir.Statement{Kind: ir.StmtVerdict, Verdict: "drop"}
	}
}

func logPrefix(base string, r *model.Rule) string {
	if r.LogPrefix != "" {
		return r.LogPrefix
	}
	return base + r.ID + " "
}

func ifaceMatch(field string, ifaces []string) (ir.Match, bool) {
	var clean []string
	for _, i := range ifaces {
		i = strings.TrimSpace(i)
		if i != "" {
			clean = append(clean, i)
		}
	}
	if len(clean) == 0 {
		return ir.Match{}, false
	}
	return ir.Match{Field: field, Values: clean}, true
}

func portField(proto model.Proto, kind string) string {
	switch proto {
	case model.ProtoUDP:
		return "udp " + kind
	default:
		return "tcp " + kind
	}
}

func normalizePorts(in []string) []string {
	out := make([]string, 0, len(in))
	for _, p := range in {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func limitUnit(per string) string {
	switch strings.ToLower(per) {
	case "minute", "m":
		return "minute"
	case "hour", "h":
		return "hour"
	case "day", "d":
		return "day"
	default:
		return "second"
	}
}

func isV6(addr string) bool {
	host := addr
	if _, ipnet, err := net.ParseCIDR(addr); err == nil {
		host = ipnet.IP.String()
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.To4() == nil
}

func isLocal(zone string) bool {
	return zone == model.ZoneLocal
}

// addrField 依据地址列表的族选择 "ip saddr"/"ip6 saddr" 之类的字段。
func addrField(addrs []string, dir string) string {
	for _, a := range addrs {
		if isV6(a) {
			return "ip6 " + dir
		}
	}
	return "ip " + dir
}

func sanitize(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '_':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	return b.String()
}
