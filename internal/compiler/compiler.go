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

	// Groups 是已加载的地址组内容，按名称索引。规则引用未加载的组时
	// 该规则的地址匹配会缺失，因此 engine 会在编译前确保引用的组都已加载。
	Groups map[string]GroupData
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
	// 编译过程中产生的提示（例如规则因地址族互斥被跳过）与校验阶段的一起返回。
	warns = append(warns, c.warnings...)
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
	policy   *model.Policy
	opts     Options
	chains   map[string]*ir.Chain
	warnings []model.Problem
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
	// 按源地址限速 / 限制并发连接数所需的动态集合。
	//
	// 两类各用一个集合：限速靠令牌桶（limit rate over），并发数靠 ct count，
	// 是两种不同的内核机制，塞进同一个集合语义会打架。
	type dynSet struct {
		name    string
		timeout time.Duration
		comment string
	}
	var sets []dynSet
	for _, name := range c.perIPLimitSets() {
		sets = append(sets, dynSet{name, time.Minute, "按源地址限速的动态集合"})
	}
	for _, name := range c.connLimitSets() {
		sets = append(sets, dynSet{name, 10 * time.Minute, "按源地址限制并发连接数的动态集合"})
	}
	for _, s := range sets {
		t.Sets = append(t.Sets, &ir.Set{
			Name:    s.name,
			KeyType: "ipv4_addr",
			Flags:   []string{"dynamic", "timeout"},
			Timeout: s.timeout,
			Comment: s.comment,
		})
	}

	// 地址组：只用区间集合承载，条目数可以到几万条。
	//
	// 必须用 interval 标志：IP 前缀在数值上是一段区间，不开 interval 时
	// 内核只能做精确匹配，10.0.0.0/8 就只能匹配到 10.0.0.0 这一个地址。
	for _, name := range c.referencedGroups() {
		g := c.opts.Groups[name]
		safe := sanitize(name)
		if len(g.V4) > 0 {
			t.Sets = append(t.Sets, &ir.Set{
				Name:     groupSetPrefix + safe + "4",
				KeyType:  "ipv4_addr",
				Flags:    []string{"interval"},
				Elements: toElements(g.V4),
				Comment:  "地址组 " + name + "（IPv4）",
			})
		}
		if len(g.V6) > 0 {
			t.Sets = append(t.Sets, &ir.Set{
				Name:     groupSetPrefix + safe + "6",
				KeyType:  "ipv6_addr",
				Flags:    []string{"interval"},
				Elements: toElements(g.V6),
				Comment:  "地址组 " + name + "（IPv6）",
			})
		}
	}
}

func toElements(cidrs []string) []ir.Element {
	out := make([]ir.Element, 0, len(cidrs))
	for _, c := range cidrs {
		out = append(out, ir.Element{Key: c})
	}
	return out
}

// referencedGroups 返回被启用的规则引用到的地址组名（已排序，保证输出稳定）。
func (c *compiler) referencedGroups() []string {
	seen := map[string]bool{}
	for _, r := range c.policy.Rules {
		if !r.IsEnabled() {
			continue
		}
		for _, name := range []string{r.SrcGroup, r.DstGroup} {
			if name == "" {
				continue
			}
			// 未加载的组不声明集合：宁可少一个空集合，也不要生成一条
			// 引用了不存在集合的规则（那会让整个规则集被内核拒绝）。
			if _, ok := c.opts.Groups[name]; ok {
				seen[name] = true
			}
		}
	}
	out := make([]string, 0, len(seen))
	for name := range seen {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// BanSetFor 返回某个地址所属的封禁集合名（依据地址族）。
func BanSetFor(addr string, set4, set6 string) string {
	if isV6(addr) {
		return set6
	}
	return set4
}

// 限速与并发限制的集合名前缀。
const (
	rateLimitPrefix = "limit_"
	connLimitPrefix = "ctlimit_"
	groupSetPrefix  = "grp_"
)

// GroupData 是一个已加载地址组的内容（按地址族分开）。
//
// 编译器只认这个简单结构，不关心地址是从文件还是从 MMDB 来的 ——
// 加载与解析是 internal/addrgroup 的事。
type GroupData struct {
	V4 []string `json:"v4,omitempty"`
	V6 []string `json:"v6,omitempty"`
}

// perIPLimitSets 返回需要按源地址限速的规则所对应的集合名。
func (c *compiler) perIPLimitSets() []string {
	return c.limitSets(func(r *model.Rule) bool {
		return r.Limit != nil && r.Limit.PerIP && r.Limit.Rate > 0
	}, rateLimitPrefix)
}

// connLimitSets 返回需要按源地址限制并发连接数的规则所对应的集合名。
func (c *compiler) connLimitSets() []string {
	return c.limitSets(func(r *model.Rule) bool {
		return r.Limit != nil && r.Limit.MaxConcurrent > 0
	}, connLimitPrefix)
}

func (c *compiler) limitSets(want func(*model.Rule) bool, prefix string) []string {
	seen := map[string]bool{}
	var out []string
	for i := range c.policy.Rules {
		r := &c.policy.Rules[i]
		if !r.IsEnabled() || !want(r) {
			continue
		}
		name := prefix + sanitize(r.ID)
		if name == prefix || seen[name] {
			continue
		}
		seen[name] = true
		out = append(out, name)
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
		// 限速与并发限制是两道独立的防线，可以同时配。
		//
		// 顺序：先按速率、再按并发数。两者都只是往动态集合里记一笔，
		// 真正决定去向的是后面那条裁决语句。
		if r.Limit != nil {
			if r.Limit.PerIP && r.Limit.Rate > 0 {
				stmts = append(stmts, ir.Statement{
					Kind: ir.StmtMeter, SetName: rateLimitPrefix + sanitize(r.ID),
					KeyField: "ip saddr", Rate: r.Limit.Rate, Per: limitUnit(r.Limit.Per), Over: true,
				})
			} else if r.Limit.Rate > 0 {
				stmts = append(stmts, ir.Statement{
					Kind: ir.StmtLimit, Rate: r.Limit.Rate, Per: limitUnit(r.Limit.Per), Burst: r.Limit.Burst,
				})
			}
			if r.Limit.MaxConcurrent > 0 {
				stmts = append(stmts, ir.Statement{
					Kind: ir.StmtConnLimit, SetName: connLimitPrefix + sanitize(r.ID),
					KeyField: "ip saddr", MaxConcurrent: r.Limit.MaxConcurrent,
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
// 地址族位掩码。0 表示"该维没有任何约束"（等价于两族都允许）。
const (
	fam4 = 1 << iota
	fam6
	famBoth = fam4 | fam6
)

// splitByFamily 把规则按地址族展开为若干条同义规则。
//
// 关键：这里做的是**交集**而不是并集。
//
// 一条规则里的所有匹配条件在语义上是「与」。如果把它按族拆成
// "源约束一条、目的约束一条"，两边的条件就各自孤立了，范围被放大 ——
// 例如 "源 10.0.0.0/8 且 目的 2001:db8::/32" 会变成
// "丢弃所有来自 10/8 的流量" 加 "丢弃所有去往 2001:db8::/32 的流量"，
// 这比原意宽得多；若动作是 accept，就是过度放行。
//
// 因此先算出每一维允许的族，取交集；交集为空说明该规则不可满足
// （没有任何包能同时是 IPv4 和 IPv6），此时不生成规则并给出提示。
func (c *compiler) splitByFamily(r *model.Rule) [][]ir.Match {
	// 域的网段只在"该域未绑定接口"时才作为地址匹配使用：
	// 域绑定接口时，接口已经界定了边界，再叠加网段会意外收窄匹配范围。
	zoneAddrs := func(name string) []string {
		z := c.policy.ZoneByName(name)
		if z == nil || len(z.Interfaces) > 0 {
			return nil
		}
		return z.Networks
	}
	splitAddrs := func(addrs []string) (a4, a6 []string) {
		for _, a := range addrs {
			if isV6(a) {
				a6 = append(a6, a)
			} else {
				a4 = append(a4, a)
			}
		}
		return a4, a6
	}

	src4, src6 := splitAddrs(append(append([]string(nil), r.SrcAddr...), zoneAddrs(r.SrcZone)...))
	dst4, dst6 := splitAddrs(append(append([]string(nil), r.DstAddr...), zoneAddrs(r.DstZone)...))

	srcAllows := famFromPresence(len(src4) > 0, len(src6) > 0)
	dstAllows := famFromPresence(len(dst4) > 0, len(dst6) > 0)

	// 地址组也参与族的判定：一个只有 IPv4 段的组，等于把规则限定在 IPv4。
	srcG4, srcG6 := c.groupSetNames(r.SrcGroup)
	dstG4, dstG6 := c.groupSetNames(r.DstGroup)
	srcAllows = addFam(srcAllows, srcG4 != "", srcG6 != "")
	dstAllows = addFam(dstAllows, dstG4 != "", dstG6 != "")

	valid := srcAllows & dstAllows
	if valid == 0 {
		// 两维限定了互斥的地址族，规则不可满足。
		id := r.ID
		if id == "" {
			id = "(匿名)"
		}
		c.warn("rules["+id+"]",
			"源与目的分别限定了不同的地址族（如 IPv4 源 + IPv6 目的），没有任何包能满足，已跳过该规则")
		return nil
	}

	var out [][]ir.Match
	for _, f := range []struct {
		bit int
		v4  bool
	}{
		{fam4, true},
		{fam6, false},
	} {
		if valid&f.bit == 0 {
			continue
		}
		var m []ir.Match
		if f.v4 {
			if len(src4) > 0 {
				m = append(m, ir.Match{Field: "ip saddr", Values: src4})
			}
			if srcG4 != "" {
				m = append(m, ir.Match{Field: "ip saddr", Set: srcG4})
			}
			if len(dst4) > 0 {
				m = append(m, ir.Match{Field: "ip daddr", Values: dst4})
			}
			if dstG4 != "" {
				m = append(m, ir.Match{Field: "ip daddr", Set: dstG4})
			}
		} else {
			if len(src6) > 0 {
				m = append(m, ir.Match{Field: "ip6 saddr", Values: src6})
			}
			if srcG6 != "" {
				m = append(m, ir.Match{Field: "ip6 saddr", Set: srcG6})
			}
			if len(dst6) > 0 {
				m = append(m, ir.Match{Field: "ip6 daddr", Values: dst6})
			}
			if dstG6 != "" {
				m = append(m, ir.Match{Field: "ip6 daddr", Set: dstG6})
			}
		}
		out = append(out, m)
	}
	return out
}

// addFam 把"某个族有组约束"并入已有的族掩码。
//
// 注意与 famFromPresence 的区别：这里是在已有限制上**追加**，而不是从零推导，
// 所以没有组约束时保持原值不变。
func addFam(mask int, has4, has6 bool) int {
	if has4 {
		mask |= fam4
	}
	if has6 {
		mask |= fam6
	}
	return mask
}

// famFromPresence 依据"该维是否对某个族有约束"返回允许的族。
// 完全没有约束时返回 famBoth —— 不限制就是两族都不限制。
func famFromPresence(has4, has6 bool) int {
	switch {
	case has4 && has6:
		return famBoth
	case has4:
		return fam4
	case has6:
		return fam6
	default:
		return famBoth
	}
}

// groupSetNames 返回地址组在 v4/v6 两个族上对应的集合名；该族没有地址时返回空串。
func (c *compiler) groupSetNames(name string) (set4, set6 string) {
	if name == "" {
		return "", ""
	}
	g, ok := c.opts.Groups[name]
	if !ok {
		return "", ""
	}
	safe := sanitize(name)
	if len(g.V4) > 0 {
		set4 = groupSetPrefix + safe + "4"
	}
	if len(g.V6) > 0 {
		set6 = groupSetPrefix + safe + "6"
	}
	return set4, set6
}

// warn 记录一条编译期的非阻断提示。
func (c *compiler) warn(where, msg string) {
	c.warnings = append(c.warnings, model.Problem{Level: "warning", Where: where, Message: msg})
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
