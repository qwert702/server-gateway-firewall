package compiler

import (
	"strings"
	"testing"
	"time"

	"fwdd/internal/model"
)

func samplePolicy() *model.Policy {
	return &model.Policy{
		Version: 1,
		Zones: []model.Zone{
			{Name: "wan", Interfaces: []string{"eth0"}, Trust: model.TrustUntrusted},
			{Name: "lan", Interfaces: []string{"eth1"}, Networks: []string{"10.0.0.0/8"}, Trust: model.TrustLAN},
			{Name: "dmz", Interfaces: []string{"eth2"}, Trust: model.TrustDMZ},
		},
		Rules: []model.Rule{
			{
				ID: "lan-web", Priority: 100, SrcZone: "lan", DstZone: "dmz",
				Proto: model.ProtoTCP, DstPort: []string{"80", "443"},
				State: []string{"new", "established"}, Action: model.ActionAccept,
				Comment: "LAN 访问 DMZ Web",
			},
			{
				ID: "wan-est", Priority: 10, SrcZone: "wan", DstZone: "any",
				State: []string{"established", "related"}, Action: model.ActionAccept,
			},
			{
				ID: "ssh-admin", Priority: 50, SrcZone: "lan", DstZone: model.ZoneLocal,
				Proto: model.ProtoTCP, DstPort: []string{"22"}, Action: model.ActionAccept,
				Limit: &model.RateLimit{Rate: 10, Per: "minute", Burst: 20},
			},
			{
				ID: "block-v6", Priority: 200, SrcZone: "wan", DstZone: "lan",
				SrcAddr: []string{"2001:db8::/32"}, Proto: model.ProtoTCP, DstPort: []string{"445"},
				Action: model.ActionReject, Reject: model.RejectTCPReset,
			},
			{
				ID: "disabled", Priority: 300, SrcZone: "wan", DstZone: "lan",
				Action: model.ActionDrop, Enabled: boolPtr(false),
			},
		},
		NATRules: []model.NATRule{
			{ID: "web-dnat", Kind: model.NATDNAT, Proto: model.ProtoTCP, SrcZone: "wan",
				MatchPort: "8080", ToAddr: "10.0.0.10", ToPort: "80", Comment: "对外暴露内网 Web"},
			{ID: "masq", Kind: model.NATMasquerade, OutZone: "wan"},
		},
		Default: model.DefaultPolicy{Forward: model.ActionDrop, Input: model.ActionDrop, Output: model.ActionAccept},
	}
}

func boolPtr(b bool) *bool { return &b }

func TestCompileChainsAndPolicies(t *testing.T) {
	res, err := Compile(samplePolicy(), Options{TableName: "fw", ConntrackFastPath: true, Counters: true})
	if err != nil {
		t.Fatalf("Compile 失败: %v", err)
	}
	tbl := res.Snapshot.Table("inet", "fw")
	if tbl == nil {
		t.Fatal("未生成 inet fw 表")
	}

	want := map[string]struct {
		hook   string
		policy string
	}{
		"prerouting":  {"prerouting", ""},
		"input":       {"input", "drop"},
		"forward":     {"forward", "drop"},
		"output":      {"output", "accept"},
		"postrouting": {"postrouting", ""},
	}
	if len(tbl.Chains) != len(want) {
		t.Fatalf("链数量 = %d, 期望 %d", len(tbl.Chains), len(want))
	}
	for name, exp := range want {
		ch := tbl.Chain(name)
		if ch == nil {
			t.Errorf("缺少链 %s", name)
			continue
		}
		if string(ch.Hook) != exp.hook {
			t.Errorf("链 %s hook = %q, 期望 %q", name, ch.Hook, exp.hook)
		}
		if ch.Policy != exp.policy {
			t.Errorf("链 %s policy = %q, 期望 %q", name, ch.Policy, exp.policy)
		}
		if len(ch.Rules) == 0 {
			t.Errorf("链 %s 没有任何规则", name)
		}
	}
}

func TestRulePlacement(t *testing.T) {
	res, err := Compile(samplePolicy(), Options{ConntrackFastPath: true, Counters: true})
	if err != nil {
		t.Fatalf("Compile 失败: %v", err)
	}
	tbl := res.Snapshot.Table("inet", "fw")

	cases := []struct {
		ruleID string
		chain  string
	}{
		{"lan-web", "forward"},
		{"wan-est", "forward"},
		{"ssh-admin", "input"},
		{"block-v6", "forward"},
		{"web-dnat", "prerouting"},
		{"masquerade/masq", "postrouting"},
	}
	for _, c := range cases {
		ch := tbl.Chain(c.chain)
		if ch == nil {
			t.Fatalf("缺少链 %s", c.chain)
		}
		found := false
		for _, r := range ch.Rules {
			if strings.Contains(r.ID, c.ruleID) {
				found = true
			}
		}
		if !found {
			var ids []string
			for _, r := range ch.Rules {
				ids = append(ids, r.ID)
			}
			t.Errorf("规则 %s 未出现在链 %s 中，该链含: %v", c.ruleID, c.chain, ids)
		}
	}
}

func TestDisabledRuleSkipped(t *testing.T) {
	res, err := Compile(samplePolicy(), Options{})
	if err != nil {
		t.Fatalf("Compile 失败: %v", err)
	}
	text := res.Snapshot.Render()
	if strings.Contains(text, "disabled") {
		t.Errorf("被停用的规则不应出现在输出中:\n%s", text)
	}
}

func TestIPv6Split(t *testing.T) {
	p := &model.Policy{
		Zones: []model.Zone{{Name: "wan", Interfaces: []string{"eth0"}}},
		Rules: []model.Rule{{
			ID: "mixed", SrcZone: "wan", DstZone: "any", Action: model.ActionAccept,
			SrcAddr: []string{"10.0.0.0/8", "2001:db8::/32"},
		}},
	}
	res, err := Compile(p, Options{})
	if err != nil {
		t.Fatalf("Compile 失败: %v", err)
	}
	fwd := res.Snapshot.Table("inet", "fw").Chain("forward")
	var v4, v6 int
	for _, r := range fwd.Rules {
		for _, m := range r.Matches {
			switch m.Field {
			case "ip saddr":
				v4++
			case "ip6 saddr":
				v6++
			}
		}
	}
	if v4 != 1 || v6 != 1 {
		t.Errorf("IPv4/IPv6 拆分不正确: v4=%d v6=%d\n%s", v4, v6, res.Snapshot.Render())
	}
}

func TestBanSetsDeclaredEmptyAndRulesEmitDrop(t *testing.T) {
	p := samplePolicy()
	p.Bans = []model.BanEntry{
		{IP: "203.0.113.9", Reason: "ssh 爆破", ExpiresAt: time.Now().Add(time.Hour)},
		{IP: "2001:db8::dead", Reason: "扫描", ExpiresAt: time.Now().Add(30 * time.Minute)},
	}

	res, err := Compile(p, Options{BanSet4: "banned4", BanSet6: "banned6", BanTimeout: 24 * time.Hour})
	if err != nil {
		t.Fatalf("编译失败: %v", err)
	}
	tbl := res.Snapshot.Table("inet", "fw")

	// 集合只声明、不预置元素：封禁是运行时状态，由 engine 在下发后注入。
	for _, name := range []string{"banned4", "banned6"} {
		set := tbl.Set(name)
		if set == nil {
			t.Fatalf("缺少集合 %s", name)
		}
		if len(set.Elements) != 0 {
			t.Errorf("集合 %s 不应预置元素（否则快照不可确定）: %+v", name, set.Elements)
		}
		if len(set.Flags) == 0 || set.Flags[0] != "timeout" {
			t.Errorf("集合 %s 必须具备 timeout 标志以支持内核自动解封: %+v", name, set.Flags)
		}
	}

	// 但丢弃规则必须生成，且用集合查找而非逐条规则。
	pre := tbl.Chain("prerouting")
	text := res.Snapshot.Render()
	if !strings.Contains(text, "ip saddr @banned4") || !strings.Contains(text, "ip6 saddr @banned6") {
		t.Errorf("prerouting 链缺少封禁匹配: %s", text)
	}
	for _, want := range []string{"ip saddr @banned4", "ip6 saddr @banned6"} {
		found := false
		for _, r := range pre.Rules {
			for _, m := range r.Matches {
				if m.Field+" @"+m.Set == want {
					found = true
				}
			}
		}
		if !found {
			t.Errorf("prerouting 链缺少 %q 的匹配", want)
		}
	}
}

// 快照必须与"当前有多少封禁、剩余多久"无关，否则哈希每秒都在变，
// 对账会永远判定为不同步。
func TestSnapshotIsDeterministicRegardlessOfBans(t *testing.T) {
	a := samplePolicy()
	a.Bans = []model.BanEntry{{IP: "203.0.113.9", ExpiresAt: time.Now().Add(time.Hour)}}

	b := samplePolicy()
	b.Bans = []model.BanEntry{
		{IP: "203.0.113.9", ExpiresAt: time.Now().Add(59 * time.Minute)},
		{IP: "198.51.100.1", ExpiresAt: time.Now().Add(10 * time.Minute)},
	}

	opts := Options{BanSet4: "banned4", BanSet6: "banned6", BanTimeout: 24 * time.Hour}
	ra, err := Compile(a, opts)
	if err != nil {
		t.Fatal(err)
	}
	rb, err := Compile(b, opts)
	if err != nil {
		t.Fatal(err)
	}
	if ra.Snapshot.Render() != rb.Snapshot.Render() {
		t.Error("封禁状态不得影响编译产物，否则对账哈希会不停抖动")
	}
}

func TestBanSetForPicksFamily(t *testing.T) {
	if got := BanSetFor("203.0.113.9", "banned4", "banned6"); got != "banned4" {
		t.Errorf("IPv4 应映射到 banned4，实际 %s", got)
	}
	if got := BanSetFor("2001:db8::1", "banned4", "banned6"); got != "banned6" {
		t.Errorf("IPv6 应映射到 banned6，实际 %s", got)
	}
}

func TestValidationBlocksCompile(t *testing.T) {
	p := &model.Policy{
		Rules: []model.Rule{{ID: "bad", SrcZone: "ghost", DstZone: "lan", Action: model.ActionAccept}},
	}
	_, err := Compile(p, Options{})
	if err == nil {
		t.Fatal("悬空域引用应导致编译失败")
	}
	var ve *ValidationError
	if !asValidationError(err, &ve) {
		t.Fatalf("错误类型应为 *ValidationError, 实际 %T", err)
	}
	if !strings.Contains(err.Error(), "ghost") {
		t.Errorf("错误信息应包含问题域: %v", err)
	}
}

func asValidationError(err error, target **ValidationError) bool {
	if ve, ok := err.(*ValidationError); ok {
		*target = ve
		return true
	}
	return false
}

func TestRenderGolden(t *testing.T) {
	got, err := Compile(samplePolicy(), Options{TableName: "fw", ConntrackFastPath: true, Counters: true})
	if err != nil {
		t.Fatalf("Compile 失败: %v", err)
	}
	text := got.Snapshot.Render()

	mustContain := []string{
		"table inet fw {",
		"chain forward {",
		"type filter hook forward priority 0; policy drop;",
		`iifname "eth1" oifname "eth2" meta l4proto tcp tcp dport { 80, 443 } ct state { new, established } counter accept`,
		`iifname "eth1" meta l4proto tcp tcp dport 22 counter limit rate 10/minute burst 20 packets accept`,
		"reject with tcp reset",
		"masquerade",
		"dnat ip to 10.0.0.10:80",
		"chain postrouting {",
		"type nat hook postrouting priority 100; policy accept;",
	}
	for _, m := range mustContain {
		if !strings.Contains(text, m) {
			t.Errorf("渲染结果缺少 %q\n--- 完整输出 ---\n%s", m, text)
		}
	}
}

func TestIdempotentRender(t *testing.T) {
	a, err := Compile(samplePolicy(), Options{ConntrackFastPath: true})
	if err != nil {
		t.Fatal(err)
	}
	b, err := Compile(samplePolicy(), Options{ConntrackFastPath: true})
	if err != nil {
		t.Fatal(err)
	}
	if a.Snapshot.Render() != b.Snapshot.Render() {
		t.Error("相同输入两次编译结果不一致（非幂等）")
	}
}

func TestRenderIPv6DNATBrackets(t *testing.T) {
	p := &model.Policy{
		Zones:    []model.Zone{{Name: "wan", Interfaces: []string{"eth0"}}},
		NATRules: []model.NATRule{{ID: "v6", Kind: model.NATDNAT, Proto: model.ProtoTCP, SrcZone: "wan", MatchPort: "8443", ToAddr: "2001:db8:20::10", ToPort: "443"}},
	}
	res, err := Compile(p, Options{})
	if err != nil {
		t.Fatal(err)
	}
	text := res.Snapshot.Render()
	if !strings.Contains(text, "dnat ip6 to [2001:db8:20::10]:443") {
		t.Errorf("IPv6 DNAT 目标必须用方括号包裹:\n%s", text)
	}
}

func TestRenderPerIPLimitUsesDynamicSet(t *testing.T) {
	p := &model.Policy{
		Zones: []model.Zone{{Name: "wan", Interfaces: []string{"eth0"}}},
		Rules: []model.Rule{{
			ID: "perip", SrcZone: "wan", DstZone: model.ZoneAny, Proto: model.ProtoTCP,
			DstPort: []string{"443"}, State: []string{"new"}, Action: model.ActionDrop,
			Limit: &model.RateLimit{Rate: 20, Per: "second", PerIP: true},
		}},
	}
	res, err := Compile(p, Options{})
	if err != nil {
		t.Fatal(err)
	}
	tbl := res.Snapshot.Table("inet", "fw")
	set := tbl.Set("limit_perip")
	if set == nil {
		t.Fatalf("按源地址限速应生成动态集合:\n%s", res.Snapshot.Render())
	}
	hasDynamic := false
	for _, f := range set.Flags {
		if f == "dynamic" {
			hasDynamic = true
		}
	}
	if !hasDynamic {
		t.Errorf("动态集合必须具备 dynamic 标志: %+v", set.Flags)
	}
	text := res.Snapshot.Render()
	if !strings.Contains(text, "add @limit_perip { ip saddr limit rate over 20/second } drop") {
		t.Errorf("按源地址限速应渲染为 meter 语句:\n%s", text)
	}
}

func TestZoneNetworksOnlyUsedWhenNoInterfaces(t *testing.T) {
	p := &model.Policy{
		Zones: []model.Zone{
			{Name: "lan", Interfaces: []string{"eth1"}, Networks: []string{"10.0.0.0/8"}},
			{Name: "guest", Networks: []string{"192.168.99.0/24"}},
		},
		Rules: []model.Rule{
			{ID: "via-iface", SrcZone: "lan", DstZone: model.ZoneAny, Action: model.ActionAccept},
			{ID: "via-net", SrcZone: "guest", DstZone: model.ZoneAny, Action: model.ActionAccept},
		},
	}
	res, err := Compile(p, Options{})
	if err != nil {
		t.Fatal(err)
	}
	fwd := res.Snapshot.Table("inet", "fw").Chain("forward")
	for _, r := range fwd.Rules {
		txt := r.Comment
		hasNet := false
		for _, m := range r.Matches {
			if m.Field == "ip saddr" {
				hasNet = true
			}
		}
		switch txt {
		case "via-iface":
			if hasNet {
				t.Errorf("绑定接口的域不应再叠加网段匹配: %+v", r.Matches)
			}
		case "via-net":
			if !hasNet {
				t.Errorf("仅绑定网段的域应使用网段匹配: %+v", r.Matches)
			}
		}
	}
}

func TestDuplicateRulesDeduped(t *testing.T) {
	p := &model.Policy{
		Zones: []model.Zone{{Name: "wan", Interfaces: []string{"eth0"}}},
		Rules: []model.Rule{
			{ID: "a", SrcZone: "wan", DstZone: model.ZoneAny, State: []string{"established", "related"}, Action: model.ActionAccept},
			{ID: "b", SrcZone: "wan", DstZone: model.ZoneAny, State: []string{"established", "related"}, Action: model.ActionAccept},
		},
	}
	res, err := Compile(p, Options{ConntrackFastPath: false, Counters: true})
	if err != nil {
		t.Fatal(err)
	}
	fwd := res.Snapshot.Table("inet", "fw").Chain("forward")
	if len(fwd.Rules) != 1 {
		t.Errorf("语义相同的规则应被去重，实际保留 %d 条", len(fwd.Rules))
	}
}

// 并发连接数限制（ct count）与速率限制是两道独立的防线：
// 速率拦"连接建得太快"，并发拦"建得太多且不释放"。慢速攻击每秒只建几个
// 连接，速率限制完全看不出来，但并发数会一路涨上去。
func TestConnLimitEmitsCtCount(t *testing.T) {
	p := &model.Policy{
		Zones: []model.Zone{{Name: "wan", Interfaces: []string{"eth0"}}},
		Rules: []model.Rule{{
			ID: "slowloris", SrcZone: "wan", DstZone: model.ZoneLocal,
			Proto: model.ProtoTCP, DstPort: []string{"443"}, State: []string{"new"},
			Action: model.ActionDrop,
			Limit:  &model.RateLimit{MaxConcurrent: 30},
		}},
	}
	res, err := Compile(p, Options{})
	if err != nil {
		t.Fatal(err)
	}
	tbl := res.Snapshot.Table("inet", "fw")

	set := tbl.Set("ctlimit_slowloris")
	if set == nil {
		t.Fatalf("应生成并发限制的动态集合:\n%s", res.Snapshot.Render())
	}
	hasDynamic := false
	for _, f := range set.Flags {
		if f == "dynamic" {
			hasDynamic = true
		}
	}
	if !hasDynamic {
		t.Errorf("并发限制集合必须是 dynamic: %+v", set.Flags)
	}

	text := res.Snapshot.Render()
	want := "add @ctlimit_slowloris { ip saddr ct count over 30 }"
	if !strings.Contains(text, want) {
		t.Errorf("缺少 ct count 语句，期望包含 %q:\n%s", want, text)
	}
}

// 只配并发限制、不配速率时不应凭空生成限速语句。
func TestConnLimitWithoutRate(t *testing.T) {
	p := &model.Policy{
		Zones: []model.Zone{{Name: "wan", Interfaces: []string{"eth0"}}},
		Rules: []model.Rule{{
			ID: "cl", SrcZone: "wan", DstZone: model.ZoneAny, Proto: model.ProtoTCP,
			DstPort: []string{"80"}, Action: model.ActionDrop,
			Limit: &model.RateLimit{MaxConcurrent: 10},
		}},
	}
	res, err := Compile(p, Options{})
	if err != nil {
		t.Fatal(err)
	}
	text := res.Snapshot.Render()
	if strings.Contains(text, "limit rate") {
		t.Errorf("未配置 rate 时不应生成限速语句:\n%s", text)
	}
	if !strings.Contains(text, "ct count over 10") {
		t.Errorf("应生成 ct count:\n%s", text)
	}
}

// 两者同时配置时必须都出现，且各自用各自的集合。
func TestRateAndConnLimitTogether(t *testing.T) {
	p := &model.Policy{
		Zones: []model.Zone{{Name: "wan", Interfaces: []string{"eth0"}}},
		Rules: []model.Rule{{
			ID: "both", SrcZone: "wan", DstZone: model.ZoneAny, Proto: model.ProtoTCP,
			DstPort: []string{"80"}, Action: model.ActionDrop,
			Limit: &model.RateLimit{Rate: 20, Per: "second", PerIP: true, MaxConcurrent: 50},
		}},
	}
	res, err := Compile(p, Options{})
	if err != nil {
		t.Fatal(err)
	}
	tbl := res.Snapshot.Table("inet", "fw")
	if tbl.Set("limit_both") == nil {
		t.Error("缺少限速集合")
	}
	if tbl.Set("ctlimit_both") == nil {
		t.Error("缺少并发限制集合（两类限制不能共用一个集合）")
	}
	text := res.Snapshot.Render()
	if !strings.Contains(text, "limit rate over 20/second") {
		t.Errorf("缺少限速语句:\n%s", text)
	}
	if !strings.Contains(text, "ct count over 50") {
		t.Errorf("缺少并发限制语句:\n%s", text)
	}
}

// 并发连接数对 ICMP 没有意义，应在编译前就被拦下。
func TestConnLimitRejectsNonTCP(t *testing.T) {
	p := &model.Policy{
		Zones: []model.Zone{{Name: "wan", Interfaces: []string{"eth0"}}},
		Rules: []model.Rule{{
			ID: "bad", SrcZone: "wan", DstZone: model.ZoneAny, Proto: model.ProtoICMP,
			Action: model.ActionDrop, Limit: &model.RateLimit{MaxConcurrent: 5},
		}},
	}
	_, err := Compile(p, Options{})
	if err == nil {
		t.Fatal("对 ICMP 配置并发连接数限制应被拒绝")
	}
	if !strings.Contains(err.Error(), "max_concurrent") {
		t.Errorf("错误信息应点明是哪一项: %v", err)
	}
}

// 一个既没有 rate 也没有 max_concurrent 的 limit 等于没有限速，应被拒绝。
func TestEmptyLimitRejected(t *testing.T) {
	p := &model.Policy{
		Zones: []model.Zone{{Name: "wan", Interfaces: []string{"eth0"}}},
		Rules: []model.Rule{{
			ID: "empty", SrcZone: "wan", DstZone: model.ZoneAny, Proto: model.ProtoTCP,
			Action: model.ActionDrop, Limit: &model.RateLimit{},
		}},
	}
	if _, err := Compile(p, Options{}); err == nil {
		t.Fatal("空 limit 应被拒绝，否则是静默失效")
	}
}

// 停用的规则不应产生任何集合，否则会留下永远不会被引用的空集合。
func TestDisabledRuleProducesNoLimitSets(t *testing.T) {
	off := false
	p := &model.Policy{
		Zones: []model.Zone{{Name: "wan", Interfaces: []string{"eth0"}}},
		Rules: []model.Rule{{
			ID: "off", SrcZone: "wan", DstZone: model.ZoneAny, Proto: model.ProtoTCP,
			Action: model.ActionDrop, Enabled: &off,
			Limit: &model.RateLimit{MaxConcurrent: 10, Rate: 5, PerIP: true},
		}},
	}
	res, err := Compile(p, Options{})
	if err != nil {
		t.Fatal(err)
	}
	tbl := res.Snapshot.Table("inet", "fw")
	if tbl.Set("ctlimit_off") != nil || tbl.Set("limit_off") != nil {
		t.Error("停用的规则不应生成限速集合")
	}
}

// ---- 按地址族拆分必须是「交集」 ----
//
// 这是一条真实的安全 bug 的回归测试：早期实现把规则的约束按族拆成了
// "源约束一条、目的约束一条"，两边的条件各自孤立，范围被放大。
// 例如 "源 10.0.0.0/8 且 目的 2001:db8::/32" 会变成
// "丢弃所有来自 10/8 的流量" 加 "丢弃所有去往 2001:db8::/32 的流量"。
func TestCrossFamilyRuleIsUnsatisfiable(t *testing.T) {
	p := &model.Policy{
		Zones: []model.Zone{{Name: "wan", Interfaces: []string{"eth0"}}},
		Rules: []model.Rule{{
			ID: "cross", SrcZone: "wan", DstZone: model.ZoneAny,
			SrcAddr: []string{"10.0.0.0/8"},
			DstAddr: []string{"2001:db8::/32"},
			Action:  model.ActionDrop,
		}},
		Default: model.DefaultPolicy{Forward: model.ActionDrop},
	}
	res, err := Compile(p, Options{})
	if err != nil {
		t.Fatal(err)
	}
	fwd := res.Snapshot.Table("inet", "fw").Chain("forward")
	for _, r := range fwd.Rules {
		if strings.Contains(r.ID, "cross") {
			t.Fatalf("不可满足的规则不应生成任何 nft 规则，否则范围会被放大:\n%s",
				res.Snapshot.Render())
		}
	}
	// 但要明确告诉用户它被跳过了，而不是静默丢弃。
	found := false
	for _, w := range res.Warnings {
		if strings.Contains(w.Message, "地址族") {
			found = true
		}
	}
	if !found {
		t.Errorf("跳过的规则必须给出提示，实际 warnings=%+v", res.Warnings)
	}
}

// 同一维内同时给出 v4 与 v6 是正常的（"这些网段中的任意一个"），
// 拆成两条规则语义等价。
func TestSameDimensionMixedFamiliesStillSplits(t *testing.T) {
	p := &model.Policy{
		Zones: []model.Zone{{Name: "wan", Interfaces: []string{"eth0"}}},
		Rules: []model.Rule{{
			ID: "src", SrcZone: "wan", DstZone: model.ZoneAny,
			SrcAddr: []string{"10.0.0.0/8", "2001:db8::/32"},
			Action:  model.ActionDrop,
		}},
		Default: model.DefaultPolicy{Forward: model.ActionDrop},
	}
	res, err := Compile(p, Options{})
	if err != nil {
		t.Fatal(err)
	}
	fwd := res.Snapshot.Table("inet", "fw").Chain("forward")
	var n int
	for _, r := range fwd.Rules {
		if strings.Contains(r.ID, "src") {
			n++
		}
	}
	if n != 2 {
		t.Errorf("同一维的混合地址族应拆成 2 条，实际 %d:\n%s", n, res.Snapshot.Render())
	}
}

// 源与目的都是 v4（或都是 v6）时，拆分后必须仍然同时保留两边的约束。
func TestSameFamilyKeepsBothConstraints(t *testing.T) {
	p := &model.Policy{
		Zones: []model.Zone{{Name: "wan", Interfaces: []string{"eth0"}}},
		Rules: []model.Rule{{
			ID: "both", SrcZone: "wan", DstZone: model.ZoneAny,
			SrcAddr: []string{"10.0.0.0/8"},
			DstAddr: []string{"192.168.20.0/24"},
			Action:  model.ActionDrop,
		}},
		Default: model.DefaultPolicy{Forward: model.ActionDrop},
	}
	res, err := Compile(p, Options{})
	if err != nil {
		t.Fatal(err)
	}
	text := res.Snapshot.Render()
	if !strings.Contains(text, "ip saddr 10.0.0.0/8 ip daddr 192.168.20.0/24") {
		t.Errorf("源与目的约束都应保留在同一条规则里:\n%s", text)
	}
}

// ---- 以下三条是 2026-10-17 在真实 nft 1.0.4（Alibaba Cloud Linux 3 / kernel 5.10）
// 上用 `nft -c -f` 校验后钉死的。都是靠读文档推不出来、只有真机能发现的东西。----

// inet 表里的 NAT 必须显式带地址族限定词，否则 nft 报
// "ip or ip6 must be specified with address for inet tables" 并拒绝**整个**规则集。
func TestNATCarriesAddressFamilyKeyword(t *testing.T) {
	p := &model.Policy{
		Zones: []model.Zone{{Name: "wan", Interfaces: []string{"eth0"}}},
		NATRules: []model.NATRule{
			{ID: "v4", Kind: model.NATDNAT, Proto: model.ProtoTCP, SrcZone: "wan",
				MatchPort: "8080", ToAddr: "192.168.20.10", ToPort: "80"},
			{ID: "v6", Kind: model.NATDNAT, Proto: model.ProtoTCP, SrcZone: "wan",
				MatchPort: "8443", ToAddr: "2001:db8::10", ToPort: "443"},
			{ID: "s4", Kind: model.NATSNAT, Proto: model.ProtoTCP, OutZone: "wan", ToAddr: "203.0.113.1"},
			{ID: "s6", Kind: model.NATSNAT, Proto: model.ProtoTCP, OutZone: "wan", ToAddr: "2001:db8::1"},
		},
	}
	res, err := Compile(p, Options{})
	if err != nil {
		t.Fatal(err)
	}
	text := res.Snapshot.Render()

	for _, want := range []string{
		"dnat ip to 192.168.20.10:80",
		"dnat ip6 to [2001:db8::10]:443",
		"snat ip to 203.0.113.1",
		"snat ip6 to [2001:db8::1]",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("缺少 %q —— inet 表里不带地址族限定词的 NAT 会让整个规则集被 nft 拒绝:\n%s", want, text)
		}
	}
	// 绝不能出现没有族限定词的裸形式
	for _, bad := range []string{"dnat to ", "snat to "} {
		if strings.Contains(text, bad) {
			t.Errorf("出现了不带地址族限定词的 %q:\n%s", bad, text)
		}
	}
}

// 并发限制的集合**不能**带 timeout 标志。
//
// `flags dynamic,timeout` + `ct count over N` 会被内核以 EOPNOTSUPP
// ("Operation not supported") 拒绝，连带整个规则集加载失败。
// nft(8) 手册给的标准写法是 `flags dynamic;`（无 timeout）。
// 限速（limit rate over）则相反，带上 timeout 是合法的。
func TestConnLimitSetHasNoTimeoutFlag(t *testing.T) {
	p := &model.Policy{
		Zones: []model.Zone{{Name: "wan", Interfaces: []string{"eth0"}}},
		Rules: []model.Rule{
			{ID: "cl", SrcZone: "wan", DstZone: model.ZoneAny, Proto: model.ProtoTCP,
				DstPort: []string{"443"}, Action: model.ActionDrop,
				Limit: &model.RateLimit{MaxConcurrent: 32}},
			{ID: "rl", SrcZone: "wan", DstZone: model.ZoneAny, Proto: model.ProtoTCP,
				DstPort: []string{"80"}, Action: model.ActionDrop,
				Limit: &model.RateLimit{Rate: 10, Per: "second", PerIP: true}},
		},
	}
	res, err := Compile(p, Options{})
	if err != nil {
		t.Fatal(err)
	}
	tbl := res.Snapshot.Table("inet", "fw")

	cl := tbl.Set("ctlimit_cl")
	if cl == nil {
		t.Fatal("缺少并发限制集合")
	}
	for _, f := range cl.Flags {
		if f == "timeout" {
			t.Errorf("并发限制集合不能带 timeout 标志，否则内核会拒绝整个规则集: %+v", cl.Flags)
		}
	}
	if cl.Timeout != 0 {
		t.Errorf("并发限制集合不应设 timeout 值: %s", cl.Timeout)
	}

	rl := tbl.Set("limit_rl")
	if rl == nil {
		t.Fatal("缺少限速集合")
	}
	hasTimeout := false
	for _, f := range rl.Flags {
		if f == "timeout" {
			hasTimeout = true
		}
	}
	if !hasTimeout {
		t.Errorf("限速集合应当带 timeout 以自动清理过期条目: %+v", rl.Flags)
	}

	// 渲染结果里，ctlimit 集合的 flags 行只能是 dynamic
	text := res.Snapshot.Render()
	start := strings.Index(text, "set ctlimit_cl {")
	if start < 0 {
		t.Fatalf("渲染结果里找不到 ctlimit_cl 集合:\n%s", text)
	}
	seg := text[start:]
	if i := strings.Index(seg, "}"); i > 0 {
		seg = seg[:i]
	}
	for _, line := range strings.Split(seg, "\n") {
		// 只看 flags 行，注释里出现的 "timeout" 字样不算
		if strings.Contains(line, "flags") && strings.Contains(line, "timeout") {
			t.Errorf("ctlimit 集合的 flags 里出现了 timeout:\n%s", line)
		}
	}
}
