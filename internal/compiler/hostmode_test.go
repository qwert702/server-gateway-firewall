package compiler

import (
	"strings"
	"testing"

	"fwdd/internal/model"
)

func hostPolicy() *model.Policy {
	return &model.Policy{
		Rules: []model.Rule{
			{ID: "ssh", Priority: 100, SrcZone: model.ZoneAny, DstZone: model.ZoneLocal,
				Proto: model.ProtoTCP, DstPort: []string{"22"}, State: []string{"new"},
				Action: model.ActionAccept},
			{ID: "web", Priority: 110, SrcZone: model.ZoneAny, DstZone: model.ZoneLocal,
				Proto: model.ProtoTCP, DstPort: []string{"80", "443"}, State: []string{"new"},
				Action: model.ActionAccept},
		},
		Default: model.DefaultPolicy{Input: model.ActionDrop, Output: model.ActionAccept},
	}
}

// 主机模式只注册 input / output 两条链。
//
// 这是主机模式存在的根本理由：fwdd 的链优先级是 filter(0)，与 Docker、
// firewalld 的链同钩子同优先级，而 nft 里这种情形的求值顺序**未定义**。
// 注册一条 forward 链挂 policy drop，容器网络会不会被打断就是看运气的。
func TestHostModeEmitsNoForwardOrNATChains(t *testing.T) {
	res, err := Compile(hostPolicy(), Options{HostMode: true, ConntrackFastPath: true, Counters: true})
	if err != nil {
		t.Fatal(err)
	}
	tbl := res.Snapshot.Table("inet", "fw")
	if tbl == nil {
		t.Fatal("未生成表")
	}

	names := map[string]bool{}
	for _, c := range tbl.Chains {
		names[c.Name] = true
	}
	for _, want := range []string{"input", "output"} {
		if !names[want] {
			t.Errorf("主机模式必须保留 %s 链", want)
		}
	}
	for _, bad := range []string{"forward", "prerouting", "postrouting"} {
		if names[bad] {
			t.Errorf("主机模式**不应**注册 %s 链（会与 Docker/firewalld 同钩子同优先级冲突）", bad)
		}
	}

	text := res.Snapshot.Render()
	// 整份产物里不能出现 nat 类型的链
	if strings.Contains(text, "type nat hook") {
		t.Errorf("主机模式不该出现 nat 类型的链:\n%s", text)
	}
	if strings.Contains(text, "hook forward") {
		t.Errorf("主机模式不该出现 forward 钩子:\n%s", text)
	}
}

// 封禁规则在主機模式下必须落在 input 链（没有 prerouting 可用了）。
func TestHostModeBanRulesLandInInput(t *testing.T) {
	p := hostPolicy()
	p.Bans = []model.BanEntry{{IP: "203.0.113.9"}, {IP: "2001:db8::dead"}}

	res, err := Compile(p, Options{HostMode: true, BanSet4: "banned4", BanSet6: "banned6", Counters: true})
	if err != nil {
		t.Fatal(err)
	}
	tbl := res.Snapshot.Table("inet", "fw")

	if tbl.Set("banned4") == nil || tbl.Set("banned6") == nil {
		t.Fatal("封禁集合应仍然生成")
	}
	in := tbl.Chain("input")
	var hasV4, hasV6 bool
	for _, r := range in.Rules {
		for _, m := range r.Matches {
			if m.Set == "banned4" {
				hasV4 = true
			}
			if m.Set == "banned6" {
				hasV6 = true
			}
		}
	}
	if !hasV4 || !hasV6 {
		t.Errorf("封禁丢弃规则应落在 input 链，实际:\n%s", res.Snapshot.Render())
	}
}

// 引用 forward 的规则必须被明确拒绝，而不是静默丢弃 ——
// 否则用户会看到"我写了这条规则却不生效"。
func TestHostModeRejectsForwardRules(t *testing.T) {
	p := &model.Policy{
		Zones: []model.Zone{{Name: "wan", Interfaces: []string{"eth0"}}, {Name: "lan", Interfaces: []string{"eth1"}}},
		Rules: []model.Rule{
			{ID: "gw-rule", SrcZone: "wan", DstZone: "lan", Action: model.ActionAccept},
		},
	}
	_, err := Compile(p, Options{HostMode: true})
	if err == nil {
		t.Fatal("主机模式下引用 forward 的规则应被拒绝")
	}
	if !strings.Contains(err.Error(), "forward") {
		t.Errorf("错误信息应说明原因: %v", err)
	}
	if !strings.Contains(err.Error(), "gateway") {
		t.Errorf("错误信息应给出出路（改 mode 或改用 local）: %v", err)
	}
}

func TestHostModeRejectsNATRules(t *testing.T) {
	p := hostPolicy()
	p.Zones = []model.Zone{{Name: "wan", Interfaces: []string{"eth0"}}}
	p.NATRules = []model.NATRule{{ID: "n1", Kind: model.NATMasquerade, OutZone: "wan"}}

	_, err := Compile(p, Options{HostMode: true})
	if err == nil {
		t.Fatal("主机模式下 NAT 规则应被拒绝")
	}
	if !strings.Contains(err.Error(), "nat") {
		t.Errorf("错误信息应说明原因: %v", err)
	}
}

// 停用的 NAT 规则不应触发校验失败（它不会被编译）。
func TestHostModeAllowsDisabledNATRules(t *testing.T) {
	off := false
	p := hostPolicy()
	p.Zones = []model.Zone{{Name: "wan", Interfaces: []string{"eth0"}}}
	p.NATRules = []model.NATRule{{ID: "n1", Kind: model.NATMasquerade, OutZone: "wan", Enabled: &off}}

	if _, err := Compile(p, Options{HostMode: true}); err != nil {
		t.Errorf("停用的 NAT 规则不应导致编译失败: %v", err)
	}
}

// 网关模式的行为必须完全不受影响（默认路径不能被改坏）。
func TestGatewayModeUnchanged(t *testing.T) {
	res, err := Compile(samplePolicy(), Options{TableName: "fw"})
	if err != nil {
		t.Fatal(err)
	}
	tbl := res.Snapshot.Table("inet", "fw")
	names := map[string]bool{}
	for _, c := range tbl.Chains {
		names[c.Name] = true
	}
	for _, want := range []string{"prerouting", "input", "forward", "output", "postrouting"} {
		if !names[want] {
			t.Errorf("网关模式必须保留 %s 链", want)
		}
	}
}

// 主机模式下 input 默认策略仍然是 drop（这是主机防护的意义所在），
// output 默认 accept。
func TestHostModeDefaultPolicies(t *testing.T) {
	p := hostPolicy()
	p.Default = model.DefaultPolicy{} // 全空，看兜底
	res, err := Compile(p, Options{HostMode: true})
	if err != nil {
		t.Fatal(err)
	}
	tbl := res.Snapshot.Table("inet", "fw")
	if got := tbl.Chain("input").Policy; got != "drop" {
		t.Errorf("input 默认策略应为 drop，实际 %q", got)
	}
	if got := tbl.Chain("output").Policy; got != "accept" {
		t.Errorf("output 默认策略应为 accept，实际 %q", got)
	}
}

// 叠加模式：把 input 链放在更高优先级，使其在既有防火墙之后执行。
//
// 实测（nft 1.0.9）确认：同一钩子上的多条基础链按优先级依次执行，
// 前一条链的 accept 不会阻止后一条链继续判定，而 drop 是终局。
// 因此 fwdd 可以挂在 ufw 之上，只做"额外的丢弃"，不动既有放行规则。
func TestLayeredModeUsesHigherPriority(t *testing.T) {
	p := hostPolicy()
	p.Default = model.DefaultPolicy{Input: model.ActionAccept, Output: model.ActionAccept}

	res, err := Compile(p, Options{HostMode: true, InputPriority: 10})
	if err != nil {
		t.Fatal(err)
	}
	tbl := res.Snapshot.Table("inet", "fw")
	in, out := tbl.Chain("input"), tbl.Chain("output")
	if in.Priority != 10 {
		t.Errorf("input 链优先级应为 10，实际 %d", in.Priority)
	}
	if out.Priority != 10 {
		t.Errorf("output 链优先级应为 10，实际 %d", out.Priority)
	}
	if in.Policy != "accept" {
		t.Errorf("叠加模式下 input 默认策略应为 accept（放行交给既有防火墙），实际 %q", in.Policy)
	}
	// 渲染文本里要能看出优先级
	if !strings.Contains(res.Snapshot.Render(), "hook input priority 10") {
		t.Errorf("渲染结果里缺少 priority 10:\n%s", res.Snapshot.Render())
	}
}

// 不设优先级时保持默认 filter(0)，不影响原有行为。
func TestDefaultPriorityUnchanged(t *testing.T) {
	res, err := Compile(hostPolicy(), Options{HostMode: true})
	if err != nil {
		t.Fatal(err)
	}
	if p := res.Snapshot.Table("inet", "fw").Chain("input").Priority; p != 0 {
		t.Errorf("默认优先级应为 0，实际 %d", p)
	}
}
