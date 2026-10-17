package engine

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"fwdd/internal/model"
)

// 地址组要能承载"几万条 CIDR"这类列表：走 nft 区间集合，不内联进规则。
func TestAddrGroupCompilesToIntervalSet(t *testing.T) {
	dir := t.TempDir()
	list := filepath.Join(dir, "blocked.cidr")
	if err := os.WriteFile(list, []byte("# 威胁情报列表\n203.0.113.0/24\n198.51.100.7\n2001:db8:bad::/48\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	e, _ := newEngine(t)
	p := &model.Policy{
		Zones:      []model.Zone{{Name: "wan", Interfaces: []string{"eth0"}}},
		AddrGroups: []model.AddrGroup{{Name: "threat", File: list}},
		Rules: []model.Rule{{
			ID: "block", SrcZone: "wan", DstZone: model.ZoneAny,
			SrcGroup: "threat", Action: model.ActionDrop,
		}},
		Default: model.DefaultPolicy{Forward: model.ActionDrop},
	}
	if err := e.SetPolicy(p); err != nil {
		t.Fatalf("SetPolicy 失败: %v", err)
	}

	plan, err := e.Plan(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	text := plan.Text

	// 必须用集合而不是把地址铺开写进规则
	if !strings.Contains(text, "set grp_threat4") || !strings.Contains(text, "set grp_threat6") {
		t.Fatalf("应生成 v4/v6 两个地址组集合:\n%s", text)
	}
	// 区间集合必须带 interval 标志：否则 203.0.113.0/24 只能精确匹配到一个地址
	if !strings.Contains(text, "flags interval") {
		t.Errorf("地址组集合必须是 interval 类型:\n%s", text)
	}
	if !strings.Contains(text, "203.0.113.0/24") || !strings.Contains(text, "198.51.100.7/32") {
		t.Errorf("集合元素不正确（裸 IP 应补成 /32）:\n%s", text)
	}
	// 规则必须引用集合，且 v4/v6 分开
	if !strings.Contains(text, "ip saddr @grp_threat4") {
		t.Errorf("缺少 IPv4 集合引用:\n%s", text)
	}
	if !strings.Contains(text, "ip6 saddr @grp_threat6") {
		t.Errorf("缺少 IPv6 集合引用:\n%s", text)
	}
	// 地址绝不能铺进规则本身
	if strings.Contains(text, "ip saddr { 203.0.113.0/24") {
		t.Errorf("地址被内联进规则了，几万条时会让规则集爆炸:\n%s", text)
	}
}

// 组文件读不到时必须直接失败：少了地址的封锁是静默失效。
func TestAddrGroupMissingFileFailsLoudly(t *testing.T) {
	e, _ := newEngine(t)
	p := &model.Policy{
		Zones:      []model.Zone{{Name: "wan", Interfaces: []string{"eth0"}}},
		AddrGroups: []model.AddrGroup{{Name: "gone", File: filepath.Join(t.TempDir(), "nope.cidr")}},
		Rules: []model.Rule{{
			ID: "block", SrcZone: "wan", DstZone: model.ZoneAny,
			SrcGroup: "gone", Action: model.ActionDrop,
		}},
	}
	err := e.SetPolicy(p)
	if err == nil {
		t.Fatal("组文件不存在时应拒绝设置策略，而不是生成一条匹配不到东西的规则")
	}
	if !strings.Contains(err.Error(), "gone") {
		t.Errorf("错误信息应点明是哪个组: %v", err)
	}
}

// 引用未声明的组应在校验阶段就被拦下。
func TestAddrGroupUndeclaredReference(t *testing.T) {
	e, _ := newEngine(t)
	p := &model.Policy{
		Zones: []model.Zone{{Name: "wan", Interfaces: []string{"eth0"}}},
		Rules: []model.Rule{{
			ID: "block", SrcZone: "wan", DstZone: model.ZoneAny,
			SrcGroup: "undeclared", Action: model.ActionDrop,
		}},
	}
	err := e.SetPolicy(p)
	if err == nil {
		t.Fatal("引用未声明的地址组应被拒绝")
	}
	if !strings.Contains(err.Error(), "undeclared") {
		t.Errorf("错误信息应点明组名: %v", err)
	}
}

// 组内容变化后应能被检测到，且不自动下发（与其余变更一致，由人决定何时 apply）。
func TestReloadGroupsDetectsChange(t *testing.T) {
	dir := t.TempDir()
	list := filepath.Join(dir, "g.cidr")
	if err := os.WriteFile(list, []byte("203.0.113.0/24\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	e, _ := newEngine(t)
	ctx := context.Background()
	p := &model.Policy{
		Zones:      []model.Zone{{Name: "wan", Interfaces: []string{"eth0"}}},
		AddrGroups: []model.AddrGroup{{Name: "g", File: list}},
		Rules: []model.Rule{{
			ID: "block", SrcZone: "wan", DstZone: model.ZoneAny,
			SrcGroup: "g", Action: model.ActionDrop,
		}},
	}
	if err := e.SetPolicy(p); err != nil {
		t.Fatal(err)
	}

	// 内容没变时不应报告变化
	changed, err := e.ReloadGroups(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if changed {
		t.Error("内容未变时不应报告变化")
	}

	// 追加一条地址
	f, _ := os.OpenFile(list, os.O_APPEND|os.O_WRONLY, 0o600)
	f.WriteString("198.51.100.0/24\n")
	f.Close()

	changed, err = e.ReloadGroups(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !changed {
		t.Fatal("内容变化应被检测到")
	}

	// 期望状态变了，但内核还没变 —— 应报告未同步，而不是悄悄生效
	st := e.Status(ctx)
	if st.InSync {
		t.Error("重新加载地址组后内核尚未更新，不应报告同步")
	}

	plan, err := e.Plan(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(plan.Text, "198.51.100.0/24") {
		t.Errorf("新地址应出现在待下发的规则集中:\n%s", plan.Text)
	}
}

func TestGroupsSummary(t *testing.T) {
	dir := t.TempDir()
	list := filepath.Join(dir, "g.cidr")
	if err := os.WriteFile(list, []byte("203.0.113.0/24\n2001:db8::/32\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	e, _ := newEngine(t)
	p := &model.Policy{
		Zones:      []model.Zone{{Name: "wan", Interfaces: []string{"eth0"}}},
		AddrGroups: []model.AddrGroup{{Name: "g", File: list}},
		Rules: []model.Rule{{
			ID: "block", SrcZone: "wan", DstZone: model.ZoneAny,
			SrcGroup: "g", Action: model.ActionDrop,
		}},
	}
	if err := e.SetPolicy(p); err != nil {
		t.Fatal(err)
	}

	gs := e.Groups()
	if len(gs) != 1 {
		t.Fatalf("应有 1 个组，实际 %d", len(gs))
	}
	g := gs[0]
	if g.Name != "g" || g.V4Count != 1 || g.V6Count != 1 || g.Total != 2 {
		t.Errorf("摘要不正确: %+v", g)
	}
	if g.Source != list {
		t.Errorf("应记录来源便于排查: %q", g.Source)
	}
	if len(g.UsedBy) != 1 || g.UsedBy[0] != "block" {
		t.Errorf("应列出引用者: %+v", g.UsedBy)
	}
}
