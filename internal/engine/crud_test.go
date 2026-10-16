package engine

import (
	"context"
	"fwdd/internal/model"
	"strings"
	"testing"
)

func crudEngine(t *testing.T) *Engine {
	t.Helper()
	e, _ := newEngine(t)
	if err := e.SetPolicy(basePolicy()); err != nil {
		t.Fatal(err)
	}
	return e
}

// ---- 域 ----

func TestAddZoneRejectsDuplicatesAndReservedNames(t *testing.T) {
	e := crudEngine(t)

	if err := e.AddZone(model.Zone{Name: "lan"}); err == nil {
		t.Error("重复域名应被拒绝")
	}
	if err := e.AddZone(model.Zone{Name: model.ZoneLocal}); err == nil {
		t.Error("保留字不应能作为域名")
	}
	if err := e.AddZone(model.Zone{Name: ""}); err == nil {
		t.Error("空域名应被拒绝")
	}
	if err := e.AddZone(model.Zone{Name: "dmz", Interfaces: []string{"eth2"}}); err != nil {
		t.Fatalf("合法域名不应被拒绝: %v", err)
	}
	if e.Policy().ZoneByName("dmz") == nil {
		t.Error("域未写入策略")
	}
}

func TestDeleteZoneRefusesWhileReferenced(t *testing.T) {
	e := crudEngine(t)
	// basePolicy 里有一条 lan -> wan 的规则
	err := e.DeleteZone("lan")
	if err == nil {
		t.Fatal("被规则引用的域不应能删除")
	}
	if !strings.Contains(err.Error(), "引用") {
		t.Errorf("错误信息应说明被引用，实际: %v", err)
	}

	// 解除引用后即可删除
	rules := e.ListRules()
	for _, r := range rules {
		if err := e.DeleteRule(r.ID); err != nil {
			t.Fatal(err)
		}
	}
	if err := e.DeleteZone("lan"); err != nil {
		t.Fatalf("解除引用后应可删除: %v", err)
	}
}

func TestRenameZoneUpdatesReferences(t *testing.T) {
	e := crudEngine(t)
	if err := e.UpdateZone("lan", model.Zone{Name: "internal", Interfaces: []string{"eth1"}}); err != nil {
		t.Fatalf("改名失败: %v", err)
	}
	r := e.ListRules()[0]
	if r.SrcZone != "internal" {
		t.Errorf("规则中的域引用未同步更新: %+v", r)
	}
	if e.Policy().ZoneByName("lan") != nil {
		t.Error("旧域名不应残留")
	}
}

// ---- 规则 ----

func TestAddRuleAutoAssignsIDAndPriority(t *testing.T) {
	e := crudEngine(t)
	id, err := e.AddRule(model.Rule{SrcZone: "wan", DstZone: "lan", Action: model.ActionDrop})
	if err != nil {
		t.Fatal(err)
	}
	if id == "" {
		t.Fatal("应自动生成规则 id")
	}
	r := e.Policy().RuleByID(id)
	if r == nil {
		t.Fatalf("规则 %s 未写入", id)
	}
	if r.Priority <= 0 {
		t.Errorf("应自动分配优先级: %d", r.Priority)
	}
	// 新规则的优先级应大于已有规则，从而排在后面
	if r.Priority <= e.Policy().Rules[0].Priority {
		t.Errorf("新规则应排在已有规则之后: 新 %d, 已有 %d", r.Priority, e.Policy().Rules[0].Priority)
	}
}

func TestAddRuleRejectsDuplicateID(t *testing.T) {
	e := crudEngine(t)
	if _, err := e.AddRule(model.Rule{ID: "lan-wan", SrcZone: "wan", DstZone: "lan", Action: model.ActionDrop}); err == nil {
		t.Error("重复 id 应被拒绝")
	}
}

func TestAddRuleValidatesBeforeWriting(t *testing.T) {
	e := crudEngine(t)
	before := len(e.Policy().Rules)
	if _, err := e.AddRule(model.Rule{SrcZone: "nonexistent", DstZone: "lan", Action: model.ActionAccept}); err == nil {
		t.Fatal("悬空域引用应被拒绝")
	}
	if got := len(e.Policy().Rules); got != before {
		t.Errorf("失败的写入不应污染策略: 规则数 %d -> %d", before, got)
	}
}

func TestUpdateRuleKeepsPriorityAndEnabledWhenOmitted(t *testing.T) {
	e := crudEngine(t)
	orig := e.ListRules()[0]

	// 只改备注，不带 priority / enabled
	next := model.Rule{
		ID: orig.ID, SrcZone: orig.SrcZone, DstZone: orig.DstZone,
		Action: orig.Action, Comment: "只改了备注",
	}
	if err := e.UpdateRule(orig.ID, next); err != nil {
		t.Fatal(err)
	}
	got := e.Policy().RuleByID(orig.ID)
	if got.Priority != orig.Priority {
		t.Errorf("未指定优先级时应保留原值: %d -> %d", orig.Priority, got.Priority)
	}
	if got.IsEnabled() != orig.IsEnabled() {
		t.Errorf("未指定启用状态时应保留原值")
	}
	if got.Comment != "只改了备注" {
		t.Errorf("备注未更新: %q", got.Comment)
	}
}

func TestEnableDisableRule(t *testing.T) {
	e := crudEngine(t)
	id := e.ListRules()[0].ID

	if err := e.SetRuleEnabled(id, false); err != nil {
		t.Fatal(err)
	}
	if e.Policy().RuleByID(id).IsEnabled() {
		t.Error("停用未生效")
	}
	if err := e.SetRuleEnabled(id, true); err != nil {
		t.Fatal(err)
	}
	if !e.Policy().RuleByID(id).IsEnabled() {
		t.Error("启用未生效")
	}
	if err := e.SetRuleEnabled("不存在", true); err == nil {
		t.Error("不存在的规则应报错")
	}
}

func TestMoveRuleReorders(t *testing.T) {
	e := crudEngine(t)
	a, err := e.AddRule(model.Rule{ID: "a", SrcZone: "wan", DstZone: "lan", Action: model.ActionAccept})
	if err != nil {
		t.Fatal(err)
	}
	b, err := e.AddRule(model.Rule{ID: "b", SrcZone: "wan", DstZone: "lan", Action: model.ActionAccept})
	if err != nil {
		t.Fatal(err)
	}

	// 把 b 移到 a 之前
	if err := e.MoveRule(b, a); err != nil {
		t.Fatal(err)
	}
	ids := ruleIDs(e.ListRules())
	if idxOf(ids, b) > idxOf(ids, a) {
		t.Errorf("b 应排在 a 之前: %v", ids)
	}

	// 移到末尾
	if err := e.MoveRule(b, ""); err != nil {
		t.Fatal(err)
	}
	ids = ruleIDs(e.ListRules())
	if ids[len(ids)-1] != b {
		t.Errorf("b 应排在末尾: %v", ids)
	}
}

func TestReorderRules(t *testing.T) {
	e := crudEngine(t)
	a, _ := e.AddRule(model.Rule{ID: "a", SrcZone: "wan", DstZone: "lan", Action: model.ActionAccept})
	b, _ := e.AddRule(model.Rule{ID: "b", SrcZone: "wan", DstZone: "lan", Action: model.ActionAccept})

	if err := e.ReorderRules([]string{b, a}); err != nil {
		t.Fatal(err)
	}
	ids := ruleIDs(e.ListRules())
	if idxOf(ids, b) > idxOf(ids, a) {
		t.Errorf("重排未生效: %v", ids)
	}

	if err := e.ReorderRules([]string{"不存在"}); err == nil {
		t.Error("未知 id 应报错")
	}
}

// 重排后编译产物必须跟着变，否则改动只是"看着生效"。
func TestReorderAffectsCompiledRuleset(t *testing.T) {
	e := crudEngine(t)
	ctx := context.Background()

	before, err := e.Plan(ctx)
	if err != nil {
		t.Fatal(err)
	}
	ids := ruleIDs(e.ListRules())
	if len(ids) < 2 {
		if _, err := e.AddRule(model.Rule{ID: "extra", SrcZone: "wan", DstZone: "lan", Action: model.ActionDrop}); err != nil {
			t.Fatal(err)
		}
		ids = ruleIDs(e.ListRules())
	}
	// 反转顺序
	rev := make([]string, 0, len(ids))
	for i := len(ids) - 1; i >= 0; i-- {
		rev = append(rev, ids[i])
	}
	if err := e.ReorderRules(rev); err != nil {
		t.Fatal(err)
	}

	after, err := e.Plan(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if before.Hash == after.Hash {
		t.Error("重排规则后编译产物应发生变化")
	}
}

func TestDeleteRule(t *testing.T) {
	e := crudEngine(t)
	id := e.ListRules()[0].ID
	if err := e.DeleteRule(id); err != nil {
		t.Fatal(err)
	}
	if e.Policy().RuleByID(id) != nil {
		t.Error("规则未被删除")
	}
	if err := e.DeleteRule(id); err == nil {
		t.Error("删除不存在的规则应报错")
	}
}

// ---- NAT ----

func TestNATCRUD(t *testing.T) {
	e := crudEngine(t)

	id, err := e.AddNATRule(model.NATRule{
		Kind: model.NATDNAT, Proto: model.ProtoTCP, SrcZone: "wan",
		MatchPort: "8080", ToAddr: "10.0.0.10", ToPort: "80",
	})
	if err != nil {
		t.Fatal(err)
	}
	if id == "" {
		t.Fatal("应自动生成 NAT 规则 id")
	}
	if n := e.Policy().NATRules[0]; n.Priority <= 0 {
		t.Errorf("应自动分配优先级: %d", n.Priority)
	}

	// 非法 NAT 应被拒绝且不写入
	before := len(e.Policy().NATRules)
	if _, err := e.AddNATRule(model.NATRule{Kind: model.NATDNAT}); err == nil {
		t.Error("缺少 to_addr 的 dnat 应被拒绝")
	}
	if got := len(e.Policy().NATRules); got != before {
		t.Errorf("失败的写入不应污染策略: %d -> %d", before, got)
	}
	if _, err := e.AddNATRule(model.NATRule{Kind: model.NATDNAT, SrcZone: "ghost", ToAddr: "10.0.0.1"}); err == nil {
		t.Error("悬空 out_zone/src_zone 应被拒绝")
	}

	if err := e.UpdateNATRule(id, model.NATRule{
		Kind: model.NATDNAT, Proto: model.ProtoTCP, SrcZone: "wan",
		MatchPort: "8080", ToAddr: "10.0.0.99", ToPort: "80",
	}); err != nil {
		t.Fatal(err)
	}
	if got := e.Policy().NATRules[0].ToAddr; got != "10.0.0.99" {
		t.Errorf("NAT 更新未生效: %s", got)
	}

	if err := e.DeleteNATRule(id); err != nil {
		t.Fatal(err)
	}
	if len(e.Policy().NATRules) != 0 {
		t.Error("NAT 规则未被删除")
	}
}

// NAT 规则必须真的进到编译产物里，否则只是存了条数据。
func TestNATAppearsInRuleset(t *testing.T) {
	e := crudEngine(t)
	if _, err := e.AddNATRule(model.NATRule{
		ID: "web", Kind: model.NATDNAT, Proto: model.ProtoTCP, SrcZone: "wan",
		MatchPort: "8080", ToAddr: "10.0.0.10", ToPort: "80",
	}); err != nil {
		t.Fatal(err)
	}
	plan, err := e.Plan(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(plan.Text, "dnat to 10.0.0.10:80") {
		t.Errorf("NAT 规则未出现在规则集中:\n%s", plan.Text)
	}
}

// ---- 持久化 ----

func TestCRUDPersistsAcrossRestart(t *testing.T) {
	db := mustDB(t)
	ctx := context.Background()

	e1 := New(testConfig(), newMockBackend(), quietLogger(), WithStore(db))
	if _, err := e1.Restore(ctx, basePolicy()); err != nil {
		t.Fatal(err)
	}
	if _, err := e1.AddRule(model.Rule{ID: "added", SrcZone: "wan", DstZone: "lan", Proto: model.ProtoTCP,
		DstPort: []string{"8443"}, Action: model.ActionAccept}); err != nil {
		t.Fatal(err)
	}
	if _, err := e1.AddNATRule(model.NATRule{ID: "n2", Kind: model.NATMasquerade, OutZone: "wan"}); err != nil {
		t.Fatal(err)
	}
	if err := e1.AddZone(model.Zone{Name: "guest", Networks: []string{"192.168.99.0/24"}}); err != nil {
		t.Fatal(err)
	}

	e2 := New(testConfig(), newMockBackend(), quietLogger(), WithStore(db))
	if _, err := e2.Restore(ctx, basePolicy()); err != nil {
		t.Fatal(err)
	}
	p := e2.Policy()
	if p.RuleByID("added") == nil {
		t.Error("新增规则未持久化")
	}
	if len(p.NATRules) != 1 || p.NATRules[0].ID != "n2" {
		t.Errorf("NAT 规则未持久化: %+v", p.NATRules)
	}
	if p.ZoneByName("guest") == nil {
		t.Error("新增域未持久化")
	}
}

func TestCRUDWritesAudit(t *testing.T) {
	db := mustDB(t)
	e := New(testConfig(), newMockBackend(), quietLogger(), WithStore(db))
	if _, err := e.Restore(context.Background(), basePolicy()); err != nil {
		t.Fatal(err)
	}
	id, err := e.AddRule(model.Rule{SrcZone: "wan", DstZone: "lan", Action: model.ActionDrop})
	if err != nil {
		t.Fatal(err)
	}
	if err := e.DeleteRule(id); err != nil {
		t.Fatal(err)
	}
	if _, err := e.AddNATRule(model.NATRule{Kind: model.NATMasquerade, OutZone: "wan"}); err != nil {
		t.Fatal(err)
	}

	entries, err := e.AuditLog(context.Background(), 50)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, en := range entries {
		seen[en.Action] = true
	}
	for _, want := range []string{"rule.add", "rule.delete", "nat.add"} {
		if !seen[want] {
			t.Errorf("缺少审计记录 %q，已有 %v", want, seen)
		}
	}
}

// 没有存储时 CRUD 仍应可用（只是重启即遗忘）。
func TestCRUDWithoutStore(t *testing.T) {
	e, _ := newEngine(t)
	if err := e.SetPolicy(basePolicy()); err != nil {
		t.Fatal(err)
	}
	if _, err := e.AddRule(model.Rule{SrcZone: "wan", DstZone: "lan", Action: model.ActionDrop}); err != nil {
		t.Fatal(err)
	}
	if _, err := e.AddNATRule(model.NATRule{Kind: model.NATMasquerade, OutZone: "wan"}); err != nil {
		t.Fatal(err)
	}
	if err := e.AddZone(model.Zone{Name: "x", Networks: []string{"10.1.0.0/16"}}); err != nil {
		t.Fatal(err)
	}
}

// ---- 小工具 ----

func ruleIDs(rs []model.Rule) []string {
	out := make([]string, 0, len(rs))
	for _, r := range rs {
		out = append(out, r.ID)
	}
	return out
}

func idxOf(ss []string, s string) int {
	for i, v := range ss {
		if v == s {
			return i
		}
	}
	return -1
}

// 规则指纹靠 Plan.ChainDetails 画出来。log 规则的特别之处在于它**没有**
// 裁决语句（只记录、不决定去向），只看裁决语句会把它标成未知状态。
func TestPlanChainDetailsLabelEveryKind(t *testing.T) {
	e := crudEngine(t)
	ctx := context.Background()

	p := e.Policy()
	p.Rules = []model.Rule{
		{ID: "acc", SrcZone: "lan", DstZone: "wan", Action: model.ActionAccept},
		{ID: "drp", SrcZone: "wan", DstZone: "lan", Action: model.ActionDrop},
		{ID: "rej", SrcZone: "wan", DstZone: "lan", Proto: model.ProtoTCP,
			DstPort: []string{"445"}, Action: model.ActionReject},
		{ID: "lg", SrcZone: "wan", DstZone: "lan", Action: model.ActionLog},
		{ID: "nat", SrcZone: "wan", DstZone: model.ZoneAny, Action: model.ActionAccept},
	}
	p.NATRules = []model.NATRule{{ID: "n", Kind: model.NATMasquerade, OutZone: "wan"}}
	if err := e.SetPolicy(p); err != nil {
		t.Fatal(err)
	}

	plan, err := e.Plan(ctx)
	if err != nil {
		t.Fatal(err)
	}

	got := map[string]string{} // ruleID -> verdict
	for _, c := range plan.ChainDetails {
		for _, s := range c.Segments {
			got[s.ID] = s.Verdict
		}
	}

	for id, want := range map[string]string{
		"acc": "accept", "drp": "drop", "rej": "reject", "lg": "log",
	} {
		found := false
		for k, v := range got {
			if strings.Contains(k, id) && v == want {
				found = true
			}
		}
		if !found {
			t.Errorf("规则 %s 的裁决应为 %s，实际:%v", id, want, got)
		}
	}

	// NAT 规则必须落在 prerouting / postrouting 上并被标成 nat
	for _, c := range plan.ChainDetails {
		if c.Name == "postrouting" {
			if len(c.Segments) == 0 || c.Segments[0].Verdict != "nat" {
				t.Errorf("postrouting 的 NAT 规则未标成 nat: %+v", c.Segments)
			}
		}
	}

	// 每条链都要能给出默认策略，界面靠它画链尾的斜纹
	for _, c := range plan.ChainDetails {
		if (c.Name == "input" || c.Name == "forward" || c.Name == "output") && c.Policy == "" {
			t.Errorf("链 %s 缺少默认策略信息", c.Name)
		}
	}
}
