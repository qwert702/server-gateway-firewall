package engine

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"
	"time"

	"fwdd/internal/backend/mock"
	"fwdd/internal/config"
	"fwdd/internal/model"
)

func testConfig() config.Config {
	cfg := config.Default()
	cfg.Backend = "mock"
	cfg.Table = "fw"
	cfg.Family = "inet"
	cfg.Listen = ""
	cfg.Socket = ""
	cfg.CommitConfirm = config.CommitConfirm{Enabled: false, Timeout: 2 * time.Second}
	return cfg
}

func basePolicy() *model.Policy {
	return &model.Policy{
		Zones: []model.Zone{{Name: "wan", Interfaces: []string{"eth0"}}, {Name: "lan", Interfaces: []string{"eth1"}}},
		Rules: []model.Rule{
			{ID: "lan-wan", SrcZone: "lan", DstZone: "wan", Action: model.ActionAccept},
		},
		Default: model.DefaultPolicy{Forward: model.ActionDrop, Input: model.ActionDrop, Output: model.ActionAccept},
	}
}

func newEngine(t *testing.T) (*Engine, *mock.Backend) {
	t.Helper()
	be := mock.New(mock.WithTableName("fw"))
	e := New(testConfig(), be, quietLogger())
	return e, be
}

func TestApplyDryRunTouchesNothing(t *testing.T) {
	e, be := newEngine(t)
	if err := e.SetPolicy(basePolicy()); err != nil {
		t.Fatal(err)
	}

	res, err := e.Apply(context.Background(), ApplyOptions{DryRun: true})
	if err != nil {
		t.Fatal(err)
	}
	if !res.DryRun || res.Applied {
		t.Errorf("dry-run 不应标记为已应用: %+v", res)
	}
	if res.Text == "" || res.Rules == 0 {
		t.Errorf("dry-run 应返回规则集文本: %+v", res)
	}
	if be.ApplyCount() != 0 {
		t.Errorf("dry-run 不得调用后端，实际调用 %d 次", be.ApplyCount())
	}
}

func TestApplyIsIdempotent(t *testing.T) {
	e, be := newEngine(t)
	if err := e.SetPolicy(basePolicy()); err != nil {
		t.Fatal(err)
	}

	first, err := e.Apply(context.Background(), ApplyOptions{})
	if err != nil {
		t.Fatal(err)
	}
	second, err := e.Apply(context.Background(), ApplyOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if second.Hash != first.Hash {
		t.Errorf("相同策略两次下发哈希不同: %s vs %s", first.Hash, second.Hash)
	}
	if second.Changed {
		t.Error("第二次下发不应报告变化")
	}
	if be.ApplyCount() != 2 {
		t.Errorf("后端调用次数 = %d, 期望 2", be.ApplyCount())
	}
}

func TestApplyFailureLeavesStateUnchanged(t *testing.T) {
	e, be := newEngine(t)
	if err := e.SetPolicy(basePolicy()); err != nil {
		t.Fatal(err)
	}
	if _, err := e.Apply(context.Background(), ApplyOptions{}); err != nil {
		t.Fatal(err)
	}
	before := e.Status(context.Background()).AppliedHash

	be.FailNext(errors.New("模拟内核拒绝"))
	if _, err := e.Apply(context.Background(), ApplyOptions{}); err == nil {
		t.Fatal("后端失败时 Apply 必须返回错误")
	}
	after := e.Status(context.Background()).AppliedHash
	if after != before {
		t.Errorf("下发失败后已应用哈希不应变化: %s -> %s", before, after)
	}
}

func TestPolicyValidationRejectsDanglingZone(t *testing.T) {
	e, _ := newEngine(t)
	p := basePolicy()
	p.Rules[0].SrcZone = "ghost"
	if err := e.SetPolicy(p); err == nil {
		t.Fatal("悬空域引用应被拒绝")
	}
}

func TestUpdateIsAtomicOnError(t *testing.T) {
	e, _ := newEngine(t)
	if err := e.SetPolicy(basePolicy()); err != nil {
		t.Fatal(err)
	}
	err := e.Update(func(p *model.Policy) error {
		p.Rules = append(p.Rules, model.Rule{ID: "bad", SrcZone: "nope", DstZone: "lan", Action: model.ActionAccept})
		return nil
	})
	if err == nil {
		t.Fatal("产生非法状态的 Update 应失败")
	}
	if got := len(e.Policy().Rules); got != 1 {
		t.Errorf("失败的 Update 不得修改期望状态，规则数 = %d", got)
	}
}

func TestCommitConfirmAutoRollback(t *testing.T) {
	e, _ := newEngine(t)
	if err := e.SetPolicy(basePolicy()); err != nil {
		t.Fatal(err)
	}
	if _, err := e.Apply(context.Background(), ApplyOptions{}); err != nil {
		t.Fatal(err)
	}
	good := e.Status(context.Background()).AppliedHash

	// 改一条规则后带确认窗口下发。
	if err := e.Update(func(p *model.Policy) error {
		p.Rules[0].Comment = "临时变更"
		p.Rules[0].Proto = model.ProtoTCP
		p.Rules[0].DstPort = []string{"9999"}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	res, err := e.Apply(context.Background(), ApplyOptions{WithConfirm: true, ConfirmTimeout: 300 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	if res.Pending == nil {
		t.Fatal("带确认的下发应产生待确认记录")
	}
	if e.Status(context.Background()).AppliedHash == good {
		t.Fatal("下发后已应用哈希应当变化")
	}

	// 超时后应自动回滚。
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if e.Status(context.Background()).AppliedHash == good {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if got := e.Status(context.Background()).AppliedHash; got != good {
		t.Fatalf("超时后应自动回滚到 %s, 实际 %s", good, got)
	}
	if e.Pending() != nil {
		t.Error("自动回滚后不应再有待确认记录")
	}
}

func TestConfirmCancelsRollback(t *testing.T) {
	e, _ := newEngine(t)
	if err := e.SetPolicy(basePolicy()); err != nil {
		t.Fatal(err)
	}
	if _, err := e.Apply(context.Background(), ApplyOptions{}); err != nil {
		t.Fatal(err)
	}
	if err := e.Update(func(p *model.Policy) error {
		p.Rules[0].Proto = model.ProtoTCP
		p.Rules[0].DstPort = []string{"9999"}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	res, err := e.Apply(context.Background(), ApplyOptions{WithConfirm: true, ConfirmTimeout: 200 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	if err := e.Confirm(); err != nil {
		t.Fatal(err)
	}
	time.Sleep(400 * time.Millisecond)
	if got := e.Status(context.Background()).AppliedHash; got != res.Hash {
		t.Errorf("已确认的变更不应被回滚: 期望 %s, 实际 %s", res.Hash, got)
	}
}

func TestApplyRejectedWhilePending(t *testing.T) {
	e, _ := newEngine(t)
	if err := e.SetPolicy(basePolicy()); err != nil {
		t.Fatal(err)
	}
	if _, err := e.Apply(context.Background(), ApplyOptions{WithConfirm: true, ConfirmTimeout: time.Minute}); err != nil {
		t.Fatal(err)
	}
	_, err := e.Apply(context.Background(), ApplyOptions{})
	if !errors.Is(err, ErrPendingCommit) {
		t.Fatalf("待确认期间应拒绝新的下发，实际错误: %v", err)
	}
	if err := e.Confirm(); err != nil {
		t.Fatal(err)
	}
}

func TestBanAddsToBackendSetAndPolicy(t *testing.T) {
	e, _ := newEngine(t)
	ctx := context.Background()
	if err := e.SetPolicy(basePolicy()); err != nil {
		t.Fatal(err)
	}
	if _, err := e.Apply(ctx, ApplyOptions{}); err != nil {
		t.Fatal(err)
	}

	if err := e.Ban(ctx, model.BanEntry{IP: "203.0.113.9", Reason: "爆破"}); err != nil {
		t.Fatal(err)
	}
	elems, err := e.Backend().SetList(ctx, "banned4")
	if err != nil {
		t.Fatal(err)
	}
	if len(elems) != 1 || elems[0].Key != "203.0.113.9" {
		t.Errorf("封禁未注入内核集合: %+v", elems)
	}
	if bans := e.ListBans(); len(bans) != 1 {
		t.Errorf("封禁未写入期望状态: %+v", bans)
	}

	if err := e.Unban(ctx, "203.0.113.9"); err != nil {
		t.Fatal(err)
	}
	if bans := e.ListBans(); len(bans) != 0 {
		t.Errorf("解封后仍存在记录: %+v", bans)
	}
}

func TestBanRejectsWhitelisted(t *testing.T) {
	e, _ := newEngine(t)
	ctx := context.Background()
	p := basePolicy()
	p.BanSet.Whitelist = []string{"203.0.113.0/24"}
	if err := e.SetPolicy(p); err != nil {
		t.Fatal(err)
	}
	if err := e.Ban(ctx, model.BanEntry{IP: "203.0.113.9"}); err == nil {
		t.Fatal("白名单内的地址不应被封禁")
	}
}

func TestStatusReportsInSync(t *testing.T) {
	e, _ := newEngine(t)
	ctx := context.Background()
	if err := e.SetPolicy(basePolicy()); err != nil {
		t.Fatal(err)
	}
	if e.Status(ctx).InSync {
		t.Error("尚未下发时不应标记为同步")
	}
	if _, err := e.Apply(ctx, ApplyOptions{}); err != nil {
		t.Fatal(err)
	}
	st := e.Status(ctx)
	if !st.InSync {
		t.Errorf("下发后应处于同步状态: %+v", st)
	}
	if st.Desired.Rules != 1 || st.Desired.Zones != 2 {
		t.Errorf("摘要不正确: %+v", st.Desired)
	}
}

// 首次下发若未确认，必须撤销整张表（内核回到默认放行），
// 而不是下发一份空策略 —— 空策略会编译成 default drop 的链，等于把自己锁死。
func TestAutoRollbackOnFirstApplyResetsInsteadOfEmptyPolicy(t *testing.T) {
	e, be := newEngine(t)
	ctx := context.Background()

	if err := e.SetPolicy(basePolicy()); err != nil {
		t.Fatal(err)
	}
	res, err := e.Apply(ctx, ApplyOptions{WithConfirm: true, ConfirmTimeout: 150 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	if res.Pending == nil {
		t.Fatal("应进入待确认状态")
	}

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) && e.Pending() != nil {
		time.Sleep(20 * time.Millisecond)
	}

	if applied := be.Applied(); applied != nil {
		var rules int
		for _, tb := range applied.Tables {
			for _, c := range tb.Chains {
				rules += len(c.Rules)
			}
		}
		// 即使"空策略"也至少会渲染出 default drop 的链，这里必须是真的清空。
		if len(applied.Tables) > 0 {
			t.Errorf("首次下发撤销后应移除全部规则，实际仍有 %d 张表 / %d 条规则:\n%s",
				len(applied.Tables), rules, be.Applied().Render())
		}
	}
	if st := e.Status(ctx); st.InSync {
		t.Errorf("撤销后应报告未同步: %+v", st)
	}
}

// 已有历史版本时，未确认的变更应回滚到该版本而非清空。
func TestAutoRollbackUsesPreviousVersion(t *testing.T) {
	e, _ := newEngine(t)
	ctx := context.Background()

	if err := e.SetPolicy(basePolicy()); err != nil {
		t.Fatal(err)
	}
	if _, err := e.Apply(ctx, ApplyOptions{}); err != nil {
		t.Fatal(err)
	}
	good := e.Status(ctx).AppliedHash

	if err := e.Update(func(p *model.Policy) error {
		p.Rules = append(p.Rules, model.Rule{ID: "extra", SrcZone: "wan", DstZone: "lan", Action: model.ActionAccept})
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := e.Apply(ctx, ApplyOptions{WithConfirm: true, ConfirmTimeout: 150 * time.Millisecond}); err != nil {
		t.Fatal(err)
	}

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) && e.Status(ctx).AppliedHash != good {
		time.Sleep(20 * time.Millisecond)
	}
	if got := e.Status(ctx).AppliedHash; got != good {
		t.Fatalf("应回滚到上一版本 %s，实际 %s", good, got)
	}
	if n := len(e.Policy().Rules); n != 1 {
		t.Errorf("回滚后期望状态也应恢复到上一版本，规则数 = %d", n)
	}
}

func TestManualRollbackWithoutHistoryFails(t *testing.T) {
	e, _ := newEngine(t)
	if err := e.SetPolicy(basePolicy()); err != nil {
		t.Fatal(err)
	}
	if err := e.Rollback(context.Background()); !errors.Is(err, ErrNoRollback) {
		t.Errorf("没有可回滚版本时应返回 ErrNoRollback，实际: %v", err)
	}
}

func TestManualRollbackUndoesLastApply(t *testing.T) {
	e, _ := newEngine(t)
	ctx := context.Background()
	if err := e.SetPolicy(basePolicy()); err != nil {
		t.Fatal(err)
	}
	if _, err := e.Apply(ctx, ApplyOptions{}); err != nil {
		t.Fatal(err)
	}
	first := e.Status(ctx).AppliedHash

	if err := e.Update(func(p *model.Policy) error {
		p.Rules = append(p.Rules, model.Rule{ID: "extra", SrcZone: "wan", DstZone: "lan", Action: model.ActionAccept})
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := e.Apply(ctx, ApplyOptions{}); err != nil {
		t.Fatal(err)
	}
	if e.Status(ctx).AppliedHash == first {
		t.Fatal("第二次下发应产生不同的哈希")
	}

	if err := e.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	if got := e.Status(ctx).AppliedHash; got != first {
		t.Errorf("回滚后应回到 %s，实际 %s", first, got)
	}
}

// 这是回归测试：封禁元素曾把"剩余时长"编译进快照，导致规则集哈希随时间漂移，
// 对账永远判定不同步、每次 apply 都误报"有变化"。
func TestDesiredHashIsStableOverTime(t *testing.T) {
	e, _ := newEngine(t)
	ctx := context.Background()
	if err := e.SetPolicy(basePolicy()); err != nil {
		t.Fatal(err)
	}
	if err := e.Ban(ctx, model.BanEntry{IP: "203.0.113.9", Reason: "爆破",
		ExpiresAt: time.Now().Add(2 * time.Hour)}); err != nil {
		t.Fatal(err)
	}

	first := e.Status(ctx).DesiredHash
	time.Sleep(1100 * time.Millisecond) // 跨过一秒，剩余时长必然变化
	second := e.Status(ctx).DesiredHash

	if first != second {
		t.Errorf("期望状态哈希随时间变化: %s -> %s（封禁时长不得进入编译产物）", first, second)
	}

	// 下发后应重新注入封禁，并报告同步。
	if _, err := e.Apply(ctx, ApplyOptions{}); err != nil {
		t.Fatal(err)
	}
	st := e.Status(ctx)
	if !st.InSync {
		t.Errorf("下发后应同步: %+v", st)
	}
	elems, err := e.Backend().SetList(ctx, "banned4")
	if err != nil {
		t.Fatal(err)
	}
	if len(elems) != 1 || elems[0].Key != "203.0.113.9" {
		t.Errorf("下发重建集合后封禁丢失: %+v", elems)
	}
}

// 规则集整体替换会重建集合，回滚之后同样要重新注入封禁。
func TestRollbackReinjectsBans(t *testing.T) {
	e, _ := newEngine(t)
	ctx := context.Background()
	if err := e.SetPolicy(basePolicy()); err != nil {
		t.Fatal(err)
	}
	if _, err := e.Apply(ctx, ApplyOptions{}); err != nil {
		t.Fatal(err)
	}
	if err := e.Ban(ctx, model.BanEntry{IP: "198.51.100.7", ExpiresAt: time.Now().Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	if err := e.Update(func(p *model.Policy) error {
		p.Rules = append(p.Rules, model.Rule{ID: "extra", SrcZone: "wan", DstZone: "lan", Action: model.ActionAccept})
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := e.Apply(ctx, ApplyOptions{}); err != nil {
		t.Fatal(err)
	}
	if err := e.Rollback(ctx); err != nil {
		t.Fatal(err)
	}

	elems, err := e.Backend().SetList(ctx, "banned4")
	if err != nil {
		t.Fatal(err)
	}
	if len(elems) != 1 || elems[0].Key != "198.51.100.7" {
		t.Errorf("回滚后封禁应仍然生效: %+v", elems)
	}
}

func TestExpiredBanNotReinjected(t *testing.T) {
	e, _ := newEngine(t)
	ctx := context.Background()
	if err := e.SetPolicy(basePolicy()); err != nil {
		t.Fatal(err)
	}
	if err := e.Update(func(p *model.Policy) error {
		p.Bans = append(p.Bans, model.BanEntry{IP: "198.51.100.9", ExpiresAt: time.Now().Add(-time.Minute)})
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := e.Apply(ctx, ApplyOptions{}); err != nil {
		t.Fatal(err)
	}
	elems, err := e.Backend().SetList(ctx, "banned4")
	if err != nil {
		t.Fatal(err)
	}
	if len(elems) != 0 {
		t.Errorf("已过期的封禁不应重新注入: %+v", elems)
	}
}

// 启动恢复时必须跳过 commit-confirm：无人值守重启若还等确认，
// 超时回滚会把防火墙规则整个撤掉。
func TestForceNoConfirmSkipsRollbackWindow(t *testing.T) {
	cfg := testConfig()
	cfg.CommitConfirm = config.CommitConfirm{Enabled: true, Timeout: 150 * time.Millisecond}
	be := mock.New(mock.WithTableName("fw"))
	e := New(cfg, be, quietLogger())

	if err := e.SetPolicy(basePolicy()); err != nil {
		t.Fatal(err)
	}
	res, err := e.Apply(context.Background(), ApplyOptions{Note: "启动下发", ForceNoConfirm: true})
	if err != nil {
		t.Fatal(err)
	}
	if res.Pending != nil || e.Pending() != nil {
		t.Fatal("强制跳过确认时不应产生待确认记录")
	}

	// 等过原定时长，规则必须还在。
	time.Sleep(400 * time.Millisecond)
	if be.Applied() == nil || be.Applied().RuleCount() == 0 {
		t.Error("启动下发的规则不应被自动撤销")
	}
}

// 反之，配置开启时普通 apply 仍应进入确认窗口。
func TestConfigEnabledConfirmStillApplies(t *testing.T) {
	cfg := testConfig()
	cfg.CommitConfirm = config.CommitConfirm{Enabled: true, Timeout: 3 * time.Second}
	e := New(cfg, mock.New(mock.WithTableName("fw")), quietLogger())

	if err := e.SetPolicy(basePolicy()); err != nil {
		t.Fatal(err)
	}
	res, err := e.Apply(context.Background(), ApplyOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if res.Pending == nil {
		t.Fatal("配置开启 commit-confirm 时，普通 apply 应产生待确认记录")
	}
	if err := e.Confirm(); err != nil {
		t.Fatal(err)
	}
}

// quietLogger 让测试输出不被引擎日志淹没；需要看日志时改成 os.Stderr 即可。
func quietLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}
