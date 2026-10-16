package engine

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"fwdd/internal/backend/mock"
	"fwdd/internal/model"
	"fwdd/internal/store"
)

// newPersistentEngine 返回一个挂了真实 SQLite（内存库）的引擎，
// 用它来验证"进程重启后状态还在"。
func newPersistentEngine(t *testing.T, db *store.DB) (*Engine, *mock.Backend) {
	t.Helper()
	be := mock.New(mock.WithTableName("fw"))
	e := New(testConfig(), be, quietLogger(), WithStore(db))
	return e, be
}

func TestRestoreSeedsFromBaselineWhenEmpty(t *testing.T) {
	db := mustDB(t)
	ctx := context.Background()

	e, _ := newPersistentEngine(t, db)
	fromDB, err := e.Restore(ctx, basePolicy())
	if err != nil {
		t.Fatal(err)
	}
	if fromDB {
		t.Error("数据库为空时应从基线初始化，fromDB 应为 false")
	}
	if got := len(e.Policy().Rules); got != 1 {
		t.Errorf("基线未生效，规则数 = %d", got)
	}
	// 而且应当已经把基线写进了数据库
	if !db.HasPolicy(ctx) {
		t.Error("用基线初始化后应已写入数据库")
	}
}

func TestRestorePrefersDatabaseOverBaseline(t *testing.T) {
	db := mustDB(t)
	ctx := context.Background()

	// 第一次启动：从基线初始化
	e1, _ := newPersistentEngine(t, db)
	if _, err := e1.Restore(ctx, basePolicy()); err != nil {
		t.Fatal(err)
	}
	// 管理员改了策略
	if err := e1.Update(func(p *model.Policy) error {
		p.Rules = append(p.Rules, model.Rule{ID: "added", SrcZone: "wan", DstZone: "lan", Action: model.ActionDrop})
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	// 第二次启动：文件里还是旧基线，但数据库里是管理员改过的版本
	e2, _ := newPersistentEngine(t, db)
	fromDB, err := e2.Restore(ctx, basePolicy())
	if err != nil {
		t.Fatal(err)
	}
	if !fromDB {
		t.Error("应从数据库恢复，fromDB 应为 true")
	}
	if got := len(e2.Policy().Rules); got != 2 {
		t.Errorf("数据库中的策略应优先于陈旧基线，规则数 = %d（期望 2）", got)
	}
}

func TestBansSurviveRestart(t *testing.T) {
	db := mustDB(t)
	ctx := context.Background()
	now := time.Now()

	e1, _ := newPersistentEngine(t, db)
	if _, err := e1.Restore(ctx, basePolicy()); err != nil {
		t.Fatal(err)
	}
	if err := e1.Ban(ctx, model.BanEntry{
		IP: "203.0.113.9", Reason: "爆破", Source: model.BanManual,
		AddedAt: now, ExpiresAt: now.Add(time.Hour),
	}); err != nil {
		t.Fatal(err)
	}

	// 重启
	e2, be2 := newPersistentEngine(t, db)
	if _, err := e2.Restore(ctx, basePolicy()); err != nil {
		t.Fatal(err)
	}

	bans := e2.ListBans()
	if len(bans) != 1 || bans[0].IP != "203.0.113.9" || bans[0].Reason != "爆破" {
		t.Fatalf("重启后封禁丢失: %+v", bans)
	}
	if bans[0].Source != model.BanManual {
		t.Errorf("封禁来源丢失: %+v", bans[0])
	}

	// 下发后应重新注入内核集合（规则集替换会重建集合）
	if _, err := e2.Apply(ctx, ApplyOptions{}); err != nil {
		t.Fatal(err)
	}
	elems, err := be2.SetList(ctx, "banned4")
	if err != nil {
		t.Fatal(err)
	}
	if len(elems) != 1 || elems[0].Key != "203.0.113.9" {
		t.Errorf("重启后封禁未重新注入内核: %+v", elems)
	}
}

// 封禁绝不能同时存在于策略 JSON 和 ban_entries 表：两份副本必然漂移。
func TestBansNotDuplicatedInPolicyBlob(t *testing.T) {
	db := mustDB(t)
	ctx := context.Background()

	e, _ := newPersistentEngine(t, db)
	if _, err := e.Restore(ctx, basePolicy()); err != nil {
		t.Fatal(err)
	}
	if err := e.Ban(ctx, model.BanEntry{IP: "203.0.113.9", ExpiresAt: time.Now().Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}

	stored, err := db.LoadPolicy(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(stored.Bans) != 0 {
		t.Errorf("策略 JSON 中不应存有封禁（由 ban_entries 表统一管理）: %+v", stored.Bans)
	}

	loaded, err := db.LoadBans(ctx, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if len(loaded) != 1 {
		t.Errorf("封禁应存在于 ban_entries 表: %+v", loaded)
	}
}

func TestUnbanPersistsRemoval(t *testing.T) {
	db := mustDB(t)
	ctx := context.Background()

	e1, _ := newPersistentEngine(t, db)
	if _, err := e1.Restore(ctx, basePolicy()); err != nil {
		t.Fatal(err)
	}
	if err := e1.Ban(ctx, model.BanEntry{IP: "203.0.113.9", ExpiresAt: time.Now().Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	if err := e1.Unban(ctx, "203.0.113.9"); err != nil {
		t.Fatal(err)
	}

	e2, _ := newPersistentEngine(t, db)
	if _, err := e2.Restore(ctx, basePolicy()); err != nil {
		t.Fatal(err)
	}
	if bans := e2.ListBans(); len(bans) != 0 {
		t.Errorf("解封后重启不应复活: %+v", bans)
	}
}

// 已过期的封禁必须在上次运行时就清理掉，不能在每次重启时被重新注入。
func TestExpiredBansPrunedOnRestart(t *testing.T) {
	db := mustDB(t)
	ctx := context.Background()
	now := time.Now()

	e1, _ := newPersistentEngine(t, db)
	if _, err := e1.Restore(ctx, basePolicy()); err != nil {
		t.Fatal(err)
	}
	// 直接写入一条已过期的记录（模拟进程停机期间封禁自然到期）
	if err := db.UpsertBan(ctx, model.BanEntry{IP: "198.51.100.9", ExpiresAt: now.Add(-time.Hour)}); err != nil {
		t.Fatal(err)
	}

	e2, _ := newPersistentEngine(t, db)
	if _, err := e2.Restore(ctx, basePolicy()); err != nil {
		t.Fatal(err)
	}
	if bans := e2.ListBans(); len(bans) != 0 {
		t.Errorf("重启时不应恢复已过期的封禁: %+v", bans)
	}
	left, err := db.LoadBans(ctx, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(left) != 0 {
		t.Errorf("过期记录应已被删除: %+v", left)
	}
}

func TestAuditRecordsWrites(t *testing.T) {
	db := mustDB(t)
	ctx := context.Background()

	e, _ := newPersistentEngine(t, db)
	if _, err := e.Restore(ctx, basePolicy()); err != nil {
		t.Fatal(err)
	}
	if err := e.SetPolicy(basePolicy()); err != nil { // 显式改写策略
		t.Fatal(err)
	}
	if _, err := e.Apply(ctx, ApplyOptions{}); err != nil {
		t.Fatal(err)
	}
	if err := e.Ban(ctx, model.BanEntry{IP: "203.0.113.9", ExpiresAt: time.Now().Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	if err := e.Unban(ctx, "203.0.113.9"); err != nil {
		t.Fatal(err)
	}

	entries, err := e.AuditLog(ctx, 50)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, en := range entries {
		seen[en.Action] = true
	}
	// policy.init 来自首次启动的基线导入，policy.set 来自显式改写。
	for _, want := range []string{"policy.init", "policy.set", "apply", "ban.add", "ban.remove"} {
		if !seen[want] {
			t.Errorf("缺少审计记录 %q，已有: %v", want, seen)
		}
	}
}

func TestApplyRecordsHashForReconciliation(t *testing.T) {
	db := mustDB(t)
	ctx := context.Background()

	e, _ := newPersistentEngine(t, db)
	if _, err := e.Restore(ctx, basePolicy()); err != nil {
		t.Fatal(err)
	}
	res, err := e.Apply(ctx, ApplyOptions{})
	if err != nil {
		t.Fatal(err)
	}
	got, err := db.GetKV(ctx, "applied_hash")
	if err != nil {
		t.Fatal(err)
	}
	if got != res.Hash {
		t.Errorf("应记录下发哈希用于重启后对账：数据库 %q, 实际 %q", got, res.Hash)
	}
}

// 回滚也必须落盘，否则重启会回到被回滚掉的那个版本。
func TestRollbackPersistsState(t *testing.T) {
	db := mustDB(t)
	ctx := context.Background()

	e, _ := newPersistentEngine(t, db)
	if _, err := e.Restore(ctx, basePolicy()); err != nil {
		t.Fatal(err)
	}
	if _, err := e.Apply(ctx, ApplyOptions{}); err != nil {
		t.Fatal(err)
	}
	if err := e.Update(func(p *model.Policy) error {
		p.Rules = append(p.Rules, model.Rule{ID: "extra", SrcZone: "wan", DstZone: "lan", Action: model.ActionDrop})
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

	e2, _ := newPersistentEngine(t, db)
	if _, err := e2.Restore(ctx, basePolicy()); err != nil {
		t.Fatal(err)
	}
	if got := len(e2.Policy().Rules); got != 1 {
		t.Errorf("重启后应保持回滚后的版本，规则数 = %d（期望 1）", got)
	}
}

func TestNoStoreStillWorks(t *testing.T) {
	// 不挂 store 时（内存模式）所有操作仍应正常，只是重启即遗忘。
	e, _ := newEngine(t)
	ctx := context.Background()
	if err := e.SetPolicy(basePolicy()); err != nil {
		t.Fatal(err)
	}
	if _, err := e.Apply(ctx, ApplyOptions{}); err != nil {
		t.Fatal(err)
	}
	if err := e.Ban(ctx, model.BanEntry{IP: "203.0.113.9", ExpiresAt: time.Now().Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	if len(e.ListBans()) != 1 {
		t.Error("内存模式下封禁应仍然可用")
	}
	if entries, err := e.AuditLog(ctx, 10); err != nil || entries != nil {
		t.Errorf("无存储时审计应为空且无错误: %v %v", entries, err)
	}
}

func mustDB(t *testing.T) *store.DB {
	t.Helper()
	db, err := store.OpenMemory()
	if err != nil {
		t.Fatalf("打开内存数据库失败: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

// 回归测试：SetPolicy 曾用传入策略的 Bans 覆盖内存中的封禁列表，
// 表现为 import-policy / PUT /policy 之后"封禁看起来没了"，
// 但 ban_entries 表里还在 —— 下次重启全部复活。
func TestSetPolicyDoesNotWipeBans(t *testing.T) {
	db := mustDB(t)
	ctx := context.Background()

	e, _ := newPersistentEngine(t, db)
	if _, err := e.Restore(ctx, basePolicy()); err != nil {
		t.Fatal(err)
	}
	for _, ip := range []string{"203.0.113.9", "198.51.100.7"} {
		if err := e.Ban(ctx, model.BanEntry{IP: ip, ExpiresAt: time.Now().Add(time.Hour)}); err != nil {
			t.Fatal(err)
		}
	}

	// 传入一份不含任何封禁的策略（策略文件通常就是这样）
	next := basePolicy()
	next.Rules = append(next.Rules, model.Rule{ID: "extra", SrcZone: "wan", DstZone: "lan", Action: model.ActionDrop})
	if err := e.SetPolicy(next); err != nil {
		t.Fatal(err)
	}
	if got := len(e.ListBans()); got != 2 {
		t.Errorf("改写策略不应影响封禁，封禁数 = %d（期望 2）", got)
	}

	// 重启后也必须还是 2 条 —— 内存与数据库不能各说各话
	e2, _ := newPersistentEngine(t, db)
	if _, err := e2.Restore(ctx, basePolicy()); err != nil {
		t.Fatal(err)
	}
	if got := len(e2.ListBans()); got != 2 {
		t.Errorf("重启后封禁数 = %d（期望 2）", got)
	}
}

// 首次启动时策略文件里的封禁应当被导入封禁表。
func TestBaselineBansImportedOnFirstBoot(t *testing.T) {
	db := mustDB(t)
	ctx := context.Background()

	baseline := basePolicy()
	baseline.Bans = []model.BanEntry{
		{IP: "203.0.113.9", Reason: "来自基线", ExpiresAt: time.Now().Add(time.Hour)},
		{IP: "198.51.100.1", Reason: "已过期", ExpiresAt: time.Now().Add(-time.Minute)},
	}

	e, _ := newPersistentEngine(t, db)
	if _, err := e.Restore(ctx, baseline); err != nil {
		t.Fatal(err)
	}
	bans := e.ListBans()
	if len(bans) != 1 || bans[0].IP != "203.0.113.9" || bans[0].Reason != "来自基线" {
		t.Fatalf("首次启动应导入基线封禁（且跳过已过期的）: %+v", bans)
	}

	// 必须已落库，否则重启就丢了
	stored, err := db.LoadBans(ctx, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if len(stored) != 1 {
		t.Errorf("基线封禁未写入数据库: %+v", stored)
	}
}

// 自动封禁引擎通过 BanIP 执行封禁（实现 ban.Sink）。
func TestBanIPCreatesAutoBan(t *testing.T) {
	db := mustDB(t)
	ctx := context.Background()
	e, be := newPersistentEngine(t, db)
	if _, err := e.Restore(ctx, basePolicy()); err != nil {
		t.Fatal(err)
	}
	if _, err := e.Apply(ctx, ApplyOptions{}); err != nil {
		t.Fatal(err)
	}

	if err := e.BanIP(ctx, "203.0.113.9", "日志命中 ssh-auth-fail", 30*time.Minute); err != nil {
		t.Fatalf("BanIP 失败: %v", err)
	}

	bans := e.ListBans()
	if len(bans) != 1 {
		t.Fatalf("应产生 1 条封禁: %+v", bans)
	}
	b := bans[0]
	if b.Source != model.BanAuto {
		t.Errorf("来源应为 auto，实际 %q", b.Source)
	}
	if !strings.Contains(b.Reason, "ssh-auth-fail") {
		t.Errorf("原因应保留检测源便于追溯: %q", b.Reason)
	}
	ttl := time.Until(b.ExpiresAt)
	if ttl < 29*time.Minute || ttl > 31*time.Minute {
		t.Errorf("封禁时长应约为 30m，实际 %s", ttl)
	}

	// 应已注入内核集合
	elems, err := be.SetList(ctx, "banned4")
	if err != nil {
		t.Fatal(err)
	}
	if len(elems) != 1 || elems[0].Key != "203.0.113.9" {
		t.Errorf("未注入内核集合: %+v", elems)
	}

	// 并且落库，重启后仍在
	e2, _ := newPersistentEngine(t, db)
	if _, err := e2.Restore(ctx, basePolicy()); err != nil {
		t.Fatal(err)
	}
	if len(e2.ListBans()) != 1 {
		t.Errorf("自动封禁未持久化: %+v", e2.ListBans())
	}
}

// BanIP 未给时长时回落到默认封禁时长，而不是"永久封禁"。
func TestBanIPDefaultsTTL(t *testing.T) {
	e, _ := newEngine(t)
	ctx := context.Background()
	if err := e.SetPolicy(basePolicy()); err != nil {
		t.Fatal(err)
	}
	if err := e.BanIP(ctx, "203.0.113.9", "测试", 0); err != nil {
		t.Fatal(err)
	}
	b := e.ListBans()[0]
	if b.ExpiresAt.IsZero() {
		t.Fatal("未给时长不应变成永久封禁")
	}
	if d := time.Until(b.ExpiresAt); d < 23*time.Hour {
		t.Errorf("应回落到默认 24h，实际 %s", d)
	}
}

// 手工解封必须通知外部，否则判罚引擎窗口里的残留事件会让它立刻又被封上。
func TestUnbanFiresHook(t *testing.T) {
	e, _ := newEngine(t)
	ctx := context.Background()
	if err := e.SetPolicy(basePolicy()); err != nil {
		t.Fatal(err)
	}

	var got []string
	e.OnUnban(func(ip string) { got = append(got, ip) })

	if err := e.BanIP(ctx, "203.0.113.9", "测试", time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := e.Unban(ctx, "203.0.113.9"); err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0] != "203.0.113.9" {
		t.Errorf("解封回调未收到通知: %v", got)
	}
}

// 回归测试：audit 会被持锁的路径调用（Confirm），又被不持锁的路径调用（Update）。
// 事件钩子若在这里取锁就会自死锁 —— 表现为测试挂死到 10 分钟超时。
func TestEventHookCalledFromLockedPathDoesNotDeadlock(t *testing.T) {
	e, _ := newEngine(t)
	ctx := context.Background()
	if err := e.SetPolicy(basePolicy()); err != nil {
		t.Fatal(err)
	}

	var mu sync.Mutex
	var events []string
	e.OnEvent(func(action, _, _ string) {
		mu.Lock()
		events = append(events, action)
		mu.Unlock()
	})

	// Confirm 在持锁状态下调用 audit
	if _, err := e.Apply(ctx, ApplyOptions{WithConfirm: true, ConfirmTimeout: time.Minute}); err != nil {
		t.Fatal(err)
	}

	done := make(chan error, 1)
	go func() { done <- e.Confirm() }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Confirm 死锁：事件钩子不能在上锁路径里再取一次锁")
	}

	// 不持锁的路径同样要能触发
	if err := e.Ban(ctx, model.BanEntry{IP: "203.0.113.9", ExpiresAt: time.Now().Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}

	mu.Lock()
	defer mu.Unlock()
	var hasConfirm, hasBan bool
	for _, a := range events {
		if a == "confirm" {
			hasConfirm = true
		}
		if a == "ban.add" {
			hasBan = true
		}
	}
	if !hasConfirm || !hasBan {
		t.Errorf("事件钩子未被两条路径都触发: %v", events)
	}
}
