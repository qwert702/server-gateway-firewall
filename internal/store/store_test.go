package store

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"fwdd/internal/model"
)

func newDB(t *testing.T) *DB {
	t.Helper()
	db, err := OpenMemory()
	if err != nil {
		t.Fatalf("打开内存数据库失败: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func samplePolicy() *model.Policy {
	return &model.Policy{
		Version: 1,
		Zones: []model.Zone{
			{Name: "lan", Interfaces: []string{"eth1"}, Trust: model.TrustLAN},
			{Name: "wan", Interfaces: []string{"eth0"}, Trust: model.TrustUntrusted},
		},
		Rules: []model.Rule{
			{ID: "a", Priority: 100, SrcZone: "lan", DstZone: "wan", Action: model.ActionAccept},
			{ID: "b", Priority: 200, SrcZone: "wan", DstZone: "lan", Proto: model.ProtoTCP,
				DstPort: []string{"22"}, Action: model.ActionReject, Reject: model.RejectTCPReset},
		},
		NATRules: []model.NATRule{
			{ID: "n1", Kind: model.NATMasquerade, OutZone: "wan"},
		},
		Default: model.DefaultPolicy{Forward: model.ActionDrop},
	}
}

func TestLoadPolicyBeforeSaveReportsNotFound(t *testing.T) {
	db := newDB(t)
	_, err := db.LoadPolicy(context.Background())
	if !errors.Is(err, ErrNoPolicy) {
		t.Fatalf("应为 ErrNoPolicy，实际: %v", err)
	}
	if db.HasPolicy(context.Background()) {
		t.Error("HasPolicy 应为 false")
	}
}

func TestSaveAndLoadPolicyRoundTrip(t *testing.T) {
	db := newDB(t)
	ctx := context.Background()
	want := samplePolicy()

	if err := db.SavePolicy(ctx, want); err != nil {
		t.Fatalf("保存失败: %v", err)
	}
	if !db.HasPolicy(ctx) {
		t.Error("HasPolicy 应为 true")
	}

	got, err := db.LoadPolicy(ctx)
	if err != nil {
		t.Fatalf("读取失败: %v", err)
	}
	if got.Version != want.Version || len(got.Zones) != 2 || len(got.Rules) != 2 || len(got.NATRules) != 1 {
		t.Fatalf("往返后结构不一致: %+v", got)
	}
	r := got.Rules[1]
	if r.Proto != model.ProtoTCP || r.Reject != model.RejectTCPReset || len(r.DstPort) != 1 || r.DstPort[0] != "22" {
		t.Errorf("规则字段丢失: %+v", r)
	}
	if got.Rules[0].IsEnabled() != true {
		t.Error("enabled 缺省应保持为启用")
	}
	if got.Default.Forward != model.ActionDrop {
		t.Errorf("默认策略丢失: %+v", got.Default)
	}
}

func TestSavePolicyOverwritesInsteadOfAppending(t *testing.T) {
	db := newDB(t)
	ctx := context.Background()
	if err := db.SavePolicy(ctx, samplePolicy()); err != nil {
		t.Fatal(err)
	}
	second := samplePolicy()
	second.Rules = second.Rules[:1]
	if err := db.SavePolicy(ctx, second); err != nil {
		t.Fatal(err)
	}
	got, err := db.LoadPolicy(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Rules) != 1 {
		t.Errorf("策略应被覆盖而非追加，规则数 = %d", len(got.Rules))
	}
}

func TestBanLifecycle(t *testing.T) {
	db := newDB(t)
	ctx := context.Background()
	now := time.Now()

	entries := []model.BanEntry{
		{IP: "203.0.113.9", Reason: "爆破", Source: model.BanManual, AddedAt: now, ExpiresAt: now.Add(time.Hour)},
		{IP: "2001:db8::dead", Reason: "扫描", Source: model.BanConntrack, AddedAt: now, ExpiresAt: now.Add(30 * time.Minute)},
		{IP: "198.51.100.1", Reason: "永久", AddedAt: now}, // 零值 ExpiresAt = 永久
	}
	for _, e := range entries {
		if err := db.UpsertBan(ctx, e); err != nil {
			t.Fatalf("写入封禁 %s 失败: %v", e.IP, err)
		}
	}

	got, err := db.LoadBans(ctx, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 {
		t.Fatalf("应读到 3 条封禁，实际 %d", len(got))
	}

	byIP := map[string]model.BanEntry{}
	for _, b := range got {
		byIP[b.IP] = b
	}
	if b := byIP["2001:db8::dead"]; b.Source != model.BanConntrack {
		t.Errorf("来源未保留: %+v", b)
	}
	if b := byIP["198.51.100.1"]; !b.ExpiresAt.IsZero() {
		t.Errorf("永久封禁的到期时间应为零值: %+v", b)
	}
	if b := byIP["203.0.113.9"]; b.ExpiresAt.IsZero() {
		t.Errorf("到期时间未保留: %+v", b)
	}

	// 更新同一条封禁应覆盖而非插入
	upd := model.BanEntry{IP: "203.0.113.9", Reason: "改判", AddedAt: now, ExpiresAt: now.Add(2 * time.Hour)}
	if err := db.UpsertBan(ctx, upd); err != nil {
		t.Fatal(err)
	}
	got, _ = db.LoadBans(ctx, now)
	if len(got) != 3 {
		t.Errorf("更新不应新增记录，实际 %d 条", len(got))
	}
}

func TestLoadBansSkipsExpired(t *testing.T) {
	db := newDB(t)
	ctx := context.Background()
	now := time.Now()

	if err := db.UpsertBan(ctx, model.BanEntry{IP: "203.0.113.1", ExpiresAt: now.Add(-time.Minute)}); err != nil {
		t.Fatal(err)
	}
	if err := db.UpsertBan(ctx, model.BanEntry{IP: "203.0.113.2", ExpiresAt: now.Add(time.Minute)}); err != nil {
		t.Fatal(err)
	}

	got, err := db.LoadBans(ctx, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].IP != "203.0.113.2" {
		t.Errorf("已过期封禁不应被读出: %+v", got)
	}
}

func TestPruneExpiredBans(t *testing.T) {
	db := newDB(t)
	ctx := context.Background()
	now := time.Now()

	for _, e := range []model.BanEntry{
		{IP: "203.0.113.1", ExpiresAt: now.Add(-time.Hour)},
		{IP: "203.0.113.2", ExpiresAt: now.Add(-time.Second)},
		{IP: "203.0.113.3", ExpiresAt: now.Add(time.Hour)},
		{IP: "203.0.113.4"}, // 永久，绝不能被清理
	} {
		if err := db.UpsertBan(ctx, e); err != nil {
			t.Fatal(err)
		}
	}

	n, err := db.PruneExpiredBans(ctx, now)
	if err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Errorf("应清理 2 条，实际 %d", n)
	}
	got, _ := db.LoadBans(ctx, now)
	if len(got) != 2 {
		t.Fatalf("清理后应剩 2 条，实际 %d: %+v", len(got), got)
	}
	for _, b := range got {
		if b.IP == "203.0.113.4" && !b.ExpiresAt.IsZero() {
			t.Error("永久封禁被错误地改动")
		}
	}
}

func TestDeleteBanIsIdempotent(t *testing.T) {
	db := newDB(t)
	ctx := context.Background()
	if err := db.DeleteBan(ctx, "203.0.113.9"); err != nil {
		t.Errorf("删除不存在的封禁不应报错: %v", err)
	}
	if err := db.UpsertBan(ctx, model.BanEntry{IP: "203.0.113.9"}); err != nil {
		t.Fatal(err)
	}
	if err := db.DeleteBan(ctx, "203.0.113.9"); err != nil {
		t.Fatal(err)
	}
	got, _ := db.LoadBans(ctx, time.Now())
	if len(got) != 0 {
		t.Errorf("删除后不应还有记录: %+v", got)
	}
}

func TestAuditAppendAndList(t *testing.T) {
	db := newDB(t)
	ctx := context.Background()

	for i := 0; i < 5; i++ {
		if err := db.AppendAudit(ctx, AuditEntry{
			Actor: "tester", Action: "apply", Target: "fw", Detail: "x",
		}); err != nil {
			t.Fatal(err)
		}
	}
	got, err := db.ListAudit(ctx, 3)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 {
		t.Fatalf("limit=3 应返回 3 条，实际 %d", len(got))
	}
	// 倒序：后写入的在前
	if got[0].ID <= got[1].ID {
		t.Errorf("审计记录应按时间倒序: %+v", got)
	}
	if got[0].Actor != "tester" || got[0].Action != "apply" {
		t.Errorf("字段丢失: %+v", got[0])
	}
	if got[0].At.IsZero() {
		t.Error("未填写时间时应自动补上")
	}
}

func TestKV(t *testing.T) {
	db := newDB(t)
	ctx := context.Background()

	v, err := db.GetKV(ctx, "missing")
	if err != nil {
		t.Fatalf("读取不存在的键不应报错: %v", err)
	}
	if v != "" {
		t.Errorf("不存在的键应返回空串，实际 %q", v)
	}
	if err := db.PutKV(ctx, "applied_hash", "abc123"); err != nil {
		t.Fatal(err)
	}
	if err := db.PutKV(ctx, "applied_hash", "def456"); err != nil {
		t.Fatal(err)
	}
	if v, _ = db.GetKV(ctx, "applied_hash"); v != "def456" {
		t.Errorf("应覆盖旧值，实际 %q", v)
	}
}

// 这是本包存在的根本理由：重启后数据必须还在。
func TestDataSurvivesReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fwdd.db")
	ctx := context.Background()
	now := time.Now()

	db, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.SavePolicy(ctx, samplePolicy()); err != nil {
		t.Fatal(err)
	}
	if err := db.UpsertBan(ctx, model.BanEntry{IP: "203.0.113.9", Reason: "爆破",
		Source: model.BanManual, AddedAt: now, ExpiresAt: now.Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	if err := db.PutKV(ctx, "applied_hash", "deadbeef"); err != nil {
		t.Fatal(err)
	}
	if err := db.AppendAudit(ctx, AuditEntry{Action: "apply"}); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	// 模拟进程重启
	db2, err := Open(path)
	if err != nil {
		t.Fatalf("重新打开失败: %v", err)
	}
	defer db2.Close()

	p, err := db2.LoadPolicy(ctx)
	if err != nil {
		t.Fatalf("重启后读不到策略: %v", err)
	}
	if len(p.Rules) != 2 {
		t.Errorf("重启后规则数 = %d, 期望 2", len(p.Rules))
	}

	bans, err := db2.LoadBans(ctx, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(bans) != 1 || bans[0].IP != "203.0.113.9" || bans[0].Reason != "爆破" {
		t.Errorf("重启后封禁丢失: %+v", bans)
	}

	if v, _ := db2.GetKV(ctx, "applied_hash"); v != "deadbeef" {
		t.Errorf("重启后元数据丢失: %q", v)
	}
	audit, _ := db2.ListAudit(ctx, 10)
	if len(audit) != 1 {
		t.Errorf("重启后审计丢失: %+v", audit)
	}
}

func TestSchemaVersionIsRecorded(t *testing.T) {
	db := newDB(t)
	var ver int
	if err := db.db.QueryRow("PRAGMA user_version").Scan(&ver); err != nil {
		t.Fatal(err)
	}
	if ver != schemaVersion {
		t.Errorf("user_version = %d, 期望 %d", ver, schemaVersion)
	}
}

// 打开一个版本高于本程序的数据库必须明确失败，而不是继续写入污染数据。
func TestRejectsFutureSchema(t *testing.T) {
	path := filepath.Join(t.TempDir(), "future.db")
	db, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.db.Exec("PRAGMA user_version = 999"); err != nil {
		t.Fatal(err)
	}
	db.Close()

	if _, err := Open(path); err == nil {
		t.Fatal("更高版本的数据库结构应被拒绝")
	}
}

func TestConcurrentBansDoNotCorrupt(t *testing.T) {
	db := newDB(t)
	ctx := context.Background()
	now := time.Now()

	done := make(chan struct{})
	for w := 0; w < 4; w++ {
		go func(w int) {
			defer func() { done <- struct{}{} }()
			for i := 0; i < 20; i++ {
				ip := "198.51.100." + string(rune('0'+w)) + string(rune('0'+i%10))
				if err := db.UpsertBan(ctx, model.BanEntry{IP: ip, ExpiresAt: now.Add(time.Hour)}); err != nil {
					t.Errorf("并发写入失败: %v", err)
					return
				}
			}
		}(w)
	}
	for w := 0; w < 4; w++ {
		<-done
	}
	if _, err := db.LoadBans(ctx, now); err != nil {
		t.Fatalf("并发写入后读取失败: %v", err)
	}
}
