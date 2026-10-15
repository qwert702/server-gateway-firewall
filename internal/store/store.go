// Package store 负责期望状态的持久化。
//
// 存储划分（刻意保持简单）：
//
//	policy      —— 单行，存放完整的期望状态 JSON。策略规模有限（数百条规则也就几十 KB），
//	               整块读写让"一次修改"天然是一个事务，不会出现半截状态。
//	ban_entries —— 单独建表。封禁写入频繁、需要按到期时间查询清理，不适合塞进大 JSON。
//	audit_log   —— 只追加。记录"谁在什么时候改了什么"。
//	kv          —— 元数据，如 schema 版本、上次成功下发的哈希。
//
// 使用 modernc.org/sqlite：纯 Go，无 cgo，因此交叉编译与静态链接都不受影响。
package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"fwdd/internal/model"

	_ "modernc.org/sqlite"
)

// schemaVersion 当前结构版本，写入 PRAGMA user_version 用于迁移判断。
const schemaVersion = 1

// DB 是 SQLite 存储。
type DB struct {
	db   *sql.DB
	path string
	now  func() time.Time
}

// AuditEntry 是一条审计记录。
type AuditEntry struct {
	ID     int64     `json:"id"`
	At     time.Time `json:"at"`
	Actor  string    `json:"actor"`
	Action string    `json:"action"`
	Target string    `json:"target,omitempty"`
	Detail string    `json:"detail,omitempty"`
}

// Open 打开（必要时创建）数据库文件。
func Open(path string) (*DB, error) {
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, fmt.Errorf("创建数据目录失败: %w", err)
		}
	}
	return open("file:"+path+"?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)", path)
}

// OpenMemory 打开内存数据库（测试用）。
func OpenMemory() (*DB, error) {
	return open("file::memory:?cache=shared", ":memory:")
}

func open(dsn, path string) (*DB, error) {
	sqlDB, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("打开数据库失败: %w", err)
	}
	// SQLite 写入需要串行；限制连接数避免 "database is locked"。
	sqlDB.SetMaxOpenConns(1)
	sqlDB.SetConnMaxLifetime(0)

	d := &DB{db: sqlDB, path: path, now: time.Now}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := d.migrate(ctx); err != nil {
		sqlDB.Close()
		return nil, err
	}
	return d, nil
}

// Path 返回数据库文件路径。
func (d *DB) Path() string { return d.path }

// Close 关闭数据库。
func (d *DB) Close() error { return d.db.Close() }

func (d *DB) migrate(ctx context.Context) error {
	const schema = `
CREATE TABLE IF NOT EXISTS policy (
  id         INTEGER PRIMARY KEY CHECK (id = 1),
  hash       TEXT    NOT NULL,
  data       TEXT    NOT NULL,
  updated_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS ban_entries (
  ip         TEXT    PRIMARY KEY,
  reason     TEXT    NOT NULL DEFAULT '',
  source     TEXT    NOT NULL DEFAULT 'manual',
  added_at   INTEGER NOT NULL,
  expires_at INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS ban_expires ON ban_entries(expires_at);

CREATE TABLE IF NOT EXISTS audit_log (
  id     INTEGER PRIMARY KEY AUTOINCREMENT,
  at     INTEGER NOT NULL,
  actor  TEXT    NOT NULL DEFAULT '',
  action TEXT    NOT NULL,
  target TEXT    NOT NULL DEFAULT '',
  detail TEXT    NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS audit_at ON audit_log(at);

CREATE TABLE IF NOT EXISTS kv (
  key   TEXT PRIMARY KEY,
  value TEXT NOT NULL
);
`
	if _, err := d.db.ExecContext(ctx, schema); err != nil {
		return fmt.Errorf("初始化表结构失败: %w", err)
	}
	var ver int
	if err := d.db.QueryRowContext(ctx, "PRAGMA user_version").Scan(&ver); err != nil {
		return fmt.Errorf("读取 schema 版本失败: %w", err)
	}
	if ver > schemaVersion {
		return fmt.Errorf("数据库结构版本 %d 高于本程序支持的 %d，请升级 fwdd", ver, schemaVersion)
	}
	if ver < schemaVersion {
		if _, err := d.db.ExecContext(ctx, fmt.Sprintf("PRAGMA user_version = %d", schemaVersion)); err != nil {
			return fmt.Errorf("写入 schema 版本失败: %w", err)
		}
	}
	return nil
}

// ---- 策略 ----

// ErrNoPolicy 表示数据库中还没有保存过策略。
var ErrNoPolicy = errors.New("store: 尚未保存过策略")

// SavePolicy 覆盖保存期望状态。
func (d *DB) SavePolicy(ctx context.Context, p *model.Policy) error {
	data, err := json.Marshal(p)
	if err != nil {
		return fmt.Errorf("序列化策略失败: %w", err)
	}
	sum := sha256.Sum256(data)
	_, err = d.db.ExecContext(ctx,
		`INSERT INTO policy (id, hash, data, updated_at) VALUES (1, ?, ?, ?)
		 ON CONFLICT(id) DO UPDATE SET hash=excluded.hash, data=excluded.data, updated_at=excluded.updated_at`,
		hex.EncodeToString(sum[:8]), string(data), d.now().Unix())
	if err != nil {
		return fmt.Errorf("保存策略失败: %w", err)
	}
	return nil
}

// LoadPolicy 读取期望状态；从未保存过时返回 ErrNoPolicy。
func (d *DB) LoadPolicy(ctx context.Context) (*model.Policy, error) {
	var data string
	err := d.db.QueryRowContext(ctx, "SELECT data FROM policy WHERE id = 1").Scan(&data)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNoPolicy
	}
	if err != nil {
		return nil, fmt.Errorf("读取策略失败: %w", err)
	}
	var p model.Policy
	if err := json.Unmarshal([]byte(data), &p); err != nil {
		return nil, fmt.Errorf("策略数据已损坏: %w", err)
	}
	return &p, nil
}

// HasPolicy 报告是否保存过策略。
func (d *DB) HasPolicy(ctx context.Context) bool {
	var n int
	if err := d.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM policy").Scan(&n); err != nil {
		return false
	}
	return n > 0
}

// ---- 封禁 ----

// UpsertBan 写入或更新一条封禁。
func (d *DB) UpsertBan(ctx context.Context, b model.BanEntry) error {
	_, err := d.db.ExecContext(ctx,
		`INSERT INTO ban_entries (ip, reason, source, added_at, expires_at) VALUES (?, ?, ?, ?, ?)
		 ON CONFLICT(ip) DO UPDATE SET reason=excluded.reason, source=excluded.source,
		   added_at=excluded.added_at, expires_at=excluded.expires_at`,
		b.IP, b.Reason, string(b.Source), toUnix(b.AddedAt), toUnix(b.ExpiresAt))
	if err != nil {
		return fmt.Errorf("保存封禁失败: %w", err)
	}
	return nil
}

// DeleteBan 删除一条封禁。删除不存在的记录不算错误（解封应幂等）。
func (d *DB) DeleteBan(ctx context.Context, ip string) error {
	if _, err := d.db.ExecContext(ctx, "DELETE FROM ban_entries WHERE ip = ?", ip); err != nil {
		return fmt.Errorf("解封失败: %w", err)
	}
	return nil
}

// LoadBans 读取全部未过期封禁。
func (d *DB) LoadBans(ctx context.Context, now time.Time) ([]model.BanEntry, error) {
	rows, err := d.db.QueryContext(ctx,
		`SELECT ip, reason, source, added_at, expires_at FROM ban_entries
		 WHERE expires_at = 0 OR expires_at > ? ORDER BY added_at DESC`, now.Unix())
	if err != nil {
		return nil, fmt.Errorf("读取封禁列表失败: %w", err)
	}
	defer rows.Close()

	var out []model.BanEntry
	for rows.Next() {
		var (
			ip, reason, source string
			addedAt, expiresAt int64
		)
		if err := rows.Scan(&ip, &reason, &source, &addedAt, &expiresAt); err != nil {
			return nil, fmt.Errorf("解析封禁记录失败: %w", err)
		}
		out = append(out, model.BanEntry{
			IP:        ip,
			Reason:    reason,
			Source:    model.BanSource(source),
			AddedAt:   fromUnix(addedAt),
			ExpiresAt: fromUnix(expiresAt),
		})
	}
	return out, rows.Err()
}

// PruneExpiredBans 删除已过期封禁，返回删除条数。
//
// 内核里的封禁集合靠 timeout 自动到期，但 SQLite 不会，需要定期清理，
// 否则重启时会把早已过期的封禁重新注入回去。
func (d *DB) PruneExpiredBans(ctx context.Context, now time.Time) (int64, error) {
	res, err := d.db.ExecContext(ctx,
		"DELETE FROM ban_entries WHERE expires_at != 0 AND expires_at <= ?", now.Unix())
	if err != nil {
		return 0, fmt.Errorf("清理过期封禁失败: %w", err)
	}
	n, _ := res.RowsAffected()
	return n, nil
}

// ---- 审计 ----

// AppendAudit 追加一条审计记录。
func (d *DB) AppendAudit(ctx context.Context, e AuditEntry) error {
	if e.At.IsZero() {
		e.At = d.now()
	}
	_, err := d.db.ExecContext(ctx,
		"INSERT INTO audit_log (at, actor, action, target, detail) VALUES (?, ?, ?, ?, ?)",
		e.At.Unix(), e.Actor, e.Action, e.Target, e.Detail)
	if err != nil {
		return fmt.Errorf("写入审计记录失败: %w", err)
	}
	return nil
}

// ListAudit 返回最近的审计记录（倒序）。
func (d *DB) ListAudit(ctx context.Context, limit int) ([]AuditEntry, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := d.db.QueryContext(ctx,
		"SELECT id, at, actor, action, target, detail FROM audit_log ORDER BY id DESC LIMIT ?", limit)
	if err != nil {
		return nil, fmt.Errorf("读取审计记录失败: %w", err)
	}
	defer rows.Close()

	var out []AuditEntry
	for rows.Next() {
		var (
			e  AuditEntry
			at int64
		)
		if err := rows.Scan(&e.ID, &at, &e.Actor, &e.Action, &e.Target, &e.Detail); err != nil {
			return nil, fmt.Errorf("解析审计记录失败: %w", err)
		}
		e.At = fromUnix(at)
		out = append(out, e)
	}
	return out, rows.Err()
}

// ---- 元数据 ----

// PutKV 写入元数据。
func (d *DB) PutKV(ctx context.Context, key, value string) error {
	_, err := d.db.ExecContext(ctx,
		"INSERT INTO kv (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
		key, value)
	return err
}

// GetKV 读取元数据；不存在时返回空串。
func (d *DB) GetKV(ctx context.Context, key string) (string, error) {
	var v string
	err := d.db.QueryRowContext(ctx, "SELECT value FROM kv WHERE key = ?", key).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	return v, nil
}

// ---- 工具 ----

// 时间统一按 Unix 秒存储；零值（永久封禁）存 0。
func toUnix(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.Unix()
}

func fromUnix(v int64) time.Time {
	if v == 0 {
		return time.Time{}
	}
	return time.Unix(v, 0)
}
