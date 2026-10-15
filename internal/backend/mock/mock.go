// Package mock 是 Backend 的内存实现。
//
// 用途：
//   - 单元测试（验证编译器输出、幂等性、diff）；
//   - 在非 Linux / 无 root 的开发机上运行 fwdd 演示与联调 REST API。
//
// 它忠实地"应用"快照（保存最新状态）并支持动态集合运算，但绝不触碰内核。
package mock

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync"
	"time"

	"fwdd/internal/backend"
	"fwdd/internal/ir"
)

// Backend 是内存后端。
type Backend struct {
	mu sync.RWMutex

	tableName string
	applied   *ir.Snapshot
	text      string
	history   []ApplyRecord
	// sets 是运行时集合元素（封禁注入的落地处），并记录插入时间以模拟 timeout。
	sets map[string][]setEntry
	now  func() time.Time

	applyCount int
	failNext   error
}

// setEntry 是集合元素及其插入时间。内核用 timeout 到期自动移除元素，
// mock 没有内核定时器，因此显式记录插入时间，在读取时判断是否过期。
type setEntry struct {
	el      ir.Element
	addedAt time.Time
}

// ApplyRecord 记录一次下发。
type ApplyRecord struct {
	At        time.Time `json:"at"`
	Rules     int       `json:"rules"`
	Chains    int       `json:"chains"`
	Hash      string    `json:"hash"`
	Changed   bool      `json:"changed"`
	TableName string    `json:"table"`
}

// Option 配置 mock 后端。
type Option func(*Backend)

// WithTableName 指定逻辑表名。
func WithTableName(name string) Option { return func(b *Backend) { b.tableName = name } }

// WithClock 注入时钟（测试用）。
func WithClock(now func() time.Time) Option { return func(b *Backend) { b.now = now } }

// New 创建内存后端。
func New(opts ...Option) *Backend {
	b := &Backend{
		tableName: "fw",
		sets:      map[string][]setEntry{},
		now:       time.Now,
	}
	for _, o := range opts {
		o(b)
	}
	return b
}

// Name 实现 backend.Backend。
func (b *Backend) Name() string { return "mock" }

// FailNext 让下一次 Apply 返回给定错误（测试回滚路径）。
func (b *Backend) FailNext(err error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.failNext = err
}

// Apply 实现 backend.Backend。
func (b *Backend) Apply(ctx context.Context, s *ir.Snapshot) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	text, err := b.Render(ctx, s)
	if err != nil {
		return err
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	if b.failNext != nil {
		err := b.failNext
		b.failNext = nil
		return fmt.Errorf("mock: 注入的失败: %w", err)
	}

	hash := hashOf(text)
	changed := b.text != text
	b.applied = clone(s)
	b.text = text
	b.applyCount++
	b.history = append(b.history, ApplyRecord{
		At:        b.now(),
		Rules:     s.RuleCount(),
		Chains:    countChains(s),
		Hash:      hash,
		Changed:   changed,
		TableName: b.tableName,
	})

	// 应用快照中的集合元素（保留运行时新增的元素）。
	for _, t := range s.Tables {
		for _, set := range t.Sets {
			existing := b.sets[set.Name]
			merged := mergeElements(existing, set.Elements, b.now())
			b.sets[set.Name] = merged
		}
	}
	return nil
}

// Render 实现 backend.Backend：仅渲染，不改变状态。
func (b *Backend) Render(ctx context.Context, s *ir.Snapshot) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	return s.Render(), nil
}

// State 实现 backend.Backend。
func (b *Backend) State(ctx context.Context) (*backend.RuntimeState, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	b.mu.RLock()
	defer b.mu.RUnlock()

	st := &backend.RuntimeState{
		Backend: "mock",
		Table:   b.tableName,
		Text:    b.text,
		Hash:    hashOf(b.text),
	}
	if b.text == "" {
		st.Note = "尚未下发任何规则（mock 后端为空）"
	}
	for _, t := range b.appliedTables() {
		for _, c := range t.Chains {
			st.Chains = append(st.Chains, backend.ChainInfo{
				Name:     c.Name,
				Type:     string(c.Type),
				Hook:     string(c.Hook),
				Priority: fmt.Sprintf("%d", c.Priority),
				Policy:   c.Policy,
				Rules:    len(c.Rules),
			})
		}
		for _, set := range t.Sets {
			st.Sets = append(st.Sets, backend.SetInfo{
				Name:     set.Name,
				KeyType:  set.KeyType,
				Flags:    set.Flags,
				Elements: len(b.sets[set.Name]),
			})
		}
	}
	return st, nil
}

// Reset 实现 backend.Backend：回到"从未下发过"的状态。
func (b *Backend) Reset(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.applied = nil
	b.text = ""
	b.sets = map[string][]setEntry{}
	b.history = append(b.history, ApplyRecord{
		At: b.now(), Changed: true, TableName: b.tableName, Hash: hashOf(""),
	})
	return nil
}

// SetAdd 实现 backend.Backend。
func (b *Backend) SetAdd(ctx context.Context, set string, elems ...ir.Element) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	now := b.now()
	out := b.sets[set]
	for _, e := range elems {
		out = upsertElement(out, e, now)
	}
	b.sets[set] = out
	return nil
}

// SetDel 实现 backend.Backend。
func (b *Backend) SetDel(ctx context.Context, set string, keys ...string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	drop := make(map[string]bool, len(keys))
	for _, k := range keys {
		drop[k] = true
	}
	var out []setEntry
	for _, e := range b.sets[set] {
		if !drop[e.el.Key] {
			out = append(out, e)
		}
	}
	b.sets[set] = out
	return nil
}

// SetList 实现 backend.Backend：顺带清理已过期元素，模拟内核 timeout 语义。
func (b *Backend) SetList(ctx context.Context, set string) ([]ir.Element, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	now := b.now()
	var live []setEntry
	var out []ir.Element
	for _, e := range b.sets[set] {
		if e.el.Timeout > 0 && !now.Before(e.addedAt.Add(e.el.Timeout)) {
			continue
		}
		live = append(live, e)
		out = append(out, e.el)
	}
	b.sets[set] = live
	return out, nil
}

// Close 实现 backend.Backend。
func (b *Backend) Close() error { return nil }

// Applied 返回最近一次成功下发的快照（副本）。
func (b *Backend) Applied() *ir.Snapshot {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return clone(b.applied)
}

// History 返回下发历史。
func (b *Backend) History() []ApplyRecord {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return append([]ApplyRecord(nil), b.history...)
}

// ApplyCount 返回成功下发次数。
func (b *Backend) ApplyCount() int {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.applyCount
}

func (b *Backend) appliedTables() []*ir.Table {
	if b.applied == nil {
		return nil
	}
	return b.applied.Tables
}

// ---- 内部工具 ----

func mergeElements(existing []setEntry, incoming []ir.Element, now time.Time) []setEntry {
	out := append([]setEntry(nil), existing...)
	for _, e := range incoming {
		out = upsertElement(out, e, now)
	}
	return out
}

func upsertElement(list []setEntry, e ir.Element, now time.Time) []setEntry {
	for i := range list {
		if list[i].el.Key == e.Key {
			list[i] = setEntry{el: e, addedAt: now}
			return list
		}
	}
	return append(list, setEntry{el: e, addedAt: now})
}

func countChains(s *ir.Snapshot) int {
	n := 0
	for _, t := range s.Tables {
		n += len(t.Chains)
	}
	return n
}

func hashOf(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:8])
}

func clone(s *ir.Snapshot) *ir.Snapshot {
	if s == nil {
		return nil
	}
	out := &ir.Snapshot{}
	for _, t := range s.Tables {
		nt := &ir.Table{Family: t.Family, Name: t.Name}
		for _, set := range t.Sets {
			ns := *set
			ns.Elements = append([]ir.Element(nil), set.Elements...)
			ns.Flags = append([]string(nil), set.Flags...)
			nt.Sets = append(nt.Sets, &ns)
		}
		for _, c := range t.Chains {
			nc := *c
			nc.Rules = nil
			for _, r := range c.Rules {
				nr := *r
				nr.Matches = append([]ir.Match(nil), r.Matches...)
				nr.Stmts = append([]ir.Statement(nil), r.Stmts...)
				nc.Rules = append(nc.Rules, &nr)
			}
			nt.Chains = append(nt.Chains, &nc)
		}
		out.Tables = append(out.Tables, nt)
	}
	return out
}
