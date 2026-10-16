// Package engine 是守护进程的核心：持有期望状态，驱动编译与下发，
// 并实现 commit-confirm 这一"防止把自己锁死在门外"的兜底机制。
//
// 状态模型：
//
//	desired        用户期望的策略（可能尚未下发）
//	applied        内核中当前生效的策略
//	rollbackTarget 处于 commit-confirm 窗口时的回滚目标（=下发前的 applied）
//
// 写路径：SetPolicy 只改 desired；Apply/Commit 才把 desired 编译并下发内核。
package engine

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"fwdd/internal/backend"
	"fwdd/internal/compiler"
	"fwdd/internal/config"
	"fwdd/internal/ir"
	"fwdd/internal/model"
	"fwdd/internal/store"
)

// ErrPendingCommit 表示已有一个 commit-confirm 在等待确认。
var ErrPendingCommit = errors.New("存在待确认的变更，请先 confirm 或等待自动回滚")

// ErrNoRollback 表示没有可回滚的目标。
var ErrNoRollback = errors.New("没有可回滚的历史版本")

// Engine 是防火墙的状态机。
type Engine struct {
	mu sync.Mutex

	cfg     config.Config
	backend backend.Backend
	copts   compiler.Options
	log     *slog.Logger
	clock   func() time.Time
	// db 为 nil 时表示不持久化（纯内存运行，重启即遗忘）。
	db *store.DB

	desired  *model.Policy
	applied  *model.Policy
	prev     *model.Policy
	hasState bool // applied/prev 是否代表真实下发过的状态

	appliedHash string
	pending     *PendingCommit
	// 待确认变更被回滚时的目标；targetValid 为 false 表示"当时还没有任何规则"，
	// 此时正确的撤销是撤掉整张表而非下发空策略。
	pendingTarget      *model.Policy
	pendingTargetValid bool
	revisions          []Revision
	seq                int

	// actor 记录当前操作的发起者，写入审计日志。
	actor string

	// onAutoRollback 在自动回滚发生后被调用（用于审计/告警）。
	onAutoRollback func(to *model.Policy)

	// onUnban 在手工解封后通知外部（自动封禁引擎据此清空计数窗口）。
	onUnban func(ip string)

	// onEvent 把审计动作实时推给事件流（Web 界面的实时视图）。
	// 用原子指针而不是普通字段 + 锁：audit() 既会在持锁时被调用（Confirm），
	// 也会在不持锁时被调用，若这里再取一次 e.mu 就会自死锁。
	onEvent atomic.Pointer[func(action, target, detail string)]
}

// Option 配置引擎。
type Option func(*Engine)

// WithStore 挂载持久化存储。
func WithStore(db *store.DB) Option { return func(e *Engine) { e.db = db } }

// WithLogger 指定日志器。
func WithLogger(l *slog.Logger) Option {
	return func(e *Engine) {
		if l != nil {
			e.log = l
		}
	}
}

// WithClock 注入时钟（测试用）。
func WithClock(fn func() time.Time) Option {
	return func(e *Engine) {
		if fn != nil {
			e.clock = fn
		}
	}
}

// WithActor 设置审计记录中的操作者标识。
func WithActor(actor string) Option { return func(e *Engine) { e.actor = actor } }

// PendingCommit 描述一个等待确认的变更。
type PendingCommit struct {
	Deadline time.Time `json:"deadline"`
	At       time.Time `json:"at"`
	Hash     string    `json:"hash"`
	Rules    int       `json:"rules"`
}

// Revision 是一次成功下发的历史记录。
type Revision struct {
	Seq   int       `json:"seq"`
	At    time.Time `json:"at"`
	Hash  string    `json:"hash"`
	Rules int       `json:"rules"`
	Note  string    `json:"note"`
}

// New 创建引擎。
func New(cfg config.Config, b backend.Backend, logger *slog.Logger, opts ...Option) *Engine {
	if logger == nil {
		logger = slog.Default()
	}
	e := &Engine{
		cfg:     cfg,
		backend: b,
		log:     logger,
		clock:   time.Now,
		actor:   "local",
		copts: compiler.Options{
			TableName:         cfg.Table,
			Family:            ir.Family(cfg.Family),
			BanSet4:           "banned4",
			BanSet6:           "banned6",
			BanTimeout:        24 * time.Hour,
			ConntrackFastPath: true,
			Counters:          true,
		},
		desired: &model.Policy{},
	}
	for _, opt := range opts {
		opt(e)
	}
	return e
}

// Options 返回编译选项（供外部构造 dry-run 时复用）。
func (e *Engine) Options() compiler.Options { return e.copts }

// Backend 返回后端。
func (e *Engine) Backend() backend.Backend { return e.backend }

// Store 返回持久化存储；未配置时为 nil。
func (e *Engine) Store() *store.DB { return e.db }

// ---- 持久化 ----

// persistTimeout 限制单次持久化耗时，避免磁盘异常时拖住整个管理接口。
const persistTimeout = 5 * time.Second

// persistPolicyLocked 保存期望状态。调用方必须持有 e.mu。
//
// 封禁项会被剔除后再存：它们由 store 的 ban_entries 表单独管理
// （写入频繁、需按到期时间查询）。两份副本必然漂移，因此只保留一份。
//
// 写入失败不回滚内存状态：内存与磁盘不一致时，宁可让当前会话继续可用，
// 也要留下明确的错误日志。
func (e *Engine) persistPolicyLocked() {
	if e.db == nil {
		return
	}
	p := deepCopy(e.desired)
	p.Bans = nil

	ctx, cancel := context.WithTimeout(context.Background(), persistTimeout)
	defer cancel()
	if err := e.db.SavePolicy(ctx, p); err != nil {
		e.log.Error("保存期望状态失败", "err", err)
	}
}

// persistBan 写入封禁记录。
func (e *Engine) persistBan(ctx context.Context, b model.BanEntry) {
	if e.db == nil {
		return
	}
	if err := e.db.UpsertBan(ctx, b); err != nil {
		e.log.Error("保存封禁失败", "err", err, "ip", b.IP)
	}
}

// forgetBan 删除封禁记录。
func (e *Engine) forgetBan(ctx context.Context, ip string) {
	if e.db == nil {
		return
	}
	if err := e.db.DeleteBan(ctx, ip); err != nil {
		e.log.Error("删除封禁记录失败", "err", err, "ip", ip)
	}
}

// audit 记录一条审计日志。db 为 nil 时静默跳过。
func (e *Engine) audit(action, target, detail string) {

	if fn := e.eventHook(); fn != nil {
		fn(action, target, detail)
	}
	if e.db == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), persistTimeout)
	defer cancel()
	err := e.db.AppendAudit(ctx, store.AuditEntry{
		At:     e.clock(),
		Actor:  e.actor,
		Action: action,
		Target: target,
		Detail: detail,
	})
	if err != nil {
		e.log.Error("写入审计日志失败", "err", err, "action", action)
	}
}

// AuditLog 返回最近的审计记录。
func (e *Engine) AuditLog(ctx context.Context, limit int) ([]store.AuditEntry, error) {
	if e.db == nil {
		return nil, nil
	}
	return e.db.ListAudit(ctx, limit)
}

// Restore 从存储加载期望状态与封禁，用于进程启动。
//
// 优先级：数据库中的策略 > 传入的基线（策略文件）。
// 数据库记录的是管理员最近一次编辑的结果，不应该被一个陈旧的文件覆盖；
// 策略文件只在数据库为空（首次启动）时充当初始值。
//
// 返回是否从数据库加载了策略。
func (e *Engine) Restore(ctx context.Context, baseline *model.Policy) (fromDB bool, err error) {
	if e.db == nil {
		if baseline == nil {
			return false, nil
		}
		// 无持久化时，策略文件就是唯一的真相来源，封禁直接采用文件里的。
		np, err := e.prepare(baseline)
		if err != nil {
			return false, err
		}
		e.mu.Lock()
		e.desired = np
		e.mu.Unlock()
		return false, nil
	}

	// 清理早已过期的封禁：内核靠 timeout 自动到期，SQLite 不会，
	// 不清理就会在每次重启时把它们重新注入回去。
	if n, err := e.db.PruneExpiredBans(ctx, e.clock()); err != nil {
		e.log.Warn("清理过期封禁失败", "err", err)
	} else if n > 0 {
		e.log.Info("已清理过期封禁", "count", n)
	}

	p, err := e.db.LoadPolicy(ctx)
	switch {
	case errors.Is(err, store.ErrNoPolicy):
		if baseline == nil {
			e.log.Warn("数据库与策略文件均为空，期望状态为空（只有默认策略生效）")
			return false, nil
		}
		np, err := e.prepare(baseline)
		if err != nil {
			return false, fmt.Errorf("初始策略校验失败: %w", err)
		}
		// 首次启动才采用策略文件里的封禁列表，写入 ban_entries 成为权威副本。
		seeded := 0
		for _, b := range np.Bans {
			if b.Expired(e.clock()) {
				continue
			}
			if err := e.db.UpsertBan(ctx, b); err != nil {
				return false, fmt.Errorf("导入基线封禁失败: %w", err)
			}
			seeded++
		}
		bans, err := e.db.LoadBans(ctx, e.clock())
		if err != nil {
			return false, err
		}

		e.mu.Lock()
		np.Bans = bans
		e.desired = np
		e.persistPolicyLocked()
		e.mu.Unlock()

		e.audit("policy.init", "", fmt.Sprintf("来自策略文件 rules=%d bans=%d", len(np.Rules), seeded))
		e.log.Info("首次启动：已用策略文件初始化数据库",
			"rules", len(np.Rules), "bans", seeded)
		return false, nil
	case err != nil:
		return false, err
	}

	bans, err := e.db.LoadBans(ctx, e.clock())
	if err != nil {
		return false, err
	}
	np, err := e.prepare(p)
	if err != nil {
		return false, fmt.Errorf("数据库中的策略已不合法（可能来自旧版本）: %w", err)
	}

	// 直接落状态而不是走 SetPolicy：后者会保留当前内存中的封禁列表，
	// 而此刻要的正是刚刚从库里读出来的那一份。
	e.mu.Lock()
	np.Bans = bans
	e.desired = np
	e.mu.Unlock()

	e.log.Info("已从数据库恢复期望状态",
		"zones", len(np.Zones), "rules", len(np.Rules), "bans", len(bans))
	return true, nil
}

// pruneLoop 周期性清理过期封禁。
func (e *Engine) pruneLoop(ctx context.Context, every time.Duration) {
	if e.db == nil || every <= 0 {
		return
	}
	ticker := time.NewTicker(every)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			n, err := e.db.PruneExpiredBans(ctx, e.clock())
			if err != nil {
				e.log.Warn("清理过期封禁失败", "err", err)
				continue
			}
			if n > 0 {
				e.log.Info("已清理过期封禁", "count", n)
				// 同步剔除内存中的过期项。
				_ = e.Update(func(p *model.Policy) error {
					now := e.clock()
					out := p.Bans[:0]
					for _, b := range p.Bans {
						if !b.Expired(now) {
							out = append(out, b)
						}
					}
					p.Bans = out
					return nil
				})
			}
		}
	}
}

// StartMaintenance 启动后台维护（过期封禁清理），随 ctx 结束而停止。
func (e *Engine) StartMaintenance(ctx context.Context) {
	go e.pruneLoop(ctx, 5*time.Minute)
}

// ---- 期望状态 ----

// SetPolicy 替换期望状态（仅内存 + 持久化，需 Apply 才下发到内核）。
//
// 传入策略的 Bans 字段会被忽略：封禁由 store 的 ban_entries 表统一管理，
// 与规则分离。若直接采用调用方给的空封禁列表，内存与数据库就会不一致，
// 表现为"解封了"但重启后又全部复活。
func (e *Engine) SetPolicy(p *model.Policy) error {
	np, err := e.prepare(p)
	if err != nil {
		return err
	}
	e.mu.Lock()
	np.Bans = append([]model.BanEntry(nil), e.desired.Bans...)
	e.desired = np
	e.persistPolicyLocked()
	e.mu.Unlock()

	e.audit("policy.set", "", fmt.Sprintf("zones=%d rules=%d nat=%d",
		len(np.Zones), len(np.Rules), len(np.NATRules)))
	return nil
}

// prepare 校验并规范化一份策略，不改变引擎状态。
func (e *Engine) prepare(p *model.Policy) (*model.Policy, error) {
	if p == nil {
		return nil, errors.New("策略为空")
	}
	np := deepCopy(p)
	np.Normalize()
	if errs := model.Errors(np.Validate()); len(errs) > 0 {
		return nil, &compiler.ValidationError{Problems: errs}
	}
	return np, nil
}

// Policy 返回期望状态（深拷贝，调用方可安全修改）。
func (e *Engine) Policy() *model.Policy {
	e.mu.Lock()
	defer e.mu.Unlock()
	return deepCopy(e.desired)
}

// Update 在期望状态上做一次原子修改。
//
// 注意：fn 在引擎锁内执行，不得再调用引擎方法，也不得阻塞。
func (e *Engine) Update(fn func(p *model.Policy) error) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	next := deepCopy(e.desired)
	if err := fn(next); err != nil {
		return err
	}
	next.Normalize()
	if errs := model.Errors(next.Validate()); len(errs) > 0 {
		return &compiler.ValidationError{Problems: errs}
	}
	e.desired = next
	e.persistPolicyLocked()
	return nil
}

// ---- 编译与计划 ----

// Plan 编译期望状态并给出与当前内核状态的差异概览，不触碰内核。
type Plan struct {
	Text     string        `json:"text"`
	Hash     string        `json:"hash"`
	Rules    int           `json:"rules"`
	Chains   int           `json:"chains"`
	Warnings []Warning     `json:"warnings,omitempty"`
	Changed  bool          `json:"changed"`
	Applied  string        `json:"applied_hash,omitempty"`
	Diff     []ChainChange `json:"diff,omitempty"`
	// ChainDetails 给出每条链逐条规则的裁决，供界面画出"规则指纹"。
	ChainDetails []ChainDetail `json:"chain_details,omitempty"`
}

// ChainDetail 是一条链的逐条规则明细。
type ChainDetail struct {
	Name     string        `json:"name"`
	Type     string        `json:"type"`
	Hook     string        `json:"hook"`
	Priority int           `json:"priority"`
	Policy   string        `json:"policy,omitempty"`
	Rules    int           `json:"rules"`
	Segments []RuleSegment `json:"segments"`
}

// RuleSegment 是规则指纹里的一格：一条规则及其裁决。
type RuleSegment struct {
	ID      string `json:"id,omitempty"`
	Verdict string `json:"verdict"`
	Comment string `json:"comment,omitempty"`
}

// describeSegments 从编译产物中提取每条链的规则裁决序列。
//
// 取的是规则里最后一条裁决语句：一条规则可能先计数、再记录日志、最后才丢弃，
// 真正决定去向的是末尾那条。
func describeSegments(snap *ir.Snapshot) []ChainDetail {
	if snap == nil {
		return nil
	}
	var out []ChainDetail
	for _, t := range snap.Tables {
		for _, c := range t.Chains {
			d := ChainDetail{
				Name: c.Name, Type: string(c.Type), Hook: string(c.Hook),
				Priority: c.Priority, Policy: c.Policy, Rules: len(c.Rules),
			}
			for _, r := range c.Rules {
				seg := RuleSegment{ID: r.ID, Comment: r.Comment, Verdict: "other"}
				// isLog 单独记：`log` 动作的规则**没有**裁决语句（它只记录、
				// 不决定去向），只看裁决语句会把它误判成未知状态。
				isLog := false
				for _, st := range r.Stmts {
					switch st.Kind {
					case ir.StmtVerdict:
						seg.Verdict = st.Verdict
					case ir.StmtLog:
						isLog = true
					case ir.StmtNAT:
						if st.NATKind == "dnat" || st.NATKind == "snat" || st.NATKind == "masquerade" {
							seg.Verdict = "nat"
						}
					}
				}
				if seg.Verdict == "other" && isLog {
					seg.Verdict = "log"
				}
				d.Segments = append(d.Segments, seg)
			}
			out = append(out, d)
		}
	}
	return out
}

// Warning 是一条非阻断性提示。
type Warning struct {
	Where   string `json:"where"`
	Message string `json:"message"`
}

// ChainChange 描述某条链的规则数量变化。
type ChainChange struct {
	Chain  string `json:"chain"`
	Before int    `json:"before"`
	After  int    `json:"after"`
}

// Plan 生成下发计划。
func (e *Engine) Plan(ctx context.Context) (*Plan, error) {
	e.mu.Lock()
	desired := deepCopy(e.desired)
	applied := deepCopy(e.applied)
	appliedHash := e.appliedHash
	e.mu.Unlock()

	res, err := compiler.Compile(desired, e.copts)
	if err != nil {
		return nil, err
	}
	text, err := e.backend.Render(ctx, res.Snapshot)
	if err != nil {
		return nil, err
	}

	p := &Plan{
		Text:    text,
		Hash:    hash(text),
		Rules:   res.Snapshot.RuleCount(),
		Chains:  len(res.Snapshot.Tables[0].Chains),
		Applied: appliedHash,
		Changed: hash(text) != appliedHash,
	}
	for _, w := range res.Warnings {
		p.Warnings = append(p.Warnings, Warning{Where: w.Where, Message: w.Message})
	}
	p.Diff = diffChains(applied, desired, e.copts)
	p.ChainDetails = describeSegments(res.Snapshot)
	return p, nil
}

// ApplyResult 是 Apply 的结果。
type ApplyResult struct {
	DryRun   bool           `json:"dry_run"`
	Applied  bool           `json:"applied"`
	Changed  bool           `json:"changed"`
	Rules    int            `json:"rules"`
	Chains   int            `json:"chains"`
	Hash     string         `json:"hash"`
	Warnings []Warning      `json:"warnings,omitempty"`
	Text     string         `json:"text,omitempty"`
	Pending  *PendingCommit `json:"pending,omitempty"`
}

// ApplyOptions 控制 Apply 行为。
type ApplyOptions struct {
	// DryRun 只编译与渲染，不触碰内核。
	DryRun bool
	// WithConfirm 下发后进入 commit-confirm 窗口（需确认，否则自动回滚）。
	WithConfirm bool
	// ForceNoConfirm 强制跳过确认窗口，即使配置里开启了 commit-confirm。
	//
	// 用于启动恢复：本地策略文件是可信基线，无人值守重启时若仍要求确认，
	// 超时回滚会把防火墙规则整个撤掉，反而更危险。
	ForceNoConfirm bool
	// ConfirmTimeout 覆盖配置中的确认窗口。
	ConfirmTimeout time.Duration
	// Note 写入历史记录。
	Note string
}

// Apply 把期望状态下发到后端（原子替换）。
func (e *Engine) Apply(ctx context.Context, opts ApplyOptions) (*ApplyResult, error) {
	e.mu.Lock()
	if e.pending != nil {
		pend := *e.pending
		e.mu.Unlock()
		return nil, fmt.Errorf("%w（截止 %s）", ErrPendingCommit, pend.Deadline.Format(time.RFC3339))
	}
	desired := deepCopy(e.desired)
	e.mu.Unlock()

	res, err := compiler.Compile(desired, e.copts)
	if err != nil {
		return nil, err
	}
	text, err := e.backend.Render(ctx, res.Snapshot)
	if err != nil {
		return nil, err
	}
	out := &ApplyResult{
		DryRun: opts.DryRun,
		Rules:  res.Snapshot.RuleCount(),
		Chains: len(res.Snapshot.Tables[0].Chains),
		Hash:   hash(text),
		Text:   text,
	}
	e.mu.Lock()
	out.Changed = out.Hash != e.appliedHash
	e.mu.Unlock()
	for _, w := range res.Warnings {
		out.Warnings = append(out.Warnings, Warning{Where: w.Where, Message: w.Message})
	}
	if opts.DryRun {
		return out, nil
	}

	// 记录下发前的状态作为回滚目标（可能"尚无状态"）。
	e.mu.Lock()
	prev, hadPrev := e.applied, e.hasState
	e.mu.Unlock()

	if err := e.backend.Apply(ctx, res.Snapshot); err != nil {
		return nil, err
	}

	e.mu.Lock()
	e.prev = prev
	e.desired = desired
	e.applied = desired
	e.hasState = true
	e.appliedHash = out.Hash
	e.seq++
	e.revisions = append(e.revisions, Revision{
		Seq: e.seq, At: e.clock(), Hash: out.Hash,
		Rules: out.Rules, Note: opts.Note,
	})
	if len(e.revisions) > 100 {
		e.revisions = e.revisions[len(e.revisions)-100:]
	}

	confirm := !opts.ForceNoConfirm && (opts.WithConfirm || e.cfg.CommitConfirm.Enabled)
	if confirm {
		timeout := opts.ConfirmTimeout
		if timeout <= 0 {
			timeout = e.cfg.CommitConfirm.Timeout
		}
		if timeout <= 0 {
			timeout = 60 * time.Second
		}
		e.pendingTarget = prev
		e.pendingTargetValid = hadPrev
		e.pending = &PendingCommit{
			Deadline: e.clock().Add(timeout),
			At:       e.clock(),
			Hash:     out.Hash,
			Rules:    out.Rules,
		}
		out.Pending = e.pending
		e.armTimer(timeout)
	} else {
		e.pendingTarget = nil
	}
	e.mu.Unlock()

	out.Applied = true
	e.log.Info("策略已下发", "rules", out.Rules, "hash", out.Hash, "pending_confirm", out.Pending != nil)
	e.recordApplied(ctx, out.Hash)
	e.audit("apply", out.Hash, fmt.Sprintf("rules=%d changed=%v note=%s", out.Rules, out.Changed, opts.Note))

	// 规则集替换会重建封禁集合（集合本身是空的），因此下发后必须重新注入封禁。
	if err := e.syncBanSets(ctx); err != nil {
		e.log.Error("下发后重建封禁集合失败", "err", err)
	}
	return out, nil
}

// recordApplied 记录本次成功下发的哈希，供重启后对账。
func (e *Engine) recordApplied(ctx context.Context, hash string) {
	if e.db == nil {
		return
	}
	if err := e.db.PutKV(ctx, "applied_hash", hash); err != nil {
		e.log.Error("记录下发哈希失败", "err", err)
	}
}

// syncBanSets 把期望状态中的封禁条目重新注入内核集合。
//
// 由于规则集整体替换会连带重建集合，任何 Apply（含回滚、启动恢复）之后都要调用它。
// 元素带 timeout，剩余时长由内核倒计时，进程崩溃也不会提前解封。
func (e *Engine) syncBanSets(ctx context.Context) error {
	now := e.clock()
	bans := e.ListBans()

	elems4 := map[string]ir.Element{}
	elems6 := map[string]ir.Element{}
	for _, b := range bans {
		if b.Expired(now) {
			continue
		}
		set := compiler.BanSetFor(b.IP, e.copts.BanSet4, e.copts.BanSet6)
		if set == "" {
			continue
		}
		el := ir.Element{Key: b.IP, Timeout: b.TTL(now), Comment: b.Reason}
		if set == e.copts.BanSet6 {
			elems6[b.IP] = el
		} else {
			elems4[b.IP] = el
		}
	}

	var firstErr error
	for set, elems := range map[string]map[string]ir.Element{
		e.copts.BanSet4: elems4,
		e.copts.BanSet6: elems6,
	} {
		if set == "" || len(elems) == 0 {
			continue
		}
		list := make([]ir.Element, 0, len(elems))
		for _, el := range elems {
			list = append(list, el)
		}
		if err := e.backend.SetAdd(ctx, set, list...); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// ---- commit-confirm ----

// armTimer 在超时后自动回滚。调用方必须持有 e.mu。
func (e *Engine) armTimer(timeout time.Duration) {
	deadline := e.pending.Deadline
	go func() {
		timer := time.NewTimer(time.Until(deadline))
		defer timer.Stop()
		<-timer.C

		e.mu.Lock()
		if e.pending == nil || !e.pending.Deadline.Equal(deadline) {
			// 已被 confirm 或已被新的 pending 取代。
			e.mu.Unlock()
			return
		}
		target := e.pendingTarget
		targetValid := e.pendingTargetValid
		e.pending = nil
		e.pendingTarget = nil
		e.mu.Unlock()

		e.log.Warn("commit-confirm 超时，自动回滚",
			"deadline", deadline.Format(time.RFC3339), "目标", rollbackDesc(target, targetValid))
		if err := e.undo(context.Background(), target, targetValid, "commit-confirm 超时自动回滚"); err != nil {
			e.log.Error("自动回滚失败，规则可能停留在未确认状态", "err", err)
			return
		}
		if e.onAutoRollback != nil {
			e.onAutoRollback(target)
		}
	}()
}

func rollbackDesc(target *model.Policy, valid bool) string {
	if !valid || target == nil {
		return "移除全部规则（当时尚未下发过任何策略）"
	}
	return fmt.Sprintf("%d 条规则", len(target.Rules))
}

// OnAutoRollback 注册自动回滚回调。
func (e *Engine) OnAutoRollback(fn func(to *model.Policy)) { e.onAutoRollback = fn }

// Confirm 确认当前变更，取消自动回滚。
func (e *Engine) Confirm() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.pending == nil {
		return errors.New("没有待确认的变更")
	}
	e.pending = nil
	e.pendingTarget = nil
	e.log.Info("变更已确认")
	e.audit("confirm", "", "")
	return nil
}

// Pending 返回待确认信息；nil 表示无。
func (e *Engine) Pending() *PendingCommit {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.pending == nil {
		return nil
	}
	p := *e.pending
	return &p
}

// Rollback 撤销当前策略：优先回滚到待确认变更之前的状态，
// 否则回退到上一次成功下发的策略。
func (e *Engine) Rollback(ctx context.Context) error {
	e.mu.Lock()
	if e.pending != nil {
		target, valid := e.pendingTarget, e.pendingTargetValid
		e.pending = nil
		e.pendingTarget = nil
		e.mu.Unlock()
		return e.undo(ctx, target, valid, "手工回滚（取消待确认变更）")
	}
	if e.prev == nil {
		e.mu.Unlock()
		return ErrNoRollback
	}
	target := e.prev
	e.mu.Unlock()
	return e.undo(ctx, target, true, "手工回滚")
}

// undo 把系统恢复到给定状态。targetValid 为 false 表示"撤掉全部规则"。
func (e *Engine) undo(ctx context.Context, target *model.Policy, targetValid bool, note string) error {
	if !targetValid || target == nil {
		if err := e.backend.Reset(ctx); err != nil {
			return err
		}
		e.mu.Lock()
		e.desired = &model.Policy{}
		e.applied = nil
		e.prev = nil
		e.hasState = false
		e.appliedHash = ""
		e.seq++
		e.revisions = append(e.revisions, Revision{
			Seq: e.seq, At: e.clock(), Note: note, Rules: 0,
		})
		e.persistPolicyLocked()
		e.mu.Unlock()

		e.recordApplied(ctx, "")
		e.audit("rollback.reset", "", note)
		e.log.Warn("已撤销全部规则", "note", note)
		return nil
	}
	return e.restore(ctx, target, note)
}

func (e *Engine) restore(ctx context.Context, target *model.Policy, note string) error {
	res, err := compiler.Compile(target, e.copts)
	if err != nil {
		return fmt.Errorf("回滚目标无法编译: %w", err)
	}
	text, err := e.backend.Render(ctx, res.Snapshot)
	if err != nil {
		return err
	}
	if err := e.backend.Apply(ctx, res.Snapshot); err != nil {
		return err
	}
	h := hash(text)
	e.mu.Lock()
	e.prev = e.applied
	e.desired = deepCopy(target)
	e.applied = deepCopy(target)
	e.hasState = true
	e.appliedHash = h
	e.seq++
	e.revisions = append(e.revisions, Revision{
		Seq: e.seq, At: e.clock(), Hash: h, Rules: res.Snapshot.RuleCount(), Note: note,
	})
	e.persistPolicyLocked()
	e.mu.Unlock()

	e.recordApplied(ctx, h)
	e.audit("rollback", h, note)
	e.log.Warn("已回滚", "note", note, "rules", res.Snapshot.RuleCount())
	if err := e.syncBanSets(ctx); err != nil {
		e.log.Error("回滚后重建封禁集合失败", "err", err)
	}
	return nil
}

// Revisions 返回下发历史。
func (e *Engine) Revisions() []Revision {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]Revision(nil), e.revisions...)
}

// ---- 状态 ----

// Status 是 `fw status` / `GET /status` 的返回。
type Status struct {
	Backend     string                `json:"backend"`
	Table       string                `json:"table"`
	DesiredHash string                `json:"desired_hash,omitempty"`
	AppliedHash string                `json:"applied_hash,omitempty"`
	InSync      bool                  `json:"in_sync"`
	Desired     Summary               `json:"desired"`
	Pending     *PendingCommit        `json:"pending,omitempty"`
	Runtime     *backend.RuntimeState `json:"runtime,omitempty"`
	RuntimeErr  string                `json:"runtime_error,omitempty"`
	Revisions   int                   `json:"revisions"`
}

// Summary 是策略的规模摘要。
type Summary struct {
	Version  int `json:"version"`
	Zones    int `json:"zones"`
	Rules    int `json:"rules"`
	NATRules int `json:"nat_rules"`
	Bans     int `json:"bans"`
	Enabled  int `json:"rules_enabled"`
}

// Status 汇总当前状态。
func (e *Engine) Status(ctx context.Context) *Status {
	e.mu.Lock()
	desired := deepCopy(e.desired)
	appliedHash := e.appliedHash
	revs := len(e.revisions)
	var pending *PendingCommit
	if e.pending != nil {
		p := *e.pending
		pending = &p
	}
	e.mu.Unlock()

	st := &Status{
		Backend:     e.backend.Name(),
		Table:       e.cfg.Table,
		AppliedHash: appliedHash,
		Pending:     pending,
		Revisions:   revs,
	}
	if desired != nil {
		st.Desired = Summary{
			Version:  desired.Version,
			Zones:    len(desired.Zones),
			Rules:    len(desired.Rules),
			NATRules: len(desired.NATRules),
			Bans:     len(desired.Bans),
		}
		for _, r := range desired.Rules {
			if r.IsEnabled() {
				st.Desired.Enabled++
			}
		}
	}

	// 期望状态哈希用于判断是否需要重新下发。
	if res, err := compiler.Compile(desired, e.copts); err == nil {
		if text, err := e.backend.Render(ctx, res.Snapshot); err == nil {
			st.DesiredHash = hash(text)
			st.InSync = st.DesiredHash == appliedHash
		}
	}

	rt, err := e.backend.State(ctx)
	switch {
	case err != nil:
		st.RuntimeErr = err.Error()
	case rt != nil:
		st.Runtime = rt
		if rt.Hash != "" && appliedHash != "" {
			st.InSync = rt.Hash == appliedHash && st.DesiredHash == appliedHash
		}
	}
	return st
}

// ---- 封禁 ----

// BanIP 实现 ban.Sink：自动封禁引擎判定后调用这里执行封禁。
//
// 与 Ban 的区别只在于入参形态（IP/原因/时长），执行路径完全相同：
// 写期望状态 → 落库 → 注入内核集合。
func (e *Engine) BanIP(ctx context.Context, ip, reason string, ttl time.Duration) error {
	now := e.clock()
	if ttl <= 0 {
		ttl = e.copts.BanTimeout
	}
	return e.Ban(ctx, model.BanEntry{
		IP:        ip,
		Reason:    reason,
		Source:    model.BanAuto,
		AddedAt:   now,
		ExpiresAt: now.Add(ttl),
	})
}

// OnUnban 注册解封回调。
//
// 用于通知自动封禁引擎清掉该地址的计数窗口 —— 否则手工解封后，
// 窗口里的残留事件会让它在下一条事件到来时立刻又被封上。
func (e *Engine) OnUnban(fn func(ip string)) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.onUnban = fn
}

// Ban 立即封禁一个地址并写入期望状态。
func (e *Engine) Ban(ctx context.Context, entry model.BanEntry) error {
	ip := entry.IP
	now := e.clock()
	if entry.AddedAt.IsZero() {
		entry.AddedAt = now
	}
	if entry.ExpiresAt.IsZero() {
		ttl := e.copts.BanTimeout
		if ttl <= 0 {
			ttl = 24 * time.Hour
		}
		entry.ExpiresAt = now.Add(ttl)
	}
	if err := e.Update(func(p *model.Policy) error {
		if p.BanSet.WhitelistContains(ip) {
			return fmt.Errorf("%s 在白名单中，拒绝封禁", ip)
		}
		for i := range p.Bans {
			if p.Bans[i].IP == ip {
				p.Bans[i] = entry
				return nil
			}
		}
		p.Bans = append(p.Bans, entry)
		return nil
	}); err != nil {
		return err
	}

	set := compiler.BanSetFor(ip, e.copts.BanSet4, e.copts.BanSet6)
	if set == "" {
		return fmt.Errorf("未配置封禁集合，无法注入 %s", ip)
	}
	e.persistBan(ctx, entry)
	e.audit("ban.add", ip, entry.Reason)

	// 立即注入内核，不必等到下一次 apply。
	return e.backend.SetAdd(ctx, set, ir.Element{
		Key: ip, Timeout: entry.TTL(now), Comment: entry.Reason,
	})
}

// Unban 解除封禁。
func (e *Engine) Unban(ctx context.Context, ip string) error {
	if err := e.Update(func(p *model.Policy) error {
		out := p.Bans[:0]
		for _, b := range p.Bans {
			if b.IP != ip {
				out = append(out, b)
			}
		}
		p.Bans = out
		return nil
	}); err != nil {
		return err
	}
	e.forgetBan(ctx, ip)
	e.audit("ban.remove", ip, "")

	e.mu.Lock()
	unbanHook := e.onUnban
	e.mu.Unlock()
	if unbanHook != nil {
		unbanHook(ip)
	}

	set := compiler.BanSetFor(ip, e.copts.BanSet4, e.copts.BanSet6)
	if set == "" {
		return nil
	}
	return e.backend.SetDel(ctx, set, ip)
}

// ListBans 返回当前封禁列表（清理已过期项）。
func (e *Engine) ListBans() []model.BanEntry {
	e.mu.Lock()
	defer e.mu.Unlock()
	now := e.clock()
	var out []model.BanEntry
	for _, b := range e.desired.Bans {
		if b.Expired(now) {
			continue
		}
		out = append(out, b)
	}
	return out
}

// ---- 工具 ----

// deepCopy 通过 JSON 往返做深拷贝；nil 视为空策略，保证调用方无需判空。
func deepCopy(p *model.Policy) *model.Policy {
	if p == nil {
		return &model.Policy{}
	}
	b, err := json.Marshal(p)
	if err != nil {
		return &model.Policy{}
	}
	var out model.Policy
	if err := json.Unmarshal(b, &out); err != nil {
		return &model.Policy{}
	}
	return &out
}

func hash(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:8])
}

func diffChains(before, after *model.Policy, opts compiler.Options) []ChainChange {
	counts := func(p *model.Policy) map[string]int {
		m := map[string]int{}
		res, err := compiler.Compile(p, opts)
		if err != nil {
			return m
		}
		for _, t := range res.Snapshot.Tables {
			for _, c := range t.Chains {
				m[c.Name] = len(c.Rules)
			}
		}
		return m
	}
	b, a := counts(before), counts(after)
	seen := map[string]bool{}
	var out []ChainChange
	for name := range b {
		seen[name] = true
	}
	for name := range a {
		seen[name] = true
	}
	names := make([]string, 0, len(seen))
	for name := range seen {
		names = append(names, name)
	}
	sortStrings(names)
	for _, name := range names {
		if b[name] != a[name] {
			out = append(out, ChainChange{Chain: name, Before: b[name], After: a[name]})
		}
	}
	return out
}

func sortStrings(s []string) { sort.Strings(s) }

func isV6(addr string) bool {
	ip := net.ParseIP(addr)
	return ip != nil && ip.To4() == nil
}

// OnEvent 注册实时事件回调。回调在写操作路径上被调用，必须快速返回。
// OnEvent 注册实时事件回调。回调在写操作路径上被调用，必须快速返回。
func (e *Engine) OnEvent(fn func(action, target, detail string)) {
	if fn == nil {
		e.onEvent.Store(nil)
		return
	}
	e.onEvent.Store(&fn)
}

func (e *Engine) eventHook() func(string, string, string) {
	if p := e.onEvent.Load(); p != nil {
		return *p
	}
	return nil
}
