// Package ban 实现自动封禁：把"可疑行为事件"转换成封禁决策。
//
// 分工：
//
//	Detector  产生事件（conntrack 探测、日志匹配、nft 限速日志…）
//	Engine    消费事件，维护滑动窗口计数与递进惩罚，产出 Decision
//	Sink      执行决策（由 engine 包实现：写库 + 注入内核集合）
//
// 这样切分是为了让"判罚逻辑"完全不依赖内核与文件系统，可以在任何平台上
// 逐个用例验证；而平台相关的部分（读 /proc、tail 日志）退化成纯粹的输入源。
package ban

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"time"
)

// Event 是一次可疑行为。
type Event struct {
	IP     string    `json:"ip"`
	Source string    `json:"source"` // 产生事件检测器的名字
	Reason string    `json:"reason"`
	At     time.Time `json:"at"`
	// Weight 允许某些事件权重更高（例如 SSH 爆破比一次端口探测更可疑）。
	Weight int `json:"weight,omitempty"`
}

// Settings 是自动封禁策略。
type Settings struct {
	// Enabled 为 false 时只观察、不封禁（用于先跑一段时间看误报率）。
	Enabled bool `json:"enabled"`
	// Window 是滑动窗口长度。
	Window time.Duration `json:"window"`
	// Threshold 是窗口内累计权重达到多少即封禁。
	Threshold int `json:"threshold"`
	// BaseTTL 是首次封禁时长。
	BaseTTL time.Duration `json:"base_ttl"`
	// Multiplier 是递进惩罚倍数：第 n 次违规时长 = BaseTTL * Multiplier^(n-1)。
	Multiplier float64 `json:"multiplier"`
	// MaxTTL 是封禁时长上限。
	MaxTTL time.Duration `json:"max_ttl"`
	// StrikeResetAfter 为多久没有新的封禁就清零违规次数。
	StrikeResetAfter time.Duration `json:"strike_reset_after"`
	// Whitelist 中的地址永不封禁，也不参与计数。
	Whitelist []string `json:"whitelist,omitempty"`
	// MaxTracked 限制同时跟踪的地址数量，防止被海量随机源地址拖垮内存。
	MaxTracked int `json:"max_tracked,omitempty"`
}

// DefaultSettings 返回偏保守的默认值。
//
// 默认 Enabled=false：先只观察不封禁。误封一个有合法用途的地址
// （监控、NAT 出口、爬虫）比漏封更麻烦，应该先看一段时间真实流量再打开。
func DefaultSettings() Settings {
	return Settings{
		Enabled:          false,
		Window:           10 * time.Minute,
		Threshold:        20,
		BaseTTL:          10 * time.Minute,
		Multiplier:       2,
		MaxTTL:           24 * time.Hour,
		StrikeResetAfter: 24 * time.Hour,
		MaxTracked:       100_000,
	}
}

// Normalize 校验并补齐默认值。
func (s *Settings) Normalize() error {
	d := DefaultSettings()
	if s.Window <= 0 {
		s.Window = d.Window
	}
	if s.Threshold <= 0 {
		s.Threshold = d.Threshold
	}
	if s.BaseTTL <= 0 {
		s.BaseTTL = d.BaseTTL
	}
	if s.Multiplier < 1 {
		s.Multiplier = d.Multiplier
	}
	if s.MaxTTL <= 0 {
		s.MaxTTL = d.MaxTTL
	}
	if s.MaxTTL < s.BaseTTL {
		return fmt.Errorf("max_ttl(%s) 不能小于 base_ttl(%s)", s.MaxTTL, s.BaseTTL)
	}
	if s.StrikeResetAfter <= 0 {
		s.StrikeResetAfter = d.StrikeResetAfter
	}
	if s.MaxTracked <= 0 {
		s.MaxTracked = d.MaxTracked
	}
	for _, w := range s.Whitelist {
		if _, _, err := net.ParseCIDR(w); err != nil && net.ParseIP(w) == nil {
			return fmt.Errorf("白名单 %q 既不是 IP 也不是 CIDR", w)
		}
	}
	return nil
}

// Action 是判罚结论。
type Action string

const (
	ActionIgnore  Action = "ignore"
	ActionBan     Action = "ban"
	ActionExtend  Action = "extend"
	ActionObserve Action = "observe" // 已过阈值但未开启封禁
)

// Decision 是一条判罚结论。
type Decision struct {
	At         time.Time     `json:"at"`
	IP         string        `json:"ip"`
	Action     Action        `json:"action"`
	Reason     string        `json:"reason"`
	TTL        time.Duration `json:"ttl,omitempty"`
	Strikes    int           `json:"strikes"`
	EventCount int           `json:"event_count"`
	Sources    []string      `json:"sources,omitempty"`
}

// Offender 是一个被跟踪的地址。
type Offender struct {
	IP          string    `json:"ip"`
	Score       int       `json:"score"`   // 窗口内累计权重
	Events      int       `json:"events"`  // 窗口内事件条数
	Strikes     int       `json:"strikes"` // 历史违规次数
	FirstSeen   time.Time `json:"first_seen"`
	LastSeen    time.Time `json:"last_seen"`
	BannedUntil time.Time `json:"banned_until,omitempty"`
	Sources     []string  `json:"sources,omitempty"`
}

// Option 配置判罚引擎。
type Option func(*Engine)

// WithClock 注入时钟（测试用）。
func WithClock(fn func() time.Time) Option {
	return func(e *Engine) {
		if fn != nil {
			e.now = fn
		}
	}
}

// WithDecisionHook 注册判罚回调，用于落库、注入内核、写审计。
func WithDecisionHook(fn func(Decision)) Option {
	return func(e *Engine) { e.onDecision = fn }
}

// Engine 是判罚引擎：线程安全。
type Engine struct {
	mu  sync.Mutex
	cfg Settings
	now func() time.Time

	offenders map[string]*offender
	decisions []Decision

	// 计数器，供状态展示。
	observed int64
	dropped  int64

	onDecision func(Decision)
}

type offender struct {
	ip        string
	events    []event
	strikes   int
	firstSeen time.Time
	lastSeen  time.Time
	lastBan   time.Time
	bannedTil time.Time
	sources   map[string]bool
}

type event struct {
	at     time.Time
	weight int
	source string
}

// New 创建判罚引擎。
func New(cfg Settings, opts ...Option) (*Engine, error) {
	if err := cfg.Normalize(); err != nil {
		return nil, err
	}
	e := &Engine{
		cfg:       cfg,
		now:       time.Now,
		offenders: map[string]*offender{},
	}
	for _, o := range opts {
		o(e)
	}
	return e, nil
}

// Settings 返回当前配置。
func (e *Engine) Settings() Settings {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.cfg
}

// SetEnabled 运行时开关自动封禁（可以只观察一段时间再打开）。
func (e *Engine) SetEnabled(on bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.cfg.Enabled = on
}

// Observe 处理一个事件，返回判罚结论。
//
// 结论总会返回（含"忽略"及其原因），便于排查"为什么没封它"。
func (e *Engine) Observe(ev Event) Decision {
	e.mu.Lock()
	defer e.mu.Unlock()

	now := ev.At
	if now.IsZero() {
		now = e.now()
	}
	ev.At = now
	if ev.Weight <= 0 {
		ev.Weight = 1
	}

	d := Decision{At: now, IP: ev.IP, Action: ActionIgnore}

	ip := net.ParseIP(ev.IP)
	if ip == nil {
		d.Reason = "地址格式非法"
		return e.record(d)
	}
	if e.whitelisted(ip) {
		d.Reason = "地址在白名单中"
		return e.record(d)
	}

	e.observed++

	// 已经封着：只累计观察，不再重复下发（避免封禁风暴）。
	o := e.offenders[ev.IP]
	if o != nil && now.Before(o.bannedTil) {
		o.lastSeen = now
		o.events = append(o.events, event{at: now, weight: ev.Weight, source: ev.Source})
		e.prune(o, now)
		d.Action = ActionExtend
		d.Strikes = o.strikes
		d.EventCount = len(o.events)
		d.Sources = o.sourceList()
		d.Reason = fmt.Sprintf("已在封禁期内（至 %s），续期观察", o.bannedTil.Format(time.RFC3339))
		return e.record(d)
	}

	if o == nil {
		if len(e.offenders) >= e.cfg.MaxTracked {
			// 跟踪表满：丢弃新来源而不是无限增长。这是被扫描攻击时的自我保护。
			e.dropped++
			d.Reason = "跟踪表已满，忽略新来源"
			return e.record(d)
		}
		o = &offender{ip: ev.IP, firstSeen: now, sources: map[string]bool{}}
		e.offenders[ev.IP] = o
	}

	o.lastSeen = now
	o.events = append(o.events, event{at: now, weight: ev.Weight, source: ev.Source})
	if ev.Source != "" {
		o.sources[ev.Source] = true
	}
	e.prune(o, now)

	score := o.score()
	d.EventCount = len(o.events)
	d.Sources = o.sourceList()

	if score < e.cfg.Threshold {
		d.Reason = fmt.Sprintf("窗口内累计 %d/%d，未达阈值", score, e.cfg.Threshold)
		return e.record(d)
	}

	if !e.cfg.Enabled {
		d.Action = ActionObserve
		d.Reason = fmt.Sprintf("窗口内累计 %d 已达阈值，但自动封禁未开启", score)
		return e.record(d)
	}

	// 达到阈值 → 封禁，并按历史违规次数递进加长。
	o.strikes++
	o.lastBan = now
	ttl := e.ttlFor(o.strikes)
	o.bannedTil = now.Add(ttl)
	// 封禁后清空窗口：否则解封瞬间还会因残留计数再次触发。
	o.events = nil

	d.Action = ActionBan
	d.Strikes = o.strikes
	d.TTL = ttl
	d.Reason = fmt.Sprintf("窗口内累计 %d 达阈值（来源: %s），第 %d 次违规，封禁 %s",
		score, strings.Join(d.Sources, ","), o.strikes, ttl)
	return e.record(d)
}

// Forget 清理某个地址的跟踪状态（手工解封时调用）。
func (e *Engine) Forget(ip string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	delete(e.offenders, ip)
}

// Offenders 返回当前被跟踪的地址，按可疑度倒序。
func (e *Engine) Offenders() []Offender {
	e.mu.Lock()
	defer e.mu.Unlock()
	now := e.now()

	out := make([]Offender, 0, len(e.offenders))
	for _, o := range e.offenders {
		e.prune(o, now)
		if len(o.events) == 0 && now.After(o.bannedTil) {
			continue
		}
		out = append(out, Offender{
			IP: o.ip, Score: o.score(), Events: len(o.events), Strikes: o.strikes,
			FirstSeen: o.firstSeen, LastSeen: o.lastSeen, BannedUntil: o.bannedTil,
			Sources: o.sourceList(),
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Score != out[j].Score {
			return out[i].Score > out[j].Score
		}
		return out[i].IP < out[j].IP
	})
	return out
}

// Decisions 返回最近的判罚记录（倒序）。
func (e *Engine) Decisions() []Decision {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := make([]Decision, len(e.decisions))
	for i, d := range e.decisions {
		out[len(e.decisions)-1-i] = d
	}
	return out
}

// Stats 是引擎的计数摘要。
type Stats struct {
	Observed  int64         `json:"observed"`
	Dropped   int64         `json:"dropped"`
	Tracked   int           `json:"tracked"`
	Banned    int           `json:"banned"`
	Enabled   bool          `json:"enabled"`
	Threshold int           `json:"threshold"`
	Window    time.Duration `json:"window"`
}

// Stats 返回计数摘要。
func (e *Engine) Stats() Stats {
	e.mu.Lock()
	defer e.mu.Unlock()
	now := e.now()
	banned := 0
	for _, o := range e.offenders {
		if now.Before(o.bannedTil) {
			banned++
		}
	}
	return Stats{
		Observed: e.observed, Dropped: e.dropped,
		Tracked: len(e.offenders), Banned: banned,
		Enabled: e.cfg.Enabled, Threshold: e.cfg.Threshold, Window: e.cfg.Window,
	}
}

// ---- 内部 ----

// prune 丢弃窗口之外的事件；窗口空了且早已超过违规重置期，则清零违规次数。
func (e *Engine) prune(o *offender, now time.Time) {
	cutoff := now.Add(-e.cfg.Window)
	keep := o.events[:0]
	for _, ev := range o.events {
		if ev.at.After(cutoff) {
			keep = append(keep, ev)
		}
	}
	o.events = keep

	// 长时间没有新违规 → 惩罚归零，避免"一次误报永久加重"。
	if o.strikes > 0 && !o.lastBan.IsZero() && now.Sub(o.lastBan) > e.cfg.StrikeResetAfter {
		o.strikes = 0
	}
}

func (o *offender) score() int {
	s := 0
	for _, ev := range o.events {
		s += ev.weight
	}
	return s
}

func (o *offender) sourceList() []string {
	out := make([]string, 0, len(o.sources))
	for s := range o.sources {
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

// ttlFor 计算第 n 次违规的封禁时长：BaseTTL * Multiplier^(n-1)，上限 MaxTTL。
func (e *Engine) ttlFor(strikes int) time.Duration {
	ttl := float64(e.cfg.BaseTTL)
	for i := 1; i < strikes; i++ {
		ttl *= e.cfg.Multiplier
		if ttl >= float64(e.cfg.MaxTTL) {
			return e.cfg.MaxTTL
		}
	}
	d := time.Duration(ttl)
	if d > e.cfg.MaxTTL {
		d = e.cfg.MaxTTL
	}
	return d
}

func (e *Engine) whitelisted(ip net.IP) bool {
	for _, w := range e.cfg.Whitelist {
		if _, ipnet, err := net.ParseCIDR(w); err == nil {
			if ipnet.Contains(ip) {
				return true
			}
			continue
		}
		if other := net.ParseIP(w); other != nil && other.Equal(ip) {
			return true
		}
	}
	return false
}

// record 保存决策并触发回调。调用方必须持有 e.mu。
func (e *Engine) record(d Decision) Decision {
	// 只保留最近一段，避免长期运行内存无界增长。
	const keep = 500
	e.decisions = append(e.decisions, d)
	if len(e.decisions) > keep {
		e.decisions = e.decisions[len(e.decisions)-keep:]
	}
	if d.Action == ActionBan && e.onDecision != nil {
		// 在锁内回调：调用方（Sink）必须快速返回，不得阻塞。
		e.onDecision(d)
	}
	return d
}

// Sink 是封禁的执行者。由 engine 包实现（写库 + 注入内核集合）。
type Sink interface {
	BanIP(ctx context.Context, ip, reason string, ttl time.Duration) error
}

// AttachSink 让引擎把封禁决策直接落到 Sink 上。
//
// 与 WithDecisionHook 的区别：Sink 只负责"执行封禁"，不关心决策细节，
// 便于在守护进程里直接接线。
func (e *Engine) AttachSink(s Sink) {
	e.mu.Lock()
	prev := e.onDecision
	e.mu.Unlock()
	e.onDecision = func(d Decision) {
		if prev != nil {
			prev(d)
		}
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			_ = s.BanIP(ctx, d.IP, d.Reason, d.TTL)
		}()
	}
}
