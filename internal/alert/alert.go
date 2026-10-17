// Package alert 把运行时事件推送到外部通道（Webhook / 邮件 / 本地命令）。
//
// 设计要点：**告警本身不能变成新的洪水源。** 一次端口扫描可能瞬间产生几十条
// 封禁，如果每条都发一次，你会被自己的告警淹没，然后开始忽略它们 ——
// 那比没有告警更糟。所以这里有两层收敛：
//
//  1. 去重窗口：同一个键（事件类型 + 目标 IP）在 cooldown 内只发一次，
//     期间发生的重复事件合并计数，在下一次发送时一并告知。
//  2. 发送队列：真正的网络请求在后台协程里做，且**永不阻塞调用方** ——
//     它跑在封禁决策的路径上，一个卡住的 webhook 不能让防火墙失去响应。
package alert

import (
	"context"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"sync"
	"time"
)

// Severity 是告警级别。
type Severity string

const (
	SevInfo Severity = "info"
	SevWarn Severity = "warn"
	SevCrit Severity = "critical"
)

// rank 用于比较级别高低；越大越严重。
func (s Severity) rank() int {
	switch s {
	case SevCrit:
		return 3
	case SevWarn:
		return 2
	case SevInfo:
		return 1
	}
	return 0
}

// AtLeast 报告该级别是否达到给定的下限。
func (s Severity) AtLeast(min Severity) bool { return s.rank() >= min.rank() }

// ParseSeverity 解析配置里的级别字符串。
func ParseSeverity(s string) (Severity, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "info":
		return SevInfo, nil
	case "warn", "warning":
		return SevWarn, nil
	case "crit", "critical", "error":
		return SevCrit, nil
	}
	return "", fmt.Errorf("未知的告警级别 %q（应为 info | warn | critical）", s)
}

// Event 是一条待发送的告警。
type Event struct {
	At       time.Time `json:"at"`
	Severity Severity  `json:"severity"`
	Kind     string    `json:"kind"`
	IP       string    `json:"ip,omitempty"`
	Title    string    `json:"title"`
	Detail   string    `json:"detail,omitempty"`
	// Count 是去重窗口内被合并的事件数（>=1）。
	Count int `json:"count,omitempty"`
}

// dedupKey 返回去重键：同类型同目标视为同一件事。
func (e Event) dedupKey() string {
	return e.Kind + "|" + e.IP
}

func (e Event) String() string {
	var b strings.Builder
	fmt.Fprintf(&b, "[%s] %s", e.Severity, e.Title)
	if e.IP != "" {
		fmt.Fprintf(&b, " (%s)", e.IP)
	}
	if e.Count > 1 {
		fmt.Fprintf(&b, " ×%d", e.Count)
	}
	if e.Detail != "" {
		b.WriteString("\n" + e.Detail)
	}
	return b.String()
}

// Notifier 是一个投递通道。
type Notifier interface {
	// Name 用于日志与去重诊断，如 "webhook"。
	Name() string
	// Notify 投递一条告警。失败应返回错误，由 Manager 记录。
	Notify(ctx context.Context, ev Event) error
}

// Option 配置 Manager。
type Option func(*Manager)

// WithLogger 指定日志器。
func WithLogger(l *slog.Logger) Option {
	return func(m *Manager) {
		if l != nil {
			m.log = l
		}
	}
}

// WithCooldown 设置去重窗口（默认 5 分钟）。
func WithCooldown(d time.Duration) Option {
	return func(m *Manager) {
		if d > 0 {
			m.cooldown = d
		}
	}
}

// WithMinSeverity 设置低于该级别的告警不发送（默认 info，即全发）。
func WithMinSeverity(s Severity) Option {
	return func(m *Manager) { m.minSev = s }
}

// Manager 把事件扇出到多个通道，并做去重与异步投递。
type Manager struct {
	mu        sync.Mutex
	notifiers []Notifier
	minSev    Severity
	cooldown  time.Duration
	// pending 记录去重窗口内的事件：键 → 首次发生时间与合并后的条数。
	pending map[string]*pendingEvent
	log     *slog.Logger
	queue   chan Event
	stop    chan struct{}
	once    sync.Once
	wg      sync.WaitGroup

	// 计数，供 /metrics 与自检。
	sent    int64
	dropped int64
	merged  int64
}

type pendingEvent struct {
	first time.Time
	last  time.Time
	count int
}

// New 创建告警管理器并启动后台投递协程。
func New(notifiers []Notifier, opts ...Option) *Manager {
	m := &Manager{
		notifiers: notifiers,
		minSev:    SevInfo,
		cooldown:  5 * time.Minute,
		pending:   map[string]*pendingEvent{},
		log:       slog.Default(),
		queue:     make(chan Event, 256),
		stop:      make(chan struct{}),
	}
	for _, o := range opts {
		o(m)
	}
	m.wg.Add(1)
	go m.worker()
	return m
}

// Close 停止后台协程并等待队列排空（最多 5 秒）。
func (m *Manager) Close() {
	m.once.Do(func() { close(m.stop) })
	done := make(chan struct{})
	go func() { m.wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		m.log.Warn("告警队列未能在 5 秒内排空，可能有投递通道卡住")
	}
}

// Notifiers 返回已配置的通道名，供 CLI 与自检展示。
func (m *Manager) Notifiers() []string {
	out := make([]string, 0, len(m.notifiers))
	for _, n := range m.notifiers {
		out = append(out, n.Name())
	}
	sort.Strings(out)
	return out
}

// Enabled 报告是否配置了任何通道。
func (m *Manager) Enabled() bool { return len(m.notifiers) > 0 }

// Stats 返回计数摘要。
func (m *Manager) Stats() (sent, merged, dropped int64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.sent, m.merged, m.dropped
}

// Send 提交一条告警。**永不阻塞**，可以在封禁决策路径上直接调用。
//
// 去重：同一个键在 cooldown 内重复到来时只累加计数，不重复发送；
// 窗口过后的第一条会把累计条数带上，让你知道"这期间又来了 N 次"。
func (m *Manager) Send(ev Event) {
	if len(m.notifiers) == 0 {
		return
	}
	if ev.At.IsZero() {
		ev.At = time.Now()
	}
	if ev.Severity.rank() < m.minSev.rank() {
		return
	}

	key := ev.dedupKey()
	m.mu.Lock()
	now := time.Now()
	if p, ok := m.pending[key]; ok && now.Sub(p.first) < m.cooldown {
		p.count++
		p.last = now
		m.merged++
		m.mu.Unlock()
		return
	}
	m.pending[key] = &pendingEvent{first: now, last: now, count: 1}
	ev.Count = 1
	m.mu.Unlock()

	select {
	case m.queue <- ev:
	default:
		// 队列满：丢弃而不是阻塞调用方。丢弃要计数，否则会静默失去告警。
		m.mu.Lock()
		m.dropped++
		m.mu.Unlock()
		m.log.Warn("告警队列已满，丢弃一条", "kind", ev.Kind, "ip", ev.IP)
	}
}

// SendSync 同步发送并等待所有通道返回，用于 `fw alert test` 这类需要立刻知道
// 通不通的场景。**不要**在封禁路径上用它。
func (m *Manager) SendSync(ctx context.Context, ev Event) []error {
	if ev.At.IsZero() {
		ev.At = time.Now()
	}
	var errs []error
	for _, n := range m.notifiers {
		if err := n.Notify(ctx, ev); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", n.Name(), err))
		}
	}
	return errs
}

func (m *Manager) worker() {
	defer m.wg.Done()
	for {
		select {
		case <-m.stop:
			// 排空队列后退出
			for {
				select {
				case ev := <-m.queue:
					m.deliver(ev)
				default:
					return
				}
			}
		case ev := <-m.queue:
			m.deliver(ev)
		}
	}
}

func (m *Manager) deliver(ev Event) {
	// 单条告警的投递超时。网断了、webhook 挂了都不该拖住队列。
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	for _, n := range m.notifiers {
		if err := n.Notify(ctx, ev); err != nil {
			m.log.Warn("告警投递失败", "channel", n.Name(), "kind", ev.Kind, "err", err)
		}
	}
	m.mu.Lock()
	m.sent++
	m.mu.Unlock()
}

// Forget 清理过期的去重记录，避免长期运行时 map 无界增长。
// 由后台维护循环调用。
func (m *Manager) Forget() {
	m.mu.Lock()
	defer m.mu.Unlock()
	cutoff := time.Now().Add(-2 * m.cooldown)
	for k, p := range m.pending {
		if p.last.Before(cutoff) {
			delete(m.pending, k)
		}
	}
}
