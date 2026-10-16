package obs

import (
	"sync"
	"time"
)

// Event 是一条对外可见的运行时事件，用于 Web 界面与 CLI 的实时视图。
type Event struct {
	At     time.Time `json:"at"`
	Kind   string    `json:"kind"`
	Target string    `json:"target,omitempty"`
	Detail string    `json:"detail,omitempty"`
}

// 事件类型。取值与审计日志的 action 一致 —— 事件流就是审计日志的实时视图，
// 两套命名会让"页面上看到一条，去审计里却对不上"这种问题变得很烦人。
const (
	EventApply      = "apply"       // 下发规则集
	EventRollback   = "rollback"    // 回滚
	EventConfirm    = "confirm"     // 确认变更
	EventPolicy     = "policy.set"  // 策略被替换
	EventPolicyInit = "policy.init" // 首次启动导入基线
	EventBan        = "ban.add"     // 封禁（含自动封禁）
	EventUnban      = "ban.remove"  // 解封
	EventRuleAdd    = "rule.add"
	EventRuleDel    = "rule.delete"
	EventNATAdd     = "nat.add"
	EventNATDel     = "nat.delete"
)

// Bus 是进程内的事件总线。
//
// 订阅者慢不能拖垮发布者：缓冲区满时丢弃该订阅者的事件并计数，
// 而不是阻塞 —— 实时视图丢几条事件无所谓，但绝不能因为一个卡住的
// 浏览器标签页把防火墙的判罚流程堵住。
type Bus struct {
	mu     sync.Mutex
	subs   map[int]chan Event
	nextID int
	ring   []Event
	ringN  int
	drops  int64
}

// NewBus 创建事件总线，保留最近 ringSize 条事件供新订阅者回放。
func NewBus(ringSize int) *Bus {
	if ringSize <= 0 {
		ringSize = 200
	}
	return &Bus{subs: map[int]chan Event{}, ringN: ringSize}
}

// Publish 广播一条事件。永不阻塞。
func (b *Bus) Publish(ev Event) {
	if ev.At.IsZero() {
		ev.At = time.Now()
	}
	b.mu.Lock()
	defer b.mu.Unlock()

	b.ring = append(b.ring, ev)
	if len(b.ring) > b.ringN {
		b.ring = b.ring[len(b.ring)-b.ringN:]
	}

	for id, ch := range b.subs {
		select {
		case ch <- ev:
		default:
			// 订阅者跟不上：丢给它，并记账。
			b.drops++
			_ = id
		}
	}
}

// Subscribe 订阅事件。返回的取消函数必须被调用（通常在请求结束时 defer）。
func (b *Bus) Subscribe(buf int) (<-chan Event, func()) {
	if buf <= 0 {
		buf = 64
	}
	ch := make(chan Event, buf)

	b.mu.Lock()
	id := b.nextID
	b.nextID++
	b.subs[id] = ch
	// 回放最近的少量事件，让刚打开的页面不是一片空白。
	backlog := b.ring
	if len(backlog) > 20 {
		backlog = backlog[len(backlog)-20:]
	}
	replay := append([]Event(nil), backlog...)
	b.mu.Unlock()

	go func() {
		for _, ev := range replay {
			select {
			case ch <- ev:
			default:
				return
			}
		}
	}()

	return ch, func() {
		b.mu.Lock()
		if _, ok := b.subs[id]; ok {
			delete(b.subs, id)
			close(ch)
		}
		b.mu.Unlock()
	}
}

// Recent 返回最近的若干条事件（新的在前）。
func (b *Bus) Recent(n int) []Event {
	b.mu.Lock()
	defer b.mu.Unlock()
	if n <= 0 || n > len(b.ring) {
		n = len(b.ring)
	}
	out := make([]Event, 0, n)
	for i := len(b.ring) - 1; i >= 0 && len(out) < n; i-- {
		out = append(out, b.ring[i])
	}
	return out
}

// Stats 返回订阅者数量与被丢弃的事件数。
func (b *Bus) Stats() (subscribers int, dropped int64) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.subs), b.drops
}
