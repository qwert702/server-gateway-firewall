package alert

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

type fakeNotifier struct {
	mu     sync.Mutex
	events []Event
	err    error
	name   string
	block  chan struct{} // 非 nil 时 Notify 会阻塞直到收到信号
}

func (f *fakeNotifier) Name() string {
	if f.name == "" {
		return "fake"
	}
	return f.name
}

func (f *fakeNotifier) Notify(ctx context.Context, ev Event) error {
	if f.block != nil {
		select {
		case <-f.block:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return f.err
	}
	f.events = append(f.events, ev)
	return nil
}

func (f *fakeNotifier) got() []Event {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]Event(nil), f.events...)
}

func quiet() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("等待条件超时")
}

func TestSendDeliversEvent(t *testing.T) {
	f := &fakeNotifier{}
	m := New([]Notifier{f}, WithLogger(quiet()))
	defer m.Close()

	m.Send(Event{Kind: "autoban", IP: "203.0.113.9", Title: "测试", Severity: SevWarn})
	waitFor(t, func() bool { return len(f.got()) == 1 })

	got := f.got()[0]
	if got.IP != "203.0.113.9" || got.Title != "测试" {
		t.Errorf("事件内容不正确: %+v", got)
	}
	if got.At.IsZero() {
		t.Error("应自动补上时间")
	}
}

// 去重窗口内的重复事件只发一次 —— 一次端口扫描能瞬间产生几十条封禁，
// 逐条推送会把人淹没，然后就没人看告警了。
func TestDuplicateEventsAreMergedWithinCooldown(t *testing.T) {
	f := &fakeNotifier{}
	m := New([]Notifier{f}, WithLogger(quiet()), WithCooldown(time.Minute))
	defer m.Close()

	for i := 0; i < 20; i++ {
		m.Send(Event{Kind: "autoban", IP: "203.0.113.9", Title: "封禁", Severity: SevWarn})
	}
	waitFor(t, func() bool { return len(f.got()) >= 1 })
	time.Sleep(80 * time.Millisecond) // 给可能的重复投递留点时间

	if n := len(f.got()); n != 1 {
		t.Errorf("同一 IP 的重复封禁在去重窗口内应只发一次，实际发了 %d 次", n)
	}
	_, merged, _ := m.Stats()
	if merged != 19 {
		t.Errorf("应记录 19 条被合并，实际 %d", merged)
	}
}

// 不同 IP 不应互相合并。
func TestDifferentIPsAreNotMerged(t *testing.T) {
	f := &fakeNotifier{}
	m := New([]Notifier{f}, WithLogger(quiet()), WithCooldown(time.Minute))
	defer m.Close()

	m.Send(Event{Kind: "autoban", IP: "203.0.113.1", Title: "封禁", Severity: SevWarn})
	m.Send(Event{Kind: "autoban", IP: "203.0.113.2", Title: "封禁", Severity: SevWarn})
	waitFor(t, func() bool { return len(f.got()) == 2 })
}

// 不同类型的同 IP 也不应合并（封禁和回滚是两回事）。
func TestDifferentKindsAreNotMerged(t *testing.T) {
	f := &fakeNotifier{}
	m := New([]Notifier{f}, WithLogger(quiet()), WithCooldown(time.Minute))
	defer m.Close()

	m.Send(Event{Kind: "autoban", IP: "203.0.113.1", Title: "封禁", Severity: SevWarn})
	m.Send(Event{Kind: "rollback", IP: "203.0.113.1", Title: "回滚", Severity: SevWarn})
	waitFor(t, func() bool { return len(f.got()) == 2 })
}

func TestMinSeverityFilters(t *testing.T) {
	f := &fakeNotifier{}
	m := New([]Notifier{f}, WithLogger(quiet()), WithMinSeverity(SevWarn))
	defer m.Close()

	m.Send(Event{Kind: "info", IP: "1.1.1.1", Title: "不重要的", Severity: SevInfo})
	m.Send(Event{Kind: "crit", IP: "2.2.2.2", Title: "重要的", Severity: SevCrit})
	waitFor(t, func() bool { return len(f.got()) == 1 })

	if got := f.got()[0]; got.Title != "重要的" {
		t.Errorf("只有达到级别的应发送: %+v", got)
	}
}

// Send 绝不能阻塞：它跑在封禁决策的路径上，
// 一个卡住的 webhook 不能让防火墙失去响应。
func TestSendNeverBlocksOnStuckChannel(t *testing.T) {
	block := make(chan struct{})
	f := &fakeNotifier{block: block}
	m := New([]Notifier{f}, WithLogger(quiet()), WithCooldown(time.Minute))
	defer m.Close()
	defer close(block)

	// 每条事件的键都不同（不同 IP），所以不会被去重合并 ——
	// 目的就是让队列真的堆满。用同一个 IP 会被合并，测不到队列行为。
	done := make(chan struct{})
	go func() {
		for i := 0; i < 2000; i++ {
			m.Send(Event{
				Kind: "k", IP: string(rune('a'+i%26)) + "-" + string(rune('a'+(i/26)%26)) + "-" + string(rune('a'+(i/676)%26)),
				Title: "t", Severity: SevInfo,
			})
		}
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("Send 被卡住的通道阻塞了")
	}
	// 队列满时会丢弃，丢弃必须计数而不是静默
	_, _, dropped := m.Stats()
	if dropped == 0 {
		t.Errorf("队列溢出应被计数，否则会静默失去告警")
	}
}

func TestChannelErrorDoesNotStopOtherChannels(t *testing.T) {
	bad := &fakeNotifier{name: "bad", err: errors.New("挂了")}
	good := &fakeNotifier{name: "good"}
	m := New([]Notifier{bad, good}, WithLogger(quiet()))
	defer m.Close()

	m.Send(Event{Kind: "k", Title: "t", Severity: SevInfo})
	waitFor(t, func() bool { return len(good.got()) == 1 })
}

func TestSendSyncReportsErrors(t *testing.T) {
	bad := &fakeNotifier{name: "bad", err: errors.New("连接被拒绝")}
	good := &fakeNotifier{name: "good"}
	m := New([]Notifier{bad, good}, WithLogger(quiet()))
	defer m.Close()

	errs := m.SendSync(context.Background(), Event{Kind: "test", Title: "t"})
	if len(errs) != 1 {
		t.Fatalf("应报告 1 个通道失败，实际 %d: %v", len(errs), errs)
	}
	if !strings.Contains(errs[0].Error(), "bad") {
		t.Errorf("错误信息应指出是哪个通道: %v", errs[0])
	}
	if len(good.got()) != 1 {
		t.Error("失败的通道不应影响其他通道")
	}
}

func TestDisabledManagerIsInert(t *testing.T) {
	m := New(nil, WithLogger(quiet()))
	defer m.Close()
	if m.Enabled() {
		t.Error("没有通道时 Enabled 应为 false")
	}
	m.Send(Event{Kind: "k", Title: "t"}) // 不应 panic
}

func TestForgetCleansUpDedupTable(t *testing.T) {
	f := &fakeNotifier{}
	m := New([]Notifier{f}, WithLogger(quiet()), WithCooldown(time.Millisecond))
	defer m.Close()

	for i := 0; i < 100; i++ {
		m.Send(Event{Kind: "k", IP: string(rune('a'+i%26)) + ".0.0.1", Title: "t", Severity: SevInfo})
	}
	time.Sleep(20 * time.Millisecond)
	m.Forget()

	m.mu.Lock()
	n := len(m.pending)
	m.mu.Unlock()
	if n != 0 {
		t.Errorf("过期记录应被清理，还剩 %d 条", n)
	}
}

// ---- sink ----

func TestWebhookFormats(t *testing.T) {
	cases := []struct {
		format   WebhookFormat
		contains string
	}{
		{FormatWecom, `"msgtype":"text"`},
		{FormatDingtalk, `"msgtype":"text"`},
		{FormatFeishu, `"msg_type":"text"`},
		{FormatTelegram, `"chat_id"`},
		{FormatGeneric, `"kind"`},
	}
	for _, c := range cases {
		var got []byte
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			got, _ = io.ReadAll(r.Body)
			w.WriteHeader(200)
		}))
		n, err := NewWebhook(WebhookOptions{URL: srv.URL, Format: c.format, ChatID: "123"})
		if err != nil {
			t.Fatalf("%s: %v", c.format, err)
		}
		if err := n.Notify(context.Background(), Event{Kind: "autoban", IP: "1.2.3.4", Title: "封禁", Severity: SevWarn}); err != nil {
			t.Fatalf("%s: 投递失败: %v", c.format, err)
		}
		if !strings.Contains(string(got), c.contains) {
			t.Errorf("%s 的 payload 应含 %q，实际: %s", c.format, c.contains, got)
		}
		srv.Close()
	}
}

// 机器人接口出错时返回 HTTP 200 + 业务错误码，只看状态码会把失败当成功。
func TestWebhookDetectsRobotErrorCode(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		_, _ = w.Write([]byte(`{"errcode":93000,"errmsg":"invalid webhook url"}`))
	}))
	defer srv.Close()

	n, _ := NewWebhook(WebhookOptions{URL: srv.URL, Format: FormatWecom})
	err := n.Notify(context.Background(), Event{Kind: "test", Title: "t"})
	if err == nil {
		t.Fatal("HTTP 200 但业务错误码非 0 时必须报错")
	}
	if !strings.Contains(err.Error(), "93000") {
		t.Errorf("错误信息应带上业务错误码: %v", err)
	}
}

func TestWebhookRejectsBadConfig(t *testing.T) {
	if _, err := NewWebhook(WebhookOptions{}); err == nil {
		t.Error("缺 url 应报错")
	}
	if _, err := NewWebhook(WebhookOptions{URL: "http://x", Format: "不存在的格式"}); err == nil {
		t.Error("未知格式应报错")
	}
	if _, err := NewWebhook(WebhookOptions{URL: "http://x", Format: FormatTelegram}); err == nil {
		t.Error("telegram 缺 chat_id 应报错")
	}
}

func TestSMTPRejectsBadConfig(t *testing.T) {
	if _, err := NewSMTP(SMTPOptions{}); err == nil {
		t.Error("缺参数应报错")
	}
	if _, err := NewSMTP(SMTPOptions{Addr: "x:25", From: "a@b", To: []string{"c@d"}}); err != nil {
		t.Errorf("参数齐全时应成功: %v", err)
	}
}

func TestCommandRejectsBadConfig(t *testing.T) {
	if _, err := NewCommand(CommandOptions{}); err == nil {
		t.Error("缺 command 应报错")
	}
	n, err := NewCommand(CommandOptions{Command: "/bin/true"})
	if err != nil {
		t.Fatal(err)
	}
	if n.Name() != "command" {
		t.Errorf("通道名应为 command，实际 %q", n.Name())
	}
}

func TestParseSeverity(t *testing.T) {
	cases := map[string]Severity{"": SevInfo, "info": SevInfo, "warn": SevWarn, "warning": SevWarn, "critical": SevCrit}
	for in, want := range cases {
		got, err := ParseSeverity(in)
		if err != nil || got != want {
			t.Errorf("ParseSeverity(%q) = %v, %v；期望 %v", in, got, err, want)
		}
	}
	if _, err := ParseSeverity("nope"); err == nil {
		t.Error("未知级别应报错")
	}
}

func TestSeverityAtLeast(t *testing.T) {
	if !SevCrit.AtLeast(SevWarn) {
		t.Error("critical 应达到 warn 的下限")
	}
	if SevInfo.AtLeast(SevWarn) {
		t.Error("info 不应达到 warn 的下限")
	}
}

func TestEventStringIsReadable(t *testing.T) {
	ev := Event{Severity: SevWarn, Kind: "autoban", IP: "203.0.113.9", Title: "自动封禁", Detail: "窗口内累计 20 达阈值", Count: 3}
	s := ev.String()
	for _, want := range []string{"warn", "自动封禁", "203.0.113.9", "×3", "阈值"} {
		if !strings.Contains(s, want) {
			t.Errorf("告警文本应含 %q: %s", want, s)
		}
	}
	// 结构化部分必须能序列化（generic webhook 与 command 通道都依赖它）
	if _, err := json.Marshal(ev); err != nil {
		t.Errorf("事件应可序列化: %v", err)
	}
}
