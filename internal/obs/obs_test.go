package obs

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"fwdd/internal/ban"
	"fwdd/internal/version"
)

func TestNormalizePathBoundsCardinality(t *testing.T) {
	cases := map[string]string{
		"/api/v1/bans/203.0.113.9":     "/api/v1/bans/…",
		"/api/v1/rules/rule-1":         "/api/v1/rules/…",
		"/api/v1/status":               "/api/v1/status",
		"/metrics":                     "/metrics",
		"/api/v1/zones/lan/interfaces": "/api/v1/zones/…",
	}
	for in, want := range cases {
		if got := normalizePath(in); got != want {
			t.Errorf("normalizePath(%q) = %q，期望 %q", in, got, want)
		}
	}
}

// 日志中间件包装 ResponseWriter 时必须转发 Flush，否则 SSE 一个字节都发不出去。
func TestStatusRecorderForwardsFlush(t *testing.T) {
	underlying := &flushCounter{}
	rec := &statusRecorder{ResponseWriter: underlying, status: 200}

	f, ok := interface{}(rec).(http.Flusher)
	if !ok {
		t.Fatal("statusRecorder 必须实现 http.Flusher")
	}
	f.Flush()
	if underlying.flushed != 1 {
		t.Errorf("Flush 未透传到底层，实际调用 %d 次", underlying.flushed)
	}
}

type flushCounter struct {
	http.ResponseWriter
	flushed int
}

func (f *flushCounter) Header() http.Header         { return http.Header{} }
func (f *flushCounter) Write(b []byte) (int, error) { return len(b), nil }
func (f *flushCounter) WriteHeader(int)             {}
func (f *flushCounter) Flush()                      { f.flushed++ }

func TestBusPublishNeverBlocks(t *testing.T) {
	bus := NewBus(10)
	// 订阅者完全不读，缓冲区很快满
	_, cancel := bus.Subscribe(2)
	defer cancel()

	done := make(chan struct{})
	go func() {
		for i := 0; i < 1000; i++ {
			bus.Publish(Event{Kind: EventBan, Target: "1.2.3.4"})
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("Publish 被慢订阅者阻塞了 —— 一个卡住的页面不能拖垮防火墙")
	}

	if _, dropped := bus.Stats(); dropped == 0 {
		t.Error("应记录被丢弃的事件数，便于发现订阅者跟不上")
	}
}

func TestBusReplaysRecentToNewSubscriber(t *testing.T) {
	bus := NewBus(10)
	for i := 0; i < 3; i++ {
		bus.Publish(Event{Kind: EventPolicy, Target: "x"})
	}
	ch, cancel := bus.Subscribe(4)
	defer cancel()

	got := 0
	deadline := time.After(time.Second)
	for got < 3 {
		select {
		case <-ch:
			got++
		case <-deadline:
			t.Fatalf("新订阅者只回放到 %d 条，期望 3 条", got)
		}
	}
}

func TestBusUnsubscribeStopsDelivery(t *testing.T) {
	bus := NewBus(10)
	ch, cancel := bus.Subscribe(8)
	cancel()

	if subs, _ := bus.Stats(); subs != 0 {
		t.Errorf("取消订阅后不应还有订阅者: %d", subs)
	}
	// 取消后 Publish 不应 panic（向已关闭 channel 发送会 panic）
	bus.Publish(Event{Kind: EventBan})
	if _, ok := <-ch; ok {
		t.Error("取消订阅后 channel 应已关闭")
	}
}

func TestBusRecentNewestFirst(t *testing.T) {
	bus := NewBus(10)
	bus.Publish(Event{Kind: "a"})
	bus.Publish(Event{Kind: "b"})
	evs := bus.Recent(2)
	if len(evs) != 2 || evs[0].Kind != "b" {
		t.Errorf("最近事件应最新在前: %+v", evs)
	}
}

func TestBusRingIsBounded(t *testing.T) {
	bus := NewBus(5)
	for i := 0; i < 100; i++ {
		bus.Publish(Event{Kind: "x"})
	}
	if n := len(bus.Recent(0)); n != 5 {
		t.Errorf("环形缓冲应有上限 5，实际 %d", n)
	}
}

// 真抓一次 /metrics，确认指标名与标签形态正确。
//
// 这里特意断言标签是 name="value"：最初实现把标签**值**当成了标签名传给
// prometheus.NewDesc，导出成 {forward="forward"} 这种畸形标签，
// 只看"有输出"是发现不了的。
func TestMetricsCollectorExposesCorrectLabels(t *testing.T) {
	eng := newTestEngine(t)
	banEng, err := ban.New(ban.DefaultSettings())
	if err != nil {
		t.Fatal(err)
	}
	m := New(eng, banEng, "mock", "fw")

	rec := httptest.NewRecorder()
	m.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	body := rec.Body.String()

	for _, want := range []string{
		`fwdd_info{backend="mock",table="fw",version="` + version.Version + `"}`,
		`fwdd_rules_total `,
		`fwdd_in_sync `,
		`fwdd_chain_rules{chain="forward"}`,
		`fwdd_zones_total `,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("指标输出缺少 %q\n--- 输出 ---\n%s", want, truncate(body, 2000))
		}
	}

	// 值被当成标签名的典型症状
	if strings.Contains(body, `{forward=`) || strings.Contains(body, `{mock=`) {
		t.Errorf("标签名与值传反了:\n%s", truncate(body, 2000))
	}
}

func TestMetricsMiddlewareRecordsRequests(t *testing.T) {
	eng := newTestEngine(t)
	m := New(eng, nil, "mock", "fw")

	h := m.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
	}))
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/api/v1/bans/203.0.113.9", nil))

	rec := httptest.NewRecorder()
	m.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	body := rec.Body.String()

	if !strings.Contains(body, `fwdd_http_requests_total{method="POST",path="/api/v1/bans/…",status="201"} 1`) {
		t.Errorf("请求计数未按预期归一化路径:\n%s", truncate(body, 2000))
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "...(截断)"
}
