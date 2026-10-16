package api

import (
	"bufio"
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"fwdd/internal/config"
	"fwdd/internal/obs"
)

func quiet() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func sseTestServer(t *testing.T, bus *obs.Bus) *Server {
	t.Helper()
	cfg := config.Default()
	cfg.Listen = ""
	cfg.Socket = ""
	s := &Server{cfg: cfg, bus: bus, mux: http.NewServeMux(), log: quiet()}
	s.routes()
	return s
}

// SSE 必须走真实的 HTTP 连接来测。
//
// 用 httptest.NewRecorder 是测不出问题的：Recorder 自带 Flush 且不做缓冲，
// 而真实故障是"中间件包装了 ResponseWriter 却没转发 Flush，导致响应头与
// 事件全被服务端缓冲住" —— 表现为订阅上了但一个字节都收不到，且不报错。
func TestSSEDeliversEventsThroughFullMiddlewareChain(t *testing.T) {
	bus := obs.NewBus(10)
	srv := httptest.NewServer(sseTestServer(t, bus).Handler())
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL+"/api/v1/events", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("无法连接 SSE 端点: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("状态码 %d，期望 200", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/event-stream") {
		t.Errorf("Content-Type = %q，期望 text/event-stream", ct)
	}

	// 连接建立后必须立刻能收到响应头 —— 收不到就说明 flush 没透到底。
	reader := bufio.NewReader(resp.Body)

	done := make(chan string, 1)
	go func() {
		var b strings.Builder
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				done <- b.String()
				return
			}
			b.WriteString(line)
			if strings.Contains(b.String(), "ban.add") && strings.HasSuffix(b.String(), "\n\n") {
				done <- b.String()
				return
			}
		}
	}()

	// 给订阅一点时间建立，再发事件。
	time.Sleep(200 * time.Millisecond)
	bus.Publish(obs.Event{Kind: obs.EventBan, Target: "203.0.113.9", Detail: "测试"})

	select {
	case got := <-done:
		if !strings.Contains(got, "203.0.113.9") {
			t.Errorf("事件内容不完整: %q", got)
		}
		if !strings.Contains(got, "event: fwdd") {
			t.Errorf("缺少 SSE 事件名: %q", got)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("SSE 未在 3 秒内推送事件（很可能又是中间件没转发 Flush）")
	}
}

func TestSSEHeadersAreSentImmediately(t *testing.T) {
	bus := obs.NewBus(10)
	srv := httptest.NewServer(sseTestServer(t, bus).Handler())
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL+"/api/v1/events", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("应能立刻拿到响应头（否则说明 flush 没透到底）: %v", err)
	}
	defer resp.Body.Close()
	if resp.Header.Get("X-Accel-Buffering") != "no" {
		t.Error("应显式关闭反向代理缓冲，否则 nginx 后面 SSE 会卡住")
	}
}

func TestRecentEventsRequiresNoStream(t *testing.T) {
	bus := obs.NewBus(10)
	bus.Publish(obs.Event{Kind: obs.EventBan, Target: "1.2.3.4"})
	bus.Publish(obs.Event{Kind: obs.EventUnban, Target: "1.2.3.4"})

	srv := httptest.NewServer(sseTestServer(t, bus).Handler())
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/api/v1/events/recent?limit=5")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	// 最近事件应最新在前
	if !strings.Contains(string(body), "ban.remove") {
		t.Errorf("最近事件缺失: %s", body)
	}
	if strings.Index(string(body), "ban.remove") > strings.Index(string(body), `"ban.add"`) {
		t.Errorf("事件应最新在前: %s", body)
	}
}

func TestMetricsEndpointExposed(t *testing.T) {
	bus := obs.NewBus(10)
	s := sseTestServer(t, bus)
	// 指标未注入时应明确返回 501，而不是静默给个空页面
	srv := httptest.NewServer(s.Handler())
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/metrics")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotImplemented {
		t.Errorf("未注入指标时应返回 501，实际 %d", resp.StatusCode)
	}
}
