// Package obs 提供日志、指标与事件流。
//
// 指标用单个自定义 Collector 实现：Prometheus 每次抓取只调用一次 Collect，
// 因此"抓一次 = 计算一次当前状态"，不会因为指标数量多而重复做昂贵计算
// （例如重新编译规则集）。
package obs

import (
	"context"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"fwdd/internal/ban"
	"fwdd/internal/engine"
)

// Version 是本进程的版本标识，导出到 fwdd_info。
const Version = "0.6.0"

// Metrics 持有指标注册表。
type Metrics struct {
	reg   *prometheus.Registry
	coll  *stateCollector
	httpC *httpMetrics

	mu sync.Mutex
	// 最近一次成功抓取的时间，用于自检（Prometheus 拉不动时能看出来）。
	lastScrape time.Time
}

// New 创建指标注册表。
func New(eng *engine.Engine, banEng *ban.Engine, backend, table string) *Metrics {
	reg := prometheus.NewRegistry()
	c := &stateCollector{
		eng:     eng,
		banEng:  banEng,
		backend: backend,
		table:   table,
	}
	reg.MustRegister(c)

	hm := newHTTPMetrics()
	hm.register(reg)

	reg.MustRegister(prometheus.NewGoCollector())
	reg.MustRegister(prometheus.NewProcessCollector(prometheus.ProcessCollectorOpts{}))

	return &Metrics{reg: reg, coll: c, httpC: hm}
}

// Handler 返回 /metrics 的处理器。
func (m *Metrics) Handler() http.Handler {
	return promhttp.HandlerFor(m.reg, promhttp.HandlerOpts{
		// 抓取失败时不要静默：暴露 fwdd_metrics_scrape_errors_total。
		ErrorHandling: promhttp.ContinueOnError,
	})
}

// Middleware 包装处理器，记录请求计数与耗时。
func (m *Metrics) Middleware(next http.Handler) http.Handler {
	return m.httpC.middleware(next)
}

// ---- 状态指标 ----

type stateCollector struct {
	eng     *engine.Engine
	banEng  *ban.Engine
	backend string
	table   string
}

// Describe 故意为空：让注册表把本 Collector 当作"未检查"处理。
//
// 指标是随引擎状态动态产生的（集合、链的数量都不固定），逐个静态声明
// 既要维护一份平行列表、又会在状态变化时误报不一致。
// 代价是注册表不再替我们发现重复的指标名 —— 由测试兜底。
func (c *stateCollector) Describe(ch chan<- *prometheus.Desc) {}

func (c *stateCollector) desc(name, help string, labels ...string) *prometheus.Desc {
	return prometheus.NewDesc(name, help, labels, nil)
}

func (c *stateCollector) Collect(ch chan<- prometheus.Metric) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// emit 的 labelNames 与 labelValues 必须分开传：
	// prometheus.NewDesc 的第三个参数是**标签名**列表，值由 MustNewConstMetric 给。
	// 把值当标签名传会生成 {forward="forward"} 这种畸形标签。
	emit := func(name, help string, typ prometheus.ValueType, v float64, labelNames []string, labelValues ...string) {
		ch <- prometheus.MustNewConstMetric(
			prometheus.NewDesc(name, help, labelNames, nil), typ, v, labelValues...)
	}
	gauge := func(name, help string, v float64) { emit(name, help, prometheus.GaugeValue, v, nil) }
	counter := func(name, help string, v float64) { emit(name, help, prometheus.CounterValue, v, nil) }

	emit("fwdd_info", "构建与后端信息，恒为 1", prometheus.GaugeValue, 1,
		[]string{"version", "backend", "table"}, Version, c.backend, c.table)

	st := c.eng.Status(ctx)
	gauge("fwdd_zones_total", "安全域数量", float64(st.Desired.Zones))
	gauge("fwdd_rules_total", "规则总数", float64(st.Desired.Rules))
	gauge("fwdd_rules_enabled", "已启用的规则数", float64(st.Desired.Enabled))
	gauge("fwdd_nat_rules_total", "NAT 规则数", float64(st.Desired.NATRules))
	gauge("fwdd_bans_active", "当前生效的封禁数", float64(st.Desired.Bans))

	// 期望状态与内核是否一致 —— 这是最值得告警的一个指标。
	gauge("fwdd_in_sync", "期望状态与内核规则集是否一致（1=一致）", boolToFloat(st.InSync))
	gauge("fwdd_pending_confirm", "是否有等待确认的变更（1=有）", boolToFloat(st.Pending != nil))
	gauge("fwdd_revisions_total", "已记录的下发次数", float64(st.Revisions))

	if st.Runtime != nil {
		for _, rc := range st.Runtime.Chains {
			emit("fwdd_chain_rules", "内核中每条链的规则数", prometheus.GaugeValue,
				float64(rc.Rules), []string{"chain"}, rc.Name)
		}
		for _, s := range st.Runtime.Sets {
			emit("fwdd_set_elements", "内核中每个集合的元素数", prometheus.GaugeValue,
				float64(s.Elements), []string{"set"}, s.Name)
		}
	}

	if c.banEng != nil {
		bs := c.banEng.Stats()
		gauge("fwdd_autoban_enabled", "自动封禁是否处于封禁模式（1=会真的封）", boolToFloat(bs.Enabled))
		gauge("fwdd_autoban_tracked", "判罚引擎正在跟踪的地址数", float64(bs.Tracked))
		gauge("fwdd_autoban_banned", "判罚引擎当前判定封禁中的地址数", float64(bs.Banned))
		counter("fwdd_autoban_observed_total", "累计观察到的可疑行为事件数", float64(bs.Observed))
		counter("fwdd_autoban_dropped_total", "因跟踪表满而被丢弃的来源数（突然增长说明正在被大规模扫描）",
			float64(bs.Dropped))
	}
}

// ---- HTTP 指标 ----

type httpMetrics struct {
	requests *prometheus.CounterVec
	duration *prometheus.HistogramVec
	inFlight prometheus.Gauge
}

func newHTTPMetrics() *httpMetrics {
	return &httpMetrics{
		requests: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "fwdd_http_requests_total",
			Help: "管理接口处理过的请求数",
		}, []string{"method", "path", "status"}),
		duration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "fwdd_http_request_duration_seconds",
			Help:    "管理接口的请求耗时",
			Buckets: []float64{0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5},
		}, []string{"method", "path"}),
		inFlight: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "fwdd_http_in_flight",
			Help: "正在处理中的管理请求数",
		}),
	}
}

func (h *httpMetrics) register(reg prometheus.Registerer) {
	reg.MustRegister(h.requests, h.duration, h.inFlight)
}

// statusRecorder 记录状态码，并**转发 Flush**。
//
// 必须实现 http.Flusher：SSE 处理器会做 `w.(http.Flusher)` 断言，
// 少这一个方法就会让实时事件流直接报"当前连接不支持流式响应"。
type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(code int) {
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}

// Flush 透传到底层 ResponseWriter。
func (r *statusRecorder) Flush() {
	if f, ok := r.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (h *httpMetrics) middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		h.inFlight.Inc()
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		defer func() {
			h.inFlight.Dec()
			// 用归一化后的路径，而不是 r.Pattern：中间件包在 mux 外面，
			// 此刻 Pattern 还没被填上（mux 是在下发给具体处理器时才设置的）。
			h.requests.WithLabelValues(r.Method, normalizePath(r.URL.Path), strconv.Itoa(rec.status)).Inc()
			h.duration.WithLabelValues(r.Method, normalizePath(r.URL.Path)).Observe(time.Since(start).Seconds())
		}()
		next.ServeHTTP(rec, r)
	})
}

// normalizePath 把路径截断到前若干段，避免 /bans/1.2.3.4 这类具体值
// 撑爆指标标签基数（每个不同的 IP 都会造出一条新的时间序列）。
func normalizePath(p string) string {
	segs := strings.Split(strings.Trim(p, "/"), "/")
	const keep = 3 // /api/v1/bans
	if len(segs) <= keep {
		return "/" + strings.Join(segs, "/")
	}
	return "/" + strings.Join(segs[:keep], "/") + "/…"
}

func boolToFloat(b bool) float64 {
	if b {
		return 1
	}
	return 0
}
