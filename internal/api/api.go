// Package api 暴露 REST 接口。所有写操作都经过 engine，Web UI 与 CLI 都只是它的消费者。
package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"fwdd/internal/ban"
	"fwdd/internal/compiler"
	"fwdd/internal/config"
	"fwdd/internal/engine"
	"fwdd/internal/model"
	"fwdd/internal/netcfg"
	"fwdd/internal/obs"
	"fwdd/internal/store"
	"fwdd/internal/webui"
)

// Server 是 HTTP 服务。
type Server struct {
	cfg     config.Config
	engine  *engine.Engine
	net     netcfg.Provider
	metrics *obs.Metrics
	bus     *obs.Bus
	ban     *ban.Engine
	log     *slog.Logger
	mux     *http.ServeMux
	start   time.Time
}

// New 构造 API 服务。
func New(cfg config.Config, e *engine.Engine, net netcfg.Provider, banEng *ban.Engine, metrics *obs.Metrics, bus *obs.Bus, log *slog.Logger) *Server {
	if log == nil {
		log = slog.Default()
	}
	if net == nil {
		net = netcfg.New()
	}
	s := &Server{
		cfg: cfg, engine: e, net: net, ban: banEng,
		metrics: metrics, bus: bus,
		log: log, mux: http.NewServeMux(), start: time.Now(),
	}
	s.routes()
	return s
}

// Handler 返回带认证中间件的 http.Handler。
func (s *Server) Handler() http.Handler {
	var h http.Handler = s.mux
	if s.metrics != nil {
		h = s.metrics.Middleware(h)
	}
	return s.auth(s.logRequests(h))
}

func (s *Server) routes() {
	p := "/api/v1"
	s.mux.HandleFunc("GET "+p+"/healthz", s.handleHealthz)
	// /metrics 刻意不带 /api/v1 前缀：Prometheus 的默认约定是根路径下的 /metrics。
	s.mux.HandleFunc("GET /metrics", s.handleMetrics)
	s.mux.HandleFunc("GET "+p+"/events", s.handleEvents)
	s.mux.HandleFunc("GET "+p+"/events/recent", s.handleRecentEvents)

	// 管理界面：静态资源挂在 /ui/ 下，根路径做个跳转。
	s.mux.Handle("/ui/", webui.Handler("/ui/"))
	s.mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/ui/", http.StatusFound)
	})
	s.mux.HandleFunc("GET "+p+"/status", s.handleStatus)
	s.mux.HandleFunc("GET "+p+"/policy", s.handleGetPolicy)
	s.mux.HandleFunc("PUT "+p+"/policy", s.handlePutPolicy)
	s.mux.HandleFunc("GET "+p+"/plan", s.handlePlan)
	s.mux.HandleFunc("GET "+p+"/ruleset", s.handleRuleset)
	s.mux.HandleFunc("POST "+p+"/apply", s.handleApply)
	s.mux.HandleFunc("POST "+p+"/confirm", s.handleConfirm)
	s.mux.HandleFunc("POST "+p+"/rollback", s.handleRollback)
	s.mux.HandleFunc("GET "+p+"/revisions", s.handleRevisions)
	s.mux.HandleFunc("GET "+p+"/audit", s.handleAudit)
	s.mux.HandleFunc("GET "+p+"/bans", s.handleListBans)
	s.mux.HandleFunc("POST "+p+"/bans", s.handleAddBan)
	s.mux.HandleFunc("DELETE "+p+"/bans/{ip}", s.handleDeleteBan)

	s.mux.HandleFunc("GET "+p+"/ban/engine", s.handleBanEngine)
	s.mux.HandleFunc("POST "+p+"/ban/engine", s.handleBanEngineToggle)
	s.mux.HandleFunc("GET "+p+"/ban/offenders", s.handleBanOffenders)
	s.mux.HandleFunc("GET "+p+"/zones", s.handleListZones)
	s.mux.HandleFunc("POST "+p+"/zones", s.handleAddZone)
	s.mux.HandleFunc("PUT "+p+"/zones/{name}", s.handleUpdateZone)
	s.mux.HandleFunc("DELETE "+p+"/zones/{name}", s.handleDeleteZone)

	s.mux.HandleFunc("GET "+p+"/rules", s.handleListRules)
	s.mux.HandleFunc("POST "+p+"/rules", s.handleAddRule)
	s.mux.HandleFunc("PUT "+p+"/rules/{id}", s.handleUpdateRule)
	s.mux.HandleFunc("DELETE "+p+"/rules/{id}", s.handleDeleteRule)
	s.mux.HandleFunc("POST "+p+"/rules/{id}/enable", s.handleEnableRule)
	s.mux.HandleFunc("POST "+p+"/rules/{id}/move", s.handleMoveRule)
	s.mux.HandleFunc("POST "+p+"/rules/order", s.handleReorderRules)

	s.mux.HandleFunc("GET "+p+"/nat", s.handleListNAT)
	s.mux.HandleFunc("POST "+p+"/nat", s.handleAddNAT)
	s.mux.HandleFunc("PUT "+p+"/nat/{id}", s.handleUpdateNAT)
	s.mux.HandleFunc("DELETE "+p+"/nat/{id}", s.handleDeleteNAT)

	s.mux.HandleFunc("GET "+p+"/config", s.handleGetConfig)

	s.mux.HandleFunc("GET "+p+"/net", s.handleNetState)
	s.mux.HandleFunc("POST "+p+"/net/sysctls", s.handleSetSysctls)
	s.mux.HandleFunc("/", s.handleNotFound)
}

// ---- 中间件 ----

func (s *Server) auth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 健康检查与界面静态资源不需要认证。
		// 界面本身不含数据，数据接口仍然要过令牌；不这样放行的话，
		// 用户连"输入令牌"这个页面都打不开。
		if strings.HasSuffix(r.URL.Path, "/healthz") || strings.HasPrefix(r.URL.Path, "/ui/") {
			next.ServeHTTP(w, r)
			return
		}
		// Unix 域套接字来源视为本机可信。
		if s.fromUnixSocket(r) {
			next.ServeHTTP(w, r)
			return
		}
		if s.cfg.Token == "" {
			next.ServeHTTP(w, r)
			return
		}
		tok := bearer(r)
		if tok == "" {
			writeError(w, http.StatusUnauthorized, "缺少 Authorization: Bearer <token>")
			return
		}
		if tok != s.cfg.Token {
			writeError(w, http.StatusForbidden, "令牌无效")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) fromUnixSocket(r *http.Request) bool {
	if !strings.HasPrefix(r.RemoteAddr, "@") && !strings.HasPrefix(r.RemoteAddr, "/") {
		return false
	}
	// Go 的 unix socket 连接 RemoteAddr 形如 "@"，本地回环 TCP 则为 IP:port。
	return !strings.Contains(r.RemoteAddr, ":")
}

func bearer(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if after, ok := strings.CutPrefix(h, "Bearer "); ok {
		return strings.TrimSpace(after)
	}
	if tok := r.Header.Get("X-FW-Token"); tok != "" {
		return tok
	}
	return r.URL.Query().Get("token")
}

func (s *Server) logRequests(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &recorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rec, r)
		if r.Method != http.MethodGet {
			s.log.Info("api", "method", r.Method, "path", r.URL.Path,
				"status", rec.status, "dur", time.Since(start).String(), "remote", r.RemoteAddr)
		}
	})
}

// recorder 记录状态码。
//
// 必须转发 Flush：SSE 处理器会做 `w.(http.Flusher)` 断言。少这一个方法，
// 断言在最内层会失败，flush 到不了真正的连接，响应头与事件全被缓冲住 ——
// 表现为"订阅上了但一个字节都收不到"，而且服务端不报任何错。
// 每包一层 ResponseWriter 都要记得转发这一组方法。
type recorder struct {
	http.ResponseWriter
	status int
}

func (r *recorder) WriteHeader(code int) {
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}

// Flush 透传到底层 ResponseWriter。
func (r *recorder) Flush() {
	if f, ok := r.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// ---- Handlers ----

func (s *Server) handleHealthz(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":      true,
		"uptime":  time.Since(s.start).Round(time.Second).String(),
		"backend": s.engine.Backend().Name(),
	})
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.engine.Status(r.Context()))
}

func (s *Server) handleGetPolicy(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.engine.Policy())
}

func (s *Server) handlePutPolicy(w http.ResponseWriter, r *http.Request) {
	var p model.Policy
	if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
		writeError(w, http.StatusBadRequest, "请求体不是合法 JSON: "+err.Error())
		return
	}
	if err := s.engine.SetPolicy(&p); err != nil {
		writeValidationError(w, err)
		return
	}
	apply := r.URL.Query().Get("apply") == "true"
	if !apply {
		writeJSON(w, http.StatusOK, map[string]any{"stored": true, "applied": false})
		return
	}
	res, err := s.engine.Apply(r.Context(), engine.ApplyOptions{Note: "PUT /policy"})
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"stored": true, "applied": true, "result": res})
}

func (s *Server) handlePlan(w http.ResponseWriter, r *http.Request) {
	plan, err := s.engine.Plan(r.Context())
	if err != nil {
		writeValidationError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, plan)
}

func (s *Server) handleRuleset(w http.ResponseWriter, r *http.Request) {
	plan, err := s.engine.Plan(r.Context())
	if err != nil {
		writeValidationError(w, err)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, plan.Text)
}

func (s *Server) handleApply(w http.ResponseWriter, r *http.Request) {
	dryRun := boolParam(r, "dry_run", false)
	confirm := boolParam(r, "confirm", false)
	timeout := time.Duration(intParam(r, "timeout", 0)) * time.Second

	res, err := s.engine.Apply(r.Context(), engine.ApplyOptions{
		DryRun:         dryRun,
		WithConfirm:    confirm,
		ConfirmTimeout: timeout,
		Note:           "POST /apply",
	})
	if err != nil {
		switch {
		case errors.Is(err, engine.ErrPendingCommit):
			writeError(w, http.StatusConflict, err.Error())
		default:
			writeValidationError(w, err)
		}
		return
	}
	writeJSON(w, http.StatusOK, res)
}

func (s *Server) handleConfirm(w http.ResponseWriter, r *http.Request) {
	if err := s.engine.Confirm(); err != nil {
		writeError(w, http.StatusConflict, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"confirmed": true})
}

func (s *Server) handleRollback(w http.ResponseWriter, r *http.Request) {
	if err := s.engine.Rollback(r.Context()); err != nil {
		writeError(w, http.StatusConflict, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"rolled_back": true})
}

func (s *Server) handleRevisions(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"revisions": s.engine.Revisions()})
}

func (s *Server) handleAudit(w http.ResponseWriter, r *http.Request) {
	limit := intParam(r, "limit", 100)
	if limit > 1000 {
		limit = 1000
	}
	entries, err := s.engine.AuditLog(r.Context(), limit)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if entries == nil {
		entries = []store.AuditEntry{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"audit": entries, "count": len(entries)})
}

func (s *Server) handleListBans(w http.ResponseWriter, r *http.Request) {
	bans := s.engine.ListBans()
	if bans == nil {
		bans = []model.BanEntry{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"bans": bans, "count": len(bans)})
}

func (s *Server) handleAddBan(w http.ResponseWriter, r *http.Request) {
	var req struct {
		IP     string `json:"ip"`
		Reason string `json:"reason"`
		TTL    int    `json:"ttl_sec"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "请求体不是合法 JSON: "+err.Error())
		return
	}
	if req.IP == "" {
		writeError(w, http.StatusBadRequest, "缺少 ip")
		return
	}
	entry := model.BanEntry{
		IP:     req.IP,
		Reason: req.Reason,
		Source: model.BanManual,
	}
	if req.TTL > 0 {
		entry.ExpiresAt = time.Now().Add(time.Duration(req.TTL) * time.Second)
	} else {
		entry.ExpiresAt = time.Now().Add(24 * time.Hour)
	}
	if err := s.engine.Ban(r.Context(), entry); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"banned": entry})
}

func (s *Server) handleDeleteBan(w http.ResponseWriter, r *http.Request) {
	ip := r.PathValue("ip")
	if ip == "" {
		writeError(w, http.StatusBadRequest, "缺少 ip")
		return
	}
	if err := s.engine.Unban(r.Context(), ip); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"unbanned": ip})
}

// ---- 可观测性 ----

// handleMetrics 暴露 Prometheus 指标。
func (s *Server) handleMetrics(w http.ResponseWriter, r *http.Request) {
	if s.metrics == nil {
		writeError(w, http.StatusNotImplemented, "指标未启用")
		return
	}
	s.metrics.Handler().ServeHTTP(w, r)
}

// handleEvents 是 SSE 实时事件流。
func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	if s.bus == nil {
		writeError(w, http.StatusNotImplemented, "事件流未启用")
		return
	}
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeError(w, http.StatusInternalServerError, "当前连接不支持流式响应")
		return
	}

	h := w.Header()
	h.Set("Content-Type", "text/event-stream; charset=utf-8")
	h.Set("Cache-Control", "no-cache")
	h.Set("Connection", "keep-alive")
	// 反向代理常会缓冲 SSE，这里显式关掉。
	h.Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)
	flusher.Flush()

	events, cancel := s.bus.Subscribe(128)
	defer cancel()

	// 心跳：既能让中间设备保持连接，也能让客户端及时发现断线。
	ticker := time.NewTicker(20 * time.Second)
	defer ticker.Stop()

	enc := json.NewEncoder(w)
	for {
		select {
		case <-r.Context().Done():
			return
		case <-ticker.C:
			fmt.Fprint(w, ": keepalive\n\n")
			flusher.Flush()
		case ev, ok := <-events:
			if !ok {
				return
			}
			if _, err := fmt.Fprint(w, "event: fwdd\n"); err != nil {
				return
			}
			if _, err := fmt.Fprint(w, "data: "); err != nil {
				return
			}
			if err := enc.Encode(ev); err != nil { // Encode 会自行换行
				return
			}
			fmt.Fprint(w, "\n")
			flusher.Flush()
		}
	}
}

// handleRecentEvents 返回最近的事件，供页面首次加载时立即填充。
func (s *Server) handleRecentEvents(w http.ResponseWriter, r *http.Request) {
	if s.bus == nil {
		writeJSON(w, http.StatusOK, map[string]any{"events": []obs.Event{}})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"events": s.bus.Recent(intParam(r, "limit", 50))})
}

// ---- 自动封禁引擎 ----

func (s *Server) handleBanEngine(w http.ResponseWriter, r *http.Request) {
	if s.ban == nil {
		writeJSON(w, http.StatusOK, map[string]any{
			"enabled": false,
			"note":    "自动封禁未启用（配置 auto_ban.enabled: true 打开）",
		})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"enabled":   true,
		"settings":  s.ban.Settings(),
		"stats":     s.ban.Stats(),
		"offenders": s.ban.Offenders(),
		"decisions": s.ban.Decisions(),
	})
}

func (s *Server) handleBanEngineToggle(w http.ResponseWriter, r *http.Request) {
	if s.ban == nil {
		writeError(w, http.StatusNotImplemented, "自动封禁未启用")
		return
	}
	var req struct {
		Enabled bool `json:"enabled"`
	}
	if !decodeBody(w, r, &req) {
		return
	}
	s.ban.SetEnabled(req.Enabled)
	s.log.Warn("自动封禁开关被更改", "enabled", req.Enabled, "remote", r.RemoteAddr)
	writeJSON(w, http.StatusOK, map[string]any{"enabled": req.Enabled})
}

// handleBanOffenders 返回当前被跟踪的最可疑地址。
func (s *Server) handleBanOffenders(w http.ResponseWriter, r *http.Request) {
	if s.ban == nil {
		writeJSON(w, http.StatusOK, map[string]any{"offenders": []any{}, "note": "自动封禁未启用"})
		return
	}
	off := s.ban.Offenders()
	if off == nil {
		off = []ban.Offender{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"offenders": off, "count": len(off)})
}

func (s *Server) handleListZones(w http.ResponseWriter, r *http.Request) {
	p := s.engine.Policy()
	zones := p.Zones
	if zones == nil {
		zones = []model.Zone{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"zones": zones, "count": len(zones)})
}

func (s *Server) handleListRules(w http.ResponseWriter, r *http.Request) {
	rules := s.engine.ListRules()
	if rules == nil {
		rules = []model.Rule{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"rules": rules, "count": len(rules)})
}

// ---- 域 CRUD ----

func (s *Server) handleAddZone(w http.ResponseWriter, r *http.Request) {
	var z model.Zone
	if !decodeBody(w, r, &z) {
		return
	}
	if err := s.engine.AddZone(z); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"created": z.Name})
}

func (s *Server) handleUpdateZone(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	var z model.Zone
	if !decodeBody(w, r, &z) {
		return
	}
	if err := s.engine.UpdateZone(name, z); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"updated": name})
}

func (s *Server) handleDeleteZone(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if err := s.engine.DeleteZone(name); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"deleted": name})
}

// ---- 规则 CRUD ----

func (s *Server) handleAddRule(w http.ResponseWriter, r *http.Request) {
	var rule model.Rule
	if !decodeBody(w, r, &rule) {
		return
	}
	id, err := s.engine.AddRule(rule)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"id": id})
}

func (s *Server) handleUpdateRule(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var rule model.Rule
	if !decodeBody(w, r, &rule) {
		return
	}
	if err := s.engine.UpdateRule(id, rule); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"updated": id})
}

func (s *Server) handleDeleteRule(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := s.engine.DeleteRule(id); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"deleted": id})
}

func (s *Server) handleEnableRule(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := s.engine.SetRuleEnabled(id, boolParam(r, "enabled", true)); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"id": id, "enabled": boolParam(r, "enabled", true)})
}

func (s *Server) handleMoveRule(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var req struct {
		Before string `json:"before"`
	}
	if r.ContentLength > 0 {
		if !decodeBody(w, r, &req) {
			return
		}
	}
	if err := s.engine.MoveRule(id, req.Before); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"moved": id, "before": req.Before})
}

func (s *Server) handleReorderRules(w http.ResponseWriter, r *http.Request) {
	var req struct {
		IDs []string `json:"ids"`
	}
	if !decodeBody(w, r, &req) {
		return
	}
	if err := s.engine.ReorderRules(req.IDs); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"reordered": len(req.IDs)})
}

// ---- NAT CRUD ----

func (s *Server) handleListNAT(w http.ResponseWriter, r *http.Request) {
	rules := s.engine.ListNATRules()
	if rules == nil {
		rules = []model.NATRule{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"nat_rules": rules, "count": len(rules)})
}

func (s *Server) handleAddNAT(w http.ResponseWriter, r *http.Request) {
	var n model.NATRule
	if !decodeBody(w, r, &n) {
		return
	}
	id, err := s.engine.AddNATRule(n)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"id": id})
}

func (s *Server) handleUpdateNAT(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var n model.NATRule
	if !decodeBody(w, r, &n) {
		return
	}
	if err := s.engine.UpdateNATRule(id, n); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"updated": id})
}

func (s *Server) handleDeleteNAT(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := s.engine.DeleteNATRule(id); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"deleted": id})
}

func (s *Server) handleNetState(w http.ResponseWriter, r *http.Request) {
	st, err := s.net.Read(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	// 附上"期望值 vs 当前值"的差异，让调用方一眼看出转发是否已打开。
	baseline := s.cfg.SysctlBaseline()
	norm, err := netcfg.Normalize(baseline)
	if err != nil {
		norm = baseline
	}
	if st.Sysctls == nil {
		st.Sysctls = map[string]string{}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"state":         st,
		"supported":     s.net.Supported(),
		"baseline":      norm,
		"sysctl_diff":   netcfg.DiffSysctls(norm, st.Sysctls),
		"forwarding_ok": st.Forwarding,
	})
}

func (s *Server) handleSetSysctls(w http.ResponseWriter, r *http.Request) {
	if !s.net.Supported() {
		writeError(w, http.StatusNotImplemented,
			"netcfg: 当前平台不支持写入内核网络参数（仅 Linux）")
		return
	}
	var req struct {
		Sysctls []netcfg.Sysctl `json:"sysctls"`
		DryRun  bool            `json:"dry_run"`
	}
	if !decodeBody(w, r, &req) {
		return
	}
	list := req.Sysctls
	if len(list) == 0 {
		list = s.cfg.SysctlBaseline()
	}
	norm, err := netcfg.Normalize(list)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	st, err := s.net.Read(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	planned := netcfg.DiffSysctls(norm, st.Sysctls)
	if req.DryRun || boolParam(r, "dry_run", false) {
		writeJSON(w, http.StatusOK, map[string]any{"dry_run": true, "changes": planned})
		return
	}

	applied, err := s.net.SetSysctls(r.Context(), norm)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{
			"error": err.Error(), "applied": applied, "planned": planned,
		})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"applied": applied, "count": len(applied)})
}

func (s *Server) handleGetConfig(w http.ResponseWriter, r *http.Request) {
	c := s.cfg
	// 不泄露令牌本体。
	c.Token = mask(c.Token)
	writeJSON(w, http.StatusOK, c)
}

func (s *Server) handleNotFound(w http.ResponseWriter, r *http.Request) {
	writeError(w, http.StatusNotFound, "未找到 "+r.URL.Path)
}

// ---- 监听 ----

// Serve 同时启动 Unix 套接字（若配置）与 TCP 监听，阻塞直到 ctx 取消。
func (s *Server) Serve(ctx context.Context) error {
	handler := s.Handler()
	var servers []*http.Server
	errCh := make(chan error, 2)

	if s.cfg.Socket != "" {
		_ = os.Remove(s.cfg.Socket)
		ln, err := net.Listen("unix", s.cfg.Socket)
		if err != nil {
			s.log.Warn("无法创建 Unix 套接字，跳过", "path", s.cfg.Socket, "err", err)
		} else {
			if err := os.Chmod(s.cfg.Socket, 0o600); err != nil {
				s.log.Warn("设置套接字权限失败", "err", err)
			}
			srv := &http.Server{Handler: handler}
			servers = append(servers, srv)
			go func() {
				s.log.Info("API 就绪（Unix 套接字）", "path", s.cfg.Socket)
				if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
					errCh <- err
				}
			}()
		}
	}

	if s.cfg.Listen != "" {
		srv := &http.Server{
			Addr:              s.cfg.Listen,
			Handler:           handler,
			ReadHeaderTimeout: 10 * time.Second,
		}
		servers = append(servers, srv)
		go func() {
			s.log.Info("API 就绪（HTTP）", "addr", s.cfg.Listen)
			if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				errCh <- err
			}
		}()
	}

	select {
	case <-ctx.Done():
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		for _, srv := range servers {
			_ = srv.Shutdown(shutCtx)
		}
		return nil
	case err := <-errCh:
		return err
	}
}

// ---- 工具 ----

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}

func writeError(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]any{"error": msg})
}

// decodeBody 解析 JSON 请求体；失败时已写出 400 响应，返回 false。
func decodeBody(w http.ResponseWriter, r *http.Request, v any) bool {
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		writeError(w, http.StatusBadRequest, "请求体不是合法 JSON: "+err.Error())
		return false
	}
	return true
}

// writeValidationError 把校验失败映射为 400，其余映射为 500。
func writeValidationError(w http.ResponseWriter, err error) {
	var ve *compiler.ValidationError
	if errors.As(err, &ve) {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"error":    "策略校验失败",
			"problems": ve.Problems,
		})
		return
	}
	writeError(w, http.StatusBadRequest, err.Error())
}

func boolParam(r *http.Request, name string, def bool) bool {
	v := r.URL.Query().Get(name)
	if v == "" {
		return def
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return def
	}
	return b
}

func intParam(r *http.Request, name string, def int) int {
	v := r.URL.Query().Get(name)
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return def
	}
	return n
}

func mask(s string) string {
	if s == "" {
		return ""
	}
	if len(s) <= 4 {
		return "****"
	}
	return s[:2] + strings.Repeat("*", len(s)-4) + s[len(s)-2:]
}
