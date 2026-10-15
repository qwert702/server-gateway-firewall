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

	"fwdd/internal/compiler"
	"fwdd/internal/config"
	"fwdd/internal/engine"
	"fwdd/internal/model"
	"fwdd/internal/store"
)

// Server 是 HTTP 服务。
type Server struct {
	cfg    config.Config
	engine *engine.Engine
	log    *slog.Logger
	mux    *http.ServeMux
	start  time.Time
}

// New 构造 API 服务。
func New(cfg config.Config, e *engine.Engine, log *slog.Logger) *Server {
	if log == nil {
		log = slog.Default()
	}
	s := &Server{cfg: cfg, engine: e, log: log, mux: http.NewServeMux(), start: time.Now()}
	s.routes()
	return s
}

// Handler 返回带认证中间件的 http.Handler。
func (s *Server) Handler() http.Handler {
	return s.auth(s.logRequests(s.mux))
}

func (s *Server) routes() {
	p := "/api/v1"
	s.mux.HandleFunc("GET "+p+"/healthz", s.handleHealthz)
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
	s.mux.HandleFunc("GET "+p+"/zones", s.handleListZones)
	s.mux.HandleFunc("GET "+p+"/rules", s.handleListRules)
	s.mux.HandleFunc("GET "+p+"/config", s.handleGetConfig)
	s.mux.HandleFunc("/", s.handleNotFound)
}

// ---- 中间件 ----

func (s *Server) auth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 健康检查与静态资源不需要认证。
		if strings.HasSuffix(r.URL.Path, "/healthz") {
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

type recorder struct {
	http.ResponseWriter
	status int
}

func (r *recorder) WriteHeader(code int) {
	r.status = code
	r.ResponseWriter.WriteHeader(code)
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

func (s *Server) handleListZones(w http.ResponseWriter, r *http.Request) {
	p := s.engine.Policy()
	zones := p.Zones
	if zones == nil {
		zones = []model.Zone{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"zones": zones, "count": len(zones)})
}

func (s *Server) handleListRules(w http.ResponseWriter, r *http.Request) {
	p := s.engine.Policy()
	rules := p.Rules
	if rules == nil {
		rules = []model.Rule{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"rules": rules, "count": len(rules)})
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
