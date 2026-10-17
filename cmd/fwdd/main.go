// Command fwdd 是防火墙守护进程。
//
// 启动顺序（与计划中的"启动恢复顺序"一致）：
//
//	加载配置 → 构造后端 → 加载策略基线 → （可选）下发到内核 → 启动 REST API → 等待信号
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"fwdd/internal/alert"
	"fwdd/internal/api"
	"fwdd/internal/backend"
	"fwdd/internal/backend/mock"
	"fwdd/internal/backend/nftables"
	"fwdd/internal/ban"
	"fwdd/internal/config"
	"fwdd/internal/engine"
	"fwdd/internal/model"
	"fwdd/internal/netcfg"
	"fwdd/internal/obs"
	"fwdd/internal/store"
	"fwdd/internal/version"
	"gopkg.in/yaml.v3"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "fwdd: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	var (
		cfgPath      = flag.String("config", defaultConfigPath(), "配置文件路径（缺失时自动生成）")
		backendName  = flag.String("backend", "", "覆盖配置中的后端：nftables | mock")
		mode         = flag.String("mode", "", "覆盖部署形态：gateway（网关，默认）| host（主机）")
		listen       = flag.String("listen", "", "覆盖 HTTP 监听地址")
		policyPath   = flag.String("policy", "", "策略文件路径（YAML）")
		applyStart   = flag.Bool("apply-on-start", true, "启动时把策略下发到内核")
		dryRun       = flag.Bool("dry-run", false, "只渲染不下发，打印规则集后退出")
		noPersist    = flag.Bool("no-persist", false, "关闭持久化（策略与封禁只留在内存）")
		importPolicy = flag.Bool("import-policy", false, "用 -policy 文件覆盖数据库中的期望状态")
		actor        = flag.String("actor", "fwdd", "审计日志中的操作者标识")
		logLevel     = flag.String("log-level", "", "覆盖日志级别：debug|info|warn|error")
		showVersion  = flag.Bool("version", false, "打印版本并退出")
	)
	flag.Parse()

	if *showVersion {
		fmt.Println("fwdd " + version.Short())
		return nil
	}

	cfg, err := config.LoadOrCreate(*cfgPath)
	if err != nil {
		return err
	}
	if *backendName != "" {
		cfg.Backend = *backendName
	}
	if *mode != "" {
		cfg.Mode = *mode
	}
	if *listen != "" {
		cfg.Listen = *listen
	}
	if *policyPath != "" {
		cfg.PolicyFile = *policyPath
	}
	if *logLevel != "" {
		cfg.LogLevel = *logLevel
	}
	if err := cfg.Validate(); err != nil {
		return fmt.Errorf("配置无效: %w", err)
	}

	logger := newLogger(cfg.LogLevel)
	slog.SetDefault(logger)

	be, err := buildBackend(cfg, logger)
	if err != nil {
		return err
	}
	defer be.Close()
	logger.Info("后端就绪", "backend", be.Name(), "table", cfg.Table, "family", cfg.Family)

	// 打开持久化存储。
	var db *store.DB
	if !*noPersist && !cfg.DisablePersist {
		path := cfg.DBPath
		if path == "" {
			path = filepath.Join(cfg.DataDir, "fwdd.db")
		}
		db, err = store.Open(path)
		if err != nil {
			return fmt.Errorf("打开数据库失败: %w", err)
		}
		defer db.Close()
		logger.Info("已打开数据库", "path", path)
	} else {
		logger.Warn("持久化已关闭：策略与封禁只存在于内存，重启即遗忘")
	}

	eng := engine.New(cfg, be, logger, engine.WithStore(db), engine.WithActor(*actor))

	// 加载策略文件作为基线（仅在数据库为空时使用）。
	var baseline *model.Policy
	if cfg.PolicyFile != "" {
		p, err := loadPolicy(cfg.PolicyFile)
		if err != nil {
			return fmt.Errorf("加载策略 %s 失败: %w", cfg.PolicyFile, err)
		}
		baseline = p
		logger.Info("已读取策略基线", "path", cfg.PolicyFile,
			"zones", len(p.Zones), "rules", len(p.Rules))
	}

	fromDB, err := eng.Restore(context.Background(), baseline)
	if err != nil {
		return err
	}
	if *importPolicy {
		if baseline == nil {
			return errors.New("-import-policy 需要同时指定 -policy 策略文件")
		}
		if err := eng.SetPolicy(baseline); err != nil {
			return fmt.Errorf("导入策略失败: %w", err)
		}
		logger.Info("已用策略文件覆盖数据库中的期望状态", "path", cfg.PolicyFile)
	} else if fromDB {
		logger.Info("数据库中的策略优先于策略文件（如需用文件覆盖请加 -import-policy）")
	}

	if *dryRun {
		plan, err := eng.Plan(context.Background())
		if err != nil {
			return err
		}
		fmt.Print(plan.Text)
		return nil
	}

	if *applyStart && cfg.PolicyFile != "" {
		// 启动恢复不进入 commit-confirm 窗口：本地策略文件是可信基线，
		// 无人值守重启若还要等确认，超时回滚会把防火墙整个撤掉。
		res, err := eng.Apply(context.Background(), engine.ApplyOptions{
			Note:           "启动下发",
			ForceNoConfirm: true,
		})
		if err != nil {
			return fmt.Errorf("启动下发失败: %w", err)
		}
		logger.Info("策略已下发", "rules", res.Rules, "changed", res.Changed, "hash", res.Hash)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// 网络配置检查：这是网关防火墙最容易踩的坑 —— 转发没打开时，
	// 规则集看起来完全正确，nft 也加载成功，但跨网段流量根本不会
	// 到达 filter 钩子，表现为"策略写了却不生效"。
	netProvider := netcfg.New()
	checkNetworking(ctx, netProvider, cfg, logger)

	// 后台维护：定期清理已过期的封禁记录。
	eng.StartMaintenance(ctx)

	// 告警通道：在封禁引擎之前建好，好让判罚结果能直接推出去。
	alerts, err := buildAlerts(cfg, logger)
	if err != nil {
		return err
	}
	defer alerts.Close()

	// 自动封禁：检测器 → 判罚引擎 → 封禁执行。
	banEng, err := buildAutoBan(ctx, cfg, eng, alerts, logger)
	if err != nil {
		return err
	}

	// 可观测性：事件总线（SSE 实时视图）与 Prometheus 指标。
	bus := obs.NewBus(300)
	eng.OnEvent(func(action, target, detail string) {
		bus.Publish(obs.Event{Kind: action, Target: target, Detail: detail})
		alertFromAudit(alerts, action, target, detail)
	})
	metrics := obs.New(eng, banEng, be.Name(), cfg.Table)

	srv := api.New(cfg, eng, netProvider, banEng, metrics, bus, alerts, logger)
	logger.Info("fwdd 启动完成", "backend", be.Name())
	if err := srv.Serve(ctx); err != nil {
		return err
	}
	logger.Info("fwdd 已退出")
	return nil
}

// checkNetworking 检查（可选地管理）内核网络参数。
//
// 默认只检查并告警，不擅自改动内核 —— 悄悄打开转发开关这种事，
// 应该由管理员显式配置 manage_sysctls: true 决定。
func checkNetworking(ctx context.Context, np netcfg.Provider, cfg config.Config, logger *slog.Logger) {
	st, err := np.Read(ctx)
	if err != nil {
		logger.Warn("读取网络状态失败，跳过转发检查", "err", err)
		return
	}
	if !np.Supported() {
		logger.Info("当前平台不支持管理内核网络参数，跳过转发检查", "platform", np.Platform())
		return
	}

	baseline, err := netcfg.Normalize(cfg.SysctlBaseline())
	if err != nil {
		logger.Error("内核参数配置非法", "err", err)
		return
	}

	if cfg.ManageSysctls {
		applied, err := np.SetSysctls(ctx, baseline)
		if err != nil {
			logger.Error("写入内核网络参数失败", "err", err, "applied", len(applied))
			// 继续启动：网络参数写入失败不应阻止防火墙本身工作。
		} else if len(applied) == 0 {
			logger.Info("内核网络参数已符合基线，无需变更")
		} else {
			for _, c := range applied {
				logger.Info("已设置内核参数", "key", c.Target, "from", c.From, "to", c.To)
			}
		}
	}

	// 无论是否管理，都要重新读一次并检查转发状态。
	if st, err = np.Read(ctx); err != nil {
		return
	}
	switch {
	case cfg.IsHost():
		// 主机模式下"不转发"是**期望状态**，不是问题。
		// 这里只在它意外开着时提一句 —— 开着本身无害（没有路由就不会转发），
		// 但可能说明这台机器上有 Docker 之类的组件在设它。
		if st.Forwarding {
			logger.Info("检测到 IPv4 转发已开启（主机模式下不需要；通常是 Docker 等组件设的）",
				"提示", "主机模式不注册 forward 链，因此与它不冲突")
		}
	case !st.Forwarding:
		logger.Warn("⚠ IPv4 转发未开启：跨网段流量不会经过 forward 钩子，防火墙策略对它完全不生效",
			"修复", "sysctl -w net.ipv4.ip_forward=1，或在配置中设置 manage_sysctls: true")
	}
	for _, c := range netcfg.DiffSysctls(baseline, st.Sysctls) {
		logger.Info("内核参数与基线不一致（未自动修改）",
			"key", c.Target, "current", c.From, "expected", c.To,
			"提示", "设置 manage_sysctls: true 可让 fwdd 自动管理")
	}
}

// startAutoBan 装配并启动自动封禁：检测器 → 判罚引擎 → 封禁执行。
//
// 关键取舍：默认只观察不封禁（auto_ban.enabled=false）。误封一个有合法用途的
// 地址（监控探针、NAT 出口、爬虫）比漏封更难收拾，应该先看一段真实流量再打开。
func buildAutoBan(ctx context.Context, cfg config.Config, eng *engine.Engine, alerts *alert.Manager, logger *slog.Logger) (*ban.Engine, error) {
	ab := cfg.AutoBan

	// 未配置任何检测器时，enabled 本身就意味着"用 conntrack 检测"，
	// 否则打开开关却什么都不检测，很容易让人以为功能坏了。
	useConntrack := ab.Conntrack.Enabled
	logSources := ab.Logs
	if ab.Enabled && !useConntrack && len(logSources) == 0 {
		useConntrack = true
		logger.Info("auto_ban 已开启但未配置检测器，默认启用 conntrack 检测")
	}
	if !useConntrack && len(logSources) == 0 {
		return nil, nil
	}

	settings := cfg.BanSettings()
	be, err := ban.New(settings, ban.WithDecisionHook(func(d ban.Decision) {
		switch d.Action {
		case ban.ActionBan:
			logger.Warn("自动封禁",
				"ip", d.IP, "ttl", d.TTL.String(), "第几次", d.Strikes, "原因", d.Reason)
			alerts.Send(alert.Event{
				Severity: alert.SevWarn,
				Kind:     "autoban",
				IP:       d.IP,
				Title:    fmt.Sprintf("自动封禁 %s（第 %d 次，%s）", d.IP, d.Strikes, d.TTL),
				Detail:   d.Reason,
			})
		case ban.ActionObserve:
			logger.Info("达到封禁阈值但未开启自动封禁（观察模式）",
				"ip", d.IP, "原因", d.Reason)
			// 观察模式下也推：这正是"先看一段时间有没有误报"要用的信息。
			alerts.Send(alert.Event{
				Severity: alert.SevInfo,
				Kind:     "observe",
				IP:       d.IP,
				Title:    fmt.Sprintf("可疑来源 %s 已达阈值（当前只观察不封禁）", d.IP),
				Detail:   d.Reason,
			})
		}
		// 取证记录：判罚决策在这里留档，因为只有这里同时有
		// "窗口内命中多少次""第几次违规"这些细节。
		// 手工封禁由 engine.Ban 记录（那条路没有判罚引擎的上下文）。
		switch d.Action {
		case ban.ActionBan:
			eng.RecordAttackEvent(ctx, store.BanEvent{
				At: d.At, IP: d.IP, Action: "ban",
				Source: strings.Join(d.Sources, ","),
				Reason: d.Reason, EventCount: d.EventCount, Strikes: d.Strikes,
				TTL: d.TTL,
			})
		case ban.ActionObserve:
			eng.RecordAttackEvent(ctx, store.BanEvent{
				At: d.At, IP: d.IP, Action: "observe",
				Source: strings.Join(d.Sources, ","),
				Reason: d.Reason, EventCount: d.EventCount, Strikes: d.Strikes,
			})
		}
	}))
	if err != nil {
		return nil, fmt.Errorf("自动封禁配置无效: %w", err)
	}

	// 判罚结果直接落到 engine：写期望状态 → 落库 → 注入内核集合。
	be.AttachSink(eng)
	// 手工解封时清空计数窗口，否则残留事件会让它立刻又被封上。
	eng.OnUnban(be.Forget)

	events := make(chan ban.Event, 4096)
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case ev := <-events:
				be.Observe(ev)
			}
		}
	}()

	var detectors []ban.Detector
	if useConntrack {
		cc := ab.Conntrack
		detectors = append(detectors, &ban.ConntrackDetector{
			Path:              cc.Path,
			Interval:          cc.Interval,
			MaxNewPerInterval: cc.MaxNewPerInterval,
			MaxConcurrent:     cc.MaxConcurrent,
		})
		logger.Info("已启用 conntrack 检测",
			"interval", orDefault(cc.Interval, 10*time.Second).String(),
			"max_new_per_interval", cc.MaxNewPerInterval,
			"max_concurrent", cc.MaxConcurrent)
	}
	for _, ls := range logSources {
		pats := ls.Patterns
		if len(pats) == 0 {
			pats = ban.DefaultLogPatterns()
		}
		compiled, err := ban.CompilePatterns(pats)
		if err != nil {
			return nil, fmt.Errorf("日志检测器 %s 配置无效: %w", ls.Path, err)
		}
		detectors = append(detectors, &ban.LogWatcher{Path: ls.Path, Patterns: compiled, FromEnd: true})
		logger.Info("已启用日志检测", "path", ls.Path, "特征数", len(compiled))
	}

	for _, d := range detectors {
		go func(d ban.Detector) {
			if err := d.Run(ctx, events); err != nil {
				logger.Error("检测器退出", "detector", d.Name(), "err", err)
			}
		}(d)
	}

	mode := "观察模式（不封禁）"
	if settings.Enabled {
		mode = "封禁模式"
	}
	logger.Info("自动封禁已启动",
		"模式", mode, "窗口", settings.Window.String(), "阈值", settings.Threshold,
		"首次封禁", settings.BaseTTL.String(), "上限", settings.MaxTTL.String(),
		"白名单", len(settings.Whitelist))
	return be, nil
}

func orDefault(d, def time.Duration) time.Duration {
	if d <= 0 {
		return def
	}
	return d
}

// buildAlerts 按配置装配告警通道。
func buildAlerts(cfg config.Config, logger *slog.Logger) (*alert.Manager, error) {
	notifiers, err := cfg.Notifiers()
	if err != nil {
		return nil, err
	}
	if len(notifiers) == 0 {
		logger.Info("未配置告警通道（配置里的 alerts），只记录不推送")
		return alert.New(nil, alert.WithLogger(logger)), nil
	}
	m := alert.New(notifiers,
		alert.WithLogger(logger),
		alert.WithCooldown(cfg.AlertCooldown),
	)
	names := m.Notifiers()
	logger.Info("告警通道已就绪", "通道", strings.Join(names, ", "), "数量", len(names))
	return m, nil
}

// alertFromAudit 把审计动作翻译成告警。
//
// 不是每个审计动作都值得推送 —— 规则增删是你自己的操作，你当然知道。
// 值得推的是"你没做、但它发生了"的事：自动回滚、下发失败、解封失败。
func alertFromAudit(m *alert.Manager, action, target, detail string) {
	if !m.Enabled() {
		return
	}
	switch action {
	case "rollback", "rollback.reset":
		m.Send(alert.Event{
			Severity: alert.SevWarn,
			Kind:     "rollback",
			Title:    "防火墙规则被回滚",
			Detail:   fmt.Sprintf("%s\n%s", target, detail),
		})
	case "groups.reload":
		m.Send(alert.Event{
			Severity: alert.SevInfo,
			Kind:     "groups.reload",
			Title:    "地址组内容已变化，需要重新下发才生效",
			Detail:   detail,
		})
	}
}

func buildBackend(cfg config.Config, logger *slog.Logger) (backend.Backend, error) {
	switch cfg.Backend {
	case "mock":
		logger.Warn("使用 mock 后端：规则只保存在内存中，不会影响真实网络")
		return mock.New(mock.WithTableName(cfg.Table)), nil
	case "nftables", "":
		be := nftables.New(nftables.WithTable(cfg.Family, cfg.Table))
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		ver, err := be.Available(ctx)
		if err != nil {
			return nil, fmt.Errorf("nftables 后端不可用（可改用 -backend mock 做离线演示）: %w", err)
		}
		logger.Info("检测到 nft", "version", ver)
		return be, nil
	default:
		return nil, fmt.Errorf("未知后端 %q", cfg.Backend)
	}
}

func loadPolicy(path string) (*model.Policy, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var p model.Policy
	if err := yaml.Unmarshal(data, &p); err != nil {
		return nil, err
	}
	return &p, nil
}

func newLogger(level string) *slog.Logger {
	var lv slog.Level
	switch level {
	case "debug":
		lv = slog.LevelDebug
	case "warn":
		lv = slog.LevelWarn
	case "error":
		lv = slog.LevelError
	default:
		lv = slog.LevelInfo
	}
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: lv}))
}

func defaultConfigPath() string {
	if v := os.Getenv("FWDD_CONFIG"); v != "" {
		return v
	}
	if v := os.Getenv("ProgramData"); v != "" && os.PathSeparator == '\\' {
		return filepath.Join(v, "fwdd", "config.yaml")
	}
	return "/etc/fwdd/config.yaml"
}
