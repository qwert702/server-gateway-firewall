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
	"syscall"
	"time"

	"fwdd/internal/api"
	"fwdd/internal/backend"
	"fwdd/internal/backend/mock"
	"fwdd/internal/backend/nftables"
	"fwdd/internal/config"
	"fwdd/internal/engine"
	"fwdd/internal/model"
	"fwdd/internal/store"
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
		listen       = flag.String("listen", "", "覆盖 HTTP 监听地址")
		policyPath   = flag.String("policy", "", "策略文件路径（YAML）")
		applyStart   = flag.Bool("apply-on-start", true, "启动时把策略下发到内核")
		dryRun       = flag.Bool("dry-run", false, "只渲染不下发，打印规则集后退出")
		noPersist    = flag.Bool("no-persist", false, "关闭持久化（策略与封禁只留在内存）")
		importPolicy = flag.Bool("import-policy", false, "用 -policy 文件覆盖数据库中的期望状态")
		actor        = flag.String("actor", "fwdd", "审计日志中的操作者标识")
		logLevel     = flag.String("log-level", "", "覆盖日志级别：debug|info|warn|error")
		version      = flag.Bool("version", false, "打印版本并退出")
	)
	flag.Parse()

	if *version {
		fmt.Println("fwdd 0.1.0 (M1+M2)")
		return nil
	}

	cfg, err := config.LoadOrCreate(*cfgPath)
	if err != nil {
		return err
	}
	if *backendName != "" {
		cfg.Backend = *backendName
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

	// 后台维护：定期清理已过期的封禁记录。
	eng.StartMaintenance(ctx)

	srv := api.New(cfg, eng, logger)
	logger.Info("fwdd 启动完成", "backend", be.Name())
	if err := srv.Serve(ctx); err != nil {
		return err
	}
	logger.Info("fwdd 已退出")
	return nil
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
