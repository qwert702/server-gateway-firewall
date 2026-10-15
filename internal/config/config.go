// Package config 负责守护进程配置的加载与校验。
//
// 配置是"如何运行"，策略（model.Policy）是"过滤什么"，二者分离：
// 配置文件决定监听地址、后端选择、表名等；策略另存于策略文件 / 数据库。
package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Config 是守护进程配置。
type Config struct {
	// HTTP 监听地址；默认仅监听回环，避免管理面直接暴露。
	Listen string `yaml:"listen" json:"listen"`
	// Socket 为 Unix 域套接字路径（Linux 上优先）；Windows 上留空即回退 HTTP。
	Socket string `yaml:"socket" json:"socket"`

	// Backend 为 "nftables" 或 "mock"。
	Backend string `yaml:"backend" json:"backend"`
	// Table / Family 指定 nft 表名与地址族。
	Table  string `yaml:"table" json:"table"`
	Family string `yaml:"family" json:"family"`

	// DataDir 存放运行时数据（SQLite 数据库、快照）。
	DataDir string `yaml:"data_dir" json:"data_dir"`
	// DBPath 覆盖 SQLite 数据库路径；空则使用 DataDir/fwdd.db。
	DBPath string `yaml:"db_path" json:"db_path"`
	// DisablePersist 关闭持久化：策略与封禁只存在于内存，重启即遗忘。
	// 仅用于演示与测试。
	DisablePersist bool `yaml:"disable_persist" json:"disable_persist"`
	// PolicyFile 为声明式基线策略文件（YAML）；
	// 仅在该数据库尚无策略（首次启动）时作为初始期望状态。
	PolicyFile string `yaml:"policy_file" json:"policy_file"`

	// Token 为 HTTP API 的 Bearer 令牌；空表示不校验（仅回环）。
	Token string `yaml:"token" json:"token"`

	// LogLevel：debug / info / warn / error。
	LogLevel string `yaml:"log_level" json:"log_level"`

	// CommitConfirm 控制危险变更的兜底回滚。
	CommitConfirm CommitConfirm `yaml:"commit_confirm" json:"commit_confirm"`
}

// CommitConfirm 是 commit-confirm 的安全参数。
type CommitConfirm struct {
	// Enabled 为 true 时 apply 需要 confirm，否则超时自动回滚。
	Enabled bool `yaml:"enabled" json:"enabled"`
	// Timeout 为确认窗口。
	Timeout time.Duration `yaml:"timeout" json:"timeout"`
}

// Default 返回带默认值的配置。
func Default() Config {
	socket := ""
	if runtime.GOOS != "windows" {
		socket = "/run/fwdd.sock"
	}
	return Config{
		Listen:   "127.0.0.1:8080",
		Socket:   socket,
		Backend:  "nftables",
		Table:    "fw",
		Family:   "inet",
		DataDir:  defaultDataDir(),
		LogLevel: "info",
		Token:    "",
		CommitConfirm: CommitConfirm{
			Enabled: false,
			Timeout: 60 * time.Second,
		},
	}
}

func defaultDataDir() string {
	if runtime.GOOS == "windows" {
		if pd := os.Getenv("ProgramData"); pd != "" {
			return filepath.Join(pd, "fwdd")
		}
		return "fwdd-data"
	}
	return "/var/lib/fwdd"
}

// Load 从文件读取配置；文件不存在时返回错误。
func Load(path string) (Config, error) {
	cfg := Default()
	data, err := os.ReadFile(path)
	if err != nil {
		return cfg, err
	}
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return cfg, fmt.Errorf("解析 %s 失败: %w", path, err)
	}
	return cfg, nil
}

// LoadOrCreate 读取配置；不存在则用默认值写出一份便于编辑的样板。
func LoadOrCreate(path string) (Config, error) {
	cfg, err := Load(path)
	if err == nil {
		return cfg, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return cfg, err
	}
	cfg = Default()
	if werr := Save(path, cfg); werr != nil {
		return cfg, fmt.Errorf("写入默认配置失败: %w", werr)
	}
	return cfg, nil
}

// Save 把配置写回文件（权限 0600，可能含 token）。
func Save(path string, cfg Config) error {
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return err
		}
	}
	data, err := yaml.Marshal(cfg)
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o600)
}

// Validate 校验配置并补齐派生默认值。
func (c *Config) Validate() error {
	switch c.Backend {
	case "", "nftables", "mock":
	default:
		return fmt.Errorf("backend %q 未知（应为 nftables 或 mock）", c.Backend)
	}
	if c.Backend == "" {
		c.Backend = "nftables"
	}
	switch c.Family {
	case "", "inet", "ip", "ip6":
	default:
		return fmt.Errorf("family %q 未知（应为 inet / ip / ip6）", c.Family)
	}
	if c.Family == "" {
		c.Family = "inet"
	}
	if c.Table == "" {
		c.Table = "fw"
	}
	if c.Listen == "" && c.Socket == "" {
		return errors.New("listen 与 socket 不能同时为空")
	}
	if c.CommitConfirm.Timeout <= 0 {
		c.CommitConfirm.Timeout = 60 * time.Second
	}
	switch c.LogLevel {
	case "", "debug", "info", "warn", "error":
	default:
		return fmt.Errorf("log_level %q 未知", c.LogLevel)
	}
	if c.LogLevel == "" {
		c.LogLevel = "info"
	}
	// 监听非回环地址时必须配置 token，否则管理面可被任意来源调用。
	if c.Listen != "" && !isLoopback(c.Listen) && c.Token == "" {
		return fmt.Errorf("listen %q 非回环地址，必须配置 token", c.Listen)
	}
	return nil
}

func isLoopback(addr string) bool {
	host, _, ok := strings.Cut(addr, ":")
	if !ok {
		host = addr
	}
	host = strings.Trim(host, "[]")
	return host == "127.0.0.1" || host == "localhost" || host == "::1"
}
