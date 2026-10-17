// Package config 负责守护进程配置的加载与校验。
//
// 配置是"如何运行"，策略（model.Policy）是"过滤什么"，二者分离：
// 配置文件决定监听地址、后端选择、表名等；策略另存于策略文件 / 数据库。
package config

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"fwdd/internal/netcfg"

	"fwdd/internal/alert"
	"fwdd/internal/ban"

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
	// Mode 决定部署形态：
	//
	//	gateway —— 网关/路由器型：跨网段转发、NAT、多网卡。会生成
	//	           forward 链与两条 nat 链。默认值，保持既有行为。
	//	host    —— 主机型：只保护本机，不做转发、不做 NAT。
	//	           不生成 forward 链与 nat 链。
	//
	// 主机模式不只是"少几条规则"，它避免了一个实打实的冲突：fwdd 的链优先级
	// 是 filter(0)，与 Docker、firewalld 的链**同钩子同优先级**，而 nft 里
	// 这种情形的求值顺序是未定义的 —— 网关模式装在有 Docker 的机器上，
	// 容器网络会不会被打断是看运气的。主机模式不注册 forward 链，从根上避开。
	Mode string `yaml:"mode" json:"mode"`
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

	// ManageSysctls 为 true 时，启动会写入 Sysctls 中的内核网络参数。
	// 为 false（默认）时只读取检查并在缺失时告警，不擅自改动内核。
	ManageSysctls bool `yaml:"manage_sysctls" json:"manage_sysctls"`
	// Sysctls 为内核网络参数；为空时使用网关推荐基线。
	Sysctls []netcfg.Sysctl `yaml:"sysctls" json:"sysctls,omitempty"`

	// AutoBan 是自动封禁配置。
	AutoBan AutoBanConfig `yaml:"auto_ban" json:"auto_ban"`

	// Alerts 是告警通道列表。为空表示不推送告警。
	Alerts []AlertConfig `yaml:"alerts" json:"alerts,omitempty"`
	// AlertCooldown 是同一事件的去重窗口（默认 5 分钟）。
	//
	// 一次端口扫描可能瞬间产生几十条封禁，逐条推送会把你淹没，
	// 然后你就开始忽略告警了 —— 那比没有告警更糟。
	AlertCooldown time.Duration `yaml:"alert_cooldown" json:"alert_cooldown"`
}

// AlertConfig 是一个告警通道的配置。
//
// 用一个扁平结构 + type 区分，而不是嵌套：配置文件里写起来短，
// 而各类型的字段名不冲突（url / addr / command）。
type AlertConfig struct {
	// Type 为 webhook | smtp | command。
	Type string `yaml:"type" json:"type"`
	// MinSeverity 低于该级别的告警不发到这个通道（info | warn | critical）。
	MinSeverity string `yaml:"min_severity" json:"min_severity,omitempty"`

	// ---- webhook ----
	URL string `yaml:"url" json:"url,omitempty"`
	// Format 为 generic | wecom | dingtalk | feishu | telegram。
	// generic 发结构化 JSON 给自建系统；其余几家按各自的机器人格式发送。
	Format string `yaml:"format" json:"format,omitempty"`
	// ChatID 仅 telegram 需要。
	ChatID string `yaml:"chat_id" json:"chat_id,omitempty"`
	// Token 会作为 Authorization: Bearer 头发送。
	Token string `yaml:"token" json:"token,omitempty"`

	// ---- smtp ----
	Addr        string   `yaml:"addr" json:"addr,omitempty"`
	Username    string   `yaml:"username" json:"username,omitempty"`
	Password    string   `yaml:"password" json:"password,omitempty"`
	From        string   `yaml:"from" json:"from,omitempty"`
	To          []string `yaml:"to" json:"to,omitempty"`
	ImplicitTLS bool     `yaml:"implicit_tls" json:"implicit_tls,omitempty"`

	// ---- command ----
	Command string   `yaml:"command" json:"command,omitempty"`
	Args    []string `yaml:"args" json:"args,omitempty"`
}

// Notifiers 把配置转换成实际的告警通道。
//
// 任何一个通道配置错误都会直接返回错误而不是跳过 —— 少了一个告警通道
// 意味着你以为有人在看着，实际上没有。
func (c *Config) Notifiers() ([]alert.Notifier, error) {
	var out []alert.Notifier
	for i, a := range c.Alerts {
		sev, err := alert.ParseSeverity(a.MinSeverity)
		if err != nil {
			return nil, fmt.Errorf("alerts[%d]: %w", i, err)
		}
		var (
			n    alert.Notifier
			err2 error
		)
		switch a.Type {
		case "webhook":
			n, err2 = alert.NewWebhook(alert.WebhookOptions{
				URL: a.URL, Format: alert.WebhookFormat(a.Format),
				ChatID: a.ChatID, Token: a.Token,
			})
		case "smtp":
			n, err2 = alert.NewSMTP(alert.SMTPOptions{
				Addr: a.Addr, Username: a.Username, Password: a.Password,
				From: a.From, To: a.To, ImplicitTLS: a.ImplicitTLS,
			})
		case "command":
			n, err2 = alert.NewCommand(alert.CommandOptions{Command: a.Command, Args: a.Args})
		case "":
			err2 = fmt.Errorf("缺少 type（应为 webhook | smtp | command）")
		default:
			err2 = fmt.Errorf("未知的通道类型 %q", a.Type)
		}
		if err2 != nil {
			return nil, fmt.Errorf("alerts[%d] (%s): %w", i, a.Type, err2)
		}
		// 通道级别的严重度过滤在构建时包一层，避免每条消息都判断。
		out = append(out, &severityFiltered{inner: n, min: sev})
	}
	return out, nil
}

// severityFiltered 是一个按级别过滤的装饰器。
type severityFiltered struct {
	inner alert.Notifier
	min   alert.Severity
}

func (s *severityFiltered) Name() string { return s.inner.Name() }

func (s *severityFiltered) Notify(ctx context.Context, ev alert.Event) error {
	if !ev.Severity.AtLeast(s.min) {
		return nil
	}
	return s.inner.Notify(ctx, ev)
}

// AutoBanConfig 是自动封禁的配置（yaml 可读形态）。
type AutoBanConfig struct {
	// Enabled 为 false 时只观察、不封禁，用于先评估误报率。
	Enabled bool `yaml:"enabled" json:"enabled"`
	// Window 是判定用的滑动窗口。
	Window time.Duration `yaml:"window" json:"window"`
	// Threshold 是窗口内累计权重达到多少即封禁。
	Threshold int `yaml:"threshold" json:"threshold"`
	// BaseTTL 是首次封禁时长。
	BaseTTL time.Duration `yaml:"base_ttl" json:"base_ttl"`
	// Multiplier 是递进惩罚倍数。
	Multiplier float64 `yaml:"multiplier" json:"multiplier"`
	// MaxTTL 是封禁时长上限。
	MaxTTL time.Duration `yaml:"max_ttl" json:"max_ttl"`
	// StrikeResetAfter 为多久没有新违规就清零惩罚计数。
	StrikeResetAfter time.Duration `yaml:"strike_reset_after" json:"strike_reset_after"`
	// Whitelist 中的地址永不封禁。建议至少包含管理网段。
	Whitelist []string `yaml:"whitelist" json:"whitelist,omitempty"`

	Conntrack ConntrackConfig   `yaml:"conntrack" json:"conntrack"`
	Logs      []LogSourceConfig `yaml:"logs" json:"logs,omitempty"`
}

// ConntrackConfig 配置 conntrack 检测器。
type ConntrackConfig struct {
	Enabled bool `yaml:"enabled" json:"enabled"`
	// Path 默认 /proc/net/nf_conntrack。
	Path string `yaml:"path" json:"path"`
	// Interval 是采样周期。
	Interval time.Duration `yaml:"interval" json:"interval"`
	// MaxNewPerInterval：单源在一个采样周期内新增连接数阈值。
	MaxNewPerInterval int `yaml:"max_new_per_interval" json:"max_new_per_interval"`
	// MaxConcurrent：单源并发连接数阈值。
	MaxConcurrent int `yaml:"max_concurrent" json:"max_concurrent"`
}

// LogSourceConfig 配置一个日志检测器。
type LogSourceConfig struct {
	Path string `yaml:"path" json:"path"`
	// Patterns 为空时使用内置特征集（sshd 认证失败、nft 限速日志等）。
	Patterns []ban.LogPattern `yaml:"patterns" json:"patterns,omitempty"`
}

// BanSettings 把配置转换为判罚引擎的设置。
func (c *Config) BanSettings() ban.Settings {
	a := c.AutoBan
	s := ban.DefaultSettings()
	s.Enabled = a.Enabled
	if a.Window > 0 {
		s.Window = a.Window
	}
	if a.Threshold > 0 {
		s.Threshold = a.Threshold
	}
	if a.BaseTTL > 0 {
		s.BaseTTL = a.BaseTTL
	}
	if a.Multiplier > 0 {
		s.Multiplier = a.Multiplier
	}
	if a.MaxTTL > 0 {
		s.MaxTTL = a.MaxTTL
	}
	if a.StrikeResetAfter > 0 {
		s.StrikeResetAfter = a.StrikeResetAfter
	}
	if len(a.Whitelist) > 0 {
		s.Whitelist = a.Whitelist
	} else {
		// 没配白名单时至少要护住本机与内网，否则一次误判就可能把管理面封掉。
		s.Whitelist = []string{"127.0.0.0/8", "::1/128"}
	}
	return s
}

// 部署形态。
const (
	// ModeGateway 是网关/路由器型：转发、NAT、多网卡。
	ModeGateway = "gateway"
	// ModeHost 是主机型：只保护本机。
	ModeHost = "host"
)

// IsHost 报告当前是否为主机型部署。
func (c *Config) IsHost() bool { return c.Mode == ModeHost }

// SysctlBaseline 返回本次启动应使用的内核参数基线，按部署形态选择。
//
// 两者的差别不只是"少一项"：网关基线把 rp_filter 设成 0（多宿主/非对称路由
// 场景下避免误丢包），而**主机上应该设 1** —— 反向路径过滤是内核自带的
// 反欺骗机制，在单机上网关基线等于主动把它关掉。
func (c *Config) SysctlBaseline() []netcfg.Sysctl {
	if len(c.Sysctls) > 0 {
		return c.Sysctls
	}
	if c.IsHost() {
		return netcfg.HostBaseline()
	}
	return netcfg.GatewayBaseline()
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
		Mode:     ModeGateway,
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
	switch c.Mode {
	case "", ModeGateway, ModeHost:
	default:
		return fmt.Errorf("mode %q 未知（应为 %s 或 %s）", c.Mode, ModeGateway, ModeHost)
	}
	if c.Mode == "" {
		c.Mode = ModeGateway
	}
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
