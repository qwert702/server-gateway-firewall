// Command fw 是 fwdd 的命令行客户端。
//
// 支持两种输出：表格（给人看）与 JSON（给脚本看）。
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"fwdd/internal/client"
	"fwdd/internal/config"
	"fwdd/internal/engine"
	"fwdd/internal/model"
	"gopkg.in/yaml.v3"
)

const usage = `fw —— 服务器网关防火墙命令行

用法:
  fw status                        查看守护进程与规则集状态
  fw plan [-o json]                预览将要下发的规则集（不下发）
  fw ruleset                       打印完整 nft 规则集文本
  fw apply [--dry-run] [--confirm] [--timeout 秒]
                                   把期望状态下发到内核
  fw confirm                       确认变更（取消自动回滚倒计时）
  fw rollback                      回滚到上一个版本
  fw revisions                     查看看下发历史

  fw policy get [-o json]          查看完整策略
  fw policy set -f 文件.yaml [--apply]
                                   用文件替换期望状态

  fw zone list                     列出安全域
  fw rule list [--json]            列出规则

  fw ban add <ip> [--ttl 秒] [--reason 文本]
  fw ban list
  fw ban rm <ip>

全局参数:
  -config 路径   配置文件（默认 /etc/fwdd/config.yaml 或 $FWDD_CONFIG）
  -o json|table  输出格式
`

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "错误:", err)
		os.Exit(1)
	}
}

func run(args []string, out *os.File) error {
	if len(args) == 0 {
		fmt.Fprint(out, usage)
		return nil
	}

	// 全局参数允许出现在子命令之前或之后（如 `fw -o json ban list`）。
	cfgPath, format, cmd, sub, err := splitArgs(args)
	if err != nil {
		return err
	}
	if cmd == "" {
		fmt.Fprint(out, usage)
		return nil
	}

	cfg, err := loadConfig(cfgPath)
	if err != nil {
		return err
	}
	c := client.New(cfg)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	switch cmd {
	case "help", "-h", "--help":
		fmt.Fprint(out, usage)
		return nil
	case "version":
		fmt.Fprintln(out, "fw 0.1.0 (M1+M2)")
		return nil
	case "status":
		return cmdStatus(ctx, c, out, format)
	case "plan":
		return cmdPlan(ctx, c, out, format)
	case "ruleset":
		text, err := c.GetText(ctx, "/ruleset")
		if err != nil {
			return err
		}
		fmt.Fprint(out, text)
		return nil
	case "apply":
		return cmdApply(ctx, c, out, sub)
	case "confirm":
		var resp map[string]any
		if err := c.Post(ctx, "/confirm", nil, &resp); err != nil {
			return err
		}
		fmt.Fprintln(out, "已确认，自动回滚倒计时已取消")
		return nil
	case "rollback":
		var resp map[string]any
		if err := c.Post(ctx, "/rollback", nil, &resp); err != nil {
			return err
		}
		fmt.Fprintln(out, "已回滚到上一个版本")
		return nil
	case "revisions":
		return cmdRevisions(ctx, c, out, format)
	case "policy":
		return cmdPolicy(ctx, c, out, format, sub)
	case "zone":
		return cmdZone(ctx, c, out, format, sub)
	case "rule":
		return cmdRule(ctx, c, out, format, sub)
	case "ban":
		return cmdBan(ctx, c, out, format, sub)
	default:
		fmt.Fprint(os.Stderr, usage)
		return fmt.Errorf("未知子命令 %q", cmd)
	}
}

// splitArgs 提取全局参数，返回 (配置路径, 输出格式, 子命令, 子命令参数)。
//
// 手写扫描而不是用 flag 包，是为了让 `-config` / `-o` 能出现在任意位置，
// 同时把不属于全局的参数原样留给子命令自己解析。
func splitArgs(args []string) (cfgPath, format, cmd string, sub []string, err error) {
	cfgPath = defaultConfigPath()
	format = "table"

	takeValue := func(i *int, name string) (string, error) {
		a := args[*i]
		if _, v, ok := strings.Cut(a, "="); ok {
			return v, nil
		}
		if *i+1 >= len(args) {
			return "", fmt.Errorf("参数 %s 缺少取值", name)
		}
		*i++
		return args[*i], nil
	}

	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "-config" || a == "--config" || strings.HasPrefix(a, "-config=") || strings.HasPrefix(a, "--config="):
			v, err := takeValue(&i, "config")
			if err != nil {
				return "", "", "", nil, err
			}
			cfgPath = v
		case a == "-o" || a == "--o" || strings.HasPrefix(a, "-o=") || strings.HasPrefix(a, "--o="):
			v, err := takeValue(&i, "o")
			if err != nil {
				return "", "", "", nil, err
			}
			format = v
		default:
			if cmd == "" {
				cmd = a
			} else {
				sub = append(sub, a)
			}
		}
	}
	switch format {
	case "table", "json":
	default:
		return "", "", "", nil, fmt.Errorf("未知输出格式 %q（仅支持 table|json）", format)
	}
	return cfgPath, format, cmd, sub, nil
}

// ---- 子命令 ----

func cmdStatus(ctx context.Context, c *client.Client, out *os.File, format string) error {
	var st engine.Status
	if err := c.Get(ctx, "/status", &st); err != nil {
		return err
	}
	if format == "json" {
		return printJSON(out, st)
	}

	w := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	fmt.Fprintf(w, "后端\t%s\n", st.Backend)
	fmt.Fprintf(w, "表\t%s\n", st.Table)
	fmt.Fprintf(w, "同步\t%s\n", yesNo(st.InSync))
	fmt.Fprintf(w, "期望哈希\t%s\n", orDash(st.DesiredHash))
	fmt.Fprintf(w, "已下发哈希\t%s\n", orDash(st.AppliedHash))
	fmt.Fprintf(w, "域/规则/NAT/封禁\t%d / %d(%d 启用) / %d / %d\n",
		st.Desired.Zones, st.Desired.Rules, st.Desired.Enabled, st.Desired.NATRules, st.Desired.Bans)
	if st.Pending != nil {
		fmt.Fprintf(w, "待确认\t是（截止 %s）\n", st.Pending.Deadline.Format(time.RFC3339))
	}
	if st.RuntimeErr != "" {
		fmt.Fprintf(w, "运行态读取\t失败: %s\n", st.RuntimeErr)
	}
	_ = w.Flush()

	if st.Runtime != nil && len(st.Runtime.Chains) > 0 {
		fmt.Fprintln(out, "\n内核中的链:")
		w = tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "  链\t类型\t钩子\t优先级\t策略\t规则数")
		for _, ch := range st.Runtime.Chains {
			fmt.Fprintf(w, "  %s\t%s\t%s\t%s\t%s\t%d\n",
				ch.Name, orDash(ch.Type), orDash(ch.Hook), orDash(ch.Priority), orDash(ch.Policy), ch.Rules)
		}
		_ = w.Flush()
	}
	if st.Runtime != nil && st.Runtime.Note != "" {
		fmt.Fprintf(out, "说明: %s\n", st.Runtime.Note)
	}
	return nil
}

func cmdPlan(ctx context.Context, c *client.Client, out *os.File, format string) error {
	var plan engine.Plan
	if err := c.Get(ctx, "/plan", &plan); err != nil {
		return err
	}
	if format == "json" {
		return printJSON(out, plan)
	}
	fmt.Fprintf(out, "规则 %d 条，链 %d 条，变化: %s\n", plan.Rules, plan.Chains, yesNo(plan.Changed))
	if len(plan.Diff) > 0 {
		fmt.Fprintln(out, "\n链规则数变化:")
		w := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
		for _, d := range plan.Diff {
			fmt.Fprintf(w, "  %s\t%d -> %d\n", d.Chain, d.Before, d.After)
		}
		_ = w.Flush()
	}
	for _, warn := range plan.Warnings {
		fmt.Fprintf(out, "警告 %s: %s\n", warn.Where, warn.Message)
	}
	return nil
}

func cmdApply(ctx context.Context, c *client.Client, out *os.File, args []string) error {
	fs := flag.NewFlagSet("apply", flag.ContinueOnError)
	dryRun := fs.Bool("dry-run", false, "只渲染不下发")
	confirm := fs.Bool("confirm", false, "下发后进入确认窗口，超时自动回滚")
	timeout := fs.Int("timeout", 0, "确认窗口（秒）")
	if err := fs.Parse(args); err != nil {
		return err
	}

	path := client.Query("/apply", map[string]string{
		"dry_run": strconv.FormatBool(*dryRun),
		"confirm": strconv.FormatBool(*confirm),
		"timeout": strconv.Itoa(*timeout),
	})
	var res engine.ApplyResult
	if err := c.Post(ctx, path, nil, &res); err != nil {
		return err
	}

	if *dryRun {
		fmt.Fprint(out, res.Text)
		return nil
	}
	fmt.Fprintf(out, "已下发 %d 条规则，%d 条链，哈希 %s（变化: %s）\n",
		res.Rules, res.Chains, res.Hash, yesNo(res.Changed))
	if res.Pending != nil {
		fmt.Fprintf(out, "\n⚠  变更处于待确认状态，未在 %s 前执行 `fw confirm` 将自动回滚。\n",
			res.Pending.Deadline.Format(time.RFC3339))
	}
	for _, warn := range res.Warnings {
		fmt.Fprintf(out, "警告 %s: %s\n", warn.Where, warn.Message)
	}
	return nil
}

func cmdRevisions(ctx context.Context, c *client.Client, out *os.File, format string) error {
	var resp struct {
		Revisions []engine.Revision `json:"revisions"`
	}
	if err := c.Get(ctx, "/revisions", &resp); err != nil {
		return err
	}
	if format == "json" {
		return printJSON(out, resp.Revisions)
	}
	w := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "序号\t时间\t规则数\t哈希\t说明")
	for _, r := range resp.Revisions {
		fmt.Fprintf(w, "%d\t%s\t%d\t%s\t%s\n", r.Seq, r.At.Format("01-02 15:04:05"), r.Rules, r.Hash, orDash(r.Note))
	}
	return w.Flush()
}

func cmdPolicy(ctx context.Context, c *client.Client, out *os.File, format string, args []string) error {
	if len(args) == 0 {
		return errors.New("用法: fw policy get|set")
	}
	switch args[0] {
	case "get":
		var p model.Policy
		if err := c.Get(ctx, "/policy", &p); err != nil {
			return err
		}
		if format == "json" {
			return printJSON(out, p)
		}
		data, err := yaml.Marshal(p)
		if err != nil {
			return err
		}
		fmt.Fprint(out, string(data))
		return nil
	case "set":
		fs := flag.NewFlagSet("policy set", flag.ContinueOnError)
		file := fs.String("f", "", "策略文件（YAML）")
		apply := fs.Bool("apply", false, "写入后立即下发")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if *file == "" {
			return errors.New("必须用 -f 指定策略文件")
		}
		data, err := os.ReadFile(*file)
		if err != nil {
			return err
		}
		var p model.Policy
		if err := yaml.Unmarshal(data, &p); err != nil {
			return fmt.Errorf("解析 %s 失败: %w", *file, err)
		}
		var resp map[string]any
		if err := c.Put(ctx, client.Query("/policy", map[string]string{"apply": strconv.FormatBool(*apply)}), p, &resp); err != nil {
			return err
		}
		if *apply {
			fmt.Fprintln(out, "策略已替换并下发")
		} else {
			fmt.Fprintln(out, "策略已保存为期望状态（尚未下发，可用 fw apply 生效）")
		}
		return nil
	default:
		return fmt.Errorf("未知子命令 fw policy %s", args[0])
	}
}

func cmdZone(ctx context.Context, c *client.Client, out *os.File, format string, args []string) error {
	if len(args) > 0 && args[0] != "list" {
		return fmt.Errorf("目前仅支持 fw zone list")
	}
	var resp struct {
		Zones []model.Zone `json:"zones"`
	}
	if err := c.Get(ctx, "/zones", &resp); err != nil {
		return err
	}
	if format == "json" {
		return printJSON(out, resp.Zones)
	}
	w := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "域\t信任\t接口\t网段")
	for _, z := range resp.Zones {
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", z.Name, orDash(string(z.Trust)),
			orDash(strings.Join(z.Interfaces, ",")), orDash(strings.Join(z.Networks, ",")))
	}
	return w.Flush()
}

func cmdRule(ctx context.Context, c *client.Client, out *os.File, format string, args []string) error {
	if len(args) > 0 && args[0] != "list" {
		return fmt.Errorf("目前仅支持 fw rule list")
	}
	var resp struct {
		Rules []model.Rule `json:"rules"`
	}
	if err := c.Get(ctx, "/rules", &resp); err != nil {
		return err
	}
	if format == "json" {
		return printJSON(out, resp.Rules)
	}
	w := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "ID\t优先级\t源域\t目的域\t协议\t端口\t动作\t启用")
	for _, r := range resp.Rules {
		fmt.Fprintf(w, "%s\t%d\t%s\t%s\t%s\t%s\t%s\t%s\n",
			r.ID, r.Priority, orAny(r.SrcZone), orAny(r.DstZone), orAny(string(r.Proto)),
			orDash(strings.Join(r.DstPort, ",")), r.Action, yesNo(r.IsEnabled()))
	}
	return w.Flush()
}

func cmdBan(ctx context.Context, c *client.Client, out *os.File, format string, args []string) error {
	if len(args) == 0 {
		return errors.New("用法: fw ban add|list|rm")
	}
	switch args[0] {
	case "add":
		fs := flag.NewFlagSet("ban add", flag.ContinueOnError)
		ttl := fs.Int("ttl", 0, "封禁时长（秒），0 表示默认")
		reason := fs.String("reason", "", "封禁原因")
		positional, err := parseInterspersed(fs, args[1:])
		if err != nil {
			return err
		}
		ip := ""
		if len(positional) > 0 {
			ip = positional[0]
		}
		if ip == "" {
			return errors.New("必须指定 IP")
		}
		body := map[string]any{"ip": ip, "reason": *reason, "ttl_sec": *ttl}
		var resp map[string]any
		if err := c.Post(ctx, "/bans", body, &resp); err != nil {
			return err
		}
		fmt.Fprintf(out, "已封禁 %s\n", ip)
		return nil
	case "list", "ls":
		var resp struct {
			Bans []model.BanEntry `json:"bans"`
		}
		if err := c.Get(ctx, "/bans", &resp); err != nil {
			return err
		}
		if format == "json" {
			return printJSON(out, resp.Bans)
		}
		if len(resp.Bans) == 0 {
			fmt.Fprintln(out, "（当前无封禁）")
			return nil
		}
		w := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "IP\t剩余\t来源\t原因")
		now := time.Now()
		for _, b := range resp.Bans {
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", b.IP, remaining(b, now), orDash(string(b.Source)), orDash(b.Reason))
		}
		return w.Flush()
	case "rm", "del", "remove":
		ip := ""
		if len(args) > 1 {
			ip = args[1]
		}
		if ip == "" {
			return errors.New("必须指定 IP")
		}
		var resp map[string]any
		if err := c.Delete(ctx, "/bans/"+ip, &resp); err != nil {
			return err
		}
		fmt.Fprintf(out, "已解封 %s\n", ip)
		return nil
	default:
		return fmt.Errorf("未知子命令 fw ban %s", args[0])
	}
}

// ---- 工具 ----

// parseInterspersed 解析允许标志与位置参数混排的命令行，例如
// `fw ban add 1.2.3.4 --ttl 60`。Go 标准库的 flag 包会在遇到第一个位置参数时
// 停止解析，因此这里先按已注册的标志把参数分成两组，再交给 flag 包。
func parseInterspersed(fs *flag.FlagSet, args []string) (positional []string, err error) {
	valueFlags := map[string]bool{}
	fs.VisitAll(func(f *flag.Flag) {
		if bf, ok := f.Value.(interface{ IsBoolFlag() bool }); ok && bf.IsBoolFlag() {
			return
		}
		valueFlags[f.Name] = true
	})

	var flagArgs []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" || !strings.HasPrefix(a, "-") || a == "-" {
			positional = append(positional, a)
			continue
		}
		flagArgs = append(flagArgs, a)
		name := strings.TrimLeft(a, "-")
		if strings.Contains(name, "=") {
			continue
		}
		if valueFlags[name] && i+1 < len(args) {
			i++
			flagArgs = append(flagArgs, args[i])
		}
	}
	if err := fs.Parse(flagArgs); err != nil {
		return nil, err
	}
	return positional, nil
}

func printJSON(out *os.File, v any) error {
	enc := json.NewEncoder(out)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

func yesNo(b bool) string {
	if b {
		return "是"
	}
	return "否"
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func orAny(s string) string {
	if s == "" {
		return model.ZoneAny
	}
	return s
}

func remaining(b model.BanEntry, now time.Time) string {
	if b.ExpiresAt.IsZero() {
		return "永久"
	}
	d := b.ExpiresAt.Sub(now)
	if d <= 0 {
		return "已过期"
	}
	return d.Round(time.Second).String()
}

func loadConfig(path string) (config.Config, error) {
	cfg, err := config.Load(path)
	if err != nil {
		if os.IsNotExist(err) {
			// CLI 可以在没有配置文件时用默认值连本机。
			cfg = config.Default()
			return cfg, cfg.Validate()
		}
		return cfg, err
	}
	return cfg, cfg.Validate()
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
