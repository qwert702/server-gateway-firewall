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
	"sort"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"fwdd/internal/ban"
	"fwdd/internal/client"
	"fwdd/internal/config"
	"fwdd/internal/engine"
	"fwdd/internal/model"
	"fwdd/internal/netcfg"
	"fwdd/internal/store"
	"fwdd/internal/version"
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
  fw audit [-n 条数]                查看操作审计日志

  fw policy get [-o json]          查看完整策略
  fw policy set -f 文件.yaml [--apply]
                                   用文件替换期望状态

  fw zone list                     列出安全域
  fw zone add <名> [--iface eth0,eth1] [--net 10.0.0.0/8] [--trust lan]
  fw zone rm <名>

  fw rule list                     列出规则
  fw rule add --src-zone lan --dst-zone wan --proto tcp --dport 443 \
              --state new --action accept [--priority 100] [--log] [--comment 备注]
  fw rule rm <id> | fw rule enable <id> | fw rule disable <id>
  fw rule move <id> [--before <id>]

  fw nat list                      列出 NAT 规则
  fw nat add-dnat --proto tcp --match-port 8080 --to-addr 192.168.20.10 --to-port 80
  fw nat add-snat --to-addr 203.0.113.1 --out-zone wan
  fw nat add-masq --out-zone wan
  fw nat rm <id>

  fw ban add <ip> [--ttl 秒] [--reason 文本]
  fw ban list
  fw ban rm <ip>
  fw ban export [--format csv|json] [--since 7d] [-o 文件]
                                   导出攻击取证记录（给云厂商/CERT 投诉用）

  fw ban engine [--enable|--disable]  自动封禁引擎状态与开关
  fw ban offenders                 查看被跟踪的可疑地址

  fw net                           查看网络状态（接口/地址/路由/转发开关）
  fw net sysctl show               查看内核网络参数
  fw net sysctl apply [--dry-run]  按基线写入内核参数（仅 Linux，需 root）

  fw groups                        列出地址组（国家封锁、威胁情报列表）
  fw groups reload                 重新读取地址组文件（不自动下发）

  fw alert                         查看告警通道状态
  fw alert test                    发一条测试告警（配置完通道后先验一下）

注意：zone/rule/nat 的改动只写入期望状态，需要 fw apply 才下发到内核。

当前部署形态来自配置文件的 mode 字段：
  gateway（默认）—— 网关型，有安全域与 NAT
  host           —— 主机型，只剩本机防护；引用 forward 的规则会被拒绝，
                    规则里必须有一侧是 local（本机）

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
	currentMode = cfg.Mode
	c := client.New(cfg)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	switch cmd {
	case "help", "-h", "--help":
		fmt.Fprint(out, usage)
		return nil
	case "version":
		if len(sub) > 0 && (sub[0] == "-v" || sub[0] == "--verbose") {
			fmt.Fprintln(out, version.Full())
			return nil
		}
		fmt.Fprintln(out, "fw "+version.Short())
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
	case "audit":
		return cmdAudit(ctx, c, out, format, sub)
	case "policy":
		return cmdPolicy(ctx, c, out, format, sub)
	case "zone":
		return cmdZone(ctx, c, out, format, sub)
	case "rule":
		return cmdRule(ctx, c, out, format, sub)
	case "nat":
		return cmdNAT(ctx, c, out, format, sub)
	case "net":
		return cmdNet(ctx, c, out, format, sub)
	case "groups", "group":
		return cmdGroups(ctx, c, out, format, sub)
	case "alert", "alerts":
		return cmdAlert(ctx, c, out, format, sub)
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

func cmdAudit(ctx context.Context, c *client.Client, out *os.File, format string, args []string) error {
	fs := flag.NewFlagSet("audit", flag.ContinueOnError)
	limit := fs.Int("n", 50, "返回的记录条数上限")
	if _, err := parseInterspersed(fs, args); err != nil {
		return err
	}

	var resp struct {
		Audit []store.AuditEntry `json:"audit"`
	}
	if err := c.Get(ctx, client.Query("/audit", map[string]string{"limit": strconv.Itoa(*limit)}), &resp); err != nil {
		return err
	}
	if format == "json" {
		return printJSON(out, resp.Audit)
	}
	if len(resp.Audit) == 0 {
		fmt.Fprintln(out, "（暂无审计记录）")
		return nil
	}
	w := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "时间\t操作者\t动作\t对象\t详情")
	for _, e := range resp.Audit {
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n",
			e.At.Format("01-02 15:04:05"), orDash(e.Actor), e.Action, orDash(e.Target), orDash(e.Detail))
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
	if len(args) == 0 {
		args = []string{"list"}
	}
	switch args[0] {
	case "list", "ls":
		var resp struct {
			Zones []model.Zone `json:"zones"`
		}
		if err := c.Get(ctx, "/zones", &resp); err != nil {
			return err
		}
		if format == "json" {
			return printJSON(out, resp.Zones)
		}
		if len(resp.Zones) == 0 {
			fmt.Fprintln(out, "（暂无安全域）")
			return nil
		}
		w := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "域\t信任\t接口\t网段")
		for _, z := range resp.Zones {
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", z.Name, orDash(string(z.Trust)),
				orDash(strings.Join(z.Interfaces, ",")), orDash(strings.Join(z.Networks, ",")))
		}
		return w.Flush()

	case "add":
		fs := flag.NewFlagSet("zone add", flag.ContinueOnError)
		ifaces := fs.String("iface", "", "接口列表，逗号分隔（如 eth0,eth1.10）")
		nets := fs.String("net", "", "网段列表，逗号分隔（如 10.0.0.0/8）")
		trust := fs.String("trust", "lan", "信任级别：untrusted|dmz|lan|local")
		comment := fs.String("comment", "", "备注")
		pos, err := parseInterspersed(fs, args[1:])
		if err != nil {
			return err
		}
		if len(pos) == 0 {
			return errors.New("用法: fw zone add <域名> [--iface eth0,eth1] [--net 10.0.0.0/8] [--trust lan]")
		}
		z := model.Zone{
			Name:       pos[0],
			Interfaces: splitList(*ifaces),
			Networks:   splitList(*nets),
			Trust:      model.Trust(*trust),
			Comment:    *comment,
		}
		var resp map[string]any
		if err := c.Post(ctx, "/zones", z, &resp); err != nil {
			return err
		}
		return pendingApply(out, "已创建域 "+z.Name)

	case "rm", "del", "remove":
		if len(args) < 2 {
			return errors.New("用法: fw zone rm <域名>")
		}
		var resp map[string]any
		if err := c.Delete(ctx, "/zones/"+args[1], &resp); err != nil {
			return err
		}
		return pendingApply(out, "已删除域 "+args[1])

	default:
		return fmt.Errorf("未知子命令 fw zone %s（支持 list|add|rm）", args[0])
	}
}

// pendingApply 打印成功信息并提醒还需要 apply 才生效。
func pendingApply(out *os.File, msg string) error {
	fmt.Fprintf(out, "%s（已写入期望状态，执行 fw apply 后生效）\n", msg)
	return nil
}

func cmdRule(ctx context.Context, c *client.Client, out *os.File, format string, args []string) error {
	if len(args) == 0 {
		args = []string{"list"}
	}
	switch args[0] {
	case "list", "ls":
		var resp struct {
			Rules []model.Rule `json:"rules"`
		}
		if err := c.Get(ctx, "/rules", &resp); err != nil {
			return err
		}
		if format == "json" {
			return printJSON(out, resp.Rules)
		}
		if len(resp.Rules) == 0 {
			fmt.Fprintln(out, "（暂无规则）")
			return nil
		}
		w := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "ID\t优先级\t源域\t目的域\t协议\t端口\t动作\t启用")
		for _, r := range resp.Rules {
			fmt.Fprintf(w, "%s\t%d\t%s\t%s\t%s\t%s\t%s\t%s\n",
				r.ID, r.Priority, orAny(r.SrcZone), orAny(r.DstZone), orAny(string(r.Proto)),
				orDash(strings.Join(r.DstPort, ",")), r.Action, yesNo(r.IsEnabled()))
		}
		return w.Flush()

	case "add":
		r, err := parseRuleFlags(args[1:])
		if err != nil {
			return err
		}
		var resp struct {
			ID string `json:"id"`
		}
		if err := c.Post(ctx, "/rules", r, &resp); err != nil {
			return err
		}
		return pendingApply(out, "已添加规则 "+resp.ID)

	case "rm", "del", "remove":
		if len(args) < 2 {
			return errors.New("用法: fw rule rm <id>")
		}
		var resp map[string]any
		if err := c.Delete(ctx, "/rules/"+args[1], &resp); err != nil {
			return err
		}
		return pendingApply(out, "已删除规则 "+args[1])

	case "enable", "disable":
		if len(args) < 2 {
			return fmt.Errorf("用法: fw rule %s <id>", args[0])
		}
		on := args[0] == "enable"
		var resp map[string]any
		path := client.Query("/rules/"+args[1]+"/enable", map[string]string{"enabled": strconv.FormatBool(on)})
		if err := c.Post(ctx, path, nil, &resp); err != nil {
			return err
		}
		return pendingApply(out, fmt.Sprintf("规则 %s 已%s", args[1], map[bool]string{true: "启用", false: "停用"}[on]))

	case "move":
		fs := flag.NewFlagSet("rule move", flag.ContinueOnError)
		before := fs.String("before", "", "移到该规则之前；留空表示移到末尾")
		pos, err := parseInterspersed(fs, args[1:])
		if err != nil {
			return err
		}
		if len(pos) == 0 {
			return errors.New("用法: fw rule move <id> [--before <id>]")
		}
		var resp map[string]any
		if err := c.Post(ctx, "/rules/"+pos[0]+"/move", map[string]string{"before": *before}, &resp); err != nil {
			return err
		}
		return pendingApply(out, "已移动规则 "+pos[0])

	default:
		return fmt.Errorf("未知子命令 fw rule %s（支持 list|add|rm|enable|disable|move）", args[0])
	}
}

// parseRuleFlags 把命令行开关转成一条规则。
func parseRuleFlags(args []string) (model.Rule, error) {
	var r model.Rule
	fs := flag.NewFlagSet("rule add", flag.ContinueOnError)
	fs.StringVar(&r.ID, "id", "", "规则 id（留空自动生成）")
	fs.IntVar(&r.Priority, "priority", 0, "优先级，小的先匹配（留空排到末尾）")
	fs.StringVar(&r.SrcZone, "src-zone", model.ZoneAny, "源域")
	// 主机模式下默认目的域是 local —— any 结尾的规则会被判为 forward 规则而拒绝，
	// 默认成 any 等于让用户每次都撞一次墙。
	fs.StringVar(&r.DstZone, "dst-zone", defaultDstZone(), "目的域（local 表示本机）")
	proto := fs.String("proto", "", "协议：tcp|udp|icmp|icmpv6|any")
	srcAddr := fs.String("src", "", "源地址列表，逗号分隔")
	dstAddr := fs.String("dst", "", "目的地址列表，逗号分隔")
	sport := fs.String("sport", "", "源端口列表，逗号分隔")
	dport := fs.String("dport", "", "目的端口列表，可为区间如 1000-2000")
	state := fs.String("state", "", "conntrack 状态列表：new,established,related,invalid")
	action := fs.String("action", "", "动作：accept|drop|reject|log")
	reject := fs.String("reject", "", "reject 方式：tcp-reset|icmp-port-unreachable")
	rate := fs.Int("limit-rate", 0, "限速：单位时间内的包数")
	per := fs.String("limit-per", "second", "限速单位：second|minute|hour|day")
	burst := fs.Int("limit-burst", 0, "限速突发额度")
	perIP := fs.Bool("limit-per-ip", false, "限速是否按源地址分别计数")
	maxConn := fs.Int("limit-max-conn", 0, "单源并发连接数上限（拦慢速攻击）")
	logIt := fs.Bool("log", false, "命中时记录日志")
	comment := fs.String("comment", "", "备注")
	if _, err := parseInterspersed(fs, args); err != nil {
		return r, err
	}
	if *action == "" {
		return r, errors.New("必须用 --action 指定动作（accept|drop|reject|log）")
	}
	if r.SrcZone == "" {
		r.SrcZone = model.ZoneAny
	}
	if r.DstZone == "" {
		r.DstZone = model.ZoneAny
	}
	r.Proto = model.Proto(*proto)
	if r.Proto == "" {
		r.Proto = model.ProtoAny
	}
	r.SrcAddr = splitList(*srcAddr)
	r.DstAddr = splitList(*dstAddr)
	r.SrcPort = splitList(*sport)
	r.DstPort = splitList(*dport)
	r.State = splitList(*state)
	r.Action = model.Action(*action)
	r.Reject = model.RejectMode(*reject)
	r.Log = *logIt
	r.Comment = *comment
	if *rate > 0 || *maxConn > 0 {
		r.Limit = &model.RateLimit{Rate: *rate, Per: *per, Burst: *burst, PerIP: *perIP, MaxConcurrent: *maxConn}
	}
	return r, nil
}

func cmdNAT(ctx context.Context, c *client.Client, out *os.File, format string, args []string) error {
	if len(args) == 0 {
		args = []string{"list"}
	}
	switch args[0] {
	case "list", "ls":
		var resp struct {
			Rules []model.NATRule `json:"nat_rules"`
		}
		if err := c.Get(ctx, "/nat", &resp); err != nil {
			return err
		}
		if format == "json" {
			return printJSON(out, resp.Rules)
		}
		if len(resp.Rules) == 0 {
			fmt.Fprintln(out, "（暂无 NAT 规则）")
			return nil
		}
		w := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "ID\t优先级\t类型\t协议\t匹配\t转换\t启用")
		for _, n := range resp.Rules {
			match := strings.Join(n.MatchAddr, ",")
			if n.MatchPort != "" {
				match = strings.TrimSuffix(match, ",") + ":" + n.MatchPort
			}
			to := n.ToAddr
			if n.ToPort != "" {
				to += ":" + n.ToPort
			}
			if n.Kind == model.NATMasquerade {
				to = "出接口地址"
			}
			fmt.Fprintf(w, "%s\t%d\t%s\t%s\t%s\t%s\t%s\n",
				n.ID, n.Priority, n.Kind, orAny(string(n.Proto)), orDash(match), orDash(to), yesNo(n.IsEnabled()))
		}
		return w.Flush()

	case "add-dnat", "add-snat", "add-masq", "add-masquerade":
		n, err := parseNATFlags(args[0], args[1:])
		if err != nil {
			return err
		}
		var resp struct {
			ID string `json:"id"`
		}
		if err := c.Post(ctx, "/nat", n, &resp); err != nil {
			return err
		}
		return pendingApply(out, fmt.Sprintf("已添加 %s 规则 %s", n.Kind, resp.ID))

	case "rm", "del", "remove":
		if len(args) < 2 {
			return errors.New("用法: fw nat rm <id>")
		}
		var resp map[string]any
		if err := c.Delete(ctx, "/nat/"+args[1], &resp); err != nil {
			return err
		}
		return pendingApply(out, "已删除 NAT 规则 "+args[1])

	default:
		return fmt.Errorf("未知子命令 fw nat %s（支持 list|add-dnat|add-snat|add-masq|rm）", args[0])
	}
}

// parseNATFlags 把命令行开关转成一条 NAT 规则。
func parseNATFlags(sub string, args []string) (model.NATRule, error) {
	var n model.NATRule
	fs := flag.NewFlagSet("nat", flag.ContinueOnError)
	fs.StringVar(&n.ID, "id", "", "规则 id（留空自动生成）")
	fs.IntVar(&n.Priority, "priority", 0, "优先级（留空排到末尾）")
	proto := fs.String("proto", "", "协议：tcp|udp")
	fs.StringVar(&n.SrcZone, "src-zone", "", "匹配来源域")
	src := fs.String("src", "", "匹配源地址列表，逗号分隔")
	match := fs.String("match-addr", "", "被转换的目的地址列表（dnat 用）")
	fs.StringVar(&n.MatchPort, "match-port", "", "匹配的目的端口（dnat 用）")
	fs.StringVar(&n.ToAddr, "to-addr", "", "转换后的地址")
	fs.StringVar(&n.ToPort, "to-port", "", "转换后的端口")
	fs.StringVar(&n.OutZone, "out-zone", "", "出接口域（snat/masquerade 用）")
	fs.StringVar(&n.Comment, "comment", "", "备注")
	if _, err := parseInterspersed(fs, args); err != nil {
		return n, err
	}

	switch sub {
	case "add-dnat":
		n.Kind = model.NATDNAT
	case "add-snat":
		n.Kind = model.NATSNAT
	default:
		n.Kind = model.NATMasquerade
	}
	n.Proto = model.Proto(*proto)
	if n.Proto == "" {
		n.Proto = model.ProtoAny
	}
	n.SrcAddr = splitList(*src)
	n.MatchAddr = splitList(*match)

	// 在这里先做一次基本检查，让错误在本地就暴露，不必等 API 往返。
	switch n.Kind {
	case model.NATDNAT:
		if n.ToAddr == "" {
			return n, errors.New("dnat 必须用 --to-addr 指定转换后的地址")
		}
	case model.NATSNAT:
		if n.ToAddr == "" {
			return n, errors.New("snat 必须用 --to-addr 指定转换后的地址")
		}
	case model.NATMasquerade:
		if n.OutZone == "" {
			return n, errors.New("masquerade 必须用 --out-zone 指定出接口所属的域")
		}
	}
	return n, nil
}

func cmdNet(ctx context.Context, c *client.Client, out *os.File, format string, args []string) error {
	if len(args) > 0 && args[0] == "sysctl" {
		return cmdNetSysctl(ctx, c, out, format, args[1:])
	}
	if len(args) > 0 && args[0] != "list" && args[0] != "show" {
		return fmt.Errorf("未知子命令 fw net %s（支持 list|sysctl）", args[0])
	}

	var resp struct {
		State struct {
			Platform   string             `json:"platform"`
			Sysctls    map[string]string  `json:"sysctls"`
			Links      []netcfg.LinkState `json:"links"`
			Addresses  []netcfg.Address   `json:"addresses"`
			Routes     []netcfg.Route     `json:"routes"`
			IPRules    []netcfg.IPRule    `json:"ip_rules"`
			Forwarding bool               `json:"forwarding"`
			Note       string             `json:"note"`
		} `json:"state"`
		Supported  bool            `json:"supported"`
		Diff       []netcfg.Change `json:"sysctl_diff"`
		Forwarding bool            `json:"forwarding_ok"`
	}
	if err := c.Get(ctx, "/net", &resp); err != nil {
		return err
	}
	if format == "json" {
		return printJSON(out, resp)
	}

	st := resp.State
	fmt.Fprintf(out, "平台: %s（可管理内核参数: %s）\n", st.Platform, yesNo(resp.Supported))
	if st.Note != "" {
		fmt.Fprintf(out, "说明: %s\n", st.Note)
	}
	switch {
	case resp.Supported && st.Forwarding:
		fmt.Fprintln(out, "IPv4 转发: 已开启")
	case resp.Supported:
		fmt.Fprintln(out, "IPv4 转发: ❌ 未开启 —— 跨网段流量不会经过 forward 钩子，防火墙策略对它不生效")
		fmt.Fprintln(out, "           修复: sysctl -w net.ipv4.ip_forward=1，或设置 manage_sysctls: true")
	default:
		// 非 Linux 平台没有这个开关，不做判定，免得误报。
		fmt.Fprintln(out, "IPv4 转发: 不适用（该平台无此内核开关）")
	}

	if resp.Supported && len(resp.Diff) > 0 {
		fmt.Fprintln(out, "\n与推荐基线不一致的内核参数:")
		w := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "  参数\t当前\t建议")
		for _, c := range resp.Diff {
			fmt.Fprintf(w, "  %s\t%s\t%s\n", c.Target, orDash(c.From), c.To)
		}
		_ = w.Flush()
	}

	if len(st.Links) > 0 {
		fmt.Fprintln(out, "\n接口:")
		w := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "  名称\tMTU\t状态\t标志")
		for _, l := range st.Links {
			status := "down"
			if l.Up {
				status = "up"
			}
			fmt.Fprintf(w, "  %s\t%d\t%s\t%s\n", l.Name, l.MTU, status, orDash(strings.Join(l.Flags, ",")))
		}
		_ = w.Flush()
	}

	if len(st.Addresses) > 0 {
		fmt.Fprintln(out, "\n地址:")
		w := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
		for _, a := range st.Addresses {
			fmt.Fprintf(w, "  %s\t%s\n", orDash(a.Interface), a.CIDR)
		}
		_ = w.Flush()
	}

	if len(st.Routes) > 0 {
		fmt.Fprintln(out, "\n路由:")
		w := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "  目的\t网关\t接口\t度量")
		for _, r := range st.Routes {
			fmt.Fprintf(w, "  %s\t%s\t%s\t%d\n", r.Dst, orDash(r.Via), orDash(r.Dev), r.Metric)
		}
		_ = w.Flush()
	}

	if len(st.IPRules) > 0 {
		fmt.Fprintln(out, "\n策略路由规则:")
		w := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "  优先级\t来源\t目的\t表")
		for _, r := range st.IPRules {
			fmt.Fprintf(w, "  %d\t%s\t%s\t%d\n", r.Priority, orDash(r.From), orDash(r.To), r.Table)
		}
		_ = w.Flush()
	}
	return nil
}

func cmdNetSysctl(ctx context.Context, c *client.Client, out *os.File, format string, args []string) error {
	sub := "show"
	if len(args) > 0 {
		sub = args[0]
	}
	switch sub {
	case "show", "list":
		var resp struct {
			State struct {
				Sysctls map[string]string `json:"sysctls"`
			} `json:"state"`
			Diff []netcfg.Change `json:"sysctl_diff"`
		}
		if err := c.Get(ctx, "/net", &resp); err != nil {
			return err
		}
		if format == "json" {
			return printJSON(out, resp)
		}
		w := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "参数\t当前值\t建议值")
		advice := map[string]string{}
		for _, c := range resp.Diff {
			advice[c.Target] = c.To
		}
		for _, k := range sortedKeys(resp.State.Sysctls) {
			fmt.Fprintf(w, "%s\t%s\t%s\n", k, resp.State.Sysctls[k], orDash(advice[k]))
		}
		return w.Flush()

	case "apply":
		fs := flag.NewFlagSet("net sysctl apply", flag.ContinueOnError)
		dryRun := fs.Bool("dry-run", false, "只显示将要做的变更")
		if _, err := parseInterspersed(fs, args[1:]); err != nil {
			return err
		}
		var resp struct {
			Applied []netcfg.Change `json:"applied"`
			Changes []netcfg.Change `json:"changes"`
			DryRun  bool            `json:"dry_run"`
			Count   int             `json:"count"`
			Error   string          `json:"error"`
		}
		body := map[string]any{"dry_run": *dryRun}
		if err := c.Post(ctx, "/net/sysctls", body, &resp); err != nil {
			return err
		}
		if resp.Error != "" {
			return errors.New(resp.Error)
		}
		if *dryRun {
			if len(resp.Changes) == 0 {
				fmt.Fprintln(out, "内核参数已符合基线，无需变更")
				return nil
			}
			fmt.Fprintln(out, "将执行以下变更（未实际修改）:")
			for _, ch := range resp.Changes {
				fmt.Fprintf(out, "  %s\n", ch)
			}
			return nil
		}
		if len(resp.Applied) == 0 {
			fmt.Fprintln(out, "内核参数已符合基线，未做修改")
			return nil
		}
		for _, ch := range resp.Applied {
			fmt.Fprintf(out, "已设置 %s: %s -> %s\n", ch.Target, orDash(ch.From), ch.To)
		}
		return nil

	default:
		return fmt.Errorf("未知子命令 fw net sysctl %s（支持 show|apply）", sub)
	}
}

func cmdBanEngine(ctx context.Context, c *client.Client, out *os.File, format string, args []string) error {
	fs := flag.NewFlagSet("ban engine", flag.ContinueOnError)
	enable := fs.Bool("enable", false, "打开自动封禁")
	disable := fs.Bool("disable", false, "关闭自动封禁（转为只观察）")
	if _, err := parseInterspersed(fs, args); err != nil {
		return err
	}
	if *enable || *disable {
		var resp map[string]any
		body := map[string]any{"enabled": *enable}
		if err := c.Post(ctx, "/ban/engine", body, &resp); err != nil {
			return err
		}
		if *enable {
			fmt.Fprintln(out, "自动封禁已开启")
		} else {
			fmt.Fprintln(out, "自动封禁已关闭（仍会观察并记录，但不再封禁）")
		}
		return nil
	}

	var resp struct {
		Enabled  bool         `json:"enabled"`
		Note     string       `json:"note"`
		Settings ban.Settings `json:"settings"`
		Stats    ban.Stats    `json:"stats"`
	}
	if err := c.Get(ctx, "/ban/engine", &resp); err != nil {
		return err
	}
	if format == "json" {
		return printJSON(out, resp)
	}
	if !resp.Enabled {
		fmt.Fprintln(out, "自动封禁未启用")
		if resp.Note != "" {
			fmt.Fprintln(out, resp.Note)
		}
		return nil
	}
	w := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	mode := "仅观察（不封禁）"
	if resp.Settings.Enabled {
		mode = "封禁中"
	}
	fmt.Fprintf(w, "模式\t%s\n", mode)
	fmt.Fprintf(w, "判定窗口\t%s\n", resp.Settings.Window)
	fmt.Fprintf(w, "触发阈值\t窗口内累计 %d\n", resp.Settings.Threshold)
	fmt.Fprintf(w, "首次封禁\t%s（每多一次翻 %g 倍，上限 %s）\n",
		resp.Settings.BaseTTL, resp.Settings.Multiplier, resp.Settings.MaxTTL)
	fmt.Fprintf(w, "白名单\t%d 项\n", len(resp.Settings.Whitelist))
	fmt.Fprintf(w, "已观察事件\t%d\n", resp.Stats.Observed)
	fmt.Fprintf(w, "跟踪中地址\t%d\n", resp.Stats.Tracked)
	fmt.Fprintf(w, "当前封禁中\t%d\n", resp.Stats.Banned)
	if resp.Stats.Dropped > 0 {
		fmt.Fprintf(w, "已丢弃\t%d（跟踪表已满，可能正在被大规模扫描）\n", resp.Stats.Dropped)
	}
	return w.Flush()
}

func cmdBanOffenders(ctx context.Context, c *client.Client, out *os.File, format string, args []string) error {
	var resp struct {
		Offenders []ban.Offender `json:"offenders"`
		Note      string         `json:"note"`
	}
	if err := c.Get(ctx, "/ban/offenders", &resp); err != nil {
		return err
	}
	if format == "json" {
		return printJSON(out, resp.Offenders)
	}
	if len(resp.Offenders) == 0 {
		if resp.Note != "" {
			fmt.Fprintln(out, resp.Note)
			return nil
		}
		fmt.Fprintln(out, "（当前没有被跟踪的可疑地址）")
		return nil
	}
	w := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "地址\t可疑度\t事件数\t违规次数\t封禁至\t来源")
	now := time.Now()
	for _, o := range resp.Offenders {
		banned := "-"
		if !o.BannedUntil.IsZero() && o.BannedUntil.After(now) {
			banned = o.BannedUntil.Format("15:04:05")
		}
		fmt.Fprintf(w, "%s\t%d\t%d\t%d\t%s\t%s\n",
			o.IP, o.Score, o.Events, o.Strikes, banned, orDash(strings.Join(o.Sources, ",")))
	}
	return w.Flush()
}

func cmdGroups(ctx context.Context, c *client.Client, out *os.File, format string, args []string) error {
	if len(args) > 0 && args[0] == "reload" {
		var resp struct {
			Changed bool   `json:"changed"`
			Note    string `json:"note"`
		}
		if err := c.Post(ctx, "/groups/reload", nil, &resp); err != nil {
			return err
		}
		fmt.Fprintf(out, "已重新读取地址组：%s\n", resp.Note)
		return nil
	}

	var resp struct {
		Groups []engine.GroupInfo `json:"groups"`
	}
	if err := c.Get(ctx, "/groups", &resp); err != nil {
		return err
	}
	if format == "json" {
		return printJSON(out, resp.Groups)
	}
	if len(resp.Groups) == 0 {
		fmt.Fprintln(out, "（没有定义地址组）")
		fmt.Fprintln(out, "地址组用来承载国家封锁、威胁情报这类几万条的 CIDR 列表；")
		fmt.Fprintln(out, "在策略文件的 addr_groups 里定义，规则用 src_group / dst_group 引用。")
		return nil
	}
	w := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "名称\tIPv4\tIPv6\t来源\t被引用")
	for _, g := range resp.Groups {
		fmt.Fprintf(w, "%s\t%d\t%d\t%s\t%s\n",
			g.Name, g.V4Count, g.V6Count, orDash(g.Source), orDash(strings.Join(g.UsedBy, ",")))
	}
	return w.Flush()
}

func cmdAlert(ctx context.Context, c *client.Client, out *os.File, format string, args []string) error {
	if len(args) > 0 && args[0] == "test" {
		fs := flag.NewFlagSet("alert test", flag.ContinueOnError)
		title := fs.String("title", "", "自定义测试消息的标题")
		if _, err := parseInterspersed(fs, args[1:]); err != nil {
			return err
		}
		var resp struct {
			OK       bool     `json:"ok"`
			Channels []string `json:"channels"`
			Errors   []string `json:"errors"`
		}
		body := map[string]any{"title": *title}
		if err := c.Post(ctx, "/alerts/test", body, &resp); err != nil {
			return err
		}
		fmt.Fprintf(out, "✅ 已向 %d 个通道发送测试告警: %s\n",
			len(resp.Channels), strings.Join(resp.Channels, ", "))
		fmt.Fprintln(out, "请检查你的手机/群里是否收到。")
		return nil
	}

	var resp struct {
		Enabled  bool     `json:"enabled"`
		Channels []string `json:"channels"`
		Sent     int64    `json:"sent"`
		Merged   int64    `json:"merged"`
		Dropped  int64    `json:"dropped"`
	}
	if err := c.Get(ctx, "/alerts", &resp); err != nil {
		return err
	}
	if format == "json" {
		return printJSON(out, resp)
	}
	if !resp.Enabled {
		fmt.Fprintln(out, "未配置告警通道。")
		fmt.Fprintln(out, "在配置文件的 alerts 里加一条，例如：")
		fmt.Fprintln(out, `  alerts:`)
		fmt.Fprintln(out, `    - {type: webhook, url: "https://qyapi.weixin.qq.com/...", format: wecom}`)
		fmt.Fprintln(out, `    - {type: smtp, addr: "smtp.qq.com:465", implicit_tls: true, from: you@qq.com, to: [you@qq.com], username: you@qq.com, password: "授权码"}`)
		return nil
	}
	w := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	fmt.Fprintf(w, "通道\t%s\n", strings.Join(resp.Channels, ", "))
	fmt.Fprintf(w, "已发送\t%d\n", resp.Sent)
	fmt.Fprintf(w, "已合并\t%d（去重窗口内的重复事件）\n", resp.Merged)
	if resp.Dropped > 0 {
		fmt.Fprintf(w, "已丢弃\t%d（队列满，说明有通道严重卡住）\n", resp.Dropped)
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
	case "export":
		fs := flag.NewFlagSet("ban export", flag.ContinueOnError)
		format := fs.String("format", "csv", "导出格式：csv | json")
		since := fs.String("since", "", "起始时间：24h / 7d / 2026-01-01T00:00:00Z；留空为全部")
		outFile := fs.String("o", "", "输出文件；留空打印到标准输出")
		if _, err := parseInterspersed(fs, args[1:]); err != nil {
			return err
		}
		text, err := c.GetText(ctx, client.Query("/bans/export", map[string]string{
			"format": *format, "since": *since,
		}))
		if err != nil {
			return err
		}
		text = strings.TrimPrefix(text, "ï»¿") // 去掉导出文件开头的 BOM，避免重复
		if *outFile == "" {
			fmt.Fprint(out, text)
			return nil
		}
		if err := os.WriteFile(*outFile, []byte(text), 0o600); err != nil {
			return err
		}
		fmt.Fprintf(out, "已导出到 %s\n", *outFile)
		return nil

	case "engine":
		return cmdBanEngine(ctx, c, out, format, args[1:])
	case "offenders":
		return cmdBanOffenders(ctx, c, out, format, args[1:])
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

// splitList 把逗号分隔的列表拆成切片，忽略空白项。
func splitList(s string) []string {
	var out []string
	for _, part := range strings.Split(s, ",") {
		if p := strings.TrimSpace(part); p != "" {
			out = append(out, p)
		}
	}
	return out
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

// sortedKeys 返回排序后的键，让输出稳定可 diff。
func sortedKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// currentMode 是本次命令行读取到的部署形态。
//
// CLI 的各个子命令都从 run() 分发，把 mode 一路传下去会改动一串签名，
// 而它只影响"默认值"这类小事 —— 用包级变量更划算。
var currentMode string

func defaultDstZone() string {
	if currentMode == "host" {
		return model.ZoneLocal
	}
	return model.ZoneAny
}
