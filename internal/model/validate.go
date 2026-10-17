package model

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

// Problem 是一条校验问题。
type Problem struct {
	// Level 为 "error" 或 "warning"。
	Level   string `json:"level"`
	Where   string `json:"where"`
	Message string `json:"message"`
}

func errf(where, format string, a ...any) Problem {
	return Problem{Level: "error", Where: where, Message: fmt.Sprintf(format, a...)}
}

func warnf(where, format string, a ...any) Problem {
	return Problem{Level: "warning", Where: where, Message: fmt.Sprintf(format, a...)}
}

// Normalize 填充缺省值并做规范化；返回被修改过的说明（用于审计）。
func (p *Policy) Normalize() []string {
	var notes []string
	seen := map[string]bool{}
	for i := range p.Rules {
		r := &p.Rules[i]
		if r.ID != "" {
			continue
		}
		for n := 1; ; n++ {
			id := fmt.Sprintf("rule-%d", n)
			if !seen[id] && p.RuleByID(id) == nil {
				r.ID = id
				notes = append(notes, fmt.Sprintf("rules[%d]: 自动分配 id=%s", i, id))
				seen[id] = true
				break
			}
		}
	}
	for i := range p.NATRules {
		n := &p.NATRules[i]
		if n.ID == "" {
			id := fmt.Sprintf("nat-%d", i+1)
			n.ID = id
			notes = append(notes, fmt.Sprintf("nat_rules[%d]: 自动分配 id=%s", i, id))
		}
	}
	if p.BanSet.Timeout == 0 {
		p.BanSet.Timeout = 24 * time.Hour
	}
	return notes
}

// Validate 静态校验期望状态。返回的问题中 Level=="error" 的会阻止编译。
func (p *Policy) Validate() []Problem {
	var ps []Problem

	// 域
	zoneNames := map[string]bool{}
	for i, z := range p.Zones {
		where := fmt.Sprintf("zones[%d]", i)
		if z.Name == "" {
			ps = append(ps, errf(where, "域名为空"))
			continue
		}
		if z.Name == ZoneAny || z.Name == ZoneLocal {
			ps = append(ps, errf(where, "域名 %q 为保留字", z.Name))
		}
		if zoneNames[z.Name] {
			ps = append(ps, errf(where, "域名 %q 重复", z.Name))
		}
		zoneNames[z.Name] = true
		if len(z.Interfaces) == 0 && len(z.Networks) == 0 {
			ps = append(ps, warnf(where, "域 %q 既无接口也无网段，不会匹配任何流量", z.Name))
		}
		for _, n := range z.Networks {
			if _, _, err := net.ParseCIDR(n); err != nil {
				ps = append(ps, errf(where, "网段 %q 非法: %v", n, err))
			}
		}
		if z.Trust != "" {
			switch z.Trust {
			case TrustUntrusted, TrustDMZ, TrustLAN, TrustLocal:
			default:
				ps = append(ps, errf(where, "信任级别 %q 未知", z.Trust))
			}
		}
	}

	checkZoneRef := func(where, field, name string) {
		if name == "" || name == ZoneAny || name == ZoneLocal {
			return
		}
		if !zoneNames[name] {
			ps = append(ps, errf(where, "%s 引用了不存在的域 %q", field, name))
		}
	}

	// 地址组
	groupNames := map[string]bool{}
	for i, g := range p.AddrGroups {
		where := fmt.Sprintf("addr_groups[%d]", i)
		if g.Name == "" {
			ps = append(ps, errf(where, "地址组名为空"))
			continue
		}
		if groupNames[g.Name] {
			ps = append(ps, errf(where, "地址组名 %q 重复", g.Name))
		}
		groupNames[g.Name] = true
		where = fmt.Sprintf("addr_groups[%s]", g.Name)

		if g.File == "" && len(g.CIDRs) == 0 {
			ps = append(ps, errf(where, "地址组既没有 file 也没有 cidrs，加载不到任何地址"))
		}
		if g.File != "" && len(g.CIDRs) > 0 {
			// 两种来源同时给出时无法判断谁优先，直接拒绝而不是猜。
			ps = append(ps, errf(where, "file 与 cidrs 只能二选一"))
		}
		for _, c := range g.CIDRs {
			if _, _, err := net.ParseCIDR(c); err != nil {
				if net.ParseIP(c) == nil {
					ps = append(ps, errf(where, "地址 %q 非法的 IP 或 CIDR", c))
				}
			}
		}
	}

	checkGroupRef := func(where, field, name string) {
		if name == "" {
			return
		}
		if !groupNames[name] {
			ps = append(ps, errf(where, "%s 引用了未声明的地址组 %q", field, name))
		}
	}

	// 规则
	ruleIDs := map[string]bool{}
	for i := range p.Rules {
		r := &p.Rules[i]
		where := fmt.Sprintf("rules[%d]", i)
		if r.ID != "" {
			if ruleIDs[r.ID] {
				ps = append(ps, errf(where, "规则 id %q 重复", r.ID))
			}
			ruleIDs[r.ID] = true
			where = fmt.Sprintf("rules[%s]", r.ID)
		}
		checkZoneRef(where, "src_zone", r.SrcZone)
		checkZoneRef(where, "dst_zone", r.DstZone)
		checkGroupRef(where, "src_group", r.SrcGroup)
		checkGroupRef(where, "dst_group", r.DstGroup)
		if r.SrcGroup != "" && len(r.SrcAddr) > 0 {
			ps = append(ps, warnf(where,
				"同时指定了 src_addr 与 src_group，二者是「与」的关系（地址既要在列表里、也要在组里）"))
		}
		if r.DstGroup != "" && len(r.DstAddr) > 0 {
			ps = append(ps, warnf(where,
				"同时指定了 dst_addr 与 dst_group，二者是「与」的关系"))
		}

		if r.SrcZone == ZoneLocal && r.DstZone == ZoneLocal {
			ps = append(ps, warnf(where, "src_zone 与 dst_zone 均为 local，规则只会匹配环回流量"))
		}

		switch r.Proto {
		case "", ProtoAny, ProtoTCP, ProtoUDP, ProtoICMP, ProtoICMPv6, ProtoIGMP, ProtoGRE, ProtoESP:
		default:
			ps = append(ps, errf(where, "协议 %q 未知", r.Proto))
		}
		switch r.Action {
		case ActionAccept, ActionDrop, ActionReject, ActionLog:
		default:
			ps = append(ps, errf(where, "动作 %q 未知（应为 accept/drop/reject/log）", r.Action))
		}
		if (len(r.DstPort) > 0 || len(r.SrcPort) > 0) && !protoHasPorts(r.Proto) {
			ps = append(ps, errf(where, "指定了端口但协议 %q 不是 tcp/udp", orAny(r.Proto)))
		}
		if r.Action == ActionReject && !protoHasPorts(r.Proto) && r.Proto != ProtoICMP && r.Proto != ProtoICMPv6 && r.Reject == RejectTCPReset {
			ps = append(ps, errf(where, "reject=tcp-reset 仅适用于 tcp"))
		}
		for _, a := range append(append([]string{}, r.SrcAddr...), r.DstAddr...) {
			if _, _, err := net.ParseCIDR(a); err != nil {
				if net.ParseIP(a) == nil {
					ps = append(ps, errf(where, "地址 %q 非法的 IP 或 CIDR", a))
				}
			}
		}
		for _, port := range append(append([]string{}, r.SrcPort...), r.DstPort...) {
			if err := validatePort(port); err != nil {
				ps = append(ps, errf(where, "端口 %q 非法: %v", port, err))
			}
		}
		for _, s := range r.State {
			switch s {
			case "new", "established", "related", "invalid", "untracked":
			default:
				ps = append(ps, errf(where, "conntrack 状态 %q 未知", s))
			}
		}
		if r.Limit != nil {
			if r.Limit.Rate <= 0 && r.Limit.MaxConcurrent <= 0 {
				ps = append(ps, errf(where, "limit 既没有 rate 也没有 max_concurrent，等于没有限速"))
			}
			if r.Limit.Rate < 0 {
				ps = append(ps, errf(where, "limit.rate 不能为负"))
			}
			if r.Limit.MaxConcurrent < 0 {
				ps = append(ps, errf(where, "limit.max_concurrent 不能为负"))
			}
			if r.Limit.Rate > 0 {
				if _, err := rateUnit(r.Limit.Per); err != nil {
					ps = append(ps, errf(where, "limit.per %v", err))
				}
			}
			// ct count 只对建立连接的协议有意义：ICMP 没有"连接"可言。
			if r.Limit.MaxConcurrent > 0 && !protoHasPorts(r.Proto) {
				ps = append(ps, errf(where,
					"limit.max_concurrent 需要协议为 tcp 或 udp（并发连接数对 %s 没有意义）", orAny(r.Proto)))
			}
			// 按源限速只能表达"超额"（nft 没有"按源、限内"的写法），
			// 所以它必然意味着"超额就丢"。对纯记录日志的规则用它会把它变成丢弃规则。
			if r.Limit.PerIP && r.Limit.Rate > 0 && r.Action == ActionLog {
				ps = append(ps, errf(where,
					"action=log 不能用 limit.per_ip：按源限速在 nft 里只能表达「超额即丢弃」，"+
						"会把纯记录规则变成丢弃规则。要限制日志速率请去掉 per_ip 用全局限速"))
			}
		}
	}

	// NAT
	natIDs := map[string]bool{}
	for i := range p.NATRules {
		n := &p.NATRules[i]
		where := fmt.Sprintf("nat_rules[%d]", i)
		if n.ID != "" {
			if natIDs[n.ID] {
				ps = append(ps, errf(where, "NAT 规则 id %q 重复", n.ID))
			}
			natIDs[n.ID] = true
			where = fmt.Sprintf("nat_rules[%s]", n.ID)
		}
		checkZoneRef(where, "src_zone", n.SrcZone)
		checkZoneRef(where, "out_zone", n.OutZone)
		switch n.Kind {
		case NATSNAT, NATMasquerade, NATDNAT:
		case "":
			ps = append(ps, errf(where, "kind 不能为空（snat/masquerade/dnat）"))
		default:
			ps = append(ps, errf(where, "kind %q 未知", n.Kind))
		}
		switch n.Kind {
		case NATDNAT:
			if n.ToAddr == "" {
				ps = append(ps, errf(where, "dnat 必须指定 to_addr"))
			}
			if n.MatchPort != "" && !protoHasPorts(n.Proto) {
				ps = append(ps, errf(where, "指定了 match_port 但协议 %q 不是 tcp/udp", orAny(n.Proto)))
			}
		case NATSNAT:
			if n.ToAddr == "" {
				ps = append(ps, errf(where, "snat 必须指定 to_addr"))
			}
		case NATMasquerade:
			if n.OutZone == "" {
				ps = append(ps, warnf(where, "masquerade 未指定 out_zone，将对所有出方向流量伪装"))
			}
		}
		if n.ToAddr != "" && net.ParseIP(n.ToAddr) == nil {
			if _, _, err := net.ParseCIDR(n.ToAddr); err != nil {
				ps = append(ps, errf(where, "to_addr %q 非法的 IP 或 CIDR", n.ToAddr))
			}
		}
		if n.MatchPort != "" {
			if err := validatePort(n.MatchPort); err != nil {
				ps = append(ps, errf(where, "match_port %q 非法: %v", n.MatchPort, err))
			}
		}
		if n.ToPort != "" {
			if err := validatePort(n.ToPort); err != nil {
				ps = append(ps, errf(where, "to_port %q 非法: %v", n.ToPort, err))
			}
		}
		for _, a := range append(append([]string{}, n.SrcAddr...), n.MatchAddr...) {
			if _, _, err := net.ParseCIDR(a); err != nil {
				if net.ParseIP(a) == nil {
					ps = append(ps, errf(where, "地址 %q 非法的 IP 或 CIDR", a))
				}
			}
		}
	}

	// 封禁
	for i, b := range p.Bans {
		where := fmt.Sprintf("bans[%d]", i)
		if net.ParseIP(b.IP) == nil {
			ps = append(ps, errf(where, "封禁地址 %q 非法", b.IP))
		}
	}
	for i, w := range p.BanSet.Whitelist {
		where := fmt.Sprintf("ban_settings.whitelist[%d]", i)
		if _, _, err := net.ParseCIDR(w); err != nil {
			if net.ParseIP(w) == nil {
				ps = append(ps, errf(where, "白名单地址 %q 非法的 IP 或 CIDR", w))
			}
		}
	}

	// 默认策略
	for _, d := range []struct {
		name string
		a    Action
	}{
		{"default.input", p.Default.Input},
		{"default.forward", p.Default.Forward},
		{"default.output", p.Default.Output},
	} {
		switch d.a {
		case "", ActionAccept, ActionDrop, ActionReject:
		default:
			ps = append(ps, errf(d.name, "默认策略 %q 只能是 accept/drop/reject", d.a))
		}
	}

	return ps
}

// Errors 过滤出 error 级别的问题。
func Errors(ps []Problem) []Problem {
	var out []Problem
	for _, p := range ps {
		if p.Level == "error" {
			out = append(out, p)
		}
	}
	return out
}

func orAny(p Proto) string {
	if p == "" {
		return string(ProtoAny)
	}
	return string(p)
}

func protoHasPorts(p Proto) bool { return p == ProtoTCP || p == ProtoUDP }

func validatePort(s string) error {
	s = strings.TrimSpace(s)
	if s == "" {
		return fmt.Errorf("空端口")
	}
	lo, hi, found := strings.Cut(s, "-")
	p1, err := parsePort(lo)
	if err != nil {
		return err
	}
	if !found {
		return nil
	}
	p2, err := parsePort(hi)
	if err != nil {
		return err
	}
	if p1 > p2 {
		return fmt.Errorf("起始端口大于结束端口")
	}
	return nil
}

func parsePort(s string) (int, error) {
	n, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil {
		return 0, fmt.Errorf("不是数字")
	}
	if n < 0 || n > 65535 {
		return 0, fmt.Errorf("超出 0-65535")
	}
	return n, nil
}

func rateUnit(per string) (string, error) {
	switch strings.ToLower(per) {
	case "", "second", "s":
		return "second", nil
	case "minute", "m":
		return "minute", nil
	case "hour", "h":
		return "hour", nil
	case "day", "d":
		return "day", nil
	}
	return "", fmt.Errorf("只能是 second/minute/hour/day")
}
