package ir

import (
	"fmt"
	"net"
	"strings"
)

// Render 把快照渲染为 nft 规则集文本。
//
// 输出可直接交给 `nft -f -` 执行；同一份文本也是 dry-run 的审阅内容，
// 因此"看到什么就下发什么"。
func (s *Snapshot) Render() string {
	var b strings.Builder
	for _, t := range s.Tables {
		renderTable(&b, t)
		b.WriteString("\n")
	}
	return b.String()
}

func renderTable(b *strings.Builder, t *Table) {
	fmt.Fprintf(b, "table %s %s {\n", t.Family, quoteIfNeeded(t.Name))

	for _, set := range t.Sets {
		renderSet(b, set)
	}
	for _, c := range t.Chains {
		renderChain(b, c)
	}
	b.WriteString("}\n")
}

func renderSet(b *strings.Builder, s *Set) {
	fmt.Fprintf(b, "\tset %s {\n", quoteIfNeeded(s.Name))
	fmt.Fprintf(b, "\t\ttype %s\n", s.KeyType)
	if len(s.Flags) > 0 {
		// nft 要求 flags 之间用逗号且不留空格。
		fmt.Fprintf(b, "\t\tflags %s\n", strings.Join(s.Flags, ","))
	}
	if s.Timeout > 0 {
		fmt.Fprintf(b, "\t\ttimeout %s\n", formatDuration(s.Timeout))
	}
	if len(s.Elements) > 0 {
		var elems []string
		for _, e := range s.Elements {
			elems = append(elems, renderElement(e))
		}
		fmt.Fprintf(b, "\t\telements = { %s }\n", strings.Join(elems, ", "))
	}
	if s.Comment != "" {
		fmt.Fprintf(b, "\t\tcomment %s\n", quote(s.Comment))
	}
	b.WriteString("\t}\n")
}

func renderElement(e Element) string {
	out := e.Key
	if e.Timeout > 0 {
		out += " timeout " + formatDuration(e.Timeout)
	}
	if e.Comment != "" {
		out += " comment " + quote(e.Comment)
	}
	return out
}

func renderChain(b *strings.Builder, c *Chain) {
	fmt.Fprintf(b, "\tchain %s {\n", quoteIfNeeded(c.Name))
	if c.Base {
		policy := c.Policy
		if policy == "" {
			policy = "accept"
		}
		fmt.Fprintf(b, "\t\ttype %s hook %s priority %d; policy %s;\n",
			c.Type, c.Hook, c.Priority, policy)
	}
	for _, r := range c.Rules {
		b.WriteString("\t\t")
		b.WriteString(renderRule(r))
		b.WriteString("\n")
	}
	b.WriteString("\t}\n")
}

// renderRule 渲染单条规则（不含缩进与换行）。
func renderRule(r *Rule) string {
	if r.Raw != "" {
		return r.Raw
	}
	var parts []string
	for _, m := range r.Matches {
		parts = append(parts, renderMatch(m))
	}
	for _, st := range r.Stmts {
		if s := renderStatement(st); s != "" {
			parts = append(parts, s)
		}
	}
	body := strings.Join(parts, " ")
	if r.Comment != "" {
		if body == "" {
			body = "counter"
		}
		return body + " comment " + quote(r.Comment)
	}
	if body == "" {
		// 空规则无意义，渲染为计数以便调试。
		return "counter"
	}
	return body
}

// RuleBody 返回规则去掉注释与 ID 后的规范化文本，用于判重。
//
// 语义完全相同的两条规则（例如用户显式写的 established 放行与编译器注入的
// conntrack 快速通道）据此去重，避免生成的规则集出现冗余。
func RuleBody(r *Rule) string {
	if r.Raw != "" {
		return r.Raw
	}
	var parts []string
	for _, m := range r.Matches {
		parts = append(parts, renderMatch(m))
	}
	for _, st := range r.Stmts {
		if s := renderStatement(st); s != "" {
			parts = append(parts, s)
		}
	}
	return strings.Join(parts, " ")
}

func renderMatch(m Match) string {
	var out string
	switch {
	case m.Set != "":
		out = m.Field + " @" + m.Set
	case len(m.Values) == 1:
		out = m.Field + " " + renderValue(m.Field, m.Values[0])
	case len(m.Values) > 1:
		out = m.Field + " { " + joinValues(m.Field, m.Values) + " }"
	default:
		return ""
	}
	if m.Negate {
		// nft 的否定写法：把 != 插在字段之后。
		if idx := strings.IndexByte(out, ' '); idx >= 0 {
			return out[:idx] + " != " + strings.TrimPrefix(out[idx+1:], " ")
		}
	}
	return out
}

func joinValues(field string, vals []string) string {
	out := make([]string, 0, len(vals))
	for _, v := range vals {
		out = append(out, renderValue(field, v))
	}
	return strings.Join(out, ", ")
}

// renderValue 对接口名/字符串字段加引号；端口区间用 nft 的 a-b 形式。
func renderValue(field, v string) string {
	switch {
	case field == "iifname" || field == "oifname",
		strings.HasSuffix(field, "iifname"), strings.HasSuffix(field, "oifname"):
		return quote(v)
	case field == "ct state", field == "meta l4proto", field == "ct status", field == "ct direction":
		return v
	default:
		return v
	}
}

func renderStatement(st Statement) string {
	switch st.Kind {
	case StmtCounter:
		return "counter"
	case StmtVerdict:
		return renderVerdict(st)
	case StmtLog:
		prefix := st.Prefix
		if prefix == "" {
			prefix = "fw "
		}
		s := fmt.Sprintf("log prefix %s", quoteIfNeeded(prefix))
		if st.Level != "" {
			s += " level " + st.Level
		}
		return s
	case StmtLimit:
		per := st.Per
		if per == "" {
			per = "second"
		}
		s := fmt.Sprintf("limit rate %s/%s", humanRate(st.Rate), per)
		if st.Burst > 0 {
			s += fmt.Sprintf(" burst %d packets", st.Burst)
		}
		return s
	case StmtLimitPerIP, StmtMeter:
		per := st.Per
		if per == "" {
			per = "second"
		}
		key := st.KeyField
		if key == "" {
			key = "ip saddr"
		}
		op := "rate"
		if st.Over {
			op = "rate over"
		}
		return fmt.Sprintf("add @%s { %s limit %s %s/%s }", st.SetName, key, op, humanRate(st.Rate), per)
	case StmtConnLimit:
		// nft 里"按源地址限制并发连接数"的写法是往动态集合里 add 一条
		// ct count 表达式：超过阈值的源会被记录进集合，随后的 drop 才生效。
		key := st.KeyField
		if key == "" {
			key = "ip saddr"
		}
		if st.MaxConcurrent <= 0 {
			return ""
		}
		return fmt.Sprintf("add @%s { %s ct count over %d }", st.SetName, key, st.MaxConcurrent)
	case StmtNAT:
		switch st.NATKind {
		case "masquerade":
			return "masquerade"
		case "redirect":
			if st.Port != "" {
				return "redirect to :" + st.Port
			}
			return "redirect"
		case "snat", "dnat":
			return st.NATKind + " to " + formatNATTarget(st.Addr, st.Port)
		}
		return ""
	case StmtJump:
		return "jump " + st.Target
	case StmtGoto:
		return "goto " + st.Target
	}
	return ""
}

func renderVerdict(st Statement) string {
	switch st.Verdict {
	case "accept", "drop", "return", "continue":
		return st.Verdict
	case "reject":
		switch st.Reject {
		case "tcp-reset":
			return "reject with tcp reset"
		case "icmp-port-unreachable", "port-unreachable":
			return "reject with icmp type port-unreachable"
		case "icmp6-port-unreachable":
			return "reject with icmpv6 type port-unreachable"
		default:
			return "reject"
		}
	}
	return st.Verdict
}

// humanRate 把数字速率渲染为 nft 更易读的写法（1000/second -> 1000/second）。
func humanRate(n int) string {
	if n <= 0 {
		n = 1
	}
	return fmt.Sprintf("%d", n)
}

// formatNATTarget 渲染 NAT 目标地址：IPv6 字面量需要方括号包裹。
//
//	10.0.0.1:8080        -> 10.0.0.1:8080
//	2001:db8::1 + 8080   -> [2001:db8::1]:8080
//	10.0.0.0/24          -> 10.0.0.0/24
func formatNATTarget(addr, port string) string {
	if addr == "" {
		return ""
	}
	host := addr
	if _, ipnet, err := net.ParseCIDR(addr); err == nil {
		host = ipnet.IP.String()
	}
	ip := net.ParseIP(host)
	if ip != nil && ip.To4() == nil {
		if port != "" {
			return "[" + addr + "]:" + port
		}
		return "[" + addr + "]"
	}
	if port != "" {
		return addr + ":" + port
	}
	return addr
}
