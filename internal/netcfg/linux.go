//go:build linux

package netcfg

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/vishvananda/netlink"
)

// procSysRoot 是 sysctl 的文件系统视图；测试时可以改写。
var procSysRoot = "/proc/sys"

type linuxProvider struct{}

// New 返回当前平台的实现。
func New() Provider { return linuxProvider{} }

func (linuxProvider) Platform() string { return "linux" }
func (linuxProvider) Supported() bool  { return true }

// Read 读取接口、地址、路由、策略路由与转发开关。
//
// 全部只读，任何一项失败都不影响其余项，只是少报一部分信息。
func (linuxProvider) Read(ctx context.Context) (*State, error) {
	st := &State{Platform: "linux", Sysctls: map[string]string{}}

	// 关键参数：读不到就留空，由调用方判断。
	for _, key := range []string{KeyIPv4Forward, KeyIPv6Forward, KeyRPFilter, KeySyncookies, KeyConnMax} {
		if v, err := readSysctl(key); err == nil {
			st.Sysctls[key] = v
		}
	}
	st.Forwarding = strings.TrimSpace(st.Sysctls[KeyIPv4Forward]) == "1"

	links, err := netlink.LinkList()
	if err != nil {
		st.Note = joinNote(st.Note, fmt.Sprintf("读取接口失败: %v", err))
	} else {
		for _, l := range links {
			attrs := l.Attrs()
			up := attrs.Flags&net.FlagUp != 0
			st.Links = append(st.Links, LinkState{
				Name:  attrs.Name,
				Index: attrs.Index,
				MTU:   attrs.MTU,
				Up:    up,
				Flags: linkFlags(attrs.Flags),
			})
		}
		sort.Slice(st.Links, func(i, j int) bool { return st.Links[i].Index < st.Links[j].Index })
	}

	addrs, err := netlink.AddrList(nil, netlink.FAMILY_ALL)
	if err != nil {
		st.Note = joinNote(st.Note, fmt.Sprintf("读取地址失败: %v", err))
	} else {
		for _, a := range addrs {
			if a.IPNet == nil {
				continue
			}
			dev := ""
			if l, err := netlink.LinkByIndex(a.LinkIndex); err == nil {
				dev = l.Attrs().Name
			}
			family := "inet"
			if a.IPNet.IP.To4() == nil {
				family = "inet6"
			}
			st.Addresses = append(st.Addresses, Address{
				Interface: dev,
				CIDR:      a.IPNet.String(),
				Family:    family,
			})
		}
	}

	routes, err := netlink.RouteList(nil, netlink.FAMILY_ALL)
	if err != nil {
		st.Note = joinNote(st.Note, fmt.Sprintf("读取路由失败: %v", err))
	} else {
		for _, r := range routes {
			dev := ""
			if l, err := netlink.LinkByIndex(r.LinkIndex); err == nil {
				dev = l.Attrs().Name
			}
			dst := "default"
			if r.Dst != nil {
				dst = r.Dst.String()
			}
			via := ""
			if r.Gw != nil {
				via = r.Gw.String()
			}
			st.Routes = append(st.Routes, Route{
				Dst: dst, Via: via, Dev: dev,
				Table: r.Table, Metric: r.Priority, Proto: r.Protocol.String(),
			})
		}
	}

	rules, err := netlink.RuleList(netlink.FAMILY_ALL)
	if err == nil {
		for _, r := range rules {
			ir := IPRule{Priority: r.Priority, Table: r.Table, Mark: int(r.Mark)}
			if r.Src != nil {
				ir.From = cidrOrIP(r.Src)
			}
			if r.Dst != nil {
				ir.To = cidrOrIP(r.Dst)
			}
			st.IPRules = append(st.IPRules, ir)
		}
		sort.Slice(st.IPRules, func(i, j int) bool { return st.IPRules[i].Priority < st.IPRules[j].Priority })
	}

	return st, nil
}

// SetSysctls 写入内核参数，返回实际发生的变更。
func (linuxProvider) SetSysctls(ctx context.Context, desired []Sysctl) ([]Change, error) {
	norm, err := Normalize(desired)
	if err != nil {
		return nil, err
	}

	current := map[string]string{}
	for _, s := range norm {
		if v, err := readSysctl(s.Key); err == nil {
			current[s.Key] = v
		}
	}
	changes := DiffSysctls(norm, current)
	if len(changes) == 0 {
		return nil, nil
	}

	var applied []Change
	for _, c := range changes {
		if err := ctx.Err(); err != nil {
			return applied, err
		}
		if err := writeSysctl(c.Target, c.To); err != nil {
			return applied, fmt.Errorf("设置 %s = %s 失败: %w（需要 root 且该参数必须存在）", c.Target, c.To, err)
		}
		applied = append(applied, c)
	}
	return applied, nil
}

// ---- sysctl 读写（走 /proc/sys，不引入额外依赖）----

func sysctlPath(key string) string {
	return filepath.Join(procSysRoot, filepath.FromSlash(strings.ReplaceAll(NormalizeKey(key), ".", "/")))
}

func readSysctl(key string) (string, error) {
	b, err := os.ReadFile(sysctlPath(key))
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(b)), nil
}

func writeSysctl(key, value string) error {
	// 参数可能不存在（例如没加载 nf_conntrack 模块），此时 WriteFile 会失败，
	// 由调用方决定是致命错误还是可忽略。
	if err := os.WriteFile(sysctlPath(key), []byte(value+"\n"), 0o644); err != nil {
		return err
	}
	return nil
}

// ProbeSysctl 报告某个参数在当前系统上是否存在。
func ProbeSysctl(key string) bool {
	_, err := os.Stat(sysctlPath(key))
	return err == nil
}

func linkFlags(f net.Flags) []string {
	var out []string
	for _, fg := range []struct {
		flag net.Flags
		name string
	}{
		{net.FlagUp, "up"}, {net.FlagBroadcast, "broadcast"}, {net.FlagLoopback, "loopback"},
		{net.FlagPointToPoint, "pointtopoint"}, {net.FlagMulticast, "multicast"}, {net.FlagRunning, "running"},
	} {
		if f&fg.flag != 0 {
			out = append(out, fg.name)
		}
	}
	return out
}

func cidrOrIP(n *net.IPNet) string {
	ones, bits := n.Mask.Size()
	if ones == bits {
		return n.IP.String()
	}
	return n.String()
}

func joinNote(a, b string) string {
	if a == "" {
		return b
	}
	return a + "; " + b
}
