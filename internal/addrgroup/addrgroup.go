// Package addrgroup 把地址组定义解析成实际可用的 CIDR 列表。
//
// 存在的理由：国家封锁、威胁情报订阅这类场景动辄几万条 CIDR。把它们写进
// 规则里会被内联成规则文本（规则集直接爆炸），必须走 nft 的区间集合。
// 本包负责把"文件 / 内联列表"这类来源统一成集合元素，并按地址族分开 ——
// nft 的 ipv4_addr 与 ipv6_addr 是两个不同类型的集合。
package addrgroup

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"os"
	"sort"
	"strings"

	"fwdd/internal/model"
)

// Set 是一个已加载的地址组。
type Set struct {
	Name string   `json:"name"`
	V4   []string `json:"-"`
	V6   []string `json:"-"`
	// V4Count / V6Count 供展示与指标使用。
	V4Count int `json:"v4_count"`
	V6Count int `json:"v6_count"`
	// Source 记录来源，便于排查"为什么这个组是空的"。
	Source string `json:"source"`
}

// Total 返回该组的地址条目总数。
func (s *Set) Total() int { return s.V4Count + s.V6Count }

// Table 是全部地址组。
type Table map[string]*Set

// Load 按策略里的定义加载全部地址组。
//
// 任何一个组加载失败都会直接返回错误，而不是跳过 —— 少了地址的封禁是
// 静默失效，比起启动失败更难排查。
func Load(groups []model.AddrGroup) (Table, error) {
	out := make(Table, len(groups))
	for _, g := range groups {
		set, err := loadOne(g)
		if err != nil {
			return nil, err
		}
		out[g.Name] = set
	}
	return out, nil
}

func loadOne(g model.AddrGroup) (*Set, error) {
	var (
		v4, v6 []string
		source string
		err    error
	)
	switch {
	case g.File != "":
		f, ferr := os.Open(g.File)
		if ferr != nil {
			return nil, fmt.Errorf("地址组 %s: 打开 %s 失败: %w", g.Name, g.File, ferr)
		}
		defer f.Close()
		v4, v6, err = ParseCIDRList(f)
		source = g.File
	case len(g.CIDRs) > 0:
		v4, v6, err = ParseCIDRList(strings.NewReader(strings.Join(g.CIDRs, "\n")))
		source = "内联"
	default:
		return nil, fmt.Errorf("地址组 %s: 既没有 file 也没有 cidrs", g.Name)
	}
	if err != nil {
		return nil, fmt.Errorf("地址组 %s（%s）: %w", g.Name, source, err)
	}
	return &Set{
		Name: g.Name, V4: v4, V6: v6,
		V4Count: len(v4), V6Count: len(v6), Source: source,
	}, nil
}

// ParseCIDRList 解析一份 CIDR 列表。
//
// 格式：每行一个 CIDR 或 IP，`#` 起注释，空行忽略。
// 裸 IP 会补成 /32 或 /128 —— 公共国家的地址列表里常常混着单 IP。
//
// 遇到无法解析的行会**直接报错并指出行号**，不做静默跳过：
// 一条被悄悄忽略的 CIDR 意味着一个本该被拦住的地址能穿过去。
func ParseCIDRList(r io.Reader) (v4, v6 []string, err error) {
	seen4 := map[string]bool{}
	seen6 := map[string]bool{}

	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	lineNo := 0
	for sc.Scan() {
		lineNo++
		line := sc.Text()
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = line[:i]
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		// 容忍 "1.2.3.0/24  备注" 这种带尾随内容的行
		line = strings.Fields(line)[0]

		norm, isV6, perr := normalize(line)
		if perr != nil {
			return nil, nil, fmt.Errorf("第 %d 行 %q: %w", lineNo, line, perr)
		}
		if isV6 {
			if !seen6[norm] {
				seen6[norm] = true
				v6 = append(v6, norm)
			}
		} else {
			if !seen4[norm] {
				seen4[norm] = true
				v4 = append(v4, norm)
			}
		}
	}
	if err := sc.Err(); err != nil {
		return nil, nil, fmt.Errorf("读取失败: %w", err)
	}

	// 排序只是为了让编译产物稳定（否则同样的输入可能生成不同的规则集文本，
	// 让对账哈希无谓地抖动）。
	sort.Strings(v4)
	sort.Strings(v6)
	return v4, v6, nil
}

func normalize(entry string) (string, bool, error) {
	if _, ipnet, err := net.ParseCIDR(entry); err == nil {
		// 规整成网络地址，避免 10.0.0.5/8 这种写法在集合里产生歧义
		return ipnet.String(), ipnet.IP.To4() == nil, nil
	}
	ip := net.ParseIP(entry)
	if ip == nil {
		return "", false, fmt.Errorf("既不是 IP 也不是 CIDR")
	}
	if v4 := ip.To4(); v4 != nil {
		return v4.String() + "/32", false, nil
	}
	return ip.String() + "/128", true, nil
}
