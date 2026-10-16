package netcfg

import (
	"context"
	"runtime"
	"strings"
	"testing"
)

func TestNormalizeKeyAcceptsBothSpellings(t *testing.T) {
	cases := map[string]string{
		"net.ipv4.ip_forward":           "net.ipv4.ip_forward",
		"net/ipv4/ip_forward":           "net.ipv4.ip_forward",
		"/proc/sys/net/ipv4/ip_forward": "net.ipv4.ip_forward",
		"  net.ipv4.ip_forward  ":       "net.ipv4.ip_forward",
		"net.ipv4.conf.all.rp_filter":   "net.ipv4.conf.all.rp_filter",
	}
	for in, want := range cases {
		if got := NormalizeKey(in); got != want {
			t.Errorf("NormalizeKey(%q) = %q, 期望 %q", in, got, want)
		}
	}
}

// 同一个参数的两种写法必须归并成一项，否则会被当成两个参数重复处理。
func TestNormalizeDeduplicates(t *testing.T) {
	out, err := Normalize([]Sysctl{
		{Key: "net/ipv4/ip_forward", Value: "1"},
		{Key: "net.ipv4.ip_forward", Value: "0"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 1 {
		t.Fatalf("两种写法应归并为一项，实际 %d 项: %+v", len(out), out)
	}
	if out[0].Value != "0" {
		t.Errorf("后者应覆盖前者，实际 %q", out[0].Value)
	}
}

func TestNormalizeRejectsBadInput(t *testing.T) {
	bad := []Sysctl{
		{Key: "", Value: "1"},
		{Key: "net.ipv4.ip_forward", Value: ""},
		{Key: "net.ipv4.ip_forward", Value: "yes"},          // 内核只接受整数
		{Key: "net..forward", Value: "1"},                   // 空段
		{Key: "net.ipv4.tcp_rmem", Value: "4096 abc 65536"}, // 列表里混入非整数
	}
	for _, s := range bad {
		if _, err := Normalize([]Sysctl{s}); err == nil {
			t.Errorf("应拒绝: %+v", s)
		}
	}
}

// 多值参数（如 tcp_rmem）是合法的。
func TestNormalizeAcceptsMultiValue(t *testing.T) {
	if _, err := Normalize([]Sysctl{{Key: "net.ipv4.tcp_rmem", Value: "4096 87380 6291456"}}); err != nil {
		t.Errorf("多值参数应被接受: %v", err)
	}
}

func TestNormalizeIsSorted(t *testing.T) {
	out, err := Normalize([]Sysctl{
		{Key: "net.ipv4.tcp_syncookies", Value: "1"},
		{Key: "net.ipv4.ip_forward", Value: "1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if out[0].Key != "net.ipv4.ip_forward" {
		t.Errorf("结果应按键排序: %+v", out)
	}
}

func TestDiffSysctls(t *testing.T) {
	desired := []Sysctl{
		{Key: "net.ipv4.ip_forward", Value: "1"},
		{Key: "net.ipv4.tcp_syncookies", Value: "1"},
		{Key: "net.ipv4.conf.all.rp_filter", Value: "0"},
	}
	current := map[string]string{
		"net.ipv4.ip_forward":         "0", // 需要改
		"net.ipv4.tcp_syncookies":     "1", // 已一致
		"net.ipv4.conf.all.rp_filter": "0", // 已一致
	}
	changes := DiffSysctls(desired, current)
	if len(changes) != 1 {
		t.Fatalf("应只有 1 项需要变更，实际 %d: %+v", len(changes), changes)
	}
	c := changes[0]
	if c.Kind != "sysctl" || c.Action != "set" || c.Target != "net.ipv4.ip_forward" {
		t.Errorf("变更描述不正确: %+v", c)
	}
	if c.From != "0" || c.To != "1" {
		t.Errorf("变更应记录前后值: %+v", c)
	}
}

// 参数当前读不到（例如模块未加载）时应视为需要设置，而不是跳过。
func TestDiffSysctlsTreatsMissingAsChange(t *testing.T) {
	changes := DiffSysctls([]Sysctl{{Key: "net.netfilter.nf_conntrack_max", Value: "262144"}}, map[string]string{})
	if len(changes) != 1 {
		t.Fatalf("缺失的参数应纳入变更，实际 %d 项", len(changes))
	}
	if changes[0].From != "" {
		t.Errorf("缺失时 From 应为空: %+v", changes[0])
	}
}

func TestGatewayBaselineCoversForwarding(t *testing.T) {
	base := GatewayBaseline()
	byKey := map[string]string{}
	for _, s := range base {
		byKey[s.Key] = s.Value
	}
	// 没有这一项，网关型防火墙的策略根本不会被触发。
	if byKey[KeyIPv4Forward] != "1" {
		t.Errorf("基线必须包含 IPv4 转发开关: %+v", base)
	}
	if byKey[KeySyncookies] != "1" {
		t.Errorf("基线应包含 SYN cookies: %+v", base)
	}
}

func TestChangeString(t *testing.T) {
	if got := (Change{Kind: "sysctl", Action: "set", Target: "net.ipv4.ip_forward", From: "0", To: "1"}).String(); !strings.Contains(got, "0 -> 1") {
		t.Errorf("变更描述应含前后值: %q", got)
	}
	if got := (Change{Kind: "route", Action: "add", Target: "default", To: "via 10.0.0.1"}).String(); !strings.Contains(got, "route add default") {
		t.Errorf("无 From 时不应输出空箭头: %q", got)
	}
}

func TestCurrentProviderReportsPlatform(t *testing.T) {
	p := New()
	if p.Platform() != runtime.GOOS {
		t.Errorf("Platform = %q, 期望 %q", p.Platform(), runtime.GOOS)
	}
	if p.Supported() != (runtime.GOOS == "linux") {
		t.Errorf("Supported 与实际平台不符: %v", p.Supported())
	}
}

// 非 Linux 平台上写入必须报错，绝不能静默成功 —— 静默成功会让用户
// 以为转发已经打开。
func TestNonLinuxWritesFailLoudly(t *testing.T) {
	if runtime.GOOS == "linux" {
		t.Skip("仅在非 Linux 平台有意义")
	}
	p := New()
	if _, err := p.SetSysctls(context.Background(), GatewayBaseline()); err == nil {
		t.Fatal("非 Linux 平台写入 sysctl 必须返回错误")
	}
}

// 读取在非 Linux 上也应当能返回基本信息而不是报错，方便 `fw net` 展示。
func TestReadWorksOnAnyPlatform(t *testing.T) {
	st, err := New().Read(context.Background())
	if err != nil {
		t.Fatalf("Read 不应报错: %v", err)
	}
	if st == nil {
		t.Fatal("Read 应返回状态")
	}
	if st.Platform == "" {
		t.Error("应填充平台标识")
	}
	if len(st.Links) == 0 {
		t.Error("至少应能读到回环接口")
	}
}
