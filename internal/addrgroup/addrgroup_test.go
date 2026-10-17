package addrgroup

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"fwdd/internal/model"
)

func TestParseCIDRListSplitsByFamily(t *testing.T) {
	in := `
# 国家地址列表
10.0.0.0/8
192.168.0.0/16       # 尾随注释
2001:db8::/32
203.0.113.7
  172.16.0.0/12

::1
`
	v4, v6, err := ParseCIDRList(strings.NewReader(in))
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	want4 := []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "203.0.113.7/32"}
	if strings.Join(v4, ",") != strings.Join(want4, ",") {
		t.Errorf("IPv4 列表 = %v，期望 %v", v4, want4)
	}
	if len(v6) != 2 || v6[0] != "2001:db8::/32" {
		t.Errorf("IPv6 列表不正确: %v", v6)
	}
}

// 裸 IP 要补成 /32 或 /128：公共地址列表里常常混着单 IP。
func TestBareIPsBecomeHostRoutes(t *testing.T) {
	v4, v6, err := ParseCIDRList(strings.NewReader("1.2.3.4\n2001:db8::1\n"))
	if err != nil {
		t.Fatal(err)
	}
	if len(v4) != 1 || v4[0] != "1.2.3.4/32" {
		t.Errorf("IPv4 裸地址应补成 /32: %v", v4)
	}
	if len(v6) != 1 || v6[0] != "2001:db8::1/128" {
		t.Errorf("IPv6 裸地址应补成 /128: %v", v6)
	}
}

// 一行解析不了就必须报错并指出行号，绝不静默跳过：
// 一条被悄悄忽略的 CIDR 意味着一个本该被拦住的地址能穿过去。
func TestInvalidLineIsFatalWithLineNumber(t *testing.T) {
	in := "10.0.0.0/8\n这不是地址\n192.168.0.0/16\n"
	_, _, err := ParseCIDRList(strings.NewReader(in))
	if err == nil {
		t.Fatal("非法行必须报错，静默跳过等于静默失效")
	}
	if !strings.Contains(err.Error(), "第 2 行") {
		t.Errorf("错误信息应指出行号，实际: %v", err)
	}
}

func TestDuplicatesRemoved(t *testing.T) {
	v4, _, err := ParseCIDRList(strings.NewReader("10.0.0.0/8\n10.0.0.0/8\n10.0.0.5/8\n"))
	if err != nil {
		t.Fatal(err)
	}
	// 10.0.0.5/8 会被规整成 10.0.0.0/8，与前面重复
	if len(v4) != 1 {
		t.Errorf("重复与等价写法应被合并，实际 %v", v4)
	}
}

// 输出必须稳定，否则同样的输入会生成不同的规则集文本，让对账哈希无谓抖动。
func TestOutputIsDeterministic(t *testing.T) {
	in := "192.168.0.0/16\n10.0.0.0/8\n172.16.0.0/12\n"
	a4, _, err := ParseCIDRList(strings.NewReader(in))
	if err != nil {
		t.Fatal(err)
	}
	b4, _, err := ParseCIDRList(strings.NewReader("172.16.0.0/12\n192.168.0.0/16\n10.0.0.0/8\n"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(a4, ",") != strings.Join(b4, ",") {
		t.Errorf("输入顺序不同不应影响输出顺序:\n%v\n%v", a4, b4)
	}
}

func TestLoadFromFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cn.cidr")
	content := "1.0.1.0/24\n1.0.2.0/23\n2001:db8::/32\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	tbl, err := Load([]model.AddrGroup{{Name: "cn", File: path}})
	if err != nil {
		t.Fatal(err)
	}
	s := tbl["cn"]
	if s == nil {
		t.Fatal("应加载出 cn 组")
	}
	if s.V4Count != 2 || s.V6Count != 1 || s.Total() != 3 {
		t.Errorf("计数不正确: %+v", s)
	}
	if s.Source != path {
		t.Errorf("应记录来源便于排查空组: %q", s.Source)
	}
}

func TestLoadFromInline(t *testing.T) {
	tbl, err := Load([]model.AddrGroup{{Name: "small", CIDRs: []string{"10.0.0.0/8", "203.0.113.0/24"}}})
	if err != nil {
		t.Fatal(err)
	}
	if s := tbl["small"]; s == nil || s.V4Count != 2 {
		t.Errorf("内联列表加载失败: %+v", tbl["small"])
	}
}

// 组加载失败必须让整个加载失败 —— 少了地址的封锁是静默失效。
func TestLoadFailsOnMissingFile(t *testing.T) {
	_, err := Load([]model.AddrGroup{{Name: "gone", File: filepath.Join(t.TempDir(), "nope.cidr")}})
	if err == nil {
		t.Fatal("文件不存在时应报错")
	}
	if !strings.Contains(err.Error(), "gone") {
		t.Errorf("错误信息应点明是哪个组: %v", err)
	}
}

func TestLoadFailsOnBadContent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.cidr")
	if err := os.WriteFile(path, []byte("10.0.0.0/8\n垃圾内容\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := Load([]model.AddrGroup{{Name: "bad", File: path}})
	if err == nil {
		t.Fatal("内容非法时应报错")
	}
	if !strings.Contains(err.Error(), "第 2 行") {
		t.Errorf("错误信息应保留行号: %v", err)
	}
}

func TestLoadRejectsEmptyDefinition(t *testing.T) {
	if _, err := Load([]model.AddrGroup{{Name: "empty"}}); err == nil {
		t.Fatal("既无 file 也无 cidrs 应报错，否则是个永远匹配不到东西的组")
	}
}

// 大列表要能顺利处理 —— 这是本包存在的理由。
func TestLargeList(t *testing.T) {
	var b strings.Builder
	for i := 0; i < 20000; i++ {
		fmt.Fprintf(&b, "10.%d.%d.0/24\n", i/256, i%256)
	}
	v4, _, err := ParseCIDRList(strings.NewReader(b.String()))
	if err != nil {
		t.Fatalf("大列表解析失败: %v", err)
	}
	if len(v4) != 20000 {
		t.Errorf("应解析出 20000 条，实际 %d", len(v4))
	}
}
