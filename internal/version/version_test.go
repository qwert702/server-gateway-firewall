package version

import (
	"runtime"
	"strings"
	"testing"
)

func TestGetReflectsBuildInfo(t *testing.T) {
	i := Get()
	if i.Go != runtime.Version() {
		t.Errorf("Go 版本应取自 runtime: %q", i.Go)
	}
	if i.OS != runtime.GOOS || i.Arch != runtime.GOARCH {
		t.Errorf("平台信息不正确: %s/%s", i.OS, i.Arch)
	}
	// 未注入时是 dev，注入时是语义化版本 —— 两者都不该为空
	if i.Version == "" {
		t.Error("版本号不应为空")
	}
}

func TestShortOmitsUnknownFields(t *testing.T) {
	// 改回默认值再验证，避免依赖构建时的注入
	oldV, oldC, oldD := Version, Commit, Date
	defer func() { Version, Commit, Date = oldV, oldC, oldD }()

	Version, Commit, Date = "1.2.3", "unknown", "unknown"
	if got := Short(); got != "1.2.3" {
		t.Errorf("未知的提交与日期不应出现在输出里: %q", got)
	}

	Version, Commit, Date = "1.2.3", "abc1234", "2026-10-17T00:00:00Z"
	got := Short()
	if !strings.Contains(got, "1.2.3") || !strings.Contains(got, "abc1234") {
		t.Errorf("应包含版本与提交: %q", got)
	}
}

func TestFullIsMultiLine(t *testing.T) {
	lines := strings.Split(Full(), "\n")
	if len(lines) < 4 {
		t.Errorf("详细版本应有多行: %q", Full())
	}
	if !strings.Contains(Full(), runtime.Version()) {
		t.Error("应包含 Go 版本")
	}
}
