// Package version 集中存放版本信息。
//
// 通过 -ldflags 在构建时注入：
//
//	go build -ldflags "-X fwdd/internal/version.Version=1.2.3 \
//	                   -X fwdd/internal/version.Commit=$(git rev-parse --short HEAD) \
//	                   -X fwdd/internal/version.Date=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
//
// 不注入时退回开发态默认值。所有需要版本号的地方都从这里取 ——
// 之前 fw 与指标各自写死了一个常量，结果两边对不上。
package version

import (
	"fmt"
	"runtime"
	"strings"
)

var (
	// Version 是语义化版本号。
	Version = "dev"
	// Commit 是构建时的 git 提交短哈希。
	Commit = "unknown"
	// Date 是构建时间（RFC3339）。
	Date = "unknown"
)

// Info 是版本信息的结构化形式，供 API 返回。
type Info struct {
	Version string `json:"version"`
	Commit  string `json:"commit"`
	Date    string `json:"date"`
	Go      string `json:"go"`
	OS      string `json:"os"`
	Arch    string `json:"arch"`
}

// Get 返回当前构建的版本信息。
func Get() Info {
	return Info{
		Version: Version,
		Commit:  Commit,
		Date:    Date,
		Go:      runtime.Version(),
		OS:      runtime.GOOS,
		Arch:    runtime.GOARCH,
	}
}

// Short 返回单行版本串，用于 `--version` 与日志。
func Short() string {
	var b strings.Builder
	b.WriteString(Version)
	if Commit != "unknown" && Commit != "" {
		b.WriteString(" (" + Commit + ")")
	}
	if Date != "unknown" && Date != "" {
		b.WriteString(" 构建于 " + Date)
	}
	return b.String()
}

// Full 返回多行版本信息，用于 `fw version -v` 一类的详细输出。
func Full() string {
	i := Get()
	return fmt.Sprintf("fwdd %s\n提交:   %s\n构建:   %s\nGo:     %s\n平台:   %s/%s",
		i.Version, i.Commit, i.Date, i.Go, i.OS, i.Arch)
}
