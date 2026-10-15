package nftables

import (
	"context"
	"os/exec"
	"strings"
	"testing"
	"time"

	"fwdd/internal/ir"
)

// TestGeneratedRulesetIsValidNft 用真实的 `nft -c` 校验渲染结果。
//
// `nft -c -f -` 只做解析与内核校验，不提交任何变更，因此在开发机上也能安全运行；
// 但它需要 CAP_NET_ADMIN，且必须在 Linux 上。条件不满足时自动跳过，
// 这样 `go test ./...` 在 Windows / 无 root 环境下仍然可用。
//
// 在 Linux 上手动运行：
//
//	sudo go test ./internal/backend/nftables -run TestGeneratedRulesetIsValidNft -v
func TestGeneratedRulesetIsValidNft(t *testing.T) {
	if _, err := exec.LookPath("nft"); err != nil {
		t.Skip("跳过：未找到 nft 可执行文件")
	}
	if !isRoot() {
		t.Skip("跳过：nft -c 需要 root（CAP_NET_ADMIN）")
	}

	cases := []struct {
		name string
		snap *ir.Snapshot
	}{
		{"示例策略", goldenSnapshot(t)},
		{"封禁与限速", banAndLimitSnapshot(t)},
		{"IPv6", v6Snapshot(t)},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			text := tc.snap.Render()

			// -c 校验模式：解析 + 内核校验，不提交。
			cmd := exec.Command("nft", "-c", "-f", "-")
			cmd.Stdin = strings.NewReader(text)
			out, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("nft 拒绝了生成的规则集: %v\n--- nft 输出 ---\n%s\n--- 规则集 ---\n%s",
					err, out, text)
			}
		})
	}
}

// TestSetElementsAreValidNft 校验动态注入的集合元素语法。
func TestSetElementsAreValidNft(t *testing.T) {
	if _, err := exec.LookPath("nft"); err != nil {
		t.Skip("跳过：未找到 nft 可执行文件")
	}
	if !isRoot() {
		t.Skip("跳过：需要 root")
	}
	b := New()
	ctx := context.Background()

	if err := b.Apply(ctx, goldenSnapshot(t)); err != nil {
		t.Fatalf("下发失败: %v", err)
	}
	t.Cleanup(func() { _ = b.Apply(ctx, &ir.Snapshot{Tables: []*ir.Table{{Family: "inet", Name: "fw"}}}) })

	if err := b.SetAdd(ctx, "banned4", ir.Element{Key: "203.0.113.9", Timeout: time.Hour}); err != nil {
		t.Fatalf("添加封禁元素失败: %v", err)
	}
	elems, err := b.SetList(ctx, "banned4")
	if err != nil {
		t.Fatalf("读取封禁集合失败: %v", err)
	}
	if len(elems) != 1 || elems[0].Key != "203.0.113.9" {
		t.Fatalf("封禁集合内容不符: %+v", elems)
	}
	if err := b.SetDel(ctx, "banned4", "203.0.113.9"); err != nil {
		t.Fatalf("解封失败: %v", err)
	}
}

func isRoot() bool {
	out, err := exec.Command("id", "-u").Output()
	if err != nil {
		return false
	}
	return strings.TrimSpace(string(out)) == "0"
}
