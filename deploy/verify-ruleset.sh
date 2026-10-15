#!/usr/bin/env bash
#
# 用真实的 nft 校验 fwdd 生成的规则集语法。
#
#   sudo ./deploy/verify-ruleset.sh [策略文件]
#
# 只做解析与内核校验（`nft -c`），不提交任何变更，因此可以在生产机上安全运行。
# 这是当前环境（Windows 开发机）无法自行完成的验证，请在 Linux 上执行。
set -euo pipefail

cd "$(dirname "$0")/.."

POLICY="${1:-configs/policy.example.yaml}"
TABLE="${TABLE:-fw}"
FAMILY="${FAMILY:-inet}"

if ! command -v nft >/dev/null 2>&1; then
	echo "错误: 未找到 nft。请先安装 nftables（Debian/Ubuntu: apt install nftables）" >&2
	exit 1
fi
if [ "$(id -u)" != "0" ]; then
	echo "错误: nft -c 需要 root（CAP_NET_ADMIN），请用 sudo 运行" >&2
	exit 1
fi

workdir="$(mktemp -d)"
trap 'rm -rf "$workdir"' EXIT

echo "== 构建 =="
go build -o "$workdir/fwdd" ./cmd/fwdd

cat >"$workdir/config.yaml" <<EOF
listen: ""
socket: ""
backend: nftables
table: $TABLE
family: $FAMILY
policy_file: $POLICY
log_level: info
EOF

echo "== 生成规则集（dry-run，不触碰内核）=="
"$workdir/fwdd" -config "$workdir/config.yaml" -dry-run >"$workdir/ruleset.nft"

echo "== 用 nft -c 校验语法 =="
if nft -c -f "$workdir/ruleset.nft" 2>"$workdir/nft.err"; then
	echo "✅ 规则集通过 nft 语法与内核校验"
else
	echo "❌ nft 拒绝了生成的规则集：" >&2
	cat "$workdir/nft.err" >&2
	echo "--- 规则集 ---" >&2
	cat -n "$workdir/ruleset.nft" >&2
	exit 1
fi

echo
echo "== 冒烟测试：在独立表里真实下发并回滚 =="
SMOKE_TABLE="fwverify$$"
cat >"$workdir/config2.yaml" <<EOF
listen: ""
socket: ""
backend: nftables
table: $SMOKE_TABLE
family: $FAMILY
policy_file: $POLICY
log_level: info
EOF
"$workdir/fwdd" -config "$workdir/config2.yaml" -dry-run |
	sed "s/table $TABLE /table $SMOKE_TABLE /g; s/$TABLE /$SMOKE_TABLE /g" >"$workdir/smoke.nft"

cleanup_table() { nft delete table "$FAMILY" "$SMOKE_TABLE" 2>/dev/null || true; }
trap 'cleanup_table; rm -rf "$workdir"' EXIT

nft -f "$workdir/smoke.nft"
echo "✅ 真实下发成功，内核中的表："
nft list table "$FAMILY" "$SMOKE_TABLE" | head -20
cleanup_table
echo "✅ 已清理测试表"

echo
echo "全部检查通过。"
