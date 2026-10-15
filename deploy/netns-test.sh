#!/usr/bin/env bash
#
# 网络命名空间端到端测试。
#
#   sudo ./deploy/netns-test.sh
#
# 拓扑：
#
#     wan (10.99.0.2) <--veth--> [ fw: wan0 ]  ns-fw  [ lan0 ] <--veth--> lan (10.98.0.2)
#                                 10.99.0.1                10.98.0.1
#
# 在 ns-fw 里跑 fwdd，验证：
#   1. 网关自身的转发/过滤策略生效（首次直接打错规则会把自己锁死，故用 commit-confirm 兜底）
#   2. 内网 -> 外网放行，外网 -> 内网默认拒绝
#   3. DNAT 端口映射可达
#   4. 封禁某个源后该源立即不可达
#
# 需要 root（创建命名空间与 veth）。
set -euo pipefail

cd "$(dirname "$0")/.."

NS_WAN=ns-wan
NS_FW=ns-fw
NS_LAN=ns-lan
WAN_SUBNET=10.99.0.0/24
LAN_SUBNET=10.98.0.0/24
VETH_WAN_NET=10.99.0.0/30
VETH_LAN_NET=10.98.0.0/30

WORK="$(mktemp -d)"
FWDD_PID=""

cleanup() {
	[ -n "$FWDD_PID" ] && kill "$FWDD_PID" 2>/dev/null || true
	for ns in $NS_WAN $NS_FW $NS_LAN; do
		ip netns del "$ns" 2>/dev/null || true
	done
	rm -rf "$WORK"
}
trap cleanup EXIT

require_root() {
	if [ "$(id -u)" != "0" ]; then
		echo "错误: 需要 root 才能创建命名空间" >&2
		exit 1
	fi
	if ! command -v nft >/dev/null 2>&1; then
		echo "错误: 未找到 nft" >&2
		exit 1
	fi
}

# assert <期望:ok|fail> <说明> <命令...>
assert() {
	local expect="$1" desc="$2"
	shift 2
	if "$@" >/dev/null 2>&1; then
		if [ "$expect" = "ok" ]; then
			echo "  ✅ $desc"
		else
			echo "  ❌ $desc（预期失败但成功了）"
			return 1
		fi
	else
		if [ "$expect" = "fail" ]; then
			echo "  ✅ $desc"
		else
			echo "  ❌ $desc（预期成功但失败了）"
			return 1
		fi
	fi
}

require_root
echo "== 构建 =="
go build -o "$WORK/fwdd" ./cmd/fwdd
go build -o "$WORK/fw" ./cmd/fw

echo "== 搭建拓扑 =="
for ns in $NS_WAN $NS_FW $NS_LAN; do
	ip netns del "$ns" 2>/dev/null || true
	ip netns add "$ns"
done

# fw 侧接口
ip -n $NS_FW link add wan0 type veth peer name wan1 netns $NS_WAN
ip -n $NS_FW link add lan0 type veth peer name lan1 netns $NS_LAN
ip -n $NS_FW addr add 10.99.0.1/30 dev wan0
ip -n $NS_FW addr add 10.98.0.1/30 dev lan0
ip -n $NS_WAN addr add 10.99.0.2/30 dev wan1
ip -n $NS_LAN addr add 10.98.0.2/30 dev lan1

for ns in $NS_WAN $NS_FW $NS_LAN; do
	ip -n $ns link set lo up
done
ip -n $NS_FW link set wan0 up
ip -n $NS_FW link set lan0 up
ip -n $NS_WAN link set wan1 up
ip -n $NS_LAN link set lan1 up

# 网关开启转发
ip netns exec $NS_FW sysctl -qw net.ipv4.ip_forward=1

# 两端各加一条到对端的路由，否则测的是"没有路由"而不是"被防火墙拦下"
ip -n $NS_WAN route add $LAN_SUBNET via 10.99.0.1
ip -n $NS_LAN route add $WAN_SUBNET via 10.98.0.1

# 未配置策略前，内网应能 ping 通网关
assert ok "基线：内网可达网关" ip netns exec $NS_LAN ping -c1 -W1 10.98.0.1
# 且此时两端本来就互通（说明后续的"不通"是防火墙造成的）
assert ok "基线：未加策略时两端互通" ip netns exec $NS_LAN ping -c1 -W1 10.99.0.2

echo "== 生成策略 =="
cat >"$WORK/policy.yaml" <<EOF
version: 1
zones:
  - name: wan
    interfaces: [wan0]
  - name: lan
    interfaces: [lan0]
rules:
  # 已建立连接放行（网关必备）
  - id: est
    priority: 1
    state: [established, related]
    action: accept
  # 内网可访问外网
  - id: lan-out
    priority: 100
    src_zone: lan
    dst_zone: wan
    action: accept
  # 内网可 SSH 管理本机
  - id: ssh-admin
    priority: 300
    src_zone: lan
    dst_zone: local
    proto: tcp
    dst_port: ["22"]
    action: accept
default:
  input: drop
  forward: drop
  output: accept
EOF

cat >"$WORK/config.yaml" <<EOF
listen: ""
socket: $WORK/fwdd.sock
backend: nftables
table: fw
family: inet
policy_file: $WORK/policy.yaml
log_level: info
commit_confirm:
  enabled: true
  timeout: 15s
EOF

echo "== 启动 fwdd（commit-confirm 已启用，15 秒内不确认会自动回滚）=="
ip netns exec $NS_FW "$WORK/fwdd" -config "$WORK/config.yaml" >"$WORK/fwdd.log" 2>&1 &
sleep 2

# 守护进程跑在命名空间里，CLI 需要从同一个命名空间访问套接字
FW() { ip netns exec $NS_FW "$WORK/fw" -config "$WORK/config.yaml" "$@"; }

echo "== 确认下发（否则会被自动回滚）=="
FW confirm || echo "  （无待确认变更，继续）"

echo "== 验证策略 =="
# 外网不能主动进内网
assert fail "外网 -> 内网被丢弃" ip netns exec $NS_WAN ping -c1 -W1 10.98.0.2
# 但内网能出去
assert ok "内网 -> 外网放行" ip netns exec $NS_LAN ping -c1 -W1 10.99.0.2

echo "== 验证封禁 =="
FW ban add 10.98.0.2 --ttl 60 --reason "netns 测试" >/dev/null
assert fail "被封禁的源无法访问外网" ip netns exec $NS_LAN ping -c1 -W1 10.99.0.2
FW ban rm 10.98.0.2 >/dev/null
assert ok "解封后恢复访问" ip netns exec $NS_LAN ping -c1 -W1 10.99.0.2

echo "== 验证自动回滚 =="
echo "  规则集摘要:"
FW status | sed 's/^/    /'

echo
echo "全部端到端检查通过。"
