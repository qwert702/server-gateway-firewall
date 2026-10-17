#!/usr/bin/env bash
#
# fwdd 安装脚本。
#
#   sudo ./deploy/install.sh [二进制所在目录]
#
# 做的事：装二进制、建目录、铺示例配置、生成 API 令牌、装 systemd 单元。
#
# 刻意**不启动也不 enable 服务**。默认策略是 input/forward 全 drop，
# 在没确认管理面放行规则之前就启动，很可能把你自己关在门外。
# 脚本最后会打印启用前该检查什么。
set -euo pipefail

PREFIX="${PREFIX:-/usr/local}"
SBINDIR="$PREFIX/sbin"
CONFDIR="${CONFDIR:-/etc/fwdd}"
DATADIR="${DATADIR:-/var/lib/fwdd}"
UNITDIR="${UNITDIR:-/etc/systemd/system}"
SERVICE_USER="${SERVICE_USER:-root}"

BINDIR="${1:-bin}"

die() { echo "错误: $*" >&2; exit 1; }
info() { echo "  $*"; }

[ "$(id -u)" = "0" ] || die "需要 root（安装到 $SBINDIR 与 $UNITDIR）"
[ -f "$BINDIR/fwdd" ] || die "找不到 $BINDIR/fwdd。先执行 make build 或 make release，或把二进制路径作为第一个参数传进来。"
[ -f "$BINDIR/fw" ] || die "找不到 $BINDIR/fw"

echo "== 安装二进制到 $SBINDIR =="
install -d -m 0755 "$SBINDIR"
install -m 0755 "$BINDIR/fwdd" "$SBINDIR/fwdd"
install -m 0755 "$BINDIR/fw" "$SBINDIR/fw"
info "fwdd → $SBINDIR/fwdd"
info "fw   → $SBINDIR/fw"
"$SBINDIR/fwdd" -version

echo "== 创建目录 =="
# 配置目录 0700：里面有 API 令牌
install -d -m 0700 "$CONFDIR"
# 数据目录 0700：SQLite 里有完整策略与封禁记录
install -d -m 0700 "$DATADIR"
info "$CONFDIR（配置，含令牌，权限 0700）"
info "$DATADIR（数据库，权限 0700）"

echo "== 铺示例配置（已存在的不会被覆盖）=="
src_dir="$(cd "$(dirname "$0")/.." && pwd)"

if [ ! -f "$CONFDIR/config.yaml" ]; then
    if [ -f "$src_dir/configs/config.example.yaml" ]; then
        install -m 0600 "$src_dir/configs/config.example.yaml" "$CONFDIR/config.yaml"
        # 把示例里的绝对路径调整成本次安装实际使用的位置
        sed -i "s#^data_dir:.*#data_dir: $DATADIR#; s#^policy_file:.*#policy_file: $CONFDIR/policy.yaml#; s#^socket:.*#socket: /run/fwdd.sock#" "$CONFDIR/config.yaml"
        info "已生成 $CONFDIR/config.yaml"
    else
        die "找不到 configs/config.example.yaml，请从源码目录运行本脚本"
    fi
else
    info "$CONFDIR/config.yaml 已存在，保留不动"
fi

if [ ! -f "$CONFDIR/policy.yaml" ]; then
    if [ -f "$src_dir/configs/policy.example.yaml" ]; then
        install -m 0600 "$src_dir/configs/policy.example.yaml" "$CONFDIR/policy.yaml"
        info "已生成 $CONFDIR/policy.yaml（示例策略，**必须按你的网络改**）"
    fi
else
    info "$CONFDIR/policy.yaml 已存在，保留不动"
fi

echo "== 生成 API 令牌 =="
TOKEN_FILE="$CONFDIR/token"
if [ ! -f "$TOKEN_FILE" ]; then
    # 用 /dev/urandom 而不是 $RANDOM：后者在脚本里可预测。
    head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n' > "$TOKEN_FILE"
    chmod 0600 "$TOKEN_FILE"
    info "已生成 $TOKEN_FILE（权限 0600）"
else
    info "$TOKEN_FILE 已存在，保留不动"
fi

# 把令牌写进配置。
#
# 要处理"配置里根本没有 token 行"的情况 —— 手写的配置常常就没有这一行，
# 而 token 为空等于**关闭认证**（只监听回环，但服务器上任何能访问 localhost
# 的程序都能完全控制防火墙）。真机上正是这么漏过一次。
if grep -q '^token:' "$CONFDIR/config.yaml"; then
    sed -i "s#^token:.*#token: \"$(cat "$TOKEN_FILE")\"#" "$CONFDIR/config.yaml"
else
    printf '\ntoken: "%s"\n' "$(cat "$TOKEN_FILE")" >> "$CONFDIR/config.yaml"
fi
info "已把令牌写入 config.yaml"

# 写完立刻自检：配置里确实有非空的 token，否则起点就错了。
if ! grep -qE '^token:\s*"[^"]+"' "$CONFDIR/config.yaml"; then
    die "config.yaml 里的 token 为空 —— API 将不校验认证，请手工检查"
fi

echo "== 安装 systemd 单元 =="
if [ -f "$src_dir/deploy/fwdd.service" ]; then
    install -m 0644 "$src_dir/deploy/fwdd.service" "$UNITDIR/fwdd.service"
    # 让单元里的路径与本次安装一致
    sed -i "s#^ExecStart=.*#ExecStart=$SBINDIR/fwdd -config $CONFDIR/config.yaml#" "$UNITDIR/fwdd.service"
    if command -v systemctl >/dev/null 2>&1; then
        systemctl daemon-reload
        info "已安装 $UNITDIR/fwdd.service 并重载 systemd"
    else
        info "已安装 $UNITDIR/fwdd.service（本机没有 systemctl，未重载）"
    fi
else
    info "未找到 deploy/fwdd.service，跳过"
fi

cat <<EOF

== 安装完成，但服务尚未启动 ==

默认策略是 input / forward 全部 drop。在确认下面这条之前就启动，很可能把
你自己关在门外：

  1. 编辑 $CONFDIR/policy.yaml，确认里面有你自己的管理入口放行规则。
     示例里有一条 "ssh-from-lan"（仅允许 lan 域 SSH 管理本机），
     请把它的 src_zone 改成你实际的管理网段，或另加一条。

  2. 先看一遍将要写入内核的规则，不碰内核：

       $SBINDIR/fwdd -config $CONFDIR/config.yaml -dry-run | less

  3. 确认无误后再启动：

       systemctl enable --now fwdd
       $SBINDIR/fw status

  强烈建议在远程机器上把 commit-confirm 打开（config.yaml 里的
  commit_confirm.enabled: true）—— 改错规则时它会自动回滚。
  但在那之前请确保你有一个带外的方式能接触到这台机器。

另外两件建议做的事：

  # 打开转发开关（否则网关策略完全不生效）
  $SBINDIR/fw net sysctl apply --dry-run
  $SBINDIR/fw net sysctl apply

  # 部署前用真实 nft 校验一遍生成的规则集语法
  sudo make verify-nft        # 在源码目录执行

EOF
