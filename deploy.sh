#!/usr/bin/env bash
# =============================================================================
#  huboze DDNS Agent 一键部署脚本（Go + Docker + Docker Compose）
#
#  用法（root）：
#    bash deploy.sh                 # 首次安装默认端口 8080；升级时沿用原端口
#    bash deploy.sh -p 9090         # 指定 / 修改 Web 端口
#    bash deploy.sh info            # 再次显示部署信息（地址、账号、目录）
#
#  本脚本与程序文件 huboze-ddns-agent 放在同一目录。部署完成后会显示并保存
#  初始化信息到 /root/huboze-ddns-agent-info.txt。
# =============================================================================
set -euo pipefail
umask 077   # 部署日志里含初始密码，只允许 root 读取

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN="$DIR/huboze-ddns-agent"
LOG="/root/huboze-ddns-agent-deploy-$(date +%Y%m%d-%H%M%S).log"

red()   { printf '\033[31m%s\033[0m\n' "$*"; }
green() { printf '\033[32m%s\033[0m\n' "$*"; }
blue()  { printf '\033[34m%s\033[0m\n' "$*"; }

usage() {
  sed -n '3,12p' "$0" | sed 's/^#  \{0,1\}//'
  exit "${1:-0}"
}

PORT="${WEB_PORT:-}"
ACTION="install"
while [ $# -gt 0 ]; do
  case "$1" in
    -p|--port) PORT="${2:-}"; shift 2 ;;
    --port=*)  PORT="${1#*=}"; shift ;;
    info)      ACTION="info"; shift ;;
    -h|--help) usage 0 ;;
    *) red "未知参数：$1"; usage 1 ;;
  esac
done

[ "$(id -u)" -eq 0 ] || { red "请使用 root 运行：sudo bash $0"; exit 1; }

if [ "$ACTION" = "info" ]; then
  if command -v huboze-ddns-agent >/dev/null 2>&1; then exec huboze-ddns-agent info; fi
  exec "$BIN" info
fi

[ -f "$BIN" ] || { red "未找到程序文件：$BIN（请把 deploy.sh 与 huboze-ddns-agent 放在同一目录）"; exit 1; }

if [ -n "$PORT" ]; then
  if ! [[ "$PORT" =~ ^[0-9]+$ ]] || [ "$PORT" -lt 1 ] || [ "$PORT" -gt 65535 ]; then
    red "端口无效：$PORT（应为 1-65535）"; exit 1
  fi
fi

# 校验程序文件完整性（发布包内带 SHA256SUMS 时）
if [ -f "$DIR/SHA256SUMS" ] && command -v sha256sum >/dev/null 2>&1; then
  if (cd "$DIR" && grep ' huboze-ddns-agent$' SHA256SUMS | sha256sum -c --status -); then
    green "程序文件校验通过（SHA256）"
  else
    red "程序文件 SHA256 校验失败，文件可能损坏或被篡改，已停止部署。"; exit 1
  fi
fi

chmod +x "$BIN"
blue "程序版本：$("$BIN" version)"
blue "部署日志：$LOG"
echo

set +e
if [ -n "$PORT" ]; then
  WEB_PORT="$PORT" "$BIN" install 2>&1 | tee "$LOG"
else
  "$BIN" install 2>&1 | tee "$LOG"
fi
rc=${PIPESTATUS[0]}
set -e
chmod 600 "$LOG" 2>/dev/null || true

if [ "$rc" -ne 0 ]; then
  echo
  red "部署失败（退出码 $rc）。安装器会自动回滚本次已做的改动。"
  red "请查看日志：$LOG"
  exit "$rc"
fi
