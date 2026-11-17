#!/usr/bin/env bash
# Build the static binary and the release package:
#   dist/huboze-ddns-agent-v<VERSION>.tar.gz  (deploy.sh + binary + SHA256SUMS + README + 部署说明)
# Usage: scripts/package.sh            (version is read from main.go)
set -euo pipefail
cd "$(dirname "$0")/.."

VERSION="$(sed -n 's/^const Version = "\(.*\)"/\1/p' main.go)"
[ -n "$VERSION" ] || { echo "cannot read Version from main.go" >&2; exit 1; }
NAME="huboze-ddns-agent-v$VERSION"
OUT="dist/$NAME"

rm -rf "$OUT" "dist/$NAME.tar.gz"
mkdir -p "$OUT"
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o "$OUT/huboze-ddns-agent" .
cp deploy.sh README.md "$OUT/"
chmod +x "$OUT/huboze-ddns-agent" "$OUT/deploy.sh"

cat > "$OUT/部署说明.txt" <<TXT
huboze 线路解析管家 v$VERSION 部署包

文件：
  deploy.sh            一键部署脚本
  huboze-ddns-agent    程序（静态编译，Linux x86_64）
  SHA256SUMS           校验文件（deploy.sh 会自动校验）
  README.md            完整说明

部署（Debian 13，root）：
  tar xzf $NAME.tar.gz
  cd $NAME
  bash deploy.sh               # 首次默认端口 8080，升级沿用原端口
  bash deploy.sh -p 9090       # 指定端口

部署完成后会显示：Web 访问地址（公网/内网/本机）、健康检查地址、
admin 账号与初始密码、部署目录、常用命令和下一步操作，
并保存到 /root/huboze-ddns-agent-info.txt（仅 root 可读）。
之后可随时执行：huboze-ddns-agent info

已部署旧版本（包括 v2.2.3 Python 版）时直接运行 deploy.sh 即可原地升级，
数据库、密钥、MSR/DNS 凭据、管理员密码和端口都会保留。
使用说明见 Web 界面左侧菜单“帮助”。
TXT

(cd "$OUT" && sha256sum huboze-ddns-agent deploy.sh > SHA256SUMS)
tar -C dist -czf "dist/$NAME.tar.gz" "$NAME"
(cd dist && sha256sum "$NAME.tar.gz" > "$NAME.tar.gz.sha256")
echo "VERSION=$VERSION"
echo "PACKAGE=dist/$NAME.tar.gz"
