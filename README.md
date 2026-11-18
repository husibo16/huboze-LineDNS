# huboze 线路解析管家（LineDNS）

[![版本](https://img.shields.io/github/v/release/husibo16/huboze-LineDNS?label=%E7%89%88%E6%9C%AC)](https://github.com/husibo16/huboze-LineDNS/releases/latest)
[![许可证](https://img.shields.io/github/license/husibo16/huboze-LineDNS?label=%E8%AE%B8%E5%8F%AF%E8%AF%81)](LICENSE)
[![CI](https://github.com/husibo16/huboze-LineDNS/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/husibo16/huboze-LineDNS/actions/workflows/ci.yml)

Go + Docker + Docker Compose

H3C MSR 多线路动态解析：通过 SSH 读取路由器各拨号线路的公网 IP，自动同步到多个 DNS 服务商（Cloudflare / 腾讯云 DNSPod / 阿里云 / 华为云），并确认解析生效。

> 程序、容器、目录等技术标识仍为 `huboze-ddns-agent`，便于已部署实例原地升级。

**唯一正式部署方式：Go 静态二进制 + Docker + Docker Compose。**

同一个二进制既是安装/管理命令（宿主机），也是容器内的服务（`serve`）。

## 编译

```bash
CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o huboze-ddns-agent .
go test ./...      # 含模拟 H3C SSH 服务器、模拟 Cloudflare API 的测试；LIVE=1 额外测试公网 DNS
```

## 安装 / 升级（Debian 13，root）

### 一键部署（推荐）

发布包 `huboze-ddns-agent-vX.Y.Z.tar.gz` 内含 `deploy.sh`、程序文件和 `SHA256SUMS`：

```bash
tar xzf huboze-ddns-agent-vX.Y.Z.tar.gz && cd huboze-ddns-agent-vX.Y.Z
bash deploy.sh               # 首次默认端口 9090；升级沿用原端口
bash deploy.sh -p 8080       # 指定 / 修改端口
```

`deploy.sh` 会校验程序 SHA256、执行安装并记录日志（`/root/huboze-ddns-agent-deploy-*.log`，权限 600）。
部署完成后显示**部署信息**：所有可用的 Web 访问地址（公网 / 内网 / 本机 IPv4、IPv6）、健康检查地址、
admin 账号与初始密码、部署目录与密钥位置、常用命令、下一步操作和安全提醒，
并保存到 `/root/huboze-ddns-agent-info.txt`（仅 root 可读）。之后随时执行 `huboze-ddns-agent info` 再次查看。

### 直接使用程序

把编译好的 `huboze-ddns-agent` 拷到服务器上（单文件，约 14MB，可离线拷贝）：

```bash
./huboze-ddns-agent install                 # 首次默认端口 9090；升级时沿用原端口
WEB_PORT=8080 ./huboze-ddns-agent install   # 指定/修改端口
```

安装器会自动完成：

| 阶段 | 内容 |
|---|---|
| 检测 | root、Debian 版本、systemd、端口合法性与占用、磁盘空间、DNS 解析 / TCP / 出站 UDP 53、系统时间偏差（云 API 签名依赖）、Docker ≥ 20.10、Compose v2+、ICMP 权限（ping_group_range）、防火墙（ufw / firewalld）放行提示 |
| 依赖 | 只从 Debian 官方源安装 `docker.io` 与 Compose（Docker CE 环境装 `docker-compose-plugin`，否则装 `docker-compose`）；非交互模式，自动等待 apt 锁；**不使用 get.docker.com** |
| 镜像 | `docker import` 生成 scratch 镜像（约 20MB），**不拉取任何基础镜像、不访问 Docker Hub / PyPI** |
| 迁移 | 自动识别旧 Python/Flask Docker 版、systemd 版 Go，原地迁移：数据库、密钥、MSR/DNS 凭据、admin 密码、known_hosts 全部保留 |
| 回滚 | 失败自动恢复目录、镜像标签与旧服务；回滚备份只保留最近 3 份 |
| 验证 | /health、容器状态、容器内运行环境自检 |

## 运行时安全设置（docker-compose.yml）

- `network_mode: host`：AAAA 的 IPv6 可达性检测可用；Web 白名单能拿到真实客户端 IP
- 以 `10001:10001` 运行、根文件系统只读、`cap_drop: ALL`、`no-new-privileges`
- ICMP 使用非特权 datagram socket，不需要 `NET_RAW`
- 日志轮转：`json-file`，10MB × 3
- 初始密码通过 stdin 写入，不出现在进程参数、环境变量和 `docker inspect` 中

## 管理命令

```
huboze-ddns-agent info                           # 部署信息：访问地址、账号、目录、常用命令
huboze-ddns-agent status | logs | start | stop | restart
huboze-ddns-agent selfcheck                      # 运行环境自检（Web：设置 → 运行环境自检）
huboze-ddns-agent backup
huboze-ddns-agent restore /path/huboze-ddns-migration-xxx.tar.gz   # 兼容旧版 Web 迁移包
huboze-ddns-agent reset-password [新密码]
huboze-ddns-agent reset-whitelist                # 白名单配错被锁在外面时使用
```

## 可靠性设计

- 轮询遇到 SSH 认证失败 / 账号锁定 / 要求首次改密时，**自动禁用设备**，不再每分钟重试导致 H3C 账号被反复锁定
- 每台 MSR 同一时间只建一个 SSH 会话（轮询、测试、刷新接口、保存映射之间排队）
- 拒绝把私网 / 运营商 NAT（100.64.0.0/10）地址写入 A 记录
- 接口协议状态非 up 时跳过同步，不把域名指向已断开的线路
- 检测到 DNS 记录被外部修改时自动纠正
- 禁止同一条 DNS 记录被两个映射同时管理
- 接口状态类错误只在状态变化时记日志，不再每分钟刷屏
- Web：慢操作防重复提交；映射页优先使用缓存的接口列表（不必每次登录 MSR）；新增“运行环境自检”页

## Web 界面

- 统一视觉：带图标的侧栏、状态色标、深色 / 浅色主题（默认跟随系统，可切换并记住）；手机端自适应，表格自动变为卡片
- **仪表盘**：
  - 顶部总状态：一句话说明“一切正常 / N 个问题需要处理”，附上次检查时间与结果，“立即检查”按钮
  - 4 个指标：MSR 在线、拨号线路连通、域名正常、DNS 服务商可用（带比例条，可点击跳转）
  - “需要处理”清单：设备无法连接、账号被自动停用、同步失败、解析异常、线路不可达、调度超时，每项附原因和处理入口
  - 域名列表（问题排在前面）与按 MSR 分组的拨号线路，线路上标出绑定的域名
  - 最近事件；首次使用显示“快速开始”四步引导
- **设备 / 服务商 / 映射**：列表在前，“添加”按钮展开表单；保存失败会回到表单；状态每 5 秒自动刷新
  - 设备以卡片展示每条 Dialer 的 IPv4 / IPv6 与连通状态
  - 服务商类型用卡片选择；已保存凭据标注“已保存”（ID 类显示末 4 位）
  - 映射表单按“IP 来源 → DNS 记录 → 其他”分步；状态列合并同步结果与域名检测，可展开各公共 DNS 的解析结果
- **DNS 解析**（菜单位于“DNS 映射”与“日志”之间，只读）：每个域名的期望 IP、DNS 服务商上的记录值、各公共 DNS（AliDNS / DNSPod / Cloudflare / Google）实际返回的 IP 与 TTL、是否已生效 / 旧值缓存中 / 查询失败、线路可达性；异常记录排在前面，可单独“立即检测”。映射的配置仍在“DNS 映射”页
- **帮助**（菜单最后一项）：解决什么问题、工作原理（登录路由器 → 读取公网 IP → 更新解析 → 确认生效）、推荐用法（每条线路一个域名）、快速上手、状态说明、常见问题、安全说明、服务器命令
- 日志页按级别 / 事件 / 关键字筛选、分页；长错误折叠；时间显示为“3 分钟前”；危险操作收进“更多”菜单

`HUBOZE_INSTALL_BIN` 环境变量仅用于测试（覆盖管理命令的安装位置 `/usr/local/bin/huboze-ddns-agent`）。

## 开发与发布

```bash
go vet ./... && go test ./...
scripts/package.sh        # 生成 dist/huboze-ddns-agent-v<版本>.tar.gz（含 deploy.sh、程序、SHA256SUMS）
```

GitHub Actions（运行在打了 `huboze-linedns` 标签的自托管运行器上）：

- **CI**（`.github/workflows/ci.yml`）：推送到 `main` 或提交 PR 时执行 gofmt / vet / test / 打包，部署包作为构建产物保留 14 天
- **Release**（`.github/workflows/release.yml`）：推送 `v*` 标签（须与 `main.go` 中的 `Version` 一致，例如 `v1.0.0`）时自动创建 GitHub Release 并上传部署包


## 许可证

本项目采用 [Apache License 2.0](LICENSE) 许可证。
