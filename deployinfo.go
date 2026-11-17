package main

import (
	"bufio"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"
)

// ---------------- deployment summary ("初始化信息") ----------------
//
// Printed at the end of install and by `huboze-ddns-agent info`, and saved to
// infoFile (root-only) so the addresses and first password are not lost when
// the install output scrolls away.

const infoFile = "/root/huboze-ddns-agent-info.txt"

type accessAddr struct {
	url, label string
}

var cgnat = net.IPNet{IP: net.IPv4(100, 64, 0, 0), Mask: net.CIDRMask(10, 32)}

// accessAddrs lists every address the Web panel can be reached on, public
// addresses first. Docker bridges and virtual interfaces are skipped.
func accessAddrs(port string) []accessAddr {
	var pub, lan []accessAddr
	ifaces, _ := net.Interfaces()
	for _, ifc := range ifaces {
		n := ifc.Name
		if ifc.Flags&net.FlagUp == 0 || ifc.Flags&net.FlagLoopback != 0 ||
			n == "docker0" || strings.HasPrefix(n, "br-") || strings.HasPrefix(n, "veth") ||
			strings.HasPrefix(n, "virbr") || strings.HasPrefix(n, "cni") || strings.HasPrefix(n, "flannel") {
			continue
		}
		addrs, _ := ifc.Addrs()
		for _, a := range addrs {
			ipn, ok := a.(*net.IPNet)
			if !ok || !ipn.IP.IsGlobalUnicast() {
				continue
			}
			ip := ipn.IP
			host := ip.String()
			if ip.To4() == nil {
				host = "[" + host + "]"
			}
			u := "http://" + host + ":" + port
			switch {
			case ip.To4() != nil && (ip.IsPrivate() || cgnat.Contains(ip)):
				lan = append(lan, accessAddr{u, "内网 IPv4（" + n + "）"})
			case ip.To4() != nil:
				pub = append(pub, accessAddr{u, "公网 IPv4（" + n + "）"})
			case ip.IsPrivate(): // IPv6 ULA fc00::/7
				lan = append(lan, accessAddr{u, "内网 IPv6（" + n + "）"})
			default:
				pub = append(pub, accessAddr{u, "公网 IPv6（" + n + "）"})
			}
		}
	}
	out := append(pub, lan...)
	return append(out, accessAddr{"http://127.0.0.1:" + port, "本机"})
}

type deployInfo struct {
	version, port, password string
	freshPassword           bool   // password was issued by this install
	note                    string // e.g. "全新安装" / "从 v2.2.3 Python 版升级"
	status                  string // shown by `info`
}

func (d deployInfo) render() string {
	var b strings.Builder
	w := func(f string, a ...any) { fmt.Fprintf(&b, f+"\n", a...) }
	addrs := accessAddrs(d.port)
	main := addrs[0].url
	w("huboze 线路解析管家 v%s 部署信息", d.version)
	w("生成时间：%s", time.Now().Format("2006-01-02 15:04:05"))
	if d.note != "" {
		w("部署方式：%s", d.note)
	}
	if d.status != "" {
		w("运行状态：%s", d.status)
	}
	w("")
	w("【Web 管理地址】")
	for _, a := range addrs {
		w("  %-40s %s", a.url, a.label)
	}
	w("  健康检查：%s/health", main)
	w("")
	w("【登录信息】")
	w("  账号：admin")
	switch {
	case d.password != "":
		w("  密码：%s", d.password)
		if d.freshPassword {
			w("  ※ 这是初始密码，登录后请立即在“设置”中修改")
		}
	default:
		w("  密码：沿用原密码（未在服务器上保存明文）")
		w("  忘记密码：huboze-ddns-agent reset-password")
	}
	w("")
	w("【部署位置】")
	w("  程序目录：%s", AppDir)
	w("  配置文件：%s", composePath())
	w("  数据库：  %s/data/huboze-ddns.db", AppDir)
	w("  加密密钥：%s/config/（迁移服务器时必须一起带走）", AppDir)
	w("  容器名称：%s    镜像：%s:%s", containerName, imageRepo, d.version)
	w("  管理命令：/usr/local/bin/huboze-ddns-agent")
	w("")
	w("【常用命令】")
	w("  huboze-ddns-agent info              再次显示本信息")
	w("  huboze-ddns-agent status            运行状态")
	w("  huboze-ddns-agent logs              实时日志")
	w("  huboze-ddns-agent selfcheck         运行环境自检")
	w("  huboze-ddns-agent restart           重启服务")
	w("  huboze-ddns-agent backup            备份（含数据库与密钥）")
	w("  huboze-ddns-agent reset-password    重置管理员密码")
	w("  huboze-ddns-agent reset-whitelist   白名单配错被锁在外面时使用")
	w("")
	w("【下一步】")
	w("  1. 浏览器打开 %s 登录", main)
	w("  2. “设置”：修改管理员密码；填写来源 IP 白名单")
	w("  3. 按首页“快速开始”：添加 DNS 服务商 → 添加 MSR → 测试接口 → 创建域名映射")
	w("")
	w("【安全提醒】")
	w("  · Web 为 HTTP 明文访问，请只在内网使用，或在前面加 HTTPS 反向代理")
	w("  · 云服务器还需在安全组放行 TCP %s（建议只放行管理网段）", d.port)
	if h := firewallStatusText(d.port); h != "" {
		w("  · %s", h)
	}
	if d.password != "" {
		w("  · 本文件含明文密码（%s，仅 root 可读），改密后请删除", infoFile)
	}
	return b.String()
}

func firewallStatusText(port string) string {
	if out, err := exec.Command("ufw", "status").Output(); err == nil {
		s := string(out)
		if strings.Contains(s, "Status: active") {
			if strings.Contains(s, port) {
				return "ufw 已启用，并已放行端口 " + port
			}
			return "ufw 已启用但未放行端口 " + port + "，执行：ufw allow " + port + "/tcp"
		}
		return "本机 ufw 未启用"
	}
	if exec.Command("firewall-cmd", "--state").Run() == nil {
		return "firewalld 已启用，如需放行：firewall-cmd --permanent --add-port=" + port + "/tcp && firewall-cmd --reload"
	}
	return ""
}

// printDeployInfo shows the summary in a frame and saves it to infoFile.
func printDeployInfo(d deployInfo) {
	text := d.render()
	bar := strings.Repeat("═", 64)
	fmt.Println()
	fmt.Println(cGreen + bar + cReset)
	for _, l := range strings.Split(strings.TrimRight(text, "\n"), "\n") {
		switch {
		case strings.HasPrefix(l, "【"):
			fmt.Println(cBlue + l + cReset)
		case strings.HasPrefix(l, "  密码：") || strings.HasPrefix(l, "  账号："):
			fmt.Println(cYellow + l + cReset)
		case strings.HasPrefix(l, "huboze 线路解析管家"):
			fmt.Println(cGreen + l + cReset)
		default:
			fmt.Println(l)
		}
	}
	fmt.Println(cGreen + bar + cReset)
	if err := os.WriteFile(infoFile, []byte(text), 0o600); err == nil {
		_ = os.Chmod(infoFile, 0o600)
		fmt.Printf("以上信息已保存到 %s（仅 root 可读），也可随时执行 huboze-ddns-agent info 查看。\n\n", infoFile)
	}
}

// savedPassword returns the password line kept in infoFile (or the legacy login file).
func savedPassword() string {
	for _, f := range []string{infoFile, "/root/huboze-ddns-agent-login.txt"} {
		fh, err := os.Open(f)
		if err != nil {
			continue
		}
		sc := bufio.NewScanner(fh)
		for sc.Scan() {
			l := strings.TrimSpace(sc.Text())
			for _, p := range []string{"密码：", "Password: "} {
				if strings.HasPrefix(l, p) && !strings.Contains(l, "沿用原密码") {
					fh.Close()
					return strings.TrimSpace(strings.TrimPrefix(l, p))
				}
			}
		}
		fh.Close()
	}
	return ""
}

func cmdInfo() error {
	if err := requireRoot(); err != nil {
		return err
	}
	port := existingPort()
	if port == "" {
		return exitError{1, "未找到部署（" + composePath() + " 不存在），请先执行 huboze-ddns-agent install"}
	}
	ver := Version
	c := &http.Client{Timeout: 3 * time.Second}
	running := false
	if resp, err := c.Get("http://127.0.0.1:" + port + "/health"); err == nil {
		var buf [256]byte
		n, _ := resp.Body.Read(buf[:])
		resp.Body.Close()
		running = resp.StatusCode == 200
		if m := strings.Split(string(buf[:n]), `"version":"`); len(m) > 1 {
			ver = strings.SplitN(m[1], `"`, 2)[0]
		}
	}
	d := deployInfo{version: ver, port: port, password: savedPassword()}
	if running {
		d.status = "运行中（健康检查正常）"
	} else {
		d.status = "⚠ 服务未响应，请执行 huboze-ddns-agent status 查看"
	}
	printDeployInfo(d)
	return nil
}
