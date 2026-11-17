package main

import (
	"archive/tar"
	"bufio"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/term"
)

const (
	containerName = "huboze-ddns-agent"
	imageRepo     = "huboze-ddns-agent"
	containerUID  = 10001
	legacyUnit    = "/etc/systemd/system/huboze-ddns-agent.service" // earlier Go/systemd build
	keepBackups   = 3
)

// installBinary is the host-side manager command (HUBOZE_INSTALL_BIN overrides it for tests).
var installBinary = func() string {
	if v := os.Getenv("HUBOZE_INSTALL_BIN"); v != "" {
		return v
	}
	return "/usr/local/bin/huboze-ddns-agent"
}()

func imageRef() string       { return imageRepo + ":" + Version }
func composePath() string    { return filepath.Join(AppDir, "docker-compose.yml") }
func hostCACertPath() string { return "/etc/ssl/certs/ca-certificates.crt" }

const (
	cGreen  = "\033[32m"
	cYellow = "\033[33m"
	cRed    = "\033[31m"
	cBlue   = "\033[34m"
	cReset  = "\033[0m"
)

func line() {
	fmt.Println(cBlue + "============================================================" + cReset)
}
func info(f string, a ...any)    { fmt.Printf(cBlue+"[INFO]"+cReset+" "+f+"\n", a...) }
func success(f string, a ...any) { fmt.Printf(cGreen+"[SUCCESS]"+cReset+" "+f+"\n", a...) }
func warning(f string, a ...any) { fmt.Printf(cYellow+"[WARNING]"+cReset+" "+f+"\n", a...) }
func errorf(f string, a ...any)  { fmt.Printf(cRed+"[ERROR]"+cReset+" "+f+"\n", a...) }

// ---------------- process helpers ----------------

func runCmd(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	return cmd.Run()
}

func tailLines(s string, n int) string {
	l := strings.Split(strings.TrimSpace(s), "\n")
	if len(l) > n {
		l = l[len(l)-n:]
	}
	return strings.Join(l, "\n")
}

func runQuiet(name string, args ...string) error {
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s 失败：%v\n%s", name, strings.Join(args, " "), err, tailLines(string(out), 15))
	}
	return nil
}

func output(name string, args ...string) (string, error) {
	out, err := exec.Command(name, args...).Output()
	return strings.TrimSpace(string(out)), err
}

func commandExists(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

func requireRoot() error {
	if os.Geteuid() != 0 {
		return exitError{1, "请使用 root 执行"}
	}
	return nil
}

func promptPassword() (string, error) {
	fmt.Print("新的管理员密码：")
	a, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println()
	if err != nil {
		return "", err
	}
	fmt.Print("再次输入确认：")
	b, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println()
	if err != nil {
		return "", err
	}
	if string(a) != string(b) {
		return "", exitError{2, "两次输入的密码不一致"}
	}
	return string(a), nil
}

func copyFile(src, dst string, mode os.FileMode) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	tmp := dst + ".tmp"
	out, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	if err := out.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, dst)
}

// ---------------- apt (non-interactive, waits for the dpkg lock) ----------------

var aptUpdated bool

func aptRun(args ...string) error {
	full := append([]string{"-q", "-o", "DPkg::Lock::Timeout=600",
		"-o", "Dpkg::Options::=--force-confdef", "-o", "Dpkg::Options::=--force-confold"}, args...)
	cmd := exec.Command("apt-get", full...)
	cmd.Env = append(os.Environ(), "DEBIAN_FRONTEND=noninteractive", "NEEDRESTART_MODE=a")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("apt-get %s 失败：%v\n%s", strings.Join(args, " "), err, tailLines(string(out), 15))
	}
	return nil
}

func dpkgInstalled(p string) bool {
	out, err := exec.Command("dpkg-query", "-W", "-f=${Status}", p).Output()
	return err == nil && strings.Contains(string(out), "install ok installed")
}

func aptHasCandidate(p string) bool {
	out, err := exec.Command("apt-cache", "policy", p).Output()
	return err == nil && strings.Contains(string(out), "Candidate:") && !strings.Contains(string(out), "Candidate: (none)")
}

func aptInstall(pkgs ...string) error {
	var missing []string
	for _, p := range pkgs {
		if !dpkgInstalled(p) {
			missing = append(missing, p)
		}
	}
	if len(missing) == 0 {
		return nil
	}
	info("安装依赖：%s（如系统正在自动更新，会等待 apt 锁释放，最长 10 分钟）", strings.Join(missing, " "))
	if !aptUpdated {
		if err := aptRun("update"); err != nil {
			return err
		}
		aptUpdated = true
	}
	return aptRun(append([]string{"install", "-y", "--no-install-recommends"}, missing...)...)
}

// ---------------- environment detection ----------------

func osRelease() map[string]string {
	m := map[string]string{}
	f, err := os.Open("/etc/os-release")
	if err != nil {
		return m
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		k, v, ok := strings.Cut(sc.Text(), "=")
		if ok {
			m[k] = strings.Trim(v, `"'`)
		}
	}
	return m
}

func systemdPresent() bool { return fileExists("/run/systemd/system") }

func freeMB(p string) int64 {
	for p != "/" && !fileExists(p) {
		p = filepath.Dir(p)
	}
	var st syscall.Statfs_t
	if syscall.Statfs(p, &st) != nil {
		return -1
	}
	return int64(st.Bavail) * int64(st.Bsize) / 1024 / 1024
}

func portInUse(port string) bool {
	l, err := net.Listen("tcp", ":"+port)
	if err != nil {
		return true
	}
	l.Close()
	return false
}

var versionRE = regexp.MustCompile(`(\d+)\.(\d+)`)

func majorVersion(s string) int {
	m := versionRE.FindStringSubmatch(s)
	if m == nil {
		return 0
	}
	n, _ := strconv.Atoi(m[1])
	return n
}

// composeCmd returns a working Compose v2+ invocation.
func composeCmd() ([]string, error) {
	if out, err := output("docker", "compose", "version"); err == nil && majorVersion(out) >= 2 {
		return []string{"docker", "compose"}, nil
	}
	if commandExists("docker-compose") {
		if out, err := output("docker-compose", "version"); err == nil && majorVersion(out) >= 2 {
			return []string{"docker-compose"}, nil
		}
		return nil, errors.New("只找到旧版 docker-compose v1，请升级到 Compose v2")
	}
	return nil, errors.New("未找到 Docker Compose")
}

func composeRun(args ...string) error {
	if err := requireRoot(); err != nil {
		return err
	}
	cc, err := composeCmd()
	if err != nil {
		return err
	}
	cmd := exec.Command(cc[0], append(cc[1:], args...)...)
	cmd.Dir = AppDir
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	return cmd.Run()
}

func composeQuiet(args ...string) error {
	cc, err := composeCmd()
	if err != nil {
		return err
	}
	cmd := exec.Command(cc[0], append(cc[1:], args...)...)
	cmd.Dir = AppDir
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("compose %s 失败：%v\n%s", strings.Join(args, " "), err, tailLines(string(out), 15))
	}
	return nil
}

func dockerReady() bool { return exec.Command("docker", "info").Run() == nil }

func ensureDocker() error {
	if !commandExists("docker") {
		info("未检测到 Docker：从 Debian 官方仓库安装 docker.io（不使用 get.docker.com，国内镜像源可用）")
		if err := aptInstall("docker.io"); err != nil {
			return err
		}
	}
	if !dockerReady() && systemdPresent() {
		_ = runQuiet("systemctl", "enable", "--now", "docker")
	}
	for i := 0; i < 30 && !dockerReady(); i++ {
		time.Sleep(time.Second)
	}
	if !dockerReady() {
		return errors.New("Docker 守护进程未运行（docker info 失败），请检查：systemctl status docker")
	}
	ver, _ := output("docker", "version", "--format", "{{.Server.Version}}")
	if majorVersion(ver) < 20 {
		return fmt.Errorf("Docker 版本过低：%s（需要 20.10 或更高）", ver)
	}
	success("Docker：%s", ver)
	return nil
}

func ensureCompose() error {
	if _, err := composeCmd(); err != nil {
		// Docker CE repo ships the plugin; Debian's own repo ships docker-compose (v2).
		pkg := "docker-compose"
		if aptHasCandidate("docker-compose-plugin") {
			pkg = "docker-compose-plugin"
		}
		info("未检测到 Docker Compose v2：安装 %s", pkg)
		if err := aptInstall(pkg); err != nil {
			return err
		}
	}
	cc, err := composeCmd()
	if err != nil {
		return err
	}
	out, _ := output(cc[0], append(cc[1:], "version")...)
	success("Compose：%s", out)
	return nil
}

// ensurePingGroupRange lets container uid/gid 10001 use unprivileged ICMP
// sockets (host network namespace), so the container needs no capabilities.
func ensurePingGroupRange() {
	const p = "/proc/sys/net/ipv4/ping_group_range"
	b, err := os.ReadFile(p)
	if err != nil {
		warning("无法读取 %s，ICMP 可达性检测可能不可用", p)
		return
	}
	f := strings.Fields(string(b))
	if len(f) != 2 {
		return
	}
	lo, _ := strconv.Atoi(f[0])
	hi, _ := strconv.Atoi(f[1])
	if lo <= containerUID && containerUID <= hi {
		success("ICMP：ping_group_range=%d-%d 已包含容器用户 %d", lo, hi, containerUID)
		return
	}
	if lo > hi { // disabled
		lo, hi = containerUID, containerUID
	} else {
		lo, hi = min(lo, containerUID), max(hi, containerUID)
	}
	val := fmt.Sprintf("%d %d", lo, hi)
	_ = os.WriteFile("/etc/sysctl.d/60-huboze-ddns-agent.conf", []byte("# huboze 线路解析管家: unprivileged ICMP for container gid 10001\nnet.ipv4.ping_group_range = "+val+"\n"), 0o644)
	if err := os.WriteFile(p, []byte(val), 0o644); err != nil {
		warning("设置 ping_group_range 失败：%v；ICMP 检测将不可用（可改用 TCP 端口检测）", err)
		return
	}
	success("ICMP：已设置 net.ipv4.ping_group_range = %s（持久化于 /etc/sysctl.d/60-huboze-ddns-agent.conf）", val)
}

func firewallHint(port string) {
	if commandExists("ufw") {
		if out, _ := output("ufw", "status"); strings.Contains(out, "Status: active") {
			if !regexp.MustCompile(`(?m)^` + port + `(/tcp)?\s+ALLOW`).MatchString(out) {
				warning("检测到 ufw 防火墙已启用且未放行 %s/tcp，外部将无法访问 Web：ufw allow %s/tcp", port, port)
			} else {
				success("ufw 已放行 %s/tcp", port)
			}
		}
	}
	if commandExists("firewall-cmd") {
		if out, _ := output("firewall-cmd", "--state"); out == "running" {
			if q, _ := output("firewall-cmd", "--query-port="+port+"/tcp"); q != "yes" {
				warning("检测到 firewalld 未放行 %s/tcp：firewall-cmd --permanent --add-port=%s/tcp && firewall-cmd --reload", port, port)
			}
		}
	}
}

func containerExists() bool {
	return exec.Command("docker", "inspect", containerName).Run() == nil
}

func containerRunning() bool {
	out, err := output("docker", "inspect", "-f", "{{.State.Running}}", containerName)
	return err == nil && out == "true"
}

func imageExists(ref string) bool {
	return exec.Command("docker", "image", "inspect", ref).Run() == nil
}

var (
	composePortRE    = regexp.MustCompile(`WEB_PORT:\s*"?(\d+)"?`)
	composeOldPortRE = regexp.MustCompile(`-\s*"?(\d+):8080"?`)
	unitPortRE       = regexp.MustCompile(`Environment=WEB_PORT=(\d+)`)
)

// existingPort keeps the current port on upgrade.
func existingPort() string {
	if b, err := os.ReadFile(composePath()); err == nil {
		if m := composePortRE.FindSubmatch(b); m != nil {
			return string(m[1])
		}
		if m := composeOldPortRE.FindSubmatch(b); m != nil {
			return string(m[1])
		}
	}
	if b, err := os.ReadFile(legacyUnit); err == nil {
		if m := unitPortRE.FindSubmatch(b); m != nil {
			return string(m[1])
		}
	}
	return ""
}

func localIP() string {
	c, err := net.Dial("udp", "223.5.5.5:53")
	if err == nil {
		defer c.Close()
		return c.LocalAddr().(*net.UDPAddr).IP.String()
	}
	return "127.0.0.1"
}

func fixOwnership() {
	chownTree(DataDir, containerUID, containerUID)
	chownTree(ConfigDir, containerUID, containerUID)
	_ = os.Chmod(FernetKeyFile, 0o600)
	_ = os.Chmod(SecretKeyFile, 0o600)
}

func pruneBackups(keep int) {
	m, _ := filepath.Glob(AppDir + "-backup-*")
	sort.Strings(m)
	for len(m) > keep {
		_ = os.RemoveAll(m[0])
		info("清理旧回滚备份：%s", m[0])
		m = m[1:]
	}
}

// ---------------- image ----------------

// buildImage creates a FROM-scratch style image with `docker import`:
// no base image pull, no buildx, no network access needed.
func buildImage(binPath string) error {
	pr, pw := io.Pipe()
	go func() {
		pw.CloseWithError(writeRootfsTar(pw, binPath))
	}()
	cmd := exec.Command("docker", "import",
		"-m", "huboze 线路解析管家 "+Version,
		"--change", "USER 10001:10001",
		"--change", "ENV HUBOZE_APP_DIR=/",
		"--change", "ENV HUBOZE_IN_CONTAINER=1",
		"--change", "ENV TZ=Asia/Shanghai",
		"--change", "WORKDIR /",
		"--change", `ENTRYPOINT ["/huboze-ddns-agent"]`,
		"--change", `CMD ["serve"]`,
		"-", imageRef())
	cmd.Stdin = pr
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("docker import 失败：%v\n%s", err, tailLines(string(out), 10))
	}
	return nil
}

func writeRootfsTar(w io.Writer, binPath string) error {
	tw := tar.NewWriter(w)
	now := time.Now()
	for _, d := range []struct {
		name string
		mode int64
	}{{"etc/", 0o755}, {"etc/ssl/", 0o755}, {"etc/ssl/certs/", 0o755}, {"tmp/", 0o1777}, {"data/", 0o755}, {"config/", 0o755}} {
		if err := tw.WriteHeader(&tar.Header{Name: d.name, Typeflag: tar.TypeDir, Mode: d.mode, ModTime: now}); err != nil {
			return err
		}
	}
	addFile := func(src, name string, mode int64) error {
		f, err := os.Open(src)
		if err != nil {
			return err
		}
		defer f.Close()
		st, err := f.Stat()
		if err != nil {
			return err
		}
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: mode, Size: st.Size(), ModTime: now}); err != nil {
			return err
		}
		_, err = io.Copy(tw, f)
		return err
	}
	if err := addFile(binPath, "huboze-ddns-agent", 0o755); err != nil {
		return err
	}
	if fileExists(hostCACertPath()) { // fresher than the roots embedded in the binary
		if err := addFile(hostCACertPath(), "etc/ssl/certs/ca-certificates.crt", 0o644); err != nil {
			return err
		}
	}
	return tw.Close()
}

func composeContent(port string) string {
	return `# 由 huboze-ddns-agent install 生成，请勿手工修改。
# 修改端口：WEB_PORT=新端口 huboze-ddns-agent install
services:
  huboze-ddns-agent:
    image: ` + imageRef() + `
    container_name: ` + containerName + `
    restart: unless-stopped
    # host 网络：IPv6/AAAA 可达性检测可用，Web 白名单可获取真实客户端 IP
    network_mode: host
    user: "10001:10001"
    read_only: true
    tmpfs:
      - /tmp:size=64m,mode=1777
    cap_drop:
      - ALL
    security_opt:
      - no-new-privileges:true
    environment:
      WEB_PORT: "` + port + `"
      TZ: Asia/Shanghai
    volumes:
      - ./data:/data
      - ./config:/config:ro
    healthcheck:
      test: ["CMD", "/huboze-ddns-agent", "healthcheck"]
      interval: 20s
      timeout: 5s
      retries: 3
      start_period: 10s
    logging:
      driver: json-file
      options:
        max-size: "10m"
        max-file: "3"
`
}

// containerOneShot runs a maintenance command against the data: via
// `docker exec` when the service is running, otherwise in a throw-away container.
func containerOneShot(stdin string, args ...string) error {
	var cmd *exec.Cmd
	if containerRunning() {
		cmd = exec.Command("docker", append([]string{"exec", "-i", containerName, "/huboze-ddns-agent"}, args...)...)
	} else {
		if !imageExists(imageRef()) {
			return fmt.Errorf("镜像 %s 不存在，请先执行 huboze-ddns-agent install", imageRef())
		}
		cmd = exec.Command("docker", append([]string{"run", "--rm", "-i", "--network", "none",
			"-v", DataDir + ":/data", "-v", ConfigDir + ":/config:ro", imageRef()}, args...)...)
	}
	cmd.Stdin = strings.NewReader(stdin)
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	return cmd.Run()
}

// ---------------- install ----------------

type legacyKind string

const (
	legacyNone         legacyKind = "none"
	legacyPythonDocker legacyKind = "python-docker" // original bash/Flask v2.x
	legacyGoSystemd    legacyKind = "go-systemd"    // earlier Go build
	legacyGoDocker     legacyKind = "go-docker"     // this design (upgrade/reinstall)
)

func detectLegacy() legacyKind {
	switch {
	case fileExists(legacyUnit):
		return legacyGoSystemd
	case commandExists("docker") && containerExists() && fileExists(filepath.Join(AppDir, "app", "main.py")):
		return legacyPythonDocker
	case commandExists("docker") && containerExists():
		return legacyGoDocker
	}
	return legacyNone
}

func install() (retErr error) {
	line()
	fmt.Println("        huboze 线路解析管家 v" + Version + "（Go + Docker Compose）")
	fmt.Println("        H3C MSR Multi-WAN + Multi-DNS")
	line()

	// -------- 部署前检查 --------
	if err := requireRoot(); err != nil {
		errorf("请使用 root 执行")
		return exitError{1, ""}
	}
	info("部署前检查：系统")
	osr := osRelease()
	pretty := osr["PRETTY_NAME"]
	if pretty == "" {
		pretty = "unknown"
	}
	isDebian := osr["ID"] == "debian"
	if !isDebian && !strings.Contains(" "+osr["ID_LIKE"]+" ", " debian ") {
		errorf("仅支持 Debian 系统，当前：%s", pretty)
		return exitError{1, ""}
	}
	switch {
	case isDebian && osr["VERSION_ID"] == "13":
		success("系统检测通过：%s", pretty)
	default:
		warning("当前为 %s，非标准支持环境（Debian 13），继续执行", pretty)
	}
	if !systemdPresent() {
		warning("未检测到 systemd：Docker 需由其他方式托管并保持运行")
	}

	port := strings.TrimSpace(os.Getenv("WEB_PORT"))
	if port == "" {
		port = existingPort()
	}
	if port == "" {
		port = "8080"
	}
	if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 {
		errorf("WEB_PORT 非法：%q（应为 1-65535 的数字）", port)
		return exitError{1, ""}
	}

	info("部署前检查：磁盘空间")
	needDocker := 300
	if !commandExists("docker") {
		needDocker = 1024
	}
	if mb := freeMB(AppDir); mb >= 0 && mb < 200 {
		errorf("%s 所在分区剩余空间不足：%d MB（至少需要 200 MB）", filepath.Dir(AppDir), mb)
		return exitError{1, ""}
	}
	if mb := freeMB("/var/lib/docker"); mb >= 0 && mb < int64(needDocker) {
		errorf("/var/lib 所在分区剩余空间不足：%d MB（至少需要 %d MB）", mb, needDocker)
		return exitError{1, ""}
	}
	success("磁盘空间充足")

	info("部署前检查：网络")
	_, dnsErr := net.LookupHost("deb.debian.org")
	c, tcpErr := net.DialTimeout("tcp", "223.5.5.5:53", 3*time.Second)
	if tcpErr == nil {
		c.Close()
	}
	if dnsErr != nil && tcpErr != nil {
		errorf("网络检查失败：无法解析域名（%v），也无法连接 223.5.5.5:53", dnsErr)
		return exitError{1, ""}
	}
	if dnsErr != nil {
		warning("系统 DNS 解析失败：%v（安装依赖与 DNS 服务商 API 可能失败）", dnsErr)
	} else {
		success("网络连通、DNS 解析正常")
	}
	if r := queryDNSResolver("deb.debian.org", "223.5.5.5", "A"); r.Status == "OK" {
		success("出站 UDP 53 正常（域名健康检查可直接查询公共 DNS）")
	} else {
		warning("无法直接查询公共 DNS 223.5.5.5（%s %s）：域名健康检查会受影响，请放行出站 UDP 53", r.Status, r.Error)
	}

	info("部署前检查：系统时间")
	st := skewItem(0)
	switch st.Status {
	case "OK":
		success("%s", st.Detail)
	case "FAIL":
		if commandExists("timedatectl") {
			_ = runQuiet("timedatectl", "set-ntp", "true")
		}
		warning("%s（已尝试开启 NTP 同步，请稍后复查：timedatectl status）", st.Detail)
	default:
		warning("%s", st.Detail)
	}

	info("部署前检查：Docker / Compose")
	if err := aptInstall("ca-certificates"); err != nil {
		return err
	}
	if err := ensureDocker(); err != nil {
		return err
	}
	if err := ensureCompose(); err != nil {
		return err
	}

	legacy := detectLegacy()
	switch legacy {
	case legacyPythonDocker:
		warning("检测到旧版 Python/Flask Docker 部署：将迁移为 Go 镜像，数据、密钥与凭据全部保留")
	case legacyGoSystemd:
		warning("检测到 systemd 方式部署的 Go 版本：将迁移为 Docker Compose 部署，数据全部保留")
	case legacyGoDocker:
		info("检测到已安装的 Go Docker 版本：执行原地升级")
	}

	info("部署前检查：端口 %s", port)
	if portInUse(port) {
		if legacy != legacyNone && existingPort() == port {
			warning("端口 %s 由旧 huboze-ddns-agent 使用，将执行原地升级", port)
		} else {
			errorf("端口 %s 已被其他服务占用", port)
			if commandExists("ss") {
				_ = runCmd("sh", "-c", "ss -lntp | grep ':"+port+" ' || true")
			}
			return exitError{1, ""}
		}
	} else {
		success("端口 %s 可用", port)
	}

	info("部署前检查：ICMP 权限")
	ensurePingGroupRange()

	// -------- 备份 & 回滚 --------
	backupDir := ""
	newInstall := !fileExists(AppDir)
	if !newInstall {
		backupDir = AppDir + "-backup-" + time.Now().Format("20060102-150405")
		info("备份现有版本 -> %s", backupDir)
		if err := runQuiet("cp", "-a", AppDir, backupDir); err != nil {
			return err
		}
		success("备份完成")
	}
	var oldUnit []byte
	if legacy == legacyGoSystemd {
		oldUnit, _ = os.ReadFile(legacyUnit)
	}
	oldBinary := ""
	if fileExists(installBinary) {
		oldBinary = installBinary + ".prev"
		_ = copyFile(installBinary, oldBinary, 0o755)
	}
	prevTag := ""
	if imageExists(imageRef()) {
		prevTag = imageRef() + "-prev"
		_ = runQuiet("docker", "tag", imageRef(), prevTag)
	}

	defer func() {
		if retErr == nil {
			return
		}
		errorf("部署失败，开始回滚：%v", retErr)
		_ = exec.Command("docker", "rm", "-f", containerName).Run()
		if prevTag != "" {
			_ = exec.Command("docker", "tag", prevTag, imageRef()).Run()
		}
		if oldBinary != "" {
			_ = os.Rename(oldBinary, installBinary)
		}
		if backupDir != "" {
			_ = os.RemoveAll(AppDir)
			_ = os.Rename(backupDir, AppDir)
		} else if newInstall {
			_ = os.RemoveAll(AppDir)
		}
		switch legacy {
		case legacyPythonDocker, legacyGoDocker:
			if err := composeQuiet("up", "-d"); err == nil {
				warning("已恢复旧版本并重新启动：%s", AppDir)
			} else {
				warning("已恢复旧版本文件，但启动失败：%v", err)
			}
		case legacyGoSystemd:
			_ = os.WriteFile(legacyUnit, oldUnit, 0o644)
			_ = exec.Command("systemctl", "daemon-reload").Run()
			_ = exec.Command("systemctl", "enable", "--now", "huboze-ddns-agent").Run()
			warning("已恢复 systemd 方式的旧版本")
		}
	}()

	// -------- 生成文件 --------
	for _, d := range []string{AppDir, DataDir, ConfigDir} {
		if err := os.MkdirAll(d, 0o750); err != nil {
			return err
		}
	}
	if err := ensureKeyFiles(); err != nil {
		return err
	}

	issueCreds := false
	if !fileExists(filepath.Join(DataDir, ".full_initialized")) {
		issueCreds = true
	} else if !fileExists(filepath.Join(DataDir, ".admin_credentials_issued")) {
		issueCreds = true
		warning("检测到数据库已初始化，但没有凭据签发标记；将自动重置 admin 密码并在部署完成后显示")
	}
	initialPassword := ""
	if issueCreds {
		initialPassword = randomString(20, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789@#%+=_")
	}

	info("执行：安装管理命令 %s", installBinary)
	self, err := os.Executable()
	if err != nil {
		return err
	}
	self, _ = filepath.EvalSymlinks(self)
	if self != installBinary {
		if err := copyFile(self, installBinary, 0o755); err != nil {
			return fmt.Errorf("安装二进制失败：%w", err)
		}
	}

	info("执行：构建镜像 %s（docker import，无需拉取基础镜像）", imageRef())
	if err := buildImage(installBinary); err != nil {
		return err
	}
	success("镜像构建完成")

	if err := os.WriteFile(composePath(), []byte(composeContent(port)), 0o644); err != nil {
		return err
	}
	for _, f := range []string{"Dockerfile", ".env"} { // old Python deployment files
		_ = os.Remove(filepath.Join(AppDir, f))
	}
	_ = os.RemoveAll(filepath.Join(AppDir, "app"))
	fixOwnership()

	// -------- 停止旧服务 --------
	info("执行：停止旧服务")
	if legacy == legacyGoSystemd {
		_ = exec.Command("systemctl", "disable", "--now", "huboze-ddns-agent").Run()
		_ = os.Remove(legacyUnit)
		_ = exec.Command("systemctl", "daemon-reload").Run()
	}
	_ = exec.Command("docker", "rm", "-f", containerName).Run()

	if issueCreds {
		info("执行：签发 Web 管理员凭据")
		if err := containerOneShot(initialPassword+"\n", "reset-password", "--stdin"); err != nil {
			return fmt.Errorf("写入 admin 密码失败：%w", err)
		}
		success("admin 管理密码已写入数据库（经 stdin 传入，不出现在进程参数与容器配置中）")
	}

	info("执行：启动服务")
	if err := composeQuiet("up", "-d"); err != nil {
		return err
	}

	// -------- 部署后检查 --------
	info("部署后检查：等待健康检查")
	var health string
	for i := 0; i < 40; i++ {
		resp, err := (&http.Client{Timeout: 2 * time.Second}).Get("http://127.0.0.1:" + port + "/health")
		if err == nil {
			b, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			if resp.StatusCode == 200 {
				health = strings.TrimSpace(string(b))
				break
			}
		}
		time.Sleep(time.Second)
	}
	if health == "" {
		_ = runCmd("docker", "logs", "--tail", "120", containerName)
		return errors.New("健康检查失败")
	}
	success("HTTP /health 正常：%s", health)
	if !containerRunning() {
		return errors.New("容器未运行")
	}
	success("容器运行正常")

	info("部署后检查：运行环境自检")
	out, _ := exec.Command("docker", "exec", containerName, "/huboze-ddns-agent", "selfcheck").CombinedOutput()
	fmt.Print(string(out))
	if strings.Contains(string(out), "[✗]") {
		for _, l := range strings.Split(string(out), "\n") {
			if strings.Contains(l, "[✗]") && (strings.Contains(l, "数据目录") || strings.Contains(l, "数据库") || strings.Contains(l, "加密密钥")) {
				return errors.New("关键自检项失败：" + strings.TrimSpace(ansiRE.ReplaceAllString(l, "")))
			}
		}
		warning("存在未通过的自检项（不影响部署），请按提示处理；之后可随时执行 huboze-ddns-agent selfcheck 或在 Web “设置”页自检")
	}

	firewallHint(port)

	touch := func(p string) {
		_ = os.WriteFile(p, nil, 0o644)
		_ = os.Chown(p, containerUID, containerUID)
	}
	touch(filepath.Join(DataDir, ".full_initialized"))
	if issueCreds {
		touch(filepath.Join(DataDir, ".admin_credentials_issued"))
	}
	if oldBinary != "" {
		_ = os.Remove(oldBinary)
	}
	pruneBackups(keepBackups)

	note := "全新安装"
	switch {
	case legacy == legacyPythonDocker:
		note = "从旧版 Python/Flask 迁移（数据、凭据、密码已保留）"
	case backupDir != "":
		note = "原地升级（数据、凭据、密码已保留）"
	}
	line()
	success("结果：huboze 线路解析管家 v%s（Go + Docker Compose）部署完成", Version)
	if backupDir != "" {
		info("回滚备份：%s（仅保留最近 %d 份）", backupDir, keepBackups)
	}
	if legacy == legacyPythonDocker {
		info("旧 Python 镜像未删除，确认运行正常后可执行：docker image rm huboze-ddns-agent:2.2.3")
	}
	if prevTag != "" {
		info("上一版镜像保留为 %s，确认正常后可删除：docker image rm %s", prevTag, prevTag)
	}
	pw := ""
	if issueCreds {
		pw = initialPassword
	}
	printDeployInfo(deployInfo{version: Version, port: port, password: pw, freshPassword: issueCreds, note: note})
	return nil
}

// ---------------- management commands ----------------

func cmdStatus() error {
	if err := requireRoot(); err != nil {
		return err
	}
	if err := composeRun("ps"); err != nil {
		return err
	}
	out, err := output("docker", "inspect", "-f", "状态={{.State.Status}}  健康={{if .State.Health}}{{.State.Health.Status}}{{else}}-{{end}}  启动于={{.State.StartedAt}}  镜像={{.Config.Image}}", containerName)
	if err == nil {
		fmt.Println(out)
	}
	return nil
}

func cmdBackup() error {
	if err := requireRoot(); err != nil {
		return err
	}
	out := "/root/huboze-ddns-agent-backup-" + time.Now().Format("20060102-150405") + ".tar.gz"
	if err := runQuiet("tar", "-C", filepath.Dir(AppDir), "-czf", out, filepath.Base(AppDir)); err != nil {
		return err
	}
	_ = os.Chmod(out, 0o600)
	fmt.Println(out)
	return nil
}

func cmdRestore(bundle string) error {
	if err := requireRoot(); err != nil {
		return err
	}
	if !fileExists(bundle) {
		return exitError{2, "用法：huboze-ddns-agent restore /路径/迁移包.tar.gz"}
	}
	tmp, err := os.MkdirTemp("", "huboze-restore-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmp)

	f, err := os.Open(bundle)
	if err != nil {
		return err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return exitError{2, "迁移包无效：" + err.Error()}
	}
	tr := tar.NewReader(gz)
	hasManifest := false
	allowed := map[string]bool{"manifest.json": true, "data/huboze-ddns.db": true, "data/known_hosts": true,
		"config/fernet.key": true, "config/flask_secret.key": true}
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return exitError{2, "迁移包无效：" + err.Error()}
		}
		clean := path.Clean(h.Name)
		if strings.HasPrefix(h.Name, "/") || clean == ".." || strings.HasPrefix(clean, "../") {
			return exitError{2, "迁移包中含有不安全的路径，已拒绝"}
		}
		if clean == "manifest.json" {
			hasManifest = true
		}
		// Only known regular files are extracted; links/devices are ignored.
		if h.Typeflag != tar.TypeReg || !allowed[clean] {
			continue
		}
		dst := filepath.Join(tmp, filepath.FromSlash(clean))
		if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
			return err
		}
		out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
		if err != nil {
			return err
		}
		if _, err := io.Copy(out, io.LimitReader(tr, 4<<30)); err != nil {
			out.Close()
			return err
		}
		out.Close()
	}
	if !hasManifest {
		return exitError{2, "迁移包无效：缺少 manifest.json"}
	}
	for _, need := range [][2]string{{"data/huboze-ddns.db", "缺少数据库文件"}, {"config/fernet.key", "缺少 fernet.key 加密密钥"}, {"config/flask_secret.key", "缺少 flask_secret.key 会话密钥"}} {
		if !fileExists(filepath.Join(tmp, need[0])) {
			return exitError{2, "迁移包无效：" + need[1]}
		}
	}
	ts := time.Now().Format("20060102-150405")
	pre := "/root/huboze-ddns-agent-pre-restore-" + ts + ".tar.gz"
	if fileExists(AppDir) {
		if err := runQuiet("tar", "-C", filepath.Dir(AppDir), "-czf", pre, filepath.Base(AppDir)); err != nil {
			return err
		}
		_ = os.Chmod(pre, 0o600)
	}
	if fileExists(composePath()) {
		_ = composeQuiet("stop")
	}
	for _, d := range []string{DataDir, ConfigDir} {
		if err := os.MkdirAll(d, 0o750); err != nil {
			return err
		}
	}
	if err := copyFile(filepath.Join(tmp, "data/huboze-ddns.db"), DBPath, 0o600); err != nil {
		return err
	}
	_ = os.Remove(DBPath + "-wal")
	_ = os.Remove(DBPath + "-shm")
	if fileExists(filepath.Join(tmp, "data/known_hosts")) {
		if err := copyFile(filepath.Join(tmp, "data/known_hosts"), KnownHostsFile, 0o600); err != nil {
			return err
		}
	} else {
		_ = os.Remove(KnownHostsFile)
	}
	if err := copyFile(filepath.Join(tmp, "config/fernet.key"), FernetKeyFile, 0o600); err != nil {
		return err
	}
	if err := copyFile(filepath.Join(tmp, "config/flask_secret.key"), SecretKeyFile, 0o600); err != nil {
		return err
	}
	fixOwnership()
	if !fileExists(composePath()) {
		fmt.Println("数据已恢复。尚未安装服务，请执行：huboze-ddns-agent install")
		return nil
	}
	if err := composeQuiet("up", "-d"); err != nil {
		return err
	}
	fmt.Println("迁移恢复完成。恢复前的数据已备份到：" + pre)
	return nil
}
