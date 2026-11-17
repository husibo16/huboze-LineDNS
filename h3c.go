package main

import (
	"bufio"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

type Interface struct {
	Name       string `json:"name"`
	Physical   string `json:"physical"`
	Protocol   string `json:"protocol"`
	IP         string `json:"ip"`
	Prefix     *int   `json:"prefix"`
	IPv6       string `json:"ipv6"`
	IPv6Prefix *int   `json:"ipv6_prefix"`
}

var (
	ansiRE          = regexp.MustCompile(`\x1b\[[0-?]*[ -/]*[@-~]`)
	backspaceRE     = regexp.MustCompile(`(?s).\x08`)
	h3cIfaceRowRE   = regexp.MustCompile(`(?i)^(\S+)\s+(\*?(?:down|up)(?:\(s\))?)\s+(\*?(?:down|up)(?:\(s\))?)\s+(\S+)`)
	dialerRE        = regexp.MustCompile(`(?i)^Dialer(\d+)$`)
	ansiPat         = `(?:\x1b\[[0-?]*[ -/]*[@-~])*`
	promptRE        = regexp.MustCompile(`(?m)^[ \t]*` + ansiPat + `[<\[][^>\]\r\n]{1,160}[>\]][ \t]*` + ansiPat + `\r?$`)
	cleanedPromptRE = regexp.MustCompile(`(?m)(?:^|\n)[ \t]*[<\[][^>\]\r\n]{1,160}[>\]][ \t]*$`)
	bannerRE        = regexp.MustCompile(`(?i)(?:Last successfully login time|Copyright \(c\) 2004-\d{4} New H3C Technologies)`)
	moreRE          = regexp.MustCompile(`(?i)-{2,}\s*More\s*-{2,}`)
	cmdErrorRE      = regexp.MustCompile(`(?i)(?:unrecognized|unknown command|permission denied|insufficient|not permitted|authorization failed)`)
	firstLoginRE    = regexp.MustCompile(`First login or password reset`)
	lockedRE        = regexp.MustCompile(`(?i)(?:(?:account|user).*(?:locked|lock)|too many.*(?:attempt|authentication))`)
	ipv4HeaderRE    = regexp.MustCompile(`(?i)Interface\s+Physical\s+Protocol\s+IP\s+address/Mask`)
	ipv6HeaderRE    = regexp.MustCompile(`(?i)Interface\s+Physical\s+Protocol\s+IPv6\s+Address(?:/Prefix)?`)
)

func canonicalIfaceName(name string) string {
	name = strings.TrimSpace(name)
	if m := dialerRE.FindStringSubmatch(name); m != nil {
		return "Dia" + m[1]
	}
	return name
}

func cleanText(s string) string {
	s = ansiRE.ReplaceAllString(s, "")
	s = strings.ReplaceAll(s, "\r", "")
	for strings.Contains(s, "\x08") {
		n := backspaceRE.ReplaceAllString(s, "")
		if n == s {
			s = strings.ReplaceAll(s, "\x08", "")
			break
		}
		s = n
	}
	return s
}

func cleanTail(s string) string {
	c := []rune(cleanText(s))
	if len(c) > 2600 {
		c = c[len(c)-2600:]
	}
	return strings.TrimSpace(string(c))
}

func cleanedBufferHasPrompt(s string) bool {
	return cleanedPromptRE.MatchString(cleanText(s))
}

// ---------------- known_hosts (StrictHostKeyChecking=accept-new) ----------------

var knownHostsMu sync.Mutex

func hostKeyAlgosFor(t string) []string {
	if t == ssh.KeyAlgoRSA {
		return []string{ssh.KeyAlgoRSASHA512, ssh.KeyAlgoRSASHA256, ssh.KeyAlgoRSA}
	}
	return []string{t}
}

// knownHostCallback returns a callback implementing accept-new, plus the
// host-key algorithms that should be offered (known types first so an
// existing RSA entry is not misreported as "changed").
func knownHostCallback(addr string) (ssh.HostKeyCallback, []string, error) {
	knownHostsMu.Lock()
	defer knownHostsMu.Unlock()
	if _, err := os.Stat(KnownHostsFile); errors.Is(err, os.ErrNotExist) {
		if err := os.WriteFile(KnownHostsFile, nil, 0o600); err != nil {
			return nil, nil, err
		}
	}
	cb, err := knownhosts.New(KnownHostsFile)
	if err != nil {
		return nil, nil, fmt.Errorf("读取 known_hosts 失败：%w", err)
	}
	// Probe for existing key types for this host.
	var algos []string
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	probe, _ := ssh.NewPublicKey(pub)
	fake := &net.TCPAddr{IP: net.IPv4(0, 0, 0, 0), Port: 0}
	var ke *knownhosts.KeyError
	if err := cb(addr, fake, probe); errors.As(err, &ke) && len(ke.Want) > 0 {
		seen := map[string]bool{}
		for _, w := range ke.Want {
			for _, a := range hostKeyAlgosFor(w.Key.Type()) {
				if !seen[a] {
					seen[a] = true
					algos = append(algos, a)
				}
			}
		}
	}
	wrapped := func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		err := cb(hostname, remote, key)
		if err == nil {
			return nil
		}
		var ke *knownhosts.KeyError
		if errors.As(err, &ke) && len(ke.Want) == 0 {
			knownHostsMu.Lock()
			defer knownHostsMu.Unlock()
			f, ferr := os.OpenFile(KnownHostsFile, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0o600)
			if ferr != nil {
				return ferr
			}
			defer f.Close()
			_, ferr = f.WriteString(knownhosts.Line([]string{hostname}, key) + "\n")
			return ferr
		}
		if errors.As(err, &ke) {
			return errHostKeyChanged
		}
		return err
	}
	return wrapped, algos, nil
}

var errHostKeyChanged = errors.New("REMOTE HOST IDENTIFICATION HAS CHANGED")

// removeKnownHost mimics `ssh-keygen -R host` (also for [host]:port and hashed entries).
func removeKnownHost(host string, port int) error {
	knownHostsMu.Lock()
	defer knownHostsMu.Unlock()
	data, err := os.ReadFile(KnownHostsFile)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	names := []string{host, knownhosts.Normalize(net.JoinHostPort(host, strconv.Itoa(port)))}
	var out []string
	sc := bufio.NewScanner(strings.NewReader(string(data)))
	sc.Buffer(make([]byte, 1024*1024), 1024*1024)
	for sc.Scan() {
		line := sc.Text()
		if knownLineMatches(line, names) {
			continue
		}
		out = append(out, line)
	}
	content := strings.Join(out, "\n")
	if content != "" {
		content += "\n"
	}
	return os.WriteFile(KnownHostsFile, []byte(content), 0o600)
}

func knownLineMatches(line string, names []string) bool {
	f := strings.Fields(line)
	if len(f) == 0 || strings.HasPrefix(f[0], "#") {
		return false
	}
	field := f[0]
	if strings.HasPrefix(field, "@") && len(f) > 1 {
		field = f[1]
	}
	for _, pat := range strings.Split(field, ",") {
		if strings.HasPrefix(pat, "|1|") {
			parts := strings.Split(pat[3:], "|")
			if len(parts) != 2 {
				continue
			}
			salt, err1 := base64.StdEncoding.DecodeString(parts[0])
			want, err2 := base64.StdEncoding.DecodeString(parts[1])
			if err1 != nil || err2 != nil {
				continue
			}
			for _, n := range names {
				m := hmac.New(sha1.New, salt)
				m.Write([]byte(n))
				if hmac.Equal(m.Sum(nil), want) {
					return true
				}
			}
			continue
		}
		for _, n := range names {
			if pat == n {
				return true
			}
		}
	}
	return false
}

// ---------------- SSH session ----------------

type authState struct {
	mu       sync.Mutex
	password string
	sent     bool
	notes    []string
	// When set, keyboard-interactive password-change prompts are answered.
	oldPassword, newPassword string
	changeMode               bool
	changeSeen               bool
}

func (a *authState) note(s string) {
	a.mu.Lock()
	a.notes = append(a.notes, s)
	a.mu.Unlock()
}

func (a *authState) text() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return strings.Join(a.notes, "\n")
}

func (a *authState) keyboardInteractive(user, instruction string, questions []string, echos []bool) ([]string, error) {
	a.note(instruction + "\n" + strings.Join(questions, "\n"))
	a.mu.Lock()
	defer a.mu.Unlock()
	answers := make([]string, len(questions))
	all := instruction + "\n" + strings.Join(questions, "\n")
	if firstLoginRE.MatchString(all) || regexp.MustCompile(`(?i)(old|new) password|confirm`).MatchString(all) {
		a.changeSeen = true
		if !a.changeMode {
			return nil, errors.New("H3C 账号要求首次登录改密")
		}
		for i, q := range questions {
			ql := strings.ToLower(q)
			switch {
			case strings.Contains(ql, "old"):
				answers[i] = a.oldPassword
			case strings.Contains(ql, "new"), strings.Contains(ql, "confirm"):
				answers[i] = a.newPassword
			default:
				answers[i] = a.password
			}
		}
		return answers, nil
	}
	if len(questions) == 0 {
		return answers, nil
	}
	if a.sent {
		return nil, errors.New("密码已尝试过一次，为避免账号被锁定不再重试")
	}
	a.sent = true
	for i := range questions {
		answers[i] = a.password
	}
	return answers, nil
}

func (a *authState) passwordCallback() (string, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.sent {
		return "", errors.New("密码已尝试过一次，为避免账号被锁定不再重试")
	}
	a.sent = true
	return a.password, nil
}

type shellConn struct {
	client  *ssh.Client
	session *ssh.Session
	exp     *expecter
	auth    *authState
}

func (s *shellConn) Close() {
	if s.session != nil {
		_ = s.session.Close()
	}
	if s.client != nil {
		_ = s.client.Close()
	}
}

func openShell(d *Device, auth *authState) (*shellConn, error) {
	port := d.Port
	if port == 0 {
		port = 22
	}
	addr := net.JoinHostPort(d.Host, strconv.Itoa(port))
	hkcb, knownAlgos, err := knownHostCallback(addr)
	if err != nil {
		return nil, err
	}
	sup := ssh.SupportedAlgorithms()
	ins := ssh.InsecureAlgorithms()
	cfg := &ssh.ClientConfig{
		User: d.Username,
		Auth: []ssh.AuthMethod{
			ssh.KeyboardInteractive(auth.keyboardInteractive),
			ssh.PasswordCallback(auth.passwordCallback),
		},
		HostKeyCallback: hkcb,
		BannerCallback: func(msg string) error {
			auth.note(msg)
			return nil
		},
		Timeout: 8 * time.Second,
		Config: ssh.Config{
			KeyExchanges: append(sup.KeyExchanges, ins.KeyExchanges...),
			Ciphers:      append(sup.Ciphers, ins.Ciphers...),
			MACs:         append(sup.MACs, ins.MACs...),
		},
	}
	if len(knownAlgos) > 0 {
		cfg.HostKeyAlgorithms = knownAlgos
	} else {
		cfg.HostKeyAlgorithms = append(sup.HostKeys, ins.HostKeys...)
	}

	conn, err := net.DialTimeout("tcp", addr, 8*time.Second)
	if err != nil {
		return nil, fmt.Errorf("SSH 连接失败：%v", err)
	}
	_ = conn.SetDeadline(time.Now().Add(15 * time.Second))
	c, chans, reqs, err := ssh.NewClientConn(conn, addr, cfg)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	_ = conn.SetDeadline(time.Time{})
	client := ssh.NewClient(c, chans, reqs)
	sess, err := client.NewSession()
	if err != nil {
		_ = client.Close()
		return nil, fmt.Errorf("SSH 会话创建失败：%v", err)
	}
	modes := ssh.TerminalModes{ssh.ECHO: 1, ssh.TTY_OP_ISPEED: 38400, ssh.TTY_OP_OSPEED: 38400}
	if err := sess.RequestPty("xterm", 240, 240, modes); err != nil {
		sess.Close()
		client.Close()
		return nil, fmt.Errorf("SSH 申请终端失败：%v", err)
	}
	stdin, err := sess.StdinPipe()
	if err != nil {
		sess.Close()
		client.Close()
		return nil, err
	}
	pr, pw := io.Pipe()
	sess.Stdout = pw
	sess.Stderr = pw
	if err := sess.Shell(); err != nil {
		sess.Close()
		client.Close()
		return nil, fmt.Errorf("SSH 启动 Shell 失败：%v", err)
	}
	go func() {
		_ = sess.Wait()
		_ = pw.Close()
	}()
	return &shellConn{client: client, session: sess, exp: newExpecter(pr, stdin), auth: auth}, nil
}

func describeAuthError(err error, auth *authState) error {
	msg := err.Error()
	notes := auth.text()
	switch {
	case errors.Is(err, errHostKeyChanged) || strings.Contains(msg, "REMOTE HOST IDENTIFICATION HAS CHANGED"):
		return errors.New("SSH Host Key 已变化。请先确认该管理 IP 确实仍是目标 H3C 设备，然后在“MSR 设备”页面点击“清除 Host Key”，再重新测试。")
	case auth.changeSeen || firstLoginRE.MatchString(notes):
		return errors.New("H3C 账号要求首次登录改密，请点击“首次改密”完成后再测试")
	case lockedRE.MatchString(notes):
		return errors.New("H3C 账号已被临时锁定，请等待锁定时间结束后再测试")
	case strings.Contains(msg, "unable to authenticate"):
		return errors.New("SSH 认证失败：用户名/密码错误，或设备未允许该用户 SSH 登录")
	case strings.Contains(msg, "SSH 连接失败"):
		return err
	}
	return fmt.Errorf("SSH 会话在认证阶段被关闭：%s", msg)
}

func intPtr(i int) *int { return &i }

var deviceLocks sync.Map // device id -> *sync.Mutex

// lockDevice serialises SSH sessions per MSR so the poller, "test",
// "refresh interfaces" and "save mapping" never log in concurrently.
func lockDevice(id int64) func() {
	v, _ := deviceLocks.LoadOrStore(id, &sync.Mutex{})
	m := v.(*sync.Mutex)
	m.Lock()
	return m.Unlock
}

func collectDevice(d *Device) ([]Interface, error) {
	defer lockDevice(d.ID)()
	password, err := decryptSecret(d.PasswordEnc)
	if err != nil {
		return nil, err
	}
	if password == "" {
		return nil, errors.New("SSH 密码为空")
	}
	auth := &authState{password: password}
	sc, err := openShell(d, auth)
	if err != nil {
		return nil, describeAuthError(err, auth)
	}
	defer sc.Close()
	child := sc.exp

	var transcript strings.Builder
	consumeEcho := func(command string) {
		child.Expect(2*time.Second, regexp.MustCompile(regexp.QuoteMeta(command)+`[^\r\n]*\r?\n`))
	}
	waitUntilPrompt := func(timeout time.Duration) (string, error) {
		var pieces strings.Builder
		pages := 0
		for {
			idx := child.Expect(timeout, moreRE, promptRE)
			pieces.WriteString(child.Before)
			switch idx {
			case 0:
				pages++
				if pages > 64 {
					return "", errors.New("H3C 分页超过 64 页，已终止")
				}
				child.Send(" ")
				continue
			case 1:
				return cleanText(pieces.String()), nil
			case expEOF:
				return "", errors.New("SSH 会话在等待 H3C 提示符时被关闭")
			}
			if cleanedBufferHasPrompt(pieces.String()) {
				return cleanText(pieces.String()), nil
			}
			return "", errors.New("等待 H3C CLI 提示符超时：" + cleanTail(pieces.String()))
		}
	}
	runTable := func(command string, header *regexp.Regexp, optional bool) (string, error) {
		child.SendLine(command)
		consumeEcho(command)
		idx := child.Expect(10*time.Second, header, cmdErrorRE, promptRE)
		before := child.Before
		switch idx {
		case 1:
			detail := cleanTail(before)
			if optional {
				_, _ = waitUntilPrompt(5 * time.Second)
				return "", nil
			}
			msg := "设备拒绝或不支持命令 " + command
			if detail != "" {
				msg += "；设备返回：" + detail
			}
			return "", errors.New(msg)
		case 2:
			if optional {
				return "", nil
			}
			detail := cleanTail(before)
			msg := command + " 未返回预期接口表格"
			if detail != "" {
				msg += "；设备返回：" + detail
			}
			return "", errors.New(msg)
		case expEOF:
			msg := "执行 " + command + " 时 SSH 会话被关闭"
			if before != "" {
				msg += "；输出：" + cleanTail(before)
			}
			return "", errors.New(msg)
		case expTimeout:
			cleaned := cleanText(before)
			if optional && (strings.Contains(cleaned, "IP6Stack is not configured") || cleanedBufferHasPrompt(cleaned)) {
				return "", nil
			}
			return "", fmt.Errorf("等待 %s 输出表头超时：%s", command, cleanTail(before))
		}
		var chunks strings.Builder
		pageCount := 0
		for {
			idx := child.Expect(10*time.Second, moreRE, promptRE)
			chunks.WriteString(child.Before)
			if idx == 0 {
				pageCount++
				if pageCount > 64 {
					return "", fmt.Errorf("%s 分页超过 64 页，已终止", command)
				}
				child.Send(" ")
				continue
			}
			if idx == 1 {
				break
			}
			if idx == expEOF {
				return "", fmt.Errorf("执行 %s 时 SSH 会话中断：%s", command, cleanTail(chunks.String()))
			}
			if cleanedBufferHasPrompt(chunks.String()) {
				break
			}
			return "", fmt.Errorf("等待 %s 输出完成超时：%s", command, cleanTail(chunks.String()))
		}
		return cleanText(chunks.String()), nil
	}

	// Wait for login banner / prompt (password already handled by SSH auth).
	authenticated := false
	for i := 0; i < 12 && !authenticated; i++ {
		idx := child.Expect(12*time.Second, firstLoginRE, lockedRE, bannerRE, promptRE)
		transcript.WriteString(child.Before)
		switch idx {
		case 0:
			return nil, errors.New("H3C 账号要求首次登录改密，请点击“首次改密”完成后再测试")
		case 1:
			return nil, errors.New("H3C 账号已被临时锁定，请等待锁定时间结束后再测试")
		case 2, 3:
			authenticated = true
		case expEOF:
			return nil, errors.New("SSH 会话在认证阶段被关闭：" + cleanTail(transcript.String()))
		case expTimeout:
			return nil, errors.New("SSH 认证阶段超时：" + cleanTail(transcript.String()))
		}
	}
	if !authenticated {
		return nil, errors.New("SSH 未能确认登录状态：" + cleanTail(transcript.String()))
	}

	child.Send("\r")
	switch child.Expect(8*time.Second, promptRE) {
	case expEOF:
		return nil, errors.New("SSH 已认证，但获取 H3C CLI 提示符时连接被关闭")
	case expTimeout:
		if !cleanedBufferHasPrompt(child.Before) {
			return nil, errors.New("SSH 已认证，但未识别到 H3C CLI 提示符")
		}
	}

	// Paging disable is best-effort.
	child.SendLine("screen-length disable")
	consumeEcho("screen-length disable")
	if _, err := waitUntilPrompt(6 * time.Second); err != nil {
		child.Send("\r")
		_, _ = waitUntilPrompt(4 * time.Second)
	}

	ipv4Output, err := runTable("display ip interface brief", ipv4HeaderRE, false)
	if err != nil {
		return nil, err
	}
	ipv6Output, err := runTable("display ipv6 interface brief", ipv6HeaderRE, true)
	if err != nil {
		return nil, err
	}
	child.SendLine("quit")
	child.Expect(4 * time.Second) // wait for EOF

	return parseH3CInterfaces(ipv4Output, ipv6Output)
}

func parseH3CInterfaces(ipv4Output, ipv6Output string) ([]Interface, error) {
	byName := map[string]*Interface{}
	var order []string

	for _, raw := range strings.Split(moreRE.ReplaceAllString(ipv4Output, ""), "\n") {
		line := strings.TrimSpace(raw)
		m := h3cIfaceRowRE.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		name := canonicalIfaceName(m[1])
		addr := m[4]
		item := &Interface{Name: name, Physical: m[2], Protocol: m[3]}
		if addr != "--" && addr != "Unassigned" && addr != "unassigned" {
			if ip, prefix, ok := parseIPv4Interface(addr); ok {
				item.IP = ip
				item.Prefix = intPtr(prefix)
			}
		}
		if _, ok := byName[name]; !ok {
			order = append(order, name)
		}
		byName[name] = item
	}

	type row struct {
		name, physical, protocol string
		parts                    []string
	}
	var rows []*row
	var current *row
	for _, raw := range strings.Split(moreRE.ReplaceAllString(ipv6Output, ""), "\n") {
		stripped := strings.TrimSpace(raw)
		if stripped == "" {
			continue
		}
		if m := h3cIfaceRowRE.FindStringSubmatch(stripped); m != nil {
			if current != nil {
				rows = append(rows, current)
			}
			current = &row{name: canonicalIfaceName(m[1]), physical: m[2], protocol: m[3]}
			first := m[4]
			if l := strings.ToLower(first); l != "unassigned" && l != "--" {
				current.parts = append(current.parts, first)
			}
			continue
		}
		if current != nil && len(raw) > 0 && (raw[0] == ' ' || raw[0] == '\t') {
			token := strings.Fields(stripped)[0]
			if strings.Contains(token, ":") || strings.HasPrefix(token, "/") {
				current.parts = append(current.parts, token)
			}
		}
	}
	if current != nil {
		rows = append(rows, current)
	}
	for _, r := range rows {
		item, ok := byName[r.name]
		if !ok {
			item = &Interface{Name: r.name, Physical: r.physical, Protocol: r.protocol}
			order = append(order, r.name)
			byName[r.name] = item
		}
		if item.Physical == "" {
			item.Physical = r.physical
		}
		if item.Protocol == "" {
			item.Protocol = r.protocol
		}
		joined := strings.TrimSpace(strings.Join(r.parts, ""))
		if joined != "" {
			if ip, prefix, ok := parseIPv6Interface(joined); ok && isGlobalIP(ip) {
				item.IPv6 = ip.String()
				item.IPv6Prefix = intPtr(prefix)
			}
		}
	}

	out := make([]Interface, 0, len(byName))
	for _, n := range order {
		out = append(out, *byName[n])
	}
	sort.SliceStable(out, func(i, j int) bool {
		ai := strings.HasPrefix(strings.ToLower(out[i].Name), "dia")
		aj := strings.HasPrefix(strings.ToLower(out[j].Name), "dia")
		if ai != aj {
			return ai
		}
		return out[i].Name < out[j].Name
	})
	if len(out) == 0 {
		return nil, errors.New("SSH 已进入 H3C CLI，但未解析到 IPv4/IPv6 接口")
	}
	return out, nil
}

// parseIPv4Interface accepts "a.b.c.d/len" or "a.b.c.d/m.m.m.m" or bare address.
func parseIPv4Interface(s string) (string, int, bool) {
	addr, mask, hasMask := strings.Cut(s, "/")
	ip, err := netip.ParseAddr(addr)
	if err != nil || !ip.Is4() {
		return "", 0, false
	}
	prefix := 32
	if hasMask {
		if n, err := strconv.Atoi(mask); err == nil {
			if n < 0 || n > 32 {
				return "", 0, false
			}
			prefix = n
		} else if m, err := netip.ParseAddr(mask); err == nil && m.Is4() {
			ones, bits := net.IPMask(m.AsSlice()).Size()
			if bits == 0 {
				return "", 0, false
			}
			prefix = ones
		} else {
			return "", 0, false
		}
	}
	return ip.String(), prefix, true
}

func parseIPv6Interface(s string) (netip.Addr, int, bool) {
	addr, pl, has := strings.Cut(s, "/")
	ip, err := netip.ParseAddr(addr)
	if err != nil || !ip.Is6() || ip.Is4In6() {
		return netip.Addr{}, 0, false
	}
	prefix := 128
	if has {
		n, err := strconv.Atoi(pl)
		if err != nil || n < 0 || n > 128 {
			return netip.Addr{}, 0, false
		}
		prefix = n
	}
	return ip, prefix, true
}

// ---------------- First-login password change ----------------

var h3cPwdUpper = regexp.MustCompile(`[A-Z]`)
var h3cPwdLower = regexp.MustCompile(`[a-z]`)
var h3cPwdDigit = regexp.MustCompile(`[0-9]`)
var h3cPwdOther = regexp.MustCompile(`[^A-Za-z0-9]`)

func validateH3CPassword(username, password string) error {
	if len([]rune(password)) < 8 {
		return errors.New("新密码至少 8 位")
	}
	if strings.Contains(strings.ToLower(password), strings.ToLower(username)) {
		return errors.New("新密码不能包含用户名")
	}
	groups := 0
	for _, re := range []*regexp.Regexp{h3cPwdLower, h3cPwdUpper, h3cPwdDigit, h3cPwdOther} {
		if re.MatchString(password) {
			groups++
		}
	}
	if groups < 2 {
		return errors.New("新密码至少包含两类字符：大写/小写/数字/特殊字符")
	}
	return nil
}

func changeFirstLoginPassword(d *Device, newPassword string) error {
	if err := validateH3CPassword(d.Username, newPassword); err != nil {
		return err
	}
	defer lockDevice(d.ID)()
	oldPassword, err := decryptSecret(d.PasswordEnc)
	if err != nil {
		return err
	}
	if oldPassword == "" {
		return errors.New("当前保存的 SSH 初始密码为空")
	}
	auth := &authState{password: oldPassword, oldPassword: oldPassword, newPassword: newPassword, changeMode: true}
	sc, err := openShell(d, auth)
	if err != nil {
		if strings.Contains(err.Error(), "unable to authenticate") {
			return errors.New("当前保存的 SSH 初始密码错误")
		}
		if errors.Is(err, errHostKeyChanged) {
			return describeAuthError(err, auth)
		}
		return fmt.Errorf("SSH 连接失败：%v", err)
	}
	defer sc.Close()
	child := sc.exp
	cliPrompt := regexp.MustCompile(`<[^>\r\n]+>\s*$`)

	if auth.changeSeen {
		// Password change was completed inside keyboard-interactive auth.
		if child.Expect(15*time.Second, cliPrompt) < 0 {
			return errors.New("H3C 首次改密后未返回 CLI 提示符")
		}
		child.SendLine("quit")
		child.Expect(5 * time.Second)
		return nil
	}

	switch child.Expect(15*time.Second, firstLoginRE, cliPrompt, regexp.MustCompile(`Permission denied`), regexp.MustCompile(`(?i)incorrect`)) {
	case 0:
	case 1:
		child.SendLine("quit")
		return errors.New("该账号已经完成首次改密；无需再次执行首次改密向导")
	case 2, 3:
		return errors.New("当前保存的 SSH 初始密码错误")
	case expEOF:
		return errors.New("SSH 会话异常关闭")
	default:
		return errors.New("等待 H3C 首次改密提示超时")
	}
	step := func(re string, send string, what string) error {
		if child.Expect(15*time.Second, regexp.MustCompile(re)) != 0 {
			return fmt.Errorf("等待 H3C %s 提示超时或连接中断", what)
		}
		child.SendLine(send)
		return nil
	}
	if err := step(`Old password:\s*$`, oldPassword, "Old password"); err != nil {
		return err
	}
	if err := step(`New password:\s*$`, newPassword, "New password"); err != nil {
		return err
	}
	if err := step(`Confirm:\s*$`, newPassword, "Confirm"); err != nil {
		return err
	}
	switch child.Expect(15*time.Second,
		regexp.MustCompile(`Updating user information`),
		regexp.MustCompile(`The password must`),
		regexp.MustCompile(`Incorrect old password`),
		regexp.MustCompile(`Failed`)) {
	case 0:
	case 1:
		return errors.New("H3C 拒绝新密码：不符合设备密码策略")
	case 2:
		return errors.New("H3C 报告旧密码错误")
	default:
		return errors.New("H3C 首次改密失败")
	}
	if child.Expect(15*time.Second, cliPrompt) < 0 {
		return errors.New("H3C 首次改密后未返回 CLI 提示符")
	}
	child.SendLine("quit")
	child.Expect(5 * time.Second)
	return nil
}
