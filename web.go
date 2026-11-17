package main

import (
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"html"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const sessionLifetime = 43200 * time.Second

type Session struct {
	UserID   int64       `json:"uid,omitempty"`
	Username string      `json:"u,omitempty"`
	CSRF     string      `json:"c,omitempty"`
	Flashes  [][2]string `json:"f,omitempty"`
	Exp      int64       `json:"e,omitempty"`
}

type Ctx struct {
	W     http.ResponseWriter
	R     *http.Request
	S     *Session
	dirty bool
	saved bool
}

func loadSession(r *http.Request) *Session {
	s := &Session{}
	ck, err := r.Cookie("session")
	if err != nil {
		return s
	}
	data, ok := unsignValue(ck.Value)
	if !ok {
		return s
	}
	if json.Unmarshal(data, s) != nil || (s.Exp != 0 && time.Now().Unix() > s.Exp) {
		return &Session{}
	}
	return s
}

func (c *Ctx) saveSession() {
	if c.saved {
		return
	}
	c.saved = true
	if !c.dirty && c.S.UserID == 0 {
		return
	}
	c.S.Exp = time.Now().Add(sessionLifetime).Unix()
	b, _ := json.Marshal(c.S)
	http.SetCookie(c.W, &http.Cookie{
		Name: "session", Value: signValue(b), Path: "/", HttpOnly: true,
		SameSite: http.SameSiteLaxMode, MaxAge: int(sessionLifetime.Seconds()),
	})
}

func (c *Ctx) clearSession() {
	c.S = &Session{}
	c.dirty = true
}

func (c *Ctx) csrfToken() string {
	if c.S.CSRF == "" {
		c.S.CSRF = randomURLSafe(32)
		c.dirty = true
	}
	return c.S.CSRF
}

func (c *Ctx) verifyCSRF() bool {
	tok := c.R.FormValue("_csrf")
	if tok == "" {
		tok = c.R.Header.Get("X-CSRF-Token")
	}
	if tok == "" || c.S.CSRF == "" || subtle.ConstantTimeCompare([]byte(tok), []byte(c.S.CSRF)) != 1 {
		c.saveSession()
		http.Error(c.W, "CSRF validation failed", http.StatusBadRequest)
		return false
	}
	return true
}

func (c *Ctx) flash(msg, category string) {
	c.S.Flashes = append(c.S.Flashes, [2]string{category, zhErr(msg)})
	c.dirty = true
}

func (c *Ctx) popFlashes() [][2]string {
	f := c.S.Flashes
	if len(f) > 0 {
		c.S.Flashes = nil
		c.dirty = true
	}
	return f
}

func (c *Ctx) loggedIn() bool { return c.S.UserID != 0 }

func (c *Ctx) redirect(path string) {
	c.saveSession()
	http.Redirect(c.W, c.R, path, http.StatusFound)
}

func (c *Ctx) html(body string) {
	c.saveSession()
	c.W.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = c.W.Write([]byte(body))
}

func (c *Ctx) json(status int, v any) {
	c.saveSession()
	c.W.Header().Set("Content-Type", "application/json")
	c.W.WriteHeader(status)
	_ = json.NewEncoder(c.W).Encode(v)
}

func (c *Ctx) abort(code int) {
	c.saveSession()
	http.Error(c.W, http.StatusText(code), code)
}

func (c *Ctx) pathID(name string) int64 {
	n, _ := strconv.ParseInt(c.R.PathValue(name), 10, 64)
	return n
}

// formInt mirrors Flask's request.form.get(name, type=int): ok=false when missing/invalid.
func (c *Ctx) formInt(name string) (int, bool) {
	v, err := strconv.Atoi(strings.TrimSpace(c.R.FormValue(name)))
	return v, err == nil
}

func (c *Ctx) queryInt(name string) int64 {
	n, _ := strconv.ParseInt(c.R.URL.Query().Get(name), 10, 64)
	return n
}

type handler func(c *Ctx)

func wrap(h handler, requireLogin bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c := &Ctx{W: w, R: r, S: loadSession(r)}
		if requireLogin && !c.loggedIn() {
			c.redirect("/login?next=" + url.QueryEscape(r.URL.Path))
			return
		}
		h(c)
		c.saveSession()
	}
}

func accessControl(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" {
			next.ServeHTTP(w, r)
			return
		}
		cidrs := strings.TrimSpace(getSetting("allowed_web_cidrs", ""))
		if cidrs != "" {
			host, _, err := net.SplitHostPort(r.RemoteAddr)
			if err != nil {
				host = r.RemoteAddr
			}
			ip, err := netip.ParseAddr(host)
			if err != nil {
				http.Error(w, "Forbidden", http.StatusForbidden)
				return
			}
			ip = ip.Unmap()
			allowed := false
			for _, item := range strings.Split(cidrs, ",") {
				item = strings.TrimSpace(item)
				if item == "" {
					continue
				}
				if p, err := parseCIDRLoose(item); err == nil && p.Contains(ip) {
					allowed = true
					break
				}
			}
			if !allowed {
				http.Error(w, fmt.Sprintf("Source IP %s is not allowed", host), http.StatusForbidden)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

// parseCIDRLoose accepts "a.b.c.d/n" (host bits allowed, like strict=False) or a bare IP.
func parseCIDRLoose(s string) (netip.Prefix, error) {
	if !strings.Contains(s, "/") {
		a, err := netip.ParseAddr(s)
		if err != nil {
			return netip.Prefix{}, err
		}
		return netip.PrefixFrom(a, a.BitLen()), nil
	}
	p, err := netip.ParsePrefix(s)
	if err != nil {
		return p, err
	}
	return p.Masked(), nil
}

func newRouter() http.Handler {
	mux := http.NewServeMux()
	auth := func(pattern string, h handler) { mux.HandleFunc(pattern, wrap(h, true)) }
	mux.HandleFunc("/login", wrap(loginHandler, false))
	mux.HandleFunc("GET /logout", wrap(func(c *Ctx) { c.clearSession(); c.redirect("/login") }, false))
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok", "version": Version})
	})

	auth("GET /{$}", dashboardHandler)
	auth("POST /poll-now", pollNowHandler)

	auth("GET /providers", providersHandler)
	auth("POST /provider/save", providerSaveHandler)
	auth("POST /provider/{id}/test", providerTestHandler)
	auth("POST /provider/{id}/delete", providerDeleteHandler)

	auth("GET /devices", devicesHandler)
	auth("POST /device/save", deviceSaveHandler)
	auth("/device/{id}/first-login-password", deviceFirstLoginPasswordHandler)
	auth("POST /device/{id}/toggle", deviceToggleHandler)
	auth("POST /device/{id}/test", deviceTestHandler)
	auth("POST /device/{id}/clear-key", deviceClearKeyHandler)
	auth("POST /device/{id}/delete", deviceDeleteHandler)

	auth("GET /api/live-status", apiLiveStatusHandler)
	auth("GET /api/dashboard", apiDashboardHandler)
	auth("GET /api/devices", apiDevicesHandler)
	auth("GET /api/mappings", apiMappingsHandler)
	auth("GET /dns", dnsPageHandler)
	auth("GET /help", helpHandler)
	auth("GET /api/dns", apiDNSHandler)
	auth("GET /api/provider/{id}/zones", apiZonesHandler)
	auth("GET /api/provider/{id}/zones/{zone_id}/records", apiRecordsHandler)
	auth("GET /api/device/{id}/interfaces", apiInterfacesHandler)

	auth("GET /mappings", mappingsHandler)
	auth("POST /mapping/save", mappingSaveHandler)
	auth("POST /mapping/{id}/sync", mappingSyncHandler)
	auth("POST /mapping/{id}/check", mappingCheckHandler)
	auth("POST /mapping/{id}/delete", mappingDeleteHandler)

	auth("GET /logs", logsHandler)
	auth("POST /logs/cleanup", logsCleanupHandler)
	auth("POST /logs/clear", logsClearHandler)
	auth("GET /backup/download", backupDownloadHandler)
	auth("/settings", settingsHandler)
	auth("POST /change-password", changePasswordHandler)
	auth("GET /selfcheck", selfCheckHandler)
	return accessControl(mux)
}

// ---------------- HTML helpers ----------------

func e(v any) string { return html.EscapeString(fmt.Sprint(v)) }

func sel(b bool) string {
	if b {
		return "selected"
	}
	return ""
}

func ifs(b bool, a, z string) string {
	if b {
		return a
	}
	return z
}

func dash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

var deviceStatusZh = map[string]string{"ONLINE": "在线", "ERROR": "异常", "UNKNOWN": "未检测"}
var mappingStatusZh = map[string]string{"SUCCESS": "正常", "ERROR": "异常", "PENDING": "待同步", "UNKNOWN": "未检测"}
var providerStatusZh = map[string]string{"SUCCESS": "正常", "ERROR": "异常", "UNKNOWN": "未检测"}
var levelZh = map[string]string{"SUCCESS": "成功", "ERROR": "错误", "WARNING": "警告", "INFO": "信息"}
var eventZh = map[string]string{
	"MSR_TEST": "MSR 测试", "MSR_POLL": "MSR 轮询", "MSR_PASSWORD": "MSR 改密", "MSR_ENABLE": "MSR 启用",
	"MSR_DISABLE": "MSR 禁用", "DNS_UPDATE": "DNS 更新", "INTERFACE": "接口检测", "POLLER": "轮询任务",
	"BACKUP": "备份", "HEARTBEAT": "心跳", "DOMAIN_CHECK": "域名检测", "LOG_CLEANUP": "日志清理",
}

func lookupZh(m map[string]string, v string) string {
	if z, ok := m[v]; ok {
		return z
	}
	return v
}

func statusZh(v, kind string) string {
	v = strings.ToUpper(v)
	if v == "" {
		v = "UNKNOWN"
	}
	switch kind {
	case "mapping":
		return lookupZh(mappingStatusZh, v)
	case "provider":
		return lookupZh(providerStatusZh, v)
	}
	return lookupZh(deviceStatusZh, v)
}

func levelZhText(v string) string {
	v = strings.ToUpper(v)
	if v == "" {
		v = "INFO"
	}
	return lookupZh(levelZh, v)
}

func levelClass(v string) string {
	switch v {
	case "SUCCESS":
		return "ok"
	case "ERROR":
		return "bad"
	case "WARNING":
		return "warn"
	}
	return "info"
}

func messageZh(s string) string {
	for _, kv := range [][2]string{
		{" enabled by Web switch", " 已通过网页开关启用"},
		{" disabled by Web switch", " 已通过网页开关禁用"},
		{" first-login password changed from Web wizard", " 已通过网页首次改密向导修改密码"},
		{"Migration bundle downloaded:", "已下载迁移备份："},
		{"interface=", "接口="},
	} {
		s = strings.ReplaceAll(s, kv[0], kv[1])
	}
	return zhErr(s)
}

func detailsZh(s string) string {
	if s == "" {
		return ""
	}
	var items []map[string]any
	if json.Unmarshal([]byte(s), &items) == nil && len(items) > 0 {
		str := func(v any) string {
			if v == nil {
				return ""
			}
			return fmt.Sprint(v)
		}
		phyMap := map[string]string{"up": "已连接", "down": "断开", "*down": "管理关闭"}
		proMap := map[string]string{"up": "正常", "down": "断开", "*down": "关闭"}
		var parts []string
		for _, it := range items {
			name := str(it["name"])
			if _, ok := it["name"]; !ok {
				name = "-"
			}
			phy := phyMap[strings.ToLower(str(it["physical"]))]
			if phy == "" {
				phy = str(it["physical"])
			}
			pro := proMap[strings.ToLower(str(it["protocol"]))]
			if pro == "" {
				pro = str(it["protocol"])
			}
			ipText := func(ipKey, pfxKey string) string {
				ip := str(it[ipKey])
				if ip == "" {
					return "-"
				}
				if p, ok := it[pfxKey]; ok && p != nil {
					return ip + "/" + str(p)
				}
				return ip
			}
			parts = append(parts, fmt.Sprintf("%s：物理=%s，协议=%s，IPv4=%s，IPv6=%s", name, phy, pro, ipText("ip", "prefix"), ipText("ipv6", "ipv6_prefix")))
		}
		return strings.Join(parts, "；")
	}
	return messageZh(s)
}

func domainStatusZh(dnsStatus, reach string) (string, string) {
	dnsStatus = strings.ToUpper(dnsStatus)
	reach = strings.ToUpper(reach)
	var base, cls string
	switch dnsStatus {
	case "ERROR":
		return "解析异常", "bad"
	case "PROPAGATING":
		base, cls = "DNS传播中", "warn"
	case "DEGRADED":
		base, cls = "DNS验证不足", "warn"
	case "SUCCESS":
		base, cls = "解析正常", "ok"
	default:
		return "未检测", "warn"
	}
	switch reach {
	case "TCP_OK":
		return base + " / TCP可达", "ok"
	case "TCP_FAIL":
		return base + " / TCP不可达", "warn"
	case "PING_OK":
		return base + " / ICMP可达", "ok"
	case "PING_FAIL":
		return base + " / ICMP无响应", "warn"
	}
	return base, cls
}

func statusClass(v, okValue string) string {
	if v == okValue {
		return "ok"
	}
	if v == "ERROR" {
		return "bad"
	}
	return "warn"
}

var navItems = [][3]string{
	{"dashboard", "/", "仪表盘"},
	{"devices", "/devices", "MSR 设备"},
	{"providers", "/providers", "DNS 服务商"},
	{"mappings", "/mappings", "DNS 映射"},
	{"dns_page", "/dns", "DNS 解析"},
	{"logs_page", "/logs", "日志"},
	{"settings_page", "/settings", "设置"},
	{"help_page", "/help", "帮助"},
}

// csrfForm renders a one-button POST form.
func (c *Ctx) csrfForm(action, btnClass, label, confirm string) string {
	onsubmit := ""
	if confirm != "" {
		onsubmit = fmt.Sprintf(` onsubmit="return confirm('%s')"`, confirm)
	}
	cls := ""
	if btnClass != "" {
		cls = fmt.Sprintf(` class="%s"`, btnClass)
	}
	return fmt.Sprintf(`<form method="post" action="%s"%s><input type="hidden" name="_csrf" value="%s"><button%s>%s</button></form>`,
		action, onsubmit, e(c.csrfToken()), cls, label)
}

func (c *Ctx) csrfInput() string {
	return `<input type="hidden" name="_csrf" value="` + e(c.csrfToken()) + `">`
}

// submitGuardJS prevents double submission of slow actions (each extra click
// would be another SSH login to the MSR). Buttons are disabled after the form
// data has been captured so the clicked button's name/value is still sent.
const submitGuardJS = `<script>
document.addEventListener('submit', function (ev) {
  const f = ev.target;
  if (ev.defaultPrevented) return;
  if (f.dataset.busy === '1') { ev.preventDefault(); return; }
  f.dataset.busy = '1';
  const clicked = ev.submitter;
  setTimeout(function () {
    f.querySelectorAll('button').forEach(function (b) {
      b.disabled = true;
      if (b === clicked || (!clicked && b.type !== 'button')) { b.dataset.label = b.textContent; b.textContent = '处理中…'; }
    });
  }, 0);
});
window.addEventListener('pageshow', function () {
  document.querySelectorAll('form[data-busy="1"]').forEach(function (f) {
    f.dataset.busy = '';
    f.querySelectorAll('button').forEach(function (b) { b.disabled = false; if (b.dataset.label) b.textContent = b.dataset.label; });
  });
});
</script>`

const jsFmtDuration = `
    function fmtDuration(sec) {
      sec = Math.max(0, Math.floor(Number(sec) || 0));
      const d = Math.floor(sec / 86400); sec %= 86400;
      const h = Math.floor(sec / 3600); sec %= 3600;
      const m = Math.floor(sec / 60);
      const s = sec % 60;
      let out = '';
      if (d) out += d + '天';
      if (h || d) out += h + '小时';
      if (m || h || d) out += m + '分';
      out += s + '秒';
      return out;
    }
`

func jsonUnmarshalString(s string, v any) error { return json.Unmarshal([]byte(s), v) }

// formBack is where a failed form submission returns to: the same form, opened again.
func formBack(base string, id int64) string {
	if id != 0 {
		return fmt.Sprintf("%s?edit=%d", base, id)
	}
	return base + "?new=1"
}
