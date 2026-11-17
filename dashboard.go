package main

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// ---------------- Dashboard ----------------
//
// The page is one server-rendered fragment (#live). The browser re-fetches
// /api/dashboard every 5 seconds and swaps the fragment when it changed, so
// there is a single rendering path for first paint and live updates.

func dashboardHandler(c *Ctx) {
	c.html(c.layout("仪表盘", liveRegion("live", "/api/dashboard", "dashboard", renderDashboard(c)), "dashboard"))
}

func apiDashboardHandler(c *Ctx) { c.fragment("dashboard", renderDashboard(c)) }

type dashIssue struct {
	sev               int // 2 = error, 1 = warning
	title, detail, ts string
	href, action      string
}

type mappingView struct {
	label, cls, note string
	sev              int
}

// viewMapping folds sync status, device state and domain checks into one state.
func viewMapping(m *Mapping, d *Device) mappingView {
	dl, _ := domainStatusZh(m.DNSStatus, m.ReachabilityStatus)
	switch {
	case !m.Enabled:
		return mappingView{"已停用", "", "", 0}
	case d != nil && !d.Enabled:
		return mappingView{"设备已停用", "warn", "所属 MSR 已停用，暂停同步", 1}
	case d != nil && d.LastStatus == "ERROR":
		return mappingView{"设备离线", "warn", "MSR 无法连接，显示的是上次结果", 1}
	case m.LastStatus == "ERROR":
		return mappingView{"同步失败", "bad", m.LastError, 2}
	case m.LastStatus == "PENDING" || m.LastStatus == "UNKNOWN" || m.LastStatus == "":
		return mappingView{"等待同步", "info", "下一轮轮询时同步", 0}
	}
	switch strings.ToUpper(m.DNSStatus) {
	case "ERROR":
		note := "公共 DNS 解析结果与当前 IP 不一致"
		if m.DNSResolved != "" {
			note = "公共 DNS：" + m.DNSResolved
		}
		return mappingView{"解析异常", "bad", note, 2}
	case "PROPAGATING":
		return mappingView{"传播中", "info", "记录已更新，等待各地 DNS 缓存过期", 0}
	case "DEGRADED":
		return mappingView{"验证不足", "warn", dl, 1}
	case "SUCCESS":
	default:
		return mappingView{"等待检测", "info", "", 0}
	}
	switch strings.ToUpper(m.ReachabilityStatus) {
	case "TCP_FAIL", "PING_FAIL":
		note := dl
		if m.ReachabilityError != "" {
			note += "：" + zhErr(m.ReachabilityError)
		}
		return mappingView{"线路不可达", "warn", note, 1}
	}
	return mappingView{"正常", "ok", dl, 0}
}

func isDialer(name string) bool { return strings.HasPrefix(strings.ToLower(name), "dia") }

func ifaceUp(i Interface) bool { return strings.HasPrefix(strings.ToLower(i.Protocol), "up") }

func renderDashboard(c *Ctx) string {
	devices := queryDevices("ORDER BY id")
	mappings := queryMappings("ORDER BY m.id")
	providers := queryProviders("ORDER BY id")
	runtime := runtimeStateMap()

	devByID := map[int64]*Device{}
	devIfaces := map[int64][]Interface{}
	enDev, enMap, onlineDev, linesUp, linesAll := 0, 0, 0, 0, 0
	for _, d := range devices {
		devByID[d.ID] = d
		var ifs []Interface
		_ = jsonUnmarshalString(d.LastInterfacesJSON, &ifs)
		devIfaces[d.ID] = ifs
		if !d.Enabled {
			continue
		}
		enDev++
		if d.LastStatus == "ONLINE" {
			onlineDev++
			for _, i := range ifs {
				if isDialer(i.Name) {
					linesAll++
					if ifaceUp(i) {
						linesUp++
					}
				}
			}
		}
	}

	views := map[int64]mappingView{}
	healthy := 0
	for _, m := range mappings {
		v := viewMapping(m, devByID[m.DeviceID])
		views[m.ID] = v
		if m.Enabled {
			enMap++
			if v.cls == "ok" || v.label == "传播中" {
				healthy++
			}
		}
	}

	// ---- issues needing attention ----
	hb := computeHeartbeat(runtime, enDev > 0 || enMap > 0)
	var issues []dashIssue
	hbEpoch := parseFloat(runtime["last_heartbeat_epoch"], 0)
	if (enDev > 0 || enMap > 0) && !hb.ok && hbEpoch > 0 {
		issues = append(issues, dashIssue{2, "后台调度超时", fmt.Sprintf("超过 %d 秒没有完成一轮轮询。可在服务器执行 huboze-ddns-agent logs 查看原因。", hb.interval*2+15),
			runtime["last_heartbeat"], "/selfcheck", "运行自检"})
	}
	for _, d := range devices {
		switch {
		case d.Enabled && d.LastStatus == "ERROR":
			issues = append(issues, dashIssue{2, d.Name + " 无法连接", d.LastError, d.LastSeen, "/devices", "查看设备"})
		case !d.Enabled && d.LastError != "" && isLockoutRisk(fmt.Errorf("%s", d.LastError)):
			issues = append(issues, dashIssue{1, d.Name + " 已自动停用", "为避免 H3C 账号被反复锁定，管家已停用该设备：" + d.LastError, d.LastSeen, "/devices", "处理"})
		}
	}
	for _, p := range providers {
		if p.Enabled && p.LastStatus == "ERROR" {
			issues = append(issues, dashIssue{2, p.Name + " API 调用失败", p.LastError, "", "/providers", "检查凭据"})
		}
	}
	for _, m := range mappings {
		v := views[m.ID]
		if !m.Enabled || v.sev == 0 || v.label == "设备离线" || v.label == "设备已停用" {
			continue // device problems are reported once, on the device
		}
		href, act := "/mappings", "查看映射"
		if v.label == "解析异常" || v.label == "线路不可达" || v.label == "验证不足" {
			href, act = "/dns", "查看解析"
		}
		issues = append(issues, dashIssue{v.sev, m.RecordName + " " + v.label, v.note, ifs(m.LastCheck != "", m.LastCheck, m.LastSync), href, act})
	}
	sort.SliceStable(issues, func(i, j int) bool { return issues[i].sev > issues[j].sev })
	errs, warns := 0, 0
	for _, x := range issues {
		if x.sev == 2 {
			errs++
		} else {
			warns++
		}
	}

	var b strings.Builder

	// ---- hero: overall state ----
	state, title, ic := "s-ok", "一切正常", "check"
	switch {
	case len(devices) == 0 && len(mappings) == 0:
		state, title, ic = "s-idle", "还没有开始配置", "clock"
	case errs > 0:
		state, title, ic = "s-bad", fmt.Sprintf("%d 个问题需要处理", errs+warns), "x"
	case warns > 0:
		state, title, ic = "s-warn", fmt.Sprintf("%d 项需要留意", warns), "alert"
	case hbEpoch <= 0 && (enDev > 0 || enMap > 0):
		state, title, ic = "s-idle", "等待首次轮询", "clock"
	case enMap == 0:
		state, title, ic = "s-idle", "已就绪，尚未添加域名映射", "clock"
	}
	sub := "完成下方的快速开始后，管家会自动把 MSR 拨号线路的 IP 同步到 DNS。"
	if len(devices) > 0 || len(mappings) > 0 {
		parts := []string{}
		if hbEpoch > 0 {
			parts = append(parts, "上次检查 "+tsSpan("", runtime["last_heartbeat"]))
		} else {
			parts = append(parts, "尚未运行")
		}
		parts = append(parts, fmt.Sprintf("每 %d 秒自动检查", hb.interval))
		if r := runtime["last_poll_result"]; r != "" {
			parts = append(parts, "上一轮："+e(r))
		}
		if ms, err := strconv.Atoi(runtime["last_poll_duration_ms"]); err == nil && ms > 0 {
			parts = append(parts, fmt.Sprintf("耗时 %.1f 秒", float64(ms)/1000))
		}
		sub = strings.Join(parts, " · ")
	}
	pollBtn := ""
	if len(devices) > 0 {
		pollBtn = `<form method="post" action="/poll-now">` + c.csrfInput() + `<button>` + icon("refresh") + `立即检查</button></form>`
	}
	fmt.Fprintf(&b, `<section class="hero %s"><div class="hero-main"><div class="hero-icon">%s</div><div class="hero-text"><div class="hero-title">%s</div><div class="hero-sub">%s</div></div>%s</div>`,
		state, icon(ic), e(title), sub, pollBtn)
	kpi := func(href, label string, n, total int, showRatio bool) string {
		val := strconv.Itoa(n)
		bar := ""
		if showRatio {
			val += `<small>/ ` + strconv.Itoa(total) + `</small>`
			pct, cls := 0, "none"
			if total > 0 {
				pct = n * 100 / total
				cls = ifs(n == total, "", ifs(n == 0, "bad", "warn"))
			}
			bar = fmt.Sprintf(`<span class="bar %s"><i style="width:%d%%"></i></span>`, cls, pct)
		}
		return fmt.Sprintf(`<a class="kpi" href="%s"><div class="kpi-label">%s</div><div class="kpi-val">%s</div>%s</a>`, href, e(label), val, bar)
	}
	b.WriteString(`<div class="kpis">`)
	b.WriteString(kpi("/devices", "MSR 在线", onlineDev, enDev, true))
	b.WriteString(kpi("/devices", "拨号线路连通", linesUp, linesAll, true))
	b.WriteString(kpi("/mappings", "域名正常", healthy, enMap, true))
	pOK := 0
	for _, p := range providers {
		if p.Enabled && p.LastStatus != "ERROR" {
			pOK++
		}
	}
	b.WriteString(kpi("/providers", "DNS 服务商可用", pOK, len(providers), true))
	b.WriteString(`</div></section>`)

	// ---- onboarding (until set up) ----
	b.WriteString(onboardingCard(providers, devices, mappings))

	// ---- issues ----
	if len(issues) > 0 {
		fmt.Fprintf(&b, `<section class="card"><div class="card-head"><h2>需要处理<span class="count">%d</span></h2></div><div class="issues">`, len(issues))
		for _, x := range issues {
			ts := ""
			if x.ts != "" {
				ts = tsSpan("", x.ts)
			}
			fmt.Fprintf(&b, `<div class="issue"><span class="dot %s"></span><div><div class="issue-title">%s</div><div class="issue-detail">%s</div></div><div class="issue-side">%s<a class="btn btn2 small" href="%s">%s</a></div></div>`,
				ifs(x.sev == 2, "bad", "warn"), e(x.title), clip(x.detail, 90), ts, x.href, e(x.action))
		}
		b.WriteString(`</div></section>`)
	}

	if len(devices) == 0 && len(mappings) == 0 {
		return b.String() + recentEvents() + sysLine(runtime)
	}

	// ---- domains + lines ----
	b.WriteString(`<div class="dash-cols">`)
	b.WriteString(domainsCard(mappings, views, devByID))
	b.WriteString(linesCard(devices, devIfaces, mappings, views))
	b.WriteString(`</div>`)
	b.WriteString(recentEvents())
	b.WriteString(sysLine(runtime))
	return b.String()
}

func domainsCard(mappings []*Mapping, views map[int64]mappingView, devByID map[int64]*Device) string {
	var b strings.Builder
	fmt.Fprintf(&b, `<section class="card"><div class="card-head"><div><h2>域名<span class="count">%d</span></h2></div><a class="btn btn2 small" href="/mappings">管理映射</a></div>`, len(mappings))
	if len(mappings) == 0 {
		b.WriteString(emptyState("还没有域名映射", "把 MSR 的拨号接口绑定到一个域名，IP 变化时自动更新解析。", "/mappings?new=1#form", "添加映射"))
		b.WriteString(`</section>`)
		return b.String()
	}
	sorted := append([]*Mapping(nil), mappings...)
	sort.SliceStable(sorted, func(i, j int) bool {
		a, z := views[sorted[i].ID], views[sorted[j].ID]
		if a.sev != z.sev {
			return a.sev > z.sev
		}
		return sorted[i].Enabled && !sorted[j].Enabled
	})
	b.WriteString(`<div class="tbl"><table class="stack"><tr><th>域名 / 线路</th><th>当前 IP</th><th>状态</th><th>最近同步</th></tr>`)
	for _, m := range sorted {
		v := views[m.ID]
		dev := "-"
		if d := devByID[m.DeviceID]; d != nil {
			dev = d.Name
		}
		ip := `<span class="muted">-</span>`
		if m.CurrentIP != "" {
			ip = e(m.CurrentIP)
			if m.LastSyncedIP != "" && !sameIP(m.LastSyncedIP, m.CurrentIP) {
				ip += `<div class="sub warn">DNS 中仍为 ` + e(m.LastSyncedIP) + `</div>`
			}
		} else if m.LastSyncedIP != "" {
			ip = `<span class="muted">` + e(m.LastSyncedIP) + `</span><div class="sub">上次同步的 IP</div>`
		}
		note := ""
		if v.note != "" && v.sev == 0 && v.cls == "ok" {
			note = `<div class="sub">` + e(v.note) + `</div>`
		} else if v.note != "" {
			note = `<div class="sub">` + clip(v.note, 28) + `</div>`
		}
		fmt.Fprintf(&b, `<tr><td title="映射：%s"><div class="dom-name">%s <span class="tag">%s</span></div><div class="sub nm">%s · %s</div></td>
<td class="ipc">%s</td><td style="min-width:160px">%s%s</td>
<td class="nm">%s<div class="sub">检测 %s</div></td></tr>`,
			e(m.Name), e(m.RecordName), e(m.RecordType), e(dev), e(m.InterfaceName), ip,
			pill(v.label, v.cls), note, tsSpan("", m.LastSync), tsSpan("", m.LastCheck))
	}
	b.WriteString(`</table></div></section>`)
	return b.String()
}

func linesCard(devices []*Device, devIfaces map[int64][]Interface, mappings []*Mapping, views map[int64]mappingView) string {
	var b strings.Builder
	fmt.Fprintf(&b, `<section class="card"><div class="card-head"><h2>MSR 线路<span class="count">%d</span></h2><a class="btn btn2 small" href="/devices">管理设备</a></div>`, len(devices))
	if len(devices) == 0 {
		b.WriteString(emptyState("还没有 MSR 设备", "添加 H3C MSR 的管理地址和 SSH 账号。", "/devices?new=1#form", "添加设备") + `</section>`)
		return b.String()
	}
	// domains bound to each device/interface
	bound := map[string][]*Mapping{}
	for _, m := range mappings {
		k := fmt.Sprintf("%d/%s", m.DeviceID, m.InterfaceName)
		bound[k] = append(bound[k], m)
	}
	for _, d := range devices {
		label, cls := "在线", "ok"
		switch {
		case !d.Enabled:
			label, cls = "已停用", ""
		case d.LastStatus == "ERROR":
			label, cls = "无法连接", "bad"
		case d.LastStatus != "ONLINE":
			label, cls = "未检测", "info"
		}
		meta := e(d.Host)
		if d.Port != 0 && d.Port != 22 {
			meta += ":" + strconv.Itoa(d.Port)
		}
		if s := onlineSeconds(d); s > 0 {
			meta += " · 已在线 " + humanDuration(s)
		} else if d.LastSeen != "" {
			meta += " · 最后连接 " + tsSpan("", d.LastSeen)
		}
		fmt.Fprintf(&b, `<div class="dev"><div class="dev-head"><h3>%s</h3>%s</div><div class="sub">%s</div>`, e(d.Name), pill(label, cls), meta)
		stale := d.LastStatus != "ONLINE"
		n := 0
		b.WriteString(`<div class="lines">`)
		for _, i := range devIfaces[d.ID] {
			if !isDialer(i.Name) {
				continue
			}
			n++
			dc := ifs(ifaceUp(i), "ok", "bad")
			state := ifs(ifaceUp(i), "", ` <span class="bad" style="font-size:12px">未连通</span>`)
			if stale {
				dc, state = "", ` <span class="muted" style="font-size:12px">上次数据</span>`
			}
			ips := ""
			if i.IP != "" {
				ips += `<div class="line-ip">` + e(i.IP) + `</div>`
			}
			if i.IPv6 != "" {
				ips += `<div class="line-ip v6">` + e(i.IPv6) + `</div>`
			}
			if ips == "" {
				ips = `<div class="line-ip v6">无公网地址</div>`
			}
			var chips strings.Builder
			for _, m := range bound[fmt.Sprintf("%d/%s", d.ID, i.Name)] {
				v := views[m.ID]
				cc := ""
				if m.Enabled && v.sev > 0 {
					cc = ifs(v.sev == 2, "bad", "warn")
				}
				fmt.Fprintf(&chips, `<span class="chip %s" title="%s %s · %s">%s</span>`, cc, e(m.RecordName), e(m.RecordType), e(v.label), e(m.RecordName))
			}
			fmt.Fprintf(&b, `<div class="line"><span class="dot %s"></span><div><div class="line-name">%s%s</div>%s</div><div class="chips">%s</div></div>`,
				dc, e(i.Name), state, ips, chips.String())
		}
		if n == 0 {
			b.WriteString(`<div class="line"><span class="dot"></span><div class="muted">还没有发现 Dialer 拨号接口，到“MSR 设备”页点击“测试/发现接口”。</div><div></div></div>`)
		}
		b.WriteString(`</div></div>`)
	}
	b.WriteString(`</section>`)
	return b.String()
}

func recentEvents() string {
	var b strings.Builder
	b.WriteString(`<section class="card"><div class="card-head"><h2>最近事件</h2><a class="btn btn2 small" href="/logs">全部日志</a></div><div class="events">`)
	n := 0
	rows, err := DB.Query("SELECT ts,level,event,message FROM logs ORDER BY id DESC LIMIT 8")
	if err == nil {
		for rows.Next() {
			var ts, lv, ev, msg string
			if rows.Scan(&ts, &lv, &ev, &msg) != nil {
				continue
			}
			n++
			fmt.Fprintf(&b, `<div class="event"><span class="dot %s" title="%s"></span><div class="event-msg">%s</div><div class="event-meta">%s · %s</div></div>`,
				levelClass(lv), e(levelZhText(lv)), clip(messageZh(msg), 120), e(lookupZh(eventZh, ev)), tsSpan("", ts))
		}
		rows.Close()
	}
	if n == 0 {
		b.WriteString(`<div class="muted">暂无事件。</div>`)
	}
	b.WriteString(`</div></section>`)
	return b.String()
}

func sysLine(runtime map[string]string) string {
	started := runtime["service_started_at"]
	s := fmt.Sprintf(`<div class="sysline"><span>v%s 已运行 %s</span>`, Version, humanDuration(sessionUptime()))
	if started != "" {
		s += `<span>启动于 ` + e(started) + `</span>`
	}
	if hu := hostUptimeSeconds(); hu > 0 {
		s += `<span>服务器已开机 ` + humanDuration(hu) + `</span>`
	}
	if pc := runtime["poll_count"]; pc != "" && pc != "0" {
		s += `<span>累计检查 ` + e(pc) + ` 轮</span>`
	}
	return s + `</div>`
}

// onboardingCard guides a new installation through the setup steps; hidden once complete.
func onboardingCard(providers []*Provider, devices []*Device, mappings []*Mapping) string {
	tested := false
	for _, d := range devices {
		if d.LastStatus == "ONLINE" || d.LastInterfacesJSON != "[]" && d.LastInterfacesJSON != "" {
			tested = true
		}
	}
	steps := []struct {
		done              bool
		title, desc, href string
	}{
		{len(providers) > 0, "① 添加 DNS 服务商", "Cloudflare / 腾讯云 / 阿里云 / 华为云，建议使用只授权 DNS 的 API 凭据。", "/providers?new=1#form"},
		{len(devices) > 0, "② 添加 MSR 设备", "填写管理 IP 与 SSH 账号；要求首次登录改密的设备用“首次登录改密”。", "/devices"},
		{tested, "③ 测试并发现接口", "确认能读取 Dialer 拨号接口的 IPv4 / IPv6 地址。", "/devices"},
		{len(mappings) > 0, "④ 创建域名映射", "把拨号接口绑定到域名，保存时自动创建或更新解析记录。", "/mappings?new=1#form"},
	}
	all := true
	for _, s := range steps {
		all = all && s.done
	}
	if all {
		return ""
	}
	var b strings.Builder
	b.WriteString(`<section class="card"><div class="card-head"><div><h2>快速开始</h2><div class="muted">完成以下 4 步，管家就会按周期自动同步 DNS。</div></div><a class="btn btn2 small" href="/help">了解工作原理</a></div><div class="steps">`)
	nextMarked := false
	for _, s := range steps {
		cls := ""
		if s.done {
			cls = "done"
		} else if !nextMarked {
			cls, nextMarked = "next", true
		}
		link := ""
		if !s.done {
			link = `<div style="margin-top:10px"><a class="btn small` + ifs(cls == "next", "", " btn2") + `" href="` + s.href + `">去完成 →</a></div>`
		}
		fmt.Fprintf(&b, `<div class="step %s"><b>%s</b><div class="muted">%s</div>%s</div>`, cls, e(s.title), e(s.desc), link)
	}
	b.WriteString(`</div></section>`)
	return b.String()
}
