package main

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"strings"
	"time"
)

// ---------------- Auth ----------------

func loginHandler(c *Ctx) {
	if c.R.Method == "POST" {
		if !c.verifyCSRF() {
			return
		}
		username := strings.TrimSpace(c.R.FormValue("username"))
		password := c.R.FormValue("password")
		var id int64
		var uname, hash string
		err := DB.QueryRow("SELECT id,username,password_hash FROM users WHERE username=?", username).Scan(&id, &uname, &hash)
		if err == nil && checkPasswordHash(hash, password) {
			c.clearSession()
			c.S.UserID, c.S.Username = id, uname
			c.csrfToken()
			c.redirect("/")
			return
		}
		c.flash("用户名或密码错误", "error")
	} else if c.R.Method != "GET" {
		c.abort(405)
		return
	}
	token := c.csrfToken()
	var msgs strings.Builder
	for _, f := range c.popFlashes() {
		fmt.Fprintf(&msgs, `<div class="msg %s">%s</div>`, e(f[0]), e(f[1]))
	}
	body := `<div class="login"><div class="card">` + brandHTML + `
      <div class="muted" style="margin:0 0 20px">H3C MSR 多线路 DDNS 管理面板</div>` + msgs.String() + `
      <form method="post">
        <input type="hidden" name="_csrf" value="` + e(token) + `">
        <label>用户名<input name="username" value="admin" autocomplete="username"></label>
        <label>密码<input name="password" type="password" autocomplete="current-password" autofocus></label>
        <button type="submit">登录</button>
      </form>
    </div></div>`
	c.html(`<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>登录 - huboze DDNS Agent</title>` + baseStyle + `</head>
    <body>` + body + `</body></html>`)
}

// ---------------- shared live-status computations ----------------

type heartbeatInfo struct {
	interval int
	ok       bool
	text     string
}

func computeHeartbeat(runtime map[string]string, hasTasks bool) heartbeatInfo {
	interval := getSettingInt("poll_interval", 60)
	hbEpoch := parseFloat(runtime["last_heartbeat_epoch"], 0)
	limit := float64(interval*2 + 15)
	if limit < 90 {
		limit = 90
	}
	h := heartbeatInfo{interval: interval}
	if hbEpoch > 0 {
		age := epochNow() - hbEpoch
		h.ok = age <= limit
	}
	switch {
	case h.ok && hasTasks:
		h.text = "调度器正常"
	case h.ok:
		h.text = "调度器正常（当前无任务）"
	case hbEpoch <= 0:
		h.text = "等待首次调度"
	default:
		h.text = "调度器超时"
	}
	return h
}

func sessionUptime() int { return int(time.Since(processStarted).Seconds()) }

func onlineSeconds(d *Device) int {
	if d.LastStatus != "ONLINE" || d.OnlineSince == "" {
		return 0
	}
	loc := currentLocation()
	t, err := time.ParseInLocation(tsLayout, d.OnlineSince, loc)
	if err != nil {
		return 0
	}
	now, _ := time.ParseInLocation(tsLayout, time.Now().In(loc).Format(tsLayout), loc)
	s := int(now.Sub(t).Seconds())
	if s < 0 {
		return 0
	}
	return s
}

func diaText(raw string) string {
	var ifaces []Interface
	if json.Unmarshal([]byte(raw), &ifaces) != nil {
		return ""
	}
	var parts []string
	for _, i := range ifaces {
		if strings.HasPrefix(strings.ToLower(i.Name), "dia") {
			parts = append(parts, ifaceIPText(i))
		}
	}
	return strings.Join(parts, "\n")
}

func ifaceIPText(i Interface) string {
	v4, v6 := i.IP, i.IPv6
	if v4 == "" {
		v4 = "未获取"
	}
	if v6 == "" {
		v6 = "未获取"
	}
	return fmt.Sprintf("%s=IPv4:%s/IPv6:%s", i.Name, v4, v6)
}

func pollNowHandler(c *Ctx) {
	if !c.verifyCSRF() {
		return
	}
	r := pollOnce(false, 0, 0)
	if r.Success {
		s := r.Summary
		c.flash(fmt.Sprintf("轮询完成：设备 %d，映射 %d，更新 %d，错误 %d", s.Devices, s.Mappings, s.Updated, s.Errors), ifs(s.Errors == 0, "success", "warning"))
	} else {
		msg := r.Message
		if msg == "" {
			msg = "轮询失败"
		}
		c.flash(msg, "warning")
	}
	c.redirect("/")
}

// ---------------- Live status API ----------------

func apiLiveStatusHandler(c *Ctx) {
	devices := queryDevices("ORDER BY id")
	mappings := queryMappings("ORDER BY m.id")
	runtime := runtimeStateMap()
	enDev, enMap := 0, 0
	for _, d := range devices {
		if d.Enabled {
			enDev++
		}
	}
	for _, m := range mappings {
		if m.Enabled {
			enMap++
		}
	}
	hb := computeHeartbeat(runtime, enDev > 0 || enMap > 0)
	su := sessionUptime()
	now := epochNow()
	total := parseFloat(runtime["total_runtime_seconds"], float64(su))
	if last := parseFloat(runtime["last_runtime_tick_epoch"], now); now > last {
		total += now - last
	}
	devList := []map[string]any{}
	for _, d := range devices {
		devList = append(devList, map[string]any{
			"id": d.ID, "enabled": d.Enabled, "status": d.LastStatus, "status_text": statusZh(d.LastStatus, "device"),
			"online_seconds": onlineSeconds(d), "last_seen": d.LastSeen, "dia": diaText(d.LastInterfacesJSON),
		})
	}
	mapList := []map[string]any{}
	for _, m := range mappings {
		dl, _ := domainStatusZh(m.DNSStatus, m.ReachabilityStatus)
		mapList = append(mapList, map[string]any{
			"id": m.ID, "current_ip": m.CurrentIP, "last_synced_ip": m.LastSyncedIP, "status": m.LastStatus,
			"status_text": statusZh(m.LastStatus, "mapping"), "domain_status": dl, "last_check": m.LastCheck, "last_sync": m.LastSync,
		})
	}
	pc := runtime["poll_count"]
	if pc == "" {
		pc = "0"
	}
	dur := runtime["last_poll_duration_ms"]
	if dur == "" {
		dur = "0"
	}
	c.json(200, map[string]any{
		"success": true, "server_epoch": time.Now().Unix(), "poll_interval": hb.interval,
		"heartbeat_ok": hb.ok, "heartbeat_text": hb.text, "last_heartbeat": runtime["last_heartbeat"],
		"poll_count": pc, "last_poll_duration_ms": dur, "session_uptime_seconds": su,
		"host_uptime_seconds": hostUptimeSeconds(), "total_runtime_seconds": int(total),
		"devices": devList, "mappings": mapList,
	})
}

func apiZonesHandler(c *Ctx) {
	p := getProvider(c.pathID("id"))
	if p == nil {
		c.json(404, map[string]any{"success": false, "error": "provider not found"})
		return
	}
	zones, err := providerListZones(p)
	if err != nil {
		c.json(400, map[string]any{"success": false, "error": zhErr(err.Error())})
		return
	}
	if zones == nil {
		zones = []Zone{}
	}
	c.json(200, map[string]any{"success": true, "zones": zones})
}

func apiRecordsHandler(c *Ctx) {
	p := getProvider(c.pathID("id"))
	if p == nil {
		c.json(404, map[string]any{"success": false, "error": "provider not found"})
		return
	}
	zoneName := strings.TrimRight(strings.TrimSpace(c.R.URL.Query().Get("zone_name")), ".")
	rt := strings.ToUpper(strings.TrimSpace(c.R.URL.Query().Get("record_type")))
	recs, err := providerListRecords(p, c.R.PathValue("zone_id"), zoneName, rt)
	if err != nil {
		c.json(400, map[string]any{"success": false, "error": zhErr(err.Error())})
		return
	}
	if recs == nil {
		recs = []DNSRecord{}
	}
	c.json(200, map[string]any{"success": true, "records": recs})
}

func apiInterfacesHandler(c *Ctx) {
	if c.R.URL.Query().Get("cached") == "1" {
		d := getDevice(c.pathID("id"))
		if d == nil {
			c.json(404, map[string]any{"success": false, "error": "device not found"})
			return
		}
		ifaces := []Interface{}
		_ = json.Unmarshal([]byte(d.LastInterfacesJSON), &ifaces)
		c.json(200, map[string]any{"success": true, "interfaces": ifaces, "cached": true})
		return
	}
	ifaces, err := testAndStoreDevice(c.pathID("id"))
	if err != nil {
		c.json(400, map[string]any{"success": false, "error": zhErr(err.Error())})
		return
	}
	c.json(200, map[string]any{"success": true, "interfaces": ifaces})
}

// ---------------- Providers ----------------

func providersHandler(c *Ctx) {
	editID := c.queryInt("edit")
	items := queryProviders("ORDER BY id")
	var edit *Provider
	if editID != 0 {
		edit = getProvider(editID)
	}
	showForm := edit != nil || c.R.URL.Query().Get("new") == "1" || len(items) == 0

	var list strings.Builder
	if len(items) > 0 {
		list.WriteString(`<section class="card"><div class="tbl"><table class="stack"><tr><th>服务商</th><th>状态</th><th>域名映射</th><th>最近错误</th><th>操作</th></tr>`)
		for _, x := range items {
			label, cls := statusZh(x.LastStatus, "provider"), statusClass(x.LastStatus, "SUCCESS")
			if !x.Enabled {
				label, cls = "已停用", ""
			} else if x.LastStatus == "UNKNOWN" || x.LastStatus == "" {
				label, cls = "未测试", "info"
			}
			n := countWhere("SELECT COUNT(*) FROM mappings WHERE provider_id=?", x.ID)
			fmt.Fprintf(&list, `<tr><td><div style="display:flex;gap:12px;align-items:center"><span class="ptype %s">%s</span><div><div class="dom-name">%s</div><div class="sub">%s</div></div></div></td>
<td>%s</td><td>%d 条</td><td class="err">%s</td><td class="act"><div class="actions">%s<a class="btn btn2 small" href="/providers?edit=%d#form">编辑</a>%s</div></td></tr>`,
				e(x.ProviderType), e(providerInitial(x.ProviderType)), e(x.Name), e(providerLabel(x.ProviderType)),
				pill(label, cls), n, ifs(x.LastError == "", `<span class="muted">-</span>`, `<span class="bad">`+clip(x.LastError, 60)+`</span>`),
				c.csrfForm(fmt.Sprintf("/provider/%d/test", x.ID), "small", "测试连接", ""), x.ID,
				moreMenu(c.csrfForm(fmt.Sprintf("/provider/%d/delete", x.ID), "danger small", "删除服务商", "确认删除该 DNS 服务商？")))
		}
		list.WriteString(`</table></div></section>`)
	}

	form := ""
	if showForm {
		editName, editType, editEnabled, editIDStr := "", "cloudflare", true, ""
		region := "cn-north-4"
		saved := ProviderConfig{}
		if edit != nil {
			editName, editType, editEnabled, editIDStr = edit.Name, edit.ProviderType, edit.Enabled, fmt.Sprint(edit.ID)
			if cfg, err := providerConfig(edit); err == nil {
				saved = cfg
				if edit.ProviderType == "huawei" && cfg["region"] != "" {
					region = cfg["region"]
				}
			}
		}
		ph := func(editText, newText string) string { return e(ifs(edit != nil, editText, newText)) }
		var choice strings.Builder
		for _, t := range []string{"cloudflare", "tencent", "aliyun", "huawei"} {
			fmt.Fprintf(&choice, `<label><input type="radio" name="provider_type" value="%s" %s onchange="showProviderFields()"><span class="ptype %s">%s</span>%s</label>`,
				t, ifs(editType == t, "checked", ""), t, providerInitial(t), e(providerLabel(t)))
		}
		form = formCard(ifs(edit != nil, "编辑服务商", "添加 DNS 服务商"), "凭据使用 Fernet 加密保存在本机数据库，编辑时不会回显。", "/providers", `
    <form method="post" action="/provider/save" id="providerForm">
      `+c.csrfInput()+`
      <input type="hidden" name="id" value="`+e(editIDStr)+`">
      <label>服务商类型</label><div class="choice">`+choice.String()+`</div>
      <div class="row">
        <label>名称<input name="name" required value="`+e(editName)+`" placeholder="例如：公司主 DNS"></label>
        <label>状态<select name="enabled"><option value="1" `+sel(editEnabled)+`>启用</option><option value="0" `+sel(!editEnabled)+`>停用</option></select></label>
      </div>
      <div id="fields-cloudflare"><label>API Token`+savedBadge(saved["token"], false)+`<input name="cf_token" type="password" placeholder="`+ph("留空则保持原 Token", "Cloudflare API Token")+`"></label><div class="hint">建议只授予 Zone:DNS:Edit 和 Zone:Zone:Read 权限。</div></div>
      <div id="fields-tencent"><div class="row"><label>SecretId`+savedBadge(saved["secret_id"], true)+`<input name="tc_secret_id" type="password" placeholder="`+ph("留空则保持原 SecretId", "腾讯云 SecretId")+`"></label><label>SecretKey`+savedBadge(saved["secret_key"], false)+`<input name="tc_secret_key" type="password" placeholder="`+ph("留空则保持原 SecretKey", "腾讯云 SecretKey")+`"></label></div><div class="hint">建议使用只授权 DNSPod 的子账号密钥。</div></div>
      <div id="fields-aliyun"><div class="row"><label>AccessKey ID`+savedBadge(saved["access_key_id"], true)+`<input name="ali_access_key_id" type="password" placeholder="`+ph("留空则保持原 AccessKey ID", "阿里云 AccessKey ID")+`"></label><label>AccessKey Secret`+savedBadge(saved["access_key_secret"], false)+`<input name="ali_access_key_secret" type="password" placeholder="`+ph("留空则保持原 Secret", "阿里云 AccessKey Secret")+`"></label></div><div class="hint">建议使用只授予 AliyunDNSFullAccess 的 RAM 用户。</div></div>
      <div id="fields-huawei"><div class="row"><label>Access Key (AK)`+savedBadge(saved["ak"], true)+`<input name="hw_ak" type="password" placeholder="`+ph("留空则保持原 AK", "华为云 AK")+`"></label><label>Secret Key (SK)`+savedBadge(saved["sk"], false)+`<input name="hw_sk" type="password" placeholder="`+ph("留空则保持原 SK", "华为云 SK")+`"></label></div><label>Region<input name="hw_region" value="`+e(region)+`" placeholder="cn-north-4"></label><div class="hint">公网 DNS 是全局资源，一般保持默认的 cn-north-4 即可。</div></div>
      <div class="actions"><button>保存</button></div>
    </form>
    <script>
    function showProviderFields(){
      const t=(document.querySelector('input[name=provider_type]:checked')||{}).value||'cloudflare';
      ['cloudflare','tencent','aliyun','huawei'].forEach(x=>{document.getElementById('fields-'+x).style.display=(x===t?'block':'none');});
    }
    showProviderFields();
    </script>`, len(items) > 0)
	}
	head := ""
	if !showForm {
		head = addButton("/providers?new=1", "添加服务商")
	}
	c.html(c.layoutWith("DNS 服务商", "Cloudflare · 腾讯云 DNSPod · 阿里云 · 华为云", head, form+list.String(), "providers"))
}

func providerInitial(t string) string {
	switch t {
	case "cloudflare":
		return "CF"
	case "tencent":
		return "腾"
	case "aliyun":
		return "阿"
	case "huawei":
		return "华"
	}
	return "?"
}

func providerSaveHandler(c *Ctx) {
	if !c.verifyCSRF() {
		return
	}
	pidInt, _ := c.formInt("id")
	pid := int64(pidInt)
	name := strings.TrimSpace(c.R.FormValue("name"))
	ptype := strings.ToLower(strings.TrimSpace(c.R.FormValue("provider_type")))
	if ptype == "" {
		ptype = "cloudflare"
	}
	enabled := c.R.FormValue("enabled") == "1"
	if _, ok := providerLabels[ptype]; !ok {
		c.flash("不支持的 DNS 服务商类型", "error")
		c.redirect(formBack("/providers", pid))
		return
	}
	if name == "" {
		c.flash("名称不能为空", "error")
		c.redirect(formBack("/providers", pid))
		return
	}
	var old *Provider
	if pid != 0 {
		old = getProvider(pid)
		if old == nil {
			c.abort(404)
			return
		}
	}
	if old != nil && old.ProviderType != ptype && countWhere("SELECT COUNT(*) FROM mappings WHERE provider_id=?", pid) > 0 {
		c.flash("该服务商已有 DNS 映射，不能直接更换服务商类型；请新建服务商。", "error")
		c.redirect(formBack("/providers", pid))
		return
	}
	oldcfg := ProviderConfig{}
	if old != nil {
		if cfg, err := providerConfig(old); err == nil {
			oldcfg = cfg
		}
	}
	keep := func(field, oldkey string) string {
		if v := strings.TrimSpace(c.R.FormValue(field)); v != "" {
			return v
		}
		return oldcfg[oldkey]
	}
	var cfg ProviderConfig
	var required [][2]string
	switch ptype {
	case "cloudflare":
		cfg = ProviderConfig{"token": keep("cf_token", "token")}
		required = [][2]string{{"API Token", cfg["token"]}}
	case "tencent":
		cfg = ProviderConfig{"secret_id": keep("tc_secret_id", "secret_id"), "secret_key": keep("tc_secret_key", "secret_key")}
		required = [][2]string{{"SecretId", cfg["secret_id"]}, {"SecretKey", cfg["secret_key"]}}
	case "aliyun":
		cfg = ProviderConfig{"access_key_id": keep("ali_access_key_id", "access_key_id"), "access_key_secret": keep("ali_access_key_secret", "access_key_secret")}
		required = [][2]string{{"AccessKey ID", cfg["access_key_id"]}, {"AccessKey Secret", cfg["access_key_secret"]}}
	default:
		region := strings.TrimSpace(c.R.FormValue("hw_region"))
		if region == "" {
			region = oldcfg["region"]
		}
		if region == "" {
			region = "cn-north-4"
		}
		cfg = ProviderConfig{"ak": keep("hw_ak", "ak"), "sk": keep("hw_sk", "sk"), "region": region}
		required = [][2]string{{"AK", cfg["ak"]}, {"SK", cfg["sk"]}}
	}
	var missing []string
	for _, r := range required {
		if r[1] == "" {
			missing = append(missing, r[0])
		}
	}
	if len(missing) > 0 {
		c.flash("缺少凭据："+strings.Join(missing, "、"), "error")
		c.redirect(formBack("/providers", pid))
		return
	}
	configEnc := providerPackConfig(cfg)
	tokenEnc := ""
	if ptype == "cloudflare" {
		tokenEnc = encryptSecret(cfg["token"])
	}
	ts := nowStr()
	en := boolInt(enabled)
	if old != nil {
		mustExec("UPDATE providers SET name=?,provider_type=?,token_enc=?,config_enc=?,enabled=?,updated_at=? WHERE id=?",
			name, ptype, tokenEnc, configEnc, en, ts, pid)
	} else {
		mustExec("INSERT INTO providers(name,provider_type,token_enc,config_enc,enabled,created_at,updated_at) VALUES(?,?,?,?,?,?,?)",
			name, ptype, tokenEnc, configEnc, en, ts, ts)
	}
	c.flash("DNS 服务商已保存："+providerLabel(ptype), "success")
	c.redirect("/providers")
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func providerTestHandler(c *Ctx) {
	if !c.verifyCSRF() {
		return
	}
	id := c.pathID("id")
	p := getProvider(id)
	if p == nil {
		c.abort(404)
		return
	}
	zones, err := providerListZones(p)
	if err != nil {
		mustExec("UPDATE providers SET last_status='ERROR',last_error=?,updated_at=? WHERE id=?", truncRunes(err.Error(), 1000), nowStr(), id)
		c.flash(fmt.Sprintf("%s 测试失败：%v", providerLabel(p.ProviderType), err), "error")
	} else {
		mustExec("UPDATE providers SET last_status='SUCCESS',last_error='',updated_at=? WHERE id=?", nowStr(), id)
		c.flash(fmt.Sprintf("%s 连接成功，可读取 %d 个域名区域", providerLabel(p.ProviderType), len(zones)), "success")
	}
	c.redirect("/providers")
}

func providerDeleteHandler(c *Ctx) {
	if !c.verifyCSRF() {
		return
	}
	id := c.pathID("id")
	if countWhere("SELECT COUNT(*) FROM mappings WHERE provider_id=?", id) > 0 {
		c.flash("该 DNS 服务商正被 DNS 映射使用，不能删除", "error")
		c.redirect("/providers")
		return
	}
	mustExec("DELETE FROM providers WHERE id=?", id)
	c.flash("DNS 服务商已删除", "success")
	c.redirect("/providers")
}

// ---------------- Devices ----------------

func devicesHandler(c *Ctx) {
	editID := c.queryInt("edit")
	items := queryDevices("ORDER BY id")
	var edit *Device
	if editID != 0 {
		edit = getDevice(editID)
	}
	showForm := edit != nil || c.R.URL.Query().Get("new") == "1" || len(items) == 0
	var name, host, user, idStr string
	port := 22
	enabled := true
	if edit != nil {
		name, host, user, idStr, port, enabled = edit.Name, edit.Host, edit.Username, fmt.Sprint(edit.ID), edit.Port, edit.Enabled
	}
	form := ""
	if showForm {
		form = formCard(ifs(edit != nil, "编辑 "+e(name), "添加 H3C MSR"), "Agent 通过 SSH 登录 MSR 读取拨号接口地址，只执行 display 类查看命令。", "/devices", `
    <form method="post" action="/device/save">
      `+c.csrfInput()+`
      <input type="hidden" name="id" value="`+e(idStr)+`">
      <div class="row">
        <label>名称<input name="name" required value="`+e(name)+`" placeholder="例如：深圳 MSR3640"></label>
        <label>管理 IP<input name="host" required value="`+e(host)+`" placeholder="172.16.10.1"></label>
        <label>SSH 端口<input name="port" type="number" min="1" max="65535" value="`+e(port)+`"></label>
        <label>SSH 用户名<input name="username" required value="`+e(user)+`" placeholder="huboze"></label>
      </div>
      <div class="row">
      <label>SSH 密码`+ifs(edit != nil && edit.PasswordEnc != "", `<span class="saved">✓ 已保存</span>`, "")+`
        <div class="password-wrap">
          <input id="device_password" name="password" type="password" `+ifs(edit == nil, "required", "")+` placeholder="`+ifs(edit != nil, "留空则保持原密码", "MSR SSH 密码")+`" autocomplete="new-password">
          <button class="pw-toggle" type="button" onclick="togglePassword('device_password', this)">显示</button>
        </div>
      </label>
      <label>状态<select name="enabled"><option value="1" `+sel(enabled)+`>启用</option><option value="0" `+sel(!enabled)+`>停用</option></select></label>
      </div>
      <div class="hint">保存并测试时会立即登录一次 MSR。如果账号密码错误，设备会被自动停用，避免 H3C 因连续失败锁定账号。</div>
      <div class="actions">
        <button name="save_action" value="save_test">保存并测试 SSH</button>
        <button class="btn2" name="save_action" value="save">仅保存</button>
      </div>
    </form>`+togglePasswordJS, len(items) > 0)
	}
	head := ""
	if !showForm {
		head = addButton("/devices?new=1", "添加设备")
	}
	content := form
	if len(items) > 0 {
		content += liveRegion("devlist", "/api/devices", "devices", renderDeviceList(c))
	}
	c.html(c.layoutWith("MSR 设备", "状态每 5 秒自动刷新", head, content, "devices"))
}

func apiDevicesHandler(c *Ctx) { c.fragment("devices", renderDeviceList(c)) }

func renderDeviceList(c *Ctx) string {
	items := queryDevices("ORDER BY id")
	var b strings.Builder
	b.WriteString(`<div class="devgrid">`)
	for _, x := range items {
		label, cls := "在线", "ok"
		switch {
		case !x.Enabled:
			label, cls = "已停用", ""
		case x.LastStatus == "ERROR":
			label, cls = "无法连接", "bad"
		case x.LastStatus != "ONLINE":
			label, cls = "等待检测", "info"
		}
		meta := e(x.Username) + "@" + e(x.Host) + ":" + fmt.Sprint(x.Port)
		if s := onlineSeconds(x); s > 0 {
			meta += " · 已连续在线 " + humanDuration(s)
		}
		if x.LastSeen != "" {
			meta += " · 最后连接 " + tsSpan("", x.LastSeen)
		}
		toggle := fmt.Sprintf(`<form method="post" action="/device/%d/toggle">%s<button class="small %s" title="点击%s">%s</button></form>`,
			x.ID, c.csrfInput(), ifs(x.Enabled, "toggle-on", "toggle-off"), ifs(x.Enabled, "停用", "启用"), ifs(x.Enabled, "已启用", "已停用"))
		fmt.Fprintf(&b, `<div class="card dcard"><div class="dev-head"><div style="display:flex;gap:10px;align-items:center;min-width:0"><h3>%s</h3>%s</div>%s</div><div class="sub">%s</div>`,
			e(x.Name), pill(label, cls), toggle, meta)
		if x.LastError != "" && (x.LastStatus == "ERROR" || !x.Enabled) {
			b.WriteString(`<div class="errbox">` + clip(x.LastError, 80) + `</div>`)
		}
		var ifaces []Interface
		_ = jsonUnmarshalString(x.LastInterfacesJSON, &ifaces)
		stale := x.LastStatus != "ONLINE"
		b.WriteString(`<div class="lines">`)
		n, others := 0, 0
		for _, i := range ifaces {
			if !isDialer(i.Name) {
				others++
				continue
			}
			n++
			dc := ifs(ifaceUp(i), "ok", "bad")
			st := ifs(ifaceUp(i), `<span class="ok" style="font-size:12px">已连通</span>`, `<span class="bad" style="font-size:12px">未连通</span>`)
			if stale {
				dc, st = "", `<span class="muted" style="font-size:12px">上次数据</span>`
			}
			v4, v6 := i.IP, i.IPv6
			if v4 == "" {
				v4 = "无 IPv4"
			}
			if v6 == "" {
				v6 = "无 IPv6"
			}
			fmt.Fprintf(&b, `<div class="line"><span class="dot %s"></span><div><div class="line-name">%s</div></div><div style="text-align:right"><div class="line-ip">%s</div><div class="line-ip v6">%s</div><div>%s</div></div></div>`,
				dc, e(i.Name), e(v4), e(v6), st)
		}
		if n == 0 {
			b.WriteString(`<div class="line"><span class="dot"></span><div class="muted">尚未发现 Dialer 拨号接口，点击下方“测试/发现接口”读取。</div><div></div></div>`)
		}
		b.WriteString(`</div>`)
		if others > 0 {
			fmt.Fprintf(&b, `<div class="sub" style="margin-top:6px">另有 %d 个非拨号接口未显示</div>`, others)
		}
		fmt.Fprintf(&b, `<div class="actions dcard-foot">%s<a class="btn btn2 small" href="/devices?edit=%d#form">编辑</a>%s</div></div>`,
			c.csrfForm(fmt.Sprintf("/device/%d/test", x.ID), "small", "测试/发现接口", ""), x.ID,
			moreMenu(
				fmt.Sprintf(`<a class="btn btn2 small" href="/device/%d/first-login-password">首次登录改密</a>`, x.ID),
				c.csrfForm(fmt.Sprintf("/device/%d/clear-key", x.ID), "btn2 small", "清除 Host Key", "确认清除该设备的 SSH Host Key？请先确认设备身份。"),
				c.csrfForm(fmt.Sprintf("/device/%d/delete", x.ID), "danger small", "删除设备", "确认删除该设备？")))
	}
	b.WriteString(`</div>`)
	return b.String()
}

func deviceSaveHandler(c *Ctx) {
	if !c.verifyCSRF() {
		return
	}
	didInt, _ := c.formInt("id")
	did := int64(didInt)
	name := strings.TrimSpace(c.R.FormValue("name"))
	host := strings.TrimSpace(c.R.FormValue("host"))
	port, ok := c.formInt("port")
	if !ok || port == 0 {
		port = 22
	}
	username := strings.TrimSpace(c.R.FormValue("username"))
	password := c.R.FormValue("password")
	enabled := boolInt(c.R.FormValue("enabled") == "1")
	if _, err := netip.ParseAddr(host); err != nil {
		c.flash("管理 IP 格式不正确", "error")
		c.redirect(formBack("/devices", did))
		return
	}
	if name == "" || username == "" || port < 1 || port > 65535 {
		c.flash("设备配置不完整", "error")
		c.redirect(formBack("/devices", did))
		return
	}
	ts := nowStr()
	targetID := did
	if did != 0 {
		old := getDevice(did)
		if old == nil {
			c.abort(404)
			return
		}
		penc := old.PasswordEnc
		if password != "" {
			penc = encryptSecret(password)
		}
		mustExec("UPDATE devices SET name=?,host=?,port=?,username=?,password_enc=?,enabled=?,updated_at=? WHERE id=?",
			name, host, port, username, penc, enabled, ts, did)
	} else {
		if password == "" {
			c.flash("首次添加必须填写 SSH 密码", "error")
			c.redirect(formBack("/devices", did))
			return
		}
		res, err := DB.Exec(`INSERT INTO devices(name,host,port,username,password_enc,enabled,last_status,last_error,last_seen,last_interfaces_json,created_at,updated_at)
			VALUES(?,?,?,?,?,?,'UNKNOWN','','','[]',?,?)`, name, host, port, username, encryptSecret(password), enabled, ts, ts)
		if err != nil {
			c.flash("保存失败："+err.Error(), "error")
			c.redirect(formBack("/devices", did))
			return
		}
		targetID, _ = res.LastInsertId()
	}
	action := c.R.FormValue("save_action")
	if action == "" {
		action = "save_test"
	}
	if action == "save_test" && targetID != 0 {
		ifaces, err := testAndStoreDevice(targetID)
		if err == nil {
			var parts []string
			for _, x := range ifaces {
				if strings.HasPrefix(strings.ToLower(x.Name), "dia") {
					parts = append(parts, ifaceIPText(x))
				}
			}
			detail := strings.Join(parts, "，")
			if detail == "" {
				detail = "已成功读取接口"
			}
			c.flash("设备已保存，SSH 测试成功："+detail, "success")
		} else {
			mustExec("UPDATE devices SET enabled=0,last_status='ERROR',last_error=?,updated_at=? WHERE id=?",
				truncRunes(err.Error(), 1000), nowStr(), targetID)
			c.flash(fmt.Sprintf("设备已保存，但 SSH 测试失败：%v。为避免 H3C 账号被连续锁定，已自动禁用该设备。", err), "error")
		}
	} else {
		c.flash("MSR 设备已保存", "success")
	}
	c.redirect("/devices")
}

func deviceFirstLoginPasswordHandler(c *Ctx) {
	id := c.pathID("id")
	d := getDevice(id)
	if d == nil {
		c.abort(404)
		return
	}
	if c.R.Method == "POST" {
		if !c.verifyCSRF() {
			return
		}
		np := c.R.FormValue("new_password")
		cp := c.R.FormValue("confirm_password")
		if np != cp {
			c.flash("两次输入的新密码不一致", "error")
			c.redirect(fmt.Sprintf("/device/%d/first-login-password", id))
			return
		}
		if err := changeFirstLoginPassword(d, np); err != nil {
			logEvent("ERROR", "MSR_PASSWORD", fmt.Sprintf("%s: %v", d.Name, err))
			c.flash(fmt.Sprintf("首次改密失败：%v", err), "error")
		} else {
			mustExec("UPDATE devices SET password_enc=?,last_status='UNKNOWN',last_error='',updated_at=? WHERE id=?", encryptSecret(np), nowStr(), id)
			logEvent("SUCCESS", "MSR_PASSWORD", d.Name+" 已通过 Web 首次改密向导修改密码")
			ifaces, verr := testAndStoreDevice(id)
			if verr == nil {
				var parts []string
				for _, x := range ifaces {
					if strings.HasPrefix(strings.ToLower(x.Name), "dia") {
						parts = append(parts, x.Name+"="+x.IP)
					}
				}
				detail := strings.Join(parts, "，")
				if detail == "" {
					detail = "SSH 已验证"
				}
				c.flash("H3C 首次改密成功；Agent 已保存新密码；SSH 复测成功："+detail, "success")
			} else {
				c.flash(fmt.Sprintf("H3C 首次改密已经成功，Agent 也已保存新密码；但随后 SSH 复测失败：%v。请查看设备状态。", verr), "warning")
			}
			c.redirect("/devices")
			return
		}
	} else if c.R.Method != "GET" {
		c.abort(405)
		return
	}
	body := `
    <div class="card" style="max-width:720px">
      <h2>H3C 首次登录改密</h2>
      <div class="msg warning">此向导用于 H3C 提示 <b>First login or password reset</b> 的场景。
      当前保存的初始 SSH 密码不会显示；成功后 Agent 会自动把新密码加密保存。</div>
      <div class="code">设备：` + e(d.Name) + `
地址：` + e(d.Host) + `:` + e(d.Port) + `
账号：` + e(d.Username) + `</div><br>
      <form method="post" onsubmit="return validatePwMatch()">
        ` + c.csrfInput() + `
        <label>新 SSH 密码
          <div class="password-wrap">
            <input id="new_password" type="password" name="new_password" minlength="8" required autocomplete="new-password" oninput="checkPwMatch()">
            <button class="pw-toggle" type="button" onclick="togglePw('new_password', this)">显示</button>
          </div>
        </label>
        <label>确认新 SSH 密码
          <div class="password-wrap">
            <input id="confirm_password" type="password" name="confirm_password" minlength="8" required autocomplete="new-password" oninput="checkPwMatch()">
            <button class="pw-toggle" type="button" onclick="togglePw('confirm_password', this)">显示</button>
          </div>
        </label>
        <div id="pw_match" class="muted">请输入两次相同的新密码。</div>
        <div class="muted">至少 8 位、至少两类字符、不要包含用户名。实际仍以 H3C 当前 password-control 策略为准。</div><br>
        <button type="submit">执行首次改密并同步到 Agent</button>
        <a class="btn btn2" href="/devices">返回</a>
      </form>
    </div>
    <script>
    function togglePw(id, btn){
      const el=document.getElementById(id);
      const show=el.type==='password';
      el.type=show?'text':'password';
      btn.textContent=show?'隐藏':'显示';
    }
    function checkPwMatch(){
      const a=document.getElementById('new_password').value;
      const b=document.getElementById('confirm_password').value;
      const m=document.getElementById('pw_match');
      if(!a && !b){m.textContent='请输入两次相同的新密码。';m.className='muted';return false;}
      if(a===b && a.length>=8){m.textContent='✓ 两次密码一致';m.className='match-ok';return true;}
      m.textContent='✗ 两次密码不一致或长度不足';m.className='match-bad';return false;
    }
    function validatePwMatch(){
      if(!checkPwMatch()){alert('请确认两次密码完全一致，并且至少 8 位。');return false;}
      return confirm('确认执行 H3C 首次登录改密？成功后 Agent 会立即保存新密码并重新测试 SSH。');
    }
    </script>`
	c.html(c.layout("H3C 首次登录改密", body, "devices"))
}

func deviceToggleHandler(c *Ctx) {
	if !c.verifyCSRF() {
		return
	}
	id := c.pathID("id")
	d := getDevice(id)
	if d == nil {
		c.abort(404)
		return
	}
	newEnabled := !d.Enabled
	mustExec("UPDATE devices SET enabled=?,updated_at=? WHERE id=?", boolInt(newEnabled), nowStr(), id)
	if newEnabled {
		logEvent("INFO", "MSR_ENABLE", d.Name+" 已通过 Web 开关启用")
		c.flash(d.Name+" 已启用；后台轮询将在下一个周期恢复。", "success")
	} else {
		logEvent("INFO", "MSR_DISABLE", d.Name+" 已通过 Web 开关禁用")
		c.flash(d.Name+" 已禁用；后台自动轮询立即停止。", "warning")
	}
	c.redirect("/devices")
}

func deviceTestHandler(c *Ctx) {
	if !c.verifyCSRF() {
		return
	}
	id := c.pathID("id")
	ifaces, err := testAndStoreDevice(id)
	if err == nil {
		var parts []string
		for _, x := range ifaces {
			if strings.HasPrefix(strings.ToLower(x.Name), "dia") {
				parts = append(parts, ifaceIPText(x))
			}
		}
		c.flash("SSH 测试通过："+strings.Join(parts, ", "), "success")
	} else {
		msg := err.Error()
		if isLockoutRisk(err) {
			mustExec("UPDATE devices SET enabled=0,last_status='ERROR',last_error=?,updated_at=? WHERE id=?", truncRunes(msg, 1000), nowStr(), id)
			c.flash("MSR 测试失败："+msg+"。已自动禁用设备，避免后台继续重试导致 H3C 账号锁定。", "error")
		} else {
			c.flash("MSR 测试失败："+msg, "error")
		}
	}
	c.redirect("/devices")
}

func deviceClearKeyHandler(c *Ctx) {
	if !c.verifyCSRF() {
		return
	}
	d := getDevice(c.pathID("id"))
	if d == nil {
		c.abort(404)
		return
	}
	port := d.Port
	if port == 0 {
		port = 22
	}
	if err := removeKnownHost(d.Host, port); err != nil {
		c.flash("清除 Host Key 失败："+err.Error(), "error")
	} else {
		c.flash("已清除该设备保存的 SSH Host Key。请确认目标设备身份无误后，再点击“测试/发现接口”；下次连接会重新记录新的 Host Key。", "warning")
	}
	c.redirect("/devices")
}

func deviceDeleteHandler(c *Ctx) {
	if !c.verifyCSRF() {
		return
	}
	id := c.pathID("id")
	if countWhere("SELECT COUNT(*) FROM mappings WHERE device_id=?", id) > 0 {
		c.flash("该设备正被 DNS 映射使用，不能删除", "error")
		c.redirect("/devices")
		return
	}
	mustExec("DELETE FROM devices WHERE id=?", id)
	c.flash("设备已删除", "success")
	c.redirect("/devices")
}
