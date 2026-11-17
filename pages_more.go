package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// ---------------- Mappings ----------------

func queryMappingsFull() []*Mapping {
	rowsQ, err := DB.Query("SELECT " + mappingCols + `, d.name, p.name FROM mappings m
		JOIN devices d ON d.id=m.device_id JOIN providers p ON p.id=m.provider_id ORDER BY m.id`)
	var items []*Mapping
	if err == nil {
		for rowsQ.Next() {
			var dn, pn string
			m, err := scanMapping(rowsQ, &dn, &pn)
			if err == nil {
				m.DeviceName, m.ProviderName = dn, pn
				items = append(items, m)
			}
		}
		rowsQ.Close()
	}
	return items
}

func renderMappingList(c *Ctx) string {
	items := queryMappingsFull()
	devByID := map[int64]*Device{}
	for _, d := range queryDevices("ORDER BY id") {
		devByID[d.ID] = d
	}
	var b strings.Builder
	b.WriteString(`<section class="card"><div class="tbl"><table class="stack"><tr><th>域名 / 线路</th><th>当前 IP</th><th>状态</th><th>最近检测</th><th>操作</th></tr>`)
	for _, x := range items {
		v := viewMapping(x, devByID[x.DeviceID])
		note := ""
		if v.note != "" {
			note = `<div class="sub">` + clip(v.note, 40) + `</div>`
		}
		ip := e(dash(x.CurrentIP))
		if x.CurrentIP != "" && x.LastSyncedIP != "" && !sameIP(x.CurrentIP, x.LastSyncedIP) {
			ip += `<div class="sub warn">DNS 中仍为 ` + e(x.LastSyncedIP) + `</div>`
		} else if x.CurrentIP == "" && x.LastSyncedIP != "" {
			ip = `<span class="muted">` + e(x.LastSyncedIP) + `</span><div class="sub">上次同步的 IP</div>`
		}
		port := "ICMP"
		if x.CheckPort > 0 {
			port = fmt.Sprintf("TCP %d", x.CheckPort)
		}
		fmt.Fprintf(&b, `<tr><td><div class="dom-name">%s <span class="tag">%s</span></div><div class="sub nm">%s · %s · %s</div><div class="sub">%s · 可达性检测 %s</div></td>
<td class="ipc">%s</td><td style="min-width:200px;max-width:340px">%s%s%s</td><td class="nm">%s<div class="sub">同步 %s</div></td>
<td class="act"><div class="actions">%s<a class="btn btn2 small" href="/mappings?edit=%d#form">编辑</a>%s</div></td></tr>`,
			e(x.RecordName), e(x.RecordType), e(x.DeviceName), e(x.InterfaceName), e(x.ProviderName), e(x.Name), port,
			ip, pill(v.label, v.cls), note, `<div class="sub"><a class="link" href="/dns#m-`+fmt.Sprint(x.ID)+`">查看解析详情 →</a></div>`, tsSpan("", x.LastCheck), tsSpan("", x.LastSync),
			c.csrfForm(fmt.Sprintf("/mapping/%d/sync", x.ID), "small", "立即同步", ""), x.ID,
			moreMenu(
				c.csrfForm(fmt.Sprintf("/mapping/%d/check", x.ID), "btn2 small", "检测域名", ""),
				c.csrfForm(fmt.Sprintf("/mapping/%d/delete", x.ID), "danger small", "删除映射", "确认删除这个映射？\\nDNS 服务商上的解析记录不会被删除，如不再使用请到服务商控制台手动删除。")))
	}
	b.WriteString(`</table></div></section>`)
	return b.String()
}

func apiMappingsHandler(c *Ctx) { c.fragment("mappings", renderMappingList(c)) }

func mappingsHandler(c *Ctx) {
	editID := c.queryInt("edit")
	nItems := countWhere("SELECT COUNT(*) FROM mappings")
	devicesList := queryDevices("WHERE enabled=1 ORDER BY name")
	providersList := queryProviders("WHERE enabled=1 ORDER BY name")
	var edit *Mapping
	if editID != 0 {
		edit = getMapping(editID)
	}
	showForm := edit != nil || c.R.URL.Query().Get("new") == "1" || nItems == 0

	form := ""
	if showForm {
		var deviceOpts, providerOpts strings.Builder
		for _, d := range devicesList {
			fmt.Fprintf(&deviceOpts, `<option value="%d" %s>%s (%s)</option>`, d.ID, sel(edit != nil && edit.DeviceID == d.ID), e(d.Name), e(d.Host))
		}
		for _, p := range providersList {
			fmt.Fprintf(&providerOpts, `<option value="%d" %s>%s · %s</option>`, p.ID, sel(edit != nil && edit.ProviderID == p.ID), e(p.Name), e(providerLabel(p.ProviderType)))
		}
		var iface, zoneID, zoneName, recordName, name, idStr string
		rtype := "A"
		checkPort := 0
		enabled := true
		if edit != nil {
			iface, zoneID, zoneName, recordName, name = edit.InterfaceName, edit.ZoneID, edit.ZoneName, edit.RecordName, edit.Name
			rtype, checkPort, enabled, idStr = edit.RecordType, edit.CheckPort, edit.Enabled, fmt.Sprint(edit.ID)
		}
		recordHost := ""
		if recordName != "" && zoneName != "" {
			switch {
			case recordName == zoneName:
				recordHost = "@"
			case strings.HasSuffix(recordName, "."+zoneName):
				recordHost = strings.TrimSuffix(recordName, "."+zoneName)
			default:
				recordHost = recordName
			}
		}
		missing := ""
		if len(devicesList) == 0 || len(providersList) == 0 {
			missing = `<div class="msg warning">创建映射前需要先` +
				ifs(len(devicesList) == 0, ` <a class="link" href="/devices?new=1#form">添加并启用一台 MSR</a>`, "") +
				ifs(len(devicesList) == 0 && len(providersList) == 0, " 和", "") +
				ifs(len(providersList) == 0, ` <a class="link" href="/providers?new=1#form">添加一个 DNS 服务商</a>`, "") + `。</div>`
		}
		form = formCard(ifs(edit != nil, "编辑映射", "添加域名映射"), "把 MSR 拨号接口的公网 IP 绑定到一条 DNS 记录；保存时记录不存在会自动创建，已存在则直接接管。", "/mappings", missing+`
    <form method="post" action="/mapping/save" id="mapForm">
      `+c.csrfInput()+`
      <input type="hidden" name="id" value="`+e(idStr)+`">
      <input type="hidden" name="zone_name" id="zone_name" value="`+e(zoneName)+`">
      <div class="section-title" style="margin-top:4px;border-top:0;padding-top:0">① IP 来源</div>
      <div class="row">
        <label>MSR 设备
          <select name="device_id" id="device" required>
            <option value="">请选择设备</option>`+deviceOpts.String()+`
          </select>
        </label>
        <label>公网接口
          <select name="interface_name" id="iface" required>
            <option value="`+e(iface)+`">`+e(ifs(iface == "", "请先选择设备", iface))+`</option>
          </select>
          <button type="button" class="btn2 small" id="iface_refresh" style="margin-top:6px" onclick="loadInterfaces(false)">刷新接口（实时登录 MSR）</button>
        </label>
      </div>
      <div class="section-title">② DNS 记录</div>
      <div class="row">
        <label>DNS 服务商
          <select name="provider_id" id="provider" required onchange="loadZones()">
            <option value="">请选择服务商</option>`+providerOpts.String()+`
          </select>
        </label>
        <label>域名区域
          <select name="zone_id" id="zone" required onchange="setZoneName()">
            <option value="`+e(zoneID)+`">`+e(ifs(zoneName == "", "请先选择服务商", zoneName))+`</option>
          </select>
        </label>
        <label>主机记录
          <input name="record_host" id="record_host" required value="`+e(recordHost)+`"
                 placeholder="例如：wan1；根域名填写 @" oninput="updateRecordPreview()">
        </label>
        <label>记录类型
          <select name="record_type" id="record_type" required onchange="updateRecordPreview()">
            <option value="A" `+sel(rtype == "A")+`>A（使用接口 IPv4）</option>
            <option value="AAAA" `+sel(rtype == "AAAA")+`>AAAA（使用接口全局 IPv6）</option>
          </select>
        </label>
      </div>
      <div class="hint" id="record_preview">保存时自动检测：不存在则创建，已存在则绑定并同步 IP。</div>
      <div class="section-title">③ 其他</div>
      <div class="row row3">
        <label>映射名称
          <input name="name" required value="`+e(name)+`" placeholder="例如：深圳电信 v4">
        </label>
        <label>可达性检测端口（可选）
          <input name="check_port" type="number" min="0" max="65535" value="`+e(checkPort)+`" placeholder="例如 443；0 表示使用 ICMP">
        </label>
        <label>状态
          <select name="enabled">
            <option value="1" `+sel(enabled)+`>启用</option>
            <option value="0" `+sel(!enabled)+`>停用</option>
          </select>
        </label>
      </div>
      <div class="actions"><button>保存并同步 DNS</button></div>
      <div class="muted" style="margin-top:10px">A 与 AAAA 是两条独立的映射，只有 IPv4 时只建 A 即可。Cloudflare 新建记录默认“仅 DNS”、TTL 自动。</div>
    </form>
`+`    <script>
    async function getJSON(u){
      let r=await fetch(u);
      let d=await r.json();
      if(!d.success) throw new Error(d.error||'请求失败');
      return d;
    }

    // cached=true uses the interfaces from the last successful poll (no SSH login);
    // the refresh button logs in to the MSR for live data.
    async function loadInterfaces(cached){
      let id=document.getElementById('device').value;
      if(!id){ if(!cached) alert('请先选择 MSR 设备'); return; }
      const btn=document.getElementById('iface_refresh');
      const s=document.getElementById('iface');
      const keep=s.value;
      if(!cached){btn.disabled=true;btn.textContent='正在登录 MSR 读取…';}
      try{
        let d=await getJSON('/api/device/'+id+'/interfaces'+(cached?'?cached=1':''));
        if(cached && !d.interfaces.length){ s.innerHTML='<option value="">暂无缓存，请点击“刷新接口”</option>'; return; }
        s.innerHTML='';
        d.interfaces.forEach(x=>{
          let o=document.createElement('option');
          o.value=x.name;
          o.textContent=x.name+' - IPv4:'+(x.ip||'-')+' / IPv6:'+(x.ipv6||'-')+(x.name.toLowerCase().startsWith('dia')?'（拨号接口）':'');
          if(x.name===keep) o.selected=true;
          s.appendChild(o);
        });
      }catch(e){alert(e.message);}
      finally{ if(!cached){btn.disabled=false;btn.textContent='刷新接口（实时登录 MSR）';} }
    }
    document.getElementById('device').addEventListener('change',()=>loadInterfaces(true));

    async function loadZones(){
      let id=document.getElementById('provider').value;
      if(!id)return;
      try{
        let d=await getJSON('/api/provider/'+id+'/zones');
        let s=document.getElementById('zone');
        s.innerHTML='<option value="">请选择域名区域</option>';
        d.zones.forEach(x=>{
          let o=document.createElement('option');
          o.value=x.id;
          o.textContent=x.name;
          s.appendChild(o);
        });
        document.getElementById('zone_name').value='';
        updateRecordPreview();
      }catch(e){alert(e.message);}
    }

    function setZoneName(){
      let z=document.getElementById('zone');
      let name=(z.selectedIndex>=0?z.options[z.selectedIndex].textContent:'');
      document.getElementById('zone_name').value=(name==='请选择域名区域'?'':name);
      updateRecordPreview();
    }

    function updateRecordPreview(){
      let host=(document.getElementById('record_host').value||'').trim().replace(/\.$/,'');
      let zone=(document.getElementById('zone_name').value||'').trim().replace(/\.$/,'');
      let p=document.getElementById('record_preview');
      if(!host||!zone){
        p.textContent='保存时自动检测：不存在则创建，已存在则绑定并同步 IP。';
        return;
      }
      let fqdn=(host==='@') ? zone : ((host===zone||host.endsWith('.'+zone)) ? host : host+'.'+zone);
      let rt=document.getElementById('record_type').value||'A'; p.textContent='将使用 '+rt+' 记录：'+fqdn+'；如果不存在会自动创建。';
    }

    updateRecordPreview();
    </script>`, nItems > 0)
	}
	head := ""
	if !showForm {
		head = addButton("/mappings?new=1", "添加映射")
	}
	content := form
	if nItems > 0 {
		content += liveRegion("maplist", "/api/mappings", "mappings", renderMappingList(c))
	}
	c.html(c.layoutWith("DNS 映射", "域名健康检查直接查询多个公共 DNS；状态每 5 秒自动刷新", head, content, "mappings"))
}

var hostnameRE = regexp.MustCompile(`^(?:[A-Za-z0-9_](?:[A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?\.)*[A-Za-z0-9_](?:[A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?$`)

func mappingSaveHandler(c *Ctx) {
	if !c.verifyCSRF() {
		return
	}
	midInt, _ := c.formInt("id")
	mid := int64(midInt)
	name := strings.TrimSpace(c.R.FormValue("name"))
	didInt, _ := c.formInt("device_id")
	did := int64(didInt)
	iface := strings.TrimSpace(c.R.FormValue("interface_name"))
	recordType := strings.ToUpper(strings.TrimSpace(c.R.FormValue("record_type")))
	if recordType == "" {
		recordType = "A"
	}
	if recordType != "A" && recordType != "AAAA" {
		c.flash("DNS 记录类型只支持 A / AAAA", "error")
		c.redirect(formBack("/mappings", mid))
		return
	}
	pidInt, _ := c.formInt("provider_id")
	pid := int64(pidInt)
	zoneID := strings.TrimSpace(c.R.FormValue("zone_id"))
	zoneName := strings.ToLower(strings.TrimRight(strings.TrimSpace(c.R.FormValue("zone_name")), "."))
	recordHost := strings.TrimRight(strings.TrimSpace(c.R.FormValue("record_host")), ".")
	checkPort, _ := c.formInt("check_port")
	checkPort = clamp(checkPort, 0, 65535)
	enabled := boolInt(c.R.FormValue("enabled") == "1")

	if name == "" || did == 0 || iface == "" || pid == 0 || zoneID == "" || zoneName == "" || recordHost == "" {
		c.flash("映射配置不完整，请检查设备、接口、DNS 服务商、域名区域和主机记录。", "error")
		c.redirect(formBack("/mappings", mid))
		return
	}
	lh := strings.ToLower(recordHost)
	var recordName string
	switch {
	case recordHost == "@", lh == zoneName:
		recordName = zoneName
	case strings.HasSuffix(lh, "."+zoneName):
		recordName = lh
	default:
		recordName = lh + "." + zoneName
	}
	if len(recordName) > 253 || !hostnameRE.MatchString(recordName) {
		c.flash("主机记录格式不正确，请填写类似 wan1、@ 或 wan1.example.com。", "error")
		c.redirect(formBack("/mappings", mid))
		return
	}
	// Two mappings on the same record would overwrite each other every poll.
	var dupName string
	if err := DB.QueryRow(`SELECT name FROM mappings WHERE provider_id=? AND zone_id=? AND lower(record_name)=? AND upper(record_type)=? AND id<>? LIMIT 1`,
		pid, zoneID, recordName, recordType, mid).Scan(&dupName); err == nil {
		c.flash(fmt.Sprintf("%s 的 %s 记录已由映射「%s」管理；同一条记录只能绑定一个映射，否则会被互相覆盖。", recordName, recordType, dupName), "error")
		c.redirect(formBack("/mappings", mid))
		return
	}
	device := getDevice(did)
	provider := getProvider(pid)
	if mid != 0 {
		if old := getMapping(mid); old != nil && strings.ToUpper(old.RecordType) != recordType {
			c.flash("为避免遗留旧 DNS 记录，现有映射不能直接在 A 与 AAAA 之间切换；请新建另一条映射。", "error")
			c.redirect(fmt.Sprintf("/mappings?edit=%d", mid))
			return
		}
	}
	if device == nil {
		c.flash("MSR 设备不存在。", "error")
		c.redirect(formBack("/mappings", mid))
		return
	}
	if provider == nil || !provider.Enabled {
		c.flash("DNS 服务商不存在或已停用。", "error")
		c.redirect(formBack("/mappings", mid))
		return
	}

	currentIP, err := func() (string, error) {
		ifaces, err := collectDevice(device)
		if err != nil {
			return "", err
		}
		for _, x := range ifaces {
			if x.Name == iface {
				return mappingIPFromInterface(x, recordType)
			}
		}
		return "", fmt.Errorf("在 MSR 输出中没有找到接口 %s", iface)
	}()
	if err != nil {
		c.flash(fmt.Sprintf("无法读取 MSR 当前公网 IP：%v", err), "error")
		c.redirect(formBack("/mappings", mid))
		return
	}

	err = func() error {
		rec, err := providerFindRecord(provider, zoneID, zoneName, recordName, recordType)
		if err != nil {
			return err
		}
		created := false
		var recordID string
		if rec != nil {
			recordID = rec.ID
			if !sameIP(rec.Content, currentIP) {
				if _, err := providerUpdateRecord(provider, zoneID, zoneName, recordID, recordName, recordType, currentIP); err != nil {
					return err
				}
			}
		} else {
			r, err := providerCreateRecord(provider, zoneID, zoneName, recordName, recordType, currentIP)
			if err != nil {
				return err
			}
			recordID = r.ID
			if recordID == "" {
				return errors.New("DNS 服务商创建记录后未返回 Record ID")
			}
			created = true
		}
		ts := nowStr()
		var savedID int64
		if mid != 0 {
			if err := dbExec(`UPDATE mappings SET name=?,device_id=?,interface_name=?,provider_id=?,zone_id=?,zone_name=?,
				record_id=?,record_name=?,record_type=?,enabled=?,check_port=?,current_ip=?,last_synced_ip=?,
				last_status='SUCCESS',last_error='',last_sync=?,updated_at=? WHERE id=?`,
				name, did, iface, pid, zoneID, zoneName, recordID, recordName, recordType, enabled, checkPort,
				currentIP, currentIP, ts, ts, mid); err != nil {
				return err
			}
			savedID = mid
		} else {
			res, err := DB.Exec(`INSERT INTO mappings(name,device_id,interface_name,provider_id,zone_id,zone_name,record_id,record_name,
				record_type,enabled,check_port,current_ip,last_synced_ip,last_status,last_error,last_sync,created_at,updated_at)
				VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,'SUCCESS','',?,?,?)`,
				name, did, iface, pid, zoneID, zoneName, recordID, recordName, recordType, enabled, checkPort,
				currentIP, currentIP, ts, ts, ts)
			if err != nil {
				return err
			}
			savedID, _ = res.LastInsertId()
		}
		action := ifs(created, "已自动创建", "已绑定现有记录并同步")
		logEvent("SUCCESS", "DNS_UPDATE", fmt.Sprintf("%s %s %s：%s", recordName, recordType, action, currentIP),
			fmt.Sprintf("接口=%s；域名区域=%s", iface, zoneName))
		checkText := ""
		if saved := getMapping(savedID); saved != nil {
			r := checkMappingDomain(saved, currentIP, true)
			label, _ := domainStatusZh(r.DNSStatus, r.ReachabilityStatus)
			checkText = "；域名检测：" + label
		}
		c.flash(fmt.Sprintf("DNS 映射保存成功：%s → %s（%s）%s", recordName, currentIP, action, checkText), "success")
		return nil
	}()
	if err != nil {
		logEvent("ERROR", "DNS_UPDATE", fmt.Sprintf("%s 保存失败：%v", recordName, err))
		c.flash(fmt.Sprintf("DNS 映射保存失败：%v", err), "error")
		c.redirect(formBack("/mappings", mid))
		return
	}
	c.redirect("/mappings")
}

func mappingSyncHandler(c *Ctx) {
	if !c.verifyCSRF() {
		return
	}
	m := getMapping(c.pathID("id"))
	if m == nil {
		c.abort(404)
		return
	}
	r := pollOnce(true, m.DeviceID, m.ID)
	if r.Success && r.Summary.Errors == 0 {
		c.flash("强制同步成功", "success")
	} else if !r.Success && r.Message != "" {
		c.flash("强制同步未执行："+r.Message, "error")
	} else {
		c.flash("强制同步完成但存在错误，请查看日志", "error")
	}
	c.redirect("/mappings")
}

func mappingCheckHandler(c *Ctx) {
	if !c.verifyCSRF() {
		return
	}
	m := getMapping(c.pathID("id"))
	if m == nil {
		c.abort(404)
		return
	}
	expected := m.CurrentIP
	if expected == "" {
		expected = m.LastSyncedIP
	}
	if expected == "" {
		c.flash("当前映射还没有可用于检测的公网 IP。", "warning")
		c.redirect(backTo(c, "/mappings"))
		return
	}
	r := checkMappingDomain(m, expected, true)
	label, _ := domainStatusZh(r.DNSStatus, r.ReachabilityStatus)
	detail := strings.Join(r.Errors, "；")
	if detail == "" {
		detail = "正常"
	}
	c.flash(fmt.Sprintf("%s 检测结果：%s；%s", m.RecordName, label, detail), ifs(r.DNSStatus == "SUCCESS", "success", "warning"))
	c.redirect(backTo(c, "/mappings"))
}

func mappingDeleteHandler(c *Ctx) {
	if !c.verifyCSRF() {
		return
	}
	mustExec("DELETE FROM mappings WHERE id=?", c.pathID("id"))
	c.flash("映射已删除", "success")
	c.redirect("/mappings")
}

// ---------------- Logs ----------------

const logsPageSize = 100

func logsHandler(c *Ctx) {
	q := c.R.URL.Query()
	level := strings.ToUpper(strings.TrimSpace(q.Get("level")))
	event := strings.ToUpper(strings.TrimSpace(q.Get("event")))
	kw := strings.TrimSpace(q.Get("q"))
	page := int(c.queryInt("page"))
	if page < 1 {
		page = 1
	}
	var where []string
	var args []any
	if _, ok := levelZh[level]; ok {
		where = append(where, "level=?")
		args = append(args, level)
	} else {
		level = ""
	}
	if _, ok := eventZh[event]; ok {
		where = append(where, "event=?")
		args = append(args, event)
	} else {
		event = ""
	}
	if kw != "" {
		like := "%" + strings.NewReplacer("\\", "\\\\", "%", "\\%", "_", "\\_").Replace(kw) + "%"
		where = append(where, `(message LIKE ? ESCAPE '\' OR details LIKE ? ESCAPE '\')`)
		args = append(args, like, like)
	}
	whereSQL := ""
	if len(where) > 0 {
		whereSQL = " WHERE " + strings.Join(where, " AND ")
	}
	total := countWhere("SELECT COUNT(*) FROM logs")
	matched := countWhere("SELECT COUNT(*) FROM logs"+whereSQL, args...)
	pages := (matched + logsPageSize - 1) / logsPageSize
	if pages < 1 {
		pages = 1
	}
	if page > pages {
		page = pages
	}
	var trs strings.Builder
	rows, err := DB.Query("SELECT ts,level,event,message,COALESCE(details,'') FROM logs"+whereSQL+" ORDER BY id DESC LIMIT ? OFFSET ?",
		append(args, logsPageSize, (page-1)*logsPageSize)...)
	if err == nil {
		for rows.Next() {
			var ts, lv, ev, msg, det string
			if rows.Scan(&ts, &lv, &ev, &msg, &det) == nil {
				detail := ""
				if d := detailsZh(det); d != "" {
					detail = clip(d, 70)
				}
				fmt.Fprintf(&trs, `<tr><td>%s<div class="muted" style="font-size:11px">%s</div></td><td>%s</td><td class="nm">%s</td><td>%s</td><td style="max-width:460px" class="muted">%s</td></tr>`,
					tsSpan("", ts), e(ts), pill(levelZhText(lv), levelClass(lv)), e(lookupZh(eventZh, ev)), e(messageZh(msg)), detail)
			}
		}
		rows.Close()
	}
	if trs.Len() == 0 {
		trs.WriteString(`<tr><td colspan="5" class="muted">没有符合条件的日志</td></tr>`)
	}

	levelOpts := `<option value="">全部级别</option>`
	for _, k := range []string{"ERROR", "WARNING", "SUCCESS", "INFO"} {
		levelOpts += fmt.Sprintf(`<option value="%s" %s>%s</option>`, k, sel(level == k), levelZh[k])
	}
	evKeys := make([]string, 0, len(eventZh))
	for k := range eventZh {
		evKeys = append(evKeys, k)
	}
	sort.Strings(evKeys)
	eventOpts := `<option value="">全部事件</option>`
	for _, k := range evKeys {
		eventOpts += fmt.Sprintf(`<option value="%s" %s>%s</option>`, k, sel(event == k), e(eventZh[k]))
	}
	link := func(p int) string {
		v := url.Values{}
		if level != "" {
			v.Set("level", level)
		}
		if event != "" {
			v.Set("event", event)
		}
		if kw != "" {
			v.Set("q", kw)
		}
		if p > 1 {
			v.Set("page", strconv.Itoa(p))
		}
		if len(v) == 0 {
			return "/logs"
		}
		return "/logs?" + v.Encode()
	}
	pager := fmt.Sprintf(`<span class="muted">第 %d / %d 页，共 %d 条</span>`, page, pages, matched)
	if page > 1 {
		pager += `<a class="btn btn2 small" href="` + e(link(1)) + `">« 首页</a><a class="btn btn2 small" href="` + e(link(page-1)) + `">‹ 上一页</a>`
	}
	if page < pages {
		pager += `<a class="btn btn2 small" href="` + e(link(page+1)) + `">下一页 ›</a><a class="btn btn2 small" href="` + e(link(pages)) + `">末页 »</a>`
	}
	filtered := ""
	if whereSQL != "" {
		filtered = fmt.Sprintf("；筛选结果 %d 条", matched)
	}
	content := fmt.Sprintf(`
    <div class="card">
      <div class="actions" style="justify-content:space-between">
        <div><h2>日志管理</h2><div class="muted">当前共 %d 条%s；保留策略：%s 天。</div></div>
        <div class="actions">%s%s</div>
      </div>
      <form method="get" action="/logs" class="filters" style="margin-top:12px">
        <label>级别<select name="level">%s</select></label>
        <label>事件<select name="event">%s</select></label>
        <label>关键字<input name="q" value="%s" placeholder="搜索内容或详情，例如设备名、域名、IP"></label>
        <div class="actions" style="margin-bottom:11px"><button>筛选</button><a class="btn btn2" href="/logs">重置</a></div>
      </form>
    </div>
    <div class="card"><div class="tbl"><table><tr><th style="width:150px">时间</th><th>级别</th><th>事件</th><th>内容</th><th>详情</th></tr>%s</table></div>
    <div class="pager">%s</div></div>
    `, total, filtered, e(getSetting("log_retention_days", "7")),
		c.csrfForm("/logs/cleanup", "btn2", "清理过期日志", ""),
		c.csrfForm("/logs/clear", "danger", "清空全部日志", "确认清空全部日志？此操作不可恢复。"),
		levelOpts, eventOpts, e(kw), trs.String(), pager)
	c.html(c.layout("日志", content, "logs_page"))
}

func logsCleanupHandler(c *Ctx) {
	if !c.verifyCSRF() {
		return
	}
	n := cleanupLogs(getSettingInt("log_retention_days", 7))
	c.flash(fmt.Sprintf("日志清理完成，已删除 %d 条超过保留期限的日志。", n), "success")
	c.redirect("/logs")
}

func logsClearHandler(c *Ctx) {
	if !c.verifyCSRF() {
		return
	}
	n := countWhere("SELECT COUNT(*) FROM logs")
	mustExec("DELETE FROM logs")
	c.flash(fmt.Sprintf("已清空全部日志，共删除 %d 条。", n), "warning")
	c.redirect("/logs")
}

// ---------------- Backup ----------------

// buildMigrationBundle returns a tar.gz with DB + keys, same layout as v2.2.3.
func buildMigrationBundle() ([]byte, error) {
	td, err := os.MkdirTemp("", "huboze-backup-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(td)
	dbCopy := filepath.Join(td, "huboze-ddns.db")
	if _, err := DB.Exec("VACUUM INTO ?", dbCopy); err != nil {
		return nil, fmt.Errorf("数据库快照失败：%w", err)
	}
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	add := func(name string, data []byte) error {
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o600, Size: int64(len(data)), ModTime: time.Now()}); err != nil {
			return err
		}
		_, err := tw.Write(data)
		return err
	}
	manifest, _ := json.MarshalIndent(map[string]any{
		"product": "huboze DDNS Agent", "version": Version, "created_at": nowStr(), "contains_secrets": true,
	}, "", "  ")
	if err := add("manifest.json", manifest); err != nil {
		return nil, err
	}
	files := [][2]string{{dbCopy, "data/huboze-ddns.db"}, {KnownHostsFile, "data/known_hosts"},
		{FernetKeyFile, "config/fernet.key"}, {SecretKeyFile, "config/flask_secret.key"}}
	for _, f := range files {
		data, err := os.ReadFile(f[0])
		if err != nil {
			if f[1] == "data/known_hosts" && errors.Is(err, os.ErrNotExist) {
				continue
			}
			return nil, err
		}
		if err := add(f[1], data); err != nil {
			return nil, err
		}
	}
	if err := tw.Close(); err != nil {
		return nil, err
	}
	if err := gz.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func backupDownloadHandler(c *Ctx) {
	data, err := buildMigrationBundle()
	if err != nil {
		c.flash("生成迁移备份失败："+err.Error(), "error")
		c.redirect("/settings")
		return
	}
	filename := "huboze-ddns-migration-" + time.Now().Format("20060102-150405") + ".tar.gz"
	logEvent("INFO", "BACKUP", "已下载迁移备份："+filename)
	c.saveSession()
	c.W.Header().Set("Content-Type", "application/gzip")
	c.W.Header().Set("Content-Disposition", `attachment; filename="`+filename+`"`)
	_, _ = c.W.Write(data)
}

// ---------------- Settings ----------------

func settingsHandler(c *Ctx) {
	if c.R.Method == "POST" {
		if !c.verifyCSRF() {
			return
		}
		interval, ok := c.formInt("poll_interval")
		if !ok || interval == 0 {
			interval = 60
		}
		interval = clamp(interval, 30, 3600)
		dci, ok := c.formInt("domain_check_interval")
		if !ok || dci == 0 {
			dci = 300
		}
		dci = clamp(dci, 60, 86400)
		lrd, ok := c.formInt("log_retention_days")
		if !ok {
			lrd = 7
		}
		lrd = clamp(lrd, 0, 3650)
		hb := ifs(c.R.FormValue("heartbeat_log_enabled") == "1", "1", "0")
		resolvers := strings.TrimSpace(c.R.FormValue("dns_resolvers"))
		tz := strings.TrimSpace(c.R.FormValue("timezone"))
		if tz == "" {
			tz = "Asia/Shanghai"
		}
		cidrs := strings.TrimSpace(c.R.FormValue("allowed_web_cidrs"))
		err := func() error {
			if _, err := time.LoadLocation(tz); err != nil {
				return fmt.Errorf("'No time zone found with key %s'", tz)
			}
			var list []string
			for _, x := range strings.Split(resolvers, ",") {
				if x = strings.TrimSpace(x); x != "" {
					list = append(list, x)
				}
			}
			if len(list) == 0 {
				return errors.New("至少需要配置 1 个公共 DNS 服务器")
			}
			if len(list) > 8 {
				return errors.New("公共 DNS 服务器最多配置 8 个")
			}
			seen := map[string]bool{}
			var uniq []string
			for _, item := range list {
				a, err := netip.ParseAddr(item)
				if err != nil {
					return fmt.Errorf("'%s' does not appear to be an IPv4 or IPv6 address", item)
				}
				if !a.Is4() {
					return errors.New("公共 DNS 当前仅支持 IPv4 地址")
				}
				if !seen[item] {
					seen[item] = true
					uniq = append(uniq, item)
				}
			}
			resolvers = strings.Join(uniq, ",")
			for _, item := range strings.Split(cidrs, ",") {
				if item = strings.TrimSpace(item); item != "" {
					if _, err := parseCIDRLoose(item); err != nil {
						return fmt.Errorf("'%s' does not appear to be an IPv4 or IPv6 network", item)
					}
				}
			}
			return nil
		}()
		if err != nil {
			c.flash(fmt.Sprintf("设置格式错误：%v", err), "error")
			c.redirect("/settings")
			return
		}
		setSetting("poll_interval", interval)
		setSetting("domain_check_interval", dci)
		setSetting("log_retention_days", lrd)
		setSetting("heartbeat_log_enabled", hb)
		setSetting("dns_resolvers", resolvers)
		setSetting("timezone", tz)
		setSetting("allowed_web_cidrs", cidrs)
		cleanupLogs(lrd)
		c.flash("设置已保存", "success")
		c.redirect("/settings")
		return
	} else if c.R.Method != "GET" {
		c.abort(405)
		return
	}
	hbOn := getSetting("heartbeat_log_enabled", "1") == "1"
	content := `
    <div class="card"><h2>运行设置</h2>
    <form method="post">` + c.csrfInput() + `
    <div class="row">
      <label>轮询周期（秒，30-3600）<input name="poll_interval" type="number" min="30" max="3600" value="` + e(getSetting("poll_interval", "60")) + `"></label>
      <label>域名健康检查周期（秒，60-86400）<input name="domain_check_interval" type="number" min="60" max="86400" value="` + e(getSetting("domain_check_interval", "300")) + `"></label>
      <label>日志保留天数（0=永久，建议 7）<input name="log_retention_days" type="number" min="0" max="3650" value="` + e(getSetting("log_retention_days", "7")) + `"></label>
      <label>自动调度日志
        <select name="heartbeat_log_enabled">
          <option value="1" ` + sel(hbOn) + `>开启（存在已启用任务时，每次自动轮询记录一条）</option>
          <option value="0" ` + sel(!hbOn) + `>关闭（仪表盘仍显示调度状态，不影响 DDNS）</option>
        </select>
      </label>
      <label>公共 DNS 健康检查服务器
        <input name="dns_resolvers" value="` + e(getSetting("dns_resolvers", "223.5.5.5,119.29.29.29,1.1.1.1,8.8.8.8")) + `">
        <div class="muted">逗号分隔，最多 8 个。管家会直接查询这些 DNS，不经过系统 DNS 缓存。默认：AliDNS、DNSPod、Cloudflare DNS、Google DNS。</div>
      </label>
      <label>时区<input name="timezone" value="` + e(getSetting("timezone", "Asia/Shanghai")) + `"></label>
    </div>
    <label>Web 来源 CIDR 白名单（可选，逗号分隔）<input name="allowed_web_cidrs" value="` + e(getSetting("allowed_web_cidrs", "")) + `" placeholder="例如 10.168.9.0/24"></label>
    <div class="muted">留空表示不限制来源；仍需登录。修改白名单前请确认你的管理终端在允许网段内。</div><br>
    <button>保存设置</button></form></div>
    <div class="card"><h2>修改管理员密码</h2>
    <form method="post" action="/change-password">` + c.csrfInput() + `
      <div class="row"><label>当前密码<input name="old_password" type="password" required></label><label>新密码<input name="new_password" type="password" minlength="10" required></label></div>
      <button>修改密码</button>
    </form></div>
    <div class="card"><h2>迁移 / 灾备</h2>
      <p>下载迁移包后，可在新服务器恢复当前数据库、DNS 服务商凭据、MSR SSH 密码、Web 管理员密码和加密密钥。</p>
      <div class="msg warning">迁移包包含加密密钥，等同于敏感凭据备份，请保存在安全位置。</div>
      <a class="btn" href="/backup/download">下载迁移备份</a>
      <div class="muted" style="margin-top:10px">新服务器恢复：先安装同版本/更高版本，再执行 <b>huboze-ddns-agent restore /path/backup.tar.gz</b>。</div>
    </div>
    <div class="card"><div class="actions" style="justify-content:space-between"><div><h2>运行环境自检</h2>
      <div class="muted">检查数据目录、数据库、密钥、系统时间、公共 DNS、DNS 服务商 API、ICMP、IPv6 出口、后台轮询和 MSR 设备状态。</div></div>
      <a class="btn" href="/selfcheck">开始自检</a></div></div>
    <div class="card"><h2>运行信息</h2>
      <div class="code">版本：` + Version + `（Go）
健康检查：/health
数据库：` + e(DBPath) + `
SSH 主机密钥记录：` + e(KnownHostsFile) + `</div>
    </div>`
	c.html(c.layout("设置", content, "settings_page"))
}

func changePasswordHandler(c *Ctx) {
	if !c.verifyCSRF() {
		return
	}
	old := c.R.FormValue("old_password")
	nw := c.R.FormValue("new_password")
	if len([]rune(nw)) < 10 {
		c.flash("新密码至少 10 位", "error")
		c.redirect("/settings")
		return
	}
	var hash string
	if err := DB.QueryRow("SELECT password_hash FROM users WHERE id=?", c.S.UserID).Scan(&hash); err != nil || !checkPasswordHash(hash, old) {
		c.flash("当前密码错误", "error")
		c.redirect("/settings")
		return
	}
	h, err := generatePasswordHash(nw)
	if err != nil {
		c.flash("修改失败："+err.Error(), "error")
		c.redirect("/settings")
		return
	}
	mustExec("UPDATE users SET password_hash=? WHERE id=?", h, c.S.UserID)
	c.flash("管理员密码已修改", "success")
	c.redirect("/settings")
}
