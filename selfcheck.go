package main

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

type CheckItem struct {
	Order    int
	Name     string
	Status   string // OK / WARN / FAIL
	Detail   string
	Critical bool
}

// clockSkew compares local time with the Date header of a cloud API endpoint.
func clockSkew() (time.Duration, string, error) {
	var lastErr error
	for _, u := range []string{"https://dnspod.tencentcloudapi.com", "https://alidns.aliyuncs.com", "https://api.cloudflare.com"} {
		c := &http.Client{Timeout: 5 * time.Second}
		before := time.Now()
		resp, err := c.Head(u)
		if err != nil {
			lastErr = err
			continue
		}
		resp.Body.Close()
		t, err := http.ParseTime(resp.Header.Get("Date"))
		if err != nil {
			lastErr = err
			continue
		}
		local := before.Add(time.Since(before) / 2)
		return local.Sub(t), u, nil
	}
	return 0, "", lastErr
}

func skewItem(order int) CheckItem {
	it := CheckItem{Order: order, Name: "系统时间"}
	skew, src, err := clockSkew()
	if err != nil {
		it.Status, it.Detail = "WARN", "无法获取网络时间进行比对："+err.Error()
		return it
	}
	abs := skew
	if abs < 0 {
		abs = -abs
	}
	it.Detail = fmt.Sprintf("与 %s 相差 %.1f 秒", strings.TrimPrefix(src, "https://"), skew.Seconds())
	switch {
	case abs <= 60*time.Second:
		it.Status = "OK"
	case abs <= 300*time.Second:
		it.Status, it.Detail = "WARN", it.Detail+"；建议开启 NTP 时间同步（timedatectl set-ntp true）"
	default:
		it.Status, it.Detail = "FAIL", it.Detail+"；时间偏差过大，腾讯云/阿里云/华为云 API 签名会被拒绝，请先同步系统时间"
	}
	return it
}

var providerEndpoints = map[string]string{
	"cloudflare": "https://api.cloudflare.com",
	"tencent":    "https://dnspod.tencentcloudapi.com",
	"aliyun":     "https://alidns.aliyuncs.com",
	"huawei":     "https://dns.cn-north-4.myhuaweicloud.com",
}

// runSelfCheck runs runtime environment checks inside the service.
func runSelfCheck() []CheckItem {
	var mu sync.Mutex
	var items []CheckItem
	add := func(it CheckItem) {
		mu.Lock()
		items = append(items, it)
		mu.Unlock()
	}
	var wg sync.WaitGroup
	run := func(f func()) {
		wg.Add(1)
		go func() { defer wg.Done(); f() }()
	}

	// 1. data dir writable
	run(func() {
		it := CheckItem{Order: 1, Name: "数据目录可写", Critical: true}
		p := filepath.Join(DataDir, ".selfcheck")
		if err := os.WriteFile(p, []byte("ok"), 0o600); err != nil {
			it.Status, it.Detail = "FAIL", fmt.Sprintf("%s 不可写：%v（检查目录属主是否为 10001:10001）", DataDir, err)
		} else {
			os.Remove(p)
			it.Status, it.Detail = "OK", DataDir
		}
		add(it)
	})
	// 2. database
	run(func() {
		it := CheckItem{Order: 2, Name: "数据库读写", Critical: true}
		if err := dbExec("INSERT OR REPLACE INTO runtime_state(key,value) VALUES('selfcheck_at',?)", nowStr()); err != nil {
			it.Status, it.Detail = "FAIL", err.Error()
		} else {
			it.Status, it.Detail = "OK", DBPath
		}
		add(it)
	})
	// 3. keys
	run(func() {
		it := CheckItem{Order: 3, Name: "加密密钥", Critical: true}
		tok := encryptSecret("selfcheck")
		if v, err := decryptSecret(tok); err != nil || v != "selfcheck" {
			it.Status, it.Detail = "FAIL", fmt.Sprintf("fernet.key 加解密失败：%v", err)
		} else {
			it.Status, it.Detail = "OK", "fernet.key 可用"
		}
		add(it)
	})
	// 4. clock
	run(func() { add(skewItem(4)) })
	// 5. public DNS resolvers
	run(func() {
		it := CheckItem{Order: 5, Name: "公共 DNS（UDP 53）"}
		res := queryPublicDNSMulti("dnspod.tencentcloudapi.com", "A")
		var ok, bad []string
		for _, r := range res {
			if r.Status == "OK" {
				ok = append(ok, r.Label)
			} else {
				bad = append(bad, fmt.Sprintf("%s(%s)=%s", r.Label, r.Resolver, r.Status))
			}
		}
		switch {
		case len(bad) == 0:
			it.Status, it.Detail = "OK", strings.Join(ok, "、")+" 均可查询"
		case len(ok) > 0:
			it.Status, it.Detail = "WARN", "部分不可用："+strings.Join(bad, "；")+"；域名检测会显示“DNS验证不足”"
		default:
			it.Status, it.Detail = "FAIL", "全部不可用："+strings.Join(bad, "；")+"；请检查出站 UDP 53 是否被防火墙拦截"
		}
		add(it)
	})
	// 6. provider APIs
	run(func() {
		it := CheckItem{Order: 6, Name: "DNS 服务商 API（HTTPS）"}
		types := map[string]bool{}
		for _, p := range queryProviders("WHERE enabled=1") {
			types[p.ProviderType] = true
		}
		if len(types) == 0 {
			it.Status, it.Detail = "WARN", "尚未配置 DNS 服务商"
			add(it)
			return
		}
		var ok, bad []string
		c := &http.Client{Timeout: 6 * time.Second}
		for t := range types {
			u := providerEndpoints[t]
			if u == "" {
				continue
			}
			resp, err := c.Head(u)
			if err != nil {
				bad = append(bad, providerLabel(t)+"："+err.Error())
				continue
			}
			resp.Body.Close()
			ok = append(ok, providerLabel(t))
		}
		sort.Strings(ok)
		if len(bad) == 0 {
			it.Status, it.Detail = "OK", strings.Join(ok, "、")+" 可访问"
		} else {
			it.Status, it.Detail = "FAIL", strings.Join(bad, "；")
		}
		add(it)
	})
	// 7. ICMP
	run(func() {
		it := CheckItem{Order: 7, Name: "ICMP（ping）"}
		if err := icmpPing("223.5.5.5", false, 3*time.Second); err != nil {
			it.Status, it.Detail = "WARN", "ping 223.5.5.5 失败："+err.Error()+"；可达性检测会显示“ICMP无响应”，可在映射中填写 TCP 检测端口代替"
		} else {
			it.Status, it.Detail = "OK", "ping 223.5.5.5 正常"
		}
		add(it)
	})
	// 8. IPv6
	run(func() {
		it := CheckItem{Order: 8, Name: "IPv6 出口"}
		r := queryDNSResolver("dnspod.tencentcloudapi.com", "2400:3200::1", "A")
		if r.Status == "OK" {
			it.Status, it.Detail = "OK", "可通过 IPv6 访问 AliDNS（2400:3200::1）；AAAA 可达性检测可用"
		} else {
			it.Status, it.Detail = "WARN", "本机没有可用的 IPv6 出口："+resolverStatusZh(r.Status)+" "+r.Error+"；不影响 A 记录，AAAA 映射的可达性检测会失败"
		}
		add(it)
	})
	// 9. poller heartbeat
	run(func() {
		it := CheckItem{Order: 9, Name: "后台轮询"}
		enDev := countWhere("SELECT COUNT(*) FROM devices WHERE enabled=1")
		enMap := countWhere("SELECT COUNT(*) FROM mappings WHERE enabled=1")
		rt := runtimeStateMap()
		hb := computeHeartbeat(rt, enDev > 0 || enMap > 0)
		detail := fmt.Sprintf("%s；最后调度：%s；结果：%s", hb.text, dash(rt["last_heartbeat"]), dash(rt["last_poll_result"]))
		switch {
		case hb.ok:
			it.Status = "OK"
		case hb.text == "等待首次调度":
			it.Status = "WARN"
		default:
			it.Status = "FAIL"
		}
		it.Detail = detail
		add(it)
	})
	// 10. devices
	run(func() {
		it := CheckItem{Order: 10, Name: "MSR 设备"}
		devs := queryDevices("ORDER BY id")
		var bad, disabled []string
		enabled := 0
		for _, d := range devs {
			if !d.Enabled {
				disabled = append(disabled, d.Name)
				continue
			}
			enabled++
			if d.LastStatus == "ERROR" {
				bad = append(bad, d.Name+"："+truncRunes(d.LastError, 80))
			}
		}
		switch {
		case len(devs) == 0:
			it.Status, it.Detail = "WARN", "尚未添加 MSR 设备"
		case len(bad) > 0:
			it.Status, it.Detail = "WARN", "异常："+strings.Join(bad, "；")
		default:
			it.Status, it.Detail = "OK", fmt.Sprintf("已启用 %d 台", enabled)
		}
		if len(disabled) > 0 {
			it.Detail += "；已禁用：" + strings.Join(disabled, "、")
			if it.Status == "OK" {
				it.Status = "WARN"
			}
		}
		add(it)
	})
	wg.Wait()
	sort.Slice(items, func(i, j int) bool { return items[i].Order < items[j].Order })
	return items
}

func statusIcon(s string) string {
	switch s {
	case "OK":
		return "✓"
	case "WARN":
		return "!"
	}
	return "✗"
}

func printCheckItems(items []CheckItem) (failCritical, failAny bool) {
	for _, it := range items {
		color := cGreen
		switch it.Status {
		case "WARN":
			color = cYellow
		case "FAIL":
			color = cRed
			failAny = true
			if it.Critical {
				failCritical = true
			}
		}
		fmt.Printf("  %s[%s]%s %-18s %s\n", color, statusIcon(it.Status), cReset, it.Name, zhErr(it.Detail))
	}
	return
}

// ---------------- Web page ----------------

func selfCheckHandler(c *Ctx) {
	items := runSelfCheck()
	var rows strings.Builder
	for _, it := range items {
		cls := map[string]string{"OK": "ok", "WARN": "warn", "FAIL": "bad"}[it.Status]
		label := map[string]string{"OK": "正常", "WARN": "注意", "FAIL": "失败"}[it.Status]
		fmt.Fprintf(&rows, `<tr><td>%s</td><td class="%s"><span class="status-badge">%s %s</span></td><td>%s</td></tr>`,
			e(it.Name), cls, statusIcon(it.Status), label, e(zhErr(it.Detail)))
	}
	content := `<div class="card"><div class="actions" style="justify-content:space-between">
      <div><h2>运行环境自检</h2><div class="muted">检查时间：` + e(nowStr()) + `。检测在容器内执行，结果反映 Agent 实际运行环境。</div></div>
      <a class="btn" href="/selfcheck">重新检测</a></div>
      <table><tr><th style="width:180px">检查项</th><th style="width:110px">结果</th><th>说明</th></tr>` + rows.String() + `</table></div>`
	c.html(c.layout("运行环境自检", content, "settings_page"))
}
