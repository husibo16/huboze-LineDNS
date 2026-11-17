package main

import (
	"encoding/json"
	"fmt"
	"strings"
)

// ---------------- DNS 解析 ----------------
//
// Read-only view of how each mapped record actually resolves: the IP the
// Agent expects, what the DNS provider holds, and what every public resolver
// answers (with TTL), plus line reachability. Configuration stays on /mappings.

// backTo returns the form's "next" target when it is a local page, else def.
func backTo(c *Ctx, def string) string {
	n := c.R.FormValue("next")
	if strings.HasPrefix(n, "/") && !strings.HasPrefix(n, "//") && !strings.ContainsAny(n, "\\\r\n") {
		return n
	}
	return def
}

func dnsPageHandler(c *Ctx) {
	n := countWhere("SELECT COUNT(*) FROM mappings")
	content := ""
	if n == 0 {
		content = `<section class="card">` + emptyState("还没有需要检测的域名", "在“DNS 映射”中添加映射后，这里会显示每个域名在各公共 DNS 上的实际解析结果。", "/mappings?new=1#form", "添加映射") + `</section>`
	} else {
		content = liveRegion("dnslist", "/api/dns", "dns", renderDNSPage(c))
	}
	sub := fmt.Sprintf("Agent 直接查询公共 DNS（不经过本机缓存），每 %d 秒复检一次；传播中或异常的记录每 60 秒快速复检", getSettingInt("domain_check_interval", 300))
	c.html(c.layoutWith("DNS 解析", sub, "", content, "dns_page"))
}

func apiDNSHandler(c *Ctx) { c.fragment("dns", renderDNSPage(c)) }

// dnsState is the resolution state of one record (independent of sync state).
func dnsState(m *Mapping) (string, string) {
	if !m.Enabled {
		return "已停用", ""
	}
	switch strings.ToUpper(m.DNSStatus) {
	case "SUCCESS":
		switch strings.ToUpper(m.ReachabilityStatus) {
		case "TCP_FAIL", "PING_FAIL":
			return "已生效 · 不可达", "warn"
		}
		return "已生效", "ok"
	case "PROPAGATING":
		return "传播中", "info"
	case "DEGRADED":
		return "验证不足", "warn"
	case "ERROR":
		return "解析异常", "bad"
	}
	return "未检测", ""
}

func reachText(m *Mapping) (string, string) {
	switch strings.ToUpper(m.ReachabilityStatus) {
	case "TCP_OK":
		if m.CheckPort > 0 {
			return fmt.Sprintf("TCP %d 端口可连接", m.CheckPort), "ok"
		}
		return "TCP 可连接", "ok"
	case "TCP_FAIL":
		if m.CheckPort > 0 {
			return fmt.Sprintf("TCP %d 端口无法连接", m.CheckPort), "warn"
		}
		return "TCP 无法连接", "warn"
	case "PING_OK":
		return "ICMP 有响应", "ok"
	case "PING_FAIL":
		return "ICMP 无响应（部分线路默认禁 ping，仅供参考）", "warn"
	}
	return "未检测", ""
}

func renderDNSPage(c *Ctx) string {
	items := queryMappingsFull()
	counts := map[string]int{}
	for _, m := range items {
		l, _ := dnsState(m)
		counts[strings.SplitN(l, " ", 2)[0]]++
	}
	var b strings.Builder
	b.WriteString(`<div class="sumbar">`)
	for _, s := range []struct{ k, cls string }{{"已生效", "ok"}, {"传播中", "info"}, {"验证不足", "warn"}, {"解析异常", "bad"}, {"未检测", ""}, {"已停用", ""}} {
		if counts[s.k] == 0 && s.k != "已生效" {
			continue
		}
		fmt.Fprintf(&b, `<div class="sum"><span class="dot %s"></span>%s<b>%d</b></div>`, s.cls, e(s.k), counts[s.k])
	}
	b.WriteString(`</div><div class="dnsgrid">`)

	// problems first
	order := func(m *Mapping) int {
		switch _, cls := dnsState(m); cls {
		case "bad":
			return 0
		case "warn":
			return 1
		case "info":
			return 2
		case "ok":
			return 3
		}
		return 4
	}
	sorted := append([]*Mapping(nil), items...)
	for i := 1; i < len(sorted); i++ {
		for j := i; j > 0 && order(sorted[j]) < order(sorted[j-1]); j-- {
			sorted[j], sorted[j-1] = sorted[j-1], sorted[j]
		}
	}

	for _, m := range sorted {
		label, cls := dnsState(m)
		var probe probeDetails
		_ = json.Unmarshal([]byte(m.DNSResolverJSON), &probe)
		expected := probe.ExpectedIP
		if expected == "" {
			expected = m.CurrentIP
		}
		if expected == "" {
			expected = m.LastSyncedIP
		}

		fmt.Fprintf(&b, `<section class="card%s" id="m-%d"><div class="dev-head"><div style="min-width:0"><div class="dom-name" style="font-size:15px">%s <span class="tag">%s</span></div><div class="sub">%s · %s → %s</div></div>%s</div>`,
			ifs(m.Enabled, "", " dns-off"), m.ID, e(m.RecordName), e(m.RecordType), e(m.DeviceName), e(m.InterfaceName), e(m.ProviderName), pill(label, cls))

		// expected vs provider
		prov := `<span class="muted">未读取</span>`
		if probe.ProviderContent != "" {
			mark := ifs(sameIP(probe.ProviderContent, expected), ` <span class="ok">✓ 一致</span>`, ` <span class="bad">✗ 与期望不一致</span>`)
			prov = `<code>` + e(probe.ProviderContent) + `</code>` + mark
			if probe.Proxied {
				prov += ` <span class="tag">Cloudflare 代理</span>`
			}
		} else if probe.ProviderName != "" && !probe.ProviderOK {
			prov = `<span class="warn">读取服务商记录失败</span>`
		}
		rt, rc := reachText(m)
		fmt.Fprintf(&b, `<div class="kv"><div>期望 IP</div><div><code>%s</code></div><div>服务商记录</div><div>%s</div><div>线路可达性</div><div class="%s">%s</div><div>结论</div><div>%s</div></div>`,
			e(dash(expected)), prov, rc, e(rt), e(dash(m.DNSResolved)))

		// per-resolver answers
		if len(probe.Resolvers) > 0 {
			b.WriteString(`<div class="tbl"><table class="res"><tr><th>公共 DNS</th><th>返回</th><th>TTL</th><th>结果</th></tr>`)
			for _, r := range probe.Resolvers {
				name := r.Label
				if name == "" {
					name = r.Resolver
				}
				ttl := "-"
				if r.TTL != nil {
					ttl = fmt.Sprintf("%d 秒", *r.TTL)
				}
				ans, res := "-", ""
				switch r.Status {
				case "OK":
					ans = strings.Join(r.IPs, "<br>")
					if ans == "" {
						ans = "-"
					}
					if anySame(probe.ExpectedIP, r.IPs) {
						res = pill("已生效", "ok")
					} else {
						res = pill("旧值缓存中", "info")
					}
				case "NXDOMAIN", "NOANSWER":
					ans = `<span class="muted">` + e(resolverStatusZh(r.Status)) + `</span>`
					res = pill("负缓存", "info")
				default:
					st := r.Status
					if st == "" {
						st = "ERROR"
					}
					ans = `<span class="muted">` + e(resolverStatusZh(st)) + `</span>`
					res = pill("查询失败", "warn")
				}
				if r.Status == "OK" {
					var esc []string
					for _, ip := range r.IPs {
						esc = append(esc, e(ip))
					}
					ans = `<code>` + strings.Join(esc, "<br>") + `</code>`
					if len(esc) == 0 {
						ans = "-"
					}
				}
				errHTML := ""
				if r.Error != "" {
					errHTML = `<div class="sub">` + clip(r.Error, 40) + `</div>`
				}
				fmt.Fprintf(&b, `<tr><td class="nm">%s<div class="sub">%s</div></td><td>%s</td><td class="nm">%s</td><td>%s%s</td></tr>`,
					e(name), e(r.Resolver), ans, ttl, res, errHTML)
			}
			b.WriteString(`</table></div>`)
		} else {
			b.WriteString(`<div class="hint">还没有检测结果。点击“立即检测”马上查询一次。</div>`)
		}
		if strings.ToUpper(m.DNSStatus) == "PROPAGATING" && probe.PropagationTTLMax != nil {
			fmt.Fprintf(&b, `<div class="hint">部分公共 DNS 还缓存着旧记录，最长约 %d 秒后全部生效。</div>`, *probe.PropagationTTLMax)
		}
		if m.ReachabilityError != "" && strings.HasSuffix(strings.ToUpper(m.ReachabilityStatus), "FAIL") {
			b.WriteString(`<div class="sub" style="margin-top:6px">` + clip(m.ReachabilityError, 100) + `</div>`)
		}
		checkBtn := ""
		if m.Enabled {
			checkBtn = fmt.Sprintf(`<form method="post" action="/mapping/%d/check">%s<input type="hidden" name="next" value="/dns"><button class="small">立即检测</button></form>`, m.ID, c.csrfInput())
		}
		fmt.Fprintf(&b, `<div class="actions dcard-foot" style="justify-content:space-between"><span class="muted">最后检测 %s</span><div class="actions">%s<a class="btn btn2 small" href="/mappings?edit=%d#form">修改映射</a></div></div></section>`,
			tsSpan("", m.LastCheck), checkBtn, m.ID)
	}
	b.WriteString(`</div>`)
	return b.String()
}
