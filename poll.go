package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

var pollLock sync.Mutex

// ---------------- IP helpers ----------------

var nonGlobalPrefixes = func() []netip.Prefix {
	var out []netip.Prefix
	for _, s := range []string{
		// IPv4 (Python ipaddress is_private + shared address space)
		"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12",
		"192.0.0.0/24", "192.0.2.0/24", "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24",
		"203.0.113.0/24", "240.0.0.0/4", "255.255.255.255/32",
		// IPv6
		"::1/128", "::/128", "::ffff:0:0/96", "64:ff9b:1::/48", "100::/64", "2001::/23",
		"2001:db8::/32", "2002::/16", "3fff::/20", "fc00::/7", "fe80::/10", "ff00::/8",
	} {
		out = append(out, netip.MustParsePrefix(s))
	}
	return out
}()

var globalExceptions = func() []netip.Prefix {
	var out []netip.Prefix
	for _, s := range []string{"192.0.0.9/32", "192.0.0.10/32", "2001:1::1/128", "2001:1::2/128",
		"2001:3::/32", "2001:4:112::/48", "2001:20::/28", "2001:30::/28"} {
		out = append(out, netip.MustParsePrefix(s))
	}
	return out
}()

func isGlobalIP(ip netip.Addr) bool {
	for _, p := range globalExceptions {
		if p.Contains(ip) {
			return true
		}
	}
	for _, p := range nonGlobalPrefixes {
		if p.Contains(ip) {
			return false
		}
	}
	return true
}

func mappingIPFromInterface(iface Interface, recordType string) (string, error) {
	rt := strings.ToUpper(recordType)
	if rt == "" {
		rt = "A"
	}
	name := iface.Name
	if name == "" {
		name = "unknown"
	}
	// A line whose link protocol is down must not be published, even if the
	// table still shows a (stale) address for it.
	if proto := strings.ToLower(strings.TrimSpace(iface.Protocol)); proto != "" && !strings.HasPrefix(proto, "up") {
		return "", fmt.Errorf("接口 %s 协议状态为 %s（线路未连通），本轮跳过同步，避免把域名指向已断开的线路。", name, iface.Protocol)
	}
	switch rt {
	case "A":
		v := strings.TrimSpace(iface.IP)
		if v == "" {
			return "", fmt.Errorf("接口 %s 当前没有 IPv4 地址，无法同步 A 记录；这不会影响该设备的 AAAA 映射。", name)
		}
		a, err := netip.ParseAddr(v)
		if err != nil || !a.Is4() {
			return "", fmt.Errorf("接口 %s 返回的 IPv4 地址无效：%s", name, v)
		}
		if !isGlobalIP(a) {
			return "", fmt.Errorf("接口 %s 的 IPv4 地址 %s 不是公网地址（私网或运营商 NAT 100.64.0.0/10），不会写入 A 记录；请确认该线路是否有公网 IP。", name, v)
		}
		return a.String(), nil
	case "AAAA":
		v := strings.TrimSpace(iface.IPv6)
		if v == "" {
			return "", fmt.Errorf("接口 %s 当前没有获取到全局 IPv6 地址，无法同步 AAAA 记录；IPv4 A 记录可继续单独使用，不要求双栈同时开通。", name)
		}
		a, err := netip.ParseAddr(v)
		if err != nil || !a.Is6() {
			return "", fmt.Errorf("接口 %s 返回的 IPv6 地址无效：%s", name, v)
		}
		if !isGlobalIP(a) {
			return "", fmt.Errorf("接口 %s 的 IPv6 地址不是全局公网地址：%s，不会写入 AAAA 记录。", name, v)
		}
		return a.String(), nil
	}
	return "", fmt.Errorf("不支持的 DNS 记录类型：%s", rt)
}

// ---------------- Public DNS probing ----------------

var dnsResolverLabels = map[string]string{
	"223.5.5.5":    "AliDNS",
	"119.29.29.29": "DNSPod",
	"1.1.1.1":      "Cloudflare DNS",
	"8.8.8.8":      "Google DNS",
}

func resolverLabel(ip string) string {
	if l, ok := dnsResolverLabels[ip]; ok {
		return l
	}
	return ip
}

func configuredDNSResolvers() []string {
	raw := getSetting("dns_resolvers", "223.5.5.5,119.29.29.29,1.1.1.1,8.8.8.8")
	var out []string
	seen := map[string]bool{}
	for _, item := range strings.Split(raw, ",") {
		ip := strings.TrimSpace(item)
		if ip == "" || seen[ip] {
			continue
		}
		a, err := netip.ParseAddr(ip)
		if err != nil || !a.Is4() {
			continue
		}
		seen[ip] = true
		out = append(out, ip)
		if len(out) >= 8 {
			break
		}
	}
	if len(out) == 0 {
		out = []string{"223.5.5.5", "119.29.29.29", "1.1.1.1"}
	}
	return out
}

type ResolverResult struct {
	Resolver string   `json:"resolver"`
	Label    string   `json:"label"`
	Status   string   `json:"status"`
	IPs      []string `json:"ips"`
	TTL      *int     `json:"ttl"`
	Error    string   `json:"error"`
}

func negativeCacheTTL(m *dns.Msg) *int {
	if m == nil {
		return nil
	}
	for _, rr := range m.Ns {
		if soa, ok := rr.(*dns.SOA); ok {
			t := int(soa.Hdr.Ttl)
			if int(soa.Minttl) < t {
				t = int(soa.Minttl)
			}
			return &t
		}
	}
	return nil
}

func queryDNSResolver(recordName, resolverIP, recordType string) ResolverResult {
	res := ResolverResult{Resolver: resolverIP, Label: resolverLabel(resolverIP), IPs: []string{}}
	qtype := dns.TypeA
	if recordType == "AAAA" {
		qtype = dns.TypeAAAA
	}
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(recordName), qtype)
	m.RecursionDesired = true
	timeout := 2500 * time.Millisecond
	deadline := time.Now().Add(timeout)
	c := &dns.Client{Net: "udp", Timeout: timeout}
	server := net.JoinHostPort(resolverIP, "53")
	resp, _, err := c.Exchange(m, server)
	if err == nil && resp != nil && resp.Truncated && time.Until(deadline) > 0 {
		ct := &dns.Client{Net: "tcp", Timeout: time.Until(deadline)}
		if r2, _, err2 := ct.Exchange(m, server); err2 == nil {
			resp = r2
		}
	}
	if err != nil {
		var ne net.Error
		if errors.As(err, &ne) && ne.Timeout() {
			res.Status, res.Error = "TIMEOUT", "查询超时"
		} else {
			res.Status, res.Error = "ERROR", err.Error()
		}
		return res
	}
	switch resp.Rcode {
	case dns.RcodeSuccess:
	case dns.RcodeNameError:
		res.Status, res.TTL, res.Error = "NXDOMAIN", negativeCacheTTL(resp), "域名不存在（可能为负缓存）"
		return res
	default:
		res.Status = "ERROR"
		res.Error = fmt.Sprintf("DNS服务器不可用：%s answered %s", resolverIP, dns.RcodeToString[resp.Rcode])
		return res
	}
	set := map[string]bool{}
	var minTTL *int
	for _, rr := range resp.Answer {
		var ip string
		switch v := rr.(type) {
		case *dns.A:
			if qtype == dns.TypeA {
				ip = v.A.String()
			}
		case *dns.AAAA:
			if qtype == dns.TypeAAAA {
				ip = v.AAAA.String()
			}
		}
		if ip == "" {
			continue
		}
		set[ip] = true
		t := int(rr.Header().Ttl)
		if minTTL == nil || t < *minTTL {
			minTTL = &t
		}
	}
	for ip := range set {
		res.IPs = append(res.IPs, ip)
	}
	sort.Strings(res.IPs)
	if len(res.IPs) > 0 {
		res.Status, res.TTL = "OK", minTTL
	} else {
		res.Status, res.TTL = "NOANSWER", negativeCacheTTL(resp)
		res.Error = fmt.Sprintf("未返回 %s 记录（可能为负缓存）", recordType)
	}
	return res
}

func queryPublicDNSMulti(recordName, recordType string) []ResolverResult {
	ips := configuredDNSResolvers()
	results := make([]ResolverResult, len(ips))
	var wg sync.WaitGroup
	for i, ip := range ips {
		wg.Add(1)
		go func(i int, ip string) {
			defer wg.Done()
			results[i] = queryDNSResolver(recordName, ip, recordType)
		}(i, ip)
	}
	wg.Wait()
	return results
}

func anySame(expected string, ips []string) bool {
	for _, v := range ips {
		if sameIP(expected, v) {
			return true
		}
	}
	return false
}

func dnsProbeSummary(results []ResolverResult, expectedIP string, proxied bool) (string, int, int, int, int) {
	var responders, negatives, failures []ResolverResult
	for _, r := range results {
		switch {
		case r.Status == "OK" && len(r.IPs) > 0:
			responders = append(responders, r)
		case r.Status == "NXDOMAIN" || r.Status == "NOANSWER":
			negatives = append(negatives, r)
		default:
			failures = append(failures, r)
		}
	}
	total := len(results)
	if total == 0 {
		return "ERROR", 0, 0, 0, 0
	}
	var status string
	if proxied {
		positive := len(responders)
		switch {
		case positive == total:
			status = "SUCCESS"
		case positive > 0 && len(negatives) > 0:
			status = "PROPAGATING"
		case positive > 0 && len(failures) > 0:
			status = "DEGRADED"
		case len(negatives) > 0:
			status = "PROPAGATING"
		default:
			status = "ERROR"
		}
		return status, positive, 0, len(negatives), len(failures)
	}
	matched, stale := 0, 0
	for _, r := range responders {
		if anySame(expectedIP, r.IPs) {
			matched++
		} else {
			stale++
		}
	}
	switch {
	case matched == total:
		status = "SUCCESS"
	case matched > 0 && (stale > 0 || len(negatives) > 0):
		status = "PROPAGATING"
	case matched > 0 && len(failures) > 0:
		status = "DEGRADED"
	case stale > 0 || len(negatives) > 0:
		status = "PROPAGATING"
	default:
		status = "ERROR"
	}
	return status, matched, stale, len(negatives), len(failures)
}

func resolverDetailsText(results []ResolverResult, expectedIP string) string {
	var parts []string
	for _, r := range results {
		switch r.Status {
		case "OK":
			ips := strings.Join(r.IPs, ",")
			if ips == "" {
				ips = "-"
			}
			mark := "⏳"
			if anySame(expectedIP, r.IPs) {
				mark = "✓"
			}
			ttl := ""
			if r.TTL != nil {
				ttl = fmt.Sprintf(" TTL≈%d秒", *r.TTL)
			}
			parts = append(parts, fmt.Sprintf("%s(%s)=%s %s%s", r.Label, r.Resolver, ips, mark, ttl))
		case "NXDOMAIN", "NOANSWER":
			ttl := ""
			if r.TTL != nil {
				ttl = fmt.Sprintf(" 负缓存TTL≈%d秒", *r.TTL)
			}
			parts = append(parts, strings.TrimSpace(fmt.Sprintf("%s(%s)=%s ⏳%s %s", r.Label, r.Resolver, r.Status, ttl, r.Error)))
		default:
			parts = append(parts, strings.TrimSpace(fmt.Sprintf("%s(%s)=%s %s", r.Label, r.Resolver, r.Status, r.Error)))
		}
	}
	return strings.Join(parts, "；")
}

type probeDetails struct {
	ExpectedIP        string           `json:"expected_ip"`
	ProviderName      string           `json:"provider_name"`
	ProviderContent   string           `json:"provider_content"`
	ProviderOK        bool             `json:"provider_ok"`
	RecordType        string           `json:"record_type"`
	Proxied           bool             `json:"proxied"`
	MatchedCount      int              `json:"matched_count"`
	StaleCount        int              `json:"stale_count"`
	NegativeCount     int              `json:"negative_count"`
	FailureCount      int              `json:"failure_count"`
	StaleTTLMin       *int             `json:"stale_ttl_min"`
	StaleTTLMax       *int             `json:"stale_ttl_max"`
	NegativeTTLMin    *int             `json:"negative_ttl_min"`
	NegativeTTLMax    *int             `json:"negative_ttl_max"`
	PropagationTTLMax *int             `json:"propagation_ttl_max"`
	Resolvers         []ResolverResult `json:"resolvers"`
}

type domainCheckResult struct {
	DNSStatus          string
	ResolvedIPs        []string
	ResolverResults    []ResolverResult
	ReachabilityStatus string
	Errors             []string
	// ProviderChecked is true when the provider API returned the record.
	ProviderChecked bool
	ProviderContent string
}

func minMax(v []int) (*int, *int) {
	if len(v) == 0 {
		return nil, nil
	}
	mn, mx := v[0], v[0]
	for _, x := range v {
		if x < mn {
			mn = x
		}
		if x > mx {
			mx = x
		}
	}
	return &mn, &mx
}

func checkMappingDomain(m *Mapping, expectedIP string, writeLog bool) domainCheckResult {
	recordName := m.RecordName
	recordType := strings.ToUpper(m.RecordType)
	if recordType == "" {
		recordType = "A"
	}
	checkPort := m.CheckPort
	oldDNS, oldReach := m.DNSStatus, m.ReachabilityStatus
	reach := "UNKNOWN"
	var errs []string

	providerContent := ""
	providerChecked := false
	providerOK := false
	proxied := false
	providerName := "DNS 服务商"

	func() {
		p := getProvider(m.ProviderID)
		if p == nil {
			errs = append(errs, providerName+" API 校验失败：DNS 服务商不存在")
			return
		}
		providerName = providerLabel(p.ProviderType)
		rec, err := providerGetRecord(p, m.ZoneID, m.ZoneName, m.RecordID)
		if err != nil {
			errs = append(errs, fmt.Sprintf("%s API 校验失败：%v", providerName, err))
			return
		}
		providerContent = rec.Content
		providerChecked = true
		proxied = rec.Proxied
		providerOK = sameIP(providerContent, expectedIP)
		if !providerOK {
			c := providerContent
			if c == "" {
				c = "-"
			}
			errs = append(errs, fmt.Sprintf("%s 记录值=%s，预期=%s", providerName, c, expectedIP))
		}
	}()

	results := queryPublicDNSMulti(recordName, recordType)
	dnsStatus, matched, stale, negative, failure := dnsProbeSummary(results, expectedIP, proxied)

	if !proxied {
		switch dnsStatus {
		case "PROPAGATING":
			errs = append(errs, fmt.Sprintf("公共 DNS 尚未全部生效：已更新 %d，旧 IP 缓存 %d，负缓存 %d，查询失败 %d", matched, stale, negative, failure))
		case "DEGRADED":
			errs = append(errs, fmt.Sprintf("公共 DNS 验证不完整：已确认 %d，查询失败 %d", matched, failure))
		case "ERROR":
			errs = append(errs, "多个公共 DNS 均未能确认当前公网 IP")
		}
	} else if dnsStatus != "SUCCESS" {
		errs = append(errs, fmt.Sprintf("Cloudflare 代理记录尚未被全部公共 DNS 正常解析：负缓存 %d，查询失败 %d", negative, failure))
	}
	if providerContent != "" && !providerOK {
		dnsStatus = "ERROR"
	}

	allSet := map[string]bool{}
	var staleTTLs, negTTLs []int
	for _, r := range results {
		if r.Status == "OK" {
			for _, ip := range r.IPs {
				allSet[ip] = true
			}
			if !anySame(expectedIP, r.IPs) && r.TTL != nil {
				staleTTLs = append(staleTTLs, *r.TTL)
			}
		}
		if (r.Status == "NXDOMAIN" || r.Status == "NOANSWER") && r.TTL != nil {
			negTTLs = append(negTTLs, *r.TTL)
		}
	}
	var allResolved []string
	for ip := range allSet {
		allResolved = append(allResolved, ip)
	}
	sort.Strings(allResolved)
	staleMin, staleMax := minMax(staleTTLs)
	negMin, negMax := minMax(negTTLs)
	_, propMax := minMax(append(append([]int{}, staleTTLs...), negTTLs...))

	target := expectedIP
	if proxied {
		target = recordName
	}
	if dnsStatus == "SUCCESS" || dnsStatus == "PROPAGATING" || dnsStatus == "DEGRADED" {
		if checkPort > 0 {
			c, err := net.DialTimeout("tcp", net.JoinHostPort(target, strconv.Itoa(checkPort)), 3*time.Second)
			if err == nil {
				c.Close()
				reach = "TCP_OK"
			} else {
				reach = "TCP_FAIL"
				errs = append(errs, fmt.Sprintf("TCP %s:%d 不可达：%v", target, checkPort, err))
			}
		} else {
			err := icmpPing(target, recordType == "AAAA", 3*time.Second)
			switch {
			case err == nil:
				reach = "PING_OK"
			case strings.Contains(err.Error(), "超时无响应"):
				reach = "PING_FAIL"
				errs = append(errs, fmt.Sprintf("ICMP %s 无响应（不一定代表业务不可用）", target))
			default:
				reach = "PING_FAIL"
				errs = append(errs, fmt.Sprintf("ICMP 检测失败：%v", err))
			}
		}
	}

	details := probeDetails{
		ExpectedIP: expectedIP, ProviderName: providerName, ProviderContent: providerContent, ProviderOK: providerOK,
		RecordType: recordType, Proxied: proxied, MatchedCount: matched, StaleCount: stale, NegativeCount: negative,
		FailureCount: failure, StaleTTLMin: staleMin, StaleTTLMax: staleMax, NegativeTTLMin: negMin,
		NegativeTTLMax: negMax, PropagationTTLMax: propMax, Resolvers: results,
	}
	var resolved string
	n := len(results)
	if proxied {
		resolved = fmt.Sprintf("公共DNS响应 %d/%d", matched, n)
	} else {
		switch dnsStatus {
		case "SUCCESS":
			resolved = fmt.Sprintf("%d/%d 一致", matched, n)
		case "PROPAGATING":
			resolved = fmt.Sprintf("%d/%d 已生效", matched, n)
			if propMax != nil {
				resolved += fmt.Sprintf(" / 传播缓存TTL最长≈%d秒", *propMax)
			} else if negative > 0 {
				resolved += fmt.Sprintf(" / 负缓存 %d", negative)
			}
		default:
			resolved = fmt.Sprintf("%d/%d 已确认", matched, n)
		}
	}
	dj, _ := json.Marshal(details)
	ts := nowStr()
	mustExec(`UPDATE mappings SET last_check=?,last_check_epoch=?,dns_status=?,dns_resolved=?,dns_resolver_json=?,
		reachability_status=?,reachability_error=?,updated_at=? WHERE id=?`,
		ts, epochNow(), dnsStatus, resolved, string(dj), reach, truncRunes(strings.Join(errs, "；"), 2000), ts, m.ID)

	if writeLog || oldDNS != dnsStatus || oldReach != reach {
		label, _ := domainStatusZh(dnsStatus, reach)
		level := "WARNING"
		if dnsStatus == "SUCCESS" {
			level = "SUCCESS"
		} else if dnsStatus == "ERROR" {
			level = "ERROR"
		}
		pc := providerContent
		if pc == "" {
			pc = "-"
		}
		portText := "ICMP"
		if checkPort > 0 {
			portText = strconv.Itoa(checkPort)
		}
		detail := strings.Join(errs, "；")
		if detail == "" {
			detail = "正常"
		}
		logEvent(level, "DOMAIN_CHECK", fmt.Sprintf("%s：%s", recordName, label),
			fmt.Sprintf("%s=%s；类型=%s；预期IP=%s；%s；可达性目标=%s:%s；详情=%s",
				providerName, pc, recordType, expectedIP, resolverDetailsText(results, expectedIP), target, portText, detail))
	}
	return domainCheckResult{DNSStatus: dnsStatus, ResolvedIPs: allResolved, ResolverResults: results, ReachabilityStatus: reach, Errors: errs,
		ProviderChecked: providerChecked, ProviderContent: providerContent}
}

func domainCheckDue(m *Mapping) bool {
	interval := getSettingInt("domain_check_interval", 300)
	interval = clamp(interval, 60, 86400)
	switch strings.ToUpper(m.DNSStatus) {
	case "PROPAGATING", "DEGRADED", "ERROR", "UNKNOWN", "":
		if interval > 60 {
			interval = 60
		}
	}
	return epochNow()-m.LastCheckEpoch >= float64(interval)
}

func clamp(v, lo, hi int) int {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

func syncMapping(m *Mapping, ip string, force bool) (string, error) {
	p := getProvider(m.ProviderID)
	if p == nil || !p.Enabled {
		return "", errors.New("DNS 服务商已停用或不存在")
	}
	if !force && sameIP(m.LastSyncedIP, ip) {
		return "UNCHANGED", nil
	}
	rt := strings.ToUpper(m.RecordType)
	res, err := providerUpdateRecord(p, m.ZoneID, m.ZoneName, m.RecordID, m.RecordName, rt, ip)
	if err != nil {
		return "", err
	}
	if res.Content != "" && !sameIP(res.Content, ip) {
		return "", fmt.Errorf("DNS 服务商返回值不一致：returned %s, expected %s", res.Content, ip)
	}
	return "UPDATED", nil
}

type PollSummary struct {
	Devices, Mappings, Updated, Errors int
}

type PollResult struct {
	Success bool
	Message string
	Summary PollSummary
}

func storeDeviceOnline(id int64, ifaces []Interface) {
	b, _ := json.Marshal(ifaces)
	ts := nowStr()
	mustExec(`UPDATE devices SET last_status='ONLINE',last_error='',last_seen=?,
		online_since=CASE WHEN last_status='ONLINE' AND online_since<>'' THEN online_since ELSE ? END,
		last_interfaces_json=?,updated_at=? WHERE id=?`, ts, ts, string(b), ts, id)
}

func storeDeviceError(id int64, err error) {
	mustExec("UPDATE devices SET last_status='ERROR',last_error=?,online_since='',updated_at=? WHERE id=?",
		truncRunes(err.Error(), 1000), nowStr(), id)
}

func pollOnce(force bool, deviceID, mappingID int64) PollResult {
	if !pollLock.TryLock() {
		return PollResult{Success: false, Message: "poll already running"}
	}
	defer pollLock.Unlock()
	var s PollSummary

	var devices []*Device
	if deviceID != 0 {
		devices = queryDevices("WHERE enabled=1 AND id=?", deviceID)
	} else {
		devices = queryDevices("WHERE enabled=1 ORDER BY id")
	}
	for _, d := range devices {
		s.Devices++
		ifaces, err := collectDevice(d)
		if err != nil {
			storeDeviceError(d.ID, err)
			s.Errors++
			logEvent("ERROR", "MSR_POLL", fmt.Sprintf("%s: %v", d.Name, err))
			if isLockoutRisk(err) {
				// Never keep retrying a bad credential: that is what locks the H3C account.
				mustExec("UPDATE devices SET enabled=0,updated_at=? WHERE id=?", nowStr(), d.ID)
				logEvent("WARNING", "MSR_DISABLE", fmt.Sprintf("%s 已被自动禁用：认证失败/账号锁定/需首次改密，继续重试会导致 H3C 账号被反复锁定。请修正密码后在“MSR 设备”页面重新启用。", d.Name))
			}
			continue
		}
		imap := map[string]Interface{}
		for _, x := range ifaces {
			imap[x.Name] = x
		}
		storeDeviceOnline(d.ID, ifaces)
		var maps []*Mapping
		if mappingID != 0 {
			maps = queryMappings("WHERE m.enabled=1 AND m.device_id=? AND m.id=?", d.ID, mappingID)
		} else {
			maps = queryMappings("WHERE m.enabled=1 AND m.device_id=? ORDER BY m.id", d.ID)
		}
		for _, m := range maps {
			s.Mappings++
			iface, ok := imap[m.InterfaceName]
			if !ok {
				e := fmt.Sprintf("接口 %s 在设备上不存在（可能已改名或删除）", m.InterfaceName)
				mustExec("UPDATE mappings SET last_status='ERROR',last_error=?,updated_at=? WHERE id=?", e, nowStr(), m.ID)
				s.Errors++
				if !(m.LastStatus == "ERROR" && m.LastError == e) { // log state changes only
					logEvent("ERROR", "INTERFACE", fmt.Sprintf("%s: %s", m.Name, e))
				}
				continue
			}
			ip, err := mappingIPFromInterface(iface, m.RecordType)
			if err != nil {
				msg := truncRunes(err.Error(), 1000)
				mustExec("UPDATE mappings SET current_ip='',last_status='ERROR',last_error=?,updated_at=? WHERE id=?",
					msg, nowStr(), m.ID)
				s.Errors++
				if !(m.LastStatus == "ERROR" && m.LastError == msg) {
					logEvent("WARNING", "INTERFACE", fmt.Sprintf("%s: %v", m.Name, err),
						fmt.Sprintf("interface=%s; record_type=%s", m.InterfaceName, m.RecordType))
				}
				continue
			}
			mustExec("UPDATE mappings SET current_ip=?,updated_at=? WHERE id=?", ip, nowStr(), m.ID)
			action, err := syncMapping(m, ip, force)
			if err != nil {
				mustExec("UPDATE mappings SET last_status='ERROR',last_error=?,updated_at=? WHERE id=?",
					truncRunes(err.Error(), 1000), nowStr(), m.ID)
				s.Errors++
				logEvent("ERROR", "DNS_UPDATE", fmt.Sprintf("%s: %v", m.Name, err))
				continue
			}
			if action == "UPDATED" {
				ts := nowStr()
				mustExec("UPDATE mappings SET last_synced_ip=?,last_status='SUCCESS',last_error='',last_sync=?,updated_at=? WHERE id=?",
					ip, ts, ts, m.ID)
				s.Updated++
				logEvent("SUCCESS", "DNS_UPDATE", fmt.Sprintf("%s -> %s", m.RecordName, ip), "接口="+m.InterfaceName)
			} else {
				mustExec("UPDATE mappings SET last_status='SUCCESS',last_error='',updated_at=? WHERE id=?", nowStr(), m.ID)
			}
			if domainCheckDue(m) || action == "UPDATED" {
				if fresh := getMapping(m.ID); fresh != nil {
					r := checkMappingDomain(fresh, ip, action == "UPDATED")
					// Self-heal drift: the record was changed outside the Agent.
					if action != "UPDATED" && r.ProviderChecked && r.ProviderContent != "" && !sameIP(r.ProviderContent, ip) {
						if _, err := syncMapping(fresh, ip, true); err != nil {
							logEvent("ERROR", "DNS_UPDATE", fmt.Sprintf("%s 被外部修改为 %s，自动纠正失败：%v", m.RecordName, r.ProviderContent, err))
						} else {
							ts := nowStr()
							mustExec("UPDATE mappings SET last_synced_ip=?,last_status='SUCCESS',last_error='',last_sync=?,last_check_epoch=0,updated_at=? WHERE id=?",
								ip, ts, ts, m.ID)
							s.Updated++
							logEvent("WARNING", "DNS_UPDATE", fmt.Sprintf("%s 记录被外部修改为 %s，已自动纠正为 %s", m.RecordName, r.ProviderContent, ip),
								"接口="+m.InterfaceName)
						}
					}
				}
			}
		}
	}
	return PollResult{Success: true, Summary: s}
}

func recordHeartbeat(r PollResult, durationMS int) {
	runtimeTick()
	count, _ := strconv.Atoi(getRuntimeState("poll_count", "0"))
	count++
	s := r.Summary
	text := fmt.Sprintf("设备 %d，映射 %d，更新 %d，错误 %d", s.Devices, s.Mappings, s.Updated, s.Errors)
	for k, v := range map[string]string{
		"last_heartbeat":        nowStr(),
		"last_heartbeat_epoch":  fmtFloat(epochNow()),
		"last_poll_duration_ms": strconv.Itoa(durationMS),
		"last_poll_result":      text,
		"poll_count":            strconv.Itoa(count),
	} {
		setRuntimeState(k, v)
	}
	if (s.Devices > 0 || s.Mappings > 0) && getSetting("heartbeat_log_enabled", "1") == "1" {
		logEvent("INFO", "HEARTBEAT", fmt.Sprintf("第 %d 次自动轮询完成：%s", count, text),
			fmt.Sprintf("耗时=%dms；周期=%s秒", durationMS, getSetting("poll_interval", "60")))
	}
	cleanupLogs(getSettingInt("log_retention_days", 7))
}

func pollerLoop(ctx context.Context) {
	select {
	case <-ctx.Done():
		return
	case <-time.After(5 * time.Second):
	}
	for {
		started := time.Now()
		var res PollResult
		func() {
			defer func() {
				if rec := recover(); rec != nil {
					res = PollResult{Summary: PollSummary{Errors: 1}}
					logEvent("ERROR", "POLLER", fmt.Sprint(rec))
				}
			}()
			res = pollOnce(false, 0, 0)
		}()
		recordHeartbeat(res, int(time.Since(started).Milliseconds()))
		interval := clamp(getSettingInt("poll_interval", 60), 30, 3600)
		select {
		case <-ctx.Done():
			return
		case <-time.After(time.Duration(interval) * time.Second):
		}
	}
}

// isLockoutRisk reports errors where retrying the same credential can lock the H3C account.
func isLockoutRisk(err error) bool {
	m := err.Error()
	return strings.Contains(m, "SSH 认证失败") || strings.Contains(m, "账号已被临时锁定") || strings.Contains(m, "首次登录改密")
}

// testAndStoreDevice runs an SSH collection and stores the outcome.
func testAndStoreDevice(id int64) ([]Interface, error) {
	d := getDevice(id)
	if d == nil {
		return nil, errors.New("设备不存在")
	}
	ifaces, err := collectDevice(d)
	if err != nil {
		storeDeviceError(id, err)
		logEvent("ERROR", "MSR_TEST", fmt.Sprintf("%s: %v", d.Name, err))
		return nil, err
	}
	storeDeviceOnline(id, ifaces)
	b, _ := json.Marshal(ifaces)
	logEvent("SUCCESS", "MSR_TEST", d.Name+" SSH/CLI 测试通过", string(b))
	return ifaces, nil
}
