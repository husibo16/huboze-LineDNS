package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

var providerLabels = map[string]string{
	"cloudflare": "Cloudflare",
	"tencent":    "腾讯云 DNSPod",
	"aliyun":     "阿里云 DNS",
	"huawei":     "华为云 DNS",
}

func providerLabel(t string) string {
	if t == "" {
		t = "cloudflare"
	}
	if l, ok := providerLabels[t]; ok {
		return l
	}
	return t
}

var httpClient = &http.Client{Timeout: 15 * time.Second}

type Zone struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Status string `json:"status"`
}

type DNSRecord struct {
	ID      string   `json:"id"`
	Name    string   `json:"name"`
	Type    string   `json:"type"`
	Content string   `json:"content"`
	TTL     int      `json:"ttl"`
	Line    string   `json:"line,omitempty"`
	Status  string   `json:"status,omitempty"`
	Proxied bool     `json:"proxied"`
	Records []string `json:"records,omitempty"`
}

type ProviderConfig map[string]string

func providerConfig(p *Provider) (ProviderConfig, error) {
	cfg := ProviderConfig{}
	if p.ConfigEnc != "" {
		raw, err := decryptSecret(p.ConfigEnc)
		if err == nil {
			var m map[string]any
			err = json.Unmarshal([]byte(raw), &m)
			for k, v := range m {
				cfg[k] = fmt.Sprint(v)
			}
		}
		if err != nil {
			return nil, fmt.Errorf("DNS 服务商配置解密失败：%v", err)
		}
	}
	if p.ProviderType == "cloudflare" && cfg["token"] == "" && p.TokenEnc != "" {
		t, err := decryptSecret(p.TokenEnc)
		if err != nil {
			return nil, err
		}
		cfg["token"] = t
	}
	return cfg, nil
}

func providerPackConfig(cfg ProviderConfig) string {
	b, _ := json.Marshal(cfg)
	return encryptSecret(string(b))
}

// ---------------- helpers ----------------

func normalizeIP(v string) string {
	v = strings.TrimSpace(v)
	if a, err := netip.ParseAddr(v); err == nil {
		return a.String()
	}
	return v
}

func sameIP(a, b string) bool {
	x, e1 := netip.ParseAddr(strings.TrimSpace(a))
	y, e2 := netip.ParseAddr(strings.TrimSpace(b))
	if e1 == nil && e2 == nil {
		return x == y
	}
	return strings.ToLower(strings.TrimSpace(a)) == strings.ToLower(strings.TrimSpace(b))
}

func rrFromFQDN(recordName, zoneName string) string {
	recordName = strings.ToLower(strings.TrimRight(recordName, "."))
	zoneName = strings.ToLower(strings.TrimRight(zoneName, "."))
	if recordName == zoneName {
		return "@"
	}
	if strings.HasSuffix(recordName, "."+zoneName) {
		r := strings.TrimSuffix(recordName, "."+zoneName)
		if r == "" {
			return "@"
		}
		return r
	}
	return recordName
}

func fqdnFromRR(rr, zoneName string) string {
	rr = strings.TrimRight(rr, ".")
	zoneName = strings.ToLower(strings.TrimRight(zoneName, "."))
	if rr == "" || rr == "@" {
		return zoneName
	}
	l := strings.ToLower(rr)
	if l == zoneName || strings.HasSuffix(l, "."+zoneName) {
		return l
	}
	return l + "." + zoneName
}

// percentEncode is RFC 3986 encoding used by Aliyun and Huawei signers.
func percentEncode(s string) string {
	e := url.QueryEscape(s)
	e = strings.ReplaceAll(e, "+", "%20")
	e = strings.ReplaceAll(e, "*", "%2A")
	e = strings.ReplaceAll(e, "%7E", "~")
	return e
}

func hmacSHA256(key []byte, msg string) []byte {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(msg))
	return m.Sum(nil)
}

func sha256Hex(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

func readBody(resp *http.Response) []byte {
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	resp.Body.Close()
	return b
}

// ---------------- Cloudflare ----------------

var cfBase = "https://api.cloudflare.com/client/v4"

type cfResp struct {
	Success bool            `json:"success"`
	Errors  []any           `json:"errors"`
	Result  json.RawMessage `json:"result"`
	Info    struct {
		TotalPages int `json:"total_pages"`
	} `json:"result_info"`
}

func cfCall(token, method, path string, params url.Values, payload any) (*cfResp, error) {
	u := cfBase + path
	if len(params) > 0 {
		u += "?" + params.Encode()
	}
	var body io.Reader
	if payload != nil {
		b, _ := json.Marshal(payload)
		body = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, u, body)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("Cloudflare 请求失败：%v", err)
	}
	raw := readBody(resp)
	var data cfResp
	if err := json.Unmarshal(raw, &data); err != nil {
		return nil, fmt.Errorf("Cloudflare 返回 HTTP %d 非 JSON 响应", resp.StatusCode)
	}
	if resp.StatusCode >= 400 || !data.Success {
		var msgs []string
		for _, e := range data.Errors {
			if m, ok := e.(map[string]any); ok && m["message"] != nil {
				msgs = append(msgs, fmt.Sprint(m["message"]))
			} else {
				msgs = append(msgs, fmt.Sprint(e))
			}
		}
		if len(msgs) == 0 {
			return nil, fmt.Errorf("Cloudflare 返回 HTTP %d", resp.StatusCode)
		}
		return nil, cloudflareError(msgs)
	}
	return &data, nil
}

type cfRecord struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Type    string `json:"type"`
	Content string `json:"content"`
	TTL     int    `json:"ttl"`
	Proxied bool   `json:"proxied"`
}

func (r cfRecord) toRecord() DNSRecord {
	return DNSRecord{ID: r.ID, Name: r.Name, Type: strings.ToUpper(r.Type), Content: r.Content, TTL: r.TTL, Proxied: r.Proxied}
}

func cfListZones(token string) ([]Zone, error) {
	var zones []Zone
	for page := 1; page <= 20; page++ {
		data, err := cfCall(token, "GET", "/zones", url.Values{"per_page": {"50"}, "page": {strconv.Itoa(page)}}, nil)
		if err != nil {
			return nil, err
		}
		var batch []Zone
		_ = json.Unmarshal(data.Result, &batch)
		for i := range batch {
			if batch[i].Status == "" {
				batch[i].Status = "active"
			}
		}
		zones = append(zones, batch...)
		tp := data.Info.TotalPages
		if tp == 0 {
			tp = 1
		}
		if page >= tp {
			break
		}
	}
	return zones, nil
}

func cfListRecords(token, zoneID, recordType string) ([]DNSRecord, error) {
	var out []DNSRecord
	for page := 1; page <= 20; page++ {
		p := url.Values{"per_page": {"100"}, "page": {strconv.Itoa(page)}}
		if recordType != "" {
			p.Set("type", recordType)
		}
		data, err := cfCall(token, "GET", "/zones/"+url.PathEscape(zoneID)+"/dns_records", p, nil)
		if err != nil {
			return nil, err
		}
		var batch []cfRecord
		_ = json.Unmarshal(data.Result, &batch)
		for _, r := range batch {
			out = append(out, r.toRecord())
		}
		tp := data.Info.TotalPages
		if tp == 0 {
			tp = 1
		}
		if page >= tp {
			break
		}
	}
	return out, nil
}

func cfGetRecord(token, zoneID, recordID string) (DNSRecord, error) {
	data, err := cfCall(token, "GET", "/zones/"+url.PathEscape(zoneID)+"/dns_records/"+url.PathEscape(recordID), nil, nil)
	if err != nil {
		return DNSRecord{}, err
	}
	var r cfRecord
	_ = json.Unmarshal(data.Result, &r)
	if r.ID == "" {
		r.ID = recordID
	}
	return r.toRecord(), nil
}

func cfCreateRecord(token, zoneID, name, rtype, value string) (DNSRecord, error) {
	data, err := cfCall(token, "POST", "/zones/"+url.PathEscape(zoneID)+"/dns_records", nil, map[string]any{
		"type": rtype, "name": name, "content": normalizeIP(value), "ttl": 1, "proxied": false,
	})
	if err != nil {
		return DNSRecord{}, err
	}
	var r cfRecord
	_ = json.Unmarshal(data.Result, &r)
	return r.toRecord(), nil
}

func cfUpdateRecord(token, zoneID, recordID, value string) (DNSRecord, error) {
	data, err := cfCall(token, "PATCH", "/zones/"+url.PathEscape(zoneID)+"/dns_records/"+url.PathEscape(recordID), nil,
		map[string]any{"content": normalizeIP(value)})
	if err != nil {
		return DNSRecord{}, err
	}
	var r cfRecord
	_ = json.Unmarshal(data.Result, &r)
	return r.toRecord(), nil
}

// ---------------- Tencent Cloud DNSPod (TC3-HMAC-SHA256) ----------------

func tcCall(cfg ProviderConfig, action string, payload map[string]any, out any) error {
	sid := strings.TrimSpace(cfg["secret_id"])
	skey := strings.TrimSpace(cfg["secret_key"])
	if sid == "" || skey == "" {
		return errors.New("腾讯云 SecretId / SecretKey 为空")
	}
	const host = "dnspod.tencentcloudapi.com"
	const service = "dnspod"
	body, _ := json.Marshal(payload)
	now := time.Now().UTC()
	ts := strconv.FormatInt(now.Unix(), 10)
	date := now.Format("2006-01-02")
	ct := "application/json; charset=utf-8"
	canonical := "POST\n/\n\ncontent-type:" + ct + "\nhost:" + host + "\n\ncontent-type;host\n" + sha256Hex(body)
	scope := date + "/" + service + "/tc3_request"
	sts := "TC3-HMAC-SHA256\n" + ts + "\n" + scope + "\n" + sha256Hex([]byte(canonical))
	kDate := hmacSHA256([]byte("TC3"+skey), date)
	kService := hmacSHA256(kDate, service)
	kSigning := hmacSHA256(kService, "tc3_request")
	sig := hex.EncodeToString(hmacSHA256(kSigning, sts))
	auth := fmt.Sprintf("TC3-HMAC-SHA256 Credential=%s/%s, SignedHeaders=content-type;host, Signature=%s", sid, scope, sig)

	req, _ := http.NewRequest("POST", "https://"+host+"/", bytes.NewReader(body))
	req.Header.Set("Content-Type", ct)
	req.Header.Set("Host", host)
	req.Header.Set("Authorization", auth)
	req.Header.Set("X-TC-Action", action)
	req.Header.Set("X-TC-Timestamp", ts)
	req.Header.Set("X-TC-Version", "2021-03-23")
	resp, err := httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("腾讯云请求失败：%v", err)
	}
	raw := readBody(resp)
	var env struct {
		Response json.RawMessage `json:"Response"`
	}
	if err := json.Unmarshal(raw, &env); err != nil || len(env.Response) == 0 {
		return fmt.Errorf("腾讯云返回 HTTP %d 非 JSON 响应", resp.StatusCode)
	}
	var e struct {
		Error     *struct{ Code, Message string } `json:"Error"`
		RequestID string                          `json:"RequestId"`
	}
	_ = json.Unmarshal(env.Response, &e)
	if e.Error != nil {
		return providerError("腾讯云", e.Error.Code, e.Error.Message, e.RequestID)
	}
	if out != nil {
		return json.Unmarshal(env.Response, out)
	}
	return nil
}

func tcListZones(cfg ProviderConfig) ([]Zone, error) {
	var r struct {
		DomainList []struct {
			DomainId uint64
			Name     string
			Status   string
		}
	}
	if err := tcCall(cfg, "DescribeDomainList", map[string]any{"Offset": 0, "Limit": 3000}, &r); err != nil {
		return nil, err
	}
	var out []Zone
	for _, x := range r.DomainList {
		st := x.Status
		if st == "" {
			st = "ENABLE"
		}
		out = append(out, Zone{ID: strconv.FormatUint(x.DomainId, 10), Name: x.Name, Status: st})
	}
	return out, nil
}

func tcListRecords(cfg ProviderConfig, zoneName, recordType string) ([]DNSRecord, error) {
	p := map[string]any{"Domain": zoneName, "Offset": 0, "Limit": 3000, "ErrorOnEmpty": "no"}
	if recordType != "" {
		p["RecordType"] = recordType
	}
	var r struct {
		RecordList []struct {
			RecordId uint64
			Name     string
			Type     string
			Value    string
			TTL      int
			Line     string
			Status   string
		}
	}
	if err := tcCall(cfg, "DescribeRecordList", p, &r); err != nil {
		return nil, err
	}
	var out []DNSRecord
	for _, x := range r.RecordList {
		line := x.Line
		if line == "" {
			line = "默认"
		}
		st := x.Status
		if st == "" {
			st = "ENABLE"
		}
		name := x.Name
		if name == "" {
			name = "@"
		}
		out = append(out, DNSRecord{ID: strconv.FormatUint(x.RecordId, 10), Name: fqdnFromRR(name, zoneName),
			Type: strings.ToUpper(x.Type), Content: x.Value, TTL: x.TTL, Line: line, Status: st})
	}
	return out, nil
}

func tcGetRecord(cfg ProviderConfig, zoneName, recordID string) (DNSRecord, error) {
	id, err := strconv.ParseUint(recordID, 10, 64)
	if err != nil {
		return DNSRecord{}, fmt.Errorf("无效的腾讯云 RecordId：%s", recordID)
	}
	var r struct {
		RecordInfo struct {
			Id         uint64
			SubDomain  string
			RecordType string
			Value      string
			TTL        int
			RecordLine string
		}
	}
	if err := tcCall(cfg, "DescribeRecord", map[string]any{"Domain": zoneName, "RecordId": id}, &r); err != nil {
		return DNSRecord{}, err
	}
	x := r.RecordInfo
	rid := recordID
	if x.Id != 0 {
		rid = strconv.FormatUint(x.Id, 10)
	}
	line := x.RecordLine
	if line == "" {
		line = "默认"
	}
	sub := x.SubDomain
	if sub == "" {
		sub = "@"
	}
	return DNSRecord{ID: rid, Name: fqdnFromRR(sub, zoneName), Type: strings.ToUpper(x.RecordType), Content: x.Value, TTL: x.TTL, Line: line}, nil
}

func tcCreateRecord(cfg ProviderConfig, zoneName, name, rtype, value string) (DNSRecord, error) {
	var r struct{ RecordId uint64 }
	err := tcCall(cfg, "CreateRecord", map[string]any{
		"Domain": zoneName, "SubDomain": rrFromFQDN(name, zoneName), "RecordType": rtype,
		"RecordLine": "默认", "Value": normalizeIP(value), "TTL": 600,
	}, &r)
	if err != nil {
		return DNSRecord{}, err
	}
	id := ""
	if r.RecordId != 0 {
		id = strconv.FormatUint(r.RecordId, 10)
	}
	return DNSRecord{ID: id, Name: name, Type: rtype, Content: normalizeIP(value), TTL: 600, Line: "默认"}, nil
}

func tcUpdateRecord(cfg ProviderConfig, zoneName, recordID, name, rtype, value string) (DNSRecord, error) {
	cur, err := tcGetRecord(cfg, zoneName, recordID)
	if err != nil {
		return DNSRecord{}, err
	}
	id, _ := strconv.ParseUint(recordID, 10, 64)
	ttl := cur.TTL
	if ttl == 0 {
		ttl = 600
	}
	line := cur.Line
	if line == "" {
		line = "默认"
	}
	err = tcCall(cfg, "ModifyRecord", map[string]any{
		"Domain": zoneName, "RecordId": id, "SubDomain": rrFromFQDN(name, zoneName),
		"RecordType": rtype, "RecordLine": line, "Value": normalizeIP(value), "TTL": ttl,
	}, nil)
	if err != nil {
		return DNSRecord{}, err
	}
	cur.Name, cur.Type, cur.Content = name, rtype, normalizeIP(value)
	return cur, nil
}

// ---------------- Alibaba Cloud DNS (RPC, HMAC-SHA1) ----------------

func aliCall(cfg ProviderConfig, action string, params map[string]string, out any) error {
	ak := strings.TrimSpace(cfg["access_key_id"])
	sec := strings.TrimSpace(cfg["access_key_secret"])
	if ak == "" || sec == "" {
		return errors.New("阿里云 AccessKey ID / Secret 为空")
	}
	p := map[string]string{
		"Format": "JSON", "Version": "2015-01-09", "AccessKeyId": ak, "SignatureMethod": "HMAC-SHA1",
		"Timestamp": time.Now().UTC().Format("2006-01-02T15:04:05Z"), "SignatureVersion": "1.0",
		"SignatureNonce": randomURLSafe(16), "Action": action,
	}
	for k, v := range params {
		p[k] = v
	}
	keys := make([]string, 0, len(p))
	for k := range p {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var parts []string
	for _, k := range keys {
		parts = append(parts, percentEncode(k)+"="+percentEncode(p[k]))
	}
	canon := strings.Join(parts, "&")
	sts := "GET&" + percentEncode("/") + "&" + percentEncode(canon)
	m := hmac.New(sha1.New, []byte(sec+"&"))
	m.Write([]byte(sts))
	sig := base64.StdEncoding.EncodeToString(m.Sum(nil))
	u := "https://alidns.aliyuncs.com/?" + canon + "&Signature=" + percentEncode(sig)
	resp, err := httpClient.Get(u)
	if err != nil {
		return fmt.Errorf("阿里云请求失败：%v", err)
	}
	raw := readBody(resp)
	if resp.StatusCode != 200 {
		var e struct{ Code, Message, RequestId string }
		if json.Unmarshal(raw, &e) == nil && e.Code != "" {
			return providerError("阿里云", e.Code, e.Message, e.RequestId)
		}
		return fmt.Errorf("阿里云返回 HTTP %d", resp.StatusCode)
	}
	if out != nil {
		return json.Unmarshal(raw, out)
	}
	return nil
}

type aliRecord struct {
	RecordId   string
	RR         string
	Type       string
	Value      string
	TTL        int
	Line       string
	Status     string
	DomainName string
}

func (x aliRecord) toRecord(zoneName string) DNSRecord {
	line := x.Line
	if line == "" {
		line = "default"
	}
	st := x.Status
	if st == "" {
		st = "Enable"
	}
	rr := x.RR
	if rr == "" {
		rr = "@"
	}
	return DNSRecord{ID: x.RecordId, Name: fqdnFromRR(rr, zoneName), Type: strings.ToUpper(x.Type), Content: x.Value, TTL: x.TTL, Line: line, Status: st}
}

func aliListZones(cfg ProviderConfig) ([]Zone, error) {
	var zones []Zone
	for page := 1; page <= 100; page++ {
		var r struct {
			Domains struct {
				Domain []struct{ DomainId, DomainName string }
			}
		}
		if err := aliCall(cfg, "DescribeDomains", map[string]string{"PageNumber": strconv.Itoa(page), "PageSize": "100"}, &r); err != nil {
			return nil, err
		}
		for _, x := range r.Domains.Domain {
			id := x.DomainId
			if id == "" {
				id = x.DomainName
			}
			zones = append(zones, Zone{ID: id, Name: x.DomainName, Status: "ENABLE"})
		}
		if len(r.Domains.Domain) < 100 {
			break
		}
	}
	return zones, nil
}

func aliListRecords(cfg ProviderConfig, zoneName, recordType string) ([]DNSRecord, error) {
	var out []DNSRecord
	for page := 1; page <= 100; page++ {
		p := map[string]string{"DomainName": zoneName, "PageNumber": strconv.Itoa(page), "PageSize": "500"}
		if recordType != "" {
			p["TypeKeyWord"] = recordType
		}
		var r struct {
			DomainRecords struct{ Record []aliRecord }
		}
		if err := aliCall(cfg, "DescribeDomainRecords", p, &r); err != nil {
			return nil, err
		}
		for _, x := range r.DomainRecords.Record {
			rec := x.toRecord(zoneName)
			if recordType != "" && rec.Type != recordType {
				continue
			}
			out = append(out, rec)
		}
		if len(r.DomainRecords.Record) < 500 {
			break
		}
	}
	return out, nil
}

func aliGetRecord(cfg ProviderConfig, recordID string) (DNSRecord, error) {
	var x aliRecord
	if err := aliCall(cfg, "DescribeDomainRecordInfo", map[string]string{"RecordId": recordID}, &x); err != nil {
		return DNSRecord{}, err
	}
	if x.RecordId == "" {
		x.RecordId = recordID
	}
	return x.toRecord(x.DomainName), nil
}

func aliCreateRecord(cfg ProviderConfig, zoneName, name, rtype, value string) (DNSRecord, error) {
	var r struct{ RecordId string }
	err := aliCall(cfg, "AddDomainRecord", map[string]string{
		"DomainName": zoneName, "RR": rrFromFQDN(name, zoneName), "Type": rtype,
		"Value": normalizeIP(value), "TTL": "600", "Line": "default",
	}, &r)
	if err != nil {
		return DNSRecord{}, err
	}
	return DNSRecord{ID: r.RecordId, Name: name, Type: rtype, Content: normalizeIP(value), TTL: 600, Line: "default"}, nil
}

func aliUpdateRecord(cfg ProviderConfig, recordID, zoneName, name, rtype, value string) (DNSRecord, error) {
	cur, err := aliGetRecord(cfg, recordID)
	if err != nil {
		return DNSRecord{}, err
	}
	ttl := cur.TTL
	if ttl == 0 {
		ttl = 600
	}
	line := cur.Line
	if line == "" {
		line = "default"
	}
	err = aliCall(cfg, "UpdateDomainRecord", map[string]string{
		"RecordId": recordID, "RR": rrFromFQDN(name, zoneName), "Type": rtype,
		"Value": normalizeIP(value), "TTL": strconv.Itoa(ttl), "Line": line,
	}, nil)
	if err != nil {
		return DNSRecord{}, err
	}
	cur.Name, cur.Type, cur.Content = name, rtype, normalizeIP(value)
	return cur, nil
}

// ---------------- Huawei Cloud DNS (SDK-HMAC-SHA256) ----------------

var hwProjectCache sync.Map // key: ak|region -> project id

func hwSign(req *http.Request, body []byte, ak, sk string) {
	date := time.Now().UTC().Format("20060102T150405Z")
	req.Header.Set("X-Sdk-Date", date)
	hdrs := map[string]string{"host": req.URL.Host}
	for k, v := range req.Header {
		hdrs[strings.ToLower(k)] = strings.TrimSpace(strings.Join(v, ","))
	}
	var names []string
	for k := range hdrs {
		names = append(names, k)
	}
	sort.Strings(names)
	var canonHeaders strings.Builder
	for _, n := range names {
		canonHeaders.WriteString(n + ":" + hdrs[n] + "\n")
	}
	segs := strings.Split(req.URL.Path, "/")
	for i, s := range segs {
		segs[i] = percentEncode(s)
	}
	uri := strings.Join(segs, "/")
	if !strings.HasSuffix(uri, "/") {
		uri += "/"
	}
	q := req.URL.Query()
	var qkeys []string
	for k := range q {
		qkeys = append(qkeys, k)
	}
	sort.Strings(qkeys)
	var qparts []string
	for _, k := range qkeys {
		vals := q[k]
		sort.Strings(vals)
		for _, v := range vals {
			qparts = append(qparts, percentEncode(k)+"="+percentEncode(v))
		}
	}
	signed := strings.Join(names, ";")
	canonical := strings.Join([]string{req.Method, uri, strings.Join(qparts, "&"), canonHeaders.String(), signed, sha256Hex(body)}, "\n")
	sts := "SDK-HMAC-SHA256\n" + date + "\n" + sha256Hex([]byte(canonical))
	sig := hex.EncodeToString(hmacSHA256([]byte(sk), sts))
	req.Header.Set("Authorization", fmt.Sprintf("SDK-HMAC-SHA256 Access=%s, SignedHeaders=%s, Signature=%s", ak, signed, sig))
}

func hwRequest(method, rawURL string, payload any, ak, sk, projectID string, out any) error {
	var body []byte
	if payload != nil {
		body, _ = json.Marshal(payload)
	}
	req, err := http.NewRequest(method, rawURL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if projectID != "" {
		req.Header.Set("X-Project-Id", projectID)
	}
	hwSign(req, body, ak, sk)
	resp, err := httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("华为云请求失败：%v", err)
	}
	raw := readBody(resp)
	if resp.StatusCode >= 400 {
		var e struct {
			Code      string `json:"code"`
			Message   string `json:"message"`
			ErrorCode string `json:"error_code"`
			ErrorMsg  string `json:"error_msg"`
		}
		_ = json.Unmarshal(raw, &e)
		code, msg := e.Code, e.Message
		if code == "" {
			code, msg = e.ErrorCode, e.ErrorMsg
		}
		if code != "" || msg != "" {
			return providerError("华为云", code, msg, "")
		}
		return fmt.Errorf("华为云返回 HTTP %d", resp.StatusCode)
	}
	if out != nil && len(raw) > 0 {
		return json.Unmarshal(raw, out)
	}
	return nil
}

type hwClient struct {
	ak, sk, region, project string
}

func newHWClient(cfg ProviderConfig) (*hwClient, error) {
	ak, sk := strings.TrimSpace(cfg["ak"]), strings.TrimSpace(cfg["sk"])
	region := strings.TrimSpace(cfg["region"])
	if region == "" {
		region = "cn-north-4"
	}
	if ak == "" || sk == "" {
		return nil, errors.New("华为云 AK / SK 为空")
	}
	c := &hwClient{ak: ak, sk: sk, region: region}
	// Same as the Huawei SDK: resolve the project id of the region via IAM.
	key := ak + "|" + region
	if v, ok := hwProjectCache.Load(key); ok {
		c.project = v.(string)
	} else {
		var r struct {
			Projects []struct {
				ID string `json:"id"`
			} `json:"projects"`
		}
		u := "https://iam." + region + ".myhuaweicloud.com/v3/projects?name=" + url.QueryEscape(region)
		if hwRequest("GET", u, nil, ak, sk, "", &r) == nil && len(r.Projects) > 0 {
			c.project = r.Projects[0].ID
			hwProjectCache.Store(key, c.project)
		}
	}
	return c, nil
}

func (c *hwClient) do(method, path string, q url.Values, payload, out any) error {
	u := "https://dns." + c.region + ".myhuaweicloud.com" + path
	if len(q) > 0 {
		u += "?" + q.Encode()
	}
	return hwRequest(method, u, payload, c.ak, c.sk, c.project, out)
}

type hwRecordSet struct {
	ID      string   `json:"id"`
	Name    string   `json:"name"`
	Type    string   `json:"type"`
	TTL     int      `json:"ttl"`
	Records []string `json:"records"`
	Status  string   `json:"status"`
}

func (x hwRecordSet) toRecord() DNSRecord {
	content := ""
	if len(x.Records) > 0 {
		content = x.Records[0]
	}
	st := x.Status
	if st == "" {
		st = "ACTIVE"
	}
	return DNSRecord{ID: x.ID, Name: strings.TrimRight(x.Name, "."), Type: strings.ToUpper(x.Type), Content: content,
		Records: x.Records, TTL: x.TTL, Status: st}
}

func hwListZones(cfg ProviderConfig) ([]Zone, error) {
	c, err := newHWClient(cfg)
	if err != nil {
		return nil, err
	}
	var r struct {
		Zones []struct{ ID, Name, Status string } `json:"zones"`
	}
	if err := c.do("GET", "/v2/zones", url.Values{"type": {"public"}, "limit": {"500"}}, nil, &r); err != nil {
		return nil, err
	}
	var out []Zone
	for _, z := range r.Zones {
		st := z.Status
		if st == "" {
			st = "ACTIVE"
		}
		out = append(out, Zone{ID: z.ID, Name: strings.TrimRight(z.Name, "."), Status: st})
	}
	return out, nil
}

func hwListRecords(cfg ProviderConfig, zoneID, recordType string) ([]DNSRecord, error) {
	c, err := newHWClient(cfg)
	if err != nil {
		return nil, err
	}
	q := url.Values{"limit": {"500"}}
	if recordType != "" {
		q.Set("type", recordType)
	}
	var r struct {
		Recordsets []hwRecordSet `json:"recordsets"`
	}
	if err := c.do("GET", "/v2/zones/"+url.PathEscape(zoneID)+"/recordsets", q, nil, &r); err != nil {
		return nil, err
	}
	var out []DNSRecord
	for _, x := range r.Recordsets {
		rec := x.toRecord()
		if recordType != "" && rec.Type != recordType {
			continue
		}
		out = append(out, rec)
	}
	return out, nil
}

func hwGetRecord(cfg ProviderConfig, zoneID, recordID string) (DNSRecord, error) {
	c, err := newHWClient(cfg)
	if err != nil {
		return DNSRecord{}, err
	}
	var x hwRecordSet
	if err := c.do("GET", "/v2/zones/"+url.PathEscape(zoneID)+"/recordsets/"+url.PathEscape(recordID), nil, nil, &x); err != nil {
		return DNSRecord{}, err
	}
	if x.ID == "" {
		x.ID = recordID
	}
	return x.toRecord(), nil
}

func hwCreateRecord(cfg ProviderConfig, zoneID, name, rtype, value string) (DNSRecord, error) {
	c, err := newHWClient(cfg)
	if err != nil {
		return DNSRecord{}, err
	}
	ip := normalizeIP(value)
	var x hwRecordSet
	err = c.do("POST", "/v2/zones/"+url.PathEscape(zoneID)+"/recordsets", nil, map[string]any{
		"name": strings.TrimRight(name, ".") + ".", "type": rtype, "ttl": 300, "records": []string{ip},
	}, &x)
	if err != nil {
		return DNSRecord{}, err
	}
	ttl := x.TTL
	if ttl == 0 {
		ttl = 300
	}
	st := x.Status
	if st == "" {
		st = "PENDING_CREATE"
	}
	return DNSRecord{ID: x.ID, Name: name, Type: rtype, Content: ip, Records: []string{ip}, TTL: ttl, Status: st}, nil
}

func hwUpdateRecord(cfg ProviderConfig, zoneID, recordID, name, rtype, value string) (DNSRecord, error) {
	cur, err := hwGetRecord(cfg, zoneID, recordID)
	if err != nil {
		return DNSRecord{}, err
	}
	c, err := newHWClient(cfg)
	if err != nil {
		return DNSRecord{}, err
	}
	ttl := cur.TTL
	if ttl == 0 {
		ttl = 300
	}
	ip := normalizeIP(value)
	err = c.do("PUT", "/v2/zones/"+url.PathEscape(zoneID)+"/recordsets/"+url.PathEscape(recordID), nil, map[string]any{
		"name": strings.TrimRight(name, ".") + ".", "type": rtype, "ttl": ttl, "records": []string{ip},
	}, nil)
	if err != nil {
		return DNSRecord{}, err
	}
	cur.Name, cur.Type, cur.Content, cur.Records = name, rtype, ip, []string{ip}
	return cur, nil
}

// ---------------- Generic provider API ----------------

func errUnsupported(t string) error { return fmt.Errorf("不支持的 DNS 服务商类型：%s", t) }

func providerListZones(p *Provider) ([]Zone, error) {
	cfg, err := providerConfig(p)
	if err != nil {
		return nil, err
	}
	switch p.ProviderType {
	case "cloudflare":
		if cfg["token"] == "" {
			return nil, errors.New("Cloudflare Token 为空")
		}
		return cfListZones(cfg["token"])
	case "tencent":
		return tcListZones(cfg)
	case "aliyun":
		return aliListZones(cfg)
	case "huawei":
		return hwListZones(cfg)
	}
	return nil, errUnsupported(p.ProviderType)
}

func providerListRecords(p *Provider, zoneID, zoneName, recordType string) ([]DNSRecord, error) {
	cfg, err := providerConfig(p)
	if err != nil {
		return nil, err
	}
	switch p.ProviderType {
	case "cloudflare":
		return cfListRecords(cfg["token"], zoneID, recordType)
	case "tencent":
		return tcListRecords(cfg, zoneName, recordType)
	case "aliyun":
		return aliListRecords(cfg, zoneName, recordType)
	case "huawei":
		return hwListRecords(cfg, zoneID, recordType)
	}
	return nil, errUnsupported(p.ProviderType)
}

func providerFindRecord(p *Provider, zoneID, zoneName, recordName, recordType string) (*DNSRecord, error) {
	target := strings.ToLower(strings.TrimRight(recordName, "."))
	recs, err := providerListRecords(p, zoneID, zoneName, recordType)
	if err != nil {
		return nil, err
	}
	for _, r := range recs {
		if strings.ToLower(strings.TrimRight(r.Name, ".")) == target && strings.ToUpper(r.Type) == recordType {
			rr := r
			return &rr, nil
		}
	}
	return nil, nil
}

func providerGetRecord(p *Provider, zoneID, zoneName, recordID string) (DNSRecord, error) {
	cfg, err := providerConfig(p)
	if err != nil {
		return DNSRecord{}, err
	}
	switch p.ProviderType {
	case "cloudflare":
		return cfGetRecord(cfg["token"], zoneID, recordID)
	case "tencent":
		return tcGetRecord(cfg, zoneName, recordID)
	case "aliyun":
		return aliGetRecord(cfg, recordID)
	case "huawei":
		return hwGetRecord(cfg, zoneID, recordID)
	}
	return DNSRecord{}, errUnsupported(p.ProviderType)
}

func providerCreateRecord(p *Provider, zoneID, zoneName, recordName, recordType, value string) (DNSRecord, error) {
	cfg, err := providerConfig(p)
	if err != nil {
		return DNSRecord{}, err
	}
	switch p.ProviderType {
	case "cloudflare":
		return cfCreateRecord(cfg["token"], zoneID, recordName, recordType, value)
	case "tencent":
		return tcCreateRecord(cfg, zoneName, recordName, recordType, value)
	case "aliyun":
		return aliCreateRecord(cfg, zoneName, recordName, recordType, value)
	case "huawei":
		return hwCreateRecord(cfg, zoneID, recordName, recordType, value)
	}
	return DNSRecord{}, errUnsupported(p.ProviderType)
}

func providerUpdateRecord(p *Provider, zoneID, zoneName, recordID, recordName, recordType, value string) (DNSRecord, error) {
	cfg, err := providerConfig(p)
	if err != nil {
		return DNSRecord{}, err
	}
	switch p.ProviderType {
	case "cloudflare":
		return cfUpdateRecord(cfg["token"], zoneID, recordID, value)
	case "tencent":
		return tcUpdateRecord(cfg, zoneName, recordID, recordName, recordType, value)
	case "aliyun":
		return aliUpdateRecord(cfg, recordID, zoneName, recordName, recordType, value)
	case "huawei":
		return hwUpdateRecord(cfg, zoneID, recordID, recordName, recordType, value)
	}
	return DNSRecord{}, errUnsupported(p.ProviderType)
}
