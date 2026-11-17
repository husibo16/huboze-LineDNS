package main

import (
	"fmt"
	"regexp"
	"strings"
)

// ---------------- Chinese wording for errors ----------------
//
// The Agent's own messages are written in Chinese. Errors that originate
// elsewhere (Go networking, SSH library, DNS provider APIs) arrive in English;
// they are translated here. Provider error codes are kept in brackets so they
// can still be looked up in the provider's documentation.

// providerHints maps well-known provider error codes to a Chinese explanation.
var providerHints = map[string]string{
	// 腾讯云
	"AuthFailure.SecretIdNotFound":      "SecretId 不存在或已删除",
	"AuthFailure.SignatureFailure":      "SecretKey 错误，签名校验失败",
	"AuthFailure.SignatureExpire":       "签名已过期，请检查服务器系统时间",
	"AuthFailure.InvalidSecretId":       "SecretId 格式不正确",
	"AuthFailure.UnauthorizedOperation": "该密钥没有调用此接口的权限",
	"UnauthorizedOperation":             "该密钥没有 DNSPod 操作权限",
	"ResourceNotFound.NoDataOfRecord":   "解析记录不存在",
	"InvalidParameter.DomainNotExists":  "域名不在该账号下",
	"RequestLimitExceeded":              "请求过于频繁，已被限流",
	// 阿里云
	"InvalidAccessKeyId.NotFound": "AccessKey ID 不存在或已删除",
	"InvalidAccessKeyId.Inactive": "AccessKey 已被禁用",
	"SignatureDoesNotMatch":       "AccessKey Secret 错误，签名校验失败",
	"InvalidTimeStamp.Expired":    "请求时间戳过期，请检查服务器系统时间",
	"Forbidden.RAM":               "RAM 用户没有云解析权限",
	"DomainRecordDuplicate":       "已存在相同的解析记录",
	"InvalidDomainName.NoExist":   "域名不在该账号下",
	"Throttling.User":             "请求过于频繁，已被限流",
	// 华为云
	"APIGW.0301": "AK/SK 认证失败，请检查 AK、SK 是否正确",
	"APIGW.0303": "AK/SK 认证失败，请检查 AK、SK 是否正确",
	"APIGW.0101": "接口不存在或区域（Region）填写错误",
	"APIGW.0308": "请求过于频繁，已被限流",
	"DNS.0302":   "域名不在该账号下",
	"DNS.0335":   "已存在相同的解析记录",
	"DNS.0005":   "没有操作该资源的权限",
}

// cfHints translates common Cloudflare API error messages.
var cfHints = [][2]string{
	{"Invalid API Token", "API Token 无效"},
	{"Invalid request headers", "API Token 无效或格式错误"},
	{"Authentication error", "认证失败，请检查 API Token 是否正确"},
	{"Unauthorized to access requested resource", "该 Token 没有访问此资源的权限（需要 Zone:DNS:Edit 和 Zone:Zone:Read）"},
	{"An identical record already exists", "已存在相同的解析记录"},
	{"Record does not exist", "解析记录不存在"},
	{"Rate limited", "请求过于频繁，已被限流"},
}

// providerError builds a Chinese error for a provider API failure.
func providerError(vendor, code, msg, requestID string) error {
	text := vendor + " API 返回错误"
	if hint, ok := providerHints[code]; ok {
		text = vendor + "：" + hint
	}
	detail := strings.TrimSpace(strings.Trim(code+"："+msg, "："))
	if requestID != "" {
		detail += "；RequestId " + requestID
	}
	if detail != "" {
		text += "（" + detail + "）"
	}
	return fmt.Errorf("%s", text)
}

func cloudflareError(msgs []string) error {
	var out []string
	for _, m := range msgs {
		zh := ""
		for _, h := range cfHints {
			if strings.Contains(strings.ToLower(m), strings.ToLower(h[0])) {
				zh = h[1]
				break
			}
		}
		if zh != "" {
			out = append(out, zh+"（"+m+"）")
		} else {
			out = append(out, m)
		}
	}
	return fmt.Errorf("Cloudflare：%s", strings.Join(out, "；"))
}

var netErrRules = []struct {
	re   *regexp.Regexp
	repl string
}{
	{regexp.MustCompile(`(?:dial tcp|dial udp) (\S+?): i/o timeout`), "连接 $1 超时"},
	{regexp.MustCompile(`(?:dial tcp|dial udp) (\S+?): connect: connection refused`), "$1 拒绝连接（端口未开放或被 ACL 拒绝）"},
	{regexp.MustCompile(`(?:dial tcp|dial udp) (\S+?): connect: no route to host`), "无法路由到 $1"},
	{regexp.MustCompile(`(?:dial tcp|dial udp) (\S+?): connect: network is unreachable`), "到 $1 的网络不可达"},
	{regexp.MustCompile(`(?:dial tcp|dial udp) (\S+?): connect: host is down`), "主机 $1 不在线"},
	{regexp.MustCompile(`dial tcp: lookup (\S+?)(?: on \S+)?: no such host`), "域名 $1 无法解析"},
	{regexp.MustCompile(`lookup (\S+?)(?: on \S+)?: no such host`), "域名 $1 无法解析"},
	{regexp.MustCompile(`(?:read|write) tcp \S+->(\S+?): read: connection reset by peer`), "与 $1 的连接被对方重置"},
	{regexp.MustCompile(`(?:read|write) tcp \S+->(\S+?): i/o timeout`), "与 $1 通信超时"},
	{regexp.MustCompile(`\(Client\.Timeout exceeded while awaiting headers\)`), "（等待响应超时）"},
	{regexp.MustCompile(`context deadline exceeded`), "请求超时"},
	{regexp.MustCompile(`tls: failed to verify certificate: x509: [^;）]*`), "TLS 证书校验失败（请检查服务器时间或网络是否被劫持）"},
	{regexp.MustCompile(`x509: certificate (?:has expired|is not yet valid)[^;）]*`), "TLS 证书不在有效期内（请检查服务器系统时间）"},
	{regexp.MustCompile(`x509: certificate signed by unknown authority`), "TLS 证书不受信任（网络可能被劫持）"},
	{regexp.MustCompile(`ssh: handshake failed: `), "SSH 握手失败："},
	{regexp.MustCompile(`ssh: unable to authenticate, attempted methods \[[^\]]*\], no supported methods remain`), "用户名或密码错误"},
	{regexp.MustCompile(`connection reset by peer`), "连接被对方重置"},
	{regexp.MustCompile(`broken pipe`), "连接已断开"},
	{regexp.MustCompile(`use of closed network connection`), "连接已关闭"},
	{regexp.MustCompile(`i/o timeout`), "超时"},
	{regexp.MustCompile(`(^|[：: ])EOF$`), "${1}连接被对方关闭"},
	{regexp.MustCompile(`unexpected EOF`), "连接意外中断"},
	{regexp.MustCompile(`^Interface (\S+) not found$`), "接口 $1 在设备上不存在（可能已改名或删除）"},
	{regexp.MustCompile(`Interface (\S+) not found`), "接口 $1 在设备上不存在"},
	{regexp.MustCompile(`first login password change required`), "H3C 账号要求首次登录改密"},
	{regexp.MustCompile(`password already tried once`), "密码已尝试过一次，为避免账号被锁定不再重试"},
	{regexp.MustCompile(`Device not found`), "设备不存在"},
	{regexp.MustCompile(`Cloudflare request failed: `), "Cloudflare 请求失败："},
	{regexp.MustCompile(`Cloudflare returned HTTP (\d+) with non-JSON response`), "Cloudflare 返回 HTTP $1 非 JSON 响应"},
	{regexp.MustCompile(`\[TencentCloudSDKException\] code:(\S+) message:(.*?) requestId:(\S+)`), "腾讯云 API 返回错误（$1：$2；RequestId $3）"},
	{regexp.MustCompile(`HTTP Status: (\d+) Error:(\S+) (.*?) RequestID: (\S+)`), "阿里云 API 返回错误（HTTP $1，$2：$3；RequestId $4）"},
}

// zhErr translates English error text from libraries and providers. It is
// applied when messages are displayed, so records stored by older versions
// are shown in Chinese too.
func zhErr(s string) string {
	if s == "" {
		return s
	}
	for _, r := range netErrRules {
		s = r.re.ReplaceAllString(s, r.repl)
	}
	// provider codes stored by older versions: add the hint in front
	for code, hint := range providerHints {
		if strings.Contains(s, code) && !strings.Contains(s, hint) {
			s = hint + "（" + s + "）"
			break
		}
	}
	return s
}

// resolverStatusZh is the Chinese label of a public-resolver query status.
func resolverStatusZh(st string) string {
	switch strings.ToUpper(st) {
	case "OK":
		return "正常"
	case "TIMEOUT":
		return "查询超时"
	case "SERVFAIL":
		return "服务器失败（SERVFAIL）"
	case "REFUSED":
		return "拒绝查询（REFUSED）"
	case "NXDOMAIN":
		return "记录不存在（NXDOMAIN）"
	case "NOANSWER":
		return "无此类型记录（NOANSWER）"
	case "", "ERROR":
		return "查询失败"
	}
	return st
}
