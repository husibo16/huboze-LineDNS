package main

import (
	"strings"
	"testing"
)

func TestZhErr(t *testing.T) {
	cases := map[string]string{
		"SSH 连接失败：dial tcp 10.20.0.1:22: i/o timeout":                                                         "连接 10.20.0.1:22 超时",
		"dial tcp 1.2.3.4:443: connect: connection refused":                                                   "拒绝连接",
		`Post "https://x": context deadline exceeded (Client.Timeout exceeded while awaiting headers)`:        "请求超时",
		"Interface Dialer9 not found":                                                                         "接口 Dialer9 在设备上不存在",
		"HTTP Status: 404 Error:InvalidAccessKeyId.NotFound Specified access key is not found. RequestID: R1": "AccessKey ID 不存在",
		"[TencentCloudSDKException] code:AuthFailure.SignatureFailure message:bad requestId:r":                "SecretKey 错误",
		"dial tcp: lookup api.cloudflare.com on 127.0.0.53:53: no such host":                                  "域名 api.cloudflare.com 无法解析",
	}
	for in, want := range cases {
		if got := zhErr(in); !strings.Contains(got, want) {
			t.Errorf("zhErr(%q) = %q, want contains %q", in, got, want)
		}
	}
	if got := zhErr("接口 Dialer3 协议状态为 down"); got != "接口 Dialer3 协议状态为 down" {
		t.Errorf("Chinese text must be unchanged, got %q", got)
	}
}

func TestProviderErrors(t *testing.T) {
	if s := providerError("阿里云", "InvalidAccessKeyId.NotFound", "Specified access key is not found.", "R1").Error(); !strings.HasPrefix(s, "阿里云：AccessKey ID 不存在") || !strings.Contains(s, "RequestId R1") {
		t.Errorf("aliyun: %s", s)
	}
	if s := providerError("华为云", "X.999", "unknown", "").Error(); !strings.HasPrefix(s, "华为云 API 返回错误（X.999") {
		t.Errorf("huawei: %s", s)
	}
	if s := cloudflareError([]string{"Invalid API Token"}).Error(); !strings.Contains(s, "API Token 无效") {
		t.Errorf("cloudflare: %s", s)
	}
}
