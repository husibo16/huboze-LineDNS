package main

import (
	"strings"
	"testing"
)

func TestDeployInfoRender(t *testing.T) {
	s := deployInfo{version: "9.9.9", port: "8080", password: "Abc#123456", freshPassword: true, note: "全新安装"}.render()
	for _, want := range []string{"v9.9.9", ":8080", "http://127.0.0.1:8080", "/health", "账号：admin", "密码：Abc#123456", "初始密码", "huboze-ddns-agent info", "TCP 8080"} {
		if !strings.Contains(s, want) {
			t.Errorf("render missing %q", want)
		}
	}
	s = deployInfo{version: "9.9.9", port: "9090"}.render()
	if !strings.Contains(s, "沿用原密码") || strings.Contains(s, "仅 root 可读），改密后请删除") {
		t.Errorf("upgrade render wrong:\n%s", s)
	}
}
