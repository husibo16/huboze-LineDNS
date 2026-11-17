package main

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

// Cross-check werkzeug-format hashes against Python's stdlib hashlib.
func TestWerkzeugHashCompat(t *testing.T) {
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("python3 not available")
	}
	script := `
import hashlib
pw = "Huboze@Test123"
salt = "abcDEF0123456789"
s = hashlib.scrypt(pw.encode(), salt=salt.encode(), n=32768, r=8, p=1, maxmem=132*32768*8).hex()
p = hashlib.pbkdf2_hmac("sha256", pw.encode(), salt.encode(), 600000).hex()
print(f"scrypt:32768:8:1${salt}${s}")
print(f"pbkdf2:sha256:600000${salt}${p}")
`
	out, err := exec.Command("python3", "-I", "-c", script).Output()
	if err != nil {
		t.Fatal(err)
	}
	for _, h := range strings.Fields(string(out)) {
		if !checkPasswordHash(h, "Huboze@Test123") {
			t.Errorf("python hash not accepted: %s", h[:20])
		}
		if checkPasswordHash(h, "wrong") {
			t.Errorf("wrong password accepted")
		}
	}
	// Our own hash must be verifiable by Python's algorithm.
	h, _ := generatePasswordHash("Another#Pass9")
	parts := strings.Split(h, "$")
	verify := `import hashlib,sys
print(hashlib.scrypt(b"Another#Pass9", salt=sys.argv[1].encode(), n=32768, r=8, p=1, maxmem=132*32768*8).hex() == sys.argv[2])`
	out, err = exec.Command("python3", "-I", "-c", verify, parts[1], parts[2]).Output()
	if err != nil || strings.TrimSpace(string(out)) != "True" {
		t.Errorf("python could not verify Go hash: %s %v", out, err)
	}
}

func TestParseHelpers(t *testing.T) {
	cases := map[string]string{"wan1.example.com|example.com": "wan1", "example.com|example.com": "@", "a.b.example.com.|Example.com": "a.b"}
	for in, want := range cases {
		p := strings.Split(in, "|")
		if got := rrFromFQDN(p[0], p[1]); got != want {
			t.Errorf("rrFromFQDN(%s)=%s want %s", in, got, want)
		}
	}
	if fqdnFromRR("@", "Example.com") != "example.com" || fqdnFromRR("WAN1", "example.com") != "wan1.example.com" {
		t.Error("fqdnFromRR")
	}
	if !sameIP("240E::1", "240e:0::1") || sameIP("1.1.1.1", "1.1.1.2") {
		t.Error("sameIP")
	}
	if !hostnameRE.MatchString("wan1.example.com") || hostnameRE.MatchString("bad..example.com") || hostnameRE.MatchString("-x.example.com") {
		t.Error("hostnameRE")
	}
	if formatDuration(90061) != "1天1小时1分1秒" || formatDuration(5) != "5秒" {
		t.Error("formatDuration")
	}
	st, m, s, n, f := dnsProbeSummary([]ResolverResult{
		{Status: "OK", IPs: []string{"1.2.3.4"}}, {Status: "OK", IPs: []string{"9.9.9.9"}}, {Status: "NXDOMAIN"}, {Status: "TIMEOUT"},
	}, "1.2.3.4", false)
	if st != "PROPAGATING" || m != 1 || s != 1 || n != 1 || f != 1 {
		t.Errorf("summary %s %d %d %d %d", st, m, s, n, f)
	}
}

func TestLiveDNSQuery(t *testing.T) {
	if os.Getenv("LIVE") == "" {
		t.Skip("set LIVE=1")
	}
	for _, rt := range []string{"A", "AAAA"} {
		r := queryDNSResolver("www.cloudflare.com", "1.1.1.1", rt)
		t.Logf("%s: %+v ttl=%v", rt, r, r.TTL)
		if r.Status != "OK" || len(r.IPs) == 0 {
			t.Errorf("unexpected %+v", r)
		}
	}
	r := queryDNSResolver("nonexistent-zz9.example.com", "223.5.5.5", "A")
	t.Logf("nx: %+v ttl=%v", r, *r.TTL)
	if (r.Status != "NXDOMAIN" && r.Status != "NOANSWER") || r.TTL == nil {
		t.Errorf("unexpected %+v", r)
	}
}
