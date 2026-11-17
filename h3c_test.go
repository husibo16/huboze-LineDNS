package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/fernet/fernet-go"
	"golang.org/x/crypto/ssh"
)

const ipv4Table = "Interface                Physical Protocol IP address/Mask    VPN instance Description\r\n" +
	"Dia0                     up       up(s)    113.87.10.20/32    --           --\r\n" +
	"GE0/0                    up       up       192.168.1.1/24     --           --\r\n" +
	"---- More ----"
const ipv4Table2 = "\x1b[16D                \x1b[16D" +
	"Dialer1                  *down    down     --                 --           --\r\n" +
	"Vlan1                    up       up       10.0.0.1/255.255.255.0 --       --\r\n"

const ipv6Table = "*down: administratively down\r\n(s): spoofing\r\n" +
	"Interface                Physical Protocol IPv6 Address\r\n" +
	"Dia0                     up       up       240E:3B0:30B8:611D:\r\n" +
	"                                           882A:5E05:8394:4406\r\n" +
	"                                           /64\r\n" +
	"Vlan1                    up       up       240E:3BC:3089:EBE0:\r\n" +
	"                                           :1/64\r\n" +
	"GE0/0                    up       up       FE80::1/64\r\n"

type fakeH3C struct {
	addr       string
	authTries  atomic.Int32
	firstLogin bool
	changed    atomic.Bool
	noIPv6     bool
}

func startFakeH3C(t *testing.T, password string, fake *fakeH3C) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	signer, _ := ssh.NewSignerFromKey(priv)
	cfg := &ssh.ServerConfig{
		PasswordCallback: func(c ssh.ConnMetadata, p []byte) (*ssh.Permissions, error) {
			fake.authTries.Add(1)
			if string(p) == password {
				return nil, nil
			}
			return nil, fmt.Errorf("denied")
		},
	}
	cfg.AddHostKey(signer)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	fake.addr = ln.Addr().String()
	go func() {
		for {
			nc, err := ln.Accept()
			if err != nil {
				return
			}
			go fake.handle(nc, cfg)
		}
	}()
}

func (f *fakeH3C) handle(nc net.Conn, cfg *ssh.ServerConfig) {
	_, chans, reqs, err := ssh.NewServerConn(nc, cfg)
	if err != nil {
		return
	}
	go ssh.DiscardRequests(reqs)
	for nch := range chans {
		ch, creqs, _ := nch.Accept()
		go func() {
			for r := range creqs {
				r.Reply(r.Type == "pty-req" || r.Type == "shell", nil)
			}
		}()
		go f.shell(ch)
	}
}

func readLine(ch ssh.Channel) (string, bool) {
	var b strings.Builder
	buf := make([]byte, 1)
	for {
		n, err := ch.Read(buf)
		if err != nil {
			return b.String(), false
		}
		if n == 0 {
			continue
		}
		c := buf[0]
		if c == '\r' || c == '\n' {
			io.WriteString(ch, "\r\n")
			return b.String(), true
		}
		ch.Write([]byte{c}) // echo
		b.WriteByte(c)
	}
}

func (f *fakeH3C) shell(ch ssh.Channel) {
	defer ch.Close()
	prompt := "<H3C MSR3640-XS>"
	if f.firstLogin && !f.changed.Load() {
		io.WriteString(ch, "\r\nFirst login or password reset. For security reason, you need to change your password. Please enter your password.\r\nOld password:")
		old, _ := readLine(ch)
		io.WriteString(ch, "New password:")
		nw, _ := readLine(ch)
		io.WriteString(ch, "Confirm:")
		cf, _ := readLine(ch)
		if old == "" || nw != cf {
			io.WriteString(ch, "Failed\r\n")
			return
		}
		f.changed.Store(true)
		io.WriteString(ch, "Updating user information. Please wait ... ...\r\n"+prompt)
	} else {
		io.WriteString(ch, "\r\n******************************************************************************\r\n* Copyright (c) 2004-2024 New H3C Technologies Co., Ltd. All rights reserved.*\r\n******************************************************************************\r\n\r\n"+prompt)
	}
	for {
		l, ok := readLine(ch)
		if !ok {
			return
		}
		switch strings.TrimSpace(l) {
		case "":
		case "screen-length disable":
			io.WriteString(ch, "Info: It's not allowed to disable screen length on this terminal... \r\n")
		case "display ip interface brief":
			io.WriteString(ch, "*down: administratively down\r\n(s): spoofing  (l): loopback\r\n"+ipv4Table)
			// wait for the space that continues paging
			buf := make([]byte, 1)
			ch.Read(buf)
			io.WriteString(ch, ipv4Table2)
		case "display ipv6 interface brief":
			if f.noIPv6 {
				io.WriteString(ch, "IP6Stack is not configured.\r\n")
			} else {
				io.WriteString(ch, ipv6Table)
			}
		case "quit":
			return
		default:
			io.WriteString(ch, "                   ^\r\n % Unrecognized command found at '^' position.\r\n")
		}
		io.WriteString(ch, "\x1b[0m"+prompt)
	}
}

func setupTestEnv(t *testing.T) {
	dir := t.TempDir()
	AppDir = dir
	DataDir = filepath.Join(dir, "data")
	ConfigDir = filepath.Join(dir, "config")
	os.MkdirAll(DataDir, 0o700)
	KnownHostsFile = filepath.Join(DataDir, "known_hosts")
	var k fernet.Key
	k.Generate()
	fernetKeys = []*fernet.Key{&k}
}

func testDevice(t *testing.T, addr, password string) *Device {
	host, port, _ := net.SplitHostPort(addr)
	p, _ := strconv.Atoi(port)
	return &Device{ID: 1, Name: "fake", Host: host, Port: p, Username: "admin", PasswordEnc: encryptSecret(password)}
}

func TestCollectDevice(t *testing.T) {
	setupTestEnv(t)
	fake := &fakeH3C{}
	startFakeH3C(t, "Secret@123", fake)
	ifaces, err := collectDevice(testDevice(t, fake.addr, "Secret@123"))
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	got := map[string]Interface{}
	for _, i := range ifaces {
		got[i.Name] = i
	}
	if ifaces[0].Name != "Dia0" || ifaces[1].Name != "Dia1" {
		t.Errorf("dialer interfaces should sort first: %+v", ifaces)
	}
	d0 := got["Dia0"]
	if d0.IP != "113.87.10.20" || *d0.Prefix != 32 || d0.Protocol != "up(s)" {
		t.Errorf("Dia0 v4 wrong: %+v", d0)
	}
	if d0.IPv6 != "240e:3b0:30b8:611d:882a:5e05:8394:4406" || *d0.IPv6Prefix != 64 {
		t.Errorf("Dia0 v6 wrong: %q", d0.IPv6)
	}
	if v := got["Vlan1"]; v.IPv6 != "240e:3bc:3089:ebe0::1" || v.IP != "10.0.0.1" || *v.Prefix != 24 {
		t.Errorf("Vlan1 wrong: %+v", v)
	}
	if g := got["GE0/0"]; g.IPv6 != "" {
		t.Errorf("link-local must be ignored: %+v", g)
	}
	if d1 := got["Dia1"]; d1.Physical != "*down" || d1.IP != "" {
		t.Errorf("Dialer1 canonicalisation wrong: %+v", d1)
	}
	if fake.authTries.Load() != 1 {
		t.Errorf("auth tries = %d", fake.authTries.Load())
	}
	// second run re-uses known_hosts (accept-new already stored)
	if _, err := collectDevice(testDevice(t, fake.addr, "Secret@123")); err != nil {
		t.Fatalf("second collect: %v", err)
	}
	ip, err := mappingIPFromInterface(d0, "AAAA")
	if err != nil || ip != "240e:3b0:30b8:611d:882a:5e05:8394:4406" {
		t.Errorf("AAAA ip: %v %v", ip, err)
	}
}

func TestCollectNoIPv6(t *testing.T) {
	setupTestEnv(t)
	fake := &fakeH3C{noIPv6: true}
	startFakeH3C(t, "pw12345678", fake)
	ifaces, err := collectDevice(testDevice(t, fake.addr, "pw12345678"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := mappingIPFromInterface(ifaces[0], "AAAA"); err == nil || !strings.Contains(err.Error(), "没有获取到全局 IPv6") {
		t.Errorf("expected missing IPv6 error, got %v", err)
	}
}

func TestWrongPasswordSingleAttempt(t *testing.T) {
	setupTestEnv(t)
	fake := &fakeH3C{}
	startFakeH3C(t, "right", fake)
	_, err := collectDevice(testDevice(t, fake.addr, "wrong"))
	if err == nil || !strings.Contains(err.Error(), "SSH 认证失败") {
		t.Fatalf("expected auth failure, got %v", err)
	}
	if n := fake.authTries.Load(); n != 1 {
		t.Errorf("password must be tried exactly once to avoid lockout, tried %d", n)
	}
}

func TestHostKeyChanged(t *testing.T) {
	setupTestEnv(t)
	fake := &fakeH3C{}
	startFakeH3C(t, "pw", fake)
	dev := testDevice(t, fake.addr, "pw")
	if _, err := collectDevice(dev); err != nil {
		t.Fatal(err)
	}
	// Replace the server (new host key) on a new port, then rewrite known_hosts to claim the old key for it.
	fake2 := &fakeH3C{}
	startFakeH3C(t, "pw", fake2)
	data, _ := os.ReadFile(KnownHostsFile)
	_, oldPort, _ := net.SplitHostPort(fake.addr)
	_, newPort, _ := net.SplitHostPort(fake2.addr)
	os.WriteFile(KnownHostsFile, []byte(strings.ReplaceAll(string(data), "]:"+oldPort+" ", "]:"+newPort+" ")), 0o600)
	dev2 := testDevice(t, fake2.addr, "pw")
	_, err := collectDevice(dev2)
	if err == nil || !strings.Contains(err.Error(), "Host Key 已变化") {
		t.Fatalf("expected host key changed, got %v", err)
	}
	if err := removeKnownHost(dev2.Host, dev2.Port); err != nil {
		t.Fatal(err)
	}
	if _, err := collectDevice(dev2); err != nil {
		t.Fatalf("after clearing host key: %v", err)
	}
}

func TestFirstLoginFlow(t *testing.T) {
	setupTestEnv(t)
	fake := &fakeH3C{firstLogin: true}
	startFakeH3C(t, "init", fake)
	dev := testDevice(t, fake.addr, "init")
	_, err := collectDevice(dev)
	if err == nil || !strings.Contains(err.Error(), "首次登录改密") {
		t.Fatalf("expected first-login error, got %v", err)
	}
	if err := changeFirstLoginPassword(dev, "abc"); err == nil {
		t.Fatal("weak password must be rejected")
	}
	if err := changeFirstLoginPassword(dev, "NewPass@2024"); err != nil {
		t.Fatalf("first login change: %v", err)
	}
	if !fake.changed.Load() {
		t.Fatal("password not changed on device")
	}
	if _, err := collectDevice(dev); err != nil {
		t.Fatalf("collect after change: %v", err)
	}
}
