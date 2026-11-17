package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func TestMappingIPRules(t *testing.T) {
	p := func(i int) *int { return &i }
	cases := []struct {
		iface   Interface
		rt      string
		wantErr string
		wantIP  string
	}{
		{Interface{Name: "Dia0", Protocol: "up", IP: "113.87.10.20", Prefix: p(32)}, "A", "", "113.87.10.20"},
		{Interface{Name: "Dia0", Protocol: "up(s)", IP: "113.87.10.20"}, "A", "", "113.87.10.20"},
		{Interface{Name: "Dia0", Protocol: "down", IP: "113.87.10.20"}, "A", "协议状态为 down", ""},
		{Interface{Name: "Dia1", Protocol: "*down", IP: "113.87.10.20"}, "A", "协议状态为 *down", ""},
		{Interface{Name: "Dia0", Protocol: "up", IP: "100.64.12.3"}, "A", "不是公网地址", ""},
		{Interface{Name: "Dia0", Protocol: "up", IP: "10.1.1.1"}, "A", "不是公网地址", ""},
		{Interface{Name: "Dia0", Protocol: "up", IP: "192.168.1.1"}, "A", "不是公网地址", ""},
		{Interface{Name: "Dia0", Protocol: "up", IPv6: "fe80::1"}, "AAAA", "不是全局公网地址", ""},
		{Interface{Name: "Dia0", Protocol: "up", IPv6: "240e:3b0::1"}, "AAAA", "", "240e:3b0::1"},
	}
	for _, c := range cases {
		ip, err := mappingIPFromInterface(c.iface, c.rt)
		if c.wantErr != "" {
			if err == nil || !strings.Contains(err.Error(), c.wantErr) {
				t.Errorf("%+v %s: want error %q, got ip=%s err=%v", c.iface, c.rt, c.wantErr, ip, err)
			}
		} else if err != nil || ip != c.wantIP {
			t.Errorf("%+v %s: want %s, got %s %v", c.iface, c.rt, c.wantIP, ip, err)
		}
	}
}

func setupTestDB(t *testing.T) {
	setupTestEnv(t)
	DBPath = filepath.Join(DataDir, "test.db")
	if err := openDB(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { DB.Close() })
	if err := initDB(); err != nil {
		t.Fatal(err)
	}
	// Keep the domain check offline: an unreachable resolver fails fast.
	setSetting("dns_resolvers", "127.0.0.1")
}

func insertDevice(t *testing.T, addr, pw string) int64 {
	d := testDevice(t, addr, pw)
	res, err := DB.Exec(`INSERT INTO devices(name,host,port,username,password_enc,enabled,created_at,updated_at)
		VALUES(?,?,?,?,?,1,'','')`, "MSR-A", d.Host, d.Port, d.Username, d.PasswordEnc)
	if err != nil {
		t.Fatal(err)
	}
	id, _ := res.LastInsertId()
	return id
}

func TestPollerAutoDisablesOnAuthFailure(t *testing.T) {
	setupTestDB(t)
	fake := &fakeH3C{}
	startFakeH3C(t, "right-password", fake)
	id := insertDevice(t, fake.addr, "wrong-password")

	r := pollOnce(false, 0, 0)
	if r.Summary.Errors != 1 {
		t.Fatalf("summary %+v", r.Summary)
	}
	d := getDevice(id)
	if d.Enabled {
		t.Fatal("device must be auto-disabled after an authentication failure")
	}
	// next poll must not try to log in again
	pollOnce(false, 0, 0)
	if n := fake.authTries.Load(); n != 1 {
		t.Fatalf("expected exactly 1 login attempt in total, got %d", n)
	}
	if countWhere("SELECT COUNT(*) FROM logs WHERE event='MSR_DISABLE'") != 1 {
		t.Error("missing MSR_DISABLE log")
	}
}

func TestDriftSelfHeal(t *testing.T) {
	setupTestDB(t)
	fake := &fakeH3C{}
	startFakeH3C(t, "pw", fake)
	devID := insertDevice(t, fake.addr, "pw")

	// Mock Cloudflare: the record was changed externally to 9.9.9.9.
	var mu sync.Mutex
	content := "9.9.9.9"
	var patched []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if r.Method == "PATCH" {
			var body map[string]string
			b, _ := io.ReadAll(r.Body)
			json.Unmarshal(b, &body)
			content = body["content"]
			patched = append(patched, content)
		}
		json.NewEncoder(w).Encode(map[string]any{"success": true, "result": map[string]any{
			"id": "rec1", "name": "wan1.example.com", "type": "A", "content": content, "ttl": 1, "proxied": false}})
	}))
	defer srv.Close()
	old := cfBase
	cfBase = srv.URL
	defer func() { cfBase = old }()

	ts := nowStr()
	res, _ := DB.Exec(`INSERT INTO providers(name,provider_type,token_enc,config_enc,enabled,created_at,updated_at) VALUES('cf','cloudflare',?,?,1,?,?)`,
		encryptSecret("tok"), providerPackConfig(ProviderConfig{"token": "tok"}), ts, ts)
	pid, _ := res.LastInsertId()
	// last_synced_ip equals the current WAN IP, so a normal poll would NOT update.
	_, err := DB.Exec(`INSERT INTO mappings(name,device_id,interface_name,provider_id,zone_id,zone_name,record_id,record_name,record_type,
		enabled,current_ip,last_synced_ip,last_status,created_at,updated_at,last_check_epoch)
		VALUES('wan1',?,'Dia0',?,'z1','example.com','rec1','wan1.example.com','A',1,'113.87.10.20','113.87.10.20','SUCCESS',?,?,0)`,
		devID, pid, ts, ts)
	if err != nil {
		t.Fatal(err)
	}
	r := pollOnce(false, 0, 0)
	if len(patched) != 1 || patched[0] != "113.87.10.20" {
		t.Fatalf("drift must be corrected once to 113.87.10.20, patched=%v summary=%+v", patched, r.Summary)
	}
	if countWhere("SELECT COUNT(*) FROM logs WHERE message LIKE '%已自动纠正为 113.87.10.20%'") != 1 {
		t.Error("missing drift log")
	}
	// Second poll: record now matches, nothing to patch.
	DB.Exec("UPDATE mappings SET last_check_epoch=0")
	pollOnce(false, 0, 0)
	if len(patched) != 1 {
		t.Fatalf("no further patch expected, got %v", patched)
	}
}

func TestMain(m *testing.M) {
	os.Exit(m.Run())
}
