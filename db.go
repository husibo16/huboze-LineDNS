package main

import (
	"database/sql"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

var DB *sql.DB

func openDB() error {
	if err := os.MkdirAll(DataDir, 0o750); err != nil {
		return err
	}
	dsn := "file:" + DBPath + "?_pragma=busy_timeout(15000)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)&_txlock=immediate"
	d, err := sql.Open("sqlite", dsn)
	if err != nil {
		return err
	}
	d.SetMaxOpenConns(4)
	if err := d.Ping(); err != nil {
		return err
	}
	DB = d
	return nil
}

func dbExec(q string, args ...any) error {
	_, err := DB.Exec(q, args...)
	return err
}

func mustExec(q string, args ...any) {
	if _, err := DB.Exec(q, args...); err != nil {
		log.Printf("[数据库错误] %v：%s", err, q)
	}
}

func tableColumns(table string) map[string]bool {
	cols := map[string]bool{}
	rows, err := DB.Query("PRAGMA table_info(" + table + ")")
	if err != nil {
		return cols
	}
	defer rows.Close()
	for rows.Next() {
		var cid int
		var name, ctype string
		var notnull, pk int
		var dflt sql.NullString
		if rows.Scan(&cid, &name, &ctype, &notnull, &dflt, &pk) == nil {
			cols[name] = true
		}
	}
	return cols
}

func ensureColumn(table, definition string) error {
	name := strings.Fields(definition)[0]
	if !tableColumns(table)[name] {
		_, err := DB.Exec("ALTER TABLE " + table + " ADD COLUMN " + definition)
		return err
	}
	return nil
}

func initDB() error {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS users(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL UNIQUE,
        password_hash TEXT NOT NULL,
        created_at TEXT NOT NULL
    )`,
		`CREATE TABLE IF NOT EXISTS devices(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT,
        host TEXT
    )`,
	}
	for _, s := range stmts {
		if err := dbExec(s); err != nil {
			return err
		}
	}
	for _, col := range []string{
		"port INTEGER DEFAULT 22",
		"username TEXT DEFAULT ''",
		"password_enc TEXT DEFAULT ''",
		"enabled INTEGER DEFAULT 1",
		"last_status TEXT DEFAULT 'UNKNOWN'",
		"last_error TEXT DEFAULT ''",
		"last_seen TEXT DEFAULT ''",
		"online_since TEXT DEFAULT ''",
		"last_interfaces_json TEXT DEFAULT '[]'",
		"created_at TEXT DEFAULT ''",
		"updated_at TEXT DEFAULT ''",
	} {
		if err := ensureColumn("devices", col); err != nil {
			return err
		}
	}
	if err := dbExec(`CREATE TABLE IF NOT EXISTS providers(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        provider_type TEXT NOT NULL DEFAULT 'cloudflare',
        token_enc TEXT NOT NULL,
        enabled INTEGER NOT NULL DEFAULT 1,
        last_status TEXT DEFAULT 'UNKNOWN',
        last_error TEXT DEFAULT '',
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
    )`); err != nil {
		return err
	}
	if err := ensureColumn("providers", "config_enc TEXT DEFAULT ''"); err != nil {
		return err
	}
	if err := dbExec(`CREATE TABLE IF NOT EXISTS mappings(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        device_id INTEGER NOT NULL,
        interface_name TEXT NOT NULL,
        provider_id INTEGER NOT NULL,
        zone_id TEXT NOT NULL,
        zone_name TEXT NOT NULL,
        record_id TEXT NOT NULL,
        record_name TEXT NOT NULL,
        record_type TEXT NOT NULL DEFAULT 'A',
        enabled INTEGER NOT NULL DEFAULT 1,
        current_ip TEXT DEFAULT '',
        last_synced_ip TEXT DEFAULT '',
        last_status TEXT DEFAULT 'PENDING',
        last_error TEXT DEFAULT '',
        last_sync TEXT DEFAULT '',
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
    )`); err != nil {
		return err
	}
	for _, col := range []string{
		"check_port INTEGER DEFAULT 0",
		"last_check TEXT DEFAULT ''",
		"last_check_epoch REAL DEFAULT 0",
		"dns_status TEXT DEFAULT 'UNKNOWN'",
		"dns_resolved TEXT DEFAULT ''",
		"dns_resolver_json TEXT DEFAULT '{}'",
		"reachability_status TEXT DEFAULT 'UNKNOWN'",
		"reachability_error TEXT DEFAULT ''",
	} {
		if err := ensureColumn("mappings", col); err != nil {
			return err
		}
	}
	for _, s := range []string{
		`CREATE TABLE IF NOT EXISTS runtime_state(key TEXT PRIMARY KEY, value TEXT NOT NULL)`,
		`CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY, value TEXT NOT NULL)`,
		`CREATE TABLE IF NOT EXISTS logs(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ts TEXT NOT NULL,
        level TEXT NOT NULL,
        event TEXT NOT NULL,
        message TEXT NOT NULL,
        details TEXT DEFAULT ''
    )`,
	} {
		if err := dbExec(s); err != nil {
			return err
		}
	}
	defaults := [][2]string{
		{"poll_interval", "60"},
		{"timezone", "Asia/Shanghai"},
		{"allowed_web_cidrs", ""},
		{"log_retention_days", "7"},
		{"heartbeat_log_enabled", "1"},
		{"domain_check_interval", "300"},
		{"dns_resolvers", "223.5.5.5,119.29.29.29,1.1.1.1,8.8.8.8"},
	}
	for _, kv := range defaults {
		mustExec("INSERT OR IGNORE INTO settings(key,value) VALUES(?,?)", kv[0], kv[1])
	}

	var count int
	if err := DB.QueryRow("SELECT COUNT(*) FROM users").Scan(&count); err != nil {
		return err
	}
	if count == 0 {
		initial := strings.TrimSpace(os.Getenv("ADMIN_INITIAL_PASSWORD"))
		if initial == "" {
			initial = randomURLSafe(18)
		}
		h, err := generatePasswordHash(initial)
		if err != nil {
			return err
		}
		if err := dbExec("INSERT INTO users(username,password_hash,created_at) VALUES(?,?,?)", "admin", h, nowStr()); err != nil {
			return err
		}
	}
	return nil
}

func getSetting(key, def string) string {
	var v string
	if err := DB.QueryRow("SELECT value FROM settings WHERE key=?", key).Scan(&v); err != nil {
		return def
	}
	return v
}

func setSetting(key string, value any) {
	mustExec("INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", key, fmt.Sprint(value))
}

func getSettingInt(key string, def int) int {
	n, err := strconv.Atoi(strings.TrimSpace(getSetting(key, strconv.Itoa(def))))
	if err != nil {
		return def
	}
	return n
}

const tsLayout = "2006-01-02 15:04:05"

func currentLocation() *time.Location {
	name := getSetting("timezone", "Asia/Shanghai")
	loc, err := time.LoadLocation(name)
	if err != nil {
		return time.Local
	}
	return loc
}

func nowStr() string {
	return time.Now().In(currentLocation()).Format(tsLayout)
}

func epochNow() float64 {
	return float64(time.Now().UnixNano()) / 1e9
}

var processStarted = time.Now()

func getRuntimeState(key, def string) string {
	var v string
	if err := DB.QueryRow("SELECT value FROM runtime_state WHERE key=?", key).Scan(&v); err != nil {
		return def
	}
	return v
}

func setRuntimeState(key, value string) {
	mustExec("INSERT INTO runtime_state(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", key, value)
}

func runtimeStateMap() map[string]string {
	m := map[string]string{}
	rows, err := DB.Query("SELECT key,value FROM runtime_state")
	if err != nil {
		return m
	}
	defer rows.Close()
	for rows.Next() {
		var k, v string
		if rows.Scan(&k, &v) == nil {
			m[k] = v
		}
	}
	return m
}

func initRuntimeState() {
	nowText := nowStr()
	mustExec("INSERT OR IGNORE INTO runtime_state(key,value) VALUES('first_started_at',?)", nowText)
	for _, kv := range [][2]string{
		{"total_runtime_seconds", "0"}, {"poll_count", "0"}, {"last_heartbeat", ""},
		{"last_heartbeat_epoch", "0"}, {"last_poll_duration_ms", "0"}, {"last_poll_result", "未运行"},
	} {
		mustExec("INSERT OR IGNORE INTO runtime_state(key,value) VALUES(?,?)", kv[0], kv[1])
	}
	mustExec("INSERT OR REPLACE INTO runtime_state(key,value) VALUES('service_started_at',?)", nowText)
	mustExec("INSERT OR REPLACE INTO runtime_state(key,value) VALUES('last_runtime_tick_epoch',?)", fmtFloat(epochNow()))
	// Restart creates a monitoring gap; first successful poll starts a new timer.
	mustExec("UPDATE devices SET last_status='UNKNOWN', online_since='', last_error='', updated_at=? WHERE enabled=1", nowText)
}

func fmtFloat(f float64) string { return strconv.FormatFloat(f, 'f', -1, 64) }

func parseFloat(s string, def float64) float64 {
	f, err := strconv.ParseFloat(strings.TrimSpace(s), 64)
	if err != nil {
		return def
	}
	return f
}

func runtimeTick() {
	now := epochNow()
	last := parseFloat(getRuntimeState("last_runtime_tick_epoch", fmtFloat(now)), now)
	delta := now - last
	if delta < 0 {
		delta = 0
	}
	total := parseFloat(getRuntimeState("total_runtime_seconds", "0"), 0) + delta
	mustExec("INSERT OR REPLACE INTO runtime_state(key,value) VALUES('total_runtime_seconds',?)", strconv.Itoa(int(total)))
	mustExec("INSERT OR REPLACE INTO runtime_state(key,value) VALUES('last_runtime_tick_epoch',?)", fmtFloat(now))
}

func hostUptimeSeconds() int {
	b, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return 0
	}
	f := strings.Fields(string(b))
	if len(f) == 0 {
		return 0
	}
	return int(parseFloat(f[0], 0))
}

func formatDuration(seconds int) string {
	if seconds < 0 {
		seconds = 0
	}
	days := seconds / 86400
	rem := seconds % 86400
	hours := rem / 3600
	rem %= 3600
	minutes := rem / 60
	secs := rem % 60
	var b strings.Builder
	if days > 0 {
		fmt.Fprintf(&b, "%d天", days)
	}
	if hours > 0 || days > 0 {
		fmt.Fprintf(&b, "%d小时", hours)
	}
	if minutes > 0 || hours > 0 || days > 0 {
		fmt.Fprintf(&b, "%d分", minutes)
	}
	fmt.Fprintf(&b, "%d秒", secs)
	return b.String()
}

func cleanupLogs(retentionDays int) int {
	deleted := 0
	if retentionDays > 0 {
		cutoff := time.Now().In(currentLocation()).AddDate(0, 0, -retentionDays).Format(tsLayout)
		if res, err := DB.Exec("DELETE FROM logs WHERE ts < ?", cutoff); err == nil {
			n, _ := res.RowsAffected()
			deleted += int(n)
		}
	}
	mustExec("DELETE FROM logs WHERE id NOT IN (SELECT id FROM logs ORDER BY id DESC LIMIT 50000)")
	return deleted
}

func logEvent(level, event, message string, details ...string) {
	d := ""
	if len(details) > 0 {
		d = truncRunes(details[0], 4000)
	}
	level = strings.ToUpper(level)
	if _, err := DB.Exec("INSERT INTO logs(ts,level,event,message,details) VALUES(?,?,?,?,?)", nowStr(), level, event, message, d); err != nil {
		log.Printf("[日志写入失败] %v", err)
	}
	log.Printf("[%s] %s：%s", levelZhText(level), lookupZh(eventZh, event), messageZh(message))
}

func truncRunes(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n])
}

// ---------------- Models ----------------

type Device struct {
	ID                 int64
	Name, Host         string
	Port               int
	Username           string
	PasswordEnc        string
	Enabled            bool
	LastStatus         string
	LastError          string
	LastSeen           string
	OnlineSince        string
	LastInterfacesJSON string
}

const deviceCols = `id, COALESCE(name,''), COALESCE(host,''), COALESCE(port,22), COALESCE(username,''),
 COALESCE(password_enc,''), COALESCE(enabled,1), COALESCE(last_status,'UNKNOWN'), COALESCE(last_error,''),
 COALESCE(last_seen,''), COALESCE(online_since,''), COALESCE(last_interfaces_json,'[]')`

func scanDevice(sc interface{ Scan(...any) error }) (*Device, error) {
	d := &Device{}
	var en int
	err := sc.Scan(&d.ID, &d.Name, &d.Host, &d.Port, &d.Username, &d.PasswordEnc, &en, &d.LastStatus,
		&d.LastError, &d.LastSeen, &d.OnlineSince, &d.LastInterfacesJSON)
	d.Enabled = en != 0
	return d, err
}

func queryDevices(where string, args ...any) []*Device {
	rows, err := DB.Query("SELECT "+deviceCols+" FROM devices "+where, args...)
	if err != nil {
		log.Printf("[数据库错误] %v", err)
		return nil
	}
	defer rows.Close()
	var out []*Device
	for rows.Next() {
		if d, err := scanDevice(rows); err == nil {
			out = append(out, d)
		}
	}
	return out
}

func getDevice(id int64) *Device {
	d, err := scanDevice(DB.QueryRow("SELECT "+deviceCols+" FROM devices WHERE id=?", id))
	if err != nil {
		return nil
	}
	return d
}

type Provider struct {
	ID           int64
	Name         string
	ProviderType string
	TokenEnc     string
	ConfigEnc    string
	Enabled      bool
	LastStatus   string
	LastError    string
}

const providerCols = `id, name, COALESCE(provider_type,'cloudflare'), COALESCE(token_enc,''), COALESCE(config_enc,''),
 COALESCE(enabled,1), COALESCE(last_status,'UNKNOWN'), COALESCE(last_error,'')`

func scanProvider(sc interface{ Scan(...any) error }) (*Provider, error) {
	p := &Provider{}
	var en int
	err := sc.Scan(&p.ID, &p.Name, &p.ProviderType, &p.TokenEnc, &p.ConfigEnc, &en, &p.LastStatus, &p.LastError)
	p.Enabled = en != 0
	if p.ProviderType == "" {
		p.ProviderType = "cloudflare"
	}
	return p, err
}

func queryProviders(where string, args ...any) []*Provider {
	rows, err := DB.Query("SELECT "+providerCols+" FROM providers "+where, args...)
	if err != nil {
		log.Printf("[数据库错误] %v", err)
		return nil
	}
	defer rows.Close()
	var out []*Provider
	for rows.Next() {
		if p, err := scanProvider(rows); err == nil {
			out = append(out, p)
		}
	}
	return out
}

func getProvider(id int64) *Provider {
	p, err := scanProvider(DB.QueryRow("SELECT "+providerCols+" FROM providers WHERE id=?", id))
	if err != nil {
		return nil
	}
	return p
}

type Mapping struct {
	ID                 int64
	Name               string
	DeviceID           int64
	InterfaceName      string
	ProviderID         int64
	ZoneID, ZoneName   string
	RecordID           string
	RecordName         string
	RecordType         string
	Enabled            bool
	CurrentIP          string
	LastSyncedIP       string
	LastStatus         string
	LastError          string
	LastSync           string
	CheckPort          int
	LastCheck          string
	LastCheckEpoch     float64
	DNSStatus          string
	DNSResolved        string
	DNSResolverJSON    string
	ReachabilityStatus string
	ReachabilityError  string
	// joined
	DeviceName, ProviderName string
}

const mappingCols = `m.id, m.name, m.device_id, m.interface_name, m.provider_id, m.zone_id, m.zone_name, m.record_id,
 m.record_name, COALESCE(m.record_type,'A'), COALESCE(m.enabled,1), COALESCE(m.current_ip,''), COALESCE(m.last_synced_ip,''),
 COALESCE(m.last_status,'PENDING'), COALESCE(m.last_error,''), COALESCE(m.last_sync,''), COALESCE(m.check_port,0),
 COALESCE(m.last_check,''), COALESCE(m.last_check_epoch,0), COALESCE(m.dns_status,'UNKNOWN'), COALESCE(m.dns_resolved,''),
 COALESCE(m.dns_resolver_json,'{}'), COALESCE(m.reachability_status,'UNKNOWN'), COALESCE(m.reachability_error,'')`

func scanMapping(sc interface{ Scan(...any) error }, extra ...any) (*Mapping, error) {
	m := &Mapping{}
	var en int
	dest := []any{&m.ID, &m.Name, &m.DeviceID, &m.InterfaceName, &m.ProviderID, &m.ZoneID, &m.ZoneName, &m.RecordID,
		&m.RecordName, &m.RecordType, &en, &m.CurrentIP, &m.LastSyncedIP, &m.LastStatus, &m.LastError, &m.LastSync,
		&m.CheckPort, &m.LastCheck, &m.LastCheckEpoch, &m.DNSStatus, &m.DNSResolved, &m.DNSResolverJSON,
		&m.ReachabilityStatus, &m.ReachabilityError}
	dest = append(dest, extra...)
	err := sc.Scan(dest...)
	m.Enabled = en != 0
	if m.RecordType == "" {
		m.RecordType = "A"
	}
	return m, err
}

func queryMappings(where string, args ...any) []*Mapping {
	rows, err := DB.Query("SELECT "+mappingCols+" FROM mappings m "+where, args...)
	if err != nil {
		log.Printf("[数据库错误] %v", err)
		return nil
	}
	defer rows.Close()
	var out []*Mapping
	for rows.Next() {
		if m, err := scanMapping(rows); err == nil {
			out = append(out, m)
		}
	}
	return out
}

func getMapping(id int64) *Mapping {
	m, err := scanMapping(DB.QueryRow("SELECT "+mappingCols+" FROM mappings m WHERE m.id=?", id))
	if err != nil {
		return nil
	}
	return m
}

func countWhere(q string, args ...any) int {
	var n int
	_ = DB.QueryRow(q, args...).Scan(&n)
	return n
}

// chownTree makes files created by root CLI commands readable by the service user.
func chownTree(root string, uid, gid int) {
	_ = filepath.Walk(root, func(p string, _ os.FileInfo, err error) error {
		if err == nil {
			_ = os.Lchown(p, uid, gid)
		}
		return nil
	})
}
