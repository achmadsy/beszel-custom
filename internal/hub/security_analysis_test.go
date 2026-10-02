package hub

import (
	"database/sql"
	"encoding/json"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pocketbase/pocketbase/core"
	"github.com/pocketbase/pocketbase/tools/router"
)

func TestSecurityAnalysis(t *testing.T) {
	app := core.NewBaseApp(core.BaseAppConfig{DataDir: t.TempDir()})
	if err := app.Bootstrap(); err != nil {
		t.Fatal(err)
	}
	defer app.ClearBootstrap()
	col := core.NewBaseCollection("systems")
	if err := app.Save(col); err != nil {
		t.Fatal(err)
	}
	ids := []string{}
	for range 2 {
		r := core.NewRecord(col)
		if err := app.Save(r); err != nil {
			t.Fatal(err)
		}
		ids = append(ids, r.Id)
	}
	if _, err := app.DB().NewQuery(`CREATE TABLE security_known_ips(system TEXT NOT NULL REFERENCES systems(id) ON DELETE CASCADE,network TEXT NOT NULL,label TEXT NOT NULL,PRIMARY KEY(system,network))`).Execute(); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "security.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	_, err = db.Exec(`CREATE TABLE events(id INTEGER PRIMARY KEY,occurred_at INTEGER,source TEXT,kind TEXT,peer_ip TEXT,client_ip TEXT,provenance TEXT,host TEXT,username TEXT,method TEXT,path TEXT,port INTEGER,status INTEGER,web_category TEXT);
 CREATE TABLE collector_state(id INTEGER PRIMARY KEY,started_at INTEGER,finished_at INTEGER,last_success_at INTEGER,status TEXT,error TEXT);
 CREATE TABLE ip_countries(ip TEXT PRIMARY KEY,country_code TEXT);
 INSERT INTO ip_countries VALUES ('203.0.113.8','US'),('2001:db8::8','DE');`)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().Unix()
	for _, v := range []struct {
		id, at                                 int64
		kind, ip, user, method, path, category string
	}{
		{1, now - 100, "ssh_failure", "203.0.113.8", "root", "password", "", ""},
		{2, now - 50, "ssh_probe", "2001:db8::8", "root", "", "", ""},
		{3, now - 10, "ssh_success", "203.0.113.8", "alice", "publickey", "", ""},
		{4, now - 5, "ssh_success", "198.51.100.8", "bob", "password", "", ""},
		{5, now - 2, "ssh_success", "2001:db8::8", "carol", "keyboard-interactive/pam", "", ""},
		{6, now - 1, "web_probe", "203.0.113.8", "", "GET", "/.env", "sensitive_files"},
	} {
		source := "ssh"
		if v.kind == "web_probe" {
			source = "web"
		}
		_, err = db.Exec("INSERT INTO events(id,occurred_at,source,kind,peer_ip,client_ip,provenance,username,method,path,web_category) VALUES (?,?,?,?,?,?,'direct',?,?,?,?)", v.id, v.at, source, v.kind, v.ip, v.ip, v.user, v.method, v.path, v.category)
		if err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("SECURITY_SYSTEM_DATABASES", `{"`+ids[0]+`":"`+path+`","`+ids[1]+`":"`+path+`"}`)
	h := &Hub{}
	call := func(method, query, body string, handler func(*core.RequestEvent) error) (map[string]any, error) {
		w := httptest.NewRecorder()
		r := httptest.NewRequest(method, "/?"+query, strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		e := &core.RequestEvent{App: app, Event: router.Event{Request: r, Response: w}}
		err := handler(e)
		if err != nil {
			return nil, err
		}
		v := map[string]any{}
		err = json.Unmarshal(w.Body.Bytes(), &v)
		return v, err
	}
	put := func(body string) error {
		_, err := call("PUT", "system="+ids[0], body, h.putSecurityKnownIPs)
		return err
	}
	if err := put(`{"items":[{"network":"203.0.113.9/24","label":"Home"},{"network":"2001:db8::/64","label":"IPv6"}]}`); err != nil {
		t.Fatal(err)
	}
	for _, body := range []string{`{"items":[{"network":"bad"}]}`, `{"items":[{"network":"203.0.113.8/24"},{"network":"203.0.113.9/24"}]}`, `{"items":[{"network":"::ffff:203.0.113.8/120"}]}`} {
		if put(body) == nil {
			t.Fatal("invalid entry accepted", body)
		}
	}
	items, err := knownSecurityIPs(app, ids[0])
	if err != nil || len(items) != 2 || items[0].Network != "2001:db8::/64" {
		t.Fatal(items, err)
	}
	other, _ := knownSecurityIPs(app, ids[1])
	if len(other) != 0 {
		t.Fatal("known IP leaked into other VPS")
	}
	queryEvents := func(system, query string) []any {
		v, err := call("GET", "system="+system+"&"+query, "", h.getSecurityEvents)
		if err != nil {
			t.Fatal(query, err)
		}
		return v["items"].([]any)
	}
	for _, c := range []struct {
		q string
		n int
	}{
		{"ip_status=known", 2}, {"ip_status=unrecognized", 1}, {"auth_method=publickey&ip_status=known&country=US&q=alice", 1}, {"auth_method=keyboard-interactive", 1}, {"auth_method=unavailable", 1}, {"web_category=sensitive_files", 1}, {"ssh_attempts=true&q=root", 2}, {"web_category=wordpress", 0},
	} {
		if rows := queryEvents(ids[0], c.q); len(rows) != c.n {
			t.Fatalf("%s: %d rows, wanted %d", c.q, len(rows), c.n)
		}
	}
	if len(queryEvents(ids[1], "ip_status=known")) != 0 {
		t.Fatal("trust filter leaked across VPS")
	}
	rows := queryEvents(ids[0], "kind=ssh_success&q=alice")
	login := rows[0].(map[string]any)
	if login["prior_failures_24h"] != float64(1) || login["known_ip_label"] != "Home" {
		t.Fatal(login)
	}
	first, err := call("GET", "system="+ids[0]+"&ip_status=known&limit=1", "", h.getSecurityEvents)
	if err != nil {
		t.Fatal(err)
	}
	second := queryEvents(ids[0], "ip_status=known&limit=1&before="+first["next_before"].(string))
	if len(second) != 1 || second[0].(map[string]any)["id"] == first["items"].([]any)[0].(map[string]any)["id"] {
		t.Fatal("cursor filter broken")
	}
	for _, q := range []string{"ip_status=bad", "auth_method=GET", "web_category=bad", "ssh_attempts=yes"} {
		if _, err := call("GET", "system="+ids[0]+"&"+q, "", h.getSecurityEvents); err == nil {
			t.Fatal("invalid filter accepted", q)
		}
	}
	_, err = db.Exec("INSERT INTO collector_state VALUES (1,?,?,?,'success','')", now, now, now)
	if err != nil {
		t.Fatal(err)
	}
	summary, err := call("GET", "system="+ids[0], "", h.getSecuritySummary)
	if err != nil {
		t.Fatal(err)
	}
	user := summary["top_usernames"].([]any)[0].(map[string]any)
	if user["key"] != "root" || user["unique_ips"] != float64(2) || user["count"] != float64(2) {
		t.Fatal(user)
	}
	if len(summary["top_ssh_ips"].([]any)) != 2 || len(summary["web_categories"].([]any)) != 1 {
		t.Fatal(summary)
	}
	for _, status := range []string{"success", "failed", "running", "delayed"} {
		success, started := now, now
		actual := status
		if status == "delayed" {
			actual = "success"
			success = now - 600
		}
		_, err = db.Exec("UPDATE collector_state SET status=?,last_success_at=?,started_at=?", actual, success, started)
		if err != nil {
			t.Fatal(err)
		}
		result, err := securityCollectorStatus(db)
		if err != nil || result["status"] != status {
			t.Fatal(status, result, err)
		}
	}
	_, err = db.Exec("DROP TABLE collector_state")
	if err != nil {
		t.Fatal(err)
	}
	result, err := securityCollectorStatus(db)
	if err != nil || result["status"] != "unavailable" {
		t.Fatal(result, err)
	}
}

func TestSecurityKnownIPAccess(t *testing.T) {
	e := &core.RequestEvent{}
	if requireAdminRole(e) == nil {
		t.Fatal("anonymous access allowed")
	}
	collection := core.NewAuthCollection("users")
	collection.Fields.Add(&core.TextField{Name: "role"})
	e.Auth = core.NewRecord(collection)
	e.Auth.Set("role", "user")
	if requireAdminRole(e) == nil {
		t.Fatal("non-admin access allowed")
	}
	e.Auth.Set("role", "admin")
	if err := requireAdminRole(e); err != nil {
		t.Fatal(err)
	}
}
