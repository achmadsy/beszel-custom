package hub

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"github.com/pocketbase/pocketbase/core"
	_ "github.com/pocketbase/pocketbase/migrations"
	"github.com/pocketbase/pocketbase/tools/router"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"testing"
	"time"
)

func TestOpenSecurityDBReadOnly(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.db")
	writer, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = writer.Exec("CREATE TABLE events (id INTEGER PRIMARY KEY)"); err != nil {
		t.Fatal(err)
	}
	writer.Close()
	t.Setenv("SECURITY_DB_PATH", path)
	t.Setenv("SECURITY_SYSTEM_ID", "vps-a")
	reader, err := openSecurityDB("vps-a")
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	var count int
	if err = reader.QueryRow("SELECT COUNT(*) FROM events").Scan(&count); err != nil {
		t.Fatal(err)
	}
	if _, err = reader.Exec("INSERT INTO events DEFAULT VALUES"); err == nil {
		t.Fatal("security database unexpectedly writable")
	}
}

func TestSecurityDatabaseIsolation(t *testing.T) {
	t.Setenv("SECURITY_SYSTEM_DATABASES", `{"vps-a":"/data/a.db","vps-b":"/data/b.db"}`)
	t.Setenv("SECURITY_SYSTEM_ID", "legacy")
	t.Setenv("SECURITY_DB_PATH", "/data/legacy.db")
	for id, want := range map[string]string{"vps-a": "/data/a.db", "vps-b": "/data/b.db", "legacy": "/data/legacy.db"} {
		got, err := securityDBPath(id)
		if err != nil || got != want {
			t.Fatalf("%s: got %q, %v", id, got, err)
		}
	}
	for _, id := range []string{"", "vps-c", "../../data/a.db"} {
		if _, err := securityDBPath(id); err == nil {
			t.Fatalf("unexpected access for %q", id)
		}
	}
}

// Exercise both API handlers against two distinct databases, including cursors.
func TestSecurityAPIPerVPS(t *testing.T) {
	app := core.NewBaseApp(core.BaseAppConfig{DataDir: t.TempDir()})
	if err := app.Bootstrap(); err != nil {
		t.Fatal(err)
	}
	defer app.ClearBootstrap()
	collection := core.NewBaseCollection("systems")
	if err := app.Save(collection); err != nil {
		t.Fatal(err)
	}
	paths := map[string]string{}
	ids := []string{}
	now := time.Now().Unix()
	for i := 0; i < 2; i++ {
		record := core.NewRecord(collection)
		if err := app.Save(record); err != nil {
			t.Fatal(err)
		}
		ids = append(ids, record.Id)
		path := filepath.Join(t.TempDir(), "events.db")
		paths[record.Id] = path
		db, err := sql.Open("sqlite", path)
		if err != nil {
			t.Fatal(err)
		}
		_, err = db.Exec(`CREATE TABLE events(id INTEGER PRIMARY KEY, occurred_at INTEGER, source TEXT, kind TEXT, peer_ip TEXT, client_ip TEXT, provenance TEXT, host TEXT, username TEXT, method TEXT, path TEXT, port INTEGER, status INTEGER)`)
		if err != nil {
			t.Fatal(err)
		}
		kind := "ssh_success"
		if i == 1 {
			kind = "ssh_failure"
		}
		for n := 1; n <= i+2; n++ {
			_, err = db.Exec("INSERT INTO events (id,occurred_at,source,kind,provenance,username) VALUES (?,?,'ssh',?,'direct',?)", n, now, kind, record.Id)
			if err != nil {
				t.Fatal(err)
			}
		}
		if i == 0 {
			_, err = db.Exec("CREATE TABLE ip_countries(ip TEXT PRIMARY KEY,country_code TEXT NOT NULL); INSERT INTO ip_countries VALUES ('8.8.8.8','US'); UPDATE events SET peer_ip='9.0.0.1',client_ip='8.8.8.8'")
			if err != nil {
				t.Fatal(err)
			}
		}
		db.Close()
	}
	config, _ := json.Marshal(paths)
	t.Setenv("SECURITY_SYSTEM_DATABASES", string(config))
	h := &Hub{}
	request := func(query string, summary bool) (map[string]json.RawMessage, error) {
		response := httptest.NewRecorder()
		event := &core.RequestEvent{App: app, Event: router.Event{Request: httptest.NewRequest("GET", "/?"+query, nil), Response: response}}
		var err error
		if summary {
			err = h.getSecuritySummary(event)
		} else {
			err = h.getSecurityEvents(event)
		}
		if err != nil {
			return nil, err
		}
		result := map[string]json.RawMessage{}
		err = json.Unmarshal(response.Body.Bytes(), &result)
		return result, err
	}
	for i, id := range ids {
		result, err := request("system="+id, true)
		if err != nil {
			t.Fatal(err)
		}
		var countries []struct {
			Key   string
			Count int
		}
		if err := json.Unmarshal(result["countries"], &countries); err != nil {
			t.Fatal(err)
		}
		if i == 0 && (len(countries) != 1 || countries[0].Key != "US" || countries[0].Count != i+2) {
			t.Fatalf("country aggregation incorrect: %s", result["countries"])
		}
		if i == 1 && len(countries) != 0 {
			t.Fatal("country data leaked into older VPS database")
		}
		var counts []struct {
			Key   string
			Count int
		}
		if err = json.Unmarshal(result["kinds"], &counts); err != nil {
			t.Fatal(err)
		}
		if len(counts) != 1 || counts[0].Count != i+2 {
			t.Fatalf("unexpected summary for %s: %s", id, result["kinds"])
		}
		expected := "ssh_success"
		if i == 1 {
			expected = "ssh_failure"
		}
		if counts[0].Key != expected {
			t.Fatalf("another VPS's kind returned for %s", id)
		}
		result, err = request("system="+id+"&limit=1", false)
		if err != nil {
			t.Fatal(err)
		}
		var items []map[string]any
		json.Unmarshal(result["items"], &items)
		if len(items) != 1 || items[0]["username"] != id {
			t.Fatalf("another VPS's events returned: %s", result["items"])
		}
		if i == 0 && items[0]["country_code"] != "US" {
			t.Fatal("event did not use visitor IP country")
		}
		if i == 1 && items[0]["country_code"] != "" {
			t.Fatal("older collector country fallback failed")
		}
		var cursor string
		json.Unmarshal(result["next_before"], &cursor)
		next, err := request("system="+id+"&limit=1&before="+url.QueryEscape(cursor), false)
		if err != nil {
			t.Fatal(err)
		}
		var more []map[string]any
		json.Unmarshal(next["items"], &more)
		if len(more) != 1 || more[0]["id"] == items[0]["id"] {
			t.Fatal("cursor repeated an event")
		}
	}
	// Verify the lower bound is included and the upper bound is excluded by both handlers.
	db, err := sql.Open("sqlite", paths[ids[0]])
	if err != nil {
		t.Fatal(err)
	}
	for id, at := range map[int]int64{90: now - 3600, 91: now - 7200} {
		if _, err := db.Exec("INSERT INTO events (id,occurred_at,source,kind,provenance,username) VALUES (?,?,'ssh','ssh_probe','direct','probe-user')", id, at); err != nil {
			t.Fatal(err)
		}
	}
	db.Close()
	bounds := fmt.Sprintf("system=%s&from=%d&to=%d", ids[0], now-7200, now-3600)
	result, err := request(bounds, true)
	if err != nil {
		t.Fatal(err)
	}
	var boundedCounts []struct {
		Key   string
		Count int
	}
	if err := json.Unmarshal(result["kinds"], &boundedCounts); err != nil {
		t.Fatal(err)
	}
	if len(boundedCounts) != 1 || boundedCounts[0].Key != "ssh_probe" || boundedCounts[0].Count != 1 {
		t.Fatalf("summary date bounds incorrect: %s", result["kinds"])
	}
	var buckets []struct {
		At    int64
		Count int
	}
	if err := json.Unmarshal(result["series"], &buckets); err != nil {
		t.Fatal(err)
	}
	if len(buckets) != 1 || buckets[0].At != now-7200 || buckets[0].Count != 1 {
		t.Fatalf("unexpected chart buckets: %s", result["series"])
	}
	result, err = request(bounds, false)
	if err != nil {
		t.Fatal(err)
	}
	var boundedItems []struct{ ID int64 }
	if err := json.Unmarshal(result["items"], &boundedItems); err != nil {
		t.Fatal(err)
	}
	if len(boundedItems) != 1 || boundedItems[0].ID != 91 {
		t.Fatalf("event date bounds incorrect: %s", result["items"])
	}

	db, err = sql.Open("sqlite", paths[ids[0]])
	if err != nil {
		t.Fatal(err)
	}
	oldest := now - 120*86400
	_, err = db.Exec("INSERT INTO events (id,occurred_at,source,kind,provenance,username) VALUES (92,?,'ssh','ssh_success','direct','historical-user')", oldest)
	if err != nil {
		t.Fatal(err)
	}
	db.Close()
	all, err := request("system="+ids[0]+"&range=all", true)
	if err != nil {
		t.Fatal(err)
	}
	var since int64
	json.Unmarshal(all["since"], &since)
	if since != oldest {
		t.Fatalf("all time did not start at oldest event: %d", since)
	}
	past, err := request(fmt.Sprintf("system=%s&from=%d&to=%d", ids[0], oldest, oldest+86400), false)
	if err != nil {
		t.Fatal(err)
	}
	var pastItems []map[string]any
	json.Unmarshal(past["items"], &pastItems)
	if len(pastItems) != 1 || pastItems[0]["username"] != "historical-user" {
		t.Fatalf("older event missing: %s", past["items"])
	}
	for _, query := range []string{"", "system=unknown", "system=" + ids[0] + "&range=bad", "system=" + ids[0] + "&kind=invalid", "system=" + ids[0] + "&before=invalid"} {
		if _, err := request(query, false); err == nil {
			t.Fatalf("invalid query accepted: %s", query)
		}
	}
}

func TestSecurityCustomDateValidation(t *testing.T) {
	now := time.Now().Unix()
	for _, query := range []string{"range=all", fmt.Sprintf("from=%d&to=%d", now-365*86400, now)} {
		e := &core.RequestEvent{Event: router.Event{Request: httptest.NewRequest("GET", "/?"+query, nil)}}
		if _, _, err := securityBounds(e); err != nil {
			t.Fatalf("historical range rejected: %v", err)
		}
	}
	invalid := []string{
		"from=abc&to=123", "from=&to=", fmt.Sprintf("from=%d", now-3600), fmt.Sprintf("to=%d", now),
		fmt.Sprintf("from=%d&to=%d", now, now), fmt.Sprintf("from=%d&to=%d", now, now-3600),
		fmt.Sprintf("from=%d&to=%d", now, now+2*86400),
	}
	for _, query := range invalid {
		e := &core.RequestEvent{Event: router.Event{Request: httptest.NewRequest("GET", "/?"+query, nil)}}
		if _, _, err := securityBounds(e); err == nil {
			t.Fatalf("invalid date range accepted: %s", query)
		}
	}
}
