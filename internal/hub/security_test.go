package hub

import (
	"database/sql"
	"encoding/json"
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
	for _, query := range []string{"", "system=unknown", "system=" + ids[0] + "&range=bad", "system=" + ids[0] + "&kind=invalid", "system=" + ids[0] + "&before=invalid"} {
		if _, err := request(query, false); err == nil {
			t.Fatalf("invalid query accepted: %s", query)
		}
	}
}
