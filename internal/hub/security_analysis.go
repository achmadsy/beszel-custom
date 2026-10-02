package hub

import (
	"database/sql"
	"database/sql/driver"
	"fmt"
	"net/http"
	"net/netip"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/pocketbase/dbx"
	"github.com/pocketbase/pocketbase/core"
	"modernc.org/sqlite"
)

func init() {
	sqlite.MustRegisterDeterministicScalarFunction("security_ip_in_network", 2, func(_ *sqlite.FunctionContext, args []driver.Value) (driver.Value, error) {
		ip, _ := args[0].(string)
		network, _ := args[1].(string)
		addr, err := netip.ParseAddr(ip)
		prefix, pErr := netip.ParsePrefix(network)
		if err == nil && pErr == nil && prefix.Contains(addr.Unmap()) {
			return int64(1), nil
		}
		return int64(0), nil
	})
}

type securityKnownIP struct {
	Network string `json:"network" db:"network"`
	Label   string `json:"label" db:"label"`
}

func knownSecurityIPs(app core.App, system string) ([]securityKnownIP, error) {
	items := []securityKnownIP{}
	// Older test apps and installations without the migration remain readable.
	var count int
	if err := app.DB().NewQuery("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='security_known_ips'").Row(&count); err != nil {
		return nil, err
	}
	if count == 0 {
		return items, nil
	}
	err := app.DB().NewQuery("SELECT network,label FROM security_known_ips WHERE system={:system} ORDER BY network").Bind(dbx.Params{"system": system}).All(&items)
	return items, err
}

func securitySystem(e *core.RequestEvent) (string, error) {
	id := e.Request.URL.Query().Get("system")
	if id == "" {
		return "", e.BadRequestError("system is required", nil)
	}
	if _, err := e.App.FindRecordById("systems", id); err != nil {
		return "", e.NotFoundError("VPS not found", nil)
	}
	return id, nil
}

func (h *Hub) getSecurityKnownIPs(e *core.RequestEvent) error {
	id, err := securitySystem(e)
	if err != nil {
		return err
	}
	items, err := knownSecurityIPs(e.App, id)
	if err != nil {
		return e.InternalServerError("Could not load known IPs", err)
	}
	return e.JSON(http.StatusOK, map[string]any{"items": items})
}

func (h *Hub) putSecurityKnownIPs(e *core.RequestEvent) error {
	id, err := securitySystem(e)
	if err != nil {
		return err
	}
	var body struct {
		Items []securityKnownIP `json:"items"`
	}
	if err := e.BindBody(&body); err != nil {
		return e.BadRequestError("invalid known IP list", err)
	}
	if len(body.Items) > 100 {
		return e.BadRequestError("at most 100 known IP entries are allowed", nil)
	}
	seen := map[string]bool{}
	for i, item := range body.Items {
		raw := strings.TrimSpace(item.Network)
		prefix, err := netip.ParsePrefix(raw)
		if err != nil {
			addr, aErr := netip.ParseAddr(raw)
			if aErr != nil || addr.Zone() != "" {
				return e.BadRequestError("provide a valid IP address or CIDR", nil)
			}
			addr = addr.Unmap()
			prefix = netip.PrefixFrom(addr, addr.BitLen())
		}
		if prefix.Addr().Is4In6() {
			return e.BadRequestError("use an IPv4 address instead of mapped IPv6 CIDR", nil)
		}
		body.Items[i].Network = prefix.Masked().String()
		body.Items[i].Label = strings.TrimSpace(item.Label)
		if utf8.RuneCountInString(body.Items[i].Label) > 80 || strings.ContainsAny(body.Items[i].Label, "\x00\r\n") {
			return e.BadRequestError("labels must be one line and 80 characters or fewer", nil)
		}
		if seen[body.Items[i].Network] {
			return e.BadRequestError("duplicate network", nil)
		}
		seen[body.Items[i].Network] = true
	}
	err = e.App.RunInTransaction(func(app core.App) error {
		if _, err := app.DB().NewQuery("DELETE FROM security_known_ips WHERE system={:system}").Bind(dbx.Params{"system": id}).Execute(); err != nil {
			return err
		}
		for _, item := range body.Items {
			if _, err := app.DB().NewQuery("INSERT INTO security_known_ips(system,network,label) VALUES ({:system},{:network},{:label})").Bind(dbx.Params{"system": id, "network": item.Network, "label": item.Label}).Execute(); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return e.InternalServerError("Could not save known IPs", err)
	}
	return h.getSecurityKnownIPs(e)
}

func knownIPPredicate(items []securityKnownIP) string {
	parts := []string{}
	for _, item := range items {
		// Reparse database values before using canonical network text as a SQL literal.
		if prefix, err := netip.ParsePrefix(item.Network); err == nil {
			parts = append(parts, fmt.Sprintf("security_ip_in_network(COALESCE(NULLIF(events.client_ip,''),events.peer_ip), '%s')", prefix.Masked().String()))
		}
	}
	if len(parts) == 0 {
		return "0"
	}
	return "(" + strings.Join(parts, " OR ") + ")"
}

func knownIPLabel(ip string, items []securityKnownIP) (bool, string) {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return false, ""
	}
	best := -1
	label := ""
	for _, item := range items {
		prefix, err := netip.ParsePrefix(item.Network)
		if err == nil && prefix.Contains(addr.Unmap()) && prefix.Bits() > best {
			best = prefix.Bits()
			label = item.Label
		}
	}
	return best >= 0, label
}

func securityTableReady(db *sql.DB, name string) bool {
	var n int
	return db.QueryRow("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?", name).Scan(&n) == nil && n > 0
}

func securityCategoryColumn(db *sql.DB) string {
	rows, err := db.Query("PRAGMA table_info(events)")
	if err != nil {
		return "''"
	}
	defer rows.Close()
	for rows.Next() {
		var cid, notnull, pk int
		var name, typ string
		var def any
		if rows.Scan(&cid, &name, &typ, &notnull, &def, &pk) == nil && name == "web_category" {
			return "COALESCE(events.web_category,'')"
		}
	}
	return "''"
}

func securityCollectorStatus(db *sql.DB) (map[string]any, error) {
	result := map[string]any{"status": "unavailable", "started_at": nil, "finished_at": nil, "last_success_at": nil, "error": ""}
	var oldest, newest sql.NullInt64
	if err := db.QueryRow("SELECT MIN(occurred_at),MAX(occurred_at) FROM events").Scan(&oldest, &newest); err != nil {
		return nil, err
	}
	if oldest.Valid {
		result["oldest_event_at"] = oldest.Int64
		result["newest_event_at"] = newest.Int64
	}
	if !securityTableReady(db, "collector_state") {
		return result, nil
	}
	var started, finished, success sql.NullInt64
	var status, message string
	err := db.QueryRow("SELECT started_at,finished_at,last_success_at,status,error FROM collector_state WHERE id=1").Scan(&started, &finished, &success, &status, &message)
	if err == sql.ErrNoRows {
		return result, nil
	}
	if err != nil {
		return nil, err
	}
	result["status"] = status
	result["error"] = message
	if started.Valid {
		result["started_at"] = started.Int64
	}
	if finished.Valid {
		result["finished_at"] = finished.Int64
	}
	if success.Valid {
		result["last_success_at"] = success.Int64
	}
	if status != "failed" && (!success.Valid || time.Now().Unix()-success.Int64 > 300) {
		if status != "running" || !started.Valid || time.Now().Unix()-started.Int64 > 300 {
			result["status"] = "delayed"
		}
	}
	return result, nil
}
