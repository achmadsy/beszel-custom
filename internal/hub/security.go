package hub

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/pocketbase/pocketbase/core"
	_ "modernc.org/sqlite"
)

type securityEvent struct {
	ID         int64          `json:"id"`
	At         int64          `json:"at"`
	Source     string         `json:"source"`
	Kind       string         `json:"kind"`
	PeerIP     sql.NullString `json:"-"`
	ClientIP   sql.NullString `json:"-"`
	Provenance string         `json:"provenance"`
	Host       sql.NullString `json:"-"`
	Username   sql.NullString `json:"-"`
	Method     sql.NullString `json:"-"`
	Path       sql.NullString `json:"-"`
	Port       sql.NullInt64  `json:"-"`
	Status     sql.NullInt64  `json:"-"`
}

// Database paths are server configuration, never request-supplied paths.
func securityDBPath(systemID string) (string, error) {
	if systemID == "" {
		return "", fmt.Errorf("system is required")
	}
	paths := map[string]string{}
	if raw := os.Getenv("SECURITY_SYSTEM_DATABASES"); raw != "" {
		if err := json.Unmarshal([]byte(raw), &paths); err != nil {
			return "", fmt.Errorf("invalid security database configuration")
		}
	}
	if path := paths[systemID]; path != "" {
		return path, nil
	}
	// Legacy databases must be explicitly assigned to their original VPS.
	if systemID == os.Getenv("SECURITY_SYSTEM_ID") {
		if path := os.Getenv("SECURITY_DB_PATH"); path != "" {
			return path, nil
		}
	}
	return "", fmt.Errorf("security collector is not configured for this VPS")
}

func openSecurityDB(systemID string) (*sql.DB, error) {
	path, err := securityDBPath(systemID)
	if err != nil {
		return nil, err
	}
	return sql.Open("sqlite", (&url.URL{Scheme: "file", Path: path, RawQuery: "mode=ro&_pragma=query_only(1)"}).String())
}

func (h *Hub) securityDatabase(e *core.RequestEvent) (*sql.DB, error) {
	id := e.Request.URL.Query().Get("system")
	if id == "" {
		return nil, e.BadRequestError("system is required", nil)
	}
	if _, err := e.App.FindRecordById("systems", id); err != nil {
		return nil, e.NotFoundError("VPS not found", nil)
	}
	if _, err := securityDBPath(id); err != nil {
		return nil, e.BadRequestError(err.Error(), nil)
	}
	db, err := openSecurityDB(id)
	if err != nil {
		return nil, e.InternalServerError("Security history unavailable", err)
	}
	return db, nil
}

func securitySince(e *core.RequestEvent) (int64, error) {
	switch e.Request.URL.Query().Get("range") {
	case "", "24h":
		return time.Now().Add(-24 * time.Hour).Unix(), nil
	case "7d":
		return time.Now().Add(-7 * 24 * time.Hour).Unix(), nil
	case "30d":
		return time.Now().Add(-30 * 24 * time.Hour).Unix(), nil
	default:
		return 0, fmt.Errorf("invalid range")
	}
}

func (h *Hub) getSecuritySummary(e *core.RequestEvent) error {
	since, err := securitySince(e)
	if err != nil {
		return e.BadRequestError(err.Error(), nil)
	}
	db, err := h.securityDatabase(e)
	if err != nil {
		return err
	}
	defer db.Close()
	if err = db.Ping(); err != nil {
		return e.InternalServerError("Security history unavailable", err)
	}
	type count struct {
		Key   string `json:"key"`
		Count int    `json:"count"`
	}
	collect := func(query string, args ...any) ([]count, error) {
		rows, err := db.Query(query, args...)
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		result := []count{}
		for rows.Next() {
			var item count
			if err = rows.Scan(&item.Key, &item.Count); err != nil {
				return nil, err
			}
			result = append(result, item)
		}
		return result, rows.Err()
	}
	kinds, err := collect("SELECT kind, COUNT(*) FROM events WHERE occurred_at >= ? GROUP BY kind ORDER BY COUNT(*) DESC", since)
	if err != nil {
		return e.InternalServerError("Failed to query security history", err)
	}
	// Epoch buckets are returned for correct local-time labels and explicit zero gaps.
	step := int64(3600)
	if e.Request.URL.Query().Get("range") == "30d" {
		step = 86400
	}
	type bucket struct {
		At    int64  `json:"at"`
		Kind  string `json:"kind"`
		Count int    `json:"count"`
	}
	series := []bucket{}
	rows, err := db.Query("SELECT (occurred_at / ?) * ?, kind, COUNT(*) FROM events WHERE occurred_at >= ? GROUP BY 1,2 ORDER BY 1", step, step, since)
	if err != nil {
		return e.InternalServerError("Failed to query security history", err)
	}
	for rows.Next() {
		var item bucket
		if err = rows.Scan(&item.At, &item.Kind, &item.Count); err != nil {
			rows.Close()
			return e.InternalServerError("Failed to query security history", err)
		}
		series = append(series, item)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return e.InternalServerError("Failed to query security history", err)
	}
	insight, err := collect("SELECT COALESCE(client_ip, peer_ip, 'unknown'), COUNT(*) FROM events WHERE occurred_at >= ? AND kind != 'web_request' GROUP BY 1 ORDER BY 2 DESC LIMIT 10", since)
	if err != nil {
		return e.InternalServerError("Failed to query security history", err)
	}
	ports, err := collect("SELECT CAST(port AS TEXT), COUNT(*) FROM events WHERE occurred_at >= ? AND port IS NOT NULL AND kind = 'firewall_block' GROUP BY port ORDER BY 2 DESC LIMIT 10", since)
	if err != nil {
		return e.InternalServerError("Failed to query security history", err)
	}
	return e.JSON(http.StatusOK, map[string]any{"kinds": kinds, "series": series, "top_ips": insight, "top_ports": ports, "since": since, "until": time.Now().Unix(), "step": step, "system": e.Request.URL.Query().Get("system")})
}

func (h *Hub) getSecurityEvents(e *core.RequestEvent) error {
	since, err := securitySince(e)
	if err != nil {
		return e.BadRequestError(err.Error(), nil)
	}
	q := e.Request.URL.Query()
	limit, _ := strconv.Atoi(q.Get("limit"))
	if limit < 1 || limit > 100 {
		limit = 50
	}
	beforeTime, beforeID := int64(1<<63-1), int64(1<<63-1)
	if raw := q.Get("before"); raw != "" {
		parts := strings.Split(raw, ":")
		if len(parts) != 2 {
			return e.BadRequestError("invalid cursor", nil)
		}
		beforeTime, err = strconv.ParseInt(parts[0], 10, 64)
		if err != nil {
			return e.BadRequestError("invalid cursor", nil)
		}
		beforeID, err = strconv.ParseInt(parts[1], 10, 64)
		if err != nil {
			return e.BadRequestError("invalid cursor", nil)
		}
	}
	source := q.Get("source")
	if source != "" && source != "ssh" && source != "web" && source != "firewall" {
		return e.BadRequestError("invalid source", nil)
	}
	kind := q.Get("kind")
	allowed := map[string]bool{"": true, "ssh_success": true, "ssh_failure": true, "ssh_probe": true, "firewall_block": true, "web_request": true, "web_probe": true}
	if !allowed[kind] {
		return e.BadRequestError("invalid kind", nil)
	}
	db, err := h.securityDatabase(e)
	if err != nil {
		return err
	}
	defer db.Close()
	query := "SELECT id,occurred_at,source,kind,peer_ip,client_ip,provenance,host,username,method,path,port,status FROM events WHERE occurred_at >= ? AND (occurred_at < ? OR (occurred_at = ? AND id < ?))"
	args := []any{since, beforeTime, beforeTime, beforeID}
	if source != "" {
		query += " AND source = ?"
		args = append(args, source)
	}
	if kind != "" {
		query += " AND kind = ?"
		args = append(args, kind)
	}
	query += " ORDER BY occurred_at DESC, id DESC LIMIT ?"
	args = append(args, limit)
	rows, err := db.Query(query, args...)
	if err != nil {
		return e.InternalServerError("Failed to query security history", err)
	}
	defer rows.Close()
	items := []map[string]any{}
	for rows.Next() {
		var v securityEvent
		if err = rows.Scan(&v.ID, &v.At, &v.Source, &v.Kind, &v.PeerIP, &v.ClientIP, &v.Provenance, &v.Host, &v.Username, &v.Method, &v.Path, &v.Port, &v.Status); err != nil {
			return e.InternalServerError("Failed to query security history", err)
		}
		items = append(items, map[string]any{"id": v.ID, "at": v.At, "source": v.Source, "kind": v.Kind, "peer_ip": v.PeerIP.String, "client_ip": v.ClientIP.String, "provenance": v.Provenance, "host": v.Host.String, "username": v.Username.String, "method": v.Method.String, "path": v.Path.String, "port": v.Port.Int64, "status": v.Status.Int64})
	}
	if err = rows.Err(); err != nil {
		return e.InternalServerError("Failed to query security history", err)
	}
	next := ""
	if len(items) == limit {
		last := items[len(items)-1]
		next = fmt.Sprintf("%d:%d", last["at"].(int64), last["id"].(int64))
	}
	return e.JSON(http.StatusOK, map[string]any{"items": items, "next_before": next})
}
