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
	"unicode/utf8"

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

// Custom bounds use Unix seconds: inclusive from, exclusive to.
func securityBounds(e *core.RequestEvent) (int64, int64, error) {
	q := e.Request.URL.Query()
	now := time.Now()
	if q.Has("from") || q.Has("to") {
		from, errFrom := strconv.ParseInt(q.Get("from"), 10, 64)
		to, errTo := strconv.ParseInt(q.Get("to"), 10, 64)
		if errFrom != nil || errTo != nil || from <= 0 || to <= from {
			return 0, 0, fmt.Errorf("provide a valid start and end date")
		}
		if to > now.Add(24*time.Hour).Unix() {
			return 0, 0, fmt.Errorf("end date cannot be in the future")
		}
		return from, to, nil
	}
	days := 1
	switch q.Get("range") {
	case "", "24h":
	case "7d":
		days = 7
	case "30d":
		days = 30
	case "all":
		return 0, now.Unix() + 1, nil
	default:
		return 0, 0, fmt.Errorf("invalid range")
	}
	return now.Add(-time.Duration(days) * 24 * time.Hour).Unix(), now.Unix() + 1, nil
}

// Older collector databases continue to work while enrichment is being installed.
func securityCountriesReady(db *sql.DB) bool {
	var count int
	return db.QueryRow("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='ip_countries'").Scan(&count) == nil && count == 1
}

func (h *Hub) getSecuritySummary(e *core.RequestEvent) error {
	since, until, err := securityBounds(e)
	if err != nil {
		return e.BadRequestError(err.Error(), nil)
	}
	db, err := h.securityDatabase(e)
	if err != nil {
		return err
	}
	defer db.Close()
	if since == 0 {
		if err := db.QueryRow("SELECT COALESCE(MIN(occurred_at), ?) FROM events", until-1).Scan(&since); err != nil {
			return e.InternalServerError("Failed to query security history", err)
		}
	}
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
	kinds, err := collect("SELECT kind, COUNT(*) FROM events WHERE occurred_at >= ? AND occurred_at < ? GROUP BY kind ORDER BY COUNT(*) DESC", since, until)
	if err != nil {
		return e.InternalServerError("Failed to query security history", err)
	}
	// Epoch buckets are returned for correct local-time labels and explicit zero gaps.
	step := int64(3600)
	if until-since > 3*86400 {
		step = 86400
	}
	if until-since > 366*86400 {
		step = 7 * 86400
	}
	if until-since > 5*366*86400 {
		step = 30 * 86400
	}
	type bucket struct {
		At    int64  `json:"at"`
		Kind  string `json:"kind"`
		Count int    `json:"count"`
	}
	series := []bucket{}
	rows, err := db.Query("SELECT ((occurred_at - ?) / ?) * ? + ?, kind, COUNT(*) FROM events WHERE occurred_at >= ? AND occurred_at < ? GROUP BY 1,2 ORDER BY 1", since, step, step, since, since, until)
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
	insight, err := collect("SELECT COALESCE(client_ip, peer_ip, 'unknown'), COUNT(*) FROM events WHERE occurred_at >= ? AND occurred_at < ? AND kind != 'web_request' GROUP BY 1 ORDER BY 2 DESC LIMIT 10", since, until)
	if err != nil {
		return e.InternalServerError("Failed to query security history", err)
	}
	ports, err := collect("SELECT CAST(port AS TEXT), COUNT(*) FROM events WHERE occurred_at >= ? AND occurred_at < ? AND port IS NOT NULL AND kind = 'firewall_block' GROUP BY port ORDER BY 2 DESC LIMIT 10", since, until)
	if err != nil {
		return e.InternalServerError("Failed to query security history", err)
	}
	countries := []count{}
	if securityCountriesReady(db) {
		countries, err = collect("SELECT COALESCE(c.country_code, ''), COUNT(*) FROM events e LEFT JOIN ip_countries c ON c.ip=COALESCE(NULLIF(e.client_ip,''),NULLIF(e.peer_ip,'')) WHERE e.occurred_at >= ? AND e.occurred_at < ? GROUP BY 1 ORDER BY 2 DESC,1", since, until)
		if err != nil {
			return e.InternalServerError("Failed to query country history", err)
		}
	}
	sshIPs, err := collect("SELECT COALESCE(NULLIF(client_ip,''),peer_ip,'unknown'),COUNT(*) FROM events WHERE occurred_at>=? AND occurred_at<? AND kind IN ('ssh_failure','ssh_probe') GROUP BY 1 ORDER BY 2 DESC LIMIT 10", since, until)
	if err != nil {
		return e.InternalServerError("Failed to query SSH rankings", err)
	}
	type usernameCount struct {
		Key       string `json:"key"`
		Count     int    `json:"count"`
		UniqueIPs int    `json:"unique_ips"`
	}
	users := []usernameCount{}
	userRows, err := db.Query("SELECT username,COUNT(*),COUNT(DISTINCT COALESCE(NULLIF(client_ip,''),peer_ip)) FROM events WHERE occurred_at>=? AND occurred_at<? AND kind IN ('ssh_failure','ssh_probe') AND COALESCE(username,'')!='' GROUP BY username ORDER BY 2 DESC,username LIMIT 10", since, until)
	if err != nil {
		return e.InternalServerError("Failed to query username rankings", err)
	}
	for userRows.Next() {
		var user usernameCount
		if err = userRows.Scan(&user.Key, &user.Count, &user.UniqueIPs); err != nil {
			userRows.Close()
			return e.InternalServerError("Failed to query username rankings", err)
		}
		users = append(users, user)
	}
	err = userRows.Err()
	userRows.Close()
	if err != nil {
		return e.InternalServerError("Failed to query username rankings", err)
	}
	categoryColumn := securityCategoryColumn(db)
	categories, err := collect("SELECT "+categoryColumn+",COUNT(*) FROM events WHERE occurred_at>=? AND occurred_at<? AND kind='web_probe' AND "+categoryColumn+"!='' GROUP BY 1 ORDER BY 2 DESC", since, until)
	if err != nil {
		return e.InternalServerError("Failed to query probe categories", err)
	}
	paths, err := collect("SELECT path,COUNT(*) FROM events WHERE occurred_at>=? AND occurred_at<? AND kind='web_probe' AND COALESCE(path,'')!='' GROUP BY path ORDER BY 2 DESC,path LIMIT 10", since, until)
	if err != nil {
		return e.InternalServerError("Failed to query probe paths", err)
	}
	collector, err := securityCollectorStatus(db)
	if err != nil {
		return e.InternalServerError("Failed to query collector status", err)
	}
	return e.JSON(http.StatusOK, map[string]any{"kinds": kinds, "series": series, "top_ips": insight, "top_ports": ports, "top_ssh_ips": sshIPs, "top_usernames": users, "web_categories": categories, "top_web_paths": paths, "collector": collector, "countries": countries, "since": since, "until": until, "step": step, "system": e.Request.URL.Query().Get("system")})
}

func (h *Hub) getSecurityEvents(e *core.RequestEvent) error {
	since, until, err := securityBounds(e)
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
	country := strings.ToUpper(strings.TrimSpace(q.Get("country")))
	if country != "" && country != "LOCAL" && country != "UNKNOWN" && !(len(country) == 2 && country[0] >= 'A' && country[0] <= 'Z' && country[1] >= 'A' && country[1] <= 'Z') {
		return e.BadRequestError("invalid country filter", nil)
	}
	countryColumn, eventSource := "''", "events"
	if securityCountriesReady(db) {
		countryColumn = "COALESCE(c.country_code, '')"
		eventSource += " LEFT JOIN ip_countries c ON c.ip=COALESCE(NULLIF(events.client_ip,''),NULLIF(events.peer_ip,''))"
	}
	known, err := knownSecurityIPs(e.App, q.Get("system"))
	if err != nil {
		return e.InternalServerError("Could not load known IPs", err)
	}
	knownPredicate := knownIPPredicate(known)
	categoryColumn := securityCategoryColumn(db)
	ipStatus, authMethod, category := q.Get("ip_status"), q.Get("auth_method"), q.Get("web_category")
	if ipStatus != "" && ipStatus != "known" && ipStatus != "unrecognized" {
		return e.BadRequestError("invalid IP status", nil)
	}
	if authMethod != "" && authMethod != "publickey" && authMethod != "password" && authMethod != "keyboard-interactive" && authMethod != "unavailable" {
		return e.BadRequestError("invalid authentication method", nil)
	}
	allowedCategories := map[string]bool{"": true, "sensitive_files": true, "wordpress": true, "php_tooling": true, "admin_panels": true, "traversal_injection": true, "other_probes": true}
	if !allowedCategories[category] {
		return e.BadRequestError("invalid web category", nil)
	}
	query := "SELECT id,occurred_at,source,kind,peer_ip,client_ip,provenance,host,username,method,path,port,status," + countryColumn + "," + categoryColumn + " FROM " + eventSource + " WHERE occurred_at >= ? AND occurred_at < ? AND (occurred_at < ? OR (occurred_at = ? AND id < ?))"
	args := []any{since, until, beforeTime, beforeTime, beforeID}
	if source != "" {
		query += " AND source = ?"
		args = append(args, source)
	}
	if kind != "" {
		query += " AND kind = ?"
		args = append(args, kind)
	}
	if country != "" {
		query += " AND " + countryColumn + " = ?"
		if country == "UNKNOWN" {
			country = ""
		}
		args = append(args, country)
	}
	if ipStatus != "" {
		query += " AND kind='ssh_success' AND " + knownPredicate
		if ipStatus == "unrecognized" {
			query += "=0"
		}
	}
	if authMethod != "" {
		query += " AND source='ssh'"
		switch authMethod {
		case "unavailable":
			query += " AND COALESCE(method,'')=''"
		case "keyboard-interactive":
			query += " AND method IN ('keyboard-interactive','keyboard-interactive/pam')"
		default:
			query += " AND method=?"
			args = append(args, authMethod)
		}
	}
	if category != "" {
		query += " AND kind='web_probe' AND " + categoryColumn + "=?"
		args = append(args, category)
	}
	attemptsOnly := q.Get("ssh_attempts")
	if attemptsOnly != "" && attemptsOnly != "true" {
		return e.BadRequestError("invalid SSH attempts filter", nil)
	}
	if attemptsOnly == "true" {
		query += " AND kind IN ('ssh_failure','ssh_probe')"
	}
	query += " ORDER BY occurred_at DESC, id DESC LIMIT ?"
	search := strings.TrimSpace(q.Get("q"))
	if utf8.RuneCountInString(search) > 200 {
		return e.BadRequestError("search must be 200 characters or fewer", nil)
	}
	if search != "" {
		query = strings.TrimSuffix(query, " ORDER BY occurred_at DESC, id DESC LIMIT ?")
		query += " AND (peer_ip LIKE ? ESCAPE '\\' OR client_ip LIKE ? ESCAPE '\\' OR username LIKE ? ESCAPE '\\' OR path LIKE ? ESCAPE '\\') ORDER BY occurred_at DESC, id DESC LIMIT ?"
		pattern := "%" + strings.NewReplacer("\\", "\\\\", "%", "\\%", "_", "\\_").Replace(search) + "%"
		args = append(args, pattern, pattern, pattern, pattern)
	}
	args = append(args, limit+1)
	rows, err := db.Query(query, args...)
	if err != nil {
		return e.InternalServerError("Failed to query security history", err)
	}
	defer rows.Close()
	items := []map[string]any{}
	for rows.Next() {
		var v securityEvent
		var country, category string
		if err = rows.Scan(&v.ID, &v.At, &v.Source, &v.Kind, &v.PeerIP, &v.ClientIP, &v.Provenance, &v.Host, &v.Username, &v.Method, &v.Path, &v.Port, &v.Status, &country, &category); err != nil {
			return e.InternalServerError("Failed to query security history", err)
		}
		ip := v.ClientIP.String
		if ip == "" {
			ip = v.PeerIP.String
		}
		knownIP, label := knownIPLabel(ip, known)
		var priorFailures int64
		status := ""
		if v.Kind == "ssh_success" {
			status = "unrecognized"
			if knownIP {
				status = "known"
			}
			if err = db.QueryRow("SELECT COUNT(*) FROM events WHERE source='ssh' AND kind='ssh_failure' AND COALESCE(NULLIF(client_ip,''),peer_ip)=? AND occurred_at>=? AND occurred_at<=?", ip, v.At-86400, v.At).Scan(&priorFailures); err != nil {
				return e.InternalServerError("Failed to query prior authentication failures", err)
			}
		}
		items = append(items, map[string]any{"web_category": category, "ip_status": status, "known_ip_label": label, "prior_failures_24h": priorFailures, "country_code": country, "id": v.ID, "at": v.At, "source": v.Source, "kind": v.Kind, "peer_ip": v.PeerIP.String, "client_ip": v.ClientIP.String, "provenance": v.Provenance, "host": v.Host.String, "username": v.Username.String, "method": v.Method.String, "path": v.Path.String, "port": v.Port.Int64, "status": v.Status.Int64})
	}
	if err = rows.Err(); err != nil {
		return e.InternalServerError("Failed to query security history", err)
	}
	next := ""
	if len(items) > limit {
		items = items[:limit]
		last := items[len(items)-1]
		next = fmt.Sprintf("%d:%d", last["at"].(int64), last["id"].(int64))
	}
	return e.JSON(http.StatusOK, map[string]any{"items": items, "next_before": next})
}
