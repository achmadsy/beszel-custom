# Beszel security per VPS

This fork adds an admin-only security history page to Beszel 0.20.0. Open **Riwayat Keamanan** to choose a VPS, or use the security link on its system detail page. Direct URLs use `/security/<system-id>`. Summary cards link to dedicated successful and failed SSH tables. Charts include activity by event type, event composition, top IPs, blocked destination ports, and SSH authentication outcomes.

## Configure each VPS

Run `collector.py` on each monitored VPS, using the included systemd service and timer as templates. The collector reads that VPS's SSH/UFW journal and Nginx logs and retains 30 days of sanitized events. Install it at `/opt/beszel-security/collector.py` and its units under `/etc/systemd/system/`. Run it as `beszel-audit`, with access through the `adm` and `systemd-journal` groups. Set `SECURITY_DB` in the service to choose its output database (default `/var/lib/beszel-security/events.db`). Use `nginx-audit.conf` and `nginx-logrotate` as templates for Nginx JSON logs.

On the hub, mount each VPS database read-only and map **Beszel system record IDs** to those mounted paths:

```yaml
services:
  beszel:
    image: beszel-custom:0.20.0
    environment:
      SECURITY_SYSTEM_DATABASES: '{"system_id_a":"/security_data/vps-a/events.db","system_id_b":"/security_data/vps-b/events.db"}'
    volumes:
      - ./beszel_data:/beszel_data
      - ./security-data:/security_data:ro
```

For remote VPSes, arrange database snapshot delivery to the hub separately. This fork does **not** add security collection to the standard Beszel agent or automatically transfer remote logs. Create consistent snapshots using SQLite's backup API, transfer them to a temporary file, and atomically rename them into the destination directory. Mount the directory rather than an individual file so replacements are visible. Never label the hub's database as another VPS's history. Each collector database belongs to exactly one VPS; the Nginx `host` column is an HTTP virtual host, not a VPS identifier.

For an existing single database, explicitly assign it to its original VPS:

```yaml
environment:
  SECURITY_DB_PATH: /security_data/events.db
  SECURITY_SYSTEM_ID: your_beszel_system_id
```

Without a mapping, that VPS displays a configuration message. A request without `system` is rejected. Paths come exclusively from server configuration. Existing databases need no schema migration. The `/api/beszel/security/{summary,events}` endpoints require authentication and the admin role, and validate the system record before opening its database. Time series use Unix timestamps, bucket counts per event kind, and return `since`, `until`, and `step`; the UI fills empty buckets with zero and shows local time.

## Build

```sh
cd internal/site
npm ci
npm run build
cd ../..
CGO_ENABLED=0 go build -o build/beszel_linux_amd64 -ldflags '-w -s' ./internal/cmd/hub
cd build
docker build -f ../security/Dockerfile -t beszel-custom:0.20.0 .
```

Run `go test -tags testing ./internal/hub -run Security` and `npx tsc -b` (inside `internal/site`) to check database isolation and frontend types.

## Event semantics

The hub opens databases in SQLite read-only/query-only mode. Collection does not issue alerts or block traffic. Cloudflare visitor IP headers are accepted only when the immediate peer matches the refreshed official Cloudflare CIDR list; stale/unavailable lists fall back to the peer IP. Existing combined Nginx logs are imported once as `legacy_unknown`. Query strings, request headers, bodies, cookies, referrers, and user agents are not stored.

UFW logging may be rate-limited. `web_probe` and `ssh_probe` are heuristics, not proof of compromise. SSH event ports are client source ports; firewall event ports are blocked destination ports. Backfill only covers logs and journal entries that remain on each VPS.
