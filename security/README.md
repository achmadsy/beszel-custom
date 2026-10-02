# Security history per VPS

This fork adds an admin-only security dashboard to Beszel: event charts, per-VPS history, and separate tables for successful and failed SSH logins. Cards, dropdowns, and tooltips use Beszel's theme. Colors identify event types.

**Installation is not yet plug and play.** The normal Beszel agent still collects system metrics. Security history uses a separate Python collector on each VPS, plus a read-only database mount on the hub. These instructions build the custom Docker image locally. There is no bundled installer or automatic transfer of remote security databases.

## Where the data comes from

| Events | Source on the monitored VPS |
| --- | --- |
| Successful/failed SSH logins and SSH probes | `journalctl -u ssh.service` |
| Firewall blocks and blocked destination ports | Kernel journal entries containing `[UFW BLOCK]` |
| Web requests and suspicious web paths | `/var/log/nginx/beszel-security.log`, a JSON Nginx access log |
| Initial web backfill | Existing `/var/log/nginx/access.log` rotations, marked `legacy_unknown` |

The systemd timer runs the collector every minute. It stores sanitized events and collection cursors in `/var/lib/beszel-security/events.db`, keeping all imported history by default. The hub reads this SQLite database through a read-only mount. Graphs reflect recorded log events, not every packet or connection. A successful SSH login is not the same as an active SSH session.

## Supported quick start

The commands below target **Ubuntu/Debian with systemd, Docker Compose, and a rootful Docker daemon**. They collect SSH from `ssh.service`; another distribution using `sshd.service` needs the unit name adjusted in `collector.py`. Nginx is optional for web data. UFW block data requires UFW to be installed and logging enabled. Neither service is enabled or installed by this collector.

Run the hub and collector on the **same VPS** for a local installation. For a remote monitored VPS, also follow the snapshot delivery section.

### 1. Clone and build the custom hub

Install Git, Python 3, Node.js/npm compatible with `internal/site/package.json` and Vite, Docker Compose, and the Go version required by `go.mod`. The current Dockerfile targets Linux amd64.

```sh
git clone https://github.com/hafizhrf/beszel-custom.git
cd beszel-custom
npm --prefix internal/site ci
npm --prefix internal/site run build
mkdir -p build
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build \
  -o build/beszel_linux_amd64 -ldflags '-w -s' ./internal/cmd/hub
docker build -f security/Dockerfile -t beszel-custom:0.20.0 build
```

Keep this repository directory for the collector installation below. The image contains the custom hub; it does not install a collector onto the host. If you already have a Beszel deployment, use your existing hub data volume and agent configuration when switching its hub image.

### 2. Install the collector on each monitored VPS

Run these commands from the repository root on the VPS whose logs you want to collect. You can copy the `security/` directory there instead of building the hub on every VPS.

```sh
sudo apt-get update
sudo apt-get install -y python3 ca-certificates
id beszel-audit >/dev/null 2>&1 || sudo useradd --system \
  --user-group --no-create-home --shell /usr/sbin/nologin beszel-audit
sudo usermod -aG adm,systemd-journal beszel-audit
sudo install -d -m 0755 /opt/beszel-security
sudo install -d -m 0700 -o beszel-audit -g beszel-audit /var/lib/beszel-security
sudo install -m 0755 security/collector.py /opt/beszel-security/collector.py
sudo install -m 0644 security/countries.py /opt/beszel-security/countries.py
sudo install -m 0644 security/beszel-security.service /etc/systemd/system/
sudo install -m 0644 security/beszel-security.timer /etc/systemd/system/
```

The supplied service already treats absent Nginx and journal directories as optional. Existing installations can use this override when upgrading:

```sh
sudo mkdir -p /etc/systemd/system/beszel-security.service.d
sudo tee /etc/systemd/system/beszel-security.service.d/read-paths.conf >/dev/null <<'UNIT'
[Service]
ReadOnlyPaths=
ReadOnlyPaths=-/var/log/nginx -/var/log/journal -/run/log/journal
UNIT
```

### 3. Enable web logging if you use Nginx

Skip this section if you only want SSH/firewall data. The supplied Nginx log format belongs in the `http` context; Ubuntu/Debian normally include `/etc/nginx/conf.d/*.conf` there.

```sh
sudo install -m 0644 security/nginx-audit.conf /etc/nginx/conf.d/beszel-security.conf
sudo nginx -t
sudo systemctl reload nginx
```

If a `server` or `location` block defines its own `access_log`, it overrides the inherited log destinations. Add the following directive in those blocks as well, alongside their existing logs:

```nginx
access_log /var/log/nginx/beszel-security.log beszel_security;
```

Check your existing `/etc/logrotate.d/nginx` rules. If they already rotate `/var/log/nginx/*.log`, they cover the audit log too; use those rules. If they do not cover the audit log, install the supplied rule:

```sh
sudo install -m 0644 security/nginx-logrotate /etc/logrotate.d/beszel-security
sudo logrotate --debug /etc/logrotate.conf
```

Do not configure both a wildcard rule and a separate rule for the same file: logrotate rejects duplicate entries.

Run `sudo nginx -t` and reload Nginx after any changes. Generate a request to one of your hosted sites and check that `/var/log/nginx/beszel-security.log` contains JSON entries. Check permissions with `sudo -u beszel-audit head -n 1 /var/log/nginx/beszel-security.log`; the collector needs read access through `adm`.

### 4. Start collection and check it

```sh
sudo systemctl daemon-reload
sudo -u beszel-audit python3 /opt/beszel-security/collector.py --backfill
sudo systemctl enable --now beszel-security.timer
systemctl list-timers beszel-security.timer
sudo journalctl -u beszel-security.service -n 30 --no-pager
sudo -u beszel-audit python3 - <<'PY'
import sqlite3
with sqlite3.connect('file:/var/lib/beszel-security/events.db?mode=ro', uri=True) as db:
    print(db.execute('SELECT source, kind, COUNT(*) FROM events GROUP BY source, kind').fetchall())
PY
```

The backfill command runs in the foreground and prints the log being imported, progress every 10,000 records, and the final event count and timestamp coverage. Wait for it to finish before enabling the timer or attaching the database. The service has no startup timeout, so a large import can finish. Repeat `--backfill` to rescan retained logs after an upgrade; existing event IDs prevent repeat imports.

Historical imports read all available SSH and kernel journal boots, SSH text logs (`auth.log*`, `secure*`), firewall logs (`ufw.log*`, `kern.log*`), and Nginx access logs, including `.gz` rotations. Installing this fork months after creating a VPS can show those months if the logs still exist. Deleted, expired, or never recorded logs cannot be recovered. Traditional syslog timestamps omit the year; the importer infers it from the file modification date. Very old archives with changed modification dates may have inaccurate years. Existing combined Nginx logs do not provide verified visitor IPs behind a proxy.

An empty result is valid when no matching events remain in the logs. Check free disk space before importing large archives. The collector stores selected event fields rather than complete log lines.

### Retention

`SECURITY_RETENTION_DAYS=0` is the default and keeps all stored events. To limit storage, add a systemd override:

```ini
[Service]
Environment=SECURITY_RETENTION_DAYS=90
```

Run `sudo systemctl daemon-reload` after saving it with `sudo systemctl edit beszel-security.service`. A positive value filters imports and deletes stored events older than that many days on the next collection. For a manual backfill, pass the same value with `sudo -u beszel-audit env SECURITY_RETENTION_DAYS=90 python3 /opt/beszel-security/collector.py --backfill`. Back up the database before reducing retention.

If UFW is already managing this VPS's firewall, check `sudo ufw status verbose`. Enable logging with `sudo ufw logging low` if desired. The collector does not enable UFW, change firewall rules, or block IPs.

### 5. Attach the database to the correct Beszel VPS

Add your VPS using the normal Beszel agent setup. Open its detail page and copy the system record ID from `/system/<id>`. Use that ID, not its display name, hostname, IP address, or Nginx virtual host.

In your **existing hub** Compose configuration, switch to the custom image, add the database directory mount, and assign it to that ID:

```yaml
services:
  beszel:
    image: beszel-custom:0.20.0
    ports:
      - "127.0.0.1:8091:8090"
    volumes:
      - ./beszel_data:/beszel_data
      - /var/lib/beszel-security:/security_data:ro
      # Keep any existing agent socket and other mounts.
    environment:
      SECURITY_DB_PATH: /security_data/events.db
      SECURITY_SYSTEM_ID: replace_with_your_beszel_system_id
```

This is a hub configuration fragment, not a full agent installation. Preserve your current data path, ports, proxy configuration, and agent service. Apply the change from the directory containing your Compose file:

```sh
docker compose up -d --no-deps beszel
```

Log in as an admin and open **Security history**, select your VPS, or open `/security/<id>` directly. A VPS without a database mapping shows a configuration message. Mapping one VPS does not enable history for other VPSes.

The example uses rootful Docker because collector output is private to `beszel-audit` and the hub image runs as root. Rootless Docker or a custom hub UID needs an appropriate read-only ACL or group permission on the database directory and files; do not make them world-readable.

## Remote VPSes and multiple databases

Install the collector on **each** monitored VPS. The standard Beszel agent does not send security events to the hub. You must arrange delivery of consistent database snapshots to the hub, for example through an existing SSH/SFTP job.

1. On the monitored VPS, create a SQLite snapshot using the backup API. Do not copy an actively written database file directly.
2. Send the snapshot to a temporary file in that VPS's destination directory on the hub.
3. Rename the temporary file to `events.db` after the transfer finishes. Keep one destination directory per VPS.
4. Schedule this process at your preferred interval; the UI freshness depends on both collection and delivery.

Example snapshot command, run as root on the monitored VPS:

```sh
sudo python3 - <<'PY'
import os
import sqlite3
os.umask(0o077)
with sqlite3.connect('file:/var/lib/beszel-security/events.db?mode=ro', uri=True) as source:
    with sqlite3.connect('/var/lib/beszel-security/export.db') as target:
        source.backup(target)
PY
```

Transfer `export.db` through your chosen authorized transport. The command above only creates a snapshot; it does not set up SSH credentials, transfer files, or create a scheduled delivery job. On the hub, an example layout is:

```text
security-data/
  vps-a/events.db
  vps-b/events.db
```

Mount the parent directory, then configure the record-to-database mapping:

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

Replace both system IDs with the IDs from Beszel. Mount directories rather than individual database files so atomic snapshot replacements remain visible inside Docker. Each database belongs to one VPS. The Nginx `host` field is the HTTP virtual host and cannot identify the originating VPS.

## Troubleshooting

| Symptom | What to check |
| --- | --- |
| Collector service fails to start | Its journal, the `beszel-audit` account/groups, data directory ownership, and optional read paths in step 2 |
| No SSH events | Existing SSH journal entries, whether the system uses `ssh.service` or `sshd.service`, and collector journal permissions |
| No firewall events | Whether UFW is installed, logging is enabled, and `[UFW BLOCK]` entries exist in the kernel journal |
| No web events | JSON log format, Nginx log inheritance, a request reaching Nginx, and collector read permissions |
| VPS says collector is not configured | Exact Beszel system ID, environment variables on the hub, and whether the hub was recreated after the change |
| Security history unavailable | Mounted database path, file/directory read permissions, and whether a successful collector run created `events.db` |
| Remote history is stale | Snapshot creation, delivery schedule, and completion of the atomic rename |
| Security page/API returns 403 | The account must have Beszel's admin role |

## Development checks

```sh
go test -tags testing ./internal/hub -run Security
python3 -m unittest discover -s security -p 'test_*.py'
cd internal/site
npx tsc -b
npm run build
```

The inherited upstream frontend currently has TypeScript errors outside the security page. A full `tsc` pass may therefore fail even when the security changes compile. Production frontend builds use Vite.

## Event semantics and privacy

The hub opens security databases in SQLite read-only/query-only mode and validates the requested system record. Database paths come exclusively from server configuration. Existing collector databases need no schema migration. Requests to `/api/beszel/security/{summary,events}` require authentication, the admin role, and a `system` parameter.

Collection does not issue alerts or block traffic. Cloudflare visitor IP headers are accepted only when the immediate peer matches the refreshed official Cloudflare CIDR list; stale or unavailable lists fall back to the peer IP. Existing combined Nginx logs are marked `legacy_unknown`. Query strings, request headers, bodies, cookies, referrers, and user agents are not stored.

UFW logging may be rate-limited. `web_probe` and `ssh_probe` are heuristics, not proof of compromise. SSH event ports are client source ports; firewall event ports are blocked destination ports. Backfill only covers logs and journal entries still available on each VPS. Time series use Unix timestamps; the UI fills empty buckets with zero and displays local time.

## Date filters and event details

Use the single **Date range** field to open the themed calendar. Choose **All time**, **30 days**, **7 days**, or **Today**, or click a start and end date and select **Apply dates**. Both calendar dates are included in your local time zone. Today is the default. All time covers every event stored in the selected VPS database. The 7-day and 30-day presets include today. Cancel keeps the current selection. Use the month and year dropdowns to reach older dates.

The same dates apply to summary counts, all charts, SSH success and failure tables, and the recent events table. Changing the VPS or dates resets table pagination. Source and event-type filters apply to the recent events table. Charts use hourly, daily, weekly, or 30-day buckets depending on the length of the range.

API clients can send `from` and `to` as Unix timestamps in seconds. `from` is inclusive and `to` is exclusive. To include an entire end date, send the following local midnight as `to`. Both parameters are required when either is supplied. The API rejects reversed bounds, invalid timestamps, and end dates more than a day in the future. `range=all` includes all stored history. Legacy `range=24h`, `7d`, and `30d` parameters remain supported for existing API clients; the page offers presets and custom calendar dates.

SSH details show the recorded username and source port. Missing values say **Not recorded for this event**. Expand **Example SSH command (illustration)** to see a sample connection command with placeholders explained. The collector does not capture the original client command or commands run inside an SSH session. Source ports are sender-side ports. They are not the destination SSH port on the VPS.

The **IP address source** column explains whether an address came directly from a VPS service, a verified Cloudflare proxy, an unverified Nginx connection, or an older web log.

## IP countries

The country chart shows the ten countries with the most recorded events in the selected VPS and date range. Every event table includes a country name and flag for its displayed sender IP. Unknown and non-public addresses have explicit labels. Country counts include all event types, including normal web requests.

The collector downloads IPv4 and IPv6 country ranges from [IPtoASN](https://iptoasn.com/) and performs lookups locally. It sends no event IPs to a lookup API. The compressed databases are cached next to `events.db` and refreshed weekly. Compact binary caches provide local lookups without parsing the complete datasets on each collection. New IPs are enriched on the next collector run. Existing events are enriched automatically, so another historical log import is not required. Country mappings use the current database rather than the assignment at the time of the event.

No API key or extra Python package is required. The first run needs outbound HTTPS access to `iptoasn.com`. Failed refreshes keep valid cached data and do not interrupt log collection. Missing country databases leave public IP countries unknown and retry downloads at most hourly. Non-public IPs are labelled separately. Country mappings are included in SQLite snapshots for remote VPSes.

Country labels estimate an IP's country. They do not establish a person's location, nationality, or identity. A VPN, proxy, or hosting server can determine the displayed country. Verified Cloudflare visitor addresses take priority over peer addresses. Older unverified web logs can identify a proxy's country instead. Older collector databases continue to work without country enrichment, showing Unknown until the collector is upgraded.

To upgrade an existing installation, copy both `collector.py` and `countries.py` using step 2, then run `sudo systemctl start beszel-security.service`. Check its journal for country download or lookup progress.
