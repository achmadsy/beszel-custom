#!/usr/bin/env python3
"""Read-only VPS audit collector. Stores a deliberately small, sanitized event set."""
import argparse
import fcntl
import datetime as dt
import gzip
import hashlib
import ipaddress
import json
import os
import re
import sqlite3
import subprocess
import urllib.request
import urllib.parse
import time
from pathlib import Path
from countries import enrich as enrich_countries

DB = Path(os.environ.get("SECURITY_DB", "/var/lib/beszel-security/events.db"))
AUDIT_LOG = Path("/var/log/nginx/beszel-security.log")
ACCESS_LOG = Path("/var/log/nginx/access.log")
NOW = dt.datetime.now(dt.timezone.utc)
RETENTION_DAYS = int(os.environ.get("SECURITY_RETENTION_DAYS", "0"))
if RETENTION_DAYS < 0:
    raise ValueError("SECURITY_RETENTION_DAYS must be zero or positive")
CUTOFF = NOW - dt.timedelta(days=RETENTION_DAYS) if RETENTION_DAYS else None
BACKFILL = False
SSH_SUCCESS = re.compile(r"Accepted (publickey|password|keyboard-interactive(?:/pam)?) for (\S+) from ([0-9a-fA-F:.]+) port (\d+)")
SSH_FAIL = re.compile(r"Failed (password|publickey|keyboard-interactive(?:/pam)?) for (?:invalid user )?(\S+) from ([0-9a-fA-F:.]+) port (\d+)")
SSH_INVALID = re.compile(r"Invalid user (\S+) from ([0-9a-fA-F:.]+)")
SSH_PROBE = re.compile(r"(?:Connection closed by|Disconnected from|Unable to negotiate with) (?:invalid user \S+ )?([0-9a-fA-F:.]+) port (\d+)")
UFW = re.compile(r"\[UFW BLOCK\].*?SRC=([0-9a-fA-F:.]+)")
UFW_PORT = re.compile(r"\bDPT=(\d+)")
COMBINED = re.compile(r'^(\S+) \S+ \S+ \[([^]]+)\] "([A-Z]+) ([^ ]+) [^\"]+" (\d{3}) ')
PROBE = re.compile(r"(?:^|/)(?:\.env|\.git|wp-admin|wp-login|phpmyadmin|actuator|cgi-bin)(?:/|$)|(?:\.php$)", re.I)


WEB_CATEGORIES = [
    ("traversal_injection", re.compile(r"(?i)(\.\./|/etc/passwd|\$\{jndi|(?:cmd|exec)=|exec\(|union.+select|<script)")),
    ("sensitive_files", re.compile(r"(?i)(/\.(?:env|git|aws|ssh|svn)|credentials|id_rsa|config\.(?:json|ya?ml|php|js)|\.(?:sql|bak|old|backup|zip|tar|tgz|7z)(?:$|[?/])|/backup)")),
    ("wordpress", re.compile(r"(?i)(wp-login|wp-admin|xmlrpc\.php|wp-content|wp-includes|wp-config|wlwmanifest)")),
    ("php_tooling", re.compile(r"(?i)(phpmyadmin|/pma(?:/|$)|phpunit|eval-stdin|\.php(?:$|[?/]))")),
    ("admin_panels", re.compile(r"(?i)(^/admin|/manager/|/boaform|/hnap1|/cgi-bin|/gponform|/actuator|/console|/solr|/owa/|/ecp/|/remote/login|/geoserver|/jenkins|/druid|/telescope|/vendor/)")),
]


def web_category(raw):
    decoded = urllib.parse.unquote(urllib.parse.unquote(str(raw or "")))
    for category, pattern in WEB_CATEGORIES:
        if pattern.search(decoded):
            return category
    return "other_probes" if PROBE.search(decoded.split("?", 1)[0]) else ""


def safe_path(raw):
    path = str(raw or "").split("?", 1)[0].split("#", 1)[0]
    path = re.sub(r"[\x00-\x1f\x7f]", "", path)
    return re.sub(r"[A-Za-z0-9_-]{20,}", "[id]", path)[:400]


def clean_ip(value):
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        return None


def clean_text(value, limit=200):
    return str(value or "").replace("\x00", "")[:limit]


def init(db):
    # DELETE mode keeps a read-only bind-mounted database usable without a writable -shm file.
    db.execute("PRAGMA journal_mode=DELETE")
    db.execute("CREATE TABLE IF NOT EXISTS events (id INTEGER PRIMARY KEY, source_id TEXT UNIQUE NOT NULL, occurred_at INTEGER NOT NULL, source TEXT NOT NULL, kind TEXT NOT NULL, peer_ip TEXT, client_ip TEXT, provenance TEXT NOT NULL, host TEXT, username TEXT, method TEXT, path TEXT, port INTEGER, status INTEGER)")
    db.execute("CREATE INDEX IF NOT EXISTS events_time ON events(occurred_at DESC, id DESC)")
    db.execute("CREATE INDEX IF NOT EXISTS events_kind_time ON events(kind, occurred_at DESC)")
    db.execute("CREATE TABLE IF NOT EXISTS ip_countries (ip TEXT PRIMARY KEY, country_code TEXT NOT NULL)")
    db.execute("CREATE TABLE IF NOT EXISTS cursors (source TEXT PRIMARY KEY, value TEXT NOT NULL)")
    columns = {row[1] for row in db.execute("PRAGMA table_info(events)")}
    if "web_category" not in columns:
        db.execute("ALTER TABLE events ADD COLUMN web_category TEXT")
    db.execute("CREATE INDEX IF NOT EXISTS events_ssh_ip_time ON events(COALESCE(NULLIF(client_ip,''),peer_ip), kind, occurred_at) WHERE source='ssh'")
    db.execute("CREATE INDEX IF NOT EXISTS events_web_category_time ON events(web_category, occurred_at DESC) WHERE web_category IS NOT NULL")
    db.execute("CREATE TABLE IF NOT EXISTS collector_state (id INTEGER PRIMARY KEY CHECK(id=1), started_at INTEGER, finished_at INTEGER, last_success_at INTEGER, status TEXT NOT NULL, error TEXT NOT NULL DEFAULT '')")
    if not cursor(db, "analysis:v1"):
        after = 0
        while True:
            rows = db.execute("SELECT id,path,kind FROM events WHERE source='web' AND id>? ORDER BY id LIMIT 1000", (after,)).fetchall()
            if not rows:
                break
            for event_id, path, kind in rows:
                category = web_category(path) or ("other_probes" if kind == "web_probe" else "")
                db.execute("UPDATE events SET path=?,web_category=?,kind=? WHERE id=?", (safe_path(path), category or None, "web_probe" if category else kind, event_id))
            after = rows[-1][0]
            db.commit()
        set_cursor(db, "analysis:v1", "1")



def cursor(db, key):
    row = db.execute("SELECT value FROM cursors WHERE source=?", (key,)).fetchone()
    return row[0] if row else None


def set_cursor(db, key, value):
    db.execute("INSERT INTO cursors VALUES (?, ?) ON CONFLICT(source) DO UPDATE SET value=excluded.value", (key, str(value)))


def add(db, source_id, when, source, kind, peer=None, client=None, provenance="direct", host=None, username=None, method=None, path=None, port=None, status=None, category=None):
    if (CUTOFF and when < int(CUTOFF.timestamp())) or when > int((NOW + dt.timedelta(minutes=5)).timestamp()):
        return
    db.execute("INSERT INTO events(source_id,occurred_at,source,kind,peer_ip,client_ip,provenance,host,username,method,path,port,status,web_category) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(source_id) DO UPDATE SET method=COALESCE(excluded.method,events.method),web_category=COALESCE(excluded.web_category,events.web_category),kind=CASE WHEN excluded.source='web' AND excluded.web_category IS NOT NULL THEN 'web_probe' ELSE events.kind END", (source_id, when, source, kind, peer, client, provenance, clean_text(host, 150) or None, clean_text(username, 100) or None, clean_text(method, 32) or None, (safe_path(path) if source == "web" else clean_text(path, 400)) or None, port, status, category))


def add_message(db, name, source_id, when, message):
    if name == "ssh":
        match = SSH_SUCCESS.search(message)
        if match:
            method, user, ip, port = match.groups()
            add(db, source_id, when, "ssh", "ssh_success", clean_ip(ip), clean_ip(ip), username=user, method=method, port=int(port))
            return
        match = SSH_FAIL.search(message)
        if match:
            method, user, ip, port = match.groups()
            add(db, source_id, when, "ssh", "ssh_failure", clean_ip(ip), clean_ip(ip), username=user, method=method, port=int(port))
            return
        match = SSH_INVALID.search(message)
        if match:
            user, ip = match.groups()
            add(db, source_id, when, "ssh", "ssh_probe", clean_ip(ip), clean_ip(ip), username=user)
            return
        match = SSH_PROBE.search(message)
        if match:
            ip, port = match.groups()
            add(db, source_id, when, "ssh", "ssh_probe", clean_ip(ip), clean_ip(ip), port=int(port))
    else:
        match = UFW.search(message)
        if match:
            ip = match.group(1)
            port = UFW_PORT.search(message)
            add(db, source_id, when, "firewall", "firewall_block", clean_ip(ip), clean_ip(ip), port=int(port.group(1)) if port else None)


def journal(db, name, args):
    key = "journal:" + name
    command = ["journalctl", "--no-pager", "-o", "json", *args]
    previous = None if BACKFILL else cursor(db, key)
    if previous:
        command += ["--after-cursor", previous]
    elif CUTOFF:
        command += ["--since", CUTOFF.isoformat()]
    print(f"Reading {name} journal...", flush=True)
    proc = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, errors="replace")
    last = None
    for number, line in enumerate(proc.stdout, 1):
        if number % 10000 == 0:
            db.commit()
            print(f"{name}: scanned {number:,} journal records", flush=True)
        try:
            item = json.loads(line)
            last = item.get("__CURSOR", last)
            message = item.get("MESSAGE", "")
            when = int(item["__REALTIME_TIMESTAMP"]) // 1000000
            add_message(db, name, last, when, message)
        except (ValueError, TypeError, KeyError, json.JSONDecodeError):
            continue
    stderr = proc.communicate()[1]
    if proc.returncode:
        raise RuntimeError(f"journalctl {name}: {stderr[:300]}")
    if last:
        set_cursor(db, key, last)
    db.commit()


def cf_ranges(db):
    key = "cloudflare:updated"
    old = cursor(db, key)
    if not old or NOW.timestamp() - float(old) > 7 * 86400:
        try:
            ranges = []
            for family in ("v4", "v6"):
                with urllib.request.urlopen("https://www.cloudflare.com/ips-" + family, timeout=8) as response:
                    ranges += [str(ipaddress.ip_network(line.strip())) for line in response.read().decode().splitlines() if line.strip()]
            if not ranges:
                raise ValueError("empty Cloudflare list")
            set_cursor(db, "cloudflare:ranges", json.dumps(ranges))
            set_cursor(db, key, NOW.timestamp())
            db.commit()
        except (OSError, ValueError):
            pass  # fail closed: untrusted header without a known valid range
    if not cursor(db, key) or NOW.timestamp() - float(cursor(db, key)) > 14 * 86400:
        return []
    return [ipaddress.ip_network(x) for x in json.loads(cursor(db, "cloudflare:ranges") or "[]")]


def add_web_record(db, line, ranges, fallback_id):
    try:
        record = json.loads(line)
        when = int(float(record["time"]))
        peer = clean_ip(record.get("peer", ""))
        asserted = clean_ip(record.get("cf_ip", ""))
        trusted = bool(peer and asserted and any(ipaddress.ip_address(peer) in network for network in ranges))
        client = asserted if trusted else peer
        category = web_category(record.get("path", ""))
        path = safe_path(record.get("path", ""))
        kind = "web_probe" if category else "web_request"
        source_id = "nginx:" + clean_text(record.get("request_id"), 100)
        if source_id == "nginx:":
            source_id = fallback_id
        add(db, source_id, when, "web", kind, peer, client, "cloudflare_validated" if trusted else "direct_peer", record.get("host"), method=record.get("method"), path=path, status=int(record.get("status", 0)), category=category or None)
    except (ValueError, TypeError, KeyError, json.JSONDecodeError):
        pass


def web(db, ranges):
    # Process compressed rotations once, even if collection was interrupted for days.
    for file in sorted(AUDIT_LOG.parent.glob(AUDIT_LOG.name + ".*.gz")):
        stat = file.stat()
        key = f"web:gzip:{stat.st_dev}:{stat.st_ino}:{stat.st_size}"
        if cursor(db, key) and not BACKFILL:
            continue
        try:
            with gzip.open(file, "rt", encoding="utf-8", errors="replace") as handle:
                for number, line in enumerate(handle):
                    add_web_record(db, line, ranges, f"web:gzip:{stat.st_ino}:{number}")
        except OSError:
            continue
        set_cursor(db, key, "done")
        db.commit()
    files = [AUDIT_LOG.with_name(AUDIT_LOG.name + ".1"), AUDIT_LOG]
    for file in files:
        if not file.exists():
            continue
        stat = file.stat()
        key = f"web:inode:{stat.st_dev}:{stat.st_ino}"
        offset = 0 if BACKFILL else int(cursor(db, key) or 0)
        if offset > stat.st_size:
            offset = 0
        with file.open("r", encoding="utf-8", errors="replace") as handle:
            handle.seek(offset)
            while line := handle.readline():
                if not line.endswith("\n"):
                    break
                position = handle.tell()
                add_web_record(db, line, ranges, f"web:{stat.st_ino}:{position}")
                set_cursor(db, key, position)
        db.commit()


def historic_web(db):
    if cursor(db, "historical:v2") and not BACKFILL:
        return
    files = sorted(ACCESS_LOG.parent.glob("access.log*"))
    for file in files:
        print(f"Importing {file.name}...", flush=True)
        opener = gzip.open if file.suffix == ".gz" else open
        try:
            with opener(file, "rt", encoding="utf-8", errors="replace") as handle:
                for number, line in enumerate(handle):
                    if number and number % 10000 == 0:
                        db.commit()
                        print(f"{file.name}: scanned {number:,} records", flush=True)
                    match = COMBINED.match(line)
                    if not match:
                        continue
                    ip, timestamp, method, path, status = match.groups()
                    try:
                        when = int(dt.datetime.strptime(timestamp, "%d/%b/%Y:%H:%M:%S %z").timestamp())
                    except ValueError:
                        continue
                    category = web_category(path)
                    path = safe_path(path)
                    existing = db.execute("SELECT id FROM events WHERE occurred_at=? AND source='web' AND peer_ip IS ? AND method=? AND path=? AND status=? LIMIT 1", (when, clean_ip(ip), method, path, int(status))).fetchone()
                    if existing:
                        if category:
                            db.execute("UPDATE events SET web_category=?,kind='web_probe' WHERE id=?", (category, existing[0]))
                        continue
                    event_id = hashlib.sha256(f"{file.name}:{number}:{line}".encode()).hexdigest()
                    add(db, "historic:" + event_id, when, "web", "web_probe" if category else "web_request", clean_ip(ip), None, "legacy_unknown", method=method, path=path, status=int(status), category=category or None)
        except OSError:
            continue
    set_cursor(db, "historical:v2", "1")
    db.commit()


def historic_system(db):
    """Import retained SSH and firewall text logs, including gzip archives."""
    for pattern in ("auth.log*", "secure*", "ufw.log*", "kern.log*"):
        for file in sorted(Path("/var/log").glob(pattern)):
            if not file.is_file():
                continue
            stat = file.stat()
            key = f"system-file:{stat.st_dev}:{stat.st_ino}:{stat.st_size}:{stat.st_mtime_ns}"
            if cursor(db, key) and not BACKFILL:
                continue
            print(f"Importing {file.name}...", flush=True)
            compressed = file.suffix == ".gz"
            opener = gzip.open if compressed else open
            offset_key = f"system-offset:{stat.st_dev}:{stat.st_ino}"
            offset = 0 if BACKFILL or compressed else int(cursor(db, offset_key) or 0)
            if offset > stat.st_size:
                offset = 0
            try:
                with opener(file, "rt", encoding="utf-8", errors="replace") as handle:
                    handle.seek(offset)
                    number = 0
                    while line := handle.readline():
                        if not line.endswith("\n"):
                            break
                        number += 1
                        if not compressed:
                            set_cursor(db, offset_key, handle.tell())
                        if number % 10000 == 0:
                            db.commit()
                            print(f"{file.name}: scanned {number:,} records", flush=True)
                        if "sshd" not in line and "[UFW BLOCK]" not in line:
                            continue
                        try:
                            when = syslog_time(line, stat.st_mtime)
                        except ValueError:
                            continue
                        name = "ssh" if "sshd" in line else "ufw"
                        source_id = "syslog:" + hashlib.sha256(line.encode()).hexdigest()
                        before = db.total_changes
                        add_message(db, name, source_id, when, line)
                        if db.total_changes != before:
                            # A retained text log can enrich an older journal event even
                            # when its own duplicate row is removed below.
                            imported = db.execute("SELECT id,method,occurred_at,source,kind,peer_ip,username,port FROM events WHERE source_id=? AND source='ssh'", (source_id,)).fetchone()
                            if imported and imported[1]:
                                db.execute("UPDATE events SET method=? WHERE id!=? AND occurred_at=? AND source=? AND kind=? AND peer_ip IS ? AND username IS ? AND port IS ? AND COALESCE(method,'')=''", (imported[1], imported[0], *imported[2:]))
                            db.execute("DELETE FROM events WHERE source_id=? AND EXISTS (SELECT 1 FROM events AS other WHERE other.id != events.id AND other.occurred_at=events.occurred_at AND other.source=events.source AND other.kind=events.kind AND other.peer_ip IS events.peer_ip AND other.username IS events.username AND other.port IS events.port)", (source_id,))
            except OSError as error:
                print(f"Could not read {file.name}: {error.strerror}", flush=True)
                continue
            set_cursor(db, key, "done")
            db.commit()


def syslog_time(line, modified):
    first = line.split(" ", 1)[0]
    if re.match(r"^\d{4}-\d{2}-\d{2}T", first):
        return int(dt.datetime.fromisoformat(first.replace("Z", "+00:00")).timestamp())
    reference = dt.datetime.fromtimestamp(modified).astimezone()
    date = dt.datetime.strptime(f"{reference.year} {line[:15]}", "%Y %b %d %H:%M:%S").astimezone()
    if date > reference + dt.timedelta(days=1):
        date = date.replace(year=date.year - 1)
    return int(date.timestamp())


def main():
    global BACKFILL
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--backfill", action="store_true", help="Rescan available logs with progress")
    BACKFILL = parser.parse_args().backfill
    DB.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    old_umask = os.umask(0o077)
    try:
        with (DB.parent / "collector.lock").open("w") as lock:
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                print("Collection is already running. Try again after it finishes.", flush=True)
                return
            collect()
    finally:
        os.umask(old_umask)


def collect():
    with sqlite3.connect(DB, timeout=30) as db:
        init(db)
        started = int(time.time())
        db.execute("INSERT INTO collector_state(id,started_at,status,error) VALUES (1,?,'running','') ON CONFLICT(id) DO UPDATE SET started_at=excluded.started_at,finished_at=NULL,status='running',error=''", (started,))
        db.commit()
        try:
            journal(db, "ssh", ["_COMM=sshd"])
            journal(db, "ufw", ["_TRANSPORT=kernel"])
            web(db, cf_ranges(db))
            historic_system(db)
            historic_web(db)
            enrich_countries(db, DB.parent)
            if CUTOFF:
                db.execute("DELETE FROM events WHERE occurred_at < ?", (int(CUTOFF.timestamp()),))
            finished = int(time.time())
            db.execute("UPDATE collector_state SET finished_at=?,last_success_at=?,status='success',error='' WHERE id=1", (finished, finished))
            db.commit()
            count, oldest, newest = db.execute("SELECT COUNT(*), MIN(occurred_at), MAX(occurred_at) FROM events").fetchone()
            print(f"Collection complete: {count:,} events. Timestamp coverage: {oldest} to {newest}.", flush=True)
        except Exception as error:
            db.rollback()
            # Log details stay in the host journal; the dashboard gets a safe error type.
            db.execute("UPDATE collector_state SET finished_at=?,status='failed',error=? WHERE id=1", (int(time.time()), type(error).__name__))
            db.commit()
            raise


if __name__ == "__main__":
    main()
