#!/usr/bin/env python3
"""Read-only VPS audit collector. Stores a deliberately small, sanitized event set."""
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
from pathlib import Path

DB = Path(os.environ.get("SECURITY_DB", "/var/lib/beszel-security/events.db"))
AUDIT_LOG = Path("/var/log/nginx/beszel-security.log")
ACCESS_LOG = Path("/var/log/nginx/access.log")
NOW = dt.datetime.now(dt.timezone.utc)
CUTOFF = NOW - dt.timedelta(days=30)
SSH_SUCCESS = re.compile(r"Accepted (?:publickey|password|keyboard-interactive(?:/pam)?) for (\S+) from ([0-9a-fA-F:.]+) port (\d+)")
SSH_FAIL = re.compile(r"Failed (?:password|publickey|keyboard-interactive(?:/pam)?) for (?:invalid user )?(\S+) from ([0-9a-fA-F:.]+) port (\d+)")
SSH_INVALID = re.compile(r"Invalid user (\S+) from ([0-9a-fA-F:.]+)")
SSH_PROBE = re.compile(r"(?:Connection closed by|Disconnected from|Unable to negotiate with) (?:invalid user \S+ )?([0-9a-fA-F:.]+) port (\d+)")
UFW = re.compile(r"\[UFW BLOCK\].*?SRC=([0-9a-fA-F:.]+)")
UFW_PORT = re.compile(r"\bDPT=(\d+)")
COMBINED = re.compile(r'^(\S+) \S+ \S+ \[([^]]+)\] "([A-Z]+) ([^ ]+) [^\"]+" (\d{3}) ')
PROBE = re.compile(r"(?:^|/)(?:\.env|\.git|wp-admin|wp-login|phpmyadmin|actuator|cgi-bin)(?:/|$)|(?:\.php$)", re.I)


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
    db.execute("CREATE TABLE IF NOT EXISTS cursors (source TEXT PRIMARY KEY, value TEXT NOT NULL)")


def cursor(db, key):
    row = db.execute("SELECT value FROM cursors WHERE source=?", (key,)).fetchone()
    return row[0] if row else None


def set_cursor(db, key, value):
    db.execute("INSERT INTO cursors VALUES (?, ?) ON CONFLICT(source) DO UPDATE SET value=excluded.value", (key, str(value)))


def add(db, source_id, when, source, kind, peer=None, client=None, provenance="direct", host=None, username=None, method=None, path=None, port=None, status=None):
    if when < int(CUTOFF.timestamp()) or when > int((NOW + dt.timedelta(minutes=5)).timestamp()):
        return
    db.execute("INSERT OR IGNORE INTO events(source_id,occurred_at,source,kind,peer_ip,client_ip,provenance,host,username,method,path,port,status) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)", (source_id, when, source, kind, peer, client, provenance, clean_text(host, 150) or None, clean_text(username, 100) or None, clean_text(method, 16) or None, clean_text(path, 400) or None, port, status))


def journal(db, name, args):
    key = "journal:" + name
    command = ["journalctl", "--no-pager", "-o", "json", *args]
    previous = cursor(db, key)
    command += ["--after-cursor", previous] if previous else ["--since", "30 days ago"]
    proc = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, errors="replace")
    last = None
    for line in proc.stdout:
        try:
            item = json.loads(line)
            last = item.get("__CURSOR", last)
            message = item.get("MESSAGE", "")
            when = int(item["__REALTIME_TIMESTAMP"]) // 1000000
            if name == "ssh":
                match = SSH_SUCCESS.search(message)
                if match:
                    user, ip, port = match.groups()
                    add(db, last, when, "ssh", "ssh_success", clean_ip(ip), clean_ip(ip), username=user, port=int(port))
                    continue
                match = SSH_FAIL.search(message)
                if match:
                    user, ip, port = match.groups()
                    add(db, last, when, "ssh", "ssh_failure", clean_ip(ip), clean_ip(ip), username=user, port=int(port))
                    continue
                match = SSH_INVALID.search(message)
                if match:
                    user, ip = match.groups()
                    add(db, last, when, "ssh", "ssh_probe", clean_ip(ip), clean_ip(ip), username=user)
                    continue
                match = SSH_PROBE.search(message)
                if match:
                    ip, port = match.groups()
                    add(db, last, when, "ssh", "ssh_probe", clean_ip(ip), clean_ip(ip), port=int(port))
            else:
                match = UFW.search(message)
                if match:
                    ip = match.group(1)
                    port = UFW_PORT.search(message)
                    add(db, last, when, "firewall", "firewall_block", clean_ip(ip), clean_ip(ip), port=int(port.group(1)) if port else None)
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
        path = record.get("path", "").split("?", 1)[0]
        kind = "web_probe" if PROBE.search(path) else "web_request"
        source_id = "nginx:" + clean_text(record.get("request_id"), 100)
        if source_id == "nginx:":
            source_id = fallback_id
        add(db, source_id, when, "web", kind, peer, client, "cloudflare_validated" if trusted else "direct_peer", record.get("host"), method=record.get("method"), path=path, status=int(record.get("status", 0)))
    except (ValueError, TypeError, KeyError, json.JSONDecodeError):
        pass


def web(db, ranges):
    # Process compressed rotations once, even if collection was interrupted for days.
    for file in sorted(AUDIT_LOG.parent.glob(AUDIT_LOG.name + ".*.gz")):
        stat = file.stat()
        key = f"web:gzip:{stat.st_dev}:{stat.st_ino}:{stat.st_size}"
        if cursor(db, key):
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
        offset = int(cursor(db, key) or 0)
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
    if cursor(db, "historical:done"):
        return
    files = sorted(ACCESS_LOG.parent.glob("access.log*"))
    for file in files:
        opener = gzip.open if file.suffix == ".gz" else open
        try:
            with opener(file, "rt", encoding="utf-8", errors="replace") as handle:
                for number, line in enumerate(handle):
                    match = COMBINED.match(line)
                    if not match:
                        continue
                    ip, timestamp, method, path, status = match.groups()
                    try:
                        when = int(dt.datetime.strptime(timestamp, "%d/%b/%Y:%H:%M:%S %z").timestamp())
                    except ValueError:
                        continue
                    path = path.split("?", 1)[0]
                    event_id = hashlib.sha256(f"{file.name}:{number}:{line}".encode()).hexdigest()
                    add(db, "historic:" + event_id, when, "web", "web_probe" if PROBE.search(path) else "web_request", clean_ip(ip), None, "legacy_unknown", method=method, path=path, status=int(status))
        except OSError:
            continue
    set_cursor(db, "historical:done", "1")
    db.commit()


def main():
    DB.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    old_umask = os.umask(0o077)
    try:
        with sqlite3.connect(DB, timeout=30) as db:
            init(db)
            journal(db, "ssh", ["-u", "ssh.service"])
            journal(db, "ufw", ["-k"])
            web(db, cf_ranges(db))
            historic_web(db)
            db.execute("DELETE FROM events WHERE occurred_at < ?", (int(CUTOFF.timestamp()),))
            db.commit()
    finally:
        os.umask(old_umask)


if __name__ == "__main__":
    main()
