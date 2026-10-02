"""Local IPv4/IPv6 country lookup using IPtoASN country range downloads."""
from bisect import bisect_right
import gzip
import ipaddress
import mmap
import os
import re
import time
import urllib.request

BASE_URL = 'https://iptoasn.com/data/'
REFRESH_SECONDS = 7 * 86400


def read_ranges(path, version):
    rows = []
    with gzip.open(path, 'rt', encoding='ascii') as file:
        for line in file:
            first, last, code = line.rstrip('\r\n').split('\t')
            start, end = ipaddress.ip_address(first), ipaddress.ip_address(last)
            if start.version != version or end.version != version or int(start) > int(end):
                raise ValueError('Invalid country address range')
            code = code.upper()
            rows.append((int(start), int(end), code if re.fullmatch('[A-Z]{2}', code) and code != 'ZZ' else ''))
    rows.sort()
    if not rows:
        raise ValueError('Empty country database')
    if any(rows[i][0] <= rows[i-1][1] for i in range(1, len(rows))):
        raise ValueError('Overlapping country address ranges')
    return [row[0] for row in rows], rows


def load_ranges(directory, version):
    path = directory / f'ip2country-v{version}.tsv.gz'
    refreshed = False
    if not path.exists() or time.time() - path.stat().st_mtime > REFRESH_SECONDS:
        temporary = path.with_suffix('.download')
        try:
            request = urllib.request.Request(BASE_URL + path.name, headers={'User-Agent': 'Beszel-Security-Country/1.0'})
            with urllib.request.urlopen(request, timeout=20) as response, temporary.open('wb') as file:
                size = 0
                while chunk := response.read(65536):
                    size += len(chunk)
                    if size > 20 * 1024 * 1024:
                        raise ValueError('Country download exceeds size limit')
                    file.write(chunk)
            read_ranges(temporary, version)
            os.replace(temporary, path)
            refreshed = True
        except (OSError, ValueError, EOFError) as error:
            print(f'IPv{version} country download unavailable: {error}', flush=True)
        finally:
            temporary.unlink(missing_ok=True)
    try:
        return read_ranges(path, version), refreshed
    except (OSError, ValueError, EOFError):
        return None, False


class MappedRanges:
    """Compact on-disk ranges; binary search avoids parsing TSV on every run."""
    header = b'BSCGEO1\n'
    width = 34

    def __init__(self, path):
        with path.open('rb') as file:
            self.data = mmap.mmap(file.fileno(), 0, access=mmap.ACCESS_READ)
        if self.data[:8] != self.header or (len(self.data) - 8) % self.width:
            self.data.close()
            raise ValueError('Invalid country cache')
        self.count = (len(self.data) - 8) // self.width

    def find(self, address):
        key = address.to_bytes(16, 'big')
        low, high = 0, self.count
        while low < high:
            middle = (low + high) // 2
            offset = 8 + middle * self.width
            if self.data[offset:offset+16] <= key:
                low = middle + 1
            else:
                high = middle
        if low == 0:
            return ''
        offset = 8 + (low - 1) * self.width
        if key > self.data[offset+16:offset+32]:
            return ''
        return self.data[offset+32:offset+34].rstrip(b'\0').decode('ascii')

    def close(self):
        self.data.close()


def cached_ranges(directory, version, download_allowed):
    source = directory / f'ip2country-v{version}.tsv.gz'
    cache = directory / f'ip2country-v{version}.bin'
    source_fresh = source.exists() and time.time() - source.stat().st_mtime < REFRESH_SECONDS
    if cache.exists() and source.exists() and cache.stat().st_mtime >= source.stat().st_mtime and (source_fresh or not download_allowed):
        try:
            return MappedRanges(cache), False
        except (OSError, ValueError):
            pass
    if download_allowed:
        data, refreshed = load_ranges(directory, version)
    else:
        refreshed = False
        try:
            data = read_ranges(source, version)
        except (OSError, ValueError, EOFError):
            data = None
    if not data:
        return None, False
    temporary = cache.with_suffix('.tmp')
    try:
        with temporary.open('wb') as file:
            file.write(MappedRanges.header)
            for start, end, code in data[1]:
                file.write(start.to_bytes(16, 'big') + end.to_bytes(16, 'big') + code.encode('ascii').ljust(2, b'\0'))
        os.replace(temporary, cache)
        return MappedRanges(cache), refreshed
    except OSError as error:
        print(f'IPv{version} compiled country cache unavailable: {error}', flush=True)
        return data, refreshed
    finally:
        temporary.unlink(missing_ok=True)


def lookup(ip, databases):
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return ''
    if not address.is_global or address.is_multicast:
        return 'LOCAL'
    if address.version == 6 and address.ipv4_mapped:
        address = address.ipv4_mapped
    database = databases.get(address.version)
    if not database:
        return ''
    if isinstance(database, MappedRanges):
        return database.find(int(address))
    starts, rows = database
    position = bisect_right(starts, int(address)) - 1
    if position >= 0 and int(address) <= rows[position][1]:
        return rows[position][2]
    return ''


def enrich(db, directory):
    now = int(time.time())
    attempted = db.execute("SELECT value FROM cursors WHERE source='country:attempt'").fetchone()
    # Collect new IPs every minute. Retry unavailable downloads at most hourly.
    download_allowed = not attempted or now - int(attempted[0]) >= 3600
    databases, refreshed = {}, False
    for version in (4, 6):
        databases[version], changed = cached_ranges(directory, version, download_allowed)
        refreshed |= changed
    if download_allowed:
        db.execute("INSERT INTO cursors VALUES ('country:attempt',?) ON CONFLICT(source) DO UPDATE SET value=excluded.value", (str(now),))
    query = "SELECT DISTINCT COALESCE(NULLIF(client_ip,''),NULLIF(peer_ip,'')) AS ip FROM events WHERE ip IS NOT NULL"
    if not refreshed:
        query += " AND NOT EXISTS (SELECT 1 FROM ip_countries WHERE ip_countries.ip=COALESCE(NULLIF(events.client_ip,''),NULLIF(events.peer_ip,'')))"
    ips = [row[0] for row in db.execute(query)]
    print(f'Looking up countries for {len(ips):,} IP addresses...', flush=True)
    for number, ip in enumerate(ips, 1):
        code = lookup(ip, databases)
        # Keep previous countries when a database download temporarily fails.
        try:
            version = ipaddress.ip_address(ip).version
        except ValueError:
            version = None
        if not code and version and not databases.get(version):
            continue
        db.execute('INSERT INTO ip_countries(ip,country_code) VALUES (?,?) ON CONFLICT(ip) DO UPDATE SET country_code=excluded.country_code', (ip, code))
        if number % 1000 == 0:
            db.commit()
    db.commit()
    for database in databases.values():
        if isinstance(database, MappedRanges):
            database.close()
