import gzip
import ipaddress
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
import countries
import collector

class CountryTests(unittest.TestCase):
    def fixture(self, directory, version, text):
        path = directory / f'ip2country-v{version}.tsv.gz'
        with gzip.open(path, 'wt') as file:
            file.write(text)
        return path

    def test_ipv4_ipv6_boundaries_and_non_public(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            v4 = self.fixture(root,4,'8.8.8.0\t8.8.8.255\tUS\n9.0.0.0\t9.0.0.10\tDE\n11.0.0.0\t11.0.0.10\t\n')
            v6 = self.fixture(root,6,'2001:4860::\t2001:4860:ffff:ffff:ffff:ffff:ffff:ffff\tUS\n')
            data = {4:countries.read_ranges(v4,4),6:countries.read_ranges(v6,6)}
            for ip in ('8.8.8.0','8.8.8.255','2001:4860::8888','::ffff:8.8.8.8'):
                self.assertEqual(countries.lookup(ip,data),'US')
            self.assertEqual(countries.lookup('8.8.9.0',data),'')
            self.assertEqual(countries.lookup('9.0.0.10',data),'DE')
            self.assertEqual(countries.lookup('10.0.0.1',data),'LOCAL')
            self.assertEqual(countries.lookup('not-an-ip',data),'')

    def test_existing_history_and_client_ip_priority(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            self.fixture(root,4,'8.8.8.0\t8.8.8.255\tUS\n9.0.0.0\t9.0.0.255\tDE\n')
            self.fixture(root,6,'2001:4860::\t2001:4860:ffff:ffff:ffff:ffff:ffff:ffff\tUS\n')
            db=sqlite3.connect(':memory:')
            collector.init(db)
            db.execute("INSERT INTO events(source_id,occurred_at,source,kind,peer_ip,client_ip,provenance) VALUES ('old',1,'web','web_request','9.0.0.1','8.8.8.8','cloudflare_validated')")
            with patch.object(countries.urllib.request,'urlopen',side_effect=AssertionError('No IP should be sent to a remote lookup')):
                countries.enrich(db,root)
                countries.enrich(db,root)
            self.assertEqual(db.execute('SELECT ip,country_code FROM ip_countries').fetchall(),[('8.8.8.8','US')])
            db.close()

    def test_failed_refresh_preserves_valid_cache(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            path=self.fixture(root,4,'8.8.8.0\t8.8.8.255\tUS\n')
            with patch.object(countries.time,'time',return_value=path.stat().st_mtime+8*86400),patch.object(countries.urllib.request,'urlopen',side_effect=OSError('offline')):
                data,refreshed=countries.load_ranges(root,4)
            self.assertFalse(refreshed)
            self.assertEqual(countries.lookup('8.8.8.8',{4:data}),'US')

    def test_compiled_cache_avoids_reparsing(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            self.fixture(root,4,'8.8.8.0\t8.8.8.255\tUS\n9.0.0.0\t9.0.0.10\tDE\n')
            data,_=countries.cached_ranges(root,4,True)
            self.assertEqual(countries.lookup('8.8.8.255',{4:data}),'US')
            self.assertEqual(countries.lookup('8.8.9.0',{4:data}),'')
            data.close()
            with patch.object(countries,'read_ranges',side_effect=AssertionError('Cached lookup must not parse TSV')):
                data,_=countries.cached_ranges(root,4,False)
                self.assertEqual(countries.lookup('9.0.0.10',{4:data}),'DE')
                data.close()
