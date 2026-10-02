import datetime as dt
import gzip
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
import collector

class HistoryTests(unittest.TestCase):
    def test_old_ssh_retention_and_deduplication(self):
        db = sqlite3.connect(':memory:')
        collector.init(db)
        old = int((collector.NOW - dt.timedelta(days=120)).timestamp())
        message = 'Accepted publickey for alice from 203.0.113.1 port 1234'
        with patch.object(collector, 'CUTOFF', None):
            collector.add_message(db, 'ssh', 'one', old, message)
            collector.add_message(db, 'ssh', 'one', old, message)
        with patch.object(collector, 'CUTOFF', collector.NOW - dt.timedelta(days=90)):
            collector.add_message(db, 'ssh', 'two', old, message)
        self.assertEqual(db.execute('SELECT kind,username,COUNT(*) FROM events').fetchone(), ('ssh_success', 'alice', 1))
        db.close()

    def test_compressed_historical_web(self):
        db = sqlite3.connect(':memory:')
        collector.init(db)
        old = collector.NOW - dt.timedelta(days=120)
        with tempfile.TemporaryDirectory() as directory:
            timestamp = old.strftime('%d/%b/%Y:%H:%M:%S %z')
            with gzip.open(Path(directory) / 'access.log.2.gz', 'wt') as file:
                file.write(f'203.0.113.2 - - [{timestamp}] "GET /.env?secret=hidden HTTP/1.1" 404 0\n')
            with patch.object(collector, 'ACCESS_LOG', Path(directory) / 'access.log'), patch.object(collector, 'CUTOFF', None), patch.object(collector, 'BACKFILL', True):
                collector.historic_web(db)
                collector.historic_web(db)
        self.assertEqual(db.execute('SELECT kind,path,COUNT(*) FROM events').fetchone(), ('web_probe', '/.env', 1))
        db.close()

    def test_year_rollover(self):
        modified = dt.datetime(2026, 1, 2).astimezone().timestamp()
        value = collector.syslog_time('Dec 31 23:00:00 host sshd: test', modified)
        self.assertEqual(dt.datetime.fromtimestamp(value).year, 2025)
