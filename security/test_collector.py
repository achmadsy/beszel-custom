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

class AnalysisTests(unittest.TestCase):
    def test_methods_categories_and_sanitization(self):
        db = sqlite3.connect(':memory:')
        collector.init(db)
        now = int(collector.NOW.timestamp())
        for n, method in enumerate(['publickey', 'password', 'keyboard-interactive/pam']):
            collector.add_message(db, 'ssh', str(n), now, f'Accepted {method} for alice from 2001:db8::1 port 2345')
        self.assertEqual([r[0] for r in db.execute('SELECT method FROM events ORDER BY id')], ['publickey', 'password', 'keyboard-interactive/pam'])
        cases = {'/.env':'sensitive_files', '/wp-login.php':'wordpress', '/phpmyadmin/':'php_tooling', '/actuator/health':'admin_panels', '/admin/../../etc/passwd':'traversal_injection', '/%252e%252e/etc/passwd':'traversal_injection', '/?cmd=whoami':'traversal_injection', '/normal':'', '/admin?key=secret':'admin_panels'}
        for path, expected in cases.items():
            self.assertEqual(collector.web_category(path), expected, path)
        self.assertEqual(collector.safe_path('/webhook/abcdefghijklmnopqrstuvwxyz?key=secret#fragment'), '/webhook/[id]')
        collector.add_web_record(db, '{"time":'+str(now)+',"peer":"203.0.113.1","path":"/webhook/abcdefghijklmnopqrstuvwxyz?cmd=whoami","method":"GET","status":404}', [], 'request')
        self.assertEqual(db.execute("SELECT kind,path,web_category FROM events WHERE source='web'").fetchone(), ('web_probe','/webhook/[id]','traversal_injection'))

    def test_old_database_upgrade_and_backfill_method(self):
        db = sqlite3.connect(':memory:')
        db.execute('CREATE TABLE events (id INTEGER PRIMARY KEY,source_id TEXT UNIQUE NOT NULL,occurred_at INTEGER NOT NULL,source TEXT NOT NULL,kind TEXT NOT NULL,peer_ip TEXT,client_ip TEXT,provenance TEXT NOT NULL,host TEXT,username TEXT,method TEXT,path TEXT,port INTEGER,status INTEGER)')
        db.execute("INSERT INTO events(source_id,occurred_at,source,kind,provenance,path) VALUES ('old',1,'web','web_request','direct','/admin/abcdefghijklmnopqrstuvwxyz?key=secret')")
        collector.init(db)
        self.assertEqual(db.execute('SELECT kind,path,web_category FROM events').fetchone(),('web_probe','/admin/[id]','admin_panels'))
        now = int(collector.NOW.timestamp())
        collector.add(db, 'ssh-old', now, 'ssh', 'ssh_success', username='alice')
        collector.add_message(db, 'ssh', 'ssh-old', now, 'Accepted publickey for alice from 203.0.113.1 port 1234')
        self.assertEqual(db.execute("SELECT method,COUNT(*) FROM events WHERE source='ssh'").fetchone(),('publickey',1))
        collector.init(db)
        self.assertEqual(db.execute('SELECT COUNT(*) FROM events').fetchone()[0],2)

    def test_collector_failure_preserves_status_and_rollback(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(collector, 'DB', Path(directory)/'events.db'):
            def fail(db, *args):
                collector.add(db,'failed',int(collector.NOW.timestamp()),'ssh','ssh_failure')
                raise RuntimeError('secret error content')
            with patch.object(collector,'journal',side_effect=fail):
                with self.assertRaises(RuntimeError): collector.collect()
            with sqlite3.connect(collector.DB) as db:
                self.assertEqual(db.execute('SELECT status,error,last_success_at FROM collector_state').fetchone(),('failed','RuntimeError',None))
                self.assertEqual(db.execute('SELECT COUNT(*) FROM events').fetchone()[0],0)
            with patch.object(collector,'journal'), patch.object(collector,'web'), patch.object(collector,'cf_ranges'), patch.object(collector,'historic_system'), patch.object(collector,'historic_web'), patch.object(collector,'enrich_countries'):
                collector.collect()
            with sqlite3.connect(collector.DB) as db:
                state=db.execute('SELECT status,error,last_success_at FROM collector_state').fetchone()
                self.assertEqual(state[:2],('success',''))
                self.assertIsNotNone(state[2])

    def test_retained_logs_upgrade_old_query_classification(self):
        db=sqlite3.connect(':memory:')
        collector.init(db)
        old=collector.NOW-dt.timedelta(days=120)
        when=int(old.timestamp())
        collector.add(db,'previous',when,'web','web_request','203.0.113.2',provenance='legacy_unknown',method='GET',path='/normal',status=404)
        with tempfile.TemporaryDirectory() as directory:
            timestamp=old.strftime('%d/%b/%Y:%H:%M:%S %z')
            with gzip.open(Path(directory)/'access.log.2.gz','wt') as file:
                file.write(f'203.0.113.2 - - [{timestamp}] "GET /normal?cmd=whoami HTTP/1.1" 404 0\n')
            with patch.object(collector,'ACCESS_LOG',Path(directory)/'access.log'),patch.object(collector,'CUTOFF',None),patch.object(collector,'BACKFILL',True):
                collector.historic_web(db)
        self.assertEqual(db.execute("SELECT COUNT(*),kind,web_category,path FROM events").fetchone(),(1,'web_probe','traversal_injection','/normal'))

    def test_text_backfill_enriches_existing_journal_event(self):
        db=sqlite3.connect(':memory:');collector.init(db)
        when=int(collector.NOW.timestamp())
        collector.add(db,'journal-original',when,'ssh','ssh_success','203.0.113.1','203.0.113.1',username='alice',port=1234)
        with tempfile.TemporaryDirectory() as directory:
            folder=Path(directory)
            (folder/'auth.log').write_text(collector.NOW.isoformat()+' host sshd: Accepted publickey for alice from 203.0.113.1 port 1234\n')
            with patch.object(collector,'Path',side_effect=lambda p: folder if p=='/var/log' else Path(p)),patch.object(collector,'BACKFILL',True):
                collector.historic_system(db)
        self.assertEqual(db.execute('SELECT COUNT(*),source_id,method FROM events').fetchone(),(1,'journal-original','publickey'))

    def test_long_backfill_accepts_current_events_and_skips_unchanged_rows(self):
        db=sqlite3.connect(':memory:');collector.init(db)
        later=int(collector.NOW.timestamp())+600
        with patch.object(collector.time,'time',return_value=later):
            collector.add(db,'current',later,'ssh','ssh_probe')
            before=db.total_changes
            collector.add(db,'current',later,'ssh','ssh_probe')
            self.assertEqual(db.total_changes,before)
            collector.add(db,'future',later+301,'ssh','ssh_probe')
        self.assertEqual(db.execute('SELECT COUNT(*),source_id FROM events').fetchone(),(1,'current'))
