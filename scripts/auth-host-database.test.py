import importlib.util
import pathlib
import unittest
spec = importlib.util.spec_from_file_location('worker', pathlib.Path(__file__).with_name('auth-host-database.py'))
worker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(worker)


class Cursor:
    def __init__(self, owner): self.owner = owner
    def __enter__(self): return self
    def __exit__(self, *args): pass
    def execute(self, sql, args=None): self.owner.calls.append((sql, args))
    def fetchone(self): return self.owner.database, 'on'
    def fetchall(self): return [('0039', 'a'*64)]


class Connection:
    def __init__(self): self.calls = []; self.closed = False; self.rolled_back = False; self.database = 'canonical'
    def cursor(self): return Cursor(self)
    def rollback(self): self.rolled_back = True
    def close(self): self.closed = True


class TestObserver(unittest.TestCase):
    def request(self):
        return {'databaseAuthority': 'canonical', 'databaseBounds': {'connectTimeoutMs':3000,'statementTimeoutMs':3000,'acquireTimeoutMs':3000}, 'ledgerAdapter':{'versionColumn':'version','checksumColumn':'checksum'}, 'requiredMigrations':[{'ledger':'ovvaults.enrollment_schema_migrations','id':'0039'}]}
    def test_bounded_readonly_exact_ledger_no_session_mutation(self):
        c=Connection(); options={}
        def connect(dsn, **kw): options.update(kw); return c
        r=worker.observe(self.request(), connect, 'test-only')
        self.assertTrue(r['reachable']); self.assertTrue(c.closed and c.rolled_back)
        self.assertEqual(options['connect_timeout'],3)
        self.assertIn('statement_timeout=3000',options['options']);self.assertIn('default_transaction_read_only=on',options['options'])
        self.assertIn('"ovvaults"."enrollment_schema_migrations"',c.calls[-1][0]);self.assertEqual(c.calls[-1][1],('0039',))
        self.assertFalse(any(x in sql.upper() for sql,_ in c.calls for x in ('INSERT','UPDATE','DELETE','CREATE')))
    def test_wrong_database_closes_connection(self):
        c=Connection();c.database='wrong'
        with self.assertRaisesRegex(ValueError,'DATABASE_AUTHORITY_MISMATCH'): worker.observe(self.request(),lambda *a,**k:c,'test')
        self.assertTrue(c.closed and c.rolled_back)
    def test_identifier_injection_never_connects(self):
        r=self.request();r['requiredMigrations'][0]['ledger']='ovvaults.x;DROP'
        with self.assertRaisesRegex(ValueError,'INVALID_LEDGER'): worker.observe(r,lambda *a,**k:self.fail('connected'),'test')
    def test_driver_failure_has_no_retry(self):
        calls=[]
        def broken(*a,**k): calls.append(1);raise RuntimeError('PRIVATE')
        with self.assertRaises(RuntimeError): worker.observe(self.request(),broken,'test')
        self.assertEqual(calls,[1])


if __name__=='__main__': unittest.main()
