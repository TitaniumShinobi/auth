"""Read-only, one-connection observer. Never imports application/session writers."""
import json
import math
import os
import re
import signal
import stat
import sys


def datasource(reference):
    # Use the existing host's protected file; do not copy its value into a manifest.
    if not os.path.isabs(reference):
        raise ValueError('PROTECTED_DATASOURCE_REQUIRED')
    fd = os.open(reference, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        s = os.fstat(fd)
        if not stat.S_ISREG(s.st_mode) or s.st_uid != 0 or s.st_mode & 0o027:
            raise ValueError('PROTECTED_DATASOURCE_PERMISSIONS')
        with os.fdopen(fd, 'r', closefd=False) as f:
            lines = f.read(65537)
        if len(lines) > 65536:
            raise ValueError('PROTECTED_DATASOURCE_TOO_LARGE')
        values = []
        for line in lines.splitlines():
            if line.startswith('VVAULT_BODY_DATABASE_URL='):
                value = line.split('=', 1)[1].strip()
                if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
                    value = value[1:-1]
                if not value or any(c in value for c in ('$', '`', '\\', '\n')):
                    raise ValueError('UNSUPPORTED_ENV_ENCODING')
                values.append(value)
        if len(values) != 1:
            raise ValueError('EXACT_DATASOURCE_REFERENCE_REQUIRED')
        return values[0]
    finally:
        os.close(fd)


def observe(request, connect, dsn):
    bounds = request['databaseBounds']
    for k in ('connectTimeoutMs', 'statementTimeoutMs', 'acquireTimeoutMs'):
        if not isinstance(bounds[k], int) or not 1 <= bounds[k] <= 10000:
            raise ValueError('DATABASE_BOUNDS_REQUIRED')
    ident = re.compile(r'^[a-z_][a-z_0-9]*$')
    migrations = request['requiredMigrations']
    for m in migrations:
        parts = m['ledger'].split('.')
        if len(parts) != 2 or not all(ident.fullmatch(p) for p in parts):
            raise ValueError('INVALID_LEDGER')
    cols = request['ledgerAdapter']
    if not all(ident.fullmatch(cols[k]) for k in ('versionColumn', 'checksumColumn')):
        raise ValueError('INVALID_LEDGER_COLUMNS')
    # No shared pool or acquire queue: exactly one fresh connection, always closed.
    conn = connect(dsn, connect_timeout=max(1, math.ceil(bounds['connectTimeoutMs']/1000)),
                   options='-c default_transaction_read_only=on -c statement_timeout=%d -c lock_timeout=%d'
                   % (bounds['statementTimeoutMs'], bounds['statementTimeoutMs']))
    try:
        with conn.cursor() as cur:
            cur.execute('BEGIN READ ONLY')
            cur.execute('SELECT current_database(), current_setting(\'transaction_read_only\')')
            authority, readonly = cur.fetchone()
            if readonly != 'on' or authority != request['databaseAuthority']:
                raise ValueError('DATABASE_AUTHORITY_MISMATCH')
            rows = []
            for m in migrations:
                schema, table = m['ledger'].split('.')
                # Identifiers strictly validated above; values are parameterized.
                cur.execute('SELECT "%s", "%s" FROM "%s"."%s" WHERE "%s" = %%s LIMIT 2'
                            % (cols['versionColumn'], cols['checksumColumn'], schema, table, cols['versionColumn']), (m['id'],))
                for version, checksum in cur.fetchall():
                    if str(version) != m['id'] or not isinstance(checksum, str) or not re.fullmatch(r'[a-f0-9]{64}', checksum):
                        raise ValueError('INVALID_LEDGER_ROW')
                    rows.append({'ledger': m['ledger'], 'id': str(version), 'sha256': checksum, 'applied': True})
            return {'reachable': True, 'authority': authority, 'readOnly': True,
                    'observerConnections': 1, 'migrations': rows}
    finally:
        try:
            conn.rollback()
        finally:
            conn.close()


def main():
    # Parent also SIGKILLs at deadline. Driver timeout + process isolation bound SQL,
    # including a wedged driver. No retry and no persistent pool survives a probe.
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(2))
    try:
        request = json.loads(sys.stdin.read(65537))
        import psycopg
        result = observe(request, psycopg.connect, datasource(request['datasourceReference']))
        print(json.dumps(result))
    except Exception:
        print(json.dumps({'reachable': False, 'error': 'DATABASE_OBSERVATION_UNAVAILABLE'}))
        return 2
    return 0


if __name__ == '__main__':
    sys.exit(main())
