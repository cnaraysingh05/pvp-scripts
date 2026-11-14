#!/usr/bin/env python3
"""
credential_ledger.py

Private local record of rotated passwords and scoring-engine password change
requests (PCRs). The briefing only scores accounts whose PCR the engine knows
about, so a rotated scored account with no PCR is a self-inflicted outage.

This never changes a password and never contacts the scoring engine. It stores
the host, username, password and PCR state in a mode-0700 directory so nothing
gets forgotten during the 30-minute grace period.

Usage:
    python3 tools/credential_ledger.py add --scope config/local/scope.json \\
        --host 172.16.XX.52 --user lilypad
    python3 tools/credential_ledger.py pcr-submitted --host 172.16.XX.52 --user lilypad
    python3 tools/credential_ledger.py verified --host 172.16.XX.52 --user lilypad
    python3 tools/credential_ledger.py list
    python3 tools/credential_ledger.py pending
    python3 tools/credential_ledger.py export --host 172.16.XX.52
"""
import argparse
import getpass
import json
import os
import sqlite3
import stat
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from pvp_core import literal_ip, scope_hosts, utc


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['add', 'pcr-submitted', 'pcr-pending', 'verified', 'list', 'pending', 'export'])
    parser.add_argument('--directory', default='private/credentials')
    parser.add_argument('--scope'); parser.add_argument('--host'); parser.add_argument('--user')
    args = parser.parse_args()

    if os.name != 'posix':
        raise ValueError('Use this private ledger on the provided Kali; POSIX permissions required.')
    directory = Path(args.directory).absolute()
    if directory.is_symlink():
        raise ValueError('Ledger directory cannot be a symlink.')
    os.umask(0o077)
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = directory.stat()
    if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
        raise ValueError('Ledger directory must be owned by you and mode 0700.')

    host = None
    if args.host:
        host = literal_ip(args.host)
        if args.scope:
            own, opponents = scope_hosts(args.scope)
            if host not in own | opponents:
                raise ValueError('Host is not in the confirmed own or opponent scope.')
    user = args.user
    if user and (not isinstance(user, str) or any(c in user for c in ':\n\r') or user.startswith('-')):
        raise ValueError('Supply one literal username.')

    database = directory / 'credentials.sqlite3'
    if database.is_symlink(): raise ValueError('Invalid ledger file.')
    with sqlite3.connect(database) as db:
        db.execute('CREATE TABLE IF NOT EXISTS credentials (host TEXT, username TEXT, password TEXT, '
                   'created TEXT, pcr_state TEXT, verified TEXT, PRIMARY KEY (host, username))')
        columns = {row[1] for row in db.execute('PRAGMA table_info(credentials)')}
        for required in ('host', 'username', 'password', 'created', 'pcr_state', 'verified'):
            if required not in columns:
                raise ValueError('Credential ledger has an incompatible schema.')

        if args.action == 'list':
            rows = db.execute('SELECT host, username, pcr_state, verified, created FROM credentials ORDER BY host, username').fetchall()
            print(json.dumps(rows, indent=2)); return
        if args.action == 'pending':
            rows = db.execute('SELECT host, username, created FROM credentials WHERE pcr_state != ? ORDER BY host, username', ('submitted',)).fetchall()
            print(json.dumps(rows, indent=2))
            if not rows: print('No pending PCRs.')
            return
        if args.action == 'export':
            if not host: raise ValueError('export requires --host.')
            if not sys.stdin.isatty(): raise ValueError('Export requires an interactive terminal.')
            if input('Reveal stored passwords for ' + host + '? Type the host to confirm: ') != host:
                raise ValueError('Confirmation did not match.')
            rows = db.execute('SELECT username, password FROM credentials WHERE host = ? ORDER BY username', (host,)).fetchall()
            print('\n'.join('{},{}'.format(u, p) for u, p in rows))
            print('# Paste these into the PCR field, then mark each account pcr-submitted.', file=sys.stderr)
            return

        if not host or not user:
            raise ValueError(args.action + ' requires --host and --user.')

        if args.action == 'add':
            if not sys.stdin.isatty(): raise ValueError('Use an interactive hidden password prompt.')
            password = getpass.getpass('New password for ' + user + '@' + host + ': ')
            if not password or any(c in password for c in '\r\n\x00'):
                raise ValueError('Empty or multiline passwords are not supported.')
            db.execute('INSERT INTO credentials (host, username, password, created, pcr_state, verified) '
                       'VALUES (?,?,?,?,?,?) ON CONFLICT(host, username) DO UPDATE SET '
                       "password=excluded.password, created=excluded.created, pcr_state='pending', verified='no'",
                       (host, user, password, utc()))
        else:
            state = 'submitted' if args.action == 'pcr-submitted' else 'pending'
            if args.action == 'verified':
                cursor = db.execute('UPDATE credentials SET verified=?, created=? WHERE host=? AND username=?',
                                    ('yes', utc(), host, user))
            else:
                cursor = db.execute('UPDATE credentials SET pcr_state=?, created=? WHERE host=? AND username=?',
                                    (state, utc(), host, user))
            if cursor.rowcount != 1:
                raise ValueError('No ledger entry for that host and user.')
        print('Recorded locally. Verify the change on the host and in the scoring engine.')


if __name__ == '__main__':
    try: main()
    except (OSError, ValueError, sqlite3.Error) as exc:
        print('ERROR: ' + str(exc), file=sys.stderr); sys.exit(2)
