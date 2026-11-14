#!/usr/bin/env python3
"""Private local flag tracking; never submits messages or modifies target flags."""
import argparse
import getpass
import hashlib
import json
import os
import stat
import sqlite3
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from pvp_core import literal_ip, scope_targets, utc


def flag_value(text):
    """Accept the value the target supplied: a bare SHA-256 hash or a raw flag string."""
    value = text.strip()
    if not value or len(value) > 512:
        raise ValueError('Flag value must be 1..512 characters.')
    if not all(32 <= ord(c) < 127 for c in value):
        raise ValueError('Flag value must be printable ASCII.')
    if any(c in value for c in ' \t'):
        raise ValueError('Flag value must not contain whitespace.')
    return value


def digest(value):
    return hashlib.sha256(value.encode('utf-8')).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['add', 'accepted', 'rejected', 'list'])
    parser.add_argument('--directory', default='private/flags')
    parser.add_argument('--scope'); parser.add_argument('--host'); parser.add_argument('--path')
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
        raise ValueError('Ledger directory must be owned by you with mode 0700.')
    database = directory / 'flags.sqlite3'
    if database.is_symlink(): raise ValueError('Invalid ledger file.')
    with sqlite3.connect(database) as db:
        db.execute('CREATE TABLE IF NOT EXISTS flags (flag TEXT PRIMARY KEY, host TEXT, path TEXT, state TEXT, updated TEXT, sha256 TEXT)')
        # Older ledgers predate the separate hash column; keep them readable.
        columns = {row[1] for row in db.execute('PRAGMA table_info(flags)')}
        if 'sha256' not in columns:
            db.execute('ALTER TABLE flags ADD COLUMN sha256 TEXT')
        if args.action == 'list':
            rows = db.execute('SELECT substr(flag,1,12), substr(sha256,1,12), host, path, state, updated FROM flags ORDER BY updated').fetchall()
            print(json.dumps(rows, indent=2)); return
        if not sys.stdin.isatty(): raise ValueError('Use an interactive hidden flag prompt.')
        value = flag_value(getpass.getpass('Exact flag value: '))
        if args.action == 'add':
            if not args.scope or not args.host or not args.path: raise ValueError('add requires --scope, --host, --path.')
            host = literal_ip(args.host)
            if host not in scope_targets(args.scope, 'offense'): raise ValueError('Host is not an opponent target.')
            db.execute('INSERT INTO flags (flag, host, path, state, updated, sha256) VALUES (?,?,?,?,?,?)', (value, host, args.path, 'found', utc(), digest(value)))
        else:
            cursor = db.execute('UPDATE flags SET state=?, updated=? WHERE flag=?', (args.action, utc(), value))
            if cursor.rowcount != 1: raise ValueError('Flag is not in the ledger.')
        print('Recorded locally. Submission/acceptance must be verified in FlagKeeper.')


if __name__ == '__main__':
    try: main()
    except (OSError, ValueError, sqlite3.Error) as exc:
        print('ERROR: ' + str(exc), file=sys.stderr); sys.exit(2)
