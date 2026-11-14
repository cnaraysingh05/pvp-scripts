#!/usr/bin/env python3
"""Private local flag tracking; never submits messages or modifies target flags."""
import argparse
import getpass
import json
import os
import re
import sqlite3
import stat
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from pvp_core import literal_ip, scope_targets, utc


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['add', 'accepted', 'rejected', 'list'])
    parser.add_argument('--directory', default='private/flags')
    parser.add_argument('--scope'); parser.add_argument('--host'); parser.add_argument('--path')
    args = parser.parse_args()
    if os.name != 'posix':
        raise ValueError('Use this private ledger on the provided Kali; POSIX permissions required.')
    directory = Path(args.directory).absolute()
    if any(p.is_symlink() for p in (directory, *directory.parents)):
        raise ValueError('Ledger path cannot traverse symlinks.')
    os.umask(0o077)
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = directory.stat()
    if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
        raise ValueError('Ledger directory must be owned by you with mode 0700.')
    database = directory / 'flags.sqlite3'
    if database.is_symlink(): raise ValueError('Invalid ledger file.')
    with sqlite3.connect(database) as db:
        db.execute('CREATE TABLE IF NOT EXISTS flags (flag TEXT PRIMARY KEY, host TEXT, path TEXT, state TEXT, updated TEXT)')
        if args.action == 'list':
            rows = db.execute('SELECT substr(flag,1,12), host, path, state, updated FROM flags ORDER BY updated').fetchall()
            print(json.dumps(rows, indent=2)); return
        if not sys.stdin.isatty(): raise ValueError('Use an interactive hidden flag prompt.')
        value = getpass.getpass('Exact flag value: ').strip()
        if not re.fullmatch(r'[0-9a-fA-F]{64}', value): raise ValueError('Expected 64 hexadecimal characters.')
        if args.action == 'add':
            if not args.scope or not args.host or not args.path: raise ValueError('add requires --scope, --host, --path.')
            host = literal_ip(args.host)
            if host not in scope_targets(args.scope, 'offense'): raise ValueError('Host is not an opponent target.')
            db.execute('INSERT INTO flags VALUES (?,?,?,?,?)', (value, host, args.path, 'found', utc()))
        else:
            cursor = db.execute('UPDATE flags SET state=?, updated=? WHERE flag=?', (args.action, utc(), value))
            if cursor.rowcount != 1: raise ValueError('Flag is not in the ledger.')
        print('Recorded locally. Submission/acceptance must be verified in FlagKeeper.')


if __name__ == '__main__':
    try: main()
    except (OSError, ValueError, sqlite3.Error) as exc:
        print('ERROR: ' + str(exc), file=sys.stderr); sys.exit(2)
