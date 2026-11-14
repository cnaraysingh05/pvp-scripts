#!/usr/bin/env python3
"""Root-only selected configuration snapshots; restore one file at a time, preview first."""
import argparse
import base64
import hashlib
import json
import os
import platform
import stat
import sys
import tempfile
import uuid
from datetime import datetime, timezone
from pathlib import Path

BASE = Path('/var/lib/pvp-scripts/backups')
ALLOWED = tuple(Path(p) for p in ('/etc/ssh', '/etc/nginx', '/etc/apache2', '/etc/httpd',
    '/etc/pihole', '/etc/dnsmasq.d', '/etc/mysql', '/etc/postgresql', '/etc/my.cnf.d'))
SINGLE = {Path('/etc/my.cnf'), Path('/etc/dnsmasq.conf')}


def allowed(path):
    return path in SINGLE or any(path == root or root in path.parents for root in ALLOWED)


def regular_config(path):
    if not path.is_absolute() or '..' in path.parts or not allowed(path):
        raise ValueError('Path is outside supported configuration locations.')
    if any(p.is_symlink() for p in (path, *path.parents)):
        raise ValueError('Symlink paths are excluded.')
    if path.name.lower() == 'flag.txt' or path.suffix.lower() in ('.db', '.sqlite', '.sqlite3', '.log'):
        raise ValueError('Flags, live databases and logs are excluded.')
    info = path.stat()
    if not stat.S_ISREG(info.st_mode) or info.st_size > 10 * 1024 * 1024:
        raise ValueError('Expected a regular config file of at most 10 MiB.')
    return info


def digest(data):
    return hashlib.sha256(data).hexdigest()


def secure_base():
    if any(p.is_symlink() for p in (BASE, *BASE.parents)):
        raise ValueError('Backup location may not traverse symlinks.')
    BASE.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = BASE.stat()
    if info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o700:
        raise ValueError('Backup base must be root-owned mode 0700.')


def snapshot(paths):
    selected = []
    skipped = []
    for raw in paths:
        path = Path(raw)
        if not path.is_absolute() or not allowed(path) or path.is_symlink():
            raise ValueError('Unsupported path: ' + str(path))
        candidates = [path] if path.is_file() else sorted(path.rglob('*'))
        if not path.exists():
            raise ValueError('Missing configuration path: ' + str(path))
        for candidate in candidates:
            if candidate.is_dir() and not candidate.is_symlink():
                continue
            try:
                regular_config(candidate)
                selected.append(candidate)
            except (ValueError, OSError) as exc:
                skipped.append({'path': str(candidate), 'reason': str(exc)})
    selected = sorted(set(selected))
    if not selected:
        raise ValueError('No eligible files.')
    secure_base()
    folder = BASE / (datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S') + '-' + uuid.uuid4().hex[:8])
    folder.mkdir(mode=0o700)
    records = []
    for index, path in enumerate(selected):
        info = regular_config(path)
        data = path.read_bytes()
        blob = '%05d.bin' % index
        (folder / blob).write_bytes(data)
        records.append({'path': str(path), 'blob': blob, 'sha256': digest(data),
                        'uid': info.st_uid, 'gid': info.st_gid, 'mode': stat.S_IMODE(info.st_mode),
                        'xattrs': {name: base64.b64encode(os.getxattr(path, name)).decode('ascii') for name in os.listxattr(path)}})
    manifest = {'host': platform.node(), 'files': records, 'skipped': skipped,
                'note': 'File content, ownership, mode and accessible xattrs (including file ACL/SELinux attributes where present). Not an application database backup.'}
    (folder / 'manifest.json').write_text(json.dumps(manifest, indent=2))
    print(folder)
    print('Saved %s files; skipped %s. Review manifest.' % (len(records), len(skipped)))


def restore(folder, target, apply):
    secure_base()
    folder = Path(folder)
    if folder.parent != BASE or folder.is_symlink() or folder.stat().st_uid != 0 or stat.S_IMODE(folder.stat().st_mode) != 0o700:
        raise ValueError('Select a root-owned private snapshot directly beneath the backup base.')
    manifest_path = folder / 'manifest.json'
    if manifest_path.is_symlink():
        raise ValueError('Invalid manifest.')
    manifest = json.loads(manifest_path.read_text())
    if manifest['host'] != platform.node():
        raise ValueError('Snapshot host does not match.')
    rows = [r for r in manifest['files'] if r['path'] == target]
    if len(rows) != 1:
        raise ValueError('Select exactly one file from this snapshot.')
    row = rows[0]
    path = Path(target)
    regular_config(path)
    blob = folder / row['blob']
    if blob.parent != folder or blob.is_symlink() or not blob.is_file():
        raise ValueError('Invalid backup blob.')
    data = blob.read_bytes()
    if digest(data) != row['sha256']:
        raise ValueError('Backup hash mismatch.')
    print('Restore selected file: ' + target)
    if not apply:
        print('PREVIEW only. No files or services changed.'); return
    if input('Type the exact target path: ') != target:
        raise ValueError('Confirmation mismatch.')
    snapshot([target])  # Preserve the immediately preceding version before replacement.
    fd, temporary = tempfile.mkstemp(dir=path.parent, prefix='.pvp-restore-')
    try:
        with os.fdopen(fd, 'wb') as handle:
            handle.write(data); handle.flush(); os.fsync(handle.fileno())
            os.fchown(handle.fileno(), row['uid'], row['gid'])
            os.fchmod(handle.fileno(), row['mode'])
        for name, value in row.get('xattrs', {}).items():
            os.setxattr(temporary, name, base64.b64decode(value, validate=True))
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary): os.unlink(temporary)
    print('Restored with recorded metadata. Validate syntax and permissions/SELinux context before reload. No service restarted.')


def main():
    p = argparse.ArgumentParser(description=__doc__)
    sub = p.add_subparsers(dest='action', required=True)
    save = sub.add_parser('save'); save.add_argument('--path', action='append', required=True)
    recover = sub.add_parser('restore'); recover.add_argument('--snapshot', required=True)
    recover.add_argument('--file', required=True); recover.add_argument('--apply', action='store_true')
    args = p.parse_args()
    if platform.system() != 'Linux' or os.geteuid() != 0:
        raise ValueError('Run as root on the managed Linux host.')
    os.umask(0o077)
    if args.action == 'save': snapshot(args.path)
    else: restore(args.snapshot, args.file, args.apply)


if __name__ == '__main__':
    try: main()
    except (OSError, ValueError, KeyError) as exc:
        print('ERROR: ' + str(exc), file=sys.stderr); sys.exit(2)
