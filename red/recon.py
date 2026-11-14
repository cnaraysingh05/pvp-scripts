#!/usr/bin/env python3
"""Scoped, bounded Nmap discovery from the provided competition Kali. Preview by default."""
import argparse
import json
import shutil
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from pvp_core import command, private_run_dir, utc, write_json
from red.scope_gate import require_authorized_target

PROFILES = {
    'inventory': ('22,53,80,88,135,139,389,443,445,636,1433,3306,3389,5432,5985,5986,8080,8443', None),
    'web': ('80,443,8080,8443', 'http-title,http-headers'),
    'windows': ('135,139,389,445,636,3389,5985,5986', 'smb-protocols,smb2-security-mode,ldap-rootdse'),
    'ssh': ('22', 'ssh-hostkey'),
    'database': ('1433,3306,5432', None),
}


def build_argv(target, profile, output):
    ports, scripts = PROFILES[profile]
    args = ['nmap', '-n', '-Pn', '-sT', '-sV', '--version-light', '-T3',
            '--max-retries', '1', '--max-rate', '50', '--host-timeout', '180s',
            '--script-timeout', '20s', '-p', ports]
    if scripts:
        args += ['--script', scripts]
    return args + ['-oA', str(output), target]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--scope', required=True)
    parser.add_argument('--target', required=True)
    parser.add_argument('--profile', choices=PROFILES, default='inventory')
    parser.add_argument('--output', default='reports/recon')
    parser.add_argument('--run', action='store_true')
    parser.add_argument('--grace-ended', action='store_true')
    parser.add_argument('--provided-kali', action='store_true')
    args = parser.parse_args()
    target = require_authorized_target(args)
    preview = build_argv(target, args.profile, Path('<private-run-directory>') / 'nmap')
    if not args.run:
        print(json.dumps({'mode': 'plan', 'command': preview}, indent=2))
        return 0
    if not shutil.which('nmap'):
        raise ValueError('nmap is not installed; no scan started.')
    output = private_run_dir(args.output, target + '-' + args.profile)
    argv = build_argv(target, args.profile, output / 'nmap')
    result = command(argv, timeout=200)
    write_json(output / 'run.json', {'utc': utc(), 'target': target, 'profile': args.profile,
                                    'command': argv, 'result': result})
    print(output)
    return 0 if result['returncode'] == 0 else 1


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (ValueError, OSError) as exc:
        print('ERROR: ' + str(exc), file=sys.stderr)
        sys.exit(2)
