#!/usr/bin/env python3
"""External functional checks. Default: validate/preview; --run contacts own scoped hosts."""
import argparse
import getpass
import http.client
import ipaddress
import json
import os
import re
import shutil
import socket
import ssl
import sys
import tempfile
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from pvp_core import command, literal_ip, load_json, port, safe_text, scope_targets, utc

FIELDS = {
    'tcp': set(),
    'http': {'path', 'status', 'contains', 'tls'},
    'dns': {'query', 'expected', 'transport'},
    'ssh': {'user', 'identity_file', 'known_hosts'},
    'ldap': {'bind_dn', 'base_dn', 'tls', 'contains'},
    'smb': {'user', 'domain', 'share', 'contains'},
    'mysql': {'user', 'database'},
    'postgres': {'user', 'database'},
}
TOOLS = {'dns': 'dig', 'ssh': 'ssh', 'ldap': 'ldapsearch', 'smb': 'smbclient',
         'mysql': 'mysql', 'postgres': 'psql'}


def validate(items, allowed):
    if not isinstance(items, list) or not 1 <= len(items) <= 64:
        raise ValueError('Provide 1..64 checks.')
    names = set()
    for item in items:
        if not isinstance(item, dict):
            raise ValueError('Each check must be an object.')
        kind = item.get('type')
        if kind not in FIELDS:
            raise ValueError('Unknown check type.')
        required = {'name', 'type', 'host', 'port'} | FIELDS[kind]
        optional = {'host_header'} if kind == 'http' else set()
        if not required <= set(item) or set(item) - required - optional:
            raise ValueError('Unexpected or missing fields for ' + kind)
        name = item['name']
        if not isinstance(name, str) or not re.fullmatch(r'[A-Za-z0-9_-]{1,60}', name) or name in names:
            raise ValueError('Check names must be unique simple identifiers.')
        names.add(name)
        if literal_ip(item['host']) not in allowed:
            raise ValueError(name + ': host is outside own confirmed scope.')
        port(item['port'])
        for key in FIELDS[kind] - {'status', 'tls'}:
            safe_text(item[key], key)
        if kind == 'http':
            if type(item['tls']) is not bool or type(item['status']) is not int or not 100 <= item['status'] <= 599:
                raise ValueError('HTTP requires boolean tls and integer status.')
            if not item['path'].startswith('/'):
                raise ValueError('HTTP path must begin with /.')
            if 'host_header' in item:
                safe_text(item['host_header'], 'host_header')
        if kind == 'dns':
            if item['transport'] not in ('tcp', 'udp') or not re.fullmatch(r'[A-Za-z0-9_.-]+', item['query']) or item['query'].startswith('-'):
                raise ValueError('Invalid DNS query/transport.')
            if ipaddress.ip_address(item['expected']).version != 4:
                raise ValueError('DNS check expects an IPv4 A record.')
        if kind == 'ldap' and item['tls'] not in ('starttls', 'ldaps'):
            raise ValueError('LDAP credentials require starttls or ldaps; no plaintext fallback.')
        if kind == 'smb' and not re.fullmatch(r'[A-Za-z0-9_$ .-]+', item['share']):
            raise ValueError('Invalid SMB share name.')
        if kind in ('mysql', 'postgres') and not re.fullmatch(r'[A-Za-z0-9_.-]+', item['database']):
            raise ValueError('Use a simple database name, not a connection string.')
    return items


def secret_file(directory, name, text):
    path = Path(directory) / name
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'w', encoding='utf-8') as f:
        f.write(text)
    return str(path)


def mysql_quote(value):
    return '"' + value.replace('\\', '\\\\').replace('"', '\\"') + '"'


def pg_escape(value):
    return value.replace('\\', '\\\\').replace(':', '\\:')


def native_check(item, timeout, directory, password):
    kind, host, number = item['type'], item['host'], str(item['port'])
    env = os.environ.copy()
    if kind == 'dns':
        argv = ['dig', '@' + host, '-p', number, item['query'], 'A', '+short',
                '+time=3', '+tries=1', '+tcp' if item['transport'] == 'tcp' else '+notcp']
    elif kind == 'ssh':
        for name in ('identity_file', 'known_hosts'):
            if not Path(item[name]).is_file():
                raise ValueError('Missing SSH ' + name)
        argv = ['ssh', '-F', '/dev/null', '-o', 'BatchMode=yes', '-o', 'IdentitiesOnly=yes',
                '-o', 'StrictHostKeyChecking=yes', '-o', 'ProxyCommand=none', '-o', 'ProxyJump=none',
                '-o', 'ConnectTimeout=5', '-o', 'UserKnownHostsFile=' + str(Path(item['known_hosts']).resolve()),
                '-i', str(Path(item['identity_file']).resolve()), '-p', number, '-l', item['user'],
                host, 'printf PVP_SSH_OK']
    elif kind == 'ldap':
        pwfile = secret_file(directory, 'ldap-password', password)
        scheme = 'ldaps' if item['tls'] == 'ldaps' else 'ldap'
        argv = ['ldapsearch', '-x', '-LLL', '-H', scheme + '://' + host + ':' + number,
                '-D', item['bind_dn'], '-y', pwfile, '-b', item['base_dn'], '-s', 'base',
                '-l', '5', '(objectClass=*)', 'distinguishedName']
        if item['tls'] == 'starttls':
            argv.insert(1, '-ZZ')
        env['LDAPTLS_REQCERT'] = 'demand'
    elif kind == 'smb':
        auth = secret_file(directory, 'smb-auth', 'username = ' + item['user'] + '\npassword = ' + password + '\ndomain = ' + item['domain'] + '\n')
        argv = ['smbclient', '//' + host + '/' + item['share'], '-I', host, '-p', number,
                '-A', auth, '-c', 'ls', '-t', '5']
    elif kind == 'mysql':
        auth = secret_file(directory, 'mysql.cnf', '[client]\nuser=' + mysql_quote(item['user']) + '\npassword=' + mysql_quote(password) + '\n')
        argv = ['mysql', '--defaults-extra-file=' + auth, '--protocol=TCP', '--host=' + host,
                '--port=' + number, '--database=' + item['database'], '--connect-timeout=5',
                '--batch', '--skip-column-names', '--execute=SELECT 1;']
    else:
        auth = secret_file(directory, 'pgpass', ':'.join(pg_escape(x) for x in
                           (host, number, item['database'], item['user'], password)) + '\n')
        env['PGPASSFILE'] = auth
        env.pop('PGPASSWORD', None)
        env.pop('PGSERVICE', None)
        env['PGCONNECT_TIMEOUT'] = '5'
        argv = ['psql', '-X', '-w', '-h', host, '-p', number, '-U', item['user'], '-d', item['database'],
                '-v', 'ON_ERROR_STOP=1', '-At', '-c', 'SELECT 1;']
    result = command(argv, timeout, env)
    if result['returncode'] != 0:
        return False, result.get('error', 'Native client failed (exit %s). Check credentials, TLS, access and service logs.' % result['returncode'])
    output = result['stdout']
    if kind == 'dns':
        passed = item['expected'] in output.splitlines()
    elif kind == 'ssh':
        passed = 'PVP_SSH_OK' in output
    elif kind in ('mysql', 'postgres'):
        passed = output.strip() == '1'
    else:
        passed = item['contains'] in output
    return passed, 'Authenticated/read operation matched expected result.' if passed else 'Operation completed but expected result was absent.'


def check(item, timeout):
    kind = item['type']
    if kind in TOOLS and not shutil.which(TOOLS[kind]):
        return False, 'Missing dependency: ' + TOOLS[kind]
    if kind == 'tcp':
        with socket.create_connection((item['host'], item['port']), timeout):
            return True, 'Reachability only; authentication/application not verified.'
    if kind == 'http':
        cls = http.client.HTTPSConnection if item['tls'] else http.client.HTTPConnection
        options = {'context': ssl.create_default_context()} if item['tls'] else {}
        conn = cls(item['host'], item['port'], timeout=timeout, **options)
        try:
            headers = {'User-Agent': 'pvp-scripts/1.0'}
            if 'host_header' in item:
                headers['Host'] = item['host_header']
            conn.request('GET', item['path'], headers=headers)
            response = conn.getresponse()
            body = response.read(1048577)
            if len(body) > 1048576:
                return False, 'Response exceeds 1 MiB inspection limit.'
            passed = response.status == item['status'] and item['contains'] in body.decode('utf-8', errors='replace')
            return passed, 'HTTP status %s; content %s. Redirects are not followed.' % (response.status, 'matched' if passed else 'did not match')
        finally:
            conn.close()
    if os.name != 'posix':
        raise ValueError('Native checks run on Linux/macOS; Windows has Check-Services.ps1.')
    password = ''
    if kind in ('ldap', 'smb', 'mysql', 'postgres'):
        if not sys.stdin.isatty():
            raise ValueError('Authenticated checks require an interactive hidden password prompt.')
        password = getpass.getpass(item['name'] + ' password: ')
        if not password or any(c in password for c in '\r\n\x00'):
            raise ValueError('Empty/multiline passwords are not supported.')
    with tempfile.TemporaryDirectory(prefix='pvp-auth-') as directory:
        return native_check(item, timeout, directory, password)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', required=True); parser.add_argument('--scope', required=True)
    parser.add_argument('--only', help='One check name; useful while configuring templates.')
    parser.add_argument('--run', action='store_true')
    parser.add_argument('--timeout', type=int, choices=range(1, 61), default=15)
    args = parser.parse_args()
    items = load_json(args.config)
    if not isinstance(items, list):
        raise ValueError('Check config must be an array.')
    if args.only:
        items = [x for x in items if isinstance(x, dict) and x.get('name') == args.only]
    items = validate(items, scope_targets(args.scope, 'defense'))
    if not args.run:
        print(json.dumps({'mode': 'plan', 'checks': items}, indent=2)); return 0
    results = []
    for item in items:
        try:
            passed, detail = check(item, args.timeout)
        except (OSError, ValueError, http.client.HTTPException) as exc:
            passed, detail = False, str(exc)
        results.append({'name': item['name'], 'passed': passed, 'detail': detail})
    print(json.dumps({'utc': utc(), 'checks': results, 'note': 'Compare with scoring engine; these checks do not reproduce an unpublished scorer.'}, indent=2))
    return 0 if all(r['passed'] for r in results) else 1


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (OSError, ValueError) as exc:
        print('ERROR: ' + str(exc), file=sys.stderr); sys.exit(2)
