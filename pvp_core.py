"""Shared validation and private report helpers (Python 3.10+)."""
import ipaddress
import json
import os
import re
import subprocess
import uuid
from datetime import datetime, timezone
from pathlib import Path

# The briefing's host grid is 172.16.XX.50-54. A /12 also covers the conflicting
# 172.25.XX.52 Ubuntu address, so that discrepancy is reported, not silently allowed.
COMPETITION_NETWORK = ipaddress.ip_network('172.16.0.0/12')


def utc():
    return datetime.now(timezone.utc).isoformat()


def load_json(path):
    return json.loads(Path(path).read_text(encoding='utf-8-sig'))


def literal_ip(value):
    if not isinstance(value, str) or '%' in value or 'XX' in value.upper():
        raise ValueError('Replace XX with the confirmed literal address before running.')
    return str(ipaddress.ip_address(value))


def port(value):
    if type(value) is not int or not 1 <= value <= 65535:
        raise ValueError('Port must be an integer from 1 through 65535.')
    return value


def safe_text(value, label='value'):
    if not isinstance(value, str) or not value or any(ord(c) < 32 or ord(c) == 127 for c in value):
        raise ValueError(label + ' must be nonempty text without control characters.')
    if 'XX' in value:
        raise ValueError('Replace XX in ' + label + ' before running.')
    return value


def competition_host(value):
    """Validate one literal competition host: IPv4 in 172.16.0.0/12 ending .50-.54."""
    address = literal_ip(value)
    ip = ipaddress.ip_address(address)
    if ip.version != 4:
        raise ValueError('PvP targets must be explicit IPv4 hosts.')
    if ip not in COMPETITION_NETWORK:
        raise ValueError('PvP targets must be inside 172.16.0.0/12; ' + address + ' is not a competition address.')
    last = int(address.split('.')[-1])
    if last == 1:
        raise ValueError('PvP targets cannot be a pod router (.1); it is out of scope defensively and offensively.')
    if last == 2:
        raise ValueError('PvP targets cannot be a Kali machine (.2); it is out of scope and holds no flags.')
    if last not in range(50, 55):
        raise ValueError('PvP targets must be explicit IPv4 hosts ending .50 through .54.')
    if ip.is_loopback or ip.is_multicast or ip.is_unspecified:
        raise ValueError('Invalid competition target.')
    return address


def _scope_lists(path):
    data = load_json(path)
    if not isinstance(data, dict) or not isinstance(data.get('own_targets'), list) or not isinstance(data.get('opponent_targets'), list):
        raise ValueError('Scope requires own_targets and opponent_targets arrays.')
    if data.get('confirmed') is not True:
        raise ValueError('Scope is not confirmed. Resolve addresses with Green Team first.')
    own = {competition_host(x) for x in data.get('own_targets', [])}
    opponents = {competition_host(x) for x in data.get('opponent_targets', [])}
    if own & opponents:
        raise ValueError('Own and opponent target lists overlap.')
    return own, opponents


def scope_hosts(path):
    """Every confirmed host, own and opponent, for local bookkeeping utilities."""
    own, opponents = _scope_lists(path)
    return own, opponents


def scope_targets(path, purpose):
    if purpose not in ('defense', 'offense'):
        raise ValueError('Unknown scope purpose.')
    own, opponents = _scope_lists(path)
    result = own if purpose == 'defense' else opponents
    if not result:
        raise ValueError('Selected target list is empty.')
    return result


def private_run_dir(base, label):
    if not re.fullmatch(r'[A-Za-z0-9_.-]+', label):
        raise ValueError('Invalid report label.')
    base = Path(base)
    base.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S')
    path = base / (stamp + '-' + label + '-' + uuid.uuid4().hex[:10])
    path.mkdir(mode=0o700)
    return path


def write_json(path, data):
    # New files only: never silently overwrite another run or follow a symlink.
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'w', encoding='utf-8') as handle:
        json.dump(data, handle, indent=2)
        handle.write('\n')


def command(argv, timeout=30, env=None):
    try:
        result = subprocess.run(argv, stdin=subprocess.DEVNULL, capture_output=True,
                                text=True, errors='replace', timeout=timeout, env=env)
        return {'returncode': result.returncode, 'stdout': result.stdout, 'stderr': result.stderr}
    except subprocess.TimeoutExpired:
        return {'returncode': None, 'error': 'Timed out after %s seconds' % timeout}
    except OSError as exc:
        return {'returncode': None, 'error': str(exc)}
