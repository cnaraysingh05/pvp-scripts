"""Bounded execution, private per-run evidence and redacted previews."""
import getpass
import json
import os
import re
import shlex
import shutil
import signal
import subprocess
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from pvp_core import private_run_dir, utc, write_json


def redact(text, secrets=()):
    for value in sorted((str(x) for x in secrets if x and str(x) != '<hidden-password>'), key=len, reverse=True):
        text = text.replace(value, '[REDACTED]')
    return text


def hidden_password(args, needed=True):
    if not needed:
        return ''
    supplied = getattr(args, 'password', None)
    if supplied is not None:
        if args.run:
            print('Warning: --password can expose secrets in shell history/process arguments. Prefer the hidden prompt.', file=sys.stderr)
        password = supplied
    elif not args.run:
        return '<hidden-password>'
    elif sys.stdin.isatty():
        password = getpass.getpass('Password: ')
    else:
        raise ValueError('An interactive password prompt is required.')
    if any(c in password for c in '\r\n\x00'):
        raise ValueError('Multiline passwords are not supported.')
    return password


def single_identity(value):
    if not re.fullmatch(r'[A-Za-z0-9_.@\\$-]+', value) or value.startswith('-') or Path(value).is_file():
        raise ValueError('Supply one literal username, not options or a credential-list file.')
    return value


def bounded_run(argv, timeout, secrets=()):
    process = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, text=True, errors='replace', start_new_session=True)
    reason = None
    try:
        stdout, stderr = process.communicate(timeout=timeout)
    except (subprocess.TimeoutExpired, KeyboardInterrupt) as exc:
        reason = 'timeout' if isinstance(exc, subprocess.TimeoutExpired) else 'interrupted'
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        stdout, stderr = process.communicate()
    return {'returncode': process.returncode if reason is None else (124 if reason == 'timeout' else 130),
            'reason': reason, 'stdout': redact(stdout, secrets), 'stderr': redact(stderr, secrets)}


def execute(args, target, label, build, secrets=(), verify=None, stop_on_failure=True):
    """Stop on failed dependencies. Return process success separately from findings."""
    preview = build(Path('<run-directory>'))
    for cmd in preview:
        print('Command:', shlex.join([redact(str(x), secrets) for x in cmd]))
    if not args.run:
        print('PREVIEW: no commands, files or network actions.'); return 0
    if os.name != 'posix':
        raise ValueError('Run wrappers on the provided Kali.')
    for cmd in preview:
        if not shutil.which(cmd[0]):
            raise ValueError('Missing dependency: ' + cmd[0])
    directory = private_run_dir(args.output, target + '-' + label)
    commands = build(directory)
    records = []
    outcome = 0
    old_umask = os.umask(0o077)
    try:
        for index, cmd in enumerate(commands):
            result = bounded_run(cmd, args.timeout, secrets)
            write_json(directory / ('step-%02d.json' % index), {'utc': utc(),
                       'command': [redact(str(x), secrets) for x in cmd], 'result': result})
            records.append({'step': index, 'returncode': result['returncode'], 'reason': result['reason']})
            if result['returncode'] != 0:
                outcome = result['returncode']
                if stop_on_failure: break
        if outcome == 0 and verify:
            verify(directory)
    except (OSError, ValueError) as exc:
        records.append({'error': redact(str(exc), secrets)})
        outcome = 1
    finally:
        os.umask(old_umask)
        write_json(directory / 'run.json', {'utc': utc(), 'target': target, 'tool': label,
                   'exit_code': outcome, 'steps': records,
                   'note': 'Exit 0 means commands/artifact validation completed, not that credentials succeeded or a vulnerability exists. Review native output. Remote processes may outlive a lost connection.'})
    print('Evidence:', directory)
    return outcome


def cli(main):
    try:
        return main()
    except (OSError, ValueError) as exc:
        print('ERROR: ' + str(exc), file=sys.stderr); return 2
    except KeyboardInterrupt:
        return 130
