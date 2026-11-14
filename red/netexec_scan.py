#!/usr/bin/env python3
"""
red/netexec_scan.py

Wraps NetExec (nxc) for SMB/LDAP/WinRM enumeration and credential
validation against an in-scope Windows/AD host (thehouse, sunflower).
Gated the same way as the other red/ wrappers.

Credential validation (--username/--password) checks one set of creds
at a time against one protocol - this is NOT a spray tool by design here.
If you want to test many accounts, loop this script's preview output
yourself rather than passing a credential list, so you stay aware of
lockout risk one attempt at a time.

Requires netexec (https://github.com/Pennyw0rth/NetExec) on the Kali box.

Usage - unauthenticated enumeration (preview):
    python3 red/netexec_scan.py --scope config/local/scope.json \\
        --target 172.16.XX.51 --protocol smb

Usage - unauthenticated enumeration (actually run):
    python3 red/netexec_scan.py --scope config/local/scope.json \\
        --target 172.16.XX.51 --protocol smb \\
        --run --grace-ended --provided-kali

Usage - with a single credential pair to validate (hidden prompt):
    python3 red/netexec_scan.py --scope config/local/scope.json \\
        --target 172.16.XX.50 --protocol ldap \\
        --username jalapeno --run --grace-ended --provided-kali
"""

import argparse
import shlex
import sys

sys.path.insert(0, "red")
from runner import cli, execute, hidden_password  # noqa: E402
from scope_gate import add_common_args, require_authorized_target  # noqa: E402

VALID_PROTOCOLS = ["smb", "ldap", "winrm"]


def build_command(protocol: str, target: str, username: str, password: str, extra: str) -> list:
    cmd = ["netexec", protocol, target]
    if username:
        cmd += ["-u", username, "-p", password or ""]
    if extra:
        cmd += shlex.split(extra)
    return cmd


def main() -> int:
    parser = argparse.ArgumentParser(description="Gated NetExec wrapper for an in-scope Windows/AD host.")
    add_common_args(parser)
    parser.add_argument("--protocol", required=True, choices=VALID_PROTOCOLS, help="Protocol to target")
    parser.add_argument("--username", default="", help="Single username to validate (omit for unauthenticated enum)")
    parser.add_argument("--password", default=None, help="Password for --username (prefer the hidden prompt; this flag leaks into shell history)")
    parser.add_argument("--extra", default="", help="Extra nxc flags passed through verbatim, e.g. '--shares' or '--users'")
    args = parser.parse_args()

    target = require_authorized_target(args)
    password = hidden_password(args, needed=bool(args.username))
    secrets = (password,) if password else ()

    def build(directory):
        return [build_command(args.protocol, target, args.username, password, args.extra)]

    return execute(args, target, "netexec-" + args.protocol, build, secrets=secrets)


if __name__ == "__main__":
    sys.exit(cli(main))
