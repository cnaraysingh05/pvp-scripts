#!/usr/bin/env python3
"""
red/kerbrute_scan.py

Wraps kerbrute for username enumeration and password spraying against an
in-scope AD domain controller (thehouse). Gated the same way as the other
red/ wrappers.

Username enumeration is low-risk (no bad password attempts logged for
valid users, but it does confirm which names exist). Password spraying is
NOT low-risk: repeated failures can lock out accounts, and a lockout on a
scored service account costs your own team uptime points.

Usage - username enumeration (preview):
    python3 red/kerbrute_scan.py --scope config/local/scope.json \\
        --target 172.16.XX.50 --domain misty.view --userlist users.txt

Usage - username enumeration (actually run):
    python3 red/kerbrute_scan.py --scope config/local/scope.json \\
        --target 172.16.XX.50 --domain misty.view --userlist users.txt \\
        --run --grace-ended --provided-kali

Usage - password spray (hidden prompt; requires --spray):
    python3 red/kerbrute_scan.py --scope config/local/scope.json \\
        --target 172.16.XX.50 --domain misty.view --userlist valid_users.txt \\
        --spray --run --grace-ended --provided-kali
"""

import argparse
import sys
from pathlib import Path

sys.path.insert(0, "red")
from runner import cli, execute, hidden_password  # noqa: E402
from scope_gate import add_common_args, require_authorized_target  # noqa: E402


def build_command(mode: str, target: str, domain: str, userlist: str, password: str, threads: int) -> list:
    base = ["kerbrute", mode, "-d", domain, "--dc", target, "-t", str(threads)]
    if mode == "userenum":
        return base + [userlist]
    if mode == "passwordspray":
        return base + [userlist, password]
    raise ValueError(f"Unknown mode: {mode}")


def main() -> int:
    parser = argparse.ArgumentParser(description="Gated kerbrute wrapper for an in-scope AD domain controller.")
    add_common_args(parser)
    parser.add_argument("--domain", required=True, help="AD domain name, e.g. misty.view")
    parser.add_argument("--userlist", required=True, help="Path to username wordlist")
    parser.add_argument("--spray", action="store_true", help="Password-spray instead of enumerate. Reads the risk warning below.")
    parser.add_argument("--password", default=None, help="Single password to spray (prefer the hidden prompt; this flag leaks into shell history)")
    parser.add_argument("--threads", type=int, default=10, help="kerbrute thread count (default 10, keep conservative for spraying)")
    args = parser.parse_args()

    if args.threads < 1:
        raise ValueError("--threads must be a positive integer.")

    target = require_authorized_target(args)

    if args.run and not Path(args.userlist).is_file():
        raise ValueError("Userlist not found: " + args.userlist)

    password = hidden_password(args, needed=args.spray)
    secrets = (password,) if password else ()

    if args.spray:
        if not password:
            raise ValueError("--spray requires a password.")
        print(
            "[WARNING] Password spraying can trigger account lockouts depending on the domain's "
            "lockout policy. If any sprayed account is also a scored service account, a lockout "
            "will tank your own uptime score. Only spray against accounts you've confirmed are not "
            "scored, and keep --threads low.\n"
        )
        mode = "passwordspray"
    else:
        mode = "userenum"

    def build(directory):
        return [build_command(mode, target, args.domain, args.userlist, password, args.threads)]

    return execute(args, target, "kerbrute-" + mode, build, secrets=secrets)


if __name__ == "__main__":
    sys.exit(cli(main))
