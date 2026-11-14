#!/usr/bin/env python3
"""
red/smb_enum.py

SMB enumeration wrapper around smbmap and enum4linux-ng, gated the same
way as the other red/ wrappers. Intended for sunflower (the SMB-scored
Server 2019 box), but works against any in-scope SMB target.

Requires smbmap and enum4linux-ng installed on the provided Kali box.

Usage (preview):
    python3 red/smb_enum.py --scope config/local/scope.json --target 172.16.XX.51

Usage (actually run, with credentials if you have any — anonymous/null
session attempted if omitted):
    python3 red/smb_enum.py --scope config/local/scope.json --target 172.16.XX.51 \\
        --run --grace-ended --provided-kali --username guest --password ""
"""

import argparse
import shlex
import subprocess
import sys

sys.path.insert(0, "red")
from scope_gate import add_common_args, require_authorized_target  # noqa: E402


def build_commands(target: str, username: str, password: str) -> list:
    commands = []

    e4l_cmd = ["enum4linux-ng", "-A", target]
    if username:
        e4l_cmd += ["-u", username, "-p", password or ""]
    commands.append(e4l_cmd)

    smbmap_cmd = ["smbmap", "-H", target]
    if username:
        smbmap_cmd += ["-u", username, "-p", password or ""]
    commands.append(smbmap_cmd)

    return commands


def main() -> int:
    parser = argparse.ArgumentParser(description="Gated SMB enumeration wrapper for an in-scope target.")
    add_common_args(parser)
    parser.add_argument("--username", default="", help="SMB username (omit for anonymous/null session attempt)")
    parser.add_argument("--password", default="", help="SMB password")
    args = parser.parse_args()

    target = require_authorized_target(args)
    commands = build_commands(target, args.username, args.password)

    for cmd in commands:
        print("Command:", " ".join(shlex.quote(c) for c in cmd))

    if not args.run:
        return 0

    for cmd in commands:
        try:
            subprocess.run(cmd, check=True)
        except FileNotFoundError:
            sys.exit(f"[ERROR] {cmd[0]} not found on this machine. Install it on the provided Kali box first.")
        except subprocess.CalledProcessError as e:
            print(f"[WARN] {cmd[0]} exited with status {e.returncode} — continuing to next tool.")

    return 0


if __name__ == "__main__":
    sys.exit(main())
