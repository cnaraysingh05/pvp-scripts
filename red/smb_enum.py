#!/usr/bin/env python3
"""
red/smb_enum.py

SMB enumeration wrapper around smbmap and enum4linux-ng, gated the same
way as the other red/ wrappers. Intended for sunflower (the SMB-scored
Server 2019 box), but works against any in-scope SMB target.

Requires smbmap and enum4linux-ng installed on the provided Kali box.

Usage (preview):
    python3 red/smb_enum.py --scope config/local/scope.json --target 172.16.XX.51

Usage (actually run, with credentials if you have any - anonymous/null
session attempted if omitted):
    python3 red/smb_enum.py --scope config/local/scope.json --target 172.16.XX.51 \\
        --run --grace-ended --provided-kali --username guest
"""

import argparse
import sys

sys.path.insert(0, "red")
from runner import cli, execute, hidden_password  # noqa: E402
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
    parser.add_argument("--password", default=None, help="SMB password (prefer the hidden prompt; this flag leaks into shell history)")
    args = parser.parse_args()

    target = require_authorized_target(args)
    password = hidden_password(args, needed=bool(args.username))
    secrets = (password,) if password else ()

    def build(directory):
        return build_commands(target, args.username, password)

    # Keep going to the second tool if the first one fails.
    return execute(args, target, "smb-enum", build, secrets=secrets, stop_on_failure=False)


if __name__ == "__main__":
    sys.exit(cli(main))
