#!/usr/bin/env python3
"""
red/linpeas_deploy.py

Deploys and runs linpeas over SSH on an in-scope Linux host you already
have valid credentials for (e.g. cherrybomb, chomper, peashooter - or your
own boxes, for self-review). This is a post-foothold privilege-escalation
enumeration tool, not an access tool: it requires a working SSH login
you've already obtained legitimately within the competition's rules.

Download linpeas.sh once ahead of time (open source, from carlospolop's
PEASS-ng project) and keep a local copy at tools/linpeas.sh - this wrapper
does not fetch it live, since you don't want a network dependency mid-comp.

Usage (preview):
    python3 red/linpeas_deploy.py --scope config/local/scope.json \\
        --target 172.16.XX.52 --ssh-user user --linpeas-path tools/linpeas.sh

Usage (actually run):
    python3 red/linpeas_deploy.py --scope config/local/scope.json \\
        --target 172.16.XX.52 --ssh-user user --linpeas-path tools/linpeas.sh \\
        --run --grace-ended --provided-kali
"""

import argparse
import sys
from pathlib import Path

sys.path.insert(0, "red")
from runner import cli, execute  # noqa: E402
from scope_gate import add_common_args, require_authorized_target  # noqa: E402

REMOTE_PATH = "/tmp/.lp_review.sh"


def build_commands(target: str, ssh_user: str, linpeas_path: str, ssh_port: int) -> list:
    scp_cmd = [
        "scp", "-P", str(ssh_port), "-o", "StrictHostKeyChecking=accept-new",
        linpeas_path, f"{ssh_user}@{target}:{REMOTE_PATH}",
    ]
    run_cmd = [
        "ssh", "-p", str(ssh_port), "-o", "StrictHostKeyChecking=accept-new",
        f"{ssh_user}@{target}",
        f"chmod +x {REMOTE_PATH} && {REMOTE_PATH} -a",
    ]
    cleanup_cmd = [
        "ssh", "-p", str(ssh_port), "-o", "StrictHostKeyChecking=accept-new",
        f"{ssh_user}@{target}",
        f"rm -f {REMOTE_PATH}",
    ]
    return [scp_cmd, run_cmd, cleanup_cmd]


def main() -> int:
    parser = argparse.ArgumentParser(description="Gated linpeas deployment over SSH for an in-scope Linux host you already have creds for.")
    add_common_args(parser)
    parser.add_argument("--ssh-user", required=True, help="SSH username to authenticate as")
    parser.add_argument("--ssh-port", type=int, default=22, help="SSH port (default 22)")
    parser.add_argument("--linpeas-path", default="tools/linpeas.sh", help="Local path to a pre-downloaded linpeas.sh (default tools/linpeas.sh)")
    args = parser.parse_args()

    if not 1 <= args.ssh_port <= 65535:
        raise ValueError("--ssh-port must be 1..65535.")

    target = require_authorized_target(args)

    if args.run and not Path(args.linpeas_path).is_file():
        raise ValueError(
            args.linpeas_path + " not found. Download linpeas.sh ahead of time from the "
            "PEASS-ng project and place it there - this wrapper won't fetch it live mid-comp."
        )

    def build(directory):
        return build_commands(target, args.ssh_user, args.linpeas_path, args.ssh_port)

    # Cleanup should still be attempted if the remote run fails.
    return execute(args, target, "linpeas", build, stop_on_failure=False)


if __name__ == "__main__":
    sys.exit(cli(main))
