#!/usr/bin/env python3
"""
red/nuclei_scan.py

Template-based scan wrapper around nuclei, gated the same way as the other
red/ wrappers. Useful across all five hosts since nuclei has templates for
HTTP, SSH banner checks, SMB, LDAP, and generic misconfig detection — but
it is still only as good as its template set, so keep templates updated
before comp day (not during).

Requires nuclei and its template repo already cloned/updated:
    nuclei -update-templates

Usage (preview):
    python3 red/nuclei_scan.py --scope config/local/scope.json --target 172.16.XX.52

Usage (actually run):
    python3 red/nuclei_scan.py --scope config/local/scope.json --target 172.16.XX.52 \\
        --run --grace-ended --provided-kali --tags http,misconfig
"""

import argparse
import shlex
import subprocess
import sys

sys.path.insert(0, "red")
from scope_gate import add_common_args, require_authorized_target  # noqa: E402

DEFAULT_TAGS = "http,ssh,smb,ldap,misconfig,exposure"
DEFAULT_SEVERITY = "info,low,medium,high,critical"


def build_command(target: str, tags: str, severity: str, rate_limit: int) -> list:
    out_file = f"nuclei_{target.replace('.', '_')}.json"
    return [
        "nuclei",
        "-target", target,
        "-tags", tags,
        "-severity", severity,
        "-rate-limit", str(rate_limit),
        "-jsonl",
        "-o", out_file,
    ]


def main() -> int:
    parser = argparse.ArgumentParser(description="Gated nuclei wrapper for in-scope hosts.")
    add_common_args(parser)
    parser.add_argument("--tags", default=DEFAULT_TAGS, help=f"Comma-separated template tags (default: {DEFAULT_TAGS})")
    parser.add_argument("--severity", default=DEFAULT_SEVERITY, help=f"Comma-separated severities (default: {DEFAULT_SEVERITY})")
    parser.add_argument("--rate-limit", type=int, default=50, help="Requests per second cap (default 50) — keep this sane, you don't want to be the reason a shared box falls over")
    args = parser.parse_args()

    target = require_authorized_target(args)
    cmd = build_command(target, args.tags, args.severity, args.rate_limit)

    print("Command:", " ".join(shlex.quote(c) for c in cmd))

    if not args.run:
        return 0

    try:
        subprocess.run(cmd, check=True)
    except FileNotFoundError:
        sys.exit("[ERROR] nuclei not found on this machine. Install it on the provided Kali box first.")
    except subprocess.CalledProcessError as e:
        sys.exit(f"[ERROR] nuclei exited with status {e.returncode}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
