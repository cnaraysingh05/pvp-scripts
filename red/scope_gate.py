"""
scope_gate.py

Shared safety gate for every offensive wrapper in red/. Preview by default,
explicit --run to touch the network, and --grace-ended --provided-kali
required before anything leaves the box.

All host validation lives in pvp_core.competition_host/scope_targets so this
gate and the rest of the toolkit cannot drift apart. This module does not run
anything by itself - it only decides whether a wrapper is allowed to proceed.
"""

import argparse
import json
import platform
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from pvp_core import scope_targets  # noqa: E402


def add_common_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--scope", required=True, help="Path to scope.json (e.g. config/local/scope.json)")
    parser.add_argument("--target", required=True, help="Single target IP - must exactly match an entry in opponent_targets")
    parser.add_argument("--output", default="reports/red", help="Private per-run evidence directory (default reports/red)")
    parser.add_argument("--timeout", type=int, default=300, help="Per-command timeout in seconds (default 300)")
    parser.add_argument("--run", action="store_true", help="Actually execute. Without this, only the command that WOULD run is printed.")
    parser.add_argument("--grace-ended", action="store_true", help="Acknowledge the 30-minute grace period has ended per the official clock/Green Team")
    parser.add_argument("--provided-kali", action="store_true", help="Acknowledge this is being run from the competition-provided Kali machine")


def require_provided_kali() -> None:
    """Verify the local host actually reports as Kali, not just that a flag was passed."""
    release = Path("/etc/os-release")
    if platform.system() != "Linux" or not release.is_file():
        raise ValueError("Offensive tooling must run on the competition-provided Kali machine.")
    fields = {}
    for line in release.read_text(encoding="utf-8", errors="replace").splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            fields[key.strip()] = value.strip().strip('"')
    if fields.get("ID") != "kali":
        raise ValueError("This host is not Kali (" + fields.get("ID", "unknown") + "); run offensive tooling from the provided Kali machine.")


def require_authorized_target(args: argparse.Namespace) -> str:
    """
    Returns the validated target IP, or raises ValueError with a clear reason.
    Does not execute anything - just gates.
    """
    try:
        opponents = scope_targets(args.scope, "offense")
    except FileNotFoundError:
        raise ValueError("Scope file not found: " + str(args.scope))
    except json.JSONDecodeError as exc:
        raise ValueError("Scope file is not valid JSON: " + str(exc))

    if args.target not in opponents:
        raise ValueError(
            str(args.target) + " is not in opponent_targets in " + str(args.scope) + ". "
            "Add it explicitly after confirming it is in scope - never infer a target from a team number."
        )

    if args.run and getattr(args, "timeout", None) is not None and args.timeout < 1:
        raise ValueError("--timeout must be a positive number of seconds.")

    if args.run and not (args.grace_ended and args.provided_kali):
        raise ValueError(
            "--run requires both --grace-ended and --provided-kali. These are an honor-system acknowledgment, "
            "not a clock check - do not set them until Green Team / the official timer confirms the grace "
            "period has ended, and you are actually running from the provided Kali box."
        )

    if args.run:
        require_provided_kali()

    return args.target
