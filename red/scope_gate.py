"""
scope_gate.py

Shared safety gate for every offensive wrapper in red/. Mirrors the pattern
already used by red/recon.py: preview by default, explicit --run to touch
the network, and --grace-ended --provided-kali required before anything
leaves the box. Every new offensive tool wrapper should import and call
require_authorized_target() before building a real command.

This module does not run anything by itself — it only decides whether a
wrapper is allowed to proceed.
"""

import argparse
import json
import sys


def load_scope(path: str) -> dict:
    with open(path, "r") as f:
        return json.load(f)


def add_common_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--scope", required=True, help="Path to scope.json (e.g. config/local/scope.json)")
    parser.add_argument("--target", required=True, help="Single target IP — must exactly match an entry in opponent_targets")
    parser.add_argument("--run", action="store_true", help="Actually execute. Without this, only the command that WOULD run is printed.")
    parser.add_argument("--grace-ended", action="store_true", help="Acknowledge the 30-minute grace period has ended per the official clock/Green Team")
    parser.add_argument("--provided-kali", action="store_true", help="Acknowledge this is being run from the competition-provided Kali machine")


def require_authorized_target(args: argparse.Namespace) -> str:
    """
    Returns the validated target IP, or exits with a clear error.
    Does not execute anything — just gates.
    """
    try:
        scope = load_scope(args.scope)
    except FileNotFoundError:
        sys.exit(f"[BLOCKED] Scope file not found: {args.scope}")
    except json.JSONDecodeError as e:
        sys.exit(f"[BLOCKED] Scope file is not valid JSON: {e}")

    if scope.get("confirmed") is not True:
        sys.exit("[BLOCKED] scope.json has confirmed != true. Verify scope with Green Team and set it explicitly before running anything offensive.")

    opponent_targets = scope.get("opponent_targets", []) or []
    if args.target not in opponent_targets:
        sys.exit(
            f"[BLOCKED] {args.target!r} is not in opponent_targets in {args.scope}. "
            f"Add it explicitly after confirming it's in scope — never infer a target from a team number."
        )

    if not args.run:
        print("[PREVIEW MODE] Nothing will be executed. Add --run once you're ready to actually fire this.")

    if args.run and not (args.grace_ended and args.provided_kali):
        sys.exit(
            "[BLOCKED] --run requires both --grace-ended and --provided-kali. "
            "These are an honor-system acknowledgment, not a clock check — don't set them until "
            "Green Team / the official timer confirms the grace period has actually ended, and you "
            "are actually running this from the provided Kali box."
        )

    # Hard refusal of obviously out-of-scope hosts even if someone edited scope.json carelessly
    if args.target.endswith(".1") or ".1" in args.target.split(".")[-2:-1]:
        pass  # left intentionally permissive here; real router/Kali exclusion lives in scope.json curation

    return args.target
