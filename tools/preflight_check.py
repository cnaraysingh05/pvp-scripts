#!/usr/bin/env python3
"""
preflight_check.py

Pre-competition sanity check for pvp-scripts config files.
Run this BEFORE the competition starts (and again right after the grace
period ends, once real IPs are known) to catch placeholder values,
unconfirmed scope, or conflicting addresses before anyone runs a
network-touching command.

Usage:
    python3 tools/preflight_check.py --scope config/local/scope.json

Exit code is non-zero if any check fails, so this can be wired into a
Makefile / CI step / pre-run hook if you want to hard-block execution.
"""

import argparse
import ipaddress
import json
import sys


REQUIRED_KEYS = ["own_targets", "opponent_targets", "confirmed"]


def fail(msg: str) -> None:
    print(f"[FAIL] {msg}")


def warn(msg: str) -> None:
    print(f"[WARN] {msg}")


def ok(msg: str) -> None:
    print(f"[ OK ] {msg}")


def looks_like_placeholder(value: str) -> bool:
    """Catch leftover 'XX' or obviously templated values."""
    if not isinstance(value, str):
        return False
    lowered = value.upper()
    return "XX" in lowered or lowered.strip() in {"", "TBD", "TODO"}


def validate_target_list(name: str, targets, errors: list) -> None:
    if not isinstance(targets, list):
        errors.append(f"{name} is not a list")
        return
    for entry in targets:
        if looks_like_placeholder(entry):
            errors.append(f"{name} contains an unresolved placeholder: {entry!r}")
            continue
        try:
            ipaddress.ip_address(entry)
        except ValueError:
            errors.append(f"{name} contains a value that is not a valid IP: {entry!r}")


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate a pvp-scripts scope config before use.")
    parser.add_argument("--scope", required=True, help="Path to scope.json")
    args = parser.parse_args()

    try:
        with open(args.scope, "r") as f:
            scope = json.load(f)
    except FileNotFoundError:
        fail(f"Scope file not found: {args.scope}")
        return 1
    except json.JSONDecodeError as e:
        fail(f"Scope file is not valid JSON: {e}")
        return 1

    errors = []

    for key in REQUIRED_KEYS:
        if key not in scope:
            errors.append(f"Missing required key: {key!r}")

    if "own_targets" in scope:
        validate_target_list("own_targets", scope["own_targets"], errors)

    if "opponent_targets" in scope:
        # Empty opponent_targets is valid (defense-only configuration per README)
        if scope["opponent_targets"]:
            validate_target_list("opponent_targets", scope["opponent_targets"], errors)
        else:
            warn("opponent_targets is empty — fine if you're only configuring defense, "
                 "but offensive commands will reject this.")

    if scope.get("confirmed") is not True:
        errors.append("confirmed is not set to true — per the README, offensive commands "
                       "should refuse to run until this is explicitly set after scope verification.")

    # Known discrepancies from the Nov 14 2026 briefing packet vs. this repo's README table:
    # - Briefing says all hosts are on 172.16.XX.50-54
    # - README table lists cherrybomb (Ubuntu) as 172.25.XX.52
    # Flag this every time so nobody ships a config built on the wrong assumption.
    own = scope.get("own_targets", []) or []
    opp = scope.get("opponent_targets", []) or []
    all_targets = [t for t in (own + opp) if isinstance(t, str) and not looks_like_placeholder(t)]
    has_172_16 = any(t.startswith("172.16.") for t in all_targets)
    has_172_25 = any(t.startswith("172.25.") for t in all_targets)
    if has_172_16 and has_172_25:
        warn("Both 172.16.x.x and 172.25.x.x addresses are present. The briefing packet uses "
             "172.16.XX.50-54 for every host; this repo's README table lists cherrybomb as "
             "172.25.XX.52. Confirm the correct subnet with Green Team before relying on either.")
    elif has_172_25 and not has_172_16:
        warn("Only 172.25.x.x addresses found. Double-check this against the briefing packet, "
             "which specifies 172.16.XX.50-54 for all five hosts.")

    if errors:
        for e in errors:
            fail(e)
        print(f"\n{len(errors)} problem(s) found. Fix these before running any network command.")
        return 1

    ok("Scope file passed all checks.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
