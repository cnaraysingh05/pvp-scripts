#!/usr/bin/env python3
"""
preflight_check.py

Pre-competition sanity check for pvp-scripts scope files. Run this BEFORE
the competition starts (and again right after real addresses are confirmed)
to catch placeholder values, unresolved scope, out-of-grid hosts or
own/opponent overlap before anyone runs a network-touching command.

Validation is delegated to pvp_core.competition_host so this can never
disagree with what the actual wrappers enforce.

Usage:
    python3 tools/preflight_check.py --scope config/local/scope.json

Exit code is non-zero if any check fails, so it can be wired into a
Makefile / CI step / pre-run hook if you want to hard-block execution.
"""

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from pvp_core import competition_host, load_json

REQUIRED_KEYS = ["own_targets", "opponent_targets", "confirmed"]


def fail(msg):
    print("[FAIL] " + msg)


def warn(msg):
    print("[WARN] " + msg)


def ok(msg):
    print("[ OK ] " + msg)


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate a pvp-scripts scope config before use.")
    parser.add_argument("--scope", required=True, help="Path to scope.json")
    args = parser.parse_args()

    try:
        scope = load_json(args.scope)
    except FileNotFoundError:
        fail("Scope file not found: " + args.scope)
        return 1
    except json.JSONDecodeError as exc:
        fail("Scope file is not valid JSON: " + str(exc))
        return 1
    if not isinstance(scope, dict):
        fail("Scope file must contain a JSON object.")
        return 1

    errors = []
    warnings = []

    for key in REQUIRED_KEYS:
        if key not in scope:
            errors.append("Missing required key: " + repr(key))

    hosts = {"own_targets": set(), "opponent_targets": set()}
    for name, bucket in hosts.items():
        entries = scope.get(name)
        if not isinstance(entries, list):
            errors.append(name + " must be a list.")
            continue
        if not entries and name == "own_targets":
            errors.append("own_targets is empty; defense checks need at least one confirmed host.")
        for entry in entries:
            try:
                bucket.add(competition_host(entry))
            except ValueError as exc:
                errors.append(name + ": " + repr(entry) + ": " + str(exc))

    overlap = hosts["own_targets"] & hosts["opponent_targets"]
    if overlap:
        errors.append("Own and opponent targets overlap: " + ", ".join(sorted(overlap)))

    if scope.get("confirmed") is not True:
        errors.append("confirmed is not set to true; offensive commands refuse to run until it is.")

    if not scope.get("opponent_targets"):
        warnings.append("opponent_targets is empty - fine for defense only, but offensive commands will reject this.")

    for address in sorted(hosts["own_targets"] | hosts["opponent_targets"]):
        if not address.startswith("172.16."):
            warnings.append(address + " is inside 172.16.0.0/12 but outside the packet's 172.16.XX.50-54 grid. Confirm with Green Team.")

    if any(a.startswith("172.25.") for a in hosts["own_targets"] | hosts["opponent_targets"]):
        warnings.append("A 172.25.x.x address is present. The packet's host pages conflict (Ubuntu is listed as both 172.16.XX.52 and 172.25.XX.52). Confirm before relying on it.")

    for message in warnings:
        warn(message)
    if errors:
        for message in errors:
            fail(message)
        print("\n" + str(len(errors)) + " problem(s) found. Fix these before running any network command.")
        return 1

    ok("Scope file passed all checks.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
