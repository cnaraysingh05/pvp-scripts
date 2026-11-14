#!/usr/bin/env python3
"""
tools/password_gen.py

Generates strong, unique passwords for a list of usernames and prints
them directly in the "username,password" format the scoring engine's PCR
screen expects (one per line) — meant to save time during the 30-minute
grace period when you're rotating ~20 accounts across 5 hosts.

This does NOT submit anything or touch the network. It only prints text
for you to paste into the PCR form yourself, and optionally saves a local
copy (gitignored — never commit this file).

Usage:
    python3 tools/password_gen.py --users crazydave,penny,greenshadow

    # or from a file, one username per line:
    python3 tools/password_gen.py --users-file config/local/thehouse_users.txt

    # save a local copy for your own records (do NOT commit this):
    python3 tools/password_gen.py --users-file config/local/thehouse_users.txt \\
        --save config/local/thehouse_passwords.txt
"""

import argparse
import secrets
import string
import sys
from pathlib import Path

AMBIGUOUS = "Il1O0"


def generate_password(length: int = 16) -> str:
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*-_=+"
    alphabet = "".join(c for c in alphabet if c not in AMBIGUOUS)
    while True:
        pwd = "".join(secrets.choice(alphabet) for _ in range(length))
        # enforce at least one of each class so it survives typical complexity policies
        if (any(c.islower() for c in pwd)
                and any(c.isupper() for c in pwd)
                and any(c.isdigit() for c in pwd)
                and any(c in "!@#$%^&*-_=+" for c in pwd)):
            return pwd


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate PCR-ready username,password lines.")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--users", help="Comma-separated usernames")
    group.add_argument("--users-file", help="Path to a file with one username per line")
    parser.add_argument("--length", type=int, default=16, help="Password length (default 16)")
    parser.add_argument("--save", help="Optional path to also save the output (make sure this path is gitignored)")
    args = parser.parse_args()

    if args.users:
        users = [u.strip() for u in args.users.split(",") if u.strip()]
    else:
        path = Path(args.users_file)
        if not path.is_file():
            sys.exit(f"[ERROR] users file not found: {args.users_file}")
        users = [line.strip() for line in path.read_text().splitlines() if line.strip()]

    if not users:
        sys.exit("[ERROR] No usernames provided.")

    lines = [f"{user},{generate_password(args.length)}" for user in users]
    output = "\n".join(lines)

    print("Paste this block directly into the PCR 'Credentials' field:\n")
    print(output)

    if args.save:
        save_path = Path(args.save)
        save_path.parent.mkdir(parents=True, exist_ok=True)
        save_path.write_text(output + "\n")
        print(f"\n[SAVED] Also written to {save_path} — confirm this path is covered by .gitignore before you forget.")

    print(
        "\n[REMINDER] This only generates passwords. You still need to:\n"
        "  1. Actually set these passwords on the real accounts on the machine.\n"
        "  2. Submit the PCR in the scoring engine for any SCORED service account.\n"
        "  Submitting a PCR for a non-scored user does nothing."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
