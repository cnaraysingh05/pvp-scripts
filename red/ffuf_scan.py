#!/usr/bin/env python3
"""
red/ffuf_scan.py

Directory/file fuzzing wrapper around ffuf, gated the same way as recon.py.
Intended for cherrybomb's HTTP service, but works against any in-scope
target running a web server.

Requires ffuf and a wordlist (defaults to a common SecLists path - adjust
--wordlist if yours lives elsewhere).

Usage (preview, safe, no network traffic):
    python3 red/ffuf_scan.py --scope config/local/scope.json --target 172.16.XX.52

Usage (actually run, once grace period is over and you're on provided Kali):
    python3 red/ffuf_scan.py --scope config/local/scope.json --target 172.16.XX.52 \\
        --run --grace-ended --provided-kali
"""

import argparse
import sys
from pathlib import Path

sys.path.insert(0, "red")
from runner import cli, execute  # noqa: E402
from scope_gate import add_common_args, require_authorized_target  # noqa: E402

DEFAULT_WORDLIST = "/usr/share/seclists/Discovery/Web-Content/common.txt"
DEFAULT_EXTENSIONS = "php,html,txt,bak,zip,js"


def build_command(directory: Path, target: str, port: int, wordlist: str, extensions: str, threads: int) -> list:
    url = f"http://{target}:{port}/FUZZ"
    return [
        "ffuf",
        "-u", url,
        "-w", wordlist,
        "-e", extensions,
        "-t", str(threads),
        "-mc", "200,204,301,302,307,401,403",
        "-of", "json",
        "-o", str(directory / "ffuf.json"),
    ]


def main() -> int:
    parser = argparse.ArgumentParser(description="Gated ffuf wrapper for in-scope web targets.")
    add_common_args(parser)
    parser.add_argument("--port", type=int, default=80, help="Target port (default 80)")
    parser.add_argument("--wordlist", default=DEFAULT_WORDLIST, help=f"Wordlist path (default {DEFAULT_WORDLIST})")
    parser.add_argument("--extensions", default=DEFAULT_EXTENSIONS, help=f"Comma-separated extensions (default {DEFAULT_EXTENSIONS})")
    parser.add_argument("--threads", type=int, default=40, help="ffuf thread count (default 40)")
    args = parser.parse_args()

    if not 1 <= args.port <= 65535:
        raise ValueError("--port must be 1..65535.")
    if args.threads < 1:
        raise ValueError("--threads must be a positive integer.")

    target = require_authorized_target(args)
    if args.run and not Path(args.wordlist).is_file():
        raise ValueError("Wordlist not found: " + args.wordlist)

    def build(directory):
        return [build_command(directory, target, args.port, args.wordlist, args.extensions, args.threads)]

    return execute(args, target, "ffuf", build)


if __name__ == "__main__":
    sys.exit(cli(main))
