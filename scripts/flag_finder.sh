#!/usr/bin/env bash
#
# scripts/flag_finder.sh
#
# Read-only filesystem sweep for likely flag files, meant to run ON a host
# you already have a shell on (your own box during the grace period, or a
# host you've legitimately gained access to during the competition). This
# does not touch the network and does not modify, move, or delete anything
# it finds — it only lists candidates so a human can confirm and submit
# them via /submit_flag.
#
# Per the briefing packet: do NOT alter a flag or its location once found.
# This script never writes to any file it discovers.
#
# Usage (run directly on the target host):
#   bash scripts/flag_finder.sh
#   bash scripts/flag_finder.sh --quick     # skip the slower full-disk sweep

set -uo pipefail

QUICK=false
if [[ "${1:-}" == "--quick" ]]; then
  QUICK=true
fi

echo "=== Documented flag locations ==="
for path in /root/flag.txt /user/flag.txt /home/*/flag.txt; do
  if [[ -f "$path" ]]; then
    echo "[FOUND] $path"
    echo "        sha256: $(sha256sum "$path" 2>/dev/null | awk '{print $1}')"
  fi
done

echo
echo "=== Common 'hidden' locations worth checking manually ==="
CANDIDATE_DIRS=(/opt /var/www /srv /tmp /var/tmp /var/backups /etc /var/log /home /usr/local)
for dir in "${CANDIDATE_DIRS[@]}"; do
  [[ -d "$dir" ]] || continue
  find "$dir" -maxdepth 4 -iname "*flag*" -type f 2>/dev/null
done

echo
echo "=== Files literally named like a flag, anywhere readable ==="
if $QUICK; then
  echo "(skipped — rerun without --quick for a full sweep, slower on big disks)"
else
  find / -xdev -iname "*flag*.txt" -type f \
    -not -path "/proc/*" -not -path "/sys/*" \
    2>/dev/null
fi

echo
echo "=== Recently modified files outside normal package locations ==="
echo "(flags are often dropped at build time — recent mtimes can be a tell)"
find /root /home /opt /srv /var/www -xdev -type f -mtime -30 2>/dev/null | head -n 50

echo
echo "Done. This list is read-only — confirm each hit manually before submitting."
echo "Remember: do not move, rename, or edit any flag file you find."
