#!/usr/bin/env python3
"""Collect timestamped inventory reports into a private directory; no system changes."""
import argparse
import json
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from pvp_core import command, private_run_dir, utc, write_json
from common import require_linux


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', default='/var/lib/pvp-scripts/reports')
    args = parser.parse_args()
    require_linux()
    folder = private_run_dir(args.output, 'baseline')
    summary = []
    for name in ('recon', 'review', 'persistence', 'service_inventory'):
        result = command([sys.executable, str(Path(__file__).with_name(name + '.py'))], timeout=600)
        if result['returncode'] == 0:
            try:
                report = json.loads(result['stdout'])
                write_json(folder / (name + '.json'), report)
                summary.append({'report': name, 'collected': True})
            except ValueError:
                summary.append({'report': name, 'collected': False, 'error': 'Invalid JSON report'})
        else:
            summary.append({'report': name, 'collected': False, 'error': result.get('error', result.get('stderr'))})
    write_json(folder / 'collection.json', {'utc': utc(), 'reports': summary,
        'note': 'Collected reports may contain per-section errors. Review these; collected does not mean clean.'})
    print(folder)
    return 0 if all(r['collected'] for r in summary) else 1


if __name__ == '__main__':
    try: sys.exit(main())
    except (OSError, ValueError, RuntimeError) as exc:
        print('ERROR: ' + str(exc), file=sys.stderr); sys.exit(2)
