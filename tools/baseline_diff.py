#!/usr/bin/env python3
"""Compare inventory JSON without losing added/removed objects in reordered arrays."""
import argparse
import json
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from pvp_core import load_json

VOLATILE = {'utc', 'UTC', 'collected_at'}


def normalize(value):
    if isinstance(value, dict):
        return {k: normalize(v) for k, v in sorted(value.items()) if k not in VOLATILE}
    if isinstance(value, list):
        return sorted((normalize(v) for v in value), key=lambda x: json.dumps(x, sort_keys=True))
    return value


def diff(before, after, path='$'):
    if isinstance(before, dict) and isinstance(after, dict):
        changes = []
        for key in sorted(set(before) | set(after)):
            here = path + '.' + key
            if key not in before:
                changes.append({'path': here, 'kind': 'added', 'after': after[key]})
            elif key not in after:
                changes.append({'path': here, 'kind': 'removed', 'before': before[key]})
            else:
                changes.extend(diff(before[key], after[key], here))
        return changes
    if before != after:
        return [{'path': path, 'kind': 'changed', 'before': before, 'after': after}]
    return []


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('before'); p.add_argument('after')
    a = p.parse_args()
    before, after = load_json(a.before), load_json(a.after)
    for key in ('host', 'HostName'):
        if key in before and before.get(key) != after.get(key):
            raise ValueError('Reports belong to different hosts.')
    changes = diff(normalize(before), normalize(after))
    print(json.dumps({'changes': changes, 'note': 'Changes are review leads, not malware verdicts. Collection errors remain visible.'}, indent=2))
    return 1 if changes else 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (OSError, ValueError) as exc:
        print('ERROR: ' + str(exc), file=sys.stderr); sys.exit(2)
