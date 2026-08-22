#!/usr/bin/env python3
"""Generate middleware/express/config.json from config/defaults.py.

The Node runtime cannot import Python; this script is the ONE-WAY mirror,
and tests/parity asserts the two agree so drift fails CI instead of
passing silently (plan Section 0: config consolidation).
"""

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from config import defaults  # noqa: E402


def main() -> None:
    out_path = ROOT / "middleware" / "express" / "config.json"
    payload = dict(defaults.ALL_DEFAULTS)
    out_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    print(f"wrote {out_path} ({len(payload)} keys)")


if __name__ == "__main__":
    main()
