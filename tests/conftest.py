import os
import sys
from pathlib import Path

# Ensure root stealthwall package and submodules are on sys.path for test discovery
ROOT = Path(__file__).resolve().parent.parent / "stealthwall"
for p in (
    str(ROOT.parent),
    str(ROOT),
    str(ROOT / "middleware" / "fastapi"),
    str(ROOT / "block_engine"),
    str(ROOT / "models"),
    str(ROOT / "config"),
    str(ROOT / "data"),
):
    if p not in sys.path:
        sys.path.insert(0, p)

os.environ.setdefault("STEALTHWALL_ALLOW_NO_IPTABLES", "1")
