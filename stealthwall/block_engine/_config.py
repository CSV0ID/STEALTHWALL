"""Config bridge: every block_engine module imports tuned values through
this shim so config/defaults.py stays the single source of truth.

Star re-export (not hand-picked names) so a new constant added to
config/defaults.py can never be forgotten here."""

from __future__ import annotations

import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from config.defaults import *  # noqa: F401,F403
from config import defaults as _d  # noqa: F401
