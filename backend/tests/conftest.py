from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

os.environ.setdefault("AEGIS_GENAI_PROVIDER", "offline")


@pytest.fixture(autouse=True)
def reset_perimeter_state():
    from app.security import GLOBAL_BLOCKLIST, GLOBAL_RATE_TRACKER

    GLOBAL_BLOCKLIST._blocked.clear()
    GLOBAL_RATE_TRACKER._request_times.clear()
    GLOBAL_RATE_TRACKER._endpoints.clear()
    GLOBAL_RATE_TRACKER._failed_login_ip.clear()
    GLOBAL_RATE_TRACKER._failed_login_user.clear()
    yield
