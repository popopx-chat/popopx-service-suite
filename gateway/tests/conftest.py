# Copyright (c) 2026 POPOPX (popopx.chat)
# SPDX-License-Identifier: AGPL-3.0-only
"""Make `app` importable when pytest is started from anywhere."""

import sys
from pathlib import Path

GATEWAY_DIR = Path(__file__).resolve().parents[1]
if str(GATEWAY_DIR) not in sys.path:
    sys.path.insert(0, str(GATEWAY_DIR))