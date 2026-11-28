# Copyright (c) 2026 POPOPX (popopx.chat)
# SPDX-License-Identifier: AGPL-3.0-only
"""Three-tier data lifecycle for the privacy-aware compute runtime.

The package is split so each decision has exactly one owner:

``policy``          what an operator may configure — the three retention modes,
                    the TTL bounds, and the policy rows in SQLite;
``retention``       the time arithmetic every other module shares;
``audit``           the metadata-only audit trail (no column can hold content);
``policy_engine``   the admission path, including the in-memory only broker
                    behind ``zero_retention``;
``cleanup``         expiry sweeps and the explicit erasure requests.

Import order is acyclic: ``policy`` imports nothing from the package,
``retention`` and ``audit`` import ``policy``, and the two runtime modules import
all three. Nothing here imports ``app.main`` — the gateways' routes call into
this package, never the other way round.
"""

__all__: list = []
