# Copyright (c) 2026 POPOPX (popopx.chat)
# SPDX-License-Identifier: AGPL-3.0-only
"""The POPOPX service-account gateway.

Import order matters once and only once: :mod:`app.config` must be loaded
before anything that can read the environment, because every module below it
takes its settings as constructor arguments rather than reaching for
``os.environ`` itself. That is what makes the gateway testable without a node,
and what keeps a credential out of a log line by construction.
"""

__version__ = "1.0.0"
__all__ = ["__version__"]
