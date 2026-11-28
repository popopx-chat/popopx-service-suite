# Copyright (c) 2026 POPOPX (popopx.chat)
# SPDX-License-Identifier: AGPL-3.0-only
"""Retention arithmetic shared by the engine, the sweep and the API.

Three rules, each one line of arithmetic that exists in exactly one place:

* an ephemeral state blob expires at ``created_at_ms + ttl`` and is expired
  *at* that instant, not one tick later — a sweep that runs at the boundary
  must already be allowed to delete it;
* a missing expiry (``None``) never expires, which is how ``user_owned``
  metadata and in-flight zero-retention work are represented;
* every mode has a one-line storage story that the API and the audit trail can
  quote without re-deriving it from prose.

Seconds are configuration, milliseconds are storage: the conversion happens
once, in :func:`expires_at_ms`, so no other module multiplies by 1000.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from app.data_lifecycle.policy import (
    MODE_EPHEMERAL,
    MODE_USER_OWNED,
    MODE_ZERO_RETENTION,
    MODES,
)

__all__ = [
    "expires_at_ms",
    "is_expired",
    "remaining_seconds",
    "retention_story",
    "self_test",
]


def expires_at_ms(created_at_ms: int, ttl_seconds: Optional[int]) -> Optional[int]:
    """The millisecond instant a temporary row dies, or ``None`` for never."""
    if ttl_seconds is None:
        return None
    return int(created_at_ms) + int(ttl_seconds) * 1000


def is_expired(expires_at_ms_value: Optional[int], now_ms: int) -> bool:
    """Is this row expired at ``now_ms``? No expiry means no."""
    if expires_at_ms_value is None:
        return False
    return int(now_ms) >= int(expires_at_ms_value)


def remaining_seconds(expires_at_ms_value: Optional[int], now_ms: int) -> int:
    """Whole seconds left before expiry; 0 once expired and 0 for no expiry.

    The "no expiry" case returns 0 rather than a sentinel because every caller
    that asks this question is rendering a countdown; the mode, not the number,
    is what distinguishes "kept forever" from "gone".
    """
    if expires_at_ms_value is None:
        return 0
    remaining_ms = int(expires_at_ms_value) - int(now_ms)
    if remaining_ms <= 0:
        return 0
    return remaining_ms // 1000


def retention_story(mode: str, ttl_seconds: Optional[int] = None) -> Dict[str, Any]:
    """What one mode promises about content, in the words the API can serve.

    This is the single source for the ``GET /api/v1/data-lifecycle/policies``
    description and for the README's table; a change here changes both.
    """
    if mode not in MODES:
        raise ValueError("unknown retention mode %r" % (mode,))
    if mode == MODE_ZERO_RETENTION:
        return {
            "content_persisted": False,
            "content_location": "process_memory",
            "erased_on": "first_delivery_or_completion",
            "max_age_seconds": 0,
        }
    if mode == MODE_EPHEMERAL:
        if ttl_seconds is None:
            raise ValueError("the ephemeral mode needs its ttl_seconds")
        return {
            "content_persisted": True,
            "content_location": "gateway_sqlite_and_temp_area",
            "erased_on": "expiry_or_erase_request",
            "max_age_seconds": int(ttl_seconds),
        }
    return {
        "content_persisted": False,
        "content_location": "user_device",
        "erased_on": "device_policy",
        "max_age_seconds": 0,
    }


def self_test() -> List[str]:
    """The boundary conditions the sweep depends on."""
    checks: List[str] = []

    def check(name: str, condition: bool) -> None:
        if not condition:
            raise AssertionError("retention self_test failed: %s" % name)
        checks.append(name)

    def refuses(name: str, call: Any) -> None:
        try:
            call()
        except ValueError:
            checks.append(name)
            return
        raise AssertionError("retention self_test: %s was accepted" % name)

    check("seconds_become_milliseconds_once",
          expires_at_ms(1_000, 60) == 61_000 and expires_at_ms(1_000, None) is None)
    check("a_row_is_not_expired_before_its_instant", not is_expired(61_000, 60_999))
    check("a_row_is_expired_at_its_instant", is_expired(61_000, 61_000))
    check("a_row_is_expired_after_its_instant", is_expired(61_000, 90_000))
    check("no_expiry_never_expires", not is_expired(None, 10 ** 15))
    check("the_countdown_is_whole_seconds", remaining_seconds(61_500, 60_000) == 1)
    check("an_expired_countdown_is_zero", remaining_seconds(61_000, 61_000) == 0)
    check("a_missing_expiry_counts_down_to_zero", remaining_seconds(None, 1) == 0)

    zero = retention_story("zero_retention")
    ephemeral = retention_story("ephemeral", 3600)
    owned = retention_story("user_owned")
    check("zero_retention_persists_nothing", zero["content_persisted"] is False
          and zero["content_location"] == "process_memory")
    check("ephemeral_persists_for_its_ttl", ephemeral["content_persisted"] is True
          and ephemeral["max_age_seconds"] == 3600)
    check("user_owned_lives_on_the_device", owned["content_persisted"] is False
          and owned["content_location"] == "user_device")
    refuses("an_unknown_mode_has_no_story", lambda: retention_story("forever"))
    refuses("ephemeral_without_a_ttl_has_no_story", lambda: retention_story("ephemeral"))

    return checks
