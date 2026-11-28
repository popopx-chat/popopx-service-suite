# Copyright (c) 2026 POPOPX (popopx.chat)
# SPDX-License-Identifier: AGPL-3.0-only
"""Data-retention policies: the three modes, their bounds and their rows.

The three modes are a privacy contract, not a preference:

``zero_retention``  task bodies, temporary files and agent context live in
                    process memory only and are erased at first delivery or
                    completion. The gateway must not persist a task row, a
                    state blob or a file — the audit trail is the only trace.
``ephemeral``       temporary state and short-lived attachments may be stored,
                    but only until ``temporary_ttl_seconds`` expires; the
                    cleanup sweep (and the erase API) removes them.
``user_owned``      the user's own device keeps the authoritative copy. The
                    gateway stores metadata, never a copy of the content.

Built-in policies are *virtual*: they are constants in this module, so a fresh
database needs no seeding and a read never writes. A ``PUT`` against a built-in
id stores only an override row (the ephemeral TTL is the only field worth
overriding); the mode of a built-in id can never change, which keeps
``policy_id = "zero_retention"`` from ever meaning something weaker.

Every timestamp is epoch milliseconds, matching the rest of the suite.
"""

from __future__ import annotations

import re
import time
from typing import Any, Dict, List, Mapping, Optional

__all__ = [
    "DEFAULT_EPHEMERAL_TTL_SECONDS",
    "MAX_TTL_SECONDS",
    "MIN_TTL_SECONDS",
    "MODES",
    "MODE_EPHEMERAL",
    "MODE_USER_OWNED",
    "MODE_ZERO_RETENTION",
    "builtin_policies",
    "get_policy",
    "list_policies",
    "normalize_policy",
    "policy_id_is_valid",
    "self_test",
    "upsert_policy",
]

MODE_ZERO_RETENTION = "zero_retention"
MODE_EPHEMERAL = "ephemeral"
MODE_USER_OWNED = "user_owned"

#: Closed set. A typo in a `PUT` is a 400, not a fourth, quietly weaker mode.
MODES = (MODE_ZERO_RETENTION, MODE_EPHEMERAL, MODE_USER_OWNED)

#: TTL bounds for the ephemeral mode. The floor keeps a "temporary" store from
#: being configured shorter than the sweep cadence; the ceiling keeps an
#: operator from turning ephemeral into a year-long archive by accident.
MIN_TTL_SECONDS = 60
MAX_TTL_SECONDS = 30 * 24 * 60 * 60
DEFAULT_EPHEMERAL_TTL_SECONDS = 60 * 60

#: A policy id is also a URL segment and a scope name, so the grammar is strict.
POLICY_ID_RE = re.compile(r"^[a-z][a-z0-9_-]{0,47}$")


def _now_ms() -> int:
    return int(time.time() * 1000)


def policy_id_is_valid(policy_id: Any) -> bool:
    return bool(POLICY_ID_RE.match(str(policy_id or "")))


def _ttl_seconds(value: Any) -> int:
    """A TTL as an int, refusing bools and floats that merely look integral.

    ``bool`` is an ``int`` subclass, so ``isinstance(True, int)`` is true and a
    JSON ``true`` would otherwise configure a one-second TTL.
    """
    if isinstance(value, bool):
        raise ValueError("temporary_ttl_seconds must be an integer, not a boolean")
    if isinstance(value, float):
        if not value.is_integer():
            raise ValueError("temporary_ttl_seconds must be a whole number of seconds")
        value = int(value)
    if not isinstance(value, int):
        raise ValueError("temporary_ttl_seconds must be an integer")
    if value < MIN_TTL_SECONDS or value > MAX_TTL_SECONDS:
        raise ValueError(
            "temporary_ttl_seconds must be between %d and %d" % (MIN_TTL_SECONDS, MAX_TTL_SECONDS)
        )
    return int(value)


def normalize_policy(raw: Mapping[str, Any]) -> Dict[str, Any]:
    """Validate one policy body. Raises ``ValueError`` with the reason.

    ``temporary_ttl_seconds`` is meaningful only for ``ephemeral``; supplying it
    for the other two modes is refused instead of ignored, because a caller who
    believes zero-retention data has a TTL has misunderstood the contract.
    """
    if not isinstance(raw, Mapping):
        raise ValueError("a policy body must be a JSON object")
    mode = str(raw.get("mode") or "").strip()
    if mode not in MODES:
        raise ValueError("mode must be one of %s" % ", ".join(MODES))
    ttl_raw = raw.get("temporary_ttl_seconds")
    if mode == MODE_EPHEMERAL:
        ttl = (
            DEFAULT_EPHEMERAL_TTL_SECONDS
            if ttl_raw in (None, "")
            else _ttl_seconds(ttl_raw)
        )
    else:
        if ttl_raw not in (None, ""):
            raise ValueError("temporary_ttl_seconds only applies to the ephemeral mode")
        ttl = None
    return {"mode": mode, "temporary_ttl_seconds": ttl}


def builtin_policies() -> List[Dict[str, Any]]:
    """The three modes as policies, with ids equal to their mode names."""
    return [
        {
            "policy_id": MODE_ZERO_RETENTION,
            "mode": MODE_ZERO_RETENTION,
            "temporary_ttl_seconds": None,
            "builtin": True,
        },
        {
            "policy_id": MODE_EPHEMERAL,
            "mode": MODE_EPHEMERAL,
            "temporary_ttl_seconds": DEFAULT_EPHEMERAL_TTL_SECONDS,
            "builtin": True,
        },
        {
            "policy_id": MODE_USER_OWNED,
            "mode": MODE_USER_OWNED,
            "temporary_ttl_seconds": None,
            "builtin": True,
        },
    ]


def _row_to_policy(row: Any) -> Dict[str, Any]:
    policy_id = str(row["policy_id"])
    ttl = row["temporary_ttl_seconds"]
    return {
        "policy_id": policy_id,
        "mode": str(row["mode"]),
        "temporary_ttl_seconds": int(ttl) if ttl is not None else None,
        "builtin": policy_id in MODES,
        "created_at_ms": int(row["created_at_ms"]),
        "updated_at_ms": int(row["updated_at_ms"]),
    }


def get_policy(db: Any, policy_id: Any) -> Optional[Dict[str, Any]]:
    """One policy by id, built-in defaults included, ``None`` when unknown."""
    clean = str(policy_id or "").strip()
    if not policy_id_is_valid(clean):
        return None
    row = db.query_one("SELECT * FROM data_lifecycle_policies WHERE policy_id = ?", (clean,))
    if row is not None:
        return _row_to_policy(row)
    for policy in builtin_policies():
        if policy["policy_id"] == clean:
            return dict(policy)
    return None


def list_policies(db: Any) -> List[Dict[str, Any]]:
    """Built-ins first (with any stored override), then custom policies by id."""
    rows = {
        str(row["policy_id"]): _row_to_policy(row)
        for row in db.query("SELECT * FROM data_lifecycle_policies ORDER BY policy_id")
    }
    out: List[Dict[str, Any]] = []
    for policy in builtin_policies():
        merged = dict(policy)
        override = rows.pop(policy["policy_id"], None)
        if override is not None:
            merged["temporary_ttl_seconds"] = override["temporary_ttl_seconds"]
            merged["created_at_ms"] = override["created_at_ms"]
            merged["updated_at_ms"] = override["updated_at_ms"]
        out.append(merged)
    out.extend(rows[key] for key in sorted(rows))
    return out


def upsert_policy(
    db: Any, policy_id: Any, raw: Mapping[str, Any], *, now_ms: Optional[int] = None
) -> Dict[str, Any]:
    """Create or update one policy. Built-in ids keep their mode forever."""
    clean = str(policy_id or "").strip()
    if not policy_id_is_valid(clean):
        raise ValueError(
            "policy_id must match %s (lowercase letter, then lowercase/digits/_/-)"
            % POLICY_ID_RE.pattern
        )
    normalized = normalize_policy(raw)
    if clean in MODES and normalized["mode"] != clean:
        raise ValueError("the built-in policy %r keeps its mode %r" % (clean, clean))
    timestamp = int(now_ms if now_ms is not None else _now_ms())
    existing = db.query_one(
        "SELECT policy_id FROM data_lifecycle_policies WHERE policy_id = ?", (clean,)
    )
    if existing is None:
        db.execute(
            "INSERT INTO data_lifecycle_policies"
            " (policy_id, mode, temporary_ttl_seconds, created_at_ms, updated_at_ms)"
            " VALUES (?, ?, ?, ?, ?)",
            (clean, normalized["mode"], normalized["temporary_ttl_seconds"], timestamp, timestamp),
        )
    else:
        db.execute(
            "UPDATE data_lifecycle_policies SET mode = ?, temporary_ttl_seconds = ?, updated_at_ms = ?"
            " WHERE policy_id = ?",
            (normalized["mode"], normalized["temporary_ttl_seconds"], timestamp, clean),
        )
    stored = get_policy(db, clean)
    if stored is None:  # pragma: no cover — the write above either landed or raised
        raise RuntimeError("policy %r vanished after its own write" % clean)
    return stored


def self_test() -> List[str]:
    """The mode set, the TTL bounds and the built-in/custom row semantics."""
    import tempfile
    from pathlib import Path

    from app.database import Database

    checks: List[str] = []

    def check(name: str, condition: bool) -> None:
        if not condition:
            raise AssertionError("policy self_test failed: %s" % name)
        checks.append(name)

    def refuses(name: str, call: Any) -> None:
        try:
            call()
        except ValueError:
            checks.append(name)
            return
        raise AssertionError("policy self_test: %s was accepted" % name)

    check("there_are_exactly_three_modes", MODES == (MODE_ZERO_RETENTION, MODE_EPHEMERAL, MODE_USER_OWNED))
    check("every_builtin_policy_id_is_its_mode",
          [policy["policy_id"] for policy in builtin_policies()] == list(MODES))
    check("only_the_ephemeral_builtin_carries_a_default_ttl",
          [policy["temporary_ttl_seconds"] for policy in builtin_policies()]
          == [None, DEFAULT_EPHEMERAL_TTL_SECONDS, None])
    check("the_ttl_bounds_are_ordered", 0 < MIN_TTL_SECONDS <= DEFAULT_EPHEMERAL_TTL_SECONDS <= MAX_TTL_SECONDS)
    check("a_policy_id_accepts_lowercase_and_hyphens", policy_id_is_valid("edge-cache_v2"))
    check("a_policy_id_rejects_uppercase_and_leading_digits",
          not policy_id_is_valid("Edge") and not policy_id_is_valid("2fast"))

    check("zero_retention_needs_no_ttl",
          normalize_policy({"mode": "zero_retention"})
          == {"mode": "zero_retention", "temporary_ttl_seconds": None})
    check("ephemeral_defaults_its_ttl",
          normalize_policy({"mode": "ephemeral"})["temporary_ttl_seconds"]
          == DEFAULT_EPHEMERAL_TTL_SECONDS)
    check("ephemeral_accepts_an_integral_float",
          normalize_policy({"mode": "ephemeral", "temporary_ttl_seconds": 120.0})["temporary_ttl_seconds"] == 120)
    refuses("an_unknown_mode_is_refused", lambda: normalize_policy({"mode": "forever"}))
    refuses("a_missing_mode_is_refused", lambda: normalize_policy({}))
    refuses("a_non_ephemeral_ttl_is_refused",
            lambda: normalize_policy({"mode": "zero_retention", "temporary_ttl_seconds": 60}))
    refuses("a_boolean_ttl_is_refused",
            lambda: normalize_policy({"mode": "ephemeral", "temporary_ttl_seconds": True}))
    refuses("a_fractional_ttl_is_refused",
            lambda: normalize_policy({"mode": "ephemeral", "temporary_ttl_seconds": 90.5}))
    refuses("a_ttl_below_the_floor_is_refused",
            lambda: normalize_policy({"mode": "ephemeral", "temporary_ttl_seconds": MIN_TTL_SECONDS - 1}))
    refuses("a_ttl_above_the_ceiling_is_refused",
            lambda: normalize_policy({"mode": "ephemeral", "temporary_ttl_seconds": MAX_TTL_SECONDS + 1}))
    refuses("a_non_mapping_body_is_refused", lambda: normalize_policy(["mode"]))

    with tempfile.TemporaryDirectory(prefix="popopx-policy-") as tmp:
        db = Database(Path(tmp) / "policy.db")
        try:
            listed = list_policies(db)
            check("a_fresh_database_lists_the_three_builtins_without_seeding",
                  [policy["policy_id"] for policy in listed] == list(MODES)
                  and db.scalar("SELECT COUNT(*) FROM data_lifecycle_policies") == 0)
            check("a_builtin_resolves_without_a_row",
                  get_policy(db, "ephemeral")["temporary_ttl_seconds"] == DEFAULT_EPHEMERAL_TTL_SECONDS)
            check("an_unknown_policy_is_none",
                  get_policy(db, "nope") is None and get_policy(db, "Not A Slug") is None)

            custom = upsert_policy(
                db, "edge-daily", {"mode": "ephemeral", "temporary_ttl_seconds": 7200}, now_ms=1_700_000_000_000
            )
            check("a_custom_policy_is_created",
                  custom["policy_id"] == "edge-daily" and custom["builtin"] is False
                  and custom["temporary_ttl_seconds"] == 7200)
            overridden = upsert_policy(
                db, "ephemeral", {"mode": "ephemeral", "temporary_ttl_seconds": 300}, now_ms=1_700_000_000_001
            )
            check("a_builtin_ttl_can_be_overridden",
                  overridden["builtin"] is True and overridden["temporary_ttl_seconds"] == 300
                  and db.scalar("SELECT COUNT(*) FROM data_lifecycle_policies") == 2)
            refuses("a_builtin_mode_cannot_change",
                    lambda: upsert_policy(db, "zero_retention", {"mode": "user_owned"}))
            refuses("an_invalid_policy_id_is_refused",
                    lambda: upsert_policy(db, "bad id", {"mode": "ephemeral"}))
            ids = [policy["policy_id"] for policy in list_policies(db)]
            check("the_list_keeps_builtins_first_and_sorts_customs",
                  ids == ["zero_retention", "ephemeral", "user_owned", "edge-daily"])
            check("the_listed_builtin_carries_its_override",
                  list_policies(db)[1]["temporary_ttl_seconds"] == 300)
        finally:
            db.close()

    return checks
