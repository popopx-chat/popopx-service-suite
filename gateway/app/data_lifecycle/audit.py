# Copyright (c) 2026 POPOPX (popopx.chat)
# SPDX-License-Identifier: AGPL-3.0-only
"""Metadata-only audit trail for the data lifecycle.

The privacy contract of this table is enforced by its *shape*, not by a policy
someone has to remember:

* the ``data_lifecycle_audit`` table has no column that could hold a message
  body, a file, a key, a URL or a free-form ``detail`` string;
* :func:`record` accepts ``task_id``, ``principal``, ``tool``, ``mode``,
  ``action``, ``status_code`` and a timestamp — keyword-only, so a caller
  cannot "just add" the payload that caused the decision; the only way to pass
  one is a ``TypeError``;
* ``action`` and ``mode`` are closed sets, so a typo cannot invent a new event
  class that a reviewer would not recognise;
* the text fields are trimmed and capped, and a cap is also the refusal of a
  body pasted into ``principal`` — 120 characters is a principal name, not a
  transcript.

The table is bounded like ``admin_token_audit``: a long-lived gateway should
not be able to fill its own disk with its own audit trail. ``AUDIT_RETENTION``
rows is far more history than an incident review needs.
"""

from __future__ import annotations

import time
from typing import Any, Dict, List, Optional

from app.data_lifecycle.policy import MODES

__all__ = [
    "ACTIONS",
    "AUDIT_FIELDS",
    "AUDIT_RETENTION",
    "list_audit",
    "record",
    "self_test",
]

#: Keep the table useful without letting it grow without bound.
AUDIT_RETENTION = 5000

#: The event classes this table can express. A caller with a new kind of event
#: extends this tuple deliberately — which is the review gate.
ACTIONS = ("admit", "erase", "sweep", "reject")

#: The columns of ``data_lifecycle_audit``, minus the autoincrement id. Every
#: value that can land in the table is one of these; there is no tenth field.
AUDIT_FIELDS = ("task_id", "principal", "tool", "mode", "action", "status_code", "created_at_ms")


def _now_ms() -> int:
    return int(time.time() * 1000)


def _clean(value: Any, limit: int) -> str:
    """One line, trimmed, capped. Newlines are folded so a row stays one row."""
    text = " ".join(str(value if value is not None else "").split())
    return text[:limit]


def record(
    db: Any,
    *,
    action: str,
    mode: str = "",
    task_id: Optional[str] = None,
    principal: Any = "",
    tool: Any = "",
    status_code: Optional[int] = None,
    now_ms: Optional[int] = None,
) -> None:
    """Append one audit row. There is deliberately no ``detail`` argument.

    ``mode`` is empty for events that are not about one task (a sweep), and
    ``task_id`` is ``None`` for the same reason. ``action`` must be one of
    :data:`ACTIONS`; everything else is validated or capped.
    """
    if action not in ACTIONS:
        raise ValueError("action must be one of %s" % ", ".join(ACTIONS))
    clean_mode = str(mode or "").strip()
    if clean_mode and clean_mode not in MODES:
        raise ValueError("mode must be empty or one of %s" % ", ".join(MODES))
    clean_task = _clean(task_id, 96) if task_id is not None else None
    timestamp = int(now_ms if now_ms is not None else _now_ms())
    db.execute(
        "INSERT INTO data_lifecycle_audit"
        " (task_id, principal, tool, mode, action, status_code, created_at_ms)"
        " VALUES (?, ?, ?, ?, ?, ?, ?)",
        (
            clean_task,
            _clean(principal, 120),
            _clean(tool, 120),
            clean_mode,
            action,
            int(status_code) if status_code is not None else None,
            timestamp,
        ),
    )
    _prune(db, AUDIT_RETENTION)


def _prune(db: Any, keep: int) -> None:
    db.execute(
        "DELETE FROM data_lifecycle_audit WHERE id NOT IN"
        " (SELECT id FROM data_lifecycle_audit ORDER BY id DESC LIMIT ?)",
        (max(1, int(keep)),),
    )


def list_audit(db: Any, *, limit: int = 100) -> List[Dict[str, Any]]:
    rows = db.query(
        "SELECT id, task_id, principal, tool, mode, action, status_code, created_at_ms"
        " FROM data_lifecycle_audit ORDER BY id DESC LIMIT ?",
        (max(1, min(int(limit), 1000)),),
    )
    return [
        {
            "id": int(row["id"]),
            "task_id": row["task_id"],
            "principal": str(row["principal"] or ""),
            "tool": str(row["tool"] or ""),
            "mode": str(row["mode"] or ""),
            "action": str(row["action"] or ""),
            "status_code": row["status_code"],
            "created_at_ms": int(row["created_at_ms"]),
        }
        for row in rows
    ]


def self_test() -> List[str]:
    """The table's shape, the closed sets and the capping, against real SQLite."""
    import tempfile
    from pathlib import Path

    from app.database import Database

    checks: List[str] = []

    def check(name: str, condition: bool) -> None:
        if not condition:
            raise AssertionError("audit self_test failed: %s" % name)
        checks.append(name)

    def refuses(name: str, call: Any) -> None:
        try:
            call()
        except (ValueError, TypeError):
            checks.append(name)
            return
        raise AssertionError("audit self_test: %s was accepted" % name)

    with tempfile.TemporaryDirectory(prefix="popopx-audit-") as tmp:
        db = Database(Path(tmp) / "audit.db")
        try:
            columns = {
                str(row["name"])
                for row in db.query("PRAGMA table_info(data_lifecycle_audit)")
            }
            check("the_audit_table_has_metadata_columns_only",
                  columns == {"id"} | set(AUDIT_FIELDS))
            check("no_audit_column_could_hold_content",
                  not any(word in column for column in columns
                          for word in ("body", "content", "payload", "message", "secret", "file")))

            record(
                db, action="admit", mode="zero_retention", task_id="task-1",
                principal="operator-a", tool="summarize", status_code=200, now_ms=1_700_000_000_000,
            )
            row = list_audit(db)[0]
            check("a_row_carries_exactly_the_metadata_fields",
                  set(row) == {"id"} | set(AUDIT_FIELDS))
            check("the_row_keeps_what_it_was_given",
                  row["task_id"] == "task-1" and row["principal"] == "operator-a"
                  and row["tool"] == "summarize" and row["mode"] == "zero_retention"
                  and row["action"] == "admit" and row["status_code"] == 200
                  and row["created_at_ms"] == 1_700_000_000_000)
            record(db, action="sweep", status_code=200, now_ms=1_700_000_000_001)
            sweep_row = list_audit(db)[0]
            check("a_sweep_has_no_task_and_no_mode",
                  sweep_row["task_id"] is None and sweep_row["mode"] == "" and sweep_row["action"] == "sweep")

            refuses("an_unknown_action_is_refused",
                    lambda: record(db, action="debug", mode="ephemeral"))
            refuses("an_unknown_mode_is_refused",
                    lambda: record(db, action="admit", mode="forever"))
            refuses("a_content_argument_does_not_exist",
                    lambda: record(db, action="admit", mode="ephemeral", payload="the secret plan"))
            refuses("a_detail_argument_does_not_exist",
                    lambda: record(db, action="admit", mode="ephemeral", detail="why"))

            long_text = "x" * 500
            record(db, action="erase", task_id=None, principal=long_text, tool="line\nbreak",
                   status_code=200, now_ms=1_700_000_000_002)
            capped = list_audit(db)[0]
            check("a_long_field_is_capped", len(capped["principal"]) == 120)
            check("a_field_stays_on_one_line", "\n" not in capped["tool"] and capped["tool"] == "line break")

            for index in range(6):
                record(db, action="admit", mode="ephemeral", task_id="bulk-%d" % index,
                       now_ms=1_700_000_000_100 + index)
            _prune(db, 3)
            check("the_table_can_be_bounded", db.scalar("SELECT COUNT(*) FROM data_lifecycle_audit") == 3)

            sentinel = "zdr-sentinel-9f3c1a"
            record(db, action="admit", mode="zero_retention", task_id="t" * 200,
                   principal=sentinel[:120], now_ms=1_700_000_000_200)
            capped_task = list_audit(db)[0]
            check("a_long_task_id_is_capped", len(capped_task["task_id"]) == 96)
            check("the_schema_has_no_column_for_the_sentinel_to_hide_in",
                  sentinel not in " ".join(sorted(columns)))
        finally:
            db.close()

    return checks
