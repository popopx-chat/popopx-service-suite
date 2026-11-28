# Copyright (c) 2026 POPOPX (popopx.chat)
# SPDX-License-Identifier: AGPL-3.0-only
"""The admission path for a task under one data-lifecycle policy.

The three modes produce three different receipts, and only one of them is
allowed to leave a row behind:

* **zero_retention** — the payload is handed to :class:`ZeroRetentionBroker`,
  delivered at most once, and wiped from memory in a ``finally``. No task row,
  no state row, no file: the only durable trace is the audit row, which by
  construction carries metadata and nothing else. A delivery that raises still
  wipes — "first delivery" failing is not a reason to keep the plaintext.
* **ephemeral** — a metadata task row plus an optional temporary state blob,
  both stamped with an expiry the sweep enforces.
* **user_owned** — a metadata task row only; the content is on the user's
  device and the gateway never receives a copy to store.

The broker deliberately keeps one copy per task id: a second submission under
the same id is refused instead of silently replacing the first, because an id
collision is a caller bug and the wrong resolution loses work.

Everything here is standard library, so the wheel-less interpreter can run the
whole suite: the guarantee this module makes is about *which store* a byte
lands in, and that is testable without FastAPI.
"""

from __future__ import annotations

import base64
import json
import re
import threading
import time
from typing import Any, Callable, Dict, List, Optional

from app.data_lifecycle import audit
from app.data_lifecycle import policy as policy_module
from app.data_lifecycle import retention

__all__ = [
    "ZeroRetentionBroker",
    "admit_task",
    "state_json",
    "self_test",
]

#: The task id is quoted in audit rows and erase requests, so it is a slug, not
#: a free-form string. Colons and dots are allowed because tools namespace ids.
TASK_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,95}$")


def _now_ms() -> int:
    return int(time.time() * 1000)


def _as_bytes(payload: Any) -> bytes:
    if isinstance(payload, (bytes, bytearray)):
        return bytes(payload)
    if isinstance(payload, str):
        return payload.encode("utf-8")
    raise ValueError("a zero-retention payload must be str or bytes")


def _wipe(buffer: bytearray) -> None:
    """Overwrite a buffer in place before dropping the last reference.

    This is not a defence against a process-memory dump — Python may have
    copied the bytes somewhere already — it is the ordinary hygiene that keeps
    a long-lived gateway from holding plaintext in a freed-but-reusable
    allocation. The guarantee that matters is the *absence* of a database row,
    which is asserted separately.
    """
    for index in range(len(buffer)):
        buffer[index] = 0


class ZeroRetentionBroker:
    """In-memory-only staging for ``zero_retention`` payloads.

    One entry per task id; delivery pops the entry *before* calling the sink,
    so a sink that raises cannot leave the plaintext behind. The lock makes the
    pop-and-wipe atomic with respect to a concurrent erase.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._entries: Dict[str, Dict[str, Any]] = {}

    def submit(self, task_id: str, payload: Any, *, workspace_id: Optional[str] = None) -> None:
        data = _as_bytes(payload)
        with self._lock:
            if task_id in self._entries:
                raise ValueError("task %r already has an in-memory zero-retention payload" % task_id)
            self._entries[task_id] = {"buffer": bytearray(data), "workspace_id": workspace_id}

    def deliver(self, task_id: str, sink: Callable[[bytes], Any]) -> Any:
        with self._lock:
            entry = self._entries.pop(task_id, None)
        if entry is None:
            raise KeyError(task_id)
        buffer = entry["buffer"]
        try:
            return sink(bytes(buffer))
        finally:
            _wipe(buffer)

    def discard(self, task_id: str) -> bool:
        with self._lock:
            entry = self._entries.pop(task_id, None)
        if entry is None:
            return False
        _wipe(entry["buffer"])
        return True

    def wipe_workspace(self, workspace_id: str) -> int:
        with self._lock:
            doomed = [key for key, entry in self._entries.items()
                      if entry.get("workspace_id") == workspace_id]
            entries = [self._entries.pop(key) for key in doomed]
        for entry in entries:
            _wipe(entry["buffer"])
        return len(entries)

    def wipe_all(self) -> int:
        with self._lock:
            entries = list(self._entries.values())
            self._entries.clear()
        for entry in entries:
            _wipe(entry["buffer"])
        return len(entries)

    def active_tasks(self) -> int:
        with self._lock:
            return len(self._entries)

    def pending_bytes(self) -> int:
        with self._lock:
            return sum(len(entry["buffer"]) for entry in self._entries.values())


def state_json(state: Any) -> str:
    """Serialize one ephemeral state blob for storage.

    Strings and objects keep their shape; raw bytes are wrapped in base64 so
    the column stays TEXT. The result is only ever written for the ephemeral
    mode — the zero-retention path never calls this function.
    """
    if isinstance(state, (bytes, bytearray)):
        return json.dumps(
            {"encoding": "base64", "data": base64.b64encode(bytes(state)).decode("ascii")},
            separators=(",", ":"),
        )
    if isinstance(state, str):
        return json.dumps({"text": state}, ensure_ascii=False, separators=(",", ":"))
    return json.dumps(state, ensure_ascii=False, separators=(",", ":"), default=str)


def _validate_task_id(task_id: Any) -> str:
    clean = str(task_id or "").strip()
    if not TASK_ID_RE.match(clean):
        raise ValueError(
            "task_id must match %s (letters, digits, dot, colon, underscore, hyphen)"
            % TASK_ID_RE.pattern
        )
    return clean


def _task_exists(db: Any, task_id: str) -> bool:
    return db.query_one("SELECT 1 AS one FROM data_lifecycle_tasks WHERE task_id = ?", (task_id,)) is not None


def admit_task(
    db: Any,
    broker: ZeroRetentionBroker,
    *,
    task_id: Any,
    policy_id: Any,
    principal: str = "",
    tool: str = "",
    payload: Any = None,
    state: Any = None,
    attachment_path: Optional[str] = None,
    workspace_id: Optional[str] = None,
    deliver: Optional[Callable[[bytes], Any]] = None,
    now_ms: Optional[int] = None,
) -> Dict[str, Any]:
    """Admit one task under ``policy_id`` and return its receipt.

    The receipt never contains the payload; it reports *where* the bytes are
    and, for the ephemeral mode, when they expire. A caller that wants the
    content back must be the ``deliver`` sink of a zero-retention task, and it
    gets exactly one call.
    """
    clean_task = _validate_task_id(task_id)
    policy = policy_module.get_policy(db, policy_id)
    if policy is None:
        raise ValueError("no data-lifecycle policy %r" % (policy_id,))
    mode = str(policy["mode"])
    timestamp = int(now_ms if now_ms is not None else _now_ms())
    payload_bytes = len(_as_bytes(payload)) if payload is not None else (
        len(state_json(state)) if state is not None else 0
    )
    base = {
        "task_id": clean_task,
        "policy_id": str(policy["policy_id"]),
        "mode": mode,
        "payload_bytes": payload_bytes,
        "workspace_id": workspace_id,
    }

    if mode == policy_module.MODE_ZERO_RETENTION:
        if payload is None:
            raise ValueError("zero_retention tasks must be submitted with their payload")
        if _task_exists(db, clean_task):
            raise ValueError("task %r already exists; erase it before reusing the id" % clean_task)
        broker.submit(clean_task, payload, workspace_id=workspace_id)
        delivered = False
        try:
            if deliver is not None:
                broker.deliver(clean_task, deliver)
                delivered = True
        except BaseException:
            # The broker wiped the buffer before the exception left `deliver`;
            # the rejection is recorded, and no admit row claims success.
            audit.record(
                db, action="reject", mode=mode, task_id=clean_task,
                principal=principal, tool=tool, status_code=502, now_ms=timestamp,
            )
            raise
        audit.record(
            db, action="admit", mode=mode, task_id=clean_task,
            principal=principal, tool=tool, status_code=200, now_ms=timestamp,
        )
        return dict(
            base,
            persisted=False,
            stored="process_memory",
            delivered=delivered,
            memory_wiped=delivered,
            expires_at_ms=None,
        )

    if mode == policy_module.MODE_USER_OWNED:
        if _task_exists(db, clean_task):
            raise ValueError("task %r already exists; erase it before reusing the id" % clean_task)
        # The content stays on the user's device; even a payload handed to this
        # call is deliberately dropped rather than written.
        db.execute(
            "INSERT INTO data_lifecycle_tasks"
            " (task_id, policy_id, mode, principal, tool, workspace_id, status, payload_bytes,"
            "  created_at_ms, expires_at_ms, erased_at_ms)"
            " VALUES (?, ?, ?, ?, ?, ?, 'device_only', ?, ?, NULL, NULL)",
            (clean_task, str(policy["policy_id"]), mode, str(principal)[:120], str(tool)[:120],
             workspace_id, payload_bytes, timestamp),
        )
        audit.record(
            db, action="admit", mode=mode, task_id=clean_task,
            principal=principal, tool=tool, status_code=200, now_ms=timestamp,
        )
        return dict(base, persisted=False, stored="user_device", delivered=False,
                    memory_wiped=False, expires_at_ms=None)

    # ephemeral
    if _task_exists(db, clean_task):
        raise ValueError("task %r already exists; erase it before reusing the id" % clean_task)
    expires = retention.expires_at_ms(timestamp, policy["temporary_ttl_seconds"])
    stored_state = state_json(state) if state is not None else None
    with db.transaction():
        db.execute(
            "INSERT INTO data_lifecycle_tasks"
            " (task_id, policy_id, mode, principal, tool, workspace_id, status, payload_bytes,"
            "  created_at_ms, expires_at_ms, erased_at_ms)"
            " VALUES (?, ?, ?, ?, ?, ?, 'admitted', ?, ?, ?, NULL)",
            (clean_task, str(policy["policy_id"]), mode, str(principal)[:120], str(tool)[:120],
             workspace_id, payload_bytes, timestamp, expires),
        )
        if stored_state is not None or attachment_path:
            db.execute(
                "INSERT INTO data_lifecycle_ephemeral"
                " (task_id, workspace_id, state_json, attachment_path, created_at_ms, expires_at_ms)"
                " VALUES (?, ?, ?, ?, ?, ?)",
                (clean_task, workspace_id, stored_state or "", attachment_path, timestamp, expires),
            )
    audit.record(
        db, action="admit", mode=mode, task_id=clean_task,
        principal=principal, tool=tool, status_code=200, now_ms=timestamp,
    )
    return dict(base, persisted=True, stored="gateway_sqlite", delivered=False,
                memory_wiped=False, expires_at_ms=expires,
                state_stored=stored_state is not None)


def self_test() -> List[str]:
    """Admission for all three modes, and the absence of a zero-retention row."""
    import tempfile
    from pathlib import Path

    from app.database import Database

    checks: List[str] = []

    def check(name: str, condition: bool) -> None:
        if not condition:
            raise AssertionError("policy_engine self_test failed: %s" % name)
        checks.append(name)

    def refuses(name: str, call: Any) -> None:
        try:
            call()
        except ValueError:
            checks.append(name)
            return
        raise AssertionError("policy_engine self_test: %s was accepted" % name)

    sentinel = "zdr-plaintext-4b8e2d"
    with tempfile.TemporaryDirectory(prefix="popopx-engine-") as tmp:
        root = Path(tmp)
        db = Database(root / "engine.db")
        broker = ZeroRetentionBroker()
        try:
            delivered: List[bytes] = []
            receipt = admit_task(
                db, broker, task_id="task-zdr-1", policy_id="zero_retention",
                principal="operator-a", tool="summarize", payload=sentinel,
                deliver=delivered.append, now_ms=1_700_000_000_000,
            )
            check("a_zero_retention_payload_is_delivered_once",
                  delivered == [sentinel.encode("utf-8")] and receipt["delivered"] is True)
            check("a_zero_retention_memory_buffer_is_gone_after_delivery",
                  broker.active_tasks() == 0 and broker.pending_bytes() == 0)
            check("a_zero_retention_receipt_says_memory_only",
                  receipt["persisted"] is False and receipt["stored"] == "process_memory"
                  and receipt["memory_wiped"] is True)
            check("a_zero_retention_admission_writes_no_task_row",
                  db.scalar("SELECT COUNT(*) FROM data_lifecycle_tasks") == 0
                  and db.scalar("SELECT COUNT(*) FROM data_lifecycle_ephemeral") == 0)
            audit_rows = audit.list_audit(db, limit=10)
            check("a_zero_retention_admission_is_audited_without_its_payload",
                  len(audit_rows) == 1 and audit_rows[0]["action"] == "admit"
                  and audit_rows[0]["mode"] == "zero_retention"
                  and sentinel not in json.dumps(audit_rows))

            pending = admit_task(
                db, broker, task_id="task-zdr-2", policy_id="zero_retention", payload=sentinel,
                now_ms=1_700_000_000_001,
            )
            check("an_undelivered_zero_retention_task_stays_in_memory_only",
                  pending["delivered"] is False and pending["memory_wiped"] is False
                  and broker.active_tasks() == 1)
            refuses("a_duplicate_live_task_id_is_refused",
                    lambda: admit_task(db, broker, task_id="task-zdr-2", policy_id="zero_retention",
                                       payload=sentinel))
            check("the_refused_duplicate_did_not_replace_the_first",
                  broker.pending_bytes() == len(sentinel.encode("utf-8")))
            broker.discard("task-zdr-2")

            def explode(_payload: bytes) -> None:
                raise RuntimeError("the sink went away")

            try:
                admit_task(db, broker, task_id="task-zdr-3", policy_id="zero_retention",
                           payload=sentinel, deliver=explode, now_ms=1_700_000_000_002)
            except RuntimeError:
                pass
            check("a_failed_delivery_still_wipes_the_buffer", broker.active_tasks() == 0)
            check("a_failed_delivery_is_audited_as_a_rejection",
                  audit.list_audit(db, limit=10)[0]["action"] == "reject")

            ephemeral = admit_task(
                db, broker, task_id="task-eph-1", policy_id="ephemeral",
                workspace_id="ws-1", state={"scratch": "ephemeral-state"},
                attachment_path="/tmp/not-a-real-attachment", now_ms=1_700_000_000_000,
            )
            check("an_ephemeral_task_is_persisted_with_its_expiry",
                  ephemeral["persisted"] is True
                  and ephemeral["expires_at_ms"] == 1_700_000_000_000 + 3600 * 1000)
            row = db.query_one("SELECT * FROM data_lifecycle_tasks WHERE task_id = 'task-eph-1'")
            check("the_ephemeral_task_row_carries_metadata_only",
                  row is not None and row["mode"] == "ephemeral" and row["status"] == "admitted")
            state_row = db.query_one("SELECT * FROM data_lifecycle_ephemeral WHERE task_id = 'task-eph-1'")
            check("the_ephemeral_state_blob_is_stored_until_expiry",
                  state_row is not None and "ephemeral-state" in state_row["state_json"]
                  and int(state_row["expires_at_ms"]) == ephemeral["expires_at_ms"])
            metadata_only = admit_task(
                db, broker, task_id="task-eph-2", policy_id="ephemeral",
                now_ms=1_700_000_000_000,
            )
            check("an_ephemeral_task_without_state_has_no_state_row",
                  metadata_only["state_stored"] is False
                  and db.scalar("SELECT COUNT(*) FROM data_lifecycle_ephemeral WHERE task_id = 'task-eph-2'") == 0)

            owned = admit_task(
                db, broker, task_id="task-owned-1", policy_id="user_owned",
                payload=sentinel, state={"scratch": "never-stored"}, now_ms=1_700_000_000_000,
            )
            check("a_user_owned_receipt_points_at_the_device",
                  owned["persisted"] is False and owned["stored"] == "user_device")
            check("a_user_owned_task_keeps_metadata_but_no_content_row",
                  db.scalar("SELECT COUNT(*) FROM data_lifecycle_tasks WHERE task_id = 'task-owned-1'") == 1
                  and db.scalar("SELECT COUNT(*) FROM data_lifecycle_ephemeral WHERE task_id = 'task-owned-1'") == 0)

            refuses("an_unknown_policy_is_refused",
                    lambda: admit_task(db, broker, task_id="task-x", policy_id="forever"))
            refuses("an_invalid_task_id_is_refused",
                    lambda: admit_task(db, broker, task_id="bad id", policy_id="ephemeral"))
            refuses("a_zero_retention_task_without_a_payload_is_refused",
                    lambda: admit_task(db, broker, task_id="task-empty", policy_id="zero_retention"))
        finally:
            db.close()

        db_files = sorted(root.glob("engine.db*"))
        raw = b"".join(path.read_bytes() for path in db_files if path.is_file())
        check("the_zero_retention_plaintext_is_absent_from_every_database_file",
              raw != b"" and sentinel.encode("utf-8") not in raw)

    return checks
