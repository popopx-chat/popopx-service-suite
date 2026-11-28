# Copyright (c) 2026 POPOPX (popopx.chat)
# SPDX-License-Identifier: AGPL-3.0-only
"""Expiry sweeps, explicit erasure, and the restricted temp area.

Two ways a byte leaves the gateway early, both implemented here:

* **expiry** — :func:`sweep_expired` deletes ephemeral state rows past their
  TTL and the attachments they point at, then writes one ``sweep`` audit row;
* **an erase request** — :func:`erase_request` is what ``POST
  /api/v1/data-lifecycle/erase`` calls: by task, by workspace, or a sweep of
  everything expired.

:class:`TempArea` is the "restricted temporary area" the zero-retention mode
allows a tool to use: a ``0700`` directory, ``0600`` files, no path separators
in names, and :meth:`TempArea.remove` refuses any path that resolves outside
the root. Attachment paths are only ever removed through it — a stored path is
data, and data is not allowed to direct a delete at ``/etc``.

Erasing a zero-retention task also wipes its in-memory buffer, so the same
request that clears the audit-visible metadata clears the plaintext. Erasure is
idempotent: a second request reports zeroes instead of failing, which is what a
retry after a dropped connection needs.
"""

from __future__ import annotations

import os
import re
import tempfile
import time
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional

from app.data_lifecycle import audit

__all__ = [
    "TempArea",
    "erase_request",
    "erase_task",
    "erase_workspace",
    "sweep_expired",
    "self_test",
]

TASK_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,95}$")

ERASE_SCOPES = ("task", "workspace", "expired")


def _now_ms() -> int:
    return int(time.time() * 1000)


class TempArea:
    """A per-gateway scratch directory that never deletes outside itself."""

    def __init__(self, root: Optional[Any] = None) -> None:
        self._root = Path(root) if root is not None else None

    @property
    def root(self) -> Path:
        if self._root is None:
            self._root = Path(tempfile.mkdtemp(prefix="popopx-lifecycle-"))
            try:
                os.chmod(self._root, 0o700)
            except OSError:  # pragma: no cover — a chmod on our own fresh dir
                pass
        return self._root

    def write(self, name: str, data: Any) -> Path:
        clean = str(name or "")
        if not clean or "/" in clean or "\\" in clean or clean in (".", ".."):
            raise ValueError("a temp-area file name must be one path segment")
        raw = data.encode("utf-8") if isinstance(data, str) else bytes(data)
        path = self.root / clean
        fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            os.write(fd, raw)
        finally:
            os.close(fd)
        return path

    def contains(self, path: Any) -> bool:
        """Does ``path`` resolve to a file *inside* this area?"""
        try:
            candidate = Path(str(path)).resolve()
            root = self.root.resolve()
        except OSError:
            return False
        return candidate != root and root in candidate.parents

    def remove(self, path: Any) -> bool:
        if not self.contains(path):
            return False
        try:
            Path(str(path)).unlink()
            return True
        except OSError:
            return False

    def wipe(self) -> int:
        removed = 0
        for child in sorted(self.root.rglob("*")):
            if child.is_file() or child.is_symlink():
                try:
                    child.unlink()
                    removed += 1
                except OSError:
                    continue
        return removed


def erase_task(
    db: Any,
    broker: Any,
    task_id: Any,
    *,
    principal: str = "",
    temp_area: Optional[TempArea] = None,
    now_ms: Optional[int] = None,
) -> Dict[str, Any]:
    """Erase one task: memory buffer, state row, temp attachment, task row."""
    clean = str(task_id or "").strip()
    if not TASK_ID_RE.match(clean):
        raise ValueError("task_id must match %s" % TASK_ID_RE.pattern)
    timestamp = int(now_ms if now_ms is not None else _now_ms())
    task = db.query_one("SELECT mode FROM data_lifecycle_tasks WHERE task_id = ?", (clean,))
    state = db.query_one(
        "SELECT attachment_path FROM data_lifecycle_ephemeral WHERE task_id = ?", (clean,)
    )
    mode = str(task["mode"]) if task is not None else ""
    files = 0
    attachment = state["attachment_path"] if state is not None else None
    if attachment and temp_area is not None and temp_area.remove(attachment):
        files = 1
    memory_wiped = bool(broker.discard(clean)) if broker is not None else False
    ephemeral = db.execute("DELETE FROM data_lifecycle_ephemeral WHERE task_id = ?", (clean,))
    tasks = db.execute("DELETE FROM data_lifecycle_tasks WHERE task_id = ?", (clean,))
    audit.record(
        db, action="erase", mode=mode, task_id=clean, principal=principal,
        status_code=200, now_ms=timestamp,
    )
    return {
        "task_id": clean,
        "memory_wiped": memory_wiped,
        "ephemeral": int(ephemeral),
        "tasks": int(tasks),
        "files": files,
    }


def erase_workspace(
    db: Any,
    broker: Any,
    workspace_id: Any,
    *,
    principal: str = "",
    temp_area: Optional[TempArea] = None,
    now_ms: Optional[int] = None,
) -> Dict[str, Any]:
    """Erase every lifecycle row a workspace owns, plus its in-memory buffers."""
    clean = str(workspace_id or "").strip()
    if not clean:
        raise ValueError("workspace_id is required")
    timestamp = int(now_ms if now_ms is not None else _now_ms())
    rows = db.query(
        "SELECT attachment_path FROM data_lifecycle_ephemeral WHERE workspace_id = ?", (clean,)
    )
    files = 0
    for row in rows:
        attachment = row["attachment_path"]
        if attachment and temp_area is not None and temp_area.remove(attachment):
            files += 1
    memory_wiped = int(broker.wipe_workspace(clean)) if broker is not None else 0
    ephemeral = db.execute("DELETE FROM data_lifecycle_ephemeral WHERE workspace_id = ?", (clean,))
    tasks = db.execute("DELETE FROM data_lifecycle_tasks WHERE workspace_id = ?", (clean,))
    audit.record(db, action="erase", principal=principal, status_code=200, now_ms=timestamp)
    return {
        "workspace_id": clean,
        "memory_wiped": memory_wiped,
        "ephemeral": int(ephemeral),
        "tasks": int(tasks),
        "files": files,
    }


def sweep_expired(
    db: Any,
    *,
    temp_area: Optional[TempArea] = None,
    principal: str = "",
    now_ms: Optional[int] = None,
) -> Dict[str, Any]:
    """Delete everything past its TTL and report what went."""
    timestamp = int(now_ms if now_ms is not None else _now_ms())
    expired_state = db.query(
        "SELECT attachment_path FROM data_lifecycle_ephemeral WHERE expires_at_ms <= ?",
        (timestamp,),
    )
    files = 0
    for row in expired_state:
        attachment = row["attachment_path"]
        if attachment and temp_area is not None and temp_area.remove(attachment):
            files += 1
    ephemeral = db.execute(
        "DELETE FROM data_lifecycle_ephemeral WHERE expires_at_ms <= ?", (timestamp,)
    )
    tasks = db.execute(
        "DELETE FROM data_lifecycle_tasks WHERE expires_at_ms IS NOT NULL AND expires_at_ms <= ?",
        (timestamp,),
    )
    audit.record(db, action="sweep", principal=principal, status_code=200, now_ms=timestamp)
    return {"tasks": int(tasks), "ephemeral": int(ephemeral), "files": files}


def erase_request(
    db: Any,
    broker: Any,
    body: Mapping[str, Any],
    *,
    principal: str = "",
    temp_area: Optional[TempArea] = None,
    now_ms: Optional[int] = None,
) -> Dict[str, Any]:
    """The body parser behind ``POST /api/v1/data-lifecycle/erase``.

    ``scope`` may be omitted when the id makes it unambiguous; an explicit
    ``scope`` with a missing or unsuitable id is a ``ValueError``, which the
    route turns into a 400.
    """
    if not isinstance(body, Mapping):
        raise ValueError("an erase body must be a JSON object")
    task_id = body.get("task_id")
    workspace_id = body.get("workspace_id")
    scope = str(body.get("scope") or "").strip().lower()
    if not scope:
        if task_id not in (None, ""):
            scope = "task"
        elif workspace_id not in (None, ""):
            scope = "workspace"
    if scope == "expired":
        return dict(sweep_expired(db, temp_area=temp_area, principal=principal, now_ms=now_ms), scope=scope)
    if scope == "task":
        if task_id in (None, ""):
            raise ValueError("scope task needs task_id")
        return dict(
            erase_task(db, broker, task_id, principal=principal, temp_area=temp_area, now_ms=now_ms),
            scope=scope,
        )
    if scope == "workspace":
        if workspace_id in (None, ""):
            raise ValueError("scope workspace needs workspace_id")
        return dict(
            erase_workspace(db, broker, workspace_id, principal=principal, temp_area=temp_area,
                            now_ms=now_ms),
            scope=scope,
        )
    raise ValueError("scope must be one of %s (or an id that implies one)" % ", ".join(ERASE_SCOPES))


def self_test() -> List[str]:
    """Sweeps, targeted erasure, and the temp area's containment rule."""
    import tempfile
    from pathlib import Path

    from app.data_lifecycle import policy_engine
    from app.database import Database

    checks: List[str] = []

    def check(name: str, condition: bool) -> None:
        if not condition:
            raise AssertionError("cleanup self_test failed: %s" % name)
        checks.append(name)

    def refuses(name: str, call: Any) -> None:
        try:
            call()
        except ValueError:
            checks.append(name)
            return
        raise AssertionError("cleanup self_test: %s was accepted" % name)

    with tempfile.TemporaryDirectory(prefix="popopx-cleanup-") as tmp:
        root = Path(tmp)
        area = TempArea(root / "scratch")
        area.root.mkdir(mode=0o700)
        attachment = area.write("attachment-1.bin", "short-lived attachment")
        check("the_temp_area_accepts_a_plain_name",
              attachment.is_file() and oct(attachment.stat().st_mode & 0o777) == "0o600")
        check("the_temp_area_refuses_to_erase_outside_itself",
              area.contains(str(root / "outside.txt")) is False
              and area.remove(str(root / "outside.txt")) is False)
        refuses("the_temp_area_refuses_a_path_separator",
                lambda: area.write("../escape", "x"))

        db = Database(root / "cleanup.db")
        broker = policy_engine.ZeroRetentionBroker()
        try:
            policy_engine.admit_task(
                db, broker, task_id="task-exp", policy_id="ephemeral", workspace_id="ws-a",
                state={"scratch": "gone soon"}, attachment_path=str(attachment),
                now_ms=1_700_000_000_000,
            )
            before = sweep_expired(db, temp_area=area, now_ms=1_700_000_000_001)
            check("a_sweep_before_expiry_removes_nothing",
                  before == {"tasks": 0, "ephemeral": 0, "files": 0}
                  and db.scalar("SELECT COUNT(*) FROM data_lifecycle_tasks") == 1)
            after = sweep_expired(
                db, temp_area=area, now_ms=1_700_000_000_000 + 3600 * 1000
            )
            check("a_sweep_at_the_expiry_instant_removes_the_state_and_its_file",
                  after["tasks"] == 1 and after["ephemeral"] == 1 and after["files"] == 1
                  and db.scalar("SELECT COUNT(*) FROM data_lifecycle_tasks") == 0
                  and not attachment.exists())

            policy_engine.admit_task(
                db, broker, task_id="task-mem", policy_id="zero_retention",
                payload="forget me", workspace_id="ws-a", now_ms=1_700_000_000_100,
            )
            erased = erase_task(db, broker, "task-mem", principal="operator-b", now_ms=1_700_000_000_101)
            check("erasing_a_zero_retention_task_wipes_its_only_copy",
                  erased["memory_wiped"] is True and broker.active_tasks() == 0
                  and erased["tasks"] == 0 and erased["ephemeral"] == 0)
            again = erase_task(db, broker, "task-mem", now_ms=1_700_000_000_102)
            check("erasure_is_idempotent", again["memory_wiped"] is False
                  and again["tasks"] == 0 and again["ephemeral"] == 0)
            rows = audit.list_audit(db, limit=20)
            check("every_erase_is_audited",
                  sum(1 for row in rows if row["action"] == "erase") == 2)

            policy_engine.admit_task(
                db, broker, task_id="task-ws-1", policy_id="ephemeral", workspace_id="ws-b",
                state={"scratch": "one"}, now_ms=1_700_000_000_200,
            )
            policy_engine.admit_task(
                db, broker, task_id="task-ws-2", policy_id="user_owned", workspace_id="ws-b",
                now_ms=1_700_000_000_201,
            )
            swept = erase_request(
                db, broker, {"workspace_id": "ws-b"}, principal="operator-c", now_ms=1_700_000_000_202
            )
            check("an_erase_request_infers_its_scope_from_the_workspace",
                  swept["scope"] == "workspace" and swept["tasks"] == 2 and swept["ephemeral"] == 1)
            check("the_workspace_erase_is_audited",
                  audit.list_audit(db, limit=5)[0]["action"] == "erase")
            refuses("an_erase_request_without_a_target_is_refused",
                    lambda: erase_request(db, broker, {}))
            refuses("an_unknown_scope_is_refused",
                    lambda: erase_request(db, broker, {"scope": "everything"}))
            refuses("a_task_scope_without_an_id_is_refused",
                    lambda: erase_request(db, broker, {"scope": "task"}))
            expired = erase_request(db, broker, {"scope": "expired"}, now_ms=1_700_000_000_300)
            check("the_expired_scope_runs_a_sweep",
                  expired["scope"] == "expired" and expired["tasks"] == 0)
        finally:
            db.close()

    return checks
