# Copyright (c) 2026 POPOPX (popopx.chat)
# SPDX-License-Identifier: AGPL-3.0-only
"""The four lifecycle promises, asserted against a real SQLite file.

The zero-retention test does not merely inspect tables: it checkpoints the WAL
and greps every database file for the plaintext, with an ephemeral blob in the
same file as the control that proves the scan can *find* text that is meant to
persist. Without that control a scan of a database the fixture never wrote would
pass for the wrong reason.
"""

from __future__ import annotations

import json

import pytest

from app.data_lifecycle import audit, cleanup, policy, policy_engine
from app.database import Database

NOW = 1_700_000_000_000


@pytest.fixture()
def env(tmp_path):
    db = Database(tmp_path / "lifecycle.db")
    broker = policy_engine.ZeroRetentionBroker()
    area = cleanup.TempArea(tmp_path / "area")
    area.root.mkdir(parents=True, exist_ok=True)
    try:
        yield db, broker, area
    finally:
        area.wipe()
        db.close()


def database_bytes(tmp_path) -> bytes:
    return b"".join(path.read_bytes() for path in sorted(tmp_path.glob("lifecycle.db*")))


def test_zdr_payload_is_delivered_once_and_never_lands_in_any_database_file(tmp_path, env):
    db, broker, _area = env
    payload = "zdr-plaintext-SENTINEL-4f21c9"
    delivered = []

    receipt = policy_engine.admit_task(
        db, broker, task_id="zdr-1", policy_id="zero_retention",
        principal="operator-a", tool="llm.summarise",
        payload=payload, deliver=delivered.append, now_ms=NOW,
    )

    assert receipt["persisted"] is False
    assert receipt["stored"] == "process_memory"
    assert receipt["delivered"] is True and receipt["memory_wiped"] is True
    assert delivered == [payload.encode("utf-8")]
    assert broker.active_tasks() == 0 and broker.pending_bytes() == 0
    assert db.scalar("SELECT COUNT(*) FROM data_lifecycle_tasks") == 0
    assert db.scalar("SELECT COUNT(*) FROM data_lifecycle_ephemeral") == 0

    control = "ephemeral-state-CONTROL-91ab70"
    policy_engine.admit_task(
        db, broker, task_id="eph-1", policy_id="ephemeral",
        state={"blob": control}, now_ms=NOW,
    )
    db.connection().execute("PRAGMA wal_checkpoint(FULL)")
    raw = database_bytes(tmp_path)
    assert control.encode("utf-8") in raw, "the scan cannot see a blob that was meant to persist"
    assert payload.encode("utf-8") not in raw

    with pytest.raises(KeyError):
        broker.deliver("zdr-1", delivered.append)


def test_zdr_delivery_that_fails_wipes_the_buffer_and_is_audited_as_a_reject(env):
    db, broker, _area = env
    payload = "zdr-failing-sink-SENTINEL"
    received = []

    def failing_sink(data: bytes) -> None:
        received.append(data)
        raise RuntimeError("downstream refused the frame")

    with pytest.raises(RuntimeError):
        policy_engine.admit_task(
            db, broker, task_id="zdr-fail", policy_id="zero_retention",
            payload=payload, deliver=failing_sink, now_ms=NOW,
        )

    assert received == [payload.encode("utf-8")]
    assert broker.active_tasks() == 0 and broker.pending_bytes() == 0
    assert db.scalar("SELECT COUNT(*) FROM data_lifecycle_tasks") == 0
    actions = [row["action"] for row in audit.list_audit(db)]
    assert actions == ["reject"]
    assert payload not in json.dumps(audit.list_audit(db))


def test_policy_erasure_deletes_state_attachment_and_rows_and_is_idempotent(env):
    db, broker, area = env
    attachment = area.write("ctx-1.bin", "attachment-SENTINEL-c3d4")
    policy_engine.admit_task(
        db, broker, task_id="eph-1", policy_id="ephemeral",
        state={"scratch": "agent context"}, attachment_path=str(attachment),
        workspace_id="ws-erase", now_ms=NOW,
    )
    assert attachment.is_file()
    assert db.scalar("SELECT COUNT(*) FROM data_lifecycle_tasks") == 1
    assert db.scalar("SELECT COUNT(*) FROM data_lifecycle_ephemeral") == 1

    erased = cleanup.erase_task(db, broker, "eph-1", principal="operator-a", temp_area=area)

    assert erased["tasks"] == 1 and erased["ephemeral"] == 1 and erased["files"] == 1
    assert not attachment.exists()
    assert db.scalar("SELECT COUNT(*) FROM data_lifecycle_tasks") == 0
    assert db.scalar("SELECT COUNT(*) FROM data_lifecycle_ephemeral") == 0

    again = cleanup.erase_task(db, broker, "eph-1", temp_area=area)
    assert again["tasks"] == 0 and again["ephemeral"] == 0 and again["files"] == 0


def test_erasing_a_zero_retention_task_wipes_the_only_copy(env):
    db, broker, _area = env
    policy_engine.admit_task(
        db, broker, task_id="zdr-pending", policy_id="zero_retention",
        payload="held-in-memory-SENTINEL", workspace_id="ws-mem", now_ms=NOW,
    )
    assert broker.active_tasks() == 1 and broker.pending_bytes() > 0

    erased = cleanup.erase_task(db, broker, "zdr-pending")

    assert erased["memory_wiped"] is True
    assert broker.active_tasks() == 0 and broker.pending_bytes() == 0
    assert db.scalar("SELECT COUNT(*) FROM data_lifecycle_tasks") == 0


def test_erasing_a_workspace_wipes_its_in_memory_zero_retention_buffers(env):
    db, broker, _area = env
    for task_id, workspace in (("zdr-a", "ws-1"), ("zdr-b", "ws-2")):
        policy_engine.admit_task(
            db, broker, task_id=task_id, policy_id="zero_retention",
            payload="workspace-buffer-" + task_id, workspace_id=workspace, now_ms=NOW,
        )

    erased = cleanup.erase_workspace(db, broker, "ws-1")

    assert erased["memory_wiped"] == 1
    assert broker.active_tasks() == 1 and broker.pending_bytes() > 0


def test_expiry_sweep_waits_for_the_ttl_boundary(env):
    db, broker, _area = env
    policy.upsert_policy(db, "short-lived", {"mode": "ephemeral", "temporary_ttl_seconds": 60}, now_ms=NOW)
    policy_engine.admit_task(
        db, broker, task_id="eph-short", policy_id="short-lived",
        state={"temp": "one minute"}, now_ms=NOW,
    )

    early = cleanup.sweep_expired(db, now_ms=NOW + 59_999)
    assert early["tasks"] == 0 and early["ephemeral"] == 0
    assert db.scalar("SELECT COUNT(*) FROM data_lifecycle_tasks") == 1

    at_boundary = cleanup.sweep_expired(db, now_ms=NOW + 60_000)
    assert at_boundary["tasks"] == 1 and at_boundary["ephemeral"] == 1
    assert db.scalar("SELECT COUNT(*) FROM data_lifecycle_tasks") == 0


def test_user_owned_records_metadata_only_and_drops_the_payload(env):
    db, broker, _area = env
    sentinel = "user-owned-payload-SENTINEL-77e1"
    receipt = policy_engine.admit_task(
        db, broker, task_id="owned-1", policy_id="user_owned",
        payload=sentinel, now_ms=NOW,
    )

    assert receipt["persisted"] is False and receipt["stored"] == "user_device"
    row = db.query_one("SELECT * FROM data_lifecycle_tasks WHERE task_id = ?", ("owned-1",))
    assert row is not None and row["status"] == "device_only"
    assert sentinel not in json.dumps(dict(row))


def test_audit_is_metadata_only_and_has_no_column_able_to_hold_content(env):
    db, _broker, _area = env
    sentinel = "audit-must-not-keep-this-SENTINEL-2b6c"
    policy_engine.admit_task(
        db, policy_engine.ZeroRetentionBroker(), task_id="audit-1", policy_id="ephemeral",
        principal="operator-a", tool="ocr", state={"body": sentinel}, now_ms=NOW,
    )

    rows = audit.list_audit(db)
    assert len(rows) == 1
    assert rows[0]["task_id"] == "audit-1"
    assert rows[0]["principal"] == "operator-a"
    assert rows[0]["tool"] == "ocr"
    assert rows[0]["mode"] == "ephemeral"
    assert rows[0]["action"] == "admit"
    assert rows[0]["status_code"] == 200
    assert sentinel not in json.dumps(rows)

    columns = {str(row["name"]) for row in db.query("PRAGMA table_info(data_lifecycle_audit)")}
    assert columns == {"id"}.union(audit.AUDIT_FIELDS)
    assert not columns & {"payload", "content", "body", "message", "secret", "key", "state"}


def test_the_audit_api_cannot_be_handed_content(env):
    db, _broker, _area = env
    with pytest.raises(TypeError):
        audit.record(db, action="admit", payload="never")  # type: ignore[call-arg]
    with pytest.raises(TypeError):
        audit.record(db, action="admit", detail="never")  # type: ignore[call-arg]
    with pytest.raises(ValueError):
        audit.record(db, action="exfiltrate")
