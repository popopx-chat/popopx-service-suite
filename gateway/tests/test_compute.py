# Copyright (c) 2026 POPOPX (popopx.chat)
# SPDX-License-Identifier: AGPL-3.0-only
"""Compute authorisation: default deny, and every refusal has a named reason.

The chain is asserted rung by rung — policy, registration, health, capability,
approval, capacity — because a single "denied" assertion would let one gate stand
in for another. The audit assertions then prove that a denial is recorded with
the principal who asked and with *none* of the request body, which is the same
"metadata, not content" rule the lifecycle audit follows.
"""

from __future__ import annotations

import json

import pytest

from app.compute import authorizer, registry
from app.database import Database

NOW = 1_700_000_000_000
APPROVAL = {"approved": True, "approval_id": "apr-9001"}


@pytest.fixture()
def db(tmp_path):
    handle = Database(tmp_path / "compute.db")
    try:
        yield handle
    finally:
        handle.close()


def register_healthy(db: Database, node_id: str = "node-a", *, gpu: bool = False,
                     labels=None) -> None:
    registry.register_node(
        db, node_id, "personal_node",
        capabilities={"gpu": gpu, "labels": labels or [], "max_concurrent_tasks": 1}, now_ms=NOW,
    )
    registry.heartbeat(db, node_id, now_ms=NOW)


def allocation(workspace: str = "ws-1", **overrides):
    body = {
        "workspace_id": workspace,
        "node_id": "node-a",
        "policy_id": "zero_retention",
        "capabilities": [],
        "approval": dict(APPROVAL),
    }
    body.update(overrides)
    return body


def test_an_unregistered_node_is_refused(db):
    decision = authorizer.authorize_allocation(
        db, allocation(), principal="operator-a", now_ms=NOW
    )

    assert decision["allowed"] is False
    assert decision["reason"] == "node_not_registered"
    assert decision["status_code"] == 404
    assert decision["node"] is None and decision["allocation"] is None
    assert registry.allocation_count(db, "node-a") == 0

    rows = db.query("SELECT * FROM compute_audit WHERE outcome = 'denied'")
    assert len(rows) == 1
    assert rows[0]["reason"] == "node_not_registered"
    assert rows[0]["principal"] == "operator-a"
    assert rows[0]["status_code"] == 404


def test_a_registered_node_that_never_heartbeat_is_refused(db):
    registry.register_node(db, "node-a", "dedicated_worker", now_ms=NOW)

    decision = authorizer.authorize_allocation(db, allocation(), now_ms=NOW)

    assert decision["allowed"] is False
    assert decision["reason"] == "node_heartbeat_missing"
    assert decision["status_code"] == 409


def test_a_capability_the_node_did_not_declare_is_refused(db):
    register_healthy(db, gpu=False)

    decision = authorizer.authorize_allocation(
        db, allocation(capabilities=["gpu"]), now_ms=NOW
    )

    assert decision["allowed"] is False
    assert decision["reason"] == "capability_not_granted"
    assert decision["status_code"] == 403
    assert "gpu" in decision["detail"]
    assert registry.allocation_count(db, "node-a") == 0


@pytest.mark.parametrize(
    "approval",
    [None, {"approved": "yes", "approval_id": "apr-1"}, {"approved": 1, "approval_id": "apr-1"},
     {"approved": True}, {"approved": True, "approval_id": "   "}],
    ids=["absent", "string-true", "integer-one", "no-id", "blank-id"],
)
def test_allocation_is_refused_without_an_explicit_named_approval(db, approval):
    register_healthy(db)

    decision = authorizer.authorize_allocation(
        db, allocation(approval=approval), now_ms=NOW
    )

    assert decision["allowed"] is False
    assert decision["reason"] == "approval_required"
    assert decision["status_code"] == 403
    assert registry.allocation_count(db, "node-a") == 0


def test_an_unknown_policy_is_refused_before_any_node_lookup(db):
    decision = authorizer.authorize_allocation(
        db, allocation(policy_id="everything_is_fine"), now_ms=NOW
    )

    assert decision["reason"] == "policy_unknown" and decision["status_code"] == 400
    # The node was never registered, so a lax chain would answer 404 instead.
    assert decision["node"] is None


def test_policy_health_capability_and_approval_together_create_one_allocation(db):
    register_healthy(db, gpu=True, labels=["llm"])

    decision = authorizer.authorize_allocation(
        db, allocation(capabilities=["gpu", "label:llm"]), principal="operator-a", now_ms=NOW
    )

    assert decision["allowed"] is True
    assert decision["status_code"] == 200
    assert decision["allocation"]["mode"] == "zero_retention"
    assert decision["allocation"]["capabilities"] == ["gpu", "label:llm"]
    assert decision["node"]["active_allocations"] == 1
    assert registry.allocation_count(db, "node-a") == 1
    allowed = db.query("SELECT * FROM compute_audit WHERE outcome = 'allowed' AND action = 'allocate'")
    assert len(allowed) == 1 and allowed[0]["reason"] == "allowed"


def test_a_full_node_is_refused_and_an_offline_node_after_that(db):
    register_healthy(db)
    assert authorizer.authorize_allocation(db, allocation(), now_ms=NOW)["allowed"] is True

    over_capacity = authorizer.authorize_allocation(db, allocation(workspace="ws-2"), now_ms=NOW)
    assert over_capacity["reason"] == "node_at_capacity" and over_capacity["status_code"] == 409

    registry.heartbeat(db, "node-a", now_ms=NOW)
    offline = authorizer.authorize_allocation(
        db, allocation(workspace="ws-3"), now_ms=NOW + registry.DEGRADED_WINDOW_MS + 1
    )
    assert offline["reason"] == "node_offline" and offline["status_code"] == 409


def test_a_denial_never_copies_the_request_body_into_the_audit(db):
    register_healthy(db)
    sentinel = "request-body-SENTINEL-c7d1e2"

    decision = authorizer.authorize_allocation(
        db,
        allocation(capabilities=["gpu"], note=sentinel,
                   approval={"approved": True, "approval_id": "apr-" + sentinel}),
        principal="operator-a", now_ms=NOW,
    )

    assert decision["allowed"] is False
    dump = json.dumps([dict(row) for row in db.query("SELECT * FROM compute_audit")])
    assert sentinel not in dump
    columns = {str(row["name"]) for row in db.query("PRAGMA table_info(compute_audit)")}
    assert columns == {
        "id", "node_id", "workspace_id", "action", "outcome", "reason",
        "status_code", "principal", "created_at_ms",
    }


def test_heartbeat_never_registers_a_node(db):
    assert registry.heartbeat(db, "nobody", now_ms=NOW) is None
    assert db.scalar("SELECT COUNT(*) FROM compute_nodes") == 0
