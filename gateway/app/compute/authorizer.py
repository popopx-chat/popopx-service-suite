# Copyright (c) 2026 POPOPX (popopx.chat)
# SPDX-License-Identifier: AGPL-3.0-only
"""The allocation gate: default deny, policy, capability, and the user's approval.

Every refusal has a named reason and a status code, and every refusal is
audited with the authorised principal that asked. There are no partial
successes: an allocation either exists in ``compute_allocations`` as ``active``
or the caller got a refusal, so "did the task escape" is one row lookup rather
than an inference from logs.

Approval is checked as a JSON shape, not a truthy value. ``{"approved": "yes"}``
is a refusal — a string that happens to be non-empty must never be able to
stand in for the human who clicked the button, which is exactly the mistake
this gate exists to make impossible.
"""

from __future__ import annotations

from typing import Any, Dict, List, Mapping, Optional, Sequence

from app.compute import registry
from app.data_lifecycle import policy as lifecycle_policy

__all__ = ["authorize_allocation", "self_test"]

APPROVAL_ID_MAX = 96


def _deny(
    db: Any,
    *,
    reason: str,
    status: int,
    detail: str,
    principal: str,
    node_id: Optional[str] = None,
    workspace_id: Optional[str] = None,
    node: Optional[Dict[str, Any]] = None,
    now_ms: Optional[int] = None,
) -> Dict[str, Any]:
    registry.record_audit(
        db,
        action="allocate",
        outcome="denied",
        node_id=node_id,
        workspace_id=workspace_id,
        reason=reason,
        status_code=status,
        principal=principal,
        now_ms=now_ms,
    )
    return {
        "allowed": False,
        "reason": reason,
        "status_code": status,
        "detail": detail,
        "node": node,
        "allocation": None,
    }


def _requested_capabilities(body: Mapping[str, Any]) -> List[Any]:
    raw = body.get("capabilities")
    if raw is None:
        return []
    if isinstance(raw, str):
        return [part for part in raw.replace(",", " ").split() if part]
    if isinstance(raw, (list, tuple)):
        return list(raw)
    raise ValueError("capabilities must be a list of tokens")


def _approval_id(body: Mapping[str, Any]) -> Optional[str]:
    """The human's approval, or ``None``. Only a literal ``true`` and a named
    approval id count; everything else — including ``"true"`` and ``1`` — is a
    missing approval, never a lenient truthy.
    """
    approval = body.get("approval")
    if not isinstance(approval, Mapping):
        return None
    if approval.get("approved") is not True:
        return None
    raw_id = approval.get("approval_id")
    if raw_id is None or isinstance(raw_id, bool):
        return None
    text = " ".join(str(raw_id).split())[:APPROVAL_ID_MAX]
    return text or None


def authorize_allocation(
    db: Any,
    body: Any,
    *,
    principal: str = "",
    now_ms: Optional[int] = None,
) -> Dict[str, Any]:
    """Decide one allocation. Returns ``allowed``/``reason``/``status_code``.

    The caller maps ``status_code`` onto the HTTP response; nothing in the
    decision depends on transport, so the same chain runs under pytest.
    """
    timestamp = int(now_ms if now_ms is not None else registry._now_ms())

    if not isinstance(body, Mapping):
        return _deny(db, reason="invalid_request", status=400,
                     detail="the request body must be a JSON object",
                     principal=principal, now_ms=timestamp)

    workspace_raw = body.get("workspace_id")
    workspace_id = str(workspace_raw).strip() if workspace_raw is not None else ""
    if not registry.WORKSPACE_ID_RE.match(workspace_id):
        return _deny(db, reason="workspace_id_invalid", status=400,
                     detail="workspace_id must match %s" % registry.WORKSPACE_ID_RE.pattern,
                     principal=principal, workspace_id=workspace_id or None,
                     now_ms=timestamp)

    node_raw = body.get("node_id")
    node_id = str(node_raw).strip() if node_raw is not None else ""
    if not node_id:
        return _deny(db, reason="node_id_missing", status=400,
                     detail="node_id is required", principal=principal,
                     workspace_id=workspace_id, now_ms=timestamp)
    if not registry.NODE_ID_RE.match(node_id):
        return _deny(db, reason="node_id_invalid", status=400,
                     detail="node_id must match %s" % registry.NODE_ID_RE.pattern,
                     principal=principal, node_id=node_id,
                     workspace_id=workspace_id, now_ms=timestamp)

    policy_raw = body.get("policy_id")
    policy_id = str(policy_raw).strip() if policy_raw is not None else ""
    selected = lifecycle_policy.get_policy(db, policy_id)
    if selected is None:
        return _deny(db, reason="policy_unknown", status=400,
                     detail="policy %r does not exist" % policy_id,
                     principal=principal, node_id=node_id,
                     workspace_id=workspace_id, now_ms=timestamp)

    node = registry.get_node(db, node_id, now_ms=timestamp)
    if node is None:
        return _deny(db, reason="node_not_registered", status=404,
                     detail="node %r is not registered with this gateway" % node_id,
                     principal=principal, node_id=node_id,
                     workspace_id=workspace_id, now_ms=timestamp)

    if node["health"] == "unknown":
        return _deny(db, reason="node_heartbeat_missing", status=409,
                     detail="node %r has never sent a heartbeat" % node_id,
                     principal=principal, node_id=node_id, workspace_id=workspace_id,
                     node=node, now_ms=timestamp)
    if node["health"] != "healthy":
        return _deny(db, reason="node_offline" if node["health"] == "offline" else "node_degraded",
                     status=409,
                     detail="node %r is %s (last heartbeat %s ms ago)"
                     % (node_id, node["health"], node["heartbeat_age_ms"]),
                     principal=principal, node_id=node_id, workspace_id=workspace_id,
                     node=node, now_ms=timestamp)

    try:
        requested = _requested_capabilities(body)
        missing = registry.missing_capabilities(node["capabilities"], requested)
    except ValueError as exc:
        return _deny(db, reason="capabilities_invalid", status=400, detail=str(exc),
                     principal=principal, node_id=node_id, workspace_id=workspace_id,
                     node=node, now_ms=timestamp)
    if missing:
        return _deny(db, reason="capability_not_granted", status=403,
                     detail="node %r has not declared %s" % (node_id, ", ".join(missing)),
                     principal=principal, node_id=node_id, workspace_id=workspace_id,
                     node=node, now_ms=timestamp)

    approval_id = _approval_id(body)
    if approval_id is None:
        return _deny(db, reason="approval_required", status=403,
                     detail="an explicit approval object with {\"approved\": true,"
                            " \"approval_id\": …} is required",
                     principal=principal, node_id=node_id, workspace_id=workspace_id,
                     node=node, now_ms=timestamp)

    if node["active_allocations"] >= node["max_concurrent_tasks"]:
        return _deny(db, reason="node_at_capacity", status=409,
                     detail="node %r already holds %d of %d concurrent allocation(s)"
                     % (node_id, node["active_allocations"], node["max_concurrent_tasks"]),
                     principal=principal, node_id=node_id, workspace_id=workspace_id,
                     node=node, now_ms=timestamp)

    allocation = registry.create_allocation(
        db,
        workspace_id=workspace_id,
        node_id=node_id,
        policy_id=str(selected["policy_id"]),
        mode=str(selected["mode"]),
        capabilities=[str(token) for token in requested],
        approval_id=approval_id,
        principal=principal,
        now_ms=timestamp,
    )
    return {
        "allowed": True,
        "reason": "allowed",
        "status_code": 200,
        "detail": "",
        "node": registry.get_node(db, node_id, now_ms=timestamp),
        "allocation": allocation,
    }


def self_test() -> List[str]:
    """The refusal chain, one reason per rung, plus the one way through."""
    import tempfile
    from pathlib import Path

    from app.database import Database

    checks: List[str] = []

    def check(name: str, condition: bool) -> None:
        if not condition:
            raise AssertionError("authorizer self_test failed: %s" % name)
        checks.append(name)

    with tempfile.TemporaryDirectory(prefix="popopx-authorizer-") as tmp:
        db = Database(Path(tmp) / "authorizer.db")
        try:
            now = 1_700_000_000_000
            base = {"workspace_id": "ws-a", "node_id": "node-a",
                    "policy_id": "zero_retention"}
            approval = {"approved": True, "approval_id": "apr-42"}

            refused = authorize_allocation(db, ["not", "a", "mapping"],
                                           principal="tester", now_ms=now)
            check("a_non_object_body_is_refused_as_invalid_request",
                  refused["reason"] == "invalid_request" and refused["status_code"] == 400)
            refused = authorize_allocation(db, dict(base, workspace_id="bad space"),
                                           principal="tester", now_ms=now)
            check("a_malformed_workspace_is_refused",
                  refused["reason"] == "workspace_id_invalid" and refused["status_code"] == 400)
            refused = authorize_allocation(db, {k: v for k, v in base.items() if k != "node_id"}, now_ms=now)
            check("a_missing_node_id_is_refused", refused["reason"] == "node_id_missing")
            refused = authorize_allocation(db, dict(base, node_id="Node A"), now_ms=now)
            check("a_malformed_node_id_is_refused", refused["reason"] == "node_id_invalid")
            refused = authorize_allocation(db, dict(base, policy_id="everything_is_fine"), now_ms=now)
            check("an_unknown_policy_is_refused_before_the_node_is_even_looked_up",
                  refused["reason"] == "policy_unknown" and refused["status_code"] == 400)
            refused = authorize_allocation(db, base, now_ms=now)
            check("an_unregistered_node_is_refused",
                  refused["reason"] == "node_not_registered" and refused["status_code"] == 404
                  and refused["node"] is None)

            registry.register_node(db, "node-a", "personal_node",
                                   capabilities={"gpu": False, "max_concurrent_tasks": 1},
                                   now_ms=now)
            refused = authorize_allocation(db, dict(base, approval=approval), now_ms=now)
            check("a_node_that_never_sent_a_heartbeat_is_refused",
                  refused["reason"] == "node_heartbeat_missing" and refused["status_code"] == 409)
            registry.heartbeat(db, "node-a", now_ms=now)

            refused = authorize_allocation(db, base, principal="tester", now_ms=now)
            check("no_approval_is_refused_even_when_everything_else_is_fine",
                  refused["reason"] == "approval_required" and refused["status_code"] == 403)
            refused = authorize_allocation(
                db, dict(base, approval={"approved": "yes", "approval_id": "apr-1"}), now_ms=now)
            check("a_truthy_string_is_not_an_approval", refused["reason"] == "approval_required")
            refused = authorize_allocation(
                db, dict(base, approval={"approved": 1, "approval_id": "apr-1"}), now_ms=now)
            check("one_is_not_an_approval_either", refused["reason"] == "approval_required")
            refused = authorize_allocation(
                db, dict(base, approval={"approved": True}), now_ms=now)
            check("an_approval_without_a_named_human_is_refused",
                  refused["reason"] == "approval_required")

            refused = authorize_allocation(
                db, dict(base, capabilities=["gpu"], approval=approval), now_ms=now)
            check("an_undeclared_capability_is_refused",
                  refused["reason"] == "capability_not_granted"
                  and refused["status_code"] == 403 and "gpu" in refused["detail"])
            refused = authorize_allocation(
                db, dict(base, capabilities=["root"], approval=approval), now_ms=now)
            check("a_malformed_capability_token_is_refused",
                  refused["reason"] == "capabilities_invalid" and refused["status_code"] == 400)

            allowed = authorize_allocation(
                db, dict(base, capabilities="cpu", approval=approval),
                principal="operator-a", now_ms=now)
            check("policy_health_capability_and_approval_together_are_allowed",
                  allowed["allowed"] is True and allowed["reason"] == "allowed"
                  and allowed["status_code"] == 200)
            check("an_allowed_decision_creates_exactly_one_active_allocation",
                  allowed["allocation"]["allocation_id"].startswith("cal_")
                  and allowed["allocation"]["mode"] == "zero_retention"
                  and registry.allocation_count(db, "node-a") == 1)
            check("the_allowed_decision_carries_the_node_view",
                  allowed["node"]["health"] == "healthy"
                  and allowed["node"]["active_allocations"] == 1)

            refused = authorize_allocation(
                db, dict(base, workspace_id="ws-b", approval=approval), now_ms=now)
            check("a_full_node_is_refused_at_capacity",
                  refused["reason"] == "node_at_capacity" and refused["status_code"] == 409)

            registry.heartbeat(db, "node-a", now_ms=now)
            stale = authorize_allocation(
                db, dict(base, approval=approval), principal="tester",
                now_ms=now + registry.DEGRADED_WINDOW_MS + 1)
            check("an_offline_node_is_refused",
                  stale["reason"] == "node_offline" and stale["status_code"] == 409)

            lifecycle_policy.upsert_policy(db, "short-lived", {
                "mode": "ephemeral", "temporary_ttl_seconds": 120,
            })
            second = authorize_allocation(
                db, dict(base, workspace_id="ws-c", policy_id="short-lived", approval=approval),
                now_ms=now + registry.DEGRADED_WINDOW_MS + 2)
            check("a_custom_policy_passes_validation_and_reaches_the_health_check",
                  second["reason"] == "node_offline")

            denied_rows = db.query(
                "SELECT reason, principal FROM compute_audit WHERE outcome = 'denied' ORDER BY id"
            )
            check("every_refusal_is_audited_exactly_once",
                  len(denied_rows) == 16)
            check("every_denial_names_its_reason",
                  all(row["reason"] for row in denied_rows))
            check("a_denial_records_the_principal_that_asked",
                  denied_rows[0]["principal"] == "tester"
                  and sum(1 for row in denied_rows if row["principal"] == "tester") == 4)
            allowed_rows = db.query(
                "SELECT node_id, workspace_id, status_code FROM compute_audit"
                " WHERE outcome = 'allowed' AND action = 'allocate'"
            )
            check("the_allowed_decision_is_audited",
                  len(allowed_rows) == 1 and allowed_rows[0]["status_code"] == 200
                  and allowed_rows[0]["workspace_id"] == "ws-a")
        finally:
            db.close()

    return checks
