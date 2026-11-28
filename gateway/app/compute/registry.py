# Copyright (c) 2026 POPOPX (popopx.chat)
# SPDX-License-Identifier: AGPL-3.0-only
"""The compute-node registry: nodes, capability profiles, heartbeats, allocations.

Health is *derived*, never stored as truth: a node's ``last_heartbeat_ms`` is
the fact, and ``healthy`` / ``degraded`` / ``offline`` are computed against the
viewer's clock. A stored status string would go stale exactly when it matters —
during the outage the operator is looking at.

Capability profiles are closed: the five known facts plus a list of labels, and
an unknown key is a validation error rather than an ignored field. That is the
same default-deny rule as the authorizer: a node declaring ``quantum: true``
must not be quietly registered with that claim dropped, because the allocation
that later asks for it would be denied for a reason nobody can see.
"""

from __future__ import annotations

import json
import re
import secrets
import time
from typing import Any, Dict, List, Mapping, Optional, Sequence

__all__ = [
    "AUDIT_RETENTION",
    "DEGRADED_WINDOW_MS",
    "HEALTHY_WINDOW_MS",
    "NODE_KINDS",
    "WORKSPACE_ID_RE",
    "allocation_count",
    "capability_tokens",
    "cleanup_workspace",
    "create_allocation",
    "get_node",
    "health_for",
    "heartbeat",
    "list_nodes",
    "missing_capabilities",
    "node_view",
    "normalize_capabilities",
    "record_audit",
    "register_node",
    "self_test",
]

#: The two node kinds the brief names. A label is free text; the kind is not.
NODE_KINDS = ("personal_node", "dedicated_worker")

#: Heartbeat thresholds. A node heard from within the first window is healthy;
#: the second window is the grace period a restarting agent gets; past it the
#: node is offline and allocations are refused.
HEALTHY_WINDOW_MS = 90_000
DEGRADED_WINDOW_MS = 300_000

#: Keep the audit table bounded, same rule as the scoped-token audit.
AUDIT_RETENTION = 5000

NODE_ID_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")
WORKSPACE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,95}$")
LABEL_RE = re.compile(r"^[a-z][a-z0-9_-]{0,31}$")

CAPABILITY_DEFAULTS: Dict[str, Any] = {
    "cpu_cores": 1,
    "memory_mb": 512,
    "gpu": False,
    "labels": [],
    "max_concurrent_tasks": 1,
}

#: Requested-capability vocabulary: a bare class token, or a declared label.
REQUESTED_CAPABILITY_RE = re.compile(r"^(cpu|gpu|label:[a-z][a-z0-9_-]{0,31})$")


def _now_ms() -> int:
    return int(time.time() * 1000)


def _int_in_range(value: Any, low: int, high: int, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError("%s must be an integer" % name)
    if value < low or value > high:
        raise ValueError("%s must be between %d and %d" % (name, low, high))
    return int(value)


def normalize_capabilities(raw: Optional[Mapping[str, Any]]) -> Dict[str, Any]:
    """Validate one capability profile, filling defaults for absent facts."""
    if raw is None:
        return dict(CAPABILITY_DEFAULTS, labels=[])
    if not isinstance(raw, Mapping):
        raise ValueError("capabilities must be a JSON object")
    unknown = sorted(set(raw) - set(CAPABILITY_DEFAULTS))
    if unknown:
        raise ValueError("unknown capability key(s): %s" % ", ".join(unknown))
    profile = dict(CAPABILITY_DEFAULTS, labels=[])
    if "cpu_cores" in raw:
        profile["cpu_cores"] = _int_in_range(raw["cpu_cores"], 1, 1024, "cpu_cores")
    if "memory_mb" in raw:
        profile["memory_mb"] = _int_in_range(raw["memory_mb"], 128, 4_194_304, "memory_mb")
    if "gpu" in raw:
        if not isinstance(raw["gpu"], bool):
            raise ValueError("gpu must be a boolean")
        profile["gpu"] = raw["gpu"]
    if "max_concurrent_tasks" in raw:
        profile["max_concurrent_tasks"] = _int_in_range(
            raw["max_concurrent_tasks"], 1, 64, "max_concurrent_tasks"
        )
    if "labels" in raw:
        labels_raw = raw["labels"]
        if not isinstance(labels_raw, (list, tuple)):
            raise ValueError("labels must be a list of slugs")
        labels: List[str] = []
        for label in labels_raw:
            text = str(label or "").strip()
            if not LABEL_RE.match(text):
                raise ValueError("label %r must match %s" % (text, LABEL_RE.pattern))
            if text not in labels:
                labels.append(text)
        if len(labels) > 16:
            raise ValueError("at most 16 labels are accepted")
        profile["labels"] = labels
    return profile


def capability_tokens(capabilities: Mapping[str, Any]) -> List[str]:
    """The granted set a request is checked against."""
    tokens = ["cpu"]
    if capabilities.get("gpu") is True:
        tokens.append("gpu")
    tokens.extend("label:" + str(label) for label in capabilities.get("labels") or [])
    return tokens


def missing_capabilities(
    capabilities: Mapping[str, Any], requested: Sequence[Any]
) -> List[str]:
    """Requested tokens the node did not declare. Raises on a malformed token."""
    if not isinstance(requested, (list, tuple)):
        raise ValueError("capabilities must be a list of tokens")
    granted = set(capability_tokens(capabilities))
    missing: List[str] = []
    for token in requested:
        text = str(token or "").strip()
        if not REQUESTED_CAPABILITY_RE.match(text):
            raise ValueError(
                "capability %r must match %s" % (text, REQUESTED_CAPABILITY_RE.pattern)
            )
        if text not in granted and text not in missing:
            missing.append(text)
    return missing


def health_for(last_heartbeat_ms: Optional[int], now_ms: int) -> str:
    if last_heartbeat_ms is None:
        return "unknown"
    age = max(0, int(now_ms) - int(last_heartbeat_ms))
    if age <= HEALTHY_WINDOW_MS:
        return "healthy"
    if age <= DEGRADED_WINDOW_MS:
        return "degraded"
    return "offline"


def _capabilities_from_json(text: Any) -> Dict[str, Any]:
    try:
        parsed = json.loads(str(text or "{}"))
    except ValueError:
        parsed = None
    if not isinstance(parsed, dict):
        return dict(CAPABILITY_DEFAULTS, labels=[])
    profile = dict(CAPABILITY_DEFAULTS, labels=[])
    profile.update({key: parsed[key] for key in CAPABILITY_DEFAULTS if key in parsed})
    return profile


def record_audit(
    db: Any,
    *,
    action: str,
    outcome: str,
    node_id: Optional[str] = None,
    workspace_id: Optional[str] = None,
    reason: str = "",
    status_code: Optional[int] = None,
    principal: str = "",
    now_ms: Optional[int] = None,
) -> None:
    """Append one compute decision and keep the table bounded.

    ``reason`` is a named code from the closed vocabulary the authorizer emits
    (``approval_required``, ``node_offline``, …), never free text from a
    request body — same rule as the lifecycle audit: metadata, not content.
    """
    timestamp = int(now_ms if now_ms is not None else _now_ms())
    db.execute(
        "INSERT INTO compute_audit"
        " (node_id, workspace_id, action, outcome, reason, status_code, principal, created_at_ms)"
        " VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (
            str(node_id)[:96] if node_id is not None else None,
            str(workspace_id)[:96] if workspace_id is not None else None,
            str(action)[:32],
            str(outcome)[:16],
            str(reason)[:64],
            int(status_code) if status_code is not None else None,
            " ".join(str(principal or "").split())[:120],
            timestamp,
        ),
    )
    db.execute(
        "DELETE FROM compute_audit WHERE id NOT IN"
        " (SELECT id FROM compute_audit ORDER BY id DESC LIMIT ?)",
        (AUDIT_RETENTION,),
    )


def allocation_count(db: Any, node_id: str) -> int:
    return int(
        db.scalar(
            "SELECT COUNT(*) FROM compute_allocations WHERE node_id = ? AND status = 'active'",
            (str(node_id),),
            0,
        )
    )


def node_view(db: Any, row: Any, now_ms: int) -> Dict[str, Any]:
    last = row["last_heartbeat_ms"]
    capabilities = _capabilities_from_json(row["capabilities"])
    age = None if last is None else max(0, int(now_ms) - int(last))
    return {
        "node_id": str(row["node_id"]),
        "kind": str(row["kind"]),
        "label": str(row["label"] or ""),
        "capabilities": capabilities,
        "capability_tokens": capability_tokens(capabilities),
        "max_concurrent_tasks": int(row["max_concurrent"]),
        "status": str(row["status"] or ""),
        "health": health_for(last, now_ms),
        "last_heartbeat_ms": int(last) if last is not None else None,
        "heartbeat_age_ms": age,
        "active_allocations": allocation_count(db, str(row["node_id"])),
        "created_at_ms": int(row["created_at_ms"]),
        "updated_at_ms": int(row["updated_at_ms"]),
    }


def get_node(db: Any, node_id: Any, *, now_ms: Optional[int] = None) -> Optional[Dict[str, Any]]:
    clean = str(node_id or "").strip()
    if not NODE_ID_RE.match(clean):
        return None
    row = db.query_one("SELECT * FROM compute_nodes WHERE node_id = ?", (clean,))
    if row is None:
        return None
    return node_view(db, row, int(now_ms if now_ms is not None else _now_ms()))


def list_nodes(db: Any, *, now_ms: Optional[int] = None) -> List[Dict[str, Any]]:
    timestamp = int(now_ms if now_ms is not None else _now_ms())
    rows = db.query("SELECT * FROM compute_nodes ORDER BY node_id")
    return [node_view(db, row, timestamp) for row in rows]


def register_node(
    db: Any,
    node_id: Any,
    kind: Any,
    *,
    label: str = "",
    capabilities: Optional[Mapping[str, Any]] = None,
    max_concurrent_tasks: Optional[int] = None,
    now_ms: Optional[int] = None,
) -> Dict[str, Any]:
    """Register (or re-declare) one node. Operator action; audited.

    Re-registering keeps the previous ``last_heartbeat_ms``: a configuration
    change must not make a node look freshly alive.
    """
    clean = str(node_id or "").strip()
    if not NODE_ID_RE.match(clean):
        raise ValueError("node_id must match %s" % NODE_ID_RE.pattern)
    clean_kind = str(kind or "").strip()
    if clean_kind not in NODE_KINDS:
        raise ValueError("kind must be one of %s" % ", ".join(NODE_KINDS))
    profile = normalize_capabilities(capabilities)
    if max_concurrent_tasks is None:
        concurrency = int(profile["max_concurrent_tasks"])
    else:
        concurrency = _int_in_range(max_concurrent_tasks, 1, 64, "max_concurrent_tasks")
    timestamp = int(now_ms if now_ms is not None else _now_ms())
    db.execute(
        "INSERT INTO compute_nodes"
        " (node_id, kind, label, capabilities, max_concurrent, status, last_heartbeat_ms,"
        "  created_at_ms, updated_at_ms)"
        " VALUES (?, ?, ?, ?, ?, 'ready', NULL, ?, ?)"
        " ON CONFLICT(node_id) DO UPDATE SET"
        "  kind = excluded.kind, label = excluded.label, capabilities = excluded.capabilities,"
        "  max_concurrent = excluded.max_concurrent, status = excluded.status,"
        "  updated_at_ms = excluded.updated_at_ms",
        (
            clean,
            clean_kind,
            " ".join(str(label or "").split())[:120],
            json.dumps(profile, ensure_ascii=False, separators=(",", ":"), sort_keys=True),
            concurrency,
            timestamp,
            timestamp,
        ),
    )
    record_audit(db, action="register", outcome="allowed", node_id=clean,
                 status_code=200, now_ms=timestamp)
    registered = get_node(db, clean, now_ms=timestamp)
    if registered is None:  # pragma: no cover — the write above either landed or raised
        raise RuntimeError("node %r vanished after its own registration" % clean)
    return registered


def heartbeat(
    db: Any,
    node_id: Any,
    *,
    capabilities: Optional[Mapping[str, Any]] = None,
    now_ms: Optional[int] = None,
) -> Optional[Dict[str, Any]]:
    """Record one heartbeat. Returns ``None`` for an unregistered node.

    A heartbeat never registers: a machine that knows the gateway's address
    must not be able to join the fleet by sending a frame. Re-declaring
    capabilities here updates the profile (including concurrency) so a node
    can downgrade itself without an operator round trip.
    """
    clean = str(node_id or "").strip()
    if not NODE_ID_RE.match(clean):
        raise ValueError("node_id must match %s" % NODE_ID_RE.pattern)
    row = db.query_one("SELECT node_id FROM compute_nodes WHERE node_id = ?", (clean,))
    if row is None:
        return None
    timestamp = int(now_ms if now_ms is not None else _now_ms())
    if capabilities is None:
        db.execute(
            "UPDATE compute_nodes SET last_heartbeat_ms = ?, updated_at_ms = ?, status = 'ready'"
            " WHERE node_id = ?",
            (timestamp, timestamp, clean),
        )
    else:
        profile = normalize_capabilities(capabilities)
        db.execute(
            "UPDATE compute_nodes SET capabilities = ?, max_concurrent = ?,"
            " last_heartbeat_ms = ?, updated_at_ms = ?, status = 'ready' WHERE node_id = ?",
            (
                json.dumps(profile, ensure_ascii=False, separators=(",", ":"), sort_keys=True),
                int(profile["max_concurrent_tasks"]),
                timestamp,
                timestamp,
                clean,
            ),
        )
    record_audit(db, action="heartbeat", outcome="allowed", node_id=clean,
                 status_code=200, now_ms=timestamp)
    return get_node(db, clean, now_ms=timestamp)


def create_allocation(
    db: Any,
    *,
    workspace_id: str,
    node_id: str,
    policy_id: str,
    mode: str,
    capabilities: Sequence[str],
    approval_id: str,
    principal: str = "",
    now_ms: Optional[int] = None,
) -> Dict[str, Any]:
    """Persist one live allocation. The authorizer has already said yes."""
    timestamp = int(now_ms if now_ms is not None else _now_ms())
    allocation_id = "cal_" + secrets.token_hex(8)
    db.execute(
        "INSERT INTO compute_allocations"
        " (allocation_id, workspace_id, node_id, policy_id, mode, capabilities, approval_id,"
        "  status, created_at_ms, released_at_ms)"
        " VALUES (?, ?, ?, ?, ?, ?, ?, 'active', ?, NULL)",
        (
            allocation_id,
            str(workspace_id),
            str(node_id),
            str(policy_id),
            str(mode),
            json.dumps(list(capabilities), ensure_ascii=False, separators=(",", ":")),
            str(approval_id),
            timestamp,
        ),
    )
    record_audit(db, action="allocate", outcome="allowed", node_id=str(node_id),
                 workspace_id=str(workspace_id), reason="allowed", status_code=200,
                 principal=principal, now_ms=timestamp)
    return {
        "allocation_id": allocation_id,
        "workspace_id": str(workspace_id),
        "node_id": str(node_id),
        "policy_id": str(policy_id),
        "mode": str(mode),
        "capabilities": list(capabilities),
        "approval_id": str(approval_id),
        "status": "active",
        "created_at_ms": timestamp,
    }


def cleanup_workspace(
    db: Any, workspace_id: Any, *, principal: str = "", now_ms: Optional[int] = None
) -> Dict[str, Any]:
    """Release every allocation a workspace holds. Idempotent."""
    clean = str(workspace_id or "").strip()
    if not clean:
        raise ValueError("workspace_id is required")
    timestamp = int(now_ms if now_ms is not None else _now_ms())
    released = db.execute(
        "DELETE FROM compute_allocations WHERE workspace_id = ?", (clean,)
    )
    record_audit(db, action="cleanup", outcome="allowed", workspace_id=clean,
                 status_code=200, principal=principal, now_ms=timestamp)
    return {"workspace_id": clean, "allocations": int(released)}


def self_test() -> List[str]:
    """The registry's facts: profiles, derived health and allocation counts."""
    import tempfile
    from pathlib import Path

    from app.database import Database

    checks: List[str] = []

    def check(name: str, condition: bool) -> None:
        if not condition:
            raise AssertionError("registry self_test failed: %s" % name)
        checks.append(name)

    def refuses(name: str, call: Any) -> None:
        try:
            call()
        except ValueError:
            checks.append(name)
            return
        raise AssertionError("registry self_test: %s was accepted" % name)

    check("there_are_two_node_kinds", NODE_KINDS == ("personal_node", "dedicated_worker"))
    profile = normalize_capabilities(None)
    check("an_absent_profile_gets_the_safe_defaults",
          profile["cpu_cores"] == 1 and profile["gpu"] is False and profile["labels"] == []
          and profile["max_concurrent_tasks"] == 1)
    check("a_full_profile_round_trips",
          normalize_capabilities({"cpu_cores": 8, "memory_mb": 16384, "gpu": True,
                                  "labels": ["llm", "batch"], "max_concurrent_tasks": 4})
          == {"cpu_cores": 8, "memory_mb": 16384, "gpu": True,
              "labels": ["llm", "batch"], "max_concurrent_tasks": 4})
    refuses("an_unknown_capability_key_is_refused",
            lambda: normalize_capabilities({"quantum": True}))
    refuses("a_boolean_core_count_is_refused",
            lambda: normalize_capabilities({"cpu_cores": True}))
    refuses("a_label_with_capitals_is_refused",
            lambda: normalize_capabilities({"labels": ["GPU"]}))

    tokens = capability_tokens(normalize_capabilities({"gpu": True, "labels": ["llm"]}))
    check("the_granted_tokens_are_cpu_plus_what_was_declared",
          tokens == ["cpu", "gpu", "label:llm"])
    check("a_missing_capability_is_named",
          missing_capabilities(normalize_capabilities(None), ["cpu"]) == [])
    check("an_undeclared_capability_is_missing",
          missing_capabilities(normalize_capabilities(None), ["gpu", "label:llm"])
          == ["gpu", "label:llm"])
    refuses("a_malformed_capability_token_is_refused",
            lambda: missing_capabilities(normalize_capabilities(None), ["root"]))

    check("never_heartbeating_is_unknown", health_for(None, 1) == "unknown")
    check("a_fresh_heartbeat_is_healthy", health_for(1_000, 1_000 + HEALTHY_WINDOW_MS) == "healthy")
    check("one_millisecond_past_the_window_is_degraded",
          health_for(1_000, 1_000 + HEALTHY_WINDOW_MS + 1) == "degraded")
    check("past_the_grace_window_is_offline",
          health_for(1_000, 1_000 + DEGRADED_WINDOW_MS + 1) == "offline")
    check("a_heartbeat_from_the_future_is_not_penalised", health_for(5_000, 1_000) == "healthy")

    with tempfile.TemporaryDirectory(prefix="popopx-registry-") as tmp:
        db = Database(Path(tmp) / "registry.db")
        try:
            refuses("an_uppercase_node_id_is_refused",
                    lambda: register_node(db, "Node-A", "personal_node"))
            refuses("an_unknown_kind_is_refused",
                    lambda: register_node(db, "node-a", "supercomputer"))
            node = register_node(
                db, "node-a", "personal_node", label="Ada's laptop",
                capabilities={"gpu": True, "max_concurrent_tasks": 2}, now_ms=1_700_000_000_000,
            )
            check("a_registered_node_reports_unknown_health_until_its_first_heartbeat",
                  node["health"] == "unknown" and node["last_heartbeat_ms"] is None)
            check("a_registered_node_keeps_its_profile",
                  node["capabilities"]["gpu"] is True and node["max_concurrent_tasks"] == 2)
            check("a_heartbeat_for_an_unregistered_node_is_none",
                  heartbeat(db, "node-missing", now_ms=1_700_000_000_001) is None)
            beat = heartbeat(db, "node-a", now_ms=1_700_000_000_002)
            check("a_heartbeat_makes_the_node_healthy",
                  beat is not None and beat["health"] == "healthy"
                  and beat["last_heartbeat_ms"] == 1_700_000_000_002)
            downgraded = heartbeat(
                db, "node-a", capabilities={"max_concurrent_tasks": 1},
                now_ms=1_700_000_000_003,
            )
            check("a_heartbeat_can_downgrade_the_profile",
                  downgraded["capabilities"]["gpu"] is False
                  and downgraded["max_concurrent_tasks"] == 1)
            re_registered = register_node(
                db, "node-a", "personal_node", label="renamed", now_ms=1_700_000_000_004
            )
            check("re_registering_keeps_the_last_heartbeat",
                  re_registered["last_heartbeat_ms"] == 1_700_000_000_003
                  and re_registered["label"] == "renamed")
            check("the_list_sees_the_node", [row["node_id"] for row in list_nodes(db, now_ms=1_700_000_000_005)] == ["node-a"])

            allocation = create_allocation(
                db, workspace_id="ws-1", node_id="node-a", policy_id="zero_retention",
                mode="zero_retention", capabilities=["gpu"], approval_id="apr-1",
                principal="operator-a", now_ms=1_700_000_000_006,
            )
            check("an_allocation_is_created_active",
                  allocation["allocation_id"].startswith("cal_")
                  and allocation_count(db, "node-a") == 1)
            check("the_node_view_counts_its_live_allocations",
                  get_node(db, "node-a", now_ms=1_700_000_000_007)["active_allocations"] == 1)
            cleaned = cleanup_workspace(db, "ws-1", now_ms=1_700_000_000_008)
            check("a_workspace_cleanup_releases_its_allocations",
                  cleaned["allocations"] == 1 and allocation_count(db, "node-a") == 0)
            check("cleanup_is_idempotent", cleanup_workspace(db, "ws-1")["allocations"] == 0)
            actions = [row["action"] for row in db.query("SELECT action FROM compute_audit ORDER BY id")]
            check("registrations_heartbeats_allocations_and_cleanups_are_audited",
                  actions == ["register", "heartbeat", "heartbeat", "register",
                              "allocate", "cleanup", "cleanup"])
        finally:
            db.close()

    return checks
