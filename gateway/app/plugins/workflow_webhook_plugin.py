# Copyright (c) 2026 POPOPX (popopx.chat)
# SPDX-License-Identifier: AGPL-3.0-only
"""Node-RED / Activepieces bridge: signed events out, approval cards in.

The plugin is disabled by default. Enabling it does not open a webhook by itself:
the operator creates a subscription (URL + per-subscription signing secret + event
scopes) and one or more ``X-PPX-Workflow-Token`` credentials for the inbound
trigger. Both secrets are returned exactly once, hashed/redacted afterwards.

Outbound
--------
``observe_inbound`` is called by ``InboundRouter.on_message`` for a follower's
text and button presses. It writes one delivery row per active subscription whose
``event_scopes`` contains the event type. The poll loop signs each body with
HMAC-SHA256 over ``timestamp + "." + body``, sends ``X-PPX-Timestamp`` and
``X-PPX-Signature: sha256=<hex>``, treats only 2xx as delivered, and backs off
exponentially. A subscription that fails repeatedly opens a circuit for 15
minutes; a success closes it again.

Inbound
-------
``POST /api/v1/workflows/trigger`` lives in ``app.main`` because the brief fixes
that path outside the plugin prefix. It delegates here. A token carries one or
both of ``message.send`` and ``approval.request``. A request that carries an
``action`` is *always* converted into a security card with 批准执行 / 拒绝 buttons,
even if the caller asked for plain text; the action is never executed by this
gateway. The card's callback payload is a single token (the iOS client refuses
whitespace and ``::`` in a payload), and only the card's own recipient can decide
it.

Privacy
-------
The audit row contains no text, URL, token or secret. The delivery queue has to
hold the event body for retries, so it is bounded, never logged, and pruned after
30 days. The console's delivery list intentionally shows metadata only.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import json
import logging
import re
import secrets
import time
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Dict, List, Mapping, Optional, Sequence, Tuple

from app.connectors import (
    ConnectorError,
    audit_rows,
    authorize_admin,
    constant_compare,
    json_dumps,
    new_id,
    normalize_endpoint_url,
    record_audit,
    request_pinned,
    sha256_hex,
    stable_error,
    text_or_empty,
)
from app.crypto_service import EcoError, build_action, build_card
from app.plugins import PluginDeps, PluginUnavailable

if TYPE_CHECKING:  # type-only
    from fastapi import APIRouter, Request

    from app.agent_bridge import InboundMessage

__all__ = [
    "PLUGIN_ID",
    "OUTBOUND_SCOPES",
    "INBOUND_SCOPES",
    "DEFAULT_SUBSCRIPTION_SCOPES",
    "token_refusal",
    "plan_trigger",
    "subscription_accepts",
    "build_signature_headers",
    "verify_signature",
    "backoff_ms",
    "approval_payload",
    "observe_inbound",
    "handle_trigger",
    "handle_inbound",
    "create_router",
    "poll_loop",
    "self_test",
]

LOG = logging.getLogger(__name__)

PLUGIN_ID = "workflow_webhook"
PAYLOAD_APPROVE = "workflow:approve:"
PAYLOAD_REJECT = "workflow:reject:"

OUTBOUND_SCOPES: Tuple[str, ...] = (
    "message.received",
    "card.callback",
    "approval.pending",
    "approval.decided",
    "workflow.test",
)
INBOUND_SCOPES: Tuple[str, ...] = ("message.send", "approval.request")
DEFAULT_SUBSCRIPTION_SCOPES: Tuple[str, ...] = (
    "message.received",
    "card.callback",
    "approval.pending",
    "approval.decided",
)

MAX_BODY_BYTES = 64 * 1024
MAX_ACTION_JSON_BYTES = 16 * 1024
MAX_SUBSCRIPTIONS = 20
MAX_TOKENS = 50
MAX_TEXT_CHARS = 4000
MAX_URL_CHARS = 2048
FETCH_LIMIT = 10
DELIVERY_RETENTION_MS = 30 * 24 * 3600 * 1000
TRIGGER_RETENTION_MS = 7 * 24 * 3600 * 1000
CIRCUIT_FAILURES = 8
CIRCUIT_OPEN_MS = 15 * 60 * 1000
BACKOFF_CAP_SECONDS = 300
DEFAULT_APPROVAL_TTL_MS = 24 * 3600 * 1000
REQUEST_ID_RE = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")


def _now_ms() -> int:
    return int(time.time() * 1000)


def _json_body(value: Any) -> str:
    return json_dumps(value)


def _scopes_from_text(raw: Any) -> Tuple[str, ...]:
    if raw is None:
        return ()
    if isinstance(raw, str):
        try:
            raw = json.loads(raw)
        except ValueError:
            raw = [part.strip() for part in raw.split(",")]
    if not isinstance(raw, (list, tuple, set)):
        return ()
    return tuple(sorted({str(item).strip() for item in raw if str(item).strip()}))


def _validate_scopes(raw: Any, allowed: Sequence[str], *, default: Sequence[str] = ()) -> Tuple[str, ...]:
    values = _scopes_from_text(raw)
    if not values:
        values = tuple(default)
    unknown = [value for value in values if value not in allowed]
    if unknown:
        raise ConnectorError("scope_unknown", "unknown scope(s): %s" % ",".join(sorted(unknown)))
    if not values:
        raise ConnectorError("scope_required", "at least one scope is required")
    return tuple(sorted(values))


def subscription_accepts(scopes: Any, event_type: str) -> bool:
    return event_type in _scopes_from_text(scopes)


def token_refusal(row: Mapping[str, Any], now_ms: int, required_scope: str) -> str:
    """Why this token may not perform ``required_scope``, or ``""``.

    Kept pure so the expiry/revocation/over-scope assertions do not need an HTTP
    server or a live node.
    """
    if row is None:
        return "token_unknown"
    if int(row.get("revoked") or 0):
        return "token_revoked"
    expires = row.get("expires_at_ms")
    if expires is not None and int(expires) > 0 and int(expires) <= int(now_ms):
        return "token_expired"
    if required_scope not in _scopes_from_text(row.get("scopes")):
        return "scope_forbidden"
    return ""


def plan_trigger(body: Mapping[str, Any]) -> Dict[str, Any]:
    """Normalise one inbound trigger without touching the database or network.

    The important rule lives here: an ``action`` makes the request an approval
    request even when ``kind`` says ``text``. A caller cannot get a high-risk
    action executed by labelling it as a text message.
    """
    if not isinstance(body, Mapping):
        raise ConnectorError("body_invalid", "trigger body must be a JSON object")
    raw_contact = body.get("contact_id")
    try:
        contact_id = int(raw_contact)
    except (TypeError, ValueError) as exc:
        raise ConnectorError("contact_id_required", "contact_id must be an integer") from exc
    if contact_id <= 0:
        raise ConnectorError("contact_id_required", "contact_id must be positive")
    request_id = body.get("request_id")
    if request_id is not None:
        request_id = str(request_id)
        if not REQUEST_ID_RE.match(request_id):
            raise ConnectorError("request_id_invalid", "request_id must be 1-128 chars of A-Z a-z 0-9 . _ : -")
    action = body.get("action")
    approval = body.get("approval") if isinstance(body.get("approval"), Mapping) else {}
    if action is not None and not isinstance(action, Mapping):
        raise ConnectorError("action_invalid", "action must be a JSON object")
    if action is None and isinstance(approval.get("action"), Mapping):
        action = approval.get("action")
    requested = str(body.get("kind") or ("approval" if action is not None else "text")).strip().lower()
    if requested not in ("text", "approval"):
        raise ConnectorError("kind_invalid", "kind must be 'text' or 'approval'")
    if action is not None:
        requested = "approval"
    if requested == "text":
        text = str(body.get("text") or "")
        if not text.strip():
            raise ConnectorError("text_required", "kind='text' needs a non-empty text")
        if len(text) > MAX_TEXT_CHARS:
            raise ConnectorError("text_too_long", "text exceeds %d characters" % MAX_TEXT_CHARS)
        return {"mode": "text", "contact_id": contact_id, "request_id": request_id, "text": text}
    title = str(approval.get("title") or body.get("title") or "工作流审批请求").strip()
    summary = str(approval.get("summary") or body.get("summary") or body.get("text") or "").strip()
    if not title:
        title = "工作流审批请求"
    if not summary:
        raise ConnectorError("summary_required", "approval needs a summary so the operator knows what is being approved")
    ttl_raw = approval.get("expires_in_seconds", body.get("expires_in_seconds", DEFAULT_APPROVAL_TTL_MS // 1000))
    try:
        ttl_seconds = int(ttl_raw)
    except (TypeError, ValueError) as exc:
        raise ConnectorError("expiry_invalid", "expires_in_seconds must be an integer") from exc
    if ttl_seconds < 60 or ttl_seconds > 7 * 24 * 3600:
        raise ConnectorError("expiry_invalid", "expires_in_seconds must be between 60 and 604800")
    if action is not None:
        encoded = json_dumps(dict(action))
        if len(encoded.encode("utf-8")) > MAX_ACTION_JSON_BYTES:
            raise ConnectorError("action_too_large", "action exceeds %d bytes" % MAX_ACTION_JSON_BYTES)
    return {
        "mode": "approval",
        "contact_id": contact_id,
        "request_id": request_id,
        "title": title[:120],
        "summary": summary[:2000],
        "action": dict(action) if action is not None else None,
        "expires_in_seconds": ttl_seconds,
    }


def build_signature_headers(secret: str, body: bytes, timestamp: int) -> Dict[str, str]:
    message = str(int(timestamp)).encode("ascii") + b"." + body
    digest = hmac.new(secret.encode("utf-8"), message, hashlib.sha256).hexdigest()
    return {"X-PPX-Timestamp": str(int(timestamp)), "X-PPX-Signature": "sha256=" + digest}


def verify_signature(secret: str, body: bytes, timestamp: Any, signature: Any, *, now_ms: Optional[int] = None, tolerance_seconds: int = 300) -> bool:
    """The receiver's rule, implemented here so the sender can be tested against it."""
    try:
        stamp = int(str(timestamp))
    except (TypeError, ValueError):
        return False
    now = int((now_ms if now_ms is not None else _now_ms()) / 1000)
    if abs(now - stamp) > int(tolerance_seconds):
        return False
    presented = str(signature or "")
    if presented.startswith("sha256="):
        presented = presented[7:]
    expected = hmac.new(secret.encode("utf-8"), str(stamp).encode("ascii") + b"." + body, hashlib.sha256).hexdigest()
    return constant_compare(presented, expected)


def backoff_ms(failures: int) -> int:
    failures = max(0, int(failures))
    if failures >= CIRCUIT_FAILURES:
        return CIRCUIT_OPEN_MS
    return min(BACKOFF_CAP_SECONDS, 2 ** min(failures, 8)) * 1000


def approval_payload(decision: str, approval_id: str) -> str:
    if decision not in ("approve", "reject"):
        raise ConnectorError("decision_invalid", "decision must be approve or reject")
    token = (PAYLOAD_APPROVE if decision == "approve" else PAYLOAD_REJECT) + approval_id
    if any(ch.isspace() for ch in token) or "::" in token:
        raise ConnectorError("payload_invalid", "approval id is not a single token")
    return token


def _event_data(message: "InboundMessage", handled: str = "") -> Tuple[Optional[str], Dict[str, Any]]:
    callback = getattr(message, "callback", None)
    kind = str(getattr(callback, "kind", "") or "")
    contact_id = int(getattr(message, "contact_id", 0) or 0)
    item_id = int(getattr(message, "item_id", 0) or 0)
    if contact_id <= 0:
        return None, {}
    if kind == "text":
        text = str(getattr(message, "text", "") or "")[:MAX_TEXT_CHARS]
        identity = str(item_id) if item_id > 0 else sha256_hex("%d:%s" % (contact_id, text))[:16]
        return "message.received", {
            "contact_id": contact_id,
            "item_id": item_id,
            "event_key": "msg:%d:%s" % (contact_id, identity),
            "text": text,
            "handled": handled or None,
        }
    if kind == "card_callback":
        payload = str(getattr(callback, "payload", "") or "")[:512]
        identity = str(item_id) if item_id > 0 else sha256_hex("%d:%s" % (contact_id, payload))[:16]
        return "card.callback", {
            "contact_id": contact_id,
            "item_id": item_id,
            "event_key": "cb:%d:%s" % (contact_id, identity),
            "payload": payload,
            "handled": handled or None,
        }
    return None, {}


def enqueue_event(deps: PluginDeps, event_type: str, event_id: str, data: Mapping[str, Any]) -> int:
    if event_type not in OUTBOUND_SCOPES:
        return 0
    body = {
        "id": event_id,
        "type": event_type,
        "service_id": deps.config.service_id,
        "created_at_ms": _now_ms(),
        "data": dict(data),
    }
    payload = _json_body(body)
    rows = deps.db.query(
        "SELECT id, scopes FROM workflow_subscriptions WHERE active = 1 ORDER BY created_at_ms"
    )
    written = 0
    now = _now_ms()
    for row in rows:
        if not subscription_accepts(row["scopes"], event_type):
            continue
        # ``Database.execute`` returns ``lastrowid`` for an INSERT, which is
        # non-zero even when OR IGNORE skipped the row. The count has to come from
        # ``rowcount``, otherwise a duplicate event looks like a second delivery.
        cursor = deps.db.connection().execute(
            "INSERT OR IGNORE INTO workflow_deliveries"
            " (subscription_id, event_id, event_type, payload_json, status, attempts, next_attempt_ms, created_at_ms)"
            " VALUES (?,?,?,?, 'pending', 0, ?, ?)",
            (str(row["id"]), event_id, event_type, payload, now, now),
        )
        written += 1 if cursor.rowcount > 0 else 0
    return written


def observe_inbound(deps: PluginDeps, message: "InboundMessage", handled: str = "") -> None:
    """Best-effort fan-out; an observer must never break the inbound handler."""
    try:
        event_type, data = _event_data(message, handled)
        if not event_type:
            return
        event_id = str(data.pop("event_key"))
        enqueue_event(deps, event_type, event_id, data)
    except Exception:  # noqa: BLE001 - the chat path outranks the bridge
        LOG.exception("workflow observer failed")


def _approval_fields(approval: Mapping[str, Any], token_label: str) -> List[Dict[str, Any]]:
    action = approval.get("action")
    action_label = "需要人工确认后才能执行"
    if isinstance(action, Mapping):
        action_label = str(action.get("title") or action.get("kind") or action.get("method") or "外部操作")[:80]
    return [
        {"k": "来源", "v": token_label or "工作流令牌"},
        {"k": "动作", "v": action_label},
        {"k": "有效期至", "v": time.strftime("%Y-%m-%d %H:%M", time.localtime(int(approval["expires_at_ms"]) / 1000))},
    ]


def _decision_card(approval: Mapping[str, Any], *, status: str) -> Dict[str, Any]:
    approved = status == "approved"
    title = "已批准 · " + str(approval.get("title") or "工作流审批")
    if status == "rejected":
        title = "已拒绝 · " + str(approval.get("title") or "工作流审批")
    elif status == "expired":
        title = "已过期 · " + str(approval.get("title") or "工作流审批")
    body = ("%s\n\n%s" % (approval.get("summary") or "", "工作流引擎将根据本决定继续执行。" if approved else "未执行任何外部操作。")).strip()
    return build_card(
        str(approval["card_id"]),
        title[:120],
        style="security",
        body=body[:2000],
        fields=_approval_fields(approval, str(approval.get("token_label") or "")),
        actions=[
            build_action(action_id="done", title="已处理", kind="callback", style="secondary",
                         payload="workflow:noop:" + str(approval["id"]))
        ],
        expires_at_ms=_now_ms() - 1,
    )


async def _retire_decision_card(deps: PluginDeps, approval: Mapping[str, Any], status: str) -> None:
    card = _decision_card(approval, status=status)
    try:
        await deps.eco.update_card(
            str(approval["card_id"]),
            int(approval["contact_id"]),
            title=card["title"],
            body=card.get("body"),
            fields=card.get("fields"),
            actions=card.get("actions"),
            expires_at_ms=_now_ms() - 1,
        )
    except Exception as exc:  # noqa: BLE001 - the decision is already committed
        LOG.warning("workflow approval %s decided but its card could not be retired: %s", approval.get("id"), type(exc).__name__)


async def _send_approval(deps: PluginDeps, planned: Mapping[str, Any], token_row: Mapping[str, Any]) -> Tuple[Dict[str, Any], int]:
    contact_id = int(planned["contact_id"])
    session = deps.eco.session_for(contact_id)
    if session is None or not getattr(session, "usable", False):
        raise ConnectorError("no_session", "the contact has no usable pairwise session", http_status=409)
    approval_id = new_id("wfa")
    card_id = ("wf_" + approval_id)[:64]
    expires_at_ms = _now_ms() + int(planned["expires_in_seconds"]) * 1000
    token_label = str(token_row.get("label") or token_row.get("id") or "")
    deps.db.execute(
        "INSERT INTO workflow_approvals"
        " (id, token_id, contact_id, title, summary, action_json, status, card_id, created_at_ms, expires_at_ms)"
        " VALUES (?,?,?,?,?,?, 'pending', ?, ?, ?)",
        (
            approval_id,
            str(token_row["id"]),
            contact_id,
            str(planned["title"]),
            str(planned["summary"]),
            _json_body(planned.get("action")) if planned.get("action") is not None else None,
            card_id,
            _now_ms(),
            expires_at_ms,
        ),
    )
    approval = deps.db.query_one("SELECT * FROM workflow_approvals WHERE id = ?", (approval_id,))
    if approval is None:
        raise ConnectorError("storage_error", "approval row disappeared", http_status=500)
    approval = dict(approval)
    approval["token_label"] = token_label
    card = build_card(
        card_id,
        str(planned["title"])[:120],
        style="security",
        body=("%s\n\n批准后，工作流引擎会收到一次 approval.decided 事件；本网关绝不自行执行外部操作。" % planned["summary"])[:2000],
        fields=_approval_fields(approval, token_label),
        actions=[
            build_action(action_id="approve", title="批准执行", kind="callback", style="primary",
                         payload=approval_payload("approve", approval_id), confirm=True),
            build_action(action_id="reject", title="拒绝", kind="callback", style="destructive",
                         payload=approval_payload("reject", approval_id)),
        ],
        expires_at_ms=expires_at_ms,
    )
    delivery = await deps.eco.deliver_card(card, contact_id, topic="workflow_approval")
    if not delivery.sent and not delivery.queued:
        deps.db.execute("UPDATE workflow_approvals SET status = 'failed' WHERE id = ?", (approval_id,))
        raise ConnectorError("card_not_delivered", "the approval card could not be delivered", http_status=502)
    enqueue_event(
        deps,
        "approval.pending",
        "approval:%s" % approval_id,
        {
            "approval_id": approval_id,
            "contact_id": contact_id,
            "title": str(planned["title"]),
            "summary": str(planned["summary"]),
            "expires_at_ms": expires_at_ms,
        },
    )
    return {
        "ok": True,
        "mode": "approval",
        "approval_id": approval_id,
        "card_id": card_id,
        "expires_at_ms": expires_at_ms,
        "delivered": bool(delivery.sent),
        "queued": bool(delivery.queued),
        "charged": int(delivery.charged or 0),
    }, 200


async def handle_inbound(deps: PluginDeps, message: "InboundMessage") -> bool:
    callback = getattr(message, "callback", None)
    payload = str(getattr(callback, "payload", "") or "")
    if not (payload.startswith(PAYLOAD_APPROVE) or payload.startswith(PAYLOAD_REJECT)):
        return False
    decision = "approve" if payload.startswith(PAYLOAD_APPROVE) else "reject"
    approval_id = payload.split(":", 2)[2] if payload.count(":") >= 2 else ""
    contact_id = int(getattr(message, "contact_id", 0) or 0)
    started = _now_ms()
    row = deps.db.query_one("SELECT * FROM workflow_approvals WHERE id = ?", (approval_id,)) if approval_id else None
    if row is None:
        record_audit(deps.db, connector="workflow", direction="inbound", action="approval.decide",
                     source="contact:%d" % contact_id, outcome="approval_unknown", status_code=404,
                     latency_ms=_now_ms() - started)
        return True
    approval = dict(row)
    if int(approval["contact_id"]) != contact_id:
        # A guessed payload is still a single token; the recipient check is what
        # makes it useless to anyone except the person the card was sent to.
        record_audit(deps.db, connector="workflow", direction="inbound", action="approval.decide",
                     source="contact:%d" % contact_id, outcome="contact_mismatch", status_code=403,
                     latency_ms=_now_ms() - started)
        return True
    now = _now_ms()
    if approval["status"] != "pending":
        record_audit(deps.db, connector="workflow", direction="inbound", action="approval.decide",
                     source="contact:%d" % contact_id, outcome="already_%s" % approval["status"], status_code=409,
                     latency_ms=now - started)
        return True
    if int(approval["expires_at_ms"]) <= now:
        deps.db.execute("UPDATE workflow_approvals SET status = 'expired', decided_at_ms = ? WHERE id = ? AND status = 'pending'", (now, approval_id))
        await _retire_decision_card(deps, approval, "expired")
        record_audit(deps.db, connector="workflow", direction="inbound", action="approval.decide",
                     source="contact:%d" % contact_id, outcome="approval_expired", status_code=409,
                     latency_ms=_now_ms() - started)
        return True
    status = "approved" if decision == "approve" else "rejected"
    changed = deps.db.execute(
        "UPDATE workflow_approvals SET status = ?, decided_at_ms = ?, decision_source = ? WHERE id = ? AND status = 'pending'",
        (status, now, "contact:%d" % contact_id, approval_id),
    )
    if not changed:
        record_audit(deps.db, connector="workflow", direction="inbound", action="approval.decide",
                     source="contact:%d" % contact_id, outcome="race_already_decided", status_code=409,
                     latency_ms=_now_ms() - started)
        return True
    approval["status"] = status
    approval["decided_at_ms"] = now
    await _retire_decision_card(deps, approval, status)
    action = None
    if approval.get("action_json"):
        try:
            action = json.loads(str(approval["action_json"]))
        except ValueError:
            action = None
    enqueue_event(
        deps,
        "approval.decided",
        "approval:%s:%s" % (approval_id, status),
        {
            "approval_id": approval_id,
            "contact_id": contact_id,
            "decision": status,
            "decided_at_ms": now,
            "action": action,
        },
    )
    record_audit(deps.db, connector="workflow", direction="inbound", action="approval.decide",
                 source="contact:%d" % contact_id, outcome=status, status_code=200,
                 latency_ms=_now_ms() - started)
    return True


def _verify_trigger_token(deps: PluginDeps, raw_token: str) -> Tuple[Optional[Dict[str, Any]], str]:
    presented = str(raw_token or "").strip()
    if not presented:
        return None, "token_missing"
    # The digest is indexed; compare_digest is still used on the hash so the
    # value compared is fixed-length even if a caller sends a huge header.
    digest = sha256_hex(presented)
    row = deps.db.query_one("SELECT * FROM workflow_tokens WHERE token_hash = ?", (digest,))
    if row is None:
        return None, "token_unknown"
    stored = str(row["token_hash"])
    if not constant_compare(stored, digest):
        return None, "token_unknown"
    return dict(row), ""


async def handle_trigger(deps: PluginDeps, request: "Request") -> Any:
    from fastapi.responses import JSONResponse

    started = _now_ms()

    def respond(status: int, body: Mapping[str, Any]) -> Any:
        return JSONResponse(status_code=int(status), content=dict(body))

    try:
        raw = await request.body()
    except Exception:  # noqa: BLE001
        return respond(400, {"ok": False, "error": "body_unreadable"})
    if len(raw) > MAX_BODY_BYTES:
        record_audit(deps.db, connector="workflow", direction="inbound", action="trigger",
                     source="http", outcome="body_too_large", status_code=413,
                     latency_ms=_now_ms() - started)
        return respond(413, {"ok": False, "error": "body_too_large"})
    token_row, token_error = _verify_trigger_token(deps, request.headers.get("x-ppx-workflow-token", ""))
    if token_row is None:
        record_audit(deps.db, connector="workflow", direction="inbound", action="trigger",
                     source="http", outcome=token_error, status_code=401,
                     latency_ms=_now_ms() - started)
        return respond(401, {"ok": False, "error": token_error})
    try:
        body = json.loads(raw.decode("utf-8")) if raw.strip() else None
    except (UnicodeDecodeError, ValueError):
        record_audit(deps.db, connector="workflow", direction="inbound", action="trigger",
                     source="token:%s" % token_row["id"], outcome="body_invalid_json", status_code=400,
                     latency_ms=_now_ms() - started)
        return respond(400, {"ok": False, "error": "body_invalid_json"})
    if not isinstance(body, Mapping):
        record_audit(deps.db, connector="workflow", direction="inbound", action="trigger",
                     source="token:%s" % token_row["id"], outcome="body_not_object", status_code=400,
                     latency_ms=_now_ms() - started)
        return respond(400, {"ok": False, "error": "body_not_object"})
    try:
        planned = plan_trigger(body)
    except ConnectorError as exc:
        record_audit(deps.db, connector="workflow", direction="inbound", action="trigger",
                     source="token:%s" % token_row["id"], outcome=exc.code, status_code=exc.http_status,
                     latency_ms=_now_ms() - started)
        return respond(exc.http_status, {"ok": False, "error": exc.code, "detail": exc.message})
    required = "approval.request" if planned["mode"] == "approval" else "message.send"
    refusal = token_refusal(token_row, _now_ms(), required)
    if refusal:
        record_audit(deps.db, connector="workflow", direction="inbound", action="trigger",
                     source="token:%s" % token_row["id"], scope=required, outcome=refusal,
                     status_code=403, latency_ms=_now_ms() - started)
        return respond(403, {"ok": False, "error": refusal, "scope": required})
    request_id = planned.get("request_id")
    request_key = ""
    if request_id:
        request_key = sha256_hex("%s\n%s" % (token_row["id"], request_id))
        replay = deps.db.query_one("SELECT response_json, status_code FROM workflow_triggers WHERE request_key = ?", (request_key,))
        if replay is not None:
            try:
                cached = json.loads(str(replay["response_json"]))
            except ValueError:
                cached = {"ok": True}
            cached["idempotent_replay"] = True
            record_audit(deps.db, connector="workflow", direction="inbound", action="trigger",
                         source="token:%s" % token_row["id"], scope=required, outcome="idempotent_replay",
                         status_code=int(replay["status_code"]), latency_ms=_now_ms() - started)
            return respond(int(replay["status_code"]), cached)
    try:
        deps.require()
    except PluginUnavailable as exc:
        record_audit(deps.db, connector="workflow", direction="inbound", action="trigger",
                     source="token:%s" % token_row["id"], scope=required, outcome=exc.decision.reason,
                     status_code=exc.http_status, latency_ms=_now_ms() - started)
        return respond(exc.http_status, exc.decision.as_body())
    deps.db.execute("UPDATE workflow_tokens SET last_used_at_ms = ? WHERE id = ?", (_now_ms(), str(token_row["id"])))
    try:
        if planned["mode"] == "text":
            charge = deps.charge(
                contact_id=int(planned["contact_id"]),
                ref="workflow:trigger",
                idempotency_key=("workflow_trigger:" + request_key) if request_key else None,
            )
            delivered = await deps.eco.send_frame(int(planned["contact_id"]), str(planned["text"]))
            if not delivered:
                try:
                    if int(getattr(charge, "charged", 0) or 0) > 0:
                        deps.billing.refund(
                            amount=int(charge.charged),
                            reason="workflow trigger was not delivered",
                            idempotency_key=("workflow_refund:" + request_key) if request_key else None,
                            ref="workflow:trigger",
                        )
                except Exception:  # noqa: BLE001 - refund failure is logged, never hides the 502
                    LOG.exception("workflow refund failed for contact %s", planned["contact_id"])
                raise ConnectorError("delivery_failed", "the node did not accept the message", http_status=502)
            result = {
                "ok": True,
                "mode": "text",
                "contact_id": int(planned["contact_id"]),
                "delivered": True,
                "charged": int(charge.charged),
            }
            status = 200
        else:
            charge = deps.charge(
                contact_id=int(planned["contact_id"]),
                ref="workflow:trigger",
                idempotency_key=("workflow_trigger:" + request_key) if request_key else None,
            )
            try:
                result, status = await _send_approval(deps, planned, token_row)
            except Exception:
                try:
                    if int(getattr(charge, "charged", 0) or 0) > 0:
                        deps.billing.refund(
                            amount=int(charge.charged),
                            reason="workflow approval card was not delivered",
                            idempotency_key=("workflow_refund:" + request_key) if request_key else None,
                            ref="workflow:trigger",
                        )
                except Exception:  # noqa: BLE001
                    LOG.exception("workflow refund failed for approval %s", planned.get("contact_id"))
                raise
            result["charged"] = int(charge.charged)
        result["request_id"] = request_id
        if request_key:
            deps.db.execute(
                "INSERT OR REPLACE INTO workflow_triggers (request_key, token_id, response_json, status_code, created_at_ms)"
                " VALUES (?,?,?,?,?)",
                (request_key, str(token_row["id"]), _json_body(result), status, _now_ms()),
            )
        record_audit(deps.db, connector="workflow", direction="inbound", action="trigger",
                     source="token:%s" % token_row["id"], scope=required,
                     outcome=("approval_created" if planned["mode"] == "approval" else "delivered"),
                     status_code=status, latency_ms=_now_ms() - started)
        return respond(status, result)
    except ConnectorError as exc:
        record_audit(deps.db, connector="workflow", direction="inbound", action="trigger",
                     source="token:%s" % token_row["id"], scope=required, outcome=exc.code,
                     status_code=exc.http_status, latency_ms=_now_ms() - started)
        return respond(exc.http_status, {"ok": False, "error": exc.code, "detail": exc.message})
    except EcoError as exc:
        record_audit(deps.db, connector="workflow", direction="inbound", action="trigger",
                     source="token:%s" % token_row["id"], scope=required, outcome="eco_rule_refused",
                     status_code=400, latency_ms=_now_ms() - started)
        return respond(400, {"ok": False, "error": "eco_rule_refused", "detail": exc.rule})
    except Exception as exc:  # noqa: BLE001
        LOG.exception("workflow trigger failed")
        record_audit(deps.db, connector="workflow", direction="inbound", action="trigger",
                     source="token:%s" % token_row["id"], scope=required, outcome=stable_error(exc),
                     status_code=500, latency_ms=_now_ms() - started)
        return respond(500, {"ok": False, "error": "internal_error"})


def _subscription_dict(row: Mapping[str, Any]) -> Dict[str, Any]:
    # deps.db hands back sqlite3.Row, which has no .get; the self-test fakes
    # return dicts, so normalise here rather than trusting either shape.
    row = dict(row)
    now = _now_ms()
    failures = int(row.get("failures") or 0)
    next_attempt = int(row.get("next_attempt_ms") or 0)
    return {
        "id": str(row["id"]),
        "label": str(row.get("label") or ""),
        "url": str(row.get("url") or ""),
        "scopes": list(_scopes_from_text(row.get("scopes"))),
        "allow_private": bool(row.get("allow_private")),
        "active": bool(row.get("active")),
        "secret_set": bool(row.get("secret")),
        "failures": failures,
        "circuit_open": failures >= CIRCUIT_FAILURES and next_attempt > now,
        "next_attempt_ms": next_attempt or None,
        "last_attempt_ms": row.get("last_attempt_ms"),
        "last_success_ms": row.get("last_success_ms"),
        "last_error": row.get("last_error") or None,
        "created_at_ms": row.get("created_at_ms"),
        "updated_at_ms": row.get("updated_at_ms"),
    }


def _token_dict(row: Mapping[str, Any]) -> Dict[str, Any]:
    row = dict(row)
    expires = row.get("expires_at_ms")
    return {
        "id": str(row["id"]),
        "label": str(row.get("label") or ""),
        "prefix": str(row.get("token_prefix") or ""),
        "scopes": list(_scopes_from_text(row.get("scopes"))),
        "revoked": bool(row.get("revoked")),
        "expires_at_ms": expires,
        "expired": bool(expires and int(expires) <= _now_ms()),
        "created_at_ms": row.get("created_at_ms"),
        "last_used_at_ms": row.get("last_used_at_ms"),
    }


def _approval_dict(row: Mapping[str, Any]) -> Dict[str, Any]:
    row = dict(row)
    return {
        "id": str(row["id"]),
        "contact_id": int(row["contact_id"]),
        "title": str(row.get("title") or ""),
        "summary": str(row.get("summary") or "")[:500],
        "status": str(row.get("status") or ""),
        "card_id": str(row.get("card_id") or ""),
        "created_at_ms": row.get("created_at_ms"),
        "expires_at_ms": row.get("expires_at_ms"),
        "decided_at_ms": row.get("decided_at_ms"),
        "decision_source": row.get("decision_source") or None,
        "has_action": bool(row.get("action_json")),
    }


def create_router(deps: PluginDeps) -> "APIRouter":
    from fastapi import APIRouter, Request
    from fastapi.responses import JSONResponse

    globals()["Request"] = Request
    router = APIRouter(prefix=deps.spec.url_prefix, tags=["workflow_webhook"])

    def json_response(status: int, body: Mapping[str, Any]) -> "JSONResponse":
        return JSONResponse(status_code=int(status), content=dict(body))

    def admin_refused(request: "Request") -> Optional[Any]:
        ok, reason = authorize_admin(request.headers, getattr(deps.config, "admin_token", ""))
        if ok:
            return None
        return json_response(401, {"ok": False, "plugin": PLUGIN_ID, "reason": "unauthorized", "detail": reason})

    async def read_json(request: "Request") -> Tuple[Any, Optional[Any]]:
        try:
            raw = await request.body()
        except Exception:  # noqa: BLE001
            return None, json_response(400, {"ok": False, "error": "body_unreadable"})
        if len(raw) > MAX_BODY_BYTES:
            return None, json_response(413, {"ok": False, "error": "body_too_large"})
        if not raw.strip():
            return {}, None
        try:
            parsed = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            return None, json_response(400, {"ok": False, "error": "body_invalid_json"})
        if not isinstance(parsed, dict):
            return None, json_response(400, {"ok": False, "error": "body_not_object"})
        return parsed, None

    @router.get("/status")
    async def status(request: "Request") -> Any:
        refusal = admin_refused(request)
        if refusal is not None:
            return refusal
        counts = {
            "subscriptions": int(deps.db.scalar("SELECT COUNT(*) FROM workflow_subscriptions") or 0),
            "active_subscriptions": int(deps.db.scalar("SELECT COUNT(*) FROM workflow_subscriptions WHERE active = 1") or 0),
            "tokens": int(deps.db.scalar("SELECT COUNT(*) FROM workflow_tokens WHERE revoked = 0") or 0),
            "pending_approvals": int(deps.db.scalar("SELECT COUNT(*) FROM workflow_approvals WHERE status = 'pending'") or 0),
            "deliveries_pending": int(deps.db.scalar("SELECT COUNT(*) FROM workflow_deliveries WHERE status = 'pending'") or 0),
        }
        return {
            "ok": True,
            "plugin": PLUGIN_ID,
            "counts": counts,
            "outbound_scopes": list(OUTBOUND_SCOPES),
            "inbound_scopes": list(INBOUND_SCOPES),
            "trigger_path": "/api/v1/workflows/trigger",
            "gate": deps.gate.status(PLUGIN_ID).as_body(),
        }

    @router.get("/subscriptions")
    async def subscriptions(request: "Request") -> Any:
        refusal = admin_refused(request)
        if refusal is not None:
            return refusal
        rows = deps.db.query("SELECT * FROM workflow_subscriptions ORDER BY created_at_ms DESC")
        return {"ok": True, "plugin": PLUGIN_ID, "subscriptions": [_subscription_dict(row) for row in rows]}

    @router.post("/subscriptions")
    async def subscription_create(request: "Request") -> Any:
        refusal = admin_refused(request)
        if refusal is not None:
            return refusal
        body, error = await read_json(request)
        if error is not None:
            return error
        if int(deps.db.scalar("SELECT COUNT(*) FROM workflow_subscriptions") or 0) >= MAX_SUBSCRIPTIONS:
            return json_response(409, {"ok": False, "error": "subscription_limit"})
        label = text_or_empty(body.get("label"), 80)
        allow_private = bool(body.get("allow_private"))
        try:
            scopes = _validate_scopes(body.get("scopes"), OUTBOUND_SCOPES, default=DEFAULT_SUBSCRIPTION_SCOPES)
            endpoint = normalize_endpoint_url(body.get("url"), allow_private=allow_private)
        except ConnectorError as exc:
            return json_response(exc.http_status, {"ok": False, "error": exc.code, "detail": exc.message})
        secret = secrets.token_urlsafe(32)
        subscription_id = new_id("wfs")
        now = _now_ms()
        deps.db.execute(
            "INSERT INTO workflow_subscriptions"
            " (id, label, url, secret, scopes, allow_private, active, created_at_ms, updated_at_ms, failures, next_attempt_ms)"
            " VALUES (?,?,?,?,?,?,1,?,?,0,0)",
            (subscription_id, label, endpoint.origin + endpoint.target, secret, _json_body(list(scopes)),
             int(allow_private), now, now),
        )
        record_audit(deps.db, connector="workflow", direction="outbound", action="subscription.create",
                     source="subscription:%s" % subscription_id, scope=scopes, outcome="created", status_code=201)
        row = deps.db.query_one("SELECT * FROM workflow_subscriptions WHERE id = ?", (subscription_id,))
        result = {"ok": True, "subscription": _subscription_dict(row), "secret": secret,
                  "notice": "This signing secret is shown once; configure it on the Node-RED/Activepieces receiver now."}
        return json_response(201, result)

    @router.patch("/subscriptions/{subscription_id}")
    async def subscription_update(subscription_id: str, request: "Request") -> Any:
        refusal = admin_refused(request)
        if refusal is not None:
            return refusal
        row = deps.db.query_one("SELECT * FROM workflow_subscriptions WHERE id = ?", (subscription_id,))
        if row is None:
            return json_response(404, {"ok": False, "error": "subscription_unknown"})
        body, error = await read_json(request)
        if error is not None:
            return error
        current = dict(row)
        label = text_or_empty(body.get("label"), 80) if "label" in body else str(current.get("label") or "")
        allow_private = bool(body.get("allow_private", current.get("allow_private")))
        url = str(body.get("url") or current.get("url") or "")
        try:
            scopes = _validate_scopes(body.get("scopes", current.get("scopes")), OUTBOUND_SCOPES)
            endpoint = normalize_endpoint_url(url, allow_private=allow_private) if "url" in body or "allow_private" in body else None
        except ConnectorError as exc:
            return json_response(exc.http_status, {"ok": False, "error": exc.code, "detail": exc.message})
        active = int(bool(body.get("active", current.get("active"))))
        secret = str(current.get("secret") or "")
        rotate = bool(body.get("rotate_secret"))
        if rotate:
            secret = secrets.token_urlsafe(32)
        if endpoint is not None:
            url = endpoint.origin + endpoint.target
        deps.db.execute(
            "UPDATE workflow_subscriptions SET label = ?, url = ?, secret = ?, scopes = ?, allow_private = ?,"
            " active = ?, updated_at_ms = ?, failures = 0, next_attempt_ms = 0, last_error = NULL WHERE id = ?",
            (label, url, secret, _json_body(list(scopes)), int(allow_private), active, _now_ms(), subscription_id),
        )
        record_audit(deps.db, connector="workflow", direction="outbound", action="subscription.update",
                     source="subscription:%s" % subscription_id, scope=scopes, outcome="updated", status_code=200)
        updated = deps.db.query_one("SELECT * FROM workflow_subscriptions WHERE id = ?", (subscription_id,))
        result: Dict[str, Any] = {"ok": True, "subscription": _subscription_dict(updated)}
        if rotate:
            result["secret"] = secret
            result["notice"] = "This signing secret is shown once; the previous secret stopped working."
        return result

    @router.delete("/subscriptions/{subscription_id}")
    async def subscription_delete(subscription_id: str, request: "Request") -> Any:
        refusal = admin_refused(request)
        if refusal is not None:
            return refusal
        changed = deps.db.execute(
            "UPDATE workflow_subscriptions SET active = 0, updated_at_ms = ? WHERE id = ?",
            (_now_ms(), subscription_id),
        )
        if not changed:
            return json_response(404, {"ok": False, "error": "subscription_unknown"})
        record_audit(deps.db, connector="workflow", direction="outbound", action="subscription.delete",
                     source="subscription:%s" % subscription_id, outcome="deactivated", status_code=200)
        return {"ok": True, "deactivated": subscription_id}

    @router.post("/subscriptions/{subscription_id}/test")
    async def subscription_test(subscription_id: str, request: "Request") -> Any:
        refusal = admin_refused(request)
        if refusal is not None:
            return refusal
        row = deps.db.query_one("SELECT * FROM workflow_subscriptions WHERE id = ?", (subscription_id,))
        if row is None:
            return json_response(404, {"ok": False, "error": "subscription_unknown"})
        body = {
            "id": "test:%s" % new_id("evt"),
            "type": "workflow.test",
            "service_id": deps.config.service_id,
            "created_at_ms": _now_ms(),
            "data": {"subscription_id": subscription_id, "message": "POPOPX workflow connectivity probe"},
        }
        result = await _deliver(deps, dict(row), _json_body(body).encode("utf-8"))
        return json_response(200 if result.get("ok") else 502, result)

    @router.get("/deliveries")
    async def deliveries(request: "Request") -> Any:
        refusal = admin_refused(request)
        if refusal is not None:
            return refusal
        limit = max(1, min(int(request.query_params.get("limit") or 50), 200))
        rows = deps.db.query(
            "SELECT id, subscription_id, event_id, event_type, status, attempts, next_attempt_ms,"
            " last_status_code, last_error, created_at_ms, delivered_at_ms"
            " FROM workflow_deliveries ORDER BY id DESC LIMIT ?",
            (limit,),
        )
        return {"ok": True, "plugin": PLUGIN_ID, "deliveries": [dict(row) for row in rows]}

    @router.get("/tokens")
    async def tokens(request: "Request") -> Any:
        refusal = admin_refused(request)
        if refusal is not None:
            return refusal
        rows = deps.db.query("SELECT * FROM workflow_tokens ORDER BY created_at_ms DESC")
        return {"ok": True, "plugin": PLUGIN_ID, "tokens": [_token_dict(row) for row in rows]}

    @router.post("/tokens")
    async def token_create(request: "Request") -> Any:
        refusal = admin_refused(request)
        if refusal is not None:
            return refusal
        body, error = await read_json(request)
        if error is not None:
            return error
        if int(deps.db.scalar("SELECT COUNT(*) FROM workflow_tokens WHERE revoked = 0") or 0) >= MAX_TOKENS:
            return json_response(409, {"ok": False, "error": "token_limit"})
        try:
            scopes = _validate_scopes(body.get("scopes"), INBOUND_SCOPES)
        except ConnectorError as exc:
            return json_response(exc.http_status, {"ok": False, "error": exc.code, "detail": exc.message})
        expires_in = body.get("expires_in_seconds", 30 * 24 * 3600)
        try:
            expires_in = int(expires_in)
        except (TypeError, ValueError):
            return json_response(400, {"ok": False, "error": "expiry_invalid"})
        if expires_in != 0 and not (60 <= expires_in <= 365 * 24 * 3600):
            return json_response(400, {"ok": False, "error": "expiry_invalid",
                                       "detail": "expires_in_seconds must be 0 (never) or 60..31536000"})
        raw_token = secrets.token_urlsafe(32)
        token_id = new_id("wft")
        now = _now_ms()
        expires_at = None if expires_in == 0 else now + expires_in * 1000
        deps.db.execute(
            "INSERT INTO workflow_tokens"
            " (id, label, token_hash, token_prefix, scopes, created_at_ms, expires_at_ms, revoked)"
            " VALUES (?,?,?,?,?,?,?,0)",
            (token_id, text_or_empty(body.get("label"), 80), sha256_hex(raw_token), raw_token[:8],
             _json_body(list(scopes)), now, expires_at),
        )
        record_audit(deps.db, connector="workflow", direction="inbound", action="token.create",
                     source="token:%s" % token_id, scope=scopes, outcome="created", status_code=201)
        row = deps.db.query_one("SELECT * FROM workflow_tokens WHERE id = ?", (token_id,))
        return json_response(201, {
            "ok": True,
            "token": raw_token,
            "record": _token_dict(row),
            "notice": "This token is shown once. Send it as X-PPX-Workflow-Token to /api/v1/workflows/trigger.",
        })

    @router.delete("/tokens/{token_id}")
    async def token_revoke(token_id: str, request: "Request") -> Any:
        refusal = admin_refused(request)
        if refusal is not None:
            return refusal
        changed = deps.db.execute("UPDATE workflow_tokens SET revoked = 1 WHERE id = ?", (token_id,))
        if not changed:
            return json_response(404, {"ok": False, "error": "token_unknown"})
        record_audit(deps.db, connector="workflow", direction="inbound", action="token.revoke",
                     source="token:%s" % token_id, outcome="revoked", status_code=200)
        return {"ok": True, "revoked": token_id}

    @router.get("/approvals")
    async def approvals(request: "Request") -> Any:
        refusal = admin_refused(request)
        if refusal is not None:
            return refusal
        rows = deps.db.query("SELECT * FROM workflow_approvals ORDER BY created_at_ms DESC LIMIT 100")
        return {"ok": True, "plugin": PLUGIN_ID, "approvals": [_approval_dict(row) for row in rows]}

    @router.get("/audit")
    async def audit(request: "Request") -> Any:
        refusal = admin_refused(request)
        if refusal is not None:
            return refusal
        limit = int(request.query_params.get("limit") or 100)
        return {"ok": True, "plugin": PLUGIN_ID, "audit": audit_rows(deps.db, "workflow", limit)}

    return router


async def _deliver(deps: PluginDeps, subscription: Mapping[str, Any], body: bytes) -> Dict[str, Any]:
    started = _now_ms()
    subscription_id = str(subscription["id"])
    try:
        headers = build_signature_headers(str(subscription["secret"]), body, int(time.time()))
        headers.update({
            "Content-Type": "application/json",
            "User-Agent": "POPOPX-Workflow/1.0",
            "X-PPX-Event": "workflow",
            "X-PPX-Delivery": subscription_id,
        })
        response = await asyncio.get_running_loop().run_in_executor(
            None,
            lambda: request_pinned(
                str(subscription["url"]),
                method="POST",
                headers=headers,
                body=body,
                timeout=10.0,
                allow_private=bool(subscription.get("allow_private")),
            ),
        )
        ok = 200 <= int(response.status) < 300
        outcome = "delivered" if ok else "http_%d" % int(response.status)
        record_audit(deps.db, connector="workflow", direction="outbound", action="delivery",
                     source="subscription:%s" % subscription_id, scope=subscription.get("scopes"),
                     status_code=int(response.status), outcome=outcome,
                     latency_ms=_now_ms() - started)
        return {"ok": ok, "status": int(response.status), "latency_ms": _now_ms() - started}
    except ConnectorError as exc:
        record_audit(deps.db, connector="workflow", direction="outbound", action="delivery",
                     source="subscription:%s" % subscription_id, scope=subscription.get("scopes"),
                     status_code=exc.http_status, outcome=exc.code, latency_ms=_now_ms() - started)
        return {"ok": False, "status": exc.http_status, "error": exc.code, "latency_ms": _now_ms() - started}
    except Exception as exc:  # noqa: BLE001
        record_audit(deps.db, connector="workflow", direction="outbound", action="delivery",
                     source="subscription:%s" % subscription_id, scope=subscription.get("scopes"),
                     outcome=stable_error(exc), latency_ms=_now_ms() - started)
        return {"ok": False, "error": "internal_error", "latency_ms": _now_ms() - started}


def _apply_delivery_result(deps: PluginDeps, delivery: Mapping[str, Any], subscription: Mapping[str, Any], result: Mapping[str, Any]) -> None:
    now = _now_ms()
    ok = bool(result.get("ok"))
    if ok:
        deps.db.execute(
            "UPDATE workflow_deliveries SET status = 'delivered', attempts = attempts + 1,"
            " last_status_code = ?, last_error = NULL, delivered_at_ms = ? WHERE id = ?",
            (result.get("status"), now, int(delivery["id"])),
        )
        deps.db.execute(
            "UPDATE workflow_subscriptions SET failures = 0, next_attempt_ms = 0, last_attempt_ms = ?,"
            " last_success_ms = ?, last_error = NULL WHERE id = ?",
            (now, now, str(subscription["id"])),
        )
        return
    failures = int(subscription.get("failures") or 0) + 1
    delay = backoff_ms(failures)
    error_code = str(result.get("error") or ("http_%s" % result.get("status") if result.get("status") else "delivery_failed"))
    deps.db.execute(
        "UPDATE workflow_deliveries SET attempts = attempts + 1, next_attempt_ms = ?,"
        " last_status_code = ?, last_error = ? WHERE id = ?",
        (now + delay, result.get("status"), error_code, int(delivery["id"])),
    )
    deps.db.execute(
        "UPDATE workflow_subscriptions SET failures = ?, next_attempt_ms = ?, last_attempt_ms = ?, last_error = ? WHERE id = ?",
        (failures, now + delay, now, error_code, str(subscription["id"])),
    )


async def deliver_due(deps: PluginDeps, limit: int = FETCH_LIMIT) -> int:
    now = _now_ms()
    rows = deps.db.query(
        "SELECT d.*, s.url, s.secret, s.allow_private, s.scopes AS subscription_scopes,"
        " s.failures, s.next_attempt_ms AS subscription_next_attempt_ms"
        " FROM workflow_deliveries d JOIN workflow_subscriptions s ON s.id = d.subscription_id"
        " WHERE d.status = 'pending' AND s.active = 1 AND d.next_attempt_ms <= ?"
        " AND s.next_attempt_ms <= ?"
        " ORDER BY d.next_attempt_ms, d.id LIMIT ?",
        (now, now, max(1, int(limit))),
    )
    delivered = 0
    for raw in rows:
        row = dict(raw)
        subscription = {
            "id": row["subscription_id"],
            "url": row["url"],
            "secret": row["secret"],
            "allow_private": row["allow_private"],
            "scopes": row["subscription_scopes"],
            "failures": row["failures"],
        }
        result = await _deliver(deps, subscription, str(row["payload_json"]).encode("utf-8"))
        _apply_delivery_result(deps, row, subscription, result)
        delivered += 1
    return delivered


async def _prune(deps: PluginDeps) -> None:
    now = _now_ms()
    deps.db.execute(
        "DELETE FROM workflow_deliveries WHERE created_at_ms < ? AND status = 'delivered'",
        (now - DELIVERY_RETENTION_MS,),
    )
    deps.db.execute(
        "DELETE FROM workflow_triggers WHERE created_at_ms < ?",
        (now - TRIGGER_RETENTION_MS,),
    )


async def poll_loop(deps: PluginDeps, stop_event: Any) -> None:
    last_prune = 0
    while not getattr(stop_event, "is_set", lambda: True)():
        try:
            await deliver_due(deps)
            now = _now_ms()
            if now - last_prune > 3600 * 1000:
                await _prune(deps)
                last_prune = now
        except Exception:  # noqa: BLE001 - a poller that dies silently is worse
            LOG.exception("workflow delivery poll failed")
        try:
            await asyncio.wait_for(stop_event.wait(), timeout=2.0)
        except asyncio.TimeoutError:
            continue
        except Exception:  # noqa: BLE001
            return


# ───────────────────────────────── self-test ────────────────────────────────


def self_test() -> List[str]:
    checks: List[str] = []

    def check(name: str, condition: bool) -> None:
        if not condition:
            raise AssertionError("workflow self_test failed: %s" % name)
        checks.append(name)

    def refused(name: str, code: str, fn: Any) -> None:
        try:
            fn()
        except ConnectorError as exc:
            check(name, exc.code == code)
        except EcoError as exc:
            check(name, exc.rule == code)
        else:
            check(name, False)

    # ── scopes and token lifecycle ─────────────────────────────────────────
    check("subscription_scopes_match_the_exact_event",
          subscription_accepts('["message.received"]', "message.received")
          and not subscription_accepts('["message.received"]', "card.callback"))
    check("subscription_scopes_accept_a_comma_string", subscription_accepts("message.received,card.callback", "card.callback"))
    check("a_workflow_test_is_not_sent_by_a_message_scope",
          not subscription_accepts('["message.received"]', "workflow.test"))
    refused("an_unknown_scope_is_refused", "scope_unknown",
            lambda: _validate_scopes(["message.received", "root"], OUTBOUND_SCOPES))
    refused("an_empty_scope_list_is_refused", "scope_required",
            lambda: _validate_scopes([], OUTBOUND_SCOPES))

    now = _now_ms()
    good = {"id": "t1", "revoked": 0, "expires_at_ms": now + 10000, "scopes": '["message.send","approval.request"]'}
    check("a_live_token_with_the_scope_passes", token_refusal(good, now, "message.send") == "")
    check("a_revoked_token_is_refused", token_refusal({**good, "revoked": 1}, now, "message.send") == "token_revoked")
    check("an_expired_token_is_refused", token_refusal({**good, "expires_at_ms": now - 1}, now, "message.send") == "token_expired")
    check("a_token_without_the_scope_is_refused", token_refusal(good, now, "approval.request") == ""
          and token_refusal({**good, "scopes": '["message.send"]'}, now, "approval.request") == "scope_forbidden")
    check("a_token_with_no_expiry_is_long_lived",
          token_refusal({**good, "expires_at_ms": None}, now, "message.send") == "")
    check("an_unknown_token_is_refused", token_refusal(None, now, "message.send") == "token_unknown")

    # ── the approval rule cannot be talked out of ──────────────────────────
    plain = plan_trigger({"contact_id": 7, "kind": "text", "text": "hello"})
    check("a_plain_trigger_stays_text", plain["mode"] == "text" and plain["contact_id"] == 7)
    forced = plan_trigger({"contact_id": 7, "kind": "text", "text": "hello", "action": {"method": "POST", "url": "https://example/x"}})
    check("an_action_forces_approval_even_when_kind_says_text",
          forced["mode"] == "approval" and forced["action"]["method"] == "POST")
    nested = plan_trigger({"contact_id": 7, "approval": {"summary": "rotate key", "action": {"op": "rotate"}}})
    check("a_nested_action_also_forces_approval", nested["mode"] == "approval" and nested["action"]["op"] == "rotate")
    refused("an_empty_text_is_refused", "text_required",
            lambda: plan_trigger({"contact_id": 7, "kind": "text", "text": "  "}))
    refused("an_unknown_kind_is_refused", "kind_invalid",
            lambda: plan_trigger({"contact_id": 7, "kind": "execute", "action": {}}))
    refused("a_contact_id_is_required", "contact_id_required",
            lambda: plan_trigger({"text": "hi"}))
    refused("a_bad_request_id_is_refused", "request_id_invalid",
            lambda: plan_trigger({"contact_id": 7, "request_id": "a b c", "text": "hi"}))
    refused("an_approval_without_a_summary_is_refused", "summary_required",
            lambda: plan_trigger({"contact_id": 7, "kind": "approval", "title": "x"}))
    refused("an_overlong_action_is_refused", "action_too_large",
            lambda: plan_trigger({"contact_id": 7, "summary": "rotate", "action": {"blob": "x" * (MAX_ACTION_JSON_BYTES + 1)}}))
    check("the_summary_is_clipped_to_the_card_body_budget", len(plan_trigger(
        {"contact_id": 7, "action": {}, "summary": "x" * 5000})["summary"]) == 2000)

    # ── signature and replay window ────────────────────────────────────────
    secret = "s" * 43
    raw = b'{"id":"e1","type":"message.received"}'
    headers = build_signature_headers(secret, raw, 1_800_000_000)
    check("the_signature_is_sha256_prefixed", headers["X-PPX-Signature"].startswith("sha256="))
    check("the_timestamp_is_the_signed_second", headers["X-PPX-Timestamp"] == "1800000000")
    check("the_signature_verifies",
          verify_signature(secret, raw, headers["X-PPX-Timestamp"], headers["X-PPX-Signature"],
                           now_ms=1_800_000_000_000))
    check("a_tampered_body_fails", not verify_signature(
        secret, raw + b" ", headers["X-PPX-Timestamp"], headers["X-PPX-Signature"], now_ms=1_800_000_000_000))
    check("the_wrong_secret_fails", not verify_signature(
        "t" * 43, raw, headers["X-PPX-Timestamp"], headers["X-PPX-Signature"], now_ms=1_800_000_000_000))
    check("a_stale_timestamp_fails", not verify_signature(
        secret, raw, headers["X-PPX-Timestamp"], headers["X-PPX-Signature"], now_ms=1_800_001_000_000))
    check("a_bare_hex_signature_is_also_accepted", verify_signature(
        secret, raw, headers["X-PPX-Timestamp"], headers["X-PPX-Signature"][7:], now_ms=1_800_000_000_000))
    check("a_non_numeric_timestamp_fails", not verify_signature(
        secret, raw, "soon", headers["X-PPX-Signature"], now_ms=1_800_000_000_000))

    # ── retry and circuit breaker ──────────────────────────────────────────
    check("the_first_failure_backs_off_two_seconds", backoff_ms(1) == 2000)
    check("the_backoff_doubles", backoff_ms(2) == 4000 and backoff_ms(3) == 8000)
    check("the_backoff_has_a_ceiling", backoff_ms(7) <= BACKOFF_CAP_SECONDS * 1000)
    check("the_circuit_opens_at_the_failure_threshold", backoff_ms(CIRCUIT_FAILURES) == CIRCUIT_OPEN_MS)
    check("the_circuit_stays_open_after_more_failures", backoff_ms(CIRCUIT_FAILURES + 5) == CIRCUIT_OPEN_MS)

    # ── payload tokens the iOS client will accept ──────────────────────────
    check("approve_payload_is_one_token", approval_payload("approve", "wfa_abc") == "workflow:approve:wfa_abc")
    check("reject_payload_is_one_token", approval_payload("reject", "wfa_abc") == "workflow:reject:wfa_abc")
    check("a_payload_has_no_whitespace_or_double_colon",
          " " not in approval_payload("approve", "wfa_abc") and "::" not in approval_payload("approve", "wfa_abc"))
    refused("an_unknown_decision_is_refused", "decision_invalid", lambda: approval_payload("maybe", "x"))

    # ── the card shape is the client's, not ours ───────────────────────────
    card = build_card(
        "wf_test", "审批请求", style="security", body="summary",
        fields=[{"k": "来源", "v": "Node-RED"}],
        actions=[build_action(action_id="approve", title="批准", kind="callback", style="primary",
                              payload=approval_payload("approve", "wfa_abc"))],
    )
    check("the_approval_card_uses_a_legal_style", card["v"] == "security")
    check("the_approval_card_payload_is_a_callback_token", card["actions"][0]["payload"].startswith("workflow:approve:"))
    check("the_approval_card_expiry_is_a_legal_timestamp", card["ut"] > 0)
    refused("the_client_still_refuses_none_actions", "action_kind",
            lambda: build_action(action_id="x", title="x", kind="none"))

    # ── DB-backed enqueue fan-out and idempotent enqueue ───────────────────
    import tempfile
    from pathlib import Path

    from app.database import Database

    root = Path(tempfile.mkdtemp(prefix="popopx-workflow-selftest-"))
    try:
        db = Database(root / "workflow.db")
        now_ms = _now_ms()
        db.execute(
            "INSERT INTO workflow_subscriptions (id,label,url,secret,scopes,allow_private,active,created_at_ms,updated_at_ms)"
            " VALUES ('wfs_a','a','https://93.184.216.34/hook','s',?,0,1,?,?)",
            (_json_body(["message.received"]), now_ms, now_ms),
        )
        db.execute(
            "INSERT INTO workflow_subscriptions (id,label,url,secret,scopes,allow_private,active,created_at_ms,updated_at_ms)"
            " VALUES ('wfs_b','b','https://93.184.216.34/hook','s',?,0,1,?,?)",
            (_json_body(["card.callback"]), now_ms, now_ms),
        )

        class _Deps:
            pass

        deps = _Deps()
        deps.db = db
        deps.config = type("C", (), {"service_id": "svc.test"})()
        check("only_the_subscribed_scope_receives_the_event",
              enqueue_event(deps, "message.received", "msg:1:1", {"contact_id": 1}) == 1)
        check("the_same_event_id_is_inserted_once_per_subscription",
              enqueue_event(deps, "message.received", "msg:1:1", {"contact_id": 1}) == 0)
        check("a_different_event_reaches_the_same_subscription",
              enqueue_event(deps, "message.received", "msg:1:2", {"contact_id": 1}) == 1)
        check("a_card_callback_reaches_only_its_subscriber",
              enqueue_event(deps, "card.callback", "cb:1:1", {"contact_id": 1}) == 1)
        check("an_unknown_event_is_not_enqueued",
              enqueue_event(deps, "root.execute", "x", {}) == 0)
        payloads = [json.loads(str(row["payload_json"])) for row in db.query(
            "SELECT payload_json FROM workflow_deliveries ORDER BY id")]
        check("the_delivery_payload_carries_the_event_envelope",
              all(set(item) == {"id", "type", "service_id", "created_at_ms", "data"} for item in payloads))
        check("the_delivery_payload_is_not_the_raw_request", all("secret" not in str(item) for item in payloads))
    finally:
        import shutil

        shutil.rmtree(root, ignore_errors=True)

    # ── sqlite3.Row, the type the routes really receive ────────────────────
    # A dict-shaped fake let all three helpers ship with `.get` and 500 on the
    # first admin click; these rows are sqlite3.Row with the same columns.
    import sqlite3

    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    token_row = conn.execute(
        "SELECT 'tok_1' AS id, 'node-red' AS label, 'wfp_abc' AS token_prefix, ? AS scopes,"
        " 0 AS revoked, NULL AS expires_at_ms, 10 AS created_at_ms, NULL AS last_used_at_ms",
        (_json_body(["message.send"]),),
    ).fetchone()
    subscription_row = conn.execute(
        "SELECT 'sub_1' AS id, 'flow' AS label, 'https://93.184.216.34/hook' AS url, 's' AS secret,"
        " ? AS scopes, 0 AS allow_private, 1 AS active, 2 AS failures, 0 AS next_attempt_ms,"
        " 5 AS last_attempt_ms, NULL AS last_success_ms, 'http_500' AS last_error,"
        " 10 AS created_at_ms, 11 AS updated_at_ms",
        (_json_body(["message.received"]),),
    ).fetchone()
    approval_row = conn.execute(
        "SELECT 'wfa_1' AS id, 7 AS contact_id, 'rotate' AS title, 'rotate the key' AS summary,"
        " 'pending' AS status, 'card_1' AS card_id, '{}' AS action_json,"
        " 10 AS created_at_ms, 20 AS expires_at_ms, NULL AS decided_at_ms, NULL AS decision_source",
    ).fetchone()
    check("a_real_sqlite_row_renders_as_a_token", _token_dict(token_row)["scopes"] == ["message.send"])
    check("a_real_sqlite_row_renders_as_a_subscription",
          _subscription_dict(subscription_row)["circuit_open"] is False)
    check("a_real_sqlite_row_renders_as_an_approval",
          _approval_dict(approval_row)["contact_id"] == 7 and _approval_dict(approval_row)["has_action"])
    conn.close()

    return checks