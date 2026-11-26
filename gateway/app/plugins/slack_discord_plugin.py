# Copyright (c) 2026 POPOPX (popopx.chat)
# SPDX-License-Identifier: AGPL-3.0-only
"""Slack / Discord bridge: one signed HTTP POST out, no message history kept.

The plugin is disabled by default (`POPOPX_PLUGIN_SLACK_DISCORD=0`). It owns no
inbound callback kind and no chat protocol state: the gateway never learns a
Slack or Discord identity, and it never stores channel keys for either service.
An admin creates one workspace row per incoming webhook, then posts text through
`POST /api/v1/plugins/slackdiscord/send`. The message text exists only in the
request body and the outbound HTTP request; the only durable trace is an audit
row with the action, the outcome and the HTTP status.

Security
--------
* The webhook URL is a bearer credential (the path is the secret), so it is
  sealed with the vault when `POPOPX_VAULT_KEY` is set and is never returned by
  any route. The console sees only the host.
* Each workspace gets its own HMAC-SHA256 signing secret, returned exactly once.
  Every delivery carries `X-Popopx-Timestamp` and
  `X-Popopx-Signature: v1=<hex HMAC-SHA256(secret, "<ts>.<body>")>` so a relay
  in front of Slack/Discord can reject anything the gateway did not send.
* Deliveries go through `connectors.request_pinned`: no redirects, no proxy, a
  DNS answer that was checked before connecting. Public destinations must be a
  known Slack/Discord webhook host over HTTPS; `allow_private` is only for a
  loopback receiver the operator runs themselves, and a LAN address is refused
  because it would move the webhook bearer token in clear text.

The bridge is metered (`slack_discord_event`); a failed delivery is refunded and
recorded, so an unreachable webhook cannot silently drain the balance.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import ipaddress
import json
import logging
import secrets
import time
import urllib.parse
from typing import TYPE_CHECKING, Any, Dict, List, Mapping, Optional, Tuple

from app import admin_auth
from app.connectors import (
    ConnectorError,
    audit_rows,
    authorize_admin,
    json_dumps,
    new_id,
    normalize_endpoint_url,
    record_audit,
    request_pinned,
    stable_error,
    text_or_empty,
)
from app.plugins import PluginDeps

if TYPE_CHECKING:  # type-only
    from fastapi import APIRouter, Request

    from app.agent_bridge import InboundMessage

__all__ = [
    "PLUGIN_ID",
    "PLATFORMS",
    "MAX_WORKSPACES",
    "MAX_TEXT_CHARS",
    "signature_headers",
    "verify_signature",
    "validate_webhook",
    "workspace_public",
    "deliver_webhook",
    "create_router",
    "handle_inbound",
    "self_test",
]

LOG = logging.getLogger(__name__)

PLUGIN_ID = "slack_discord"
PLATFORMS: Tuple[str, ...] = ("slack", "discord")
SLACK_WEBHOOK_HOSTS = ("hooks.slack.com",)
DISCORD_WEBHOOK_HOSTS = ("discord.com", "discordapp.com", "ptb.discord.com", "canary.discord.com")

MAX_WORKSPACES = 10
MAX_TEXT_CHARS = 2000
MAX_TITLE_CHARS = 200
MAX_LABEL_CHARS = 80
MAX_URL_CHARS = 2048
MAX_BODY_BYTES = 16 * 1024
DELIVERY_TIMEOUT_SECONDS = 10.0
SIGNATURE_VERSION = "v1"


def _now_ms() -> int:
    return int(time.time() * 1000)


def signature_headers(secret: str, body: bytes, timestamp: Optional[int] = None) -> Dict[str, str]:
    stamp = str(int(time.time()) if timestamp is None else int(timestamp))
    digest = hmac.new(secret.encode("utf-8"), stamp.encode("ascii") + b"." + body, hashlib.sha256).hexdigest()
    return {
        "X-Popopx-Timestamp": stamp,
        "X-Popopx-Signature": "%s=%s" % (SIGNATURE_VERSION, digest),
    }


def verify_signature(
    secret: str,
    body: bytes,
    timestamp: Any,
    signature: Any,
    *,
    now_ms: Optional[int] = None,
    tolerance_seconds: int = 300,
) -> bool:
    """The receiver-side check the self-test proves; kept here so the documented
    contract and the tested one are the same code, not two prose copies."""
    try:
        stamp = int(str(timestamp))
    except (TypeError, ValueError):
        return False
    current_ms = _now_ms() if now_ms is None else int(now_ms)
    if abs(current_ms - stamp * 1000) > int(tolerance_seconds) * 1000:
        return False
    provided = str(signature or "")
    if provided.startswith(SIGNATURE_VERSION + "="):
        provided = provided[len(SIGNATURE_VERSION) + 1:]
    expected = hmac.new(secret.encode("utf-8"), str(stamp).encode("ascii") + b"." + body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(provided.encode("utf-8", "replace"), expected.encode("utf-8"))


def validate_webhook(platform: str, url: Any, *, allow_private: bool = False) -> Any:
    """Validate one incoming-webhook URL for a platform.

    Public: a known Slack/Discord host over HTTPS. Private: loopback only, and
    only when the operator opted in — a self-hosted relay is a test harness, not
    a reason to send a bearer URL across a LAN.
    """
    if platform not in PLATFORMS:
        raise ConnectorError("platform_invalid", "platform must be slack or discord")
    if not allow_private:
        # The host allowlist is answered before DNS: an unknown public host must
        # be refused for being unknown, not for failing to resolve on this box.
        try:
            host = (urllib.parse.urlsplit(text_or_empty(url, MAX_URL_CHARS)).hostname or "").strip().lower()
        except ValueError as exc:
            raise ConnectorError("url_invalid", "URL could not be parsed") from exc
        allowed = SLACK_WEBHOOK_HOSTS if platform == "slack" else DISCORD_WEBHOOK_HOSTS
        if host not in allowed:
            raise ConnectorError(
                "platform_host",
                "a %s webhook must point at one of: %s" % (platform, ", ".join(allowed)),
            )
    endpoint = normalize_endpoint_url(url, allow_private=allow_private)
    if allow_private:
        addresses = endpoint.addresses or ()
        if not addresses or not all(ipaddress.ip_address(address).is_loopback for address in addresses):
            raise ConnectorError(
                "url_not_loopback",
                "allow_private only accepts a loopback receiver; a LAN address would expose the webhook secret",
            )
    return endpoint


def _url_host(url: str) -> str:
    try:
        return (urllib.parse.urlsplit(url).hostname or "").lower()
    except ValueError:
        return ""


def workspace_public(row: Optional[Mapping[str, Any]]) -> Dict[str, Any]:
    """The admin-facing view of one workspace: metadata and the host, never the
    webhook path (which is the credential) or the signing secret."""
    if row is None:
        return {"configured": False}
    row = dict(row)
    return {
        "id": str(row.get("id") or ""),
        "label": str(row.get("label") or ""),
        "platform": str(row.get("platform") or ""),
        "url_host": _url_host(str(row.get("webhook_url") or "")),
        "secret_set": bool(row.get("secret")),
        "allow_private": bool(row.get("allow_private")),
        "active": bool(row.get("active")),
        "created_at_ms": row.get("created_at_ms"),
        "updated_at_ms": row.get("updated_at_ms"),
        "last_delivery_ms": row.get("last_delivery_ms"),
        "last_status_code": row.get("last_status_code"),
        "last_error": row.get("last_error") or None,
    }


def _payload(platform: str, text: str, title: str) -> bytes:
    if title:
        heading = "*%s*\n%s" % (title, text) if platform == "slack" else "**%s**\n%s" % (title, text)
    else:
        heading = text
    body = {"text": heading} if platform == "slack" else {"content": heading}
    return json_dumps(body).encode("utf-8")


def _audit(deps: Any, workspace_id: str, action: str, outcome: str, status_code: Optional[int] = None) -> None:
    deps.db.execute(
        "INSERT INTO slack_discord_audit (workspace_id, action, outcome, status_code, created_at_ms)"
        " VALUES (?,?,?,?,?)",
        (workspace_id, action, outcome, status_code, _now_ms()),
    )


async def deliver_webhook(deps: Any, row: Mapping[str, Any], text: str, *, title: str = "") -> Dict[str, Any]:
    """POST one message and record metadata only. Raises `ConnectorError` for a
    refused endpoint; transport failures come back as `ok: false` with a stable
    code so the caller can refund and continue."""
    workspace_id = str(row.get("id") or "")
    platform = str(row.get("platform") or "")
    if platform not in PLATFORMS:
        raise ConnectorError("platform_invalid", "workspace platform is not slack or discord")
    url = deps.vault.open(str(row.get("webhook_url") or ""), table="slack_discord_workspaces",
                          column="webhook_url", subject=workspace_id)
    secret = deps.vault.open(str(row.get("secret") or ""), table="slack_discord_workspaces",
                             column="secret", subject=workspace_id)
    endpoint = validate_webhook(platform, url, allow_private=bool(row.get("allow_private")))
    body = _payload(platform, text, title)
    headers = {
        "Content-Type": "application/json",
        "User-Agent": "POPOPX-SlackDiscord/1.0",
        "X-Popopx-Workspace": workspace_id,
    }
    if secret:
        headers.update(signature_headers(secret, body))
    started = _now_ms()
    try:
        response = await asyncio.get_running_loop().run_in_executor(
            None,
            lambda: request_pinned(
                url,
                method="POST",
                headers=headers,
                body=body,
                timeout=DELIVERY_TIMEOUT_SECONDS,
                allow_private=bool(row.get("allow_private")),
            ),
        )
    except ConnectorError as exc:
        deps.db.execute(
            "UPDATE slack_discord_workspaces SET last_delivery_ms = ?, last_status_code = NULL,"
            " last_error = ? WHERE id = ?",
            (_now_ms(), exc.code, workspace_id),
        )
        _audit(deps, workspace_id, "delivery", exc.code, exc.http_status)
        return {"ok": False, "error": exc.code, "latency_ms": _now_ms() - started}
    ok = 200 <= int(response.status) < 300
    deps.db.execute(
        "UPDATE slack_discord_workspaces SET last_delivery_ms = ?, last_status_code = ?, last_error = ? WHERE id = ?",
        (_now_ms(), int(response.status), None if ok else "http_%d" % int(response.status), workspace_id),
    )
    _audit(deps, workspace_id, "delivery", "delivered" if ok else "http_%d" % int(response.status), int(response.status))
    return {
        "ok": ok,
        "status": int(response.status),
        "latency_ms": _now_ms() - started,
        "endpoint_error": None if ok else "http_%d" % int(response.status),
    }


def create_router(deps: PluginDeps) -> "APIRouter":
    from fastapi import APIRouter, Request
    from fastapi.responses import JSONResponse

    globals()["Request"] = Request
    router = APIRouter(prefix=deps.spec.url_prefix, tags=["slack_discord"])

    def json_response(status: int, body: Mapping[str, Any]) -> "JSONResponse":
        return JSONResponse(status_code=int(status), content=dict(body))

    def admin_refused(request: "Request") -> Optional[Any]:
        # The gateway middleware already resolved a scoped token and, for it,
        # checked `plugin:slack_discord`. Only a direct handler call (this
        # module's own self-test) reaches the root-token fallback.
        if admin_auth.grant_from_request(request) is not None:
            return None
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
            return None, json_response(400, {"ok": False, "error": "body_invalid_json"})
        return parsed, None

    def gate_refusal() -> Optional[Any]:
        # Outbound HTTP does not need the chat node: a standalone gateway can
        # still notify Slack. Toggle and billing still apply in full.
        decision = deps.gate.status(PLUGIN_ID, node_required=False)
        if decision.usable:
            return None
        return json_response(decision.http_status, decision.as_body())

    def row_for(workspace_id: str) -> Optional[Dict[str, Any]]:
        row = deps.db.query_one("SELECT * FROM slack_discord_workspaces WHERE id = ?", (workspace_id,))
        return dict(row) if row is not None else None

    @router.get("/status")
    async def status(request: "Request") -> Any:
        refusal = admin_refused(request)
        if refusal is not None:
            return refusal
        active = int(deps.db.scalar("SELECT COUNT(*) FROM slack_discord_workspaces WHERE active = 1") or 0)
        total = int(deps.db.scalar("SELECT COUNT(*) FROM slack_discord_workspaces") or 0)
        return {
            "ok": True,
            "plugin": PLUGIN_ID,
            "platforms": list(PLATFORMS),
            "workspaces": total,
            "active_workspaces": active,
            "signature": "%s=HMAC-SHA256(secret, timestamp.body)" % SIGNATURE_VERSION,
            "storage": "webhook URL and signing secret are sealed when POPOPX_VAULT_KEY is set; no message text is stored",
            "gate": deps.gate.status(PLUGIN_ID, node_required=False).as_body(),
        }

    @router.get("/workspaces")
    async def workspaces(request: "Request") -> Any:
        refusal = admin_refused(request)
        if refusal is not None:
            return refusal
        rows = deps.db.query("SELECT * FROM slack_discord_workspaces ORDER BY created_at_ms DESC")
        return {"ok": True, "plugin": PLUGIN_ID, "workspaces": [workspace_public(row) for row in rows]}

    @router.post("/workspaces")
    async def workspace_create(request: "Request") -> Any:
        refusal = admin_refused(request)
        if refusal is not None:
            return refusal
        body, error = await read_json(request)
        if error is not None:
            return error
        if int(deps.db.scalar("SELECT COUNT(*) FROM slack_discord_workspaces") or 0) >= MAX_WORKSPACES:
            return json_response(409, {"ok": False, "error": "workspace_limit"})
        platform = str(body.get("platform") or "").strip().lower()
        allow_private = bool(body.get("allow_private"))
        try:
            endpoint = validate_webhook(platform, body.get("webhook_url"), allow_private=allow_private)
        except ConnectorError as exc:
            return json_response(exc.http_status, {"ok": False, "error": exc.code, "detail": exc.message})
        workspace_id = new_id("sdw")
        secret = secrets.token_urlsafe(32)
        now = _now_ms()
        deps.db.execute(
            "INSERT INTO slack_discord_workspaces"
            " (id, label, platform, webhook_url, secret, allow_private, active, created_at_ms, updated_at_ms)"
            " VALUES (?,?,?,?,?,?,1,?,?)",
            (
                workspace_id,
                text_or_empty(body.get("label"), MAX_LABEL_CHARS),
                platform,
                deps.vault.seal(endpoint.origin + endpoint.target, table="slack_discord_workspaces",
                                column="webhook_url", subject=workspace_id),
                deps.vault.seal(secret, table="slack_discord_workspaces", column="secret", subject=workspace_id),
                int(allow_private),
                now,
                now,
            ),
        )
        _audit(deps, workspace_id, "workspace.create", "created", 201)
        return json_response(201, {
            "ok": True,
            "plugin": PLUGIN_ID,
            "workspace": workspace_public(row_for(workspace_id)),
            "secret": secret,
            "notice": "This signing secret is shown once; the webhook URL itself is never returned.",
        })

    @router.patch("/workspaces/{workspace_id}")
    async def workspace_update(workspace_id: str, request: "Request") -> Any:
        refusal = admin_refused(request)
        if refusal is not None:
            return refusal
        current = row_for(workspace_id)
        if current is None:
            return json_response(404, {"ok": False, "error": "workspace_unknown"})
        body, error = await read_json(request)
        if error is not None:
            return error
        platform = str(current.get("platform") or "")
        allow_private = bool(body.get("allow_private", current.get("allow_private")))
        label = text_or_empty(body.get("label"), MAX_LABEL_CHARS) if "label" in body else str(current.get("label") or "")
        active = int(bool(body.get("active", current.get("active"))))
        stored_url = str(current.get("webhook_url") or "")
        if "webhook_url" in body or "allow_private" in body:
            plain_url = deps.vault.open(stored_url, table="slack_discord_workspaces",
                                        column="webhook_url", subject=workspace_id)
            candidate = body.get("webhook_url", plain_url)
            try:
                endpoint = validate_webhook(platform, candidate, allow_private=allow_private)
            except ConnectorError as exc:
                return json_response(exc.http_status, {"ok": False, "error": exc.code, "detail": exc.message})
            stored_url = deps.vault.seal(endpoint.origin + endpoint.target, table="slack_discord_workspaces",
                                         column="webhook_url", subject=workspace_id)
        rotate = bool(body.get("rotate_secret"))
        stored_secret = str(current.get("secret") or "")
        new_secret = ""
        if rotate:
            new_secret = secrets.token_urlsafe(32)
            stored_secret = deps.vault.seal(new_secret, table="slack_discord_workspaces",
                                            column="secret", subject=workspace_id)
        deps.db.execute(
            "UPDATE slack_discord_workspaces SET label = ?, webhook_url = ?, secret = ?, allow_private = ?,"
            " active = ?, updated_at_ms = ? WHERE id = ?",
            (label, stored_url, stored_secret, int(allow_private), active, _now_ms(), workspace_id),
        )
        _audit(deps, workspace_id, "workspace.update", "updated", 200)
        result: Dict[str, Any] = {"ok": True, "plugin": PLUGIN_ID, "workspace": workspace_public(row_for(workspace_id))}
        if rotate:
            result["secret"] = new_secret
            result["notice"] = "This signing secret is shown once; the previous secret stopped working."
        return result

    @router.delete("/workspaces/{workspace_id}")
    async def workspace_delete(workspace_id: str, request: "Request") -> Any:
        refusal = admin_refused(request)
        if refusal is not None:
            return refusal
        if row_for(workspace_id) is None:
            return json_response(404, {"ok": False, "error": "workspace_unknown"})
        deps.db.execute("DELETE FROM slack_discord_workspaces WHERE id = ?", (workspace_id,))
        _audit(deps, workspace_id, "workspace.delete", "deleted", 200)
        return {"ok": True, "plugin": PLUGIN_ID, "deleted": workspace_id}

    @router.post("/send")
    async def send(request: "Request") -> Any:
        refusal = admin_refused(request)
        if refusal is not None:
            return refusal
        body, error = await read_json(request)
        if error is not None:
            return error
        gated = gate_refusal()
        if gated is not None:
            return gated
        workspace_id = text_or_empty(body.get("workspace_id"), 80)
        row = row_for(workspace_id)
        if row is None:
            return json_response(404, {"ok": False, "error": "workspace_unknown"})
        if not bool(row.get("active")):
            return json_response(409, {"ok": False, "error": "workspace_inactive"})
        text = str(body.get("text") or "").replace("\x00", "").strip()
        if not text:
            return json_response(400, {"ok": False, "error": "text_required"})
        if len(text) > MAX_TEXT_CHARS:
            return json_response(400, {"ok": False, "error": "text_too_long"})
        title = text_or_empty(body.get("title"), MAX_TITLE_CHARS)
        charge = deps.charge(ref="slack_discord:%s" % workspace_id)
        try:
            result = await deliver_webhook(deps, row, text, title=title)
        except ConnectorError as exc:
            _refund(deps, charge, "slack_discord refused")
            return json_response(exc.http_status, {"ok": False, "error": exc.code, "detail": exc.message})
        except Exception:  # noqa: BLE001
            _refund(deps, charge, "slack_discord failed")
            LOG.exception("slack/discord delivery failed")
            return json_response(500, {"ok": False, "error": "internal_error"})
        if not result.get("ok"):
            _refund(deps, charge, "slack_discord delivery failed")
        return {
            "ok": bool(result.get("ok")),
            "plugin": PLUGIN_ID,
            "workspace_id": workspace_id,
            "status": result.get("status"),
            "latency_ms": result.get("latency_ms"),
            "charged": int(getattr(charge, "charged", 0) or 0) if result.get("ok") else 0,
            "error": result.get("error") or result.get("endpoint_error"),
        }

    @router.get("/audit")
    async def audit(request: "Request") -> Any:
        refusal = admin_refused(request)
        if refusal is not None:
            return refusal
        limit = int(request.query_params.get("limit") or 100)
        rows = deps.db.query(
            "SELECT * FROM slack_discord_audit ORDER BY id DESC LIMIT ?",
            (max(1, min(500, limit)),),
        )
        return {"ok": True, "plugin": PLUGIN_ID, "audit": [
            {
                "workspace_id": str(row["workspace_id"]),
                "action": str(row["action"]),
                "outcome": str(row["outcome"]),
                "status_code": row["status_code"],
                "created_at_ms": row["created_at_ms"],
            }
            for row in rows
        ]}

    return router


def _refund(deps: Any, charge: Any, reason: str) -> None:
    if int(getattr(charge, "charged", 0) or 0) <= 0:
        return
    try:
        deps.billing.refund(amount=int(charge.charged), reason=reason, ref="slack_discord")
    except Exception:  # noqa: BLE001
        LOG.exception("slack/discord refund failed")


async def handle_inbound(deps: PluginDeps, message: "InboundMessage") -> bool:
    """This bridge is outbound-only; it claims no eco message."""
    return False


def self_test() -> List[str]:
    checks: List[str] = []

    def check(name: str, condition: bool) -> None:
        if not condition:
            raise AssertionError("self_test failed: %s" % name)
        checks.append(name)

    # ── the signature contract ────────────────────────────────────────────
    secret = "s" * 43
    raw = b'{"text":"hello"}'
    headers = signature_headers(secret, raw, 1_800_000_000)
    check("the_signature_is_v1_prefixed", headers["X-Popopx-Signature"].startswith("v1="))
    check("the_timestamp_is_the_signed_second", headers["X-Popopx-Timestamp"] == "1800000000")
    check("the_signature_verifies", verify_signature(secret, raw, headers["X-Popopx-Timestamp"],
                                                     headers["X-Popopx-Signature"], now_ms=1_800_000_000_000))
    check("a_tampered_body_fails", not verify_signature(secret, raw + b" ", headers["X-Popopx-Timestamp"],
                                                        headers["X-Popopx-Signature"], now_ms=1_800_000_000_000))
    check("the_wrong_secret_fails", not verify_signature("t" * 43, raw, headers["X-Popopx-Timestamp"],
                                                         headers["X-Popopx-Signature"], now_ms=1_800_000_000_000))
    check("a_stale_timestamp_fails", not verify_signature(secret, raw, headers["X-Popopx-Timestamp"],
                                                          headers["X-Popopx-Signature"], now_ms=1_800_001_000_000))
    check("a_bare_hex_signature_is_also_accepted", verify_signature(
        secret, raw, headers["X-Popopx-Timestamp"], headers["X-Popopx-Signature"][3:], now_ms=1_800_000_000_000))
    check("a_non_numeric_timestamp_fails", not verify_signature(
        secret, raw, "soon", headers["X-Popopx-Signature"], now_ms=1_800_000_000_000))

    # ── the platform allowlist (no DNS: an unknown host is refused before resolve) ──
    def refused(name: str, code: str, fn) -> None:
        try:
            fn()
            check(name, False)
        except ConnectorError as exc:
            check(name, exc.code == code)

    refused("an_unknown_platform_is_refused", "platform_invalid",
            lambda: validate_webhook("matrix", "https://hooks.slack.com/services/x"))
    refused("a_public_slack_webhook_must_be_on_hooks_slack_com", "platform_host",
            lambda: validate_webhook("slack", "https://evil.example/services/x", allow_private=False))
    refused("a_slack_webhook_on_the_discord_host_is_refused", "platform_host",
            lambda: validate_webhook("slack", "https://discord.com/api/webhooks/x", allow_private=False))
    refused("a_loopback_webhook_without_the_opt_in_is_refused", "platform_host",
            lambda: validate_webhook("slack", "http://127.0.0.1:9/hook"))
    refused("a_lan_address_is_refused_even_with_the_opt_in", "url_not_loopback",
            lambda: validate_webhook("slack", "http://10.0.0.5:9/hook", allow_private=True))
    refused("the_metadata_address_is_refused_even_with_the_opt_in", "ssrf_blocked",
            lambda: validate_webhook("slack", "http://169.254.169.254/latest", allow_private=True))
    loopback = validate_webhook("discord", "http://127.0.0.1:9/hook", allow_private=True)
    check("a_loopback_receiver_is_accepted_with_the_opt_in", loopback.host == "127.0.0.1" and loopback.scheme == "http")

    # ── the public view never carries a credential ────────────────────────
    view = workspace_public({"id": "sdw_1", "label": "ops", "platform": "slack",
                             "webhook_url": "https://hooks.slack.com/services/T/B/SECRET",
                             "secret": "vault1:abc", "allow_private": 0, "active": 1})
    check("the_webhook_path_is_never_returned", "SECRET" not in json.dumps(view))
    check("the_public_view_reports_the_host", view["url_host"] == "hooks.slack.com")
    check("the_public_view_reports_that_a_secret_exists", view["secret_set"] is True)

    # ── a real loopback receiver proves delivery, signing and the no-store rule ──
    import http.server
    import shutil
    import tempfile
    import threading
    from pathlib import Path

    from app.database import Database

    received: List[Tuple[bytes, Dict[str, str]]] = []

    class Receiver(http.server.BaseHTTPRequestHandler):
        def do_POST(self) -> None:  # noqa: N802 — stdlib spelling
            length = int(self.headers.get("Content-Length") or 0)
            received.append((self.rfile.read(length), {k.lower(): v for k, v in self.headers.items()}))
            self.send_response(200 if self.path == "/ok" else 500)
            self.send_header("Content-Length", "0")
            self.end_headers()

        def log_message(self, *args: Any) -> None:  # silence the harness
            return

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Receiver)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    root = Path(tempfile.mkdtemp(prefix="popopx-slackdiscord-selftest-"))
    try:
        port = server.server_address[1]
        db = Database(root / "bridge.db")
        now = _now_ms()
        db.execute(
            "INSERT INTO slack_discord_workspaces (id,label,platform,webhook_url,secret,allow_private,active,created_at_ms,updated_at_ms)"
            " VALUES ('sdw_ok','ops','slack',?,'bridge-secret',1,1,?,?)",
            ("http://127.0.0.1:%d/ok" % port, now, now),
        )
        db.execute(
            "INSERT INTO slack_discord_workspaces (id,label,platform,webhook_url,secret,allow_private,active,created_at_ms,updated_at_ms)"
            " VALUES ('sdw_500','ops','discord',?,'bridge-secret',1,1,?,?)",
            ("http://127.0.0.1:%d/fail" % port, now, now),
        )

        class FakeVault:
            def open(self, value, *, table, column, subject):
                return str(value)

        class FakeDeps:
            pass

        deps = FakeDeps()
        deps.db = db
        deps.vault = FakeVault()
        row = dict(db.query_one("SELECT * FROM slack_discord_workspaces WHERE id = 'sdw_ok'"))
        result = asyncio.new_event_loop().run_until_complete(deliver_webhook(deps, row, "hello", title="build"))
        check("a_loopback_delivery_succeeds", result["ok"] is True and result["status"] == 200)
        check("the_receiver_got_exactly_one_request", len(received) == 1)
        payload, got_headers = received[0]
        check("the_slack_payload_is_text_only", json.loads(payload.decode("utf-8")) == {"text": "*build*\nhello"})
        check("the_receiver_can_verify_the_signature", verify_signature(
            "bridge-secret", payload, got_headers.get("x-popopx-timestamp"),
            got_headers.get("x-popopx-signature")))
        check("the_delivery_is_audited", int(db.scalar(
            "SELECT COUNT(*) FROM slack_discord_audit WHERE workspace_id = 'sdw_ok' AND outcome = 'delivered'") or 0) == 1)
        check("the_message_text_is_not_stored", db.scalar(
            "SELECT COUNT(*) FROM slack_discord_audit WHERE action LIKE '%hello%' OR outcome LIKE '%hello%'") == 0
            and db.scalar(
            "SELECT COUNT(*) FROM slack_discord_workspaces WHERE webhook_url LIKE '%hello%'") == 0)

        failed = asyncio.new_event_loop().run_until_complete(deliver_webhook(
            deps, dict(db.query_one("SELECT * FROM slack_discord_workspaces WHERE id = 'sdw_500'")), "nope"))
        check("a_500_is_reported_not_raised", failed["ok"] is False and failed["status"] == 500)
        check("the_failed_attempt_is_audited", int(db.scalar(
            "SELECT COUNT(*) FROM slack_discord_audit WHERE workspace_id = 'sdw_500' AND outcome = 'http_500'") or 0) == 1)
        check("the_discord_payload_uses_content", json.loads(received[1][0].decode("utf-8")) == {"content": "nope"})
    finally:
        server.shutdown()
        server.server_close()
        shutil.rmtree(root, ignore_errors=True)

    return checks