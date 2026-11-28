# Copyright (c) 2026 POPOPX (popopx.chat)
# SPDX-License-Identifier: AGPL-3.0-only
"""The gateway: ECO orchestration, inbound routing, the admin API, the outbox.

This module is the only place that talks to the node *and* the only place that
writes the protocol tables (`eco_sessions`, `cards`, `menus`, `channels`,
`channel_epochs`, `channel_members`, `callbacks`, `outbox`). Plugins reach those
tables exclusively through the :class:`EcoService` below, which is published to
them as the :class:`app.plugins.Eco` protocol — see the docstring of
:mod:`app.plugins` for why the seam is a Protocol and not an import.

Layering, and why it is this way
--------------------------------
`crypto_service` is pure and synchronous: it turns data into bytes that the iOS
client accepts, and it raises `EcoError` when the client would reject them.
`billing_service` and `database` are pure and synchronous for the same reason —
a ledger entry is a SQLite transaction, not an await. Only `agent_bridge` is
asynchronous, because only it crosses a network. This file is where the two
halves meet, so almost every `async def` here is a thin sequence:

    build the frame (sync, can raise a client-rule error)
    -> charge the meter (sync, can refuse)
    -> send it (async, can fail)
    -> refund if the send failed (sync)

That order is not cosmetic. Charging after a successful send hands out the
product for free and invites a replay to charge twice; sending before charging
means the account can go negative without limit; refunding only on a raised
exception leaks credit on a node that replies `error` without raising. All three
arcs are exercised in :func:`self_test` with a fake bridge.

Deviations from the brief, all of them forced by the shipped iOS client
--------------------------------------------------------------------
The brief asks for a card whose state is updated *in place* under the same
`cardId` — the alert confirmation wants exactly that.
`PopopxEcoRouterAndDeepLink.swift:150-176` merges
`m=u` into the stored card field-by-field, and `PopopxEcoModels.swift:510-522`
re-decodes the whole card from the merge, so an update that sends *only* the
changed action would drop every other button, and there is no way to express
"remove action X". The client's own rule for a dead button is expiry
(`cardIsInert`, `ServiceCardBubbleView.swift:178`, applied at :379 as
`liveActions = cardIsInert ? [] : …`),
so :meth:`EcoService.settle_card` re-delivers the full action list with
`expiresAt` in the past. :func:`retired_actions` is that transformation, and it
is why `kind="none"` never appears in this file: `build_action` refuses it
(`crypto_service.py:512`) because the client has no such kind.

The brief mandates the `menu_config` frame but says nothing about how a re-push
is ordered, and the client does not sort: it *drops* anything not strictly newer
(`PopopxEcoStore.apply` returns `.ignoredStale`), so every re-push
in this file bumps `rev`/`ut` from the stored value rather than from the wall
clock alone — see :func:`next_monotonic_ms`, which is also what stops two cards
delivered in the same millisecond from having the same `ut`.

`articles` has no table in the mandated schema
(`database.py` defines `article_refs`, which only *logs* a `::REF::`). Article bodies therefore live in `settings` under `article:<id>`,
written through `PUT /api/v1/articles/{id}`. That is a storage choice, not a
protocol one: the wire behaviour (`::REF::<id>` in, a signed H5 link out) is
unchanged.

Nothing here imports the open-source node's code, and nothing reaches it except
over `ws://127.0.0.1:5225` via :mod:`app.agent_bridge`.
"""

from __future__ import annotations

import argparse
import ast
import asyncio
import base64
import builtins
import contextlib
import hashlib
import hmac
import inspect
import json
import logging
import os
import re
import secrets
import sqlite3
import sys
import textwrap
import time
import warnings
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, AsyncIterator, Awaitable, Callable, Dict, List, Mapping, Optional, Sequence, Set, Tuple

# The names a route signature mentions must be reachable from THIS module's globals,
# not only from inside :func:`create_app`. With ``from __future__ import annotations``
# every annotation reaching FastAPI is a string, and FastAPI resolves that string
# against ``endpoint.__globals__``; a ``Request`` imported only in ``create_app``'s
# local scope is invisible there. It then kept the literal ``"Request"`` as the
# parameter's type, which makes the parameter a required *query* field — so all 50
# core admin endpoints answered ``422 {"loc": ["query", "request"]}`` before
# ``admin_required(request)`` ran. Measured against the live router, not inferred:
# ``GET /api/v1/status`` was the first call to show it. The plugin modules were never
# affected because their handlers are declared in modules where the same name is
# resolved differently; :func:`unresolvable_route_annotations` is what keeps this
# file honest about it on a machine with no FastAPI installed.
try:
    from fastapi import Request
    from fastapi.responses import FileResponse, HTMLResponse, JSONResponse
except ImportError:  # pragma: no cover — the wheels-less self-test path
    Request = Any  # type: ignore[assignment,misc]
    FileResponse = HTMLResponse = JSONResponse = Any  # type: ignore[assignment]

from app import admin_auth
from app.agent_bridge import (
    AgentBridge,
    InboundCallback,
    InboundMessage,
    NodeCommandError,
    NodeError,
    NodeNotConnected,
    NodeTimeout,
    error_reason,
    extract_contact_request,
    parse_inbound_text,
)
from app.billing_service import BillingError, BillingService
from app.config import Config, ConfigError, load_config
from app.crypto_service import (
    ECO_MARKER,
    H5_SIG_PARAM,
    H5_TS_PARAM,
    H5_UID_PARAM,
    CARD_STYLES,
    CryptoUnavailable,
    EcoError,
    EcoLimits,
    b64_decode_lenient,
    b64_url,
    build_action,
    build_card,
    build_channel_public_uri,
    build_menu,
    build_menu_item,
    compact_json,
    encode_frame,
    frame_channel_key_update,
    frame_menu_config,
    frame_service_card,
    frame_session_handshake,
    make_channel_identity,
    make_epoch_key,
    new_session_secret,
    now_ms,
    now_seconds,
    public_key_from_private,
    seal_card,
    seal_envelope,
    sign_h5_url,
    validate_channel_public_uri,
    validate_channel_relay,
    validate_http_url,
    validate_pairwise_uid,
    validate_secret_hex,
    verify_h5_auth,
    verify_voucher_code,
    epoch_secret_plaintext,
)
from app.database import Database
from app.compute import authorizer as compute_authorizer
from app.compute import registry as compute_registry
from app.data_lifecycle import cleanup as lifecycle_cleanup
from app.data_lifecycle import policy as lifecycle_policy
from app.data_lifecycle import policy_engine as lifecycle_engine
from app.vault import SecretBox, VaultError, vault_for
from app.opaque_invite_codec import (
    LINK_PREFIX,
    InviteCodecError,
    decode_invite,
    encode_invite,
    invite_code_prefix,
    mask_invite_link,
)
from app.plugins import (
    PLUGIN_SPEC,
    CardDelivery,
    ChannelGrant,
    EcoSession,
    GateDecision,
    PluginDeps,
    PluginGate,
    PluginUnavailable,
    plugin_for_id,
)

__all__ = ["Gateway", "EcoService", "create_app", "main", "self_test"]

LOG = logging.getLogger("popopx.gateway")

#: The mount table as the scoped-token authorizer needs it: URL prefix → plugin id.
#: Read from PLUGIN_SPEC rather than written out, so a tenth plugin cannot be
#: granted under a stale slug.
ADMIN_PLUGIN_PREFIXES: Dict[str, str] = {
    str(spec.url_prefix).rstrip("/"): str(spec.plugin_id) for spec in PLUGIN_SPEC
}

#: The default `serviceId` for a frame. The client displays nothing from it and
#: only uses it to decide whether a card belongs to this service account, so it
#: is stable, human-readable, and never derived from user input.
SERVICE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")

#: Frame kinds as they appear in `outbox.frame_kind`, so a stuck queue can be
#: read by a human without decoding the body.
FRAME_HANDSHAKE = "handshake"
FRAME_MENU = "menu"
FRAME_CARD = "card"
FRAME_CARD_UPDATE = "card_update"
FRAME_KEY = "channel_key"
FRAME_TEXT = "text"
FRAME_ARTICLE = "article"

#: A queued frame that has failed this many times is abandoned and its charge is
#: released. Eight covers a node restart (the supervisor backs off to ~30s)
#: without letting a permanently unparseable frame burn credits forever.
OUTBOX_MAX_ATTEMPTS = 8

#: How many queued frames one worker pass will attempt. Bounded so that a
#: backlog drained after an outage cannot starve the inbound handler of the
#: event loop for longer than a second or two.
OUTBOX_BATCH = 25

#: Worker cadence, in seconds.
OUTBOX_INTERVAL_SECONDS = 1.0
WEB3_INTERVAL_SECONDS = 15.0

#: `cards.state`, free-form in the schema (no CHECK) but censused here so the
#: console can filter on it.
CARD_STATE_DRAFT = "draft"
CARD_STATE_SENT = "sent"
CARD_STATE_DELIVERED = "delivered"
CARD_STATE_SETTLED = "settled"
CARD_STATE_FAILED = "failed"

#: Inbound callback kinds, mirroring `agent_bridge.InboundCallback.kind`.
KIND_TEXT = "text"
KIND_CARD_CALLBACK = "card_callback"
KIND_CARD_PAID = "card_paid"
KIND_ROTATE = "rotate_request"
KIND_ARTICLE_REF = "article_ref"
KIND_SSO_SCAN = "sso_scan"
KIND_SYSTEM = "system"

#: Payload prefixes this file owns. Everything else with `::CB::` belongs to a
#: plugin, which claims it by prefix inside its own `handle_inbound`. A member's
#: own re-request for a key is NOT here: the client sends `rotate:<channelId>`
#: (`ChannelKeyRotationManager.swift:920`), which the classifier claims as
#: `rotate_request` (`agent_bridge.py:261`) and `_kind_rotate_request` handles.
PAYLOAD_CHANNEL_SUBSCRIBE = "channel:subscribe:"
PAYLOAD_MENU_OPEN = "menu:"
MENU_KEYWORD_PREFIX = "kw:"

#: `settings` keys this file owns. Plugin config lives under its own key.
SETTING_AUTO_ACCEPT = "gateway.auto_accept"
SETTING_WELCOME_TEXT = "gateway.welcome_text"
SETTING_ARTICLE_PREFIX = "article:"
SETTING_INVITE_LINK_PREFIX = "invite_link:"

#: Kinds the invite-link audit table accepts. The CHECK in `database.py` is the
#: enforcement; this tuple is what keeps the API and the DDL from drifting.
INVITE_KINDS: Tuple[str, ...] = ("service_account", "channel")

H5_PATH_VERIFY = "/api/v1/verifyH5Auth"


# ─────────────────────────────────────────────────────────────────────────────
# 1. Pure helpers: id minting, tokens, monotonic clocks, payload parsing
#
#    Everything in this section is a free function taking plain values, because
#    each one encodes a rule the iOS client enforces on the other end and a rule
#    a client enforces is worth testing without a database.
# ─────────────────────────────────────────────────────────────────────────────


def new_id(prefix: str, *, nbytes: int = 9) -> str:
    """A URL-safe identifier with a readable kind prefix.

    9 bytes is 12 base64url characters, so a `cardId` costs 17 of the client's
    64-character budget (`EcoLimits.card_id_chars`). Uniqueness comes from the
    generator, not from a counter: a counter in `settings` would be one more
    write per card and one more thing to corrupt.
    """
    if not re.fullmatch(r"[a-z][a-z0-9_]{0,11}", prefix):
        raise ValueError("id prefix must be lower snake_case, got %r" % (prefix,))
    return "%s_%s" % (prefix, secrets.token_urlsafe(nbytes).rstrip("="))


def normalize_base_url(url: str) -> str:
    """Trim trailing slashes; a public base URL is concatenated, never joined."""
    text = (url or "").strip().rstrip("/")
    if not text:
        raise ValueError("public_base_url must not be empty")
    if not text.startswith(("http://", "https://")):
        raise ValueError("public_base_url must be http(s): %r" % (url,))
    return text


def next_monotonic_ms(previous: Optional[int], now: Optional[int] = None) -> int:
    """A timestamp strictly greater than `previous`.

    The client drops an update whose `ut` is not strictly newer than the card it
    already renders (`PopopxEcoModels.swift:541` `isLive`, and the `.ignoredStale`
    branch of `apply` at `PopopxEcoRouterAndDeepLink.swift:128-146`). Two cards
    minted in the same millisecond, or a re-send of a card that was already
    delivered in this millisecond, would otherwise be silently thrown away on a
    phone that never learns anything was wrong.
    """
    current = int(now if now is not None else now_ms())
    try:
        last = int(previous or 0)
    except (TypeError, ValueError):
        last = 0
    return current if current > last else last + 1


def card_id_for_recipient(base_id: str, contact_id: int) -> str:
    """The per-follower `cardId` for a broadcast.

    `cards.card_id` is the primary key and the client keys stored cards by
    `cardId` alone — not by (cardId, sender) — so a card delivered to two
    followers with the same id would merge into one bubble across conversations
    and the second follower's status update would rewrite the first one's. The
    derivation is deterministic so that an update addressed by the base id can
    find the right row for each recipient without a lookup table.
    """
    text = str(base_id)
    candidate = "%s_%d" % (text, int(contact_id)) if len(text) <= EcoLimits.card_id_chars - 12 else "%s_%d" % (
        text[: EcoLimits.card_id_chars - 12 - 1], int(contact_id))
    if len(candidate) > EcoLimits.card_id_chars:
        # A caller that hands us a 64-character base id has mispriced its own
        # budget; digest the tail instead of failing the whole broadcast.
        digest = hashlib.sha256(candidate.encode("utf-8")).hexdigest()[:8]
        candidate = "%s_%s" % (candidate[: EcoLimits.card_id_chars - 9], digest)
    return candidate


def parse_prefixed_payload(payload: str, prefix: str, *, max_parts: int = 4) -> Optional[Tuple[str, ...]]:
    """`"channel:subscribe:green"` with prefix `"channel:subscribe:"` -> `("green",)`.

    Returns None when the payload does not carry the prefix or names an empty
    segment. Every field here arrives from a phone, so a malformed control line
    is a refusal, never an exception and never a partial match: `("green", "")`
    must not be read as channel `green` with an empty tail.
    """
    text = (payload or "").strip()
    if not text.startswith(prefix):
        return None
    tail = text[len(prefix):]
    if not tail:
        return None
    parts = tuple(part for part in tail.split(":"))
    if any(not part for part in parts):
        return None
    return parts[:max_parts] if len(parts) <= max_parts else None


def constant_compare(a: str, b: str) -> bool:
    """Timing-safe equality that tolerates non-ASCII without raising.

    `hmac.compare_digest` refuses arbitrary `str` in some builds, and an admin
    token typed by hand into a query string can contain anything.
    """
    return hmac.compare_digest(str(a).encode("utf-8"), str(b).encode("utf-8"))


def token_is_valid(presented: Optional[str], expected: str) -> bool:
    """Whether a request may act as the operator.

    An empty `expected` is a refusal, not a wildcard: `POPOPX_ADMIN_TOKEN=` in a
    half-written `.env` must not expose the console of a gateway listening on
    0.0.0.0.
    """
    if not expected:
        return False
    if presented is None:
        return False
    return constant_compare(presented.strip(), expected)


def h5_query_params(query: Mapping[str, Any]) -> Tuple[str, str, str]:
    """`(uid, ts, sig)` from a request query mapping, first value wins.

    Starlette hands back a multidict; a repeated `popopx_uid` is either a
    mistake or an attack, and in both cases the first is what we sign against.
    """
    def one(name: str) -> str:
        value = query.get(name) if hasattr(query, "get") else None
        if isinstance(value, (list, tuple)):
            value = value[0] if value else ""
        return "" if value is None else str(value)

    return one(H5_UID_PARAM), one(H5_TS_PARAM), one(H5_SIG_PARAM)


def split_csv(value: Any) -> List[str]:
    """A list of trimmed, non-empty, de-duplicated tokens from a list or a CSV string."""
    if value is None:
        return []
    items = value if isinstance(value, (list, tuple)) else str(value).split(",")
    out: List[str] = []
    seen = set()
    for item in items:
        text = str(item).strip()
        if text and text not in seen:
            seen.add(text)
            out.append(text)
    return out


def int_or_none(value: Any) -> Optional[int]:
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return None


def clamp_limit(value: Any, default: int, maximum: int) -> int:
    parsed = int_or_none(value)
    if parsed is None or parsed <= 0:
        parsed = default
    return min(parsed, maximum)


def row_dict(row: Any) -> Dict[str, Any]:
    """A JSON-safe dict from a `sqlite3.Row`, mapping, or None."""
    if row is None:
        return {}
    if isinstance(row, Mapping):
        data = dict(row)
    else:
        try:
            data = dict(row)
        except Exception:  # noqa: BLE001 — a scalar has no columns
            return {}
    for key, value in list(data.items()):
        if isinstance(value, (bytes, bytearray)):
            data[key] = value.decode("utf-8", "replace")
    return data


def json_loads_or(value: Any, fallback: Any) -> Any:
    """Decode a TEXT column that is supposed to hold JSON, without raising.

    A corrupt row must not turn a console listing into a 500.
    """
    if value is None or isinstance(value, (int, float, Mapping, list)):
        return fallback if value is None else value
    text = str(value).strip()
    if not text:
        return fallback
    try:
        return json.loads(text)
    except (ValueError, TypeError):
        return fallback


def like_prefix(text: str) -> str:
    """A LIKE pattern matching keys that start with this literal text.

    `_` and `%` are LIKE metacharacters and the ids here are full of them, so an
    unescaped `card1_` also matches `card15_<contact>`. Whatever separator the
    caller means goes inside `text` — `card_id_for_recipient` joins with `_`, an
    article key with `:` — because the pattern has to mean *that* separator and not
    one this helper guesses. The statement must declare `ESCAPE '\\'`, or the
    backslashes match nothing at all.
    """
    escaped = str(text).replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    return escaped + "%"


def retired_actions(actions: Sequence[Mapping[str, Any]], *, label: str = "已完成", kind: str = "callback") -> List[Dict[str, Any]]:
    """Turn a card's action list into its inert, single-tap successor.

    The client has no "remove this button" and no disabled button
    (`PopopxEcoModels.swift:685-702`: `case .none: return false` is not even a
    wire value; `build_action` rejects the kind at `crypto_service.py:512`). A
    used button therefore becomes one inert-looking confirmation whose *payload*
    is a no-op token, and the card itself is expired by the caller so the client
    renders no buttons at all (`ServiceCardBubbleView.swift:378-382`). Both
    halves are needed; this function only does the list.

    `actionId` must survive unchanged: the merge keys actions by id, so a new id
    would append a second button instead of replacing the first.
    """
    out: List[Dict[str, Any]] = []
    for raw in actions or ():
        action = raw if isinstance(raw, Mapping) else {}
        # `id` is the wire key (`PopopxEcoAction.CodingKeys`); `actionId` is the
        # spelling a plugin uses when it hands over a spec rather than a frame.
        action_id = str(action.get("id") or action.get("actionId") or "").strip()
        if not action_id:
            continue
        out.append(
            build_action(
                action_id=action_id,
                title=label,
                kind=kind,
                style="secondary",
                payload="noop:%s" % action_id,
            )
        )
    return out


def welcome_reply(text: str) -> Optional[str]:
    """The canned answer to a first message from a follower with no menu yet.

    Kept as a pure function because the rule "empty setting means silence" is the
    kind of thing that turns into an unsolicited marketing message if it is
    written inline twice.
    """
    body = (text or "").strip()
    return body or None


# ─────────────────────────────────────────────────────────────────────────────
# 2. Errors
# ─────────────────────────────────────────────────────────────────────────────


class GatewayError(Exception):
    """A refusal that a route turns into a JSON error body with a status code."""

    def __init__(self, status: int, code: str, detail: str = "") -> None:
        self.status = int(status)
        self.code = code
        self.detail = detail or code
        super().__init__("%s: %s" % (code, detail or code))

    def to_body(self) -> Dict[str, Any]:
        return {"ok": False, "error": self.code, "detail": self.detail}


def bad_request(code: str, detail: str = "") -> GatewayError:
    return GatewayError(400, code, detail)


def not_found(code: str = "not_found", detail: str = "") -> GatewayError:
    return GatewayError(404, code, detail)


def conflict(code: str, detail: str = "") -> GatewayError:
    return GatewayError(409, code, detail)


def unavailable(code: str, detail: str = "") -> GatewayError:
    return GatewayError(503, code, detail)


# ─────────────────────────────────────────────────────────────────────────────
# 3. EcoService — the protocol half of the gateway
#
#    Implements `app.plugins.Eco` and owns every write to `eco_sessions`,
#    `cards`, `menus`, `channels`, `channel_epochs`, `channel_members`,
#    `outbox`. The node is reached through `self.bridge`, which is only ever
#    asked for `send_text`; the outbox is the retry mechanism, so nothing here
#    needs the bridge to be up in order to accept work.
# ─────────────────────────────────────────────────────────────────────────────


class EcoService:
    """Sessions, cards, menus, channel keys, the outbox: what a follower sees."""

    def __init__(
        self,
        config: Config,
        db: Database,
        billing: BillingService,
        bridge: Any,
        *,
        outbox_interval: float = OUTBOX_INTERVAL_SECONDS,
        identity_factory: Callable[[], Tuple[bytes, bytes]] = make_channel_identity,
        sealer: Callable[..., Dict[str, Any]] = seal_envelope,
        key_factory: Callable[[], bytes] = make_epoch_key,
    ) -> None:
        self.config = config
        self.db = db
        self.billing = billing
        self.bridge = bridge
        self.vault: SecretBox = vault_for(config.vault_key)
        self.service_id = str(config.service_id or "popopx.service")
        self.public_base = normalize_base_url(config.public_base_url)
        self.outbox_interval = max(0.05, float(outbox_interval))
        # The three key-crypto primitives are arguments rather than calls because
        # `crypto_service` reaches for the `cryptography` wheel lazily
        # (`_require_crypto`) and raises `CryptoUnavailable` when it is absent. A
        # deployment without the wheel can still run every part of this class that
        # is not a channel rotation — which is the whole reason the failure is a
        # named 503 (`crypto_unavailable`) and not an import error at boot.
        self._identity_factory = identity_factory
        self._sealer = sealer
        self._key_factory = key_factory

    # ── sessions ────────────────────────────────────────────────────────────

    def session_for(self, contact_id: int) -> Optional[EcoSession]:
        row = self.db.query_one(
            "SELECT pairwise_uid, contact_id, service_id, secret_hex, revoked"
            "  FROM eco_sessions WHERE contact_id = ? ORDER BY revoked ASC, rotated_at_ms DESC LIMIT 1",
            (int(contact_id),),
        )
        if row is None:
            return None
        return self._session_from_row(row)

    def sessions_for_channel(self, channel_id: str) -> List[EcoSession]:
        """Every *active* member of a channel that still has a usable session.

        Membership, not "every follower": a key rotation is what the merchant paid
        for, and handing it to a non-member is a giveaway the schema explicitly
        models (`channel_members.status = 'active'`).
        """
        rows = self.db.query(
            "SELECT s.pairwise_uid, s.contact_id, s.service_id, s.secret_hex, s.revoked"
            "  FROM channel_members m JOIN eco_sessions s ON s.contact_id = m.contact_id"
            " WHERE m.channel_id = ? AND m.status = 'active' AND s.revoked = 0"
            " ORDER BY m.contact_id",
            (str(channel_id),),
        )
        return [self._session_from_row(row) for row in rows]

    def all_sessions(self, *, include_revoked: bool = False) -> List[EcoSession]:
        sql = ("SELECT pairwise_uid, contact_id, service_id, secret_hex, revoked FROM eco_sessions")
        if not include_revoked:
            sql += " WHERE revoked = 0"
        sql += " ORDER BY contact_id"
        return [self._session_from_row(row) for row in self.db.query(sql)]

    def _session_from_row(self, row: Any) -> EcoSession:
        data = row_dict(row)
        contact_id = int(data.get("contact_id") or 0)
        return EcoSession(
            contact_id=contact_id,
            pairwise_uid=str(data.get("pairwise_uid") or ""),
            # A vault sealed row holds `vault1:<ciphertext>`; a row written
            # before the operator turned the key on holds the hex verbatim, and
            # `open` passes that through unchanged. Both are legal at once, on
            # purpose: enabling the vault must not require stopping the gateway.
            secret_hex=self.vault.open(
                data.get("secret_hex") or "",
                table="eco_sessions",
                column="secret_hex",
                subject=contact_id,
            ),
            service_id=str(data.get("service_id") or self.service_id),
            revoked=bool(data.get("revoked")),
        )

    def ensure_session(self, contact_id: int, *, rotate: bool = False) -> EcoSession:
        """Create (or rotate) the pairwise session for one follower.

        The secret is generated here and exists in exactly two places afterwards:
        this row and the phone that received the `sh` frame. Nothing in the admin
        API returns it — `GET /api/v1/contacts` deliberately omits `secret_hex` —
        because the H5 signature is the only thing it can be used for and the
        gateway can produce that without showing it.
        """
        contact_id = int(contact_id)
        if contact_id <= 0:
            raise bad_request("contact_id_required", "a positive contact id is required")
        existing = self.db.query_one(
            "SELECT pairwise_uid, contact_id, service_id, secret_hex, revoked FROM eco_sessions WHERE contact_id = ?",
            (contact_id,),
        )
        if existing is not None and not rotate:
            return self._session_from_row(existing)
        pairwise_uid = validate_pairwise_uid(new_id("pw"))
        secret_hex = validate_secret_hex(new_session_secret())
        sealed_secret = self.vault.seal(
            secret_hex, table="eco_sessions", column="secret_hex", subject=contact_id
        )
        ts = now_ms()
        # The contact row goes in first: `eco_sessions.contact_id` is a foreign
        # key and a handshake for a follower the gateway has never seen before
        # arrives here before anything in `contacts` exists.
        self.db.execute(
            "INSERT OR IGNORE INTO contacts (contact_id, pairwise_uid, first_seen_ms, last_seen_ms, blocked)"
            " VALUES (?, ?, ?, ?, 0)",
            (contact_id, pairwise_uid, ts, ts),
        )
        with self.db.transaction() as conn:
            if existing is None:
                conn.execute(
                    "INSERT INTO eco_sessions (pairwise_uid, contact_id, service_id, secret_hex,"
                    " created_at_ms, rotated_at_ms, revoked) VALUES (?, ?, ?, ?, ?, ?, 0)",
                    (pairwise_uid, contact_id, self.service_id, sealed_secret, ts, ts),
                )
            else:
                conn.execute(
                    "UPDATE eco_sessions SET pairwise_uid = ?, service_id = ?, secret_hex = ?,"
                    " rotated_at_ms = ?, revoked = 0 WHERE contact_id = ?",
                    (pairwise_uid, self.service_id, sealed_secret, ts, contact_id),
                )
        self.db.execute(
            "UPDATE contacts SET pairwise_uid = ?, last_seen_ms = ? WHERE contact_id = ?",
            (pairwise_uid, ts, contact_id),
        )
        return EcoSession(
            contact_id=contact_id,
            pairwise_uid=pairwise_uid,
            secret_hex=secret_hex,
            service_id=self.service_id,
        )

    def revoke_session(self, contact_id: int) -> bool:
        return self.db.execute("UPDATE eco_sessions SET revoked = 1 WHERE contact_id = ?", (int(contact_id),)) > 0

    def touch_contact(self, contact_id: int, display_name: str = "", *, pairwise_uid: str = "") -> None:
        """Record that this contact exists, as seen from the node.

        `contacts` is the only table the node's own contact list can rewrite, and
        the pairwise uid is preserved when the node does not know about it: the
        mapping is the gateway's secret, not the node's.
        """
        ts = now_ms()
        name = (display_name or "").strip()[:120]
        self.db.execute(
            "INSERT INTO contacts (contact_id, pairwise_uid, local_display_name, display_name, first_seen_ms, last_seen_ms, blocked)"
            " VALUES (?, ?, '', ?, ?, ?, 0)"
            " ON CONFLICT(contact_id) DO UPDATE SET"
            "   last_seen_ms = excluded.last_seen_ms,"
            "   display_name = CASE WHEN excluded.display_name = '' THEN contacts.display_name ELSE excluded.display_name END,"
            "   pairwise_uid = CASE WHEN excluded.pairwise_uid = '' THEN contacts.pairwise_uid ELSE excluded.pairwise_uid END",
            (int(contact_id), pairwise_uid, name, ts, ts),
        )

    async def handshake(self, contact_id: int, *, rotate: bool = False) -> Dict[str, Any]:
        """Push `session_handshake` for one follower, minting the session if needed.

        The frame is *not* charged: the billing contract gates the
        plugins on the balance, and the meters it implies are the `POPOPX_CP_PER_*` keys — cards,
        menu pushes and key rotations among them, with no meter for a handshake
        (`unknown_meter` is what `billing_service.py:414` answers for one). A
        handshake is the precondition for all three, and a gateway that charged
        for it could not be topped up by an H5 purchase, because the purchase page
        needs the session the charge would pay for.
        """
        session = self.ensure_session(contact_id, rotate=rotate)
        text = frame_session_handshake(session.pairwise_uid, session.secret_hex, session.service_id)
        result = await self._deliver_frame(
            contact_id,
            text,
            kind=FRAME_HANDSHAKE,
            meter=None,
            ref="handshake:%d" % contact_id,
            idempotency_key=None,
        )
        return {
            "ok": bool(result.sent or result.queued),
            "contact_id": contact_id,
            "pairwise_uid": session.pairwise_uid,
            "sent": bool(result.sent),
            "queued": bool(result.queued),
            "error": result.error,
        }

    # ── menu ────────────────────────────────────────────────────────────────

    def menu_state(self) -> Dict[str, Any]:
        """The newest stored menu.

        `menus` is keyed by `(service_id, rev)` — every revision is kept, because
        the client's stale-frame rule means an operator sometimes has to answer
        "what did follower X have applied at that moment" — so this reads the
        highest revision rather than "the row for this service".
        """
        row = self.db.query_one(
            "SELECT service_id, rev, payload_json, updated_at_ms, last_delivered_ms FROM menus"
            " WHERE service_id = ? ORDER BY rev DESC LIMIT 1",
            (self.service_id,),
        )
        if row is None:
            return {"service_id": self.service_id, "rev": 0, "items": [], "updated_at_ms": 0, "last_delivered_ms": 0}
        data = row_dict(row)
        stored = json_loads_or(data.get("payload_json"), {}) or {}
        return {
            "service_id": data.get("service_id"),
            "rev": int(data.get("rev") or 0),
            # `payload_json` is the whole wire menu (`{"items":…, "rev":…}`), so
            # the items have to be unwrapped here or every reader sees a dict.
            "items": list(stored.get("items") or []),
            "updated_at_ms": int(data.get("updated_at_ms") or 0),
            "last_delivered_ms": int(data.get("last_delivered_ms") or 0),
        }

    def store_menu(self, items: Sequence[Mapping[str, Any]], *, revision: Optional[int] = None) -> Dict[str, Any]:
        """Validate and store the custom menu, bumping `rev` past the stored value.

        The client drops a menu whose `rev` is not strictly greater than the one it
        already applied, so a merchant who saves the same items twice still has to
        get a working re-push after a phone reinstall — hence `revision or rev + 1`
        rather than "whatever the caller sent".
        """
        current = self.menu_state()
        wanted = int(revision) if revision is not None else 0
        menu = build_menu(items, max(wanted, int(current.get("rev") or 0) + 1))
        ts = now_ms()
        payload = compact_json(menu)
        with self.db.transaction() as conn:
            conn.execute(
                # One row per revision: `rev` is part of the primary key, so a
                # re-saved menu is an insert, not an overwrite.
                "INSERT INTO menus (service_id, rev, payload_json, updated_at_ms, last_delivered_ms)"
                " VALUES (?, ?, ?, ?, 0)"
                " ON CONFLICT(service_id, rev) DO UPDATE SET payload_json = excluded.payload_json,"
                " updated_at_ms = excluded.updated_at_ms",
                (self.service_id, menu["rev"], payload, ts),
            )
        return {"service_id": self.service_id, "menu": menu, "updated_at_ms": ts}

    async def push_menu(self, *, contact_ids: Optional[Sequence[int]] = None) -> bool:
        """Deliver the stored menu to every follower (or to an explicit subset).

        Charged per recipient on the `menu_push` meter: the unit the merchant buys
        is "one phone received the menu", and a broadcast to 10 000 followers is
        10 000 node messages whether or not the price list admits it.
        """
        state = self.menu_state()
        items = state.get("items") or []
        if not items:
            raise conflict("menu_empty", "no menu has been stored yet")
        menu = build_menu(items, int(state.get("rev") or 1))
        text = frame_menu_config(menu)
        targets = [int(c) for c in (contact_ids if contact_ids is not None else [s.contact_id for s in self.all_sessions()])]
        if not targets:
            raise conflict("no_recipients", "this service account has no followers yet")
        sent = 0
        for contact_id in targets:
            result = await self._deliver_frame(
                contact_id,
                text,
                kind=FRAME_MENU,
                meter="menu_push",
                ref="menu:%d" % int(menu["rev"]),
                idempotency_key="menu:%d:c%d:r%d" % (contact_id, int(menu["rev"]), 1),
            )
            if result.sent:
                sent += 1
        self.db.execute(
            "UPDATE menus SET last_delivered_ms = ? WHERE service_id = ? AND rev = ?",
            (now_ms(), self.service_id, int(menu["rev"])),
        )
        return sent > 0

    def menu_reply_for(self, text: str) -> Optional[Dict[str, Any]]:
        """The menu leaf the follower just typed.

        Two things can name a leaf, both of them visible to the follower: the
        item's `title` (what they see in the menu and would naturally type) and an
        explicit `kw:<keyword>` payload, which lets a merchant keep a shorter or
        bilingual trigger than the label.

        Matching is whole-string and case-kept, for the reason the alert plugin
        gives at `alert_ops_plugin.py:1369-1382`: a substring rule in CJK has no
        word boundaries, so `确认收货` would match `确认`.
        """
        wanted = (text or "").strip()
        if not wanted:
            return None
        for item in self._menu_leaves():
            if str(item.get("title") or "").strip() == wanted:
                return item
            payload = str(item.get("payload") or "")
            if payload.startswith(MENU_KEYWORD_PREFIX) and payload[len(MENU_KEYWORD_PREFIX):] == wanted:
                return item
        return None

    def _menu_leaves(self) -> List[Dict[str, Any]]:
        """Every menu entry, flattened, including sub-items.

        `build_menu_item` flattens an action's `payload`/`url` onto the item itself
        (`crypto_service.py`, "the action's own payload/url are FLATTENED onto the
        item — that is what the decoder reads"), so a leaf here is read as
        `{title, action, payload?, url?}` and never as a nested `action` object.
        """
        items = self.menu_state().get("items") or []
        out: List[Dict[str, Any]] = []

        def walk(nodes: Any) -> None:
            for node in nodes or ():
                if not isinstance(node, Mapping):
                    continue
                out.append(dict(node))
                walk(node.get("sub"))

        walk(items)
        return out

    # ── cards ───────────────────────────────────────────────────────────────

    def find_card(self, card_id: str, contact_id: Optional[int] = None) -> Optional[Dict[str, Any]]:
        """The stored row for one wire `cardId`.

        Resolution order matters: an exact id (a plugin that mints a per-follower
        id itself, e.g. `poll-<id>-<contact>`) wins over this file's derivation,
        so a plugin's own naming scheme is never rewritten by the gateway.
        """
        text = str(card_id)
        if contact_id is not None:
            for candidate in (text, card_id_for_recipient(text, int(contact_id))):
                row = self.db.query_one("SELECT * FROM cards WHERE card_id = ?", (candidate,))
                if row is not None:
                    return row_dict(row)
            return None
        row = self.db.query_one("SELECT * FROM cards WHERE card_id = ?", (text,))
        if row is None:
            row = self.db.query_one(
                "SELECT * FROM cards WHERE card_id LIKE ? ESCAPE '\\' ORDER BY updated_at_ms DESC LIMIT 1",
                # The separator is part of the prefix: this looks for the ids
                # `card_id_for_recipient` derived, `base_<contact>`, and `base` on its
                # own was already tried as the exact match above.
                (like_prefix(text + "_"),),
            )
        return row_dict(row) if row is not None else None

    def cards(self, *, contact_id: Optional[int] = None, topic: Optional[str] = None, limit: int = 100) -> List[Dict[str, Any]]:
        sql = "SELECT * FROM cards"
        clauses: List[str] = []
        params: List[Any] = []
        if contact_id is not None:
            clauses.append("contact_id = ?")
            params.append(int(contact_id))
        if topic:
            clauses.append("topic = ?")
            params.append(str(topic))
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        sql += " ORDER BY updated_at_ms DESC LIMIT ?"
        params.append(clamp_limit(limit, 100, 1000))
        return [row_dict(row) for row in self.db.query(sql, params)]

    def card_wire(self, row: Mapping[str, Any]) -> Dict[str, Any]:
        """Rebuild the exact wire dict from a stored row (the seal is not stored in it)."""
        return build_card(
            str(row.get("card_id")),
            str(row.get("title") or ""),
            style=str(row.get("style") or "standard"),
            body=row.get("body") or None,
            fields=json_loads_or(row.get("fields_json"), None),
            progress=json_loads_or(row.get("progress_json"), None),
            actions=json_loads_or(row.get("actions_json"), None),
            updated_at_ms=int(row.get("updated_at_ms") or now_ms()),
            expires_at_ms=int(row["expires_at_ms"]) if row.get("expires_at_ms") else None,
        )

    def store_card(self, card: Mapping[str, Any], *, topic: str = "", state: str = CARD_STATE_DRAFT) -> Dict[str, Any]:
        """Insert or update a card row from a wire dict, without sending anything.

        `updated_at_ms` is taken from the card, never from the clock, so that the
        row and the frame the phone receives agree about `ut`; the monotonic bump
        happens in :meth:`deliver_card` / :meth:`update_card` where the previous
        row is in hand.
        """
        card_id = str(card.get("id") or "")
        if not card_id:
            raise bad_request("card_id_required")
        ts = int(card.get("ut") or now_ms())
        expires = int(card["et"]) if card.get("et") else None
        self._upsert_card_row(
            card_id,
            service_id=str(card.get("serviceId") or self.service_id),
            contact_id=int(card.get("contactId") or 0),
            style=str(card.get("v") or "standard"),
            title=str(card.get("title") or ""),
            body=card.get("body") or None,
            fields_json=compact_json(card.get("fields") or []),
            progress_json=compact_json(card["progress"]) if card.get("progress") else None,
            actions_json=compact_json(card.get("actions") or []),
            updated_at_ms=ts,
            expires_at_ms=expires,
            state=state,
            topic=topic,
        )
        self._register_paid_actions(card_id, int(card.get("contactId") or 0), card.get("actions") or [])
        return self.find_card(card_id) or {}

    def _register_paid_actions(self, card_id: str, contact_id: int, actions: Sequence[Any]) -> None:
        """Open a `card_actions` row for every `pay_credits` button on a card.

        This is what makes a payment receipt attributable. The client's reply is
        `::CB::<payload>:paid_<txHash>` (`PopopxEcoRouterAndDeepLink.swift:652-679`),
        which carries the *payload* and nothing identifying the card — so without a
        row written when the button was put on screen, the gateway could not tell
        which card to settle, which amount was really collected, or that the same
        receipt replayed twice is one payment. `UNIQUE (card_id, action_id,
        contact_id)` (`database.py`) is what lets a re-delivery of the same card
        refresh the row instead of duplicating it.
        """
        if contact_id <= 0:
            return
        for raw in actions or ():
            if not isinstance(raw, Mapping) or str(raw.get("action") or "") != "pay_credits":
                continue
            action_id = str(raw.get("id") or "")
            payload = str(raw.get("payload") or "")
            if not action_id or not payload:
                continue
            self.db.execute(
                "INSERT INTO card_actions (card_id, action_id, contact_id, kind, payload, amount, paid_ref,"
                " state, created_at_ms, settled_at_ms)"
                " VALUES (?, ?, ?, 'pay_credits', ?, ?, NULL, 'pending', ?, 0)"
                " ON CONFLICT(card_id, action_id, contact_id) DO UPDATE SET payload = excluded.payload,"
                " amount = excluded.amount",
                (str(card_id), action_id, contact_id, payload, int(raw.get("amount") or 0), now_ms()),
            )

    def pending_paid_action(self, contact_id: int, payload: str) -> Optional[Dict[str, Any]]:
        """The newest unpaid `pay_credits` row matching a receipt's payload."""
        row = self.db.query_one(
            "SELECT * FROM card_actions WHERE contact_id = ? AND payload = ? AND state = 'pending'"
            " ORDER BY id DESC LIMIT 1",
            (int(contact_id), str(payload)),
        )
        return row_dict(row) if row is not None else None

    def settle_paid_action(self, row: Mapping[str, Any], *, paid_ref: str, state: str = "paid") -> None:
        self.db.execute(
            "UPDATE card_actions SET state = ?, paid_ref = ?, settled_at_ms = ? WHERE id = ?",
            (str(state), str(paid_ref or ""), now_ms(), int(row.get("id") or 0)),
        )

    def record_menu_action(self, contact_id: int, payload: str, *, card_id: str = "") -> None:
        """Keep an audit row for a menu button that cost credits.

        A menu `pay_credits` action has no card to attach to, and `card_actions`
        enforces that with a foreign key, so the row is only written when the
        caller can name a real card. A payment with no row anywhere is the one
        thing an operator cannot reconstruct afterwards, which is why the
        gateway records every callback in `callbacks` before it charges.
        """
        if not payload or not card_id:
            return
        if self.db.query_one("SELECT card_id FROM cards WHERE card_id = ?", (str(card_id),)) is None:
            return
        self.db.execute(
            "INSERT INTO card_actions (card_id, action_id, contact_id, kind, payload, amount, paid_ref,"
            " state, created_at_ms, settled_at_ms)"
            " VALUES (?, ?, ?, 'pay_credits', ?, 0, NULL, 'confirmed', ?, ?)",
            (str(card_id), "menu", int(contact_id), str(payload), now_ms(), now_ms()),
        )

    def _upsert_card_row(self, card_id: str, **kw: Any) -> None:
        self.db.execute(
            "INSERT INTO cards (card_id, service_id, contact_id, style, title, body, fields_json, progress_json,"
            " actions_json, created_at_ms, updated_at_ms, expires_at_ms, state, sig_hex, sig_ts, topic, delivered_at_ms)"
            " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, 0, ?, NULL)"
            " ON CONFLICT(card_id) DO UPDATE SET service_id = excluded.service_id, contact_id = excluded.contact_id,"
            " style = excluded.style, title = excluded.title, body = excluded.body,"
            " fields_json = excluded.fields_json, progress_json = excluded.progress_json,"
            " actions_json = excluded.actions_json,"
            # `created_at_ms` is the first delivery's timestamp and an update must
            # not rewrite it; COALESCE keeps the stored value because callers only
            # ever pass `updated_at_ms`.
            " created_at_ms = COALESCE(cards.created_at_ms, excluded.created_at_ms),"
            " updated_at_ms = excluded.updated_at_ms,"
            " expires_at_ms = excluded.expires_at_ms, state = excluded.state, topic = excluded.topic",
            (
                card_id,
                kw["service_id"],
                kw["contact_id"],
                kw["style"],
                kw["title"],
                kw["body"],
                kw["fields_json"],
                kw["progress_json"],
                kw["actions_json"],
                kw.get("created_at_ms") or kw["updated_at_ms"],
                kw["updated_at_ms"],
                kw["expires_at_ms"],
                kw["state"],
                kw["topic"],
            ),
        )

    async def deliver_card(
        self,
        card: Mapping[str, Any],
        contact_id: int,
        *,
        visible_text: Optional[str] = None,
        topic: str = "",
    ) -> CardDelivery:
        """Store a card and deliver it as `{"t":"sc","m":"c"}`, charging `card`.

        Two rules the phone imposes, both visible from the client source:

        * `visible_text` is only legal on a create
          (`crypto_service.py:encode_frame`, from `PopopxEcoModels.swift:120-128`),
          which is why :meth:`update_card` never passes it.
        * the stored `cardId` is the wire `cardId`. A broadcast therefore gets one
          row per recipient via :func:`card_id_for_recipient` — see that function
          for the collision it prevents.
        """
        contact_id = int(contact_id)
        base = dict(card)
        base.pop("contactId", None)
        base.pop("serviceId", None)
        wire_id = str(base.get("id") or "")
        if not wire_id:
            raise bad_request("card_id_required")
        previous = self.find_card(wire_id, contact_id)
        if previous is not None and str(previous.get("state") or "") != CARD_STATE_SETTLED:
            # Re-delivering an existing card id is an update, and the client will
            # merge it; pretending otherwise would strand a second bubble.
            return await self.update_card(
                wire_id,
                contact_id,
                title=base.get("title"),
                body=base.get("body"),
                fields=base.get("fields"),
                progress=base.get("progress"),
                actions=base.get("actions"),
                expires_at_ms=base.get("et"),
            )
        ut = next_monotonic_ms(previous.get("updated_at_ms") if previous else 0)
        base["ut"] = ut
        built = build_card(
            wire_id,
            str(base.get("title") or ""),
            style=str(base.get("v") or base.get("style") or "standard"),
            body=base.get("body"),
            fields=base.get("fields"),
            progress=base.get("progress"),
            actions=base.get("actions"),
            updated_at_ms=ut,
            expires_at_ms=base.get("et"),
        )
        built["serviceId"] = self.service_id
        self.store_card({**built, "contactId": contact_id}, topic=str(topic or ""), state=CARD_STATE_DRAFT)
        text = frame_service_card(built, update=False, visible_text=visible_text)
        return await self._deliver_card_frame(
            built, contact_id, text=text, update=False, topic=str(topic or ""), visible_text=visible_text
        )

    async def update_card(
        self,
        card_id: str,
        contact_id: int,
        *,
        title: Optional[str] = None,
        body: Optional[str] = None,
        fields: Optional[Sequence[Mapping[str, Any]]] = None,
        progress: Optional[Mapping[str, Any]] = None,
        actions: Optional[Sequence[Mapping[str, Any]]] = None,
        expires_at_ms: Optional[int] = None,
    ) -> CardDelivery:
        """Re-deliver a stored card in place as `m=u`, merging the given fields.

        The merge is done here *from the stored row*, which is the only safe place
        to do it: the client merges field-by-field
        (`PopopxEcoRouterAndDeepLink.swift:150-176`) and re-decodes the result, so
        a partial frame is accepted by the phone and then discarded as insane if
        the stored card was missing `body`. Sending the full merged card means the
        phone's merge and ours agree.
        """
        contact_id = int(contact_id)
        row = self.find_card(str(card_id), contact_id)
        if row is None:
            raise not_found("card_not_found", "no card %r for contact %d" % (card_id, contact_id))
        wire_id = str(row["card_id"])
        merged = self.card_wire(row)
        if title is not None:
            merged["title"] = title
        if body is not None:
            merged["body"] = body if body else None
        if fields is not None:
            merged["fields"] = list(fields) if fields else None
        if progress is not None:
            merged["progress"] = progress if progress else None
        if actions is not None:
            # A list of *spec* dicts (`{"action_id":…, "title":…, "kind":…}`) and a
            # list of wire dicts both arrive here, from the console and from a
            # plugin respectively; `build_card` normalises both (its own
            # `_is_wire_action` test) so this layer does not copy that rule.
            merged["actions"] = list(actions) if actions else None
        if expires_at_ms is not None:
            merged["et"] = int(expires_at_ms)
        ut = next_monotonic_ms(int(row.get("updated_at_ms") or 0))
        built = build_card(
            wire_id,
            str(merged.get("title") or ""),
            style=str(merged.get("v") or "standard"),
            body=merged.get("body"),
            fields=merged.get("fields"),
            progress=merged.get("progress"),
            actions=merged.get("actions"),
            updated_at_ms=ut,
            expires_at_ms=merged.get("et"),
        )
        self.store_card({**built, "contactId": contact_id}, topic=str(row.get("topic") or ""), state=CARD_STATE_SENT)
        text = frame_service_card(built, update=True)
        return await self._deliver_card_frame(built, contact_id, text=text, update=True, topic=str(row.get("topic") or ""))

    async def settle_card(
        self,
        card_id: str,
        contact_id: int,
        *,
        title: Optional[str] = None,
        body: Optional[str] = None,
        label: str = "已完成",
    ) -> CardDelivery:
        """Retire a card's buttons in place: same id, inert actions, expired.

        This is the answer to "the pay button must not be pressable twice". The
        client's own definition of a tappable button is
        `ServiceCardBubbleView.swift:173-182` — no live actions while the card is
        expired, and `PopopxEcoModels.swift:541` (`isLive`) is what makes the
        expiry stick — so this method sends the full action list rewritten by
        :func:`retired_actions` *and* an `et` in the past.
        """
        contact_id = int(contact_id)
        row = self.find_card(str(card_id), contact_id)
        if row is None:
            raise not_found("card_not_found", "no card %r for contact %d" % (card_id, contact_id))
        actions = json_loads_or(row.get("actions_json"), []) or []
        result = await self.update_card(
            str(row["card_id"]),
            contact_id,
            title=title,
            body=body,
            actions=retired_actions(actions, label=label) if actions else [],
            expires_at_ms=now_ms() - 1,
        )
        self.db.execute("UPDATE cards SET state = ? WHERE card_id = ?", (CARD_STATE_SETTLED, str(row["card_id"])))
        return result

    async def _deliver_card_frame(
        self,
        built: Mapping[str, Any],
        contact_id: int,
        *,
        text: str,
        update: bool,
        topic: str,
        visible_text: Optional[str] = None,
    ) -> CardDelivery:
        card_id = str(built.get("id") or "")
        meter = "card"
        result = await self._deliver_frame(
            contact_id,
            text,
            kind=FRAME_CARD_UPDATE if update else FRAME_CARD,
            meter=meter,
            ref=card_id,
            idempotency_key="%s:%s:c%d:u%d" % ("u" if update else "c", card_id, contact_id, int(built.get("ut") or 0)),
            card_id=card_id,
            meta={"topic": topic, "style": built.get("v"), "update": update},
        )
        return CardDelivery(
            card_id=card_id,
            contact_id=contact_id,
            sent=result.sent,
            charged=result.charged,
            balance_after=result.balance_after,
            error=result.error,
            queued=result.queued,
        )

    # ── frames, charging and the outbox ─────────────────────────────────────

    async def _deliver_frame(
        self,
        contact_id: int,
        text: str,
        *,
        kind: str,
        meter: Optional[str],
        ref: str,
        idempotency_key: Optional[str],
        card_id: str = "",
        meta: Optional[Dict[str, Any]] = None,
    ) -> CardDelivery:
        """Charge, then send; queue uncharged while the node is down; refund on failure.

        The three-way outcome is what callers branch on:

        * `sent` — the node accepted the command *and* the ledger has the debit;
        * `queued` — the frame is durable in `outbox` and **not** charged, because
          a credit spent on a message the node may never accept is a charge the
          merchant cannot dispute away. The worker charges on drain.
        * neither — a refusal, named in `error` (`credit_*`, `send_failed`, …).

        `send_text` returning without raising is the strongest claim this layer can
        make: the phone rendering the card is only proved later, by the `::CB::`
        that a tap produces, and that lands in `callbacks`.
        """
        if not text:
            raise bad_request("empty_frame")
        if not self.bridge_connected():
            outbox_id = self.enqueue(contact_id, kind, text, card_id=card_id, meter=meter, ref=ref, idempotency_key=idempotency_key)
            return CardDelivery(card_id, contact_id, False, 0, None, error="node_unreachable", queued=True)
        charged = 0
        balance_after: Optional[int] = None
        if meter is not None:
            try:
                receipt = self.billing.charge(
                    meter,
                    contact_id=contact_id,
                    ref=ref,
                    idempotency_key=idempotency_key,
                    meta=meta,
                )
            except BillingError as exc:
                return CardDelivery(card_id, contact_id, False, 0, None, error=exc.code)
            charged = int(receipt.charged)
            balance_after = int(receipt.balance_after)
        try:
            await self.bridge.send_text(contact_id, text)
        except (NodeError, OSError, asyncio.TimeoutError) as exc:
            if charged:
                try:
                    self.billing.refund(
                        amount=charged,
                        reason="send_failed:%s" % kind,
                        idempotency_key="refund:%s" % (idempotency_key or "%s:%s" % (kind, ref)),
                        ref=ref,
                    )
                except BillingError:  # pragma: no cover — a failed refund is reported, not hidden
                    LOG.exception("refund failed after a refused send (kind=%s ref=%s)", kind, ref)
            LOG.warning("send failed to contact %d (%s): %s", contact_id, kind, exc)
            self.mark_outbox_failure(contact_id, card_id, kind, str(exc))
            return CardDelivery(card_id, contact_id, False, 0, None, error="send_failed")
        except Exception as exc:  # noqa: BLE001 — a crashed task must not lose the debit silently
            LOG.exception("unexpected send error to contact %d", contact_id)
            return CardDelivery(card_id, contact_id, False, charged, balance_after, error="send_error")
        self.db.execute(
            "UPDATE cards SET state = ?, delivered_at_ms = ? WHERE card_id = ? AND state <> ?",
            (CARD_STATE_DELIVERED, now_ms(), card_id, CARD_STATE_SETTLED),
        )
        if card_id:
            self.db.execute(
                "UPDATE outbox SET status = 'sent', sent_at_ms = ? WHERE contact_id = ? AND card_id = ? AND status IN ('queued','in_flight')",
                (now_ms(), contact_id, card_id),
            )
        return CardDelivery(card_id, contact_id, True, charged, balance_after)

    def bridge_connected(self) -> bool:
        return bool(getattr(self.bridge, "connected", False))

    async def send_frame_outcome(self, contact_id: int, text: str) -> Tuple[bool, bool]:
        """Send uncharged, or queue locally; return ``(delivered, queued)``.

        The plugin seam needs to tell an operator whether a standalone gateway
        accepted a message into its outbox or actually reached the node. A bare
        bool conflates those two outcomes and makes an offline demo look like a
        delivery failure.
        """
        if not text:
            return False, False
        if not self.bridge_connected():
            self.enqueue(int(contact_id), FRAME_TEXT, text)
            return False, True
        try:
            await self.bridge.send_text(int(contact_id), text)
        except (NodeError, OSError, asyncio.TimeoutError) as exc:
            LOG.warning("plain send to contact %d failed: %s", contact_id, exc)
            return False, False
        return True, False

    async def send_frame(self, contact_id: int, text: str) -> bool:
        """Send an already-encoded frame, or plain text, uncharged.

        Deliberately not charged: this is the seam a plugin uses for the *body* of
        an answer it has already paid for on its own meter (the AI plugin charges
        `ai_message`, then sends the reply through here). Charging `card` again
        would price one message twice. No framing rule is applied either — the
        text goes to the node as it arrived, which is what makes an
        already-encoded `::POPOPX_ECO::` frame and an ordinary sentence the same
        operation to this method. That is also why `strip_control_markers` in the
        AI plugin matters: unsanitised prose starting with the marker *is* a frame
        as far as the phone is concerned.
        """
        delivered, _queued = await self.send_frame_outcome(contact_id, text)
        return delivered

    def enqueue(
        self,
        contact_id: int,
        kind: str,
        body: str,
        *,
        card_id: str = "",
        meter: Optional[str] = None,
        ref: str = "",
        idempotency_key: Optional[str] = None,
    ) -> int:
        """Park a frame in `outbox` for the worker, without charging for it.

        The charge metadata travels with the row (`credits_charged` stays 0) so
        the worker can re-charge with the *same* idempotency key: a frame that is
        queued and later drained must be billed exactly once, and one that is
        replayed by hand must not be billed twice.

        `Database.execute` returns `lastrowid` for an INSERT, which is why the id
        is taken from the insert statement itself instead of a follow-up lookup —
        a second query would be a race with the worker on another thread.
        """
        outbox_id = int(
            self.db.execute(
                "INSERT INTO outbox (ts_ms, contact_id, frame_kind, card_id, body, status, attempts, last_error, corr_id, credits_charged)"
                " VALUES (?, ?, ?, ?, ?, 'queued', 0, NULL, NULL, 0)",
                (now_ms(), int(contact_id), kind, card_id, body),
            )
            or 0
        )
        # The billing keys go in `corr_id`, which the schema defines as a free-text
        # correlation field: keeping the triple here means the worker needs no
        # second lookup, and a drained frame is charged from the row it drained.
        self.db.execute(
            "UPDATE outbox SET corr_id = ? WHERE id = ?",
            (compact_json({"meter": meter, "ref": ref, "key": idempotency_key, "card_id": card_id}), outbox_id),
        )
        return outbox_id

    def mark_outbox_failure(self, contact_id: int, card_id: str, kind: str, error: str) -> None:
        """Record a refused send against the newest queued row for this frame.

        Only used when a delivery is attempted; a queue insert is not a failure.
        """
        if not card_id:
            return
        self.db.execute(
            "UPDATE outbox SET attempts = attempts + 1, last_error = ?,"
            " status = CASE WHEN attempts + 1 >= ? THEN 'abandoned' ELSE status END"
            " WHERE contact_id = ? AND card_id = ? AND status IN ('queued','in_flight')",
            (error[:400], OUTBOX_MAX_ATTEMPTS, int(contact_id), card_id),
        )

    def queued_frames(self, limit: int = OUTBOX_BATCH) -> List[Dict[str, Any]]:
        rows = self.db.query(
            "SELECT * FROM outbox WHERE status = 'queued' ORDER BY id LIMIT ?", (clamp_limit(limit, OUTBOX_BATCH, 500),)
        )
        return [row_dict(row) for row in rows]

    def outbox_stats(self) -> Dict[str, Any]:
        rows = self.db.query("SELECT status, COUNT(*) AS n, MIN(ts_ms) AS oldest FROM outbox GROUP BY status")
        out = {"queued": 0, "in_flight": 0, "sent": 0, "failed": 0, "abandoned": 0, "oldest_queued_ms": 0}
        for row in rows:
            data = row_dict(row)
            status = str(data.get("status") or "")
            if status in out:
                out[status] = int(data.get("n") or 0)
            if status == "queued":
                out["oldest_queued_ms"] = int(data.get("oldest") or 0)
        return out

    async def drain_outbox(self, *, limit: int = OUTBOX_BATCH) -> Dict[str, int]:
        """Attempt every queued frame this pass. Returns counts by outcome.

        Frames are attempted oldest-first so that a card a follower is waiting for
        is not overtaken by a menu broadcast queued after it. A row whose body
        no longer parses as text (a partial write from a crashed process) is
        abandoned rather than retried forever.
        """
        tally = {"sent": 0, "queued": 0, "failed": 0, "skipped": 0}
        if not self.bridge_connected():
            return tally
        for row in self.queued_frames(limit):
            outbox_id = int(row.get("id") or 0)
            meta = json_loads_or(row.get("corr_id"), {}) or {}
            kind = str(row.get("frame_kind") or FRAME_TEXT)
            body = str(row.get("body") or "")
            contact_id = int(row.get("contact_id") or 0)
            if not body or contact_id <= 0:
                self.db.execute("UPDATE outbox SET status = 'abandoned', last_error = ? WHERE id = ?", ("malformed row", outbox_id))
                tally["failed"] += 1
                continue
            claimed = self.db.execute(
                "UPDATE outbox SET status = 'in_flight', attempts = attempts + 1 WHERE id = ? AND status = 'queued'",
                (outbox_id,),
            )
            if int(claimed or 0) != 1:
                tally["skipped"] += 1
                continue
            result = await self._deliver_frame(
                contact_id,
                body,
                kind=kind,
                meter=meta.get("meter") or None,
                ref=str(meta.get("ref") or body[:64]),
                idempotency_key=meta.get("key") or None,
                card_id=str(row.get("card_id") or meta.get("card_id") or ""),
            )
            if result.sent:
                self.db.execute(
                    "UPDATE outbox SET status = 'sent', sent_at_ms = ?, credits_charged = ?, last_error = NULL WHERE id = ?",
                    (now_ms(), int(result.charged), outbox_id),
                )
                tally["sent"] += 1
            elif result.error == "node_unreachable":
                self.db.execute("UPDATE outbox SET status = 'queued' WHERE id = ?", (outbox_id,))
                tally["queued"] += 1
            else:
                again = self.db.query_one("SELECT attempts FROM outbox WHERE id = ?", (outbox_id,))
                attempts = int(row_dict(again or {}).get("attempts") or 1)
                status = "abandoned" if attempts >= OUTBOX_MAX_ATTEMPTS else "queued"
                self.db.execute(
                    "UPDATE outbox SET status = ?, last_error = ? WHERE id = ?",
                    (status, str(result.error or "failed")[:400], outbox_id),
                )
                tally["failed"] += 1
        return tally

    # ── channels: identity, epochs, membership ──────────────────────────────

    def channels(self) -> List[Dict[str, Any]]:
        rows = self.db.query("SELECT * FROM channels ORDER BY channel_id")
        return [self._channel_public(row_dict(row)) for row in rows]

    def channel_state(self, channel_id: str) -> Optional[Dict[str, Any]]:
        row = self.db.query_one("SELECT * FROM channels WHERE channel_id = ?", (str(channel_id),))
        return self._channel_public(row_dict(row)) if row is not None else None

    def _channel_public(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """A channel row with the identity *secret* removed.

        `identity_sec_b64url` signs an epoch envelope, so a console response that
        echoed the row verbatim would hand the private half of the channel to
        anyone holding an admin token for a read-only listing. The public half is
        included: it is in the members' URIs anyway.
        """
        data.pop("identity_sec_b64url", None)
        return data

    def create_channel(
        self,
        channel_id: str,
        title: str,
        *,
        relay: str = "",
        node_group_id: Optional[int] = None,
    ) -> Dict[str, Any]:
        """Mint a channel identity and open epoch 1.

        `relay` is the **bare host**, not a `group@host` address: the client parses
        `popopx://channel/<relay>/<channel_id>#key=&pub=` and requires a two-segment
        path whose segments pass `isOpaqueSegment` (PopopxEcoModels.swift:793-796),
        an alphabet of `[A-Za-z0-9._-]` with no `@` in it (allowedCharacters,
        PopopxEcoModels.swift:739). The address is only knowable from the node,
        which is why :meth:`set_channel_relay` exists separately and why creation
        does not invent one. Without a relay `channel_public_uri` returns `None`
        and every grant reports `no_relay`.
        """
        text = str(channel_id).strip()
        # The client's own segment alphabet, no colon: `PopopxChannelPublicURI`
        # parses the channel id out of a URI path segment whose allowed set is
        # `[A-Za-z0-9-_.]` (PopopxEcoModels.swift:739), so an id containing `:`
        # would mint a channel whose public URI can never be built.
        if not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", text):
            raise bad_request("channel_id_invalid", "expected 1-64 of [A-Za-z0-9_.-]")
        if self.channel_state(text) is not None:
            raise conflict("channel_exists", "channel %s already exists" % text)
        try:
            identity_private, identity_public = self._identity_factory()
            epoch_key = self._key_factory()
        except CryptoUnavailable as exc:
            raise unavailable("crypto_unavailable", str(exc)) from exc
        ts = now_ms()
        with self.db.transaction() as conn:
            conn.execute(
                "INSERT INTO channels (channel_id, relay, title, identity_pub_b64url, identity_sec_b64url,"
                " current_epoch, node_group_id, created_at_ms, rotated_at_ms, uri_published)"
                " VALUES (?, ?, ?, ?, ?, 1, ?, ?, NULL, 0)",
                (
                    text,
                    str(relay or ""),
                    str(title or "")[:120],
                    b64_url(identity_public),
                    self.vault.seal(
                        b64_url(identity_private),
                        table="channels",
                        column="identity_sec_b64url",
                        subject=text,
                    ),
                    int(node_group_id) if node_group_id else None,
                    ts,
                ),
            )
            conn.execute(
                "INSERT INTO channel_epochs (channel_id, epoch, key_b64url, created_at_ms, expires_at_ms,"
                " revoked, sealed_under_epoch, delivered_ms) VALUES (?, 1, ?, ?, NULL, 0, NULL, NULL)",
                (
                    text,
                    self.vault.seal(
                        b64_url(epoch_key),
                        table="channel_epochs",
                        column="key_b64url",
                        subject="%s:1" % text,
                    ),
                    ts,
                ),
            )
        return self.channel_state(text) or {}

    def set_channel_uri(self, channel_id: str, uri: str) -> Dict[str, Any]:
        """Record the relay this channel is published on, from its public URI.

        Only the relay *segment* is stored: the fragment is ours to mint (epoch 1's
        key and the identity public half), so `:meth:`channel_public_uri` rebuilds
        the whole URI from it. A pasted URI whose `pub=` or `key=` describes a
        different issuer is refused here rather than silently replacing the key a
        paying member's device already trusts.
        """
        validated = validate_channel_public_uri(uri)
        if self.channel_state(channel_id) is None:
            raise not_found("channel_not_found", str(channel_id))
        head = validated[len("popopx://channel/"):].partition("#")[0]
        relay, _, described_id = head.partition("/")
        if described_id != str(channel_id):
            raise bad_request(
                "channel_uri_mismatch",
                "that URI describes channel %r, not %r" % (described_id, channel_id),
            )
        fragment = validated.partition("#")[2]
        values = dict(pair.split("=", 1) for pair in fragment.split("&") if "=" in pair)
        if values.get("pub") != str((self.channel_state(channel_id) or {}).get("identity_pub_b64url") or ""):
            raise conflict(
                "channel_issuer_mismatch",
                "the URI's pub= is not this channel's identity key; re-minting it would lock out every member",
            )
        epoch_one = self.db.query_one(
            "SELECT key_b64url FROM channel_epochs WHERE channel_id = ? AND epoch = 1", (str(channel_id),)
        )
        if epoch_one is not None and values.get("key") != self.vault.open(
            row_dict(epoch_one).get("key_b64url") or "",
            table="channel_epochs",
            column="key_b64url",
            subject="%s:1" % str(channel_id),
        ):
            raise conflict(
                "channel_key_mismatch",
                "the URI's key= is not this channel's epoch-1 key; members who imported it cannot verify a rotation",
            )
        self.db.execute(
            "UPDATE channels SET relay = ?, uri_published = 1 WHERE channel_id = ?",
            (relay, str(channel_id)),
        )
        return self.channel_state(channel_id) or {}

    def set_channel_relay(self, channel_id: str, relay: str) -> Dict[str, Any]:
        """Name the server the channel's group lives on, so a URI can be built.

        Validated against the client's segment alphabet rather than stored and
        discovered broken at join time, because the failure mode of a bad relay is
        a URI that `PopopxChannelPublicURI.parse` returns `nil` for — which the
        phone reports as nothing at all.
        """
        if self.channel_state(channel_id) is None:
            raise not_found("channel_not_found", str(channel_id))
        try:
            text = validate_channel_relay(relay)
        except EcoError as exc:
            raise bad_request("relay_invalid", exc.detail) from exc
        self.db.execute("UPDATE channels SET relay = ? WHERE channel_id = ?", (text, str(channel_id)))
        return self.channel_state(channel_id) or {}

    def channel_epoch_key(self, channel_id: str, epoch: int) -> Optional[bytes]:
        row = self.db.query_one(
            "SELECT key_b64url, revoked FROM channel_epochs WHERE channel_id = ? AND epoch = ?",
            (str(channel_id), int(epoch)),
        )
        if row is None or int(row_dict(row).get("revoked") or 0):
            return None
        return b64_decode_lenient(self.vault.open(
            row_dict(row).get("key_b64url") or "",
            table="channel_epochs",
            column="key_b64url",
            subject="%s:%d" % (str(channel_id), int(epoch)),
        ))

    def epoch_history(self, channel_id: str) -> List[Dict[str, Any]]:
        rows = self.db.query(
            "SELECT epoch, created_at_ms, expires_at_ms, revoked, sealed_under_epoch, delivered_ms"
            "  FROM channel_epochs WHERE channel_id = ? ORDER BY epoch DESC",
            (str(channel_id),),
        )
        return [row_dict(row) for row in rows]

    async def rotate_channel_key(
        self,
        channel_id: str,
        *,
        expires_at_ms: Optional[int] = None,
        revoke_previous: bool = True,
        notify_members: bool = True,
    ) -> Dict[str, Any]:
        """Open a new epoch and seal it under the previous one, then hand it out.

        `sealed_under_epoch` is recorded because the client's rule is that a key
        update is only usable by a member who can decrypt it with the epoch they
        *already hold*: revoking the previous epoch first would lock out exactly
        the members the rotation is for
        (`ChannelKeyRotationManager.swift:74-127`, and the `revokePrevious` flag on
        the wire frame at `crypto_service.frame_channel_key_update`).
        """
        state = self.channel_state(channel_id)
        if state is None:
            raise not_found("channel_not_found", str(channel_id))
        previous_epoch = int(state.get("current_epoch") or 1)
        next_epoch = previous_epoch + 1
        if next_epoch > EcoLimits.max_epoch:
            raise conflict("epoch_exhausted", "the client's maximum epoch is %d" % EcoLimits.max_epoch)
        try:
            epoch_key = self._key_factory()
        except CryptoUnavailable as exc:
            raise unavailable("crypto_unavailable", str(exc)) from exc
        ts = now_ms()
        with self.db.transaction() as conn:
            conn.execute(
                "INSERT INTO channel_epochs (channel_id, epoch, key_b64url, created_at_ms, expires_at_ms, revoked,"
                " sealed_under_epoch, delivered_ms) VALUES (?, ?, ?, ?, ?, 0, ?, NULL)",
                (
                    str(channel_id),
                    next_epoch,
                    self.vault.seal(
                        b64_url(epoch_key),
                        table="channel_epochs",
                        column="key_b64url",
                        subject="%s:%d" % (str(channel_id), next_epoch),
                    ),
                    ts,
                    expires_at_ms,
                    previous_epoch,
                ),
            )
            conn.execute("UPDATE channels SET current_epoch = ?, rotated_at_ms = ? WHERE channel_id = ?",
                         (next_epoch, ts, str(channel_id)))
            if revoke_previous:
                conn.execute(
                    "UPDATE channel_epochs SET revoked = 1 WHERE channel_id = ? AND epoch < ?",
                    (str(channel_id), next_epoch),
                )
        delivered = 0
        charged = 0
        errors: List[str] = []
        if notify_members:
            for session in self.sessions_for_channel(str(channel_id)):
                grant = await self.deliver_channel_key(str(channel_id), session.contact_id)
                if grant.delivered:
                    delivered += 1
                charged += int(grant.charged or 0)
                if grant.error:
                    errors.append("%d:%s" % (session.contact_id, grant.error))
        return {
            "ok": True,
            "channel_id": str(channel_id),
            "epoch": next_epoch,
            "sealed_under_epoch": previous_epoch,
            "revoked_previous": bool(revoke_previous),
            "members_notified": delivered,
            "credits_charged": charged,
            "errors": errors[:20],
        }

    async def deliver_channel_key(
        self,
        channel_id: str,
        contact_id: int,
        *,
        sealed_under: Optional[int] = None,
        issued_epoch: Optional[int] = None,
    ) -> ChannelGrant:
        """Seal the current epoch *under the key this member already holds* and send it.

        The sealing stays here even though a plugin asked for the grant, for the
        reason stated on `Eco.deliver_channel_key`: a second implementation of the
        envelope is a second set of bugs in the one place where a bug is a
        silent-decrypt failure on a phone.

        Two rules from the client decide the whole shape of this method
        (`ChannelKeyRotationManager.swift`):

        * `PopopxChannelKeyUpdate.isSane` refuses `envelope.epoch == sealedUnderEpoch`
          (:374) — a frame may never ask a device to open a key with that same key,
          so `sealed_under` is the member's *installed* epoch, not the epoch being
          delivered.
        * `apply()` looks the sealed epoch up in the epochs this device stores
          (:632) and decrypts the envelope **with that older key** (:637-641). A
          rotation is therefore encrypted under the key the member has, and only the
          plaintext carries the new one.

        `issued_epoch` is the epoch the member's device ends up holding — the one
        the next rotation must seal under. `grant_membership` passes it for a new
        member, whose device is only ever given epoch 1 (through the public URI).
        """
        channel_id, contact_id = str(channel_id), int(contact_id)
        state = self.channel_state(channel_id)
        if state is None:
            raise not_found("channel_not_found", channel_id)
        session = self.session_for(contact_id)
        if session is None or not session.usable:
            return ChannelGrant(channel_id, contact_id, 0, False, 0, error="no_session")
        row = self.db.query_one(
            "SELECT * FROM channel_members WHERE channel_id = ? AND contact_id = ?", (channel_id, contact_id)
        )
        if row is None:
            return ChannelGrant(channel_id, contact_id, 0, False, 0, error="not_a_member")
        member = row_dict(row)
        epoch = int(state.get("current_epoch") or 1)
        under = int(sealed_under if sealed_under is not None else (member.get("epoch") or 1))
        holds = int(issued_epoch if issued_epoch is not None else (member.get("epoch") or 1))
        if under == epoch:
            # Nothing to deliver: this device already holds the key it would receive.
            return ChannelGrant(channel_id, contact_id, epoch, False, 0, error="already_issued")
        epoch_key = self.channel_epoch_key(channel_id, epoch)
        sealing_key = self.epoch_key_for_sealing(channel_id, under)
        if not epoch_key:
            return ChannelGrant(channel_id, contact_id, epoch, False, 0, error="epoch_revoked")
        if not sealing_key:
            return ChannelGrant(channel_id, contact_id, epoch, False, 0, error="unknown_sealed_epoch")
        try:
            identity_public = b64_decode_lenient(str(state.get("identity_pub_b64url") or ""))
            identity_private = self._channel_secret(channel_id)
            member_expiry = int(member.get("expires_at_ms") or 0) or None
            plaintext = epoch_secret_plaintext(
                epoch,
                epoch_key,
                identity_public_key=identity_public,
                expires_at_ms=member_expiry,
            )
            envelope = self._sealer(channel_id, epoch, sealing_key, plaintext, identity_private, identity_public)
            text = frame_channel_key_update(channel_id, under, True, envelope)
        except (CryptoUnavailable, EcoError) as exc:
            code = getattr(exc, "rule", "crypto_unavailable")
            return ChannelGrant(channel_id, contact_id, epoch, False, 0, error=str(code))
        result = await self._deliver_frame(
            contact_id,
            text,
            kind=FRAME_KEY,
            meter="key_rotation",
            ref="%s:%d" % (channel_id, epoch),
            idempotency_key="ku:%s:%d:c%d:u%d" % (channel_id, epoch, contact_id, under),
            meta={"channel_id": channel_id, "epoch": epoch},
        )
        if result.sent:
            self.db.execute(
                "UPDATE channel_epochs SET delivered_ms = ? WHERE channel_id = ? AND epoch = ?",
                (now_ms(), channel_id, epoch),
            )
            self.db.execute(
                "UPDATE channel_members SET epoch = ? WHERE channel_id = ? AND contact_id = ?",
                (epoch, channel_id, contact_id),
            )
        return ChannelGrant(
            channel_id,
            contact_id,
            epoch,
            bool(result.sent),
            int(result.charged or 0),
            public_uri=self.channel_public_uri(channel_id),
            error=result.error,
            holds_epoch=holds,
        )

    def epoch_key_for_sealing(self, channel_id: str, epoch: int) -> Optional[bytes]:
        """The key of an *older* epoch, which is what a rotation is encrypted with.

        `channel_epoch_key` refuses a revoked epoch because a revoked key must not
        be handed to anyone as if it were live. This one answers a different
        question — "can I still open a box for a member who is holding epoch N" —
        and the client's `apply()` decrypts with exactly that older key, so a
        gateway that forgot it loses the ability to rotate for anyone who joined
        before the revocation.
        """
        row = self.db.query_one(
            "SELECT key_b64url FROM channel_epochs WHERE channel_id = ? AND epoch = ?",
            (str(channel_id), int(epoch)),
        )
        if row is None:
            return None
        return b64_decode_lenient(self.vault.open(
            row_dict(row).get("key_b64url") or "",
            table="channel_epochs",
            column="key_b64url",
            subject="%s:%d" % (str(channel_id), int(epoch)),
        ))

    def channel_public_uri(self, channel_id: str) -> Optional[str]:
        """`popopx://channel/<relay>/<channel_id>#key=<epoch 1>&pub=<identity>`.

        Built here instead of pasted by an operator because the two fragment
        values are ours: epoch 1's key and the identity public half. A member's
        first key can only arrive this way — `PopopxChannelKeyUpdate.isSane`
        refuses a frame whose `se` equals the delivered epoch, so there is no
        legal `ku` frame for a device that holds nothing.
        """
        state = self.channel_state(channel_id)
        if state is None:
            raise not_found("channel_not_found", str(channel_id))
        relay = str(state.get("relay") or "").strip()
        if not relay:
            return None
        epoch_one = self.db.query_one(
            "SELECT key_b64url FROM channel_epochs WHERE channel_id = ? AND epoch = 1", (str(channel_id),)
        )
        if epoch_one is None:
            return None
        try:
            return build_channel_public_uri(
                relay,
                str(channel_id),
                self.vault.open(
                    row_dict(epoch_one).get("key_b64url") or "",
                    table="channel_epochs",
                    column="key_b64url",
                    subject="%s:1" % str(channel_id),
                ),
                str(state.get("identity_pub_b64url") or ""),
            )
        except EcoError:
            return None

    # ── opaque invite links (privacy format, not protocol) ──────────────────

    def invite_link(self, kind: str, subject_id: str, raw_uri: Optional[str]) -> Dict[str, Any]:
        """Return the stable opaque link for one subject, minting it once.

        The cache key is the subject, and the cached entry is only reused when
        it still decodes to the *current* raw URI: rotating a contact address or
        changing a channel relay therefore invalidates it without a separate
        version column. A mint writes exactly one audit row with the masked
        prefix and the generation time — never the link, the code or the relay.

        This method never raises. A missing wheel, a missing relay or an
        invalid settings row all come back as `error`, because it sits on the
        `/status` path and a status endpoint that 500s is worse than one that
        says the invite link is unavailable.
        """
        kind = str(kind or "")
        subject = str(subject_id or "")
        text = str(raw_uri or "")
        blank: Dict[str, Any] = {
            "link": None,
            "masked": None,
            "created_at_ms": None,
            "cached": False,
        }
        if kind not in INVITE_KINDS or not subject:
            return dict(blank, error="invite_kind_invalid")
        if not text:
            return dict(blank, error="invite_source_unavailable")

        key = SETTING_INVITE_LINK_PREFIX + kind + ":" + subject

        def cached_entry(value: Any) -> Optional[Dict[str, Any]]:
            if not isinstance(value, Mapping):
                return None
            link = str(value.get("link") or "")
            created = value.get("created_at_ms")
            if not link or not isinstance(created, (int, float)):
                return None
            try:
                if decode_invite(link) != text:
                    return None
            except InviteCodecError:
                return None
            return {
                "link": link,
                "masked": mask_invite_link(link),
                "created_at_ms": int(created),
                "cached": True,
            }

        hit = cached_entry(self.db.get_setting(key))
        if hit is not None:
            return hit

        try:
            link = encode_invite(text)
        except InviteCodecError as exc:
            return dict(blank, error=exc.code)
        created = now_ms()
        entry = {
            "link": link,
            "created_at_ms": created,
            "kind": kind,
            "subject_id": subject,
        }
        with self.db.transaction() as conn:
            row = conn.execute("SELECT value_json FROM settings WHERE key = ?", (key,)).fetchone()
            if row is not None:
                try:
                    winner = json.loads(row["value_json"])
                except (TypeError, ValueError):
                    winner = None
                hit = cached_entry(winner)
                if hit is not None:
                    return hit
            conn.execute(
                "INSERT INTO settings (key, value_json, updated_at_ms) VALUES (?, ?, ?)"
                " ON CONFLICT(key) DO UPDATE SET value_json = excluded.value_json, updated_at_ms = excluded.updated_at_ms",
                (key, json.dumps(entry, ensure_ascii=False, separators=(",", ":")), created),
            )
            conn.execute(
                "INSERT INTO invite_link_audit (created_at_ms, kind, subject_id, code_prefix) VALUES (?, ?, ?, ?)",
                (created, kind, subject, invite_code_prefix(link)),
            )
        return {
            "link": link,
            "masked": mask_invite_link(link),
            "created_at_ms": created,
            "cached": False,
        }

    def decorate_invite(
        self,
        payload: Dict[str, Any],
        *,
        kind: str,
        subject_id: str,
        raw_uri: Optional[str],
        field: str = "invite_link",
    ) -> Dict[str, Any]:
        """Attach the opaque link fields to an API payload without hiding the raw one.

        The raw URI stays in its existing field for the protocol and for the
        console's 高级诊断 fold. What changes is which field a caller reaches
        for by default: `*_link` is always the opaque link, and it is `None`
        (with `*_link_error`) rather than a raw fallback when it cannot be
        minted.
        """
        info = self.invite_link(kind, subject_id, raw_uri)
        payload[field] = info.get("link")
        payload[field + "_masked"] = info.get("masked")
        payload[field + "_created_at_ms"] = info.get("created_at_ms")
        if info.get("error"):
            payload[field + "_error"] = info["error"]
        return payload

    def invite_link_audit(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Recent generations, masked. There is no column that could leak a code."""
        count = max(1, min(int(limit or 50), 200))
        rows = self.db.query(
            "SELECT id, created_at_ms, kind, subject_id, code_prefix"
            "  FROM invite_link_audit ORDER BY id DESC LIMIT ?",
            (count,),
        )
        return [row_dict(row) for row in rows]

    def _channel_secret(self, channel_id: str) -> bytes:
        row = self.db.query_one(
            "SELECT identity_sec_b64url FROM channels WHERE channel_id = ?", (str(channel_id),)
        )
        if row is None:
            raise not_found("channel_not_found", channel_id)
        return b64_decode_lenient(self.vault.open(
            row_dict(row).get("identity_sec_b64url") or "",
            table="channels",
            column="identity_sec_b64url",
            subject=str(channel_id),
        ))

    def members(self, channel_id: str, *, status: Optional[str] = None) -> List[Dict[str, Any]]:
        sql = "SELECT * FROM channel_members WHERE channel_id = ?"
        params: List[Any] = [str(channel_id)]
        if status:
            sql += " AND status = ?"
            params.append(str(status))
        sql += " ORDER BY contact_id"
        return [row_dict(row) for row in self.db.query(sql, params)]

    async def grant_membership(
        self,
        channel_id: str,
        contact_id: int,
        *,
        credits: int = 0,
        paid_ref: str = "",
        days: int = 30,
        display_name: str = "",
    ) -> Dict[str, Any]:
        """Admit one follower to a channel at the current epoch and send the key.

        The member row is written *before* the delivery, because
        :meth:`sessions_for_channel` and :meth:`deliver_channel_key` both read it:
        granting and then sending is the only order in which the send is
        authorised, and a follower who is billed a key rotation they were not
        entitled to is a refund the merchant has to ask for.

        A *new* member is a special case the client forces: their device obtains
        epoch 1 only from the public URI (`importPublicURI` stores it as epoch 1,
        `ChannelKeyRotationManager.swift:593-606`), so the frame we send must be
        sealed under 1 whatever the channel has rotated to, and at epoch 1 there
        is no legal frame at all — the URI is the delivery.
        """
        channel_id, contact_id = str(channel_id), int(contact_id)
        state = self.channel_state(channel_id)
        if state is None:
            raise not_found("channel_not_found", channel_id)
        if self.session_for(contact_id) is None:
            self.ensure_session(contact_id)
        self.touch_contact(contact_id, display_name)
        ts = now_ms()
        expires = ts + max(1, int(days)) * 86_400_000
        epoch = int(state.get("current_epoch") or 1)
        existing = self.db.query_one(
            "SELECT status, epoch FROM channel_members WHERE channel_id = ? AND contact_id = ?",
            (channel_id, contact_id),
        )
        public_uri = self.channel_public_uri(channel_id)
        if existing is None:
            sealed_under, issued_epoch = 1, 1
        else:
            sealed_under = issued_epoch = int(existing["epoch"] or 1)
        self.db.execute(
            "INSERT INTO channel_members (channel_id, contact_id, epoch, paid_ref, credits_spent, granted_at_ms, expires_at_ms, status)"
            " VALUES (?, ?, ?, ?, ?, ?, ?, 'active')"
            " ON CONFLICT(channel_id, contact_id) DO UPDATE SET paid_ref = excluded.paid_ref,"
            " credits_spent = COALESCE(channel_members.credits_spent, 0) + excluded.credits_spent,"
            " granted_at_ms = excluded.granted_at_ms, expires_at_ms = excluded.expires_at_ms, status = 'active'",
            (channel_id, contact_id, issued_epoch, str(paid_ref or "") or None, int(credits or 0), ts, expires),
        )
        if sealed_under == epoch and epoch == 1 and existing is None:
            # Nothing to send: the URI *is* the key handover, and `ku` cannot carry
            # a first epoch (`isSane` refuses se == envelope.epoch).
            return self.decorate_invite(
                {
                    "ok": bool(public_uri),
                    "channel_id": channel_id,
                    "contact_id": contact_id,
                    "epoch": epoch,
                    "renewed": False,
                    "expires_at_ms": expires,
                    "delivered": False,
                    "credits_charged": 0,
                    "public_uri": public_uri,
                    "error": None if public_uri else "no_relay",
                },
                kind="channel",
                subject_id=channel_id,
                raw_uri=public_uri,
            )
        grant = await self.deliver_channel_key(
            channel_id, contact_id, sealed_under=sealed_under, issued_epoch=issued_epoch
        )
        # "This device already holds the current epoch" is a successful renewal with
        # nothing left to send, not a failure; the console must not show it as one.
        already = grant.error == "already_issued"
        # `deliver_channel_key` answers `already_issued` from an early return that
        # carries no `public_uri` (there was nothing to deliver), so the channel
        # URI resolved above is the one to report and to decorate with. Using the
        # grant's copy here would turn a successful renewal into a link-less
        # response that claims the source is unavailable.
        return self.decorate_invite(
            {
                "ok": bool(grant.delivered) or already,
                "channel_id": channel_id,
                "contact_id": contact_id,
                "epoch": epoch,
                "renewed": existing is not None,
                "expires_at_ms": expires,
                "delivered": bool(grant.delivered),
                "public_uri": grant.public_uri or public_uri,
                "credits_charged": int(grant.charged or 0),
                "error": None if already else grant.error,
            },
            kind="channel",
            subject_id=channel_id,
            raw_uri=grant.public_uri or public_uri,
        )

    def revoke_membership(self, channel_id: str, contact_id: int) -> Dict[str, Any]:
        if self.channel_state(channel_id) is None:
            raise not_found("channel_not_found", str(channel_id))
        changed = self.db.execute(
            "UPDATE channel_members SET status = 'revoked' WHERE channel_id = ? AND contact_id = ? AND status <> 'revoked'",
            (str(channel_id), int(contact_id)),
        )
        return {"ok": True, "channel_id": str(channel_id), "contact_id": int(contact_id), "revoked": int(changed or 0) > 0}

    def expire_members(self) -> int:
        """Move every past-due active membership to `expired`. Idempotent."""
        return int(
            self.db.execute(
                "UPDATE channel_members SET status = 'expired' WHERE status = 'active' AND expires_at_ms IS NOT NULL AND expires_at_ms < ?",
                (now_ms(),),
            )
            or 0
        )

    # ── articles (`::REF::<article_id>`) ────────────────────────────────────

    def article_key(self, article_id: str) -> str:
        return SETTING_ARTICLE_PREFIX + str(article_id)

    def put_article(self, article_id: str, title: str, body: str, *, url: str = "") -> Dict[str, Any]:
        """Store an article body under `settings:article:<id>`.

        The schema mandates `article_refs` (a log of who asked) but no
        article table, so the body goes in the key/value table the schema does
        provide. That is a storage decision, not a protocol one: the wire
        behaviour — `::REF::<id>` in, one signed H5 link out — is unchanged.
        """
        text = str(article_id).strip()
        if not re.fullmatch(r"[A-Za-z0-9_.:-]{1,64}", text):
            raise bad_request("article_id_invalid")
        payload = {
            "article_id": text,
            "title": str(title or "")[:120],
            "body": str(body or "")[:20000],
            "url": str(url or "")[:2048],
            "updated_at_ms": now_ms(),
        }
        self.db.set_setting(self.article_key(text), payload)
        return payload

    def get_article(self, article_id: str) -> Optional[Dict[str, Any]]:
        value = self.db.get_setting(self.article_key(article_id))
        if isinstance(value, Mapping):
            return dict(value)
        decoded = json_loads_or(value, None)
        return decoded if isinstance(decoded, Mapping) else None

    def articles(self) -> List[Dict[str, Any]]:
        rows = self.db.query("SELECT key FROM settings WHERE key LIKE ? ESCAPE '\\' ORDER BY key", (like_prefix(SETTING_ARTICLE_PREFIX),))
        out: List[Dict[str, Any]] = []
        for row in rows:
            article = self.get_article(str(row_dict(row).get("key", "")).replace(SETTING_ARTICLE_PREFIX, "", 1))
            if article:
                out.append(
                    {
                        "article_id": article.get("article_id"),
                        "title": article.get("title"),
                        "updated_at_ms": article.get("updated_at_ms"),
                    }
                )
        return out

    async def send_article(self, contact_id: int, article_id: str) -> CardDelivery:
        """Answer a `::REF::` with a `receipt` card whose button opens the H5 page.

        A card rather than a bare URL: the signed link contains the follower's
        pairwise uid, and the client only hands a signed URL to
        `PopopxH5Launcher` from a card/menu action — a pasted link in prose is a
        thing the user has to copy by hand.
        """
        article = self.get_article(article_id)
        if article is None:
            raise not_found("article_not_found", str(article_id))
        self.db.execute(
            "INSERT INTO article_refs (article_id, contact_id, ts_ms) VALUES (?, ?, ?)",
            (str(article_id), int(contact_id), now_ms()),
        )
        session = self.session_for(contact_id) or self.ensure_session(int(contact_id))
        path = "/h5/%s" % str(article_id)
        url = self.h5_url(session, path)
        card_id = new_id("art")
        fields = [{"k": "文章", "v": str(article.get("title") or article_id)}]
        card = build_card(
            card_id,
            str(article.get("title") or "内容"),
            style="receipt",
            body=str(article.get("body") or "")[: EcoLimits.card_body_chars] or None,
            fields=fields,
            actions=[
                {
                    "action_id": "read",
                    "title": "阅读全文",
                    "kind": "open_url",
                    "style": "primary",
                    "url": url,
                }
            ],
            updated_at_ms=now_ms(),
        )
        return await self.deliver_card(card, int(contact_id), topic="article:%s" % article_id)

    # ── H5 authentication ───────────────────────────────────────────────────

    def public_url(self, path: str) -> str:
        """An absolute, **unsigned** URL on this gateway's origin."""
        return self.public_base + "/" + str(path or "").lstrip("/")

    def h5_url(self, session: EcoSession, path: str) -> str:
        """The signed H5 URL for one session.

        The signature covers `uid=<pairwise>&ts=<seconds>` and nothing else —
        specifically not the path (`PopopxH5Launcher`, mirrored at
        `crypto_service.h5_preimage`) — so this function cannot be used to
        authorise two different pages with one signature *or* to protect a path
        from tampering. A merchant who needs per-page authorisation must check the
        page's own entitlement after `verifyH5Auth` returns.
        """
        return sign_h5_url(self.public_url(path), session.pairwise_uid, session.secret_hex)

    def h5_url_for_contact(self, contact_id: int, path: str) -> str:
        """`h5_url` by contact id, for the console and for a plugin's webhook body.

        Raises rather than returning "" when the follower has no session: a signed
        URL is the whole payload of an H5 entry point, and an empty string in a
        card action would be rejected by `validate_http_url` at build time anyway —
        later, and with a less useful message.
        """
        session = self.session_for(int(contact_id))
        if session is None or not session.usable:
            raise conflict("no_session", "contact %d has no usable session; deliver a handshake first" % int(contact_id))
        return self.h5_url(session, path)

    def h5_params_from_url(self, url: str) -> Tuple[str, str, str]:
        """`(uid, ts, sig)` pulled back out of a signed URL (used by the console)."""
        query = url.partition("?")[2]
        pairs = dict(pair.split("=", 1) for pair in query.split("&") if "=" in pair)
        return h5_query_params(pairs)

    def verify_h5_request(self, uid: Any, timestamp: Any, signature: Any) -> Dict[str, Any]:
        """`POST /api/v1/verifyH5Auth` — the shared-secret check for an H5 page.

        Looks the session up *by uid* rather than by contact: the whole point of
        the pairwise uid is that the merchant's H5 origin knows nothing else about
        the follower. `verify_h5_auth` returns a `(bool, reason)` pair instead of
        raising, because a page that gets `{"valid": false, "reason":
        "expired"}` can show the right message while a 500 can show nothing.

        A revoked session is refused here and *not* treated as "no such uid": the
        difference matters to the operator debugging why one phone stopped working,
        and it cannot be forged by an attacker because the reason string names no
        secret.
        """
        row = self.db.query_one(
            "SELECT pairwise_uid, contact_id, service_id, secret_hex, revoked FROM eco_sessions WHERE pairwise_uid = ?",
            (str(uid or ""),),
        )
        if row is None:
            return {"ok": True, "valid": False, "reason": "unknown_uid"}
        session = self._session_from_row(row)
        if session.revoked:
            return {"ok": True, "valid": False, "reason": "revoked", "contact_id": session.contact_id}
        valid, reason = verify_h5_auth(uid, timestamp, signature, session.secret_hex)
        body: Dict[str, Any] = {
            "ok": True,
            "valid": bool(valid),
            "reason": reason,
            "service_id": session.service_id,
        }
        if valid:
            body["contact_id"] = session.contact_id
            body["pairwise_uid"] = session.pairwise_uid
            try:
                body["ts_seconds"] = int(str(timestamp).strip())
            except (TypeError, ValueError):
                body["ts_seconds"] = 0
        return body


# ─────────────────────────────────────────────────────────────────────────────
# 4. Inbound routing
#
#    One message, one owner. The rules below are the whole reason a `::CB::`
#    cannot be answered twice: a payload prefix belongs either to the gateway or
#    to exactly one plugin's `handle_inbound`, and the first plugin that claims a
#    message ends the loop.
# ─────────────────────────────────────────────────────────────────────────────


@dataclass
class MountedPlugin:
    """One plugin as the gateway sees it after import.

    `available` is False when the module could not be imported or its router could
    not be built. The gateway still boots in that case — see :meth:`Gateway.mount_plugins`
    for why a broken optional plugin must not take the card path down with it.
    """

    spec: Any
    module: Any = None
    deps: Optional[PluginDeps] = None
    router: Any = None
    available: bool = False
    error: str = ""

    def as_dict(self) -> Dict[str, Any]:
        return {
            "plugin_id": self.spec.plugin_id,
            "url_prefix": self.spec.url_prefix,
            "meter": self.spec.meter,
            "callback_kinds": list(self.spec.callback_kinds),
            "available": self.available,
            "error": self.error or None,
        }


class InboundRouter:
    """Turns one inbound chat message into at most one protocol action.

    Every branch records a `callbacks` row *before* dispatching, with a
    `dedupe_key` unique on (contact, item). The node delivers a message at least
    once across a reconnect, and a duplicate `poll:vote:` or `alert:ack:` is not a
    cosmetic problem — it is a second charge and a second state transition. The
    row is written first precisely so that a crash mid-handler shows up as a
    callback that was seen and not completed, which an operator can read, rather
    than as a message that never arrived.
    """

    def __init__(self, config: Config, db: Database, billing: BillingService, eco: EcoService, plugins: Dict[str, MountedPlugin]) -> None:
        self.config = config
        self.db = db
        self.billing = billing
        self.eco = eco
        self.plugins = plugins
        self.stop_event: Optional[asyncio.Event] = None

    # ── the seam the bridge calls ───────────────────────────────────────────

    async def on_message(self, message: InboundMessage) -> None:
        """Entry point for `AgentBridge(on_message=...)`. Never raises.

        An exception escaping here would kill the bridge's reader task, and a dead
        reader looks exactly like a silent follower from the outside. Anything the
        handlers cannot do is recorded against the callback row instead.
        """
        callback = getattr(message, "callback", None)
        if callback is None:
            return
        if not getattr(message, "received", True):
            # The node echoes our own outbound frames back as `snd` items. Routing
            # them would mean answering ourselves: a `::CB::` we sent would be
            # treated as a follower's tap.
            return
        contact_id = int(getattr(message, "contact_id", 0) or 0)
        if contact_id <= 0:
            self._drop(message, "no_contact")
            return
        row_id = self._record(message)
        if row_id is None:
            return
        try:
            handler = getattr(self, "_kind_" + str(callback.kind), None)
            if handler is None:
                self._update(row_id, "ignored", handler=None, error="unknown_kind")
                return
            outcome = await handler(message, callback)
            self._update(row_id, outcome[0], handler=outcome[1], error=outcome[2])
            self._observe_workflow(message, outcome[0])
        except Exception as exc:  # noqa: BLE001 — a handler bug must not cost the reader task
            LOG.exception("inbound handler failed for contact %d", contact_id)
            self._update(row_id, "error", handler=None, error="%s: %s" % (type(exc).__name__, exc))

    def _observe_workflow(self, message: InboundMessage, outcome: str) -> None:
        """Fan a follower's message out to the workflow bridge, after it was routed.

        Deliberately after the gateway/plugin handlers and outside their return
        value: a Node-RED receiver being down must not turn a poll vote or an
        alert acknowledge into an error the follower sees. The module owns its
        own failure logging and audit rows.
        """
        mounted = self.plugins.get("workflow_webhook")
        if mounted is None or not mounted.available or mounted.deps is None:
            return
        observer = getattr(mounted.module, "observe_inbound", None)
        if observer is not None:
            observer(mounted.deps, message, outcome)

    async def on_event(self, tag: str, body: Mapping[str, Any]) -> None:
        """Node events: only a contact request can usefully be acted on.

        `msgReceived`/`msgSent` are already covered by `on_message` (the bridge
        parses the chat items), so anything else arriving here is logged and
        dropped: a gateway that tries to interpret every event the node invents
        breaks the first time the node adds one.

        This is not the only way a follower arrives, and must not be treated as one:
        the node sends `receivedContactRequest` *only when its own auto-accept is
        off* (bots/api/EVENTS.md:138-142), so a deployment on a node that accepts
        for us sees no event and still has to hand out sessions — which is what
        `POST /api/v1/contacts/sync` (`sync_contacts`) and the first inbound message
        are for.
        """
        if tag != "contact_request":
            LOG.debug("ignored node event %s", tag)
            return
        request = extract_contact_request(body) or {}
        request_id = int(request.get("contact_request_id") or request.get("contactRequestId") or 0)
        if request_id <= 0:
            LOG.warning("contact request without an id: %r", dict(body or {}))
            return
        display = str(request.get("display_name") or request.get("displayName") or "")
        if not self.auto_accept():
            LOG.info("contact request %d (%s) left for the console", request_id, display)
            return
        await self.accept_contact(request_id, display)

    async def on_state(self, up: bool, detail: str) -> None:
        LOG.info("node link %s (%s)", "up" if up else "down", detail)
        if up:
            # A reconnect is the moment a backlog exists, so the worker is nudged
            # rather than left to its own interval: a queued welcome card that
            # arrives two seconds late is fine, one that arrives 60 seconds late
            # after the follower has already typed is not.
            asyncio.ensure_future(self.eco.drain_outbox())

    # ── contact lifecycle ───────────────────────────────────────────────────

    def auto_accept(self) -> bool:
        stored = self.db.get_setting(SETTING_AUTO_ACCEPT)
        if stored is None:
            return True
        return bool(stored)

    async def accept_contact(self, contact_request_id: int, display_name: str = "") -> Dict[str, Any]:
        """Accept a request, then perform the handshake it makes possible.

        The order is forced by the protocol: `session_handshake` is a message to a
        contact, and there is no contact until the request is accepted. Doing it
        the other way round is the classic "the service account answered nothing
        for the first day" bug.
        """
        contact_id = 0
        try:
            resp = await self.eco.bridge.accept_contact(int(contact_request_id))
        except NodeCommandError as exc:
            # The node answered this and said no — a request that has already been
            # accepted, or an id that was never there (`contactRequestNotFound`,
            # measured live). The auto-accept path runs inside the inbound handler,
            # so it reports rather than raises; `node_error` is what makes the two
            # kinds of failure distinguishable without reading a serialised frame.
            LOG.warning("accept_contact(%d) refused: %s", contact_request_id, exc)
            return {"ok": False, "error": "node_refused", "node_error": error_reason(exc.chat_error),
                    "detail": str(exc)}
        except (NodeError, OSError) as exc:
            LOG.warning("accept_contact(%d) failed: %s", contact_request_id, exc)
            return {"ok": False, "error": "node_unreachable", "detail": str(exc)}
        contact_id = _contact_id_from_response(resp)
        if contact_id <= 0:
            return {"ok": True, "contact_id": 0, "warning": "node accepted the request without naming a contact"}
        self.eco.touch_contact(contact_id, display_name)
        handshake = await self.eco.handshake(contact_id)
        welcome = self.db.get_setting(SETTING_WELCOME_TEXT) or ""
        if welcome:
            await self.eco.send_frame(contact_id, str(welcome))
        return {"ok": True, "contact_id": contact_id, "handshake": handshake}

    async def sync_contacts(self) -> Dict[str, Any]:
        """Pull the node's contact list into `contacts` and hand out missing sessions.

        A gateway deployed beside a service account that already has followers has
        to be able to serve them without waiting for each one to send a message,
        and a follower who never gets a handshake gets no H5 page and no channel.
        """
        try:
            contacts = await self.eco.bridge.list_contacts()
        except (NodeError, OSError) as exc:
            raise unavailable("node_unreachable", str(exc)) from exc
        created, updated = 0, 0
        for item in contacts or []:
            data = item if isinstance(item, Mapping) else {}
            contact_id = _contact_id_from_response(data)
            if contact_id <= 0:
                continue
            name = str(data.get("display_name") or data.get("displayName") or data.get("local_display_name") or "")
            existed = self.db.query_one("SELECT contact_id FROM contacts WHERE contact_id = ?", (contact_id,)) is not None
            self.eco.touch_contact(contact_id, name)
            updated += 1 if existed else 0
            created += 0 if existed else 1
            if self.eco.session_for(contact_id) is None:
                await self.eco.handshake(contact_id)
        return {"ok": True, "seen": updated + created, "new": created, "updated": updated}

    # ── kind handlers ───────────────────────────────────────────────────────

    async def _kind_text(self, message: InboundMessage, callback: Any) -> Tuple[str, Optional[str], Optional[str]]:
        """Plain text, in the order that cannot double-answer it.

        1. a menu keyword, because the merchant configured it deliberately and an
           AI answer to a configured command is a regression the follower sees;
        2. an alert resolve keyword, which is an operator's message, not a
           customer's (`alert_ops_plugin.py:1755-1764` documents this exact hook);
        3. the plugins that own `callback_kinds=("text",)` — the AI agent, last, so
           that it is the fallback rather than the first thing to grab a sentence.
        """
        text = str(getattr(message, "text", "") or "").strip()
        if not text:
            return ("ignored", None, "empty_text")
        item = self.eco.menu_reply_for(text)
        if item is not None:
            handled = await self._run_menu_item(message.contact_id, item)
            return ("handled", "menu", None if handled else "menu_action_failed")
        alert = self.plugins.get("alert_ops")
        if alert is not None and alert.available and alert.deps is not None:
            resolver = getattr(alert.module, "resolve_by_keyword", None)
            if resolver is not None:
                outcome = await resolver(alert.deps, int(message.contact_id), text)
                if outcome:
                    return ("handled", "alert_ops:keyword", None)
        for spec in PLUGIN_SPEC:
            if KIND_TEXT not in spec.callback_kinds:
                continue
            plugin = self.plugins.get(spec.plugin_id)
            if plugin is None or not plugin.available or plugin.deps is None:
                continue
            if await plugin.module.handle_inbound(plugin.deps, message):
                return ("handled", spec.plugin_id, None)
        return ("unmatched", None, None)

    async def _kind_card_callback(self, message: InboundMessage, callback: Any) -> Tuple[str, Optional[str], Optional[str]]:
        payload = str(getattr(callback, "payload", "") or "")
        contact_id = int(message.contact_id)
        if payload.startswith(PAYLOAD_CHANNEL_SUBSCRIBE):
            channel_id = payload[len(PAYLOAD_CHANNEL_SUBSCRIBE):]
            if not channel_id or ":" in channel_id:
                return ("ignored", "gateway", "channel_id_invalid")
            await self.eco.grant_membership(channel_id, contact_id, paid_ref="callback")
            return ("handled", "gateway:channel_subscribe", None)
        if payload.startswith(PAYLOAD_MENU_OPEN):
            path = payload[len(PAYLOAD_MENU_OPEN):]
            await self._send_signed_h5(contact_id, path)
            return ("handled", "gateway:menu_open", None)
        for spec in PLUGIN_SPEC:
            if KIND_CARD_CALLBACK not in spec.callback_kinds:
                continue
            plugin = self.plugins.get(spec.plugin_id)
            if plugin is None or not plugin.available or plugin.deps is None:
                continue
            if await plugin.module.handle_inbound(plugin.deps, message):
                return ("handled", spec.plugin_id, None)
        return ("unmatched", None, "no_handler_for_payload")

    async def _kind_card_paid(self, message: InboundMessage, callback: Any) -> Tuple[str, Optional[str], Optional[str]]:
        """A `pay_credits` receipt: settle the button, then deliver what it bought.

        `paid_ref` is the client's `txHash` — an opaque string this gateway records
        and never interprets. The card is settled (buttons retired) whether or not
        the purchase can be delivered, because a follower who has paid and can tap
        the button again has been given a reason to contact support twice.
        """
        contact_id = int(message.contact_id)
        payload = str(getattr(callback, "payload", "") or "")
        paid_ref = str(getattr(callback, "paid_ref", "") or "")
        row = self.eco.pending_paid_action(contact_id, payload)
        if row is None:
            return ("unmatched", None, "no_pending_action")
        self.eco.settle_paid_action(row, paid_ref=paid_ref)
        try:
            await self.eco.settle_card(str(row.get("card_id") or ""), contact_id)
        except GatewayError as exc:
            LOG.warning("card %s could not be settled after payment: %s", row.get("card_id"), exc)
        detail: Optional[str] = None
        if payload.startswith(PAYLOAD_CHANNEL_SUBSCRIBE):
            channel_id = payload[len(PAYLOAD_CHANNEL_SUBSCRIBE):]
            if channel_id and ":" not in channel_id:
                await self.eco.grant_membership(
                    channel_id, contact_id, credits=int(row.get("amount") or 0), paid_ref=paid_ref
                )
                detail = "granted:%s" % channel_id
        return ("handled", "gateway:card_paid", detail)

    async def _kind_rotate_request(self, message: InboundMessage, callback: Any) -> Tuple[str, Optional[str], Optional[str]]:
        channel_id = str(getattr(callback, "channel_id", "") or "")
        if not channel_id:
            return ("ignored", "gateway", "channel_id_missing")
        grant = await self.eco.deliver_channel_key(channel_id, int(message.contact_id))
        if grant.delivered or grant.error == "node_unreachable":
            return ("handled", "gateway:rotate", None)
        return ("ignored", "gateway:rotate", grant.error)

    async def _kind_article_ref(self, message: InboundMessage, callback: Any) -> Tuple[str, Optional[str], Optional[str]]:
        article_id = str(getattr(callback, "payload", "") or "")
        if not article_id:
            return ("ignored", "gateway", "article_id_missing")
        if self.eco.get_article(article_id) is None:
            return ("ignored", "gateway", "article_not_found")
        await self.eco.send_article(int(message.contact_id), article_id)
        return ("handled", "gateway:article", None)

    async def _kind_sso_scan(self, message: InboundMessage, callback: Any) -> Tuple[str, Optional[str], Optional[str]]:
        plugin = self.plugins.get("privacy_sso")
        if plugin is None or not plugin.available or plugin.deps is None:
            return ("ignored", None, "sso_disabled")
        if await plugin.module.handle_inbound(plugin.deps, message):
            return ("handled", "privacy_sso", None)
        return ("unmatched", None, "sso_not_claimed")

    async def _kind_system(self, message: InboundMessage, callback: Any) -> Tuple[str, Optional[str], Optional[str]]:
        """`::popopx_sys::` — the web3 bridge first, then the gateway's own grant.

        The bridge claims a receipt for a channel it watches in order to write its
        audit trail (`web3_bridge_plugin.py:2881-2905`), and explicitly does *not*
        grant membership or call `deliver_channel_key`. Both of those belong here,
        which is why the plugin's claim is not the end of the branch: a receipt the
        bridge has touched still has to buy the follower their key.
        """
        contact_id = int(message.contact_id)
        sys_kind = str(getattr(callback, "sys_kind", "") or "")
        if not getattr(callback, "known_system_kind", False):
            return ("ignored", None, "unknown_system_kind")
        claimed = False
        for spec in PLUGIN_SPEC:
            if KIND_SYSTEM not in spec.callback_kinds:
                continue
            plugin = self.plugins.get(spec.plugin_id)
            if plugin is None or not plugin.available or plugin.deps is None:
                continue
            try:
                claimed = bool(await plugin.module.handle_inbound(plugin.deps, message)) or claimed
            except Exception:  # noqa: BLE001 — the grant below must survive a broken watcher
                LOG.exception("system handler in %s failed", spec.plugin_id)
        if not getattr(callback, "is_payment_receipt", False):
            return ("handled" if claimed else "ignored", "gateway:system", sys_kind)
        channel_id = str(getattr(callback, "channel_id", "") or "")
        if not channel_id or self.eco.channel_state(channel_id) is None:
            return ("handled" if claimed else "ignored", "gateway:system", "channel_unknown")
        await self.eco.grant_membership(
            channel_id,
            contact_id,
            credits=int(getattr(callback, "credits", 0) or 0),
            paid_ref=str(getattr(callback, "tx_hash", "") or "") or "system",
        )
        return ("handled", "gateway:channel_paid", None)

    # ── menu items ──────────────────────────────────────────────────────────

    async def _run_menu_item(self, contact_id: int, item: Mapping[str, Any]) -> bool:
        """Act on a menu leaf the follower typed the title of.

        The four kinds are handled exactly as the phone handles a tap, so that a
        follower who cannot find the menu (an older build, a reinstalled phone) gets
        the same result by typing. `open_channel` deliberately does *not* grant
        membership: on the client that kind opens a URI the follower already owns,
        and membership is bought with a `pay_credits` *card* button
        (the brief's rule is 卡片按钮点击与算力点解锁付费频道), so silently granting it here would hand out a paid
        channel to anyone who could guess its title.
        """
        kind = str(item.get("action") or "")
        payload = str(item.get("payload") or "")
        url = str(item.get("url") or "")
        title = str(item.get("title") or "菜单")
        if kind == "send_cmd":
            return await self.eco.send_frame(contact_id, payload) if payload else False
        if kind == "callback":
            if not payload:
                return False
            synthetic = InboundCallback(kind=KIND_CARD_CALLBACK, raw="::CB::" + payload, payload=payload)
            message = InboundMessage(
                contact_id=int(contact_id),
                display_name="",
                item_id=0,
                text="::CB::" + payload,
                callback=synthetic,
                direction="rcv",
            )
            outcome, handler, _error = await self._kind_card_callback(message, synthetic)
            LOG.debug("menu keyword routed to %s: %s", handler, outcome)
            return outcome == "handled"
        if kind == "open_url":
            return await self._send_link(contact_id, title, url) if url else False
        if kind == "open_channel":
            channel_id = payload
            if not channel_id:
                return False
            uri = self.eco.channel_public_uri(channel_id)
            if not uri:
                return False
            card = build_card(
                new_id("chn"),
                title[: EcoLimits.card_title_chars],
                style="standard",
                actions=[{"action_id": "open", "title": "进入频道", "kind": "open_channel", "payload": uri}],
                updated_at_ms=now_ms(),
            )
            result = await self.eco.deliver_card(card, contact_id, topic="channel:%s" % channel_id)
            return bool(result.sent or result.queued)
        return False

    async def _send_signed_h5(self, contact_id: int, path: str) -> bool:
        return await self._send_link(contact_id, "页面", self.eco.public_url(path))

    async def _send_link(self, contact_id: int, title: str, url: str) -> bool:
        """Send one link as a card with a single `open_url` button.

        The URL is signed here when the caller has a session: `validate_http_url`
        would otherwise reject a relative path, and an unsigned link to an H5 page
        that expects `popopx_uid` opens a login wall instead of the page. A link
        that already carries an identity is left exactly as the merchant wrote it.
        """
        target = url if url.startswith("http") else self.eco.public_url(url)
        session = self.eco.session_for(contact_id)
        if session is not None and session.usable and "/h5/" in target:
            uid, _ts, _sig = self.eco.h5_params_from_url(target)
            if not uid:
                target = self.eco.h5_url(session, target[len(self.eco.public_base):])
        try:
            validate_http_url(target)
        except EcoError as exc:
            LOG.warning("menu link rejected by the client rule %s", exc.rule)
            return False
        card = build_card(
            new_id("lnk"),
            title[: EcoLimits.card_title_chars] or "链接",
            style="standard",
            actions=[{"action_id": "open", "title": "打开", "kind": "open_url", "url": target}],
            updated_at_ms=now_ms(),
        )
        result = await self.eco.deliver_card(card, contact_id)
        return bool(result.sent or result.queued)

    # ── bookkeeping ─────────────────────────────────────────────────────────

    def _record(self, message: InboundMessage) -> Optional[int]:
        """Insert the `callbacks` row, returning None when this is a replay."""
        callback = message.callback
        marker = str(getattr(callback, "raw", "") or "")[:24]
        dedupe = "c%d:i%d" % (int(message.contact_id), int(getattr(message, "item_id", 0) or 0))
        try:
            row_id = self.db.execute(
                "INSERT INTO callbacks (ts_ms, contact_id, kind, marker, payload, paid_ref, raw, status, handler, error, dedupe_key, meta_json)"
                " VALUES (?, ?, ?, ?, ?, ?, ?, 'received', NULL, NULL, ?, NULL)",
                (
                    now_ms(),
                    int(message.contact_id),
                    str(getattr(callback, "kind", "") or ""),
                    marker,
                    str(getattr(callback, "payload", "") or "")[: EcoLimits.payload_chars],
                    str(getattr(callback, "paid_ref", "") or "")[:128],
                    str(getattr(callback, "raw", "") or "")[:2000],
                    dedupe,
                ),
            )
        except sqlite3.IntegrityError:
            # `dedupe_key` is UNIQUE by design: the node re-delivers across a
            # reconnect, and the second copy must be *seen* and dropped rather than
            # raced against a "did we already handle this?" query.
            LOG.info("duplicate inbound from contact %d (%s), dropped", message.contact_id, dedupe)
            return None
        return int(row_id or 0) or None

    def _update(self, row_id: int, status: str, *, handler: Optional[str], error: Optional[str]) -> None:
        self.db.execute(
            "UPDATE callbacks SET status = ?, handler = ?, error = ? WHERE id = ?",
            (str(status), handler, (error or "")[:400] or None, int(row_id)),
        )

    def _drop(self, message: InboundMessage, reason: str) -> None:
        LOG.warning("dropped inbound from contact %s: %s", getattr(message, "contact_id", "?"), reason)

    def recent(self, *, limit: int = 50, kind: Optional[str] = None, status: Optional[str] = None) -> List[Dict[str, Any]]:
        sql = "SELECT * FROM callbacks"
        clauses: List[str] = []
        params: List[Any] = []
        if kind:
            clauses.append("kind = ?")
            params.append(str(kind))
        if status:
            clauses.append("status = ?")
            params.append(str(status))
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        sql += " ORDER BY id DESC LIMIT ?"
        params.append(clamp_limit(limit, 50, 500))
        return [row_dict(row) for row in self.db.query(sql, params)]


def _contact_id_from_response(payload: Any) -> int:
    """Dig a contact id out of a node response, which spells it several ways.

    `@<id>` in a command echo, `contactId` in a `newChatItems` block, and
    `contact_id` in the accepted-request summary all name the same number, and a
    handshake addressed to contact 0 is a command the node rejects with an error
    that does not mention which id it disliked.
    """
    if isinstance(payload, Mapping):
        for key in ("contact_id", "contactId", "id"):
            value = payload.get(key)
            parsed = int_or_none(value)
            if parsed and parsed > 0:
                return parsed
        for key in ("chats", "chat", "contact"):
            nested = payload.get(key)
            if isinstance(nested, Mapping):
                found = _contact_id_from_response(nested)
                if found:
                    return found
        for key in ("contacts", "chatItems", "newChatItems", "item"):
            nested = payload.get(key)
            if isinstance(nested, (list, tuple)):
                for item in nested:
                    found = _contact_id_from_response(item)
                    if found:
                        return found
        contact = payload.get("contact")
        if isinstance(contact, Mapping):
            found = _contact_id_from_response(contact)
            if found:
                return found
    elif isinstance(payload, str):
        text = payload.strip()
        if text.startswith("@"):
            return int_or_none(text[1:]) or 0
    return 0


# ─────────────────────────────────────────────────────────────────────────────
# 5. The gateway process: mount, workers, lifecycle
# ─────────────────────────────────────────────────────────────────────────────


class Gateway:
    """Owns one database, one bridge, one set of plugins, and the worker tasks.

    Deliberately independent of FastAPI: :func:`create_app` builds a `Gateway` and
    calls into it, so every behaviour here is reachable without an ASGI server —
    which on a machine with no wheels installed is not a nicety but the only way to
    exercise any of it.
    """

    def __init__(self, config: Config, *, db: Optional[Database] = None, bridge: Optional[Any] = None) -> None:
        self.config = config
        self.db = db if db is not None else Database(Path(config.db_path))
        self.billing = BillingService(self.db, config, voucher_verifier=voucher_verifier_for(config))
        self.bridge = bridge if bridge is not None else AgentBridge(
            config.node.ws_url,
            service_display_name=config.service_name,
            service_full_name=config.service_full_name,
            command_timeout=config.node.command_timeout_seconds,
            reconnect_seconds=config.node.reconnect_seconds,
            service_requests=config.node.service_requests,
            send_files=config.node.send_files,
        )
        self.eco = EcoService(config, self.db, self.billing, self.bridge)
        self.gate = PluginGate(config, self.billing, self.eco.bridge_connected)
        self.plugins: Dict[str, MountedPlugin] = {}
        self.router = InboundRouter(config, self.db, self.billing, self.eco, self.plugins)
        # Zero-retention task bodies live here and nowhere else: a dict of
        # bytearrays owned by this process, wiped on delivery *and* on every
        # failure path. The temp area is only allocated when a task names an
        # attachment, so a gateway whose callers never use one touches no disk.
        self.data_lifecycle_broker = lifecycle_engine.ZeroRetentionBroker()
        self.data_lifecycle_temp = lifecycle_cleanup.TempArea()
        # The bridge takes its callbacks as constructor arguments, and its handler
        # slots are private for exactly that reason; assigning them here is the one
        # place in the suite that reaches past the constructor, and it is what keeps
        # `AgentBridge` from having to know that a gateway, a router and a billing
        # engine exist.
        self.bridge._on_message = self.router.on_message
        self.bridge._on_event = self.router.on_event
        self.bridge._on_state = self.router.on_state
        # Created by :meth:`start`, inside the loop: on Python 3.9 `asyncio.Event()`
        # binds the current event loop at construction and raises when there is none,
        # which is exactly the state a gateway object is in between `create_app` and
        # the server's startup hook.
        self.stop_event: Optional[asyncio.Event] = None
        self._tasks: List[Any] = []
        self.mounted_at_ms = 0

    # ── plugins ─────────────────────────────────────────────────────────────

    def mount_plugins(self) -> Dict[str, MountedPlugin]:
        """Import, gate-check and build the router for every plugin in the table.

        A plugin that cannot be imported leaves the gateway *running* with that one
        route prefix absent. The alternative — refuse to boot — means a broken
        optional plugin takes the handshake, the menu and every existing card down
        with it, which turns a bad deploy of one feature into an outage of the whole
        service account. The failure is recorded and surfaced by
        `GET /api/v1/plugins`, so it cannot hide.

        The dict is mutated in place because :class:`InboundRouter` holds a
        reference to it, not a copy.
        """
        import importlib

        for spec in PLUGIN_SPEC:
            mounted = MountedPlugin(spec=spec)
            self.plugins[spec.plugin_id] = mounted
            if not bool(getattr(self.config.plugins, spec.toggle, False)):
                mounted.error = "disabled"
                continue
            try:
                module = importlib.import_module(spec.module_name)
                deps = PluginDeps(
                    config=self.config,
                    db=self.db,
                    billing=self.billing,
                    eco=self.eco,
                    gate=self.gate,
                    spec=spec,
                )
                router = module.create_router(deps)
            except ModuleNotFoundError as exc:
                # The usual cause on a fresh checkout is that FastAPI itself is not
                # installed yet, which is a deployment step and not a plugin bug.
                mounted.error = "import failed: %s" % exc
                LOG.warning("plugin %s not mounted (%s)", spec.plugin_id, mounted.error)
            except Exception as exc:  # noqa: BLE001 — see the docstring: never abort boot
                mounted.error = "%s: %s" % (type(exc).__name__, exc)
                LOG.exception("plugin %s failed to mount", spec.plugin_id)
            else:
                mounted.module = module
                mounted.deps = deps
                mounted.router = router
                mounted.available = True
        self.mounted_at_ms = now_ms()
        return self.plugins

    def voucher_payload(self, code: str) -> Dict[str, Any]:
        """What a `POPX-CP` code promises, verified offline and *not* redeemed.

        The code itself is deliberately absent from the result: it is a bearer
        value until it is spent, and an admin endpoint that echoes it back into a
        console log or a support screenshot would hand anyone who sees the screen a
        redeemable code.
        """
        payload = voucher_verifier_for(self.config)(code)
        return {
            "voucher_id": str(payload.voucher_id),
            "plan": str(payload.plan),
            "credits": int(payload.credits),
            "issued_at_ms": int(payload.issued_at_ms),
            "expires_at_ms": int(payload.expires_at_ms) if payload.expires_at_ms is not None else None,
            "issuer_key_id": str(payload.issuer_key_id),
            "expired": bool(payload.is_expired()),
        }

    def plugin_status(self) -> List[Dict[str, Any]]:
        """The mount table plus the live gate decision for each plugin."""
        out: List[Dict[str, Any]] = []
        for spec in PLUGIN_SPEC:
            mounted = self.plugins.get(spec.plugin_id)
            data = mounted.as_dict() if mounted is not None else {
                "plugin_id": spec.plugin_id,
                "url_prefix": spec.url_prefix,
                "meter": spec.meter,
                "callback_kinds": list(spec.callback_kinds),
                "available": False,
                "error": "not mounted",
            }
            data["gate"] = self.gate.status(spec.plugin_id).as_body()
            out.append(data)
        return out

    # ── lifecycle ───────────────────────────────────────────────────────────

    async def start(self, *, connect_node: bool = True) -> None:
        """Bring the node link up and start the workers.

        `connect_node=False` is for a console-only deployment (an operator editing a
        menu before the node is provisioned) and for :func:`self_test`. The bridge's
        own supervisor retries forever, so a node that is merely not running yet
        does not stop the gateway from accepting work into the outbox.
        """
        await self.async_boot()
        if connect_node:
            await self.bridge.start()
        self.stop_event = asyncio.Event()
        self.router.stop_event = self.stop_event
        self._tasks.append(asyncio.ensure_future(self._outbox_loop()))
        self._tasks.append(asyncio.ensure_future(self._expiry_loop()))
        for mounted in self.plugins.values():
            if mounted.available and hasattr(mounted.module, "poll_loop"):
                # The web3 bridge and the workflow webhook declare a `poll_loop`, and the
                # name-based hook is what keeps this file from importing a plugin's
                # internals: a plugin that needs no poller is not obliged to have one.
                self._tasks.append(asyncio.ensure_future(mounted.module.poll_loop(mounted.deps, self.stop_event)))

    async def async_boot(self) -> None:
        """Anything that must happen once, in-loop, before traffic.

        The service identity row is written here rather than at import time because
        the contact address is minted by the node: a gateway that restarts after
        having paired must reuse the same address, or every existing follower's
        session points at a stranger.
        """
        ts = now_ms()
        if self.db.query_one("SELECT id FROM service_identity WHERE id = 1") is None:
            self.db.execute(
                "INSERT INTO service_identity (id, node_user_id, address, service_id, display_name, full_name,"
                " auto_accept, created_at_ms, updated_at_ms) VALUES (1, NULL, NULL, ?, ?, ?, 1, ?, ?)",
                (self.config.service_id, self.config.service_name, self.config.service_full_name, ts, ts),
            )
        user_id = int(getattr(self.bridge, "user_id", 0) or 0)
        address = str(getattr(self.bridge, "contact_address", "") or "")
        if user_id or address:
            self.db.execute(
                "UPDATE service_identity SET node_user_id = COALESCE(?, node_user_id), address = COALESCE(?, address),"
                " updated_at_ms = ? WHERE id = 1",
                (user_id or None, address or None, now_ms()),
            )

    async def stop(self) -> None:
        if self.stop_event is not None:
            self.stop_event.set()
        for task in self._tasks:
            task.cancel()
        for task in self._tasks:
            try:
                await task
            except asyncio.CancelledError:
                continue
            except Exception:  # noqa: BLE001 — shutdown is best-effort
                LOG.debug("worker raised during shutdown", exc_info=True)
        self._tasks = []
        try:
            await self.bridge.stop()
        except Exception:  # noqa: BLE001
            LOG.debug("bridge stop raised", exc_info=True)
        self.db.close_all()

    async def _outbox_loop(self) -> None:
        """Drain queued frames until told to stop.

        The sleep is interruptible by `stop_event`, so a restart does not wait out
        the interval, and a busy queue is drained at `eco.outbox_interval` instead of
        at a fixed cadence.
        """
        while not self.stop_event.is_set():
            idle = True
            try:
                tally = await self.eco.drain_outbox()
                idle = not (tally.get("sent") or tally.get("failed"))
            except Exception:  # noqa: BLE001 — a worker that raises dies, and a dead worker is invisible
                LOG.exception("outbox worker failed")
            delay = self.eco.outbox_interval if not idle else max(self.eco.outbox_interval, OUTBOX_INTERVAL_SECONDS)
            try:
                await asyncio.wait_for(self.stop_event.wait(), timeout=delay)
            except asyncio.TimeoutError:
                continue

    async def _expiry_loop(self) -> None:
        """Hourly housekeeping: memberships that ran out, and nothing else.

        Separate from the outbox loop because a slow plugin poller must not be able
        to delay an expiry that is already overdue.
        """
        while not self.stop_event.is_set():
            try:
                expired = self.eco.expire_members()
                if expired:
                    LOG.info("expired %d channel membership(s)", expired)
            except Exception:  # noqa: BLE001
                LOG.exception("expiry worker failed")
            try:
                await asyncio.wait_for(self.stop_event.wait(), timeout=3600.0)
            except asyncio.TimeoutError:
                continue

    # ── status ──────────────────────────────────────────────────────────────

    def status(self) -> Dict[str, Any]:
        from app import __version__

        contact_address = str(getattr(self.bridge, "contact_address", "") or "")
        service = {
            "service_id": self.config.service_id,
            "display_name": self.config.service_name,
            "public_base_url": self.eco.public_base,
            # Raw protocol URI: kept for the diagnostic fold and for anything
            # that imports it; `contact_link` is the field to share.
            "contact_address": contact_address,
        }
        self.eco.decorate_invite(
            service,
            kind="service_account",
            subject_id=self.eco.service_id,
            raw_uri=contact_address,
            field="contact_link",
        )
        return {
            "ok": True,
            "version": __version__,
            "service": service,
            "node": self.bridge.state(),
            "billing": self.billing.account().to_dict(),
            "outbox": self.eco.outbox_stats(),
            "counts": self.db.table_sizes(),
            "plugins": self.plugin_status(),
        }


def voucher_verifier_for(config: Config) -> Callable[[str], Any]:
    """The closure `BillingService` uses to check a `POPX-CP` code.

    Verification is *offline* and uses only the public half of the issuer key: the
    private key never exists on a gateway host (it stays with `official_tools/`, see
    the runbook), so a compromised gateway cannot mint a voucher — it can only
    reject one. `crypto_service.verify_voucher_code` raises `EcoError` for a bad
    code, and `BillingService.redeem_voucher` turns that into the refusal the
    console shows.

    `Voucher` and `billing.VoucherPayload` are separate dataclasses with identical
    field names on purpose (`billing_service.py` documents why: the ledger must not
    depend on a verifier implementation), so no adapter is needed here and none is
    written.
    """
    public_key = config.billing.official_ed25519_public_key

    def verify(code: str) -> Any:
        return verify_voucher_code(code, public_key)

    return verify


# ─────────────────────────────────────────────────────────────────────────────
# 6. The HTTP surface
#
#    FastAPI is imported inside this function on purpose: every other section of
#    this module — and therefore every rule about frames, meters, epochs and the
#    outbox — must be importable and testable on a machine where the wheels are not
#    installed yet. `install_ubuntu22.sh` and `start_macos.sh` are what put the
#    wheels there.
# ─────────────────────────────────────────────────────────────────────────────

#: Plugin paths that must NOT require the admin token, because their caller is not
#: the operator. `/webhook` authenticates with its own per-source token
#: (`alert_ops_plugin.py:authorize_webhook_token`); `/verify` is called by a
#: relying party's back channel, which has no admin credential and must not have one.
PUBLIC_PLUGIN_SUFFIXES = ("/webhook", "/verify", "/callback")

#: Method-and-path exemptions for callers that carry no admin credential and cannot be
#: named by a suffix, because the path has an id in it. The one entry is the QR page's
#: poll: `privacy_sso_plugin.py:1856-1864` answers state-only for a browser that has no
#: bearer secret, and that is the whole point of showing a QR — but a suffix list cannot
#: express `/sessions/{session_id}`, and `POST /sessions/{id}/cancel` shares its prefix,
#: so the exemption is spelled as a verb plus a route template and matched exactly.
#: The route the exemption exists for, and one concrete call of it. Both are shared with
#: the self-test controls, so a typo in either half cannot quietly make a check agree
#: with a table it is supposed to be auditing.
POLL_TEMPLATE = "/api/v1/plugins/sso/sessions/{session_id}"
POLL_PATH = "/api/v1/plugins/sso/sessions/abc123"
PUBLIC_PLUGIN_ROUTES: Tuple[Tuple[str, str], ...] = (
    ("GET", POLL_TEMPLATE),
)


def _template_to_regex(template: str) -> str:
    """A mounted route's template as a pattern: each `{param}` is one path segment.

    Written out rather than fed through `re.escape` + a substitution, because whether
    `re.escape` escapes a brace depends on the interpreter (it stopped escaping them in
    3.7), and a pattern that silently matches nothing is an auth rule that silently
    denies everything.
    """
    parts: List[str] = []
    index = 0
    while index < len(template):
        opening = template.find("{", index)
        if opening < 0:
            parts.append(re.escape(template[index:]))
            break
        closing = template.find("}", opening)
        if closing < 0:
            parts.append(re.escape(template[index:]))
            break
        parts.append(re.escape(template[index:opening]))
        parts.append("[^/]+")
        index = closing + 1
    return "".join(parts)


def matches_public_route_template(
    table: Sequence[Tuple[str, str]], method: str, path: str
) -> bool:
    """True only for a verb+path pair in `table`.

    The table is a parameter so the controls below can hand it an over-broad exemption:
    a matcher that can only be shown to allow things is not evidence that it refuses any.
    """
    verb = method.upper()
    for allowed, template in table:
        if allowed != verb:
            continue
        if re.fullmatch(_template_to_regex(template), path):
            return True
    return False


def plugin_route_is_public(method: str, path: str) -> bool:
    return matches_public_route_template(PUBLIC_PLUGIN_ROUTES, method, path)


def public_exemption_checks(server_routes: Sequence[str]) -> Dict[str, bool]:
    """Is the QR-poll exemption still true, still narrow, and still necessary?"""
    served = set(server_routes)
    return {
        "every_public_plugin_route_template_is_registered": all(
            "%s %s" % pair in served for pair in PUBLIC_PLUGIN_ROUTES
        ),
        "the_poll_exemption_cannot_be_a_suffix": not POLL_PATH.endswith(PUBLIC_PLUGIN_SUFFIXES),
        "the_poll_exemption_answers_only_its_verb": matches_public_route_template(
            PUBLIC_PLUGIN_ROUTES, "POST", POLL_PATH
        ) is False,
        "the_poll_exemption_takes_exactly_one_path_segment": (
            matches_public_route_template(PUBLIC_PLUGIN_ROUTES, "GET", POLL_PATH)
            and not matches_public_route_template(PUBLIC_PLUGIN_ROUTES, "GET", POLL_PATH + "/extra")
        ),
        "the_poll_exemption_does_not_open_the_rest_of_the_plugins": not matches_public_route_template(
            PUBLIC_PLUGIN_ROUTES, "GET", "/api/v1/plugins/sso/audit"
        ),
    }


STATIC_DIR = Path(__file__).resolve().parent / "static"

#: The only `settings` keys the generic settings routes may read or write. A
#: key/value table exposed to an authenticated-but-casual caller is how a
#: `gateway.db_path` edit happens, so the surface is an allowlist, not a prefix.
SETTINGS_ALLOWLIST = {
    SETTING_AUTO_ACCEPT: bool,
    SETTING_WELCOME_TEXT: str,
}


_HTML_ESCAPES = (
    ("&", "&amp;"),
    ("<", "&lt;"),
    (">", "&gt;"),
    ('"', "&quot;"),
    ("'", "&#x27;"),
)


def html_escape(text: Any) -> str:
    """The five characters that turn stored content into markup.

    An article body is operator input rendered inside the app's own webview, where a
    stored `<script>` runs with the reader's signed URL in `location.search` — that
    is a pairwise-credential leak, not a cosmetic bug. Escaping on render (rather
    than on write) means an existing row cannot be re-poisoned by a later change of
    policy.
    """
    out = str(text if text is not None else "")
    for needle, replacement in _HTML_ESCAPES:
        out = out.replace(needle, replacement)
    return out


def _h5_shell(article_id: str, body: str, title: str, *, error: str = "") -> str:
    """The H5 document, inline-styled and dependency-free.

    No external asset on purpose: the page is opened inside the iOS app's
    `SFSafariViewController` from a signed link, and a font or analytics request
    made there leaks the reader's URL — including `popopx_uid` — to a third party.
    """
    notice = ""
    if error:
        notice = (
            "<p class=err>此页面无法验证您的身份（%s）。请返回服务号会话，从卡片重新打开；"
            "若仍然失败，请在管理后台为该联系人重新下发握手。</p>" % html_escape(error)
        )
    paragraphs = "".join(
        "<p>%s</p>" % html_escape(line) for line in str(body or "").split("\n") if line.strip()
    )
    return (
        "<!doctype html><html lang=zh-Hans><head><meta charset=utf-8>"
        "<meta name=viewport content=\"width=device-width,initial-scale=1\">"
        "<title>%s</title><style>"
        ":root{color-scheme:light dark}body{margin:0;padding:20px 18px 48px;"
        "font:16px/1.65 -apple-system,BlinkMacSystemFont,\"PingFang SC\",sans-serif;"
        "color:#15171a;background:#fbfbfd;max-width:34rem}"
        "h1{font-size:20px;line-height:1.35;margin:0 0 6px}"
        ".meta{font-size:12px;color:#8a8f98;letter-spacing:.02em;margin-bottom:22px}"
        "p{margin:0 0 14px}.err{padding:12px 14px;border-radius:10px;background:#fff2f0;"
        "color:#8c1d18;font-size:14px}footer{margin-top:32px;font-size:12px;color:#8a8f98}"
        "@media(prefers-color-scheme:dark){body{background:#0e0f12;color:#e8e9ec}"
        ".err{background:#2a1517;color:#ffb4ab}.meta,footer{color:#7d828b}}"
        "</style></head><body><h1>%s</h1><div class=meta>POPOPX · %s</div>%s%s"
        "<footer>内容由 POPOPX 服务号签发，链接含一次性身份参数，请勿转发。</footer>"
        "</body></html>"
    ) % (html_escape(title), html_escape(title), html_escape(article_id), notice, paragraphs)


def qr_svg_for_link(link: str) -> str:
    """Render one opaque invite link as an SVG QR code.

    The QR carries the same text the console copies — the opaque link, never
    the raw URI — so a screenshot of the code cannot reveal a relay either.
    `qrcode` is imported lazily because the SVG surface is optional: a
    deployment without the wheel still serves every other route, and the
    caller turns the ImportError into a named `qr_unavailable` field rather
    than a 500.
    """
    import qrcode
    import qrcode.image.svg

    qr = qrcode.QRCode(
        error_correction=qrcode.constants.ERROR_CORRECT_M,
        box_size=10,
        border=2,
        image_factory=qrcode.image.svg.SvgPathImage,
    )
    qr.add_data(link)
    qr.make(fit=True)
    rendered = qr.make_image().to_string()
    return rendered.decode("utf-8") if isinstance(rendered, (bytes, bytearray)) else str(rendered)


def create_app(config: Optional[Config] = None, *, gateway: Optional[Gateway] = None) -> Any:
    """Build the ASGI application. Returns a `FastAPI` instance."""
    try:
        from fastapi import Depends, FastAPI, Request
        from fastapi.responses import FileResponse, HTMLResponse, JSONResponse
    except ImportError as exc:  # pragma: no cover — the only reason this fires is an uninstalled wheel
        raise RuntimeError(
            "FastAPI is not installed; run ./start_macos.sh, ./install_macos.sh or ./install_ubuntu22.sh first (%s)" % exc
        ) from None

    cfg = config if config is not None else load_config()
    gw = gateway if gateway is not None else Gateway(cfg)
    gw.mount_plugins()

    # The launch and teardown halves of one context manager, not two hooks: uvicorn
    # runs the code after `yield` for as long as the app serves, and the `finally`
    # still closes the node link and the outbox worker when a request phase raises.
    # The deprecated `app.on_event("startup"/"shutdown")` pair did this with a
    # DeprecationWarning printed on every boot and no way to order teardown after a
    # failure.
    @contextlib.asynccontextmanager
    async def _lifespan(_app: Any) -> AsyncIterator[None]:
        await gw.start()
        try:
            yield
        finally:
            await gw.stop()

    app = FastAPI(
        title="POPOPX service gateway", version="1.0.0",
        docs_url=None, redoc_url=None, lifespan=_lifespan,
    )
    app.state.gateway = gw

    # ── plugin routers ──────────────────────────────────────────────────────
    #
    # Mounted before a single route of this file is declared, because Starlette
    # dispatches to the first registration whose path and method match and
    # `create_app` below declares a generic `GET /api/v1/plugins/{plugin_id}/status`.
    # Registered after the plugin routers, that route answered for `ai_agent` and
    # `web3_bridge` too — both of which publish a far richer `/status` of their own —
    # so the console's AI panel got a mount-table row where it asked for the model,
    # the key state and the rate limiter, and no code path in either plugin could be
    # reached to explain why. The generic route still serves the three plugins that
    # do not define one, which is what it is for.
    for mounted in gw.plugins.values():
        if mounted.available and mounted.router is not None:
            # The prefix is conditional because the nine plugins do not agree on who
            # supplies it, and passing it unconditionally composes two copies:
            # `alert_ops`, `polls` and `web3_bridge` declare their router with
            # `prefix=deps.spec.url_prefix` so that the module answers at its real
            # path when started standalone, while `ai_agent` and `privacy_sso` declare
            # a bare router and rely on this loop. `include_router` concatenates its
            # own prefix with the router's, so the unconditional form served those
            # three at `/api/v1/plugins/web3/api/v1/plugins/web3/watchers` — a URL no
            # launcher, no `.env.example` and no alerting tool knows, and one that
            # 404s for every caller including this gateway's own console.
            prefix = mount_prefix(getattr(mounted.router, "prefix", ""), mounted.spec.url_prefix)
            app.include_router(mounted.router, prefix=prefix)
            LOG.info("mounted %s at %s", mounted.spec.plugin_id, mounted.spec.url_prefix)

    # ── helpers ─────────────────────────────────────────────────────────────

    async def json_body(request: Request) -> Dict[str, Any]:
        """The request body as a dict, or a 400 naming what was wrong.

        Every route uses this rather than a pydantic model per endpoint because the
        bodies are small, the validation rules are the *client's* rules
        (`crypto_service`), and a 422 from a model that disagrees with
        `EcoLimits.card_title_chars` would be two sources of truth about the same
        limit.
        """
        raw = await request.body()
        if not raw:
            return {}
        try:
            parsed = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, ValueError) as exc:
            raise bad_request("invalid_json", str(exc)) from exc
        if not isinstance(parsed, dict):
            raise bad_request("body_must_be_object", "expected a JSON object, got %s" % type(parsed).__name__)
        return parsed

    def request_principal(request: Request) -> str:
        """Who is acting: the token's label (root is labelled ``root``).

        Only the label, never the token: the label is what an operator minted it
        with, and a secret has no business in an audit row or a log line.
        """
        grant = admin_auth.grant_from_request(request) or {}
        return str(grant.get("label") or grant.get("token_id") or "root")

    def admin_required(request: Request, *, root_only: bool = False) -> None:
        """Refuse unless the request carries a credential that covers this route.

        The middleware resolves a scoped token once and attaches the grant; the
        resolution is repeated here only when a handler is called without that
        middleware (a unit test, an included router in another app). Keeping the
        check in the handler is what makes ``route_census()`` able to see it.
        """
        grant = admin_auth.grant_from_request(request)
        if grant is None:
            presented = admin_auth.presented_credential(
                request.headers, request.query_params.get("token") or ""
            )
            grant, _rejected = admin_auth.resolve_presented(
                gw.db, presented, gw.config.admin_token, path=request.url.path
            )
            if grant is not None:
                setattr(request.state, admin_auth.STATE_ATTR, grant)
        if grant is None:
            raise GatewayError(401, "unauthorized", "provide the X-Admin-Token header")
        resource, resource_root_only = admin_auth.resource_for_path(
            request.url.path, ADMIN_PLUGIN_PREFIXES
        )
        if not admin_auth.scope_allows(
            grant,
            resource,
            write=admin_auth.write_method(request.method),
            root_only=root_only or resource_root_only,
        ):
            raise GatewayError(
                403,
                "forbidden",
                "this admin token does not allow %s %s" % (request.method, request.url.path),
            )

    def contact_ids_from(body: Mapping[str, Any], session_required: bool = True) -> List[int]:
        """Resolve `contact_ids` / `all_contacts` into a list of follower ids."""
        if body.get("all_contacts"):
            return [session.contact_id for session in gw.eco.all_sessions()]
        raw = body.get("contact_ids")
        if raw is None:
            raw = body.get("contact_id")
        ids = [int(value) for value in split_csv(raw) if int_or_none(value) is not None]
        if not ids:
            raise bad_request("contact_ids_required", "pass contact_ids=[…] or all_contacts=true")
        if session_required:
            known = {session.contact_id for session in gw.eco.all_sessions()}
            missing = [value for value in ids if value not in known]
            if missing:
                raise conflict("no_session", "contacts without a handshake: %s" % ",".join(str(m) for m in missing[:20]))
        return ids

    # ── errors ──────────────────────────────────────────────────────────────

    @app.exception_handler(GatewayError)
    async def _gateway_error(_request: Request, exc: GatewayError) -> JSONResponse:
        return JSONResponse(exc.to_body(), status_code=exc.status)

    @app.exception_handler(NodeCommandError)
    async def _node_command_error(_request: Request, exc: NodeCommandError) -> JSONResponse:
        # A command error means the socket worked: the node read the command and
        # refused it. Folding that into `503 node_unreachable` sent the operator to
        # check a link that was answering — measured against a real node, where
        # `/_profile` came back `userExists` and `/_accept` came back
        # `contactRequestNotFound` on a healthy connection. `node_error` carries the
        # node's own reason name so a console or a monitor never has to parse
        # `detail`. Starlette resolves handlers along the exception's MRO, so this
        # one wins for command errors and the transport case below keeps the rest.
        return JSONResponse(
            {"ok": False, "error": "node_refused", "node_error": error_reason(exc.chat_error),
             "detail": str(exc)},
            status_code=502,
        )

    @app.exception_handler(NodeError)
    async def _node_error(_request: Request, exc: NodeError) -> JSONResponse:
        # The `/api/v1/node/*` routes ask the bridge directly, and the bridge raises
        # this the moment the link is not answering. Without a handler those seconds
        # of a restarting node — the normal state right after `start_macos.sh` — were a
        # bare 500, while the identical failure inside `sync_contacts` is already
        # reported as `503 node_unreachable`. One handler makes the two agree.
        return JSONResponse(
            {"ok": False, "error": "node_unreachable", "detail": str(exc)}, status_code=503
        )

    @app.exception_handler(PluginUnavailable)
    async def _plugin_unavailable(_request: Request, exc: PluginUnavailable) -> JSONResponse:
        return JSONResponse(exc.decision.as_body(), status_code=exc.decision.http_status)

    @app.exception_handler(BillingError)
    async def _billing_error(_request: Request, exc: BillingError) -> JSONResponse:
        return JSONResponse(
            {"ok": False, "error": exc.code, "detail": exc.message}, status_code=exc.http_status or 402
        )

    @app.exception_handler(EcoError)
    async def _eco_error(_request: Request, exc: EcoError) -> JSONResponse:
        # The client's rule name is the actionable part: "card_title" and
        # "137 characters exceeds 120" together tell a merchant what to edit.
        return JSONResponse(
            {"ok": False, "error": "client_rule", "rule": exc.rule, "detail": exc.detail}, status_code=400
        )

    @app.exception_handler(VaultError)
    async def _vault_error(_request: Request, exc: VaultError) -> JSONResponse:
        # A sealed value that does not open is an operator problem (wrong or
        # missing POPOPX_VAULT_KEY, or a ciphertext moved between rows), not a
        # client one. 503 is honest: the request may succeed after the key is
        # fixed, and the detail names the table/column/subject only.
        LOG.error("vault error: %s", exc)
        return JSONResponse(
            {"ok": False, "error": "vault_error", "detail": str(exc)}, status_code=503
        )

    @app.exception_handler(sqlite3.Error)
    async def _sqlite_error(_request: Request, exc: sqlite3.Error) -> JSONResponse:
        LOG.exception("database error")
        return JSONResponse({"ok": False, "error": "database_error", "detail": str(exc)}, status_code=500)

    # ── auth ────────────────────────────────────────────────────────────────

    @app.middleware("http")
    async def admin_gate(request: Request, call_next: Any) -> Any:
        """Resolve one admin credential per request and enforce its scopes.

        Plugin paths keep their pre-existing contract: no credential is 401
        before the plugin gate can answer 404. Core paths are annotated here and
        still refused by ``admin_required`` in the handler, so the documented
        error body and the AST census stay in one place. A valid scoped token is
        audited on the way out; the root token deliberately is not, because it is
        the operator's everyday credential and auditing every console poll would
        bury the scoped decisions this table exists to show.
        """
        path = request.url.path
        public_plugin = path.startswith("/api/v1/plugins/") and (
            path.endswith(PUBLIC_PLUGIN_SUFFIXES) or plugin_route_is_public(request.method, path)
        )
        plugin_path = path.startswith("/api/v1/plugins/") and not public_plugin
        core_path = (
            path.startswith("/api/v1/")
            and not public_plugin
            and (str(request.method).upper(), path) not in PUBLIC_ROUTE_KEYS
        )
        if not plugin_path and not core_path:
            return await call_next(request)
        presented = admin_auth.presented_credential(
            request.headers, request.query_params.get("token") or ""
        )
        grant, rejected = admin_auth.resolve_presented(
            gw.db, presented, gw.config.admin_token, path=path
        )
        if grant is None:
            if plugin_path:
                body: Dict[str, Any] = {"ok": False, "error": "unauthorized"}
                if rejected:
                    body["detail"] = "this admin token is %s" % rejected.get("reason")
                return JSONResponse(body, status_code=401)
            if rejected:
                # A known-but-dead token should not reach `admin_required`, which
                # would resolve it a second time and write the same audit row twice.
                return JSONResponse(
                    {"ok": False, "error": "unauthorized",
                     "detail": "this admin token is %s" % rejected.get("reason")},
                    status_code=401,
                )
            return await call_next(request)
        setattr(request.state, admin_auth.STATE_ATTR, grant)
        resource, root_only = admin_auth.resource_for_path(path, ADMIN_PLUGIN_PREFIXES)
        if not admin_auth.scope_allows(
            grant, resource, write=admin_auth.write_method(request.method), root_only=root_only
        ):
            admin_auth.record_audit(
                gw.db, grant.get("token_id"), "request", path, "scope_denied", 403
            )
            return JSONResponse(
                {"ok": False, "error": "forbidden",
                 "detail": "this admin token does not allow %s %s" % (request.method, path)},
                status_code=403,
            )
        response = await call_next(request)
        if not grant.get("root"):
            admin_auth.record_audit(
                gw.db, grant.get("token_id"), "request", path, "used", response.status_code
            )
        return response

    # ── public surface ──────────────────────────────────────────────────────

    @app.get("/healthz")
    async def health() -> Dict[str, Any]:
        """Liveness for a load balancer: no admin token, no database write, no node call.

        The path is what every launcher in this repo probes (`start_macos.sh`,
        `install_macos.sh`, `install_ubuntu22.sh`, `docker-compose.yml`), so renaming it
        here would break the healthcheck of an existing deployment. `gateway/Dockerfile`
        names the path in a comment and deliberately ships no `HEALTHCHECK` of its own.
        """
        return {
            "ok": True,
            "node_connected": gw.eco.bridge_connected(),
            "service_id": gw.config.service_id,
        }

    @app.post("/api/v1/verifyH5Auth")
    async def verify_h5(request: Request) -> JSONResponse:
        """The H5 authorisation check (`PopopxH5Launcher` signs the URL client-side).

        Takes `popopx_uid`/`ts`/`sig` — the three parameters the client puts in the
        URL — and answers with `{"valid": bool, "reason": …}`; no separate bearer is
        minted, because the anonymous session handle is already in the request: the
        verified `pairwise_uid` is the anonymous handle, and a second token would be
        a second thing to rotate for no additional guarantee. Deliberately open:
        the authorisation *is* the HMAC, and adding a token here would mean the
        merchant's web server needed gateway credentials, which is the secret
        distribution this endpoint exists to avoid. Rate limiting belongs in front
        of it (see the runbook's nginx block) because a 6-digit-window HMAC is
        guessable at scale otherwise; the suite does not pretend to solve it here.
        """
        body: Dict[str, Any] = {}
        if (request.headers.get("content-type") or "").startswith("application/json"):
            body = await json_body(request)
        query = dict(request.query_params)
        uid = body.get("popopx_uid") or body.get("uid") or query.get(H5_UID_PARAM) or ""
        timestamp = body.get("ts") or query.get(H5_TS_PARAM) or ""
        signature = body.get("sig") or body.get("signature") or query.get(H5_SIG_PARAM) or ""
        result = gw.eco.verify_h5_request(uid, timestamp, signature)
        return JSONResponse(result, status_code=200 if result.get("valid") else 401)

    @app.post("/api/v1/workflows/trigger")
    async def workflow_trigger(request: Request) -> JSONResponse:
        """The Node-RED/Activepieces action hop, authenticated by its own token.

        The path is fixed by the brief and deliberately outside
        ``/api/v1/plugins/``: a flow node holds ``X-PPX-Workflow-Token``, never the
        operator's admin token, so the plugin-prefix middleware must not see this
        request. When the plugin is switched off the gate answers exactly as it
        would for a mounted route (404), and a caller cannot tell the switch from
        a deployment that removed the feature.
        """
        mounted = gw.plugins.get("workflow_webhook")
        if mounted is None or not mounted.available or mounted.deps is None:
            decision = gw.gate.status("workflow_webhook")
            if decision.usable:
                # Enabled but the module did not build its router: a deployment
                # fault, not a missing feature, and 503 is retryable.
                return JSONResponse(
                    {"ok": False, "plugin": "workflow_webhook", "reason": "plugin_unavailable",
                     "detail": "the workflow module is enabled but was not mounted"},
                    status_code=503,
                )
            return JSONResponse(decision.as_body(), status_code=decision.http_status)
        return await mounted.module.handle_trigger(mounted.deps, request)

    @app.get("/", include_in_schema=False)
    async def console() -> Any:
        """Serve the management console, without asking for a token.

        Deliberate: the page is a static shell whose only content is JavaScript, and
        the token the page sends with every API call lives in the operator's browser,
        not in this response. Guarding the *page* instead of the API would only mean an
        operator cannot reach a login form, so the whole protection of the console
        is the `X-Admin-Token` check on the `/api/v1/` routes below — which is what
        :func:`route_census` proves at startup — plus the two lists that say
        otherwise: `PUBLIC_PLUGIN_SUFFIXES` and `PUBLIC_PLUGIN_ROUTES`.
        """
        index = STATIC_DIR / "index.html"
        if not index.exists():
            return HTMLResponse(
                "<!doctype html><meta charset=utf-8><title>POPOPX gateway</title>"
                "<p style='font:16px system-ui;padding:2rem'>The management console has not been"
                " installed (gateway/app/static/index.html is missing). The API is live at /api/v1/.</p>",
                status_code=200,
            )
        return FileResponse(index, media_type="text/html; charset=utf-8")

    @app.get("/h5/{article_id}", include_in_schema=False)
    async def h5_page(article_id: str, request: Request) -> HTMLResponse:
        """The reference H5 page: verify the signature, then render.

        This is the page a merchant's own host copies, and it is deliberately in the
        suite so that the `verifyH5Auth` contract has a caller. Two rules from
        `PopopxH5Launcher` shape it:

        * the signature is checked *before* any content is rendered — the query
          parameters are the only thing identifying the reader, and an
          unverified page is a public page with a nicer URL;
        * the check is made against the server (`/api/v1/verifyH5Auth`), not in
          page JavaScript with a secret, because the secret is per-follower and the
          gateway is the only party holding it.

        A follower who re-opens the link after a session rotation lands here with a
        signature that no longer verifies, and gets the reason rather than a blank
        page: that is the one failure mode an operator can fix from the console
        (`POST /api/v1/contacts/{id}/handshake` with `rotate`).
        """
        uid, timestamp, signature = h5_query_params(dict(request.query_params))
        verdict = gw.eco.verify_h5_request(uid, timestamp, signature)
        article = gw.eco.get_article(article_id)
        if not verdict.get("valid"):
            return HTMLResponse(_h5_shell(article_id, "", "签名无效或已过期", error=str(verdict.get("reason") or "invalid")), status_code=401)
        if article is None:
            return HTMLResponse(_h5_shell(article_id, "", "内容不存在", error="article_not_found"), status_code=404)
        title = str(article.get("title") or article_id)
        body = str(article.get("body") or "")
        return HTMLResponse(_h5_shell(article_id, body, title))

    # ── status and node ─────────────────────────────────────────────────────

    @app.get("/api/v1/status")
    async def status(request: Request) -> Dict[str, Any]:
        admin_required(request)
        return gw.status()

    # ── scoped admin tokens ─────────────────────────────────────────────────
    # Root-only by construction: the mint route is the one place a new credential
    # is created, and `core:admin` is not a grantable scope, so a leaked scoped
    # token cannot climb. The plaintext is in the mint response and nowhere else.

    @app.get("/api/v1/admin/tokens")
    async def admin_tokens_list(request: Request) -> Dict[str, Any]:
        admin_required(request, root_only=True)
        return {"ok": True, "tokens": admin_auth.list_tokens(gw.db)}

    @app.post("/api/v1/admin/tokens")
    async def admin_tokens_mint(request: Request) -> Dict[str, Any]:
        admin_required(request, root_only=True)
        body = await json_body(request)
        days = int_or_none(body.get("expires_in_days"))
        if days is not None and (days < 1 or days > 3650):
            raise bad_request("expires_in_days_out_of_range", "expires_in_days must be between 1 and 3650")
        expires_at = now_ms() + days * 86_400_000 if days is not None else None
        try:
            minted = admin_auth.mint_token(
                gw.db, str(body.get("label") or ""), body.get("scopes"), expires_at_ms=expires_at
            )
        except ValueError as exc:
            raise bad_request("invalid_token_request", str(exc)) from exc
        return minted

    @app.get("/api/v1/admin/tokens/audit")
    async def admin_tokens_audit(request: Request) -> Dict[str, Any]:
        admin_required(request, root_only=True)
        raw_limit = request.query_params.get("limit") if request.query_params else None
        try:
            limit = int(raw_limit) if raw_limit not in (None, "") else 50
        except (TypeError, ValueError):
            raise bad_request("invalid_limit", "limit must be an integer")
        if limit < 1 or limit > 500:
            raise bad_request("invalid_limit", "limit must be between 1 and 500")
        return {"ok": True, "audit": admin_auth.list_audit(gw.db, limit=limit)}

    @app.delete("/api/v1/admin/tokens/{token_id}")
    async def admin_tokens_revoke(token_id: str, request: Request) -> Dict[str, Any]:
        admin_required(request, root_only=True)
        row = gw.db.query_one("SELECT id FROM admin_tokens WHERE id = ?", (token_id,))
        if row is None:
            raise not_found("token_not_found", "no scoped admin token with that id")
        changed = admin_auth.revoke_token(gw.db, token_id)
        return {"ok": True, "id": token_id, "revoked": changed}

    @app.post("/api/v1/node/address")
    async def node_address(request: Request) -> Dict[str, Any]:
        """Mint (or reuse) the contact address a real iPhone scans or pastes.

        This is the "no code edits needed to pair a phone" path: the address comes
        back in the response body, the console shows it, and nothing has to be
        restarted or edited because the gateway discovered the user from the node at
        startup.
        """
        admin_required(request)
        body = await json_body(request)
        address = await gw.bridge.show_contact_address()
        if not address or body.get("rotate"):
            address = await gw.bridge.create_contact_address(pq_ratchet=bool(body.get("pq_ratchet", True)))
        gw.db.execute("UPDATE service_identity SET address = ?, updated_at_ms = ? WHERE id = 1", (address, now_ms()))
        payload = {"ok": True, "contact_address": address}
        return gw.eco.decorate_invite(
            payload,
            kind="service_account",
            subject_id=gw.eco.service_id,
            raw_uri=address,
            field="contact_link",
        )

    @app.post("/api/v1/node/accept")
    async def node_accept(request: Request) -> Dict[str, Any]:
        admin_required(request)
        body = await json_body(request)
        request_id = int_or_none(body.get("contact_request_id"))
        if not request_id or request_id <= 0:
            raise bad_request("contact_request_id_required")
        return await gw.router.accept_contact(request_id, str(body.get("display_name") or ""))

    @app.get("/api/v1/node/contacts")
    async def node_contacts(request: Request) -> Dict[str, Any]:
        """The node's own view, unprojected — for when `contacts` and reality disagree."""
        admin_required(request)
        return {"ok": True, "contacts": await gw.bridge.list_contacts()}

    @app.put("/api/v1/node/profile")
    async def node_profile(request: Request) -> Dict[str, Any]:
        admin_required(request)
        body = await json_body(request)
        display = str(body.get("display_name") or gw.config.service_name)
        full = str(body.get("full_name") or gw.config.service_full_name or display)
        resp = await gw.bridge.set_profile(display, full)
        gw.db.execute(
            "UPDATE service_identity SET display_name = ?, full_name = ?, updated_at_ms = ? WHERE id = 1",
            (display, full, now_ms()),
        )
        return {"ok": True, "node_response": resp}

    @app.post("/api/v1/send/text")
    async def send_text(request: Request) -> Dict[str, Any]:
        """Send plain text to one follower, uncharged.

        The escape hatch an operator reaches for when a plugin is fused and a human
        still has to be told something. Uncharged is the point: POPX-CP
        is the gate, and the seven `POPOPX_CP_PER_*` meters it implies are
        ECO frames and plugin actions — a plain chat message is neither, and
        `billing_service.py:414` would answer `unknown_meter` if this route asked
        for one.
        """
        admin_required(request)
        body = await json_body(request)
        contact_id = int_or_none(body.get("contact_id"))
        text = str(body.get("text") or "")
        if not contact_id or not text:
            raise bad_request("contact_id_and_text_required")
        if len(text) > EcoLimits.frame_chars:
            raise bad_request("text_too_long", "%d characters exceeds %d" % (len(text), EcoLimits.frame_chars))
        # `outbox.contact_id` has a foreign key onto `contacts`, so a made-up id
        # cannot be parked: with the node down that INSERT raised
        # `FOREIGN KEY constraint failed` and the operator got a 500. Requiring the
        # contact is the honest answer in the other case too — the node refuses an
        # id it does not have (`contactNotFound`, measured on a live node), so there
        # is nobody to send to and no queue to wait for.
        if gw.db.query_one("SELECT contact_id FROM contacts WHERE contact_id = ?", (int(contact_id),)) is None:
            raise bad_request("unknown_contact", "no contact %d in this gateway" % int(contact_id))
        delivered = await gw.eco.send_frame(int(contact_id), text)
        # `queued` is reported from the predicate `send_frame` actually branches on —
        # it enqueues only while the link is down — not from `not delivered`. A
        # refused send (an unknown contact: the live node answered `contactNotFound`)
        # leaves nothing in the outbox, and `queued: true` there tells an operator to
        # wait for a message that will never go out.
        return {
            "ok": delivered,
            "contact_id": int(contact_id),
            "delivered": delivered,
            "queued": bool(not delivered and not gw.eco.bridge_connected()),
        }

    # ── contacts and sessions ───────────────────────────────────────────────

    @app.get("/api/v1/contacts")
    async def contacts(request: Request) -> JSONResponse:
        admin_required(request)
        rows = gw.db.query(
            "SELECT c.contact_id, c.pairwise_uid, c.display_name, c.local_display_name, c.first_seen_ms, c.last_seen_ms,"
            " c.blocked, c.tags, s.revoked, s.rotated_at_ms, s.service_id"
            "  FROM contacts c LEFT JOIN eco_sessions s ON s.contact_id = c.contact_id"
            " ORDER BY c.contact_id"
        )
        out = []
        for row in rows:
            data = row_dict(row)
            # `secret_hex` is never selected above, and a session that has been
            # revoked still shows its uid: the uid is what a support conversation
            # needs, the secret is what it must never need.
            out.append(data)
        return JSONResponse({"ok": True, "contacts": out, "count": len(out)})

    @app.post("/api/v1/contacts/sync")
    async def contacts_sync(request: Request) -> Dict[str, Any]:
        admin_required(request)
        return await gw.router.sync_contacts()

    @app.post("/api/v1/contacts/{contact_id}/handshake")
    async def contact_handshake(contact_id: int, request: Request) -> Dict[str, Any]:
        """(Re)issue a follower's session and push `session_handshake`.

        Rotation is the answer to "this phone can open the H5 page but the
        signature is rejected after a restore": the uid changes, so a card signed
        against the old one stops working by design and the merchant re-sends the
        cards that matter.
        """
        admin_required(request)
        body = await json_body(request)
        return await gw.eco.handshake(int(contact_id), rotate=bool(body.get("rotate")))

    @app.delete("/api/v1/contacts/{contact_id}/session")
    async def revoke_session(contact_id: int, request: Request) -> Dict[str, Any]:
        admin_required(request)
        revoked = gw.eco.revoke_session(int(contact_id))
        return {"ok": revoked, "contact_id": int(contact_id), "revoked": revoked}

    # ── menu ────────────────────────────────────────────────────────────────

    @app.get("/api/v1/menu")
    async def menu_get(request: Request) -> Dict[str, Any]:
        admin_required(request)
        return {"ok": True, "menu": gw.eco.menu_state()}

    @app.post("/api/v1/menu")
    async def menu_post(request: Request) -> Dict[str, Any]:
        """Store the menu. `{"items": […], "push": true, "revision": 7}`.

        Items are given in the console's own vocabulary and normalised by
        `crypto_service.build_menu`, so a title that is 14 characters too long is a
        400 naming the item instead of a menu the phone silently refuses.
        """
        admin_required(request)
        body = await json_body(request)
        items = body.get("items")
        if not isinstance(items, list) or not items:
            raise bad_request("items_required", "expected a non-empty items array")
        stored = gw.eco.store_menu(items, revision=int_or_none(body.get("revision")))
        pushed = None
        if body.get("push"):
            pushed = await gw.eco.push_menu()
        return {"ok": True, **stored, "pushed": pushed}

    @app.post("/api/v1/menu/push")
    async def menu_push(request: Request) -> Dict[str, Any]:
        admin_required(request)
        body = await json_body(request)
        ids = [int(v) for v in (body.get("contact_ids") or []) if int_or_none(v) is not None] or None
        delivered = await gw.eco.push_menu(contact_ids=ids)
        return {"ok": delivered, "delivered": delivered, "recipients": len(ids) if ids else "all"}

    # ── cards ───────────────────────────────────────────────────────────────

    @app.get("/api/v1/cards")
    async def cards_get(request: Request) -> Dict[str, Any]:
        admin_required(request)
        query = dict(request.query_params)
        contact_id = int_or_none(query.get("contact_id"))
        return {
            "ok": True,
            "cards": gw.eco.cards(
                contact_id=contact_id,
                topic=query.get("topic") or None,
                limit=clamp_limit(query.get("limit"), 100, 1000),
            ),
        }

    @app.post("/api/v1/cards")
    async def cards_post(request: Request) -> Dict[str, Any]:
        """Create and deliver a card.

        `card_id` is optional: a broadcast to N followers needs a distinct stored row
        per recipient (see :func:`card_id_for_recipient`), so an id supplied by the
        console is treated as the base and derived per contact, while a plugin that
        mints per-follower ids itself is used verbatim.
        """
        admin_required(request)
        body = await json_body(request)
        targets = contact_ids_from(body)
        title = str(body.get("title") or "")
        if not title:
            raise bad_request("title_required")
        base_id = str(body.get("card_id") or new_id("card"))
        actions = body.get("actions") or []
        if not isinstance(actions, list):
            raise bad_request("actions_must_be_a_list")
        card_body = str(body.get("body") or "") or None
        fields = body.get("fields") or None
        progress = body.get("progress") or None
        expires = int_or_none(body.get("expires_at_ms"))
        style = str(body.get("style") or "standard")
        if style not in CARD_STYLES:
            raise bad_request("card_style", "%r is not one of %s" % (style, list(CARD_STYLES)))
        deliveries = []
        for contact_id in targets:
            wire_id = base_id if len(targets) == 1 else card_id_for_recipient(base_id, contact_id)
            card = build_card(
                wire_id,
                title,
                style=style,
                body=card_body,
                fields=fields,
                progress=progress,
                actions=[dict(a) if isinstance(a, Mapping) else a for a in actions],
                updated_at_ms=next_monotonic_ms(0),
                expires_at_ms=expires,
            )
            result = await gw.eco.deliver_card(
                card,
                contact_id,
                visible_text=str(body.get("visible_text") or "") or None,
                topic=str(body.get("topic") or "console"),
            )
            deliveries.append(
                {
                    "card_id": result.card_id,
                    "contact_id": result.contact_id,
                    "sent": result.sent,
                    "queued": result.queued,
                    "charged": result.charged,
                    "balance_after": result.balance_after,
                    "error": result.error,
                }
            )
        sent = sum(1 for item in deliveries if item["sent"])
        return {"ok": sent > 0 or any(i["queued"] for i in deliveries), "deliveries": deliveries, "sent": sent}

    @app.get("/api/v1/cards/{card_id}")
    async def card_get(card_id: str, request: Request) -> Dict[str, Any]:
        admin_required(request)
        row = gw.eco.find_card(card_id)
        if row is None:
            raise not_found("card_not_found", card_id)
        actions = gw.db.query("SELECT * FROM card_actions WHERE card_id = ? ORDER BY id", (str(row["card_id"]),))
        return {"ok": True, "card": row, "wire": gw.eco.card_wire(row), "actions": [row_dict(a) for a in actions]}

    @app.post("/api/v1/cards/{card_id}/update")
    async def card_update(card_id: str, request: Request) -> Dict[str, Any]:
        """In-place update for one follower, or for every follower who has it.

        The card is rebuilt from the *stored* row plus these fields
        (:meth:`EcoService.update_card`), because the phone merges field-by-field
        and a frame that omits `body` would leave an older body on screen.
        """
        admin_required(request)
        body = await json_body(request)
        contact_ids = contact_ids_from(body, session_required=False) if (body.get("contact_ids") or body.get("all_contacts")) else None
        if contact_ids is None:
            matches = [row for row in gw.eco.cards(topic=None, limit=1000) if str(row.get("card_id")) == str(card_id)
                       or str(row.get("card_id")).startswith(str(card_id) + "_")]
            contact_ids = [int(row.get("contact_id") or 0) for row in matches]
            if not contact_ids:
                raise not_found("card_not_found", card_id)
        results = []
        for contact_id in contact_ids:
            delivery = await gw.eco.update_card(
                card_id,
                int(contact_id),
                title=body.get("title"),
                body=body.get("body"),
                fields=body.get("fields"),
                progress=body.get("progress"),
                actions=body.get("actions"),
                expires_at_ms=int_or_none(body.get("expires_at_ms")),
            )
            results.append(
                {"card_id": delivery.card_id, "contact_id": delivery.contact_id, "sent": delivery.sent,
                 "queued": delivery.queued, "charged": delivery.charged, "error": delivery.error}
            )
        return {"ok": True, "updates": results}

    @app.post("/api/v1/cards/{card_id}/settle")
    async def card_settle(card_id: str, request: Request) -> Dict[str, Any]:
        """Retire a card's buttons — the "already done" state, protocol-correctly."""
        admin_required(request)
        body = await json_body(request)
        contact_ids = [int(v) for v in (body.get("contact_ids") or []) if int_or_none(v) is not None]
        if not contact_ids:
            row = gw.eco.find_card(card_id)
            if row is None:
                raise not_found("card_not_found", card_id)
            contact_ids = [int(row.get("contact_id") or 0)]
        label = str(body.get("label") or "已完成")
        results = []
        for contact_id in contact_ids:
            delivery = await gw.eco.settle_card(card_id, int(contact_id), title=body.get("title"), label=label)
            results.append({"card_id": delivery.card_id, "contact_id": delivery.contact_id, "sent": delivery.sent,
                            "queued": delivery.queued, "charged": delivery.charged, "error": delivery.error})
        return {"ok": True, "settled": results}

    # ── channels ────────────────────────────────────────────────────────────

    @app.get("/api/v1/channels")
    async def channels_get(request: Request) -> Dict[str, Any]:
        admin_required(request)
        rows = gw.eco.channels()
        for row in rows:
            channel_id = str(row.get("channel_id") or "")
            gw.eco.decorate_invite(
                row,
                kind="channel",
                subject_id=channel_id,
                raw_uri=gw.eco.channel_public_uri(channel_id),
            )
        return {"ok": True, "channels": rows}

    @app.post("/api/v1/channels")
    async def channels_post(request: Request) -> Dict[str, Any]:
        admin_required(request)
        body = await json_body(request)
        channel_id = str(body.get("channel_id") or new_id("ch", nbytes=6))
        state = gw.eco.create_channel(
            channel_id,
            str(body.get("title") or channel_id),
            relay=str(body.get("relay") or ""),
            node_group_id=int_or_none(body.get("node_group_id")),
        )
        raw_uri = gw.eco.channel_public_uri(channel_id)
        invite = {"kind": "channel", "subject_id": channel_id, "raw_uri": raw_uri}
        gw.eco.decorate_invite(state, **invite)
        payload = {"ok": True, "channel": state, "public_uri": raw_uri,
                   "epochs": gw.eco.epoch_history(channel_id)}
        return gw.eco.decorate_invite(payload, **invite)

    @app.get("/api/v1/channels/{channel_id}")
    async def channel_get(channel_id: str, request: Request) -> Dict[str, Any]:
        admin_required(request)
        state = gw.eco.channel_state(channel_id)
        if state is None:
            raise not_found("channel_not_found", channel_id)
        raw_uri = gw.eco.channel_public_uri(channel_id)
        invite = {"kind": "channel", "subject_id": channel_id, "raw_uri": raw_uri}
        gw.eco.decorate_invite(state, **invite)
        payload = {
            "ok": True,
            "channel": state,
            "epochs": gw.eco.epoch_history(channel_id),
            "members": gw.eco.members(channel_id),
            "public_uri": raw_uri,
        }
        return gw.eco.decorate_invite(payload, **invite)

    @app.put("/api/v1/channels/{channel_id}/uri")
    async def channel_uri(channel_id: str, request: Request) -> Dict[str, Any]:
        """Give a channel the relay its group lives on.

        Either `{"relay": "smp.example"}` or `{"uri": "popopx://channel/…"}` — the
        URI form is what the node prints and what a member pastes, so it is
        accepted, but only its relay segment is stored. The `#key=&pub=` fragment
        is rebuilt from our own epoch-1 key and identity half by
        :meth:`EcoService.channel_public_uri`; keeping a copy of somebody else's
        fragment would let the console hand out a URI whose key no rotation of
        this channel can ever match.
        """
        admin_required(request)
        body = await json_body(request)
        uri = str(body.get("uri") or "")
        relay = str(body.get("relay") or "")
        if uri:
            state = gw.eco.set_channel_uri(channel_id, uri)
        elif not relay:
            raise bad_request("relay_or_uri_required", "send {relay} or {uri}")
        else:
            state = gw.eco.set_channel_relay(channel_id, relay)
        raw_uri = gw.eco.channel_public_uri(channel_id)
        invite = {"kind": "channel", "subject_id": channel_id, "raw_uri": raw_uri}
        gw.eco.decorate_invite(state, **invite)
        payload = {"ok": True, "channel": state, "public_uri": raw_uri}
        return gw.eco.decorate_invite(payload, **invite)

    @app.post("/api/v1/channels/{channel_id}/rotate")
    async def channel_rotate(channel_id: str, request: Request) -> Dict[str, Any]:
        """Open a new epoch and hand it to every active member.

        Charged `key_rotation` per member, which is why `notify_members` exists: an
        operator rehearsing a rotation on a channel with 4 000 members should not
        discover the price afterwards.
        """
        admin_required(request)
        body = await json_body(request)
        return await gw.eco.rotate_channel_key(
            channel_id,
            expires_at_ms=int_or_none(body.get("expires_at_ms")),
            revoke_previous=bool(body.get("revoke_previous", True)),
            notify_members=bool(body.get("notify_members", True)),
        )

    @app.get("/api/v1/channels/{channel_id}/members")
    async def channel_members_get(channel_id: str, request: Request) -> Dict[str, Any]:
        admin_required(request)
        status = dict(request.query_params).get("status")
        return {"ok": True, "members": gw.eco.members(channel_id, status=status)}

    @app.post("/api/v1/channels/{channel_id}/members")
    async def channel_members_post(channel_id: str, request: Request) -> Dict[str, Any]:
        """Grant membership to one or many followers and deliver the key."""
        admin_required(request)
        body = await json_body(request)
        targets = contact_ids_from(body)
        days = int_or_none(body.get("days")) or 30
        out = []
        for contact_id in targets:
            out.append(
                await gw.eco.grant_membership(
                    channel_id,
                    contact_id,
                    credits=int_or_none(body.get("credits")) or 0,
                    paid_ref=str(body.get("paid_ref") or "console"),
                    days=days,
                )
            )
        granted = sum(1 for item in out if item["delivered"] or item["queued"])
        return {"ok": granted > 0, "grants": out, "granted": granted}

    @app.delete("/api/v1/channels/{channel_id}/members/{contact_id}")
    async def channel_member_delete(channel_id: str, contact_id: int, request: Request) -> Dict[str, Any]:
        """Revoke a membership.

        Revocation removes the *entitlement*, not the key the phone already holds:
        a follower who saved the epoch key can still read what was encrypted under
        it. That is the property of the scheme, not a bug in this route, and it is why
        a rotation is the real answer to a leak (`/rotate`, which invalidates every
        epoch below the new one).
        """
        admin_required(request)
        return gw.eco.revoke_membership(channel_id, int(contact_id))

    # ── opaque invite links ─────────────────────────────────────────────────

    @app.post("/api/v1/invite-links")
    async def invite_link_post(request: Request) -> Dict[str, Any]:
        """Mint (or fetch) the opaque share link and its QR for one subject.

        `uri` is deliberately not accepted from the body. The gateway seals
        only URIs it owns — the contact address the node returned, or a
        channel's own public URI — because a route that seals a caller-supplied
        string under the associated domain `popopx.chat` is a phishing oracle
        with a trusted URL.
        """
        admin_required(request)
        body = await json_body(request)
        kind = str(body.get("kind") or "service_account")
        if kind not in INVITE_KINDS:
            raise bad_request("invite_kind_invalid", "expected one of %s" % (", ".join(INVITE_KINDS),))
        if kind == "channel":
            subject_id = str(body.get("channel_id") or "").strip()
            if not subject_id:
                raise bad_request("channel_id_required")
            if gw.eco.channel_state(subject_id) is None:
                raise not_found("channel_not_found", subject_id)
            raw_uri = gw.eco.channel_public_uri(subject_id)
            if not raw_uri:
                raise conflict(
                    "invite_source_unavailable",
                    "this channel has no relay yet; set one with PUT /api/v1/channels/{id}/uri",
                )
        else:
            subject_id = gw.eco.service_id
            raw_uri = str(getattr(gw.bridge, "contact_address", "") or "")
            if not raw_uri:
                raise conflict(
                    "invite_source_unavailable",
                    "no contact address yet; POST /api/v1/node/address first",
                )
        info = gw.eco.invite_link(kind, subject_id, raw_uri)
        if not info.get("link"):
            code = str(info.get("error") or "invite_source_unavailable")
            if code == "invite_crypto_unavailable":
                raise unavailable(code, "the opaque invite codec needs the cryptography wheel")
            raise conflict(code, "the opaque invite link could not be minted")
        qr_svg = None
        qr_error = None
        if bool(body.get("qr", True)):
            try:
                qr_svg = qr_svg_for_link(info["link"])
            except ImportError:
                qr_error = "qr_unavailable"
            except Exception:  # noqa: BLE001 — a broken QR must not cost the link
                LOG.exception("QR generation failed for %s invite %s", kind, subject_id)
                qr_error = "qr_failed"
        return {
            "ok": True,
            "kind": kind,
            "subject_id": subject_id,
            "link": info["link"],
            "masked": info["masked"],
            "created_at_ms": info["created_at_ms"],
            "cached": bool(info.get("cached")),
            "qr_svg": qr_svg,
            "qr_error": qr_error,
        }

    @app.get("/api/v1/invite-links/audit")
    async def invite_link_audit_get(request: Request) -> Dict[str, Any]:
        """Generation history: masked prefixes and times, never a code or URI."""
        admin_required(request)
        limit = int_or_none(dict(request.query_params).get("limit")) or 50
        return {"ok": True, "entries": gw.eco.invite_link_audit(limit)}

    # ── articles ────────────────────────────────────────────────────────────

    @app.get("/api/v1/articles")
    async def articles_get(request: Request) -> Dict[str, Any]:
        admin_required(request)
        return {"ok": True, "articles": gw.eco.articles()}

    @app.put("/api/v1/articles/{article_id}")
    async def article_put(article_id: str, request: Request) -> Dict[str, Any]:
        admin_required(request)
        body = await json_body(request)
        return {"ok": True, "article": gw.eco.put_article(
            article_id, str(body.get("title") or ""), str(body.get("body") or ""), url=str(body.get("url") or "")
        )}

    @app.get("/api/v1/articles/{article_id}")
    async def article_get(article_id: str, request: Request) -> Dict[str, Any]:
        admin_required(request)
        article = gw.eco.get_article(article_id)
        if article is None:
            raise not_found("article_not_found", article_id)
        return {"ok": True, "article": article}

    @app.post("/api/v1/articles/{article_id}/send")
    async def article_send(article_id: str, request: Request) -> Dict[str, Any]:
        admin_required(request)
        body = await json_body(request)
        targets = contact_ids_from(body)
        results = []
        for contact_id in targets:
            delivery = await gw.eco.send_article(contact_id, article_id)
            results.append({"card_id": delivery.card_id, "contact_id": delivery.contact_id,
                            "sent": delivery.sent, "queued": delivery.queued, "charged": delivery.charged,
                            "error": delivery.error})
        return {"ok": True, "deliveries": results}

    # ── billing and vouchers ────────────────────────────────────────────────

    @app.get("/api/v1/billing/account")
    async def billing_account(request: Request) -> Dict[str, Any]:
        admin_required(request)
        return {"ok": True, "account": gw.billing.account().to_dict(), "summary": gw.billing.summary(),
                "fusings": gw.billing.plugin_fusings()}

    @app.get("/api/v1/billing/ledger")
    async def billing_ledger(request: Request) -> Dict[str, Any]:
        admin_required(request)
        query = dict(request.query_params)
        limit = clamp_limit(query.get("limit"), 100, 1000)
        offset = max(0, int_or_none(query.get("offset")) or 0)
        rows = gw.billing.ledger(limit, offset=offset)
        return {"ok": True, "entries": rows, "total": gw.billing.ledger_count(), "limit": limit, "offset": offset}

    @app.post("/api/v1/billing/online")
    async def billing_online(request: Request) -> Dict[str, Any]:
        admin_required(request)
        return {"ok": True, "account": gw.billing.go_online().to_dict()}

    @app.post("/api/v1/billing/suspend")
    async def billing_suspend(request: Request) -> Dict[str, Any]:
        admin_required(request)
        body = await json_body(request)
        reason = str(body.get("reason") or "operator:")
        if not reason.startswith("operator:"):
            reason = "operator:" + reason[:120]
        return {"ok": True, "account": gw.billing.suspend(reason).to_dict()}

    @app.post("/api/v1/billing/grant")
    async def billing_grant(request: Request) -> Dict[str, Any]:
        """Add credits without a voucher — a goodwill credit or a test, never a sale.

        Deliberately admin-only and always written to the ledger with
        `reason = console_grant`, so the two ways credits can appear are
        distinguishable in an audit: a redeemed `POPX-CP` code carries its
        `voucher_id`, and this does not.
        """
        admin_required(request)
        body = await json_body(request)
        credits = int_or_none(body.get("credits")) or 0
        if credits <= 0:
            raise bad_request("credits_required", "pass a positive credits integer")
        result = gw.billing.grant(credits=credits, reason=str(body.get("reason") or "console_grant"),
                                  idempotency_key=str(body.get("idempotency_key") or "") or None)
        return {"ok": True, "result": result.to_dict()}

    @app.get("/api/v1/vouchers")
    async def vouchers_get(request: Request) -> Dict[str, Any]:
        admin_required(request)
        status = dict(request.query_params).get("status")
        return {"ok": True, "vouchers": gw.billing.vouchers(status=status)}

    @app.post("/api/v1/vouchers/verify")
    async def voucher_verify(request: Request) -> Dict[str, Any]:
        """Check a code's signature without redeeming it.

        The merchant's front desk needs this: "is this code real, and what is it
        worth" is answerable offline with the public key, and answering it must not
        consume the code.
        """
        admin_required(request)
        body = await json_body(request)
        code = str(body.get("code") or "").strip()
        if not code:
            raise bad_request("code_required")
        try:
            payload = gw.voucher_payload(code)
        except CryptoUnavailable as exc:
            raise unavailable("crypto_unavailable", str(exc)) from exc
        except EcoError as exc:
            return {"ok": False, "valid": False, "rule": exc.rule, "detail": exc.detail}
        return {"ok": True, "valid": True, "voucher": payload}

    @app.post("/api/v1/vouchers/redeem")
    async def voucher_redeem(request: Request) -> Dict[str, Any]:
        admin_required(request)
        body = await json_body(request)
        code = str(body.get("code") or "").strip()
        if not code:
            raise bad_request("code_required")
        result = gw.billing.redeem_voucher(code, redeemed_by=str(body.get("redeemed_by") or "console"))
        # `redeem_voucher` answers a plain dict (app/billing_service.py:689), unlike the
        # `AccountView`/`ChargeResult` the other billing routes return — calling
        # `.to_dict()` on it was an `AttributeError` on the first real redemption.
        return {"ok": True, "result": result, "account": gw.billing.account().to_dict()}

    # ── plugins, callbacks, outbox ──────────────────────────────────────────

    @app.get("/api/v1/plugins")
    async def plugins_get(request: Request) -> Dict[str, Any]:
        admin_required(request)
        return {"ok": True, "plugins": gw.plugin_status()}

    @app.get("/api/v1/plugins/{plugin_id}/status")
    async def plugin_status(plugin_id: str, request: Request) -> Dict[str, Any]:
        admin_required(request)
        try:
            spec = plugin_for_id(plugin_id)
        except KeyError as exc:
            raise not_found("plugin_unknown", str(exc)) from exc
        mounted = gw.plugins.get(spec.plugin_id)
        return {"ok": True, "plugin": mounted.as_dict() if mounted else None,
                "gate": gw.gate.status(spec.plugin_id).as_body()}

    @app.get("/api/v1/callbacks")
    async def callbacks_get(request: Request) -> Dict[str, Any]:
        """What the phones actually sent, including the ones nothing handled.

        `status='unmatched'` is the interesting filter: it is how a merchant finds
        out that a button payload was wired to no handler, instead of concluding the
        follower never tapped it.
        """
        admin_required(request)
        query = dict(request.query_params)
        return {"ok": True, "callbacks": gw.router.recent(
            limit=clamp_limit(query.get("limit"), 50, 500),
            kind=query.get("kind") or None,
            status=query.get("status") or None,
        )}

    @app.get("/api/v1/outbox")
    async def outbox_get(request: Request) -> Dict[str, Any]:
        admin_required(request)
        return {"ok": True, "stats": gw.eco.outbox_stats(), "queued": gw.eco.queued_frames(200)}

    @app.post("/api/v1/outbox/drain")
    async def outbox_drain(request: Request) -> Dict[str, Any]:
        admin_required(request)
        return {"ok": True, "result": await gw.eco.drain_outbox()}

    @app.delete("/api/v1/outbox/{outbox_id}")
    async def outbox_delete(outbox_id: int, request: Request) -> Dict[str, Any]:
        """Abandon a queued frame — a refund-free way to stop a wrong broadcast.

        Only a `queued` row can be dropped, and nothing is refunded because a queued
        frame was never charged (see :meth:`EcoService._deliver_frame`).
        """
        admin_required(request)
        changed = gw.db.execute(
            "UPDATE outbox SET status = 'abandoned', last_error = ? WHERE id = ? AND status = 'queued'",
            ("abandoned by console", int(outbox_id)),
        )
        return {"ok": int(changed or 0) > 0, "outbox_id": int(outbox_id)}

    @app.post("/api/v1/outbox/{outbox_id}/retry")
    async def outbox_retry(outbox_id: int, request: Request) -> Dict[str, Any]:
        admin_required(request)
        changed = gw.db.execute(
            "UPDATE outbox SET status = 'queued', attempts = 0, last_error = NULL WHERE id = ? AND status IN ('failed','abandoned')",
            int(outbox_id),
        )
        return {"ok": int(changed or 0) > 0, "outbox_id": int(outbox_id)}

    # ── settings ────────────────────────────────────────────────────────────

    @app.get("/api/v1/settings")
    async def settings_get(request: Request) -> Dict[str, Any]:
        admin_required(request)
        return {"ok": True, "settings": {key: gw.db.get_setting(key) for key in SETTINGS_ALLOWLIST}}

    @app.put("/api/v1/settings/{key}")
    async def settings_put(key: str, request: Request) -> Dict[str, Any]:
        admin_required(request)
        if key not in SETTINGS_ALLOWLIST:
            raise bad_request("setting_not_editable", "%r is not one of %s" % (key, sorted(SETTINGS_ALLOWLIST)))
        body = await json_body(request)
        if "value" not in body:
            raise bad_request("value_required")
        value = body["value"]
        expected = SETTINGS_ALLOWLIST[key]
        if expected is bool:
            value = bool(value) if not isinstance(value, str) else value.strip().lower() in ("1", "true", "yes", "on")
        elif expected is str:
            value = str(value)[:2000]
        gw.db.set_setting(key, value)
        if key == SETTING_AUTO_ACCEPT:
            gw.db.execute("UPDATE service_identity SET auto_accept = ?, updated_at_ms = ? WHERE id = 1",
                          (1 if value else 0, now_ms()))
        return {"ok": True, "key": key, "value": gw.db.get_setting(key)}

    # ── data lifecycle and compute ──────────────────────────────────────────

    @app.get("/api/v1/data-lifecycle/policies")
    async def data_lifecycle_policies(request: Request) -> Dict[str, Any]:
        """The three built-in retention modes plus any operator policies.

        Built-ins are virtual constants, so this endpoint never writes a row just
        because somebody looked.
        """
        admin_required(request)
        return {"ok": True, "policies": lifecycle_policy.list_policies(gw.db),
                "modes": list(lifecycle_policy.MODES)}

    @app.put("/api/v1/data-lifecycle/policies/{policy_id}")
    async def data_lifecycle_policy_put(policy_id: str, request: Request) -> Dict[str, Any]:
        admin_required(request)
        body = await json_body(request)
        body["policy_id"] = policy_id
        try:
            stored = lifecycle_policy.upsert_policy(gw.db, policy_id, body)
        except ValueError as exc:
            raise bad_request("policy_invalid", str(exc)) from exc
        return {"ok": True, "policy": stored}

    @app.post("/api/v1/data-lifecycle/erase")
    async def data_lifecycle_erase(request: Request) -> Dict[str, Any]:
        """Erase one task, one workspace, or everything already expired."""
        admin_required(request)
        body = await json_body(request)
        try:
            result = lifecycle_cleanup.erase_request(
                gw.db,
                gw.data_lifecycle_broker,
                body,
                principal=request_principal(request),
                temp_area=gw.data_lifecycle_temp,
            )
        except ValueError as exc:
            raise bad_request("erase_invalid", str(exc)) from exc
        return {"ok": True, "result": result}

    @app.post("/api/v1/compute/allocate")
    async def compute_allocate(request: Request) -> Dict[str, Any]:
        """Default deny: a policy, a healthy node, a granted capability and the
        user's explicit approval, or no allocation. Every refusal is audited."""
        admin_required(request)
        body = await json_body(request)
        decision = compute_authorizer.authorize_allocation(
            gw.db, body, principal=request_principal(request)
        )
        if not decision["allowed"]:
            raise GatewayError(decision["status_code"], decision["reason"], decision["detail"])
        return {"ok": True, "decision": decision}

    @app.get("/api/v1/compute/nodes")
    async def compute_nodes(request: Request) -> Dict[str, Any]:
        admin_required(request)
        return {"ok": True, "nodes": compute_registry.list_nodes(gw.db)}

    @app.post("/api/v1/compute/nodes/{node_id}/heartbeat")
    async def compute_node_heartbeat(node_id: str, request: Request) -> Dict[str, Any]:
        """A heartbeat refreshes an existing node; it never registers one."""
        admin_required(request)
        body = await json_body(request)
        try:
            node = compute_registry.heartbeat(
                gw.db, node_id, capabilities=body.get("capabilities")
            )
        except ValueError as exc:
            raise bad_request("node_invalid", str(exc)) from exc
        if node is None:
            raise not_found("node_not_registered",
                            "node %r is not registered with this gateway" % node_id)
        return {"ok": True, "node": node}

    @app.post("/api/v1/compute/workspaces/{workspace_id}/cleanup")
    async def compute_workspace_cleanup(workspace_id: str, request: Request) -> Dict[str, Any]:
        admin_required(request)
        try:
            result = compute_registry.cleanup_workspace(
                gw.db, workspace_id, principal=request_principal(request)
            )
        except ValueError as exc:
            raise bad_request("workspace_invalid", str(exc)) from exc
        return {"ok": True, "result": result}

    # ── diagnostics ─────────────────────────────────────────────────────────

    @app.get("/api/v1/diagnostics")
    async def diagnostics(request: Request) -> Dict[str, Any]:
        """Schema health plus the counters that distinguish "nothing sent" from "nothing understood"."""
        admin_required(request)
        return {
            "ok": True,
            "integrity": gw.db.integrity_report(),
            "bridge": gw.bridge.state(),
            "outbox": gw.eco.outbox_stats(),
            "config": {
                "gateway_host": gw.config.gateway_host,
                "gateway_port": gw.config.gateway_port,
                "node_ws_url": gw.config.node.ws_url,
                "public_base_url": gw.config.public_base_url,
                "plugins": {spec.toggle: bool(getattr(gw.config.plugins, spec.toggle)) for spec in PLUGIN_SPEC},
                "warnings": list(getattr(gw.config, "warnings", []) or []),
            },
        }

    # The last thing that happens to the route table is the check on it, so every
    # launch path — `uvicorn app.main:create_app`, `python -m app.main`, a test
    # client built straight on this function — refuses an unguarded endpoint. The
    # server never binds on a table that would hand a stranger the credit balance.
    assert_routes_are_gated()
    return app


# ─────────────────────────────────────────────────────────────────────────────
# 6b. The route table, readable without FastAPI installed
# ─────────────────────────────────────────────────────────────────────────────

#: The only routes that answer without `X-Admin-Token`, and why each is allowed to:
#: `/healthz` carries no data, `/` is the static console shell, `/h5` and
#: `/api/v1/verifyH5Auth` authenticate the caller with the per-follower H5 HMAC,
#: and `/api/v1/workflows/trigger` authenticates with a scoped workflow token that
#: an operator mints and can revoke. Anything added here is a decision to publish,
#: so it is written out.
PUBLIC_ROUTE_KEYS = frozenset(
    {
        ("GET", "/healthz"),
        ("GET", "/"),
        ("GET", "/h5/{article_id}"),
        ("POST", "/api/v1/verifyH5Auth"),
        ("POST", "/api/v1/workflows/trigger"),
    }
)


def route_census() -> List[Dict[str, Any]]:
    """Every `@app.<verb>(path)` inside :func:`create_app`, read off its AST.

    This parses the source instead of importing it on purpose: FastAPI is not
    installed on a fresh checkout, and neither is a running node, but the question
    "is every admin route guarded" has to be answerable there too — that is exactly
    where the table is being edited.
    """
    tree = ast.parse(textwrap.dedent(inspect.getsource(create_app)))
    found: List[Dict[str, Any]] = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for decorator in node.decorator_list:
            if not (isinstance(decorator, ast.Call) and isinstance(decorator.func, ast.Attribute)):
                continue
            target = decorator.func
            if not (isinstance(target.value, ast.Name) and target.value.id == "app"):
                continue
            if target.attr in ("exception_handler", "middleware", "on_event"):
                continue
            verb = target.attr
            found.append(
                {
                    "verb": verb,
                    "path": decorator.args[0].value if decorator.args and isinstance(decorator.args[0], ast.Constant) else "",
                    "func": node.name,
                    "args": sorted({a.arg for a in node.args.args} | {a.arg for a in node.args.kwonlyargs}),
                    "admin": any(
                        isinstance(call, ast.Call) and getattr(call.func, "id", "") == "admin_required"
                        for call in ast.walk(node)
                    ),
                }
            )
    return found


# Names that are always available to an annotation without being imported here.
_ANNOTATION_BUILTINS = frozenset(dir(builtins))


def _annotation_names(node: ast.AST) -> Set[str]:
    """Every bare name an annotation expression mentions, `Dict[str, Any]` included.

    A subscript's *value* and every element of its slice are collected, because the
    unresolved half of a subscript fails exactly like an unresolved whole: FastAPI
    reads `Optional[Widget]` against the module globals and gets a NameError on
    `Widget`, not on `Optional`. A string annotation is parsed and walked too — it is
    the other spelling of the same runtime lookup, not a way out of it — and a string
    that is not a Python expression contributes nothing rather than raising, because
    this runs on the source of a file that may be mid-edit.
    """
    names: Set[str] = set()
    for child in ast.walk(node):
        if isinstance(child, ast.Name):
            names.add(child.id)
        elif isinstance(child, ast.Attribute):
            root: ast.AST = child
            while isinstance(root, ast.Attribute):
                root = root.value
            if isinstance(root, ast.Name):
                names.add(root.id)
        elif isinstance(child, ast.Constant) and isinstance(child.value, str):
            try:
                inner = ast.parse(child.value, mode="eval")
            except SyntaxError:
                continue
            names |= _annotation_names(inner)
    return names


def unresolvable_route_annotations(
    namespace: Optional[Mapping[str, Any]] = None, *, source: Optional[str] = None
) -> List[str]:
    """Annotation names FastAPI would fail to resolve, read off this file's AST.

    The defect this exists for is invisible to every other instrument in this file: a
    route whose annotation names `Request`, which is imported inside :func:`create_app`
    rather than at module scope, is still *registered*, still answers `route_census()`,
    still shows up in the console's API table — and returns 422 to every caller,
    because with `from __future__ import annotations` the name is only ever looked up
    in this module's globals, where it does not exist. Neither the no-wheel self-test
    nor a live `curl` of one endpoint says which routes are affected, so the answer is
    computed from the source instead: parse the handlers, collect the names they
    annotate with, subtract what this module can actually see.

    `namespace` exists for the controls — passing a namespace without `Request` is how
    the check proves it is looking at the real names and not always answering `[]`.
    """
    visible = dict(globals()) if namespace is None else dict(namespace)
    tree = ast.parse(
        source if source is not None else textwrap.dedent(inspect.getsource(create_app))
    )
    missing: Set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        if not _is_route_handler(node):
            continue
        annotations = [a.annotation for a in list(node.args.args) + list(node.args.kwonlyargs)]
        annotations = [a for a in annotations if a is not None]
        if node.returns is not None:
            annotations.append(node.returns)
        for annotation in annotations:
            missing |= {
                name
                for name in _annotation_names(annotation)
                if name not in visible and name not in _ANNOTATION_BUILTINS
            }
    return sorted(missing)


def _is_route_handler(node: ast.AST) -> bool:
    """Is this function decorated as an endpoint of `app` (route, handler or middleware)?"""
    if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
        return False
    for decorator in node.decorator_list:
        func = decorator.func if isinstance(decorator, ast.Call) else decorator
        if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
            if func.value.id in ("app", "router"):
                return True
    return False


def assert_routes_are_gated(routes: Optional[Sequence[Mapping[str, Any]]] = None) -> int:
    """Refuse a route table with an unauthenticated admin endpoint; return its size.

    Called by :func:`main` before the socket is bound, and by :func:`self_test`. The
    failure it exists for is the ordinary one — a new endpoint added with everything
    except the one `admin_required(request)` line — and the endpoints in this
    particular file mint credits, redeem vouchers and rotate channel keys, so the
    cost of that omission is not a bad read.
    """
    rows = list(routes) if routes is not None else route_census()
    leaked = sorted(
        "%s %s" % (str(r["verb"]).upper(), r["path"])
        for r in rows
        if not r["admin"] and (str(r["verb"]).upper(), str(r["path"])) not in PUBLIC_ROUTE_KEYS
    )
    blind = sorted(
        "%s %s" % (str(r["verb"]).upper(), r["path"])
        for r in rows
        if r["admin"] and "request" not in r["args"]
    )
    if leaked or blind:
        raise RuntimeError(
            "unguarded route(s): %s; guarded route(s) that cannot see `request`: %s"
            % (", ".join(leaked) or "none", ", ".join(blind) or "none")
        )
    return len(rows)


def mount_prefix(router_prefix: Any, spec_prefix: Any) -> str:
    """The prefix :func:`create_app` passes to `include_router` for one plugin.

    `""` means "the router already carries the mount table's prefix, add nothing".
    A router is built two ways in this suite and both have to keep working:
    `ai_agent`/`privacy_sso` declare a bare `APIRouter()` and expect the gateway to
    prefix it, `alert_ops`/`polls`/`web3_bridge` declare
    `APIRouter(prefix=deps.spec.url_prefix)` so that starting the plugin module on its
    own answers at the documented URL. `include_router` concatenates its `prefix` with
    the prefix the router already carries, so the unconditional form moved those three
    plugins' every route under a second copy of its own prefix —
    `POST /api/v1/plugins/web3/api/v1/plugins/web3/watchers` — which no launcher, no
    `.env.example` and no alerting tool was written for. The mount table stays the
    source of truth: a router that does not name it is still prefixed by it.
    """
    carried = str(router_prefix or "").rstrip("/")
    wanted = str(spec_prefix or "").rstrip("/")
    return "" if carried == wanted else str(spec_prefix or "")


def plugin_route_paths() -> Dict[str, List[str]]:
    """Every plugin route, at the full path the mount loop will actually serve it at.

    Read off the source, not off built routers, for the same reason as
    :func:`route_census`: the machine that needs this answered is the one where
    FastAPI is not installed, which is where the mount table gets edited. The result
    is what makes the two things that went wrong here checkable at all — a doubled
    prefix and a route order that let the gateway's generic plugin-status route answer
    instead of the plugin's own.

    A plugin whose module cannot be imported, whose `create_router` is missing or
    whose prefix expression cannot be evaluated yields an empty list, which the
    calling check treats as a failure rather than as "no routes".
    """
    import importlib

    out: Dict[str, List[str]] = {}
    for spec in PLUGIN_SPEC:
        paths: List[str] = []
        try:
            module = importlib.import_module(spec.module_name)
            tree = ast.parse(textwrap.dedent(inspect.getsource(module.create_router)))
        except Exception:  # noqa: BLE001 — the empty list is the failure signal
            out[spec.plugin_id] = paths
            continue
        declared = _declared_router_prefix(tree, module, spec)
        if declared is None:
            out[spec.plugin_id] = []
            continue
        carried = _join_path(mount_prefix(declared, spec.url_prefix), declared)
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            for decorator in node.decorator_list:
                if not (isinstance(decorator, ast.Call) and isinstance(decorator.func, ast.Attribute)):
                    continue
                if decorator.func.attr not in ("get", "post", "put", "patch", "delete"):
                    continue
                if not decorator.args or not isinstance(decorator.args[0], ast.Constant):
                    continue
                verb = str(decorator.func.attr).upper()
                paths.append("%s %s" % (verb, _join_path(carried, str(decorator.args[0].value))))
        out[spec.plugin_id] = sorted(paths)
    return out


#: The routes the console reaches by navigation instead of by `fetch`: `GET /` is the
#: document the browser already holds, and `GET /h5/{article_id}` is opened as a link so
#: the follower's phone renders the signed page. They belong to the console's `LINKS`
#: table rather than its `API` table, and the check below requires the two lists to
#: agree — an exemption list that can only be widened is not a check.
CONSOLE_NAVIGATION_ONLY: Tuple[str, ...] = ("GET /", "GET /h5/{article_id}")

#: Two decorators, one handler: the alert list is registered at both
#: `/api/v1/plugins/alerts` and `/api/v1/plugins/alerts/` (see
#: `plugins/alert_ops_plugin.py`, `@router.get("")` above `@router.get("/")`) so a
#: `curl` with or without the trailing slash reaches the same rows. The console calls
#: one spelling, and this is what keeps the coverage check from demanding a second
#: button for the same handler. An alias only excuses its own route when the route it
#: stands for is actually reachable, so this table cannot hide a handler with no panel.
CONSOLE_ROUTE_ALIASES: Dict[str, str] = {
    "GET /api/v1/plugins/alerts/": "GET /api/v1/plugins/alerts",
}


def _console_block(source: str, name: str) -> str:
    """The body of one `var NAME = { … };` table in the console.

    Anchored on a closing brace at column zero, which is how both tables are written:
    a regex over the whole file would absorb any other literal that happens to hold a
    `["GET", "/…"]` pair, and a check that reads the wrong table reads nothing.
    """
    found = re.search(r"\bvar %s = \{(.*?)^\};" % re.escape(name), source, re.MULTILINE | re.DOTALL)
    return found.group(1) if found else ""


def _console_pair_table(source: str, name: str) -> Dict[str, Tuple[str, str]]:
    """`{key: (VERB, path)}` for one console route table.

    The console writes every route as a literal — `["GET", "/api/v1/status"]`, never an
    assembled path — precisely so this can read it without a JavaScript engine. A table
    built by concatenation would be invisible here, which is the drift these checks
    exist to catch.
    """
    out: Dict[str, Tuple[str, str]] = {}
    for key, verb, path in re.findall(
        r'^[ \t]*([A-Za-z]\w*):[ \t]*\["(GET|POST|PUT|PATCH|DELETE)",[ \t]*"(/[^"]*)"\]',
        _console_block(source, name),
        re.MULTILINE,
    ):
        out[key] = (verb, path)
    return out


def console_api_table(source: str) -> Dict[str, Tuple[str, str]]:
    """The console's `fetch` table: one entry per route it calls."""
    return _console_pair_table(source, "API")


def console_link_table(source: str) -> Dict[str, Tuple[str, str]]:
    """The console's navigation table: routes opened as links rather than called."""
    return _console_pair_table(source, "LINKS")


def console_call_sites(source: str) -> List[str]:
    """Every `call("key", …)` the console makes, repeats included.

    A typo here is the failure mode this is for: `call("cardList")` when the table says
    `cards` throws inside the view, which reads to the operator as a panel that simply
    never fills in rather than as a missing route.
    """
    return re.findall(r'\bcall\("([A-Za-z]\w*)"', source)


def console_link_sites(source: str) -> List[str]:
    """Every navigation key the console resolves through `pageUrl` / `linkTo`."""
    return re.findall(r'\b(?:pageUrl|linkTo)\("([A-Za-z]\w*)"', source)


def console_quoted_words(source: str) -> set:
    """Every identifier the console writes as a string literal.

    A table entry is *used* when its key appears here: `call("contacts")` cites it in
    place, and `pluginHeader("web3", "web3Status")` cites it to hand the key to a
    helper that calls it later. Counting only literal `call("…")` sites would call the
    second one dead and push the console towards repeating fetch code everywhere just
    to satisfy the instrument. Declarations do not appear here — the table writes
    `web3Status:` unquoted — so an entry with no citation anywhere is genuinely unused.
    """
    return set(re.findall(r'"([A-Za-z]\w*)"', source))


def console_drift_checks(source: str, server_routes: Sequence[str]) -> Dict[str, bool]:
    """Compare the console's two route tables against the gateway's own instruments.

    Both directions are answered here because they fail differently. A table entry the
    server does not serve is a button that 404s; a served route missing from the table
    is an operator who cannot reach the feature at all, which is the silence that gets
    reported a week later as "the backend has no way to do X". The server side comes
    from :func:`route_census` and :func:`plugin_route_paths`, so this cannot disagree
    with what the gateway believes it mounted.
    """
    api = console_api_table(source)
    links = console_link_table(source)
    served = set(server_routes)
    declared = set("%s %s" % pair for pair in list(api.values()) + list(links.values()))
    called = set(console_call_sites(source))
    linked = set(console_link_sites(source))
    unreachable = set()
    for route in sorted(served - declared):
        stands_for = CONSOLE_ROUTE_ALIASES.get(route)
        if stands_for is not None and stands_for in declared:
            continue
        unreachable.add(route)
    return {
        "console_publishes_a_nonempty_call_table": len(api) > 0,
        "console_calls_no_route_the_gateway_does_not_serve": not (declared - served),
        "every_registered_route_is_reachable_from_the_console": not unreachable,
        "every_console_call_names_a_table_entry": called <= set(api),
        "every_console_table_entry_is_cited_by_code": not (set(api) - console_quoted_words(source)),
        "every_console_link_is_used": set(links) == linked,
        "console_navigation_routes_are_exactly_the_declared_ones": (
            set("%s %s" % pair for pair in links.values()) == set(CONSOLE_NAVIGATION_ONLY)
        ),
    }


ORACLE_RELPATH = "official_tools/swift_crypto_oracle.swift"
# The three modules whose sealed-channel verification stops being verification when the
# `cryptography` wheel is absent, and which therefore have to say where the other half
# of the proof lives. `official_tools/gen_voucher.py` also gates on the wheel
# (`gen_voucher.py:466`), but for the voucher's Ed25519-over-canonical-JSON format,
# which this oracle does not cover — so it is deliberately not in this list, and the
# check below is about the envelope rather than about every crypto path in the suite.
CRYPTO_GATE_MODULES: Tuple[str, ...] = (
    "gateway/app/crypto_service.py",
    "gateway/app/billing_service.py",
    "gateway/app/main.py",
)
# A citation is a PATH: the filename alone appears in the README's directory tree, where
# it names the file rather than promising a location, and reading it as a broken promise
# would make the check fire on the one artifact that cannot be wrong.
ORACLE_CITATION = re.compile(r"[A-Za-z0-9_./-]+/swift_crypto_oracle\.swift")
# The text this suite ships. A citation in any of these files is a promise the operator
# can act on, so the census covers all of them rather than only the module that needs
# the answer.
ORACLE_CENSUS_FILES: Tuple[str, ...] = (
    "gateway/app/main.py",
    "gateway/app/crypto_service.py",
    "gateway/app/billing_service.py",
    "gateway/app/agent_bridge.py",
    "gateway/app/config.py",
    "official_tools/gen_voucher.py",
    "README.md",
    "README.en.md",
    "start_macos.sh",
    "install_ubuntu22.sh",
    "install_macos.sh",
    "docker-compose.yml",
    "gateway/Dockerfile",
)


def oracle_citations(suite_root: Path) -> Dict[str, str]:
    """`{shipped file: the oracle path it names}` for one checkout."""
    found: Dict[str, str] = {}
    for relpath in ORACLE_CENSUS_FILES:
        candidate = suite_root / relpath
        if not candidate.is_file():
            continue
        named = set(ORACLE_CITATION.findall(candidate.read_text(encoding="utf-8")))
        if named:
            found[relpath] = ";".join(sorted(named))
    return found


def oracle_agreement_checks(
    cited: Sequence[str], shipped: bool, citers: Sequence[str]
) -> Dict[str, bool]:
    """Pure form of the rule, so the controls below can feed it a stale path.

    `shipped` and `citers` are arguments rather than reads because a check that can
    only see the real tree can never be shown to fail, and an instrument that cannot
    fail is not evidence of anything. `citers` is keyed on the modules that refuse to
    verify the sealed channel at all without this oracle, which is why a fourth
    mention in a README cannot substitute for a missing one in `crypto_service`.
    """
    named = set(cited)
    return {
        "the_crypto_oracle_ships_beside_the_voucher_tool": shipped,
        "the_crypto_oracle_is_cited_by_the_modules_that_need_it": bool(named),
        "every_crypto_oracle_citation_names_a_shipped_path": named <= {ORACLE_RELPATH},
        "every_envelope_module_that_gates_on_the_wheel_names_the_oracle": (
            set(CRYPTO_GATE_MODULES) <= set(citers)
        ),
    }


def _declared_router_prefix(tree: ast.AST, module: Any, spec: Any) -> Optional[str]:
    """Resolve the `prefix=` of the `APIRouter(...)` inside one `create_router`.

    Three spellings exist across the nine plugins and all three mean the mount table's
    value: a literal (`ai_agent_plugin.py:URL_PREFIX`), `deps.spec.url_prefix`, and
    `_router_prefix(deps)`, which returns `spec.url_prefix` for its own plugin id. A
    prefix this function cannot evaluate returns `None`, because guessing here would
    make the doubled-path check pass by construction.
    """
    for node in ast.walk(tree):
        if not (isinstance(node, ast.Call) and getattr(node.func, "id", "") == "APIRouter"):
            continue
        for keyword in node.keywords:
            if keyword.arg != "prefix":
                continue
            value = keyword.value
            if isinstance(value, ast.Constant):
                return str(value.value or "")
            if isinstance(value, ast.Name):
                mirror = getattr(module, value.id, None)
                return str(mirror) if isinstance(mirror, str) else None
            dumped = ast.dump(value)
            if "url_prefix" in dumped or "_router_prefix" in dumped:
                return str(spec.url_prefix or "")
            return None
        return ""
    return None


def _join_path(prefix: str, path: str) -> str:
    """`/api/v1/plugins/ai` + `/status` -> `/api/v1/plugins/ai/status`, and `/x` + ``."""
    left = str(prefix or "").rstrip("/")
    right = str(path or "")
    if not right:
        return left or "/"
    if not right.startswith("/"):
        right = "/" + right
    return (left + right) or "/"


# ─────────────────────────────────────────────────────────────────────────────
# 7. Self-test (stdlib only — no FastAPI, no `cryptography`, no node)
#
#    The rule this suite tests against is the one the whole file exists to obey:
#    a frame the iOS client will not render must never be charged for, and a
#    charge must never survive a refused send. Everything below runs on a Python
#    with no third-party wheels installed, which is the only way it can be run at
#    all before `install_ubuntu22.sh` has put the wheels in place.
# ─────────────────────────────────────────────────────────────────────────────


class FakeBridge:
    """The node, as far as this file cares: accepts text, reports a state.

    `fail` raises from every command to prove the refund and the "node is down"
    paths; `connected` toggles between the live and the outbox path. It stands in
    for :class:`AgentBridge`, not for the node's wire format — the command JSON is
    pinned by `agent_bridge.self_test`, which is the only place that can be.
    """

    def __init__(self) -> None:
        self.sent: List[Tuple[int, str]] = []
        self.connected = True
        self.fail: Optional[BaseException] = None
        self.user_id = 7
        self.contact_address = "https://smp1.popopx.test/a#service-account"
        self.accepted: List[int] = []

    async def send_text(self, contact_id: int, text: str, **_kwargs: Any) -> Dict[str, Any]:
        if self.fail is not None:
            raise self.fail
        self.sent.append((int(contact_id), text))
        return {"ok": True}

    async def accept_contact(self, contact_request_id: int) -> Dict[str, Any]:
        if self.fail is not None:
            raise self.fail
        self.accepted.append(int(contact_request_id))
        return {"contact_id": 42, "display_name": "Ada"}

    async def list_contacts(self) -> List[Dict[str, Any]]:
        if self.fail is not None:
            raise self.fail
        return [{"contact_id": 42, "display_name": "Ada"}, {"chats": {"contact": {"contact_id": 43}}}]

    async def show_contact_address(self) -> str:
        return self.contact_address

    async def create_contact_address(self, **_kwargs: Any) -> str:
        self.contact_address = "https://smp1.popopx.test/a#rotated"
        return self.contact_address

    async def set_profile(self, display_name: str, full_name: str = "", **_kwargs: str) -> Dict[str, Any]:
        return {"ok": True, "display_name": display_name}

    def state(self) -> Dict[str, Any]:
        return {"connected": self.connected, "user_id": self.user_id, "contact_address": self.contact_address}

    async def start(self) -> None:
        self.connected = True

    async def stop(self) -> None:
        self.connected = False


def _fake_config(tmpdir: str) -> Config:
    """A real :class:`Config`, built through :func:`load_config`.

    The test writes a `.env` rather than constructing `Config()` because every
    field of that dataclass is required and each has a rule the *gateway* has to
    agree with — an admin token shorter than 24 chars or a missing public origin
    must fail at load time, and a hand-built Config would test neither.
    """
    import os

    env = Path(tmpdir) / "test.env"
    env.write_text(
        "\n".join(
            [
                "POPOPX_ADMIN_TOKEN=" + "t" * 32,
                "POPOPX_PUBLIC_BASE_URL=https://eco.example.test/",
                "POPOPX_H5_SERVER_SECRET=" + "s" * 48,
                "POPOPX_DB_PATH=" + str(Path(tmpdir) / "gateway-test.sqlite3"),
                "POPOPX_SERVICE_ID=popopx.test",
                "POPOPX_SERVICE_NAME=POPOPX Test",
                "POPOPX_SERVICE_FULL_NAME=POPOPX Test Service",
                # The wheel is absent on the machine that runs this suite, so no
                # code path may reach an Ed25519 verify; the ledger is driven
                # directly instead of by a minted activation code.
                "POPOPX_BILLING_REQUIRE_VOUCHER=0",
                "POPOPX_OFFICIAL_ED25519_PUBLIC_KEY=",
                "POPOPX_NODE_WS_URL=ws://127.0.0.1:5225",
                "POPOPX_PLUGIN_WEB3_BRIDGE=1",
                "POPOPX_LOG_LEVEL=ERROR",
                "",
            ]
        ),
        encoding="utf-8",
    )
    saved = {k: v for k, v in list(os.environ.items()) if k.startswith("POPOPX_")}
    for key in saved:
        del os.environ[key]
    try:
        config = load_config(env)
    finally:
        os.environ.update(saved)
    return config


def _fake_identity() -> Tuple[bytes, bytes]:
    """A stand-in Ed25519 keypair: 32 bytes each, which is all `seal_envelope`'s
    replacement in this suite checks. The real one needs the `cryptography` wheel,
    and the *shape* of the identity is what the SQL and the epoch bookkeeping
    depend on."""
    return bytes(range(32)), bytes(range(32, 64))


def _fake_seal(channel_id: str, epoch: int, sealing_key: bytes, plaintext: bytes, *_rest: Any) -> Dict[str, Any]:
    """Stand in for :func:`seal_envelope`, and record what it was asked to seal with.

    The real sealing needs the `cryptography` wheel, so this suite cannot check the
    bytes — but the one property the whole rotation model turns on is *which key*
    goes into the box: the member's installed epoch, never the epoch being
    delivered. Recording the arguments makes that an assertion instead of a comment.
    """
    _fake_seal.calls.append(  # type: ignore[attr-defined]
        {"channel_id": channel_id, "epoch": int(epoch), "sealing_key": sealing_key, "plaintext": plaintext}
    )
    return {
        "protocol": "popopx.channel.enc.v1",
        "epoch": int(epoch),
        "nonce": "AAECAwQFBgcICQoL",
        "ciphertext": b64_url(plaintext),
        "signature": "A" * 86,
    }


_fake_seal.calls = []  # type: ignore[attr-defined]


def self_test() -> List[str]:
    """Returns the list of passed check names; raises `AssertionError` on the first failure."""
    import importlib.util
    import tempfile

    # Opaque invite links are the one protocol surface that cannot be faked here:
    # `invite_link` seals with the real ChaCha20-Poly1305. On an interpreter
    # without the wheel the contract is that it names the missing dependency
    # (`invite_crypto_unavailable`) instead of inventing a link, so the checks
    # below assert that degraded answer rather than skipping the semantics. The
    # codec and HTTP groups, which prove the bytes end to end, are gated on the
    # same wheel and say so on their own SKIPPED line.
    crypto_ready = importlib.util.find_spec("cryptography") is not None

    checks: List[str] = []

    def check(name: str, condition: bool) -> None:
        if not condition:
            raise AssertionError("self_test failed: %s" % name)
        checks.append(name)

    def raises(name: str, error: Any, call: Callable[[], Any]) -> None:
        try:
            call()
        except error:
            checks.append(name)
            return
        except Exception as exc:  # noqa: BLE001
            raise AssertionError("%s raised %s (%s), expected %s" % (name, type(exc).__name__, exc, error)) from exc
        raise AssertionError("%s did not raise %s" % (name, error))

    def invite_degraded(payload: Dict[str, Any], field: str = "invite_link") -> bool:
        """The only legal answer without the wheel: no link, and the reason named."""
        return (
            not crypto_ready
            and payload.get(field) is None
            and payload.get(field + "_error") == "invite_crypto_unavailable"
        )

    def invite_info_degraded(info: Dict[str, Any]) -> bool:
        """The same contract for :meth:`EcoService.invite_link`'s own result shape."""
        return (
            not crypto_ready
            and info.get("link") is None
            and info.get("error") == "invite_crypto_unavailable"
        )

    # ── 1. pure helpers ─────────────────────────────────────────────────────

    card_id = new_id("card")
    check("new_id_within_client_budget", len(card_id) <= EcoLimits.card_id_chars - 12)
    check("new_id_prefixed", card_id.startswith("card_"))
    raises("new_id_rejects_bad_prefix", ValueError, lambda: new_id("Card"))
    check("normalize_base_url_trims", normalize_base_url("https://a.test//") == "https://a.test")
    raises("normalize_base_url_rejects_ftp", ValueError, lambda: normalize_base_url("ftp://a.test"))
    raises("normalize_base_url_rejects_empty", ValueError, lambda: normalize_base_url("   "))

    # A monotonic `ut` is the difference between an update and a dropped update.
    same = 1_700_000_000_000
    check("next_monotonic_ms_advances_within_the_same_millisecond", next_monotonic_ms(same, same) == same + 1)
    check("next_monotonic_ms_uses_the_clock_when_ahead", next_monotonic_ms(same - 10, same) == same)
    check("next_monotonic_ms_accepts_none", next_monotonic_ms(None, same) == same)

    derived_a = card_id_for_recipient("broadcast_1", 11)
    derived_b = card_id_for_recipient("broadcast_1", 12)
    check("derived_card_ids_are_stable", derived_a == card_id_for_recipient("broadcast_1", 11))
    check("derived_card_ids_differ_per_follower", derived_a != derived_b)
    long_base = "x" * EcoLimits.card_id_chars
    check("derived_card_id_never_exceeds_the_client_limit", len(card_id_for_recipient(long_base, 999_999)) <= EcoLimits.card_id_chars)
    check("like_prefix_escapes_the_separator", like_prefix("a_b") == "a\\_b%")
    check("like_prefix_escapes_a_wildcard", like_prefix("a%b") == "a\\%b%")

    routes = route_census()
    keys = sorted("%s %s" % (str(row["verb"]).upper(), row["path"]) for row in routes)
    check("the_route_census_reads_the_real_table", len(routes) > 40)
    check("no_verb_and_path_is_registered_twice", len(keys) == len(set(keys)))
    check("every_api_path_is_under_api_v1",
          all(key.split(" ", 1)[1].startswith("/api/v1/") for key in keys if " /api/" in key))
    check("the_public_routes_are_exactly_the_documented_five",
          sorted(("%s %s" % (str(row["verb"]).upper(), row["path"]))
                 for row in routes if not row["admin"])
          == sorted("%s %s" % (verb, path) for verb, path in PUBLIC_ROUTE_KEYS))
    check("assert_routes_are_gated_accepts_the_table", assert_routes_are_gated() == len(routes))
    raises("the_gate_rejects_an_unguarded_admin_route", RuntimeError,
           lambda: assert_routes_are_gated(
               [{"verb": "post", "path": "/api/v1/billing/grant", "admin": False, "args": ["body"]}]
           ))
    raises("the_gate_rejects_a_guard_that_cannot_see_the_request", RuntimeError,
           lambda: assert_routes_are_gated(
               [{"verb": "get", "path": "/api/v1/cards", "admin": True, "args": ["limit"]}]
           ))

    # Annotation resolution, which no amount of AST route reading can see: a handler
    # whose annotation names a locally-imported class registers, is counted, and 422s.
    unresolved = unresolvable_route_annotations()
    if unresolved:  # the names are the whole diagnosis; a bare check name is not
        raise AssertionError("self_test failed: no_route_annotation_name_is_unresolvable: %s" % ", ".join(unresolved))
    check("no_route_annotation_name_is_unresolvable", unresolved == [])
    check("the_annotation_probe_reads_the_real_handlers",
          len(unresolvable_route_annotations(namespace={})) > 3 and
          len(unresolvable_route_annotations(namespace={"Request": Any})) <
          len(unresolvable_route_annotations(namespace={})))
    check("the_annotation_probe_recognises_request_as_resolvable_now",
          "Request" not in unresolved)
    check("the_annotation_probe_names_what_it_cannot_see",
          "Request" in unresolvable_route_annotations(namespace={
              name: value for name, value in globals().items() if name != "Request"
          }))
    probe_ns = {"Dict": Dict, "Any": Any, "Optional": Optional}
    check("the_annotation_probe_looks_inside_a_subscript",
          unresolvable_route_annotations(namespace=probe_ns, source=(
              "def create_app():\n"
              "    @app.get('/x')\n"
              "    async def handler(a: Optional[Widget]) -> Dict[str, Any]:\n"
              "        return {}\n"
          )) == ["Widget"])
    check("the_annotation_probe_looks_inside_a_quoted_annotation",
          unresolvable_route_annotations(namespace=probe_ns, source=(
              "def create_app():\n"
              "    @app.get('/x')\n"
              "    async def handler(a: 'Optional[Widget]') -> Dict[str, Any]:\n"
              "        return {}\n"
          )) == ["Widget"])
    check("the_annotation_probe_passes_a_builtin_only_signature",
          unresolvable_route_annotations(namespace={}, source=(
              "def create_app():\n"
              "    @app.get('/x')\n"
              "    async def handler(a: int) -> None:\n"
              "        return None\n"
          )) == [])
    check("an_unparsable_annotation_string_does_not_hang_the_probe",
          unresolvable_route_annotations(namespace=probe_ns, source=(
              "def create_app():\n"
              "    @app.get('/x')\n"
              "    async def handler(a: 'Optional[Widget') -> None:\n"
              "        return None\n"
          )) == [])

    # The liveness path is a contract with files this module cannot import: every
    # launcher curls it, and renaming it on one side alone leaves a gateway that is
    # healthy and reported dead. Assumes the repo layout (gateway/app/main.py, with
    # the launchers two levels up) — which is where this check has anything to say.
    suite_root = Path(__file__).resolve().parents[2]
    probed: set = set()
    advertised: set = set()
    launched_via_main = 0
    url_in_text = re.compile(r"https?://[^\s\"'<>)]*")
    for launcher in ("start_macos.sh", "install_macos.sh", "install_ubuntu22.sh", "docker-compose.yml"):
        candidate = suite_root / launcher
        if not candidate.exists():
            continue
        text = candidate.read_text(encoding="utf-8")
        if re.search(r"-m\s+app\.main", text):
            launched_via_main += 1
        for url in url_in_text.findall(text):
            path = re.sub(r"^https?://[^/]*", "", url).split("?")[0].rstrip("/") or "/"
            if path.startswith("/health"):
                probed.add(path)
        # Only the sentences that promise the operator somewhere to CLICK are
        # checked against the route table: a documentation URL in a systemd
        # `Documentation=` line is a reference to a website, not a claim that this
        # gateway serves a path, and treating it as one makes the check fire on
        # something that cannot be wrong.
        for line in text.splitlines():
            if not re.search(r"console|from your phone", line, re.I):
                continue
            for url in url_in_text.findall(line):
                path = re.sub(r"^https?://[^/]*", "", url).split("?")[0].rstrip("/") or "/"
                if not path.startswith("/health"):
                    advertised.add(path)
    check("every_launcher_probes_a_route_that_exists",
          bool(probed) and probed <= {str(row["path"]) for row in routes})
    check("every_launcher_advertises_a_console_that_responds",
          bool(advertised) and advertised <= {str(row["path"]) for row in routes})
    # Counted, not asserted equal to four: compose starts the container and the
    # container's CMD is this module, so only the three shell launchers can name the
    # entrypoint here. Requiring four would make the check fail for a reason that
    # has nothing to do with what it is measuring.
    check("every_shell_launcher_runs_the_module_entrypoint", launched_via_main == 3)

    # `launchctl bootout` is asynchronous. A `bootstrap` issued while launchd still holds
    # the label answers "Bootstrap failed: 5: Input/output error", which on a macOS
    # reinstall reads as a broken plist while the file on disk is fine — this was hit for
    # real, not in a test. The suite cannot call launchctl, so the gate is textual: inside
    # `bootstrap_job` the wait must sit between the bootout and the bootstrap that depends
    # on it, and the waiter must be bounded, because an unbounded one turns a rare failure
    # into an installer that never returns.
    macos_installer = suite_root / "install_macos.sh"
    installer_text = macos_installer.read_text(encoding="utf-8") if macos_installer.is_file() else ""
    job_body = re.search(r"^bootstrap_job\(\).*?^\}", installer_text, re.M | re.S)
    waiter_body = re.search(r"^wait_for_bootout\(\).*?^\}", installer_text, re.M | re.S)
    bootout_at = job_body.group(0).find("launchctl bootout") if job_body else -1
    wait_at = job_body.group(0).find("wait_for_bootout ") if job_body else -1
    bootstrap_at = job_body.group(0).find("launchctl bootstrap") if job_body else -1
    check("the_macos_installer_waits_for_bootout_before_bootstrapping",
          -1 < bootout_at < wait_at < bootstrap_at
          and bool(waiter_body) and "return 1" in waiter_body.group(0))

    # The plugin mount is the one part of the route table that `route_census` cannot
    # see — it reads `@app.<verb>` decorators inside this function, and a plugin's
    # routes arrive through `include_router` — so both of the defects below passed
    # every gate in this suite for a whole batch. These four checks are the missing
    # half of the census, and they are source-derived for the same reason: FastAPI is
    # not installed where they have to answer.
    check("mount_prefix_refuses_to_add_a_prefix_the_router_already_carries",
          mount_prefix("/api/v1/plugins/web3", "/api/v1/plugins/web3") == ""
          and mount_prefix("/api/v1/plugins/alerts/", "/api/v1/plugins/alerts") == "")
    # The other half of the same rule, and the control that keeps the check above
    # from passing because it matches everything: a router that carries nothing is
    # still put under the mount table's prefix, or two of the nine plugins would be
    # served at bare `/status` and `/sessions`.
    check("mount_prefix_still_prefixes_a_bare_router",
          mount_prefix("", "/api/v1/plugins/ai") == "/api/v1/plugins/ai"
          and mount_prefix(None, "/api/v1/plugins/sso") == "/api/v1/plugins/sso")
    mounted_routes = plugin_route_paths()
    check("every_plugin_publishes_routes_the_gateway_can_reach",
          all(len(mounted_routes.get(spec.plugin_id) or []) > 0 for spec in PLUGIN_SPEC))
    check("no_plugin_route_is_mounted_under_its_prefix_twice",
          all(path.count(str(spec.url_prefix)) == 1
              for spec in PLUGIN_SPEC
              for path in mounted_routes.get(spec.plugin_id) or []))
    check("every_plugin_route_starts_at_its_mount_table_prefix",
          all(path.split(" ", 1)[1].startswith(str(spec.url_prefix))
              for spec in PLUGIN_SPEC
              for path in mounted_routes.get(spec.plugin_id) or []))
    # Starlette dispatches to the first registration whose path and method match, and
    # this file declares a generic `GET /api/v1/plugins/{plugin_id}/status` that
    # pattern-matches `/api/v1/plugins/ai/status` and `…/web3/status` — the two routes
    # whose own `/status` bodies are the reason those panels exist. Registered in the
    # wrong order, the census above still shows a perfectly mounted gateway; only the
    # order answers differently.
    app_source = textwrap.dedent(inspect.getsource(create_app))
    check("the_gateway_declares_both_plugin_status_routes",
          "app.include_router(mounted.router" in app_source
          and '@app.get("/api/v1/plugins/{plugin_id}/status")' in app_source)
    check("a_plugin_route_is_not_shadowed_by_the_generic_plugin_status_route",
          app_source.index("app.include_router(mounted.router")
          < app_source.index('@app.get("/api/v1/plugins/{plugin_id}/status")'))

    # The same source text answers a second question: the app must be built with one
    # lifespan context manager rather than the two deprecated startup/shutdown hooks it
    # replaced. Those printed a DeprecationWarning on every boot, and an operator who
    # sees a warning on every launch stops reading warnings.
    check("the_app_is_built_with_a_lifespan_handler", "lifespan=_lifespan" in app_source)
    check("the_lifespan_closes_the_gateway_in_a_finally",
          app_source.index("await gw.start()")
          < app_source.index("finally:")
          < app_source.index("await gw.stop()"))
    # Decorators, not text: a comment that merely mentions the old hook must not be able
    # to fail this, and a real one coming back must.
    _app_tree = ast.parse(app_source)
    check("no_deprecated_startup_shutdown_hooks_are_registered", not any(
        isinstance(dec, ast.Call) and getattr(dec.func, "attr", "") == "on_event"
        for node in ast.walk(_app_tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        for dec in node.decorator_list))

    # The other half of that ordering: because a plugin router is mounted *first*, any
    # plugin whose own routes include a single-segment wildcard (`/{alert_id}`,
    # `/{poll_id}`) answers `GET <prefix>/status` with its wildcard's error — 404
    # `unknown_alert`, or 400 `poll_id_invalid` — and the console's panel for that
    # plugin is unreachable even though the gateway "has" a status route. The only
    # fix that survives the next wildcard is for every plugin to answer the path
    # itself, so that is what is asserted, per plugin, from the mount census.
    for spec in PLUGIN_SPEC:
        own_status = "GET %s/status" % spec.url_prefix
        check("plugin_%s_answers_status_at_its_own_prefix" % spec.plugin_id,
              own_status in set(mounted_routes.get(spec.plugin_id) or []))
    # Control: the census has to *see* the row it asserts on. Deleting it from a copy
    # changes the answer, which is what makes the per-plugin checks above non-vacuous.
    _polls_rows = set(mounted_routes.get("polls") or [])
    _polls_without_status = {row for row in _polls_rows if not row.endswith("/status")}
    check("the_status_census_can_miss_a_status_route",
          len(_polls_rows) > len(_polls_without_status)
          and "GET /api/v1/plugins/polls/status" in _polls_rows
          and "GET /api/v1/plugins/polls/status" not in _polls_without_status)

    # The console restates this route table in a language this file cannot import, so
    # the restatement drifts unless something compares them. Both directions are
    # checked: a path the gateway does not serve is a button that 404s in the operator's
    # face, and a served route with no console entry is a feature that cannot be reached
    # at all — the second one is invisible until somebody asks why the backend "has no
    # way" to do it. Each check is followed by the defect it is supposed to catch.
    console_file = STATIC_DIR / "index.html"
    check("the_console_ships_next_to_the_gateway", console_file.is_file())
    console_source = console_file.read_text(encoding="utf-8")
    check("the_console_leads_with_its_licence", console_source.startswith(
        "<!--\n  Copyright (c) 2026 POPOPX (popopx.chat)\n"
        "  SPDX-License-Identifier: AGPL-3.0-only\n-->"))

    # The console restates the client's menu ceilings in JavaScript because an operator
    # needs to be stopped before the save, not after. Two restatements drift unless
    # somebody compares them, and a ceiling that only exists in one of the two files is a
    # menu the operator can build and the phone refuses to draw — so each menu ceiling is
    # read out of `LIMITS` and matched against `EcoLimits`, one check per name.
    for _limit_name in ("max_menu_items", "max_menu_subitems", "max_menu_title_chars"):
        _js = re.search(r"\b%s:\s*(\d+)" % _limit_name, console_source)
        check("console_menu_limit_%s_matches_the_gateway" % _limit_name,
              _js is not None and int(_js.group(1)) == getattr(EcoLimits, _limit_name))
    # Control for the three checks above: the same extraction against a name the console
    # does not publish has to come back empty, otherwise a failed regex would pass silently.
    _js_absent = re.search(r"\bmax_menu_nonesuch:\s*(\d+)", console_source)
    check("the_console_limit_extractor_can_come_up_empty", _js_absent is None)
    # The console has no "+子项" button below the first level, but a wire value pasted or
    # edited into `sub` can still be three deep, and the server refuses that; the panel has
    # to say so, or the operator sees a save error with no pre-save warning.
    check("the_console_names_the_two_level_ceiling",
          "menuProblems" in console_source and "子菜单只到第二级" in console_source)
    served_routes = sorted(
        {"%s %s" % (str(row["verb"]).upper(), row["path"]) for row in routes}
        | {line for paths in mounted_routes.values() for line in paths}
    )
    drift = console_drift_checks(console_source, served_routes)
    check("the_console_drift_suite_runs_every_check", len(drift) == 7)
    for drift_name, drift_passed in sorted(drift.items()):
        check(drift_name, drift_passed)

    def console_edited(before: str, after: str) -> str:
        """One deliberate defect in the console source, for the controls below.

        The miss check is the point: `str.replace` answers with the original text, so a
        control whose anchor has been reworded would report a defect-free file and call
        the check sharp when it has gone blunt.
        """
        mutated = console_source.replace(before, after, 1)
        if mutated == console_source:
            raise AssertionError("the console control edits %r, which is not in index.html" % before)
        return mutated

    check("the_drift_suite_notices_an_empty_call_table",
          console_drift_checks(console_edited("var API = {", "var APIx = {"), served_routes)
          ["console_publishes_a_nonempty_call_table"] is False)
    check("the_drift_suite_notices_a_route_the_console_invented",
          console_drift_checks(
              console_edited("var API = {", 'var API = {\n  phantom: ["GET", "/api/v1/phantom"],'),
              served_routes)["console_calls_no_route_the_gateway_does_not_serve"] is False)
    check("the_drift_suite_notices_a_route_with_no_panel",
          console_drift_checks(console_source, served_routes + ["GET /api/v1/a_route_with_no_panel"])
          ["every_registered_route_is_reachable_from_the_console"] is False)
    check("the_drift_suite_notices_a_typo_in_a_call_site",
          console_drift_checks(
              console_edited("function showShell() {", 'function showShell() {\n  call("noSuchKey");'),
              served_routes)["every_console_call_names_a_table_entry"] is False)
    check("the_drift_suite_notices_a_table_entry_nothing_reads",
          console_drift_checks(
              console_edited('pluginHeader("web3", "web3Status")', 'pluginHeader("web3", null)'),
              served_routes)["every_console_table_entry_is_cited_by_code"] is False)
    check("the_drift_suite_notices_a_navigation_entry_nothing_opens",
          console_drift_checks(console_edited('linkTo("h5"', 'linkTo("nope"'), served_routes)
          ["every_console_link_is_used"] is False)
    check("the_drift_suite_notices_a_navigation_route_that_moved",
          console_drift_checks(
              console_edited('home:    ["GET", "/"],', 'home:    ["GET", "/console"],'),
              served_routes)["console_navigation_routes_are_exactly_the_declared_ones"] is False)
    # `GET /api/v1/plugins/alerts/` is the same handler as `GET /api/v1/plugins/alerts`,
    # so the alias excuses it — but only while the route it stands for is reachable.
    # Deleting the canonical spelling has to report both, or the alias table would be a
    # way to make a handler unreachable and keep a green self-test.
    check("an_alias_does_not_excuse_the_route_it_aliases",
          console_drift_checks(
              console_edited('  alertList:    ["GET", "/api/v1/plugins/alerts"],\n', ""),
              served_routes)["every_registered_route_is_reachable_from_the_console"] is False)

    # The oracle is what separates "this module is self-consistent" from "a phone reads
    # these bytes", and it is promised in prose in several shipped files. A citation to a
    # path that is not in the tree is a verification step that silently never happens —
    # the operator follows the instruction, finds nothing, and ships anyway.
    citations = oracle_citations(suite_root)
    named_paths: set = set()
    for paths in citations.values():
        named_paths.update(paths.split(";"))
    agreement = oracle_agreement_checks(sorted(named_paths), (suite_root / ORACLE_RELPATH).is_file(),
                                        list(citations))
    for name in sorted(agreement):
        check(name, agreement[name])
    # Controls for all four, each one a world this checkout could have been in.
    # Derived rather than written out: this file is one of the files the census reads, so
    # a literal stale path in a control here would be inventoried as a citation and the
    # check it is supposed to prove would go red for the wrong reason.
    stale_oracle_path = ORACLE_RELPATH.replace("official_tools/", "tools/")
    check("the_stale_citation_control_actually_moves_the_path", stale_oracle_path != ORACLE_RELPATH)
    check("the_crypto_oracle_checks_notice_a_stale_citation",
          oracle_agreement_checks([stale_oracle_path], True, CRYPTO_GATE_MODULES)
          ["every_crypto_oracle_citation_names_a_shipped_path"] is False)
    check("the_crypto_oracle_checks_notice_a_moved_oracle",
          oracle_agreement_checks([ORACLE_RELPATH], False, CRYPTO_GATE_MODULES)
          ["the_crypto_oracle_ships_beside_the_voucher_tool"] is False)
    check("the_crypto_oracle_checks_notice_no_citation_at_all",
          oracle_agreement_checks([], True, CRYPTO_GATE_MODULES)
          ["the_crypto_oracle_is_cited_by_the_modules_that_need_it"] is False)
    check("the_crypto_oracle_checks_notice_a_module_that_stopped_pointing",
          oracle_agreement_checks([ORACLE_RELPATH], True, ["gateway/app/main.py"])
          ["every_envelope_module_that_gates_on_the_wheel_names_the_oracle"] is False)

    # The QR-poll exemption is an auth rule, and an auth rule that only ever answers
    # "allowed" is not a rule. Each narrow claim above is paired with the table that
    # would have broken it, so the pair fails if the matcher is hard-wired rather than
    # reading the declaration.
    exemptions = public_exemption_checks(served_routes)
    for name in sorted(exemptions):
        check(name, exemptions[name])
    check("the_public_exemption_checks_notice_an_unmounted_template",
          public_exemption_checks([route for route in served_routes if route != "GET " + POLL_TEMPLATE])
          ["every_public_plugin_route_template_is_registered"] is False)
    check("the_public_route_matcher_follows_its_table",
          matches_public_route_template(
              PUBLIC_PLUGIN_ROUTES + (("POST", POLL_TEMPLATE),), "POST", POLL_PATH) is True)
    check("the_public_route_matcher_anchors_the_whole_path",
          matches_public_route_template(
              (("GET", "/api/v1/plugins/sso/sessions/{a}/{b}"),), "GET", POLL_PATH + "/extra") is True)
    # An unbalanced brace in a shipped constant has to fail closed. The loop that
    # builds the pattern would otherwise spin forever on it, which is a denial of
    # service in the one function that is supposed to be conservative.
    check("an_unbalanced_template_cannot_hang_the_matcher",
          matches_public_route_template((("GET", "/api/v1/plugins/sso/{session_id"),), "GET",
                                        "/api/v1/plugins/sso/abc") is False)

    check("parse_prefixed_payload_ok", parse_prefixed_payload("channel:subscribe:green", "channel:subscribe:") == ("green",))
    check("parse_prefixed_payload_rejects_empty_tail", parse_prefixed_payload("channel:subscribe:", "channel:subscribe:") is None)
    check("parse_prefixed_payload_rejects_empty_segment", parse_prefixed_payload("a:b::c", "a:") is None)
    check("parse_prefixed_payload_ignores_other_prefixes", parse_prefixed_payload("poll:vote:1:0", "channel:") is None)

    check("token_is_valid_matches", token_is_valid(" abc ", "abc"))
    check("token_is_valid_refuses_an_empty_expected", not token_is_valid("anything", ""))
    check("token_is_valid_refuses_a_missing_header", not token_is_valid(None, "abc"))
    check("constant_compare_handles_unicode", constant_compare("令牌", "令牌"))
    uid, ts, sig = h5_query_params({H5_UID_PARAM: ["u1", "u2"], H5_TS_PARAM: "17", H5_SIG_PARAM: ["s"]})
    check("h5_query_params_first_value_wins", (uid, ts, sig) == ("u1", "17", "s"))
    check("h5_query_params_missing_is_empty", h5_query_params({}) == ("", "", ""))
    check("split_csv_dedupes_and_trims", split_csv("a, b ,a,,") == ["a", "b"])
    check("split_csv_accepts_a_list", split_csv([1, 2, "1"]) == ["1", "2"])
    check("int_or_none_tolerates_junk", int_or_none("x") is None and int_or_none(" 42 ") == 42)
    check("clamp_limit_bounds", clamp_limit("99999", 100, 1000) == 1000 and clamp_limit("0", 100, 1000) == 100)
    check("row_dict_decodes_blobs", row_dict({"a": b"ok"}) == {"a": "ok"} and row_dict(None) == {})
    check("json_loads_or_survives_a_corrupt_row", json_loads_or("{not json", []) == [] and json_loads_or(None, []) == [])
    check("json_loads_or_passes_through_a_value", json_loads_or('[{"a":1}]', None) == [{"a": 1}])
    check("welcome_reply_silence_is_explicit", welcome_reply("  ") is None and welcome_reply("hi") == "hi")

    actions = [
        {"id": "pay", "title": "支付", "action": "pay_credits", "style": "primary", "amount": 5, "payload": "channel:subscribe:green"},
        {"id": "cancel", "title": "取消", "action": "callback", "style": "secondary", "payload": "channel:cancel:green"},
    ]
    retired = retired_actions(actions)
    check("retired_actions_keeps_every_id", [a["id"] for a in retired] == ["pay", "cancel"])
    check("retired_actions_emits_no_illegal_kind", all(a["action"] != "none" for a in retired))
    check("retired_actions_payload_is_a_noop", all(a["payload"].startswith("noop:") for a in retired))
    check("retired_actions_ignores_an_id_less_row", retired_actions([{"title": "x"}, {}]) == [])
    check("retired_actions_stops_asking_for_credits", all(a["action"] == "callback" and "amount" not in a for a in retired))
    check("retired_actions_survives_an_empty_input", retired_actions([]) == [])

    check("contact_id_from_nested_shapes", _contact_id_from_response({"chats": {"contact": {"contact_id": 9}}}) == 9)
    check("contact_id_from_list_of_items", _contact_id_from_response({"newChatItems": [{"chat": {"contactId": 8}}]}) == 8)
    check("contact_id_from_command_echo", _contact_id_from_response("@77") == 77)
    check("contact_id_from_junk_is_zero", _contact_id_from_response({"nope": 1}) == 0 and _contact_id_from_response(None) == 0)

    escaped = html_escape('<script>alert("x")</script>')
    check("html_escape_kills_markup", "<script>" not in escaped and "&lt;script&gt;" in escaped and "&quot;" in escaped)
    shell = _h5_shell("a1", "line one\n\n<b>line two</b>", "标题")
    check("h5_shell_escapes_the_body", "<b>line two</b>" not in shell and "&lt;b&gt;" in shell)
    check("h5_shell_renders_two_paragraphs", shell.count("<p>") == 2)
    check("h5_shell_error_branch_names_the_reason", "expired" in _h5_shell("a1", "", "t", error="expired"))
    check("h5_shell_has_no_third_party_request", "http://" not in shell and "//cdn" not in shell and "<script" not in shell)

    def payload_of(text: str) -> Dict[str, Any]:
        """The ECO JSON inside a frame, or a loud failure.

        Every assertion about "what the phone would receive" goes through here, so a
        frame that lost its marker — the classic way a `visible_text` prefix eats a
        `sh` frame whole (`PopopxEcoModels.swift:106-114`) — fails a check instead of
        quietly comparing a substring of nothing.
        """
        if not text.startswith(ECO_MARKER):
            raise AssertionError("frame lost its marker: %r" % (text[:48],))
        return json.loads(text[len(ECO_MARKER):])

    def run(coroutine: Any) -> Any:
        """One event loop per awaited call, so the suite stays a plain function."""
        return asyncio.run(coroutine)

    # ── 2. the protocol half, against a real SQLite file and a fake node ────

    with tempfile.TemporaryDirectory() as tmpdir:
        config = _fake_config(tmpdir)
        db = Database(Path(config.db_path))
        bridge = FakeBridge()
        billing = BillingService(db, config, voucher_verifier=None)
        eco = EcoService(config, db, billing, bridge, identity_factory=_fake_identity, sealer=_fake_seal)
        billing.go_online()
        billing.grant(credits=10_000, reason="self_test")
        balance = lambda: billing.account().balance  # noqa: E731 — a local reading of one column

        # A write's return value is load-bearing here (`revoke_session`, the outbox
        # claim, `expire_members`), and SQLite leaves `lastrowid` at the previous
        # statement's value when an UPDATE matches nothing — so these three checks
        # are what keep :meth:`Database.execute` from answering "1 changed" for a
        # write that changed nothing. The temp table keeps the probe off every real
        # table's triggers and constraints.
        db.execute("CREATE TEMP TABLE _probe (id INTEGER PRIMARY KEY, a TEXT)")
        check("an_insert_reports_the_new_row_id", int(db.execute("INSERT INTO _probe (a) VALUES ('x')")) == 1)
        check("a_write_that_matched_no_rows_reports_zero",
              db.execute("UPDATE _probe SET a = 'y' WHERE id = 999") == 0)
        check("a_write_that_changed_one_row_reports_one",
              db.execute("UPDATE _probe SET a = 'y' WHERE id = 1") == 1)
        for probe_key in ("card1_11", "card15_22", "article:welcome"):
            db.execute("INSERT INTO _probe (a) VALUES (?)", (probe_key,))

        def like_matched(pattern: str) -> List[str]:
            return [str(row_dict(row)["a"]) for row in
                    db.query("SELECT a FROM _probe WHERE a LIKE ? ESCAPE '\\' ORDER BY id", (pattern,))]

        check("like_prefix_hits_the_derived_id_but_not_a_near_miss", like_matched(like_prefix("card1_")) == ["card1_11"])
        check("like_prefix_hits_an_article_key", like_matched(like_prefix("article:")) == ["article:welcome"])

        session = eco.ensure_session(42)
        check("ensure_session_mints_a_pairwise_uid", bool(session.pairwise_uid) and session.contact_id == 42)
        check("ensure_session_is_idempotent", eco.ensure_session(42).pairwise_uid == session.pairwise_uid)
        rotated = eco.ensure_session(42, rotate=True)
        check("ensure_session_rotate_replaces_the_uid", rotated.pairwise_uid != session.pairwise_uid)
        check("a_rotated_secret_verifies", eco.verify_h5_request(*eco.h5_params_from_url(eco.h5_url(rotated, "/h5/x")))["valid"])
        old_signed = eco.h5_params_from_url(eco.h5_url(session, "/h5/x"))
        check("the_superseded_secret_stops_verifying", not eco.verify_h5_request(*old_signed)["valid"])
        check("session_row_created_a_contact", db.query_one("SELECT contact_id FROM contacts WHERE contact_id = 42") is not None)
        check("session_for_reads_it_back", eco.session_for(42) is not None and eco.session_for(42).usable)
        check("session_for_unknown_contact_is_none", eco.session_for(9999) is None)
        raises("ensure_session_refuses_contact_zero", GatewayError, lambda: eco.ensure_session(0))

        before = balance()
        handshaked = run(eco.handshake(42))
        frame = payload_of(bridge.sent[-1][1])
        check("handshake_sends_an_sh_frame", frame.get("t") == "sh")
        check("handshake_carries_the_uid_and_service",
              frame.get("uid") == rotated.pairwise_uid and frame.get("svc") == config.service_id)
        check("the_handshake_frame_sends_nothing_the_client_cannot_decode",
              validate_secret_hex(frame["sec"]) == rotated.secret_hex)
        check("handshake_is_not_charged", balance() == before and handshaked["sent"])
        check("handshake_output_names_no_secret", "secret" not in json.dumps(handshaked))

        signed = eco.h5_url(rotated, "/h5/intro")
        params = h5_query_params(
            dict(pair.split("=", 1) for pair in signed.partition("?")[2].split("&") if "=" in pair)
        )
        check("h5_url_carries_the_three_parameters", all(params))
        check("h5_url_round_trips", eco.h5_params_from_url(signed) == params)
        check("verify_h5_accepts_a_good_signature", eco.verify_h5_request(*params)["valid"])
        tampered = eco.verify_h5_request(params[0], params[1], "0" * len(params[2]))
        check("verify_h5_rejects_a_bad_signature", not tampered["valid"] and tampered["reason"] != "unknown_uid")
        check("verify_h5_names_an_unknown_uid", eco.verify_h5_request("pw_nope", params[1], params[2])["reason"] == "unknown_uid")
        stale = eco.verify_h5_request(params[0], int(params[1]) - 10_000, params[2])
        check("verify_h5_rejects_a_stale_timestamp",
              not stale["valid"] and "window" in str(stale["reason"]))
        check("public_url_is_absolute_and_unsigned",
              eco.public_url("/x") == "https://eco.example.test/x" and "sig=" not in eco.public_url("/x"))
        raises("h5_url_for_contact_needs_a_session", GatewayError, lambda: eco.h5_url_for_contact(9999, "/h5/x"))

        raises("push_menu_before_a_menu_is_stored", GatewayError, lambda: run(eco.push_menu()))
        # Written in the *spec* shape `build_menu_item` accepts, because that is the
        # shape the console posts: an action nested under `action:` with its
        # payload inside it. What the phone receives is the flattened leaf, so the
        # checks below read the flattened form on purpose.
        menu = eco.store_menu([
            {"title": "订单", "kind": "click", "action": {"action": "callback", "payload": "kw:order"}},
            {"title": "说明", "kind": "view", "action": {"action": "open_url", "url": "https://eco.example.test/h5/intro"}},
            {"title": "更多", "kind": "click", "sub_items": [
                {"title": "订阅", "kind": "click", "action": {"action": "open_channel", "payload": "green"}}]},
        ])
        check("store_menu_builds_a_revision", int(menu["menu"]["rev"]) >= 1)
        check("store_menu_flattens_the_action_payload",
              menu["menu"]["items"][0].get("payload") == "kw:order"
              and menu["menu"]["items"][0].get("action") == "callback")
        check("store_menu_keeps_a_view_url", str(menu["menu"]["items"][1].get("url") or "").endswith("/h5/intro"))
        check("store_menu_keeps_sub_items", len(menu["menu"]["items"][2].get("sub") or []) == 1)
        check("store_menu_writes_an_empty_sub_list_on_a_leaf", menu["menu"]["items"][0].get("sub") == [])
        # The store path is the one a plugin or the console actually posts through, so the
        # two-level ceiling has to bite here as well and not only inside the codec: the
        # client renders no third level at all (`BotMenuBarView.swift:137-138`).
        try:
            eco.store_menu([{"title": "更多", "kind": "click", "sub_items": [
                {"title": "订阅", "kind": "click", "sub_items": [
                    {"title": "第三代", "kind": "click", "action": {"action": "callback", "payload": "kw:x"}}]}]}])
            check("store_menu_refuses_a_third_level", False)
        except EcoError as exc:
            check("store_menu_refuses_a_third_level", exc.rule == "menu_depth")
        raises("store_menu_refuses_a_payment_action", EcoError,
               lambda: eco.store_menu([{"title": "x", "action": {"action": "pay_credits"}}]))
        check("menu_reply_finds_the_keyword", eco.menu_reply_for("order") is not None)
        check("menu_reply_finds_the_title", eco.menu_reply_for("订单") is not None)
        check("menu_reply_walks_into_sub_menus", eco.menu_reply_for("订阅") is not None)
        check("menu_reply_is_a_whole_string_match", eco.menu_reply_for("my order please") is None)
        check("menu_reply_ignores_empty_text", eco.menu_reply_for("   ") is None)
        repushed = eco.store_menu([{"title": "订单", "action": {"action": "callback", "payload": "kw:order"}}])
        check("re_storing_the_menu_advances_the_revision",
              int(repushed["menu"]["rev"]) > int(menu["menu"]["rev"]))
        check("re_storing_the_same_items_still_advances",
              int(eco.store_menu([{"title": "订单", "action": {"action": "callback", "payload": "kw:order"}}])["menu"]["rev"])
              > int(repushed["menu"]["rev"]))
        menu_push_balance = balance()
        pushed = run(eco.push_menu())
        pushed_frame = payload_of(bridge.sent[-1][1])
        check("push_menu_sends_an_mc_frame", pushed and pushed_frame.get("t") == "mc")
        check("push_menu_carries_the_current_revision", int(pushed_frame["menu"]["rev"]) == eco.menu_state()["rev"])
        check("push_menu_charges_per_recipient",
              balance() == menu_push_balance - config.billing.per_menu_push)
        check("push_menu_stamps_the_delivery", eco.menu_state()["last_delivered_ms"] > 0)

        card = build_card("order_1", "订单已发货", style="receipt",
                          fields=[{"k": "单号", "v": "A1"}],
                          actions=[{"action_id": "confirm", "title": "确认收货", "kind": "callback",
                                    "payload": "order:confirm:A1"}],
                          updated_at_ms=now_ms())
        spent = balance()
        delivery = run(eco.deliver_card(card, 42, topic="order:A1"))
        card_frame = payload_of(bridge.sent[-1][1])
        check("deliver_card_sends_a_create_frame", card_frame.get("t") == "sc" and card_frame.get("m") == "c")
        check("deliver_card_charges_the_card_meter",
              delivery.sent and delivery.charged == config.billing.per_card and balance() == spent - config.billing.per_card)
        check("deliver_card_stores_the_row", eco.find_card("order_1", 42) is not None)
        check("deliver_card_records_the_topic", str(eco.find_card("order_1", 42).get("topic")) == "order:A1")
        second = run(eco.deliver_card(card, 42))
        check("re_delivering_an_existing_id_becomes_an_update", payload_of(bridge.sent[-1][1]).get("m") == "u")
        check("an_update_is_charged_too", second.sent and second.charged == config.billing.per_card)

        updated = run(eco.update_card("order_1", 42, body="顺丰速运 SF1234567890"))
        merged = payload_of(bridge.sent[-1][1])["card"]
        check("update_card_merges_from_the_stored_row",
              merged.get("body") == "顺丰速运 SF1234567890" and merged.get("title") == "订单已发货"
              and merged.get("fields") == [{"k": "单号", "v": "A1"}])
        check("update_card_advances_ut", int(merged["ut"]) > int(card_frame["card"]["ut"]))
        check("update_card_never_carries_visible_text", bridge.sent[-1][1].startswith(ECO_MARKER))
        check("update_card_sent", updated.sent)

        settled = run(eco.settle_card("order_1", 42))
        settled_frame = payload_of(bridge.sent[-1][1])["card"]
        check("settle_card_expires_the_card", int(settled_frame["et"]) < now_ms())
        check("settle_card_rewrites_the_buttons", [a["id"] for a in settled_frame["actions"]] == ["confirm"]
              and settled_frame["actions"][0]["action"] == "callback")
        check("settle_card_marks_the_row", str(eco.find_card("order_1", 42).get("state")) == CARD_STATE_SETTLED)
        check("settle_card_delivered", settled.sent)
        raises("update_card_for_an_unknown_id", GatewayError,
               lambda: run(eco.update_card("nope_1", 42, title="x")))

        # The outbox: a node that is down must cost nothing and lose nothing.
        bridge.connected = False
        queued_balance = balance()
        queued_card = build_card("queue_1", "补发", updated_at_ms=now_ms())
        queued = run(eco.deliver_card(queued_card, 42))
        check("a_frame_with_the_node_down_is_queued", queued.queued and not queued.sent)
        check("a_queued_frame_is_not_charged", balance() == queued_balance and queued.charged == 0)
        check("the_queued_row_is_durable", len(eco.queued_frames()) == 1 and eco.outbox_stats()["queued"] == 1)
        bridge.connected = True
        drained = run(eco.drain_outbox())
        check("the_worker_drains_the_queue", drained["sent"] == 1 and eco.outbox_stats()["queued"] == 0)
        check("draining_charges_once", balance() == queued_balance - config.billing.per_card)
        check("a_second_pass_sends_nothing", run(eco.drain_outbox())["sent"] == 0)
        check("the_drained_body_is_the_original_frame", payload_of(bridge.sent[-1][1])["card"]["id"] == "queue_1")

        bridge.fail = NodeTimeout("self-test", 0.1)
        failing_balance = balance()
        failed = run(eco.deliver_card(build_card("fail_1", "会失败", updated_at_ms=now_ms()), 42))
        check("a_refused_send_is_reported", not failed.sent and failed.error == "send_failed")
        check("a_refused_send_is_refunded", balance() == failing_balance)
        bridge.fail = None

        billing.suspend("operator:self_test")
        blocked_balance = balance()
        blocked = run(eco.deliver_card(build_card("blocked_1", "欠费", updated_at_ms=now_ms()), 42))
        check("a_suspended_account_blocks_the_send", not blocked.sent and blocked.error == "account_suspended")
        check("a_blocked_delivery_costs_nothing", balance() == blocked_balance)
        check("a_blocked_delivery_is_not_queued", eco.outbox_stats()["queued"] == 0)
        billing.go_online()

        paid_card = build_card("pay_1", "会员", updated_at_ms=now_ms(),
                               actions=[{"action_id": "buy", "title": "开通", "kind": "pay_credits",
                                         "amount": 20, "payload": "channel:subscribe:green"}])
        run(eco.deliver_card(paid_card, 42))
        pending = eco.pending_paid_action(42, "channel:subscribe:green")
        check("a_pay_credits_button_is_recorded_as_pending", pending is not None and pending["amount"] == 20)
        eco.settle_paid_action(pending, paid_ref="deadbeef")
        check("the_paid_action_stops_being_pending", eco.pending_paid_action(42, "channel:subscribe:green") is None)
        check("the_paid_row_carries_the_tx_hash",
              str(db.query_one("SELECT paid_ref FROM card_actions WHERE id = ?", (pending["id"],))["paid_ref"]) == "deadbeef")

        raises("create_channel_rejects_a_junk_id", GatewayError, lambda: eco.create_channel("bad id!", "x"))
        raises("create_channel_rejects_a_colon_id", GatewayError, lambda: eco.create_channel("a:b", "x"))
        created = eco.create_channel("green", "GREEN 频道")
        check("create_channel_opens_epoch_one", int(created["current_epoch"]) == 1)
        check("the_channel_listing_hides_the_private_key", "identity_sec_b64url" not in created)
        private_b64 = str(row_dict(
            db.query_one("SELECT identity_sec_b64url FROM channels WHERE channel_id='green'")
        )["identity_sec_b64url"])
        check("the_private_key_is_actually_stored", private_b64 != "")
        raises("create_channel_refuses_a_duplicate", GatewayError, lambda: eco.create_channel("green", "again"))
        raises("rotate_an_unknown_channel", GatewayError, lambda: run(eco.rotate_channel_key("nope")))

        eco.create_channel("norelay", "no relay yet")
        check("a_channel_without_a_relay_has_no_public_uri", eco.channel_public_uri("norelay") is None)
        mute = run(eco.grant_membership("norelay", 42))
        check("a_first_grant_without_a_relay_is_not_reported_ok",
              not mute["ok"] and mute["error"] == "no_relay" and mute["public_uri"] is None)

        raises("set_channel_relay_rejects_a_group_address", GatewayError,
               lambda: eco.set_channel_relay("green", "group@smp8.example.test"))
        raises("set_channel_relay_needs_a_known_channel", GatewayError,
               lambda: eco.set_channel_relay("nope", "smp8.example.test"))
        with_relay = eco.set_channel_relay("green", "smp8.example.test")
        check("set_channel_relay_stores_the_host", with_relay["relay"] == "smp8.example.test")
        uri = eco.channel_public_uri("green")
        check("the_public_uri_is_what_the_client_parses", uri is not None and validate_channel_public_uri(uri) == uri)
        check("the_public_uri_carries_the_relay_and_channel", "/smp8.example.test/green#" in str(uri))
        check("the_public_uri_leaks_no_private_key", private_b64 not in str(uri))
        other_key = b64_url(make_epoch_key())
        foreign_pub = b64_url(bytes(range(64, 96)))
        raises("set_channel_uri_validates_the_shape", EcoError, lambda: eco.set_channel_uri("green", "https://nope"))
        raises("set_channel_uri_rejects_another_channel", GatewayError,
               lambda: eco.set_channel_uri(
                   "green", "popopx://channel/smp8.example.test/blue#key=%s&pub=%s" % (other_key, created["identity_pub_b64url"])))
        raises("set_channel_uri_rejects_another_issuer", GatewayError,
               lambda: eco.set_channel_uri(
                   "green", "popopx://channel/smp8.example.test/green#key=%s&pub=%s" % (other_key, foreign_pub)))
        raises("set_channel_uri_rejects_a_foreign_epoch_key", GatewayError,
               lambda: eco.set_channel_uri(
                   "green", build_channel_public_uri("smp8.example.test", "green", other_key, created["identity_pub_b64url"])))
        check("set_channel_uri_accepts_the_uri_we_mint",
              int(row_dict(eco.set_channel_uri("green", str(uri)))["uri_published"]) == 1)
        check("the_public_uri_carries_the_epoch_one_key",
              "key=%s" % str(row_dict(
                  db.query_one("SELECT key_b64url FROM channel_epochs WHERE channel_id='green' AND epoch=1")
              )["key_b64url"]) in str(uri))
        check("the_public_uri_carries_the_identity", "pub=%s" % created["identity_pub_b64url"] in str(uri))

        eco.ensure_session(43)
        check("deliver_key_to_a_non_member_is_refused",
              run(eco.deliver_channel_key("green", 43)).error == "not_a_member")
        sent_before = len(bridge.sent)
        granted = run(eco.grant_membership("green", 42, credits=20, paid_ref="tx1", days=7))
        check("the_first_epoch_travels_as_the_uri_not_a_frame",
              granted["ok"] and not granted["delivered"] and granted["error"] is None
              and granted["public_uri"] == uri and len(bridge.sent) == sent_before)
        check("a_bootstrap_grant_costs_nothing", granted["credits_charged"] == 0)
        check("grant_membership_writes_an_active_member", eco.members("green")[0]["status"] == "active")
        check("the_member_starts_at_the_uri_epoch", int(eco.members("green")[0]["epoch"]) == 1)
        check("sessions_for_channel_only_returns_members",
              [s.contact_id for s in eco.sessions_for_channel("green")] == [42])
        granted_link = str(granted.get("invite_link") or "")
        check("a_bootstrap_grant_publishes_the_invite_link_or_names_the_missing_wheel",
              (granted_link.startswith(LINK_PREFIX) and granted.get("invite_link_error") is None)
              if crypto_ready else invite_degraded(granted))
        check("the_grant_invite_link_binds_the_public_uri_when_present",
              decode_invite(granted_link) == uri if crypto_ready else invite_degraded(granted))
        check("the_grant_invite_link_hides_the_relay_when_present",
              "example.test" not in granted_link.lower()
              if crypto_ready else invite_degraded(granted))
        check("the_grant_invite_link_is_stable_across_reads",
              eco.invite_link("channel", "green", uri)["link"] == (granted_link if crypto_ready else None))
        check("the_grant_invite_link_reports_whether_it_came_from_the_cache",
              eco.invite_link("channel", "green", uri)["cached"] is True
              if crypto_ready else invite_info_degraded(eco.invite_link("channel", "green", uri)))
        audit_rows = eco.invite_link_audit(10)
        check("the_audit_counts_link_generations_not_reads",
              len(audit_rows) == (1 if crypto_ready else 0)
              and (not crypto_ready or (audit_rows[0]["kind"] == "channel"
                                        and audit_rows[0]["subject_id"] == "green")))
        check("the_audit_never_keeps_a_full_code_or_uri",
              (not crypto_ready or audit_rows[0]["code_prefix"] == invite_code_prefix(granted_link))
              and (not crypto_ready or granted_link[len(LINK_PREFIX):] not in json.dumps(audit_rows))
              and str(uri) not in json.dumps(audit_rows))
        cached_setting = db.get_setting(SETTING_INVITE_LINK_PREFIX + "channel:green")
        check("the_link_cache_never_stores_the_raw_uri",
              (cached_setting is None if not crypto_ready
               else isinstance(cached_setting, dict) and "link" in cached_setting)
              and "smp8" not in json.dumps(cached_setting).lower())
        missing_link = eco.invite_link("channel", "green", "")
        check("a_missing_source_is_named_not_faked",
              missing_link["link"] is None and missing_link["error"] == "invite_source_unavailable")
        bad_kind = eco.invite_link("unknown", "green", uri)
        check("an_unknown_invite_kind_is_refused",
              bad_kind["link"] is None and bad_kind["error"] == "invite_kind_invalid")

        epoch_one_key = b64_decode_lenient(str(row_dict(
            db.query_one("SELECT key_b64url FROM channel_epochs WHERE channel_id='green' AND epoch=1")
        )["key_b64url"]))
        _fake_seal.calls.clear()
        rotated_key = run(eco.rotate_channel_key("green"))
        ku_frame = payload_of(bridge.sent[-1][1])
        epoch_two_key = b64_decode_lenient(str(row_dict(
            db.query_one("SELECT key_b64url FROM channel_epochs WHERE channel_id='green' AND epoch=2")
        )["key_b64url"]))
        check("rotation_opens_the_next_epoch",
              rotated_key["epoch"] == 2 and rotated_key["sealed_under_epoch"] == 1)
        check("rotation_notifies_its_members", rotated_key["members_notified"] == 1)
        check("rotation_delivers_a_key_frame", ku_frame.get("t") == "ku" and ku_frame["update"]["ch"] == "green")
        check("the_frame_is_sealed_under_the_installed_epoch", int(ku_frame["update"]["se"]) == 1)
        check("the_key_update_is_a_valid_envelope",
              ku_frame["update"]["env"]["protocol"] == "popopx.channel.enc.v1")
        check("the_envelope_carries_the_new_epoch", int(ku_frame["update"]["env"]["epoch"]) == 2)
        check("the_box_is_sealed_with_the_old_key",
              len(_fake_seal.calls) == 1 and _fake_seal.calls[0]["sealing_key"] == epoch_one_key)
        sealed_body = json.loads(_fake_seal.calls[0]["plaintext"].decode("utf-8"))
        check("only_the_box_plaintext_carries_the_new_key",
              sealed_body["epoch"] == 2 and b64_decode_lenient(str(sealed_body["keyBase64URL"])) == epoch_two_key
              and "keyBase64URL" not in ku_frame["update"])
        check("a_rotation_charges_the_key_meter",
              rotated_key["credits_charged"] == config.billing.per_key_rotation)
        check("the_new_epoch_delivery_is_stamped",
              int(db.query_one(
                  "SELECT delivered_ms FROM channel_epochs WHERE channel_id='green' AND epoch=2")["delivered_ms"]) > 0)
        check("rotation_revokes_the_previous_epoch",
              int(db.query_one("SELECT revoked FROM channel_epochs WHERE channel_id='green' AND epoch=1")["revoked"]) == 1)
        check("a_revoked_epoch_is_never_handed_out_as_live", eco.channel_epoch_key("green", 1) is None)
        check("a_revoked_epoch_still_opens_a_box", eco.epoch_key_for_sealing("green", 1) == epoch_one_key)
        check("the_member_epoch_follows_the_delivery", int(eco.members("green")[0]["epoch"]) == 2)
        check("rotation_re_delivers_to_members", len(eco.epoch_history("green")) == 2)
        check("delivering_the_epoch_a_member_holds_is_a_no_op",
              run(eco.deliver_channel_key("green", 42)).error == "already_issued")
        renewed = run(eco.grant_membership("green", 42))
        check("renewing_at_the_current_epoch_is_ok_without_a_frame",
              renewed["ok"] and renewed["renewed"] and not renewed["delivered"]
              and renewed["error"] is None and renewed["credits_charged"] == 0)
        check("a_renewal_does_not_mint_another_link",
              renewed.get("invite_link") == (granted_link if crypto_ready else None)
              and len(eco.invite_link_audit(10)) == (1 if crypto_ready else 0))
        check("a_second_rotation_seals_under_the_delivered_epoch",
              int(run(eco.rotate_channel_key("green"))["sealed_under_epoch"]) == 2
              and _fake_seal.calls[-1]["sealing_key"] == epoch_two_key)

        db.execute("UPDATE channel_members SET expires_at_ms = ? WHERE channel_id='green' AND contact_id=42", (now_ms() - 1,))
        check("expire_members_moves_lapsed_rows", eco.expire_members() == 1 and eco.members("green")[0]["status"] == "expired")
        check("sessions_for_channel_ignores_expired_members", eco.sessions_for_channel("green") == [])
        revoked_member = eco.revoke_membership("green", 42)
        check("revoking_a_member_rewrites_its_status",
              revoked_member["ok"] and eco.members("green")[0]["status"] == "revoked")
        check("sessions_for_channel_ignores_revoked_members", eco.sessions_for_channel("green") == [])
        check("revoking_twice_reports_no_change", eco.revoke_membership("green", 42)["revoked"] is False)
        check("revoking_a_member_that_never_existed_reports_no_change",
              eco.revoke_membership("green", 999)["revoked"] is False)
        raises("revoking_on_an_unknown_channel", GatewayError, lambda: eco.revoke_membership("nope", 42))
        raises("grant_to_an_unknown_channel", GatewayError, lambda: run(eco.grant_membership("nope", 42)))

        check("an_unknown_article_cannot_be_sent", eco.get_article("nope") is None)
        stored_article = eco.put_article("intro", "欢迎指南", "第一段\n第二段")
        check("put_article_round_trips", eco.get_article("intro")["body"] == stored_article["body"])
        check("articles_lists_without_the_body", eco.articles()[0]["title"] == "欢迎指南")
        refs_before = int(db.scalar("SELECT COUNT(*) FROM article_refs") or 0)
        sent_article = run(eco.send_article(42, "intro"))
        article_frame = payload_of(bridge.sent[-1][1])
        check("send_article_delivers_a_receipt_card", article_frame["card"]["v"] == "receipt")
        check("the_article_button_is_a_signed_h5_url",
              article_frame["card"]["actions"][0]["url"].startswith("https://eco.example.test/h5/intro?"))
        uid_in_link = eco.h5_params_from_url(article_frame["card"]["actions"][0]["url"])
        check("the_article_link_verifies", eco.verify_h5_request(*uid_in_link)["valid"])
        check("send_article_logs_the_ref",
              int(db.scalar("SELECT COUNT(*) FROM article_refs") or 0) == refs_before + 1)
        check("send_article_delivered", sent_article.sent)
        raises("sending_a_missing_article_is_a_404", GatewayError, lambda: run(eco.send_article(42, "missing")))
        revoked_session = eco.revoke_session(42)
        check("revoke_session_blocks_verification",
              revoked_session and eco.verify_h5_request(rotated.pairwise_uid, params[1], params[2])["reason"] == "revoked")
        db.execute("UPDATE eco_sessions SET revoked = 0 WHERE contact_id = 42")

        # ── 3. the gateway object and the inbound router (still no FastAPI) ───

        gw = Gateway(config, db=db, bridge=bridge)
        gw.mount_plugins()
        check("every_plugin_spec_has_a_row", sorted(gw.plugins) == sorted(spec.plugin_id for spec in PLUGIN_SPEC))
        check("a_plugin_is_either_available_or_explained",
              all((m.available and not m.error) or (not m.available and bool(m.error)) for m in gw.plugins.values()))
        check("plugin_status_adds_a_gate_decision_to_every_row",
              len(gw.plugin_status()) == len(PLUGIN_SPEC) and all("gate" in row for row in gw.plugin_status()))
        run(gw.async_boot())
        run(gw.async_boot())
        identity = row_dict(db.query_one("SELECT * FROM service_identity WHERE id = 1"))
        check("async_boot_records_the_service_identity_once",
              int(db.scalar("SELECT COUNT(*) FROM service_identity") or 0) == 1
              and identity.get("service_id") == config.service_id)
        check("async_boot_keeps_the_address_the_node_named", identity.get("address") == bridge.contact_address)
        status = gw.status()
        service = status["service"]
        contact_link = str(service.get("contact_link") or "")
        check("status_keeps_the_raw_contact_address_for_diagnostics",
              service.get("contact_address") == bridge.contact_address)
        check("status_publishes_the_contact_link_or_names_the_missing_wheel",
              contact_link.startswith(LINK_PREFIX) if crypto_ready else invite_degraded(service, "contact_link"))
        check("the_contact_link_binds_the_node_address_when_present",
              decode_invite(contact_link) == bridge.contact_address if crypto_ready
              else invite_degraded(service, "contact_link"))
        check("the_contact_link_hides_the_relay_when_present",
              "popopx.test" not in contact_link.lower()
              if crypto_ready else invite_degraded(service, "contact_link"))
        check("the_contact_link_reports_whether_it_came_from_the_cache",
              eco.invite_link("service_account", config.service_id, bridge.contact_address)["cached"] is True
              if crypto_ready
              else invite_info_degraded(
                  eco.invite_link("service_account", config.service_id, bridge.contact_address)))
        service_audit = eco.invite_link_audit(10)
        check("the_service_account_generation_is_audited_under_its_own_kind",
              len(service_audit) == (2 if crypto_ready else 0)
              and (not crypto_ready or (service_audit[0]["kind"] == "service_account"
                                        and service_audit[0]["subject_id"] == config.service_id)))

        eco.store_menu([
            {"title": "订单", "kind": "click", "action": {"action": "callback", "payload": "kw:order"}},
            {"title": "说明", "kind": "view", "action": {"action": "open_url", "url": "https://eco.example.test/h5/intro"}},
            {"title": "更多", "kind": "click", "sub_items": [
                {"title": "订阅", "kind": "click", "action": {"action": "open_channel", "payload": "green"}}]},
        ])

        def inbound(text: str, item_id: int, *, contact_id: int = 42, direction: str = "rcv") -> InboundMessage:
            callback = parse_inbound_text(text)
            return InboundMessage(contact_id, "Ada", item_id, text, callback, direction)

        def callback_row(dedupe: str) -> Dict[str, Any]:
            row = db.query_one("SELECT * FROM callbacks WHERE dedupe_key = ?", (dedupe,))
            return row_dict(row) if row is not None else {}

        sent_before = len(bridge.sent)
        run(gw.router.on_message(inbound("说明", 9001)))
        link_frame = payload_of(bridge.sent[-1][1])
        check("typing_a_menu_title_sends_the_link_it_configured",
              link_frame.get("t") == "sc" and link_frame["card"]["actions"][0]["action"] == "open_url")
        check("the_menu_link_is_signed_for_this_follower",
              eco.verify_h5_request(*eco.h5_params_from_url(link_frame["card"]["actions"][0]["url"]))["valid"])
        check("a_routed_message_is_recorded_with_its_outcome",
              callback_row("c42:i9001")["status"] == "handled"
              and callback_row("c42:i9001")["handler"] == "menu")
        run(gw.router.on_message(inbound("说明", 9001)))
        check("a_replayed_item_is_never_answered_twice",
              len(bridge.sent) == sent_before
              and int(db.scalar("SELECT COUNT(*) FROM callbacks WHERE dedupe_key = 'c42:i9001'") or 0) == 1)
        run(gw.router.on_message(inbound("说明", 9002, direction="snd")))
        check("our_own_echoed_frames_are_not_inbound_traffic",
              callback_row("c42:i9002") == {} and len(bridge.sent) == sent_before)
        run(gw.router.on_message(inbound("订阅", 9003)))
        channel_frame = payload_of(bridge.sent[-1][1])
        check("a_typed_open_channel_leaf_answers_with_the_public_uri",
              channel_frame["card"]["actions"][0]["payload"] == uri
              and channel_frame["card"]["actions"][0]["action"] == "open_channel")
        run(gw.router.on_message(
            InboundMessage(42, "Ada", 9004, "::NOPE::x", InboundCallback(kind="nonsense", raw="::NOPE::x"), "rcv")
        ))
        check("a_kind_with_no_handler_is_ignored_not_raised",
              callback_row("c42:i9004")["status"] == "ignored"
              and callback_row("c42:i9004")["error"] == "unknown_kind")
        run(gw.router.on_message(inbound("::REF::intro", 9005)))
        check("an_article_reference_delivers_the_receipt_card",
              payload_of(bridge.sent[-1][1])["card"]["v"] == "receipt"
              and callback_row("c42:i9005")["handler"] == "gateway:article")
        run(gw.router.on_message(inbound("::REF::nothere", 9006)))
        check("a_missing_article_is_refused_by_id_not_by_crash",
              callback_row("c42:i9006")["status"] == "ignored"
              and callback_row("c42:i9006")["error"] == "article_not_found")
        db.execute("UPDATE channel_members SET status = 'revoked' WHERE channel_id = 'green'")
        run(gw.router.on_message(inbound("::CB::channel:subscribe:green", 9007)))
        check("a_subscribe_callback_revives_the_membership_row",
              eco.members("green")[0]["status"] == "active"
              and callback_row("c42:i9007")["handler"] == "gateway:channel_subscribe")
        run(gw.router.on_message(inbound("::CB::channel:subscribe:", 9008)))
        check("a_payload_with_no_channel_id_is_ignored",
              callback_row("c42:i9008")["status"] == "ignored"
              and callback_row("c42:i9008")["error"] == "channel_id_invalid")
        run(gw.router.on_message(inbound("::popopx_sys::rotate::nosuchchannel", 9009)))
        check("a_rotation_for_a_channel_that_does_not_exist_is_refused",
              callback_row("c42:i9009")["status"] == "ignored")
        check("recent_reads_the_callback_log_newest_first",
              [row_dict(row)["dedupe_key"] for row in gw.router.recent(limit=1)] == ["c42:i9009"])

        def contact_request(request_id: int) -> Dict[str, Any]:
            """The node's own event shape, as `extract_contact_request` reads it."""
            return {
                "type": "contactRequest",
                "contactRequest": {"contactRequestId": request_id, "profile": {"displayName": "Ada"}},
            }

        db.set_setting(SETTING_AUTO_ACCEPT, 0)
        run(gw.router.on_event("contact_request", contact_request(5)))
        check("auto_accept_off_leaves_the_request_for_the_console", bridge.accepted == [])
        db.set_setting(SETTING_AUTO_ACCEPT, 1)
        run(gw.router.on_event("contact_request", contact_request(6)))
        check("a_contact_request_is_accepted_then_handshaken",
              bridge.accepted == [6] and payload_of(bridge.sent[-1][1]).get("t") == "sh")
        sent_before_event = len(bridge.sent)
        run(gw.router.on_event("contact_request", {"type": "contactRequest", "contactRequest": {}}))
        run(gw.router.on_event("msgReceived", {}))
        check("an_event_with_nothing_to_act_on_changes_nothing",
              bridge.accepted == [6] and len(bridge.sent) == sent_before_event)
        db.execute("DELETE FROM eco_sessions WHERE contact_id = 43")
        db.execute("DELETE FROM contacts WHERE contact_id = 43")
        synced = run(gw.router.sync_contacts())
        check("sync_contacts_hands_a_session_to_a_follower_it_never_met",
              synced["seen"] == 2 and synced["new"] == 1 and eco.session_for(43) is not None
              and payload_of(bridge.sent[-1][1]).get("t") == "sh")
        bridge.fail = NodeError("self-test: node went away")
        raises("sync_contacts_reports_an_unreachable_node", GatewayError, lambda: run(gw.router.sync_contacts()))
        bridge.fail = None
        run(gw.stop())
        check("gateway_stop_takes_the_link_down", bridge.state()["connected"] is False)
        db.close_all()

    return checks


def http_self_test() -> List[str]:
    """Drive the mounted application over real HTTP and say, route by route, what answered.

    Every other suite in this repository is a statement about source text or about a
    function called directly. This is the only group that sends a request, and it
    exists because two defects passed all of that and would have shipped:

    * every core endpoint annotated ``request: Request`` while ``Request`` was imported
      only inside :func:`create_app`. With ``from __future__ import annotations``
      FastAPI resolves the name against THIS module's globals, fails to find it, and
      turns the parameter into a required *query* field — so all 50 admin endpoints
      answered ``422 {"loc": ["query", "request"]}`` before ``admin_required(request)``
      ever ran. :func:`unresolvable_route_annotations` now catches that statically; the
      first check here catches it as served, which is the form an operator notices.
    * ``POST /api/v1/vouchers/redeem`` called ``.to_dict()`` on the plain dict that
      :meth:`app.billing_service.BillingService.redeem_voucher` returns — an
      ``AttributeError``, i.e. a 500, on the first redemption anyone ever made. Only a
      signed code and a real POST can reach that line.

    The node is a fake socket and a fake command layer, so nothing dials out; the
    database is a file in a temporary directory, so this sweep may write, and the
    ``.env`` it boots from is written here rather than inherited, so a developer's
    live configuration cannot quietly satisfy an assertion this suite is not making.
    """
    import importlib.util
    import os
    import tempfile

    from fastapi import FastAPI
    from fastapi.routing import APIRoute
    from starlette.testclient import TestClient

    checks: List[str] = []

    def check(name: str, condition: bool) -> None:
        if not condition:
            raise AssertionError("http_self_test failed: %s" % name)
        checks.append(name)

    def detail(name: str, offenders: List[str]) -> None:
        """``check`` carries only a name; a sweep that fails has to say *which* route."""
        if offenders:
            raise AssertionError("http_self_test failed: %s — %s" % (name, "; ".join(offenders)))
        checks.append(name)

    root = Path(tempfile.mkdtemp(prefix="popopx-http-selftest-")).resolve()
    suite_root = Path(__file__).resolve().parents[2]
    admin_token = "http-selftest-admin-token-0123456789ab"

    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    issuer_key = Ed25519PrivateKey.generate()
    issuer_pub = base64.b64encode(issuer_key.public_key().public_bytes_raw()).decode("ascii")

    # The issuer's own tool is loaded by path, on purpose: it is not a gateway
    # dependency (a deployed gateway never holds the private half), and minting the
    # code here rather than hand-assembling one is what proves the two halves agree.
    tool_path = suite_root / "official_tools" / "gen_voucher.py"
    tool_spec = importlib.util.spec_from_file_location("popopx_gen_voucher_probe", tool_path)
    if tool_spec is None or tool_spec.loader is None:
        raise AssertionError("http_self_test cannot load %s" % tool_path)
    gen_voucher = importlib.util.module_from_spec(tool_spec)
    tool_spec.loader.exec_module(gen_voucher)
    code, _record = gen_voucher.mint_code(
        issuer_key, gen_voucher.key_id_for(issuer_key.public_key()), "commercial", 5000, None, None
    )

    env_file = root / ".env"
    env_file.write_text(
        "".join(
            "%s=%s\n" % pair
            for pair in [
                ("POPOPX_DB_PATH", str(root / "gateway.db")),
                ("POPOPX_ADMIN_TOKEN", admin_token),
                ("POPOPX_PUBLIC_BASE_URL", "http://127.0.0.1:8099"),
                ("POPOPX_SERVICE_ID", "svc-http-selftest"),
                ("POPOPX_NODE_WS_URL", "ws://127.0.0.1:1"),
                ("POPOPX_OFFICIAL_ED25519_PUBLIC_KEY", issuer_pub),
                ("POPOPX_BILLING_REQUIRE_VOUCHER", "1"),
                ("POPOPX_ALERT_WEBHOOK_TOKEN", "http-selftest-alert-token-0123456789"),
                ("POPOPX_ALERT_WEBHOOK_SECRET", "http-selftest-alert-secret-0123456789"),
                # All nine, so the sweep below cannot pass by quietly covering fewer
                # routes than the suite declares: `web3_bridge`, the three connectors and
                # the Slack/Discord bridge are off by default (config.py) and their GETs
                # vanish from the app without a word.
                ("POPOPX_PLUGIN_WEB3_BRIDGE", "1"),
                ("POPOPX_PLUGIN_WORKFLOW_WEBHOOK", "1"),
                ("POPOPX_PLUGIN_CARDDAV_CONNECTOR", "1"),
                ("POPOPX_PLUGIN_CALDAV_CONNECTOR", "1"),
                ("POPOPX_PLUGIN_SLACK_DISCORD", "1"),
            ]
        ),
        encoding="utf-8",
    )
    env_file.chmod(0o600)

    saved_env = {key: value for key, value in os.environ.items() if key.startswith("POPOPX_")}
    for key in saved_env:
        del os.environ[key]
    os.environ["POPOPX_ENV_FILE"] = str(env_file)

    class _FakeSocket:
        def __init__(self) -> None:
            self.sent: List[str] = []

        async def send(self, payload: str) -> None:
            self.sent.append(payload)

    node_up = {"linked": True, "refuse": None}

    async def _fake_command(command: Any, params: Any = None, *, timeout: Optional[float] = None) -> Dict[str, Any]:
        # Replaces `AgentBridge.command`, the one seam through which every frame leaves:
        # the real method raises `NodeNotConnected` when there is no socket, a
        # `NodeCommandError` when the socket answered and refused, and `node_up` is
        # what makes this fake answer the same way instead of hiding the failure.
        if not node_up["linked"]:
            raise NodeNotConnected("the node link is down (http_self_test)")
        if node_up["refuse"] is not None:
            raise node_up["refuse"]
        if "show" in command:
            return {"user": {"userIds": [1]}, "contacts": []}
        return {"ok": True}

    try:
        config = load_config()
        gateway = Gateway(config)
        socket = _FakeSocket()
        gateway.eco.bridge._ws = socket          # what `connected` reads (agent_bridge.py:879)
        gateway.eco.bridge._started = True
        gateway.eco.bridge.user_id = 1           # what `_require_user` reads; boot sets it from the node
        gateway.eco.bridge.command = _fake_command
        check("the_faked_link_reports_itself_connected", gateway.eco.bridge_connected() is True)

        # Building the app used to print a DeprecationWarning on every boot, because the
        # startup/shutdown pair hung on the deprecated `app.on_event`. The launch path has
        # to stay quiet, so the build is wrapped in a warning recorder — and the recorder
        # is proved to have teeth against a probe app that still uses that hook, otherwise
        # the check below passes whenever the recorder is simply broken.
        with warnings.catch_warnings(record=True) as _boot_warnings:
            warnings.simplefilter("always")
            app = create_app(config=config, gateway=gateway)
        _deprecated = sorted(
            {str(w.message).strip().splitlines()[0] for w in _boot_warnings
             if issubclass(w.category, DeprecationWarning)}
        )
        check("building_the_app_emits_no_deprecation_warning", not _deprecated)
        _noisy = FastAPI()
        with warnings.catch_warnings(record=True) as _probe_warnings:
            warnings.simplefilter("always")

            @_noisy.on_event("startup")
            def _noisy_startup() -> None:
                pass

        check("the_warning_recorder_would_have_caught_the_old_hooks",
              any(issubclass(w.category, DeprecationWarning) for w in _probe_warnings))
        # `raise_server_exceptions=False` is the point of the sweep: a handler that
        # crashes has to come back as the 500 the operator would see, so it can be
        # listed by route instead of aborting the run at the first one.
        client = TestClient(app, raise_server_exceptions=False)

        def live_api_routes(container: Any, prefix: str = "") -> List[Tuple[APIRoute, str]]:
            """`(route, full path)` for every APIRoute this app dispatches to.

            FastAPI up to 0.128 appended an `include_router()`'s routes straight onto
            `app.routes`, already carrying their full path. 0.165 — the version
            `requirements.txt` resolves today, since it pins only a range — keeps one
            `_IncludedRouter` in their place, holding the child in `original_router`
            and the include prefix in `include_context.prefix`, with no `path` of its
            own. Reading only the flat list reported this suite's 30 plugin routes as
            unmounted on that version while `GET /api/v1/plugins/ai/status` still
            answered 200: the app was fine, the census was not, and the routes it did
            not see were quietly dropped from the GET sweep below rather than
            reported. Recursing gives one answer for both shapes.
            """
            found: List[Tuple[APIRoute, str]] = []
            for route in getattr(container, "routes", []) or []:
                if isinstance(route, APIRoute):
                    found.append((route, prefix + route.path))
                    continue
                child = getattr(route, "original_router", None) or getattr(route, "router", None)
                if child is None:
                    child = route if getattr(route, "routes", None) else None
                if child is None:
                    continue
                context = getattr(route, "include_context", None)
                nested = getattr(context, "prefix", None)
                if nested is None:
                    nested = getattr(route, "path", "") or ""
                found.extend(live_api_routes(child, prefix + nested))
            return found

        routes = live_api_routes(app)

        def request_is_a_query_parameter(route: APIRoute) -> bool:
            return any(field.name == "request" for field in route.dependant.query_params)

        bent = sorted(
            "%s %s" % (",".join(sorted(route.methods - {"HEAD", "OPTIONS"})), path)
            for route, path in routes if request_is_a_query_parameter(route)
        )
        detail("no_endpoint_takes_request_as_a_query_parameter", bent)

        # The control that the detector above can fire at all: the same failure,
        # reproduced on a one-route app, spelled exactly the way main.py used to spell it.
        probe = FastAPI()

        @probe.get("/probe")
        async def _probe_endpoint(request: "NoSuchAnnotationAnywhere") -> Any:  # noqa: F821
            return {"ok": True}

        check(
            "the_query_parameter_detector_can_fire",
            any(
                request_is_a_query_parameter(route)
                for route in probe.routes if isinstance(route, APIRoute)
            ),
        )
        check(
            "the_query_parameter_detector_does_not_fire_on_a_resolved_name",
            not any(
                request_is_a_query_parameter(route)
                for route, _ in routes
            ),
        )

        headers = {"x-admin-token": admin_token}

        def concrete(path: str) -> str:
            return re.sub(r"\{[^}/]+\}", "1", path)

        offenders: List[str] = []
        swept = 0
        for route, path in routes:
            if "GET" not in route.methods:
                continue
            url = concrete(path)
            response = client.get(url, headers=headers)
            swept += 1
            if response.status_code >= 500 or response.status_code == 422:
                offenders.append("GET %s -> %d %s" % (url, response.status_code, response.text[:90]))
            elif path.startswith("/api/v1/plugins/") and response.status_code == 401:
                offenders.append("GET %s was refused by the gateway, not answered" % url)
        detail("every_GET_route_answers_when_the_token_is_present", offenders)
        declared_keys = {"%s %s" % (str(row["verb"]).upper(), row["path"]) for row in route_census()} | {
            line for paths in plugin_route_paths().values() for line in paths
        }
        live_keys = {
            "%s %s" % (method, path)
            for route, path in routes for method in (route.methods - {"HEAD", "OPTIONS"})
        }
        detail("every_declared_route_is_actually_mounted", sorted(declared_keys - live_keys))
        check(
            "the_GET_sweep_covered_every_declared_GET",
            swept == len([key for key in declared_keys if key.startswith("GET ")]) and swept >= 12,
        )

        refused = client.get("/api/v1/vouchers")
        check("an_admin_read_without_the_token_is_refused", refused.status_code == 401)

        # Scoped admin tokens: mint with the root, then prove the three decisions
        # the approval rules out — a read scope cannot write, a core scope cannot
        # reach a plugin, and no scoped token can manage tokens. Revocation has to
        # take effect on the next request, not on the next process start.
        minted_scoped = client.post(
            "/api/v1/admin/tokens",
            json={"label": "http self-test status reader", "scopes": ["core:status:ro"]},
            headers=headers,
        )
        scoped_body = minted_scoped.json() if minted_scoped.status_code == 200 else {}
        scoped_token = str(scoped_body.get("token") or "")
        scoped_id = str(scoped_body.get("id") or "")
        check("the_root_token_mints_a_scoped_token",
              minted_scoped.status_code == 200 and scoped_token.startswith(admin_auth.TOKEN_PREFIX)
              and scoped_body.get("scopes") == ["core:status:ro"] and scoped_id.startswith("atk_"))
        scoped_headers = {"x-admin-token": scoped_token}
        check("a_scoped_read_token_reads_its_resource",
              client.get("/api/v1/status", headers=scoped_headers).status_code == 200)
        read_write = client.post("/api/v1/vouchers/redeem", json={}, headers=scoped_headers)
        check("a_read_only_scope_refuses_a_write",
              read_write.status_code == 403 and read_write.json().get("error") == "forbidden")
        root_only = client.get("/api/v1/admin/tokens", headers=scoped_headers)
        check("a_scoped_token_cannot_manage_tokens", root_only.status_code == 403)
        plugin_denied = client.get("/api/v1/plugins/slackdiscord/status", headers=scoped_headers)
        check("a_core_scope_does_not_reach_a_plugin", plugin_denied.status_code == 403)

        minted_plugin = client.post(
            "/api/v1/admin/tokens",
            json={"label": "http self-test slack reader", "scopes": ["plugin:slack_discord:ro"]},
            headers=headers,
        )
        plugin_token = str((minted_plugin.json() if minted_plugin.status_code == 200 else {}).get("token") or "")
        plugin_headers = {"x-admin-token": plugin_token}
        check("a_plugin_scope_reads_its_plugin_console",
              client.get("/api/v1/plugins/slackdiscord/status", headers=plugin_headers).status_code == 200)
        plugin_write = client.post(
            "/api/v1/plugins/slackdiscord/send",
            json={"workspace_id": "sdw_missing", "text": "nope"}, headers=plugin_headers,
        )
        check("a_plugin_read_scope_refuses_a_plugin_write", plugin_write.status_code == 403)
        cross_plugin = client.get("/api/v1/plugins/sso/status", headers=plugin_headers)
        check("a_plugin_scope_does_not_reach_another_plugin", cross_plugin.status_code == 403)

        listed = client.get("/api/v1/admin/tokens", headers=headers)
        listed_text = listed.text
        check("the_root_can_list_scoped_tokens_without_their_secrets",
              listed.status_code == 200 and scoped_id in listed_text
              and scoped_token not in listed_text and admin_auth.token_hash(scoped_token) not in listed_text)
        bad_scope = client.post(
            "/api/v1/admin/tokens", json={"label": "bad", "scopes": ["core:admin:rw"]}, headers=headers
        )
        bad_expiry = client.post(
            "/api/v1/admin/tokens", json={"label": "bad", "scopes": ["core:status:ro"], "expires_in_days": 0},
            headers=headers,
        )
        check("token_minting_rejects_a_root_only_scope_and_a_past_expiry",
              bad_scope.status_code == 400 and bad_expiry.status_code == 400)

        revoked = client.delete("/api/v1/admin/tokens/" + scoped_id, headers=headers)
        check("the_root_can_revoke_a_scoped_token", revoked.status_code == 200 and revoked.json().get("revoked") is True)
        after_revoke = client.get("/api/v1/status", headers=scoped_headers)
        check("a_revoked_token_stops_working_on_the_next_request", after_revoke.status_code == 401)
        token_audit = client.get("/api/v1/admin/tokens/audit?limit=200", headers=headers)
        audit_body = token_audit.json() if token_audit.status_code == 200 else {}
        audit_text = token_audit.text
        audit_rows = audit_body.get("audit") or []
        check("scoped_requests_are_audited",
              token_audit.status_code == 200
              and any(row.get("outcome") == "scope_denied" for row in audit_rows)
              and any(row.get("outcome") == "used" for row in audit_rows)
              and any(row.get("outcome") == "revoked" for row in audit_rows))
        check("the_audit_list_carries_no_token_or_secret",
              scoped_token not in audit_text and plugin_token not in audit_text
              and admin_auth.token_hash(scoped_token) not in audit_text)

        # Data lifecycle: built-ins are virtual, a custom policy round-trips, and
        # an erase takes ids only — the API has no way to name a payload.
        policies = client.get("/api/v1/data-lifecycle/policies", headers=headers)
        policy_rows = (policies.json() if policies.status_code == 200 else {}).get("policies") or []
        check("the_three_builtin_policies_are_listed",
              policies.status_code == 200
              and [row["policy_id"] for row in policy_rows if row.get("builtin")]
              == ["zero_retention", "ephemeral", "user_owned"])
        check("listing_policies_wrote_no_rows",
              gateway.db.scalar("SELECT COUNT(*) FROM data_lifecycle_policies") == 0)
        custom = client.put("/api/v1/data-lifecycle/policies/scratch-24h",
                            json={"mode": "ephemeral", "temporary_ttl_seconds": 86400}, headers=headers)
        check("a_custom_policy_is_created_over_HTTP",
              custom.status_code == 200
              and custom.json()["policy"]["temporary_ttl_seconds"] == 86400)
        bad_mode = client.put("/api/v1/data-lifecycle/policies/forever",
                              json={"mode": "forever"}, headers=headers)
        changed_builtin = client.put("/api/v1/data-lifecycle/policies/zero_retention",
                                     json={"mode": "ephemeral", "temporary_ttl_seconds": 60}, headers=headers)
        check("a_policy_with_an_unknown_mode_and_a_changed_builtin_are_both_refused",
              bad_mode.status_code == 400 and changed_builtin.status_code == 400)

        admit = lifecycle_engine.admit_task(
            gateway.db, gateway.data_lifecycle_broker, task_id="http-ephemeral-1",
            policy_id="ephemeral", state={"note": "gone"}, workspace_id="http-ws-erase",
            now_ms=now_ms(),
        )
        erased = client.post("/api/v1/data-lifecycle/erase",
                             json={"workspace_id": "http-ws-erase"}, headers=headers)
        check("an_ephemeral_workspace_is_erased_over_HTTP",
              admit["persisted"] is True and erased.status_code == 200
              and erased.json()["result"]["tasks"] == 1
              and gateway.db.scalar("SELECT COUNT(*) FROM data_lifecycle_tasks") == 0)
        bad_erase = client.post("/api/v1/data-lifecycle/erase", json={}, headers=headers)
        expired_erase = client.post("/api/v1/data-lifecycle/erase", json={"scope": "expired"}, headers=headers)
        check("an_empty_erase_request_is_refused_and_an_expired_sweep_is_not",
              bad_erase.status_code == 400 and expired_erase.status_code == 200)
        lifecycle_minted = client.post(
            "/api/v1/admin/tokens",
            json={"label": "http self-test lifecycle reader", "scopes": ["core:data-lifecycle:ro"]},
            headers=headers,
        )
        lifecycle_token = str(
            (lifecycle_minted.json() if lifecycle_minted.status_code == 200 else {}).get("token") or ""
        )
        lifecycle_headers = {"x-admin-token": lifecycle_token}
        check("the_hyphenated_lifecycle_scope_mints_and_reads",
              lifecycle_minted.status_code == 200
              and client.get("/api/v1/data-lifecycle/policies", headers=lifecycle_headers).status_code == 200)
        check("a_lifecycle_read_scope_cannot_erase",
              client.post("/api/v1/data-lifecycle/erase", json={"scope": "expired"},
                          headers=lifecycle_headers).status_code == 403)

        # Compute: default deny, then one heartbeat, one approval, one allocation.
        denied_alloc = client.post(
            "/api/v1/compute/allocate",
            json={"workspace_id": "http-ws-compute", "node_id": "http-node",
                  "policy_id": "zero_retention"},
            headers=headers,
        )
        check("an_unregistered_compute_node_is_refused_over_HTTP",
              denied_alloc.status_code == 404
              and denied_alloc.json().get("error") == "node_not_registered")
        compute_registry.register_node(
            gateway.db, "http-node", "dedicated_worker",
            capabilities={"gpu": True}, now_ms=now_ms(),
        )
        beat = client.post("/api/v1/compute/nodes/http-node/heartbeat", json={}, headers=headers)
        check("a_registered_node_becomes_healthy_with_its_heartbeat",
              beat.status_code == 200 and beat.json()["node"]["health"] == "healthy")
        missing_approval = client.post(
            "/api/v1/compute/allocate",
            json={"workspace_id": "http-ws-compute", "node_id": "http-node",
                  "policy_id": "zero_retention", "capabilities": ["gpu"]},
            headers=headers,
        )
        check("allocation_without_user_approval_is_refused_over_HTTP",
              missing_approval.status_code == 403
              and missing_approval.json().get("error") == "approval_required")
        allowed_alloc = client.post(
            "/api/v1/compute/allocate",
            json={"workspace_id": "http-ws-compute", "node_id": "http-node",
                  "policy_id": "zero_retention", "capabilities": ["gpu"],
                  "approval": {"approved": True, "approval_id": "http-approval-1"}},
            headers=headers,
        )
        check("policy_capability_and_approval_together_allocate_over_HTTP",
              allowed_alloc.status_code == 200
              and allowed_alloc.json()["decision"]["allocation"]["allocation_id"].startswith("cal_"))
        nodes_list = client.get("/api/v1/compute/nodes", headers=headers)
        check("the_node_list_reports_the_live_allocation",
              nodes_list.status_code == 200
              and nodes_list.json()["nodes"][0]["active_allocations"] == 1)
        cleaned_up = client.post("/api/v1/compute/workspaces/http-ws-compute/cleanup", headers=headers)
        check("a_workspace_cleanup_releases_the_allocation_over_HTTP",
              cleaned_up.status_code == 200
              and cleaned_up.json()["result"]["allocations"] == 1
              and compute_registry.allocation_count(gateway.db, "http-node") == 0)
        unknown_beat = client.post("/api/v1/compute/nodes/nobody/heartbeat", json={}, headers=headers)
        check("a_heartbeat_for_an_unknown_node_is_a_404", unknown_beat.status_code == 404)

        served = client.get("/")
        check("the_console_is_served_at_the_root",
              served.status_code == 200 and "text/html" in served.headers.get("content-type", ""))

        empty = client.post("/api/v1/vouchers/redeem", json={}, headers=headers)
        check("a_redeem_without_a_code_is_a_refusal_not_a_crash",
              empty.status_code == 400 and empty.json().get("error") == "code_required")
        forged = client.post("/api/v1/vouchers/redeem", json={"code": "POPX-CP-aaaa.bbbb.cccc"}, headers=headers)
        check("a_code_the_official_key_rejects_is_refused_not_crashed",
              forged.status_code in (400, 401, 402, 403, 409) and forged.json().get("ok") is False)
        redeemed = client.post("/api/v1/vouchers/redeem", json={"code": code}, headers=headers)
        body = redeemed.json() if redeemed.status_code == 200 else {}
        check("a_genuine_POPX-CP_code_redeems_over_HTTP",
              redeemed.status_code == 200 and body.get("result", {}).get("redeemed") is True)
        check("the_redeem_response_carries_the_account_view",
              body.get("account", {}).get("balance") == 5000
              and body.get("account", {}).get("status") == "ONLINE")
        again = client.post("/api/v1/vouchers/redeem", json={"code": code}, headers=headers)
        check("the_same_code_cannot_be_redeemed_twice_over_HTTP",
              again.status_code in (402, 409) and again.json().get("ok") is False)

        poll_url = "/api/v1/plugins/sso/sessions/httpselftest1"
        check("the_qr_poll_route_is_not_token_gated", client.get(poll_url).status_code != 401)
        check("a_plugin_write_on_the_same_path_still_is",
              client.post(poll_url, json={}).status_code == 401)
        check("a_child_of_the_poll_path_is_not_exempt",
              client.get(poll_url + "/anything").status_code == 401)
        check("the_h5_verify_endpoint_is_open_to_the_merchants_server",
              client.post("/api/v1/verifyH5Auth", json={"popopx_uid": "u_x", "ts": "1", "sig": "y"}).status_code
              in (200, 400, 401))

        # The signed alert webhook: with a secret configured, the shared token alone
        # is not enough, and the same bytes cannot be accepted twice. The empty
        # `alerts` array keeps the ingest path quiet while still exercising the
        # signature gate, which is the part this check exists for.
        alert_token = "http-selftest-alert-token-0123456789"
        alert_secret = "http-selftest-alert-secret-0123456789"
        alert_raw = b'{"status":"firing","alerts":[]}'
        alert_ts = int(time.time())
        alert_sig = "v1=" + hmac.new(
            alert_secret.encode("utf-8"), b"%d." % alert_ts + alert_raw, hashlib.sha256
        ).hexdigest()
        alert_headers = {"X-Popopx-Alert-Token": alert_token}
        unsigned_alert = client.post(
            "/api/v1/plugins/alerts/webhook", content=alert_raw, headers=alert_headers
        )
        check("a_webhook_without_its_signature_is_refused_when_a_secret_is_set",
              unsigned_alert.status_code == 401)
        signed_alert = client.post(
            "/api/v1/plugins/alerts/webhook", content=alert_raw,
            headers=dict(alert_headers, **{"X-Popopx-Timestamp": str(alert_ts),
                                          "X-Popopx-Signature": alert_sig}),
        )
        check("a_correctly_signed_webhook_is_accepted",
              signed_alert.status_code == 200 and signed_alert.json().get("ok") is True)
        replayed_alert = client.post(
            "/api/v1/plugins/alerts/webhook", content=alert_raw,
            headers=dict(alert_headers, **{"X-Popopx-Timestamp": str(alert_ts),
                                          "X-Popopx-Signature": alert_sig}),
        )
        check("a_replayed_signed_webhook_is_refused", replayed_alert.status_code == 401)
        stale_ts = alert_ts - 301
        stale_sig = "v1=" + hmac.new(
            alert_secret.encode("utf-8"), b"%d." % stale_ts + alert_raw, hashlib.sha256
        ).hexdigest()
        stale_alert = client.post(
            "/api/v1/plugins/alerts/webhook", content=alert_raw,
            headers=dict(alert_headers, **{"X-Popopx-Timestamp": str(stale_ts),
                                          "X-Popopx-Signature": stale_sig}),
        )
        check("a_signed_webhook_outside_the_window_is_refused", stale_alert.status_code == 401)

        # The nine consoles. Each panel fetches `<url_prefix>/status`, and a plugin
        # router mounted first means its own wildcard (`/{alert_id}`, `/{poll_id}`)
        # answers that path first too — so this is the check that a panel is reachable,
        # not merely that a status route exists somewhere on the gateway. The header is
        # the gateway's documented `x-admin-token`, which two of these plugins used to
        # refuse in favour of their own spelling.
        shadowed = []
        for spec in PLUGIN_SPEC:
            probe = "/status"
            response = client.get(spec.url_prefix + probe, headers=headers)
            named = ""
            try:
                named = str(response.json().get("plugin") or "")
            except Exception:  # noqa: BLE001 — a non-JSON body is the failure being looked for
                named = "not-json"
            # 200 or 503: `ai_agent` answers 503 when no endpoint is configured, which
            # is that plugin documenting its own functional-off state (`/status`'s
            # contract since it was written). Either way the body has to name this
            # plugin — a wildcard's `unknown_alert`/`poll_id_invalid` names nothing.
            if response.status_code not in (200, 503) or named != spec.plugin_id:
                shadowed.append("%s -> %d %s" % (spec.url_prefix + probe, response.status_code, named))
        detail("every_plugin_console_answers_its_status_at_its_own_prefix", shadowed)
        # Control: the wildcards are still live, so the status answers above came from a
        # literal route winning the ordering, not from a matcher that accepts anything.
        wildcard = client.get("/api/v1/plugins/polls/definitely-not-an-id", headers=headers)
        check("the_plugin_wildcard_route_still_answers",
              wildcard.status_code == 400 and "poll_id_invalid" in str(wildcard.json()),
              )

        # The opaque invite format is what the console actually hands to a follower,
        # so it is asserted as served: the field names, the decoding, and — the point
        # of the format — that neither the default link nor its QR names the relay.
        raw_contact = "https://smp1.popopx.test/a#http-service"
        gateway.eco.bridge.contact_address = raw_contact
        served_status = client.get("/api/v1/status", headers=headers).json().get("service", {})
        served_link = str(served_status.get("contact_link") or "")
        check("status_serves_an_opaque_contact_link",
              served_status.get("contact_address") == raw_contact
              and served_link.startswith(LINK_PREFIX)
              and decode_invite(served_link) == raw_contact)
        check("the_status_contact_link_hides_the_relay",
              "popopx.im" not in served_link.lower() and "popopx.test" not in served_link.lower())
        check("the_status_contact_link_is_masked_for_logs",
              str(served_status.get("contact_link_masked") or "").startswith(LINK_PREFIX)
              and served_status.get("contact_link_masked") != served_link
              and served_link not in str(served_status.get("contact_link_masked")))
        check("the_status_contact_link_records_when_it_was_minted",
              isinstance(served_status.get("contact_link_created_at_ms"), int)
              and served_status["contact_link_created_at_ms"] > 0)
        check("the_status_contact_link_minted_without_an_error",
              not served_status.get("contact_link_error"))

        minted = client.post("/api/v1/invite-links", json={}, headers=headers)
        minted_body = minted.json()
        minted_link = str(minted_body.get("link") or "")
        minted_qr = str(minted_body.get("qr_svg") or "")
        check("the_invite_route_mints_the_opaque_service_account_link",
              minted.status_code == 200 and minted_body.get("kind") == "service_account"
              and minted_body.get("subject_id") == gateway.eco.service_id
              and minted_link == served_link and minted_body.get("cached") is True)
        check("the_invite_route_returns_a_QR_of_the_opaque_link",
              minted_qr.lstrip().startswith("<svg") and not minted_body.get("qr_error")
              and "popopx.im" not in minted_qr.lower() and "popopx.test" not in minted_qr.lower())
        check("the_invite_route_does_not_echo_the_raw_uri",
              raw_contact not in str(minted_body) and "smp1.popopx.test" not in str(minted_body))
        # The anti-phishing property: a caller-supplied URI is ignored, so this
        # route cannot seal somebody else's string under the popopx.chat domain.
        phishing = client.post(
            "/api/v1/invite-links",
            json={"kind": "service_account", "uri": "https://evil.example/free-money"},
            headers=headers,
        ).json()
        check("the_invite_route_ignores_a_caller_supplied_uri",
              decode_invite(str(phishing.get("link") or "")) == raw_contact
              and "evil.example" not in str(phishing))

        created = client.post(
            "/api/v1/channels",
            json={"channel_id": "ch-http-invite", "title": "HTTP Invite", "relay": "smp2.popopx.test"},
            headers=headers,
        )
        created_body = created.json()
        created_channel = created_body.get("channel", {})
        channel_link = str(created_channel.get("invite_link") or "")
        channel_uri = str(created_body.get("public_uri") or "")
        check("a_created_channel_carries_an_opaque_invite_link",
              created.status_code == 200 and channel_uri.startswith("popopx://channel/")
              and channel_link.startswith(LINK_PREFIX) and decode_invite(channel_link) == channel_uri)
        check("a_created_channel_still_exposes_the_raw_uri_for_diagnostics",
              "smp2.popopx.test" in channel_uri)
        check("a_created_channel_invite_link_hides_the_relay",
              "popopx.test" not in channel_link.lower() and channel_link != channel_uri)

        channel_minted = client.post(
            "/api/v1/invite-links", json={"kind": "channel", "channel_id": "ch-http-invite"}, headers=headers
        ).json()
        channel_minted_link = str(channel_minted.get("link") or "")
        check("the_invite_route_serves_a_channels_QR_without_its_relay",
              channel_minted.get("ok") is True and channel_minted_link == channel_link
              and str(channel_minted.get("qr_svg") or "").lstrip().startswith("<svg")
              and "smp2.popopx.test" not in str(channel_minted))
        channel_read = client.get("/api/v1/channels/ch-http-invite", headers=headers).json()
        check("a_channel_read_serves_the_same_opaque_invite_link",
              str(channel_read.get("invite_link") or "") == channel_link
              and str(channel_read.get("public_uri") or "") == channel_uri)
        channel_list = client.get("/api/v1/channels", headers=headers).json().get("channels", [])
        check("the_channel_list_carries_opaque_invite_links",
              len(channel_list) == 1 and str(channel_list[0].get("invite_link") or "") == channel_link)

        no_relay = client.post(
            "/api/v1/channels", json={"channel_id": "ch-http-no-relay", "title": "No Relay"}, headers=headers
        ).json().get("channel", {})
        check("a_channel_without_a_relay_reports_the_invite_error_instead_of_a_link",
              no_relay.get("invite_link") is None
              and no_relay.get("invite_link_error") == "invite_source_unavailable")
        refused_invite = client.post(
            "/api/v1/invite-links", json={"kind": "channel", "channel_id": "ch-http-no-relay"}, headers=headers
        )
        check("the_invite_route_conflicts_when_the_channel_has_no_relay",
              refused_invite.status_code == 409
              and refused_invite.json().get("error") == "invite_source_unavailable")

        audit = client.get("/api/v1/invite-links/audit", headers=headers).json().get("entries", [])
        audit_columns = {"id", "created_at_ms", "kind", "subject_id", "code_prefix"}
        check("the_invite_audit_lists_one_masked_row_per_generation",
              audit and all(set(entry) == audit_columns for entry in audit)
              and {entry["kind"] for entry in audit} == {"service_account", "channel"}
              and all(len(str(entry.get("code_prefix") or "")) == 10 for entry in audit))
        check("the_invite_audit_never_stores_the_link_code_or_raw_uri",
              LINK_PREFIX not in str(audit)
              and minted_link[len(LINK_PREFIX):] not in str(audit)
              and channel_link[len(LINK_PREFIX):] not in str(audit)
              and raw_contact not in str(audit)
              and "popopx.test" not in str(audit).lower()
              and "popopx.im" not in str(audit).lower())
        bad_kind = client.post("/api/v1/invite-links", json={"kind": "contact"}, headers=headers)
        check("the_invite_route_refuses_an_unknown_kind",
              bad_kind.status_code == 400 and bad_kind.json().get("error") == "invite_kind_invalid")
        missing_channel = client.post(
            "/api/v1/invite-links", json={"kind": "channel", "channel_id": "ch-nobody"}, headers=headers
        )
        check("the_invite_route_refuses_an_unknown_channel",
              missing_channel.status_code == 404 and missing_channel.json().get("error") == "channel_not_found")

        # The other failure an operator meets is the polite one: the socket is up and
        # the node refuses. These two frames are what a real `popopx-chat` answered
        # on 2026-11-21 (`userExists` to `/_profile`, `contactNotFound` to `/_send`),
        # and both used to reach the console as `503 node_unreachable` — an
        # instruction to go and check a link that had just replied.
        node_up["refuse"] = NodeCommandError(
            {"type": "error", "errorType": {"type": "userExists", "contactName": "POPOPX E2E"}},
            '/_profile 2 {"displayName":"POPOPX E2E","fullName":""}',
        )
        refused = client.put(
            "/api/v1/node/profile",
            json={"display_name": "POPOPX E2E", "full_name": ""},
            headers=headers,
        )
        check("a_refused_command_is_not_reported_as_a_dead_link",
              refused.status_code == 502 and refused.json().get("error") == "node_refused")
        check("a_refusal_carries_the_nodes_own_reason", refused.json().get("node_error") == "userExists")
        unknown = client.post(
            "/api/v1/send/text", json={"contact_id": 99, "text": "a contact nobody has"}, headers=headers
        )
        check("an_unknown_contact_is_refused_before_the_node_is_asked",
              unknown.status_code == 400 and unknown.json().get("error") == "unknown_contact")
        gateway.eco.touch_contact(99, "Probe Contact")
        refused_send = client.post(
            "/api/v1/send/text", json={"contact_id": 99, "text": "a refused send"}, headers=headers
        )
        # The frame the node refused was never written to `outbox`, so `queued` had
        # nothing behind it: it was `not delivered`, which is a different statement.
        check("a_refused_send_is_not_claimed_as_queued",
              refused_send.status_code == 200 and refused_send.json() == {
                  "ok": False, "contact_id": 99, "delivered": False, "queued": False})
        # The other half of that predicate, so the fix above cannot pass by always
        # answering `queued: false`: with no socket the frame really is durably
        # parked, and the route has to say so.
        node_up["refuse"] = None
        gateway.eco.bridge._ws = None            # what `connected` reads
        parked = client.post(
            "/api/v1/send/text", json={"contact_id": 99, "text": "queued while down"}, headers=headers
        )
        gateway.eco.bridge._ws = socket
        check("a_send_parked_while_the_link_is_down_reports_it",
              parked.status_code == 200 and parked.json().get("queued") is True
              and parked.json().get("delivered") is False)
        # Control for the split above — the transport case is still 503, asserted by
        # the block below, so this is a classification and not every node failure
        # having quietly moved to 502.

        # The link going away is the one failure every deployment meets — a node
        # restarting, a laptop closed — so the routes that ask it directly have to name
        # it rather than leak the bridge's exception as a 500.
        node_up["linked"] = False
        downed = []
        for method, url, payload in (
            ("get", "/api/v1/node/contacts", None),
            ("post", "/api/v1/node/address", {}),
            ("put", "/api/v1/node/profile", {"display_name": "Self Test", "full_name": ""}),
        ):
            response = (client.get(url, headers=headers) if payload is None
                        else getattr(client, method)(url, json=payload, headers=headers))
            try:
                error = str(response.json().get("error") or "")
            except Exception:  # noqa: BLE001 — a non-JSON body is itself the failure
                error = "not-json"
            downed.append("%s %s -> %d %s" % (method.upper(), url, response.status_code, error))
        detail(
            "a_node_dependent_route_names_the_link_instead_of_500ing",
            [row for row in downed if not row.endswith("503 node_unreachable")],
        )
        gateway.db.close_all()
    finally:
        for key in [k for k in os.environ if k.startswith("POPOPX_")]:
            del os.environ[key]
        os.environ.update(saved_env)

    return checks


# ─────────────────────────────────────────────────────────────────────────────
# 8. Entrypoint — `python -m app.main` is what every launcher in this repo runs
# ─────────────────────────────────────────────────────────────────────────────

#: Every module that owns a suite of its own. ``--self-test`` runs this list and
#: prints one line per module, because the protocol suite in ``self_test()`` above
#: proves the wire formats and nothing else: the billing state machine, the
#: channel-key crypto and the paid plugins all live in other files, and a
#: launcher that reported "220 checks passed" while leaving them out would be
#: advertising coverage it did not have. A module missing from a *file* that does
#: not exist is a build error; a module whose file exists but has no suite is only
#: visible here, which is why ``MISSING`` exits non-zero instead of printing
#: nothing.
SELF_TEST_MODULES: Tuple[str, ...] = (
    "app.database",
    "app.config",
    "app.admin_auth",
    "app.data_lifecycle.policy",
    "app.data_lifecycle.retention",
    "app.data_lifecycle.audit",
    "app.data_lifecycle.policy_engine",
    "app.data_lifecycle.cleanup",
    "app.compute.registry",
    "app.compute.authorizer",
    "app.vault",
    "app.crypto_service",
    "app.billing_service",
    "app.agent_bridge",
    "app.connectors",
    "app.plugins",
    "app.plugins.ai_agent_plugin",
    "app.plugins.alert_ops_plugin",
    "app.plugins.polls_plugin",
    "app.plugins.privacy_sso_plugin",
    "app.plugins.web3_bridge_plugin",
    "app.plugins.workflow_webhook_plugin",
    "app.plugins.carddav_connector",
    "app.plugins.caldav_connector",
    "app.plugins.slack_discord_plugin",
)


def _self_test_extra(protocol_checks: List[str]) -> int:
    """Run the suites that live outside ``app.main``, and account for the ones that cannot.

    Three outcomes per module, deliberately different on the console:

    ``ok``       — the suite ran; its count is in the total;
    ``SKIPPED``  — the module cannot be imported or its suite needs a wheel this
                   interpreter does not have (``cryptography`` for the real
                   Ed25519/ChaCha20-Poly1305 paths). Not a failure: this is the
                   state of a machine partway through installing the suite, and
                   the one-click launcher must still come up. It is printed
                   because "skipped" and "passed" must never look the same;
    ``MISSING``  — the file is importable but has no ``self_test``. That is a
                   hole in the delivery, so it fails.

    Returns the process exit status: 0 unless a suite failed or one is missing.
    """
    import importlib
    import importlib.util

    write = sys.stdout.write
    total = len(protocol_checks)
    skipped: List[str] = []
    missing: List[str] = []
    write("self-test: app.main (protocol layer) %d checks\n" % len(protocol_checks))

    for dotted in SELF_TEST_MODULES:
        try:
            module = importlib.import_module(dotted)
        except Exception as exc:  # noqa: BLE001 — any import failure is a skip, named
            skipped.append("%s (%s: %s)" % (dotted, type(exc).__name__, exc))
            write("  SKIPPED  %-36s cannot be imported here: %s: %s\n" % (dotted, type(exc).__name__, exc))
            continue
        suite = getattr(module, "self_test", None)
        if not callable(suite):
            missing.append(dotted)
            write("  MISSING  %-36s no self_test() — this module ships unverified\n" % dotted)
            continue
        try:
            names = suite()
        except Exception as exc:  # noqa: BLE001 — a failing suite is reported, not buried
            write("  FAILED   %-36s %s: %s\n" % (dotted, type(exc).__name__, exc))
            return 1
        if not isinstance(names, list) or not names:
            write("  MISSING  %-36s self_test() returned %r, not a list of check names\n" % (dotted, type(names).__name__))
            return 1
        total += len(names)
        write("  ok       %-36s %d checks\n" % (dotted, len(names)))

    # The crypto half of `crypto_service` is a separate function precisely because
    # it needs the wheel: without it, its checks would be the *stub* answers and
    # the pass would mean nothing. So it is attempted, and its absence is said.
    try:
        crypto = importlib.import_module("app.crypto_service")
        if importlib.util.find_spec("cryptography") is None:
            raise ImportError("the 'cryptography' distribution is not installed")
    except Exception as exc:  # noqa: BLE001
        skipped.append("app.crypto_service.crypto_self_test (%s)" % exc)
        write(
            "  SKIPPED  %-36s real Ed25519 / ChaCha20-Poly1305 paths NOT exercised: %s\n"
            % ("app.crypto_service.crypto_self_test", exc)
        )
        write(
            "           run it on a machine with the wheel, and against the iOS client with\n"
            "           official_tools/swift_crypto_oracle.swift, before trusting a sealed channel\n"
        )
    else:
        try:
            names = crypto.crypto_self_test()
        except Exception as exc:  # noqa: BLE001
            write("  FAILED   %-36s %s: %s\n" % ("app.crypto_service.crypto_self_test", type(exc).__name__, exc))
            return 1
        total += len(names)
        write("  ok       %-36s %d checks\n" % ("app.crypto_service.crypto_self_test", len(names)))

    # The opaque invite format rides on the same wheel as the crypto group but is
    # gated separately: its vectors are the cross-language contract with the iOS
    # client, and a suite that quietly ran against the stub would print the same
    # "ok" line as one that proved the published bytes.
    codec_gated = "app.opaque_invite_codec.opaque_invite_self_test"
    try:
        codec = importlib.import_module("app.opaque_invite_codec")
        if importlib.util.find_spec("cryptography") is None:
            raise ImportError("the 'cryptography' distribution is not installed")
    except Exception as exc:  # noqa: BLE001
        skipped.append("%s (%s)" % (codec_gated, exc))
        write(
            "  SKIPPED  %-36s cross-language invite vectors NOT verified: %s\n"
            % (codec_gated, exc)
        )
        write(
            "           run it with the wheel, and against official_tools/swift_opaque_invite_oracle.swift,\n"
            "           before trusting a console that hands these links to followers\n"
        )
    else:
        try:
            names = codec.opaque_invite_self_test()
        except Exception as exc:  # noqa: BLE001
            write("  FAILED   %-36s %s: %s\n" % (codec_gated, type(exc).__name__, exc))
            return 1
        total += len(names)
        write("  ok       %-36s %d checks\n" % (codec_gated, len(names)))

    # The HTTP group needs the wheels for a different reason than the crypto one: its
    # subject *is* the ASGI app. Without FastAPI there is no router to send a request
    # to, so the two defects it exists for — an annotation FastAPI could not resolve,
    # and a `.to_dict()` on a dict — are unanswerable rather than passing.
    http_gated = "app.main.http_self_test"
    try:
        for distribution in ("fastapi", "httpx", "cryptography"):
            if importlib.util.find_spec(distribution) is None:
                raise ImportError("the %r distribution is not installed" % distribution)
    except Exception as exc:  # noqa: BLE001
        skipped.append("%s (%s)" % (http_gated, exc))
        write(
            "  SKIPPED  %-36s no HTTP checks: %s\n" % (http_gated, exc)
        )
        write(
            "           the routes were never requested; install the wheels in gateway/requirements.txt\n"
            "           and re-run before trusting the admin API or a redemption\n"
        )
    else:
        try:
            names = http_self_test()
        except Exception as exc:  # noqa: BLE001
            write("  FAILED   %-36s %s: %s\n" % (http_gated, type(exc).__name__, exc))
            return 1
        total += len(names)
        write("  ok       %-36s %d checks\n" % (http_gated, len(names)))

    if missing:
        write("self-test: FAILED — %d module(s) ship without a suite: %s\n" % (len(missing), ", ".join(missing)))
        return 1
    write(
        "self-test: %d checks passed across %d groups\n"
        % (total, len(SELF_TEST_MODULES) + 4 - len(skipped) - len(missing))
    )
    if skipped:
        write("self-test: %d group(s) skipped on this interpreter: %s\n" % (len(skipped), "; ".join(skipped)))
        write("self-test: those paths are NOT verified here; install the wheels in gateway/requirements.txt and re-run\n")
    return 0


def main(argv: Optional[Sequence[str]] = None) -> int:
    """Serve the gateway, or answer the two questions an installer asks first.

    The bind address, the port and the log level come from the same
    :class:`~app.config.Config` the rest of the suite reads, so there is one place
    to change them; the launchers used to pass `--host/--port` on the command line
    *and* export `POPOPX_GATEWAY_HOST/PORT`, which is two sources of truth about one
    socket and the CLI flag silently won.

    `--self-test` deliberately does not load the config: it is the check that runs
    before `.env` exists, on the interpreter that has no wheels yet, and an entry
    point that needed a configured database to say "the protocol code is sound"
    could only ever be run by someone who did not need it.
    """
    parser = argparse.ArgumentParser(
        prog="python -m app.main",
        description="POPOPX service-account gateway (eco protocol, POPX-CP billing, plugins).",
    )
    parser.add_argument("--env", default=None, help="path to the environment file (default: the documented search order)")
    parser.add_argument("--host", default=None, help="override POPOPX_GATEWAY_HOST for this run")
    parser.add_argument("--port", type=int, default=None, help="override POPOPX_GATEWAY_PORT for this run")
    parser.add_argument("--self-test", action="store_true", help="run the protocol suite (no wheels, no node, no config) and exit")
    parser.add_argument("--check-routes", action="store_true", help="verify every admin route is token-guarded, then exit")
    parser.add_argument("--print-routes", action="store_true", help="print the route table and exit")
    parser.add_argument("--migrate-secrets", action="store_true", help="seal every plaintext secret with POPOPX_VAULT_KEY and exit")
    args = parser.parse_args(argv)

    if args.migrate_secrets:
        from app.vault import migrate_secrets

        try:
            config = load_config(Path(args.env)) if args.env else load_config()
        except ConfigError as exc:
            sys.stderr.write("POPOPX gateway cannot start: %s\n" % exc)
            return 3
        if not config.vault_key:
            sys.stderr.write(
                "--migrate-secrets needs POPOPX_VAULT_KEY set to a 32-byte key; "
                "generate one with: openssl rand -hex 32\n"
            )
            return 3
        database = Database(config.db_path)
        try:
            report = migrate_secrets(database, SecretBox(config.vault_key))
        except VaultError as exc:
            sys.stderr.write("migration refused: %s\n" % exc)
            return 1
        for row in report["tables"]:
            sys.stdout.write(
                "%-24s %-22s sealed=%-4d already-sealed-or-empty=%-4d errors=%d\n"
                % (row["table"], row["column"], row["sealed"], row["skipped"], row["errors"])
            )
        sys.stdout.write(
            "secrets: %d sealed, %d already sealed or empty, %d errors\n"
            % (report["sealed"], report["skipped"], report["errors"])
        )
        return 0 if report["errors"] == 0 else 1

    if args.self_test:
        logging.basicConfig(level=logging.ERROR, format="%(levelname)s %(name)s: %(message)s")
        passed = self_test()
        sys.stdout.write("self-test: %d checks passed\n" % len(passed))
        return _self_test_extra(passed)

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)-7s %(name)s: %(message)s")

    if args.print_routes or args.check_routes:
        rows = route_census()
        count = assert_routes_are_gated(rows)
        if args.print_routes:
            for row in sorted(rows, key=lambda r: (str(r["path"]), str(r["verb"]))):
                sys.stdout.write("%-6s %-42s %s\n" % (
                    str(row["verb"]).upper(), row["path"], "token" if row["admin"] else "PUBLIC"))
        sys.stdout.write("routes: %d, all guarded or explicitly public\n" % count)
        return 0

    try:
        config = load_config(Path(args.env)) if args.env else load_config()
    except ConfigError as exc:
        # One readable line and a nonzero status, not a traceback. Every reason
        # load_config refuses is an operator decision with a documented fix
        # (generate the token, print the official public key); the call stack of
        # the loader adds nothing to that and costs the reader the sentence.
        sys.stderr.write("POPOPX gateway cannot start: %s\n" % exc)
        return 3
    if args.host:
        config.gateway_host = args.host
    if args.port:
        config.gateway_port = int(args.port)

    # Printed before the import that can fail: when a deployment has no uvicorn
    # wheel — the exact state of a machine right after the installer synced the
    # source but before the venv step — the one thing an operator still needs is
    # which config the process read. The launcher greps this line to prove its
    # exported POPOPX_* overrides actually reached the child process instead of
    # being swallowed by the shell.
    sys.stdout.write(
        "POPOPX gateway config: host=%s port=%d db=%s node=%s base=%s\n"
        % (config.gateway_host, int(config.gateway_port), config.db_path,
           config.node.ws_url, config.public_base_url)
    )

    try:
        import uvicorn
    except ImportError as exc:  # pragma: no cover — deployment step, not a code fault
        sys.stderr.write(
            "uvicorn is not installed; run ./start_macos.sh or install gateway/requirements.txt "
            "into the venv first (%s)\n" % exc
        )
        return 2

    app = create_app(config=config)
    sys.stdout.write(
        "POPOPX gateway on http://%s:%d (node %s, service %s)\n"
        % (config.gateway_host, config.gateway_port, config.node.ws_url, config.service_id)
    )
    # No `workers=`: a worker count above one needs an import string, and this
    # process must not fork — the node link and its pending-correlation table are
    # per-process state, so a second worker would be a second, conflicting link.
    uvicorn.run(
        app,
        host=config.gateway_host,
        port=int(config.gateway_port),
        log_level=config.log_level.lower(),
        loop="asyncio",
        access_log=False,
        proxy_headers=True,
        forwarded_allow_ips="*",
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
