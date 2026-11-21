# Copyright (c) 2026 POPOPX (popopx.chat)
# SPDX-License-Identifier: AGPL-3.0-only
"""WebSocket link to the POPOPX chat node, plus the silent-callback grammar.

This is the only seam between this suite and the chat node, and the seam is
deliberate: everything crosses as WebSocket JSON against the node's documented
public API. Nothing here imports, links, copies or derives from node code — the
command strings and response shapes are the
documented public interface in `bots/api/COMMANDS.md` and `bots/api/TYPES.md` of
the node repository, quoted with file references where a detail is load-bearing.

The asymmetry that governs this file
------------------------------------
OUTBOUND is strict: every frame is validated against the iOS client's parser rules
in `crypto_service` before it is sent, because the client drops a frame it cannot
parse *silently*.

INBOUND is lenient, on instruction from the node's own documentation
(`bots/README.md:183`): "Your bot must allow and ignore all events it does not
process, it should not fail when it encounters undocumented event types. Your bot
JSON parser must allow additional properties in all types, and must allow and
ignore records with unknown union tags and unknown enum strings." A node upgrade
that adds an event type must not be able to take a merchant's service account
offline, so nothing here raises on an unexpected field, and unknown response tags
are treated as success unless they are the documented error tag.

The same README (:188) is why the default URL is loopback: "WebSockets API of
POPOPX Chat CLI does not support any authentication. CLI binds only to localhost
… The messages in WebSocket API are not encrypted in any way, and must not be sent
via public networks."

The command surface used here
-----------------------------
Every string is the documented syntax, e.g. `/_send` (COMMANDS.md:356-395, syntax
at :372):

    /_send <str(sendRef)>[ live=on][ ttl=<ttl>][ sign=on] json <json(composedMessages)>

Note `composedMessages` is a LIST (`[[ComposedMessage]]`, COMMANDS.md:367) —
sending one bare object is the kind of mistake that returns a parse error per
message rather than at build time. `ChatRef` is `@<contactId>` and `/_send` takes
no `<userId>` parameter at all: contact ids are unique in the node's database, so
the reference alone names the peer. Commands that DO list a `<userId>`
(`/_contacts`, `/_profile`, `/_address`, …) get it from `AgentBridge.user_id`,
discovered at startup.

`websockets` is imported inside `_connect_once`, so this module imports — and
`self_test()` runs — on a machine with no third-party packages installed.
"""

from __future__ import annotations

import asyncio
import json
import logging
import socket
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, Dict, List, Mapping, Optional, Tuple

LOG = logging.getLogger("popopx.agent_bridge")

# ─────────────────────────────────────────────────────────────────────────────
# 1. Errors
# ─────────────────────────────────────────────────────────────────────────────


class NodeError(RuntimeError):
    """Base for everything this module can fail with."""


class NodeNotConnected(NodeError):
    """The link is down. Distinct from a command error so a caller can retry
    instead of surfacing a user-visible failure."""

    def __init__(self, detail: str = "the WebSocket link to the node is not established") -> None:
        super().__init__(detail)


class NodeTimeout(NodeError):
    """No response within the deadline. The command MAY still have been executed,
    so callers must treat this as "unknown", which is why sends go through the
    outbox rather than being reported as failed."""

    def __init__(self, corr_id: str, seconds: float) -> None:
        super().__init__("no response to %s within %.1fs" % (corr_id, seconds))
        self.corr_id = corr_id
        self.seconds = seconds


class NodeCommandError(NodeError):
    """The node answered with `chatCmdError` — COMMANDS.md:390 calls it "Command
    error (only used in WebSockets API)", so this tag is the WS link's own failure
    channel and never appears inside an event."""

    def __init__(self, chat_error: Mapping[str, Any], command: str) -> None:
        self.chat_error = dict(chat_error)
        self.command = command
        super().__init__("%s -> %s" % (command, json.dumps(chat_error, ensure_ascii=False)[:400]))


# ─────────────────────────────────────────────────────────────────────────────
# 2. The silent-callback grammar
#
# These markers are emitted by the shipped client and are NOT visible chat
# messages: each arrives as an ordinary text `chatItem` and must be consumed
# without ever replying in a way that acknowledges it as user speech. Every
# literal below is transcribed from the client source, with the emitting line:
#
#   ::CB::<payload>                          a card button with action `callback`
#                                            (PopopxEcoRouterAndDeepLink.swift:497,
#                                             the kind at PopopxEcoModels.swift:651)
#   ::CB::<payload>:paid_<entryId>           a `pay_credits` button after the debit
#                                            succeeded — `<entryId>` is the local ledger
#                                            row, not a chain hash (…:569)
#   ::CB::rotate:<channelId>                 one-tap key rotation request, sent as
#                                            payload "rotate:<id>" to the issuer
#                                            (ChannelKeyRotationManager.swift:920)
#   ::REF::<article_id>                      an article opened from a card
#                                            (`PopopxEcoRouter.sendReference`, which builds
#                                            the line through `PopopxEcoUplink.wireString`)
#   ::SSO_SCAN::<session_id>                 a QR the device camera already scanned
#                                            (`PopopxEcoRouter.sendSSOScan`, same builder)
# The three prefixes are declared once, as `PopopxEcoUplink.callbackPrefix`,
# `.referencePrefix` and `.ssoScanPrefix`; no uplink line is spelled by hand on either side.
#   ::popopx_sys::<KIND>::<payload>          system requests and receipts; KIND is the
#                                            enum at PopopxBadgeCreditsModels.swift:1085-1100
#
# There is deliberately NO claim that `CHANNEL_SUB_PAID` is the contract: the brief
# names it, the client sends `CHANNEL_PAY_RCPT` with payload
# `<channelId>:<credits>:<txHash>`. Both spellings are recognised on the way in (an
# older build may exist in the wild) but only the real one is documented as such.
# ─────────────────────────────────────────────────────────────────────────────

CALLBACK_PREFIX = "::CB::"
ARTICLE_PREFIX = "::REF::"
SSO_SCAN_PREFIX = "::SSO_SCAN::"
SYSTEM_PREFIX = "::popopx_sys::"
PAID_SUFFIX = ":paid_"
ROTATE_MARKER = "rotate:"

# The exact value set of `PopopxCommerceSignalKind` (PopopxBadgeCreditsModels.swift:1085-1108),
# twelve cases, transcribed so a rename on either side is a visible diff rather than a
# silently unhandled signal. `CHANNEL_SUB_PAID` is NOT one of them; it is kept last, marked
# legacy, so an older client's receipt still resolves instead of becoming unknown text.
SYSTEM_KINDS = (
    "EXT_REDEEM_REQ",
    "EXT_REDEEM_ACK",
    "CHAT_REDEEM_REQ",
    "CHAT_REDEEM_ACK",
    "REDPACKET_CLAIMED",
    "PROFILE_UNLOCKED",
    "CHANNEL_SUB_ACK",
    "CHANNEL_PAY_RCPT",
    "CREDIT_EXT_REDEEM_REQ",
    "CREDIT_EXT_REDEEM_ACK",
    "CREDIT_CHAT_REDEEM_REQ",
    "CREDIT_CHAT_REDEEM_ACK",
    # Accepted for tolerance of older clients; not part of the current grammar.
    "CHANNEL_SUB_PAID",
)

# Kinds whose payload is `<a>::<b>` rather than `<a>:<b>:<c>` — the client splits these on
# the LAST pair of `::` because the conversation key itself looks like `#<local row>`
# (PopopxBadgeCreditsModels.swift:1094-1095).
SYSTEM_DOUBLE_COLON_KINDS = ("CHANNEL_SUB_ACK",)


@dataclass(frozen=True)
class InboundCallback:
    """One parsed inbound text message, classified.

    `.silent` is the flag that matters to the caller: True means the client sent a
    control message, so the gateway must answer through the protocol (a card
    update, a receipt) and must NOT run the merchant's autoreply or AI on it.
    """

    kind: str                      # card_callback | card_paid | rotate_request | article_ref
                                   # | sso_scan | system | text
    raw: str
    payload: str = ""
    paid_ref: str = ""
    sys_kind: str = ""
    sys_fields: Tuple[str, ...] = ()
    channel_id: str = ""
    credits: int = 0
    tx_hash: str = ""
    expires_at_ms: int = 0

    @property
    def silent(self) -> bool:
        return self.kind != "text"

    @property
    def known_system_kind(self) -> bool:
        return self.sys_kind in SYSTEM_KINDS

    @property
    def is_payment_receipt(self) -> bool:
        return self.kind == "system" and self.sys_kind in ("CHANNEL_PAY_RCPT", "CHANNEL_SUB_PAID")


def _digits(value: str) -> int:
    """An int from a decimal string, 0 otherwise. Control payloads come from a
    phone, so a non-numeric field is data to report, not a reason to lose the
    whole signal."""
    text = value.strip()
    return int(text) if text.isdigit() else 0


def parse_inbound_text(text: str) -> InboundCallback:
    """Classify a chat message body. Never raises: an unparseable control-looking
    string is returned as `kind="text"` so a user typing `::CB::hello` in a normal
    sentence cannot break the pipeline or spoof a callback more precisely than
    they could by sending the real thing."""
    if not isinstance(text, str):
        return InboundCallback(kind="text", raw="" if text is None else str(text))
    body = text.strip()
    if not body:
        return InboundCallback(kind="text", raw=text)

    if body.startswith(SYSTEM_PREFIX):
        # The kind is delimited by the FIRST `::` after the prefix; kinds contain no
        # colon, so this cannot be confused by a payload that does.
        kind, sep, payload = body[len(SYSTEM_PREFIX):].partition("::")
        if not sep:
            return InboundCallback(kind="text", raw=text)
        channel_id, credits, tx_hash, expires_at_ms = "", 0, 0, 0
        if kind in ("CHANNEL_PAY_RCPT", "CHANNEL_SUB_PAID"):
            # `{channelId}:{credits}:{txHash}` (PopopxBadgeCreditsModels.swift:1098).
            # channelId and credits are both colon-free, so maxsplit=2 is enough to
            # isolate them and leaves the hash as the tail verbatim — a hash is opaque
            # here, and re-splitting it would silently drop part of the replay key.
            fields = tuple(payload.split(":", 2))
            if len(fields) >= 2:
                channel_id, credits = fields[0], _digits(fields[1])
                tx_hash = fields[2] if len(fields) > 2 else ""
        elif kind in SYSTEM_DOUBLE_COLON_KINDS and "::" in payload:
            head, _, tail = payload.rpartition("::")
            fields = (head, tail)
            channel_id, expires_at_ms = head, _digits(tail)
        else:
            fields = (payload,) if payload else ()
        return InboundCallback(
            kind="system",
            raw=text,
            payload=payload,
            sys_kind=kind,
            sys_fields=fields,
            channel_id=channel_id,
            credits=credits,
            tx_hash=tx_hash,
            expires_at_ms=expires_at_ms,
        )

    if body.startswith(CALLBACK_PREFIX):
        payload = body[len(CALLBACK_PREFIX):]
        if payload.startswith(ROTATE_MARKER):
            return InboundCallback(
                kind="rotate_request",
                raw=text,
                payload=payload,
                channel_id=payload[len(ROTATE_MARKER):],
            )
        # `:paid_` is a suffix, so the payload itself may contain ':'. rsplit
        # keeps a payload like "order:42" intact.
        if PAID_SUFFIX in payload:
            head, _, paid_ref = payload.rpartition(PAID_SUFFIX)
            return InboundCallback(kind="card_paid", raw=text, payload=head, paid_ref=paid_ref)
        return InboundCallback(kind="card_callback", raw=text, payload=payload)

    if body.startswith(ARTICLE_PREFIX):
        return InboundCallback(kind="article_ref", raw=text, payload=body[len(ARTICLE_PREFIX):])

    if body.startswith(SSO_SCAN_PREFIX):
        return InboundCallback(kind="sso_scan", raw=text, payload=body[len(SSO_SCAN_PREFIX):])

    return InboundCallback(kind="text", raw=text, payload=body)


# ─────────────────────────────────────────────────────────────────────────────
# 3. Inbound normalisation
# ─────────────────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class InboundMessage:
    """A direct message from a contact, already reduced to what services need."""

    contact_id: int
    display_name: str
    item_id: int
    text: str
    callback: InboundCallback
    direction: str            # "rcv" | "snd" | "other"
    raw_item: Mapping[str, Any] = field(default_factory=dict)
    user_id: Optional[int] = None

    @property
    def received(self) -> bool:
        return self.direction == "rcv"

    @property
    def is_control(self) -> bool:
        return self.callback.silent


def _extract_text(chat_item: Mapping[str, Any]) -> str:
    """The body, preferring the content and falling back to the meta copy.

    `CIContent` is a union: `{"type":"rcvMsgContent","msgContent":{...}}` for a
    received message, `sndMsgContent` for a sent one (TYPES.md:702-730). `CIMeta`
    also carries `itemText` as a display string (TYPES.md:1073-1090) and is the
    fallback when the content type is one this suite does not model, e.g. a file
    or a reaction, so a message is never silently lost by a strict reader.
    """
    content = chat_item.get("content")
    if isinstance(content, Mapping):
        msg = content.get("msgContent")
        if isinstance(msg, Mapping):
            for key in ("text", "preview"):
                value = msg.get(key)
                if isinstance(value, str) and value:
                    return value
    meta = chat_item.get("meta")
    if isinstance(meta, Mapping):
        value = meta.get("itemText")
        if isinstance(value, str):
            return value
    return ""


def _direction(chat_item: Mapping[str, Any], content: Mapping[str, Any]) -> str:
    """Decide received vs sent from `content.type`, not `chatDir`.

    `chatDir` is a union the node has re-shaped across releases, while
    `rcvMsgContent` / `sndMsgContent` are the tags this command surface documents
    for message content, and they are the same field the text is read from — so
    direction and payload cannot disagree. A chatDir that is understood is still
    honoured when it contradicts, and an unknown value yields "other" rather than
    an exception.
    """
    content_type = content.get("type") if isinstance(content, Mapping) else None
    if isinstance(content_type, str):
        if content_type.startswith("rcv"):
            return "rcv"
        if content_type.startswith("snd"):
            return "snd"
    chat_dir = chat_item.get("chatDir")
    if isinstance(chat_dir, str):
        return "rcv" if "Rcv" in chat_dir or chat_dir == "received" else "snd"
    if isinstance(chat_dir, Mapping):
        marker = json.dumps(chat_dir)
        if "Rcv" in marker:
            return "rcv"
        if "Snd" in marker:
            return "snd"
    return "other"


def _contact_of(chat_info: Mapping[str, Any]) -> Tuple[Optional[int], str]:
    """`(contactId, localDisplayName)` for a direct chat, else `(None, "")`.

    `ChatInfo` is a union tagged `direct` / `group` / `local` / `contactRequest` /
    … (TYPES.md:1572-1600); only `direct` carries a `contact` (TYPES.md:2098-2103).
    Anything else is ignored rather than guessed at, because acting on a group
    message as though it came from a 1:1 contact would bill and reply to the wrong
    principal.

    This does cost us one signal class: `REDPACKET_CLAIMED`, `CHANNEL_SUB_ACK` and
    `CHANNEL_PAY_RCPT` are the three kinds the client allows inside a group
    (`acceptedInGroup`, PopopxBadgeCreditsModels.swift:1114-1115). A service account
    is a direct peer in this product and joins no groups, so the correct response to
    seeing one is to drop it and be countable, which `_dispatch` does via
    `stats.events_dropped` — not to widen this filter to a principal it cannot name.
    """
    if chat_info.get("type") != "direct":
        return None, ""
    contact = chat_info.get("contact")
    if not isinstance(contact, Mapping):
        return None, ""
    contact_id = contact.get("contactId")
    if not isinstance(contact_id, int) or isinstance(contact_id, bool):
        return None, ""
    name = contact.get("localDisplayName")
    return contact_id, name if isinstance(name, str) else ""


def _user_id(resp: Mapping[str, Any]) -> Optional[int]:
    user = resp.get("user")
    if isinstance(user, Mapping):
        value = user.get("userId")
        if isinstance(value, int) and not isinstance(value, bool):
            return value
    return None


def extract_inbound_messages(resp: Mapping[str, Any]) -> List[InboundMessage]:
    """Flatten a `newChatItems` payload into inbound messages, ignoring anything
    that is not a direct text message. Tolerant by contract: unknown fields,
    unknown chat types and malformed items are skipped, never fatal."""
    out: List[InboundMessage] = []
    if resp.get("type") != "newChatItems":
        return out
    user_id = _user_id(resp)
    items = resp.get("chatItems")
    if not isinstance(items, list):
        return out
    for entry in items:
        if not isinstance(entry, Mapping):
            continue
        chat_info = entry.get("chatInfo")
        chat_item = entry.get("chatItem")
        if not isinstance(chat_info, Mapping) or not isinstance(chat_item, Mapping):
            continue
        contact_id, display_name = _contact_of(chat_info)
        if contact_id is None:
            continue
        content = chat_item.get("content")
        meta = chat_item.get("meta")
        item_id = meta.get("itemId") if isinstance(meta, Mapping) else None
        text = _extract_text(chat_item)
        if not text:
            continue
        out.append(
            InboundMessage(
                contact_id=contact_id,
                display_name=display_name,
                item_id=item_id if isinstance(item_id, int) and not isinstance(item_id, bool) else 0,
                text=text,
                callback=parse_inbound_text(text),
                direction=_direction(chat_item, content),
                raw_item=chat_item,
                user_id=user_id,
            )
        )
    return out


def extract_contact_request(resp: Mapping[str, Any]) -> Optional[Dict[str, Any]]:
    """A pending contact request, when the node surfaces one.

    The tag and the containing key have both moved across versions, so this reads
    whichever of the known shapes is present instead of asserting one. `None` means
    "nothing recognisable", which the caller logs rather than trusts.
    """
    tag = resp.get("type")
    if not isinstance(tag, str):
        return None
    # Case-insensitive, and a substring: the node spells this two ways in its own
    # docs — `receivedContactRequest` (EVENTS.md:147, the event sent when the node
    # does NOT auto-accept) and `contactRequest` (TYPES.md:1590, the chat-item tag).
    # Lowercasing the tag and then searching it for a mixed-case needle matched
    # neither, which silently disabled auto-accept for one of the two shapes.
    if "contactrequest" not in tag.lower():
        return None
    payload = None
    for key in ("contactRequest", "request", "contactReq"):
        candidate = resp.get(key)
        if isinstance(candidate, Mapping):
            payload = candidate
            break
    if payload is None:
        payload = resp
    request_id = payload.get("contactRequestId") or payload.get("contactReqId")
    profile = payload.get("profile")
    display_name = ""
    if isinstance(profile, Mapping):
        value = profile.get("displayName")
        display_name = value if isinstance(value, str) else ""
    if not isinstance(display_name, str) or not display_name:
        value = payload.get("localDisplayName")
        display_name = value if isinstance(value, str) else ""
    return {
        "type": tag,
        "contact_request_id": request_id if isinstance(request_id, int) else None,
        "display_name": display_name,
        "user_id": _user_id(resp),
        "raw": dict(resp),
    }


# ─────────────────────────────────────────────────────────────────────────────
# 4. Command builders
#
# Pure functions returning the documented CLI strings, so they can be asserted
# without a node. The JSON is compact and single-line: the node splits the command
# string at `json ` and reads the remainder as one value, so a pretty-printed or
# multi-line payload is a parse error at best and a truncated command at worst.
# ─────────────────────────────────────────────────────────────────────────────


def _json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))


def _profile_json(display_name: str, full_name: str = "", *, short_descr: str = "", description: str = "") -> str:
    """`Profile` per TYPES.md:3800-3814 — `displayName` and `fullName` are the two
    non-optional fields, so a profile that omits `fullName` is a malformed command
    rather than a cosmetic choice."""
    body: Dict[str, Any] = {"displayName": display_name, "fullName": full_name or display_name}
    if short_descr:
        body["shortDescr"] = short_descr
    if description:
        body["description"] = description
    return _json(body)


def cmd_start(
    *,
    main: bool = True,
    send_files: bool = False,
    service_requests: bool = True,
) -> str:
    """`/_start main=on|off[ snd_files=off][ service_requests=on]` (COMMANDS.md:2929).

    The two optional switches are emitted only in the documented direction: the
    node's grammar accepts `snd_files=off` and `service_requests=on` and has no
    `snd_files=on` production at all, so building the "positive" form of either is
    a syntax error rather than a no-op. `service_requests` is left on because it is
    what lets the node answer a service request against a double-ratchet address;
    turning it off silently loses inbound contacts instead of failing.
    """
    parts = ["/_start", "main=%s" % ("on" if main else "off")]
    if not send_files:
        parts.append("snd_files=off")
    if service_requests:
        parts.append("service_requests=on")
    return " ".join(parts)


def cmd_create_user(display_name: str, full_name: str = "") -> str:
    """`/_create user <json(newUser)>`.

    The three booleans are not optional on the wire. `NewUser` is
    `{profile?, pastTimestamp, userChatRelay, clientService}` and the node's whole
    command alternation backs up when one value fails to decode, so
    `/_create user {"profile":{…}}` comes back as
    `commandError "Failed reading: empty"` — the same message it gives for a command
    that does not exist at all. Measured against `popopx-chat` 7.1.2.0 on
    2026-11-21; the payload below is what the node accepted.
    """
    return "/_create user %s" % _json(
        {
            "profile": json.loads(_profile_json(display_name, full_name)),
            "pastTimestamp": False,
            "userChatRelay": False,
            "clientService": False,
        }
    )


def cmd_list_users() -> str:
    """`/users` (Commands.hs:6689 `"/users" $> ListUsers`).

    Not `/_users`: the `_` marks the API-only commands in this grammar, and
    `ListUsers` is not one of them. `/_users` parses as nothing and the node answers
    `commandError "Failed reading: empty"` — which is what stopped the bridge from
    ever getting a user id. Confirmed against the live node as well as
    Commands.hs:6689 and COMMANDS.md:2689.
    """
    return "/users"


def cmd_show_user(user_id: int, *, view_password: Optional[str] = None) -> str:
    """`/_user <userId>[ <json(viewPwd)>]` (COMMANDS.md:2718) — the password is a
    JSON value, not a bare token, so it is quoted rather than interpolated."""
    command = "/_user %d" % int(user_id)
    if view_password:
        command += " %s" % _json(view_password)
    return command


def cmd_set_profile(user_id: int, display_name: str, full_name: str = "", **kwargs: str) -> str:
    body = _profile_json(display_name, full_name, **kwargs)
    return "/_profile %d %s" % (int(user_id), body)


def cmd_create_address(user_id: int, *, pq_ratchet: Optional[bool] = None) -> str:
    command = "/_address %d" % int(user_id)
    if pq_ratchet is not None:
        command += " pq_ratchet=%s" % ("on" if pq_ratchet else "off")
    return command


def cmd_show_address(user_id: int) -> str:
    return "/_show_address %d" % int(user_id)


def cmd_connect(user_id: int, invitation_or_address: str, *, incognito: bool = False) -> str:
    """`/_connect <userId>[ incognito=on] <invitation>` — `incognito` creates the
    contact without sharing this profile's address back."""
    command = "/_connect %d" % int(user_id)
    if incognito:
        command += " incognito=on"
    return "%s %s" % (command, invitation_or_address)


def cmd_accept_contact(contact_request_id: int) -> str:
    """`/_accept <contactReqId>` (COMMANDS.md:2070) — the request id is globally
    unique in the node's database, so there is no `<userId>` to pass; adding one is
    a syntax error, which is exactly the failure a caller cannot see from a log."""
    return "/_accept %d" % int(contact_request_id)


def cmd_list_contacts(user_id: int) -> str:
    return "/_contacts %d" % int(user_id)


def cmd_service_response(user_id: int, request_id: int, body: Mapping[str, Any]) -> str:
    return "/_service_response %d %d %s" % (int(user_id), int(request_id), _json(body))


def cmd_set_accept_member_contacts(user_id: int, enabled: bool) -> str:
    return "/_set accept member contacts %d %s" % (int(user_id), "on" if enabled else "off")


def composed_text(
    text: str, *, quoted_item_id: Optional[int] = None, mentions: Optional[Mapping[str, int]] = None
) -> Dict[str, Any]:
    """One `ComposedMessage` (TYPES.md:1905-1911):
    `{fileSource?, quotedItemId?, msgContent, mentions}`.

    `msgContent` is the tagged union `{"type":"text","text":...}`; the outer
    `text` field is not a shortcut the node accepts, so it is not offered.
    """
    body: Dict[str, Any] = {"msgContent": {"type": "text", "text": text}, "mentions": dict(mentions or {})}
    if quoted_item_id is not None:
        body["quotedItemId"] = int(quoted_item_id)
    return body


def cmd_send(
    contact_id: int,
    messages: Any,
    *,
    live: bool = True,
    ttl: Optional[int] = None,
    sign: bool = False,
) -> str:
    """`/_send @<contactId>[ live=on][ ttl=N][ sign=on] json <json(composedMessages)>`
    (COMMANDS.md:372).

    `messages` accepts one composed message or a list; it is always serialised as
    a list, because the parameter is `[[ComposedMessage]]`. `live` defaults to on:
    a service card must arrive as a live message, since a non-live message is
    delivered as a plain notification and an in-place card update relies on the
    message being addressable. `ttl` bounds delivery for time-sensitive cards
    (a payment prompt that arrives hours late is worse than one that never arrives).
    """
    items = messages if isinstance(messages, list) else [messages]
    command = "/_send @%d" % int(contact_id)
    if live:
        command += " live=on"
    if ttl is not None:
        command += " ttl=%d" % int(ttl)
    if sign:
        command += " sign=on"
    return "%s json %s" % (command, _json(items))


# ─────────────────────────────────────────────────────────────────────────────
# 5. Response reading
# ─────────────────────────────────────────────────────────────────────────────

ERROR_TAG = "chatCmdError"


def response_error(resp: Mapping[str, Any]) -> Optional[Mapping[str, Any]]:
    """The `chatError` payload when this response is a command error."""
    if resp.get("type") == ERROR_TAG:
        error = resp.get("chatError")
        return error if isinstance(error, Mapping) else {"detail": str(error)}
    return None


def error_reason(chat_error: Mapping[str, Any]) -> str:
    """The node's own name for why a command failed, or "" if it gave none.

    The reason is nested one level and the key moves with the kind of error, so a
    caller that reads only `chatError["type"]` gets `error` or `errorStore` and
    learns nothing. Both shapes below were captured from `popopx-chat` 7.1.2.0 on
    2026-11-21::

        {"type": "error", "errorType": {"type": "commandError", "message": "Failed reading: empty"}}
        {"type": "errorStore", "storeError": {"type": "userContactLinkNotFound"}}
    """
    for key in ("errorType", "storeError"):
        inner = chat_error.get(key)
        if isinstance(inner, Mapping) and isinstance(inner.get("type"), str):
            return str(inner["type"])
    tag = chat_error.get("type")
    return tag if isinstance(tag, str) else ""


def extract_link(resp: Mapping[str, Any]) -> str:
    """The full one-time invitation / contact address out of any of the shapes the
    node uses (`userContactLinkCreated`, `userContactLink`, `invitation`).

    The field names differ per command — `connLinkContact.connFullLink`,
    `contactLink.connLinkContact.connFullLink`, `connReqContact` — so all are
    tried. Returning "" rather than raising lets the caller decide whether a
    missing link is fatal.
    """
    def walk(node: Any, depth: int = 0) -> str:
        if depth > 4 or not isinstance(node, Mapping):
            return ""
        for key in ("connFullLink", "connReqContact", "invitation", "link"):
            value = node.get(key)
            if isinstance(value, str) and value:
                return value
        for key in ("connLinkContact", "contactLink", "connection", "inv", "createdConnLink"):
            nested = walk(node.get(key), depth + 1)
            if nested:
                return nested
        return ""

    return walk(resp)


def extract_contacts(resp: Mapping[str, Any]) -> List[Dict[str, Any]]:
    """`contactsList` → `[{contactId, localDisplayName, profile}]`, ignoring
    malformed rows."""
    rows = resp.get("contacts")
    if not isinstance(rows, list):
        return []
    out: List[Dict[str, Any]] = []
    for row in rows:
        if not isinstance(row, Mapping):
            continue
        contact = row.get("contact") if isinstance(row.get("contact"), Mapping) else row
        contact_id = contact.get("contactId")
        if not isinstance(contact_id, int) or isinstance(contact_id, bool):
            continue
        name = contact.get("localDisplayName")
        out.append(
            {
                "contact_id": contact_id,
                "display_name": name if isinstance(name, str) else "",
                "profile": contact.get("profile") if isinstance(contact.get("profile"), Mapping) else {},
            }
        )
    return out


def extract_users(resp: Mapping[str, Any]) -> List[Dict[str, Any]]:
    """`usersList` → `[{userId, localDisplayName, activeUser}]`."""
    rows = resp.get("users")
    if not isinstance(rows, list):
        return []
    out: List[Dict[str, Any]] = []
    for row in rows:
        if not isinstance(row, Mapping):
            continue
        user = row.get("user") if isinstance(row.get("user"), Mapping) else row
        user_id = user.get("userId")
        if not isinstance(user_id, int) or isinstance(user_id, bool):
            continue
        name = user.get("localDisplayName")
        out.append(
            {
                "user_id": user_id,
                "display_name": name if isinstance(name, str) else "",
                "active_user": bool(user.get("activeUser", True)),
            }
        )
    return out


# ─────────────────────────────────────────────────────────────────────────────
# 6. The bridge
# ─────────────────────────────────────────────────────────────────────────────

EventHandler = Callable[[str, Mapping[str, Any]], Awaitable[None]]
MessageHandler = Callable[[InboundMessage], Awaitable[None]]
StateHandler = Callable[[bool, str], Awaitable[None]]


@dataclass
class BridgeStats:
    connected_at: float = 0.0
    last_inbound_at: float = 0.0
    last_send_at: float = 0.0
    commands_sent: int = 0
    commands_failed: int = 0
    messages_in: int = 0
    messages_out: int = 0
    reconnects: int = 0
    events_dropped: int = 0
    """Count of inbound payloads this process could not understand. Kept because
    "the phone sent nothing" and "we ignored what the phone sent" look identical
    from the outside and are fixed in completely different places."""

    def as_dict(self) -> Dict[str, Any]:
        return {
            "connected_at": self.connected_at,
            "uptime_seconds": int(time.time() - self.connected_at) if self.connected_at else 0,
            "last_inbound_at": self.last_inbound_at,
            "last_send_at": self.last_send_at,
            "commands_sent": self.commands_sent,
            "commands_failed": self.commands_failed,
            "messages_in": self.messages_in,
            "messages_out": self.messages_out,
            "reconnects": self.reconnects,
            "events_dropped": self.events_dropped,
        }


def _node_unavailable_errors() -> Tuple[type, ...]:
    """Exception classes meaning "the node is not answering", not "do not start".

    `websockets` is imported lazily in :meth:`AgentBridge._connect_once` so this module
    stays importable without the wheel, which rules out naming its exception base class
    in an `except` clause; resolving it here keeps both true. Skipping it cost the
    degraded boot: a port answering with something other than HTTP raises
    `InvalidMessage`, which is a `WebSocketException` and *not* an `OSError`, so it went
    straight past the handler in :meth:`AgentBridge.start` and the gateway exited with
    the traceback instead of serving with `node_connected: false`.
    """
    try:
        from websockets.exceptions import WebSocketException  # noqa: PLC0415
    except ImportError:  # pragma: no cover - the wheel-less path
        return (NodeError, OSError, asyncio.TimeoutError)
    return (NodeError, OSError, asyncio.TimeoutError, WebSocketException)


class AgentBridge:
    """Asyncio WebSocket client for one node connection and one service user.

    Lifecycle: `await bridge.start()` connects, runs `/_start`, discovers the
    service user and then keeps one reader task alive; `await bridge.stop()`
    closes it. Commands issued while disconnected raise `NodeNotConnected`
    immediately instead of queueing, because a queued command has no deadline the
    caller can reason about — durability belongs to the outbox table, which is
    retried by the caller with a correlation id.
    """

    def __init__(
        self,
        ws_url: str = "ws://127.0.0.1:5225",
        *,
        service_display_name: str = "POPOPX Service",
        service_full_name: str = "",
        command_timeout: float = 30.0,
        reconnect_seconds: float = 3.0,
        service_requests: bool = True,
        send_files: bool = False,
        on_message: Optional[MessageHandler] = None,
        on_event: Optional[EventHandler] = None,
        on_state: Optional[StateHandler] = None,
    ) -> None:
        self.ws_url = ws_url
        self.service_display_name = service_display_name
        self.service_full_name = service_full_name or service_display_name
        self.command_timeout = float(command_timeout)
        self.reconnect_seconds = max(0.5, float(reconnect_seconds))
        self.service_requests = service_requests
        self.send_files = send_files
        self._on_message = on_message
        self._on_event = on_event
        self._on_state = on_state

        self._ws: Any = None
        self._reader: Optional[asyncio.Future] = None
        self._supervisor: Optional[asyncio.Future] = None
        self._pending: Dict[str, asyncio.Future] = {}
        self._send_lock: Optional[asyncio.Lock] = None
        self._corr = 0
        self._closing = False
        self._started = False
        self.user_id: Optional[int] = None
        self.contact_address: str = ""
        self.stats = BridgeStats()

    # ── connection state ───────────────────────────────────────────────────

    @property
    def connected(self) -> bool:
        return self._ws is not None and self._started

    def state(self) -> Dict[str, Any]:
        return {
            "connected": self.connected,
            "ws_url": self.ws_url,
            "user_id": self.user_id,
            "contact_address": self.contact_address,
            "pending_commands": len(self._pending),
            **self.stats.as_dict(),
        }

    async def start(self, *, strict: bool = False) -> None:
        """Connect and bring the node's chat API up for this service user.

        A node that is not answering *yet* is not fatal. The first attempt's failure is
        logged, the supervisor starts anyway and retries with the same capped backoff it
        uses after a restart, and `/healthz` reports `node_connected: false` until the
        link lands. Raising here instead is what killed the gateway on
        `docker compose up` — where the two containers race by design — and on a Mac
        where the phone is plugged in before the node is started, which is the exact
        bring-up the brief asks for. `strict=True` keeps a fail-fast caller, and is
        what :meth:`app.main.Gateway.start` would pass if an operator ever wanted the
        old behaviour back.
        """
        self._closing = False
        try:
            await self._connect_once(timeout=self.command_timeout)
        except _node_unavailable_errors() as exc:
            if strict:
                raise
            LOG.warning(
                "node %s is not answering yet (%s: %s); serving anyway and retrying — "
                "GET /healthz reports node_connected=false until the link lands",
                self.ws_url, type(exc).__name__, exc,
            )
            await self._notify_state(False, "not connected at boot: %s" % exc)
        self._supervisor = asyncio.ensure_future(self._supervise())

    async def stop(self) -> None:
        self._closing = True
        if self._supervisor is not None:
            self._supervisor.cancel()
            try:
                await self._supervisor
            except (asyncio.CancelledError, Exception):  # noqa: BLE001 - teardown
                pass
            self._supervisor = None
        if self._reader is not None:
            self._reader.cancel()
            try:
                await self._reader
            except (asyncio.CancelledError, Exception):  # noqa: BLE001
                pass
            self._reader = None
        ws, self._ws = self._ws, None
        if ws is not None:
            try:
                await ws.close()
            except Exception:  # noqa: BLE001 - closing a dead socket is not an error
                pass
        self._fail_pending(NodeNotConnected("bridge stopped"))
        self._started = False

    def _fail_pending(self, error: Exception) -> None:
        pending, self._pending = self._pending, {}
        for future in pending.values():
            if not future.done():
                future.set_exception(error)

    async def _connect_once(self, *, timeout: float) -> None:
        try:
            import websockets  # noqa: PLC0415 - lazy so the module imports without the wheel
        except ImportError as exc:  # pragma: no cover - depends on the host
            raise NodeError("the `websockets` package is required to reach the node") from exc
        if self._send_lock is None:
            self._send_lock = asyncio.Lock()
        LOG.info("connecting to node at %s", self.ws_url)
        # max_size: the node batches chat items, and a merchant who imports a long
        # article or sends a large menu can exceed the 1 MiB default. A dropped
        # connection that reconnects is survivable; a silently truncated frame is
        # not, so the limit is raised rather than the payload trimmed.
        ws = await asyncio.wait_for(
            websockets.connect(self.ws_url, max_size=16 * 1024 * 1024, ping_interval=20, ping_timeout=20),
            timeout=timeout,
        )
        self._ws = ws
        self.stats.connected_at = time.time()
        self._reader = asyncio.ensure_future(self._read_loop(ws))
        try:
            await self.command(cmd_start(send_files=self.send_files, service_requests=self.service_requests))
        except NodeError:
            await self._teardown_socket(ws)
            raise
        await self._ensure_user()
        self._started = True
        LOG.info("node link up (user id %s)", self.user_id)
        await self._notify_state(True, "connected")

    async def _teardown_socket(self, ws: Any) -> None:
        try:
            await ws.close()
        except Exception:  # noqa: BLE001
            pass
        if self._reader is not None:
            self._reader.cancel()
            self._reader = None
        if self._ws is ws:
            self._ws = None
        self._started = False
        self._fail_pending(NodeNotConnected())

    async def _supervise(self) -> None:
        """Reconnect forever, with a capped backoff."""
        attempt = 0
        while not self._closing:
            try:
                await asyncio.sleep(1.0)
                if self.connected:
                    attempt = 0
                    continue
                if self._ws is not None:
                    await self._teardown_socket(self._ws)
                delay = min(60.0, self.reconnect_seconds * (2 ** min(attempt, 5)))
                attempt += 1
                LOG.warning("node link down; retrying in %.1fs", delay)
                await self._notify_state(False, "reconnecting in %.1fs" % delay)
                await asyncio.sleep(delay)
                if self._closing:
                    return
                await self._connect_once(timeout=self.command_timeout)
                self.stats.reconnects += 1
                attempt = 0
            except asyncio.CancelledError:
                raise
            except Exception as exc:  # noqa: BLE001 - a supervisor that dies takes the product with it
                LOG.exception("reconnect loop error: %s", exc)
                await self._notify_state(False, "supervisor error: %s" % exc)

    async def _notify_state(self, up: bool, detail: str) -> None:
        if self._on_state is None:
            return
        try:
            await self._on_state(up, detail)
        except Exception:  # noqa: BLE001 - a broken listener must not kill the link
            LOG.exception("state handler raised")

    # ── the reader ─────────────────────────────────────────────────────────

    async def _read_loop(self, ws: Any) -> None:
        try:
            async for raw in ws:
                try:
                    message = json.loads(raw)
                except (ValueError, TypeError):
                    LOG.warning("dropping non-JSON frame from node (%d bytes)", len(raw or ""))
                    self.stats.events_dropped += 1
                    continue
                if not isinstance(message, Mapping):
                    self.stats.events_dropped += 1
                    continue
                await self._dispatch(message)
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # noqa: BLE001 - socket errors are the reconnect trigger
            LOG.warning("node socket closed: %s", exc)
        finally:
            if self._ws is ws:
                self._started = False
                self._ws = None
                self._fail_pending(NodeNotConnected("node connection dropped mid-flight"))

    async def _dispatch(self, message: Mapping[str, Any]) -> None:
        """Route by correlation id, then fan events out.

        A response arrives with `corrId`; an event arrives without one. Both cases
        also carry `resp`, and a `newChatItems` can be either: COMMANDS.md:386 lists
        it as the response to `/_send`, EVENTS.md:195 lists it as the receive event.
        So: if the id matches an outstanding command, that command owns it and gets
        it, and the send path decides what it means; only payloads nobody is waiting
        for fall through to the event handlers. A response whose command already
        timed out is treated as an event rather than discarded, because the work it
        describes (a delivered message) did happen.
        """
        corr_id = message.get("corrId")
        resp = message.get("resp")
        if not isinstance(resp, Mapping):
            self.stats.events_dropped += 1
            return
        if isinstance(corr_id, str) and corr_id in self._pending:
            future = self._pending.pop(corr_id)
            if not future.done():
                future.set_result(resp)
            return
        tag = resp.get("type")
        if not isinstance(tag, str):
            self.stats.events_dropped += 1
            return
        if tag == ERROR_TAG and corr_id is None:
            LOG.warning("unsolicited node error: %s", json.dumps(resp, ensure_ascii=False)[:400])
        messages = extract_inbound_messages(resp)
        if not messages and tag == "newChatItems":
            # Chat items arrived and none of them is addressable as a direct message:
            # a group/channel item, or a content type this suite does not model. Counted
            # rather than discarded silently, because "the phone sent nothing" and "we
            # ignored what the phone sent" are indistinguishable from the outside.
            self.stats.events_dropped += 1
        if messages:
            self.stats.messages_in += len(messages)
            self.stats.last_inbound_at = time.time()
            for item in messages:
                # Our own message echoed back as an event (a delivery update).
                # Ignoring it is what stops a reply loop.
                if not item.received or self._on_message is None:
                    continue
                try:
                    await self._on_message(item)
                except Exception:  # noqa: BLE001
                    LOG.exception("message handler raised for contact %s", item.contact_id)
            return
        request = extract_contact_request(resp)
        if request is not None and self._on_event is not None:
            try:
                await self._on_event("contact_request", request)
            except Exception:  # noqa: BLE001
                LOG.exception("contact-request handler raised")
            return
        if self._on_event is not None:
            try:
                await self._on_event(tag, dict(resp))
            except Exception:  # noqa: BLE001
                LOG.exception("event handler raised for %s", tag)

    # ── commands ───────────────────────────────────────────────────────────

    def next_corr_id(self) -> str:
        self._corr += 1
        return "popopx-%d-%d" % (int(time.time()), self._corr)

    async def command(self, command: str, *, timeout: Optional[float] = None) -> Dict[str, Any]:
        """Send one command string, await its correlated response.

        Serialised behind a lock on purpose: the node writes responses in the order
        it processes commands and the correlation map is correct regardless, but
        pipelining a `/_send` of a 6 KiB frame behind a `/_profile` update makes
        latency for the small command depend on the large one. Sequential issue
        also makes the log a faithful trace of what the node saw, which is what an
        operator needs when a phone did not show a card.
        """
        if self._ws is None:
            raise NodeNotConnected()
        deadline = self.command_timeout if timeout is None else float(timeout)
        corr_id = self.next_corr_id()
        loop = asyncio.get_running_loop()
        future: asyncio.Future = loop.create_future()
        envelope = _json({"corrId": corr_id, "cmd": command})
        assert self._send_lock is not None
        async with self._send_lock:
            self._pending[corr_id] = future
            try:
                await self._ws.send(envelope)
                self.stats.commands_sent += 1
            except Exception as exc:  # noqa: BLE001
                self._pending.pop(corr_id, None)
                self.stats.commands_failed += 1
                raise NodeNotConnected("send failed: %s" % exc) from exc
            try:
                resp = await asyncio.wait_for(future, timeout=deadline)
            except asyncio.TimeoutError:
                self._pending.pop(corr_id, None)
                self.stats.commands_failed += 1
                raise NodeTimeout(corr_id, deadline) from None
            except (NodeNotConnected, asyncio.CancelledError):
                self._pending.pop(corr_id, None)
                raise
        error = response_error(resp)
        if error is not None:
            self.stats.commands_failed += 1
            raise NodeCommandError(error, command)
        return dict(resp)

    async def _ensure_user(self) -> None:
        """Adopt the node's active user, or create the service user.

        Never create-then-forget: a gateway that makes a second user every restart
        gives every contact a different identity, and the pairwise sessions in the
        database would then be signed with secrets no user holds."""
        resp = await self.command(cmd_list_users())
        users = extract_users(resp)
        active = [u for u in users if u["active_user"]]
        named = [u for u in users if u["display_name"] == self.service_display_name]
        if named:
            self.user_id = int(named[0]["user_id"])
            return
        if active:
            self.user_id = int(active[0]["user_id"])
            LOG.warning(
                "node has no user named %r; adopting existing user id %s",
                self.service_display_name,
                self.user_id,
            )
            return
        created = await self.command(cmd_create_user(self.service_display_name, self.service_full_name))
        user = created.get("user")
        if isinstance(user, Mapping) and isinstance(user.get("userId"), int):
            self.user_id = int(user["userId"])
            LOG.info("created service user id %s", self.user_id)
            return
        raise NodeError("/_create user returned no user id: %s" % json.dumps(created, ensure_ascii=False)[:300])

    # ── the surface services call ──────────────────────────────────────────

    async def send_text(
        self,
        contact_id: int,
        text: str,
        *,
        live: bool = True,
        ttl: Optional[int] = None,
        sign: bool = False,
        quoted_item_id: Optional[int] = None,
        timeout: Optional[float] = None,
    ) -> Dict[str, Any]:
        """Send a message to one contact. Returns the node's `newChatItems` echo.

        No user id is needed: `/_send` addresses the peer by `@<contactId>` alone
        (COMMANDS.md:362-372). This method performs NO framing validation — callers
        must build the text with `crypto_service.encode_frame`, which is where the
        iOS limits are enforced. A size check here would be a second, weaker copy of
        that rule.
        """
        resp = await self.command(
            cmd_send(
                contact_id,
                [composed_text(text, quoted_item_id=quoted_item_id)],
                live=live,
                ttl=ttl,
                sign=sign,
            ),
            timeout=timeout,
        )
        self.stats.messages_out += 1
        self.stats.last_send_at = time.time()
        return resp

    async def create_contact_address(self, *, pq_ratchet: Optional[bool] = None) -> str:
        self._require_user()
        resp = await self.command(cmd_create_address(int(self.user_id), pq_ratchet=pq_ratchet))
        link = extract_link(resp)
        if link:
            self.contact_address = link
        return link

    async def show_contact_address(self) -> str:
        """The current contact address, or "" when this user has none yet.

        "none yet" is an error frame from the node, not an empty answer: a user
        without an address replies `errorStore / userContactLinkNotFound` (measured
        on a fresh user, 2026-11-21). `POST /api/v1/node/address` calls this first to
        decide whether to mint one, so letting that frame raise made the *first*
        pairing attempt against a new node die as `node_unreachable` — a link that
        had just answered — before the create command was ever sent.
        """
        self._require_user()
        try:
            resp = await self.command(cmd_show_address(int(self.user_id)))
        except NodeCommandError as exc:
            if error_reason(exc.chat_error) == "userContactLinkNotFound":
                return ""
            raise
        link = extract_link(resp)
        if link:
            self.contact_address = link
        return link

    async def list_contacts(self) -> List[Dict[str, Any]]:
        self._require_user()
        return extract_contacts(await self.command(cmd_list_contacts(int(self.user_id))))

    async def accept_contact(self, contact_request_id: int) -> Dict[str, Any]:
        return await self.command(cmd_accept_contact(int(contact_request_id)))

    async def connect_invitation(self, invitation: str, *, incognito: bool = False) -> Dict[str, Any]:
        self._require_user()
        return await self.command(cmd_connect(int(self.user_id), invitation, incognito=incognito))

    async def set_profile(self, display_name: str, full_name: str = "", **kwargs: str) -> Dict[str, Any]:
        self._require_user()
        return await self.command(cmd_set_profile(int(self.user_id), display_name, full_name, **kwargs))

    async def answer_service_request(self, request_id: int, body: Mapping[str, Any]) -> Dict[str, Any]:
        self._require_user()
        return await self.command(cmd_service_response(int(self.user_id), int(request_id), body))

    def _require_user(self) -> None:
        if self.user_id is None:
            raise NodeNotConnected("the service user has not been discovered yet; call start() first")


# ─────────────────────────────────────────────────────────────────────────────
# 7. Self-test (stdlib only; runs on any interpreter)
# ─────────────────────────────────────────────────────────────────────────────


def self_test() -> List[str]:
    """Assertions on the pure halves: the callback grammar, the command strings and
    the response readers. The socket paths need a node, so they are not claimed
    here — they are exercised by the smoke test in the deployment runbook."""
    checks: List[str] = []

    def check(name: str, condition: bool) -> None:
        if not condition:
            raise AssertionError("self_test failed: %s" % name)
        checks.append(name)

    # Callback grammar, one case per emitted literal.
    cases = [
        ("::CB::menu:orders", "card_callback", "menu:orders", ""),
        ("::CB::topup_12:paid_77", "card_paid", "topup_12", "77"),
        ("::CB::rotate:ch-9", "rotate_request", "rotate:ch-9", ""),
        ("::REF::a-1001", "article_ref", "a-1001", ""),
        ("::SSO_SCAN::s-abc", "sso_scan", "s-abc", ""),
        ("hello ::CB::inside", "text", "hello ::CB::inside", ""),
        ("::CB::", "card_callback", "", ""),
    ]
    for text, kind, payload, paid in cases:
        parsed = parse_inbound_text(text)
        check("parse_%s" % (kind + ("_" + paid if paid else "")), parsed.kind == kind)
        check("payload_%s" % (kind + ("_" + payload if payload else "")), parsed.payload == payload)
        check("paidref_%s" % (kind + ("_" + paid if paid else "")), parsed.paid_ref == paid)

    rotated = parse_inbound_text("::CB::rotate:ch-9")
    check("rotate_channel_id", rotated.channel_id == "ch-9")
    paid = parse_inbound_text("::CB::order:42:paid_ledger-9")
    check("paid_keeps_colons_in_payload", paid.kind == "card_paid" and paid.payload == "order:42" and paid.paid_ref == "ledger-9")

    system = parse_inbound_text("::popopx_sys::CHANNEL_PAY_RCPT::ch-7:20:0xdeadbeef")
    check("system_pay_rcpt", system.kind == "system" and system.sys_kind == "CHANNEL_PAY_RCPT")
    check("system_pay_fields", (system.channel_id, system.credits, system.tx_hash) == ("ch-7", 20, "0xdeadbeef"))
    check("system_is_payment_receipt", system.is_payment_receipt and system.silent)
    legacy = parse_inbound_text("::popopx_sys::CHANNEL_SUB_PAID::ch-7:20:0xdeadbeef")
    check("legacy_paid_accepted", legacy.is_payment_receipt and legacy.credits == 20)
    redeem = parse_inbound_text("::popopx_sys::EXT_REDEEM_REQ::POPX-CP-1-AAAA")
    check("system_redeem_single_payload", redeem.sys_fields == ("POPX-CP-1-AAAA",) and not redeem.is_payment_receipt)
    sub_ack = parse_inbound_text("::popopx_sys::CHANNEL_SUB_ACK::#3::1798761600000")
    check("sub_ack_splits_on_last_double_colon", sub_ack.sys_fields == ("#3", "1798761600000"))
    check("sub_ack_named_fields", sub_ack.channel_id == "#3" and sub_ack.expires_at_ms == 1798761600000)
    pay_tail = parse_inbound_text("::popopx_sys::CHANNEL_PAY_RCPT::ch:1:aabb::cc")
    check("pay_rcpt_keeps_hash_tail", pay_tail.channel_id == "ch" and pay_tail.credits == 1 and pay_tail.tx_hash == "aabb::cc")
    check("client_enum_kinds_all_present",
          all(k in SYSTEM_KINDS for k in (
              "EXT_REDEEM_REQ", "EXT_REDEEM_ACK", "CHAT_REDEEM_REQ", "CHAT_REDEEM_ACK",
              "REDPACKET_CLAIMED", "PROFILE_UNLOCKED", "CHANNEL_SUB_ACK", "CHANNEL_PAY_RCPT",
              "CREDIT_EXT_REDEEM_REQ", "CREDIT_EXT_REDEEM_ACK",
              "CREDIT_CHAT_REDEEM_REQ", "CREDIT_CHAT_REDEEM_ACK"))
          and len([k for k in SYSTEM_KINDS if k != "CHANNEL_SUB_PAID"]) == 12)
    malformed = parse_inbound_text("::popopx_sys::NO_SEPARATOR")
    check("malformed_system_is_text", malformed.kind == "text")
    bad_credits = parse_inbound_text("::popopx_sys::CHANNEL_PAY_RCPT::ch-7:notanumber")
    check("bad_credits_zero", bad_credits.credits == 0 and bad_credits.kind == "system")
    check("plain_text_not_silent", not parse_inbound_text("请问订单什么时候发货").silent)

    # Command strings, against the grammar the node actually ships. The parser is
    # `chatCommandP` (src/Popopx/Chat/Library/Commands.hs:6676) and it is total:
    # every alternative ends with `<* A.takeWhile (== ' ') <* A.endOfInput`, so a
    # command that is one token wrong and a command that does not exist produce the
    # same answer — `commandError "Failed reading: empty"`. Exact strings are
    # therefore asserted, not paraphrased.
    check("cmd_start", cmd_start() == "/_start main=on snd_files=off service_requests=on")
    check("cmd_start_files_on_omits_switch", cmd_start(send_files=True) == "/_start main=on service_requests=on")
    check("cmd_start_no_service_requests", cmd_start(service_requests=False) == "/_start main=on snd_files=off")
    check("cmd_start_off", cmd_start(main=False) == "/_start main=off snd_files=off service_requests=on")
    check("cmd_users", cmd_list_users() == "/users")
    check("cmd_users_is_not_the_api_prefixed_form", not cmd_list_users().startswith("/_"))
    check("cmd_create_user", cmd_create_user("Acme 服务", "Acme 服务中心") ==
          '/_create user {"profile":{"displayName":"Acme 服务","fullName":"Acme 服务中心"},'
          '"pastTimestamp":false,"userChatRelay":false,"clientService":false}')
    check("cmd_create_user_carries_every_newuser_field",
          set(json.loads(cmd_create_user("a", "b").split(" ", 2)[2])) ==
          {"profile", "pastTimestamp", "userChatRelay", "clientService"})
    check("cmd_contacts", cmd_list_contacts(3) == "/_contacts 3")
    check("cmd_accept", cmd_accept_contact(9) == "/_accept 9")
    check("cmd_accept_takes_no_user_id", cmd_accept_contact(9).count(" ") == 1)
    check("cmd_show_user_plain", cmd_show_user(7) == "/_user 7")
    check("cmd_show_user_json_password", cmd_show_user(7, view_password="pw") == '/_user 7 "pw"')
    check("cmd_address", cmd_create_address(3, pq_ratchet=False) == "/_address 3 pq_ratchet=off")
    check("cmd_service_response", cmd_service_response(1, 2, {"a": 1}) == '/_service_response 1 2 {"a":1}')
    check("cmd_accept_member", cmd_set_accept_member_contacts(1, True) == "/_set accept member contacts 1 on")

    sent = cmd_send(12, composed_text("hi"), live=True, ttl=300, sign=True)
    check("cmd_send_form", sent == '/_send @12 live=on ttl=300 sign=on json [{"msgContent":{"type":"text","text":"hi"},"mentions":{}}]')
    check("cmd_send_is_a_list", json.loads(sent.split(" json ", 1)[1]) == [{"msgContent": {"type": "text", "text": "hi"}, "mentions": {}}])
    check("cmd_send_single_message_wrapped", "json [" in cmd_send(1, composed_text("x")))
    check("cmd_send_no_live", cmd_send(1, composed_text("x"), live=False).startswith("/_send @1 json"))
    check("cmd_send_one_line", "\n" not in sent)
    check("cmd_send_unicode_raw", "服务" in cmd_send(1, composed_text("服务")))
    quoted = cmd_send(1, composed_text("re", quoted_item_id=7))
    check("cmd_send_quote", '"quotedItemId":7' in quoted and json.loads(quoted.split(" json ", 1)[1])[0]["quotedItemId"] == 7)
    check("cmd_send_two_messages", len(json.loads(cmd_send(1, [composed_text("a"), composed_text("b")]).split(" json ", 1)[1])) == 2)
    check("cmd_profile", cmd_set_profile(1, "Acme 服务号", "Acme") ==
          '/_profile 1 {"displayName":"Acme 服务号","fullName":"Acme"}')
    check("cmd_profile_fills_full_name", '"fullName":"Acme 服务号"' in cmd_set_profile(1, "Acme 服务号"))
    check("cmd_connect_incognito", cmd_connect(1, "popopx://invite/x", incognito=True) == "/_connect 1 incognito=on popopx://invite/x")
    # The node reads `{"type":"text","text":…}` under `msgContent`; a payload keyed
    # `content` is refused with the same "Failed reading: empty" as an unknown
    # command (measured against the live node, 2026-11-21).
    check("cmd_send_labels_the_payload_msgContent", '"msgContent"' in cmd_send(1, composed_text("x")))

    # The command prefixes, transcribed from the node's parser
    # (src/Popopx/Chat/Library/Commands.hs:6676-7103, `chatCommandP`). This is the
    # one list here that is copied out of the other codebase, and it is here because
    # that parser is total — `choice = A.choice . map (… <* A.endOfInput)`
    # (Commands.hs:7103) — so a command spelled one character wrong does not come
    # back as "unknown command". It comes back as `commandError
    # "Failed reading: empty"`, which is indistinguishable from a malformed JSON
    # argument and says nothing about the prefix. That is where the service user id
    # went missing.
    node_commands = (
        "/_accept",                       # Commands.hs:6790, COMMANDS.md:2070
        "/_address ",                     # Commands.hs:7021
        "/_contacts ",                    # Commands.hs:6969 — the argument is required
        "/_connect ",                     # Commands.hs:6978-6979
        "/_create user ",                 # Commands.hs:6685
        "/_get chats ",                   # Commands.hs:6752
        "/_profile ",                     # Commands.hs:6811
        "/_send ",                        # Commands.hs:6763
        "/_service_response ",            # Commands.hs:6801
        "/_set accept member contacts ",  # Commands.hs:6697
        "/_show_address ",                # Commands.hs:7025
        "/_start",                        # Commands.hs:6713-6715
        "/_user ",                        # Commands.hs:6690
        "/users",                         # Commands.hs:6689, COMMANDS.md:2689
    )
    built_commands = (
        cmd_start(), cmd_list_users(), cmd_create_user("a", "b"), cmd_show_user(1),
        cmd_set_profile(1, "a", "b"), cmd_create_address(1), cmd_create_address(1, pq_ratchet=False),
        cmd_show_address(1), cmd_connect(1, "popopx://invite/x"), cmd_accept_contact(1),
        cmd_list_contacts(1), cmd_service_response(1, 2, {"a": 1}),
        cmd_set_accept_member_contacts(1, True), cmd_send(1, composed_text("x")),
    )
    check("every_built_command_uses_a_real_node_prefix",
          all(any(cmd.startswith(prefix) for prefix in node_commands) for cmd in built_commands))
    check("the_prefix_census_is_not_empty", len(node_commands) == 14)
    # Control for the line above: the phantom spelling that caused this must be the
    # one thing the census refuses.
    check("the_prefix_census_refuses_the_phantom_form",
          not any("/_users".startswith(prefix) for prefix in node_commands))

    # Payloads captured from `popopx-chat` 7.1.2.0 over its WebSocket API on
    # 2026-11-21 (`/users`, `/_contacts 1`) and pasted verbatim. They hold the
    # extractors to the bytes a real node sends rather than to a description of
    # them: `users` is a list of wrapper objects carrying `unreadCount`, while
    # `contactsList.contacts` is a list of bare `Contact`s, and `agentUserId` comes
    # back as the *string* "1" although the generated TypeScript and Python types
    # both declare it int64.
    live_users_list = {"type": "usersList", "users": [
        {"user": {"userId": 1, "agentUserId": "1", "userContactId": 1, "localDisplayName": "POPOPX E2E",
                  "profile": {"profileId": 1, "displayName": "POPOPX E2E", "fullName": "", "localAlias": ""},
                  "fullPreferences": {"timedMessages": {"allow": "yes"}, "fullDelete": {"allow": "no"},
                                      "reactions": {"allow": "yes"}, "voice": {"allow": "yes"},
                                      "files": {"allow": "always"}, "calls": {"allow": "yes"},
                                      "sessions": {"allow": "no"}, "commands": []},
                  "activeUser": False, "activeOrder": 1, "showNtfs": True, "sendRcptsContacts": True,
                  "sendRcptsSmallGroups": True, "autoAcceptMemberContacts": False,
                  "autoAcceptGroupInvitations": False, "userChatRelay": False, "clientService": False},
         "unreadCount": 0},
        {"user": {"userId": 2, "agentUserId": "2", "userContactId": 3, "localDisplayName": "probe bbb",
                  "profile": {"profileId": 3, "displayName": "probe bbb", "fullName": "probe bbb",
                              "localAlias": ""},
                  "fullPreferences": {"timedMessages": {"allow": "yes"}, "fullDelete": {"allow": "no"},
                                      "reactions": {"allow": "yes"}, "voice": {"allow": "yes"},
                                      "files": {"allow": "always"}, "calls": {"allow": "yes"},
                                      "sessions": {"allow": "no"}, "commands": []},
                  "activeUser": True, "activeOrder": 2, "showNtfs": True, "sendRcptsContacts": True,
                  "sendRcptsSmallGroups": True, "autoAcceptMemberContacts": False,
                  "autoAcceptGroupInvitations": False, "userChatRelay": False, "clientService": False},
         "unreadCount": 0}]}
    live_contacts_list = {"type": "contactsList",
                          "user": {"userId": 1, "agentUserId": "1", "userContactId": 1,
                                   "localDisplayName": "POPOPX E2E",
                                   "profile": {"profileId": 1, "displayName": "POPOPX E2E", "fullName": "",
                                               "localAlias": ""},
                                   "fullPreferences": {"timedMessages": {"allow": "yes"},
                                                       "fullDelete": {"allow": "no"},
                                                       "reactions": {"allow": "yes"}, "voice": {"allow": "yes"},
                                                       "files": {"allow": "always"}, "calls": {"allow": "yes"},
                                                       "sessions": {"allow": "no"}, "commands": []},
                                   "activeUser": True, "activeOrder": 1, "showNtfs": True,
                                   "sendRcptsContacts": True, "sendRcptsSmallGroups": True,
                                   "autoAcceptMemberContacts": False, "autoAcceptGroupInvitations": False,
                                   "userChatRelay": False, "clientService": False},
                          "contacts": []}
    live_users = extract_users(live_users_list)
    check("live_users_list_yields_both_users", [u["user_id"] for u in live_users] == [1, 2])
    check("live_users_list_names_them",
          [u["display_name"] for u in live_users] == ["POPOPX E2E", "probe bbb"])
    check("live_users_list_marks_one_active",
          [u["user_id"] for u in live_users if u["active_user"]] == [2])
    check("live_users_list_ignores_the_wrapper_only_row",
          all("unreadCount" not in u for u in live_users))
    check("live_contacts_list_reads_as_no_contacts", extract_contacts(live_contacts_list) == [])
    check("live_contacts_list_has_the_key_rather_than_being_malformed",
          isinstance(live_contacts_list.get("contacts"), list))
    # The node answers a bad command inside `chatError.errorType`, and the two
    # failure kinds that matter to the bridge are `commandError` (grammar) and
    # `errorStore` (the command parsed but the row is missing) — both observed live.
    grammar_miss = {"type": "chatCmdError", "chatError": {"type": "error", "errorType": {
        "type": "commandError", "message": "Failed reading: empty"}}}
    missing_row = {"type": "chatCmdError", "chatError": {"type": "errorStore", "storeError": {
        "type": "contactRequestNotFound", "contactRequestId": 9}}}
    check("live_grammar_error_reaches_the_caller",
          (response_error(grammar_miss) or {}).get("errorType", {}).get("message") == "Failed reading: empty")
    check("live_store_error_reaches_the_caller",
          (response_error(missing_row) or {}).get("storeError", {}).get("contactRequestId") == 9)
    check("both_failure_kinds_raise_the_same_error_type",
          all(isinstance(NodeCommandError(err, "/cmd"), NodeError)  # type: ignore[arg-type]
              for err in (grammar_miss["chatError"], missing_row["chatError"])))
    # …but they are different failures, and only the second one is about the node
    # being unable to do what was asked. `error_reason` is what lets a caller tell
    # them apart without matching on a message string.
    check("error_reason_names_the_grammar_miss", error_reason(grammar_miss["chatError"]) == "commandError")
    check("error_reason_names_the_missing_row", error_reason(missing_row["chatError"]) == "contactRequestNotFound")
    check("error_reason_falls_back_to_the_outer_tag", error_reason({"type": "error"}) == "error")
    check("error_reason_is_empty_for_an_unrecognised_frame", error_reason({}) == "")

    # Response reading, with payloads shaped like the node's documented types.
    direct = {
        "type": "newChatItems",
        "user": {"userId": 1},
        "chatItems": [
            {
                "chatInfo": {"type": "direct", "contact": {"contactId": 9, "localDisplayName": "Ada"}},
                "chatItem": {
                    "chatDir": {"type": "directRcv"},
                    "meta": {"itemId": 42, "itemText": "::CB::pay_3"},
                    "content": {"type": "rcvMsgContent", "msgContent": {"type": "text", "text": "::CB::pay_3"}},
                },
            },
            {
                "chatInfo": {"type": "direct", "contact": {"contactId": 9, "localDisplayName": "Ada"}},
                "chatItem": {
                    "chatDir": {"type": "directSnd"},
                    "meta": {"itemId": 43, "itemText": "已开通"},
                    "content": {"type": "sndMsgContent", "msgContent": {"type": "text", "text": "已开通"}},
                },
            },
            {
                "chatInfo": {"type": "group", "group": {"groupId": 2}},
                "chatItem": {"meta": {"itemId": 1}, "content": {"type": "rcvMsgContent", "msgContent": {"type": "text", "text": "x"}}},
            },
            {"chatInfo": "unknown", "chatItem": {}},
        ],
    }
    messages = extract_inbound_messages(direct)
    check("extract_only_direct", len(messages) == 2)
    check("extract_rcv_direction", messages[0].received and not messages[1].received)
    check("extract_contact_id", messages[0].contact_id == 9 and messages[0].display_name == "Ada")
    check("extract_item_id", messages[0].item_id == 42)
    check("extract_control_flagged", messages[0].is_control and not messages[1].is_control)
    check("extract_user_id", messages[0].user_id == 1)
    check("extract_ignores_unknown_resp", extract_inbound_messages({"type": "contactsList"}) == [])
    check("extract_ignores_non_list", extract_inbound_messages({"type": "newChatItems"}) == [])
    check("extract_falls_back_to_meta", extract_inbound_messages({
        "type": "newChatItems",
        "chatItems": [{"chatInfo": {"type": "direct", "contact": {"contactId": 1}},
                       "chatItem": {"meta": {"itemText": "fallback"}}}],
    })[0].text == "fallback")

    request = extract_contact_request({
        "type": "receivedContactRequest",
        "contactRequest": {"contactRequestId": 5, "profile": {"displayName": "Grace"}},
    })
    check("contact_request_id", request is not None and request["contact_request_id"] == 5)
    check("contact_request_name", request is not None and request["display_name"] == "Grace")
    check("contact_request_none_for_other", extract_contact_request({"type": "newChatItems"}) is None)
    # Both spellings the node documents, because the tag decides whether a new
    # follower is accepted at all: an extractor that reads only one of them looks
    # exactly like a node that never sent the event.
    check("contact_request_reads_the_chat_item_tag", extract_contact_request({
        "type": "contactRequest",
        "contactRequest": {"contactRequestId": 6, "profile": {"displayName": "Ada"}},
    })["contact_request_id"] == 6)
    check("contact_request_reads_the_event_tag", extract_contact_request({
        "type": "receivedContactRequest",
        "contactRequest": {"contactRequestId": 7, "profile": {"displayName": "Ada"}},
    })["contact_request_id"] == 7)

    check("link_from_conn_link_contact", extract_link({
        "type": "userContactLinkCreated",
        "connLinkContact": {"connFullLink": "popopx://invite/abc"},
    }) == "popopx://invite/abc")
    check("link_nested_in_contact_link", extract_link({
        "type": "userContactLink",
        "contactLink": {"connLinkContact": {"connFullLink": "popopx://invite/def"}},
    }) == "popopx://invite/def")
    check("link_absent_is_empty", extract_link({"type": "activeUser"}) == "")

    contacts = extract_contacts({
        "type": "contactsList",
        "contacts": [
            {"contactId": 3, "localDisplayName": "Ada", "profile": {"displayName": "Ada L"}},
            {"contactId": 4, "localDisplayName": "Bob"},
            {"localDisplayName": "idless"},
            "junk",
        ],
    })
    check("contacts_parsed", [c["contact_id"] for c in contacts] == [3, 4])
    check("contacts_display_name", contacts[0]["display_name"] == "Ada")
    users = extract_users({"type": "usersList", "users": [
        {"user": {"userId": 1, "localDisplayName": "svc", "activeUser": True}},
        {"userId": 2},
    ]})
    check("users_parsed", users[0]["user_id"] == 1 and users[1]["user_id"] == 2)
    check("users_active_default_true", users[1]["active_user"])
    check("error_tag_detected", response_error({"type": "chatCmdError", "chatError": {"code": "syntax"}}) == {"code": "syntax"})
    check("non_error_returns_none", response_error({"type": "newChatItems"}) is None)

    stats = BridgeStats(connected_at=time.time() - 10, messages_in=3)
    check("stats_keys", stats.as_dict()["messages_in"] == 3 and "uptime_seconds" in stats.as_dict())
    check("stats_uptime_sane", 9 <= stats.as_dict()["uptime_seconds"] <= 11)

    bridge = AgentBridge(ws_url="ws://127.0.0.1:5225", service_display_name="Acme 服务")
    check("bridge_starts_disconnected", not bridge.connected and bridge.user_id is None)
    check("bridge_state_shape", bridge.state()["pending_commands"] == 0 and bridge.state()["connected"] is False)
    first, second = bridge.next_corr_id(), bridge.next_corr_id()
    check("corr_ids_unique", first != second and first.startswith("popopx-"))
    check("bridge_requires_user", _raises_user_required(bridge))

    # The routing that a unit test can only prove with a fake socket: correlation,
    # the error tag, and the event fan-out. Run in a private loop, so `self_test()`
    # must be called outside a running event loop (it is a development entry point;
    # nothing in the gateway calls it at boot).
    loop = asyncio.new_event_loop()
    try:
        checks.extend(loop.run_until_complete(_async_checks()))
    finally:
        loop.close()
    return checks


class _FakeNode:
    """The two methods `AgentBridge` uses from a WebSocket connection."""

    def __init__(self) -> None:
        self.sent: List[str] = []
        self.closed = False

    async def send(self, payload: str) -> None:
        self.sent.append(payload)

    async def close(self) -> None:
        self.closed = True


def _bridged(node: _FakeNode) -> AgentBridge:
    bridge = AgentBridge(ws_url="ws://127.0.0.1:5225")
    bridge._ws = node
    bridge._send_lock = asyncio.Lock()
    bridge.user_id = 1
    return bridge


async def _async_checks() -> List[str]:
    checks: List[str] = []

    def check(name: str, condition: bool) -> None:
        if not condition:
            raise AssertionError("self_test failed: %s" % name)
        checks.append(name)

    def sent_item(text: str, direction: str = "rcv") -> Dict[str, Any]:
        return {
            "chatInfo": {"type": "direct", "contact": {"contactId": 9, "localDisplayName": "Ada"}},
            "chatItem": {
                "meta": {"itemId": 1, "itemText": text},
                "content": {"type": direction + "MsgContent", "msgContent": {"type": "text", "text": text}},
            },
        }

    # A command is resolved by the response carrying its corrId, and nothing else.
    node = _FakeNode()
    bridge = _bridged(node)
    bridge.next_corr_id = lambda: "fixed-1"  # type: ignore[assignment]
    task = asyncio.ensure_future(bridge.command("/_users", timeout=1.0))
    await asyncio.sleep(0)
    check("command_waits_on_corr_id", len(bridge._pending) == 1 and "fixed-1" in bridge._pending)
    check("command_envelope_shape", json.loads(node.sent[0]) == {"corrId": "fixed-1", "cmd": "/_users"})
    await bridge._dispatch({"corrId": "other", "resp": {"type": "usersList"}})
    check("wrong_corr_id_does_not_resolve", len(bridge._pending) == 1)
    await bridge._dispatch({"corrId": "fixed-1", "resp": {"type": "usersList", "users": [{"userId": 1}]}})
    resolved = await task
    check("command_returns_resp_body", resolved.get("type") == "usersList" and len(resolved) > 0)
    check("pending_cleared", not bridge._pending)

    # The documented error tag becomes an exception, not a silent empty result.
    bridge = _bridged(_FakeNode())
    bridge.next_corr_id = lambda: "fixed-2"  # type: ignore[assignment]
    task = asyncio.ensure_future(bridge.command("/_contacts 1", timeout=1.0))
    await asyncio.sleep(0)
    await bridge._dispatch({"corrId": "fixed-2", "resp": {"type": "chatCmdError", "chatError": {"code": "syntax"}}})
    try:
        await task
        check("command_error_raises", False)
    except NodeCommandError as exc:
        check("command_error_raises", exc.chat_error.get("code") == "syntax")
    check("failure_counted_on_error", bridge.stats.commands_failed == 1)

    # No response at all is a timeout, and the pending map must not leak.
    bridge = _bridged(_FakeNode())
    bridge.next_corr_id = lambda: "fixed-3"  # type: ignore[assignment]
    try:
        await bridge.command("/_users", timeout=0.01)
        check("timeout_raises_and_clears", False)
    except NodeTimeout:
        check("timeout_raises_and_clears", not bridge._pending)

    # Disconnection fails in-flight commands instead of hanging them.
    node = _FakeNode()
    bridge = _bridged(node)
    bridge.next_corr_id = lambda: "fixed-4"  # type: ignore[assignment]
    task = asyncio.ensure_future(bridge.command("/_users", timeout=1.0))
    await asyncio.sleep(0)
    await bridge._teardown_socket(node)
    try:
        await task
        check("teardown_fails_pending", False)
    except NodeNotConnected:
        check("teardown_fails_pending", True)
    check("teardown_marks_disconnected", not bridge.connected and node.closed)

    # send_text issues the command and counts it, with no user id in the string.
    node = _FakeNode()
    bridge = _bridged(node)
    bridge.next_corr_id = lambda: "fixed-5"  # type: ignore[assignment]
    task = asyncio.ensure_future(bridge.send_text(9, "::CB::ack"))
    await asyncio.sleep(0)
    issued = json.loads(node.sent[0])["cmd"]
    check("send_text_no_user_id", issued.startswith("/_send @9 ") and " 1 " not in issued)
    await bridge._dispatch({"corrId": "fixed-5", "resp": {"type": "newChatItems", "chatItems": [sent_item("hi", "snd")]}})
    await task
    check("send_text_counts_out", bridge.stats.messages_out == 1)

    # Events: an unmatched newChatItems reaches the message handler once per
    # received item, and our own echo never re-enters the pipeline.
    seen: List[InboundMessage] = []

    async def on_message(item: InboundMessage) -> None:
        seen.append(item)

    node = _FakeNode()
    bridge = _bridged(node)
    bridge._on_message = on_message
    await bridge._dispatch({"resp": {"type": "newChatItems", "chatItems": [sent_item("hello"), sent_item("echo", "snd")]}})
    check("event_dispatch_one_received", [m.text for m in seen] == ["hello"])
    check("event_dispatch_counts_in", bridge.stats.messages_in == 2)
    await bridge._dispatch({"resp": {"type": "someFutureEventType", "extra": {"undocumented": 1}}})
    check("unknown_event_without_handler_does_not_raise", True)

    events: List[Tuple[str, Dict[str, Any]]] = []

    async def on_event(tag: str, body: Mapping[str, Any]) -> None:
        events.append((tag, dict(body)))

    bridge._on_event = on_event
    await bridge._dispatch({"resp": {"type": "someFutureEventType", "extra": {"undocumented": 1}}})
    check("unknown_event_reaches_handler", events and events[0][0] == "someFutureEventType")
    await bridge._dispatch({"resp": {"type": "receivedContactRequest", "contactRequest": {"contactRequestId": 4}}})
    check("contact_request_routed", events[-1][0] == "contact_request" and events[-1][1]["contact_request_id"] == 4)
    group_item = {
        "chatInfo": {"type": "group", "group": {"groupId": 2}},
        "chatItem": {
            "meta": {"itemText": "x"},
            "content": {"type": "rcvMsgContent", "msgContent": {"type": "text", "text": "x"}},
        },
    }
    await bridge._dispatch({"resp": {"type": "newChatItems", "chatItems": [group_item]}})
    check("group_items_counted_not_lost", bridge.stats.events_dropped == 1)

    # A handler that raises must not take the reader down with it.
    async def explodes(item: InboundMessage) -> None:
        raise RuntimeError("plugin bug")

    bridge._on_message = explodes
    await bridge._dispatch({"resp": {"type": "newChatItems", "chatItems": [sent_item("again")]}})
    check("raising_handler_survives", True)

    # Malformed frames are dropped, not exceptions.
    bridge = _bridged(_FakeNode())
    await bridge._dispatch({"resp": "not a mapping"})
    await bridge._dispatch({"noResp": 1})
    await bridge._dispatch({"corrId": 12, "resp": {"type": None}})
    check("malformed_frames_counted", bridge.stats.events_dropped == 3)

    # Boot resilience: a node that is not listening yet must not end the process.
    dialled: List[float] = []

    async def refuse(*, timeout: float) -> None:
        dialled.append(timeout)
        raise ConnectionRefusedError("connection refused (faked)")

    states: List[Tuple[bool, str]] = []

    async def on_state(up: bool, detail: str) -> None:
        states.append((up, detail))

    silent = AgentBridge(ws_url="ws://127.0.0.1:5225")
    silent._connect_once = refuse  # type: ignore[assignment]
    silent._on_state = on_state
    await silent.start()
    check("boot_dials_once", dialled == [silent.command_timeout])
    check("boot_without_node_serves", not silent.connected and silent.user_id is None)
    check("boot_without_node_retries", silent._supervisor is not None and not silent._supervisor.done())
    check("boot_without_node_reports_honest_state", states == [(False, states[0][1])] and "not connected at boot" in states[0][1])
    await silent.stop()
    check("boot_supervisor_stops", silent._supervisor is None)
    check("boot_supervisor_stop_leaves_no_task", silent._closing and not silent.connected)

    # Control: the swallow is opt-out, not the only behaviour on offer.
    try:
        await _strict_start(refuse)
        check("strict_start_still_raises", False)
    except ConnectionRefusedError:
        check("strict_start_still_raises", True)

    # The real refusal, not my exception of choice: a genuinely closed port must be
    # survivable too, or the `except` tuple above names the wrong error class.
    port = _closed_port()
    honest = AgentBridge(ws_url="ws://127.0.0.1:%d" % port)
    honest._on_state = on_state
    await honest.start()
    check("real_closed_port_survives_boot", not honest.connected)
    check("real_closed_port_state_listener_fired", len(states) == 2 and states[1][0] is False)
    await honest.stop()

    # …and a port that is NOT empty, because that is what actually killed a production
    # boot on 2026-11-22. Something answering with bytes that are not an HTTP response
    # makes `websockets` raise `InvalidMessage`, a `WebSocketException` and not an
    # `OSError`, which went straight through the boot handler and ended the gateway.
    # Every fake above raises `ConnectionRefusedError`, so this suite could not have
    # seen that hole; the listener below is a real socket so the library, not this
    # file, picks the exception class.
    junk, junk_port = _non_http_port()
    handshake: List[Tuple[bool, str]] = []

    async def on_handshake_state(up: bool, detail: str) -> None:
        handshake.append((up, detail))

    weird = AgentBridge(ws_url="ws://127.0.0.1:%d" % junk_port, command_timeout=5.0)
    weird._on_state = on_handshake_state  # type: ignore[assignment]
    try:
        await weird.start()
        handshake_survived = True
    except Exception:  # noqa: BLE001 - escaping the handler IS the defect under test
        handshake_survived = False
    check(
        "boot_survives_a_non_http_handshake",
        handshake_survived and not weird.connected
        and weird._supervisor is not None and not weird._supervisor.done(),
    )
    check(
        "boot_non_http_handshake_reports_honest_state",
        bool(handshake) and handshake[-1][0] is False and "not connected at boot" in handshake[-1][1],
    )
    await weird.stop()
    junk.close()

    # The class list itself, both ways round: with the wheel installed its exception base
    # has to be listed, and on a machine without it the three documented classes have to
    # be exactly what `start()` catches. Either branch is an assertion, so the check does
    # not quietly become true on the configuration it cannot test.
    try:
        from websockets.exceptions import WebSocketException
        tuple_matches = WebSocketException in _node_unavailable_errors()
    except ImportError:  # pragma: no cover - the wheel-less path
        tuple_matches = _node_unavailable_errors() == (NodeError, OSError, asyncio.TimeoutError)
    check("boot_error_tuple_matches_the_installed_websockets", tuple_matches)

    # A user that has never minted an address answers `/_show_address` with an error
    # frame rather than an empty success — both frames below are the bytes a real
    # `popopx-chat` 7.1.2.0 sent on 2026-11-21. The pairing route asks this method
    # first, so the not-found frame has to read as "no address yet": anything else
    # and minting an address for the first time fails as a dead link.
    absent = NodeCommandError(
        {"type": "errorStore", "storeError": {"type": "userContactLinkNotFound"}}, cmd_show_address(2)
    )
    refused = NodeCommandError(
        {"type": "error", "errorType": {"type": "commandError", "message": "Failed reading: empty"}},
        cmd_show_address(2),
    )

    def _raising(error: NodeCommandError):  # noqa: ANN202 - test helper
        async def _command(*_args: Any, **_kwargs: Any) -> Dict[str, Any]:
            raise error
        return _command

    reader = AgentBridge(ws_url="ws://127.0.0.1:5225")
    reader.user_id = 2
    reader.command = _raising(absent)  # type: ignore[assignment]
    check("an_absent_address_reads_as_empty", (await reader.show_contact_address()) == "")
    reader.command = _raising(refused)  # type: ignore[assignment]
    try:
        await reader.show_contact_address()
        check("any_other_refusal_still_raises", False)
    except NodeCommandError:
        check("any_other_refusal_still_raises", True)
    check("the_empty_address_does_not_overwrite_a_known_one", reader.contact_address == "")

    return checks


async def _strict_start(refuse) -> None:  # noqa: ANN001 - test helper
    bridge = AgentBridge(ws_url="ws://127.0.0.1:5225")
    bridge._connect_once = refuse  # type: ignore[assignment]
    await bridge.start(strict=True)


def _non_http_port() -> Tuple[socket.socket, int]:
    """A port that answers, but not with HTTP: returns the listener and its port.

    The caller closes the listener to end the thread. This is what the node's
    WebSocket control API looks like to a client when the port is owned by something
    else — a plain web server, a proxy, a node still writing its first line — and the
    point of the shape is that `websockets` turns it into `InvalidMessage`, which is
    not an `OSError`.
    """
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(4)

    def answer() -> None:
        listener.settimeout(10.0)
        try:
            while True:
                conn, _ = listener.accept()
                try:
                    conn.sendall(b"NOT HTTP AT ALL\r\n\r\n")
                finally:
                    conn.close()
        except OSError:
            pass  # the caller closed the listener; the thread's work is finished

    threading.Thread(target=answer, daemon=True).start()
    return listener, int(listener.getsockname()[1])


def _closed_port() -> int:
    """A port that was bound and released, so connecting to it is refused by the OS."""
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


def _raises_user_required(bridge: "AgentBridge") -> bool:
    """A command built from a None user id would stringify as `/_contacts None`,
    which the node rejects with a syntax error that reads like a broken install.
    Refusing locally is the only honest failure."""
    try:
        bridge._require_user()
    except NodeNotConnected:
        return True
    return False

