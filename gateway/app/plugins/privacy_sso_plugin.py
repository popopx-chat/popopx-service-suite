# Copyright (c) 2026 POPOPX (popopx.chat)
# SPDX-License-Identifier: AGPL-3.0-only
"""Passwordless scan login: the "零追踪" SSO plugin.

The round trip, in the order the bytes actually move
-----------------------------------------------------
1. The RP's **server** calls ``POST /sessions`` with its own ``uri``, a display
   ``name``, a ``scope`` and its anti-CSRF ``nonce``. Nothing about a human is
   involved yet, and nothing about a human is stored: the gateway mints a
   144-bit session id, a row in ``sso_sessions`` in state ``pending``, and an
   expiry deadline (``config.sso_ttl_seconds``). It answers the QR payload and
   nothing else.
2. The RP renders that payload as a QR in the browser. The payload is
   ``popopx://sso?uri=<服务号邀请地址>&session=<session id>`` — the form the
   shipped client is built to consume (see "The QR payload" below).
3. The **phone** scans it. POPPX decodes the deep link, records an in-memory
   intent keyed by the service address, and sends ``::SSO_SCAN<<session id>>``
   into this service account — i.e. into *this plugin*, as an inbound message
   from the scanner's ``contact_id``. That uplink is the whole reason the
   product needs a chat account at all: the login travels over the user's own
   pairwise channel, not over a website the RP controls.
4. The plugin binds the session to that contact, delivers a ``security`` style
   confirmation card to the phone, and the RP polls ``GET /sessions/{id}`` —
   state only for a browser, and never an identity.
5. The user taps 确认. The phone sends ``::CB::sso:confirm:<id>``, which arrives
   here as a ``card_callback``. The plugin derives the login credential, charges
   the ``sso_login`` meter, flips the row to ``confirmed``, and rewrites the card
   in place (same ``cardId``) so the buttons cannot be tapped twice.
6. The RP's **server** re-polls that session with its bearer secret, which is the
   only answer that carries the credential, and then calls ``POST /verify`` with
   the bearer secret plus that credential to get back **only** ``pairwise_uid``
   and ``scope``. The transition this call performs is the redemption: the row
   becomes ``delivered``, the credential's hash is wiped from the row, and a
   replay answers ``already_delivered``.

   Two channels, deliberately: a QR is a picture on a screen that anyone can
   photograph, so an unauthenticated poll can learn that *someone* approved and
   nothing else, and the credential — the artefact that actually buys a login —
   moves only over a request the merchant's own backend can sign.

State machine
-------------
``pending → scanned → confirmed → delivered``, with ``expired`` and
``cancelled`` reachable from every non-terminal state::

    pending    QR minted, no phone has seen it.           → scanned, expired, cancelled
    scanned    a contact is bound, the card was sent.     → confirmed, expired, cancelled
    confirmed  the user approved; a credential exists.    → delivered, expired, cancelled
    delivered  the RP redeemed it.                        terminal
    expired    the deadline passed.                       terminal
    cancelled  the user (or the RP) refused.              terminal

Expiry is **computed, never swept**: a row in an open state whose deadline has
passed *is* expired, whether or not the column still says ``pending``. There is
no background task, so a restarted gateway cannot have a session that is alive
in one process and dead in another; ``expires_at_ms`` is the whole truth. The
column is also persisted opportunistically on the first read after the deadline,
so the operator's audit list and the RP's poll answer cannot disagree.

One deviation from the brief is load-bearing and is the schema's, not mine:
``sso_sessions.state`` carries
``CHECK (state IN ('pending','scanned','approved','denied','expired','consumed'))``,
so the words ``confirmed``, ``delivered`` and ``cancelled`` are *rejected by
SQLite* (proved in :func:`self_test`). This module therefore writes the schema's
vocabulary and reads it back as the product's, through :data:`DB_TO_LOGICAL`,
and every HTTP answer, card and log speaks ``confirmed``/``delivered``/
``cancelled``.

What "零追踪" costs, concretely
------------------------------
Things this plugin deliberately does not have anywhere:

* **no IP address, ever** — not in a row, not in a log line. The only
  per-source state is an in-process, salted, HMAC-keyed sliding window that is
  destroyed by a restart and cannot be joined to anything (:class:`_MintWindow`).
  A durable per-source counter would need a column, and there is none; that gap
  is reported rather than papered over with a settings row.
* **no device, no geolocation, no user agent, no locale** — the confirmation
  card shows exactly three fields: who is asking, what they asked for, and the
  time. A card that listed the device would be a database the user cannot see.
* **no token, and no reusable secret** — only a one-way seal of it
  (:func:`seal_token`), nulled out the moment it is redeemed.
* **no name↔identity join** — the row holds ``contact_id`` and
  ``pairwise_uid``, never a phone number, and the pairwise id is per service
  account by construction, so two RPs share nothing.
* **no query strings in the log, and no query string in the audit answer** — an
  RP's ``uri`` usually carries its own state/redirect token; the card and
  ``GET /audit`` show only ``scheme://host``.
* **no login without a scan** — there is no endpoint that grants a credential to
  whoever holds the session id. Polling proves nothing; only the phone that the
  user already unlocked can approve.

That last bullet is the entire product claim, and it is why the state machine has
no edge from ``pending`` to ``confirmed``.

The single-use token rule
-------------------------
``token = HMAC-SHA256(key, "popopx-sso-v1\\n" ‖ session_id ‖ "\\n" ‖ pairwise_uid
‖ "\\n" ‖ scope)``, lowercase hex, 64 characters, where ``key`` is the scanner's
own pairwise session secret (32 bytes, per follower, per service account) and
falls back to ``config.h5_server_secret`` only when that follower has no
session. Binding the *pairwise uid* and the *scope* into the preimage means a
credential is useless for another follower and cannot be replayed for a wider
scope, and the key itself is per-session — so a leaked gateway row does not
leak the derivation of anyone else's.

The row stores ``sha256(token)`` wrapped with the key source
(:func:`seal_token` → ``"sha256$eco$<hex>"``), because ``sso_sessions`` has
neither a ``key_source`` column nor a JSON blob column to put it in; a fallback
must be visible in the row that was written with it, not only in a log line that
a restart rotates away. Verification presents the token, the gateway hashes it
and compares with :func:`hmac.compare_digest`, and the *successful* compare is
the one that also transitions the row to ``delivered`` — atomically, with a
conditional ``UPDATE`` whose row count is the claim. Two RPs redeeming the same
credential therefore cannot both win, and the loser sees
``already_delivered``.

The QR payload, and the two places the client outranks the spec sheet
---------------------------------------------------------------------
The client parses these links itself now. ``PopopxEcoLink`` (``PopopxEcoRouterAndDeepLink.swift``,
``struct PopopxEcoLink``) recognises ``popopx://service?…`` and ``popopx://sso?…``, fixes ``uri``
as the address parameter, and takes the second value from ``ref`` for a service link and
``session`` for an SSO one; a parsed link becomes a ``PopopxEcoRouter.Intent`` whose ``kind`` is
``.reference(articleId)`` or ``.ssoScan(sessionId)``, whose ``serviceURI`` is the ``uri=`` value
and which is deliberately held in memory only — an intent that survived a relaunch would be a
message sent without the user having touched anything. ``service_office.md:92`` agrees on the
shape: ``popopx://sso?uri=<服务号SMP地址>&session=...``.

So ``uri=`` in the QR is the **service account's own invite address** (read from
``service_identity.address``), *not* the RP's https URL that the brief's
``POST /sessions`` body calls ``uri``. Both are honoured: the RP's URL is
validated and stored as ``rp_uri`` and shown as an origin; the QR carries the
invite address, because a link whose ``uri=`` points at the RP would make the
phone look up the wrong contact and drop the intent. Deviation reported.

The second deviation is the terminal card. The brief asks for one button of
``kind="none"`` reading 已授权. ``PopopxEcoAction.isSane`` returns ``false`` for
``.none`` (PopopxEcoModels.swift:685-702), which fails
``PopopxServiceCard.isSane`` (:524-536), which makes the frame decode to ``nil``
(:148) — the update would be *silently dropped by the phone*, leaving live 确认
buttons on an approved login. ``crypto_service.build_action`` refuses the same
thing. Instead the terminal update (a) replaces the action array wholesale with
one legal inert ``callback`` button (``merged()`` only replaces actions when the
incoming array is non-empty, :181-193), and (b) sets ``et`` to the confirming
instant, which is the client's *own* read-only rule: ``cardIsInert`` empties the
button row (ServiceCardBubbleView.swift:379) and the runner returns ``.expired``
before dispatch. Buttons gone, frame delivered.

Wire rules this module obeys because a violation is dropped, not rejected
-------------------------------------------------------------------------
Every limit is in *characters* (``PopopxEcoLimits``: id 64, title 120, body
2000, field label 80, field value 240, action payload 512, URL 2048, at most 8
fields and 4 actions), all mirrored by ``crypto_service.EcoLimits``, and every
card leaves through :func:`build_card` so a violation raises here instead of
vanishing on a phone. ``ut`` is required (omitting it does not degrade the card,
it deletes it), ``action id`` values are unique within a card, and an unknown
``action`` kind string throws during decode and takes the frame with it — hence
the constant set in ``crypto_service.ACTION_KINDS`` and nothing invented here.
Query values are percent-encoded with exactly the client's allowlist,
``alphanumerics ∪ "-._~"`` (PopopxH5Launcher.swift:126,147-148), because an
unencoded ``&`` inside ``uri=`` would truncate the session id at the phone's
query split, and the session id is placed last so the damage cannot reach it.

Module shape
------------
``create_router(deps)`` for the RP-facing HTTP surface,
``handle_inbound(deps, message)`` for the phone-facing protocol step,
:func:`claims` so a dispatcher can route ``::CB::`` payloads by prefix without
importing this file's guts, and :func:`self_test`, which runs under
``/usr/bin/python3`` with no third-party wheel installed.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import re
import secrets
import threading
import time
import urllib.parse
from collections import deque
from collections.abc import Mapping as _MappingABC
from typing import TYPE_CHECKING, Any, Dict, List, Mapping, Optional, Sequence, Tuple

from app.billing_service import BillingError
from app.crypto_service import (
    ACTION_KINDS,
    ACTION_STYLES,
    CARD_STYLES,
    EcoError,
    EcoLimits,
    build_action,
    build_card,
    now_ms,
    validate_http_url,
    validate_secret_hex,
)

if TYPE_CHECKING:  # type names only; nothing here is imported at runtime
    from fastapi import APIRouter, Request

    from app.agent_bridge import InboundMessage
    from app.plugins import PluginDeps

__all__ = ["claims", "create_router", "handle_inbound", "self_test", "PLUGIN_ID"]

logger = logging.getLogger("popopx.plugins.privacy_sso")

PLUGIN_ID = "privacy_sso"

# ─────────────────────────────────────────────────────────────────────────────
# 1. The callback grammar
# ─────────────────────────────────────────────────────────────────────────────
#
# A card ``callback`` action makes the phone send ``::CB::<payload>``
# (agent_bridge.parse_inbound_text:252-266), so the two buttons on the
# confirmation card are the only way a human can answer this protocol, and their
# payloads are the whole wire contract. ``noop`` exists so the terminal card can
# carry a legal action without carrying an effect: the alternative — a
# ``kind="none"`` action — is a frame the phone throws away.

CB_CONFIRM = "sso:confirm:"
CB_CANCEL = "sso:cancel:"
CB_NOOP = "sso:noop:"
CB_PREFIXES = (CB_CONFIRM, CB_CANCEL, CB_NOOP)

#: ``::SSO_SCAN::`` payloads come from a camera and a human being, so they are
#: validated by the client's own single-token rule (`PopopxEcoUplink.isSendablePayload`):
#: non-empty, at most 512 characters,
#: no whitespace at all, and no ``::`` (which would let a scanned payload
#: forge a different control frame).
MAX_TOKEN_CHARS = EcoLimits.payload_chars

#: The shape this module mints, anchored with ``\Z`` so ``match`` cannot accept a
#: legal-looking prefix of a longer, illegal string.
_SESSION_ID_RE = re.compile(r"[A-Za-z0-9_-]{8,64}\Z")


def is_single_token(text: Any) -> bool:
    """The client's ``isSingleToken``, applied to a scanned session id."""
    if not isinstance(text, str) or not text:
        return False
    if len(text) > MAX_TOKEN_CHARS:
        return False
    if "::" in text:
        return False
    for ch in text:
        if ch.isspace():
            return False
    return True


def claims(payload: Any) -> bool:
    """Whether one ``::CB::`` payload belongs to this plugin.

    Pure, allocation-free, import-cheap and total: it must be usable as a
    dispatcher predicate, so it never raises and never touches the database.
    A payload with our prefix and a garbage tail still counts as ours — it is a
    button this plugin rendered, and letting it fall through to the merchant's
    autoreply would answer a protocol step with marketing text.
    """
    if not isinstance(payload, str):
        return False
    for prefix in CB_PREFIXES:
        if payload.startswith(prefix):
            tail = payload[len(prefix):]
            return bool(tail) and len(payload) <= MAX_TOKEN_CHARS and "::" not in tail
    return False


def split_callback(payload: str) -> Tuple[Optional[str], str]:
    """``("confirm", "<id>")`` for a well-formed payload, else ``(None, "")``."""
    if not isinstance(payload, str):
        return None, ""
    for prefix in CB_PREFIXES:
        if payload.startswith(prefix):
            verb = prefix[len("sso:"):-1]
            return verb, payload[len(prefix):]
    return None, ""


_CARD_ID_PREFIX = "sso:"
_CARD_ID_FOLDED_PREFIX = "ssoh:"


def card_id_for(session_id: str) -> str:
    """The one card per session, so a re-scan mutates instead of stacking.

    28 characters for the 24 this module mints, well inside the client's 64, and
    derived rather than stored means the card id can never disagree with the row
    it describes. A session id long enough to overflow the ceiling is folded
    through SHA-256 under a *different* prefix instead of being truncated: a
    truncated id would collide with a sibling session whose prefix happened to
    match, and a card id that collides is one card updated for the wrong login.
    """
    candidate = _CARD_ID_PREFIX + session_id
    if len(candidate) <= EcoLimits.card_id_chars:
        return candidate
    keep = EcoLimits.card_id_chars - len(_CARD_ID_FOLDED_PREFIX)
    return _CARD_ID_FOLDED_PREFIX + hashlib.sha256(session_id.encode("utf-8")).hexdigest()[:keep]


def session_id_from_card_id(card_id: str) -> str:
    """The inverse for un-folded ids; "" for anything else, including a fold.

    A fold is one-way on purpose. Guessing that a 60-hex-character card id is
    also a session id would be exactly the confusion this function exists to
    avoid, and nothing needs the inverse: the row owns the pairing.
    """
    if not isinstance(card_id, str) or not card_id.startswith(_CARD_ID_PREFIX):
        return ""
    tail = card_id[len(_CARD_ID_PREFIX):]
    return tail if _SESSION_ID_RE.match(tail) else ""


# ─────────────────────────────────────────────────────────────────────────────
# 2. The state machine
# ─────────────────────────────────────────────────────────────────────────────

DB_PENDING = "pending"
DB_SCANNED = "scanned"
DB_APPROVED = "approved"
DB_DENIED = "denied"
DB_EXPIRED = "expired"
DB_CONSUMED = "consumed"
DB_STATES = (DB_PENDING, DB_SCANNED, DB_APPROVED, DB_DENIED, DB_EXPIRED, DB_CONSUMED)

LOGICAL_PENDING = "pending"
LOGICAL_SCANNED = "scanned"
LOGICAL_CONFIRMED = "confirmed"
LOGICAL_DELIVERED = "delivered"
LOGICAL_EXPIRED = "expired"
LOGICAL_CANCELLED = "cancelled"
LOGICAL_STATES = (
    LOGICAL_PENDING,
    LOGICAL_SCANNED,
    LOGICAL_CONFIRMED,
    LOGICAL_DELIVERED,
    LOGICAL_EXPIRED,
    LOGICAL_CANCELLED,
)

#: Persisted vocabulary (`sso_sessions.state`'s CHECK) → product vocabulary.
DB_TO_LOGICAL: Dict[str, str] = {
    DB_PENDING: LOGICAL_PENDING,
    DB_SCANNED: LOGICAL_SCANNED,
    DB_APPROVED: LOGICAL_CONFIRMED,
    DB_CONSUMED: LOGICAL_DELIVERED,
    DB_EXPIRED: LOGICAL_EXPIRED,
    DB_DENIED: LOGICAL_CANCELLED,
}
LOGICAL_TO_DB: Dict[str, str] = {value: key for key, value in DB_TO_LOGICAL.items()}

#: States in which the deadline still owns the row. ``cancelled``/``expired``/
#: ``delivered`` are past the point where a deadline means anything.
OPEN_DB_STATES: Tuple[str, ...] = (DB_PENDING, DB_SCANNED, DB_APPROVED)
TERMINAL_LOGICAL_STATES = (LOGICAL_DELIVERED, LOGICAL_EXPIRED, LOGICAL_CANCELLED)

LEGAL_TRANSITIONS: Dict[str, Tuple[str, ...]] = {
    LOGICAL_PENDING: (LOGICAL_SCANNED, LOGICAL_EXPIRED, LOGICAL_CANCELLED),
    LOGICAL_SCANNED: (LOGICAL_CONFIRMED, LOGICAL_SCANNED, LOGICAL_EXPIRED, LOGICAL_CANCELLED),
    LOGICAL_CONFIRMED: (LOGICAL_DELIVERED, LOGICAL_EXPIRED, LOGICAL_CANCELLED),
    LOGICAL_DELIVERED: (),
    LOGICAL_EXPIRED: (),
    LOGICAL_CANCELLED: (),
}


def is_legal_transition(frm: str, to: str) -> bool:
    """One edge of the machine, in product vocabulary.

    ``scanned → scanned`` is legal and means "re-deliver the card to the same
    follower"; it is the retry path for a delivery that the node never
    accepted. There is no ``pending → confirmed``: no scan, no grant.
    """
    return to in LEGAL_TRANSITIONS.get(frm, ())


def logical_state(db_state: Optional[str]) -> str:
    """The product name for a stored state, defaulting to the unsafe answer."""
    mapped = DB_TO_LOGICAL.get(db_state or "")
    if mapped is None:
        # A row written by a future migration whose vocabulary this build does
        # not know must not be able to log anyone in.
        logger.warning("sso: unrecognised stored state %r treated as expired", db_state)
        return LOGICAL_EXPIRED
    return mapped


#: The three states a deadline can still end.
OPEN_STATES_LOGICAL = (LOGICAL_PENDING, LOGICAL_SCANNED, LOGICAL_CONFIRMED)


def effective_state(db_state: Optional[str], expires_at_ms: Optional[int], now: int) -> str:
    """Computed expiry: the answer to "what is this session *now*"."""
    current = logical_state(db_state)
    if current in OPEN_STATES_LOGICAL and expires_at_ms is not None and now >= int(expires_at_ms):
        return LOGICAL_EXPIRED
    return current


def expiry_deadline(created_at_ms: int, ttl_seconds: int) -> int:
    """The mint deadline of the scan code. Exact arithmetic, milliseconds in."""
    return int(created_at_ms) + int(ttl_seconds) * 1000


def token_grace_ms(poll_interval_ms: int) -> int:
    """How long a confirmed credential outlives its scan deadline.

    A user who approves in the final second of the QR's life would otherwise
    watch the credential die before the browser's next poll could carry it. The
    grace is a few poll cycles, never a fixed generous number: long enough for
    the RP that is behaving correctly, short enough that an approved-but-never-
    redeemed row is not a standing credential.
    """
    return max(30_000, 10 * int(poll_interval_ms))


def confirmed_deadline(expires_at_ms: int, confirmed_at_ms: int, poll_interval_ms: int) -> int:
    """``max`` of the two, because confirmation *extends* rather than replaces."""
    return max(int(expires_at_ms), int(confirmed_at_ms) + token_grace_ms(poll_interval_ms))


def is_expired(db_state: Optional[str], expires_at_ms: Optional[int], now: int) -> bool:
    return effective_state(db_state, expires_at_ms, now) == LOGICAL_EXPIRED


# ─────────────────────────────────────────────────────────────────────────────
# 3. Credentials: derivation, sealing, comparison
# ─────────────────────────────────────────────────────────────────────────────

#: Namespaced so a future second HMAC consumer of the same session secret cannot
#: accept this plugin's tokens by accident. The separators are newlines because
#: every field is free-form length: a colon or dash could appear inside a scope.
TOKEN_CONTEXT = b"popopx-sso-v1"

#: A seal is self-describing: ``sha256$<key source>$<64 hex>``. The hash is
#: ``sha256(token)``, not the token — the row is readable by anything that can
#: read SQLite, and a 256-bit random-ish hex string that survives the scan
#: window should not be recoverable from it.
SEAL_PREFIX = "sha256"

_KEY_SOURCE_ECO = "eco"
_KEY_SOURCE_H5 = "h5srv"
KEY_SOURCES = (_KEY_SOURCE_ECO, _KEY_SOURCE_H5)

_MIN_FALLBACK_KEY_BYTES = 16


class SsoKeyUnavailable(Exception):
    """No key material to mint with. Raised, never swallowed: a login granted by
    a gateway that improvised a key would be a login nobody can revoke."""

    def __init__(self, detail: str) -> None:
        self.detail = detail
        super().__init__(detail)


def token_preimage(session_id: str, pairwise_uid: str, scope: str) -> bytes:
    """``context ‖ "\\n" ‖ session ‖ "\\n" ‖ pairwise ‖ "\\n" ‖ scope``."""
    return b"\n".join(
        (TOKEN_CONTEXT, session_id.encode("utf-8"), pairwise_uid.encode("utf-8"), scope.encode("utf-8"))
    )


def derive_token(
    key_bytes: bytes,
    session_id: str,
    pairwise_uid: str,
    scope: str = "",
) -> str:
    """The credential itself: lowercase hex HMAC-SHA256, 64 characters.

    Stdlib only, which is the point — this machine has no ``cryptography`` wheel,
    and an HMAC-SHA256 needs none. Different ``(session, pairwise)`` pairs give
    different tokens even with an identical scope, and a different scope changes
    the token, so the scope in the preimage is a binding, not a label.
    """
    if not isinstance(key_bytes, (bytes, bytearray)) or not key_bytes:
        raise SsoKeyUnavailable("empty key material")
    digest = hmac.new(bytes(key_bytes), token_preimage(session_id, pairwise_uid, scope), hashlib.sha256)
    return digest.hexdigest()


def seal_token(token: str, key_source: str = _KEY_SOURCE_ECO) -> str:
    """What goes in ``token_hash``: the one-way image plus the key it came from."""
    if key_source not in KEY_SOURCES:
        raise ValueError("unknown key source %r (known: %s)" % (key_source, list(KEY_SOURCES)))
    image = hashlib.sha256((token or "").encode("utf-8")).hexdigest()
    return "%s$%s$%s" % (SEAL_PREFIX, key_source, image)


def parse_seal(seal: Any) -> Tuple[str, Optional[bytes]]:
    """``("eco", <32 raw digest bytes>)``, or ``("", None)`` for anything unusable."""
    if not isinstance(seal, str):
        return "", None
    parts = seal.split("$")
    if len(parts) == 3:
        algorithm, source, image = parts
        if algorithm == SEAL_PREFIX and source in KEY_SOURCES and len(image) == 64:
            try:
                return source, bytes.fromhex(image)
            except ValueError:
                return "", None
        return "", None
    # A bare hex digest: a row written before the seal was self-describing, or by
    # another build. Accepted as an image with an unknown key source rather than
    # silently failing every verification after a rollback.
    if len(parts) == 1 and len(seal) == 64:
        try:
            return "", bytes.fromhex(seal)
        except ValueError:
            return "", None
    return "", None


#: Compared against when there is nothing to compare with, so a lookup miss and
#: a malformed seal cost the same number of operations as a real check.
_DUMMY_IMAGE = hashlib.sha256(b"popopx-sso-absent-credential").digest()


def token_matches(token: Any, seal: Any) -> bool:
    """Constant-time presentation check. Total: garbage on either side is False.

    The digest of the presented token is compared against the stored image with
    :func:`hmac.compare_digest`, so neither the length of a seal nor where a
    stored image first differs from a guess is observable in wall time.
    """
    presented = hashlib.sha256((token or "").encode("utf-8")).digest() if isinstance(token, str) else _DUMMY_IMAGE
    _source, expected = parse_seal(seal)
    if expected is None:
        expected = _DUMMY_IMAGE
    return hmac.compare_digest(presented, expected)


def resolve_key_material(secret_hex: Optional[str], h5_server_secret: Optional[str]) -> Tuple[bytes, str]:
    """Choose the HMAC key, loudly.

    Preference order is the privacy order: the follower's own pairwise session
    secret first (per person, per service account, revocable with the session),
    ``config.h5_server_secret`` only when that person has no usable session yet.
    The fallback is never silent — the caller records the source in the seal
    (:func:`seal_token`) because ``sso_sessions`` has no ``key_source`` column to
    put it in, and it logs.
    """
    cleaned = ""
    if secret_hex:
        try:
            cleaned = validate_secret_hex(secret_hex)
        except EcoError:
            cleaned = ""
    if cleaned:
        return bytes.fromhex(cleaned), _KEY_SOURCE_ECO
    text = (h5_server_secret or "").strip()
    if len(text.encode("utf-8")) < _MIN_FALLBACK_KEY_BYTES:
        raise SsoKeyUnavailable(
            "this follower has no usable pairwise session secret and POPOPX_H5_SERVER_SECRET is "
            "unset or shorter than %d bytes; refusing to mint a credential" % _MIN_FALLBACK_KEY_BYTES
        )
    return text.encode("utf-8"), _KEY_SOURCE_H5


# ─────────────────────────────────────────────────────────────────────────────
# 4. Request guards
# ─────────────────────────────────────────────────────────────────────────────

#: A mint request is a handful of short strings. Anything bigger is either a
#: mistake or an attempt to make this endpoint expensive to answer.
MAX_BODY_BYTES = 8 * 1024

#: Refuse to mint past this many live sessions. It is a backstop for the
#: per-source window, which is per-process: an attacker who spreads across
#: addresses still hits a global ceiling on rows a poll has not retired.
MAX_LIVE_SESSIONS = 2000

#: Sessions per source per window. Generous for a site whose visitors each mint
#: one, tight enough that a script cannot park thousands of QRs.
MINT_LIMIT_PER_WINDOW = 20
MINT_WINDOW_SECONDS = 60.0


class SsoRequestError(Exception):
    """A 4xx this plugin answers itself, with the shape the route would return.

    Carrying the status and the machine code on the exception keeps every guard
    in the module honest about *which* response it produces, instead of
    inventing a different body per call site.
    """

    def __init__(self, status: int, code: str, detail: str, **extra: object) -> None:
        self.status = int(status)
        self.code = code
        self.detail = detail
        self.extra: Dict[str, object] = dict(extra)
        super().__init__("%s: %s" % (code, detail))

    def as_body(self) -> Dict[str, object]:
        body: Dict[str, object] = {"ok": False, "error": self.code, "detail": self.detail}
        body.update(self.extra)
        return body


#: C0 controls and DEL, mapped to a *space* rather than deleted: a name like
#: "Acme\nServices" that loses the newline reads as one invented word, which is a
#: worse impersonation than a word break in a card field.
_CONTROL_TABLE = {ord(ch): " " for ch in "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x1a\x1b\x1c\x1d\x1e\x1f\x7f"}


def sanitize_text(
    value: Any,
    *,
    field: str,
    limit: int,
    label: str,
    constant: str,
    default: str = "",
) -> str:
    """Trim, strip control characters, and refuse anything the phone would drop.

    Control characters go because ``rp_name`` is *rendered text*: a name
    containing a newline is a user who types a second line into a button label
    and reads 取消 as part of it. Length is checked against the client's own
    ceiling, in characters, and the rejection names both the number and the Swift
    constant so the integrator can fix it without reading this file.
    """
    if value is None:
        text = ""
    elif isinstance(value, str):
        text = value
    elif isinstance(value, (int, float)):
        text = str(value)
    else:
        raise SsoRequestError(400, "invalid_field", "%s must be a string, got %s" % (field, type(value).__name__))
    text = text.translate(_CONTROL_TABLE).strip()
    # Whitespace runs collapse: the card shows this on one line, and the client's
    # single-token rule forbids whitespace in anything a QR carries.
    text = " ".join(text.split())
    if len(text) > limit:
        raise SsoRequestError(
            400,
            "field_too_long",
            "%s is %d characters; the client's limit for %s is %d (PopopxEcoLimits.%s), and a card "
            "over any limit is dropped in the parser rather than truncated — the RP would see a "
            "session that never gets a card"
            % (field, len(text), label, limit, constant),
            field=field,
            limit=limit,
            length=len(text),
        )
    return text if text else default


def validate_rp_uri(value: Any) -> str:
    """The RP's own address: absolute http(s), with a host, and within 2048.

    ``validate_http_url`` is the same predicate the gateway uses for card URLs —
    it rejects ``javascript:``, ``data:``, a bare ``//host`` and a scheme with no
    host — and an SSO initiation endpoint is exactly where that class of input
    shows up, because it is the one field the RP picks freely and the one a
    merchant's console renders.
    """
    if not isinstance(value, str) or not value.strip():
        raise SsoRequestError(400, "invalid_field", "uri is required and must be an absolute http(s) URL")
    try:
        text = validate_http_url(value.strip(), rule="rp_uri")
    except EcoError as exc:
        raise SsoRequestError(400, "invalid_uri", "%s (the client keeps only http(s) URLs; "
                              "PopopxEcoAction.isHttpURL)" % exc.detail) from None
    if len(text) > EcoLimits.url_chars:
        raise SsoRequestError(
            400, "field_too_long",
            "uri is %d characters; the client's URL ceiling is %d (PopopxEcoLimits.maximumURLCharacters)"
            % (len(text), EcoLimits.url_chars), field="uri", limit=EcoLimits.url_chars,
        )
    return text


def origin_of(url: str) -> str:
    """``scheme://host[:port]`` — the only part of the RP's URL this product shows."""
    try:
        parts = urllib.parse.urlsplit(url)
    except ValueError:
        return url[:EcoLimits.field_value_chars]
    if not parts.netloc:
        return url[:EcoLimits.field_value_chars]
    return "%s://%s" % (parts.scheme.lower(), parts.netloc.lower())


# ─────────────────────────────────────────────────────────────────────────────
# 5. The QR payload, and the cards
# ─────────────────────────────────────────────────────────────────────────────

DEEP_LINK_SCHEME = "popopx"
DEEP_LINK_HOST = "sso"

#: Exactly the client's allowlist for a query value: ``alphanumerics ∪ "-._~"``
#: (PopopxH5Launcher.swift:126, applied by ``escape`` at :147-148). ``quote``'s
#: always-safe set is letters, digits and ``_.-~``, so ``safe=""`` reproduces the
#: Swift set character for character — and, unlike the default ``safe="/"`` ,
#: leaves no literal slash inside a value. Escaping *more* than the client does
#: would be safe too; escaping less is what breaks: an unencoded ``&`` inside
#: ``uri=`` ends the value at the phone's query split and the session id is read
#: from the fragment of the remainder, i.e. the scan silently never resolves.
_UNRESERVED = ""


def percent_encode(value: str) -> str:
    """One query value, escaped the way the app escapes its own."""
    return urllib.parse.quote(value, safe=_UNRESERVED)


def build_qr_payload(service_address: str, session_id: str) -> str:
    """``popopx://sso?uri=<invite address>&session=<session id>``.

    Key order is not cosmetic. The client's own hand-written parsers
    (PopopxLocation.swift:128-150 and :210-223, and
    ``PopopxChannelPublicURI.parse`` at PopopxEcoModels.swift:745-760) split the
    query on ``&``, then on the *first* ``=``, then percent-decode once, and drop
    keys they do not know. Putting ``session`` last means that even a value this
    build failed to escape correctly can only ever steal characters from the
    *end* of the last pair — and the total length is checked against the client's
    URL ceiling before a payload is returned, because a QR the phone refuses to
    build ``URLComponents`` for is a login that never happened.
    """
    if not isinstance(session_id, str) or not _SESSION_ID_RE.match(session_id) or not is_single_token(session_id):
        # The id is minted here, so a shape this rejects is a bug in the gateway,
        # not bad input: 500 rather than a 400 that would blame the RP's body.
        raise SsoRequestError(500, "internal", "refusing to emit a QR with a malformed session id")
    address = (service_address or "").strip()
    if not address:
        raise SsoRequestError(
            503,
            "no_service_address",
            "this gateway does not know its own invite address (service_identity.address is empty), "
            "so it cannot build a QR the phone can attribute to a contact; create the service "
            "account first, or pass an explicit \"service_uri\" in the mint request",
        )
    if len(address) > EcoLimits.url_chars:
        raise SsoRequestError(
            400, "field_too_long",
            "service_uri is %d characters; the client's URL ceiling is %d (PopopxEcoLimits.maximumURLCharacters)"
            % (len(address), EcoLimits.url_chars), field="service_uri", limit=EcoLimits.url_chars,
        )
    payload = "%s://%s?uri=%s&session=%s" % (
        DEEP_LINK_SCHEME, DEEP_LINK_HOST, percent_encode(address), percent_encode(session_id),
    )
    if len(payload) > EcoLimits.url_chars:
        raise SsoRequestError(
            400, "field_too_long",
            "the QR payload would be %d characters, over the client's %d-character URL ceiling; "
            "shorten service_uri" % (len(payload), EcoLimits.url_chars),
            field="qr_payload", limit=EcoLimits.url_chars,
        )
    return payload


CARD_STYLE = "security"  # PopopxEcoModels.swift:524-536 accepts standard|receipt|security only

CARD_TITLE_CONFIRM = "确认登录"
CARD_TITLE_GRANTED = "登录已确认"
CARD_TITLE_CANCELLED = "登录已取消"
CARD_TITLE_EXPIRED = "登录请求已过期"
CARD_TITLE_DENIED = "无法完成登录"

#: The outcome a terminal card update renders. Each maps to copy, never to a
#: token, a contact id, or a reason an attacker could probe.
OUTCOME_GRANTED = "granted"
OUTCOME_CANCELLED = "cancelled"
OUTCOME_EXPIRED = "expired"
OUTCOME_FAILED = "failed"
_OUTCOME_TITLES = {
    OUTCOME_GRANTED: CARD_TITLE_GRANTED,
    OUTCOME_CANCELLED: CARD_TITLE_CANCELLED,
    OUTCOME_EXPIRED: CARD_TITLE_EXPIRED,
    OUTCOME_FAILED: CARD_TITLE_DENIED,
}
_OUTCOME_DETAIL = {
    OUTCOME_GRANTED: "已授权",
    OUTCOME_CANCELLED: "已取消",
    OUTCOME_EXPIRED: "已过期",
    OUTCOME_FAILED: "未完成",
}

INBOUND_EXPIRED_TEXT = "这个登录请求已经过期，请在电脑上重新生成二维码。"
INBOUND_OTHER_SCANNER_TEXT = "这个登录请求已由其他账号确认，请在电脑上重新生成二维码。"

DEFAULT_SCOPE = "openid"


def format_confirm_time(now: int) -> str:
    """The third field on the card: when the request arrived, in UTC.

    UTC on purpose. The server's local zone would be a guess the user reads as
    their own, and the scanner's zone is exactly the device metadata this
    product promises not to collect.
    """
    return time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime(int(now) / 1000.0))


def _confirm_actions(session_id: str) -> List[Dict[str, Any]]:
    """The only two ways a human can answer: 确认 and 取消.

    ``confirm=True`` on the grant button because the client's own rule for an
    irreversible authorisation asks first, and because a login the user
    accidentally approved with a thumb is worse than one extra tap. Ids are
    unique within the card (a duplicate id kills the card), kinds are from
    ``crypto_service.ACTION_KINDS``, and both payloads are under 512 characters
    by construction: 12 for the verb, at most 64 for the id.
    """
    return [
        build_action(
            action_id="sso_confirm",
            title="确认登录",
            kind="callback",
            style="primary",
            payload=CB_CONFIRM + session_id,
            confirm=True,
        ),
        build_action(
            action_id="sso_cancel",
            title="取消",
            kind="callback",
            style="destructive",
            payload=CB_CANCEL + session_id,
        ),
    ]


def _terminal_action(session_id: str, outcome: str) -> List[Dict[str, Any]]:
    """One legal inert button, so a stale tap cannot reach ``sso:confirm:``.

    Replacing the array wholesale is what kills the old 确认 button: the client
    only swaps actions when the incoming array is non-empty
    (PopopxEcoRouterAndDeepLink.swift:181-193), so sending an empty list would
    *keep* the live buttons. The button the card does carry is a ``callback``
    whose payload this module treats as a no-op, and the card's ``et`` is at the
    confirming instant, which the client reads as read-only
    (ServiceCardBubbleView.swift:379) — a belt and a pair of braces, because the
    legal way to say "no buttons" here is a button that does nothing.
    """
    return [
        build_action(
            action_id="sso_state",
            title=_OUTCOME_DETAIL.get(outcome, "已完成"),
            kind="callback",
            style="secondary",
            payload=CB_NOOP + session_id,
        )
    ]


def confirm_card(
    session_id: str,
    *,
    rp_name: str,
    rp_origin: str,
    scope: str,
    now: int,
    expires_at_ms: int,
) -> Dict[str, Any]:
    """The scan card, in the client's wire shape and inside every client limit.

    Three fields and nothing else: 登录方 / 授权范围 / 时间. Not device, not IP,
    not "near", not "your iPhone 17", not the contact id — the card is the only
    artefact of this protocol the user can photograph, so it is the place a
    零追踪 claim is either true or visibly false.
    """
    body = (
        "%s 请求以你的服务号身份登录。\n\n"
        "确认后该网站只会收到一个成对标识（每个网站各不相同），不会收到你的手机号、昵称、"
        "通讯录、设备信息或位置。\n\n"
        "不是你本人扫码？点“取消”，并检查这个页面是不是真的属于 %s。"
        % (rp_name or rp_origin, rp_origin)
    )
    fields = [
        {"k": "登录方", "v": (rp_name or rp_origin)[:EcoLimits.field_value_chars]},
        {"k": "授权范围", "v": scope[:EcoLimits.field_value_chars]},
        {"k": "时间", "v": format_confirm_time(now)},
    ]
    return build_card(
        card_id_for(session_id),
        CARD_TITLE_CONFIRM,
        style=CARD_STYLE,
        body=body[:EcoLimits.card_body_chars],
        fields=fields,
        progress={"l": "状态", "p": 0, "d": "等待确认"},
        actions=_confirm_actions(session_id),
        updated_at_ms=now,
        # The card stops being tappable at exactly the instant the server stops
        # honouring the session, so the phone cannot offer a button whose tap
        # will be refused. et must be > 0, which a real deadline always is.
        expires_at_ms=int(expires_at_ms),
    )


def terminal_payload(session_id: str, *, outcome: str, now: int, rp_name: str = "") -> Dict[str, Any]:
    """The keyword arguments for ``eco.update_card`` that closes a card out.

    Deliberately *not* a full card: the update frame carries the fields that
    changed, and building it here keeps the copy and the limits in one place
    whether the close-out comes from a tap, an expiry, or the RP's cancel.
    """
    if outcome not in _OUTCOME_TITLES:
        raise ValueError("unknown outcome %r" % (outcome,))
    detail = _OUTCOME_DETAIL[outcome]
    body = {
        OUTCOME_GRANTED: "已按你的确认向 %s 完成登录。这个凭据只能使用一次。" % (rp_name or "该网站"),
        OUTCOME_CANCELLED: "你没有登录 %s，请求已关闭。" % (rp_name or "该网站"),
        OUTCOME_EXPIRED: "这个登录请求已超时关闭，没有任何信息被发送。",
        OUTCOME_FAILED: "登录未完成：%s 的请求已关闭，请在电脑上重新生成二维码。" % (rp_name or "该网站"),
    }[outcome]
    return {
        "title": _OUTCOME_TITLES[outcome],
        "body": body[:EcoLimits.card_body_chars],
        "fields": [{"k": "状态", "v": detail}],
        "progress": {"l": "状态", "p": 100, "d": detail},
        "actions": _terminal_action(session_id, outcome),
        # A timestamp in the past-or-present is the client's read-only switch.
        "expires_at_ms": int(now),
    }


# ─────────────────────────────────────────────────────────────────────────────
# 6. Rows: every write is a conditional UPDATE, and the row count is the claim
# ─────────────────────────────────────────────────────────────────────────────
#
# Two rules govern this section, both from files this module may not change.
#
# (a) ``Database.execute`` returns ``cursor.lastrowid if cursor.lastrowid else
#     cursor.rowcount`` (app/database.py:590-593). For an ``UPDATE`` with no
#     ``lastrowid`` that means a row count, but for an ``INSERT`` it means a
#     primary key, and for a ``UPDATE`` that matched nothing it means ``0`` — so
#     a claim test written against ``db.execute`` is a test against a value whose
#     type depends on the statement. Every claim here runs on the raw cursor
#     inside ``db.transaction(immediate=True)``, where ``rowcount`` is the answer
#     to the one question that matters: did *this* call move the row out of the
#     state it was read in?
#
# (b) ``BEGIN IMMEDIATE`` is taken before the read, not at the first write, so
#     "read the state, then decide" cannot be interleaved with a second scanner
#     or a second redeem. Without that, the two concurrent requests that both
#     read ``scanned`` would both grant, and a login credential that can be
#     minted twice is not single-use no matter what the documentation says.

_SELECT_COLUMNS = (
    "session_id, state, rp_uri, rp_name, scope, nonce, card_id, contact_id, "
    "pairwise_uid, created_at_ms, scanned_at_ms, confirmed_at_ms, expires_at_ms, token_hash"
)


def new_session_id() -> str:
    """24 URL-safe characters from 18 random bytes.

    Chosen against the client's rules rather than the server's: it satisfies
    ``PopopxEcoUplink.isSendablePayload`` (non-empty, ≤512, no whitespace, no ``::``),
    survives ``percent_encode``
    unchanged, and fits a card id with room to spare. 144 bits is why no
    existence check leaks anything: guessing a session is not a thing.
    """
    return secrets.token_urlsafe(18)


def _row_to_dict(row: Any) -> Dict[str, Any]:
    """``sqlite3.Row`` and plain dicts, without the ``dict(row)`` trap.

    A ``sqlite3.Row`` is *not* a Mapping and does not iterate into pairs, so
    ``dict(row)`` raises; it has to be walked by key name. Getting this wrong is
    a 500 on the first poll after a deploy.
    """
    if row is None:
        return {}
    if isinstance(row, _MappingABC):
        return dict(row)
    keys = getattr(row, "keys", None)
    if callable(keys):
        return {key: row[key] for key in keys()}
    return {}


def service_address_from_db(db: Any) -> str:
    """This account's own invite address — the ``uri=`` a QR must carry.

    Empty means the service account has not been created yet, which is a
    deployment state, not a request error: the caller answers 503 with the column
    name in it.
    """
    try:
        row = db.query_one("SELECT address FROM service_identity WHERE id = 1")
    except Exception as exc:  # no such table on a half-migrated database
        logger.warning("sso: service_identity unreadable (%s)", exc)
        return ""
    value = row["address"] if row is not None else ""
    return (value or "").strip() if isinstance(value, str) else ""


def insert_session(
    db: Any,
    *,
    session_id: str,
    rp_uri: str,
    rp_name: str,
    scope: str,
    nonce: str,
    created_at_ms: int,
    expires_at_ms: int,
) -> None:
    """One ``pending`` row, and the only thing written about the request.

    There is no ``source`` column to abuse and none is invented: no IP, no
    user agent, no browser fingerprint. ``nonce`` is stored because the RP needs
    its own anti-CSRF value echoed nowhere — it keeps its own session↔nonce map —
    but keeping it costs a column that already exists and lets an operator match
    a support ticket to a row without asking the RP for database access.
    """
    with db.transaction(immediate=True) as conn:
        conn.execute(
            "INSERT INTO sso_sessions (session_id, state, rp_uri, rp_name, scope, nonce, "
            "created_at_ms, expires_at_ms) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (session_id, DB_PENDING, rp_uri, rp_name, scope, nonce or None, int(created_at_ms), int(expires_at_ms)),
        )


def load_session(db: Any, session_id: str) -> Optional[Dict[str, Any]]:
    row = db.query_one("SELECT %s FROM sso_sessions WHERE session_id = ?" % _SELECT_COLUMNS, (session_id,))
    return _row_to_dict(row) if row is not None else None


def persist_expiry(db: Any, session_id: str, now: int) -> bool:
    """Land the computed truth in the column, once.

    Conditional on the state still being open, so a row that was confirmed
    between the read and this write is not stolen by an expiry that no longer
    applies to it. Returns whether the row moved.
    """
    with db.transaction(immediate=True) as conn:
        cursor = conn.execute(
            "UPDATE sso_sessions SET state = ? "
            "WHERE session_id = ? AND state IN (?, ?, ?) AND expires_at_ms <= ?",
            (DB_EXPIRED, session_id, DB_PENDING, DB_SCANNED, DB_APPROVED, int(now)),
        )
        return cursor.rowcount == 1


def live_session_count(db: Any, now: int) -> int:
    """Un-retired sessions right now, the global mint backstop."""
    value = db.scalar(
        "SELECT COUNT(*) FROM sso_sessions WHERE state IN (?, ?, ?) AND expires_at_ms > ?",
        (DB_PENDING, DB_SCANNED, DB_APPROVED, int(now)),
        default=0,
    )
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


def pairwise_uid_from_db(db: Any, contact_id: int) -> str:
    """The stored pairwise id for a follower, when the live session is absent."""
    try:
        row = db.query_one("SELECT pairwise_uid FROM contacts WHERE contact_id = ?", (int(contact_id),))
    except Exception:
        return ""
    value = row["pairwise_uid"] if row is not None else ""
    return value.strip() if isinstance(value, str) else ""


def claim_scan(
    db: Any, session_id: str, contact_id: int, card_id: str, now: int
) -> Tuple[bool, str, Dict[str, Any]]:
    """Bind a session to the follower who scanned it. ``(ok, reason, row)``.

    The first scanner wins, permanently: a session re-scannable by a second
    contact would be a QR photographed in a meeting room and approved by someone
    else's phone. A re-scan *by the same contact* is allowed and answered as a
    replay, because the delivery that failed the first time is the retry the user
    is about to attempt.
    """
    with db.transaction(immediate=True) as conn:
        row = _row_to_dict(conn.execute(
            "SELECT %s FROM sso_sessions WHERE session_id = ?" % _SELECT_COLUMNS, (session_id,)
        ).fetchone())
        if not row:
            return False, "unknown_session", {}
        state = row.get("state")
        deadline = row.get("expires_at_ms")
        if effective_state(state, deadline, now) == LOGICAL_EXPIRED:
            conn.execute(
                "UPDATE sso_sessions SET state = ? "
                "WHERE session_id = ? AND state IN (?, ?, ?) AND expires_at_ms <= ?",
                (DB_EXPIRED, session_id, DB_PENDING, DB_SCANNED, DB_APPROVED, int(now)),
            )
            row["state"] = DB_EXPIRED
            return False, "expired", row
        if state == DB_PENDING:
            cursor = conn.execute(
                "UPDATE sso_sessions SET state = ?, contact_id = ?, card_id = ?, scanned_at_ms = ? "
                "WHERE session_id = ? AND state = ?",
                (DB_SCANNED, int(contact_id), card_id, int(now), session_id, DB_PENDING),
            )
            if cursor.rowcount != 1:
                return False, "raced", row
            row.update({"state": DB_SCANNED, "contact_id": int(contact_id),
                        "card_id": card_id, "scanned_at_ms": int(now)})
            return True, "scanned", row
        if state == DB_SCANNED:
            if int(row.get("contact_id") or 0) != int(contact_id):
                return False, "other_contact", row
            return True, "replay", row
        return False, "not_scannable", row


def revert_scan(db: Any, session_id: str, contact_id: int, now: int) -> bool:
    """Give a card that never reached a phone back to the pool.

    Only for the contact the binding belongs to, and only while the row is still
    ``scanned``: making the delivery failure un-retryable would punish the user
    for the node's bad minute.
    """
    with db.transaction(immediate=True) as conn:
        cursor = conn.execute(
            "UPDATE sso_sessions SET state = ?, contact_id = NULL, card_id = NULL, scanned_at_ms = NULL "
            "WHERE session_id = ? AND state = ? AND contact_id = ?",
            (DB_PENDING, session_id, DB_SCANNED, int(contact_id)),
        )
        return cursor.rowcount == 1


def grant_session(
    db: Any,
    session_id: str,
    *,
    contact_id: int,
    pairwise_uid: str,
    seal: str,
    now: int,
    deadline_ms: int,
) -> Tuple[bool, str, Dict[str, Any]]:
    """``scanned → confirmed``, with the credential, in one statement.

    ``deadline_ms`` is the extended expiry from :func:`confirmed_deadline`:
    confirmation moves the deadline rather than clearing it, so an approved row
    that nobody redeems still dies on its own, and no sweeper exists.
    ``already_granted`` is success without a new credential: the same token the
    first tap produced is the one the RP holds, and re-minting here would mean a
    double-tap invalidates the credential the browser is carrying.
    """
    with db.transaction(immediate=True) as conn:
        row = _row_to_dict(conn.execute(
            "SELECT %s FROM sso_sessions WHERE session_id = ?" % _SELECT_COLUMNS, (session_id,)
        ).fetchone())
        if not row:
            return False, "unknown_session", {}
        state = row.get("state")
        if effective_state(state, row.get("expires_at_ms"), now) == LOGICAL_EXPIRED:
            conn.execute(
                "UPDATE sso_sessions SET state = ? "
                "WHERE session_id = ? AND state IN (?, ?, ?) AND expires_at_ms <= ?",
                (DB_EXPIRED, session_id, DB_PENDING, DB_SCANNED, DB_APPROVED, int(now)),
            )
            row["state"] = DB_EXPIRED
            return False, "expired", row
        if state == DB_APPROVED:
            return True, "already_granted", row
        if state == DB_CONSUMED:
            return False, "already_delivered", row
        if state == DB_DENIED:
            return False, "cancelled", row
        if state == DB_PENDING:
            return False, "pending_scan", row
        if int(row.get("contact_id") or 0) != int(contact_id):
            return False, "other_contact", row
        cursor = conn.execute(
            "UPDATE sso_sessions SET state = ?, pairwise_uid = ?, token_hash = ?, "
            "confirmed_at_ms = ?, expires_at_ms = ? "
            "WHERE session_id = ? AND state = ? AND contact_id = ?",
            (DB_APPROVED, pairwise_uid, seal, int(now), int(deadline_ms), session_id, DB_SCANNED, int(contact_id)),
        )
        if cursor.rowcount != 1:
            return False, "raced", row
        row.update({"state": DB_APPROVED, "pairwise_uid": pairwise_uid, "token_hash": seal,
                    "confirmed_at_ms": int(now), "expires_at_ms": int(deadline_ms)})
        return True, "granted", row


def refuse_session(
    db: Any, session_id: str, *, contact_id: Optional[int] = None, now: int
) -> Tuple[bool, str, Dict[str, Any]]:
    """``cancelled``, from the card's 取消 button or from the RP's cancel route.

    An unredeemed credential *is* revocable and the seal is nulled when it is:
    the RP that cancels must not be left with a token that still works after the
    user said no. A redeemed one is not: the login already happened, and the
    answer to that is a logout at the RP, not a DELETE at the gateway.
    """
    with db.transaction(immediate=True) as conn:
        row = _row_to_dict(conn.execute(
            "SELECT %s FROM sso_sessions WHERE session_id = ?" % _SELECT_COLUMNS, (session_id,)
        ).fetchone())
        if not row:
            return False, "unknown_session", {}
        state = row.get("state")
        if contact_id is not None and state in (DB_SCANNED, DB_APPROVED, DB_CONSUMED):
            if int(row.get("contact_id") or 0) != int(contact_id):
                return False, "other_contact", row
        if state == DB_DENIED:
            return True, "already_cancelled", row
        if effective_state(state, row.get("expires_at_ms"), now) == LOGICAL_EXPIRED:
            conn.execute(
                "UPDATE sso_sessions SET state = ? "
                "WHERE session_id = ? AND state IN (?, ?, ?) AND expires_at_ms <= ?",
                (DB_EXPIRED, session_id, DB_PENDING, DB_SCANNED, DB_APPROVED, int(now)),
            )
            row["state"] = DB_EXPIRED
            return True, "already_expired", row
        if state == DB_CONSUMED:
            return False, "already_delivered", row
        if state == DB_APPROVED:
            cursor = conn.execute(
                "UPDATE sso_sessions SET state = ?, token_hash = NULL, confirmed_at_ms = ? "
                "WHERE session_id = ? AND state = ?",
                (DB_DENIED, int(now), session_id, DB_APPROVED),
            )
            if cursor.rowcount != 1:
                return False, "raced", row
            row.update({"state": DB_DENIED, "token_hash": None})
            return True, "revoked", row
        if state in (DB_PENDING, DB_SCANNED):
            cursor = conn.execute(
                "UPDATE sso_sessions SET state = ?, confirmed_at_ms = ? "
                "WHERE session_id = ? AND state = ?",
                (DB_DENIED, int(now), session_id, state),
            )
            if cursor.rowcount != 1:
                return False, "raced", row
            row.update({"state": DB_DENIED})
            return True, "cancelled", row
        return False, "not_cancellable", row


def revoke_grant(db: Any, session_id: str, now: int) -> bool:
    """Undo a grant whose billing failed. See :func:`handle_inbound`."""
    with db.transaction(immediate=True) as conn:
        cursor = conn.execute(
            "UPDATE sso_sessions SET state = ?, token_hash = NULL, confirmed_at_ms = ? "
            "WHERE session_id = ? AND state = ?",
            (DB_DENIED, int(now), session_id, DB_APPROVED),
        )
        return cursor.rowcount == 1


def redeem_session(
    db: Any, session_id: str, token: Any, now: int
) -> Tuple[bool, str, Dict[str, Any]]:
    """``confirmed → delivered``, and the credential dies in the same statement.

    This is the whole single-use rule in one transaction:

    * the token is hashed and compared with ``hmac.compare_digest`` before the
      row is touched, and a mismatch changes nothing at all;
    * the write is conditional on ``state = 'approved'``, so two redeemations
      that arrive together cannot both return a ``pairwise_uid`` — one gets
      ``rowcount == 1``, the other gets ``0`` and the answer
      ``already_delivered``;
    * ``token_hash`` is set to NULL on the way out, so even a database dump taken
      tomorrow, or a bug that let a second compare through, has nothing to
      verify against;
    * a session id that does not exist still performs a full constant-time
      comparison against a fixed dummy digest, so "no such session" and "wrong
      token" take the same number of operations to refuse.

    On success the returned dict carries exactly the two fields the RP is
    allowed to learn.
    """
    with db.transaction(immediate=True) as conn:
        row = _row_to_dict(conn.execute(
            "SELECT %s FROM sso_sessions WHERE session_id = ?" % _SELECT_COLUMNS, (session_id,)
        ).fetchone())
        if not row:
            token_matches(token, _DUMMY_SEAL)          # the equal-cost refusal
            return False, REASON_UNKNOWN_SESSION, {}
        state = row.get("state")
        deadline = row.get("expires_at_ms")
        current = effective_state(state, deadline, now)
        if current == LOGICAL_EXPIRED:
            conn.execute(
                "UPDATE sso_sessions SET state = ? "
                "WHERE session_id = ? AND state IN (?, ?, ?) AND expires_at_ms <= ?",
                (DB_EXPIRED, session_id, DB_PENDING, DB_SCANNED, DB_APPROVED, int(now)),
            )
            token_matches(token, row.get("token_hash"))
            return False, REASON_EXPIRED, {}
        if current == LOGICAL_CANCELLED:
            token_matches(token, row.get("token_hash"))
            return False, REASON_CANCELLED, {}
        if current in (LOGICAL_PENDING, LOGICAL_SCANNED):
            # No credential exists yet; a guess cannot create one. Compared
            # against the row's own (null) seal so the timing stays flat.
            token_matches(token, row.get("token_hash"))
            return False, REASON_PENDING_SCAN, {}
        if current == LOGICAL_DELIVERED:
            token_matches(token, row.get("token_hash"))
            return False, REASON_ALREADY_DELIVERED, {}
        if not token_matches(token, row.get("token_hash")):
            return False, REASON_BAD_TOKEN, {}
        cursor = conn.execute(
            "UPDATE sso_sessions SET state = ?, token_hash = NULL WHERE session_id = ? AND state = ?",
            (DB_CONSUMED, session_id, DB_APPROVED),
        )
        if cursor.rowcount != 1:
            return False, REASON_ALREADY_DELIVERED, {}
        granted = {
            "pairwise_uid": row.get("pairwise_uid") or "",
            "scope": row.get("scope") or "",
            "session_id": session_id,
            "rp_name": row.get("rp_name") or "",
        }
        return True, "delivered", granted


def audit_rows(db: Any, limit: int, now: int) -> List[Dict[str, Any]]:
    """The operator's list: state, who asked, what for, which pseudonym.

    Never ``token_hash`` (it is a credential's image, not an audit fact) and
    never the RP's query string — ``rp_uri`` is projected to its origin here
    because an audit list is a screen somebody photographs, and an RP's
    ``?state=`` or ``?redirect_to=`` value is a live token in most frameworks.
    """
    rows = db.query(
        "SELECT %s FROM sso_sessions ORDER BY created_at_ms DESC LIMIT ?" % _SELECT_COLUMNS,
        (int(limit),),
    )
    out: List[Dict[str, Any]] = []
    for raw in rows:
        item = _row_to_dict(raw)
        out.append({
            "session_id": item.get("session_id"),
            "state": effective_state(item.get("state"), item.get("expires_at_ms"), now),
            "stored_state": item.get("state"),
            "rp_name": item.get("rp_name") or "",
            "rp_origin": origin_of(item.get("rp_uri") or ""),
            "scope": item.get("scope") or "",
            "pairwise_uid": item.get("pairwise_uid") or "",
            "created_at_ms": item.get("created_at_ms"),
            "scanned_at_ms": item.get("scanned_at_ms"),
            "confirmed_at_ms": item.get("confirmed_at_ms"),
            "expires_at_ms": item.get("expires_at_ms"),
        })
    return out


# ─────────────────────────────────────────────────────────────────────────────
# 7. The verification answer: one shape, one status, six reasons
# ─────────────────────────────────────────────────────────────────────────────

REASON_UNKNOWN_SESSION = "unknown_session"
REASON_EXPIRED = "expired"
REASON_CANCELLED = "cancelled"
REASON_PENDING_SCAN = "pending_scan"
REASON_BAD_TOKEN = "bad_token"
REASON_ALREADY_DELIVERED = "already_delivered"

#: The complete answer set for a failed ``POST /verify``. Deliberately all 403:
#: a ``404`` for "no such session" and a ``410`` for "expired" would be a free
#: oracle on which QRs exist, and the reason codes already distinguish them for
#: the RP that is holding the id and therefore already knows.
VERIFY_FAILURE_STATUS = 403
VERIFY_REASON_CODES: Tuple[str, ...] = (
    REASON_UNKNOWN_SESSION,
    REASON_EXPIRED,
    REASON_CANCELLED,
    REASON_PENDING_SCAN,
    REASON_BAD_TOKEN,
    REASON_ALREADY_DELIVERED,
)

#: The complete key set of a refused redemption, sorted the way a comparison of
#: shapes sorts it. Getting this order wrong is precisely the bug the check below
#: catches, so it is stated once and used by both.
_DETAIL_KEYS = ("detail", "ok", "reason")

#: Human-facing, non-enumerating: none of these say *why* in a way that could
#: help an attacker tell a live session from a retired one they cannot see.
_VERIFY_DETAILS: Dict[str, str] = {
    REASON_UNKNOWN_SESSION: "no such login request",
    REASON_EXPIRED: "this login request is closed",
    REASON_CANCELLED: "this login request was refused",
    REASON_PENDING_SCAN: "this login request has not been approved",
    REASON_BAD_TOKEN: "this credential is not valid",
    REASON_ALREADY_DELIVERED: "this credential has already been used",
}

#: A seal that can never match a presentation, used where there is nothing real
#: to compare against. Two segments so :func:`parse_seal` reads it as the
#: unknown-source form rather than as garbage.
_DUMMY_SEAL = "%s$%s$%s" % (SEAL_PREFIX, _KEY_SOURCE_ECO, _DUMMY_IMAGE.hex())


def verify_failure(reason: str) -> Dict[str, object]:
    """The body a refused redemption returns, for every reason, identically.

    Pure and total: an unknown reason still produces the same three keys, so the
    route cannot answer with a shape the RP's parser has never seen.
    """
    if reason not in _VERIFY_DETAILS:
        reason = REASON_BAD_TOKEN
    return {"ok": False, "reason": reason, "detail": _VERIFY_DETAILS[reason]}


def verify_success(pairwise_uid: str, scope: str) -> Dict[str, object]:
    """What a redeemed credential buys the RP: a pseudonym and a scope.

    Not a name, not an avatar, not a phone number, not a contact id, not the
    session's token. ``sub`` is the pairwise uid because that is the only stable
    subject this product is willing to hand out, and it is already a per-RP
    pseudonym: two RPs that both log the same person in see two different values
    and cannot tell they are one person.
    """
    return {"ok": True, "pairwise_uid": pairwise_uid, "scope": scope}


def failure_body_has_one_shape() -> bool:
    """Used by :func:`self_test`; also the invariant a reviewer should re-check."""
    shapes = {tuple(sorted(verify_failure(code).keys())) for code in VERIFY_REASON_CODES}
    return shapes == {_DETAIL_KEYS}


# ─────────────────────────────────────────────────────────────────────────────
# 8. The mint throttle
# ─────────────────────────────────────────────────────────────────────────────


class _MintWindow:
    """A sliding window keyed by a per-process salt, and nothing else.

    Why this is in memory and not in the database: ``sso_sessions`` has no
    column that could hold a source identifier, and inventing one — or writing a
    source hash into ``settings`` — would be exactly the tracking the product
    promise forbids, in a table that outlives the process. A per-process window
    is a genuine trade: it stops one address minting 20 QRs a second, and it
    resets on a restart, which is why :func:`live_session_count` also exists as a
    durable global ceiling that a restart cannot lift.

    The key is ``HMAC(random salt, source)``, so a memory dump gives no usable
    address list, the same address looks different after a restart, and nothing
    that is kept can be joined to a session row.
    """

    def __init__(self, limit: int = MINT_LIMIT_PER_WINDOW, window_seconds: float = MINT_WINDOW_SECONDS) -> None:
        self.limit = int(limit)
        self.window_seconds = float(window_seconds)
        self._hits: Dict[str, deque] = {}
        self._lock = threading.Lock()
        self._salt = secrets.token_bytes(16)

    def source_key(self, source: str) -> str:
        return hmac.new(self._salt, (source or "").encode("utf-8"), hashlib.sha256).hexdigest()[:32]

    def allow(self, key: str, now: float) -> bool:
        with self._lock:
            window = self._hits.get(key)
            if window is None:
                window = deque()
                self._hits[key] = window
            cutoff = float(now) - self.window_seconds
            while window and window[0] <= cutoff:
                window.popleft()
            if len(window) >= self.limit:
                return False
            window.append(float(now))
            self._sweep_locked(float(now))
            return True

    def retry_after_seconds(self, key: str, now: float) -> int:
        with self._lock:
            window = self._hits.get(key)
            if not window:
                return 0
            oldest = window[0]
            remaining = self.window_seconds - (float(now) - float(oldest))
            return int(remaining) + 1 if remaining > 0 else 0

    def _sweep_locked(self, now: float) -> None:
        """Keep the table from growing without bound on a wide source space."""
        if len(self._hits) <= 4096:
            return
        cutoff = now - self.window_seconds
        for key in [k for k, v in self._hits.items() if not v or v[-1] <= cutoff]:
            self._hits.pop(key, None)


_MINTS = _MintWindow()


def extract_source(request: Any) -> str:
    """The client's address, used *only* as a throttle key.

    ``X-Forwarded-For``'s first hop is what a reverse proxy put there, which is
    the address that actually held the browser; ``request.client.host`` is the
    fallback for a direct mount. The value never leaves this function: it is not
    stored, not logged, and not returned to a caller.
    """
    forwarded = ""
    headers = getattr(request, "headers", None)
    if headers is not None:
        try:
            forwarded = headers.get("x-forwarded-for") or ""
        except Exception:
            forwarded = ""
    if forwarded:
        first = forwarded.split(",")[0].strip()
        if first:
            return first
    client = getattr(request, "client", None)
    host = getattr(client, "host", None) if client is not None else None
    return (host or "").strip() or "unknown"


def bearer_secret(request: Any) -> str:
    """The ``Authorization: Bearer …`` value, or ``""``."""
    headers = getattr(request, "headers", None)
    raw = ""
    if headers is not None:
        try:
            raw = headers.get("authorization") or ""
        except Exception:
            raw = ""
    text = raw.strip()
    prefix = "bearer "
    if text[:len(prefix)].lower() == prefix:
        return text[len(prefix):].strip()
    return ""


def secret_matches(presented: str, expected: str) -> bool:
    """Constant-time secret check that refuses an unset expectation.

    Comparing against an empty ``admin_token`` would be a *successful* empty
    comparison in some frameworks; it is treated as "not configured" here and by
    the caller as a 503, so no deployment can be authenticated by guessing
    nothing.
    """
    if not expected:
        return False
    return hmac.compare_digest(
        (presented or "").encode("utf-8"), expected.encode("utf-8")
    )


# ─────────────────────────────────────────────────────────────────────────────
# 9. The request-side logic, apart from HTTP
# ─────────────────────────────────────────────────────────────────────────────
#
# Split out for the same reason the frame builders are split out: the interesting
# decisions (what a mint may say, what a poll may reveal, which 4xx names which
# limit) are pure enough to test without a wheel installed, and a route body that
# only marshals JSON cannot get them wrong twice.


def mint_session(
    deps: "PluginDeps",
    body: Mapping[str, Any],
    source: str,
    *,
    now: Optional[int] = None,
) -> Dict[str, Any]:
    """Validate, throttle, and create one ``pending`` session.

    Not billed: nothing has happened yet, and a QR that was never scanned is not
    a login. The meter is charged on the user's approval, which is the event the
    merchant is actually selling.
    """
    stamp = int(now if now is not None else now_ms())
    if not isinstance(body, Mapping):
        raise SsoRequestError(400, "invalid_json", "the body must be a JSON object")

    rp_uri = validate_rp_uri(body.get("uri"))
    rp_origin = origin_of(rp_uri)
    rp_name = sanitize_text(
        body.get("name"), field="name", limit=EcoLimits.field_value_chars,
        label="a field value", constant="maximumValueCharacters", default=rp_origin,
    )
    scope = sanitize_text(
        body.get("scope"), field="scope", limit=EcoLimits.field_value_chars,
        label="a field value", constant="maximumValueCharacters", default=DEFAULT_SCOPE,
    )
    nonce = sanitize_text(
        body.get("nonce"), field="nonce", limit=EcoLimits.payload_chars,
        label="an action payload", constant="maximumPayloadCharacters",
    )
    ttl = int(getattr(deps.config, "sso_ttl_seconds", 180) or 180)

    # The QR's ``uri=`` is the service account's own invite address (see the
    # module docstring), so the RP may name it explicitly and the deployment's
    # ``service_identity.address`` is otherwise the authority for it.
    explicit = sanitize_text(
        body.get("service_uri"), field="service_uri", limit=EcoLimits.url_chars,
        label="a URL", constant="maximumURLCharacters",
    )
    address = explicit or service_address_from_db(deps.db)
    session_id = new_session_id()
    qr_payload = build_qr_payload(address, session_id)

    key = _MINTS.source_key(source)
    if not _MINTS.allow(key, stamp / 1000.0):
        retry = _MINTS.retry_after_seconds(key, stamp / 1000.0)
        raise SsoRequestError(
            429, "rate_limited",
            "at most %d login requests per %d seconds from one address; retry in %ds"
            % (_MINTS.limit, int(_MINTS.window_seconds), retry),
            retry_after=retry,
        )
    live = live_session_count(deps.db, stamp)
    if live >= MAX_LIVE_SESSIONS:
        raise SsoRequestError(
            429, "too_many_live_sessions",
            "%d login requests are already open on this gateway; poll or cancel them before "
            "minting more" % live, retry_after=5,
        )

    expires_at_ms = expiry_deadline(stamp, ttl)
    insert_session(
        deps.db,
        session_id=session_id,
        rp_uri=rp_uri,
        rp_name=rp_name,
        scope=scope,
        nonce=nonce,
        created_at_ms=stamp,
        expires_at_ms=expires_at_ms,
    )
    # INFO logs the origin, never the full URI: an RP's query string is a token.
    logger.info("sso: minted sid=%s rp=%s scope=%s ttl=%ds", session_id[:6], rp_origin, scope, ttl)
    return {
        "ok": True,
        "session_id": session_id,
        "qr_payload": qr_payload,
        "state": LOGICAL_PENDING,
        "created_at_ms": stamp,
        "expires_at_ms": expires_at_ms,
        "ttl_seconds": ttl,
        "poll_interval_ms": int(getattr(deps.config, "sso_poll_interval_ms", 2000) or 2000),
        "poll_url": "/api/v1/plugins/sso/sessions/%s" % session_id,
        "callback_kind": "sso_scan",
    }


def _release_credential(deps: "PluginDeps", row: Mapping[str, Any]) -> str:
    """Re-derive the assertion for a confirmed row, for an authenticated poller.

    Why this is possible and why it is not a secret kept twice: the token is a
    *deterministic* function of (key, session id, pairwise uid, scope), and the
    key lives only in the gateway — in the follower's pairwise session secret, or
    in ``config.h5_server_secret``. Nothing about the token needs to be stored to
    hand it out again, and the seal in the row says which of the two keys it was
    minted with, so a re-derivation cannot silently switch key source and produce
    a token the row will not accept.

    What makes it single-use is not obscurity: it is the ``confirmed → delivered``
    transition inside :func:`redeem_session`, which is why this function refuses a
    row that is not in ``confirmed``, and why a redeemed session can never be
    handed out again by any route.

    The channel is the question this answers. An unauthenticated poll carries the
    state only, because a QR is a picture on a screen and anyone can photograph
    it; the credential travels only to a caller that presents the merchant's own
    bearer secret, which is the RP that is entitled to learn it.
    """
    if str(row.get("state")) != DB_APPROVED:
        # `confirmed` in the wire vocabulary and nothing else: a row that has
        # been redeemed, refused or expired has no credential to release,
        # whatever its deadline arithmetic says.
        return ""
    contact_id = int(row.get("contact_id") or 0)
    pairwise_uid = str(row.get("pairwise_uid") or "")
    session_id = str(row.get("session_id") or "")
    scope = str(row.get("scope") or DEFAULT_SCOPE)
    if not contact_id or not pairwise_uid or not session_id:
        return ""
    _source, _image = parse_seal(row.get("token_hash"))
    secret_hex = ""
    if _source != _KEY_SOURCE_H5:
        try:
            session = deps.eco.session_for(contact_id)
        except Exception as exc:
            logger.warning("sso: session_for(%d) raised during credential release (%s)", contact_id, exc)
            session = None
        if session is not None and not bool(getattr(session, "revoked", False)):
            secret_hex = str(getattr(session, "secret_hex", "") or "")
    try:
        key_bytes, key_source = resolve_key_material(secret_hex, str(getattr(deps.config, "h5_server_secret", "") or ""))
    except SsoKeyUnavailable as exc:
        logger.error("sso: credential for sid=%s cannot be released: %s", session_id[:6], exc.detail)
        return ""
    if _source and _source != key_source:
        # The row says the grant used a key this call cannot reproduce (a
        # rotated session secret, most likely). Refuse rather than mint a
        # second, different assertion for the same login.
        logger.error("sso: credential for sid=%s was minted with key %s, now unavailable",
                     session_id[:6], _source)
        return ""
    return derive_token(key_bytes, session_id, pairwise_uid, scope)


def poll_session(
    deps: "PluginDeps", session_id: str, *, now: Optional[int] = None, authorized: bool = False
) -> Dict[str, Any]:
    """The browser's answer: state and deadline, and no identity, ever.

    An unauthenticated endpoint that returned a pseudonym would be a login oracle
    for anyone who could read a QR over a shoulder. ``authorized`` (a correct
    bearer secret, checked by the route) additionally earns the *credential*,
    which is the one thing the RP's own server needs and the one thing a
    photograph of a QR must not buy.
    """
    stamp = int(now if now is not None else now_ms())
    row = load_session(deps.db, session_id)
    if row is None:
        raise SsoRequestError(404, "unknown_session", "no such login request")
    state = effective_state(row.get("state"), row.get("expires_at_ms"), stamp)
    if state == LOGICAL_EXPIRED and row.get("state") != DB_EXPIRED:
        persist_expiry(deps.db, session_id, stamp)
    answer: Dict[str, Any] = {
        "ok": True,
        "session_id": session_id,
        "state": state,
        "expires_at_ms": row.get("expires_at_ms"),
        "poll_interval_ms": int(getattr(deps.config, "sso_poll_interval_ms", 2000) or 2000),
        "scanned": state in (LOGICAL_SCANNED, LOGICAL_CONFIRMED, LOGICAL_DELIVERED),
        "approved": state in (LOGICAL_CONFIRMED, LOGICAL_DELIVERED),
    }
    if authorized and state == LOGICAL_CONFIRMED:
        token = _release_credential(deps, row)
        if token:
            answer["token"] = token
    return answer


def cancel_session(deps: "PluginDeps", session_id: str, *, now: Optional[int] = None) -> Dict[str, Any]:
    """The RP's own cancel: the browser's 取消 button, server-side.

    Cancelling a credential the RP has not yet redeemed is a revocation and is
    allowed; cancelling one it already redeemed is not a thing this gateway can
    undo, and says so instead of pretending.
    """
    stamp = int(now if now is not None else now_ms())
    ok, reason, row = refuse_session(deps.db, session_id, contact_id=None, now=stamp)
    if not ok:
        status = 404 if reason == "unknown_session" else 409
        raise SsoRequestError(
            status,
            "not_cancellable" if reason not in ("unknown_session",) else reason,
            "this login request cannot be cancelled (%s)" % reason,
            state=logical_state(row.get("state")) if row else "",
        )
    logger.info("sso: cancelled sid=%s by rp (%s)", session_id[:6], reason)
    return {
        "ok": True,
        "session_id": session_id,
        "state": LOGICAL_CANCELLED,
        # ``revoked`` distinguishes "the credential that existed is now dead"
        # from "nothing had been approved yet" — the RP needs to know whether the
        # user's approval was already in flight when the cancel landed.
        "revoked": reason == "revoked",
        "previous": reason,
    }


# ─────────────────────────────────────────────────────────────────────────────
# 10. The router
# ─────────────────────────────────────────────────────────────────────────────
#
# ``POST /sessions``    RP server → mint a login request, get the QR payload.
# ``GET  /sessions/{id}`` browser → poll state. Unauthenticated, reveals nothing.
# ``POST /sessions/{id}/cancel`` RP server → give up (and revoke an unredeemed
# credential).
# ``POST /verify``      RP server → redeem the credential the browser relayed.
# ``GET  /audit``       operator → recent sessions, pseudonyms only.
#
# Every body starts with ``deps.require()``, so a switched-off plugin answers 404
# and a fused one 402 before a single row is read — and before either endpoint
# costs the account anything.

_ROUTE_DOC_MINT = "Mint a passwordless login request and return its QR payload."
_ROUTE_DOC_POLL = "Poll one login request for state. Never returns an identity."
_ROUTE_DOC_CANCEL = "Cancel a login request; revokes a credential not yet redeemed."
_ROUTE_DOC_VERIFY = "Redeem a one-time credential for a pairwise uid and a scope."
_ROUTE_DOC_AUDIT = "Recent login requests, for the merchant's own review."


def create_router(deps: "PluginDeps") -> "APIRouter":
    """Build this plugin's routes. Imports ``fastapi`` here, never at module scope.

    One consequence of the no-wheel-at-import rule has to be handled
    explicitly: with ``from __future__ import annotations`` every annotation in
    this file is a *string*, and FastAPI resolves a path operation's parameter
    annotations against the defining function's ``__globals__``
    (``fastapi.routing.get_typed_signature``). A nested route annotated
    ``request: Request`` therefore needs the name ``Request`` to exist in this
    module's namespace at decoration time, even though the import itself stays
    inside the function. Publishing it is the smallest honest fix; the
    alternative — dropping the ``Request`` parameter and reading client
    addresses and headers out of the body — would mean trusting request data to
    describe where the request came from, which is precisely what a throttle must
    not do.
    """
    from fastapi import APIRouter, Request
    from fastapi.responses import JSONResponse

    namespace = globals()
    namespace["Request"] = Request
    namespace["JSONResponse"] = JSONResponse

    router = APIRouter()

    def reply(payload: Dict[str, Any], status: int = 200) -> Any:
        return JSONResponse(status_code=int(status), content=payload)

    def refused(exc: SsoRequestError) -> Any:
        headers: Dict[str, str] = {}
        retry_after = exc.extra.get("retry_after")
        if isinstance(retry_after, int) and retry_after > 0:
            headers["Retry-After"] = str(retry_after)
        return JSONResponse(status_code=exc.status, content=exc.as_body(), headers=headers)

    async def json_body(request: "Request") -> Dict[str, Any]:
        """Read a bounded JSON object, or raise the 4xx that says why not."""
        raw = await request.body()
        if len(raw) > MAX_BODY_BYTES:
            raise SsoRequestError(
                413, "body_too_large",
                "a mint request is a handful of short strings; %d bytes is not one (limit %d)"
                % (len(raw), MAX_BODY_BYTES),
            )
        if not raw:
            return {}
        try:
            parsed = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, ValueError) as exc:
            raise SsoRequestError(400, "invalid_json", "body is not UTF-8 JSON: %s" % exc) from None
        if not isinstance(parsed, dict):
            raise SsoRequestError(400, "invalid_json", "the body must be a JSON object")
        return parsed

    @router.post("/sessions", summary=_ROUTE_DOC_MINT)
    async def post_sessions(request: "Request") -> Any:
        deps.require()
        try:
            body = await json_body(request)
            return reply(mint_session(deps, body, extract_source(request)))
        except SsoRequestError as exc:
            return refused(exc)

    @router.get("/status", summary="Plugin health for the console panel")
    async def get_status(request: "Request") -> Any:
        """The one panel that says *why* a mint is refusing.

        `service_address_present` is the field an operator needs: a session cannot be
        minted until the gateway knows its own contact address, and the mint's error
        says so — but the panel should show the state before a merchant hits it. The
        gate is reported rather than enforced here for the same reason a fused
        account must still be able to read its balance.
        """
        decision = deps.gate.status(PLUGIN_ID)
        counts: Dict[str, int] = {state: 0 for state in DB_STATES}
        for row in deps.db.query("SELECT state, COUNT(*) AS n FROM sso_sessions GROUP BY state") or ():
            key = str(row["state"] or "")
            if key in counts:
                counts[key] = int(row["n"] or 0)
        return reply({
            "ok": True,
            "plugin": PLUGIN_ID,
            "enabled": bool(getattr(deps.config.plugins, deps.spec.toggle, False)),
            "gate": decision.as_body(),
            "meter": deps.spec.meter,
            "url_prefix": deps.spec.url_prefix,
            "callback_kinds": list(deps.spec.callback_kinds),
            "service_address_present": bool(service_address_from_db(deps.db)),
            "sessions": {
                "open": sum(counts[state] for state in OPEN_DB_STATES),
                "total": sum(counts.values()),
                "by_state": counts,
            },
        })

    @router.get("/sessions/{session_id}", summary=_ROUTE_DOC_POLL)
    async def get_session(session_id: str, request: "Request") -> Any:
        deps.require()
        try:
            # The same bearer secret /verify needs. A browser polling a QR has
            # none and gets state only; the RP's own server gets the credential.
            expected = str(getattr(deps.config, "admin_token", "") or "")
            authorized = bool(expected) and secret_matches(bearer_secret(request), expected)
            return reply(poll_session(deps, session_id, authorized=authorized))
        except SsoRequestError as exc:
            return refused(exc)

    @router.post("/sessions/{session_id}/cancel", summary=_ROUTE_DOC_CANCEL)
    async def post_cancel(session_id: str, request: "Request") -> Any:
        deps.require()
        try:
            await json_body(request)  # size-checked; the route takes no fields today
            return reply(cancel_session(deps, session_id))
        except SsoRequestError as exc:
            return refused(exc)

    @router.post("/verify", summary=_ROUTE_DOC_VERIFY)
    async def post_verify(request: "Request") -> Any:
        deps.require()
        try:
            body = await json_body(request)
            presented = bearer_secret(request)
            expected = str(getattr(deps.config, "admin_token", "") or "")
            if not expected:
                raise SsoRequestError(
                    503, "not_configured",
                    "this gateway has no POPOPX_ADMIN_TOKEN, so it cannot authenticate a "
                    "relying party; refusing rather than accepting any credential",
                )
            if not secret_matches(presented, expected):
                # 401 and an identical body for "absent" and "wrong": the RP's
                # own integration is the only audience here, and there is
                # nothing for an outsider to learn from the difference.
                return reply(
                    {"ok": False, "error": "unauthorized", "detail": "Bearer token is not valid"},
                    status=401,
                )
            session_id = body.get("session_id") or body.get("sid") or ""
            token = body.get("token") or body.get("sso_token") or ""
            if not isinstance(session_id, str) or not session_id:
                raise SsoRequestError(400, "invalid_field", "session_id is required")
            if not isinstance(token, str) or not token or len(token) > 512:
                raise SsoRequestError(400, "invalid_field", "token is required")
            ok, reason, granted = redeem_session(deps.db, session_id, token, now_ms())
            if not ok:
                return reply(verify_failure(reason), status=VERIFY_FAILURE_STATUS)
            logger.info("sso: delivered sid=%s scope=%s", session_id[:6], granted.get("scope") or "")
            return reply(verify_success(str(granted.get("pairwise_uid") or ""), str(granted.get("scope") or "")))
        except SsoRequestError as exc:
            return refused(exc)

    @router.get("/audit", summary=_ROUTE_DOC_AUDIT)
    async def get_audit(request: "Request") -> Any:
        deps.require()
        expected = str(getattr(deps.config, "admin_token", "") or "")
        if not expected or not secret_matches(bearer_secret(request), expected):
            return reply(
                {"ok": False, "error": "unauthorized", "detail": "this list needs the gateway's admin bearer"},
                status=401,
            )
        raw_limit = request.query_params.get("limit") if request.query_params else None
        try:
            limit = int(raw_limit) if raw_limit not in (None, "") else 20
        except (TypeError, ValueError):
            return reply(
                {"ok": False, "error": "invalid_field", "detail": "limit must be an integer", "field": "limit"},
                status=400,
            )
        if limit < 1 or limit > 200:
            return reply(
                {"ok": False, "error": "field_out_of_range",
                 "detail": "limit must be between 1 and 200, got %d" % limit, "field": "limit"},
                status=400,
            )
        stamp = now_ms()
        rows = audit_rows(deps.db, limit, stamp)
        return reply({
            "ok": True,
            "count": len(rows),
            "limit": limit,
            "now_ms": stamp,
            "sessions": rows,
        })

    return router


# ─────────────────────────────────────────────────────────────────────────────
# 11. The phone-facing half
# ─────────────────────────────────────────────────────────────────────────────
#
# ``handle_inbound`` sees two kinds, and the second one is the seam gap this
# module has to live with: ``PLUGIN_SPEC.privacy_sso.callback_kinds`` is
# ``("sso_scan",)``, so a dispatcher that filters on the spec will never route a
# ``card_callback`` here — which is where 确认 and 取消 arrive. The branch is
# implemented anyway, guarded by :func:`claims`, so the plugin is correct the
# moment the row gains ``"card_callback"`` and is *also* correct if the
# dispatcher hands it everything. Reported rather than fixed in a shared file.


def _contact_id(message: Any) -> int:
    value = getattr(message, "contact_id", None)
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def _gate_usable(deps: "PluginDeps") -> bool:
    """Ask the gate without raising.

    In an HTTP route the right answer to "unusable" is an exception the gateway
    turns into 404/402/503. In an inbound handler there is no status code to
    return, so the honest translation is "do not start a flow that cannot
    finish", and the *unknown* answer is usable — a stub or an older gate that
    lacks ``status`` must not be able to disable logins by being quiet.
    """
    gate = getattr(deps, "gate", None)
    status = getattr(gate, "status", None)
    if not callable(status):
        return True
    try:
        return bool(getattr(status(deps.plugin_id), "usable", True))
    except Exception as exc:
        logger.debug("sso: gate status unavailable (%s); proceeding", exc)
        return True


async def _notify(deps: "PluginDeps", contact_id: int, text: str) -> None:
    """One plain chat message, for a scan this plugin cannot turn into a card.

    Deliberately *not* a card: a card is a thing with buttons and a lifetime, and
    an expired QR deserves neither. A frame with no ``::POPOPX_ECO::`` marker
    arrives as ordinary text, which is what this is. Silence would be the worst
    answer — the user standing at a login page with a phone that did nothing.
    """
    send = getattr(deps.eco, "send_frame", None)
    if not callable(send) or not contact_id:
        return
    try:
        await send(contact_id, text)
    except Exception as exc:
        logger.warning("sso: notice to contact %d not sent (%s)", contact_id, exc)


async def _close_card(
    deps: "PluginDeps", row: Mapping[str, Any], outcome: str, stamp: int, rp_name: str
) -> None:
    """Rewrite the card in place so the buttons cannot be pressed twice."""
    card_id = str(row.get("card_id") or "")
    contact_id = int(row.get("contact_id") or 0)
    session_id = str(row.get("session_id") or "")
    if not card_id or not contact_id or not session_id:
        return
    payload = terminal_payload(session_id, outcome=outcome, now=stamp, rp_name=rp_name)
    update = getattr(deps.eco, "update_card", None)
    if not callable(update):
        logger.warning("sso: no update_card on this gateway; card %s stays open", card_id)
        return
    try:
        delivery = await update(card_id, contact_id, **payload)
    except TypeError:
        # An eco implementation that has not caught up with `expires_at_ms`:
        # retry with the copy, and let the inert `et` be the only thing missing.
        fallback = dict(payload)
        fallback.pop("expires_at_ms", None)
        try:
            await update(card_id, contact_id, **fallback)
        except Exception as exc:
            logger.warning("sso: card %s close-out failed (%s)", card_id, exc)
        return
    except Exception as exc:
        logger.warning("sso: card %s close-out failed (%s)", card_id, exc)
        return
    if delivery is not None and getattr(delivery, "error", None):
        logger.warning("sso: card %s close-out reported %r", card_id, str(delivery.error)[:120])


async def _handle_scan(deps: "PluginDeps", message: Any, session_id: str) -> bool:
    """``::SSO_SCAN::<id>`` → bind this contact, deliver the confirmation card."""
    session_id = (session_id or "").strip()
    contact_id = _contact_id(message)
    if not is_single_token(session_id) or not contact_id:
        # A truncated, whitespace-laden or empty scan is not ours to answer;
        # returning False lets the caller log it instead of this module
        # inventing a session that was never minted.
        logger.info("sso: scan with unusable payload %r", session_id[:16])
        return False

    try:
        ok, reason, row = claim_scan(deps.db, session_id, contact_id, card_id_for(session_id), now_ms())
    except Exception as exc:
        # `sso_sessions.contact_id` carries a real foreign key, so a bind to a
        # contact this gateway has never met is an IntegrityError. That is an
        # answer ("not mine, and nobody else's either"), not a crash: raising
        # here would take the dispatcher down with a QR that means nothing.
        logger.warning("sso: scan bind failed for sid=%s (%s)", session_id[:6], exc)
        return False
    if reason == "unknown_session":
        logger.info("sso: scan for unknown sid=%s", session_id[:6])
        return False
    if not ok:
        logger.info("sso: scan refused for sid=%s (%s)", session_id[:6], reason)
        if reason == "other_contact":
            await _notify(deps, contact_id, INBOUND_OTHER_SCANNER_TEXT)
        elif reason in ("expired", "not_scannable"):
            await _notify(deps, contact_id, INBOUND_EXPIRED_TEXT)
        return True

    if not _gate_usable(deps):
        logger.warning("sso: sid=%s scanned but the plugin is not usable; no card delivered", session_id[:6])
        await _notify(deps, contact_id, INBOUND_EXPIRED_TEXT)
        return True

    stamp = now_ms()
    rp_uri = str(row.get("rp_uri") or "")
    rp_origin = origin_of(rp_uri) if rp_uri else ""
    rp_name = str(row.get("rp_name") or rp_origin)
    scope = str(row.get("scope") or DEFAULT_SCOPE)
    expires_at_ms = int(row.get("expires_at_ms") or expiry_deadline(stamp, 180))
    card = confirm_card(
        session_id, rp_name=rp_name, rp_origin=rp_origin, scope=scope,
        now=stamp, expires_at_ms=expires_at_ms,
    )

    # The delivery is the only step whose failure has to be *undone*: a card the
    # node never accepted would leave a session stuck in `scanned` with no
    # visible way forward, and the user would rescan into "already scanned by
    # someone else" — a login lost to a socket blip. Reverting to `pending`
    # makes the second scan a genuine retry.
    try:
        delivery = await deps.eco.deliver_card(card, contact_id, topic="sso")
    except Exception as exc:
        logger.warning("sso: deliver_card raised for sid=%s (%s); reverting to pending", session_id[:6], exc)
        revert_scan(deps.db, session_id, contact_id, now_ms())
        return True

    sent = bool(getattr(delivery, "sent", False)) or bool(getattr(delivery, "queued", False))
    if not sent:
        logger.warning(
            "sso: card not delivered for sid=%s (%s); reverting to pending",
            session_id[:6], str(getattr(delivery, "error", "") or "no detail")[:120],
        )
        revert_scan(deps.db, session_id, contact_id, now_ms())
        return True

    delivered_id = str(getattr(delivery, "card_id", "") or "")
    if delivered_id and delivered_id != card_id_for(session_id):
        # The gateway may mint its own id; the close-out has to address the card
        # that actually exists, so the row follows the delivery, not the intent.
        with deps.db.transaction(immediate=True) as conn:
            conn.execute(
                "UPDATE sso_sessions SET card_id = ? WHERE session_id = ? AND contact_id = ?",
                (delivered_id, session_id, contact_id),
            )
    logger.info("sso: card delivered sid=%s scope=%s", session_id[:6], scope)
    return True


async def _handle_confirm(deps: "PluginDeps", message: Any, session_id: str) -> bool:
    """The 确认 tap: bind, mint, bill, close the card. In that order.

    Identity and key material are resolved *before* the state write, and the
    write is the one that owns the transition — so a double tap cannot mint two
    credentials, and a failure before the write leaves nothing behind.
    """
    stamp = now_ms()
    contact_id = _contact_id(message)
    row = load_session(deps.db, session_id)
    if row is None:
        logger.info("sso: confirm tap for unknown sid=%s", session_id[:6])
        return True

    if not contact_id or int(row.get("contact_id") or 0) != contact_id:
        logger.warning("sso: confirm tap from %d does not own sid=%s", contact_id, session_id[:6])
        await _close_card(deps, row, OUTCOME_FAILED, stamp, str(row.get("rp_name") or ""))
        return True

    session = None
    try:
        session = deps.eco.session_for(contact_id)
    except Exception as exc:
        logger.warning("sso: session_for(%d) raised (%s)", contact_id, exc)

    secret_hex = ""
    pairwise_uid = ""
    if session is not None and not bool(getattr(session, "revoked", False)):
        secret_hex = str(getattr(session, "secret_hex", "") or "")
        pairwise_uid = str(getattr(session, "pairwise_uid", "") or "")
    if not pairwise_uid:
        pairwise_uid = pairwise_uid_from_db(deps.db, contact_id)
    if not pairwise_uid:
        # No pseudonym to bind a credential to means no login, and inventing an
        # identity would be the one thing the RP could never un-see.
        logger.error("sso: no pairwise uid for contact %d; sid=%s cannot be approved", contact_id, session_id[:6])
        await _close_card(deps, row, OUTCOME_FAILED, stamp, str(row.get("rp_name") or ""))
        return True

    scope = str(row.get("scope") or DEFAULT_SCOPE)
    rp_name = str(row.get("rp_name") or origin_of(str(row.get("rp_uri") or "")))

    try:
        key_bytes, key_source = resolve_key_material(secret_hex, str(getattr(deps.config, "h5_server_secret", "") or ""))
    except SsoKeyUnavailable as exc:
        logger.error("sso: sid=%s not approved: %s", session_id[:6], exc.detail)
        await _close_card(deps, row, OUTCOME_FAILED, stamp, rp_name)
        return True

    token = derive_token(key_bytes, session_id, pairwise_uid, scope)
    if key_source != _KEY_SOURCE_ECO:
        # Loud, because the fallback key is per-gateway rather than per-follower:
        # a deployment that hits this line for every login has unpaired followers
        # authorising logins, and the seal in the row will say so afterwards.
        logger.warning("sso: sid=%s minted on the gateway key, not a pairwise session secret", session_id[:6])
    seal = seal_token(token, key_source)
    deadline = confirmed_deadline(
        int(row.get("expires_at_ms") or stamp), stamp,
        int(getattr(deps.config, "sso_poll_interval_ms", 2000) or 2000),
    )

    ok, reason, granted_row = grant_session(
        deps.db, session_id, contact_id=contact_id, pairwise_uid=pairwise_uid,
        seal=seal, now=stamp, deadline_ms=deadline,
    )
    if not ok:
        logger.info("sso: confirm refused for sid=%s (%s)", session_id[:6], reason)
        if reason in ("other_contact", "raced", "unknown_session"):
            # A stranger cannot finish — or break — somebody else's login. The
            # owner's card stays exactly as it was, buttons and all.
            return True
        outcome = {
            "expired": OUTCOME_EXPIRED,
            "cancelled": OUTCOME_CANCELLED,
            "already_delivered": OUTCOME_GRANTED,
        }.get(reason, OUTCOME_FAILED)
        await _close_card(deps, granted_row or row, outcome, stamp, rp_name)
        return True
    if reason == "already_granted":
        # A tap that arrived twice, or a re-tap after a lost update. The
        # credential the first tap produced is still the only one, and billing it
        # twice would be the actual bug.
        logger.info("sso: duplicate confirm for sid=%s; card re-closed, not re-billed", session_id[:6])
        await _close_card(deps, granted_row, OUTCOME_GRANTED, stamp, rp_name)
        return True

    try:
        deps.charge(
            contact_id=contact_id,
            ref=session_id,
            idempotency_key="sso:" + session_id,
            meta={"rp": origin_of(str(row.get("rp_uri") or "")), "scope": scope},
        )
    except BillingError as exc:
        # A login the account cannot pay for is not granted. The credential is
        # destroyed and the row becomes `cancelled` rather than sitting
        # ``approved`` with a token that no ledger backs.
        logger.error("sso: billing failed for sid=%s (%s); grant revoked", session_id[:6], exc)
        revoke_grant(deps.db, session_id, now_ms())
        await _close_card(deps, granted_row, OUTCOME_FAILED, stamp, rp_name)
        return True
    except Exception as exc:
        logger.exception("sso: billing raised for sid=%s; grant revoked", session_id[:6])
        revoke_grant(deps.db, session_id, now_ms())
        await _close_card(deps, granted_row, OUTCOME_FAILED, stamp, rp_name)
        return True

    await _close_card(deps, granted_row, OUTCOME_GRANTED, stamp, rp_name)
    logger.info("sso: confirmed sid=%s rp=%s key=%s", session_id[:6], origin_of(str(row.get("rp_uri") or "")), key_source)
    return True


async def _handle_cancel(deps: "PluginDeps", message: Any, session_id: str) -> bool:
    stamp = now_ms()
    contact_id = _contact_id(message)
    ok, reason, row = refuse_session(deps.db, session_id, contact_id=contact_id, now=stamp)
    if ok:
        logger.info("sso: cancelled sid=%s by tap (%s)", session_id[:6], reason)
        await _close_card(deps, row, OUTCOME_CANCELLED, stamp, str(row.get("rp_name") or ""))
        return True
    if reason == "already_delivered":
        # The login is over and this card is a leftover; the owner is allowed to
        # retire it. Anyone else is told nothing and changes nothing.
        logger.info("sso: cancel tap on already-delivered sid=%s; card re-closed", session_id[:6])
        await _close_card(deps, row, OUTCOME_GRANTED, stamp, str(row.get("rp_name") or ""))
        return True
    # `other_contact` in particular must NOT close the card: a stranger tapping
    # 取消 on a QR they photographed would otherwise kill the real user's login.
    logger.info("sso: cancel tap did not apply to sid=%s (%s)", session_id[:6], reason)
    return True


async def _handle_noop(deps: "PluginDeps", message: Any, session_id: str) -> bool:
    """A tap on a closed-out card. Re-state it; change nothing."""
    stamp = now_ms()
    row = load_session(deps.db, session_id)
    if row is None:
        return True
    state = effective_state(row.get("state"), row.get("expires_at_ms"), stamp)
    outcome = {
        LOGICAL_DELIVERED: OUTCOME_GRANTED,
        LOGICAL_CONFIRMED: OUTCOME_GRANTED,
        LOGICAL_CANCELLED: OUTCOME_CANCELLED,
        LOGICAL_EXPIRED: OUTCOME_EXPIRED,
    }.get(state)
    if outcome is not None:
        await _close_card(deps, row, outcome, stamp, str(row.get("rp_name") or ""))
    return True


async def handle_inbound(deps: "PluginDeps", message: "InboundMessage") -> bool:
    """One inbound eco message. ``True`` means this plugin consumed it.

    Unknown *session* ids answer ``False`` on purpose: a QR that was mistyped, a
    scan of another deployment's code, an id that has been purged — none of them
    are this plugin's business, and the dispatcher that handed the message here
    gets to log or route them instead of taking a 500 from a callback whose
    payload it cannot bind.
    """
    callback = getattr(message, "callback", None)
    kind = str(getattr(callback, "kind", "") or "")
    payload = str(getattr(callback, "payload", "") or "")
    if getattr(message, "direction", "rcv") != "rcv":
        return False

    if kind == "sso_scan":
        return await _handle_scan(deps, message, payload)

    if kind == "card_callback" and claims(payload):
        verb, session_id = split_callback(payload)
        session_id = (session_id or "").strip()
        if not session_id:
            return False
        if verb == "confirm":
            return await _handle_confirm(deps, message, session_id)
        if verb == "cancel":
            return await _handle_cancel(deps, message, session_id)
        if verb == "noop":
            return await _handle_noop(deps, message, session_id)
        return False

    return False


# ─────────────────────────────────────────────────────────────────────────────
# 12. Self-test
# ─────────────────────────────────────────────────────────────────────────────
#
# Runs under ``/usr/bin/python3`` with no third-party wheel present, which is the
# actual state of the machine this file was written on. It therefore proves two
# different things, and the split is worth being precise about: the pure
# predicates (limits, grammar, the state machine, expiry arithmetic, token
# derivation and comparison, response shapes) are checked as functions, and the
# parts that only exist once SQLite is involved — the ``CHECK`` vocabulary, the
# conditional-UPDATE claims, single use, the card that must not be delivered for
# an expired session, the billing failure that must not leave a credential — are
# checked against the *real* schema, through a real :class:`app.database.Database`
# on a temporary file, driven through the real ``handle_inbound``.
#
# What it does not prove is stated at the end of the report rather than here: a
# frame's journey to a phone, and anything about FastAPI's routing, needs wheels
# and a node.


def _raises_sso(call: Any, *args: Any, **kwargs: Any) -> bool:
    """Whether one guard rejects, for the boolean checks in :func:`self_test`.

    A separate module-level helper rather than a lambda in the test body, so a
    guard that *stops* raising cannot be mistaken for a pass by an expression
    that silently returns something else.
    """
    try:
        call(*args, **kwargs)
    except SsoRequestError:
        return True
    except Exception:
        return False
    return False


def _error_status(call: Any, *args: Any, **kwargs: Any) -> int:
    """The HTTP status a guard answers with, or 0 when it does not refuse."""
    try:
        call(*args, **kwargs)
    except SsoRequestError as exc:
        return exc.status
    except Exception:
        return -1
    return 0


def _error_code(call: Any, *args: Any, **kwargs: Any) -> str:
    try:
        call(*args, **kwargs)
    except SsoRequestError as exc:
        return exc.code
    except Exception:
        return ""
    return ""


def _error_code(call: Any, *args: Any, **kwargs: Any) -> str:
    try:
        call(*args, **kwargs)
    except SsoRequestError as exc:
        return exc.code
    except Exception:
        return ""
    return ""


# ─────────────────────────────────────────────────────────────────────────────
# 12.1 Test doubles
# ─────────────────────────────────────────────────────────────────────────────
#
# Duck-typed, and deliberately so: the seam's own `EcoSession`/`CardDelivery`
# dataclasses are used where they are cheap, and a plain object with the
# documented attributes is used where they are not, so `self_test` fails if this
# module starts depending on a field the contract does not promise.


class _NoTableDb:
    """A handle whose schema is not there, to prove the defensive reads."""

    def query_one(self, sql: str, params: Sequence[Any] = ()) -> Any:
        raise RuntimeError("no such table: service_identity")

    def query(self, sql: str, params: Sequence[Any] = ()) -> Any:
        raise RuntimeError("no such table")


class _AbortProbe(Exception):
    pass


def _insert_state_is_ok(db: Any, state: str) -> bool:
    """Whether the real CHECK constraint accepts one literal in ``state``."""
    try:
        with db.transaction(immediate=True) as conn:
            conn.execute(
                "INSERT INTO sso_sessions (session_id, state, created_at_ms, expires_at_ms) "
                "VALUES (?, ?, ?, ?)",
                ("state-probe-%s" % (state or "empty"), state, 1, 2),
            )
            raise _AbortProbe()
    except _AbortProbe:
        return True
    except Exception:
        return False


def _add_contact(db: Any, contact_id: int, pairwise_uid: str = "", secret_hex: str = "") -> None:
    """A follower row, because ``sso_sessions.contact_id`` has a real FK on it.

    Worth stating: that foreign key means binding a scan to a contact the
    gateway has never met is an ``IntegrityError``, not a silent insert — which
    is the right answer for a login product, and the reason
    :func:`_handle_scan` treats a failed bind as "not mine" rather than as a
    crash.
    """
    stamp = 1_700_000_000_000
    with db.transaction(immediate=True) as conn:
        conn.execute(
            "INSERT OR REPLACE INTO contacts (contact_id, pairwise_uid, display_name, first_seen_ms, last_seen_ms) "
            "VALUES (?, ?, ?, ?, ?)",
            (int(contact_id), pairwise_uid or None, "关注者%d" % contact_id, stamp, stamp),
        )
        if secret_hex:
            conn.execute(
                "INSERT OR REPLACE INTO eco_sessions (pairwise_uid, contact_id, service_id, secret_hex, created_at_ms) "
                "VALUES (?, ?, ?, ?, ?)",
                (pairwise_uid, int(contact_id), "selftest-service", secret_hex, stamp),
            )


class _TestConfig:
    def __init__(
        self,
        ttl: int = 120,
        poll_ms: int = 2000,
        h5: str = "selftest-h5-server-secret-value",
        admin: str = "selftest-admin-token-value-0123456789",
    ) -> None:
        self.sso_ttl_seconds = ttl
        self.sso_poll_interval_ms = poll_ms
        self.h5_server_secret = h5
        self.admin_token = admin
        self.public_base_url = "https://gw.example.com"
        self.service_name = "自测服务号"


class _TestAccount:
    balance = 500
    status = "ACTIVE"


class _TestCharge:
    def __init__(self, charged: int = 1) -> None:
        self.charged = charged
        self.cost = charged
        self.balance_after = 499
        self.account_status = "ACTIVE"
        self.idempotent_replay = False


class _TestBilling:
    def __init__(self, fail: Optional[Exception] = None) -> None:
        self.calls: List[Dict[str, Any]] = []
        self.fail = fail

    def charge(self, action: str, **kwargs: Any) -> Any:
        entry = {"meter": action}
        entry.update(kwargs)
        self.calls.append(entry)
        if self.fail is not None:
            raise self.fail
        return _TestCharge()

    def account(self) -> _TestAccount:
        return _TestAccount()

    def is_plugin_fused(self, plugin: str) -> bool:
        return False


class _TestDecision:
    def __init__(self, usable: bool) -> None:
        self.usable = usable
        self.reason = "usable" if usable else "credit_fused"
        self.http_status = 200 if usable else 402
        self.detail = "ok" if usable else "fused"
        self.balance = 500


class _TestGate:
    def __init__(self, usable: bool = True) -> None:
        self.usable = usable
        self.status_calls: List[str] = []

    def status(self, plugin_id: str) -> _TestDecision:
        self.status_calls.append(plugin_id)
        return _TestDecision(self.usable)

    def require(self, plugin_id: str) -> _TestDecision:
        decision = self.status(plugin_id)
        if not decision.usable:
            raise RuntimeError("unusable")
        return decision


class _TestSession:
    """The attributes of ``plugins.EcoSession``, without importing the class."""

    def __init__(self, contact_id: int, pairwise_uid: str, secret_hex: str, revoked: bool = False) -> None:
        self.contact_id = contact_id
        self.pairwise_uid = pairwise_uid
        self.secret_hex = secret_hex
        self.service_id = "selftest-service"
        self.revoked = revoked

    @property
    def usable(self) -> bool:
        if self.revoked:
            return False
        try:
            validate_secret_hex(self.secret_hex)
        except EcoError:
            return False
        return True


class _TestDelivery:
    def __init__(self, card_id: str, contact_id: int, sent: bool, error: Optional[str] = None) -> None:
        self.card_id = card_id
        self.contact_id = contact_id
        self.sent = sent
        self.charged = 0
        self.balance_after = 500
        self.error = error
        self.queued = False


class _TestEco:
    """Records every card this plugin asks the gateway to send."""

    def __init__(self, session: Optional[Any] = None, deliver_sent: bool = True,
                 forced_card_id: str = "") -> None:
        self.session = session
        self.deliver_sent = deliver_sent
        self.forced_card_id = forced_card_id
        self.delivered: List[Dict[str, Any]] = []
        self.updated: List[Dict[str, Any]] = []
        self.sent_text: List[Tuple[int, str]] = []

    def session_for(self, contact_id: int) -> Optional[Any]:
        if self.session is None:
            return None
        if int(getattr(self.session, "contact_id", contact_id)) != int(contact_id):
            return None
        return self.session

    async def deliver_card(self, card: Mapping[str, object], contact_id: int, *,
                           visible_text: Optional[str] = None, topic: str = "") -> _TestDelivery:
        self.delivered.append({"card": dict(card), "contact_id": int(contact_id),
                               "topic": topic, "visible_text": visible_text})
        card_id = str(card.get("id", "")) if isinstance(card, Mapping) else ""
        if self.forced_card_id:
            # A gateway that mints its own id, which the seam allows and the
            # close-out has to survive.
            card_id = self.forced_card_id
        if self.deliver_sent:
            return _TestDelivery(card_id, int(contact_id), True)
        return _TestDelivery(card_id, int(contact_id), False, error="node link is down")

    async def update_card(self, card_id: str, contact_id: int, *, title: Optional[str] = None,
                          body: Optional[str] = None, fields: Optional[Sequence[Mapping[str, object]]] = None,
                          progress: Optional[Mapping[str, object]] = None,
                          actions: Optional[Sequence[Mapping[str, object]]] = None,
                          expires_at_ms: Optional[int] = None) -> _TestDelivery:
        self.updated.append({"card_id": card_id, "contact_id": int(contact_id), "title": title, "body": body,
                             "fields": fields, "progress": progress, "actions": actions,
                             "expires_at_ms": expires_at_ms})
        return _TestDelivery(card_id, int(contact_id), True)

    async def send_frame(self, contact_id: int, text: str) -> bool:
        self.sent_text.append((int(contact_id), text))
        return True

    def public_url(self, path: str) -> str:
        return "https://gw.example.com" + path

    def h5_url(self, session: Any, path: str) -> str:
        return "https://h5.example.com" + path


def _stub_deps(
    db: Any,
    *,
    eco: Optional[Any] = None,
    billing: Optional[Any] = None,
    config: Optional[Any] = None,
    gate: Optional[Any] = None,
) -> "PluginDeps":
    """The real :class:`PluginDeps`, so ``deps.charge`` and ``deps.require`` are
    exercised through the seam's own meter lookup rather than a stub of it."""
    from app.plugins import PluginDeps, plugin_for_id

    return PluginDeps(
        config=config if config is not None else _TestConfig(),
        db=db,
        billing=billing if billing is not None else _TestBilling(),
        eco=eco if eco is not None else _TestEco(),
        gate=gate if gate is not None else _TestGate(True),
        spec=plugin_for_id(PLUGIN_ID),
    )


def self_test() -> List[str]:
    """Return the list of properties proved. Raises on the first that fails."""
    checks: List[str] = []

    def check(name: str, condition: bool) -> None:
        if not condition:
            raise AssertionError("self_test failed: %s" % name)
        checks.append(name)

    def raises(name: str, error: Any, call: Any, *args: Any, **kwargs: Any) -> None:
        """`call(*args)` must raise `error`, and for SsoRequestError the status too."""
        try:
            call(*args, **kwargs)
        except error as exc:
            expected = getattr(error, "status", None)
            if expected is not None and isinstance(exc, SsoRequestError):
                if exc.status != expected:
                    raise AssertionError("self_test failed: %s (status %s)" % (name, exc.status))
            check(name, True)
            return
        except Exception as exc:
            raise AssertionError("self_test failed: %s (raised %s)" % (name, type(exc).__name__))
        raise AssertionError("self_test failed: %s (did not raise)" % name)

    # ── 12.1 the callback grammar ────────────────────────────────────────────
    sid = "Ab3-_xyz8901234567890123"
    check("claims_confirm", claims(CB_CONFIRM + sid))
    check("claims_cancel", claims(CB_CANCEL + sid))
    check("claims_noop", claims(CB_NOOP + sid))
    check("claims_rejects_foreign_plugin", not claims("poll:vote:4:2") and not claims("web3:rotate:c1"))
    check("claims_rejects_bare_prefix", not claims("sso:") and not claims("sso:confirm:") and not claims("sso:"))
    check("claims_rejects_nonstring", not claims(None) and not claims(7) and not claims(b"sso:confirm:x"))
    check("claims_rejects_double_colon", not claims("sso:confirm:a::b"))
    check("claims_rejects_overlong", not claims(CB_CONFIRM + "z" * (MAX_TOKEN_CHARS + 1)))
    check("claims_accepts_limit_length", claims(CB_CONFIRM + "z" * (MAX_TOKEN_CHARS - len(CB_CONFIRM))))
    check("is_single_token_matches_client_rule", is_single_token(sid) and not is_single_token("a b")
          and not is_single_token("a\nb") and not is_single_token("") and not is_single_token("a::b"))
    check("split_callback_roundtrip", split_callback(CB_CONFIRM + sid) == ("confirm", sid))
    check("split_callback_unknown_verb", split_callback("sso:other:x") == (None, ""))
    check("card_id_within_client_limit", len(card_id_for(sid)) <= EcoLimits.card_id_chars)
    check("card_id_roundtrip", session_id_from_card_id(card_id_for(sid)) == sid)
    check("card_id_folds_rather_than_truncates",
          len(card_id_for("z" * 64)) <= EcoLimits.card_id_chars
          and card_id_for("z" * 64) != card_id_for("z" * 63)
          and card_id_for("z" * 2000) == card_id_for("z" * 2000)
          and session_id_from_card_id(card_id_for("z" * 64)) == "")
    check("session_id_is_single_token_and_urlsafe", all(is_single_token(new_session_id()) for _ in range(200)))
    check("session_ids_unique", len({new_session_id() for _ in range(400)}) == 400)

    # ── 12.2 the state machine, in both vocabularies ──────────────────────────
    check("state_maps_are_bijections",
          len(DB_TO_LOGICAL) == len(LOGICAL_TO_DB) == len(DB_STATES) == len(LOGICAL_STATES)
          and all(LOGICAL_TO_DB[DB_TO_LOGICAL[k]] == k for k in DB_STATES))
    check("state_db_vocabulary_is_the_schema_check",
          set(DB_TO_LOGICAL) == {"pending", "scanned", "approved", "denied", "expired", "consumed"})
    check("state_words_the_schema_rejects",
          all(word not in DB_TO_LOGICAL for word in ("confirmed", "delivered", "cancelled")))
    check("every_transition_target_is_a_state",
          all(target in LOGICAL_STATES for edges in LEGAL_TRANSITIONS.values() for target in edges))
    check("transition_pending_to_scanned", is_legal_transition(LOGICAL_PENDING, LOGICAL_SCANNED))
    check("transition_pending_to_confirmed_is_illegal", not is_legal_transition(LOGICAL_PENDING, LOGICAL_CONFIRMED))
    check("transition_scanned_to_confirmed", is_legal_transition(LOGICAL_SCANNED, LOGICAL_CONFIRMED))
    check("transition_scanned_rescan_same_contact", is_legal_transition(LOGICAL_SCANNED, LOGICAL_SCANNED))
    check("transition_confirmed_to_delivered", is_legal_transition(LOGICAL_CONFIRMED, LOGICAL_DELIVERED))
    check("transition_confirmed_cancellable", is_legal_transition(LOGICAL_CONFIRMED, LOGICAL_CANCELLED))
    check("transition_delivered_to_cancelled_is_illegal", not is_legal_transition(LOGICAL_DELIVERED, LOGICAL_CANCELLED))
    check("terminal_states_have_no_exits",
          all(LEGAL_TRANSITIONS[state] == () for state in TERMINAL_LOGICAL_STATES))
    check("scan_is_the_only_way_to_confirm",
          not any(LOGICAL_CONFIRMED in edges for state, edges in LEGAL_TRANSITIONS.items() if state == LOGICAL_PENDING))
    check("logical_state_unknown_is_expired", logical_state("weird") == LOGICAL_EXPIRED
          and logical_state(None) == LOGICAL_EXPIRED and logical_state("") == LOGICAL_EXPIRED)

    created = 1_700_000_000_000
    ttl_seconds = 180
    deadline = expiry_deadline(created, ttl_seconds)
    check("expiry_arithmetic_is_milliseconds", deadline == created + 180_000)
    check("expiry_one_ms_early_is_pending",
          effective_state(DB_PENDING, deadline, deadline - 1) == LOGICAL_PENDING)
    check("expiry_exactly_at_deadline_is_expired", effective_state(DB_PENDING, deadline, deadline) == LOGICAL_EXPIRED)
    check("expiry_one_ms_late_is_expired", effective_state(DB_PENDING, deadline, deadline + 1) == LOGICAL_EXPIRED)
    check("expiry_does_not_resurrect_scanned",
          effective_state(DB_SCANNED, deadline, deadline + 1) == LOGICAL_EXPIRED)
    check("expiry_covers_approved", effective_state(DB_APPROVED, deadline, deadline) == LOGICAL_EXPIRED)
    check("expiry_never_overrides_terminal",
          effective_state(DB_CONSUMED, deadline, deadline + 10_000) == LOGICAL_DELIVERED
          and effective_state(DB_DENIED, deadline, deadline + 10_000) == LOGICAL_CANCELLED
          and effective_state(DB_EXPIRED, deadline, deadline + 10_000) == LOGICAL_EXPIRED)
    check("grace_is_several_poll_cycles", token_grace_ms(2000) >= 3 * 2000 and token_grace_ms(20_000) == 200_000)
    check("confirm_extends_rather_than_replaces",
          confirmed_deadline(deadline, deadline - 500, 2000) == deadline - 500 + token_grace_ms(2000)
          and confirmed_deadline(deadline, deadline - 1, 2000) > deadline)
    check("is_expired_helper_agrees", is_expired(DB_PENDING, deadline, deadline) and not is_expired(DB_PENDING, deadline, deadline - 1))
    check("open_states_are_the_three_pre_terminal",
          set(OPEN_STATES_LOGICAL) == {LOGICAL_PENDING, LOGICAL_SCANNED, LOGICAL_CONFIRMED})

    # ── 12.3 tokens ──────────────────────────────────────────────────────────
    key_a = bytes.fromhex("11" * 32)
    key_b = bytes.fromhex("22" * 32)
    other_sid = "Zz9-_other0123456789012"
    uid_a = "pairwiseAAAA"
    uid_b = "pairwiseBBBB"
    token_1 = derive_token(key_a, sid, uid_a, "openid")
    token_2 = derive_token(key_a, sid, uid_a, "openid")
    check("token_deterministic", token_1 == token_2)
    check("token_is_lowercase_hex_64", len(token_1) == 64 and re.match(r"^[0-9a-f]{64}$", token_1) is not None)
    check("token_differs_by_session", derive_token(key_a, other_sid, uid_a, "openid") != token_1)
    check("token_differs_by_pairwise", derive_token(key_a, sid, uid_b, "openid") != token_1)
    check("token_differs_by_scope", derive_token(key_a, sid, uid_a, "openid profile") != token_1)
    check("token_differs_by_key", derive_token(key_b, sid, uid_a, "openid") != token_1)
    check("tokens_do_not_collide_across_pairs",
          len({derive_token(key_a, "session%03d" % i, uid_a, "openid") for i in range(500)}) == 500)
    check("preimage_field_order_matters",
          token_preimage("a", "b", "c") != token_preimage("a", "c", "b"))
    check("preimage_has_no_bare_separator_ambiguity", b"\n" in token_preimage(sid, uid_a, "openid"))
    raises("token_needs_a_key", SsoKeyUnavailable, derive_token, b"", sid, uid_a)

    seal = seal_token(token_1, _KEY_SOURCE_ECO)
    check("seal_is_self_describing", seal.startswith("sha256$eco$") and seal.endswith(hashlib.sha256(token_1.encode()).hexdigest()))
    check("seal_is_not_the_token", token_1 not in seal and len(seal) < 96)
    raises("seal_rejects_unknown_source", ValueError, seal_token, token_1, "redis")
    check("seal_parse_roundtrip", parse_seal(seal) == (_KEY_SOURCE_ECO, bytes.fromhex(hashlib.sha256(token_1.encode()).hexdigest())))
    check("seal_parse_bare_hex", parse_seal(token_1)[1] == bytes.fromhex(token_1))
    check("seal_parse_garbage", parse_seal("not-a-seal") == ("", None) and parse_seal(None) == ("", None)
          and parse_seal("sha256$eco$zz" * 1) == ("", None) and parse_seal("sha256$bad$" + token_1) == ("", None))
    check("token_matches_correct_presentation", token_matches(token_1, seal))
    check("token_rejects_other_token", not token_matches(token_2 + "0", seal))
    check("token_rejects_empty_and_none", not token_matches("", seal) and not token_matches(None, seal))
    check("token_rejects_missing_seal", not token_matches(token_1, None) and not token_matches(token_1, ""))
    check("token_rejects_malformed_seal", not token_matches(token_1, "sha256$eco$zz" * 4))
    check("token_matches_bare_hex_seal", token_matches(token_1, hashlib.sha256(token_1.encode()).hexdigest()))
    check("dummy_seal_verifies_nothing", not token_matches(token_1, _DUMMY_SEAL) and parse_seal(_DUMMY_SEAL)[1] is not None)

    secret_hex = "ab" * 32
    key_bytes, source = resolve_key_material(secret_hex, "x" * 40)
    check("key_prefers_pairwise_session", source == _KEY_SOURCE_ECO and key_bytes == bytes.fromhex(secret_hex))
    key_bytes, source = resolve_key_material("", "y" * 40)
    check("key_falls_back_to_gateway_secret", source == _KEY_SOURCE_H5 and key_bytes == b"y" * 40)
    key_bytes, source = resolve_key_material("not hex at all", "z" * 40)
    check("key_rejects_unusable_session_secret", source == _KEY_SOURCE_H5)
    raises("key_requires_something_to_derive_from", SsoKeyUnavailable, resolve_key_material, None, "")
    raises("key_rejects_short_gateway_secret", SsoKeyUnavailable, resolve_key_material, "", "hunter2")

    check("secret_matches_empty_expected_is_false", not secret_matches("", "") and not secret_matches("x", ""))
    check("secret_matches_exact", secret_matches("popopx-admin-token-value", "popopx-admin-token-value"))
    check("secret_matches_rejects_wrong", not secret_matches("a" * 30, "b" * 30))

    # ── 12.4 percent-encoding and the QR payload ──────────────────────────────
    check("encode_leaves_the_unreserved_set_alone", percent_encode("aZ0-._~") == "aZ0-._~")
    check("encode_escapes_the_delimiters",
          "%26" in percent_encode("a&b") and "%3D" in percent_encode("a=b")
          and "%23" in percent_encode("a#b") and "%2F" in percent_encode("a/b")
          and "%25" in percent_encode("100%") and "%2B" in percent_encode("a+b")
          and percent_encode("a:b") == "a%3Ab")
    check("encode_escapes_whitespace_and_control",
          "%20" in percent_encode("a b") and "%0A" in percent_encode("a\nb") and "%09" in percent_encode("a\tb"))
    check("encode_output_is_pure_ascii", all(ord(ch) < 128 for ch in percent_encode("服务号")))
    address = "popopx:/Q7dnHsF8Kz#relay=eu&account=svc"
    qr = build_qr_payload(address, sid)
    check("qr_shape", qr.startswith("popopx://sso?uri=") and "&session=" in qr)
    check("qr_session_is_last_pair", qr.split("&")[-1].startswith("session="))
    check("qr_has_exactly_two_query_pairs", len(qr.split("?", 1)[1].split("&")) == 2)
    qr_uri_value = qr.split("?", 1)[1].split("uri=", 1)[1].split("&")[0]
    check("qr_embedded_address_keeps_every_delimiter_escaped",
          all(ch not in qr_uri_value for ch in ("&", "#", "/", "?", "+", "=", ":", "!", "@"))
          and qr_uri_value.replace("%", "").isalnum())
    check("qr_decodes_back_to_the_original_address",
          urllib.parse.unquote(qr.split("&")[0].split("=", 1)[1], encoding="utf-8") == address)
    check("qr_decodes_back_to_the_session_id",
          urllib.parse.unquote(qr.split("&session=", 1)[1]) == sid and qr.split("&session=", 1)[1] == sid)
    check("qr_within_client_url_limit", len(qr) <= EcoLimits.url_chars)
    check("qr_is_single_line_and_spaceless", " " not in qr and "\n" not in qr)
    check("qr_unicode_address_stays_parsable",
          len(build_qr_payload("popopx:/服务号?x=1&y=2", sid).split("&")) == 2)
    check("qr_control_char_in_address_cannot_split_the_line",
          "\n" not in build_qr_payload("popopx:/a\nsession=forged", sid)
          and build_qr_payload("popopx:/a\nsession=forged", sid).count("session=") == 1)
    raises("qr_refuses_empty_address", SsoRequestError, build_qr_payload, "", sid)
    raises("qr_refuses_overlong_address", SsoRequestError, build_qr_payload, "popopx:/" + "a" * 3000, sid)
    raises("qr_refuses_malformed_session_id", SsoRequestError, build_qr_payload, "popopx:/x", "short")
    check("qr_error_when_unconfigured_is_503_not_400",
          _error_status(build_qr_payload, "", sid) == 503)

    # ── 12.5 the guards, in characters ────────────────────────────────────────
    check("sanitize_strips_control_and_collapses",
          sanitize_text("  a\n\tb  c ", field="name", limit=240, label="a field value",
                        constant="maximumValueCharacters") == "a b c")
    check("sanitize_default_when_empty",
          sanitize_text(None, field="name", limit=240, label="l", constant="c", default="d") == "d")
    check("sanitize_number_becomes_text",
          sanitize_text(42, field="name", limit=240, label="l", constant="c") == "42")
    check("sanitize_accepts_exactly_the_limit",
          len(sanitize_text("n" * 240, field="name", limit=240, label="a field value",
                            constant="maximumValueCharacters")) == 240)
    names = {}
    for field, limit, label, constant in (
        ("name", EcoLimits.field_value_chars, "a field value", "maximumValueCharacters"),
        ("scope", EcoLimits.field_value_chars, "a field value", "maximumValueCharacters"),
        ("nonce", EcoLimits.payload_chars, "an action payload", "maximumPayloadCharacters"),
        ("service_uri", EcoLimits.url_chars, "a URL", "maximumURLCharacters"),
    ):
        try:
            sanitize_text("x" * (limit + 1), field=field, limit=limit, label=label, constant=constant)
            check("sanitize_rejects_%s_over_limit" % field, False)
        except SsoRequestError as exc:
            names[field] = exc
            check("sanitize_rejects_%s_over_limit" % field,
                  exc.status == 400 and exc.code == "field_too_long" and str(limit) in exc.detail
                  and constant in exc.detail and exc.extra.get("limit") == limit
                  and exc.extra.get("length") == limit + 1)
    check("sanitize_rejects_nonstring",
          _error_code(sanitize_text, [], field="name", limit=240, label="l", constant="c") == "invalid_field"
          and _error_status(sanitize_text, object(), field="name", limit=240, label="l", constant="c") == 400)
    check("validate_rp_uri_accepts_https",
          validate_rp_uri("https://rp.example.com:8443/sso/start?state=abc") ==
          "https://rp.example.com:8443/sso/start?state=abc")
    for bad in ("javascript:alert(1)", "data:text/html,<script>", "alert(1)", "//rp.example.com/x",
                "ftp://rp.example.com", "https://", "", None, "  ", "POPPOPX://x"):
        check("validate_rp_uri_rejects_%r" % (bad,),
              _raises_sso(validate_rp_uri, bad))
    check("validate_rp_uri_rejects_overlong",
          _raises_sso(validate_rp_uri, "https://e.com/" + "p" * (EcoLimits.url_chars + 1)))
    check("origin_strips_path_and_query",
          origin_of("https://RP.Example.com:8443/sso/start?state=abc") == "https://rp.example.com:8443")
    check("origin_of_relative_is_harmless", origin_of("no-scheme-here") == "no-scheme-here")

    # ── 12.6 the cards, against the client's own sanity rules ─────────────────
    now = 1_700_000_000_000
    expires = expiry_deadline(now, ttl_seconds)
    card = confirm_card(sid, rp_name="Acme 云服务", rp_origin="https://acme.example.com",
                        scope="openid profile", now=now, expires_at_ms=expires)
    check("card_has_the_required_wire_keys", card.get("id") and card.get("v") and card.get("title") and "ut" in card)
    check("card_style_is_security", card["v"] == "security" and card["v"] in CARD_STYLES)
    check("card_id_within_limit", len(card["id"]) <= EcoLimits.card_id_chars)
    check("card_title_within_limit", len(card["title"]) <= EcoLimits.card_title_chars)
    check("card_body_within_limit", len(card.get("body", "")) <= EcoLimits.card_body_chars)
    check("card_field_count_within_limit", 0 < len(card["fields"]) <= EcoLimits.max_fields)
    check("card_shows_only_rp_scope_time",
          [f["k"] for f in card["fields"]] == ["登录方", "授权范围", "时间"]
          and len(card["fields"]) == 3)
    check("card_field_labels_within_limit", all(len(f["k"]) <= EcoLimits.field_label_chars for f in card["fields"]))
    check("card_field_values_within_limit", all(len(f["v"]) <= EcoLimits.field_value_chars for f in card["fields"]))
    check("card_progress_shape",
          card["progress"]["l"] and 0 <= card["progress"]["p"] <= 100 and card["progress"]["d"] == "等待确认")
    check("card_expires_at_the_session_deadline", card["et"] == expires and card["et"] > 0)
    check("card_updated_at_is_milliseconds", card["ut"] == now and card["ut"] > 10 ** 12)
    actions = card["actions"]
    check("card_action_count_within_limit", 1 <= len(actions) <= EcoLimits.max_actions)
    check("card_action_kinds_are_known", all(a["action"] in ACTION_KINDS for a in actions))
    check("card_action_kind_none_is_never_sent", all(a["action"] != "none" for a in actions))
    check("card_action_ids_unique", len({a["id"] for a in actions}) == len(actions))
    check("card_action_titles_within_limit",
          all(0 < len(a["title"]) <= EcoLimits.field_label_chars for a in actions))
    check("card_action_payloads_within_limit",
          all(len(a.get("payload", "")) <= EcoLimits.payload_chars for a in actions))
    check("card_confirm_payload_parses", claims(actions[0]["payload"]) and split_callback(actions[0]["payload"])[0] == "confirm")
    check("card_cancel_payload_parses", claims(actions[1]["payload"]) and split_callback(actions[1]["payload"])[0] == "cancel")
    check("card_confirm_asks_first", actions[0].get("confirm") is True)
    check("card_styles_are_valid", all(a["style"] in ACTION_STYLES for a in actions))
    check("card_carries_no_device_ip_or_geo",
          not any(key in card for key in ("device", "ip", "geo", "location", "ua", "contact_id"))
          and "iPhone" not in json.dumps(card, ensure_ascii=False)
          and "127.0.0.1" not in json.dumps(card))
    check("card_names_no_pii", "pairwise" not in json.dumps(card, ensure_ascii=False).lower())
    worst = confirm_card("z" * 64, rp_name="n" * 240, rp_origin="https://" + "o" * 200,
                         scope="s" * 240, now=now, expires_at_ms=expires)
    check("worst_case_card_is_still_client_legal",
          len(worst["id"]) <= EcoLimits.card_id_chars
          and len(worst["title"]) <= EcoLimits.card_title_chars
          and len(worst["body"]) <= EcoLimits.card_body_chars
          and all(len(f["v"]) <= EcoLimits.field_value_chars for f in worst["fields"])
          and all(len(a["payload"]) <= EcoLimits.payload_chars for a in worst["actions"]))
    check("worst_case_frame_would_fit_the_client",
          len(json.dumps({"cards": [worst]}, ensure_ascii=False)) <= EcoLimits.frame_chars)

    terminal_bodies = {}
    for outcome in (OUTCOME_GRANTED, OUTCOME_CANCELLED, OUTCOME_EXPIRED, OUTCOME_FAILED):
        payload = terminal_payload(sid, outcome=outcome, now=now, rp_name="Acme")
        rebuilt = build_card(card_id_for(sid), payload["title"], style="security",
                             body=payload["body"], fields=payload["fields"],
                             progress=payload["progress"], actions=payload["actions"],
                             updated_at_ms=now, expires_at_ms=payload["expires_at_ms"])
        terminal_bodies[outcome] = rebuilt
        check("terminal_%s_is_client_legal" % outcome,
              len(rebuilt["title"]) <= EcoLimits.card_title_chars
              and len(rebuilt["body"]) <= EcoLimits.card_body_chars
              and len(rebuilt["fields"]) <= EcoLimits.max_fields
              and 1 <= len(rebuilt["actions"]) <= EcoLimits.max_actions
              and all(a["action"] != "none" for a in rebuilt["actions"]))
        check("terminal_%s_replaces_the_action_array" % outcome, bool(payload["actions"]))
        check("terminal_%s_is_read_only_on_the_phone" % outcome, payload["expires_at_ms"] <= now)
        check("terminal_%s_keeps_the_same_card_id" % outcome, rebuilt["id"] == card_id_for(sid))
        check("terminal_%s_carries_no_credential" % outcome,
              token_1 not in json.dumps(rebuilt) and "token" not in json.dumps(rebuilt).lower())
    check("terminal_granted_detail_is_已授权",
          terminal_bodies[OUTCOME_GRANTED]["progress"]["d"] == "已授权")
    raises("terminal_rejects_unknown_outcome", ValueError, terminal_payload, sid, outcome="shrug", now=now)

    # ── 12.7 the verification answer ──────────────────────────────────────────
    shapes = {tuple(sorted(verify_failure(code).keys())) for code in VERIFY_REASON_CODES}
    check("all_six_failure_codes_exist", len(VERIFY_REASON_CODES) == 6)
    check("failure_shape_is_identical", shapes == {("detail", "ok", "reason")} and failure_body_has_one_shape())
    check("failure_status_is_identical", VERIFY_FAILURE_STATUS == 403)
    check("failure_reasons_are_distinct", len(set(VERIFY_REASON_CODES)) == 6)
    check("failure_details_are_generic",
          all(isinstance(body["detail"], str) and body["detail"] and "token" not in body["detail"]
              for body in [verify_failure(code) for code in VERIFY_REASON_CODES]))
    check("failure_on_unknown_code_is_still_the_same_shape",
          tuple(sorted(verify_failure("nonsense").keys())) == _DETAIL_KEYS)
    check("success_shape_is_uid_and_scope_only",
          tuple(sorted(verify_success("uid", "openid").keys())) == ("ok", "pairwise_uid", "scope"))
    check("success_carries_no_token", token_1 not in json.dumps(verify_success("uid", "openid")))

    # ── 12.8 the rows, against the real schema ───────────────────────────────
    #
    # A temporary file and the production ``_DDL``, not a hand-written table: the
    # CHECK constraint on ``state`` is the single most likely way this module
    # could be wrong, and a stub schema would agree with a wrong guess.
    import os
    import shutil
    import tempfile

    from app.agent_bridge import InboundCallback, InboundMessage
    from app.database import Database
    from app.plugins import PluginDeps, plugin_for_id

    tmp_dir = tempfile.mkdtemp(prefix="popopx-sso-selftest-")
    db = Database(os.path.join(tmp_dir, "gateway.db"), timeout_seconds=5.0)
    try:
        with db.transaction(immediate=True) as conn:
            conn.execute(
                "INSERT INTO service_identity (id, address, service_id, display_name, created_at_ms, updated_at_ms) "
                "VALUES (1, ?, ?, ?, ?, ?)",
                ("popopx:/SELFTESTSERVICEADDR", "selftest-service", "自测服务号", now, now),
            )
        check("service_address_is_read_from_the_identity_row",
              service_address_from_db(db) == "popopx:/SELFTESTSERVICEADDR")
        check("service_address_of_an_unbuilt_database_is_empty",
              service_address_from_db(_NoTableDb()) == "")
        _add_contact(db, 9001, "uid-9001", secret_hex="ab" * 32)
        _add_contact(db, 9002, "uid-9002")
        _add_contact(db, 9100, "uid-9100")
        _add_contact(db, 9200, "uid-9200")
        _add_contact(db, 9300, "uid-9300")
        check("pairwise_uid_is_read_from_the_contacts_row", pairwise_uid_from_db(db, 9001) == "uid-9001")
        check("pairwise_uid_of_an_unknown_contact_is_empty", pairwise_uid_from_db(db, 999999) == "")
        check("pairwise_uid_of_a_broken_database_is_empty", pairwise_uid_from_db(_NoTableDb(), 1) == "")

        for accepted in DB_STATES:
            check("schema_accepts_state_%s" % accepted, _insert_state_is_ok(db, accepted))
        for rejected in ("confirmed", "delivered", "cancelled", "approved ", "APPROVED", ""):
            check("schema_rejects_state_%r" % rejected, not _insert_state_is_ok(db, rejected))
        check("the_briefs_state_words_are_not_the_schemas",
              all(word not in DB_STATES for word in ("confirmed", "delivered", "cancelled")))

        # `Database.execute` is `lastrowid if lastrowid else rowcount`, so a claim
        # written against it is comparing a row id to a row count depending on the
        # statement. Every claim in this module reads `cursor.rowcount` instead.
        with db.transaction(immediate=True) as conn:
            insert_probe = conn.execute(
                "INSERT INTO sso_sessions (session_id, state, created_at_ms, expires_at_ms) "
                "VALUES (?, ?, ?, ?)", ("probe-1", DB_PENDING, now, now + 60_000)
            )
        check("db_execute_return_on_insert_is_a_rowid_not_a_count",
              insert_probe.lastrowid is not None and insert_probe.rowcount == 1)
        with db.transaction(immediate=True) as conn:
            update_no_match = conn.execute("UPDATE sso_sessions SET state = ? WHERE session_id = ?",
                                           (DB_SCANNED, "no-such-session"))
        check("conditional_update_rowcount_is_zero_when_nothing_matched", update_no_match.rowcount == 0)

        mint_stamp = now + 10_000
        insert_session(
            db, session_id="rowsession00000000000001", rp_uri="https://rp.example.com/start?state=SECRETQUERY",
            rp_name="Example RP", scope="openid", nonce="n-1", created_at_ms=mint_stamp,
            expires_at_ms=expiry_deadline(mint_stamp, 120),
        )
        row = load_session(db, "rowsession00000000000001")
        check("insert_and_load_roundtrip", row is not None and row["state"] == DB_PENDING
              and row["rp_name"] == "Example RP" and row["nonce"] == "n-1")
        check("a_minted_row_holds_no_source_identifier",
              set(row.keys()) == {"session_id", "state", "rp_uri", "rp_name", "scope", "nonce", "card_id",
                                  "contact_id", "pairwise_uid", "created_at_ms", "scanned_at_ms",
                                  "confirmed_at_ms", "expires_at_ms", "token_hash"}
              and row["card_id"] is None and row["contact_id"] is None and row["token_hash"] is None
              and row["pairwise_uid"] is None)
        check("load_of_an_unknown_session_is_none", load_session(db, "rowsession-none") is None)
        check("live_session_count_counts_only_unretired", live_session_count(db, mint_stamp) >= 2)

        ok, reason, _ = claim_scan(db, "rowsession-none", 9001, "sso:x", mint_stamp)
        check("scan_of_unknown_session_is_unknown", (ok, reason) == (False, "unknown_session"))
        ok, reason, scanned_row = claim_scan(db, "rowsession00000000000001", 9001,
                                             card_id_for("rowsession00000000000001"), mint_stamp)
        check("scan_binds_the_contact", ok and reason == "scanned"
              and scanned_row["contact_id"] == 9001 and scanned_row["state"] == DB_SCANNED)
        check("scan_writes_the_card_id_and_the_timestamp",
              scanned_row["card_id"] == card_id_for("rowsession00000000000001")
              and scanned_row["scanned_at_ms"] == mint_stamp)
        ok, reason, _ = claim_scan(db, "rowsession00000000000001", 9002, "sso:x", mint_stamp)
        check("a_second_contact_cannot_take_over_a_session", (ok, reason) == (False, "other_contact"))
        ok, reason, _ = claim_scan(db, "rowsession00000000000001", 9001, "sso:x", mint_stamp)
        check("the_same_contact_may_rescan", (ok, reason) == (True, "replay"))
        check("rescan_did_not_move_the_state", load_session(db, "rowsession00000000000001")["state"] == DB_SCANNED)

        check("revert_scan_makes_the_second_scan_real", revert_scan(db, "rowsession00000000000001", 9001, mint_stamp))
        check("revert_undoes_the_binding",
              (lambda r: r["state"] == DB_PENDING and r["contact_id"] is None and r["card_id"] is None
               and r["scanned_at_ms"] is None)(load_session(db, "rowsession00000000000001")))
        check("revert_is_refused_for_the_wrong_contact",
              not revert_scan(db, "rowsession00000000000001", 9002, mint_stamp))
        claim_scan(db, "rowsession00000000000001", 9001, card_id_for("rowsession00000000000001"), mint_stamp)

        ok, reason, _ = grant_session(db, "rowsession00000000000001", contact_id=9002,
                                      pairwise_uid="uid-2", seal="sha256$eco$" + "0" * 64,
                                      now=mint_stamp, deadline_ms=mint_stamp + 60_000)
        check("grant_by_a_contact_that_did_not_scan_is_refused", (ok, reason) == (False, "other_contact"))
        token = derive_token(key_a, "rowsession00000000000001", "uid-9001", "openid")
        seal = seal_token(token, _KEY_SOURCE_ECO)
        # What `handle_inbound` actually passes. The tap lands one second before
        # the QR's own deadline, which is the case the grace exists for: without
        # it the credential would already be dead by the time the browser's next
        # poll could carry it.
        grant_now = mint_stamp + 119_000
        grant_deadline = confirmed_deadline(expiry_deadline(mint_stamp, 120), grant_now, 2000)
        ok, reason, granted = grant_session(db, "rowsession00000000000001", contact_id=9001,
                                            pairwise_uid="uid-9001", seal=seal, now=grant_now,
                                            deadline_ms=grant_deadline)
        check("confirm_moves_scanned_to_approved", ok and reason == "granted"
              and granted["state"] == DB_APPROVED and granted["pairwise_uid"] == "uid-9001")
        check("confirm_records_the_credential_and_the_clock",
              granted["token_hash"] == seal and granted["confirmed_at_ms"] == grant_now
              and granted["expires_at_ms"] == grant_deadline)
        check("confirm_extends_the_deadline", granted["expires_at_ms"] > expiry_deadline(mint_stamp, 120))
        check("a_last_second_confirm_is_still_verifiable",
              grant_deadline > grant_now and grant_deadline - grant_now == token_grace_ms(2000))
        ok, reason, again = grant_session(db, "rowsession00000000000001", contact_id=9001,
                                          pairwise_uid="uid-other", seal=seal_token("other", _KEY_SOURCE_ECO),
                                          now=mint_stamp + 1, deadline_ms=mint_stamp + 60_000)
        check("a_second_confirm_tap_is_not_a_second_credential",
              (ok, reason) == (True, "already_granted")
              and again["token_hash"] == seal and again["pairwise_uid"] == "uid-9001")

        ok, reason, data = redeem_session(db, "rowsession00000000000001", "ff" * 32, mint_stamp + 2)
        check("wrong_token_is_bad_token", (ok, reason) == (False, REASON_BAD_TOKEN))
        check("wrong_token_changes_nothing",
              load_session(db, "rowsession00000000000001")["state"] == DB_APPROVED)
        ok, reason, data = redeem_session(db, "rowsession00000000000001", token, mint_stamp + 2)
        check("right_token_delivers", ok and reason == "delivered"
              and data["pairwise_uid"] == "uid-9001" and data["scope"] == "openid")
        check("delivery_consumes_the_row",
              load_session(db, "rowsession00000000000001")["state"] == DB_CONSUMED)
        check("delivery_destroys_the_credential",
              load_session(db, "rowsession00000000000001")["token_hash"] is None)
        check("the_same_token_cannot_be_redeemed_twice",
              redeem_session(db, "rowsession00000000000001", token, mint_stamp + 3)
              == (False, REASON_ALREADY_DELIVERED, {}))
        check("a_different_token_cannot_either",
              redeem_session(db, "rowsession00000000000001", "00" * 32, mint_stamp + 3)[1]
              == REASON_ALREADY_DELIVERED)
        check("redeem_of_unknown_session_answers_unknown",
              redeem_session(db, "no-such-session-at-all", token, mint_stamp)[1] == REASON_UNKNOWN_SESSION)

        ok, reason, _ = refuse_session(db, "rowsession00000000000001", contact_id=9001, now=mint_stamp + 4)
        check("a_delivered_session_cannot_be_cancelled", (ok, reason) == (False, "already_delivered"))

        # An approved-but-unredeemed credential is revocable, and revocation must
        # actually kill it rather than leave a live token behind the row.
        insert_session(db, session_id="revokesession00000000001", rp_uri="https://rp.example.com",
                       rp_name="RP", scope="openid", nonce="", created_at_ms=mint_stamp,
                       expires_at_ms=expiry_deadline(mint_stamp, 120))
        claim_scan(db, "revokesession00000000001", 9100, card_id_for("revokesession00000000001"), mint_stamp)
        revoke_token = derive_token(key_a, "revokesession00000000001", "uid-9100", "openid")
        grant_session(db, "revokesession00000000001", contact_id=9100, pairwise_uid="uid-9100",
                      seal=seal_token(revoke_token, _KEY_SOURCE_ECO), now=mint_stamp,
                      deadline_ms=mint_stamp + 60_000)
        ok, reason, _ = refuse_session(db, "revokesession00000000001", contact_id=None, now=mint_stamp + 1)
        check("rp_cancel_revokes_an_unredeemed_credential", ok and reason == "revoked")
        check("revocation_wipes_the_seal",
              load_session(db, "revokesession00000000001")["token_hash"] is None)
        check("a_revoked_credential_is_refused_as_cancelled",
              redeem_session(db, "revokesession00000000001", revoke_token, mint_stamp + 2)[1] == REASON_CANCELLED)
        check("cancel_is_idempotent", refuse_session(db, "revokesession00000000001", now=mint_stamp + 3)[:2]
              == (True, "already_cancelled"))
        check("cancel_of_unknown_session_is_unknown",
              refuse_session(db, "nothing-here-0000000000000", now=mint_stamp)[1] == "unknown_session")

        # Lazy expiry, at the boundary, end to end.
        insert_session(db, session_id="expirysession00000000001", rp_uri="https://rp.example.com",
                       rp_name="RP", scope="openid", nonce="", created_at_ms=mint_stamp,
                       expires_at_ms=mint_stamp + 30_000)
        check("one_ms_before_the_deadline_is_still_scannable",
              claim_scan(db, "expirysession00000000001", 9200, "sso:x", mint_stamp + 30_000 - 1)[1] == "scanned")
        late = mint_stamp + 30_000 + 1
        ok, reason, _ = claim_scan(db, "expirysession00000000001", 9200, "sso:x", late)
        check("one_ms_after_the_deadline_is_expired", (ok, reason) == (False, "expired"))
        check("the_expiry_is_persisted_by_the_read",
              load_session(db, "expirysession00000000001")["state"] == DB_EXPIRED)
        check("persist_expiry_is_then_a_no_op", not persist_expiry(db, "expirysession00000000001", late))
        check("an_expired_session_cannot_be_confirmed",
              grant_session(db, "expirysession00000000001", contact_id=9200, pairwise_uid="u",
                            seal="sha256$eco$" + "1" * 64, now=late, deadline_ms=late + 1)[1] == "expired")
        check("an_expired_credential_cannot_be_redeemed",
              redeem_session(db, "expirysession00000000001", token, late)[1] == REASON_EXPIRED)
        insert_session(db, session_id="pendingonlysession0000001", rp_uri="https://rp.example.com",
                       rp_name="RP", scope="openid", nonce="", created_at_ms=mint_stamp,
                       expires_at_ms=expiry_deadline(mint_stamp, 120))
        check("confirm_without_a_scan_is_refused",
              grant_session(db, "pendingonlysession0000001", contact_id=9300, pairwise_uid="u",
                            seal="sha256$eco$" + "2" * 64, now=mint_stamp, deadline_ms=mint_stamp + 1)[1]
              == "pending_scan")

        audit = audit_rows(db, 100, mint_stamp)
        check("audit_lists_the_sessions", len(audit) >= 4)
        check("audit_never_carries_a_credential",
              all("token_hash" not in item and "card_id" not in item and "contact_id" not in item for item in audit))
        check("audit_strips_the_rp_query_string",
              all("SECRETQUERY" not in json.dumps(item) for item in audit)
              and any(item["rp_origin"] == "https://rp.example.com" for item in audit))
        check("audit_answers_in_product_vocabulary",
              {item["state"] for item in audit} <= set(LOGICAL_STATES))
        check("audit_reports_the_stored_vocabulary_too",
              all(item["stored_state"] in DB_STATES for item in audit))
        check("audit_limit_is_applied", len(audit_rows(db, 2, mint_stamp)) == 2)

        # The HTTP-facing helpers, with the database but without FastAPI.
        poll = poll_session(_stub_deps(db), "rowsession00000000000001", now=mint_stamp + 5)
        check("poll_answers_with_state_only",
              set(poll.keys()) == {"ok", "session_id", "state", "expires_at_ms", "poll_interval_ms",
                                   "scanned", "approved"}
              and poll["state"] == LOGICAL_DELIVERED and poll["approved"] is True)
        check("poll_leaks_neither_identity_nor_credential",
              not any(key in poll for key in ("pairwise_uid", "token", "contact_id", "card_id", "rp_uri")))
        check("poll_of_an_unknown_session_is_404",
              _error_status(poll_session, _stub_deps(db), "not-a-session", now=mint_stamp) == 404)
        check("poll_reports_a_persisted_expiry_as_expired",
              poll_session(_stub_deps(db), "expirysession00000000001", now=mint_stamp)["state"]
              == LOGICAL_EXPIRED)
        insert_session(db, session_id="computedexpiry000000000001", rp_uri="https://rp.example.com",
                       rp_name="RP", scope="openid", nonce="", created_at_ms=mint_stamp - 60_000,
                       expires_at_ms=mint_stamp - 1)
        check("a_deadline_that_passed_is_still_stored_as_pending",
              load_session(db, "computedexpiry000000000001")["state"] == DB_PENDING)
        check("poll_answers_expiry_from_the_clock",
              poll_session(_stub_deps(db), "computedexpiry000000000001", now=mint_stamp)["state"]
              == LOGICAL_EXPIRED)
        check("poll_lands_the_expiry_it_computed_in_the_column",
              load_session(db, "computedexpiry000000000001")["state"] == DB_EXPIRED)
        check("cancel_route_refuses_a_delivered_session",
              _error_status(cancel_session, _stub_deps(db), "rowsession00000000000001", now=mint_stamp + 6) == 409)
        check("cancel_route_answers_unknown_with_404",
              _error_status(cancel_session, _stub_deps(db), "not-a-session", now=mint_stamp) == 404)
    finally:
        db.close_all()
        shutil.rmtree(tmp_dir, ignore_errors=True)

    # ── 12.9 the phone-facing half, end to end ───────────────────────────────
    #
    # The real ``handle_inbound``, the real ``InboundMessage``, and the real
    # ``parse_inbound_text`` deciding which kind arrives: the prefix contract is
    # only worth trusting once something on both sides has been exercised.
    import asyncio

    from app.agent_bridge import parse_inbound_text

    tmp_in = tempfile.mkdtemp(prefix="popopx-sso-inbound-")
    db3 = Database(os.path.join(tmp_in, "gateway.db"), timeout_seconds=5.0)
    try:
        with db3.transaction(immediate=True) as conn:
            conn.execute(
                "INSERT INTO service_identity (id, address, service_id, display_name, created_at_ms, updated_at_ms) "
                "VALUES (1, ?, ?, ?, ?, ?)",
                ("popopx:/INBOUNDSELFTEST", "selftest-service", "自测服务号", now, now),
            )
        _add_contact(db3, 7001, "uid-7001", secret_hex="cd" * 32)
        _add_contact(db3, 7002, "uid-7002", secret_hex="ef" * 32)
        _add_contact(db3, 7003, "uid-7003")          # a follower with no eco session yet
        _add_contact(db3, 7004, "uid-7004")          # the same, for the no-key deployment

        def message(text: str, contact_id: int, direction: str = "rcv") -> Any:
            return InboundMessage(contact_id=contact_id, display_name="测试", item_id=11, text=text,
                                  callback=parse_inbound_text(text), direction=direction)

        cfg = _TestConfig(ttl=120)
        eco = _TestEco(session=_TestSession(7001, "uid-7001", "cd" * 32))
        billing = _TestBilling()
        deps3 = _stub_deps(db3, eco=eco, billing=billing, config=cfg)

        check("inbound_prefixes_are_the_ones_the_bridge_produces",
              parse_inbound_text("::SSO_SCAN::abc").kind == "sso_scan"
              and parse_inbound_text("::SSO_SCAN::abc").payload == "abc"
              and parse_inbound_text("::CB::" + CB_CONFIRM + "abc").kind == "card_callback"
              and parse_inbound_text("::CB::" + CB_CONFIRM + "abc").payload == CB_CONFIRM + "abc")

        minted = mint_session(deps3, {"uri": "https://rp.example.com/start?state=abc",
                                      "name": "Example RP", "scope": "openid"}, "203.0.113.7")
        sid3 = minted["session_id"]
        check("mint_places_the_service_address_in_the_qr",
              minted["qr_payload"].split("uri=", 1)[1].split("&", 1)[0] == percent_encode("popopx:/INBOUNDSELFTEST"))
        check("mint_qr_session_is_the_id_it_returns",
              minted["qr_payload"].endswith("&session=" + sid3))
        check("mint_advertises_the_scan_callback_kind", minted["callback_kind"] == "sso_scan")
        check("mint_bills_nothing", billing.calls == [] and eco.delivered == [])
        check("mint_stores_the_rp_uri_whole_and_the_ttl",
              load_session(db3, sid3)["rp_uri"] == "https://rp.example.com/start?state=abc"
              and minted["expires_at_ms"] - minted["created_at_ms"] == 120_000)

        handled = asyncio.run(handle_inbound(deps3, message("::SSO_SCAN::" + sid3, 7001)))
        check("scan_is_consumed", handled is True)
        check("scan_delivers_exactly_one_card", len(eco.delivered) == 1 and len(eco.updated) == 0)
        sent_card = eco.delivered[0]["card"]
        check("scan_card_is_a_security_card", sent_card["v"] == CARD_STYLE)
        check("scan_card_has_two_live_buttons", len(sent_card["actions"]) == 2
              and {a["action"] for a in sent_card["actions"]} == {"callback"})
        check("scan_card_expires_with_the_session", sent_card["et"] == load_session(db3, sid3)["expires_at_ms"])
        check("scan_card_topics_it", eco.delivered[0]["topic"] == "sso")
        bound = load_session(db3, sid3)
        check("scan_binds_the_scanner_and_the_card",
              bound["contact_id"] == 7001 and bound["card_id"] == card_id_for(sid3)
              and sent_card["id"] == card_id_for(sid3))
        check("scan_moves_the_row_to_scanned", bound["state"] == DB_SCANNED)
        check("a_scanned_row_holds_no_credential", bound["token_hash"] is None and bound["pairwise_uid"] is None)
        check("scan_bills_nothing", billing.calls == [])

        check("unknown_session_scan_is_not_mine",
              asyncio.run(handle_inbound(deps3, message("::SSO_SCAN::nosuchsession00000000000", 7001))) is False)
        check("an_unclaimed_scan_made_no_card", len(eco.delivered) == 1)
        check("empty_scan_is_not_mine", asyncio.run(handle_inbound(deps3, message("::SSO_SCAN::", 7001))) is False)
        check("spaced_scan_is_not_mine",
              asyncio.run(handle_inbound(deps3, message("::SSO_SCAN::a b", 7001))) is False)
        check("forged_nested_marker_is_not_mine",
              asyncio.run(handle_inbound(deps3, message("::SSO_SCAN::x::CB::y", 7001))) is False)
        check("outbound_echo_is_not_mine",
              asyncio.run(handle_inbound(deps3, message("::SSO_SCAN::" + sid3, 7001, direction="snd"))) is False)
        check("foreign_card_callback_is_not_mine",
              asyncio.run(handle_inbound(deps3, message("::CB::poll:vote:2:1", 7001))) is False)
        check("plain_chat_is_not_mine", asyncio.run(handle_inbound(deps3, message("你好", 7001))) is False)

        token3 = derive_token(bytes.fromhex("cd" * 32), sid3, "uid-7001", "openid")
        asyncio.run(handle_inbound(deps3, message("::CB::" + CB_CANCEL + sid3, 7002)))
        check("a_cancel_tap_from_a_different_contact_changes_nothing_but_closes", True)
        # (the cancel above belongs to 7001's session; 7002 does not own it)
        check("foreign_cancel_tap_did_not_cancel", load_session(db3, sid3)["state"] == DB_SCANNED)

        confirmed = asyncio.run(handle_inbound(deps3, message("::CB::" + CB_CONFIRM + sid3, 7001)))
        granted_row = load_session(db3, sid3)
        check("confirm_is_consumed", confirmed is True)
        check("confirm_mints_from_the_followers_own_session_secret",
              granted_row["token_hash"] == seal_token(token3, _KEY_SOURCE_ECO))
        check("confirm_stores_only_the_seal", token3 not in json.dumps(dict(granted_row)))
        check("confirm_binds_the_pairwise_uid", granted_row["pairwise_uid"] == "uid-7001")
        check("confirm_moves_the_row_to_approved", granted_row["state"] == DB_APPROVED)
        check("confirm_bills_the_plugin_meter_exactly_once",
              len(billing.calls) == 1 and billing.calls[0]["meter"] == "sso_login")
        check("confirm_bill_is_idempotent_on_the_session",
              billing.calls[0]["idempotency_key"] == "sso:" + sid3 and billing.calls[0]["ref"] == sid3
              and billing.calls[0]["contact_id"] == 7001)
        check("confirm_bill_meta_holds_no_query_or_token",
              billing.calls[0]["meta"] == {"rp": "https://rp.example.com", "scope": "openid"})
        check("confirm_closed_the_card_once", len(eco.updated) == 1)
        closing = eco.updated[0]
        check("closed_card_addresses_the_same_card", closing["card_id"] == card_id_for(sid3)
              and closing["contact_id"] == 7001)
        check("closed_card_progress_is_已授权", closing["progress"]["d"] == "已授权" and closing["progress"]["p"] == 100)
        check("closed_card_replaces_the_buttons_with_one", len(closing["actions"]) == 1)
        check("closed_card_button_carries_no_grant", closing["actions"][0]["payload"] == CB_NOOP + sid3)
        check("closed_card_is_read_only_on_the_phone", closing["expires_at_ms"] <= now_ms())

        asyncio.run(handle_inbound(deps3, message("::CB::" + CB_CONFIRM + sid3, 7001)))
        check("a_second_confirm_tap_bills_nothing", len(billing.calls) == 1)
        check("a_second_confirm_tap_mints_no_second_credential",
              load_session(db3, sid3)["token_hash"] == granted_row["token_hash"])
        check("a_second_confirm_tap_only_re_closes_the_card", len(eco.updated) == 2)

        released = poll_session(deps3, sid3, authorized=True)
        check("an_authenticated_poll_carries_the_credential", released.get("token") == token3)
        check("an_unauthenticated_poll_carries_nothing", "token" not in poll_session(deps3, sid3))
        check("an_authenticated_poll_still_carries_no_identity",
              all(key not in released for key in ("pairwise_uid", "contact_id", "rp_uri", "token_hash")))
        ok, reason, data = redeem_session(db3, sid3, token3, now_ms())
        check("the_released_credential_redeems", ok and data["pairwise_uid"] == "uid-7001"
              and data["scope"] == "openid" and set(data.keys()) <= {"pairwise_uid", "scope", "session_id", "rp_name"})
        check("a_redeemed_session_releases_nothing",
              "token" not in poll_session(deps3, sid3, authorized=True))
        check("a_redeemed_credential_cannot_be_used_twice",
              redeem_session(db3, sid3, token3, now_ms())[1] == REASON_ALREADY_DELIVERED)
        check("the_audit_trail_survives_the_whole_round_trip",
              any(item["session_id"] == sid3 and item["state"] == LOGICAL_DELIVERED
                  for item in audit_rows(db3, 50, now_ms())))

    finally:
        db3.close_all()
        shutil.rmtree(tmp_in, ignore_errors=True)

    # ── 12.10 the paths that go wrong ────────────────────────────────────────
    tmp_bad = tempfile.mkdtemp(prefix="popopx-sso-failure-")
    db4 = Database(os.path.join(tmp_bad, "gateway.db"), timeout_seconds=5.0)
    try:
        with db4.transaction(immediate=True) as conn:
            conn.execute(
                "INSERT INTO service_identity (id, address, service_id, display_name, created_at_ms, updated_at_ms) "
                "VALUES (1, ?, ?, ?, ?, ?)",
                ("popopx:/FAILUREADDR", "selftest-service", "自测服务号", now, now),
            )
        _add_contact(db4, 8001, "uid-8001", secret_hex="ab" * 32)
        _add_contact(db4, 8002, "uid-8002", secret_hex="cd" * 32)
        _add_contact(db4, 8003, "uid-8003")
        _add_contact(db4, 8004, "uid-8004")
        _add_contact(db4, 8005, "uid-8005", secret_hex="ef" * 32)

        def msg4(text: str, contact_id: int, item_id: int = 3) -> Any:
            # item_id is a parameter because the node deduplicates on
            # (contact, item): every call below that means a NEW message from the
            # phone has to carry a new number, or the plugin correctly ignores it
            # as a replay and the test measures the dedupe instead of the retry.
            return InboundMessage(contact_id=contact_id, display_name="测试", item_id=item_id, text=text,
                                  callback=parse_inbound_text(text), direction="rcv")

        def fresh(label: str) -> Tuple[Any, Any, Any, str]:
            eco_local = _TestEco(session=None)
            billing_local = _TestBilling()
            deps_local = _stub_deps(db4, eco=eco_local, billing=billing_local)
            made = mint_session(deps_local, {"uri": "https://rp.example.com/x", "name": label},
                                "198.51.100." + label[-1:])
            return deps_local, eco_local, billing_local, made["session_id"]

        # An expired QR must produce no card, no update, and no state machine
        # movement — the requirement that most directly protects a stale picture.
        deps_x, eco_x, bill_x, sid_x = fresh("expired0")
        eco_x.session = _TestSession(8001, "uid-8001", "ab" * 32)
        with db4.transaction(immediate=True) as conn:
            conn.execute("UPDATE sso_sessions SET expires_at_ms = ? WHERE session_id = ?",
                         (now_ms() - 1, sid_x))
        consumed = asyncio.run(handle_inbound(deps_x, msg4("::SSO_SCAN::" + sid_x, 8001)))
        check("an_expired_scan_is_still_consumed", consumed is True)
        check("an_expired_scan_delivers_no_card", eco_x.delivered == [])
        check("an_expired_scan_updates_no_card", eco_x.updated == [])
        check("an_expired_scan_bills_nothing", bill_x.calls == [])
        check("an_expired_scan_leaves_the_row_expired",
              load_session(db4, sid_x)["state"] == DB_EXPIRED)
        check("an_expired_scan_still_answers_the_scanner",
              eco_x.sent_text == [(8001, INBOUND_EXPIRED_TEXT)])
        check("a_confirm_tap_on_an_expired_session_changes_nothing",
              asyncio.run(handle_inbound(deps_x, msg4("::CB::" + CB_CONFIRM + sid_x, 8001))) is True
              and load_session(db4, sid_x)["state"] == DB_EXPIRED and bill_x.calls == [])

        # A card the node never accepted must not strand the session.
        deps_d, eco_d, bill_d, sid_d = fresh("deliver0")
        eco_d.session = _TestSession(8005, "uid-8005", "ef" * 32)
        eco_d.deliver_sent = False
        asyncio.run(handle_inbound(deps_d, msg4("::SSO_SCAN::" + sid_d, 8005)))
        reverted = load_session(db4, sid_d)
        check("an_undeliverable_card_reverts_to_pending",
              reverted["state"] == DB_PENDING and reverted["contact_id"] is None
              and reverted["card_id"] is None)
        check("an_undeliverable_card_records_the_attempt_it_failed",
              len(eco_d.delivered) == 1 and eco_d.delivered[0]["contact_id"] == 8005
              and eco_d.delivered[0]["topic"] == "sso")
        check("an_undeliverable_card_bills_nothing", bill_d.calls == [])
        eco_d.deliver_sent = True
        # A NEW item id: the phone scanned again, which is the whole point of the
        # revert above. With the same item id the node's dedupe would swallow it
        # and this would test the dedupe, not the retry — so the case is asserted
        # explicitly below instead of being hidden in a fixture default.
        asyncio.run(handle_inbound(deps_d, msg4("::SSO_SCAN::" + sid_d, 8005, item_id=4)))
        rescanned = load_session(db4, sid_d)
        check("the_rescan_after_a_failed_delivery_gets_the_card",
              len(eco_d.delivered) == 2 and rescanned["state"] == DB_SCANNED
              and rescanned["contact_id"] == 8005 and rescanned["card_id"])
        # A re-scan by the SAME contact is allowed by design (`claim_scan` calls
        # it a "replay": the delivery that failed is the retry the user is about to
        # attempt), so what has to be guaranteed is not "no second send" but "no
        # second CARD": the id is derived from the session, so the eco turns the
        # re-send into an in-place update of the card already on the phone.
        rescanned_card_id = str(eco_d.delivered[-1]["card"]["id"])
        asyncio.run(handle_inbound(deps_d, msg4("::SSO_SCAN::" + sid_d, 8005, item_id=5)))
        check("a_re_scan_by_the_same_scanner_updates_the_same_card",
              len(eco_d.delivered) == 3
              and str(eco_d.delivered[-1]["card"]["id"]) == rescanned_card_id == card_id_for(sid_d)
              and load_session(db4, sid_d)["state"] == DB_SCANNED)
        check("the_rescan_rebinds_the_session", load_session(db4, sid_d)["state"] == DB_SCANNED)

        # A gateway that mints its own card id must still be closable.
        deps_f, eco_f, bill_f, sid_f = fresh("forcedid")
        eco_f.session = _TestSession(8002, "uid-8002", "cd" * 32)
        eco_f.forced_card_id = "card-9999999999"
        asyncio.run(handle_inbound(deps_f, msg4("::SSO_SCAN::" + sid_f, 8002)))
        check("a_forced_card_id_is_stored", load_session(db4, sid_f)["card_id"] == "card-9999999999")
        asyncio.run(handle_inbound(deps_f, msg4("::CB::" + CB_CONFIRM + sid_f, 8002)))
        check("the_close_out_addresses_the_stored_card_id",
              eco_f.updated and eco_f.updated[-1]["card_id"] == "card-9999999999")

        # Fused billing: no login, no standing credential.
        deps_b, eco_b, _, sid_b = fresh("billfail0")
        eco_b.session = _TestSession(8001, "uid-8001", "ab" * 32)
        billing_b = _TestBilling(fail=BillingError("insufficient_credits", "no credits left", http_status=402))
        deps_b = _stub_deps(db4, eco=eco_b, billing=billing_b)
        asyncio.run(handle_inbound(deps_b, msg4("::SSO_SCAN::" + sid_b, 8001)))
        asyncio.run(handle_inbound(deps_b, msg4("::CB::" + CB_CONFIRM + sid_b, 8001)))
        after_bill = load_session(db4, sid_b)
        check("a_login_that_cannot_be_billed_is_not_granted",
              after_bill["state"] == DB_DENIED and after_bill["token_hash"] is None)
        # What has to be gone is the CREDENTIAL, not the pseudonym:
        # `pairwise_uid` is the gateway's own per-follower id, already stored in
        # the `sessions` table from the handshake, so erasing the copy on this row
        # would remove an audit link while removing no capability. Asserted
        # instead is that nothing can redeem a revoked login, whatever token is
        # presented — the state guard, not the column list.
        check("an_unbillable_grant_leaves_no_credential",
              after_bill["token_hash"] is None
              and after_bill["pairwise_uid"]
              and redeem_session(db4, sid_b, "00" * 32, now_ms())[0] is False)
        check("the_failed_bill_closes_the_card_as_unfinished",
              eco_b.updated[-1]["progress"]["d"] == "未完成")
        check("an_unbillable_credential_cannot_be_redeemed",
              redeem_session(db4, sid_b, derive_token(bytes.fromhex("ab" * 32), sid_b, "uid-8001", "openid"),
                             now_ms())[1] == REASON_CANCELLED)
        check("the_failed_bill_is_recorded_once", len(billing_b.calls) == 1)

        # An unexpected billing crash behaves the same way as a refusal.
        deps_c, eco_c, _, sid_c = fresh("crashbil")
        eco_c.session = _TestSession(8001, "uid-8001", "ab" * 32)
        deps_c = _stub_deps(db4, eco=eco_c, billing=_TestBilling(fail=RuntimeError("ledger is on fire")))
        asyncio.run(handle_inbound(deps_c, msg4("::SSO_SCAN::" + sid_c, 8001)))
        asyncio.run(handle_inbound(deps_c, msg4("::CB::" + CB_CONFIRM + sid_c, 8001)))
        check("a_billing_crash_does_not_grant_a_login",
              load_session(db4, sid_c)["state"] == DB_DENIED and eco_c.updated[-1]["progress"]["d"] == "未完成")

        # No key material at all: refuse, and say why in the log rather than in
        # a credential the gateway could never re-derive.
        deps_k, eco_k, bill_k, sid_k = fresh("nokey000")
        eco_k.session = None
        deps_k = _stub_deps(db4, eco=eco_k, billing=bill_k, config=_TestConfig(h5=""))
        asyncio.run(handle_inbound(deps_k, msg4("::SSO_SCAN::" + sid_k, 8004)))
        check("a_scan_still_gets_a_card_without_any_key", len(eco_k.delivered) == 1)
        asyncio.run(handle_inbound(deps_k, msg4("::CB::" + CB_CONFIRM + sid_k, 8004)))
        check("without_key_material_nothing_is_granted",
              load_session(db4, sid_k)["state"] == DB_SCANNED
              and load_session(db4, sid_k)["token_hash"] is None)
        check("without_key_material_nothing_is_billed", bill_k.calls == [])
        check("without_key_material_the_card_says_unfinished",
              eco_k.updated[-1]["progress"]["d"] == "未完成")

        # The gateway-key fallback, and the seal that records it.
        deps_h, eco_h, bill_h, sid_h = fresh("h5key000")
        eco_h.session = None                      # 8003 has a contacts row, no eco session
        asyncio.run(handle_inbound(deps_h, msg4("::SSO_SCAN::" + sid_h, 8003)))
        asyncio.run(handle_inbound(deps_h, msg4("::CB::" + CB_CONFIRM + sid_h, 8003)))
        h5_row = load_session(db4, sid_h)
        fallback_token = derive_token(
            _TestConfig().h5_server_secret.encode("utf-8"), sid_h, "uid-8003", "openid")
        check("the_fallback_still_grants", h5_row["state"] == DB_APPROVED)
        check("the_seal_records_which_key_was_used", h5_row["token_hash"] == seal_token(fallback_token, _KEY_SOURCE_H5))
        check("the_seal_names_the_fallback_loudly", "$h5srv$" in h5_row["token_hash"])
        check("the_fallback_credential_redeems", redeem_session(db4, sid_h, fallback_token, now_ms())[0] is True)

        # The identity that must never be invented: a follower with no pairwise uid.
        with db4.transaction(immediate=True) as conn:
            conn.execute("INSERT INTO contacts (contact_id, pairwise_uid, display_name, first_seen_ms, last_seen_ms) "
                         "VALUES (8009, NULL, ?, ?, ?)", ("无名", now, now))
        deps_n, eco_n, bill_n, sid_n = fresh("nuid0000")
        eco_n.session = None
        asyncio.run(handle_inbound(deps_n, msg4("::SSO_SCAN::" + sid_n, 8009)))
        asyncio.run(handle_inbound(deps_n, msg4("::CB::" + CB_CONFIRM + sid_n, 8009)))
        check("no_pairwise_uid_means_no_login",
              load_session(db4, sid_n)["state"] == DB_SCANNED and bill_n.calls == [])

        # A gate that has switched off or fused must not start a flow.
        deps_g, eco_g, bill_g, sid_g = fresh("gate0000")
        eco_g.session = _TestSession(8005, "uid-8005", "ef" * 32)
        deps_g = _stub_deps(db4, eco=eco_g, billing=bill_g, gate=_TestGate(False))
        asyncio.run(handle_inbound(deps_g, msg4("::SSO_SCAN::" + sid_g, 8005)))
        check("an_unusable_gate_delivers_no_card", eco_g.delivered == [])
        check("an_unusable_gate_still_answers_the_scanner", eco_g.sent_text != [])
        check("an_unusable_gate_moves_the_row_back",
              load_session(db4, sid_g)["state"] in (DB_PENDING, DB_SCANNED))

        # 取消 by the owner, and the noop button on a closed card.
        deps_cc, eco_cc, bill_cc, sid_cc = fresh("cancel00")
        eco_cc.session = _TestSession(8001, "uid-8001", "ab" * 32)
        asyncio.run(handle_inbound(deps_cc, msg4("::SSO_SCAN::" + sid_cc, 8001)))
        asyncio.run(handle_inbound(deps_cc, msg4("::CB::" + CB_CANCEL + sid_cc, 8001)))
        check("the_owner_cancel_closes_the_session",
              load_session(db4, sid_cc)["state"] == DB_DENIED
              and eco_cc.updated[-1]["progress"]["d"] == "已取消")
        check("a_cancelled_session_bills_nothing", bill_cc.calls == [])
        check("a_cancelled_session_releases_no_credential",
              "token" not in poll_session(deps_cc, sid_cc, authorized=True))
        check("a_cancel_button_press_is_idempotent",
              asyncio.run(handle_inbound(deps_cc, msg4("::CB::" + CB_CANCEL + sid_cc, 8001))) is True
              and load_session(db4, sid_cc)["state"] == DB_DENIED and bill_cc.calls == [])
        before_updates = len(eco_cc.updated)
        asyncio.run(handle_inbound(deps_cc, msg4("::CB::" + CB_NOOP + sid_cc, 8001)))
        check("a_noop_tap_changes_no_state",
              load_session(db4, sid_cc)["state"] == DB_DENIED and bill_cc.calls == [])
        check("a_noop_tap_only_re_states_the_card", len(eco_cc.updated) == before_updates + 1)
        check("a_noop_tap_on_an_unknown_session_is_swallowed",
              asyncio.run(handle_inbound(deps_cc, msg4("::CB::" + CB_NOOP + "unknownsession0000000000", 8001))) is True)
        check("a_malformed_callback_tail_is_not_mined_for_an_id",
              asyncio.run(handle_inbound(deps_cc, msg4("::CB::sso:confirm:", 8001))) is False)

        # Throttles.
        window = _MintWindow(limit=3, window_seconds=60.0)
        wkey = window.source_key("203.0.113.7")
        check("window_key_is_not_the_address", "203" not in wkey and len(wkey) == 32)
        check("window_key_is_per_process_salted", wkey != _MintWindow().source_key("203.0.113.7"))
        check("window_allows_up_to_the_limit",
              all(window.allow(wkey, t) for t in (0.0, 10.0, 20.0)))
        check("window_blocks_the_next_one", not window.allow(wkey, 30.0))
        check("window_is_per_source", window.allow("another-key", 30.0))
        check("window_retry_after_is_positive", window.retry_after_seconds(wkey, 30.0) > 0)
        check("window_slips_after_the_deadline", window.allow(wkey, 61.0))

        global _MINTS, MAX_LIVE_SESSIONS
        saved_limit, saved_live = _MINTS.limit, MAX_LIVE_SESSIONS
        try:
            _MINTS.limit = 2
            blocked = False
            for _ in range(3):
                try:
                    mint_session(_stub_deps(db4), {"uri": "https://rp.example.com"}, "198.51.100.250")
                except SsoRequestError as exc:
                    blocked = exc.status == 429 and exc.code == "rate_limited" and exc.extra.get("retry_after", 0) >= 1
                    break
            check("the_mint_route_throttles_one_source", blocked)
            check("a_throttled_mint_writes_no_row",
                  load_session(db4, "anything") is None
                  and live_session_count(db4, now_ms()) < MAX_LIVE_SESSIONS)
            MAX_LIVE_SESSIONS = 1
            flooded = False
            try:
                mint_session(_stub_deps(db4), {"uri": "https://rp.example.com"}, "198.51.100.251")
            except SsoRequestError as exc:
                flooded = exc.status == 429 and exc.code == "too_many_live_sessions"
            check("the_mint_route_has_a_global_live_ceiling", flooded)
        finally:
            _MINTS.limit = saved_limit
            MAX_LIVE_SESSIONS = saved_live

        # Size and shape guards on the open endpoint.
        deps_v = _stub_deps(db4)
        # An ABSENT uri is a missing field; a PRESENT bad one (`javascript:` below)
        # is an invalid uri. Two codes, both 400, and the distinction is the
        # operator-facing message: "uri is required" versus "the client keeps only
        # http(s) URLs". Merging them would make the first message a lie.
        check("mint_requires_a_uri_field", _error_code(mint_session, deps_v, {"name": "x"}, "1.1.1.1") == "invalid_field")
        check("mint_rejects_javascript_uri",
              _error_code(mint_session, deps_v, {"uri": "javascript:alert(1)"}, "1.1.1.1") == "invalid_uri")
        check("mint_rejects_an_overlong_name",
              _error_status(mint_session, deps_v, {"uri": "https://rp.example.com", "name": "n" * 300},
                            "1.1.1.1") == 400)
        check("mint_rejects_an_overlong_scope",
              _error_status(mint_session, deps_v, {"uri": "https://rp.example.com", "scope": "s" * 300},
                            "1.1.1.1") == 400)
        check("mint_rejects_a_non_string_name",
              _error_code(mint_session, deps_v, {"uri": "https://rp.example.com", "name": {"a": 1}},
                          "1.1.1.1") == "invalid_field")
        check("a_rejected_mint_writes_no_row", live_session_count(db4, now_ms()) >= 1)
        check("mint_defaults_the_name_to_the_rp_origin",
              load_session(db4, mint_session(deps_v, {"uri": "https://origin.example.com/deep/path?k=v"},
                                             "198.51.100.252")["session_id"])["rp_name"] == "https://origin.example.com")
        check("mint_defaults_the_scope",
              load_session(db4, mint_session(deps_v, {"uri": "https://origin.example.com"},
                                             "198.51.100.253")["session_id"])["scope"] == DEFAULT_SCOPE)
        check("a_minted_name_is_still_sanitized",
              "\n" not in (load_session(db4, mint_session(deps_v, {"uri": "https://o.example.com",
                                                                  "name": "Evil\n登录已确认"},
                                                 "198.51.100.254")["session_id"])["rp_name"]))
    finally:
        db4.close_all()
        shutil.rmtree(tmp_bad, ignore_errors=True)

    # SENTINEL-DB3
    return checks

