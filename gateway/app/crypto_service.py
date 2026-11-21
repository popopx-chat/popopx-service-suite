# Copyright (c) 2026 POPOPX (popopx.chat)
# SPDX-License-Identifier: AGPL-3.0-only
"""ECO protocol codec and cryptographic services for the POPOPX service suite.

Everything in this file exists to satisfy one property: a frame this gateway
produces must be accepted by the shipped iOS client, and a signature this
gateway checks must match what the client's `PopopxH5Launcher` actually signs.
The client never reports a protocol error to its user — `PopopxEcoParser.parse`
returns `nil` and the message is dropped silently — so every rule encoded here
is enforced *before sending*, and raised as `EcoValidationError` instead of
being emitted and lost.

Source of truth for each rule is cited as `file:line` in the nearest comment.
The files are in the sibling checkout at
`apps/ios/Shared/Features/ServiceAccount/`:

    PopopxEcoModels.swift            frame codec, limits, card/menu/action shapes
    ChannelKeyRotationManager.swift  the `popopx.channel.enc.v1` envelope
    PopopxH5Launcher.swift           the H5 URL signature

Two deliberate divergences from the written brief, both because the client code
contradicts it and the client code is what has to accept the bytes:

1. The brief specifies a `service_card` HMAC gate (`sig` over
   `cardId|title|creditsAmount|timestamp`, checked by the phone, gating
   `pay_credits`). The client has no such check: `ServiceCardBubbleView.issuerVerified`
   is `PopopxEcoSessionStore.hasSession(for: contactId)` — a *held session*, not a
   signature. `seal_card()` below still produces the signature, because it is
   genuinely useful as a server-side audit seal, but nothing here may claim the
   phone verified it. The requirement that `pay_credits` only works for a verified
   issuer is satisfied by sending `session_handshake` first.
2. The brief says the rotation envelope signs `epoch + nonce + ciphertext`.
   `ChannelKeyRotationManager.swift:26-29` rejects exactly that reading and
   `signingPreimage(channelId:)` (:146-157) defines the real preimage, which
   includes the channel id and a `0x7C` separator layout. `signing_preimage()`
   implements the client's version.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import re
import secrets
import sys
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

# ─────────────────────────────────────────────────────────────────────────────
# 1. Limits, measured from PopopxEcoLimits (PopopxEcoModels.swift:48-72)
#
# Every one of these counts CHARACTERS, not bytes: the client compares against
# `String.count`, which is a grapheme-cluster count. Python's len() on a str is
# the same unit for the BMP text this suite sends, so a frame that passes here
# passes there. This is also why `_compact_json` uses ensure_ascii=False — see
# its docstring for the failure mode that choice avoids.
# ─────────────────────────────────────────────────────────────────────────────

ECO_MARKER = "::POPOPX_ECO::"


class EcoLimits:
    frame_chars = 8192
    card_id_chars = 64
    card_title_chars = 120
    card_body_chars = 2000
    field_label_chars = 80
    field_value_chars = 240
    payload_chars = 512
    url_chars = 2048
    max_fields = 8
    max_actions = 4
    max_menu_items = 3
    max_menu_subitems = 5
    max_menu_title_chars = 80
    progress_percent_min = 0
    progress_percent_max = 100
    credits_min = 1
    credits_max = 100_000
    secret_hex_chars = 64          # 32 bytes, the client's ceiling
    pairwise_uid_chars = 128
    service_id_chars = 128
    style_version_min = 1
    max_epoch = 1_000_000          # PopopxEcoLimits.maximumEpoch
    max_ciphertext_bytes = 512 * 1024


class ChannelEnvelope:
    """`popopx.channel.enc.v1` constants (ChannelKeyRotationManager.swift:74-127)."""

    PROTOCOL = "popopx.channel.enc.v1"
    NONCE_BYTES = 12
    TAG_BYTES = 16
    EPOCH_KEY_BYTES = 32
    IDENTITY_KEY_BYTES = 32        # Ed25519 raw public key
    SIGNATURE_BYTES = 64
    SEPARATOR = 0x7C               # '|', the AAD/preimage field delimiter


H5_MAX_SKEW_SECONDS = 300          # replay window for verifyH5Auth
H5_UID_PARAM = "popopx_uid"
H5_TS_PARAM = "ts"
H5_SIG_PARAM = "sig"


class EcoError(Exception):
    """Base class. `.rule` names the client-side rule that would have rejected it."""

    def __init__(self, rule: str, message: str) -> None:
        super().__init__("%s: %s" % (rule, message))
        self.rule = rule
        self.detail = message


class EcoValidationError(EcoError):
    """A frame that the iOS parser would drop silently. Never send these."""


class CryptoUnavailable(EcoError):
    """`cryptography` is not importable in this process."""

    def __init__(self, what: str) -> None:
        super().__init__(
            "crypto_dependency_missing",
            "%s needs the `cryptography` package (pip install -r requirements.txt). "
            "It is deliberately not vendored: Ed25519 and ChaCha20-Poly1305 come from an "
            "audited library or not at all." % what,
        )


# ─────────────────────────────────────────────────────────────────────────────
# 2. Primitives
# ─────────────────────────────────────────────────────────────────────────────


def now_ms() -> int:
    """Epoch milliseconds — the unit of `ut`, `et` and `expiresAtMs` (Int64 on the client)."""
    return int(time.time() * 1000)


def now_seconds() -> int:
    """Epoch seconds — the unit of the H5 `ts` parameter (PopopxH5Launcher.swift:103)."""
    return int(time.time())


def b64_std(data: bytes) -> str:
    """Standard padded base64: `PopopxChannelBase64.encode` = `Data.base64EncodedString()` (:276).

    Used for the envelope's `nonce`, `ciphertext` and `signature`.
    """
    return base64.b64encode(data).decode("ascii")


def b64_url(data: bytes) -> str:
    """base64url WITHOUT padding, matching `Data.popopxBase64URL`
    (PopopxSecurePayload.swift:404-409, which strips `=`).

    Used for `keyBase64URL` / `publicKeyBase64URL` inside the epoch secret. The
    client's decoder re-pads (PopopxSecurePayload.swift:424-427), so both forms
    are accepted; the unpadded form is what the client itself emits, and is what
    the field name promises.
    """
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64_decode_lenient(text: str) -> bytes:
    """Mirror `PopopxChannelBase64.decode` (:278-283): standard first, then base64url.

    Accepting both is not generosity — it is what the peer does, and a stricter
    decoder here would reject a frame a phone accepted.
    """
    candidate = text.strip()
    if not candidate:
        raise EcoError("base64_empty", "expected base64 text, got empty")
    try:
        return base64.b64decode(candidate, validate=True)
    except Exception:
        pass
    padded = candidate + "=" * (-len(candidate) % 4)
    try:
        return base64.urlsafe_b64decode(padded)
    except Exception as exc:
        raise EcoError("base64_invalid", "%r is neither standard nor URL-safe base64 (%s)" % (text, exc))


def hmac_sha256(key: bytes, message: bytes) -> bytes:
    return hmac.new(key, message, hashlib.sha256).digest()


def hmac_hex(key: bytes, message: bytes) -> str:
    """Lowercase hex, because `PopopxEcoHex.encode` is `%02x` and the launcher
    compares/renders hex (PopopxH5Launcher.swift:134)."""
    return hmac_sha256(key, message).hex()


def _require_crypto() -> Dict[str, Any]:
    """Lazy import so the codec, limits and HMAC paths work without the wheel."""
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (  # noqa: F401
            Ed25519PrivateKey,
            Ed25519PublicKey,
        )
        from cryptography.hazmat.primitives.ciphers.aead import (  # noqa: F401
            ChaCha20Poly1305,
        )
    except ImportError as exc:  # pragma: no cover - depends on the host
        raise CryptoUnavailable("channel envelope / Ed25519 signing") from exc
    from cryptography.hazmat.primitives.asymmetric import ed25519
    from cryptography.hazmat.primitives.ciphers import aead

    return {
        "Ed25519PrivateKey": ed25519.Ed25519PrivateKey,
        "Ed25519PublicKey": ed25519.Ed25519PublicKey,
        "ChaCha20Poly1305": aead.ChaCha20Poly1305,
    }


# ─────────────────────────────────────────────────────────────────────────────
# 3. JSON codec
# ─────────────────────────────────────────────────────────────────────────────


def compact_json(payload: Mapping[str, Any]) -> str:
    """Serialize the way the client's bare `JSONEncoder()` does.

    Key facts this mirrors:
      * No key sorting and no key transformation: the wire names are exactly the
        `CodingKeys` raw values the Swift structs declare, so the caller supplies
        them already short (`t`, `uid`, `card`, `ut`, ...).
      * No `keyDecodingStrategy` exists on the decoder (PopopxEcoModels.swift:208),
        so a snake_case key is not merely ugly, it is invisible to the client and
        the field decodes as absent.
      * `ensure_ascii=False`. The client measures the frame in CHARACTERS
        (:48-72) and escapes are counted before decoding: one CJK glyph is 1
        character as UTF-8 text but 6 as `\\uXXXX`. A 40-character Chinese card
        body would cost 240 against an 8192 budget for no reason, and would
        silently truncate nothing — it would just fail the limit.
      * `allow_nan=False`: JSON has no NaN, Python's default `dumps` emits one,
        and Swift's decoder would reject the whole frame.
    """
    try:
        text = json.dumps(
            payload,
            ensure_ascii=False,
            separators=(",", ":"),
            allow_nan=False,
        )
    except (TypeError, ValueError) as exc:
        raise EcoValidationError("json_unserializable", "%s" % exc) from exc
    # The client's control-frame parser requires the remainder after the marker to
    # contain no newline and no carriage return (PopopxEcoModels.swift:106-114);
    # a single one drops the message with no diagnostic. json.dumps already
    # escapes control characters inside strings, so this is a guard against a
    # future change here, not a live bug.
    if "\n" in text or "\r" in text:
        raise EcoValidationError("frame_contains_line_break", "ECO frames must be single-line")
    return text


def _escape_whitespace(text: str) -> str:
    """Turn every space into `\\u0020` so the frame is one whitespace-delimited token.

    `parseVisibleCard` finds a visible card by splitting the message on
    whitespace and scanning from the end (PopopxEcoModels.swift:120-128), so a
    frame carrying readable text alongside it may not contain a space. Structural
    JSON never does (`separators=(",", ":")`), which leaves only spaces inside
    string values — and `\\u0020` is the same character to the decoder.
    """
    return text.replace(" ", "\\u0020")


# ─────────────────────────────────────────────────────────────────────────────
# 4. Field validators
#
# Each function encodes one client-side guard and raises with the rule name, so
# an operator sees "why did the phone not show this" as an HTTP 400 instead of a
# shrug.
# ─────────────────────────────────────────────────────────────────────────────


def _text(value: Any, rule: str, limit: int, *, required: bool = True) -> str:
    if value is None:
        if required:
            raise EcoValidationError(rule, "value is required")
        return ""
    if not isinstance(value, str):
        raise EcoValidationError(rule, "expected a string, got %s" % type(value).__name__)
    if required and not value.strip():
        raise EcoValidationError(rule, "value must not be empty or whitespace")
    if len(value) > limit:
        raise EcoValidationError(
            rule, "%d characters exceeds the client limit of %d" % (len(value), limit)
        )
    return value


def _bounded_int(value: Any, rule: str, low: int, high: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise EcoValidationError(rule, "expected an integer, got %r" % (value,))
    if not low <= value <= high:
        raise EcoValidationError(rule, "%d is outside %d..%d" % (value, low, high))
    return value


_PAIRWISE_UID_RE = re.compile(r"^[A-Za-z0-9_.-]{1,%d}$" % EcoLimits.pairwise_uid_chars)
_SECRET_HEX_RE = re.compile(r"^(?:[0-9a-fA-F]{2}){1,32}$")
_CHANNEL_ID_RE = re.compile(r"^[A-Za-z0-9-_.]{1,%d}$" % EcoLimits.payload_chars)


def validate_pairwise_uid(uid: Any) -> str:
    """Opaque per-contact id. Kept to URL-safe characters because it travels in
    the H5 query string unescaped (PopopxH5Launcher.swift:126 uses an unreserved-only set)."""
    if not isinstance(uid, str) or not _PAIRWISE_UID_RE.match(uid):
        raise EcoValidationError(
            "pairwise_uid", "must be 1-%d characters of [A-Za-z0-9_.-], got %r"
            % (EcoLimits.pairwise_uid_chars, uid)
        )
    return uid


def validate_secret_hex(secret: Any) -> str:
    """`sec` must decode to 1..32 bytes of hex, mirroring `PopopxEcoHex.decode`.

    The client's decoder (PopopxEcoModels.swift:891-907) trims surrounding
    whitespace, rejects the empty string, requires `count.isMultiple(of: 2)` at
    :894, requires every character to be a hex digit, and rejects anything over
    `maximumByteCount * 2` characters rather than truncating it. Odd length is the
    case worth naming: a 63-character "secret" looks fine to a `{2,64}` regex and
    decodes to nothing on the phone, so the handshake frame is dropped in silence
    and the follower never gets a session. Accepting exactly what the client accepts
    is the whole point of this module, so this is the client's rule and not ours.
    """
    if not isinstance(secret, str):
        raise EcoValidationError("session_secret", "must be a hex string, got %r" % (secret,))
    trimmed = secret.strip()
    if len(trimmed) > EcoLimits.secret_hex_chars:
        raise EcoValidationError("session_secret", "hex longer than %d characters" % EcoLimits.secret_hex_chars)
    if not _SECRET_HEX_RE.match(trimmed):
        raise EcoValidationError(
            "session_secret", "must be 2..64 hex characters in even-length pairs (1..32 bytes), got %r" % (secret,)
        )
    return trimmed.lower()


def new_session_secret() -> str:
    """32 random bytes as lowercase hex — the maximum the client accepts, so a
    session key is a full-strength HMAC key rather than a short token."""
    return secrets.token_hex(32)


# ─────────────────────────────────────────────────────────────────────────────
# 5. Action and menu validation
# ─────────────────────────────────────────────────────────────────────────────

ACTION_KINDS = ("callback", "pay_credits", "open_url", "open_channel", "send_cmd", "none")
ACTION_STYLES = ("primary", "secondary", "destructive")
MENU_ITEM_KINDS = ("click", "view", "scancode", "location", "click_text")
CARD_STYLES = ("standard", "receipt", "security")

# Menu items may only carry these action kinds. `.none` and `.pay_credits` are
# rejected on a menu item by the client (`PopopxEcoMenu.Item.isSane`, whose `switch` answers
# `false` for exactly those two) even
# though both are legal on a card action — payment happens from a card, whose
# amount and confirmation copy the user can see, not from a menu label.
# The client has since grown `subItems` (reachable only under a `click` kind, capped by
# `PopopxEcoLimits.maximumSubItems`); this suite emits none of those, so every menu it builds
# is still flat — the `sub_menu` the brief asks for is a server-side gap, not a client limit.
MENU_ACTION_KINDS = ("open_url", "send_cmd", "open_channel", "callback")

_SEGMENT_RE = re.compile(r"^[A-Za-z0-9-_.]{1,128}$")


def validate_channel_public_uri(uri: Any) -> str:
    """`popopx://channel/<relay>/<channelId>#key=<b64url 32B>&pub=<b64url 32B>`.

    Mirrors `PopopxChannelPublicURI` (PopopxEcoModels.swift:729-797). An
    `open_channel` action whose payload fails this makes the WHOLE frame
    undecodable, not just that one action.
    """
    if not isinstance(uri, str) or not uri:
        raise EcoValidationError("channel_uri", "must be a non-empty string")
    prefix = "popopx://channel/"
    if not uri.startswith(prefix):
        raise EcoValidationError("channel_uri", "must start with %r" % prefix)
    head, _, fragment = uri[len(prefix):].partition("#")
    segments = head.split("/")
    if len(segments) != 2 or not all(_SEGMENT_RE.match(s or "") for s in segments):
        raise EcoValidationError(
            "channel_uri", "expected <relay>/<channelId> of 1-128 chars in [A-Za-z0-9-_.], got %r" % head
        )
    if not fragment:
        raise EcoValidationError("channel_uri", "fragment with key= and pub= is required")
    seen: Dict[str, str] = {}
    for pair in fragment.split("&"):
        if not pair:
            continue
        name, sep, value = pair.partition("=")
        if not sep or name not in ("key", "pub") or name in seen:
            raise EcoValidationError(
                "channel_uri", "fragment may contain only key= and pub=, each once (got %r)" % pair
            )
        seen[name] = value
    if "key" not in seen:
        raise EcoValidationError("channel_uri", "key= is required")
    try:
        if len(b64_decode_lenient(seen["key"])) != 32:
            raise EcoValidationError("channel_uri", "key= must decode to 32 bytes")
    except EcoError as exc:
        raise EcoValidationError("channel_uri", "key= is not base64url: %s" % exc.detail)
    if "pub" in seen:
        try:
            if len(b64_decode_lenient(seen["pub"])) != 32:
                raise EcoValidationError("channel_uri", "pub= must decode to 32 bytes")
        except EcoError as exc:
            raise EcoValidationError("channel_uri", "pub= is not base64url: %s" % exc.detail)
    return uri


def validate_channel_relay(relay: Any) -> str:
    """The `<relay>` segment of a channel URI: the node's own server name.

    Same alphabet as `PopopxChannelPublicURI.isOpaqueSegment`
    (PopopxEcoModels.swift:793-796) — a relay with a space or a `/` in it turns
    the URI's two path segments into three and the whole URI stops parsing.
    """
    text = str(relay).strip()
    if not _SEGMENT_RE.match(text):
        raise EcoValidationError(
            "channel_relay", "expected 1-128 characters of [A-Za-z0-9-_.], got %r" % (str(relay)[:40],)
        )
    return text


def build_channel_public_uri(relay: str, channel_id: str, key_b64url: str, public_key_b64url: str) -> str:
    """The inverse of :func:`validate_channel_public_uri`.

    Both fragment values are things the gateway already holds — epoch 1's key and
    the identity public half — so a merchant never has to copy a URI out of a
    node log and paste it into an admin form. Everything else about this string is
    the client's: `PopopxChannelPublicURI` requires exactly two path segments and
    only `key=`/`pub=` in the fragment, and the *first* epoch key of a channel can
    only reach a phone through this URI, because a `channel_key_update` sealed
    under the epoch it delivers is refused by `isSane`.
    """
    head = "%s/%s" % (validate_channel_relay(relay), validate_channel_relay(channel_id))
    uri = "popopx://channel/%s#key=%s&pub=%s" % (
        head,
        str(key_b64url).strip(),
        str(public_key_b64url).strip(),
    )
    return validate_channel_public_uri(uri)


def validate_http_url(url: Any, rule: str = "action_url") -> str:
    """`open_url` and menu `view` need an http(s) URL *with a host*
    (PopopxEcoModels.swift:685-702 checks `url.host != nil`)."""
    text = _text(url, rule, EcoLimits.url_chars)
    if not (text.startswith("http://") or text.startswith("https://")):
        raise EcoValidationError(rule, "must be an absolute http(s) URL, got %r" % (url,))
    rest = text.split("://", 1)[1]
    host = re.split(r"[/?#]", rest, maxsplit=1)[0]
    if not host:
        raise EcoValidationError(rule, "URL has no host: %r" % (url,))
    return text


def build_action(
    *,
    action_id: str,
    title: str,
    kind: str,
    style: str = "primary",
    payload: Optional[str] = None,
    url: Optional[str] = None,
    target: Optional[str] = None,
    amount: Optional[int] = None,
    confirm: bool = False,
) -> Dict[str, Any]:
    """One card button, in the client's wire shape.

    Keys are `PopopxEcoAction.CodingKeys` (PopopxEcoModels.swift:638-648):
    `id, title, action, style, payload, url, target, amount, confirm`. Note that
    the *kind* is encoded under `action` and the *visual colour* under `style`;
    swapping them is the single easiest way to make a card undecodable, since an
    unknown kind string throws and takes the whole frame with it.
    """
    out: Dict[str, Any] = {
        # `id` defaults to "" on the client and ids must be unique within a card,
        # so omitting it on a second action kills the card. Always sent.
        "id": _text(action_id, "action_id", EcoLimits.payload_chars),
        "title": _text(title, "action_title", EcoLimits.field_label_chars),
        "action": kind,
        "style": style,
    }
    if kind not in ACTION_KINDS:
        raise EcoValidationError(
            "action_kind", "%r is not one of %s (unknown kinds throw, dropping the frame)" % (kind, list(ACTION_KINDS))
        )
    if style not in ACTION_STYLES:
        raise EcoValidationError("action_style", "%r is not one of %s" % (style, list(ACTION_STYLES)))

    if kind == "none":
        raise EcoValidationError("action_kind", "'none' fails PopopxEcoAction.isSane (:685-702); omit the action")
    if kind in ("callback", "send_cmd"):
        out["payload"] = _text(payload, "action_payload", EcoLimits.payload_chars)
    elif kind == "open_url":
        out["url"] = validate_http_url(url)
        if payload is not None:
            out["payload"] = _text(payload, "action_payload", EcoLimits.payload_chars)
    elif kind == "open_channel":
        out["payload"] = validate_channel_public_uri(payload)
    elif kind == "pay_credits":
        out["amount"] = _bounded_int(amount, "action_amount", EcoLimits.credits_min, EcoLimits.credits_max)
        if payload is not None:
            out["payload"] = _text(payload, "action_payload", EcoLimits.payload_chars)
    if target:
        out["target"] = _text(target, "action_target", EcoLimits.payload_chars)
    if confirm:
        out["confirm"] = True
    return out


def build_menu_item(
    *,
    title: str,
    kind: str = "click",
    action: Optional[Dict[str, Any]] = None,
    sub_items: Optional[Sequence[Mapping[str, Any]]] = None,
) -> Dict[str, Any]:
    """One menu entry: `PopopxEcoMenu.Item` keys `title, kind, action, payload, url, sub`
    (PopopxEcoModels.swift:356-359). The action's own payload/url are FLATTENED
    onto the item — that is what the decoder reads, so nesting them under
    `action:` would silently produce an item with no target."""
    if kind not in MENU_ITEM_KINDS:
        raise EcoValidationError("menu_item_kind", "%r is not one of %s" % (kind, list(MENU_ITEM_KINDS)))
    out: Dict[str, Any] = {"title": _text(title, "menu_title", EcoLimits.max_menu_title_chars), "kind": kind}
    subs = list(sub_items or [])
    if kind == "view":
        if action is None or action.get("action") != "open_url":
            raise EcoValidationError("menu_view", "kind 'view' requires an open_url action")
        out["url"] = validate_http_url(action.get("url"), "menu_url")
        if subs:
            raise EcoValidationError("menu_view", "'view' must not carry sub-items")
        return out
    if action is not None:
        if action.get("action") not in MENU_ACTION_KINDS:
            raise EcoValidationError(
                "menu_action", "menu items may not be %r; payment needs a card the user can read"
                % action.get("action")
            )
        out["action"] = action["action"]
        if "payload" in action:
            out["payload"] = action["payload"]
        if "url" in action:
            out["url"] = validate_http_url(action["url"], "menu_url")
    if kind in ("scancode", "location") and action is not None:
        raise EcoValidationError("menu_kind", "'%s' must not carry an action" % kind)
    if subs:
        if len(subs) > EcoLimits.max_menu_subitems:
            raise EcoValidationError("menu_subitems", "%d exceeds %d" % (len(subs), EcoLimits.max_menu_subitems))
        out["sub"] = [build_menu_item(**_as_menu_kwargs(s)) for s in subs]
    else:
        # `subItems` is non-optional on the client with a default of []; sending
        # [] is the honest mirror of "no submenu".
        out["sub"] = []
    return out


def _as_menu_kwargs(item: Mapping[str, Any]) -> Dict[str, Any]:
    """Accept the keyword form *and* an already-built wire item.

    Re-building a stored menu has to work: the console reads the menu back, a
    human edits it and posts the whole thing again, and what it posts is the
    flattened leaf this function produced — `action` a bare string with
    `payload`/`url` sitting next to it, not nested inside an `action` object.
    Without this branch that round trip raises, which would make "edit the menu"
    impossible while "set the menu" still worked.
    """
    if not isinstance(item, Mapping) or "title" not in item:
        return dict(item)
    kind = str(item.get("kind") or "click")
    action = item.get("action")
    rebuilt: Optional[Dict[str, Any]] = None
    if isinstance(action, Mapping):
        rebuilt = dict(action)
    elif isinstance(action, str) and action:
        rebuilt = {"action": action}
        if "payload" in item:
            rebuilt["payload"] = item["payload"]
        if "url" in item:
            rebuilt["url"] = item["url"]
    elif kind == "view" and "url" in item:
        # A `view` leaf carries only `url`; the action kind is implied by the kind.
        rebuilt = {"action": "open_url", "url": item["url"]}
    return {
        "title": item["title"],
        "kind": kind,
        "action": rebuilt,
        "sub_items": item.get("sub") or item.get("sub_items") or None,
    }


def build_menu(items: Sequence[Mapping[str, Any]], revision: Optional[int] = None) -> Dict[str, Any]:
    """`PopopxEcoMenu` = `{"items": [...], "rev": n}` (:400-404), max 3 top-level
    items, titles unique within a list."""
    if not items:
        raise EcoValidationError("menu_items", "a menu with no items is not decodable")
    if len(items) > EcoLimits.max_menu_items:
        raise EcoValidationError("menu_items", "%d exceeds %d" % (len(items), EcoLimits.max_menu_items))
    built = [build_menu_item(**_as_menu_kwargs(i)) for i in items]
    _assert_unique_titles([b["title"] for b in built], "menu_items")
    out: Dict[str, Any] = {"items": built}
    if revision is not None:
        out["rev"] = _bounded_int(revision, "menu_revision", 0, 2 ** 63 - 1)
    return out


def _assert_unique_titles(titles: Sequence[str], rule: str) -> None:
    seen = set()
    for title in titles:
        if title in seen:
            raise EcoValidationError(rule, "duplicate menu title %r; the client requires uniqueness" % title)
        seen.add(title)


# ─────────────────────────────────────────────────────────────────────────────
# 6. Service cards
# ─────────────────────────────────────────────────────────────────────────────


def build_card(
    card_id: str,
    title: str,
    *,
    style: str = "standard",
    body: Optional[str] = None,
    fields: Optional[Sequence[Mapping[str, Any]]] = None,
    progress: Optional[Mapping[str, Any]] = None,
    actions: Optional[Sequence[Mapping[str, Any]]] = None,
    updated_at_ms: Optional[int] = None,
    expires_at_ms: Optional[int] = None,
) -> Dict[str, Any]:
    """`PopopxServiceCard` wire shape (PopopxEcoModels.swift:469-479).

    `v` (style) and `ut` (updated timestamp in **milliseconds**) are required by
    the decoder: omit either and the card does not render degraded, it does not
    exist. `m` is deliberately not written here — the frame carries the mode, and
    the nested field is ignored on decode.
    """
    if style not in CARD_STYLES:
        raise EcoValidationError("card_style", "%r is not one of %s" % (style, list(CARD_STYLES)))
    card: Dict[str, Any] = {
        "id": _text(card_id, "card_id", EcoLimits.card_id_chars),
        "v": style,
        "title": _text(title, "card_title", EcoLimits.card_title_chars),
        "ut": updated_at_ms if updated_at_ms is not None else now_ms(),
    }
    card["ut"] = _bounded_int(card["ut"], "card_updated_at_ms", 1, 2 ** 63 - 1)
    if body is not None:
        card["body"] = _text(body, "card_body", EcoLimits.card_body_chars, required=False)
    if fields:
        if len(fields) > EcoLimits.max_fields:
            raise EcoValidationError("card_fields", "%d exceeds %d" % (len(fields), EcoLimits.max_fields))
        built_fields: List[Dict[str, Any]] = []
        for raw in fields:
            label = _text(raw.get("k", raw.get("label")), "field_label", EcoLimits.field_label_chars)
            value = _text(raw.get("v", raw.get("value")), "field_value", EcoLimits.field_value_chars)
            entry: Dict[str, Any] = {"k": label, "v": value}
            if raw.get("mono"):
                entry["mono"] = True
            built_fields.append(entry)
        card["fields"] = built_fields
    if progress is not None:
        card["progress"] = {
            "l": _text(progress.get("l", progress.get("label")), "progress_label", EcoLimits.field_label_chars),
            "p": _bounded_int(
                progress.get("p", progress.get("percent")),
                "progress_percent",
                EcoLimits.progress_percent_min,
                EcoLimits.progress_percent_max,
            ),
        }
        detail = progress.get("d", progress.get("detail"))
        if detail is not None:
            card["progress"]["d"] = _text(detail, "progress_detail", EcoLimits.field_value_chars, required=False)
    if actions:
        if len(actions) > EcoLimits.max_actions:
            raise EcoValidationError("card_actions", "%d exceeds %d" % (len(actions), EcoLimits.max_actions))
        built_actions = [a if _is_wire_action(a) else build_action(**dict(a)) for a in actions]
        _assert_unique_action_ids([a["id"] for a in built_actions])
        card["actions"] = built_actions
    if expires_at_ms is not None:
        card["et"] = _bounded_int(expires_at_ms, "card_expires_at_ms", 1, 2 ** 63 - 1)
    return card


def _is_wire_action(candidate: Mapping[str, Any]) -> bool:
    """True when the caller already produced a dict via `build_action`."""
    return "action" in candidate and "title" in candidate and "id" in candidate


def _assert_unique_action_ids(ids: Sequence[str]) -> None:
    seen = set()
    for action_id in ids:
        if action_id in seen:
            raise EcoValidationError(
                "action_id", "duplicate id %r; the client keys action taps by id and rejects the card" % action_id
            )
        seen.add(action_id)


# ─────────────────────────────────────────────────────────────────────────────
# 7. Frame assembly
# ─────────────────────────────────────────────────────────────────────────────


def encode_frame(payload: Mapping[str, Any], *, visible_text: Optional[str] = None) -> str:
    """Wrap an ECO payload dict in its marker, producing the message text to send.

    The visible-text rule is the subtle one and it comes from two different
    parsers on the client:

      * `PopopxEcoParser.parse` (PopopxEcoModels.swift:106-114) takes the WHOLE
        message text, requires the marker prefix after trimming, and returns nil
        if the remainder contains a newline. So `sh`, `mc` and `ku` frames can
        never share a message with prose — appending the `\\n\\n<fallback text>` the
        brief describes to those frames silently destroys them.
      * `parseVisibleCard` (:120-128) splits on whitespace, scans from the end,
        and accepts a `service_card` with mode `create` only. So only a new card
        may be preceded by readable text, and only if the frame is the last token.
    """
    frame_type = payload.get("t")
    if frame_type not in ("sh", "mc", "sc", "ku"):
        raise EcoValidationError("frame_type", "%r is not a known ECO frame type" % (frame_type,))
    if frame_type != "sc":
        if visible_text:
            raise EcoValidationError(
                "frame_exclusive",
                "a %r frame is parsed with PopopxEcoParser.parse and must be the entire message; "
                "readable text may only accompany a create card" % frame_type,
            )
    elif visible_text and payload.get("m") != "c":
        raise EcoValidationError(
            "frame_exclusive",
            "only mode 'c' cards may carry visible text; an update (%r) is read by parse and must stand alone"
            % payload.get("m"),
        )

    body = compact_json(payload)
    if visible_text:
        body = _escape_whitespace(body)
    frame = ECO_MARKER + body
    if len(frame) > EcoLimits.frame_chars:
        raise EcoValidationError(
            "frame_limit",
            "frame is %d characters, the client drops anything over %d" % (len(frame), EcoLimits.frame_chars),
        )
    if visible_text is not None:
        text = _text(visible_text, "visible_text", EcoLimits.card_body_chars, required=False)
        if not text:
            return frame
        # The card is found by scanning whitespace-separated tokens from the END,
        # so the frame has to be last.
        message = "%s\n%s" % (text.rstrip(), frame)
        if len(message) > EcoLimits.frame_chars:
            raise EcoValidationError(
                "frame_limit",
                "card plus visible text is %d characters, over the %d limit" % (len(message), EcoLimits.frame_chars),
            )
        return message
    return frame


def frame_session_handshake(pairwise_uid: str, secret_hex: str, service_id: str) -> str:
    """`{"t":"sh","uid":…,"sec":…,"svc":…}` — the frame that makes the phone treat
    this service as a verified issuer, which is what actually enables `pay_credits`
    (see the module docstring, divergence 1)."""
    payload = {
        "t": "sh",
        "uid": validate_pairwise_uid(pairwise_uid),
        "sec": validate_secret_hex(secret_hex),
        "svc": _text(service_id, "service_id", EcoLimits.service_id_chars),
    }
    return encode_frame(payload)


def frame_menu_config(menu: Mapping[str, Any]) -> str:
    return encode_frame({"t": "mc", "menu": menu})


def frame_service_card(
    card: Mapping[str, Any],
    *,
    update: bool = False,
    visible_text: Optional[str] = None,
) -> str:
    """`update=False` creates the card, `update=True` replaces it **in place** by
    `cardId` — that is the mechanism behind "the progress bar moved without a new
    message appearing"."""
    payload = {"t": "sc", "m": "u" if update else "c", "card": card}
    return encode_frame(payload, visible_text=visible_text)


def frame_channel_key_update(
    channel_id: str,
    sealed_under_epoch: int,
    revoke_previous: bool,
    envelope: Mapping[str, Any],
) -> str:
    """`{"t":"ku","update":{ch,se,rp,env}}` (ChannelKeyRotationManager.swift:353-358).

    `se != env.epoch` is enforced by the client's `isSane` (:374) with the reason
    spelled out at :370-373 — a frame sealed under the key it replaces would be
    self-decrypting, and there would be no way to detect a replay.
    """
    channel = _text(channel_id, "channel_id", EcoLimits.payload_chars)
    # Stricter than the client, on purpose: `isSane` only asks that `ch` be non-empty
    # and short (ChannelKeyRotationManager.swift:370-372), but an id carrying anything
    # outside the URI segment alphabet could never be published as a public URI, so
    # accepting it here would hand a member a channel they cannot rotate into.
    if not _CHANNEL_ID_RE.match(channel):
        raise EcoValidationError("channel_id", "%r is not [A-Za-z0-9-_.]{1,%d}" % (channel_id, EcoLimits.payload_chars))
    sealed = _bounded_int(sealed_under_epoch, "sealed_under_epoch", 1, EcoLimits.max_epoch)
    envelope_epoch = envelope.get("epoch")
    if envelope_epoch is not None and envelope_epoch == sealed:
        raise EcoValidationError(
            "epoch_equals_sealed_under",
            "PopopxChannelKeyUpdate.isSane rejects se == env.epoch (:374); rotate the epoch instead",
        )
    payload = {
        "t": "ku",
        "update": {
            "ch": channel,
            "se": sealed,
            "rp": bool(revoke_previous),
            "env": dict(envelope),
        },
    }
    return encode_frame(payload)


# ─────────────────────────────────────────────────────────────────────────────
# 8. H5 authentication
# ─────────────────────────────────────────────────────────────────────────────


def h5_preimage(pairwise_uid: str, timestamp_seconds: int) -> bytes:
    """`"uid=<pairwise_uid>&ts=<unix-seconds>"` as UTF-8 (PopopxH5Launcher.swift:128-132).

    Not `popopx_uid=` in the preimage even though the *query parameter* is
    `popopx_uid` — the two differ, and a server that "normalises" them starts
    rejecting every phone.
    """
    return ("uid=%s&ts=%d" % (pairwise_uid, timestamp_seconds)).encode("utf-8")


def h5_signature(secret_hex: str, pairwise_uid: str, timestamp_seconds: int) -> str:
    """HMAC-SHA256 keyed on the raw session secret, lowercase hex (:134)."""
    key = bytes.fromhex(validate_secret_hex(secret_hex))
    return hmac_hex(key, h5_preimage(pairwise_uid, timestamp_seconds))


def sign_h5_url(url: str, pairwise_uid: str, secret_hex: str, *, timestamp: Optional[int] = None) -> str:
    """Produce the URL the client would produce, for console previews and for the
    urls the gateway embeds in cards.

    Parameter order `popopx_uid, ts, sig` is the client's, and any pre-existing
    copy of those three names is dropped first (PopopxH5Launcher.swift:117-142) so
    a card author cannot smuggle a `sig=` that survives signing.
    """
    ts = timestamp if timestamp is not None else now_seconds()
    uid = validate_pairwise_uid(pairwise_uid)
    signature = h5_signature(secret_hex, uid, ts)
    base, _, _query = url.partition("?")
    kept = [
        pair
        for pair in (_query.split("&") if _query else [])
        if pair and pair.split("=", 1)[0] not in (H5_UID_PARAM, H5_TS_PARAM, H5_SIG_PARAM)
    ]
    kept.extend(["%s=%s" % (H5_UID_PARAM, uid), "%s=%d" % (H5_TS_PARAM, ts), "%s=%s" % (H5_SIG_PARAM, signature)])
    return "%s?%s" % (base, "&".join(kept))


def verify_h5_auth(
    pairwise_uid: Any,
    timestamp_seconds: Any,
    signature: Any,
    secret_hex: str,
    *,
    window_seconds: int = H5_MAX_SKEW_SECONDS,
    now: Optional[int] = None,
) -> Tuple[bool, str]:
    """The server half of `POST /api/v1.verifyH5Auth`.

    Returns `(ok, reason)` rather than raising: the caller has to answer a browser
    either way, and the reason distinguishes "replay window" from "wrong secret"
    well enough to log without leaking which one to a client.

    `hmac.compare_digest`, not `==`: this is a network-facing check on a value an
    attacker controls, and a byte-by-byte early-out turns the window into an
    oracle.
    """
    try:
        uid = validate_pairwise_uid(pairwise_uid)
    except EcoError as exc:
        return False, "uid: %s" % exc.detail
    if not isinstance(signature, str) or len(signature) != 64:
        return False, "signature: expected 64 hex characters"
    try:
        provided = bytes.fromhex(signature)
    except ValueError:
        return False, "signature: not hex"
    try:
        ts = int(timestamp_seconds)
    except (TypeError, ValueError):
        return False, "timestamp: not an integer"
    current = now if now is not None else now_seconds()
    if abs(current - ts) > window_seconds:
        # Both directions on purpose: a client with a clock 20 minutes ahead would
        # otherwise hand out a signature that stays valid for twice the window.
        return False, "timestamp: outside the %d second window" % window_seconds
    expected = hmac_sha256(bytes.fromhex(validate_secret_hex(secret_hex)), h5_preimage(uid, ts))
    if not hmac.compare_digest(expected, provided):
        return False, "signature: mismatch"
    return True, "ok"


# ─────────────────────────────────────────────────────────────────────────────
# 9. Card audit seal
# ─────────────────────────────────────────────────────────────────────────────


def card_seal_preimage(card_id: str, title: str, credits_amount: int, timestamp_ms: int) -> bytes:
    """The brief's `cardId|title|creditsAmount|timestamp` layout, kept verbatim."""
    return ("%s|%s|%d|%d" % (card_id, title, credits_amount, timestamp_ms)).encode("utf-8")


def seal_card(
    card: Mapping[str, Any],
    secret_hex: str,
    credits_amount: int = 0,
) -> Tuple[str, int]:
    """Sign a card for the audit trail; returns `(sig_hex, ts_ms)`.

    Honest labelling matters more here than anywhere else in this file. The iOS
    renderer has no signature field on a card, so this value proves nothing to a
    phone. What it does prove is server-side: `cards.sig_hex` plus `sig_ts` let an
    operator show which card body was issued at which moment under which session,
    which is the evidence a dispute about a `pay_credits` charge actually needs.
    It is written as a JSON field pair (`sig`, `ts`) only on the server row and in
    admin payloads — never as part of an ECO frame, where an unknown key would be
    harmless but a longer frame is not.
    """
    ts = int(card.get("ut") or now_ms())
    title = str(card.get("title") or "")
    key = bytes.fromhex(validate_secret_hex(secret_hex))
    signature = hmac_hex(key, card_seal_preimage(str(card.get("id") or ""), title, credits_amount, ts))
    return signature, ts


def verify_card_seal(
    card: Mapping[str, Any], secret_hex: str, signature: str, timestamp_ms: int, credits_amount: int = 0
) -> bool:
    key = bytes.fromhex(validate_secret_hex(secret_hex))
    expected = hmac_sha256(
        key, card_seal_preimage(str(card.get("id") or ""), str(card.get("title") or ""), credits_amount, int(timestamp_ms))
    )
    try:
        return hmac.compare_digest(expected, bytes.fromhex(signature))
    except ValueError:
        return False


# ─────────────────────────────────────────────────────────────────────────────
# 10. Channel key rotation — the `popopx.channel.enc.v1` envelope
# ─────────────────────────────────────────────────────────────────────────────


def envelope_aad(channel_id: str, epoch: int, identity_public_key: bytes) -> bytes:
    """`protocol ‖ 0x7C ‖ channelId ‖ 0x7C ‖ ASCII(epoch) ‖ 0x7C ‖ identityPub32`

    (ChannelKeyRotationManager.swift:134-143.) The AAD is what binds a rotation to
    *this* channel: ChaCha20-Poly1305 authenticates it, so an envelope recorded
    from one channel and replayed onto another fails the tag check even though the
    ciphertext is byte-identical.
    """
    if len(identity_public_key) != ChannelEnvelope.IDENTITY_KEY_BYTES:
        raise EcoError(
            "identity_key_length",
            "expected %d bytes, got %d" % (ChannelEnvelope.IDENTITY_KEY_BYTES, len(identity_public_key)),
        )
    return b"".join(
        [
            ChannelEnvelope.PROTOCOL.encode("ascii"),
            bytes([ChannelEnvelope.SEPARATOR]),
            channel_id.encode("utf-8"),
            bytes([ChannelEnvelope.SEPARATOR]),
            str(epoch).encode("ascii"),
            bytes([ChannelEnvelope.SEPARATOR]),
            identity_public_key,
        ]
    )


def signing_preimage(channel_id: str, epoch: int, nonce: bytes, ciphertext_with_tag: bytes) -> bytes:
    """`protocol ‖ 0x7C ‖ channelId ‖ 0x7C ‖ ASCII(epoch) ‖ 0x7C ‖ nonce ‖ 0x7C ‖ ct‖tag`

    (ChannelKeyRotationManager.swift:146-157.) Raw bytes, not base64, and the
    header comment at :26-29 explicitly rejects the shorter `epoch+nonce+ciphertext`
    reading. Getting this wrong produces an envelope that decrypts fine and fails
    verification on every device, which is the worst possible failure mode for a
    key rotation: the channel looks alive and is silently deaf.
    """
    if len(nonce) != ChannelEnvelope.NONCE_BYTES:
        raise EcoError("nonce_length", "expected %d bytes, got %d" % (ChannelEnvelope.NONCE_BYTES, len(nonce)))
    return b"".join(
        [
            ChannelEnvelope.PROTOCOL.encode("ascii"),
            bytes([ChannelEnvelope.SEPARATOR]),
            channel_id.encode("utf-8"),
            bytes([ChannelEnvelope.SEPARATOR]),
            str(epoch).encode("ascii"),
            bytes([ChannelEnvelope.SEPARATOR]),
            nonce,
            bytes([ChannelEnvelope.SEPARATOR]),
            ciphertext_with_tag,
        ]
    )


def epoch_secret_plaintext(
    epoch: int,
    key: bytes,
    *,
    identity_public_key: Optional[bytes] = None,
    expires_at_ms: Optional[int] = None,
) -> bytes:
    """The JSON inside the box (`PopopxChannelEpochSecret`, :381-399).

    This is the only place the new epoch key ever appears, which is why the box
    exists: the relay carrying the message sees opaque base64.
    """
    if len(key) != ChannelEnvelope.EPOCH_KEY_BYTES:
        raise EcoError("epoch_key_length", "expected %d bytes, got %d" % (ChannelEnvelope.EPOCH_KEY_BYTES, len(key)))
    body: Dict[str, Any] = {"epoch": _bounded_int(epoch, "epoch", 1, EcoLimits.max_epoch), "keyBase64URL": b64_url(key)}
    if identity_public_key is not None:
        if len(identity_public_key) != ChannelEnvelope.IDENTITY_KEY_BYTES:
            raise EcoError(
                "identity_key_length", "expected %d bytes" % ChannelEnvelope.IDENTITY_KEY_BYTES
            )
        # Presenting a public key is an identity HANDOVER, and the client only
        # swaps its stored identity when this field is present (:688), so it must
        # never be sent "just in case" with an unchanged value.
        body["publicKeyBase64URL"] = b64_url(identity_public_key)
    if expires_at_ms is not None:
        body["expiresAtMs"] = _bounded_int(expires_at_ms, "expires_at_ms", 1, 2 ** 63 - 1)
    return compact_json(body).encode("utf-8")


def seal_envelope(
    channel_id: str,
    epoch: int,
    epoch_key: bytes,
    plaintext: bytes,
    identity_private_key: bytes,
    identity_public_key: bytes,
) -> Dict[str, Any]:
    """Encrypt under `epoch_key`, authenticate with the channel identity.

    Mirrors `seal` (ChannelKeyRotationManager.swift:171-204) field for field,
    including the one detail that is easy to get wrong: the envelope's
    `ciphertext` is `box.ciphertext ‖ box.tag` — the tag **appended**, not
    `SealedBox.combined`'s nonce-first layout. The client decrypts by
    `dropLast(16)` / `suffix(16)` (:234-251), so a nonce-prefixed blob here
    authenticates nothing correctly and fails every time.
    """
    lib = _require_crypto()
    if len(epoch_key) != ChannelEnvelope.EPOCH_KEY_BYTES:
        raise EcoError("epoch_key_length", "expected 32 bytes, got %d" % len(epoch_key))
    if len(plaintext) > EcoLimits.max_ciphertext_bytes:
        raise EcoError("plaintext_limit", "%d bytes exceeds the client's %d" % (len(plaintext), EcoLimits.max_ciphertext_bytes))
    nonce = secrets.token_bytes(ChannelEnvelope.NONCE_BYTES)
    aead = lib["ChaCha20Poly1305"](epoch_key)
    sealed = aead.encrypt(nonce, plaintext, envelope_aad(channel_id, epoch, identity_public_key))
    # cryptography's ChaCha20Poly1305 returns ciphertext ‖ tag already.
    ciphertext_with_tag = sealed
    signature = lib["Ed25519PrivateKey"].from_private_bytes(identity_private_key).sign(
        signing_preimage(channel_id, epoch, nonce, ciphertext_with_tag)
    )
    return {
        "protocol": ChannelEnvelope.PROTOCOL,
        "epoch": epoch,
        "nonce": b64_std(nonce),
        "ciphertext": b64_std(ciphertext_with_tag),
        "signature": b64_std(signature),
    }


def open_envelope(
    channel_id: str,
    envelope: Mapping[str, Any],
    epoch_key: bytes,
    identity_public_key: bytes,
) -> bytes:
    """Verify then decrypt — the same order as `apply` (:623-694), which checks the
    signature before spending any work on decryption, so a forged envelope is
    rejected without touching the cipher."""
    lib = _require_crypto()
    if envelope.get("protocol") != ChannelEnvelope.PROTOCOL:
        raise EcoError("envelope_protocol", "expected %r" % ChannelEnvelope.PROTOCOL)
    epoch = int(envelope["epoch"])
    nonce = b64_decode_lenient(envelope["nonce"])
    ciphertext_with_tag = b64_decode_lenient(envelope["ciphertext"])
    signature = b64_decode_lenient(envelope["signature"])
    if len(nonce) != ChannelEnvelope.NONCE_BYTES:
        raise EcoError("nonce_length", "expected 12 bytes")
    if len(signature) != ChannelEnvelope.SIGNATURE_BYTES:
        raise EcoError("signature_length", "expected 64 bytes")
    if len(ciphertext_with_tag) < ChannelEnvelope.TAG_BYTES:
        raise EcoError("ciphertext_short", "no room for a 16-byte tag")
    preimage = signing_preimage(channel_id, epoch, nonce, ciphertext_with_tag)
    try:
        lib["Ed25519PublicKey"].from_public_bytes(identity_public_key).verify(signature, preimage)
    except Exception as exc:
        raise EcoError("signature_invalid", "envelope was not signed by this channel's identity key: %s" % exc) from exc
    aead = lib["ChaCha20Poly1305"](epoch_key)
    try:
        return aead.decrypt(
            nonce,
            ciphertext_with_tag,
            envelope_aad(channel_id, epoch, identity_public_key),
        )
    except Exception as exc:
        raise EcoError("decrypt_failed", "tag mismatch: wrong epoch key or tampered ciphertext (%s)" % exc) from exc


def make_channel_identity() -> Tuple[bytes, bytes]:
    """Fresh Ed25519 keypair as `(private_32, public_32)` raw bytes."""
    lib = _require_crypto()
    private = lib["Ed25519PrivateKey"].generate()
    return private.private_bytes_raw(), private.public_key().public_bytes_raw()


def make_epoch_key() -> bytes:
    return secrets.token_bytes(ChannelEnvelope.EPOCH_KEY_BYTES)


def public_key_from_private(identity_private_key: bytes) -> bytes:
    lib = _require_crypto()
    return lib["Ed25519PrivateKey"].from_private_bytes(identity_private_key).public_key().public_bytes_raw()


# ─────────────────────────────────────────────────────────────────────────────
# 11. Voucher verification (POPX-CP activation codes)
# ─────────────────────────────────────────────────────────────────────────────

VOUCHER_PREFIX = "POPX-CP-1"
VOUCHER_MAGIC = "popopx"
VOUCHER_SCHEMA = "popx_cp_v1"
VOUCHER_FIELDS = 8

# Frozen at both ends on purpose. `official_tools/gen_voucher.py` carries the same
# constant and its `--self-test` checks the format half against it. If the two
# copies ever disagree, one of the two self-tests fails, which is a much better
# outcome than codes minted today failing to redeem next month.
VOUCHER_TEST_VECTOR_PAYLOAD = "popopx|popx_cp_v1|V-0001|startup|500|1767225600000||k-test"


@dataclass(frozen=True)
class Voucher:
    """A verified voucher. Field names match what `billing_service` records."""

    voucher_id: str
    plan: str
    credits: int
    issued_at_ms: int
    expires_at_ms: Optional[int]
    issuer_key_id: str
    signature_b64: str
    code: str

    def is_expired(self, *, now: Optional[int] = None) -> bool:
        if self.expires_at_ms is None:
            return False
        return (now if now is not None else now_ms()) > self.expires_at_ms


def voucher_canonical_payload(
    voucher_id: str,
    plan: str,
    credits: int,
    issued_at_ms: int,
    expires_at_ms: Optional[int],
    issuer_key_id: str,
) -> str:
    """`popopx|popx_cp_v1|<id>|<plan>|<credits>|<issued_ms>|<expires_ms or "">|<key id>`

    Eight fields, always — a missing expiry is the empty string, never a shorter
    join, so a parser cannot shift one field into another's position. The layout
    is copied from the house style of the client's own badge-credit signing
    (`PopopxBadgeCreditsModels.swift:1553`), which is what makes it reviewable
    against code the team has already shipped.
    """
    return "|".join(
        [
            VOUCHER_MAGIC,
            VOUCHER_SCHEMA,
            voucher_id,
            plan,
            str(credits),
            str(issued_at_ms),
            "" if expires_at_ms is None else str(expires_at_ms),
            issuer_key_id,
        ]
    )


def parse_voucher_code(code: str) -> Tuple[bytes, bytes, str]:
    """Split `POPX-CP-1.<b64url(payload)>.<b64url(sig)>` and return
    `(payload_bytes, signature_bytes, canonical_text)`."""
    if not isinstance(code, str):
        raise EcoError("voucher_format", "code must be a string")
    parts = code.strip().split(".")
    if len(parts) != 3 or parts[0] != VOUCHER_PREFIX:
        raise EcoError(
            "voucher_format",
            "expected %s.<payload>.<signature>, got %r" % (VOUCHER_PREFIX, code[:40]),
        )
    payload_bytes = b64_decode_lenient(parts[1])
    signature = b64_decode_lenient(parts[2])
    if len(signature) != ChannelEnvelope.SIGNATURE_BYTES:
        raise EcoError("voucher_signature", "expected %d raw bytes, got %d" % (ChannelEnvelope.SIGNATURE_BYTES, len(signature)))
    try:
        canonical = payload_bytes.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise EcoError("voucher_payload", "payload is not UTF-8: %s" % exc) from exc
    fields = canonical.split("|")
    if len(fields) != VOUCHER_FIELDS:
        raise EcoError("voucher_payload", "expected %d '|' fields, got %d" % (VOUCHER_FIELDS, len(fields)))
    if fields[0] != VOUCHER_MAGIC or fields[1] != VOUCHER_SCHEMA:
        raise EcoError("voucher_payload", "unknown magic/schema %r/%r" % (fields[0], fields[1]))
    return payload_bytes, signature, canonical


def voucher_from_canonical(canonical: str, signature_b64: str, code: str) -> Voucher:
    fields = canonical.split("|")
    try:
        credits = int(fields[4])
        issued = int(fields[5])
    except ValueError as exc:
        raise EcoError("voucher_payload", "credits/issued_at must be integers: %s" % exc) from exc
    if credits < 1:
        raise EcoError("voucher_payload", "credits must be positive, got %d" % credits)
    if issued <= 0:
        raise EcoError("voucher_payload", "issued_at_ms must be positive, got %d" % issued)
    expires: Optional[int] = None
    if fields[6]:
        try:
            expires = int(fields[6])
        except ValueError as exc:
            raise EcoError("voucher_payload", "expires_at_ms is not an integer: %r" % fields[6]) from exc
        if expires <= issued:
            raise EcoError("voucher_payload", "expires_at_ms (%d) is not after issued_at_ms (%d)" % (expires, issued))
    return Voucher(
        voucher_id=fields[2],
        plan=fields[3],
        credits=credits,
        issued_at_ms=issued,
        expires_at_ms=expires,
        issuer_key_id=fields[7],
        signature_b64=signature_b64,
        code=code,
    )


def verify_voucher_code(code: str, public_key: bytes, *, now: Optional[int] = None) -> Voucher:
    """Offline verification with the official public key — no call to the issuer.

    Deliberately the mirror of `official_tools/gen_voucher.py --verify` rather
    than an import of it: the minting tool holds the private key and runs on one
    machine in the whole deployment, the gateway must never be able to mint. Two
    small implementations of one frozen format is the price of that boundary.
    """
    lib = _require_crypto()
    _payload, signature, canonical = parse_voucher_code(code)
    if len(public_key) != ChannelEnvelope.IDENTITY_KEY_BYTES:
        raise EcoError("voucher_public_key", "expected 32 raw bytes, got %d" % len(public_key))
    try:
        lib["Ed25519PublicKey"].from_public_bytes(public_key).verify(signature, canonical.encode("utf-8"))
    except Exception as exc:
        raise EcoError("voucher_signature", "signature does not verify against the official key: %s" % exc) from exc
    voucher = voucher_from_canonical(canonical, b64_std(signature), code)
    if voucher.is_expired(now=now):
        raise EcoError("voucher_expired", "expired at %d" % (voucher.expires_at_ms or 0))
    return voucher


# ─────────────────────────────────────────────────────────────────────────────
# 12. Self-test
# ─────────────────────────────────────────────────────────────────────────────


def self_test() -> List[str]:
    """Assertions that need only the standard library.

    Runs here (Python 3.9, no wheels installed) and in CI. The crypto-dependent
    paths are covered by `crypto_self_test()`, which needs `cryptography` and — to
    be worth anything at all — a Swift oracle run against the real client types;
    see `official_tools/swift_crypto_oracle.swift`. This function checks the byte layout of the parts
    that are pure arithmetic, which is where a "works, but the phone ignores it"
    bug would live.
    """
    checks: List[str] = []

    def check(name: str, condition: bool) -> None:
        if not condition:
            raise AssertionError("self_test failed: %s" % name)
        checks.append(name)

    # Frame codec: compact, no spaces, no line breaks, marker exact.
    frame = encode_frame({"t": "sh", "uid": "u-1", "sec": "aa" * 32, "svc": "popopx-service"})
    check("marker_prefix", frame.startswith(ECO_MARKER))
    check("frame_is_one_token", not any(c.isspace() for c in frame))
    check("frame_has_no_line_break", "\n" not in frame and "\r" not in frame)
    check("frame_within_client_limit", len(frame) <= EcoLimits.frame_chars)

    # Non-ASCII must stay raw: the client counts characters, and \u escapes cost 6 each.
    cjk = build_card("c-1", "订单已支付", body="感谢您的惠顾，服务将在三日内开通。")
    cjk_frame = frame_service_card(cjk, visible_text="订单已支付")
    check("cjk_not_escaped", "订单" in cjk_frame and "\\u" not in cjk_frame.split("\n")[-1])
    # ...and with visible text attached, the frame token itself must stay whitespace-free.
    check("visible_split_frame_token", cjk_frame.rsplit("\n", 1)[-1].startswith(ECO_MARKER))
    check("visible_frame_single_token", not any(c.isspace() for c in cjk_frame.rsplit("\n", 1)[-1]))

    # A create card may carry text; nothing else may.
    for payload in ({"t": "mc", "menu": build_menu([{"title": "查询", "kind": "click"}])}, {"t": "sh"}):
        try:
            encode_frame(payload, visible_text="x")
            check("exclusive_frame_rejects_text:%s" % payload.get("t"), False)
        except EcoValidationError:
            check("exclusive_frame_rejects_text:%s" % payload.get("t"), True)

    # H5: the exact preimage, hex, and key-bytes semantics.
    secret = "00112233445566778899aabbccddeeff" * 2
    uid, ts = "U-abc_123", 1767225600
    check("h5_preimage_layout", h5_preimage(uid, ts) == b"uid=U-abc_123&ts=1767225600")
    key = bytes.fromhex(secret)
    check("h5_key_is_raw_bytes", len(key) == 32)
    check("h5_signature_is_hex64", len(h5_signature(secret, uid, ts)) == 64)
    signed = sign_h5_url("https://s.example.com/redeem?sig=dead&ts=1&popopx_uid=x&id=7", uid, secret, timestamp=ts)
    check("h5_drops_forged_params", signed.count("sig=") == 1 and signed.count("ts=") == 1)
    check("h5_param_order", signed.index("popopx_uid=") < signed.index("&ts=") < signed.index("&sig="))
    check("h5_keeps_unrelated_param", "id=7" in signed)
    ok, reason = verify_h5_auth(uid, ts, signed.rsplit("sig=", 1)[1], secret, now=ts)
    check("h5_roundtrip", ok)
    check("h5_replays_outside_window", not verify_h5_auth(uid, ts + 301, signed.rsplit("sig=", 1)[1], secret, now=ts)[0])
    check(
        "h5_rejects_other_secret",
        not verify_h5_auth(uid, ts, signed.rsplit("sig=", 1)[1], "ff" * 32, now=ts)[0],
    )
    check("h5_rejects_uid_swap", not verify_h5_auth("other-uid", ts, signed.rsplit("sig=", 1)[1], secret, now=ts)[0])

    # Session-secret hex: the client's decoder rule and nothing looser
    # (PopopxEcoModels.swift:891-907). The odd-length case is the one worth a test:
    # `{2,64}` accepts 61 hex characters, the phone's `isMultiple(of: 2)` guard does
    # not, and the difference is a handshake frame that decodes to nothing on the
    # device — silent, because `parse(controlText:)` answers nil rather than erroring.
    check("secret_hex_accepts_32_bytes", validate_secret_hex(secret) == secret)
    check("secret_hex_accepts_one_byte", validate_secret_hex("abcd") == "abcd")
    check("secret_hex_lowercases", validate_secret_hex("AABB" * 16) == "aabb" * 16)
    check("secret_hex_trims_like_the_client", validate_secret_hex("  " + secret + "\n") == secret)
    for bad_name, bad in (
        ("odd_length", "abc" * 20 + "a"),
        ("empty", ""),
        ("whitespace_only", "   "),
        ("interior_space", "ab cd"),
        ("over_32_bytes", "ab" * 33),
        ("non_hex", "zz" * 32),
        ("not_a_string", 1234),
    ):
        try:
            validate_secret_hex(bad)
            check("secret_hex_rejects_%s" % bad_name, False)
        except EcoValidationError:
            check("secret_hex_rejects_%s" % bad_name, True)
    check("secret_hex_frame_would_be_dropped_by_client", len("abc" * 20 + "a") % 2 == 1)

    # Envelope byte layout: AAD and preimage, checked against a hand-built expectation.
    chan = "popopx-channel-1"
    pub = bytes(range(32))
    expected_aad = b"popopx.channel.enc.v1|" + chan.encode() + b"|7|" + pub
    check("aad_layout", envelope_aad(chan, 7, pub) == expected_aad)
    nonce = bytes(range(12))
    blob = b"\x01" * 32 + b"\x02" * 16
    expected_pre = (
        b"popopx.channel.enc.v1|" + chan.encode() + b"|7|" + nonce + b"|" + blob
    )
    check("preimage_layout", signing_preimage(chan, 7, nonce, blob) == expected_pre)
    check("preimage_is_not_the_aad", signing_preimage(chan, 7, nonce, blob) != envelope_aad(chan, 7, pub))

    # base64 variants: the two are NOT interchangeable and the client uses both.
    raw = bytes([0xFB, 0xFF, 0xBF])
    check("b64_std_padded", b64_std(raw) == "+/+/")
    check("b64_url_unpadded", b64_url(raw) == "-_-_")
    check("b64_lenient_reads_both", b64_decode_lenient(b64_std(raw)) == raw and b64_decode_lenient(b64_url(raw)) == raw)
    key32 = bytes(range(32))
    # 32 bytes = 10 full 3-byte groups (40 chars) + 2 leftover bytes (3 chars),
    # so the padded form is 44 with one '=' and the URL form is 43. The client
    # re-pads by remainder (PopopxSecurePayload.swift:424-427): 43 % 4 == 3 → "=".
    check("epoch_key_b64url_43_chars", len(b64_url(key32)) == 43 and "=" not in b64_url(key32))

    # Epoch secret plaintext: required keys, optional identity handover only when given.
    plain = json.loads(epoch_secret_plaintext(4, key32).decode("utf-8"))
    check("epoch_secret_keys", set(plain) == {"epoch", "keyBase64URL"})
    plain2 = json.loads(epoch_secret_plaintext(4, key32, identity_public_key=pub, expires_at_ms=1).decode("utf-8"))
    check("epoch_secret_handover_present", set(plain2) == {"epoch", "keyBase64URL", "publicKeyBase64URL", "expiresAtMs"})

    # ku frame rejects the self-decrypting shape.
    try:
        frame_channel_key_update(chan, 3, False, {"protocol": ChannelEnvelope.PROTOCOL, "epoch": 3})
        check("ku_rejects_equal_epoch", False)
    except EcoValidationError:
        check("ku_rejects_equal_epoch", True)

    # Limits that would otherwise be silent drops.
    for name, thunk in {
        "card_id_too_long": lambda: build_card("x" * 65, "t"),
        "title_too_long": lambda: build_card("c", "x" * 121),
        "body_too_long": lambda: build_card("c", "t", body="x" * 2001),
        "too_many_fields": lambda: build_card("c", "t", fields=[{"k": "a", "v": "b"}] * 9),
        "too_many_actions": lambda: build_card(
            "c", "t", actions=[build_action(action_id=str(i), title="x", kind="send_cmd", payload="p") for i in range(5)]
        ),
        "duplicate_action_id": lambda: build_card(
            "c",
            "t",
            actions=[
                build_action(action_id="same", title="a", kind="send_cmd", payload="p"),
                build_action(action_id="same", title="b", kind="send_cmd", payload="p"),
            ],
        ),
        "missing_style": lambda: build_card("c", "t", style="premium"),
        "menu_pay_credits": lambda: build_menu(
            [{"title": "a", "kind": "click", "action": build_action(action_id="x", title="pay", kind="pay_credits", amount=5)}]
        ),
        "unknown_action_kind": lambda: build_action(action_id="x", title="t", kind="launch_missiles"),
        "credits_over_ceiling": lambda: build_action(action_id="x", title="t", kind="pay_credits", amount=100_001),
        "open_channel_bad_uri": lambda: build_action(action_id="x", title="t", kind="open_channel", payload="popopx://channel/a"),
        "url_without_host": lambda: validate_http_url("https:///nope"),
    }.items():
        try:
            thunk()
            check("rejects_" + name, False)
        except EcoValidationError:
            check("rejects_" + name, True)

    # A menu read back out of storage is the flattened wire shape, and the console
    # posts that shape straight back in. `build_menu` must be idempotent or "edit
    # the menu" is impossible while "set the menu" still appears to work.
    once = build_menu(
        [
            {"title": "订单", "kind": "click", "action": {"action": "callback", "payload": "kw:order"}},
            {"title": "说明", "kind": "view", "action": {"action": "open_url", "url": "https://a.test/i"}},
            {"title": "更多", "kind": "click", "sub_items": [
                {"title": "订阅", "kind": "click", "action": {"action": "open_channel", "payload": "green"}}]},
        ],
        7,
    )
    check("build_menu_is_idempotent", build_menu(once["items"], 7) == once)

    # Card style/version required by the decoder, never defaulted away here.
    minimal = build_card("c-min", "hi")
    check("card_always_has_v_and_ut", "v" in minimal and "ut" in minimal and isinstance(minimal["ut"], int))
    check("card_no_nested_mode", "m" not in minimal)

    # Voucher canonical form against the vector shared with the minting tool.
    canonical = voucher_canonical_payload("V-0001", "startup", 500, 1767225600000, None, "k-test")
    check("voucher_vector_matches", canonical == VOUCHER_TEST_VECTOR_PAYLOAD)
    check("voucher_field_count", len(VOUCHER_TEST_VECTOR_PAYLOAD.split("|")) == VOUCHER_FIELDS)

    # Card audit seal round-trips (server-side only; see divergence 1).
    sig, ts_ms = seal_card({"id": "c-1", "title": "订单", "ut": 1767225600123}, secret, credits_amount=10)
    check("card_seal_roundtrip", verify_card_seal({"id": "c-1", "title": "订单", "ut": 1767225600123}, secret, sig, ts_ms, 10))
    check(
        "card_seal_detects_edit",
        not verify_card_seal({"id": "c-1", "title": "退款", "ut": 1767225600123}, secret, sig, ts_ms, 10),
    )

    return checks


def crypto_self_test() -> List[str]:
    """The `cryptography`-dependent half: seal, verify, open, and reject a forgery.

    Runs only where the wheel is installed. It is a same-language round-trip, so
    it cannot prove cross-language agreement with CryptoKit — that is what the
    Swift oracle in `official_tools/swift_crypto_oracle.swift` is for. What it does prove is that this module uses
    the primitives in the shape the client's code describes (tag appended, AAD on
    both sides, signature over the raw preimage).
    """
    checks: List[str] = []
    private, public = make_channel_identity()
    if len(private) != 32 or len(public) != 32:
        raise AssertionError("identity keys are not raw 32 bytes")
    checks.append("identity_keypair_raw32")
    check_channel = "ch-selftest"
    epoch_key = make_epoch_key()
    plaintext = epoch_secret_plaintext(2, epoch_key)
    envelope = seal_envelope(check_channel, 2, epoch_key, plaintext, private, public)
    checks.append("envelope_keys=%s" % ",".join(sorted(envelope)))
    opened = open_envelope(check_channel, envelope, epoch_key, public)
    if opened != plaintext:
        raise AssertionError("round-trip changed the plaintext")
    checks.append("envelope_roundtrip")

    for name, mutation in {
        "wrong_channel": lambda: open_envelope("other-channel", envelope, epoch_key, public),
        "wrong_key": lambda: open_envelope(check_channel, envelope, make_epoch_key(), public),
    }.items():
        try:
            mutation()
            checks.append("rejected_%s=False" % name)
            raise AssertionError("envelope accepted %s" % name)
        except EcoError:
            checks.append("rejected_" + name)

    tampered = dict(envelope)
    raw_ct = bytearray(b64_decode_lenient(envelope["ciphertext"]))
    raw_ct[0] ^= 0x01
    tampered["ciphertext"] = b64_std(bytes(raw_ct))
    try:
        open_envelope(check_channel, tampered, epoch_key, public)
        raise AssertionError("tampered ciphertext was accepted")
    except EcoError:
        checks.append("rejected_tampered_ciphertext")
    return checks


# ─────────────────────────────────────────────────────────────────────────────
# 13. Cross-implementation fixture CLI
# ─────────────────────────────────────────────────────────────────────────────
#
# `crypto_self_test()` above is a same-language round trip: it can prove this
# module is internally consistent, and it cannot prove a phone will read what we
# write. `official_tools/swift_crypto_oracle.swift` is the other half — it speaks
# the envelope with CryptoKit, the framework the client's own
# ChannelKeyRotationManager.swift:134-251 uses. The two halves exchange a fixture
# file and each checks the other's bytes, in both directions.
#
#   /usr/bin/swiftc -o /tmp/oracle official_tools/swift_crypto_oracle.swift
#   python3 -m app.crypto_service emit /tmp/py.json          # Python seals
#   /tmp/oracle verify /tmp/py.json                           # CryptoKit opens it
#   /tmp/oracle seal --out /tmp/sw.json                       # CryptoKit seals
#   python3 -m app.crypto_service open /tmp/sw.json           # Python opens it
#   python3 -m app.crypto_service open /tmp/sw.json --tamper aad   # and refuses a forgery

FIXTURE_PLAINTEXT = b'{"epoch":3,"keyBase64URL":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}'
FORGERY_CHANNEL = "ch-a-different-channel"


def build_aad_forgery(
    channel_id: str,
    epoch: int,
    epoch_key: bytes,
    plaintext: bytes,
    identity_private_key: bytes,
    identity_public_key: bytes,
) -> Dict[str, Any]:
    """Signed correctly for `channel_id`, sealed for somebody else's AAD.

    Making one needs the identity private key, so the emitter builds the finished
    bytes and the fixture carries those: neither implementation ever writes a signing
    key to disk, and the peer can still be shown the forgery it has to refuse. This is
    the only mutation that tests the AAD rather than the signature — everything else
    an attacker can reach already invalidates the signature first.
    """
    lib = _require_crypto()
    nonce = secrets.token_bytes(ChannelEnvelope.NONCE_BYTES)
    sealed = lib["ChaCha20Poly1305"](epoch_key).encrypt(
        nonce, plaintext, envelope_aad(FORGERY_CHANNEL, epoch, identity_public_key)
    )
    signature = lib["Ed25519PrivateKey"].from_private_bytes(identity_private_key).sign(
        signing_preimage(channel_id, epoch, nonce, sealed)
    )
    return {
        "protocol": ChannelEnvelope.PROTOCOL,
        "epoch": epoch,
        "nonce": b64_std(nonce),
        "ciphertext": b64_std(sealed),
        "signature": b64_std(signature),
    }


def build_fixture(
    channel_id: str = "ch-cross-check",
    epoch: int = 2,
    plaintext: bytes = FIXTURE_PLAINTEXT,
) -> Dict[str, Any]:
    """Seal one envelope and record every intermediate byte the peer must agree on.

    `aad` and `preimage` are the point of the whole exercise: a tag that verifies
    under our AAD and fails under the client's is indistinguishable from a correct
    implementation at this end, so they are written out rather than recomputed.
    """
    private, public = make_channel_identity()
    epoch_key = make_epoch_key()
    envelope = seal_envelope(channel_id, epoch, epoch_key, plaintext, private, public)
    return {
        "channel_id": channel_id,
        "epoch": epoch,
        "plaintext": b64_std(plaintext),
        # No `identity_private`: nothing on the receiving side needs it, and a fixture
        # file that carries a signing key is a fixture that leaks one.
        "identity_public": b64_std(public),
        "epoch_key": b64_std(epoch_key),
        "aad": b64_std(envelope_aad(channel_id, epoch, public)),
        "preimage": b64_std(
            signing_preimage(
                channel_id,
                epoch,
                b64_decode_lenient(envelope["nonce"]),
                b64_decode_lenient(envelope["ciphertext"]),
            )
        ),
        "envelope": envelope,
        "forgery_aad": build_aad_forgery(channel_id, epoch, epoch_key, plaintext, private, public),
        "sealed_by": "gateway crypto_service",
    }


def read_fixture(path: str) -> Dict[str, Any]:
    with open(path, "rb") as handle:
        fixture = json.loads(handle.read())
    missing = [key for key in ("channel_id", "epoch", "plaintext", "identity_public", "epoch_key", "envelope")
               if key not in fixture]
    if missing:
        raise EcoError("fixture_incomplete", "no %s in %s" % (",".join(missing), path))
    return fixture


def open_fixture(fixture: Dict[str, Any], tamper: str = "none") -> str:
    """Open a fixture written by either implementation. `tamper` must make it fail.

    The three forgeries break a *different* guarantee each, which is why all three
    are exercised: `signature` and `ciphertext` are both caught by the Ed25519 check
    (the client verifies first, `ChannelKeyRotationManager.swift:215`), while `aad`
    is signed correctly and only fails on the AEAD tag — the one mutation that would
    still decrypt if the AAD were shorter or taken from the frame.
    """
    channel_id = str(fixture["channel_id"])
    epoch = int(fixture["epoch"])
    public = b64_decode_lenient(fixture["identity_public"])
    epoch_key = b64_decode_lenient(fixture["epoch_key"])
    plaintext = b64_decode_lenient(fixture["plaintext"])
    envelope = dict(fixture["envelope"])
    if tamper not in ("none", "signature", "ciphertext", "aad"):
        raise EcoError("tamper_mode", "no such mode %r" % tamper)
    if tamper in ("signature", "ciphertext"):
        field = tamper
        raw = bytearray(b64_decode_lenient(envelope["ciphertext" if field == "ciphertext" else "signature"]))
        raw[0] ^= 0x01
        envelope[field] = b64_std(bytes(raw))
    elif tamper == "aad":
        forgery = fixture.get("forgery_aad")
        if forgery is None:
            raise EcoError("fixture_incomplete", "the fixture has no forgery_aad to replay")
        envelope = dict(forgery)
    try:
        got = open_envelope(channel_id, envelope, epoch_key, public)
    except EcoError as exc:
        if tamper == "none":
            raise
        return "refused (%s: %s)" % (exc.rule, exc.detail)
    if tamper != "none":
        raise EcoError("tamper_not_caught", "%s was accepted as valid" % tamper)
    if got != plaintext:
        raise EcoError("plaintext_mismatch", "opened bytes differ from the fixture")
    derived = (
        ("aad", envelope_aad(channel_id, epoch, public), fixture.get("aad")),
        ("preimage",
         signing_preimage(channel_id, epoch, b64_decode_lenient(envelope["nonce"]),
                          b64_decode_lenient(envelope["ciphertext"])), fixture.get("preimage")),
    )
    for name, ours, theirs in derived:
        if theirs is None:
            continue
        if b64_std(ours) != b64_std(b64_decode_lenient(theirs)):
            raise EcoError("%s_disagreement" % name, "this module and the fixture derive different bytes")
    return "opened %d bytes; aad and preimage agree" % len(got)


def _fixture_main(argv: Sequence[str]) -> int:
    parser = argparse.ArgumentParser(
        prog="python3 -m app.crypto_service",
        description="Cross-implementation fixture tool: pair with official_tools/swift_crypto_oracle.swift.",
    )
    sub = parser.add_subparsers(dest="verb")
    emit = sub.add_parser("emit", help="seal a fixture with this module and write it out")
    emit.add_argument("path")
    emit.add_argument("--channel", default="ch-cross-check")
    emit.add_argument("--epoch", type=int, default=2)
    read = sub.add_parser("open", help="open a fixture sealed by either implementation")
    read.add_argument("path")
    read.add_argument("--tamper", default="none", choices=("none", "signature", "ciphertext", "aad"))
    args = parser.parse_args(list(argv))
    try:
        if args.verb == "emit":
            payload = build_fixture(args.channel, args.epoch)
            with open(args.path, "w", encoding="utf-8") as handle:
                handle.write(compact_json(payload) + "\n")
            print("emitted %s (sealed by %s)" % (args.path, payload["sealed_by"]))
            return 0
        if args.verb == "open":
            fixture = read_fixture(args.path)
            print("%s <- %s: %s" % (args.path, fixture.get("sealed_by", "unknown"),
                                    open_fixture(fixture, args.tamper)))
            return 0
    except (EcoError, OSError) as exc:
        print("%s: %s" % (type(exc).__name__, exc), file=sys.stderr)
        return 1
    parser.print_help()
    return 2


if __name__ == "__main__":  # pragma: no cover - the CLI is a release-verification tool
    raise SystemExit(_fixture_main(sys.argv[1:]))
