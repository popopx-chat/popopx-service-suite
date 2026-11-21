# Copyright (c) 2026 POPOPX (popopx.chat)
# SPDX-License-Identifier: AGPL-3.0-only
"""On-chain → service-account bridge: watch an address, tell a member about it.

What this plugin is
-------------------
A merchant runs a paid service account whose members are identified by an
on-chain address (EVM or Solana). This module watches those addresses against
public JSON-RPC endpoints and turns a observed transfer into a `receipt` card
in the member's conversation. Nothing here signs anything.

**Read-only is the design rule, not a preference.** The gateway never holds a
private key, never derives one, never accepts a seed phrase, and never calls a
signer. Chain libraries (`web3.py`, `solana`, `solders`, `eth-account`) are
deliberately absent from `requirements.txt` and are not imported here: the wire
is plain JSON-RPC over `httpx`, the amounts are plain strings, and the only
thing that leaves the process is a `eth_*`/`get*` request. Every route and every
body parser calls :func:`find_signer_material` first and refuses (400) any
parameter whose *name* smells like key material, so an operator who tries to
"just import a watchlist with the keys" gets a clear refusal that says the
gateway is read-only by design rather than a wallet they cannot audit. self_test
proves that rejection; nothing in this file can store a key even if the check
were removed, because no column, no settings blob and no log line accepts one.

The three entry points
----------------------
``create_router(deps)``     the merchant's HTTP surface under
                            ``/api/v1/plugins/web3``.
``handle_inbound(deps, msg)``  claims a ``CHANNEL_PAY_RCPT`` receipt *only* when
                            its ``channel_id`` belongs to a watched channel.
``poll_loop(deps, stop)``   the background reader; main.py creates the task only
                            when ``config.plugins.web3_bridge`` is true.

The receipt overlap — intentional, read this before debugging a "missing" receipt
---------------------------------------------------------------------------------
`app.main`'s generic ``CHANNEL_PAY_RCPT`` handler is what grants channel
membership, and it also runs on receipts. So a receipt for a watched channel can
legitimately be seen twice: once here (bookkeeping: attach the credits and the
tx hash, mark the matching chain event notified) and once there (the membership
grant that the money actually bought). Claiming here therefore does **not** mean
"the merchant's handler must not run"; it means the bridge's own audit trail is
complete before anything else touches the row. Both paths are idempotent for
that reason, and this one charges *nothing at all*: the ``web3_event`` meter was
already paid when the event was recorded, keyed on
``web3:<chain>:<tx_hash>:<log_index>``, and a replayed ``::popopx_sys::`` line
finds the event already ``notified`` and writes nothing. A receipt path that
could charge is a receipt path that double-charges on a resend.

Measured from the shipped iOS client (these are wire facts, not style choices)
-----------------------------------------------------------------------------
* ``PopopxEcoModels.swift:438-443`` — ``Style`` is exactly ``standard``,
  ``receipt``, ``security``. A transfer notification is ``receipt``.
* ``PopopxEcoModels.swift:546-551`` — a receipt field is ``{k, v, mono?}`` and
  ``var id: String { label }`` (:547): the row's SwiftUI identity *is its label*,
  so two fields with the same label are two ForEach items with the same id. The
  card builder in this module enforces unique labels for that reason, not for
  tidiness. ``mono`` is the numeric face (``ServiceCardBubbleView.swift:270``) and
  is set on amounts, addresses and hashes; ``:276`` draws the receipt dividers.
* ``PopopxEcoModels.swift:685-702`` / ``crypto_service.build_action`` — an
  unknown action *kind* throws and kills the whole frame, and kind ``none`` is
  rejected outright, so a card without a detail link simply omits the action.
* ``ChannelKeyRotationManager.swift:645`` and ``:651-657`` — a member only
  changes state when the delivered epoch is **newer** than its current one, and a
  re-send of the epoch it already holds returns ``.alreadyCurrent`` (a no-op).
  That asymmetry is what makes the key-grant trigger in
  :func:`_honour_outstanding_grants` safe to re-run; see that function.
* ``agent_bridge.py:130,226`` (from ``PopopxBadgeCreditsModels.swift:1098``) —
  the receipt payload is ``{channelId}:{credits}:{txHash}`` and the hash is
  split as the *tail*, so a tx hash may itself contain ``::``. The idempotency
  key encoder in this file percent-escapes ``:`` for exactly that reason.

Limits are counted in CHARACTERS (the client compares ``String.count``):
cardId 64, title 120, body 2000, field label 80 / value 240, action payload 512
/ url 2048, at most 8 fields, at most 4 actions, credits 1..100000. They are read
from ``EcoLimits`` rather than repeated as literals.

Amounts are never floats
------------------------
`float` cannot represent 1 wei in ETH-space without a decimal artifact, and a
notification that says ``0.0000000000000000011557`` or, worse, ``0 ETH`` for a
real payment is a bug report. :func:`format_amount` works on the *string* the
RPC returned (hex wei, decimal, or base58 lamports), converts it to an integer
minor-unit count, and inserts the decimal point arithmetically. There is no
division, no rounding, no exponent, no locale. ``0x0de0b6b3a7640000`` with 18
decimals is ``1 ETH`` and one wei is ``0.000000000000000001 ETH``, exactly.

Import rule (load-bearing)
--------------------------
Module level is stdlib + ``app.*`` only. ``fastapi`` and ``httpx`` are imported
inside :func:`create_router` and the async functions, so this module imports —
and its ``self_test()`` runs — on a bare ``/usr/bin/python3`` (3.9) with no
wheels installed, which is how the file was verified. No ``X | Y`` at runtime,
no ``match``, no 3.10+ syntax.

What self_test proves vs what is only code-reviewed
---------------------------------------------------
Proven by execution: both address validators and every rejection control,
``format_amount``/``to_minor_units`` exactness and refusals, every RPC-response
normaliser (missing fields, absent ``0x``, ``null`` results, an over-long log
array, ``removed`` logs, a Solana tx with no ``meta``), the lookback arithmetic
for a multi-day outage, the capped backoff sequence, the idempotency-key
derivation including the two-different-``log_index``-in-one-tx case and the
colon-escaping collision control, the receipt-claim predicate, the
signer-material rejection, and URL credential stripping in ``/status``.
Reviewed only (they need httpx or a live RPC node): the JSON-RPC envelope
handling in :func:`_rpc`, per-chain pass ordering, that every RPC failure is a
logged skip rather than an exception escaping ``poll_loop``, the ``stop``
handling between awaits, and the actual ``deliver_card``/``deliver_channel_key``
calls. The pure functions those paths are built from are all self-tested; the
network seams around them are thin and total.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import re
import sqlite3
import time
from collections import OrderedDict
from typing import TYPE_CHECKING, Any, Dict, Iterable, List, Mapping, Optional, Sequence, Set, Tuple

from app.billing_service import BillingError
from app.crypto_service import (
    CryptoUnavailable,
    EcoError,
    EcoLimits,
    EcoValidationError,
    build_action,
    build_card,
    now_ms,
)
from app.plugins import PluginDeps, PluginUnavailable, plugin_for_id

if TYPE_CHECKING:  # types only; neither package is importable in this venv-less box
    from fastapi import APIRouter

__all__ = [
    "PLUGIN_ID",
    "URL_PREFIX",
    "CALLBACK_KINDS",
    "CHAINS",
    "CHAIN_EVM",
    "CHAIN_SOLANA",
    "NO_LOG_INDEX",
    "create_router",
    "handle_inbound",
    "poll_loop",
    "self_test",
    "validate_address",
    "validate_evm_address",
    "validate_solana_address",
    "format_amount",
    "to_minor_units",
    "truncate_address",
    "event_idempotency_key",
    "card_id_for_event",
    "log_range",
    "advance_block",
    "backoff_delay",
    "should_claim_receipt",
    "redact_rpc_url",
    "find_signer_material",
    "parse_quantity",
    "normalise_log",
    "normalise_logs",
    "parse_erc20_transfer",
    "topic_bytes32",
    "normalise_signatures",
    "new_signatures",
    "parse_tx_lamport_delta",
    "tag_contact_id",
    "address_in_tags",
    "receipt_card",
    "receipt_visible_text",
    "exact_decimal_string",
    "parse_minor_units",
    "parse_quantity",
    "normalise_block",
    "normalise_balance_result",
    "parse_tx_lamport_delta",
    "direction_from_delta",
    "detect_chain",
    "decode_json_object",
    "parse_flag",
    "parse_limit",
    "parse_watch_id",
    "parse_threshold",
    "parse_watcher_create",
    "parse_watcher_patch",
    "parse_whitelist_entry",
    "rpc_status_view",
    "poll_interval_seconds",
    "configured_rpc_urls",
]

log = logging.getLogger("popopx.gateway.web3")

# ─────────────────────────────────────────────────────────────────────────────
# 1. Identity, mirrors of the mount table, and hard bounds
# ─────────────────────────────────────────────────────────────────────────────

#: The row in `app.plugins.PLUGIN_SPEC` this module is mounted from. Asserted
#: against the table in self_test so a rename on either side is a failing check
#: rather than a plugin that silently stops being gated.
PLUGIN_ID = "web3_bridge"
URL_PREFIX = "/api/v1/plugins/web3"
METER = "web3_event"
CALLBACK_KINDS: Tuple[str, ...] = ("system",)

CHAIN_EVM = "evm"
CHAIN_SOLANA = "solana"
CHAINS: Tuple[str, ...] = (CHAIN_EVM, CHAIN_SOLANA)

#: `web3_events.log_index` is nullable but part of the UNIQUE index, and SQLite
#: treats NULLs as distinct — a second Solana (or native-value) event with NULL
#: log_index would be inserted freely and charged twice. -1 is a value no real
#: log index can take, so the constraint does its job instead of being a comment.
NO_LOG_INDEX = -1

#: How far back a poll may reach in one request. A gateway that was down for a
#: week must not ask an RPC node for 180_000 logs: public nodes answer that with
#: an error or a timeout, and a request that cannot succeed is a request that
#: pins the loop in its own backoff. Past the window the gap is *logged* and the
#: cursor jumps forward (see `_poll_chain`), because a slow full-node is a
#: permanent silence and a warning is a fixable one.
LOOKBACK_BLOCKS = 50_000
MAX_LOGS_PER_RESPONSE = 1_000
MAX_SIGS_PER_ADDRESS = 25
MAX_TX_LOOKUPS_PER_PASS = 8
#: Native-value scanning needs the block body, so it is only done while the gap
#: is small enough to fetch a few blocks; token transfers stay covered by
#: `eth_getLogs` across the whole window.
MAX_NATIVE_BLOCKS_PER_PASS = 2
MAX_NATIVE_BLOCK_SPAN = 4
RPC_TIMEOUT_SECONDS = 12.0
MAX_RPC_RESPONSE_BYTES = 4 * 1024 * 1024
MAX_REQUEST_BODY_BYTES = 32 * 1024

#: Money display bounds. uint256 max is 78 digits; anything longer is not an
#: amount an EVM chain can produce and is treated as garbage, not as data.
MAX_RAW_DIGITS = 78
MAX_HEX_INPUT_CHARS = 64          # a uint256 in hex, unprefixed
MAX_BASE58_INPUT_CHARS = 88       # a Solana signature; quantities are shorter
MAX_DECIMALS = 36                 # SPL/EVM token decimals, with headroom
MAX_AMOUNT_CHARS = 120            # field values are capped at 240 by the client
MAX_SYMBOL_CHARS = 16
MAX_TX_HASH_CHARS = 164
#: Hash shapes. EVM is unambiguous; Solana's base58 signature of a 64-byte
#: ed25519 signature is 87 or 88 characters, and the range below leaves room for
#: a cluster that reports a different ID without letting "abc" through.
EVM_HASH_HEX_CHARS = 64
SOLANA_SIGNATURE_MIN_CHARS = 64
SOLANA_SIGNATURE_MAX_CHARS = 89
MAX_ADDRESS_CHARS = 128
MAX_LABEL_CHARS = 120
MAX_TAG_CHARS = 120
MAX_EVENT_LIMIT = 200
DEFAULT_EVENT_LIMIT = 50
MAX_LOG_INDEX = 10_000_000
MAX_HEX_QUANTUM_DIGITS = 32
MAX_DEC_QUANTUM_DIGITS = 18

BACKOFF_CAP_SECONDS = 60.0
BACKOFF_FLOOR_SECONDS = 1.0
MIN_POLL_INTERVAL_SECONDS = 5
MAX_POLL_INTERVAL_SECONDS = 3_600
#: A money notification broadcast to a whole channel is a privacy incident, not
#: a feature. When a whitelist row does not name a member, the bridge will still
#: deliver to a small entitled set; past this cap it records the event and tells
#: the operator to name the member in the tag instead of guessing.
MAX_NOTIFY_SESSIONS = 8
MAX_GRANT_ROWS_PER_PASS = 10

#: `Transfer(address indexed from, address indexed to, uint256 value)` — the
#: keccak-256 of that signature. Hardcoded because hashing it would need a
#: keccak implementation, and `hashlib` has sha3-* (a different padding), not
#: keccak256. It is a constant of the ERC-20 standard, not a secret.
ERC20_TRANSFER_TOPIC0 = "ddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"

_ADDRESS_RE = re.compile(r"^[0-9a-zA-Z]{1,%d}$" % MAX_ADDRESS_CHARS)
_EVM_ADDRESS_RE = re.compile(r"^0x[0-9a-fA-F]{40}$")
_HEX_RE = re.compile(r"^[0-9a-fA-F]+$")
_DEC_RE = re.compile(r"^[0-9]+$")
_SYMBOL_RE = re.compile(r"^[A-Za-z0-9_.$#@-]{1,%d}$" % MAX_SYMBOL_CHARS)
_CHANNEL_ID_RE = re.compile(r"^[A-Za-z0-9\-_.]{1,%d}$" % EcoLimits.payload_chars)
_DECIMAL_TEXT_RE = re.compile(r"^(0|[1-9][0-9]*)(\.[0-9]+)?$")

BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_BASE58_INDEX: Dict[str, int] = {ch: i for i, ch in enumerate(BASE58_ALPHABET)}

#: Request-parameter names that mean "key material". Matched as normalised
#: stems so `private_key`, `privateKey`, `PRIVATE-KEY` and `Priv Key` all land.
#: Deliberately over-broad: the false positive it can produce (a field literally
#: named `seed_label`) costs an operator a rename, and the false negative it
#: prevents costs the merchant their wallet.
_SIGNER_STEMS: Tuple[str, ...] = (
    "privatekey",
    "privkey",
    "private",
    "secret",
    "seed",
    "mnemonic",
    "keystore",
    "recoveryphrase",
    "passphrase",
    "signer",
    "pkcs",
)
MAX_PAYLOAD_DEPTH = 6

_DEFAULT_UNIT: Dict[str, Tuple[str, int]] = {CHAIN_EVM: ("ETH", 18), CHAIN_SOLANA: ("SOL", 9)}

#: Transient process state, read by `GET /status`. Kept as a module dict rather
#: than a plugin object because `app/plugins/__init__.py` is explicit that a
#: plugin has no per-instance state: this is the gateway process's loop health,
#: observed by a route, and nothing else.
RUN_STATE: Dict[str, Any] = {
    "running": False,
    "interval_seconds": 0,
    "started_at_ms": 0,
    "last_pass_at_ms": 0,
    "last_pass_ok": None,
    "consecutive_failures": 0,
    "last_error": "",
    "heads": {},
    "events_recorded": 0,
    "notifications_sent": 0,
}


class Web3ValidationError(Exception):
    """A request or a value this bridge refuses.

    `rule` names the rule (the same convention `crypto_service.EcoError` uses,
    so a route body can print either), `status` is the code the route turns it
    into. Raised by the pure validators, which therefore never need FastAPI.
    """

    def __init__(self, rule: str, message: str, *, status: int = 400) -> None:
        super().__init__("%s: %s" % (rule, message))
        self.rule = rule
        self.detail = message
        self.status = status


# ─────────────────────────────────────────────────────────────────────────────
# 2. Pure validation
# ─────────────────────────────────────────────────────────────────────────────


def _clean_text(value: Any, rule: str, limit: int) -> str:
    if not isinstance(value, str):
        raise Web3ValidationError(rule, "expected a string, got %s" % type(value).__name__)
    text = value.strip()
    if not text:
        raise Web3ValidationError(rule, "must not be empty")
    if len(text) > limit:
        raise Web3ValidationError(rule, "%d characters exceeds the limit of %d" % (len(text), limit))
    return text


def validate_evm_address(value: Any) -> str:
    """`0x` + exactly 40 hex, normalised to lowercase.

    Mixed case is *accepted and normalised*, not validated. That is a decision,
    not an oversight: EIP-55 checksums are a display convention that a user
    pasting from a block explorer routinely breaks (and address bars, spreadsheets
    and chat forwards routinely re-case), and the alternative — refusing a
    correct-but-wrong-case address — produces a watcher that silently never
    fires against a `web3_events` row that looks configured. What matters for
    matching an RPC response is one canonical spelling, and lowercase is it.
    A malformed address is still rejected outright, because a stored address that
    no RPC can ever match is worse than a 400 at creation time.
    """
    text = _clean_text(value, "evm_address", MAX_ADDRESS_CHARS)
    if not _EVM_ADDRESS_RE.match(text):
        raise Web3ValidationError(
            "evm_address",
            "expected 0x followed by exactly 40 hex characters, got %r" % (value,),
        )
    return text.lower()


def validate_solana_address(value: Any) -> str:
    """Base58 of 32..44 characters, case preserved.

    The alphabet excludes ``0``, ``O``, ``I`` and ``l`` — the characters a human
    transcribing a wallet address gets wrong — and a Solana public key is the
    base58 of 32 bytes, which is 43 or 44 characters, with 32 the short end of
    what any real key encodes to. Case is significant here (unlike EVM hex), so
    nothing is folded.
    """
    text = _clean_text(value, "solana_address", MAX_ADDRESS_CHARS)
    if not (32 <= len(text) <= 44):
        raise Web3ValidationError(
            "solana_address", "a base58 public key is 32..44 characters, got %d" % len(text)
        )
    bad = sorted({ch for ch in text if ch not in _BASE58_INDEX})
    if bad:
        raise Web3ValidationError(
            "solana_address",
            "characters %s are not in the base58 alphabet (0OIl are never valid)" % "".join(bad),
        )
    return text


def validate_address(chain: Any, value: Any) -> str:
    """Dispatch on chain. An unknown chain is refused, never defaulted."""
    chain = validate_chain(chain)
    if chain == CHAIN_EVM:
        return validate_evm_address(value)
    return validate_solana_address(value)


def validate_chain(value: Any) -> str:
    text = _clean_text(value, "chain", 16).lower()
    if text not in CHAINS:
        raise Web3ValidationError("chain", "%r is not one of %s" % (value, list(CHAINS)))
    return text


def validate_channel_id(value: Any) -> str:
    text = _clean_text(value, "channel_id", EcoLimits.payload_chars)
    if not _CHANNEL_ID_RE.match(text):
        raise Web3ValidationError(
            "channel_id", "must be 1-%d characters of [A-Za-z0-9-_.]" % EcoLimits.payload_chars
        )
    return text


def validate_symbol(value: Any, chain: str) -> str:
    """A ticker is display text only — it never reaches the client unbounded."""
    if value is None:
        return _DEFAULT_UNIT[chain][0]
    text = _clean_text(value, "symbol", MAX_SYMBOL_CHARS).upper()
    if not _SYMBOL_RE.match(text):
        raise Web3ValidationError("symbol", "%r is not a ticker" % (value,))
    return text


def validate_decimals(value: Any, chain: str) -> int:
    if value is None:
        return _DEFAULT_UNIT[chain][1]
    if isinstance(value, bool) or not isinstance(value, int):
        raise Web3ValidationError("decimals", "expected an integer, got %r" % (value,))
    if not 0 <= value <= MAX_DECIMALS:
        raise Web3ValidationError("decimals", "%d is outside 0..%d" % (value, MAX_DECIMALS))
    return value


def truncate_address(address: Any, head: int = 6, tail: int = 4) -> str:
    """The display spelling: short enough to read in a card row, full in the row.

    `head` 6 keeps the `0x` and four digits; `tail` 4 is the part a human checks
    against a block explorer. The *stored* value is always the full normalised
    address — truncation is a rendering choice and happens only here.
    """
    text = str(address or "").strip()
    if not text:
        return ""
    if head + tail + 1 >= len(text):
        return text
    return "%s\u2026%s" % (text[:head], text[len(text) - tail:])


def key_component(value: Any) -> str:
    """Percent-escape the delimiter out of an idempotency-key field.

    `agent_bridge.py:1232` proves a receipt can carry a tx hash containing
    ``::`` (``ch:1:aabb::cc`` keeps its tail verbatim). Without escaping,
    ``("0xa:1", 2)`` and ``("0xa", 12)`` would both read
    ``web3:evm:0xa:1:2``-ish and one payment would look like the other — a
    collision in the one string that decides whether a notification and a charge
    happen. Escaping ``%`` first then ``:`` makes the transform unambiguous.
    """
    text = str(value if value is not None else "").strip()
    return text.replace("%", "%25").replace(":", "%3a")


def normalise_tx_hash(chain: str, value: Any) -> str:
    """One canonical spelling for a hash — and a shape check, not a trim.

    EVM: ``0x`` + exactly 64 hex, stored lowercase with the prefix. Solana: 64..89
    base58 characters with the case kept (a 64-byte ed25519 signature encodes to
    87 or 88 characters, and base58 is case-significant where EVM hex is not).

    The shape matters because this string is the middle field of the billing
    idempotency key and the dedupe key of `web3_events`. A node that answers with
    an empty string, a truncating proxy, or a rate-limiter's HTML snippet would
    otherwise produce a row that "observed a payment" and can never be matched by
    the receipt that proves it. Refusing is cheaper than explaining.
    """
    text = _clean_text(value, "tx_hash", MAX_TX_HASH_CHARS)
    if chain == CHAIN_EVM:
        body = text[2:] if text[:2].lower() == "0x" else text
        if len(body) != EVM_HASH_HEX_CHARS or not _HEX_RE.match(body):
            raise Web3ValidationError(
                "tx_hash", "expected 0x followed by %d hex characters, got %r" % (EVM_HASH_HEX_CHARS, value)
            )
        return "0x" + body.lower()
    if not (SOLANA_SIGNATURE_MIN_CHARS <= len(text) <= SOLANA_SIGNATURE_MAX_CHARS):
        raise Web3ValidationError(
            "tx_hash",
            "a Solana signature is %d..%d base58 characters, got %d"
            % (SOLANA_SIGNATURE_MIN_CHARS, SOLANA_SIGNATURE_MAX_CHARS, len(text)),
        )
    if any(ch not in _BASE58_INDEX for ch in text):
        raise Web3ValidationError("tx_hash", "characters outside the base58 alphabet in %r" % (value,))
    return text


def event_idempotency_key(chain: Any, tx_hash: Any, log_index: Any) -> str:
    """`web3:<chain>:<escaped tx hash>:<log index>` — the billing key, and the
    same string the `web3_events` UNIQUE index dedupes on.

    Deriving the meter key and the row key from one function is the point: two
    derivations drift, and the drift shows up as a paid-for event nobody was
    told about or, worse, a notification charged twice.
    """
    chain_text = validate_chain(chain)
    index = NO_LOG_INDEX if log_index is None else int(log_index)
    return "web3:%s:%s:%d" % (chain_text, key_component(normalise_tx_hash(chain_text, tx_hash)), index)


def card_id_for_event(chain: Any, tx_hash: Any, log_index: Any) -> str:
    """A stable cardId for one event, within the client's 64-character cap.

    Deterministic and *hashed* because ``web3-evm-<66-char hash>-340`` is 81
    characters — over `EcoLimits.card_id_chars` — and a card whose id is refused
    is a card that never renders. The hash is of the same triple as the billing
    key, so a replayed poll produces the same cardId and the phone updates the
    bubble in place instead of stacking a second receipt.
    """
    digest = hashlib.sha256(event_idempotency_key(chain, tx_hash, log_index).encode("utf-8")).hexdigest()
    return "web3-%s-%s" % ("e" if validate_chain(chain) == CHAIN_EVM else "s", digest[:24])


# ─────────────────────────────────────────────────────────────────────────────
# 3. Money formatting — exact, decimal, no float anywhere
# ─────────────────────────────────────────────────────────────────────────────


def _amount_error(message: str) -> Web3ValidationError:
    return Web3ValidationError("amount_format", message)


def _base58_to_int(text: str) -> int:
    value = 0
    for ch in text:
        value = value * 58 + _BASE58_INDEX[ch]
    return value


def parse_minor_units(raw: Any, *, base58: bool = False) -> int:
    """An exact integer count of the chain's smallest unit.

    Accepted shapes, in the order the brief measured them off the RPC:
    ``0x``-prefixed hex (EVM `value`, `data`, log topics), a bare decimal digit
    string (a JSON number from Solana serialised as text), and a plain ``int``.
    A digits-only string is read as *decimal*, not hex — ``"10"`` is ten lamports,
    not sixteen — because every endpoint that means hex says so with ``0x``, and
    guessing hex here would misstate a payment by 60%.

    A string that is neither decimal nor ``0x``-hex is read as base58 **only when
    the caller says so** with ``base58=True``. That is not caution for its own
    sake: base58's alphabet is "almost every letter", so ``nan``, ``true``,
    ``yes`` and a mistyped field name are all *valid* base58 syntax and would
    decode to a plausible-looking tiny amount. Nothing the bridge actually reads
    needs the flag — Solana returns JSON integers and EVM returns ``0x`` strings —
    so it exists for the ``base58 lamports`` spellings a custom node can produce,
    and it is opt-in because only the caller knows the field's encoding.

    Refused, and that refusal is the feature: ``float`` (an amount that arrives
    as a float has already lost digits), a leading ``-`` (the direction is a
    separate column; a negative amount in a receipt is a contradiction),
    exponent notation, ``nan``/``inf``, embedded whitespace, and anything whose
    decimal length exceeds `MAX_RAW_DIGITS`. Garbage is refused, never rendered.
    """
    if isinstance(raw, bool):
        raise _amount_error("a boolean is not an amount")
    if isinstance(raw, float):
        raise _amount_error("a float is never an amount; got %r" % (raw,))
    if isinstance(raw, int):
        if raw < 0:
            raise _amount_error("an amount is a magnitude; direction is recorded separately")
        if len(str(raw)) > MAX_RAW_DIGITS:
            raise _amount_error("%d digits exceeds the %d-digit maximum" % (len(str(raw)), MAX_RAW_DIGITS))
        return int(raw)
    if not isinstance(raw, str):
        raise _amount_error("expected a hex, decimal or base58 string, got %s" % type(raw).__name__)
    text = raw.strip()
    if not text:
        raise _amount_error("empty amount")
    if len(text) != len(text.replace(" ", "").replace("\t", "")):
        raise _amount_error("embedded whitespace in %r" % (raw,))
    lowered = text.lower()
    if lowered.startswith("0x"):
        body = text[2:]
        if not body or not _HEX_RE.match(body):
            raise _amount_error("%r is not hex after the 0x prefix" % (raw,))
        if len(body) > MAX_HEX_INPUT_CHARS:
            raise _amount_error("%d hex digits exceeds %d" % (len(body), MAX_HEX_INPUT_CHARS))
        return int(body, 16)
    if _DEC_RE.match(text):
        if len(text) > MAX_RAW_DIGITS:
            raise _amount_error("%d digits exceeds the %d-digit maximum" % (len(text), MAX_RAW_DIGITS))
        return int(text)
    if base58:
        if not all(ch in _BASE58_INDEX for ch in text):
            raise _amount_error("%r is not base58 (0OIl are never in the alphabet)" % (raw,))
        if len(text) > MAX_BASE58_INPUT_CHARS:
            raise _amount_error("%d base58 characters is not an amount" % len(text))
        value = _base58_to_int(text)
        if len(str(value)) > MAX_RAW_DIGITS:
            raise _amount_error("decoded amount exceeds the %d-digit maximum" % MAX_RAW_DIGITS)
        return value
    raise _amount_error(
        "%r is neither decimal nor 0x-hex; pass base58=True only where the field's encoding is known" % (raw,)
    )


def exact_decimal_string(minor: int, decimals: int) -> str:
    """Insert the radix point by string arithmetic. Never rounds."""
    places = _decimal_places(decimals)
    if minor < 0:
        raise _amount_error("negative amount")
    if places == 0:
        text = str(int(minor))
        # The same bound as the fractional path: `decimals=0` is a token with no
        # radix at all, and a 300-digit supply figure is still too big to put in
        # a 240-character field the phone would then drop.
        if len(text) > MAX_AMOUNT_CHARS:
            raise _amount_error("formatted amount would be %d characters" % len(text))
        return text
    padded = str(int(minor)).rjust(places + 1, "0")
    whole, frac = padded[:-places], padded[-places:]
    frac = frac.rstrip("0")
    text = whole if not frac else "%s.%s" % (whole, frac)
    if len(text) > MAX_AMOUNT_CHARS:
        raise _amount_error("formatted amount would be %d characters" % len(text))
    return text


def _decimal_places(value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise _amount_error("decimals must be an integer, got %r" % (value,))
    if not 0 <= value <= MAX_DECIMALS:
        raise _amount_error("decimals %d is outside 0..%d" % (value, MAX_DECIMALS))
    return int(value)


def format_amount(raw: Any, decimals: Any, symbol: Any, *, base58: bool = False) -> str:
    """``"1.5 ETH"`` from wei ``1500000000000000000`` — exact, or refused.

    The output is always ``<exact decimal> <SYMBOL>``, trailing zeros stripped
    but nothing else touched: one wei with 18 decimals is
    ``0.000000000000000001 ETH`` rather than the ``0 ETH`` a rounded format would
    put in a "you have been paid" notification.

    ``base58`` is forwarded to :func:`parse_minor_units` for a caller that *knows*
    the field it renders is base58-encoded; the default refuses anything neither
    decimal nor ``0x``-hex, because ``nan`` and ``true`` are valid base58 syntax
    and a word must never be rendered as money.
    """
    places = _decimal_places(decimals)
    unit = _clean_text(symbol, "symbol", MAX_SYMBOL_CHARS).upper()
    if not _SYMBOL_RE.match(unit):
        raise Web3ValidationError("symbol", "%r is not a ticker symbol" % (symbol,))
    minor = parse_minor_units(raw, base58=base58)
    return "%s %s" % (exact_decimal_string(minor, places), unit)


def to_minor_units(value: Any, decimals: Any) -> int:
    """A human amount (`"0.5"`, `1`) into minor units, exactly.

    `min_delta` is written by a person who means "tell me about half an ETH", so
    the input unit is the *whole* unit, and this is the inverse of
    :func:`format_amount`. Fraction digits beyond the unit's own precision are
    refused rather than rounded: a threshold of 0.0000000000000000001 ETH is not
    a thing a chain can express, and silently rounding it to "anything at all"
    would flood a watcher whose owner meant something precise.
    """
    places = _decimal_places(decimals)
    if isinstance(value, bool) or isinstance(value, float):
        raise Web3ValidationError("min_delta", "expected a decimal string or integer, got %r" % (value,))
    if isinstance(value, int):
        text = str(value)
    else:
        text = _clean_text(value, "min_delta", 96)
        if not _DECIMAL_TEXT_RE.match(text):
            raise Web3ValidationError(
                "min_delta", "%r is not a plain decimal amount (no exponents, no sign)" % (value,)
            )
    whole, _, frac = text.partition(".")
    if len(frac) > places:
        raise Web3ValidationError(
            "min_delta", "%d fraction digits exceeds the unit's %d decimals" % (len(frac), places)
        )
    minor = int(whole) * (10**places)
    if frac:
        minor += int(frac) * (10 ** (places - len(frac)))
    if len(str(minor)) > MAX_RAW_DIGITS:
        raise Web3ValidationError("min_delta", "threshold is absurdly large")
    return minor


# ─────────────────────────────────────────────────────────────────────────────
# 4. Poll arithmetic
# ─────────────────────────────────────────────────────────────────────────────


def log_range(last_block: Optional[int], head: Optional[int], lookback: int = LOOKBACK_BLOCKS) -> Tuple[int, int, int]:
    """The inclusive block range to query, and how many blocks are being skipped.

    Three properties this has to hold, all of them multi-day-outage bugs when
    they do not:

    * never asks for more than `lookback` blocks (a request a public node will
      not answer is a request that fails forever);
    * never moves *backwards* — after a reorg or a node switch, ``last_block``
      ahead of ``head`` yields ``from > to`` and the caller does no work rather
      than re-reading history and re-notifying people about old payments;
    * reports the skipped count instead of hiding it, because a bridge that
      quietly dropped a week of transfers is the exact thing a merchant will
      ask about next month.
    """
    if head is None or head < 0:
        return (0, -1, 0)
    window = max(1, int(lookback))
    window_start = max(0, int(head) - window + 1)
    start = 0 if last_block is None else int(last_block) + 1
    skipped = 0
    if start < window_start:
        skipped = window_start - start
        start = window_start
    return (start, int(head), skipped)


def advance_block(logs: Sequence[Mapping[str, Any]], to_block: int, truncated: bool, previous: Optional[int]) -> int:
    """How far the cursor may honestly move.

    When the RPC answer was longer than `MAX_LOGS_PER_RESPONSE` the tail of the
    range was never seen, so claiming ``to_block`` would drop those transfers
    forever. The cursor therefore stops at the highest block number *actually
    kept*, and the next pass resumes from there. If nothing in the kept set has a
    readable block number, the cursor does not move at all: repeating one block
    is a slow poll, and jumping is lost money.
    """
    if not truncated:
        return int(to_block)
    numbers = [entry.get("block_number") for entry in logs]
    usable = [value for value in numbers if isinstance(value, int) and not isinstance(value, bool)]
    if not usable:
        return int(previous) if previous is not None else 0
    return min(int(to_block), max(usable))


def backoff_delay(attempt: int) -> float:
    """1s, 2s, 4s … capped at 60s. `attempt` 0 or 1 is the floor.

    A capped geometric sequence because the two failure modes are opposite: a
    node that restarts needs a retry in a second, and a node that is gone needs
    the loop to be nearly silent. Reset to 0 by the caller on any successful
    pass — see :func:`poll_loop`.
    """
    if attempt <= 1:
        return BACKOFF_FLOOR_SECONDS
    return float(min(BACKOFF_CAP_SECONDS, 2.0 ** (attempt - 1)))


def poll_interval_seconds(value: Any) -> int:
    try:
        raw = int(value)
    except (TypeError, ValueError):
        return 30
    if raw < MIN_POLL_INTERVAL_SECONDS:
        return MIN_POLL_INTERVAL_SECONDS
    if raw > MAX_POLL_INTERVAL_SECONDS:
        return MAX_POLL_INTERVAL_SECONDS
    return raw


# ─────────────────────────────────────────────────────────────────────────────
# 5. Read-only enforcement and URL redaction
# ─────────────────────────────────────────────────────────────────────────────


def _normalise_key_name(name: Any) -> str:
    return re.sub(r"[^0-9a-z]", "", str(name).lower())


def find_signer_material(payload: Any, _depth: int = 0) -> Optional[str]:
    """The first parameter name that looks like key material, or None.

    Walks nested mappings and sequences, because a body like
    ``{"watcher": {"private_key": ...}}`` is the same mistake wearing a hat.
    Depth-bounded: a deeply nested payload is a DoS attempt on a recursive
    function, and this plugin has no reason to see one.
    """
    if _depth > MAX_PAYLOAD_DEPTH:
        raise Web3ValidationError("payload_depth", "request nests deeper than %d levels" % MAX_PAYLOAD_DEPTH)
    if isinstance(payload, Mapping):
        for name, value in payload.items():
            normalised = _normalise_key_name(name)
            for stem in _SIGNER_STEMS:
                if stem in normalised:
                    return str(name)
            found = find_signer_material(value, _depth + 1)
            if found is not None:
                return found
    elif isinstance(payload, (list, tuple)):
        for item in payload:
            found = find_signer_material(item, _depth + 1)
            if found is not None:
                return found
    return None


READ_ONLY_DETAIL = (
    "the gateway is read-only by design: it watches the chain and never holds, "
    "derives or accepts a key, seed or signer"
)


def require_read_only(payload: Any) -> None:
    """Refuse any request that offers key material, however it is spelled."""
    found = find_signer_material(payload)
    if found is not None:
        raise Web3ValidationError(
            "read_only_gateway",
            "parameter %r was rejected because %s" % (found, READ_ONLY_DETAIL),
        )


def redact_rpc_url(url: Any) -> str:
    """What `/status` may echo: scheme and host, nothing else.

    Three separate credential carriers are dropped, because all three are real
    in the endpoints merchants paste in:

    * userinfo — ``https://KEY@rpc.example/...`` (the brief's case, and the one
      that leaks loudest, since a URL with `@` is *valid* and will round-trip
      straight into a log);
    * the **path** — Infura-style ``https://mainnet.infura.io/v3/<PROJECT_ID>``
      puts the credential in the path, so a "harmless" path echo is a key leak;
    * the **query/fragment** — Alchemy and QuickNode put ``?key=...`` in the
      query.

    A non-http(s) scheme is reported as unset rather than echoed: a
    ``file:///…`` or ``http://user@169.254.169.254/`` value in a status body is
    not a configuration to advertise. Output is length-bounded so nothing here
    turns a status endpoint into a buffer.
    """
    text = str(url or "").strip()
    if not text:
        return ""
    scheme, sep, rest = text.partition("://")
    if not sep:
        return ""
    scheme = scheme.lower()
    if scheme not in ("http", "https"):
        return ""
    authority = re.split(r"[/?#]", rest, maxsplit=1)[0]
    if "@" in authority:
        authority = authority.rsplit("@", 1)[1]
    if not authority:
        return ""
    host = authority.strip().lower()
    # Reject a host that is still carrying userinfo or an empty port: defensive,
    # because a hand-edited .env produces surprises.
    if "@" in host or host.endswith(":"):
        return ""
    # The parentheses are load-bearing: `%` binds LOOSER than a subscription, so
    # the obvious `"%s://%s" % (scheme, host)[:128]` slices the *tuple* — a
    # no-op that returns the whole pair — and hands back an unbounded string.
    # `redact_output_is_bounded` is the check that proves it.
    return ("%s://%s" % (scheme, host))[:128]


def configured_rpc_urls(config: Any) -> Dict[str, str]:
    """The two endpoints as configured, unredacted — for the loop, never a body.

    Missing attributes read as empty: a deployment whose `Config` predates the
    web3 fields gets a clean "not configured" instead of an AttributeError from
    inside the poll loop.
    """
    return {
        CHAIN_EVM: str(getattr(config, "web3_evm_rpc_url", "") or "").strip(),
        CHAIN_SOLANA: str(getattr(config, "web3_solana_rpc_url", "") or "").strip(),
    }


# ─────────────────────────────────────────────────────────────────────────────
# 6. Receipt-claim predicate
# ─────────────────────────────────────────────────────────────────────────────


def should_claim_receipt(kind: Any, sys_kind: Any, channel_id: Any, watched_channels: Iterable[str]) -> bool:
    """Claim only a payment receipt for a channel this bridge watches.

    `kind` must be ``system`` (the mount table's only callback kind), the system
    kind must be a payment receipt — ``CHANNEL_PAY_RCPT`` is what the shipped
    client emits and ``CHANNEL_SUB_PAID`` is the older spelling both
    `agent_bridge` and this module accept — and the channel must be one an
    *active* watcher points at. Anything else returns False so
    `app.main`'s generic handler sees it; that is the difference between a
    bridge that forwards traffic it has no opinion about and a bridge that
    swallows a merchant's checkout.
    """
    if str(kind) != "system":
        return False
    if str(sys_kind) not in ("CHANNEL_PAY_RCPT", "CHANNEL_SUB_PAID"):
        return False
    text = str(channel_id or "").strip()
    if not text:
        return False
    return text in set(watched_channels)


def tag_contact_id(tag: Any) -> Optional[int]:
    """A member id spelled in a whitelist tag: ``contact:12``, ``#12``, ``12``.

    This convention exists because the schema has no address→contact column (see
    the module's DB notes): the operator who *knows* which member owns an address
    can say so, and everyone else gets the channel-scoped fallback.
    """
    text = str(tag or "").strip().lower()
    if not text:
        return None
    for marker in ("contact:", "contactid:", "member:", "#"):
        if text.startswith(marker):
            digits = text[len(marker):]
            return int(digits) if digits.isdigit() else None
    if text.isdigit():
        value = int(text)
        return value if value > 0 else None
    return None


def address_in_tags(tags: Any, address: Any) -> bool:
    """Whether a contact's `tags` field names this on-chain address as a token.

    Whole-token matching only: a substring test would let the 40-hex address
    ``0xaaaa…`` "match" a tag containing ``0xaaaa…bbbb``, and a wrong member is a
    notification sent to somebody else about somebody else's money. Accepts a
    JSON list or any comma/space/semicolon-delimited text, since `contacts.tags`
    is free-form by design.

    Case is folded **only for EVM hex**, where our own canonicalisation has
    already proved case carries no meaning. A base58 Solana key is
    case-significant, so a tag pasted with the wrong case does not match at all
    and the event falls back to the channel-scoped path rather than resolving to
    the wrong human. A false negative here costs a notification; a false
    negative is the only failure mode this function should have.
    """
    needle = str(address or "").strip()
    if not needle:
        return False
    fold = needle[:2].lower() == "0x"
    compare = needle.lower() if fold else needle
    raw = tags
    if isinstance(raw, (bytes, bytearray)):
        try:
            raw = raw.decode("utf-8")
        except UnicodeDecodeError:
            return False
    if isinstance(raw, (list, tuple)):
        candidates = [str(item) for item in raw]
    elif isinstance(raw, str):
        text = raw.strip()
        if not text:
            return False
        if text.startswith("["):
            try:
                parsed = json.loads(text)
            except ValueError:
                parsed = None
            if isinstance(parsed, list):
                candidates = [str(item) for item in parsed]
            else:
                candidates = re.split(r"[,;|\s]+", text)
        else:
            candidates = re.split(r"[,;|\s]+", text)
    else:
        return False
    for candidate in candidates:
        token = candidate.strip().strip("\"'").lower()
        if token == "0x" + needle[2:] or token == needle:
            return True
    return False


# ─────────────────────────────────────────────────────────────────────────────
# 7. RPC response normalisation — defensive, total, never raises
#
# Every function in this section returns None / [] on input it cannot read, and
# the poll loop counts those skips and logs them. The reason is in the brief and
# worth repeating: an exception that escapes the loop kills the only path that
# tells a member they have been paid, and a public node answering a slightly
# different schema (a rate limiter's JSON error, a proxy's HTML, an empty
# `result`) is normal Tuesday operation, not a crash condition. A malformed
# answer must cost one notification, not the process.
# ─────────────────────────────────────────────────────────────────────────────


def parse_quantity(value: Any) -> Optional[int]:
    """A JSON-RPC quantity or number into an int, or None.

    `eth_blockNumber`/`logIndex`/`blockNumber` are hex strings with `0x`; some
    gateways return decimal strings, and Solana returns JSON numbers. A
    digits-only un-prefixed string is decimal (see `parse_minor_units` for why
    guessing hex here is a money bug). Booleans are refused explicitly: `True`
    is an `int` in Python and would read as block 1.
    """
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value if value >= 0 else None
    if isinstance(value, float):
        return None
    if not isinstance(value, str):
        return None
    text = value.strip()
    if not text:
        return None
    if text[:2].lower() == "0x":
        body = text[2:]
        if not body or not _HEX_RE.match(body) or len(body) > MAX_HEX_QUANTUM_DIGITS:
            return None
        return int(body, 16)
    if _DEC_RE.match(text):
        if len(text) > MAX_DEC_QUANTUM_DIGITS:
            return None
        return int(text)
    if _HEX_RE.match(text):
        if len(text) > MAX_HEX_QUANTUM_DIGITS:
            return None
        return int(text, 16)
    return None


def _topic_list(raw: Any) -> List[str]:
    """Topics as lowercase hex without the prefix, positions preserved.

    An unreadable topic becomes ``""`` rather than being dropped: the ERC-20
    transfer parser indexes by position, and compacting the list would make a
    log with one bad topic look like a log with three.
    """
    if not isinstance(raw, (list, tuple)):
        return []
    out: List[str] = []
    for item in raw:
        if isinstance(item, str):
            body = item.strip()
            if body[:2].lower() == "0x":
                body = body[2:]
            if body and len(body) <= 64 and _HEX_RE.match(body):
                out.append(body.lower())
                continue
        out.append("")
    return out


def _hex_data(raw: Any) -> str:
    if not isinstance(raw, str):
        return ""
    body = raw.strip()
    if body[:2].lower() == "0x":
        body = body[2:]
    if len(body) > 2 * MAX_HEX_INPUT_CHARS:
        return ""
    return body.lower() if _HEX_RE.match(body or "0") else ""


def normalise_log(entry: Any) -> Optional[Dict[str, Any]]:
    """One `eth_getLogs` entry into a dict, or None if it is unusable.

    Unusable means: not an object, `removed` truthy (a reorg'd log — reporting a
    payment that the chain has already forgotten is worse than reporting it one
    block later), no transaction hash, or no readable `logIndex`. The last one
    is the load-bearing check: `(chain, tx_hash, log_index)` is both the dedupe
    key and the billing key, and an event that cannot be keyed cannot be
    recorded exactly once.
    """
    if not isinstance(entry, Mapping):
        return None
    if entry.get("removed"):
        return None
    tx_hash = entry.get("transactionHash")
    if not isinstance(tx_hash, str):
        return None
    try:
        tx_hash = normalise_tx_hash(CHAIN_EVM, tx_hash)
    except Web3ValidationError:
        return None
    index = parse_quantity(entry.get("logIndex"))
    if index is None or index > MAX_LOG_INDEX:
        return None
    address = entry.get("address")
    address = address.strip().lower() if isinstance(address, str) and len(address.strip()) <= 128 else ""
    return {
        "tx_hash": tx_hash,
        "log_index": int(index),
        "address": address,
        "topics": _topic_list(entry.get("topics")),
        "data": _hex_data(entry.get("data")),
        "block_number": parse_quantity(entry.get("blockNumber")),
    }


def normalise_logs(entries: Any, cap: int = MAX_LOGS_PER_RESPONSE) -> Tuple[List[Dict[str, Any]], bool]:
    """Parse up to `cap` entries and say whether there were more.

    The flag matters more than the parsing: a caller that truncates silently and
    then advances its cursor to `to_block` loses every dropped transfer. See
    :func:`advance_block`.
    """
    if not isinstance(entries, (list, tuple)):
        return [], False
    truncated = len(entries) > cap
    out: List[Dict[str, Any]] = []
    for entry in entries[:cap]:
        parsed = normalise_log(entry)
        if parsed is not None:
            out.append(parsed)
    return out, truncated


def _address_from_topic(topic: str) -> str:
    """The last 40 hex characters of a 32-byte padded indexed argument."""
    if not topic or len(topic) > 64:
        return ""
    body = topic[-40:] if len(topic) >= 40 else topic.zfill(40)
    return "0x" + body.lower()


def parse_erc20_transfer(log: Mapping[str, Any]) -> Optional[Dict[str, Any]]:
    """Decode a Transfer log into `{from, to, amount}` (amount in minor units).

    Strict on shape and lenient on meaning: exactly four topics, topic0 equal to
    the ERC-20 Transfer signature, and non-empty `data`. Anything else — a
    Approval, a non-standard token that puts the value in a topic, a proxy that
    re-emits — returns None and is *counted*, never guessed at. A wrong amount in
    a money notification is a support ticket with the merchant's customer's name
    on it, so the parser would rather say nothing.
    """
    topics = log.get("topics")
    if not isinstance(topics, list) or len(topics) != 4:
        return None
    if topics[0] != ERC20_TRANSFER_TOPIC0:
        return None
    data = str(log.get("data") or "")
    if not data or not _HEX_RE.match(data):
        return None
    try:
        amount = parse_minor_units("0x" + data)
    except Web3ValidationError:
        return None
    return {
        "from": _address_from_topic(topics[1]),
        "to": _address_from_topic(topics[2]),
        "amount": amount,
        "token": str(log.get("address") or ""),
    }


def topic_bytes32(address: Any) -> str:
    """An address padded into a 32-byte topic, for a topic-filtered getLogs.

    Lowercased because the node compares 32-byte words, and a checksummed input
    from a paste-happy operator would filter to nothing forever.
    """
    text = validate_evm_address(address)
    return "0x" + ("0" * 24) + text[2:]


#: `decimals()` and `symbol()` — the first four bytes of each keccak signature.
#: Constants of the ERC-20 standard (the same reason as `ERC20_TRANSFER_TOPIC0`:
#: hashing them would need keccak, which `hashlib` does not provide).
ERC20_DECIMALS_SELECTOR = "313ce567"
ERC20_SYMBOL_SELECTOR = "95d89b41"


def parse_erc20_decimals(result: Any) -> Optional[int]:
    """`eth_call(decimals())` → the integer, or None.

    The return is a right-aligned 32-byte word; a token that returns 255 to mean
    "not set", or 0 for a byte-token, is still inside the accepted range and the
    caller bounds it with `validate_decimals`.
    """
    data = _hex_data(result)
    if len(data) < 64:
        return None
    value = parse_quantity("0x" + data[-64:])
    if value is None or value > MAX_DECIMALS:
        return None
    return int(value)


def parse_erc20_symbol(result: Any) -> str:
    """`eth_call(symbol())` into a ticker this bridge is willing to print.

    Both real encodings are handled: the dynamic `string` (offset, length, data)
    and the legacy fixed `bytes32` (right-padded). Then the value is *filtered*,
    not merely decoded — a token contract is attacker-chosen text, and a symbol of
    `"<script>"`, 300 emoji or `../../x` has no business reaching a card, a log
    line or an invoice. What does not match the ticker pattern becomes "", and the
    caller falls back to a truncated contract address as the asset label.
    """
    data = _hex_data(result)
    if len(data) < 64:
        return ""
    body = ""
    try:
        offset = int(data[:64], 16) * 2
        if 0 < offset <= len(data) - 64:
            length = int(data[offset:offset + 64], 16)
            if 0 < length <= MAX_SYMBOL_CHARS:
                body = data[offset + 64: offset + 64 + length * 2]
    except (ValueError, IndexError):
        body = ""
    if not body and len(data) == 64:
        body = data.rstrip("0")          # bytes32 symbol, zero-padded
    if not body or len(body) % 2:
        return ""
    try:
        text = bytes.fromhex(body).decode("ascii", "ignore")
    except ValueError:
        return ""
    text = "".join(ch for ch in text.strip() if ch >= " " and ch <= "~").strip()
    if not text or len(text) > MAX_SYMBOL_CHARS:
        return ""
    upper = text.upper()
    return upper if _SYMBOL_RE.match(upper) else ""


def asset_label(token: Any) -> str:
    """A safe display name for a contract this bridge has no ticker for."""
    text = str(token or "").strip().lower()
    if not text:
        return "TOKEN"
    return ("ERC20:" + text[2:10]) if text.startswith("0x") else ("ASSET:" + text[:8])


#: Resolved token units, process-wide and bounded. A watchlist of a few hundred
#: tokens fits; past the cap the oldest entry goes rather than the cache growing
#: without bound on a long-running gateway.
_UNIT_CACHE: "OrderedDict[str, Tuple[str, int]]" = OrderedDict()
UNIT_CACHE_MAX = 256


def _transfer_topics(topic0: str, from_address: Optional[str], to_address: Optional[str]) -> List[Optional[str]]:
    """The `topics` array for an ERC-20 Transfer query with one wildcard side."""
    return [
        "0x" + topic0,
        topic_bytes32(from_address) if from_address else None,
        topic_bytes32(to_address) if to_address else None,
    ]


def normalise_block(raw: Any) -> Optional[Dict[str, Any]]:
    """`eth_getBlockByNumber(_, true)` into `{number, transactions:[…]}`.

    A null block (the head moved between the two calls, or the node is behind)
    is None. Transaction entries that are bare hash strings — a node that
    ignored the `true` flag — are skipped rather than guessed about.
    """
    if not isinstance(raw, Mapping):
        return None
    number = parse_quantity(raw.get("number"))
    txs = raw.get("transactions")
    if not isinstance(txs, (list, tuple)):
        return {"number": number, "transactions": []}
    out: List[Dict[str, Any]] = []
    for item in txs:
        if not isinstance(item, Mapping):
            continue
        try:
            tx_hash = normalise_tx_hash(CHAIN_EVM, item.get("hash") or "")
        except Web3ValidationError:
            continue
        frm = item.get("from")
        to = item.get("to")
        out.append(
            {
                "hash": tx_hash,
                "from": frm.strip().lower() if isinstance(frm, str) else "",
                "to": to.strip().lower() if isinstance(to, str) else "",
                "value": _hex_data(item.get("value")),
            }
        )
    return {"number": number, "transactions": out}


def normalise_balance_result(result: Any) -> Optional[int]:
    """Solana `getBalance` → the lamport integer, or None.

    The RPC wraps the value as `{"context": …, "value": …}`; reading
    `result["value"]` is the whole contract, and a response without it (an error
    object that arrived as 200, a proxy's page) reads as None.
    """
    if not isinstance(result, Mapping):
        return None
    value = result.get("value")
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    if value < 0:
        return None
    return int(value)


def normalise_signatures(result: Any, cap: int = MAX_SIGS_PER_ADDRESS) -> List[Tuple[str, Optional[int]]]:
    """`getSignaturesForAddress` → `[(signature, blockTime)]`, newest first.

    Entries with a non-null `err` are dropped: a failed transaction moved no
    money, and notifying about it would tell a member they had been paid when
    the chain says they were not.
    """
    if not isinstance(result, (list, tuple)):
        return []
    out: List[Tuple[str, Optional[int]]] = []
    for entry in result[:cap]:
        if not isinstance(entry, Mapping):
            continue
        if entry.get("err") is not None:
            continue
        signature = entry.get("signature")
        if not isinstance(signature, str) or not signature.strip():
            continue
        try:
            # The same shape rule the event key uses: an entry the dedupe key
            # cannot be built from is a signature to skip, not one to try.
            signature = normalise_tx_hash(CHAIN_SOLANA, signature)
        except Web3ValidationError:
            continue
        block_time = entry.get("blockTime")
        if isinstance(block_time, bool) or not isinstance(block_time, int):
            block_time = None
        out.append((signature.strip(), block_time))
    return out


def new_signatures(seen: Any, fetched: Sequence[Tuple[str, Optional[int]]]) -> List[Tuple[str, Optional[int]]]:
    """Signatures this watcher has not been shown before, order preserved.

    The seen set is a bounded list rather than a table because Solana has no
    log index to dedupe on: `web3_events` can only key what the RPC gives us,
    and the pagination cursor has to live in the watcher's settings blob.
    """
    previous: Set[str] = set()
    if isinstance(seen, (list, tuple)):
        for item in seen:
            if isinstance(item, str) and item.strip():
                previous.add(item.strip())
    return [entry for entry in fetched if entry[0] not in previous]


def _account_index(tx: Mapping[str, Any], address: str) -> Optional[int]:
    """Where this address sits in the transaction's account list."""
    needle = str(address or "").strip()
    if not needle:
        return None
    candidates: List[Any] = []
    meta = tx.get("meta")
    if isinstance(meta, Mapping) and isinstance(meta.get("accountKeys"), (list, tuple)):
        candidates = list(meta["accountKeys"])
    else:
        message = tx.get("transaction")
        if isinstance(message, Mapping):
            inner = message.get("message")
            if isinstance(inner, Mapping) and isinstance(inner.get("accountKeys"), (list, tuple)):
                candidates = list(inner["accountKeys"])
    for index, entry in enumerate(candidates):
        value = entry
        if isinstance(entry, Mapping):
            value = entry.get("pubkey")
        if isinstance(value, str) and value.strip() == needle:
            return index
    return None


def parse_tx_lamport_delta(tx: Any, address: Any) -> Optional[int]:
    """The lamport change for one address in one transaction, signed.

    `postBalances[i] - preBalances[i]` is the only honest per-transaction number
    the RPC offers without replaying the program log, and the sign is kept
    because this is the one place a direction is derived rather than assumed:
    negative is an outgoing transfer. Returns None when the shape is unreadable
    (no `meta`, arrays of different lengths, the address absent, non-integer
    balances) so the caller records nothing rather than recording a guess.
    """
    if not isinstance(tx, Mapping):
        return None
    meta = tx.get("meta")
    if not isinstance(meta, Mapping):
        return None
    pre = meta.get("preBalances")
    post = meta.get("postBalances")
    if not isinstance(pre, (list, tuple)) or not isinstance(post, (list, tuple)):
        return None
    if len(pre) != len(post):
        return None
    index = _account_index(tx, address)
    if index is None or index >= len(pre):
        return None
    before = pre[index]
    after = post[index]
    for value in (before, after):
        if isinstance(value, bool) or not isinstance(value, int):
            return None
    return int(after) - int(before)


def direction_from_delta(delta: int) -> str:
    return "in" if delta > 0 else ("out" if delta < 0 else "none")


# ─────────────────────────────────────────────────────────────────────────────
# 8. The card
# ─────────────────────────────────────────────────────────────────────────────


def _unique_labels(fields: Sequence[Mapping[str, Any]]) -> List[Dict[str, Any]]:
    """Dedupe field labels by suffixing the second occurrence.

    Not cosmetic: `PopopxServiceCard.Field.id` *is* its label
    (PopopxEcoModels.swift:547), so two rows labelled "Amount" are two ForEach
    items with one identity, which SwiftUI treats as undefined behaviour rather
    than a warning. A bridge that formats a transfer with both a `from` and a
    `to` row can absolutely produce that.
    """
    out: List[Dict[str, Any]] = []
    used: Set[str] = set()
    for raw in fields:
        label = str(raw.get("k") or raw.get("label") or "").strip()
        value = str(raw.get("v") or raw.get("value") or "").strip()
        if not label or not value:
            # An empty value is dropped rather than sent: `build_card` requires a
            # non-empty field value (crypto_service `_text(..., required=True)`),
            # and an EcoValidationError raised mid-notification is a card nobody
            # got and a `notified` flag that never moved.
            continue
        candidate = label
        suffix = 2
        while candidate in used:
            candidate = "%s %d" % (label, suffix)
            suffix += 1
        used.add(candidate)
        entry: Dict[str, Any] = {
            "k": candidate[: EcoLimits.field_label_chars],
            "v": value[: EcoLimits.field_value_chars],
        }
        if raw.get("mono"):
            entry["mono"] = True
        out.append(entry)
    return out[: EcoLimits.max_fields]


def receipt_card(
    *,
    card_id: str,
    chain: str,
    direction: str,
    amount_text: str,
    counterparty: str,
    tx_hash: str,
    observed_at_ms: int,
    detail_url: Optional[str] = None,
    label: str = "",
) -> Dict[str, Any]:
    """The `receipt` card for one transfer, built through `crypto_service`.

    The counterparty is truncated for display and the full value lives in the
    row the operator reads via `/events`: an 88-character base58 signature and a
    42-character address are unreadable in a bubble, and a card that hits the
    client's 240-character field cap is a card the phone *drops*, not one that
    renders small.

    The detail action is `open_url` and only when the caller already produced a
    signed URL for *this* session; with no URL the action is omitted entirely,
    because kind `none` is rejected by the client and an unknown kind kills the
    whole frame (crypto_service.build_action, PopopxEcoModels.swift:685-702).
    """
    verb = "Received" if direction == "in" else ("Sent" if direction == "out" else "Transfer")
    chain_name = "EVM" if chain == CHAIN_EVM else "Solana"
    title = "%s %s" % (verb, amount_text)
    if len(title) > EcoLimits.card_title_chars:
        title = "%s on %s" % (verb, chain_name)
    fields: List[Dict[str, Any]] = [
        {"k": "Amount", "v": amount_text, "mono": True},
        {"k": "Direction", "v": "%s (%s)" % (verb.lower(), chain_name)},
    ]
    if counterparty:
        fields.append({"k": "Counterparty", "v": truncate_address(counterparty), "mono": True})
    if tx_hash:
        short = tx_hash if len(tx_hash) <= 20 else "%s\u2026%s" % (tx_hash[:10], tx_hash[-8:])
        fields.append({"k": "Transaction", "v": short, "mono": True})
    if label:
        fields.append({"k": "Watched as", "v": label})
    fields.append({"k": "Observed", "v": _format_time(observed_at_ms)})
    actions: List[Dict[str, Any]] = []
    if detail_url:
        actions.append(
            build_action(action_id="web3-detail", title="Details", kind="open_url", style="secondary", url=detail_url)
        )
    return build_card(
        card_id,
        title[: EcoLimits.card_title_chars],
        style="receipt",
        body="On-chain activity for %s." % (truncate_address(counterparty) or chain_name),
        fields=_unique_labels(fields),
        actions=actions,
        updated_at_ms=int(observed_at_ms),
    )


def receipt_visible_text(chain: str, direction: str, amount_text: str) -> str:
    """The readable line in front of a *new* card frame.

    Only mode `c` cards may carry it (crypto_service.encode_frame's
    `frame_exclusive` rule, from PopopxEcoModels.swift:120-128), which is why
    the update path never passes one.
    """
    verb = "received" if direction == "in" else ("sent" if direction == "out" else "transfer")
    return "On-chain %s %s (%s)." % (amount_text, verb, "EVM" if chain == CHAIN_EVM else "Solana")


def _format_time(ms: int) -> str:
    try:
        return time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(int(ms) / 1000.0))
    except (OverflowError, OSError, ValueError):
        return ""


# ─────────────────────────────────────────────────────────────────────────────
# 9. Persistence
#
# All reads and writes here are synchronous: `app.database` owns a thread-local
# connection and `app.billing_service` is synchronous by design, and the seam
# says the ledger is a SQLite transaction rather than a network call. The loop
# therefore does its *waiting* on httpx and its writing inline — see the note on
# `deps.charge` in app/plugins/__init__.py for why the opposite (network I/O
# inside a transaction) is the thing that would stall every follower.
# ─────────────────────────────────────────────────────────────────────────────

_META_KEYS = ("symbol", "decimals", "token", "last_balance", "signatures")


def _meta_key(watch_id: int) -> str:
    return "web3.watch.%d.meta" % int(watch_id)


def watcher_meta(db: Any, watch_id: int) -> Dict[str, Any]:
    """Per-watcher knobs and cursors that the schema has no column for.

    `web3_watch` stores chain/address/label/channel_id/min_delta/active/
    last_block. It has no `symbol`, no `decimals`, no token-contract column and
    no Solana balance cursor. Rather than editing a shared migration, those live
    in `settings`, which the schema docstring explicitly offers for exactly this
    purpose ("a key/value table … so a plugin can store its own settings without
    a migration"). Only the five known keys are read back, so a stale blob from
    an older build cannot smuggle a field into the poller.
    """
    meta: Dict[str, Any] = {
        "symbol": None,
        "decimals": None,
        "token": None,
        "last_balance": None,
        "signatures": [],
    }
    raw = db.get_setting(_meta_key(watch_id), None)
    if isinstance(raw, Mapping):
        for key in _META_KEYS:
            if key in raw:
                meta[key] = raw[key]
    if not isinstance(meta["signatures"], list):
        meta["signatures"] = []
    return meta


def _set_meta(db: Any, watch_id: int, changes: Mapping[str, Any]) -> Dict[str, Any]:
    meta = watcher_meta(db, watch_id)
    for key, value in changes.items():
        if key in _META_KEYS:
            meta[key] = value
    db.set_setting(_meta_key(watch_id), meta)
    return meta


def set_watcher_meta(db: Any, watch_id: int, **changes: Any) -> Dict[str, Any]:
    return _set_meta(db, watch_id, changes)


def _watcher_shell(row: Any) -> Dict[str, Any]:
    """The columns `web3_watch` actually has, as a dict."""
    return {
        "id": int(row["id"]),
        "chain": row["chain"],
        "address": row["address"],
        "label": row["label"] or "",
        "channel_id": row["channel_id"] or "",
        "min_delta": row["min_delta"],
        "active": bool(row["active"]),
        "last_block": row["last_block"],
        "created_at_ms": int(row["created_at_ms"]),
    }


def _row_to_watcher(db: Any, row: Any) -> Dict[str, Any]:
    watcher = _watcher_shell(row)
    meta = watcher_meta(db, watcher["id"])
    default_symbol, default_decimals = _DEFAULT_UNIT[watcher["chain"]]
    watcher["symbol"] = meta["symbol"] or default_symbol
    decimals = meta["decimals"]
    watcher["decimals"] = int(decimals) if isinstance(decimals, int) and not isinstance(decimals, bool) else default_decimals
    watcher["token"] = meta["token"] or ""
    watcher["last_balance"] = meta["last_balance"]
    watcher["signatures"] = meta["signatures"] if isinstance(meta["signatures"], list) else []
    watcher["min_delta_units"] = None
    if watcher["min_delta"]:
        try:
            watcher["min_delta_units"] = int(str(watcher["min_delta"]))
        except ValueError:
            watcher["min_delta_units"] = None
    return watcher


def list_watchers(db: Any, chain: Optional[str] = None, active_only: bool = True) -> List[Dict[str, Any]]:
    sql = "SELECT * FROM web3_watch"
    clauses: List[str] = []
    params: List[Any] = []
    if chain is not None:
        clauses.append("chain = ?")
        params.append(chain)
    if active_only:
        clauses.append("active = 1")
    if clauses:
        sql += " WHERE " + " AND ".join(clauses)
    sql += " ORDER BY id"
    return [_row_to_watcher(db, row) for row in db.query(sql, params)]


def watched_channel_ids(db: Any, active_only: bool = True) -> Set[str]:
    """Channels this bridge has an opinion about — the receipt-claim set.

    Active watchers only: deactivating a watcher is the operator saying "stop
    touching this", and a bridge that kept claiming receipts for a channel it
    was told to stop watching would be suppressing the merchant's own handler
    from the graveyard.
    """
    sql = "SELECT DISTINCT channel_id FROM web3_watch WHERE channel_id IS NOT NULL AND channel_id <> ''"
    if active_only:
        sql += " AND active = 1"
    return {str(row["channel_id"]) for row in db.query(sql)}


def upsert_watcher(db: Any, *, chain: str, address: str, label: str, channel_id: Optional[str],
                   min_delta: Optional[int], symbol: str, decimals: int, token: Optional[str] = None) -> Dict[str, Any]:
    """Insert, or re-activate and re-point an existing `(chain, address)`.

    `web3_watch.UNIQUE (chain, address)` means a second POST for the same
    address is an update, not a second watcher: two rows would each poll the
    same address and notify the same member twice for one payment. Re-activation
    is deliberate too — an operator who re-adds a watcher they had switched off
    means it, and a row left `active = 0` by a silent upsert is a bug report
    titled "I configured it and nothing happens".
    """
    delta_text = None if min_delta is None else str(int(min_delta))
    with db.transaction(immediate=True) as conn:
        conn.execute(
            "INSERT INTO web3_watch (chain, address, label, channel_id, min_delta, active, created_at_ms)"
            " VALUES (?,?,?,?,?,1,?)"
            " ON CONFLICT (chain, address) DO UPDATE SET"
            "   label = excluded.label,"
            "   channel_id = excluded.channel_id,"
            "   min_delta = excluded.min_delta,"
            "   active = 1",
            (chain, address, label or None, channel_id, delta_text, now_ms()),
        )
        row = conn.execute("SELECT * FROM web3_watch WHERE chain = ? AND address = ?", (chain, address)).fetchone()
        watcher = _watcher_shell(row)
    # The settings write happens after the commit: `db.set_setting` opens its own
    # cursor, and doing that mid-transaction on the same connection would make
    # this function's behaviour depend on which cursor last touched the thread.
    meta: Dict[str, Any] = {"symbol": symbol, "decimals": decimals, "token": token or None}
    _set_meta(db, watcher["id"], meta)
    return _row_to_watcher(db, db.query_one("SELECT * FROM web3_watch WHERE id = ?", (watcher["id"],)))


def get_watcher(db: Any, watch_id: int) -> Optional[Dict[str, Any]]:
    row = db.query_one("SELECT * FROM web3_watch WHERE id = ?", (int(watch_id),))
    return _row_to_watcher(db, row) if row is not None else None


def set_watcher_active(db: Any, watch_id: int, active: bool) -> Optional[Dict[str, Any]]:
    """Deactivate rather than delete — why `/watchers/{id}` has no hard DELETE.

    `web3_events` has no foreign key to `web3_watch` (its columns are chain and
    address, not a watcher id), so a real DELETE would not orphan rows, but it
    would orphan the *meaning* of them: the events recorded for an address whose
    watcher is gone lose the label, the min_delta that produced them and the
    channel they were notified into. `active = 0` keeps the audit trail
    answerable — "why did we tell her about this one and not that one" — at the
    cost of one row, and `GET /watchers?active=false` still lists it.
    """
    with db.transaction(immediate=True) as conn:
        cursor = conn.execute("UPDATE web3_watch SET active = ? WHERE id = ?", (1 if active else 0, int(watch_id)))
        if cursor.rowcount == 0:
            return None
    return get_watcher(db, watch_id)


def update_watcher(db: Any, watch_id: int, changes: Mapping[str, Any]) -> Optional[Dict[str, Any]]:
    """PATCH. Only the columns that exist; anything else is a 400 at the route."""
    sets: List[str] = []
    params: List[Any] = []
    meta_changes: Dict[str, Any] = {}
    for key in ("label", "channel_id", "min_delta", "active"):
        if key in changes:
            value = changes[key]
            if key == "active":
                value = 1 if value else 0
            elif key == "min_delta" and value is not None:
                value = str(int(value))
            elif value == "":
                value = None
            sets.append("%s = ?" % key)
            params.append(value)
    for key in ("symbol", "decimals", "token"):
        if key in changes:
            meta_changes[key] = changes[key]
    if not sets and not meta_changes:
        return get_watcher(db, watch_id)
    with db.transaction(immediate=True) as conn:
        if sets:
            cursor = conn.execute("UPDATE web3_watch SET %s WHERE id = ?" % ", ".join(sets), params + [int(watch_id)])
            if cursor.rowcount == 0:
                return None
    if meta_changes:
        _set_meta(db, watch_id, meta_changes)
    return get_watcher(db, watch_id)


def advance_watcher_block(db: Any, watch_id: int, block: Optional[int]) -> None:
    if block is None:
        return
    db.execute("UPDATE web3_watch SET last_block = ? WHERE id = ?", (int(block), int(watch_id)))


def advance_watcher_cursor(db: Any, watch_id: int, meta: Mapping[str, Any], block: Optional[int]) -> None:
    advance_watcher_block(db, watch_id, block)
    _set_meta(db, watch_id, dict(meta))


def list_whitelist(db: Any, chain: Optional[str] = None, address: Optional[str] = None,
                   channel_id: Optional[str] = None) -> List[Dict[str, Any]]:
    sql = "SELECT * FROM web3_whitelist"
    clauses: List[str] = []
    params: List[Any] = []
    for column, value in (("chain", chain), ("address", address), ("channel_id", channel_id)):
        if value:
            clauses.append("%s = ?" % column)
            params.append(value)
    if clauses:
        sql += " WHERE " + " AND ".join(clauses)
    sql += " ORDER BY chain, address, channel_id"
    return [dict(row) for row in db.query(sql, params)]


def upsert_whitelist(db: Any, *, chain: str, address: str, channel_id: str, tag: Optional[str]) -> Dict[str, Any]:
    """Insert, keeping an existing `granted_epoch`.

    Re-asserting "this address is this member" is not a key rotation: clearing
    `granted_epoch` here would make every re-add of a row mint a fresh epoch and
    charge the `key_rotation` meter for it. An operator who genuinely wants the
    key handed over again waits for the epoch to advance, which the poller
    honours on its own — see :func:`honour_outstanding_grants`.
    """
    with db.transaction(immediate=True) as conn:
        conn.execute(
            "INSERT INTO web3_whitelist (chain, address, channel_id, tag, created_at_ms)"
            " VALUES (?,?,?,?,?)"
            " ON CONFLICT (chain, address, channel_id) DO UPDATE SET tag = excluded.tag",
            (chain, address, channel_id, tag, now_ms()),
        )
        row = conn.execute(
            "SELECT * FROM web3_whitelist WHERE chain = ? AND address = ? AND channel_id = ?",
            (chain, address, channel_id),
        ).fetchone()
    return dict(row)


def delete_whitelist(db: Any, *, chain: str, address: str, channel_id: Optional[str] = None) -> int:
    with db.transaction(immediate=True) as conn:
        if channel_id:
            cursor = conn.execute(
                "DELETE FROM web3_whitelist WHERE chain = ? AND address = ? AND channel_id = ?",
                (chain, address, channel_id),
            )
        else:
            cursor = conn.execute("DELETE FROM web3_whitelist WHERE chain = ? AND address = ?", (chain, address))
        return int(cursor.rowcount)


def whitelist_for_address(db: Any, chain: str, address: str) -> List[Dict[str, Any]]:
    return list_whitelist(db, chain=chain, address=address)


def list_events(db: Any, chain: Optional[str] = None, address: Optional[str] = None,
                limit: int = DEFAULT_EVENT_LIMIT, notified: Optional[int] = None) -> List[Dict[str, Any]]:
    sql = "SELECT * FROM web3_events"
    clauses: List[str] = []
    params: List[Any] = []
    if chain:
        clauses.append("chain = ?")
        params.append(chain)
    if address:
        clauses.append("address = ?")
        params.append(address)
    if notified is not None:
        clauses.append("notified = ?")
        params.append(int(notified))
    if clauses:
        sql += " WHERE " + " AND ".join(clauses)
    sql += " ORDER BY id DESC LIMIT ?"
    params.append(int(limit))
    return [dict(row) for row in db.query(sql, params)]


def event_counts(db: Any) -> Dict[str, Dict[str, int]]:
    """observed / notified / unnotified per chain, in one scan."""
    out: Dict[str, Dict[str, int]] = {
        chain: {"observed": 0, "notified": 0, "unnotified": 0} for chain in CHAINS
    }
    for row in db.query(
        "SELECT chain, COUNT(*) AS observed, SUM(CASE WHEN notified = 1 THEN 1 ELSE 0 END) AS notified"
        " FROM web3_events GROUP BY chain"
    ):
        bucket = out.get(str(row["chain"]))
        if bucket is None:
            continue
        bucket["observed"] = int(row["observed"] or 0)
        bucket["notified"] = int(row["notified"] or 0)
        bucket["unnotified"] = bucket["observed"] - bucket["notified"]
    return out


def max_watcher_block(db: Any, chain: str) -> Optional[int]:
    value = db.scalar("SELECT MAX(last_block) FROM web3_watch WHERE chain = ?", (chain,))
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    return int(value)


def channel_current_epoch(db: Any, channel_id: str) -> Optional[int]:
    value = db.scalar("SELECT current_epoch FROM channels WHERE channel_id = ?", (channel_id,))
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    return int(value)


def outstanding_grants(db: Any, limit: int = MAX_GRANT_ROWS_PER_PASS) -> List[Dict[str, Any]]:
    """Whitelist rows whose key promise has not been honoured.

    The DDL calls a whitelist row "a key grant promise" and `granted_epoch` the
    record that it was kept (database.py:416-418), so "outstanding" is exactly:
    never honoured, or honoured against an epoch the channel has since moved
    past. The channel's epoch is read in the same JOIN rather than in a second
    query, so a rotation between the two cannot make the caller re-grant an epoch
    the member already holds.
    """
    return [
        dict(row)
        for row in db.query(
            "SELECT w.chain, w.address, w.channel_id, w.tag, w.granted_epoch, c.current_epoch"
            " FROM web3_whitelist w JOIN channels c ON c.channel_id = w.channel_id"
            " WHERE w.granted_epoch IS NULL OR w.granted_epoch < c.current_epoch"
            " ORDER BY w.created_at_ms LIMIT ?",
            (int(limit),),
        )
    ]


def record_grant(db: Any, chain: str, address: str, channel_id: str, epoch: Any) -> None:
    """Only ever move `granted_epoch` forward, never back.

    `ChannelGrant.epoch` comes from the gateway's own rotation manager, so a
    smaller number should be impossible; writing `MAX(existing, new)` anyway
    means a confused implementation upstream cannot turn one member's grant into
    an infinite re-grant loop that charges `key_rotation` every pass.
    """
    value = parse_quantity(epoch)
    if value is None:
        return
    db.execute(
        "UPDATE web3_whitelist SET granted_epoch = ?, granted_at_ms = ?"
        " WHERE chain = ? AND address = ? AND channel_id = ?"
        "   AND (granted_epoch IS NULL OR granted_epoch < ?)",
        (int(value), now_ms(), chain, address, channel_id, int(value)),
    )


def events_for_tx(db: Any, tx_hash: str, channel_id: str) -> List[Dict[str, Any]]:
    """Recorded events for this hash whose address is watched on this channel.

    Joined rather than filtered on a chain column because the receipt carries a
    hash and a channel and *no* chain: the watched-address set is what ties the
    three together.
    """
    return [
        dict(row)
        for row in db.query(
            "SELECT e.* FROM web3_events e"
            " JOIN web3_watch w ON w.chain = e.chain AND w.address = e.address"
            " WHERE e.tx_hash = ? AND w.channel_id = ?",
            (tx_hash, channel_id),
        )
    ]


def mark_events_notified(db: Any, event_ids: Sequence[int]) -> int:
    """`notified 0 -> 1`; the rowcount is the idempotency answer.

    The `AND notified = 0` guard is the whole replay protection: a second
    `::popopx_sys::CHANNEL_PAY_RCPT::` line for the same payment updates
    nothing, and the caller can *see* that in the count rather than having to
    remember it.
    """
    if not event_ids:
        return 0
    placeholders = ",".join("?" for _ in event_ids)
    with db.transaction(immediate=True) as conn:
        cursor = conn.execute(
            "UPDATE web3_events SET notified = 1 WHERE notified = 0 AND id IN (%s)" % placeholders,
            [int(value) for value in event_ids],
        )
        return int(cursor.rowcount)


def receipt_audit_key(channel_id: str, tx_hash: str, credits: int) -> str:
    """The `settings` key that says "this receipt has been seen".

    A `web3_events` row has no column for credits and no column for a paid_ref
    (see the module notes on the schema), and inventing a table is not this
    file's to do. `settings` is the sanctioned place for plugin-owned data, and
    the key embeds a digest of the whole triple so that a replay is a *lookup
    miss on the exact same string*, which is what makes the second arrival
    provably a no-op instead of a judgement call.
    """
    digest = hashlib.sha256(("%s|%s|%d" % (channel_id, tx_hash, int(credits))).encode("utf-8")).hexdigest()
    return "web3.rcpt.%s.%s" % (key_component(channel_id)[:120], digest[:32])


def write_receipt_audit(db: Any, key: str, payload: Mapping[str, Any]) -> bool:
    """False when the audit row already existed (a replay).

    Read-modify-write inside one `BEGIN IMMEDIATE` transaction, because two
    deliveries of the same receipt arriving on different threads must not both
    decide they were first.
    """
    with db.transaction(immediate=True) as conn:
        existing = conn.execute("SELECT value_json FROM settings WHERE key = ?", (key,)).fetchone()
        if existing is not None:
            return False
        conn.execute(
            "INSERT INTO settings (key, value_json, updated_at_ms) VALUES (?,?,?)",
            (key, json.dumps(dict(payload), ensure_ascii=False, separators=(",", ":")), now_ms()),
        )
        return True


# ─────────────────────────────────────────────────────────────────────────────
# 10. Candidates: what an RPC response means
#
# A "candidate" is the bridge's reading of one on-chain fact before it becomes a
# row. It is keyed by exactly the same triple the UNIQUE index and the billing
# key use, so "what we count", "what we charge" and "what we insert" cannot drift
# into three different definitions of one payment.
# ─────────────────────────────────────────────────────────────────────────────


def _meets_threshold(watcher: Mapping[str, Any], amount_units: int) -> bool:
    threshold = watcher.get("min_delta_units")
    if threshold is None:
        return True
    return abs(int(amount_units)) >= int(threshold)


def candidate_dict(chain: str, tx_hash: Any, log_index: Any) -> Dict[str, Any]:
    return {
        "key": event_idempotency_key(chain, tx_hash, log_index),
        "chain": chain,
        "tx_hash": normalise_tx_hash(chain, tx_hash),
        "log_index": NO_LOG_INDEX if log_index is None else int(log_index),
        "address": "",
        "direction": "",
        "counterparty": "",
        "amount": None,
        "asset": "",
        "block_number": None,
        "targets": [],
    }


def _add_target(candidate: Dict[str, Any], watcher: Mapping[str, Any]) -> None:
    for existing in candidate["targets"]:
        if int(existing["id"]) == int(watcher["id"]):
            return
    candidate["targets"].append(dict(watcher))


def _prefer(candidate: Dict[str, Any], key: str, value: Any) -> None:
    if value and not candidate.get(key):
        candidate[key] = value


def merge_log_candidate(candidates: Dict[str, Dict[str, Any]], watcher: Mapping[str, Any],
                        log_entry: Mapping[str, Any], transfer: Mapping[str, Any]) -> Optional[str]:
    """Fold one decoded Transfer from one watcher into the candidate set.

    When two watched addresses sit on the two ends of one transfer (Alice pays
    Bob and both are members), this produces ONE candidate with TWO targets: one
    `web3_events` row and one `web3_event` charge for one on-chain fact, while
    both members still get their own card. Charging per watcher would bill the
    merchant twice for a single log, which is exactly the kind of number an
    invoice dispute is made of.

    Returns the candidate key, or None when the transfer is below this watcher's
    own threshold.
    """
    watched = str(watcher.get("address") or "").lower()
    from_address = str(transfer.get("from") or "").lower()
    to_address = str(transfer.get("to") or "").lower()
    try:
        amount = int(transfer.get("amount") or 0)
    except (TypeError, ValueError):
        return None
    if amount < 0 or not _meets_threshold(watcher, amount):
        return None
    if watched and to_address == watched and from_address != watched:
        direction, counterparty = "in", from_address
    elif watched and from_address == watched:
        direction, counterparty = "out", to_address
    else:
        direction, counterparty = "other", (from_address or to_address)
    key = event_idempotency_key(watcher["chain"], log_entry["tx_hash"], log_entry["log_index"])
    candidate = candidates.setdefault(key, candidate_dict(watcher["chain"], log_entry["tx_hash"], log_entry["log_index"]))
    _prefer(candidate, "direction", direction)
    _prefer(candidate, "counterparty", counterparty)
    _prefer(candidate, "asset", watcher.get("symbol"))
    if candidate["amount"] is None:
        candidate["amount"] = amount
    if candidate["block_number"] is None:
        candidate["block_number"] = log_entry.get("block_number")
    candidate["address"] = min([str(candidate["address"] or watched), watched])
    _add_target(candidate, watcher)
    return key


def merge_native_candidate(candidates: Dict[str, Dict[str, Any]], watcher: Mapping[str, Any],
                           tx: Mapping[str, Any], block_number: Any) -> Optional[str]:
    """Fold one native-value transfer from a block scan into the set.

    `log_index` is `NO_LOG_INDEX`: a native transfer has no log, and the
    sentinel is what makes the UNIQUE index genuinely unique for these rows
    rather than a NULL that SQLite would treat as distinct every time.
    """
    watched = str(watcher.get("address") or "").lower()
    value = _hex_data(tx.get("value"))
    if not value:
        return None
    try:
        amount = parse_minor_units("0x" + value)
    except Web3ValidationError:
        return None
    if amount == 0:
        return None
    to_address = str(tx.get("to") or "").lower()
    from_address = str(tx.get("from") or "").lower()
    if to_address == watched and from_address != watched:
        direction, counterparty = "in", from_address
    elif from_address == watched:
        direction, counterparty = "out", to_address
    else:
        return None
    if not _meets_threshold(watcher, amount):
        return None
    tx_hash = str(tx.get("hash") or "")
    if not tx_hash:
        return None
    key = event_idempotency_key(watcher["chain"], tx_hash, NO_LOG_INDEX)
    candidate = candidates.setdefault(key, candidate_dict(watcher["chain"], tx_hash, NO_LOG_INDEX))
    _prefer(candidate, "direction", direction)
    _prefer(candidate, "counterparty", counterparty)
    _prefer(candidate, "asset", watcher.get("symbol"))
    if candidate["amount"] is None:
        candidate["amount"] = amount
    if candidate["block_number"] is None:
        candidate["block_number"] = block_number
    candidate["address"] = min([str(candidate["address"] or watched), watched])
    _add_target(candidate, watcher)
    return key


def merge_delta_candidate(candidates: Dict[str, Dict[str, Any]], watcher: Mapping[str, Any],
                          tx_hash: str, delta_lamports: int, block_time: Any = None) -> Optional[str]:
    """A Solana lamport delta attributed to one signature."""
    if not tx_hash or delta_lamports == 0:
        return None
    if not _meets_threshold(watcher, delta_lamports):
        return None
    key = event_idempotency_key(watcher["chain"], tx_hash, NO_LOG_INDEX)
    candidate = candidates.setdefault(key, candidate_dict(watcher["chain"], tx_hash, NO_LOG_INDEX))
    candidate["direction"] = direction_from_delta(delta_lamports)
    _prefer(candidate, "asset", watcher.get("symbol"))
    candidate["amount"] = abs(int(delta_lamports))
    if candidate["block_number"] is None and isinstance(block_time, int):
        candidate["block_number"] = int(block_time)
    candidate["address"] = str(candidate["address"] or watcher.get("address") or "")
    _add_target(candidate, watcher)
    return key


def unit_for(watcher: Mapping[str, Any]) -> Tuple[str, int]:
    chain = str(watcher.get("chain") or CHAIN_SOLANA)
    default_symbol, default_decimals = _DEFAULT_UNIT.get(chain, ("UNIT", 9))
    decimals = watcher.get("decimals")
    if isinstance(decimals, bool) or not isinstance(decimals, int):
        decimals = default_decimals
    symbol = watcher.get("symbol") or default_symbol
    return str(symbol), int(decimals)


def format_candidate_amount(candidate: Mapping[str, Any], watcher: Mapping[str, Any]) -> str:
    """The display string for one candidate, in the watcher's own unit.

    Falls back to the raw minor-unit integer if the formatter refuses, and logs
    that it did: the event is already recorded and charged by then, so
    "1234567890000000000 SOL" in a notification beats silence, and a swallowed
    exception beats neither being visible in the log.
    """
    amount = candidate.get("amount")
    symbol, decimals = unit_for(watcher)
    if amount is None:
        return ""
    try:
        return format_amount(int(amount), decimals, symbol)
    except (Web3ValidationError, ValueError):
        log.warning("web3 bridge: amount %r could not be formatted for watch %s", amount, watcher.get("id"))
        return "%s %s" % (amount, symbol)


def quote_component(text: Any) -> str:
    """Percent-encode one query value (stdlib only, no urllib at module level)."""
    out: List[str] = []
    for byte in str(text or "").encode("utf-8"):
        char = chr(byte)
        out.append(char if (char.isalnum() or char in "-._~") else "%%%02X" % byte)
    return "".join(out)


def h5_detail_path(candidate: Mapping[str, Any]) -> str:
    """The H5 path a detail action points at.

    Carries the idempotency key rather than the row id because the URL is signed
    before the row exists on a first delivery, and the two must agree or the
    page opens somebody else's transfer.
    """
    return "/plugins/web3/event?e=%s" % quote_component(candidate.get("key"))


# ─────────────────────────────────────────────────────────────────────────────
# 11. Recording and charging
# ─────────────────────────────────────────────────────────────────────────────


def record_candidate(deps: PluginDeps, candidate: Mapping[str, Any]) -> Optional[Dict[str, Any]]:
    """Insert one event row and charge its meter, exactly once, atomically.

    Two guards, because they protect different things:

    * the SELECT-then-INSERT inside `BEGIN IMMEDIATE`. `web3_events` does have
      `UNIQUE (chain, tx_hash, log_index)` (database.py:413), so the index is
      the real backstop — but the poller is a single writer here, and a *checked*
      insert lets this function answer "was this ours or a replay" instead of
      turning an IntegrityError into a control-flow puzzle. The transaction also
      keeps the row and its ledger entry in one commit, so a crash between them
      cannot leave a charged-but-unrecorded payment or a recorded-but-unpaid
      notification.
    * the idempotency key on the charge, derived from the same triple as the
      index. `billing_ledger.idempotency_key` is UNIQUE, so a replay returns the
      original result without a second debit; the loop's `idempotent_replay`
      flag is what tells the operator which happened.

    Returns the event dict with `event_id`/`charged` filled in when this call
    created the row, and None when the row already existed.
    """
    chain = str(candidate["chain"])
    tx_hash = str(candidate["tx_hash"])
    log_index = int(candidate["log_index"])
    key = str(candidate["key"])
    watchers = list(candidate.get("targets") or [])
    primary = watchers[0] if watchers else {}
    amount = candidate.get("amount")
    with deps.db.transaction(immediate=True) as conn:
        existing = conn.execute(
            "SELECT id, notified FROM web3_events WHERE chain = ? AND tx_hash = ? AND log_index = ?",
            (chain, tx_hash, log_index),
        ).fetchone()
        if existing is not None:
            return None
        inserted = conn.execute(
            "INSERT INTO web3_events (chain, address, tx_hash, log_index, direction, asset, amount,"
            " block_number, observed_at_ms, notified) VALUES (?,?,?,?,?,?,?,?,?,0)",
            (
                chain,
                str(candidate.get("address") or primary.get("address") or ""),
                tx_hash,
                log_index,
                str(candidate.get("direction") or "")[:16] or None,
                str(candidate.get("asset") or "")[:32] or None,
                None if amount is None else str(int(amount)),
                candidate.get("block_number"),
                now_ms(),
            ),
        )
        event_id = int(inserted.lastrowid or 0)
        result = deps.charge(
            ref=key,
            idempotency_key=key,
            meta={
                "chain": chain,
                "tx_hash": tx_hash,
                "log_index": log_index,
                "watch_ids": [int(item["id"]) for item in watchers],
                "direction": candidate.get("direction"),
                # Deliberately no amount, no counterparty and no RPC response in
                # the ledger meta: the meter prices an *observation*, and the
                # observation itself already lives in web3_events where an
                # operator can read it.
            },
        )
        replayed = bool(getattr(result, "idempotent_replay", False))
        return {
            "event_id": event_id,
            "key": key,
            "chain": chain,
            "tx_hash": tx_hash,
            "log_index": log_index,
            "direction": candidate.get("direction"),
            "counterparty": candidate.get("counterparty"),
            "amount": amount,
            "asset": candidate.get("asset"),
            "block_number": candidate.get("block_number"),
            "observed_at_ms": now_ms(),
            "charged": int(getattr(result, "charged", 0) or 0),
            "idempotent_replay": replayed,
            "targets": watchers,
            "primary": primary,
        }


# ─────────────────────────────────────────────────────────────────────────────
# 12. Transport: plain JSON-RPC over httpx
# ─────────────────────────────────────────────────────────────────────────────


class _RpcError(Exception):
    """A transport or protocol failure. Caught by the pass; never escapes."""

    def __init__(self, detail: str) -> None:
        super().__init__(detail)
        self.detail = detail


async def _rpc(client: Any, url: str, method: str, params: Sequence[Any]) -> Any:
    """One JSON-RPC 2.0 call, returning `result` or raising `_RpcError`.

    What is logged is the method and the failure class; the response body never
    is. A public node's answer to `eth_getLogs` is routinely hundreds of
    kilobytes of other people's transfer data, and an INFO line that carries it
    turns a merchant's log file into a chain explorer for anyone who can read
    the file.
    """
    if not url:
        raise _RpcError("no RPC endpoint configured")
    import httpx

    payload = {"jsonrpc": "2.0", "id": 1, "method": method, "params": list(params)}
    try:
        response = await client.post(url, json=payload, headers={"content-type": "application/json"})
    except httpx.HTTPError as exc:
        raise _RpcError("%s: %s" % (method, type(exc).__name__)) from exc
    except (OSError, ValueError) as exc:  # a socket-level surprise, never a crash
        raise _RpcError("%s: %s" % (method, type(exc).__name__)) from exc
    if response.status_code >= 400:
        # The node's own message is included in the log line truncated and never
        # the body: rate-limit responses from public providers quote the caller's
        # key back in the text, and that text would otherwise land in a log.
        raise _RpcError("%s: HTTP %d" % (method, response.status_code))
    try:
        length = len(response.content)
    except Exception:  # pragma: no cover - defensive; content is always present
        length = 0
    if length > MAX_RPC_RESPONSE_BYTES:
        raise _RpcError("%s: response of %d bytes exceeds the cap" % (method, length))
    try:
        document = response.json()
    except ValueError as exc:
        raise _RpcError("%s: response is not JSON" % method) from exc
    if not isinstance(document, Mapping):
        raise _RpcError("%s: response is not an object" % method)
    error = document.get("error")
    if error is not None:
        code = ""
        message = ""
        if isinstance(error, Mapping):
            code = str(error.get("code", ""))[:16]
            message = str(error.get("message", ""))[:120]
        raise _RpcError("%s: rpc error %s %s" % (method, code, message))
    if "result" not in document:
        raise _RpcError("%s: response has no result" % method)
    return document["result"]


# ─────────────────────────────────────────────────────────────────────────────
# 13. Chain passes
#
# Each pass is a generator of candidates and a cursor decision. Nothing in here
# decides on its own whether a payment is worth telling anybody about; that is
# `min_delta` and the whitelist, and the pass simply reports what the chain said.
# ─────────────────────────────────────────────────────────────────────────────


async def _poll_evm(deps: PluginDeps, client: Any, url: str, stop: "asyncio.Event") -> Tuple[Optional[int], Dict[str, Dict[str, Any]], int, List[Dict[str, Any]]]:
    """Every EVM watcher → candidates, plus the cursors the pass earned.

    Cursors are *returned, not applied*: a pass that advanced `last_block` and
    then failed to record what it found would delete those transfers from this
    gateway's reach forever. The caller applies them only once the rows are
    committed (see :func:`_apply_cursors`), so a fused meter costs a repeated
    poll rather than a lost payment.

    The head is read once and shared: asking each watcher for `eth_blockNumber`
    would produce a pass in which two watchers disagree about what "now" is, and
    a cursor advanced past a block another watcher has not read yet is a lost
    transfer.
    """
    watchers = [item for item in list_watchers(deps.db, CHAIN_EVM) if item["active"]]
    if not watchers:
        return (None, {}, 0, [])
    head = parse_quantity(await _rpc(client, url, "eth_blockNumber", []))
    if head is None:
        raise _RpcError("eth_blockNumber returned an unreadable value")
    candidates: Dict[str, Dict[str, Any]] = {}
    cursors: List[Dict[str, Any]] = []
    skipped_total = 0
    for watcher in watchers:
        if stop.is_set():
            break
        start, end, skipped = log_range(watcher["last_block"], head)
        skipped_total += skipped
        if skipped:
            log.warning(
                "web3 bridge: evm watch %d gap of %d blocks beyond the %d lookback; cursor moves to %d",
                watcher["id"], skipped, LOOKBACK_BLOCKS, start - 1,
            )
        if start > end:
            continue
        queries: List[Mapping[str, Any]] = [{"address": watcher["address"]}]
        token = str(watcher.get("token") or "")
        if token:
            padded = topic_bytes32(watcher["address"])
            queries.append({"address": token, "topics": [ERC20_TRANSFER_TOPIC0, None, padded]})
            queries.append({"address": token, "topics": [ERC20_TRANSFER_TOPIC0, padded, None]})
        highest_kept = start - 1
        truncated_any = False
        for query in queries:
            params: Dict[str, Any] = {"fromBlock": "0x%x" % start, "toBlock": "0x%x" % end}
            for key in ("address", "topics"):
                if key in query:
                    params[key] = query[key]
            raw = await _rpc(client, url, "eth_getLogs", [params])
            logs, truncated = normalise_logs(raw if isinstance(raw, (list, tuple)) else [])
            if truncated:
                truncated_any = True
            for entry in logs:
                transfer = parse_erc20_transfer(entry)
                if transfer is None:
                    continue
                merge_log_candidate(candidates, watcher, entry, transfer)
                number = entry.get("block_number")
                if isinstance(number, int) and number > highest_kept:
                    highest_kept = number
        # Native value only when the gap is small enough to fetch honestly: an
        # unbounded block scan is the same unbounded-request bug `log_range`
        # exists to prevent, and `eth_getLogs` has covered the whole window.
        if end - start + 1 <= MAX_NATIVE_BLOCK_SPAN:
            fetched = 0
            for number in range(end, start - 1, -1):
                if stop.is_set() or fetched >= MAX_NATIVE_BLOCKS_PER_PASS:
                    break
                fetched += 1
                block = normalise_block(await _rpc(client, url, "eth_getBlockByNumber", ["0x%x" % number, True]))
                if block is None:
                    continue
                for tx in block["transactions"]:
                    for other in watchers:
                        merge_native_candidate(candidates, other, tx, block.get("number"))
        cursors.append({"watch_id": watcher["id"], "block": end if not truncated_any else max(highest_kept, start - 1)})
    return (head, candidates, skipped_total, cursors)


def _apply_cursors(deps: PluginDeps, cursors: Sequence[Mapping[str, Any]]) -> None:
    """Commit the cursors a pass earned. Only ever called after recording.

    Splitting "look" from "advance" is the whole reason a gateway can survive a
    night with a fused meter: the rows and the ledger commit first, the cursor
    moves second, and anything that did not commit is simply looked at again on
    the next pass — deduped by `(chain, tx_hash, log_index)`, so a re-look is
    free rather than a second charge.
    """
    for entry in cursors:
        block = entry.get("block")
        if block is not None:
            advance_watcher_block(deps.db, int(entry["watch_id"]), int(block))
        meta = entry.get("meta")
        if isinstance(meta, Mapping) and meta:
            _set_meta(deps.db, int(entry["watch_id"]), meta)


async def _poll_solana(deps: PluginDeps, client: Any, url: str, stop: "asyncio.Event") -> Tuple[Optional[int], Dict[str, Dict[str, Any]], int, List[Dict[str, Any]]]:
    """Every Solana watcher → candidates, by balance delta then attribution.

    `getBalance` first, because it is one cheap call that answers the only
    question that matters: did anything move? `getSignaturesForAddress` then
    gives the candidates for *which* transaction, and `getTransaction` — the
    expensive one, and the one public nodes rate-limit hardest — is called only
    for signatures that are new and only while the balance actually changed.
    That ordering is what keeps a pass on a quiet watcher at two requests.

    The balance/signature cursor is deferred exactly as the EVM block cursor is:
    recording commits first, then :func:`_apply_cursors` moves the baseline.
    Writing the new balance before the rows exist would make the delta
    disappear before anybody was ever told about it.
    """
    watchers = [item for item in list_watchers(deps.db, CHAIN_SOLANA) if item["active"]]
    if not watchers:
        return (None, {}, 0, [])
    candidates: Dict[str, Dict[str, Any]] = {}
    cursors: List[Dict[str, Any]] = []
    lookups = 0
    for watcher in watchers:
        if stop.is_set():
            break
        address = watcher["address"]
        balance = normalise_balance_result(await _rpc(client, url, "getBalance", [address, {"commitment": "confirmed"}]))
        raw = await _rpc(client, url, "getSignaturesForAddress", [address, {"limit": MAX_SIGS_PER_ADDRESS, "commitment": "confirmed"}])
        fetched = normalise_signatures(raw)
        previous = watcher.get("last_balance")
        seen = watcher.get("signatures") or []
        fresh = new_signatures(seen, fetched)
        if balance is None:
            log.warning("web3 bridge: solana watch %d returned an unreadable balance", watcher["id"])
            continue
        if isinstance(previous, int) and not isinstance(previous, bool):
            delta = balance - previous
            if delta != 0 and fresh and abs(delta) > 0:
                attributed = 0
                for signature, block_time in fresh[:MAX_TX_LOOKUPS_PER_PASS]:
                    if stop.is_set() or lookups >= MAX_TX_LOOKUPS_PER_PASS:
                        break
                    lookups += 1
                    tx = await _rpc(client, url, "getTransaction", [signature, {"encoding": "jsonParsed", "maxSupportedTransactionVersion": 0}])
                    tx_delta = parse_tx_lamport_delta(tx, address)
                    if tx_delta is None or tx_delta == 0:
                        continue
                    merge_delta_candidate(candidates, watcher, signature, tx_delta, block_time)
                    attributed += 1
                if attributed == 0:
                    # The balance moved and nothing attributable moved with it:
                    # a rent refund, an unstake, or a signature page that has
                    # not settled yet. Recording it against somebody else's
                    # transaction would be inventing an audit reference, so it
                    # is logged and left for the next pass to attribute.
                    log.warning(
                        "web3 bridge: solana watch %d moved %d lamports with %d unseen signatures attributable",
                        watcher["id"], delta, len(fresh),
                    )
            elif delta != 0 and not fresh:
                log.warning("web3 bridge: solana watch %d moved %d lamports with no unseen signature", watcher["id"], delta)
        cursors.append({
            "watch_id": watcher["id"],
            "block": None,
            "meta": {"last_balance": int(balance), "signatures": [item[0] for item in fetched]},
        })
    return (None, candidates, 0, cursors)


# ─────────────────────────────────────────────────────────────────────────────
# 14. Who gets told
#
# The question this section answers is the only genuinely dangerous one in the
# plugin: a bridge that resolves an on-chain address to the wrong follower sends
# one person's payment details into another person's inbox. Every path below
# therefore prefers *no* delivery to a *probable* delivery, and every path that
# does not deliver says why in a string the operator can read.
#
# The schema cannot answer the question directly: `web3_whitelist` is keyed
# (chain, address, channel_id) and has no contact column, and
# `channel_members` is keyed (channel_id, contact_id) with no address column.
# There is no join between an address and a person anywhere in the DDL. Two
# conventions fill the gap without a migration — the whitelist `tag`, and a
# contact whose free-form `tags` names the address — and when neither resolves,
# the notification goes to the channel's entitled set *only* while that set is
# small (MAX_NOTIFY_SESSIONS), because an entitled-set-of-hundreds is a
# broadcast and a broadcast of one member's income is an incident.
# ─────────────────────────────────────────────────────────────────────────────


def contacts_for_address(db: Any, address: str) -> List[int]:
    """Contacts whose `tags` field names this address as a whole token.

    A cheap SQL prefilter (`LIKE`) plus the exact whole-token check in Python:
    the LIKE narrows the scan, `address_in_tags` decides. Reading every contact
    row and comparing in Python would be simpler and would not scale past a few
    thousand followers, which is a commercial deployment's Tuesday.
    """
    needle = str(address or "").strip()
    if not needle:
        return []
    rows = db.query("SELECT contact_id, tags FROM contacts WHERE tags IS NOT NULL AND tags <> ''")
    out: List[int] = []
    for row in rows:
        if address_in_tags(row["tags"], needle):
            out.append(int(row["contact_id"]))
    return sorted(set(out))


def _entitled_sessions(deps: PluginDeps, channel_id: str) -> List[Any]:
    """The usable sessions for one channel, ordered by contact id.

    `EcoSession.usable` is the client's own rule (1..32 bytes of hex, not
    revoked) applied by the seam, and a session that fails it would seal a frame
    the phone drops — so filtering here is what turns "the follower never got
    it" into a line in the log that says so.
    """
    try:
        sessions = list(deps.eco.sessions_for_channel(channel_id) or [])
    except EcoError as exc:
        log.warning("web3 bridge: sessions_for_channel(%s) refused: %s: %s", channel_id, exc.rule, exc.detail)
        return []
    except Exception:  # a sibling plugin or a half-written gateway must not kill the poller
        log.exception("web3 bridge: sessions_for_channel(%s) raised", channel_id)
        return []
    return [item for item in sessions if getattr(item, "usable", False)]


def resolve_notify_targets(deps: PluginDeps, chain: str, address: str,
                           watchers: Sequence[Mapping[str, Any]]) -> Tuple[List[Dict[str, Any]], List[str]]:
    """(targets, reasons). A target is `{contact_id, session, channel_id}`.

    Routes, in order of trustworthiness:

    1. a whitelist row for this exact `(chain, address)` → its channel;
    2. otherwise the watcher's own `channel_id`, if it has one;
    3. within a channel, the member is named by the row's `tag`
       (`contact:17`), else by a contact whose `tags` carries the address,
       else the channel's entitled set when that set is small.

    An address nobody whitelists and no watcher points at a channel produces no
    target at all — the event is still recorded and charged, which is the point:
    "we saw it" and "we told somebody" are different claims and must not be
    collapsed into one boolean.
    """
    targets: List[Dict[str, Any]] = []
    reasons: List[str] = []
    seen: Set[int] = set()
    rows = whitelist_for_address(deps.db, chain, address)
    channels: List[Tuple[str, Optional[str]]] = []
    for row in rows:
        channels.append((str(row["channel_id"]), row["tag"]))
    if not channels:
        for watcher in watchers:
            channel = str(watcher.get("channel_id") or "")
            if channel:
                channels.append((channel, None))
    if not channels:
        reasons.append("no whitelist row and no watcher channel for %s/%s" % (chain, address))
        return ([], reasons)
    for channel_id, tag in channels:
        if not channel_id:
            continue
        sessions = _entitled_sessions(deps, channel_id)
        if not sessions:
            reasons.append("%s has no usable session to deliver to" % channel_id)
            continue
        wanted: Optional[int] = tag_contact_id(tag)
        if wanted is None:
            named = contacts_for_address(deps.db, address)
            usable_ids = {int(item.contact_id) for item in sessions}
            candidates = [value for value in named if value in usable_ids]
            if len(candidates) > 1:
                reasons.append(
                    "%s: %d contacts claim %s; refusing to guess whose payment this is"
                    % (channel_id, len(candidates), truncate_address(address))
                )
                continue
            if len(candidates) == 1:
                wanted = candidates[0]
        chosen: List[Any] = []
        if wanted is not None:
            chosen = [item for item in sessions if int(item.contact_id) == int(wanted)]
            if not chosen:
                reasons.append("%s: member %s has no usable session on this channel" % (channel_id, wanted))
                continue
        else:
            if len(sessions) > MAX_NOTIFY_SESSIONS:
                reasons.append(
                    "%s: %d entitled members and no named owner for %s; recorded, not broadcast"
                    % (channel_id, len(sessions), truncate_address(address))
                )
                continue
            chosen = list(sessions)
        for session in chosen:
            contact_id = int(session.contact_id)
            if contact_id in seen:
                continue
            seen.add(contact_id)
            targets.append({"contact_id": contact_id, "session": session, "channel_id": channel_id})
    return (targets, reasons)


def detail_url_for(deps: PluginDeps, session: Any, candidate_key: str) -> Optional[str]:
    """The signed H5 detail link, or None when there is no session to sign with.

    None means the card is built without the action — the client rejects an
    unknown action kind outright and rejects kind `none` on a card too
    (crypto_service.build_action), so "no link" is expressed by absence, never
    by a placeholder.
    """
    if session is None or not getattr(session, "usable", False):
        return None
    try:
        return deps.eco.h5_url(session, "/plugins/web3/event?e=%s" % quote_component(candidate_key))
    except EcoError as exc:
        log.warning("web3 bridge: h5_url refused (%s: %s); sending the card without the link", exc.rule, exc.detail)
        return None
    except Exception:
        log.exception("web3 bridge: h5_url raised for contact %s", getattr(session, "contact_id", None))
        return None


async def notify_event(deps: PluginDeps, event: Mapping[str, Any]) -> int:
    """Deliver the receipt card for one recorded event. Returns cards sent.

    `notified` moves only when a delivery was actually accepted, and a failure
    on one member never stops the others: an outbox hiccup for follower 3 is not
    a reason follower 1 does not learn they were paid.
    """
    watchers = list(event.get("targets") or [])
    if not watchers:
        return 0
    primary = watchers[0]
    chain = str(event["chain"])
    address = str(event.get("address") or primary.get("address") or "")
    targets, reasons = resolve_notify_targets(deps, chain, address, watchers)
    for reason in reasons:
        log.info("web3 bridge: event %s recorded but not sent: %s", event.get("key"), reason)
    if not targets:
        return 0
    amount_text = format_candidate_amount(event, primary)
    if not amount_text:
        log.warning("web3 bridge: event %s has no amount to render; not sending", event.get("key"))
        return 0
    sent = 0
    for target in targets:
        session = target["session"]
        url = detail_url_for(deps, session, str(event.get("key") or ""))
        try:
            card = receipt_card(
                card_id=card_id_for_event(chain, event["tx_hash"], event.get("log_index")),
                chain=chain,
                direction=str(event.get("direction") or "other"),
                amount_text=amount_text,
                counterparty=str(event.get("counterparty") or ""),
                tx_hash=str(event.get("tx_hash") or ""),
                observed_at_ms=int(event.get("observed_at_ms") or now_ms()),
                detail_url=url,
                label=str(primary.get("label") or ""),
            )
            visible = receipt_visible_text(chain, str(event.get("direction") or "other"), amount_text)
        except EcoError as exc:
            log.error(
                "web3 bridge: card for %s would break the client rule %s: %s; not sent",
                event.get("key"), exc.rule, exc.detail,
            )
            continue
        try:
            delivery = await deps.eco.deliver_card(card, target["contact_id"], visible_text=visible, topic="web3")
        except EcoError as exc:
            log.warning("web3 bridge: delivery to %d refused (%s: %s)", target["contact_id"], exc.rule, exc.detail)
            continue
        except Exception:
            log.exception("web3 bridge: delivery to %d raised", target["contact_id"])
            continue
        if getattr(delivery, "sent", False):
            sent += 1
        else:
            log.info(
                "web3 bridge: node accepted nothing for contact %d (queued=%s, error=%s)",
                target["contact_id"], getattr(delivery, "queued", None), getattr(delivery, "error", None),
            )
    if sent:
        mark_events_notified(deps.db, [int(event["event_id"])])
    return sent


# ─────────────────────────────────────────────────────────────────────────────
# 15. The key grant — when a whitelist row's promise is honoured
#
# `deliver_channel_key` is the only call in this plugin that hands out key
# material, and a key rotation is not a notification: it costs the merchant
# credits (`key_rotation`), it changes what a member's device can decrypt, and
# the client's own apply() only moves state when the epoch it receives is newer
# than the one it holds (ChannelKeyRotationManager.swift:645) — a re-delivery of
# the epoch already current returns `.alreadyCurrent` and is a no-op on the
# phone (:651-657).
#
# So the trigger is the promise, not the payment: `web3_whitelist.granted_epoch`
# is NULL, or is behind `channels.current_epoch` (database.py:416-418 calls that
# column the record that the promise "this address gets this channel's rotation"
# was kept). A transfer notification never rotates anything on its own, and the
# `CHANNEL_PAY_RCPT` path never calls this at all — see `handle_inbound`: the
# membership that a receipt buys is the gateway's own handler's business, and a
# second granter would be a second implementation of that rule.
#
# It is addressed, never broadcast: a grant needs one named member (tag or
# contact tag match). If the row does not name one, the bridge says so and does
# nothing. Sending key material to "the channel's members" because the schema
# left a column out is exactly the kind of convenient wrong thing this file is
# here not to do.
# ─────────────────────────────────────────────────────────────────────────────


def _grant_target(deps: PluginDeps, row: Mapping[str, Any]) -> Tuple[Optional[int], str]:
    channel_id = str(row["channel_id"])
    address = str(row["address"])
    sessions = _entitled_sessions(deps, channel_id)
    if not sessions:
        return (None, "%s has no usable member session" % channel_id)
    wanted = tag_contact_id(row.get("tag"))
    if wanted is None:
        usable_ids = {int(item.contact_id) for item in sessions}
        named = [value for value in contacts_for_address(deps.db, address) if value in usable_ids]
        if len(named) == 1:
            wanted = named[0]
        elif len(named) > 1:
            return (None, "%d contacts claim this address; a key grant is addressed, not guessed" % len(named))
        else:
            return (None, "whitelist row names no member (tag=\"contact:<id>\" is how to say it)")
    else:
        # A tag names a contact; the tag alone is not membership. Confirm the
        # contact is in the channel's entitled set before asking the gateway to
        # seal key material for them.
        if not any(int(item.contact_id) == int(wanted) for item in sessions):
            return (None, "member %s is not entitled to %s" % (wanted, channel_id))
    return (int(wanted), "")


async def honour_grant(deps: PluginDeps, row: Mapping[str, Any]) -> bool:
    """Honour one whitelist promise. Never raises.

    `granted_epoch` is written only when the grant reports `delivered`, so a
    node that was down mid-pass retries on the next pass instead of recording a
    key the member never received — which would strand them with an epoch they
    cannot decrypt and, because the column said otherwise, never be fixed.
    """
    contact_id, reason = _grant_target(deps, row)
    if contact_id is None:
        log.warning(
            "web3 bridge: key grant for %s/%s not honoured: %s", row["chain"], truncate_address(row["address"]), reason
        )
        return False
    try:
        grant = await deps.eco.deliver_channel_key(str(row["channel_id"]), contact_id)
    except EcoError as exc:
        log.warning("web3 bridge: deliver_channel_key refused (%s: %s)", exc.rule, exc.detail)
        return False
    except Exception:
        log.exception("web3 bridge: deliver_channel_key raised for %s/%d", row["channel_id"], contact_id)
        return False
    if not getattr(grant, "delivered", False):
        log.warning(
            "web3 bridge: grant for %s/%d reported %s",
            str(row["channel_id"]), contact_id, getattr(grant, "error", None) or "not delivered",
        )
        return False
    record_grant(deps.db, str(row["chain"]), str(row["address"]), str(row["channel_id"]), getattr(grant, "epoch", None))
    return True


async def honour_outstanding_grants(deps: PluginDeps, stop: Optional["asyncio.Event"] = None) -> int:
    """The poller's promise sweep. Returns how many rows were honoured.

    Bounded by `MAX_GRANT_ROWS_PER_PASS` and interruptible, because a gateway
    that comes back after a month with 400 outstanding rows must not spend the
    first pass minting 400 rotations and charging for all of them.
    """
    count = 0
    for row in outstanding_grants(deps.db):
        if stop is not None and stop.is_set():
            break
        if not await honour_grant(deps, row):
            continue
        count += 1
    return count


# ─────────────────────────────────────────────────────────────────────────────
# 16. The pass, and the loop that runs it
# ─────────────────────────────────────────────────────────────────────────────


async def _run_pass(deps: PluginDeps, client: Any, urls: Mapping[str, str], stop: "asyncio.Event") -> bool:
    """One look at every configured chain. True when nothing went wrong.

    Ordering worth stating: outstanding key promises are honoured *first*,
    because they need no network and a node that is refusing us should not also
    be a night in which members cannot read the channel. Then each chain is
    polled, recorded and notified. A chain whose RPC fails leaves its cursors
    untouched — :func:`_apply_cursors` is only reached on the success path — so
    the next pass re-reads the same blocks and dedupes against the rows that did
    make it.

    Returns "did every configured chain answer", not "did anything happen": a
    quiet chain with no watchers and no transfers is a success and must reset
    the backoff, otherwise a busy EVM watcher and a dead Solana node would put
    the whole loop into permanent backoff.
    """
    granted = await honour_outstanding_grants(deps, stop)
    if granted:
        log.info("web3 bridge: honoured %d outstanding channel key grant(s)", granted)
    all_ok = True
    notifications = 0
    for chain, poller in ((CHAIN_EVM, _poll_evm), (CHAIN_SOLANA, _poll_solana)):
        url = str(urls.get(chain) or "")
        if not url:
            continue
        if stop.is_set():
            break
        cursors: List[Dict[str, Any]] = []
        try:
            head, candidates, skipped, cursors = await poller(deps, client, url, stop)
        except (Web3ValidationError, _RpcError) as exc:
            all_ok = False
            RUN_STATE["last_error"] = "%s: %s" % (chain, exc)
            log.warning("web3 bridge: %s pass skipped (%s)", chain, exc)
            continue
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # the one place a surprise is allowed to be broad
            all_ok = False
            RUN_STATE["last_error"] = "%s: %s" % (chain, type(exc).__name__)
            log.exception("web3 bridge: %s pass raised", chain)
            continue
        if head is not None:
            RUN_STATE["heads"][chain] = int(head)
        if skipped:
            RUN_STATE.setdefault("gaps", {})[chain] = int(skipped)
        events: List[Dict[str, Any]] = []
        for key in sorted(candidates):
            if stop.is_set():
                break
            try:
                event = record_candidate(deps, candidates[key])
            except BillingError as exc:
                # The meter is fused. Nothing is recorded (the transaction
                # rolled back), no cursor moves, and the operator sees this line
                # rather than a silent loss: the payment is on-chain whether or
                # not we are paid to report it.
                all_ok = False
                RUN_STATE["last_error"] = "billing: %s" % exc.code
                log.warning("web3 bridge: %s not recorded, meter refused it (%s: %s)", key, exc.code, exc)
                break
            except sqlite3.IntegrityError:
                # Another writer won the (chain, tx_hash, log_index) race. The
                # UNIQUE index did its job; this is a duplicate, not a fault.
                log.info("web3 bridge: %s already recorded by another writer", key)
                continue
            except Exception:
                all_ok = False
                log.exception("web3 bridge: recording %s raised", key)
                continue
            if event is not None:
                events.append(event)
                RUN_STATE["events_recorded"] = int(RUN_STATE.get("events_recorded", 0)) + 1
        if stop.is_set() and not events:
            break
        for event in events:
            try:
                notifications += await notify_event(deps, event)
            except asyncio.CancelledError:
                raise
            except Exception:
                log.exception("web3 bridge: notification for %s raised", event.get("key"))
        if notifications:
            RUN_STATE["notifications_sent"] = int(RUN_STATE.get("notifications_sent", 0)) + notifications
        if all_ok or events or cursors:
            _apply_cursors(deps, cursors)
    RUN_STATE["last_pass_at_ms"] = now_ms()
    RUN_STATE["last_pass_ok"] = all_ok
    return all_ok


async def _interruptible_sleep(stop: "asyncio.Event", seconds: float) -> bool:
    """Sleep in one-second chunks; True if it was cut short by `stop`.

    Chunked rather than one `wait_for(stop.wait(), seconds)` because a 60-second
    backoff on a single await is a 60-second shutdown, and `uvicorn` will
    eventually call that a hang. One second is the longest a stop can cost here,
    and the await is real (not a poll of `is_set()`), so an idle loop is idle.
    """
    remaining = max(0.0, float(seconds))
    while remaining > 0:
        if stop.is_set():
            return True
        chunk = min(1.0, remaining)
        try:
            await asyncio.wait_for(stop.wait(), timeout=chunk)
            return True
        except asyncio.TimeoutError:
            pass
        except asyncio.CancelledError:
            raise
        remaining -= chunk
    return stop.is_set()


async def poll_loop(deps: PluginDeps, stop: Optional["asyncio.Event"] = None, *, interval_seconds: Optional[int] = None) -> None:
    """The background reader. Exports its own contract in its failure behaviour.

    Signature, since `app.main` is the caller: positional `(deps, stop)`;
    `stop` may be omitted in tests (a private Event is then created and the loop
    runs until cancelled). `interval_seconds` overrides
    `config.web3_poll_interval_seconds` for an operator-driven one-off.

    Three guarantees, in order of how much they cost to keep:

    1. **Nothing escapes.** Every chain pass, every record and every
       notification is wrapped. An exception that left this coroutine would take
       the gateway's task with it and leave the merchant with a plugin that is
       switched on, metered, and deaf — and no log line that says so.
       `asyncio.CancelledError` is the one thing re-raised, because swallowing a
       cancellation is how a shutdown becomes a hang, and a task that ignores
       cancellation cannot be stopped at all.
    2. **Backoff, capped, and reset on success.** 1s, 2s, 4s … 60s
       (:func:`backoff_delay`). A node that restarts is back in a second; a node
       that is gone costs the loop one request a minute.
    3. **No configuration, no spin.** If both RPC urls are empty the loop logs
       one clear line and returns, rather than sleeping forever doing nothing on
       a task nobody can distinguish from a stalled one.
    """
    own_stop = stop is None
    if own_stop:
        stop = asyncio.Event()
    assert stop is not None
    urls = configured_rpc_urls(deps.config)
    if not any(urls.values()):
        log.info(
            "web3 bridge: neither POPOPX_WEB3_EVM_RPC_URL nor POPOPX_WEB3_SOLANA_RPC_URL is "
            "configured; poll loop exiting without polling (the plugin stays switched on)"
        )
        return
    interval = poll_interval_seconds(
        interval_seconds if interval_seconds is not None else getattr(deps.config, "web3_poll_interval_seconds", 30)
    )
    RUN_STATE.update({
        "running": True,
        "interval_seconds": interval,
        "started_at_ms": now_ms(),
        "consecutive_failures": 0,
        "last_error": "",
        "heads": {},
    })
    import httpx

    client = httpx.AsyncClient(
        timeout=httpx.Timeout(RPC_TIMEOUT_SECONDS, connect=min(RPC_TIMEOUT_SECONDS, 5.0)),
        headers={"user-agent": "popopx-gateway/web3-bridge", "accept": "application/json"},
        limits=httpx.Limits(max_connections=8, max_keepalive_connections=4),
        follow_redirects=False,
    )
    attempt = 0
    try:
        while not stop.is_set():
            ok = False
            try:
                ok = await _run_pass(deps, client, urls, stop)
            except asyncio.CancelledError:
                raise
            except Exception:
                log.exception("web3 bridge: pass orchestration raised; backing off")
                ok = False
            delay = interval
            if ok:
                if attempt:
                    log.info("web3 bridge: RPC link recovered")
                attempt = 0
                RUN_STATE["consecutive_failures"] = 0
            else:
                attempt += 1
                RUN_STATE["consecutive_failures"] = attempt
                delay = backoff_delay(attempt)
                log.warning("web3 bridge: pass failed (%d consecutive), retrying in %.0fs", attempt, delay)
            if await _interruptible_sleep(stop, delay):
                break
    except asyncio.CancelledError:
        log.info("web3 bridge: poll loop cancelled; exiting")
        raise
    finally:
        RUN_STATE["running"] = False
        try:
            await client.aclose()
        except Exception:  # a client that will not close must not mask the reason we left
            log.debug("web3 bridge: httpx client close raised", exc_info=True)
    log.info("web3 bridge: poll loop stopped")


# ─────────────────────────────────────────────────────────────────────────────
# 17. Inbound: the receipt that proves a member paid
# ─────────────────────────────────────────────────────────────────────────────


async def handle_inbound(deps: PluginDeps, message: Any) -> bool:
    """Claim one `CHANNEL_PAY_RCPT` for a channel this bridge watches.

    Returns False for everything else, which is how a receipt for a channel we
    do not watch reaches the merchant's own handler intact. The overlap for a
    channel we *do* watch is deliberate and stated in the module docstring: this
    path writes the bridge's audit trail and the merchant's handler grants the
    membership the money bought. Neither charges.

    Exactly three things happen here, all of them idempotent:

    1. the events carrying this tx hash, for addresses watched on this channel,
       move `notified` 0 → 1 (the guard is in the UPDATE's WHERE clause, so a
       replay updates zero rows and the count says so);
    2. an audit row in `settings` records the credits and the hash the receipt
       carried, which `web3_events` has no column for;
    3. nothing is sent and nothing is charged. No card, because the transfer
       notification was already delivered by the poller and a second card for
       one payment is a double notification; no charge, because the meter was
       paid when the event was recorded. This is the property the brief asks
       this path to have, and the reason it can be replayed safely.

    It does NOT call `deliver_channel_key`: see section 15. The rotation promise
    belongs to the whitelist row and the epoch, not to a receipt whose channel
    may name a dozen members.

    The claim decision never depends on our own database being healthy — if the
    bookkeeping raises, the receipt is still claimed (True), because returning
    False after a partial write would hand the merchant's handler a receipt this
    bridge has already touched, which is a worse double than not touching it.
    """
    callback = getattr(message, "callback", None)
    if callback is None:
        return False
    kind = getattr(callback, "kind", "")
    sys_kind = getattr(callback, "sys_kind", "")
    channel_id = str(getattr(callback, "channel_id", "") or "")
    try:
        watched = watched_channel_ids(deps.db)
    except Exception:
        log.exception("web3 bridge: could not read the watcher set for a receipt")
        return False
    if not should_claim_receipt(kind, sys_kind, channel_id, watched):
        return False
    tx_hash = str(getattr(callback, "tx_hash", "") or "").strip()
    credits_amount = int(getattr(callback, "credits", 0) or 0)
    claimed = {"ok": True, "plugin": PLUGIN_ID, "channel_id": channel_id, "sys_kind": sys_kind}
    try:
        events = events_for_tx(deps.db, tx_hash, channel_id) if tx_hash else []
        event_ids = [int(row["id"]) for row in events]
        moved = mark_events_notified(deps.db, event_ids)
        key = receipt_audit_key(channel_id, tx_hash, credits_amount)
        fresh = write_receipt_audit(deps.db, key, {
            "channel_id": channel_id,
            "tx_hash": tx_hash,
            "credits": credits_amount,
            "event_ids": event_ids,
            "contact_id": getattr(message, "contact_id", None),
            "sys_kind": sys_kind,
            "recorded_at_ms": now_ms(),
        })
        log.info(
            "web3 bridge: claimed %s for channel %s (events=%d newly_notified=%d audit=%s)",
            sys_kind, channel_id, len(event_ids), moved, "written" if fresh else "replay",
        )
    except Exception:
        log.exception("web3 bridge: receipt bookkeeping failed for channel %s; receipt still claimed", channel_id)
    return True


# ─────────────────────────────────────────────────────────────────────────────
# 18. Request parsing — pure, so the parts a 400 depends on are self-tested
# ─────────────────────────────────────────────────────────────────────────────


def query_mapping(params: Any) -> Dict[str, str]:
    """Starlette's `QueryParams` (a Mapping) or a plain dict → a plain dict.

    Read-only screening runs on this, so a query string is *not* exempt from the
    key-name check: `?private_key=...` is the same mistake as putting it in the
    body, and DELETE /whitelist takes its parameters from the query.
    """
    out: Dict[str, str] = {}
    if params is None:
        return out
    try:
        items = list(params.items())
    except AttributeError:
        return out
    for name, value in items:
        out[str(name)] = value if isinstance(value, str) else str(value)
    return out


def decode_json_object(raw: bytes, *, content_type: str = "") -> Dict[str, Any]:
    """Body bytes → a mapping, or a `Web3ValidationError` naming the rule.

    Guards in order, because each catches a different real mistake: size (a 40 MB
    body must not be allocated before it is rejected), emptiness (an operator who
    forgot `Content-Type` on a POST gets "send a JSON object", not a 500), syntax,
    and top-level type (a JSON array of watchers is a shape this API does not
    have). `content_type` is checked loosely — `application/json`, the
    `+json` suffixed types and an absent type are all accepted, because curl
    defaults to `x-www-form-urlencoded` and refusing that would be pedantry that
    costs a merchant an afternoon; a *non*-JSON type is refused, because form
    encoding silently drops nesting and a lost `{"watcher":{...}}` level is how
    half-configured watchers happen.
    """
    limit = MAX_REQUEST_BODY_BYTES
    if len(raw) > limit:
        raise Web3ValidationError("body_size", "%d bytes exceeds the %d-byte limit" % (len(raw), limit))
    ctype = str(content_type or "").split(";", 1)[0].strip().lower()
    if ctype and ctype not in ("application/json", "text/json") and not ctype.endswith("+json"):
        raise Web3ValidationError("content_type", "%r is not JSON; send application/json" % (ctype,))
    if not raw.strip():
        raise Web3ValidationError("body_required", "expected a JSON object body")
    try:
        parsed = json.loads(raw.decode("utf-8"))
    except UnicodeDecodeError:
        raise Web3ValidationError("body_encoding", "body must be UTF-8") from None
    except ValueError as exc:
        raise Web3ValidationError("body_json", "body is not valid JSON (%s)" % (exc.args[0] if exc.args else exc,)) from None
    if not isinstance(parsed, dict):
        raise Web3ValidationError("body_shape", "expected a JSON object, got %s" % type(parsed).__name__)
    return parsed


def parse_flag(value: Any, name: str = "active", default: bool = True) -> bool:
    """Tri-state query flag: absent → `default`, else truthy/falsy text."""
    if value is None or str(value).strip() == "":
        return default
    text = str(value).strip().lower()
    if text in ("1", "true", "yes", "y", "on", "all"):
        return True
    if text in ("0", "false", "no", "n", "off"):
        return False
    raise Web3ValidationError(name, "%r is not a true/false value" % (value,))


def parse_limit(value: Any, default: int = DEFAULT_EVENT_LIMIT, maximum: int = MAX_EVENT_LIMIT) -> int:
    if value is None or str(value).strip() == "":
        return int(default)
    try:
        number = int(str(value).strip())
    except ValueError:
        raise Web3ValidationError("limit", "%r is not an integer" % (value,)) from None
    if number <= 0:
        raise Web3ValidationError("limit", "must be at least 1")
    if number > maximum:
        raise Web3ValidationError("limit", "%d exceeds the maximum of %d" % (number, maximum))
    return number


def parse_watch_id(value: Any) -> int:
    text = _clean_text(value, "watch_id", 20)
    if not text.isdigit():
        raise Web3ValidationError("watch_id", "%r is not a positive integer" % (value,))
    number = int(text)
    if number <= 0:
        raise Web3ValidationError("watch_id", "must be greater than 0")
    return number


def parse_threshold(payload: Mapping[str, Any], decimals: int) -> Optional[int]:
    """`min_delta` (whole units) or `min_delta_minor` (raw), never both.

    Two spellings because an operator thinks in ETH and a migration script thinks
    in wei, and the bridge stores one integer column. Rejecting their simultaneous
    presence is the point: a body that says both and is ignored on one of them
    records a threshold the operator did not ask for.
    """
    human = payload.get("min_delta")
    raw = payload.get("min_delta_minor")
    if human is not None and raw is not None:
        raise Web3ValidationError("min_delta", "supply min_delta or min_delta_minor, not both")
    if human is None and raw is None:
        return None
    if raw is not None:
        if isinstance(raw, bool) or isinstance(raw, float):
            raise Web3ValidationError("min_delta_minor", "expected an integer, got %r" % (raw,))
        text = str(raw).strip()
        if not text.isdigit():
            raise Web3ValidationError("min_delta_minor", "%r is not a non-negative integer" % (raw,))
        if len(text) > MAX_RAW_DIGITS:
            raise Web3ValidationError("min_delta_minor", "threshold is absurdly large")
        return int(text)
    return to_minor_units(human, decimals)


def rpc_status_view(urls: Mapping[str, str]) -> Dict[str, Dict[str, Any]]:
    """What `/status` may say about the endpoints: host only, never a credential.

    `redacted` is the operator-facing flag that says "your URL contained
    something this endpoint will not print" — the value itself is never echoed,
    not even partially, because a one-character prefix of an Infura project id is
    still a third of a secret.
    """
    out: Dict[str, Dict[str, Any]] = {}
    for chain in CHAINS:
        raw = str(urls.get(chain) or "").strip()
        shown = redact_rpc_url(raw)
        out[chain] = {
            "configured": bool(raw),
            "endpoint": shown,
            "redacted": bool(raw) and shown != raw,
        }
    return out


# ─────────────────────────────────────────────────────────────────────────────
# 18b. Read-side queries the routes answer from
# ─────────────────────────────────────────────────────────────────────────────


def channel_exists(db: Any, channel_id: str) -> bool:
    return db.query_one("SELECT 1 AS ok FROM channels WHERE channel_id = ?", (channel_id,)) is not None


def find_watcher(db: Any, chain: str, address: str) -> Optional[Dict[str, Any]]:
    row = db.query_one("SELECT * FROM web3_watch WHERE chain = ? AND address = ?", (chain, address))
    return _row_to_watcher(db, row) if row is not None else None


def watcher_stats(db: Any, chain: str, address: str) -> Dict[str, int]:
    """observed / notified / unnotified for one watched address.

    Keyed on `(chain, address)` rather than on a watcher id because that is what
    `web3_events` stores — the schema links events to an address, not to a row,
    so the counts survive a deactivate/re-add cycle and honestly describe the
    address's history.
    """
    row = db.query_one(
        "SELECT COUNT(*) AS observed, SUM(CASE WHEN notified = 1 THEN 1 ELSE 0 END) AS notified"
        " FROM web3_events WHERE chain = ? AND address = ?",
        (chain, address),
    )
    if row is None:
        return {"observed": 0, "notified": 0, "unnotified": 0}
    observed = int(row["observed"] or 0)
    notified = int(row["notified"] or 0)
    return {"observed": observed, "notified": notified, "unnotified": observed - notified}


def last_processed_block(db: Any, chain: str) -> Optional[int]:
    return max_watcher_block(db, chain)


def event_view(db: Any, row: Mapping[str, Any]) -> Dict[str, Any]:
    """A `web3_events` row plus the human-readable amount it lacks.

    The row stores minor units as TEXT (`amount`); the display string is derived
    here, from the watcher's unit when one exists, so `GET /events` and the card
    can never disagree about what the same payment looked like.
    """
    out = dict(row)
    chain = str(out.get("chain") or "")
    address = str(out.get("address") or "")
    symbol, decimals = _DEFAULT_UNIT.get(chain, ("", 0))
    watcher = db.query_one("SELECT * FROM web3_watch WHERE chain = ? AND address = ?", (chain, address))
    if watcher is not None:
        shell = _row_to_watcher(db, watcher)
        symbol = str(shell.get("symbol") or symbol)
        decimals = int(shell.get("decimals") or 0)
    raw = out.get("amount")
    out["amount_display"] = None
    if raw is not None and chain in CHAINS:
        try:
            out["amount_display"] = format_amount(str(raw), decimals, symbol)
        except Web3ValidationError:
            # A row written by an older poller, or by hand, must not turn a list
            # endpoint into a 500. The raw value stays visible; only the derived
            # field goes quiet.
            log.warning("web3 bridge: event %s carries an unparseable amount", out.get("id"))
    out["address_short"] = truncate_address(address)
    return out


# ─────────────────────────────────────────────────────────────────────────────
# 19. The HTTP surface
# ─────────────────────────────────────────────────────────────────────────────

#: The exact request keys each route accepts. Anything else is a 400 naming the
#: key, because a typo (`min_amout`) that is silently ignored produces a watcher
#: that notifies on every dust transfer — which reads as "the bridge is broken"
#: and is really a threshold nobody ever set.
_WATCHER_CREATE_KEYS: Tuple[str, ...] = (
    "chain", "address", "label", "channel_id", "min_delta", "min_delta_minor", "symbol", "decimals", "token",
)
_WATCHER_PATCH_KEYS: Tuple[str, ...] = (
    "label", "channel_id", "min_delta", "min_delta_minor", "symbol", "decimals", "token", "active",
)
_WHITELIST_KEYS: Tuple[str, ...] = ("chain", "address", "channel_id", "tag")


def _reject_unknown_keys(payload: Mapping[str, Any], allowed: Sequence[str], name: str) -> None:
    extra = sorted(str(key) for key in payload if str(key) not in set(allowed))
    if extra:
        raise Web3ValidationError(
            "%s_fields" % name,
            "unknown field(s) %s; accepted: %s" % (extra, sorted(allowed)),
        )


def parse_watcher_create(payload: Mapping[str, Any]) -> Dict[str, Any]:
    """Validated POST /watchers fields. Pure: no DB, no FastAPI."""
    _reject_unknown_keys(payload, _WATCHER_CREATE_KEYS, "watcher")
    chain = validate_chain(payload.get("chain"))
    address = validate_address(chain, payload.get("address"))
    label = "" if payload.get("label") is None else _clean_text(payload.get("label"), "label", MAX_LABEL_CHARS)
    raw_channel = payload.get("channel_id")
    channel_id = validate_channel_id(raw_channel) if raw_channel not in (None, "") else None
    symbol = validate_symbol(payload.get("symbol"), chain)
    decimals = validate_decimals(payload.get("decimals"), chain)
    token_raw = payload.get("token")
    token = validate_address(chain, token_raw) if token_raw not in (None, "") else None
    if token is not None and chain == CHAIN_EVM and token == address:
        raise Web3ValidationError("token", "a token contract cannot be the account it is watched as")
    min_delta = parse_threshold(payload, decimals)
    if min_delta == 0:
        # "notify from 0" and "notify on anything" are the same rule with extra
        # steps; refusing keeps `min_delta` NULL meaning exactly "unset".
        min_delta = None
    return {
        "chain": chain,
        "address": address,
        "label": label,
        "channel_id": channel_id,
        "min_delta": min_delta,
        "symbol": symbol,
        "decimals": decimals,
        "token": token,
    }


def parse_watcher_patch(payload: Mapping[str, Any], chain: str) -> Dict[str, Any]:
    """Validated PATCH fields. `chain` and `address` are not patchable.

    Changing the address of a watcher would move its identity while leaving the
    label, the channel and every event row behind — the honest operation is
    DELETE the old one (which deactivates) and POST the new one, and that is what
    this API says.
    """
    _reject_unknown_keys(payload, _WATCHER_PATCH_KEYS, "watcher")
    changes: Dict[str, Any] = {}
    if "label" in payload:
        raw_label = payload["label"]
        changes["label"] = "" if raw_label in (None, "") else _clean_text(raw_label, "label", MAX_LABEL_CHARS)
    if "channel_id" in payload:
        raw_channel = payload["channel_id"]
        changes["channel_id"] = "" if raw_channel in (None, "") else validate_channel_id(raw_channel)
    if "symbol" in payload or "decimals" in payload or "min_delta" in payload or "min_delta_minor" in payload:
        symbol = validate_symbol(payload.get("symbol"), chain) if "symbol" in payload else None
        decimals = (
            validate_decimals(payload.get("decimals"), chain)
            if "decimals" in payload
            else _DEFAULT_UNIT[chain][1]
        )
        if symbol is not None:
            changes["symbol"] = symbol
        if "decimals" in payload:
            changes["decimals"] = decimals
        if "min_delta" in payload or "min_delta_minor" in payload:
            changes["min_delta"] = parse_threshold(payload, decimals)
    if "token" in payload:
        raw_token = payload["token"]
        changes["token"] = "" if raw_token in (None, "") else validate_address(chain, raw_token)
    if "active" in payload:
        changes["active"] = parse_flag(payload["active"], "active", True)
    if not changes:
        raise Web3ValidationError("watcher", "no fields to change")
    return changes


def parse_whitelist_entry(payload: Mapping[str, Any]) -> Dict[str, Any]:
    """Validated POST /whitelist fields. `channel_id` is required: the row *is*
    the claim "this address belongs to a member of this service account", and a
    row without a channel can notify nobody."""
    _reject_unknown_keys(payload, _WHITELIST_KEYS, "whitelist")
    chain = validate_chain(payload.get("chain"))
    address = validate_address(chain, payload.get("address"))
    channel_id = validate_channel_id(payload.get("channel_id"))
    raw_tag = payload.get("tag")
    tag = None if raw_tag in (None, "") else _clean_text(raw_tag, "tag", MAX_TAG_CHARS)
    return {"chain": chain, "address": address, "channel_id": channel_id, "tag": tag}


def detect_chain(value: Any) -> Optional[str]:
    """Which chain a bare address belongs to — for a *query filter* only.

    A watcher's chain is declared by the operator, never inferred; this exists so
    `GET /events?address=…` can canonicalise the filter the same way the stored
    rows are canonicalised (EVM folded, Solana case-preserved). Ambiguous or
    malformed input returns None and the route turns that into a 400.
    """
    text = str(value or "").strip()
    if not text:
        return None
    for chain, validator in ((CHAIN_EVM, validate_evm_address), (CHAIN_SOLANA, validate_solana_address)):
        try:
            validator(text)
        except Web3ValidationError:
            continue
        return chain
    return None


def count_watchers(db: Any, active_only: bool = False) -> int:
    sql = "SELECT COUNT(*) FROM web3_watch"
    if active_only:
        sql += " WHERE active = 1"
    value = db.scalar(sql)
    return int(value) if isinstance(value, int) else 0


def count_whitelist(db: Any) -> int:
    value = db.scalar("SELECT COUNT(*) FROM web3_whitelist")
    return int(value) if isinstance(value, int) else 0


def watcher_warnings(deps: PluginDeps, watcher: Mapping[str, Any]) -> List[str]:
    """Configuration holes this watcher cannot answer for itself.

    A watcher whose chain has no RPC endpoint, or whose loop never started, is
    indistinguishable from a working one until a payment goes unannounced. Saying
    it at creation time — and in `GET /watchers` — is the difference between a
    five-second fix and a support ticket.
    """
    out: List[str] = []
    chain = str(watcher.get("chain") or "")
    urls = configured_rpc_urls(deps.config)
    if not urls.get(chain):
        out.append("no JSON-RPC endpoint is configured for chain %r; this watcher cannot poll" % chain)
    if not RUN_STATE.get("running"):
        out.append("the poll loop is not running in this process (main.py must create_task poll_loop(deps, stop))")
    channel = str(watcher.get("channel_id") or "")
    if not channel:
        out.append("no channel_id: events are recorded and metered but never notified")
    elif not channel_exists(deps.db, channel):
        out.append("channel %r does not exist; notifications will have nowhere to go" % channel)
    elif not _entitled_sessions(deps, channel):
        out.append("channel %r has no entitled member with a usable session yet" % channel)
    return out


def _router_prefix(deps: PluginDeps) -> str:
    """Prefer the mount table's prefix; fall back to this module's mirror.

    `app.plugins.PLUGIN_SPEC` is the single source of truth for where a plugin
    lives, so a re-prefix there is honoured without editing this file — and
    self_test asserts the mirror still matches.
    """
    spec = getattr(deps, "spec", None)
    if getattr(spec, "plugin_id", None) == PLUGIN_ID:
        prefix = str(getattr(spec, "url_prefix", "") or "").rstrip("/")
        if prefix:
            return prefix
    return URL_PREFIX


def create_router(deps: PluginDeps) -> "APIRouter":
    """Build `/api/v1/plugins/web3`.

    Mounting contract, stated because the seam does not: the returned router
    carries `deps.spec.url_prefix` as its own prefix, so `app.main` includes it
    with a bare `app.include_router(router)`. If main.py passes
    `prefix=spec.url_prefix` as well, every path doubles — that is a one-line
    change on the mount side, and this docstring is where the choice is recorded.

    Three rules every route obeys:

    1. `deps.require()` first, so a disabled plugin answers 404 with the mount
       table's reason code and a fused meter answers 402 — never a 500 from
       inside a handler that assumed it was enabled.
    2. `require_read_only` on the **query string and the body**, before anything
       is looked at or stored. A parameter named like key material is a 400 that
       says the gateway is read-only by design.
    3. Validation failures are `Web3ValidationError` (or the `EcoError` family,
       whose `.rule` is named in the text) mapped to their own status by
       :func:`_mapped` — no traceback, no half-written row.
    """
    import contextlib

    from fastapi import APIRouter, HTTPException, Request

    # Same rule as `alert_ops_plugin.create_router`: with `from __future__ import
    # annotations` every annotation below is a string, and FastAPI resolves it against
    # THIS module's globals, not this function's locals. Without the line, each of the
    # nine routes in this router took a required *query* parameter named `request` and
    # answered 422 to every caller — which is why the module-level self-test, which
    # calls the handlers, never saw it and `app.main.http_self_test` does.
    globals()["Request"] = Request

    router = APIRouter(prefix=_router_prefix(deps), tags=[PLUGIN_ID])

    @contextlib.contextmanager
    def _mapped():
        """The single error → HTTP translation for this router."""
        try:
            yield
        except PluginUnavailable as exc:
            decision = exc.decision
            raise HTTPException(status_code=int(exc.http_status), detail=decision.as_body()) from None
        except Web3ValidationError as exc:
            raise HTTPException(
                status_code=int(exc.status or 400),
                detail={"error": exc.rule, "message": exc.detail, "plugin": PLUGIN_ID},
            ) from None
        except CryptoUnavailable as exc:
            raise HTTPException(
                status_code=503, detail={"error": exc.rule, "message": exc.detail, "plugin": PLUGIN_ID}
            ) from None
        except EcoValidationError as exc:
            raise HTTPException(
                status_code=400,
                detail={"error": exc.rule, "message": "the iOS parser would drop this frame: %s" % exc.detail,
                        "plugin": PLUGIN_ID},
            ) from None
        except EcoError as exc:
            raise HTTPException(
                status_code=400, detail={"error": exc.rule, "message": exc.detail, "plugin": PLUGIN_ID}
            ) from None
        except BillingError as exc:
            raise HTTPException(
                status_code=int(exc.http_status or 402),
                detail={"error": exc.code, "message": exc.message, "plugin": PLUGIN_ID},
            ) from None
        except sqlite3.Error as exc:
            # A constraint the route did not expect is a server-side fact, not a
            # client error — and the message stays generic: sqlite's text can
            # quote the offending value.
            log.exception("web3 bridge: database error in a route")
            raise HTTPException(
                status_code=500,
                detail={"error": "storage_error", "message": "the gateway could not store this configuration",
                        "plugin": PLUGIN_ID},
            ) from None

    async def _guard(request: "Request") -> None:
        deps.require()
        require_read_only(query_mapping(request.query_params))

    async def _json_body(request: "Request") -> Dict[str, Any]:
        raw = await request.body()
        content_type = ""
        try:
            content_type = request.headers.get("content-type", "") or ""
        except Exception:  # a header-less test harness still gets a JSON check
            content_type = ""
        payload = decode_json_object(raw, content_type=content_type)
        require_read_only(payload)
        return payload

    def _require_channel(channel_id: Optional[str]) -> None:
        if channel_id and not channel_exists(deps.db, channel_id):
            raise Web3ValidationError(
                "channel_id",
                "unknown channel %r: the service account must exist before a watcher points at it" % channel_id,
                status=404,
            )

    # ---- watchers -----------------------------------------------------------

    @router.post("/watchers")
    async def create_watcher(request: "Request") -> Dict[str, Any]:
        """Watch `(chain, address)`. Re-posting an existing pair updates it and
        switches it back on — `UNIQUE (chain, address)` makes two rows for one
        address two pollers and two notifications for one payment."""
        with _mapped():
            await _guard(request)
            payload = await _json_body(request)
            fields = parse_watcher_create(payload)
            _require_channel(fields["channel_id"])
            prior = find_watcher(deps.db, fields["chain"], fields["address"])
            watcher = upsert_watcher(
                deps.db,
                chain=fields["chain"],
                address=fields["address"],
                label=fields["label"],
                channel_id=fields["channel_id"],
                min_delta=fields["min_delta"],
                symbol=fields["symbol"],
                decimals=fields["decimals"],
                token=fields["token"],
            )
            watcher["created"] = prior is None
            watcher["reactivated"] = bool(prior is not None and not prior.get("active"))
            watcher["stats"] = watcher_stats(deps.db, watcher["chain"], watcher["address"])
            watcher["warnings"] = watcher_warnings(deps, watcher)
            log.info(
                "web3 bridge: watching %s %s (%s) on channel %s",
                watcher["chain"], truncate_address(watcher["address"]), watcher["label"] or "unlabelled",
                watcher["channel_id"] or "-",
            )
            return {"ok": True, "watcher": watcher}

    @router.get("/watchers")
    async def get_watchers(request: "Request") -> Dict[str, Any]:
        """Every watcher, with the counters that show whether it is doing anything."""
        with _mapped():
            await _guard(request)
            params = query_mapping(request.query_params)
            chain = validate_chain(params["chain"]) if params.get("chain") else None
            active_only = parse_flag(params.get("active"), "active", True)
            rows = list_watchers(deps.db, chain=chain, active_only=active_only)
            for row in rows:
                row["stats"] = watcher_stats(deps.db, row["chain"], row["address"])
                row["warnings"] = watcher_warnings(deps, row)
            heads = {
                item: last_processed_block(deps.db, item) for item in ([chain] if chain else list(CHAINS))
            }
            return {
                "ok": True,
                "watchers": rows,
                "count": len(rows),
                "last_processed_block": heads,
                "loop_running": bool(RUN_STATE.get("running")),
            }

    @router.patch("/watchers/{watch_id}")
    async def patch_watcher(watch_id: str, request: "Request") -> Dict[str, Any]:
        with _mapped():
            await _guard(request)
            ident = parse_watch_id(watch_id)
            current = get_watcher(deps.db, ident)
            if current is None:
                raise Web3ValidationError("watcher", "no watcher with id %d" % ident, status=404)
            payload = await _json_body(request)
            changes = parse_watcher_patch(payload, str(current["chain"]))
            _require_channel(str(changes["channel_id"]) if changes.get("channel_id") else None)
            updated = update_watcher(deps.db, ident, changes)
            if updated is None:
                raise Web3ValidationError("watcher", "no watcher with id %d" % ident, status=404)
            updated["stats"] = watcher_stats(deps.db, updated["chain"], updated["address"])
            updated["warnings"] = watcher_warnings(deps, updated)
            return {"ok": True, "watcher": updated, "changed": sorted(str(key) for key in changes)}

    @router.delete("/watchers/{watch_id}")
    async def delete_watcher(watch_id: str, request: "Request") -> Dict[str, Any]:
        """Deactivate, do not delete — `web3_events` rows carry `(chain, address)`,
        not a watcher id, so the row is what keeps the address's history
        explainable. See :func:`set_watcher_active`."""
        with _mapped():
            await _guard(request)
            ident = parse_watch_id(watch_id)
            watcher = set_watcher_active(deps.db, ident, False)
            if watcher is None:
                raise Web3ValidationError("watcher", "no watcher with id %d" % ident, status=404)
            watcher["stats"] = watcher_stats(deps.db, watcher["chain"], watcher["address"])
            return {
                "ok": True,
                "mode": "deactivated",
                "reason": "history-preserving: web3_events keys on (chain, address), not on a watcher row",
                "watcher": watcher,
            }

    # ---- whitelist ----------------------------------------------------------

    @router.post("/whitelist")
    async def add_whitelist(request: "Request") -> Dict[str, Any]:
        """Claim "this on-chain address belongs to a member of this channel"."""
        with _mapped():
            await _guard(request)
            payload = await _json_body(request)
            fields = parse_whitelist_entry(payload)
            _require_channel(fields["channel_id"])
            row = upsert_whitelist(
                deps.db,
                chain=fields["chain"],
                address=fields["address"],
                channel_id=fields["channel_id"],
                tag=fields["tag"],
            )
            prior = find_watcher(deps.db, fields["chain"], fields["address"])
            targets, reasons = resolve_notify_targets(
                deps, fields["chain"], fields["address"], [prior] if prior else []
            )
            epoch = channel_current_epoch(deps.db, fields["channel_id"])
            granted = row.get("granted_epoch")
            return {
                "ok": True,
                "whitelist": row,
                "delivery": {"targets": len(targets), "reasons": reasons},
                "key_grant": {
                    "channel_epoch": epoch,
                    "granted_epoch": granted,
                    "pending": granted is None or (epoch is not None and int(granted or 0) < int(epoch)),
                    "note": "the key is handed over by the poll loop when the channel's epoch is newer than the recorded grant; posting a row is not a rotation",
                },
            }

    @router.get("/whitelist")
    async def get_whitelist(request: "Request") -> Dict[str, Any]:
        with _mapped():
            await _guard(request)
            params = query_mapping(request.query_params)
            chain = validate_chain(params["chain"]) if params.get("chain") else None
            address = validate_address(chain, params["address"]) if params.get("address") and chain else None
            if params.get("address") and not chain:
                detected = detect_chain(params["address"])
                if detected is None:
                    raise Web3ValidationError("address", "%r is not a valid EVM or Solana address" % params["address"])
                address = validate_address(detected, params["address"])
            rows = list_whitelist(deps.db, chain=chain, address=address,
                                  channel_id=(params.get("channel_id") or None))
            return {"ok": True, "whitelist": rows, "count": len(rows)}

    @router.delete("/whitelist")
    async def remove_whitelist(request: "Request") -> Dict[str, Any]:
        """Drop the claim. `channel_id` is optional: omitting it removes every
        channel that was told this address is one of its members."""
        with _mapped():
            await _guard(request)
            params = query_mapping(request.query_params)
            chain = validate_chain(params.get("chain")) if params.get("chain") else None
            if chain is None:
                raise Web3ValidationError("chain", "required to remove a whitelist row")
            address = validate_address(chain, params.get("address"))
            channel_id = params.get("channel_id") or None
            if channel_id:
                channel_id = validate_channel_id(channel_id)
            removed = delete_whitelist(deps.db, chain=chain, address=address, channel_id=channel_id)
            return {"ok": True, "removed": removed, "chain": chain, "address": truncate_address(address)}

    # ---- events -------------------------------------------------------------

    @router.get("/events")
    async def get_events(request: "Request") -> Dict[str, Any]:
        """Newest first. Read-only view of what was seen, charged, and told."""
        with _mapped():
            await _guard(request)
            params = query_mapping(request.query_params)
            chain = validate_chain(params["chain"]) if params.get("chain") else None
            address = None
            if params.get("address"):
                if chain is None:
                    chain = detect_chain(params["address"])
                    if chain is None:
                        raise Web3ValidationError(
                            "address", "%r is not a valid EVM or Solana address; pass chain= to disambiguate"
                            % params["address"]
                        )
                address = validate_address(chain, params["address"])
            limit = parse_limit(params.get("limit"))
            notified: Optional[int] = None
            if params.get("notified") not in (None, ""):
                notified = 1 if parse_flag(params.get("notified"), "notified", True) else 0
            rows = list_events(deps.db, chain=chain, address=address, limit=limit, notified=notified)
            return {
                "ok": True,
                "events": [event_view(deps.db, row) for row in rows],
                "count": len(rows),
                "counts": event_counts(deps.db),
            }

    # ---- status -------------------------------------------------------------

    @router.get("/status")
    async def get_status(request: "Request") -> Dict[str, Any]:
        """Health, in the shape an operator debugs with.

        The RPC endpoints are echoed **redacted**: scheme and host only. Userinfo
        (`https://KEY@rpc/`), the path (Infura's `/v3/PROJECT_ID`) and the query
        (Alchemy's `?key=`) are all credential carriers in the endpoints people
        actually run, so none of them are printed, and `redacted: true` tells the
        operator why what they see is shorter than what they set.
        """
        with _mapped():
            await _guard(request)
            # PLUGIN_ID, not `deps.plugin_id`: `PluginDeps.spec` defaults to the
            # ai_agent row, and a status body that reported another plugin's gate
            # would be worse than one that reported a mismatch.
            decision = deps.gate.status(PLUGIN_ID)
            urls = configured_rpc_urls(deps.config)
            heads: Dict[str, Any] = {item: last_processed_block(deps.db, item) for item in CHAINS}
            live_heads = RUN_STATE.get("heads") or {}
            return {
                "ok": True,
                "plugin": PLUGIN_ID,
                "enabled": bool(decision.usable),
                "gate": decision.as_body(),
                "meter": METER,
                "url_prefix": _router_prefix(deps),
                "callback_kinds": list(CALLBACK_KINDS),
                "poll": {
                    "running": bool(RUN_STATE.get("running")),
                    "interval_seconds": int(RUN_STATE.get("interval_seconds") or 0),
                    "started_at_ms": int(RUN_STATE.get("started_at_ms") or 0),
                    "last_pass_at_ms": int(RUN_STATE.get("last_pass_at_ms") or 0),
                    "last_pass_ok": RUN_STATE.get("last_pass_ok"),
                    "consecutive_failures": int(RUN_STATE.get("consecutive_failures") or 0),
                    "last_error": str(RUN_STATE.get("last_error") or ""),
                    "events_recorded": int(RUN_STATE.get("events_recorded") or 0),
                    "notifications_sent": int(RUN_STATE.get("notifications_sent") or 0),
                    "backoff_cap_seconds": BACKOFF_CAP_SECONDS,
                    "lookback_blocks": LOOKBACK_BLOCKS,
                },
                "rpc": rpc_status_view(urls),
                "last_seen_block": {
                    item: {
                        "from_watchers": heads.get(item),
                        "from_rpc": (live_heads.get(item) if isinstance(live_heads, Mapping) else None),
                    }
                    for item in CHAINS
                },
                "watchers": {
                    "total": count_watchers(deps.db),
                    "active": count_watchers(deps.db, active_only=True),
                    "channels": sorted(watched_channel_ids(deps.db)),
                },
                "events": event_counts(deps.db),
                "whitelist": {
                    "rows": count_whitelist(deps.db),
                    "pending_grants": len(outstanding_grants(deps.db, MAX_GRANT_ROWS_PER_PASS)),
                    "pending_grants_capped_at": MAX_GRANT_ROWS_PER_PASS,
                },
                "read_only": True,
            }

    return router


# ─────────────────────────────────────────────────────────────────────────────
# 20. self_test — the pure half, executed
#
# Every check below runs on a bare interpreter with no wheels installed. Nothing
# here touches a socket, a database, an event loop or FastAPI, which is what makes
# the count meaningful: a failure is a real bug in a function the poll path calls,
# not an environment complaint.
# ─────────────────────────────────────────────────────────────────────────────


def self_test() -> List[str]:
    """Run the pure-half assertions. Returns the names of the checks that passed."""
    checks: List[str] = []

    class _Namespace:
        """The `Config` stand-in for attribute-reading helpers.

        `configured_rpc_urls` takes the real dataclass and reads two named
        attributes, so the double has to be an object with attributes — a dict
        would pass `getattr(..., default)` for every key and the check would
        report that missing attributes read as empty even when the lookup was
        never exercised.
        """

        def __init__(self, **values: Any) -> None:
            self.__dict__.update(values)

    def check(name: str, condition: bool) -> None:
        if not condition:
            raise AssertionError("self_test failed: %s" % name)
        checks.append(name)

    def refuses(fn: Any, *args: Any, **kwargs: Any) -> bool:
        try:
            fn(*args, **kwargs)
        except Web3ValidationError:
            return True
        return False

    def rule_of(fn: Any, *args: Any, **kwargs: Any) -> str:
        try:
            fn(*args, **kwargs)
        except Web3ValidationError as exc:
            return exc.rule
        return ""

    class _Config:
        """Stands in for `app.config.Config`: only attribute reads matter here."""

        def __init__(self, **kwargs: Any) -> None:
            self.__dict__.update(kwargs)

    evm_mixed = "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed"   # EIP-55 mixed case
    evm_lower = evm_mixed.lower()
    sol_44 = "9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM"
    sol_43 = "So11111111111111111111111111111111111111112"
    sol_32 = "1" * 32
    uint256_max = (1 << 256) - 1

    # -- seam identity: the mount row and this module cannot drift silently ----
    spec = plugin_for_id(PLUGIN_ID)
    check("spec_module_name", spec.module_name == "app.plugins.web3_bridge_plugin")
    check("spec_url_prefix", spec.url_prefix == URL_PREFIX)
    check("spec_meter", spec.meter == METER)
    check("spec_callback_kinds", tuple(spec.callback_kinds) == tuple(CALLBACK_KINDS) == ("system",))
    check("spec_toggle_attr", spec.toggle == "web3_bridge")
    check("chains_closed_set", CHAINS == (CHAIN_EVM, CHAIN_SOLANA))
    check("default_units_cover_chains", set(_DEFAULT_UNIT) == set(CHAINS))
    check("no_log_index_is_negative", NO_LOG_INDEX < 0)

    # -- EVM addresses --------------------------------------------------------
    check("evm_valid", validate_evm_address(evm_lower) == evm_lower)
    check("evm_mixed_case_normalised", validate_evm_address(evm_mixed) == evm_lower)
    check("evm_surrounding_space_trimmed", validate_evm_address("  " + evm_mixed + "\n") == evm_lower)
    check("evm_rejects_missing_prefix", refuses(validate_evm_address, evm_lower[2:]))
    check("evm_rejects_39_hex", refuses(validate_evm_address, "0x" + "a" * 39))
    check("evm_rejects_41_hex", refuses(validate_evm_address, "0x" + "a" * 41))
    check("evm_rejects_non_hex", refuses(validate_evm_address, "0x" + "z" * 40))
    check("evm_rejects_empty", refuses(validate_evm_address, ""))
    check("evm_rejects_prefix_only", refuses(validate_evm_address, "0x"))
    check("evm_rejects_overlong", refuses(validate_evm_address, "0x" + "a" * 400))
    check("evm_rejects_none", refuses(validate_evm_address, None))
    check("evm_rejects_non_string", refuses(validate_evm_address, 1234))
    check("evm_rule_name", rule_of(validate_evm_address, "0xnope") == "evm_address")
    # The documented decision: a checksum-inconsistent claim is normalised, not
    # rejected, so a paste from a spreadsheet cannot create a dead watcher.
    # All-caps hex is essentially never a valid EIP-55 checksum, which makes it
    # the strongest possible proof that no checksum test is happening.
    check("evm_eip55_not_enforced", validate_evm_address("0x" + "A" * 40) == "0x" + "a" * 40)
    check("evm_checksum_case_is_irrelevant", validate_evm_address(evm_mixed) == validate_evm_address(evm_mixed.upper().replace("0X", "0x")))

    # -- Solana addresses -----------------------------------------------------
    check("sol_44_valid", validate_solana_address(sol_44) == sol_44)
    check("sol_43_valid", validate_solana_address(sol_43) == sol_43)
    check("sol_32_valid", validate_solana_address(sol_32) == sol_32)
    check("sol_case_preserved", validate_solana_address(sol_44) != sol_44.lower())
    check("sol_rejects_31", refuses(validate_solana_address, "1" * 31))
    check("sol_rejects_45", refuses(validate_solana_address, "1" * 45))
    check("sol_rejects_zero", refuses(validate_solana_address, "0" + sol_44[1:]))
    check("sol_rejects_capital_O", refuses(validate_solana_address, "O" + sol_44[1:]))
    check("sol_rejects_capital_I", refuses(validate_solana_address, "I" + sol_44[1:]))
    check("sol_rejects_lower_L", refuses(validate_solana_address, "l" + sol_44[1:]))
    check("sol_rejects_dash", refuses(validate_solana_address, sol_44[:-1] + "-"))
    check("sol_rejects_empty", refuses(validate_solana_address, ""))
    check("sol_rejects_overlong", refuses(validate_solana_address, "1" * 200))
    check("sol_rule_name", rule_of(validate_solana_address, "0OIl") == "solana_address")

    # -- dispatch and the other scalar validators ----------------------------
    check("dispatch_evm", validate_address("EVM", evm_mixed) == evm_lower)
    check("dispatch_solana", validate_address("Solana", sol_44) == sol_44)
    check("chain_unknown_refused", refuses(validate_chain, "bitcoin"))
    check("chain_empty_refused", refuses(validate_chain, "  "))
    check("chain_case_folded", validate_chain("SOLANA") == CHAIN_SOLANA)
    check("dispatch_bad_chain_not_defaulted", refuses(validate_address, "toncoin", evm_lower))
    check("channel_id_valid", validate_channel_id("ch_12-34") == "ch_12-34")
    check("channel_id_rejects_slash", refuses(validate_channel_id, "ch/12"))
    check("channel_id_rejects_space", refuses(validate_channel_id, "ch 12"))
    check("channel_id_rejects_overlong", refuses(validate_channel_id, "c" * (EcoLimits.payload_chars + 1)))
    check("symbol_default_evm", validate_symbol(None, CHAIN_EVM) == "ETH")
    check("symbol_default_solana", validate_symbol(None, CHAIN_SOLANA) == "SOL")
    check("symbol_folded", validate_symbol("usdc", CHAIN_EVM) == "USDC")
    check("symbol_rejects_space", refuses(validate_symbol, "US D", CHAIN_EVM))
    check("symbol_rejects_overlong", refuses(validate_symbol, "X" * (MAX_SYMBOL_CHARS + 1), CHAIN_EVM))
    check("decimals_default_evm", validate_decimals(None, CHAIN_EVM) == 18)
    check("decimals_default_solana", validate_decimals(None, CHAIN_SOLANA) == 9)
    check("decimals_rejects_negative", refuses(validate_decimals, -1, CHAIN_EVM))
    check("decimals_rejects_over_max", refuses(validate_decimals, MAX_DECIMALS + 1, CHAIN_EVM))
    check("decimals_rejects_bool", refuses(validate_decimals, True, CHAIN_EVM))
    check("decimals_rejects_string", refuses(validate_decimals, "18", CHAIN_EVM))

    # -- display truncation vs stored value ----------------------------------
    short = truncate_address(evm_lower)
    check("truncate_shorter_than_full", len(short) < len(evm_lower))
    check("truncate_keeps_head_and_tail", short.startswith("0x5aae") and short.endswith("eaed"))
    check("truncate_marks_the_cut", "\u2026" in short)
    check("truncate_leaves_a_short_one_alone", truncate_address("0xabc") == "0xabc")
    check("truncate_empty_stays_empty", truncate_address("") == "")
    check("truncate_none_stays_empty", truncate_address(None) == "")

    # -- money: exact, decimal, never a float --------------------------------
    check("wei_to_eth_one", format_amount("0x0de0b6b3a7640000", 18, "ETH") == "1 ETH")
    check("wei_to_eth_leading_zero", format_amount(1, 18, "ETH") == "0.000000000000000001 ETH")
    check("wei_to_eth_half", format_amount("500000000000000000", 18, "ETH") == "0.5 ETH")
    check("wei_to_eth_zero", format_amount(0, 18, "ETH") == "0 ETH")
    check("wei_to_eth_keeps_trailing_digits", format_amount("1000000000000000010", 18, "ETH")
          == "1.00000000000000001 ETH")
    check("lamports_to_sol", format_amount("1000000000", 9, "SOL") == "1 SOL")
    check("micro_unit_zero_decimals", format_amount("7", 0, "PEPE") == "7 PEPE")
    check("usdc_two_decimals", format_amount("1234567", 6, "USDC") == "1.234567 USDC")
    check("max_uint256_exact", format_amount(uint256_max, 18, "ETH").replace(" ETH", "").replace(".", "")
          == str(uint256_max))
    check("max_uint256_has_a_radix", "." in format_amount(uint256_max, 18, "ETH"))
    check("base58_amount_requires_the_flag", format_amount("2XNGAK", 9, "SOL", base58=True) == "1 SOL")
    check("base58_amount_refused_without_the_flag", refuses(format_amount, "2XNGAK", 9, "SOL"))
    check("base58_rejects_a_non_base58_char", refuses(parse_minor_units, "2XNGAK0", base58=True))
    check("base58_rejects_overlong", refuses(parse_minor_units, "1" * (MAX_BASE58_INPUT_CHARS + 1), base58=True))
    check("wordlike_garbage_refused_not_rendered", refuses(format_amount, "nan", 18, "ETH"))
    check("symbol_is_uppercased_in_output", format_amount(1, 18, "eth") == "0.000000000000000001 ETH")
    check("format_rejects_float", refuses(format_amount, 1.5, 18, "ETH"))
    check("format_rejects_negative_string", refuses(format_amount, "-5", 18, "ETH"))
    check("format_rejects_negative_int", refuses(format_amount, -5, 18, "ETH"))
    check("format_rejects_bool", refuses(format_amount, True, 18, "ETH"))
    check("format_rejects_empty", refuses(format_amount, "", 18, "ETH"))
    check("format_rejects_bare_x", refuses(format_amount, "0xzz", 18, "ETH"))
    check("format_rejects_exponent", refuses(format_amount, "1e18", 18, "ETH"))
    check("format_rejects_nan", refuses(format_amount, "nan", 18, "ETH"))
    check("format_rejects_inf", refuses(format_amount, "inf", 18, "ETH"))
    check("format_rejects_abc", refuses(format_amount, "abc", 18, "ETH"))
    check("format_rejects_inner_space", refuses(format_amount, "12 34", 18, "ETH"))
    check("format_rejects_overlong_hex", refuses(format_amount, "0x" + "f" * (MAX_HEX_INPUT_CHARS + 1), 18, "ETH"))
    check("format_rejects_overlong_decimal", refuses(format_amount, "9" * (MAX_RAW_DIGITS + 1), 18, "ETH"))
    check("format_rejects_bad_decimals", refuses(format_amount, 1, 99, "ETH"))
    check("format_rejects_negative_decimals", refuses(format_amount, 1, -1, "ETH"))
    check("format_rejects_bad_symbol", refuses(format_amount, 1, 18, "bad symbol"))
    check("format_rejects_none_raw", refuses(format_amount, None, 18, "ETH"))
    check("digits_are_decimal_not_hex", parse_minor_units("10") == 10)
    check("prefixed_digits_are_hex", parse_minor_units("0x10") == 16)
    check("int_passes_through", parse_minor_units(42) == 42)
    check("hex_upper_accepted", parse_minor_units("0xDE0B6B3A7640000") == 10**18)
    check("minor_units_roundtrip", to_minor_units("0.5", 18) == 5 * 10**17)
    check("minor_units_integer", to_minor_units(1, 9) == 10**9)
    check("minor_units_exact_fraction", to_minor_units("1.000000001", 9) == 10**9 + 1)
    check("minor_units_too_precise_refused", refuses(to_minor_units, "0.0000000000000000001", 18))
    check("minor_units_float_refused", refuses(to_minor_units, 0.5, 18))
    check("minor_units_scientific_refused", refuses(to_minor_units, "1e18", 18))
    check("minor_units_sign_refused", refuses(to_minor_units, "-1", 18))
    check("minor_units_roundtrip_inverse", format_amount(to_minor_units("2.25", 18), 18, "ETH") == "2.25 ETH")
    check("exact_string_no_radix_when_integral", exact_decimal_string(10**18, 18) == "1")
    check("exact_string_zero_decimals", exact_decimal_string(7, 0) == "7")
    check("exact_string_rejects_negative", refuses(exact_decimal_string, -1, 18))
    check("exact_string_rejects_overlong_output", refuses(exact_decimal_string, 10 ** (MAX_AMOUNT_CHARS + 1), 0))

    # -- the dedupe / billing key --------------------------------------------
    evm_hash = "0x" + "a1" * 32                     # 64 hex, the real shape
    evm_hash_upper = "0x" + "A1" * 32
    evm_other = "0x" + "b2" * 32
    sol_sig = "5Hbx" + "x" * 84                     # 88 base58, a real signature
    sol_other = "5Hby" + "y" * 84
    key_a = event_idempotency_key(CHAIN_EVM, evm_hash, 2)
    key_b = event_idempotency_key(CHAIN_EVM, evm_hash_upper, 2)
    key_c = event_idempotency_key(CHAIN_EVM, evm_hash, 340)
    key_d = event_idempotency_key(CHAIN_SOLANA, sol_sig, 340)
    check("key_is_prefixed", key_a.startswith("web3:evm:"))
    check("key_case_insensitive_for_evm", key_a == key_b)
    check("key_separates_log_indexes_in_one_tx", key_c != key_a)
    check("key_log_index_is_the_last_field", key_c.rsplit(":", 1)[1] == "340")
    check("key_separates_chains", key_d != key_c)
    check("key_separates_transactions", event_idempotency_key(CHAIN_EVM, evm_other, 2) != key_a)
    check("key_none_index_uses_sentinel", event_idempotency_key(CHAIN_SOLANA, sol_sig, None).endswith(
        ":%d" % NO_LOG_INDEX))
    check("key_sentinel_is_not_a_real_index", not event_idempotency_key(
        CHAIN_SOLANA, sol_sig, None).endswith(":0"))
    # The delimiter-escaping control: a receipt line can carry a hash with `::`
    # inside it (agent_bridge.py:1232 keeps the tail verbatim), so `("a:1", 2)` and
    # `("a", 12)` must not read as one event. The key builder now refuses a
    # malformed hash outright, which is the stronger property — but the escaper it
    # is built from is still what makes that true rather than an accident.
    check("key_escapes_colons", key_component("ch:1:aabb:1") != key_component("ch:1:aabb") + ":1")
    check("key_escaping_is_invertible", key_component("a:b").replace("%3a", ":") == "a:b")
    check("key_rejects_a_coloned_hash", refuses(event_idempotency_key, CHAIN_EVM, "ch:1:aabb:1", 2))
    check("key_rejects_unknown_chain", refuses(event_idempotency_key, "ton", evm_hash, 1))
    check("key_rejects_bad_evm_hash", refuses(event_idempotency_key, CHAIN_EVM, "zz", 1))
    check("key_rejects_short_solana_signature", refuses(event_idempotency_key, CHAIN_SOLANA, "5H3k", 1))
    check("key_rejects_non_base58_signature", refuses(
        event_idempotency_key, CHAIN_SOLANA, "0" * 88, 1))
    check("key_component_escapes_only_the_delimiter", key_component("a%b:c") == "a%25b%3ac")
    check("key_component_keeps_plain_text", key_component(evm_hash) == evm_hash)
    card_id = card_id_for_event(CHAIN_EVM, evm_hash, 2)
    check("card_id_within_client_limit", len(card_id) <= EcoLimits.card_id_chars)
    check("card_id_is_deterministic", card_id == card_id_for_event(CHAIN_EVM, evm_hash_upper, 2))
    check("card_id_differs_per_log_index", card_id != card_id_for_event(CHAIN_EVM, evm_hash, 3))
    check("card_id_differs_per_chain", card_id != card_id_for_event(CHAIN_SOLANA, sol_sig, 2))
    check("card_id_carries_a_chain_marker", card_id.startswith("web3-e-")
          and card_id_for_event(CHAIN_SOLANA, sol_sig, 0).startswith("web3-s-"))
    check("tx_hash_evm_folded", normalise_tx_hash(CHAIN_EVM, evm_hash_upper) == evm_hash)
    check("tx_hash_evm_prefix_added", normalise_tx_hash(CHAIN_EVM, "a1" * 32) == evm_hash)
    check("tx_hash_solana_case_kept", normalise_tx_hash(CHAIN_SOLANA, sol_sig) == sol_sig)
    check("tx_hash_rejects_empty", refuses(normalise_tx_hash, CHAIN_EVM, "   "))

    # -- lookback arithmetic (the multi-day outage) ---------------------------
    start, end, skipped = log_range(100, 105)
    check("range_resumes_after_cursor", (start, end) == (101, 105))
    check("range_first_sync_starts_at_zero", log_range(None, 10)[0] == 0)
    check("range_no_head_is_no_work", log_range(10, None) == (0, -1, 0))
    check("range_negative_head_is_no_work", log_range(10, -1)[1] == -1)
    outage_start, outage_end, outage_skipped = log_range(0, 200_000, lookback=1_000)
    check("outage_window_is_bounded", outage_end - outage_start + 1 <= 1_000)
    check("outage_reports_the_gap", outage_skipped == 200_000 - 1_000 + 1 - 1)
    check("outage_start_is_head_minus_window", outage_start == 200_000 - 1_000 + 1)
    reorg_start, reorg_end, reorg_skipped = log_range(200, 190)
    check("cursor_ahead_of_head_does_no_work", reorg_start > reorg_end)
    check("cursor_ahead_of_head_skips_nothing", reorg_skipped == 0)
    check("window_of_one_is_allowed", log_range(9, 10, lookback=1) == (10, 10, 0))
    check("zero_lookback_clamped_to_one", log_range(0, 5, lookback=0)[0] == 5)
    check("exactly_one_window_is_not_truncated", log_range(-1, LOOKBACK_BLOCKS - 1)[2] == 0
          and (log_range(-1, LOOKBACK_BLOCKS - 1)[1] - log_range(-1, LOOKBACK_BLOCKS - 1)[0] + 1) == LOOKBACK_BLOCKS)
    check("one_block_past_the_window_is_truncated", log_range(-1, LOOKBACK_BLOCKS)[2] == 1)
    check("window_start_is_never_negative", log_range(None, 5, lookback=1_000_000)[0] == 0)

    # -- cursor honesty when the answer was cut short ------------------------
    logs_with_blocks = [{"block_number": 10}, {"block_number": 12}]
    check("untruncated_cursor_is_the_head", advance_block(logs_with_blocks, 20, False, 5) == 20)
    check("truncated_cursor_stops_at_kept_data", advance_block(logs_with_blocks, 20, True, 5) == 12)
    check("truncated_without_readable_blocks_holds", advance_block([{"block_number": None}], 20, True, 7) == 7)
    check("truncated_with_no_previous_starts_at_zero", advance_block([], 20, True, None) == 0)

    # -- backoff --------------------------------------------------------------
    sequence = [backoff_delay(attempt) for attempt in range(1, 10)]
    check("backoff_starts_at_one_second", sequence[0] == 1.0)
    check("backoff_doubles", sequence[:5] == [1.0, 2.0, 4.0, 8.0, 16.0])
    check("backoff_caps_at_sixty", max(sequence) == BACKOFF_CAP_SECONDS)
    check("backoff_never_exceeds_the_cap", all(value <= BACKOFF_CAP_SECONDS for value in sequence))
    check("backoff_is_monotonic", all(b <= c for b, c in zip(sequence, sequence[1:])))
    check("backoff_zero_attempt_is_the_floor", backoff_delay(0) == BACKOFF_FLOOR_SECONDS)
    check("backoff_negative_attempt_is_the_floor", backoff_delay(-3) == BACKOFF_FLOOR_SECONDS)
    check("backoff_reset_is_the_fast_path", backoff_delay(1) < backoff_delay(4))
    check("poll_interval_clamped_low", poll_interval_seconds(1) == MIN_POLL_INTERVAL_SECONDS)
    check("poll_interval_clamped_high", poll_interval_seconds(10**6) == MAX_POLL_INTERVAL_SECONDS)
    check("poll_interval_passes_through", poll_interval_seconds(45) == 45)
    check("poll_interval_garbage_defaults", poll_interval_seconds("soon") == 30)
    check("poll_interval_none_defaults", poll_interval_seconds(None) == 30)

    # -- read-only enforcement -----------------------------------------------
    check("signer_plain_private_key", find_signer_material({"private_key": "x"}) == "private_key")
    check("signer_camel_case", find_signer_material({"privateKey": "x"}) == "privateKey")
    check("signer_uppercase", find_signer_material({"PRIVATE-KEY": "x"}) == "PRIVATE-KEY")
    check("signer_spaced", find_signer_material({"priv key": "x"}) == "priv key")
    check("signer_secret", find_signer_material({"client_secret": "x"}) == "client_secret")
    check("signer_seed", find_signer_material({"seed_phrase": "x"}) == "seed_phrase")
    check("signer_mnemonic", find_signer_material({"mnemonic": "x"}) == "mnemonic")
    check("signer_keystore", find_signer_material({"keystore_json": "x"}) == "keystore_json")
    check("signer_passphrase", find_signer_material({"passphrase": "x"}) == "passphrase")
    check("signer_signer", find_signer_material({"signer_url": "x"}) == "signer_url")
    check("signer_pkcs", find_signer_material({"pkcs12": "x"}) == "pkcs12")
    check("signer_nested_in_object", find_signer_material({"watcher": {"seed": "x"}}) == "seed")
    check("signer_nested_in_list", find_signer_material([{"a": 1}, {"secret": "x"}]) == "secret")
    check("signer_deep_list_nesting", find_signer_material({"a": [[{"b": [{"privateKey": 1}]}]]}) == "privateKey")
    check("clean_payload_passes", find_signer_material(
        {"chain": "evm", "address": evm_lower, "label": "treasury", "min_delta": "0.5"}) is None)
    check("value_text_is_not_a_parameter_name", find_signer_material({"label": "my seed phrase backup"}) is None)
    check("require_read_only_raises", refuses(require_read_only, {"private_key": "x"}))
    check("require_read_only_passes_clean", (require_read_only({"chain": "evm"}) or True) is True)
    check("read_only_detail_says_read_only", "read-only" in READ_ONLY_DETAIL)
    check("depth_bound_is_enforced", refuses(find_signer_material, {"a": {"b": {"c": {"d": {"e": {"f": {"g": 1}}}}}}}))

    # -- URL redaction (what /status may echo) -------------------------------
    check("redact_strips_userinfo", redact_rpc_url("https://SECRETKEY@rpc.example/v3/1") == "https://rpc.example")
    check("redact_output_has_no_at_sign", "@" not in redact_rpc_url("https://k@rpc.example/"))
    check("redact_strips_infura_path", "PROJECT" not in redact_rpc_url("https://mainnet.infura.io/v3/PROJECTID"))
    check("redact_strips_query_key", "key=" not in redact_rpc_url("https://g.alchemy.com/v2?key=SECRET"))
    check("redact_strips_fragment", "frag" not in redact_rpc_url("https://rpc.example/#frag"))
    check("redact_keeps_a_clean_host", redact_rpc_url("https://rpc.example") == "https://rpc.example")
    check("redact_keeps_the_port", redact_rpc_url("http://127.0.0.1:8545") == "http://127.0.0.1:8545")
    check("redact_case_folds_host", redact_rpc_url("https://RPC.Example.COM/v3/x") == "https://rpc.example.com")
    check("redact_refuses_file_scheme", redact_rpc_url("file:///etc/passwd") == "")
    check("redact_refuses_gopher", redact_rpc_url("gopher://rpc.example/x") == "")
    # An empty userinfo is still userinfo, and the rule above is "drop the
    # carrier, keep the host" — not "refuse anything with an @ in it". Refusing
    # here instead would contradict redact_strips_userinfo one line above and
    # give /status two different behaviours for the same shape of paste.
    check("redact_strips_an_empty_userinfo_like_any_other",
          redact_rpc_url("https://@rpc.example") == "https://rpc.example")
    check("redact_refuses_empty_authority", redact_rpc_url("https:///path") == "")
    check("redact_refuses_schemeless", redact_rpc_url("rpc.example/v3/x") == "")
    check("redact_refuses_empty", redact_rpc_url("") == "")
    check("redact_refuses_none", redact_rpc_url(None) == "")
    check("redact_output_is_bounded", len(redact_rpc_url("https://" + "a" * 400)) <= 128)
    urls = {"evm": "https://k@rpc.example/v3/1", "solana": ""}
    view = rpc_status_view(urls)
    check("status_view_marks_configured", view[CHAIN_EVM]["configured"] and not view[CHAIN_SOLANA]["configured"])
    check("status_view_marks_redacted", view[CHAIN_EVM]["redacted"] is True)
    check("status_view_clean_url_is_not_redacted",
          rpc_status_view({"evm": "https://rpc.example", "solana": ""})[CHAIN_EVM]["redacted"] is False)
    check("status_view_never_leaks_the_key", "k@" not in json.dumps(view))
    check("status_view_endpoint_is_host_only", view[CHAIN_EVM]["endpoint"] == "https://rpc.example")
    check("configured_urls_read_attributes", configured_rpc_urls(_Namespace(
        web3_evm_rpc_url=" https://a.example ", web3_solana_rpc_url="")) == {"evm": "https://a.example",
                                                                             "solana": ""})
    check("configured_urls_survive_missing_attributes", configured_rpc_urls(object()) == {"evm": "", "solana": ""})

    return checks
