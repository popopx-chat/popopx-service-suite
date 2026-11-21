# Copyright (c) 2026 POPOPX (popopx.chat)
# SPDX-License-Identifier: AGPL-3.0-only
"""AI chatbot (智能客服) for a POPOPX 服务号: an OpenAI-compatible model, metered
per exchange by ``POPX-CP``, and shaped entirely by what the shipped iOS client
is able to receive.

Why the client decides the design
---------------------------------
A message this plugin sends that breaks one of the client's limits is not an
error. `PopopxEcoMarker.parse(controlText:)`
(`PopopxEcoModels.swift:96-105`) trims, requires the marker prefix and then
refuses anything whose remainder contains a newline; `decode(json:)`
(`PopopxEcoModels.swift:142-148`) drops the frame when it is over
`maximumFrameCharacters` (8192, `PopopxEcoModels.swift:51`) or fails the
second-pass `isSane`; an action whose `action` string is not one of the six
known kinds throws inside `decodeIfPresent` (`PopopxEcoModels.swift:602-616`)
and takes the whole frame with it. The phone shows nothing and says nothing.
So every size in this file is a client measurement, and the reply path is
guarded *before* sending rather than trusting the transport:
`agent_bridge.AgentBridge.send_message` documents that it "performs NO framing
validation" (`app/agent_bridge.py:1121-1127`), which means the truncation here
is the only thing between a long model output and a silently dropped answer.

The inbound → model → reply lifecycle
-------------------------------------
1. `handle_inbound` is called for `callback.kind == "text"` only. It re-checks
   the body itself (`claims_inbound`): a control marker that
   `parse_inbound_text` classified as text — a malformed `::popopx_sys::` line,
   or a `::POPOPX_ECO::` frame typed by a user — is protocol, not conversation,
   and must never reach a model or come back out of one.
2. The per-contact sliding window is evaluated *and* the user turn is inserted
   inside one `BEGIN IMMEDIATE` transaction, counted from `ai_messages` rows
   with `role='user'`. Nothing about the budget lives in process memory, so a
   restart does not hand a flooded contact a fresh allowance and N workers do
   not each get their own.
3. The turn is charged (`deps.charge`, meter `ai_message` from the mount table)
   before the model is called, because the billing rule is 每次对话自动
   扣减 POPX-CP and the credits fuse has to be enforced by the ledger, not by a
   counter this process can forget.
4. History is the last N `ai_messages` rows for that contact inside the window,
   oldest-first, with the current turn excluded; then `POST
   {ai_base_url}/chat/completions` with bearer auth.
5. The reply is sanitised (control markers neutralised), shape-guarded,
   whitespace-rejected, truncated to 8192 characters, sent as ORDINARY chat text
   through `deps.eco.send_frame`, and only then persisted as the assistant row.

Charge first, refund on failure
-------------------------------
Every path in which the follower did not get an answer gives the credits back
with a reason naming the failure class (`model_failure:transport`,
`model_failure:empty`, `send_refused`, …). The pairing is mandatory and is
commented at the call site: a billed model call that produced nothing is theft.
`billing_ledger.ref` is the `ai_messages.id` of the user turn, so the two sides
join, and the refund carries its OWN idempotency key namespace
(`ai_refund:…`) — `BillingService._refund_txn` replays on `idempotency_key`
(`app/billing_service.py:647-649`), so reusing the charge's key would make the
refund a silent no-op.

Metered and exhausted paths
---------------------------
`insufficient_credits` never reaches the model. The follower gets at most ONE
额度不足 notice per contact per rate window, worded by the merchant
(`exhausted_message`), defaulting to copy that mentions 额度不足 and how to top
up without ever stating a balance. The slot is claimed atomically inside a
transaction, so two workers facing the same burst send one notice, not two. An
*operator* suspension (`suspended_reason` prefixed `operator:`) is deliberately
excluded from that notice: telling a follower to top up when a human halted the
account is a lie about who owes what, so the plugin goes quiet instead.

Chat-state recovery model
-------------------------
There is no in-process conversation object to lose. Durable state is exactly
three things: the transcript rows in `ai_messages` (per contact), the rate
budget, which is recomputed from those rows, and the notice-dedupe map in
`settings` under `ai_agent.exhausted_notices`, pruned on write to the window.
A crash therefore costs at most the one in-flight turn, and it costs it
visibly: a `consume` row on the `ai_message` meter whose `ref` points at a user
row with no later `assistant` row for the same contact is precisely "charged,
answered, died before persisting" (harmless — the follower has the answer on
their phone) or "charged, not answered, refund lost" (an operator action, and
the only kind of money error this plugin can leave behind). Recovery is a
join, not a guess. `DELETE /history?contact_id=` closes the loop for the
follower's side: the transcript and their notice slot go together, in one
click, which is also the model's amnesia.

What is deliberately not here
----------------------------
No cards, no menus, no `pay_credits`. A card body is capped at 2000 characters
(`PopopxEcoModels.swift:54`) and a whole frame at 8192 (:51) — a real answer
would be chopped or dropped — and `deliver_card` charges the separate `card`
meter for something the `ai_message` meter already paid for. Ordinary text has
neither ceiling problem and no signature question: the client has no `sig`/`ts`
field on a card at all (`PopopxEcoModels.swift:510-521` ignores unknown keys,
and issuer trust is `PopopxEcoSessionStore.hasSession`, per the note at
`app/crypto_service.py:22-27`), so `seal_card()` could only ever be a
server-side audit artifact. This plugin has nothing to audit-sign, so it does
not pretend to.

Import discipline
-----------------
Module level is stdlib plus `app.*` only: `fastapi`, `fastapi.responses`,
`httpx` and pydantic are imported inside `create_router()` and the async
functions, so this file imports and its pure half self-tests under
`/usr/bin/python3` (3.9), where none of those wheels exist. Route endpoints
carry NO return annotation and their parameters are annotated only with
builtins and `typing` names present in this module's globals — under
`from __future__ import annotations` FastAPI resolves those strings against the
module namespace, so a locally-defined pydantic model or a `Request`/`Response`
annotation imported inside `create_router` would be an unresolvable forward
reference at mount time.
"""

from __future__ import annotations

import collections.abc
import json
import logging
import re
import time
import urllib.parse
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Dict, List, Mapping, Optional, Sequence, Tuple

from app.billing_service import REASON_OPERATOR, BillingError
from app.crypto_service import ECO_MARKER, EcoError, EcoLimits, EcoValidationError, now_ms
from app.plugins import (
    REASON_DISABLED,
    REASON_FUSED,
    REASON_NODE_DOWN,
    REASON_NO_ISSUER,
    REASON_SUSPENDED,
    PluginDeps,
    PluginUnavailable,
)

if TYPE_CHECKING:  # type names only; never imported at runtime
    from fastapi import APIRouter

    from app.agent_bridge import InboundMessage

log = logging.getLogger("popopx.plugin.ai_agent")

__all__ = ["PLUGIN_ID", "create_router", "handle_inbound", "self_test"]

# ─────────────────────────────────────────────────────────────────────────────
# 1. Identity and knobs
# ─────────────────────────────────────────────────────────────────────────────

#: Cross-checked against the mount table in `self_test`; runtime code reads
#: `deps.spec`, so a rename there cannot leave this string behind and price the
#: wrong meter.
PLUGIN_ID = "ai_agent"
METER = "ai_message"
URL_PREFIX = "/api/v1/plugins/ai"

#: The settings-row namespace this plugin owns. `settings` is a JSON key/value
#: table (`app/database.py:472-476`) precisely so a plugin can hold configuration
#: without a migration — see the docstring section "schema gaps" for why this is
#: not an `ai_config` table.
SETTING_CONFIG = "ai_agent.config"
SETTING_NOTICES = "ai_agent.exhausted_notices"

#: The tightest text limit the client owns (`card_body_chars`,
#: `PopopxEcoModels.swift:54`). A system prompt or an exhausted notice is not
#: itself a card body, but both are text the merchant edits in a console and the
#: plugin may later be asked to render into one, so the console refuses anything
#: that could not survive the wire. The reply path uses 8192 (:51) because a
#: reply is a whole message.
CONFIG_CHAR_LIMITS: Dict[str, int] = {
    "system_prompt": EcoLimits.card_body_chars,
    "exhausted_message": EcoLimits.card_body_chars,
    "model": EcoLimits.card_title_chars,
}

#: Editable-through-`/configure` keys, and nothing else. `ai_api_key` is not in
#: this list on purpose: a prompt-editing endpoint that can also write a
#: credential turns a console compromise into an exfiltration of it.
CONFIG_KEYS: Tuple[str, ...] = (
    "system_prompt",
    "model",
    "exhausted_message",
    "history_size",
    "temperature",
    "max_tokens",
)

HISTORY_DEFAULT = 10
#: Chosen, not arbitrary: 10 turns is ~20 rows and keeps a request under a few
#: thousand tokens at 5 CP/message, while 0 is the operator's "no memory at all"
#: privacy switch, which the plugin honours exactly.
HISTORY_HARD_CAP = 50
#: The SQL fetch ceiling, and therefore the ceiling of `GET /transcript` too:
#: 8x HISTORY_HARD_CAP so that a contact who wrote 300 messages in the window
#: still gets their newest 50 remembered after the window filter runs. An export
#: beyond this is a support action on a database, not an endpoint.
HISTORY_FETCH_CAP = 400

TEMPERATURE_DEFAULT = 0.7
TEMPERATURE_MIN = 0.0
TEMPERATURE_MAX = 2.0
#: `config.py:456` caps `ai_max_tokens` at 8192; the same ceiling here keeps the
#: console and the environment from disagreeing about one request.
MAX_TOKENS_CEILING = EcoLimits.frame_chars
MAX_TOKENS_DEFAULT = 512

#: Reply budget, in CHARACTERS, because that is the unit the client counts
#: (`PopopxEcoModels.swift:51`, compared against Swift `String.count`).
REPLY_LIMIT_CHARS = EcoLimits.frame_chars
TRUNCATION_MARKER = "…[内容已截断]"
#: A pasted document is not a question. Truncating rather than rejecting keeps a
#: single follower from turning the bot into an error page.
MAX_USER_TEXT_CHARS = 4000
#: Per history row, so 50 remembered rows cannot become an unbounded request.
HISTORY_ROW_MAX_CHARS = 1200

#: A byte-identical repeat of the immediately-preceding user turn inside this
#: window is treated as the node redelivering one message: no charge, no second
#: answer. 10s is deliberately shorter than any window a person re-types in, and
#: longer than a WebSocket reconnect burst.
REDELIVERY_WINDOW_MS = 10_000

DEFAULT_MODEL = "gpt-4o-mini"
DEFAULT_SYSTEM_PROMPT = (
    "你是 POPOPX 服务号的智能客服。回答简洁、礼貌，不索要任何个人身份信息。"
)
#: Mentions 额度不足 and the remedy, states no number, and is 60 characters of
#: Chinese well inside every wire budget.
DEFAULT_EXHAUSTED_MESSAGE = (
    "服务号当前额度不足，AI 客服暂时无法回复。请稍后再试，或提醒商户在控制台兑换 POPX-CP 激活码补充额度。"
)
#: Neutral copy for a failure that is the plugin's fault rather than the
#: account's. Sent only on the `/chat`-style console path? No — it is never sent
#: to a follower automatically; it is the `detail` an operator sees.
OPERATOR_FAILURE_HINT = "the model call failed; credits for it were returned to the balance"

#: Everything the client parses as a machine line rather than as prose. A reply
#: that merely *starts* with one of these becomes a control frame on the phone
#: (`PopopxEcoModels.swift:96-105`), so a model that parrots one back would let a
#: prompt-injection reach `menu_config` or `channel_key_update` handling. These
#: strings are stripped out of every reply and out of every remembered turn.
CONTROL_MARKERS: Tuple[str, ...] = (
    ECO_MARKER,
    "::CB::",
    "::REF::",
    "::SSO_SCAN::",
    "::popopx_sys::",
)

USER_AGENT = "popopx-gateway-ai/1.0 (+https://popopx.chat)"

# Outcome statuses. `consumes_inbound` and `status_to_http` translate them for
# the two entry points, so the pipeline itself has one vocabulary.
STATUS_ANSWERED = "answered"
STATUS_RATE_LIMITED = "rate_limited"
STATUS_DUPLICATE = "duplicate"
STATUS_NOTIFIED = "notified"
STATUS_UNKNOWN_CONTACT = "unknown_contact"
STATUS_UNCONFIGURED = "unconfigured"
STATUS_PLUGIN_DISABLED = "plugin_disabled"
STATUS_NODE_DOWN = "node_down"
STATUS_BILLING_HELD = "billing_held"
STATUS_SEND_REFUSED = "send_refused"

#: Gate reason -> outcome status, for the "not usable" branch of the gate.
GATE_REASON_TO_STATUS: Dict[str, str] = {
    REASON_DISABLED: STATUS_PLUGIN_DISABLED,
    REASON_NODE_DOWN: STATUS_NODE_DOWN,
    REASON_SUSPENDED: STATUS_BILLING_HELD,
    REASON_NO_ISSUER: STATUS_BILLING_HELD,
}


class ModelCallFailure(RuntimeError):
    """Any failure of the outbound model call. `.failure_class` is what the
    refund reason and the 502 body name — never the URL, never the key."""

    failure_class = "unknown"

    def __init__(self, detail: str = "") -> None:
        super().__init__(detail or self.failure_class)
        self.detail = detail


class ModelTransportFailure(ModelCallFailure):
    """Connection, timeout, TLS — the request did not complete."""

    failure_class = "transport"


class ModelStatusFailure(ModelCallFailure):
    """The endpoint answered with a non-2xx status.

    Carries only the status code and a one-word hint. The upstream body is not
    kept: providers echo the request in it, and a request contains the merchant's
    followers' words.
    """

    failure_class = "http_status"

    def __init__(self, status: int) -> None:
        super().__init__("upstream status %d" % status)
        self.status = int(status)


class ModelShapeFailure(ModelCallFailure):
    """2xx, but not the documented envelope: no `choices`, no string content."""

    failure_class = "bad_shape"


class ModelEmptyFailure(ModelCallFailure):
    """A structurally fine answer with nothing sayable in it (whitespace, or a
    reply made only of a control marker that sanitising removed)."""

    failure_class = "empty"


@dataclass(frozen=True)
class RateClaim:
    """The result of the atomic "may this turn be recorded" decision.

    A dataclass rather than a tuple because the three outcomes each need one
    different extra: the row id, the wait, nothing.
    """

    status: str                 # "claimed" | "rate_limited" | "duplicate"
    row_id: int = 0
    retry_after_ms: int = 0


# ─────────────────────────────────────────────────────────────────────────────
# 2. Pure helpers: the wire, the window, the config
#
# Everything in this section is testable with no FastAPI, no httpx and no
# database, which is what makes `self_test` at the bottom worth running.
# ─────────────────────────────────────────────────────────────────────────────


def normalize_chat_endpoint(base_url: Any) -> str:
    """`ai_base_url` -> the absolute chat-completions URL. Pure.

    The three shapes a merchant actually pastes are a bare host
    (`api.openai.com`), a versioned root (`https://api.openai.com/v1`, the
    OpenAI SDK convention and config.py's own default) and the full endpoint.
    A missing `/v1` is the commonest silent breakage: the request goes to
    `/{model}/chat/completions`, the provider answers 404, and the follower sees
    nothing at all. Schemeless input gets `https://` rather than being refused,
    because the env var is read from a `.env` file a human types into.
    """
    text = "" if base_url is None else str(base_url).strip()
    if not text:
        return ""
    if "://" not in text:
        text = "https://" + text
    text = text.rstrip("/")
    if text.endswith("/chat/completions"):
        return text
    tail = text.rsplit("/", 1)[-1]
    if "/" in text and _VERSION_SEGMENT_RE.match(tail):
        return text + "/chat/completions"
    return text + "/v1/chat/completions"


_VERSION_SEGMENT_RE = re.compile(r"^v[0-9]+(?:[._-][0-9]+)*$")


def endpoint_host(url: Any) -> str:
    """Host (and port) of an endpoint, credentials removed. For `/status`.

    A merchant may legitimately put `user:token@host` in a base URL. That
    credential must never be echoed by an endpoint the console can call, so the
    only thing taken from the URL is `hostname` plus `port`.
    """
    text = "" if url is None else str(url).strip()
    if not text:
        return ""
    parsed = urllib.parse.urlsplit(text if "://" in text else "https://" + text)
    host = parsed.hostname or ""
    if not host:
        return ""
    if parsed.port:
        return "%s:%d" % (host, parsed.port)
    return host


def hostname_is_insecure(host: str) -> bool:
    """True for a host that should not carry a bearer token over plain http.

    Reported by `/status` only; the plugin still sends (a local llama.cpp on
    `http://127.0.0.1:11434/v1` is the normal development setup), because
    refusing would break the one configuration an operator uses to test.
    """
    return bool(host) and host not in ("127.0.0.1", "localhost", "::1")


def api_key_facts(api_key: Any) -> Tuple[bool, int]:
    """`(present, character_count)` — the whole of what `/status` may say.

    Length rather than a masked prefix: `sk-…abcd` is 4 characters of a 51
    character secret, which is enough to correlate a leaked log with a key and
    buys an operator nothing they cannot get from their own provider console.
    """
    text = "" if api_key is None else str(api_key).strip()
    return (bool(text), len(text))


def model_is_ready(cfg: Mapping[str, Any]) -> bool:
    """Whether the plugin may talk to a model *and* to a follower.

    `ai_api_key` empty means the plugin is functionally off: every hosted
    provider answers 401, and a 401 costs the follower a rate-limit slot and the
    merchant a charge attempt for an answer that cannot arrive. `accepting` is
    the flag `/status` reports and `handle_inbound` obeys.
    """
    return bool(cfg.get("api_key_present")) and bool(cfg.get("endpoint"))


def claims_inbound(kind: Any, text: Any, is_control: bool = False) -> bool:
    """Whether this inbound body belongs to the AI plugin. Pure.

    Three refusals, each for a different reason:
      * a kind other than `text` is another plugin's protocol step;
      * an empty or whitespace body is not a question, and answering it would put
        a bot turn in the transcript that the follower never asked for;
      * a body that opens with a control marker is machine traffic that
        `parse_inbound_text` classified as text (a malformed `::popopx_sys::`
        with no delimiter, `app/agent_bridge.py:225-227`) or a forged eco frame.
        Feeding either to a model risks a regurgitation, and the plugin's own
        reply is sent as a plain message, so a marker at the front of it would be
        executed by the phone (`PopopxEcoModels.swift:96-105`).
    """
    if is_control:
        return False
    if not isinstance(kind, str) or kind.strip().lower() != "text":
        return False
    if not isinstance(text, str):
        return False
    body = text.strip()
    if not body:
        return False
    for marker in CONTROL_MARKERS:
        if marker in body:
            return False
    return True


def consumes_inbound(status: str) -> bool:
    """Whether a finished pipeline outcome means the caller must not fall through.

    True for every outcome where the plugin either answered, decided silence on
    the follower's behalf (rate limit, redelivery), or spoke about money (the
    exhausted notice). False where the plugin simply could not act (switched off,
    node down, no credential, unknown contact) so that whatever else the gateway
    would have done still gets its chance. A bot answering out of turn is worse
    than silence, which is why the rate-limited branch stays silent *and* claims
    the message: the reply that arrives two messages late is the confusing one.
    """
    return status in (
        STATUS_ANSWERED,
        STATUS_RATE_LIMITED,
        STATUS_DUPLICATE,
        STATUS_NOTIFIED,
    )


def status_to_http(status: str) -> int:
    """The console-side status for one pipeline outcome (`POST /chat`)."""
    return {
        STATUS_ANSWERED: 200,
        STATUS_DUPLICATE: 409,
        STATUS_RATE_LIMITED: 429,
        STATUS_UNKNOWN_CONTACT: 404,
        STATUS_PLUGIN_DISABLED: 404,
        STATUS_NODE_DOWN: 503,
        STATUS_UNCONFIGURED: 503,
        STATUS_NOTIFIED: 402,
        STATUS_BILLING_HELD: 402,
        STATUS_SEND_REFUSED: 502,
    }.get(status, 500)


def window_start_ms(now_value: int, window_seconds: int) -> int:
    """Inclusive lower bound of the sliding window, in epoch ms."""
    seconds = max(1, int(window_seconds))
    return int(now_value) - seconds * 1000


def inside_window(ts_ms: Any, now_value: int, window_seconds: int) -> bool:
    """`>=` on purpose: a row stamped exactly at the boundary is inside.

    The complement (`<`) is what a `BETWEEN`-style reflex gets wrong, and the
    error is a message that silently stops counting rather than one that counts
    twice.
    """
    try:
        stamp = int(ts_ms)
    except (TypeError, ValueError):
        return False
    return stamp >= window_start_ms(now_value, window_seconds)


def rate_limited(count_in_window: int, limit: int) -> bool:
    """`count >= limit`, so a limit of N allows exactly N and refuses N+1.

    A non-positive limit means "no limit", which is the only reading that makes
    `POPOPX_AI_RATE_LIMIT_MESSAGES=0` a footgun-free escape hatch; `config.py:463`
    already clamps the env value to a minimum of 1, so this branch exists for a
    hand-edited settings value.
    """
    if limit <= 0:
        return False
    return int(count_in_window) >= int(limit)


def retry_after_ms(oldest_ts_ms: Any, now_value: int, window_seconds: int) -> int:
    """How long until the oldest counted message leaves the window.

    Named in the 429's `Retry-After` so a caller waits the real amount instead of
    a guessed one. Clamped below by 0 (clock skew) and above by the window.
    """
    try:
        oldest = int(oldest_ts_ms)
    except (TypeError, ValueError):
        return max(0, int(window_seconds)) * 1000
    wait = oldest + max(1, int(window_seconds)) * 1000 - int(now_value)
    return max(0, min(wait, max(1, int(window_seconds)) * 1000))


def looks_like_redelivery(previous_content: Any, previous_age_ms: Any, content: str, limit_ms: int) -> bool:
    """Byte-identical repeat of the last user turn, close in time.

    Guards a billing bug rather than a formatting one: the node re-delivers an
    un-acked message after a reconnect, and each delivery would otherwise be a
    fresh `ai_message` charge for the same question. Negative age means the
    clock moved backwards and is refused, because "the future just repeated me"
    is not evidence of anything.
    """
    if not isinstance(previous_content, str) or previous_content != content:
        return False
    try:
        age = int(previous_age_ms)
    except (TypeError, ValueError):
        return False
    return 0 <= age <= int(limit_ms)


def strip_control_markers(text: str) -> str:
    """Neutralise every machine-line marker in a piece of text, keeping it readable.

    Replaces rather than deletes: `::CB::vote_yes` becoming `[CB]vote_yes` still
    tells a human what was in there, while no longer being anything the client
    would parse. The set is exactly `CONTROL_MARKERS`, matched case-sensitively,
    because the client's prefix comparisons are case-sensitive
    (`PopopxEcoModels.swift:99`).
    """
    out = text if isinstance(text, str) else str(text or "")
    for marker in CONTROL_MARKERS:
        if marker in out:
            out = out.replace(marker, "[%s]" % marker.strip(":"))
    return out


def truncate_to_limit(text: str, limit: int = REPLY_LIMIT_CHARS) -> str:
    """Cut to at most `limit` CHARACTERS, appending a visible marker when cut.

    The marker is inside the budget, never after it: `text[:limit] + marker` is
    the reflex that produces an 8203-character message from an 8192-character
    rule and drops the frame. Trailing whitespace is pulled off first so the
    marker does not land on a line break the client would then have to see.
    """
    body = text if isinstance(text, str) else str(text or "")
    cap = max(0, int(limit))
    if len(body) <= cap:
        return body
    if cap <= len(TRUNCATION_MARKER):
        return body[:cap]
    head = body[: cap - len(TRUNCATION_MARKER)].rstrip(" \t\r\n")
    return head + TRUNCATION_MARKER


def is_marker_only(text: str) -> bool:
    """Whether a reply is nothing but machine markers and whitespace.

    The case that makes this worth a function: a model that hallucinates or
    repeats a prompt-injection answers `::POPOPX_ECO::` and nothing else. After
    neutralising, that is the string "[POPOPX_ECO]" — printable, so a plain
    emptiness check passes it — and the follower pays 5 CP to receive a bracketed
    word. Refusing it is a `ModelEmptyFailure`, which refunds the turn.
    """
    body = text if isinstance(text, str) else str(text or "")
    for marker in CONTROL_MARKERS:
        body = body.replace(marker, "")
    return not body.strip()


def reply_is_usable(text: Any, limit: int = REPLY_LIMIT_CHARS) -> bool:
    """Whether a reply may be put in front of a person.

    Whitespace-only is a failure, not an empty bubble: the follower paid for the
    turn and a blank message is the worst possible receipt of that. So is a
    reply that is only a control marker (see `is_marker_only`).
    """
    if not isinstance(text, str) or not text.strip():
        return False
    if is_marker_only(text):
        return False
    return truncate_to_limit(strip_control_markers(text), limit).strip() != ""


def extract_completion_text(data: Any) -> Optional[str]:
    """`choices[0].message.content` from an OpenAI-compatible envelope, or None.

    Nothing here raises: a provider that answers `{"choices":[{"text":"…"}]}`
    (a completions-style gateway) or with content-part lists still yields a
    string, and any other shape yields None, which the caller turns into a refund.
    The alternative — trusting `data["choices"][0]["message"]["content"]` — is a
    TypeError in the middle of a charged turn.
    """
    if not isinstance(data, collections.abc.Mapping):
        return None
    choices = data.get("choices")
    if not isinstance(choices, (list, tuple)) or not choices:
        return None
    first = choices[0]
    if isinstance(first, str):
        return first
    if not isinstance(first, collections.abc.Mapping):
        return None
    message = first.get("message")
    content: Any = None
    if isinstance(message, collections.abc.Mapping):
        content = message.get("content")
    if content is None:
        content = first.get("text")
    if isinstance(content, (list, tuple)):
        parts = [
            block.get("text")
            for block in content
            if isinstance(block, collections.abc.Mapping) and isinstance(block.get("text"), str)
        ]
        content = "".join(parts) if parts else None
    if not isinstance(content, str):
        return None
    return content


def extract_usage(data: Any) -> Tuple[Optional[int], Optional[int]]:
    """`(prompt_tokens, completion_tokens)`, each None when the provider omitted it.

    `ai_messages` has no column for either (see `self_test`), so these values
    travel in the HTTP response of `/chat` and in the log line, and are not
    persisted. Booleans are refused: `True` is an `int` in Python and a token
    count of 1 that nobody typed is worse than an honest None.
    """
    if not isinstance(data, collections.abc.Mapping):
        return (None, None)
    usage = data.get("usage")
    if not isinstance(usage, collections.abc.Mapping):
        return (None, None)
    out: List[Optional[int]] = []
    for key in ("prompt_tokens", "completion_tokens"):
        value = usage.get(key)
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            out.append(None)
        else:
            out.append(int(value))
    return (out[0], out[1])


def failure_class_of(exc: BaseException) -> str:
    """The stable name of a failure class, for refund reasons and 502 bodies."""
    return str(getattr(exc, "failure_class", None) or type(exc).__name__)


def bounded_int(value: Any, rule: str, low: int, high: int) -> int:
    """An int inside `low..high`, else `EcoValidationError` naming the rule.

    Mirrors `crypto_service._bounded_int`'s refusal of `bool`: `temperature=True`
    arriving from a console form should be a 400, not a request with a token
    budget of 1.
    """
    if isinstance(value, bool) or not isinstance(value, int):
        raise EcoValidationError(rule, "expected an integer, got %r" % (value,))
    if not low <= value <= high:
        raise EcoValidationError(rule, "%d is outside %d..%d" % (value, low, high))
    return int(value)


def bounded_float(value: Any, rule: str, low: float, high: float) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise EcoValidationError(rule, "expected a number, got %r" % (value,))
    number = float(value)
    if number != number or number in (float("inf"), float("-inf")):
        raise EcoValidationError(rule, "%r is not a finite number" % (value,))
    if not low <= number <= high:
        raise EcoValidationError(rule, "%s is outside %s..%s" % (number, low, high))
    return number


def validated_config(raw: Any) -> Dict[str, Any]:
    """The settings-row override layer, typed and clamped. Raises EcoValidationError.

    Unknown keys are refused rather than ignored. A console that typo'd
    `sytem_prompt` and saw a green tick would ship a prompt change that never
    happened, and the only way to discover that is to read the model's mind.
    """
    if raw is None:
        return {}
    if not isinstance(raw, collections.abc.Mapping):
        raise EcoValidationError("config_shape", "stored AI configuration must be an object")
    data = dict(raw)
    unknown = sorted(str(key) for key in data if key not in CONFIG_KEYS)
    if unknown:
        raise EcoValidationError(
            "config_unknown_key",
            "not editable here: %s (editable: %s)" % (", ".join(unknown), ", ".join(sorted(CONFIG_KEYS))),
        )
    out: Dict[str, Any] = {}
    for key in ("system_prompt", "exhausted_message", "model"):
        if key not in data:
            continue
        value = data[key]
        if value is None or (isinstance(value, str) and not value.strip()):
            continue  # an empty value clears the override, so env/default wins
        if not isinstance(value, str):
            raise EcoValidationError("config_%s" % key, "must be a string, got %s" % type(value).__name__)
        text = value.strip()
        limit = CONFIG_CHAR_LIMITS[key]
        if len(text) > limit:
            raise EcoValidationError(
                "config_%s" % key,
                "%d characters exceeds the client limit of %d; shorten it in the console" % (len(text), limit),
            )
        out[key] = text
    if "history_size" in data:
        out["history_size"] = bounded_int(data["history_size"], "config_history_size", 0, HISTORY_HARD_CAP)
    if "temperature" in data:
        out["temperature"] = bounded_float(data["temperature"], "config_temperature", TEMPERATURE_MIN, TEMPERATURE_MAX)
    if "max_tokens" in data:
        out["max_tokens"] = bounded_int(data["max_tokens"], "config_max_tokens", 1, MAX_TOKENS_CEILING)
    return out


def merge_config(current: Any, updates: Any) -> Dict[str, Any]:
    """The new override layer after applying `updates` to `current`.

    A key whose value is None or blank is *removed* from the layer rather than
    stored blank, which is what makes "clear this prompt" round-trip to the env
    default instead of pinning an empty string forever.
    """
    merged = dict(validated_config(current))
    if updates is None:
        return merged
    if not isinstance(updates, collections.abc.Mapping):
        raise EcoValidationError("config_shape", "a configuration patch must be an object")
    for key in CONFIG_KEYS:
        if key not in updates:
            continue
        value = updates[key]
        if value is None or (isinstance(value, str) and not value.strip()):
            merged.pop(key, None)
        else:
            merged[key] = value
    # Re-validate the whole layer, not just the patch: a merged dict is what gets
    # stored, and `history_size` clamped against a stale value would be a lie.
    return validated_config(merged)


def resolve_system_prompt(raw: Any, config_prompt: Any) -> str:
    """Console override > environment default > built-in default.

    Also the last function in that chain to be called with an *already
    validated* override dict, which `validated_config` is idempotent on — so
    `effective_config` gets this precedence from one place instead of restating
    it and letting the two drift.
    """
    override = validated_config(raw).get("system_prompt")
    if override:
        return override
    text = "" if config_prompt is None else str(config_prompt).strip()
    return text or DEFAULT_SYSTEM_PROMPT


def effective_config(raw: Any, config: Any) -> Dict[str, Any]:
    """One flat, serialisable view of "what the plugin will do next turn".

    `config` is duck-typed with `getattr(..., default)` everywhere: this module
    must not crash because a deployment's `Config` predates a field, and a
    default here is a documented opinion rather than a silent one.

    The api key is deliberately absent — only `api_key_present` and
    `api_key_chars` are computed from it, so this dict can be handed to a JSON
    response without a second thought.
    """
    overrides = validated_config(raw)
    base_url = str(getattr(config, "ai_base_url", "") or "").strip()
    key_present, key_chars = api_key_facts(getattr(config, "ai_api_key", ""))
    history_size = overrides.get("history_size")
    if history_size is None:
        history_size = HISTORY_DEFAULT
    return {
        "system_prompt": resolve_system_prompt(overrides, getattr(config, "ai_system_prompt", "")),
        "model": overrides.get("model") or str(getattr(config, "ai_model", "") or "").strip() or DEFAULT_MODEL,
        "exhausted_message": overrides.get("exhausted_message") or DEFAULT_EXHAUSTED_MESSAGE,
        "history_size": min(int(history_size), HISTORY_HARD_CAP),
        "temperature": float(overrides.get("temperature", TEMPERATURE_DEFAULT)),
        "max_tokens": int(overrides.get("max_tokens") or int(getattr(config, "ai_max_tokens", MAX_TOKENS_DEFAULT) or MAX_TOKENS_DEFAULT)),
        "rate_limit_messages": max(0, int(getattr(config, "ai_rate_limit_messages", 20) or 0)),
        "rate_limit_window_seconds": max(1, int(getattr(config, "ai_rate_limit_window_seconds", 300) or 300)),
        "timeout_seconds": float(getattr(config, "ai_timeout_seconds", 30.0) or 30.0),
        "base_url": base_url,
        "endpoint": normalize_chat_endpoint(base_url),
        "endpoint_host": endpoint_host(normalize_chat_endpoint(base_url)),
        "api_key_present": key_present,
        "api_key_chars": key_chars,
    }


def notice_slot_due(stored: Mapping[str, Any], contact_id: int, now_value: int, window_ms: int) -> bool:
    """Whether this contact may be told about money again.

    `>= window_ms` is the boundary that matters: a notice exactly one window old
    is due, because the dedupe promise is "one per window", not "one per window
    plus a hair". A slot in the future (clock stepped backwards) is NOT due —
    waiting it out is cheaper than a duplicate notice the follower cannot dismiss.
    """
    key = str(int(contact_id))
    if not isinstance(stored, collections.abc.Mapping) or key not in stored:
        return True
    try:
        last = int(stored[key])
    except (TypeError, ValueError):
        return True
    return (int(now_value) - last) >= int(window_ms)


def notice_slot_write(stored: Mapping[str, Any], contact_id: int, now_value: int, window_ms: int) -> Dict[str, str]:
    """Claim this contact's slot and prune every slot that has already expired.

    Pruning on write is what keeps one row from growing by one entry per
    follower per window forever; an unbounded settings blob is a slow-motion
    outage in the middle of a backup.
    """
    out: Dict[str, str] = {}
    horizon = int(now_value) - int(window_ms)
    if isinstance(stored, collections.abc.Mapping):
        for key, value in stored.items():
            try:
                stamp = int(value)
            except (TypeError, ValueError):
                continue
            if stamp >= horizon and str(key) != str(int(contact_id)):
                out[str(key)] = str(stamp)
    out[str(int(contact_id))] = str(int(now_value))
    return out


def select_history(
    rows: Sequence[Mapping[str, Any]],
    *,
    now_value: int,
    window_seconds: int,
    limit: int,
    before_id: Optional[int] = None,
    exclude_content: Optional[str] = None,
) -> List[Dict[str, str]]:
    """The remembered turns, oldest-first, as `{role, content}` messages.

    Excluded, in order: any row that is not a turn of the conversation (a
    `system` row is this plugin's own scaffolding, never something the model
    said), a blank row, a row outside the window, the current user row (already
    appended separately — including it would ask the model the same question
    twice), and any row equal to `exclude_content`, which is how an exhausted
    notice stays out of the model's mouth: replaying "额度不足" as an assistant
    turn teaches the bot to refuse people. `rows` arrive newest-first from SQL;
    `before_id` and the cap are applied in that order so the cap keeps the
    NEWEST N and the reversal at the end makes them readable.
    """
    if limit <= 0:
        return []
    kept: List[Dict[str, str]] = []
    for row in rows:
        role = row.get("role")
        if role not in ("user", "assistant"):
            continue
        try:
            row_id = int(row.get("id") or 0)
        except (TypeError, ValueError):
            row_id = 0
        if before_id is not None and row_id >= int(before_id):
            continue
        if not inside_window(row.get("ts_ms"), now_value, window_seconds):
            continue
        content = row.get("content")
        if not isinstance(content, str) or not content.strip():
            continue
        if exclude_content is not None and content == exclude_content:
            continue
        kept.append({"role": str(role), "content": content})
    kept.reverse()          # SQL gave newest-first; a conversation is oldest-first
    return kept[-int(limit):]


def build_model_messages(
    system_prompt: str,
    history: Sequence[Mapping[str, Any]],
    user_text: str,
    *,
    row_char_cap: int = HISTORY_ROW_MAX_CHARS,
    user_char_cap: int = MAX_USER_TEXT_CHARS,
) -> List[Dict[str, str]]:
    """`[system] + history + [user]`, each row clamped and marker-stripped.

    Clamping per row rather than rejecting the turn: one follower who pastes a
    200KB log once should degrade their own context, not stop the bot for the
    window.
    """
    messages: List[Dict[str, str]] = []
    prompt = strip_control_markers(str(system_prompt or "")).strip()
    if prompt:
        messages.append({"role": "system", "content": prompt})
    for row in history:
        role = row.get("role")
        content = row.get("content")
        if role not in ("user", "assistant") or not isinstance(content, str):
            continue
        text = strip_control_markers(content).strip()
        if not text or is_marker_only(content):
            continue
        messages.append({"role": str(role), "content": truncate_to_limit(text, row_char_cap)})
    body = strip_control_markers(str(user_text or "")).strip()
    if body:
        messages.append({"role": "user", "content": truncate_to_limit(body, user_char_cap)})
    return messages


def build_request_payload(cfg: Mapping[str, Any], messages: Sequence[Mapping[str, str]]) -> Dict[str, Any]:
    """The JSON body. Exactly the four documented keys, no extras.

    `stream` is not sent and `n`/`temperature` are not invented: a provider that
    defaults differently from OpenAI is the merchant's integration to configure,
    and a field this plugin adds silently is a field it cannot take back.
    """
    return {
        "model": str(cfg.get("model") or DEFAULT_MODEL),
        "messages": [dict(m) for m in messages],
        "max_tokens": int(cfg.get("max_tokens") or MAX_TOKENS_DEFAULT),
        "temperature": float(cfg.get("temperature", TEMPERATURE_DEFAULT)),
    }


def render_transcript(
    *,
    contact_id: int,
    rows: Sequence[Mapping[str, Any]],
    generated_ms: int,
    service_name: str = "",
    include_credits: bool = True,
) -> str:
    """Plain-text conversation export, for support and for the follower's copy.

    Text rather than JSON because both audiences are human, and because a
    follower exercising a data-access request should not need a parser to read
    their own conversation. UTC is stated in the header: an export without a
    zone is an argument waiting to happen.
    """
    lines: List[str] = ["# POPOPX AI 对话记录 / conversation export"]
    lines.append("contact_id: %d" % int(contact_id))
    if service_name:
        lines.append("service: %s" % service_name)
    lines.append("generated_utc: %s" % time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(int(generated_ms) / 1000.0)))
    lines.append("messages: %d" % len(rows))
    if include_credits:
        spent = 0
        for row in rows:
            try:
                spent += int(row.get("credits_charged") or 0)
            except (TypeError, ValueError):
                continue
        lines.append("credits_charged_total: %d" % spent)
    lines.append("")
    lines.append("---")
    labels = {"user": "访客", "assistant": "服务号", "system": "系统"}
    for row in rows:
        stamp = row.get("ts_ms")
        try:
            when = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(int(stamp) / 1000.0))
        except (TypeError, ValueError):
            when = "unknown-time"
        who = labels.get(str(row.get("role")), str(row.get("role")))
        content = str(row.get("content") or "")
        first, _, rest = content.partition("\n")
        lines.append("[%s] %s: %s" % (when, who, first))
        # `rest.split("\n")` on an empty `rest` returns [""] -- without this guard
        # every single-line message would gain a stray indented blank line.
        if rest:
            for extra in rest.split("\n"):
                lines.append("        %s" % extra)
    return "\n".join(lines).rstrip() + "\n"


def status_payload(
    *,
    cfg: Mapping[str, Any],
    gate_body: Mapping[str, Any],
    price: int,
    balance: Optional[int],
    history_rows: Optional[int] = None,
) -> Dict[str, Any]:
    """`/status`'s body, built purely so that its omissions are testable.

    No api key, no masked api key, no prompt text, no follower message. The
    balance is here and nowhere near the follower: it is the merchant's own
    number, and `/status` is a console endpoint behind the gateway's admin token.
    """
    endpoint = str(cfg.get("endpoint") or "")
    ready = model_is_ready(cfg)
    host = str(cfg.get("endpoint_host") or "")
    body: Dict[str, Any] = {
        "ok": bool(gate_body.get("ok")) and ready,
        "plugin": str(gate_body.get("plugin") or PLUGIN_ID),
        "meter": METER,
        "reason": str(gate_body.get("reason") or ""),
        "gate": dict(gate_body),
        "enabled": bool(gate_body.get("ok")),
        "accepting": ready,
        "model": cfg.get("model"),
        "endpoint_configured": bool(endpoint),
        "endpoint_host": host,
        "endpoint_insecure_host": hostname_is_insecure(host) if endpoint else False,
        "api_key": {"present": bool(cfg.get("api_key_present")), "chars": int(cfg.get("api_key_chars") or 0)},
        "rate_limit": {
            "messages": int(cfg.get("rate_limit_messages") or 0),
            "window_seconds": int(cfg.get("rate_limit_window_seconds") or 0),
        },
        "credits_per_message": int(price),
        "history_size": int(cfg.get("history_size") or 0),
        "temperature": float(cfg.get("temperature") or 0.0),
        "max_tokens": int(cfg.get("max_tokens") or 0),
        "system_prompt_chars": len(str(cfg.get("system_prompt") or "")),
        "exhausted_message_chars": len(str(cfg.get("exhausted_message") or "")),
        "reply_limit_chars": REPLY_LIMIT_CHARS,
    }
    if balance is not None:
        body["balance"] = int(balance)
    if history_rows is not None:
        body["stored_messages_total"] = int(history_rows)
    if not ready:
        body["detail"] = "ai_api_key or ai_base_url is not configured; the bot will not answer and nothing is charged"
    return body


# ─────────────────────────────────────────────────────────────────────────────
# 3. Database reads and writes
#
# Thin on purpose: every decision these functions touch is made by a pure helper
# above, so the SQL is the only part that needs a live gateway to confirm.
# ─────────────────────────────────────────────────────────────────────────────


def _read_raw_config(db: Any) -> Dict[str, Any]:
    """The settings row, or `{}`. A corrupt row must not stop the bot.

    `Database.get_setting` already swallows a JSON error into `default`
    (`app/database.py:623-632`), so the remaining failure mode is a missing
    `settings` table on a half-migrated database, which is a reason to fall back
    to the environment rather than to 500.
    """
    try:
        raw = db.get_setting(SETTING_CONFIG, None)
    except Exception:  # noqa: BLE001 - a broken knob must not break the chat
        log.warning("ai_agent: configuration row unreadable; using environment defaults")
        return {}
    if not isinstance(raw, collections.abc.Mapping):
        return {}
    try:
        validated_config(raw)
    except EcoError as exc:
        # A value an older build stored that this build would refuse: keep
        # serving from the environment, and name the rule so the operator can fix
        # it through /configure rather than by hand-editing JSON.
        log.warning("ai_agent: stored configuration rejected (%s); using environment defaults", exc.rule)
        return {}
    return dict(raw)


def _load_config(deps: PluginDeps) -> Dict[str, Any]:
    return effective_config(_read_raw_config(deps.db), deps.config)


def _contact_row(db: Any, contact_id: int) -> Optional[Dict[str, Any]]:
    try:
        row = db.query_one(
            "SELECT contact_id, pairwise_uid, blocked, display_name, local_display_name, full_name "
            "FROM contacts WHERE contact_id = ?",
            (int(contact_id),),
        )
    except Exception:  # noqa: BLE001 - see _read_raw_config
        log.exception("ai_agent: contact lookup failed")
        return None
    return dict(row) if row is not None else None


def _claim_turn(
    db: Any,
    *,
    contact_id: int,
    pairwise_uid: str,
    content: str,
    now_value: int,
    window_seconds: int,
    limit: int,
) -> RateClaim:
    """Count, decide and record one user turn in a single IMMEDIATE transaction.

    The three steps cannot be separated: `db.scalar` then `db.execute` would let
    two workers both read "9 of 20" and both insert, and the limit would be a
    suggestion. `pairwise_uid` is NOT NULL in the schema (`app/database.py:434-442`)
    while `contacts.pairwise_uid` is nullable, so an un-handshaked follower gets
    the empty string here — harmless because every read is keyed on `contact_id`,
    never on uid, for exactly that reason.
    """
    window_start = window_start_ms(now_value, window_seconds)
    with db.transaction(immediate=True) as conn:
        last = conn.execute(
            "SELECT id, content, ts_ms FROM ai_messages WHERE contact_id = ? AND role = 'user' "
            "ORDER BY id DESC LIMIT 1",
            (int(contact_id),),
        ).fetchone()
        if last is not None and looks_like_redelivery(
            last["content"], now_value - int(last["ts_ms"]), content, REDELIVERY_WINDOW_MS
        ):
            return RateClaim(STATUS_DUPLICATE)
        used = int(
            conn.execute(
                "SELECT COUNT(*) FROM ai_messages WHERE contact_id = ? AND role = 'user' AND ts_ms >= ?",
                (int(contact_id), window_start),
            ).fetchone()[0]
        )
        if rate_limited(used, limit):
            oldest = conn.execute(
                "SELECT MIN(ts_ms) FROM ai_messages WHERE contact_id = ? AND role = 'user' AND ts_ms >= ?",
                (int(contact_id), window_start),
            ).fetchone()[0]
            return RateClaim(
                STATUS_RATE_LIMITED,
                retry_after_ms=retry_after_ms(oldest, now_value, window_seconds),
            )
        cursor = conn.execute(
            "INSERT INTO ai_messages (pairwise_uid, contact_id, role, content, credits_charged, ts_ms) "
            "VALUES (?,?,?,?,0,?)",
            (pairwise_uid or "", int(contact_id), "user", content, now_value),
        )
        return RateClaim("claimed", row_id=int(cursor.lastrowid or 0))


def _recent_rows(db: Any, contact_id: int, cap: int = HISTORY_FETCH_CAP) -> List[Dict[str, Any]]:
    """The newest `cap` rows for one contact, newest-first."""
    rows = db.query(
        "SELECT id, role, content, ts_ms, credits_charged FROM ai_messages "
        "WHERE contact_id = ? ORDER BY id DESC LIMIT ?",
        (int(contact_id), int(cap)),
    )
    return [dict(row) for row in rows]


def _record_assistant(
    db: Any,
    *,
    contact_id: int,
    pairwise_uid: str,
    content: str,
    credits_charged: int,
    now_value: int,
) -> int:
    return int(
        db.execute(
            "INSERT INTO ai_messages (pairwise_uid, contact_id, role, content, credits_charged, ts_ms) "
            "VALUES (?,?,?,?,?,?)",
            (pairwise_uid or "", int(contact_id), "assistant", content, int(credits_charged), now_value),
        )
        or 0
    )


def _count_messages(db: Any, contact_id: Optional[int] = None) -> int:
    try:
        if contact_id is None:
            return int(db.scalar("SELECT COUNT(*) FROM ai_messages", (), 0) or 0)
        return int(
            db.scalar(
                "SELECT COUNT(*) FROM ai_messages WHERE contact_id = ?", (int(contact_id),), 0
            )
            or 0
        )
    except Exception:  # noqa: BLE001 - a diagnostic count is never worth a 500
        return 0


def _delete_history(db: Any, contact_id: int) -> int:
    """Forget this follower, one click.

    The `ai_messages` rows and their notice slot go together: leaving a stale
    slot behind would let the plugin suppress a legitimate notice for a person
    whose entire history it has just agreed to delete.

    The count comes from `cursor.rowcount` inside our own transaction rather than
    from `Database.execute`, because that helper returns `lastrowid` whenever it
    is non-zero and CPython populates `lastrowid` for every DML statement — a
    DELETE can therefore report the row id of somebody else's earlier INSERT as
    the number of rows erased.
    """
    with db.transaction(immediate=True) as conn:
        deleted = int(conn.execute(
            "DELETE FROM ai_messages WHERE contact_id = ?", (int(contact_id),)
        ).rowcount or 0)
    _notice_slot_reset(db, contact_id)
    return deleted


def _claim_notice_slot(db: Any, contact_id: int, now_value: int, window_ms: int) -> bool:
    """Atomically take this contact's exhausted-notice slot for this window."""
    with db.transaction(immediate=True) as conn:
        row = conn.execute("SELECT value_json FROM settings WHERE key = ?", (SETTING_NOTICES,)).fetchone()
        stored: Dict[str, Any] = {}
        if row is not None:
            try:
                parsed = json.loads(row[0])
                if isinstance(parsed, collections.abc.Mapping):
                    stored = dict(parsed)
            except ValueError:
                stored = {}
        if not notice_slot_due(stored, contact_id, now_value, window_ms):
            return False
        updated = notice_slot_write(stored, contact_id, now_value, window_ms)
        conn.execute(
            "INSERT INTO settings (key, value_json, updated_at_ms) VALUES (?,?,?) "
            "ON CONFLICT(key) DO UPDATE SET value_json = excluded.value_json, "
            "updated_at_ms = excluded.updated_at_ms",
            (SETTING_NOTICES, json.dumps(updated, ensure_ascii=False, separators=(",", ":")), now_value),
        )
        return True


def _notice_slot_reset(db: Any, contact_id: int) -> None:
    try:
        with db.transaction(immediate=True) as conn:
            row = conn.execute("SELECT value_json FROM settings WHERE key = ?", (SETTING_NOTICES,)).fetchone()
            if row is None:
                return
            stored = json.loads(row[0])
            if not isinstance(stored, collections.abc.Mapping):
                return
            pruned = {str(k): v for k, v in stored.items() if str(k) != str(int(contact_id))}
            conn.execute("DELETE FROM settings WHERE key = ?", (SETTING_NOTICES,))
            if pruned:
                conn.execute(
                    "INSERT INTO settings (key, value_json, updated_at_ms) VALUES (?,?,?)",
                    (SETTING_NOTICES, json.dumps(pruned, ensure_ascii=False, separators=(",", ":")), now_ms()),
                )
    except Exception:  # noqa: BLE001 - the transcript is already gone; do not fail the erasure twice
        log.warning("ai_agent: exhausted-notice slot could not be reset for contact %s", contact_id)


# ─────────────────────────────────────────────────────────────────────────────
# 4. The model call — the only place httpx exists
# ─────────────────────────────────────────────────────────────────────────────


def _api_key(deps: PluginDeps) -> str:
    """Read the credential at the moment of use, from config only.

    Not stored in the effective-config dict, never in a settings row, never in a
    log line, never in a response body: `/configure` has no branch that accepts
    it, and `/status` reports `present`/`chars`.
    """
    return str(getattr(deps.config, "ai_api_key", "") or "").strip()


async def _request_completion(cfg: Mapping[str, Any], api_key: str, payload: Mapping[str, Any]) -> Any:
    """One `POST {endpoint}` with bearer auth. Returns the decoded JSON body.

    Raises a `ModelCallFailure` subclass. No retry: the turn is already charged,
    a retry doubles the latency the follower is waiting on, and a provider that
    is down is down for the window whether we poke it twice or not.
    """
    import httpx

    endpoint = str(cfg.get("endpoint") or "") or normalize_chat_endpoint(cfg.get("base_url"))
    timeout = float(cfg.get("timeout_seconds") or 30.0)
    headers = {
        "authorization": "Bearer %s" % api_key,
        "content-type": "application/json",
        "accept": "application/json",
        "user-agent": USER_AGENT,
    }
    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            response = await client.post(endpoint, json=dict(payload), headers=headers)
    except httpx.HTTPError as exc:
        # Class name only: `httpx` exception messages embed the URL, and a base
        # URL can legitimately carry a credential.
        log.warning("ai_agent: model transport failure (%s)", type(exc).__name__)
        raise ModelTransportFailure(type(exc).__name__) from None
    except Exception as exc:  # noqa: BLE001 - a client that explodes for another reason is still a transport failure here
        log.warning("ai_agent: model call raised %s", type(exc).__name__)
        raise ModelTransportFailure(type(exc).__name__) from None
    status = int(getattr(response, "status_code", 0) or 0)
    if status < 200 or status >= 300:
        if status in (401, 403):
            log.warning("ai_agent: endpoint rejected the credential (%d); check POPOPX_AI_API_KEY", status)
        else:
            log.warning("ai_agent: endpoint answered %d", status)
        raise ModelStatusFailure(status)
    try:
        return response.json()
    except Exception:  # noqa: BLE001 - a 200 with HTML in it is a proxy, not a model
        raise ModelShapeFailure("the endpoint returned a body that is not JSON") from None


def _shape_reply(data: Any) -> str:
    """Envelope -> the exact text to send, or a `ModelCallFailure`.

    Order matters: shape guard, then sanitise (a marker-only answer is empty
    after this and must fail rather than send a blank bubble the client may also
    suppress), then the 8192-character budget. Truncating before sanitising could
    leave half a marker, which is inert but ugly; sanitising before the shape
    guard would let a garbage envelope pass as an answer.
    """
    content = extract_completion_text(data)
    if content is None:
        raise ModelShapeFailure("no message content in the model response")
    text = strip_control_markers(content).strip()
    if not text or is_marker_only(content):
        raise ModelEmptyFailure("the model returned nothing sayable")
    final = truncate_to_limit(text, REPLY_LIMIT_CHARS)
    if not reply_is_usable(final):
        # Last gate before a charged message reaches a phone. It re-checks the
        # exact string being sent rather than the string that arrived, so a bug in
        # the sanitising or truncating above costs a refund instead of a blank
        # bubble the follower paid for.
        raise ModelEmptyFailure("the reply was not sendable after sanitising")
    return final


def _refund(deps: PluginDeps, charge: Any, *, contact_id: int, row_id: int, reason: str) -> Optional[Dict[str, Any]]:
    """Give the credits back for an exchange the follower did not receive.

    Mandatory counterpart to the charge three lines up. `amount` is
    `charge.charged`, not `charge.cost`: a charge that was allowed on a drained
    balance took less than the price, and refunding the price here would mint
    credits (`BillingService.refund` is capped by lifetime spend, so the error
    would at least be caught, but by an accounting rule rather than by us).

    A refund that itself fails is logged with the `ref` and left alone: retrying
    blindly from a request handler is how one outage becomes a double credit.
    """
    charged = int(getattr(charge, "charged", 0) or 0)
    if charged <= 0:
        return None
    try:
        result = deps.billing.refund(
            amount=charged,
            reason="ai_agent:%s" % reason,
            # A distinct namespace from the charge's key: `_refund_txn` replays on
            # `idempotency_key` (`app/billing_service.py:647-649`), so reusing the
            # charge key would report success while returning nothing.
            idempotency_key="ai_refund:c%d:r%d" % (int(contact_id), int(row_id)),
            ref=str(int(row_id)),
        )
    except Exception as exc:  # noqa: BLE001 - never let the remedy hide the failure it is remediating
        log.error(
            "ai_agent: REFUND FAILED for contact %s ref %s amount %d (%s); reconcile by hand",
            contact_id, row_id, charged, type(exc).__name__,
        )
        return None
    log.warning(
        "ai_agent: refunded %d CP to contact %s (ref %s): %s", charged, contact_id, row_id, reason
    )
    if result is None:
        return None
    return {"charged": int(getattr(result, "cost", 0) or 0), "balance_after": int(getattr(result, "balance_after", 0) or 0)}


# ─────────────────────────────────────────────────────────────────────────────
# 5. The pipeline, shared by the inbound path and the console path
# ─────────────────────────────────────────────────────────────────────────────


def _new_outcome(cfg: Mapping[str, Any]) -> Dict[str, Any]:
    return {
        "status": STATUS_ANSWERED,
        "detail": "",
        "reply": None,
        "charged": 0,
        "cost": 0,
        "balance_after": None,
        "user_row_id": None,
        "assistant_row_id": None,
        "model": str(cfg.get("model") or DEFAULT_MODEL),
        "tokens_in": None,
        "tokens_out": None,
        "notified": False,
        "retry_after_ms": 0,
        "history_rows": 0,
        "truncated": False,
        "refunded": None,
    }


async def _notify_exhausted(deps: PluginDeps, contact_id: int, cfg: Mapping[str, Any], pairwise_uid: str) -> bool:
    """At most one money notice per contact per window. Returns whether it went out."""
    window_ms = max(1, int(cfg.get("rate_limit_window_seconds") or 300)) * 1000
    try:
        claimed = _claim_notice_slot(deps.db, contact_id, now_ms(), window_ms)
    except Exception as exc:  # noqa: BLE001 - an unreadable settings table must not become a notice storm
        log.warning("ai_agent: notice slot unavailable for contact %s (%s); staying silent", contact_id, type(exc).__name__)
        return False
    if not claimed:
        log.debug("ai_agent: exhausted notice suppressed for contact %s (already told this window)", contact_id)
        return False
    text = truncate_to_limit(strip_control_markers(str(cfg.get("exhausted_message") or "")).strip(), REPLY_LIMIT_CHARS)
    if not text:
        text = DEFAULT_EXHAUSTED_MESSAGE
    try:
        sent = bool(await deps.eco.send_frame(int(contact_id), text))
    except Exception as exc:  # noqa: BLE001 - a notice that cannot be delivered must not become a 500 in the chat loop
        log.warning("ai_agent: exhausted notice failed for contact %s (%s)", contact_id, type(exc).__name__)
        return False
    if not sent:
        log.warning("ai_agent: exhausted notice refused by the node for contact %s", contact_id)
        return False
    # The slot is already spent. Deliberately not released: two notices racing a
    # flapping node would otherwise both be handed the free slot and the follower
    # would get the same sentence twice in a row.
    try:
        _record_assistant(
            deps.db,
            contact_id=contact_id,
            pairwise_uid=pairwise_uid,
            content=text,
            credits_charged=0,
            now_value=now_ms(),
        )
    except Exception:  # noqa: BLE001 - the follower has the notice; the transcript is secondary
        log.warning("ai_agent: exhausted notice delivered but not recorded for contact %s", contact_id)
    return True


async def run_turn(
    deps: PluginDeps,
    contact_id: int,
    text: str,
    *,
    item_id: int = 0,
) -> Dict[str, Any]:
    """One follower turn, start to finish. The single implementation.

    `POST /chat` calls this and nothing else, which is what makes the console a
    faithful test of the inbound path rather than a second, easier one.
    """
    cfg = _load_config(deps)
    outcome = _new_outcome(cfg)

    # The contact is resolved before anything else, including the money branch:
    # a notice sent to a contact id that does not exist is a write against
    # nothing, and a blocked contact must not receive the plugin's copy either.
    body = str(text or "").strip()
    if len(body) > MAX_USER_TEXT_CHARS:
        outcome["truncated"] = True
        body = truncate_to_limit(body, MAX_USER_TEXT_CHARS)
    contact = _contact_row(deps.db, contact_id)
    if contact is None or int(contact.get("blocked") or 0):
        outcome["status"] = STATUS_UNKNOWN_CONTACT
        outcome["detail"] = "no such contact" if contact is None else "contact is blocked"
        return outcome
    pairwise_uid = str(contact.get("pairwise_uid") or "")

    gate = deps.gate.status(deps.plugin_id)
    if not gate.usable:
        if gate.reason == REASON_FUSED:
            outcome["status"] = STATUS_NOTIFIED
            outcome["notified"] = await _notify_exhausted(deps, contact_id, cfg, pairwise_uid)
            outcome["detail"] = gate.reason
            outcome["balance_after"] = gate.balance
            return outcome
        if gate.reason == REASON_SUSPENDED:
            # An operator halt wearing a credit fuse's clothes
            # (`BillingService._fused` returns True for any SUSPENDED,
            # `app/billing_service.py:1139-1147`). Telling the follower to top up
            # would blame them for a decision the merchant made, so: silence.
            reason = ""
            try:
                reason = str(getattr(deps.billing.account(), "suspended_reason", "") or "")
            except Exception:  # noqa: BLE001
                reason = ""
            if reason.startswith(REASON_OPERATOR):
                outcome["status"] = STATUS_BILLING_HELD
                outcome["detail"] = "account halted by an operator; no follower-facing notice is correct"
                return outcome
            outcome["status"] = STATUS_NOTIFIED
            outcome["notified"] = await _notify_exhausted(deps, contact_id, cfg, pairwise_uid)
            outcome["detail"] = reason or gate.reason
            return outcome
        outcome["status"] = GATE_REASON_TO_STATUS.get(gate.reason, STATUS_PLUGIN_DISABLED)
        outcome["detail"] = gate.reason
        return outcome

    if not model_is_ready(cfg):
        # Functionally off. Record nothing, charge nothing, send nothing: a
        # follower who gets an apology from a plugin that will never answer has
        # been told something unkind for no reason.
        outcome["status"] = STATUS_UNCONFIGURED
        outcome["detail"] = OPERATOR_FAILURE_HINT
        log.debug("ai_agent: not configured (key present=%s endpoint=%s); ignoring contact %s",
                  cfg["api_key_present"], bool(cfg["endpoint"]), contact_id)
        return outcome

    stamp = now_ms()
    claim = _claim_turn(
        deps.db,
        contact_id=contact_id,
        pairwise_uid=pairwise_uid,
        content=body,
        now_value=stamp,
        window_seconds=int(cfg["rate_limit_window_seconds"]),
        limit=int(cfg["rate_limit_messages"]),
    )
    if claim.status != "claimed":
        outcome["status"] = claim.status
        outcome["retry_after_ms"] = claim.retry_after_ms
        outcome["detail"] = "recorded nothing" if claim.status == STATUS_RATE_LIMITED else "same message as the previous turn"
        return outcome
    row_id = int(claim.row_id)
    outcome["user_row_id"] = row_id

    # ── charge first, refund on failure ───────────────────────────────────
    # Nothing between here and the refund below may return without either
    # delivering an answer or handing the credits back.
    ref = str(row_id)
    try:
        charge = deps.charge(
            contact_id=int(contact_id),
            ref=ref,
            # Keyed on the row we just wrote, so a replay of THIS call cannot
            # double-charge while a genuinely new turn always can.
            idempotency_key="ai_msg:c%d:r%d" % (int(contact_id), row_id),
            meta={"inbound_item_id": int(item_id or 0), "history_size": int(cfg["history_size"])},
        )
    except BillingError as exc:
        if exc.code == "insufficient_credits":
            # The fuse blew between the gate's read and this transaction, or the
            # gate was consulted by another route. Either way: the model is NOT
            # called (a refusal that still costs the merchant an API call is a
            # refusal with a bill attached) and nothing is refunded, because
            # `BillingService.charge` commits no `consume` row when it raises
            # (`app/billing_service.py:576-583`).
            outcome["status"] = STATUS_NOTIFIED
            outcome["notified"] = await _notify_exhausted(deps, contact_id, cfg, pairwise_uid)
            outcome["detail"] = exc.code
            return outcome
        # `account_suspended` / `account_draft` / `unknown_meter`: a state the
        # follower cannot act on. Let it propagate — `/chat` turns it into the
        # billing status, `handle_inbound`'s caller logs it, and neither is asked
        # to apologize on the merchant's behalf with credit-scarcity wording.
        raise
    outcome["charged"] = int(getattr(charge, "charged", 0) or 0)
    outcome["cost"] = int(getattr(charge, "cost", 0) or 0)
    outcome["balance_after"] = getattr(charge, "balance_after", None)
    if int(getattr(charge, "charged", 0) or 0) < int(getattr(charge, "cost", 0) or 0):
        # The last turn the balance could pay for (billing branch 5): allowed to
        # run, and the account is fused for the next one.
        log.warning(
            "ai_agent: partial charge for contact %s (%d of %d CP); the meter is now fused",
            contact_id, getattr(charge, "charged", 0), getattr(charge, "cost", 0),
        )

    history = select_history(
        _recent_rows(deps.db, contact_id),
        now_value=stamp,
        window_seconds=int(cfg["rate_limit_window_seconds"]),
        limit=int(cfg["history_size"]),
        before_id=row_id,
        exclude_content=str(cfg["exhausted_message"]),
    )
    outcome["history_rows"] = len(history)
    messages = build_model_messages(cfg["system_prompt"], history, body)

    try:
        data = await _request_completion(cfg, _api_key(deps), build_request_payload(cfg, messages))
        reply = _shape_reply(data)
    except Exception as exc:  # noqa: BLE001 - every model failure owes the follower a refund
        # THE PAIRING, and it is not optional: this turn has been charged, so a
        # model call that raised or answered with nothing usable must put the
        # credits back before the exception leaves this function. No assistant row
        # exists yet (the row is written only after a successful send), so there is
        # nothing to delete; the `consume` ledger row keeps `ref = user row id`,
        # which is how an operator finds exactly this case.
        outcome["refunded"] = _refund(
            deps, charge, contact_id=contact_id, row_id=row_id, reason="model_failure:%s" % failure_class_of(exc)
        )
        raise
    tokens_in, tokens_out = extract_usage(data)
    outcome["tokens_in"] = tokens_in
    outcome["tokens_out"] = tokens_out
    outcome["reply"] = reply

    try:
        delivered = bool(await deps.eco.send_frame(int(contact_id), reply))
    except Exception as exc:  # noqa: BLE001 - the node link failed after the answer existed
        outcome["refunded"] = _refund(
            deps, charge, contact_id=contact_id, row_id=row_id, reason="send_error:%s" % failure_class_of(exc)
        )
        outcome["status"] = STATUS_SEND_REFUSED
        outcome["reply"] = None
        return outcome
    if not delivered:
        # The node refused the write. Same accounting as a send error: the
        # follower did not get what they paid for.
        outcome["refunded"] = _refund(
            deps, charge, contact_id=contact_id, row_id=row_id, reason="send_refused"
        )
        outcome["status"] = STATUS_SEND_REFUSED
        outcome["reply"] = None
        return outcome

    try:
        outcome["assistant_row_id"] = _record_assistant(
            deps.db,
            contact_id=contact_id,
            pairwise_uid=pairwise_uid,
            content=reply,
            credits_charged=outcome["charged"],
            now_value=now_ms(),
        )
    except Exception:  # noqa: BLE001 - the answer is on their phone; do not un-send it
        log.exception("ai_agent: reply delivered but not persisted for contact %s", contact_id)
    log.info(
        "ai_agent: answered contact %s (%d chars, %d CP, %d history rows, model %s)",
        contact_id, len(reply), outcome["charged"], outcome["history_rows"], cfg["model"],
    )
    outcome["status"] = STATUS_ANSWERED
    return outcome


async def handle_inbound(deps: PluginDeps, message: "InboundMessage") -> bool:
    """Claim one inbound chat message. True means the caller must stop routing it.

    Returns False, without recording anything, when the plugin is switched off,
    the node is down, no credential is configured, or the contact does not exist
    — in each of those the gateway still has something better to do with the
    message than a plugin that cannot act on it.
    """
    callback = getattr(message, "callback", None)
    kind = getattr(callback, "kind", "")
    silent = bool(getattr(callback, "silent", False)) or bool(getattr(message, "is_control", False))
    text = getattr(message, "text", "")
    if not claims_inbound(kind, text, silent):
        return False
    contact_id = int(getattr(message, "contact_id", 0) or 0)
    if contact_id <= 0:
        return False
    outcome = await run_turn(deps, contact_id, str(text or ""), item_id=int(getattr(message, "item_id", 0) or 0))
    status = str(outcome.get("status"))
    if status == STATUS_RATE_LIMITED:
        # Deliberate silence, and deliberate claiming: the budget is the whole
        # point of the window, and an apology sent now is one more message the
        # follower never asked for. Debug-level because a flooded contact makes
        # this the noisiest line in the file.
        log.debug(
            "ai_agent: contact %s is rate limited (retry in %d ms); message not recorded",
            contact_id, int(outcome.get("retry_after_ms") or 0),
        )
    elif status == STATUS_DUPLICATE:
        log.debug("ai_agent: contact %s repeated the previous turn verbatim; treating as a redelivery", contact_id)
    elif status in (STATUS_PLUGIN_DISABLED, STATUS_NODE_DOWN, STATUS_UNCONFIGURED, STATUS_UNKNOWN_CONTACT):
        log.debug("ai_agent: contact %s not served (%s); falling through", contact_id, status)
        return False
    return consumes_inbound(status)


# ─────────────────────────────────────────────────────────────────────────────
# 6. The merchant's HTTP surface
# ─────────────────────────────────────────────────────────────────────────────


def create_router(deps: PluginDeps) -> "APIRouter":
    """Build the console surface. FastAPI is imported here, never at module scope.

    Paths are relative: the gateway mounts this router on `deps.spec.url_prefix`
    (`/api/v1/plugins/ai`), which is why nothing here repeats the prefix — a
    second copy would be a doubled `/api/v1/plugins/ai/api/v1/plugins/ai/status`.
    """
    from fastapi import APIRouter, HTTPException
    from fastapi.responses import PlainTextResponse

    db = deps.db

    def guard() -> Any:
        """`deps.require()`, translated locally.

        `PluginUnavailable` is documented as the gateway handler's business, but
        the 404-vs-402 distinction is this plugin's promise to the merchant, and
        `app/main.py` is not a file this module may assume anything about beyond
        the seam. Translating it here is idempotent: if the gateway also handles
        it, it simply never sees the exception.
        """
        try:
            return deps.require()
        except PluginUnavailable as exc:
            raise HTTPException(status_code=exc.http_status, detail=exc.decision.as_body()) from None

    def bad_request(rule: str, detail: str) -> "HTTPException":
        return HTTPException(status_code=400, detail={"ok": False, "error": rule, "detail": detail})

    def client_error(exc: EcoError) -> "HTTPException":
        """An EcoError is always a caller mistake about a wire rule -> 4xx."""
        return HTTPException(status_code=400, detail={"ok": False, "error": exc.rule, "detail": exc.detail})

    def require_contact(contact_id: Any) -> int:
        try:
            parsed = int(contact_id)
        except (TypeError, ValueError):
            raise bad_request("contact_id", "contact_id must be an integer, got %r" % (contact_id,)) from None
        if parsed <= 0:
            raise bad_request("contact_id", "contact_id must be a positive node contact id") from None
        if _contact_row(db, parsed) is None:
            raise HTTPException(
                status_code=404,
                detail={"ok": False, "error": "unknown_contact", "detail": "no follower with contact_id %d" % parsed},
            ) from None
        return parsed

    router = APIRouter(tags=["ai_agent"])

    @router.get("/status")
    def status() -> Any:
        """State, model, prices, rate limits. Never the key, never a message body.

        503 when `ai_api_key`/`ai_base_url` are absent: that is the plugin being
        functionally off, which is neither "disabled" (404) nor "unfunded" (402)
        and must not be confused with either by a merchant reading a console.
        """
        decision = guard()
        cfg = _load_config(deps)
        try:
            price = int(deps.billing.quote(METER))
        except BillingError as exc:
            raise HTTPException(
                status_code=exc.http_status or 402,
                detail={"ok": False, "error": exc.code, "detail": exc.message},
            ) from None
        body = status_payload(
            cfg=cfg,
            gate_body=decision.as_body(),
            price=price,
            balance=decision.balance,
            history_rows=_count_messages(db),
        )
        if not model_is_ready(cfg):
            return PlainTextResponse(
                content=json.dumps(body, ensure_ascii=False, sort_keys=True),
                status_code=503,
                media_type="application/json",
            )
        return body

    @router.post("/chat")
    async def chat(body: Dict[str, Any]) -> Any:
        """Run one turn through the real pipeline, for the merchant's console.

        Same rate limit, same charge, same refund rules as a message from a
        phone. Refuses an unknown contact rather than inventing one, because a
        test against a contact id that does not exist measures nothing.
        """
        guard()
        if not isinstance(body, collections.abc.Mapping):
            raise bad_request("body", "expected a JSON object with contact_id and text")
        contact_id = require_contact(body.get("contact_id"))
        text = body.get("text")
        if not isinstance(text, str) or not text.strip():
            raise bad_request("text", "text must be a non-empty string")
        try:
            outcome = await run_turn(deps, contact_id, text, item_id=int(body.get("item_id") or 0))
        except ModelCallFailure as exc:
            raise HTTPException(
                status_code=502,
                detail={
                    "ok": False,
                    "error": "model_%s" % exc.failure_class,
                    "detail": OPERATOR_FAILURE_HINT,
                    "refunded": True,
                },
            ) from None
        except EcoError as exc:
            raise client_error(exc) from None
        except BillingError as exc:
            raise HTTPException(
                status_code=exc.http_status or 402,
                detail={"ok": False, "error": exc.code, "detail": exc.message},
            ) from None
        status_name = str(outcome.get("status"))
        code = status_to_http(status_name)
        payload = {"ok": status_name == STATUS_ANSWERED, "status": status_name}
        payload.update({key: value for key, value in outcome.items() if key != "status"})
        if code != 200:
            raise HTTPException(
                status_code=code,
                detail=payload,
                headers={"Retry-After": str(max(1, int(outcome.get("retry_after_ms") or 0) // 1000))}
                if status_name == STATUS_RATE_LIMITED else None,
            )
        return payload

    @router.get("/history")
    def history(contact_id: Optional[int] = None, limit: int = 50) -> Any:
        """Newest-first transcript rows, for the console's conversation view."""
        guard()
        if contact_id is None:
            raise bad_request("contact_id", "contact_id is required; history is per follower")
        parsed = require_contact(contact_id)
        if not 1 <= int(limit) <= 500:
            raise bad_request("limit", "limit must be between 1 and 500") from None
        rows = _recent_rows(db, parsed, cap=max(HISTORY_HARD_CAP, min(500, int(limit))))
        # `_recent_rows` is already `ORDER BY id DESC`, i.e. newest-first.
        return {
            "ok": True,
            "contact_id": parsed,
            "count": len(rows),
            "order": "newest_first",
            "messages": [
                {
                    "id": int(row.get("id") or 0),
                    "role": str(row.get("role")),
                    "content": str(row.get("content") or ""),
                    "ts_ms": int(row.get("ts_ms") or 0),
                    "credits_charged": int(row.get("credits_charged") or 0),
                }
                for row in rows[: int(limit)]
            ],
        }

    @router.delete("/history")
    def forget(contact_id: Optional[int] = None) -> Any:
        """Erase one follower's conversation. The right to be forgotten should not
        need a SQL script, and a plugin that remembers what it deleted has not
        deleted anything."""
        guard()
        if contact_id is None:
            raise bad_request("contact_id", "contact_id is required; this endpoint deletes, so it will not guess")
        parsed = require_contact(contact_id)
        deleted = _delete_history(db, parsed)
        log.info("ai_agent: forgot contact %d (%d rows)", parsed, deleted)
        return {"ok": True, "contact_id": parsed, "deleted": deleted}

    @router.post("/configure")
    def configure(body: Dict[str, Any]) -> Any:
        """Write the editable knobs. No restart, no file edit, no credential.

        Sizes are checked against the client limits the text may one day be sent
        inside, so a prompt written here cannot later become a dropped frame.
        """
        guard()
        if not isinstance(body, collections.abc.Mapping):
            raise bad_request("body", "expected a JSON object of configuration keys")
        current = _read_raw_config(db)
        try:
            merged = merge_config(current, dict(body))
        except EcoError as exc:
            raise client_error(exc) from None
        try:
            db.set_setting(SETTING_CONFIG, merged)
        except Exception as exc:  # noqa: BLE001 - a settings write that fails must not report success
            raise HTTPException(
                status_code=500,
                detail={"ok": False, "error": "configuration_not_written", "detail": type(exc).__name__},
            ) from None
        cfg = effective_config(merged, deps.config)
        log.info(
            "ai_agent: configuration updated (%s); model=%s history=%d",
            ", ".join(sorted(str(key) for key in body)) or "none",
            cfg["model"],
            cfg["history_size"],
        )
        return {
            "ok": True,
            "updated": sorted(str(key) for key in body),
            "effective": {
                "model": cfg["model"],
                "history_size": cfg["history_size"],
                "temperature": cfg["temperature"],
                "max_tokens": cfg["max_tokens"],
                "system_prompt_chars": len(cfg["system_prompt"]),
                "exhausted_message_chars": len(cfg["exhausted_message"]),
                "overrides": sorted(merged),
                "falling_back_to_environment": sorted(key for key in CONFIG_KEYS if key not in merged),
            },
        }

    @router.get("/transcript/{contact_id}/export")
    def transcript(contact_id: int) -> Any:
        """Plain-text export of one follower's conversation.

        Scoped to that contact by the URL, so there is no "all" variant to
        mistake for a support tool and a bulk data grab.
        """
        guard()
        parsed = require_contact(contact_id)
        rows = _recent_rows(db, parsed)
        rows.reverse()  # chronological: an export you have to re-sort is a support queue
        contact = _contact_row(db, parsed) or {}
        text = render_transcript(
            contact_id=parsed,
            rows=rows,
            generated_ms=now_ms(),
            service_name=str(getattr(deps.config, "service_name", "") or ""),
        )
        return PlainTextResponse(
            content=text,
            media_type="text/plain; charset=utf-8",
            headers={"content-disposition": 'attachment; filename="ai-transcript-%d.txt"' % parsed},
        )

    return router


# ─────────────────────────────────────────────────────────────────────────────
# 7. Self-test: the pure half, no FastAPI, no httpx, no database
# ─────────────────────────────────────────────────────────────────────────────


def self_test() -> List[str]:
    """Assertions over everything that can be decided without a socket or a row.

    Run it: `cd gateway && /usr/bin/python3 -c "import sys; sys.path.insert(0,'.');
    from app.plugins import ai_agent_plugin as p; print(len(p.self_test()))"`.
    What is NOT here — routes, `httpx`, `deps.eco.send_frame`, the transactional
    bodies of `_claim_turn`/`_claim_notice_slot` — is stated as such in the module
    docstring rather than claimed by a test that could not reach it anyway.
    """
    checks: List[str] = []

    def check(name: str, condition: bool) -> None:
        if not condition:
            raise AssertionError("self_test failed: %s" % name)
        checks.append(name)

    # ── mount-table agreement ──────────────────────────────────────────────
    from app.plugins import plugin_for_id

    spec = plugin_for_id(PLUGIN_ID)
    check("spec_plugin_id", spec.plugin_id == PLUGIN_ID)
    check("spec_meter_matches_this_module", spec.meter == METER)
    check("spec_prefix_matches", spec.url_prefix == URL_PREFIX)
    check("spec_claims_text_only", spec.callback_kinds == ("text",))

    # ── base-url normalisation ─────────────────────────────────────────────
    check(
        "endpoint_versioned_root_gets_the_path",
        normalize_chat_endpoint("https://api.openai.com/v1") == "https://api.openai.com/v1/chat/completions",
    )
    check(
        "endpoint_trailing_slash_is_ignored",
        normalize_chat_endpoint("https://api.openai.com/v1///") == "https://api.openai.com/v1/chat/completions",
    )
    check(
        "endpoint_schemeless_gets_https",
        normalize_chat_endpoint("api.openai.com/v1") == "https://api.openai.com/v1/chat/completions",
    )
    check(
        "endpoint_full_path_is_left_alone",
        normalize_chat_endpoint("https://api.openai.com/v1/chat/completions")
        == "https://api.openai.com/v1/chat/completions",
    )
    check(
        "endpoint_missing_version_root_gets_v1",
        normalize_chat_endpoint("https://api.openai.com") == "https://api.openai.com/v1/chat/completions",
    )
    check(
        "endpoint_unversioned_path_gets_v1",
        normalize_chat_endpoint("http://127.0.0.1:11434/llama") == "http://127.0.0.1:11434/llama/v1/chat/completions",
    )
    check(
        "endpoint_dated_version_counts_as_a_version",
        normalize_chat_endpoint("https://host/api/v20240101") == "https://host/api/v20240101/chat/completions",
    )
    check("endpoint_local_with_port_keeps_the_port", normalize_chat_endpoint("http://localhost:8000/v1").endswith(":8000/v1/chat/completions"))
    check("endpoint_blank_stays_blank", normalize_chat_endpoint("   ") == "" and normalize_chat_endpoint(None) == "")
    check("endpoint_whitespace_survives", normalize_chat_endpoint("  https://api.openai.com/v1  ").startswith("https://"))
    check("endpoint_host_strips_credentials", endpoint_host("https://user:hunter2@api.example.com/v1") == "api.example.com")
    check("endpoint_host_keeps_port", endpoint_host("http://127.0.0.1:11434/v1") == "127.0.0.1:11434")
    check("endpoint_host_of_nothing", endpoint_host("") == "")
    check("insecure_host_flags_the_internet", hostname_is_insecure("api.example.com") is True)
    check("insecure_host_exempts_loopback", hostname_is_insecure("127.0.0.1") is False)

    # ── the api key's only permitted representations ───────────────────────
    present, chars = api_key_facts("sk-" + "x" * 40)
    check("key_facts_are_a_boolean_and_a_length", present is True and chars == 43)
    check("key_facts_of_blank", api_key_facts("   ") == (False, 0) and api_key_facts(None) == (False, 0))

    # ── system-prompt precedence: console > env > built-in ─────────────────
    class FakeConfig:
        def __init__(self, **kwargs: Any) -> None:
            self.ai_base_url = "https://api.openai.com/v1"
            self.ai_api_key = "sk-secret-value-do-not-print"
            self.ai_model = "env-model"
            self.ai_system_prompt = "env prompt"
            self.ai_max_tokens = 512
            self.ai_timeout_seconds = 30.0
            self.ai_rate_limit_messages = 20
            self.ai_rate_limit_window_seconds = 300
            for key, value in kwargs.items():
                setattr(self, key, value)

    check("prompt_env_used_when_no_override", resolve_system_prompt({}, "env prompt") == "env prompt")
    check("prompt_override_wins", resolve_system_prompt({"system_prompt": "db prompt"}, "env prompt") == "db prompt")
    check("prompt_blank_override_falls_back", resolve_system_prompt({"system_prompt": "   "}, "env prompt") == "env prompt")
    check("prompt_empty_env_reaches_the_builtin", resolve_system_prompt({}, "") == DEFAULT_SYSTEM_PROMPT)
    cfg = effective_config({"model": "db-model", "history_size": 3, "temperature": 0.1, "max_tokens": 64}, FakeConfig())
    check("config_override_model", cfg["model"] == "db-model")
    check("config_override_history_temperature_maxtokens", cfg["history_size"] == 3 and cfg["temperature"] == 0.1 and cfg["max_tokens"] == 64)
    check("config_falls_back_to_env_prompt", cfg["system_prompt"] == "env prompt")
    check("config_rate_limit_comes_from_env_only", cfg["rate_limit_messages"] == 20 and cfg["rate_limit_window_seconds"] == 300)
    check("config_history_default", effective_config({}, FakeConfig())["history_size"] == HISTORY_DEFAULT)
    check("config_history_zero_is_honoured", effective_config({"history_size": 0}, FakeConfig())["history_size"] == 0)
    dump = json.dumps(cfg, ensure_ascii=False)
    check("config_view_never_carries_the_key", "sk-secret-value" not in dump and "api_key" not in cfg)
    check("config_view_carries_only_facts_about_the_key", effective_config({}, FakeConfig())["api_key_present"] is True)
    check("config_default_max_tokens_from_env", effective_config({}, FakeConfig())["max_tokens"] == 512)
    check("config_missing_attributes_still_work", effective_config({}, object())["model"] == DEFAULT_MODEL)

    # ── configuration validation against the client's own numbers ──────────
    def raises_rule(rule_fragment: str, raw: Mapping[str, Any]) -> bool:
        try:
            validated_config(raw)
        except EcoValidationError as exc:
            return rule_fragment in exc.rule
        except EcoError:
            return False
        return False

    check("config_rejects_unknown_key", raises_rule("config_unknown_key", {"sytem_prompt": "typo"}))
    check("config_rejects_oversize_prompt", raises_rule("config_system_prompt", {"system_prompt": "x" * (EcoLimits.card_body_chars + 1)}))
    check("config_accepts_prompt_at_exactly_the_limit", len(validated_config({"system_prompt": "x" * EcoLimits.card_body_chars})["system_prompt"]) == EcoLimits.card_body_chars)
    check("config_rejects_oversize_notice", raises_rule("config_exhausted_message", {"exhausted_message": "x" * 2001}))
    check("config_rejects_history_above_cap", raises_rule("config_history_size", {"history_size": HISTORY_HARD_CAP + 1}))
    check("config_rejects_negative_history", raises_rule("config_history_size", {"history_size": -1}))
    check("config_rejects_temperature_above_two", raises_rule("config_temperature", {"temperature": 2.5}))
    check("config_rejects_boolean_temperature", raises_rule("config_temperature", {"temperature": True}))
    check("config_rejects_nan_temperature", raises_rule("config_temperature", {"temperature": float("nan")}))
    check("config_rejects_max_tokens_over_the_ceiling", raises_rule("config_max_tokens", {"max_tokens": MAX_TOKENS_CEILING + 1}))
    check("config_rejects_non_string_model", raises_rule("config_model", {"model": 42}))
    check("config_strips_whitespace", validated_config({"model": "  gpt  "})["model"] == "gpt")
    merged = merge_config({"model": "a", "history_size": 4}, {"model": "", "temperature": 1.0})
    check("merge_clears_a_blank_override", merged == {"history_size": 4, "temperature": 1.0})
    check("merge_validates_the_result", merge_config({}, {"history_size": 2})["history_size"] == 2)
    try:
        merge_config({}, {"history_size": 9999})
        check("merge_rejects_bad_input", False)
    except EcoValidationError:
        check("merge_rejects_bad_input", True)

    # ── rate-window arithmetic ────────────────────────────────────────────
    now_value = 1_700_000_000_000
    check("window_start_is_the_window_back", window_start_ms(now_value, 300) == now_value - 300_000)
    check("window_floor_of_one_second", window_start_ms(now_value, 0) == now_value - 1000)
    check("inside_window_at_the_boundary", inside_window(window_start_ms(now_value, 300), now_value, 300) is True)
    check("inside_window_one_ms_early", inside_window(window_start_ms(now_value, 300) - 1, now_value, 300) is False)
    check("inside_window_rejects_garbage", inside_window("nope", now_value, 300) is False and inside_window(None, now_value, 300) is False)
    check("rate_limit_allows_exactly_n", rate_limited(19, 20) is False and rate_limited(18, 20) is False)
    check("rate_limit_refuses_at_n", rate_limited(20, 20) is True)
    check("rate_limit_refuses_above_n", rate_limited(21, 20) is True)
    check("rate_limit_of_one_blocks_the_second", rate_limited(0, 1) is False and rate_limited(1, 1) is True)
    check("rate_limit_zero_means_unlimited", rate_limited(10_000, 0) is False and rate_limited(10_000, -1) is False)
    check("retry_after_at_the_boundary_is_zero", retry_after_ms(now_value - 300_000, now_value, 300) == 0)
    check("retry_after_mid_window", retry_after_ms(now_value - 100_000, now_value, 300) == 200_000)
    check("retry_after_is_clamped_to_the_window", retry_after_ms(now_value + 9_000_000, now_value, 300) == 300_000)
    check("retry_after_without_an_oldest_is_the_whole_window", retry_after_ms(None, now_value, 300) == 300_000)

    # ── redelivery detection ──────────────────────────────────────────────
    check("redelivery_same_text_1s_ago", looks_like_redelivery("hello", 1000, "hello", REDELIVERY_WINDOW_MS) is True)
    check("redelivery_boundary_is_inclusive", looks_like_redelivery("hello", REDELIVERY_WINDOW_MS, "hello", REDELIVERY_WINDOW_MS) is True)
    check("not_redelivery_1ms_late", looks_like_redelivery("hello", REDELIVERY_WINDOW_MS + 1, "hello", REDELIVERY_WINDOW_MS) is False)
    check("not_redelivery_different_text", looks_like_redelivery("hello", 10, "Hello", REDELIVERY_WINDOW_MS) is False)
    check("not_redelivery_from_the_future", looks_like_redelivery("hello", -1, "hello", REDELIVERY_WINDOW_MS) is False)
    check("not_redelivery_on_garbage_age", looks_like_redelivery("hello", "x", "hello", REDELIVERY_WINDOW_MS) is False)
    check("not_redelivery_on_a_null_previous", looks_like_redelivery(None, 5, "hello", REDELIVERY_WINDOW_MS) is False)

    # ── claims predicate ──────────────────────────────────────────────────
    check("claims_plain_text", claims_inbound("text", "你好", False) is True)
    check("claims_uppercase_kind", claims_inbound("TEXT", "hi", False) is True)
    check("refuses_other_kinds", claims_inbound("card_callback", "hi", True) is False)
    check("refuses_system_kind", claims_inbound("system", "::popopx_sys::X::1", True) is False)
    check("refuses_empty_and_whitespace", claims_inbound("text", "   \n ", False) is False and claims_inbound("text", "", False) is False)
    check("refuses_non_string_body", claims_inbound("text", None, False) is False and claims_inbound("text", 12, False) is False)
    check("refuses_an_eco_frame_typed_as_text", claims_inbound("text", ECO_MARKER + '{"t":"mc"}', False) is False)
    check("refuses_a_malformed_sys_marker", claims_inbound("text", "::popopx_sys::NO_DELIMITER", False) is False)
    check("refuses_an_embedded_callback_marker", claims_inbound("text", "sure, ::CB::pay_1 then", False) is False)
    check("refuses_when_flagged_control", claims_inbound("text", "hi", True) is False)
    check("refuses_a_bare_sso_marker", claims_inbound("text", "::SSO_SCAN::abc", False) is False)

    # ── inbound claiming after a turn ran ─────────────────────────────────
    check("consumes_answered", consumes_inbound(STATUS_ANSWERED) is True)
    check("consumes_rate_limited_silence", consumes_inbound(STATUS_RATE_LIMITED) is True)
    check("consumes_redelivery", consumes_inbound(STATUS_DUPLICATE) is True)
    check("consumes_the_money_notice", consumes_inbound(STATUS_NOTIFIED) is True)
    check("does_not_consume_when_unconfigured", consumes_inbound(STATUS_UNCONFIGURED) is False)
    check("does_not_consume_when_disabled", consumes_inbound(STATUS_PLUGIN_DISABLED) is False)
    check("does_not_consume_when_node_down", consumes_inbound(STATUS_NODE_DOWN) is False)
    check("does_not_consume_unknown_contact", consumes_inbound(STATUS_UNKNOWN_CONTACT) is False)
    check("does_not_consume_an_operator_halt", consumes_inbound(STATUS_BILLING_HELD) is False)
    check("gate_reasons_map_to_statuses", GATE_REASON_TO_STATUS[REASON_DISABLED] == STATUS_PLUGIN_DISABLED and GATE_REASON_TO_STATUS[REASON_NODE_DOWN] == STATUS_NODE_DOWN)

    # ── console status codes for each outcome ─────────────────────────────
    check("http_answered", status_to_http(STATUS_ANSWERED) == 200)
    check("http_rate_limited_is_429", status_to_http(STATUS_RATE_LIMITED) == 429)
    check("http_unknown_contact_is_404", status_to_http(STATUS_UNKNOWN_CONTACT) == 404)
    check("http_disabled_is_404_not_402", status_to_http(STATUS_PLUGIN_DISABLED) == 404 and status_to_http(STATUS_NOTIFIED) == 402)
    check("http_unconfigured_is_503", status_to_http(STATUS_UNCONFIGURED) == 503 and status_to_http(STATUS_NODE_DOWN) == 503)
    check("http_send_refused_is_502", status_to_http(STATUS_SEND_REFUSED) == 502)
    check("http_unknown_status_is_500", status_to_http("nonsense") == 500)

    # ── model readiness ───────────────────────────────────────────────────
    ready_cfg = effective_config({}, FakeConfig())
    check("ready_with_a_key_and_an_endpoint", model_is_ready(ready_cfg) is True)
    no_key = effective_config({}, FakeConfig(ai_api_key=""))
    check("not_ready_without_a_key", model_is_ready(no_key) is False)
    no_url = effective_config({}, FakeConfig(ai_base_url="  "))
    check("not_ready_without_a_base_url", model_is_ready(no_url) is False)
    check(
        "unconfigured_status_says_503_and_admits_it",
        status_payload(cfg=no_key, gate_body={"ok": True, "plugin": PLUGIN_ID, "reason": "usable"}, price=5, balance=10)["accepting"] is False,
    )
    unconfigured_body = status_payload(cfg=no_key, gate_body={"ok": True, "plugin": PLUGIN_ID, "reason": "usable"}, price=5, balance=10)
    check("unconfigured_status_is_not_ok", unconfigured_body["ok"] is False and "not configured" in unconfigured_body["detail"])

    # ── /status payload hygiene ───────────────────────────────────────────
    status_body = status_payload(cfg=ready_cfg, gate_body={"ok": True, "plugin": PLUGIN_ID, "reason": "usable", "balance": 99}, price=5, balance=99, history_rows=7)
    serialised = json.dumps(status_body, ensure_ascii=False)
    check("status_has_no_key_material", "sk-secret-value-do-not-print" not in serialised)
    check("status_has_no_prompt_text", "env prompt" not in serialised and "system_prompt" not in status_body)
    check("status_reports_key_as_boolean_and_length", status_body["api_key"] == {"present": True, "chars": 28})
    check("status_reports_price_and_limits", status_body["credits_per_message"] == 5 and status_body["rate_limit"]["messages"] == 20 and status_body["reply_limit_chars"] == 8192)
    check("status_reports_model_and_host", status_body["model"] == "env-model" and status_body["endpoint_host"] == "api.openai.com")
    check("status_reports_stored_count", status_body["stored_messages_total"] == 7)
    check("status_omits_an_unmeasured_count", "stored_messages_total" not in status_payload(
        cfg=ready_cfg, gate_body={"ok": True, "plugin": PLUGIN_ID, "reason": "usable"}, price=5, balance=1))
    check("status_ok_when_enabled_and_configured", status_body["ok"] is True and status_body["accepting"] is True)
    check("status_not_ok_when_the_gate_said_no", status_payload(cfg=ready_cfg, gate_body={"ok": False, "plugin": PLUGIN_ID, "reason": "disabled"}, price=5, balance=None)["ok"] is False)
    check("status_omits_an_absent_balance", "balance" not in status_payload(cfg=ready_cfg, gate_body={"ok": True, "plugin": PLUGIN_ID, "reason": "usable"}, price=5, balance=None))
    check("status_endpoint_host_has_no_credentials", "@" not in status_body["endpoint_host"])

    # ── the exhausted-notice dedupe predicate ─────────────────────────────
    window_ms = 300_000
    check("first_notice_is_due", notice_slot_due({}, 7, now_value, window_ms) is True)
    check("second_notice_in_the_window_is_not_due", notice_slot_due({"7": str(now_value - 1000)}, 7, now_value, window_ms) is False)
    check("notice_exactly_one_window_old_is_due", notice_slot_due({"7": str(now_value - window_ms)}, 7, now_value, window_ms) is True)
    check("notice_one_ms_short_is_not_due", notice_slot_due({"7": str(now_value - window_ms + 1)}, 7, now_value, window_ms) is False)
    check("another_contact_is_unaffected", notice_slot_due({"7": str(now_value)}, 8, now_value, window_ms) is True)
    check("a_garbage_entry_does_not_silence_someone_forever", notice_slot_due({"7": "not-a-number"}, 7, now_value, window_ms) is True)
    check("a_slot_in_the_future_waits_it_out", notice_slot_due({"7": str(now_value + 60_000)}, 7, now_value, window_ms) is False)
    written = notice_slot_write({"7": str(now_value)}, 8, now_value, window_ms)
    check("write_claims_the_contact_and_keeps_the_other", written == {"7": str(now_value), "8": str(now_value)})
    pruned = notice_slot_write({"9": str(now_value - window_ms - 1), "10": str(now_value - 10)}, 8, now_value, window_ms)
    check("write_prunes_expired_slots", "9" not in pruned and "10" in pruned and pruned["8"] == str(now_value))
    check("write_overwrites_the_same_contact", notice_slot_write({"8": str(now_value - 5000)}, 8, now_value, window_ms)["8"] == str(now_value))
    round_trip = notice_slot_write({}, 8, now_value, window_ms)
    check("a_claimed_slot_is_not_due", notice_slot_due(round_trip, 8, now_value, window_ms) is False)
    check("notice_keys_are_strings_for_json", all(isinstance(key, str) for key in round_trip))
    check("default_notice_says_quota", "额度不足" in DEFAULT_EXHAUSTED_MESSAGE)
    check("default_notice_says_how_to_top_up", "POPX-CP" in DEFAULT_EXHAUSTED_MESSAGE)
    check("default_notice_leaks_no_balance", not any(ch.isdigit() for ch in DEFAULT_EXHAUSTED_MESSAGE) and "余额" not in DEFAULT_EXHAUSTED_MESSAGE)
    check("default_notice_fits_a_message", len(DEFAULT_EXHAUSTED_MESSAGE) < REPLY_LIMIT_CHARS)
    check("notice_override_reaches_the_outcome", effective_config({"exhausted_message": "商户自定义：额度不足"}, FakeConfig())["exhausted_message"] == "商户自定义：额度不足")

    # ── reply truncation at the client's 8192-character cliff ─────────────
    exactly = "啊" * REPLY_LIMIT_CHARS
    check("no_truncation_at_exactly_the_limit", truncate_to_limit(exactly) == exactly and len(truncate_to_limit(exactly)) == REPLY_LIMIT_CHARS)
    over = "x" * (REPLY_LIMIT_CHARS + 1)
    cut = truncate_to_limit(over)
    check("truncation_at_8193_produces_8192", len(cut) == REPLY_LIMIT_CHARS)
    check("truncation_leaves_no_doubt", cut.endswith(TRUNCATION_MARKER) and TRUNCATION_MARKER in cut)
    check("truncation_marker_is_inside_the_budget", len(cut) <= REPLY_LIMIT_CHARS)
    check("truncation_counts_characters_not_bytes", len(truncate_to_limit("啊" * 9000)) == REPLY_LIMIT_CHARS)
    check("truncation_strips_the_trailing_space_it_would_orphan", truncate_to_limit("y" * 8192 + "   ").endswith(TRUNCATION_MARKER))
    check("truncation_below_the_marker_length_just_cuts", truncate_to_limit("abcdef", 2) == "ab")
    check("truncation_of_empty_is_empty", truncate_to_limit("") == "")
    check("short_reply_untouched", truncate_to_limit("你好") == "你好")

    # ── control-marker neutralisation ─────────────────────────────────────
    check("marker_neutralised_at_the_front", not strip_control_markers(ECO_MARKER + '{"t":"mc"}').startswith(ECO_MARKER))
    check("marker_replaced_readably", strip_control_markers(ECO_MARKER) == "[POPOPX_ECO]")
    check("callback_marker_neutralised", "[CB]" in strip_control_markers("::CB::vote_yes"))
    check("sys_marker_neutralised", "[popopx_sys]" in strip_control_markers("::popopx_sys::X::1"))
    check("clean_text_untouched", strip_control_markers("a normal answer with [brackets]") == "a normal answer with [brackets]")
    check("a_marker_only_reply_is_not_usable", reply_is_usable(ECO_MARKER) is False)
    def shape_raises(data: Any, expected: str) -> bool:
        try:
            _shape_reply(data)
        except ModelCallFailure as exc:
            return exc.failure_class == expected
        return False

    check("shape_guard_rejects_a_marker_only_answer",
          shape_raises({"choices": [{"message": {"content": ECO_MARKER}}]}, "empty"))
    check("shape_guard_rejects_an_absent_envelope", shape_raises({}, "bad_shape"))
    check("shape_guard_rejects_empty_choices", shape_raises({"choices": []}, "bad_shape"))
    check("shape_guard_rejects_a_non_string_answer", shape_raises({"choices": [{"message": {"content": 9}}]}, "bad_shape"))
    check("shape_guard_rejects_a_whitespace_answer", shape_raises({"choices": [{"message": {"content": "   \n"}}]}, "empty"))
    check("shape_guard_neutralises_an_embedded_marker",
          _shape_reply({"choices": [{"message": {"content": "看 " + ECO_MARKER + " 这里"}}]}) == "看 [POPOPX_ECO] 这里")
    check("shape_guard_truncates_a_long_answer",
          len(_shape_reply({"choices": [{"message": {"content": "啊" * 9000}}]})) == REPLY_LIMIT_CHARS)
    check("marker_only_is_detected", is_marker_only(ECO_MARKER) is True and is_marker_only("  ::CB:: \n") is True)
    check("marker_only_of_every_marker", all(is_marker_only(m) is True for m in CONTROL_MARKERS))
    check("markers_with_real_words_are_not_marker_only", is_marker_only("答案是 ::CB:: 之一") is False)
    check("empty_string_is_marker_only_but_not_usable", is_marker_only("") is True and reply_is_usable("") is False)
    check("a_sys_marker_only_reply_is_not_usable", reply_is_usable("::popopx_sys::") is False)
    check("whitespace_is_not_usable", reply_is_usable("  \n\t ") is False and reply_is_usable(None) is False)
    check("usable_after_the_marker_is_neutralised", reply_is_usable("see " + ECO_MARKER + " here") is True)
    check("sanitised_reply_still_fits_the_wire", len(truncate_to_limit(strip_control_markers(ECO_MARKER + ("z" * 9000)), REPLY_LIMIT_CHARS)) <= REPLY_LIMIT_CHARS)

    # ── response-shape guards ─────────────────────────────────────────────
    check("no_choices", extract_completion_text({}) is None and extract_completion_text({"choices": []}) is None)
    check("choices_wrong_type", extract_completion_text({"choices": "oops"}) is None and extract_completion_text(None) is None)
    check("choice_element_not_an_object", extract_completion_text({"choices": [3]}) is None)
    check("content_not_a_string", extract_completion_text({"choices": [{"message": {"content": None}}]}) is None)
    check("content_a_number", extract_completion_text({"choices": [{"message": {"content": 7}}]}) is None)
    check("no_message_at_all", extract_completion_text({"choices": [{}]}) is None)
    check("plain_string_choice_is_taken", extract_completion_text({"choices": ["hi"]}) == "hi")
    check("legacy_text_field_works", extract_completion_text({"choices": [{"text": "hi"}]}) == "hi")
    check("content_part_lists_are_joined", extract_completion_text({"choices": [{"message": {"content": [{"text": "a"}, {"text": "b"}]}}]}) == "ab")
    check("content_parts_with_no_text_fail_closed", extract_completion_text({"choices": [{"message": {"content": [{"x": 1}]}}]}) is None)
    check("happy_path", extract_completion_text({"choices": [{"message": {"content": "  你好  "}}]}) == "  你好  ")
    check("usage_absent", extract_usage({}) == (None, None) and extract_usage({"usage": {}}) == (None, None))
    check("usage_types", extract_usage({"usage": {"prompt_tokens": 11, "completion_tokens": 22}}) == (11, 22))
    check("usage_rejects_booleans_and_negatives", extract_usage({"usage": {"prompt_tokens": True, "completion_tokens": -1}}) == (None, None))
    check("usage_ignores_a_non_mapping", extract_usage("nope") == (None, None))

    # ── failure classes: the words a refund reason is allowed to contain ───
    check("failure_class_of_our_own", failure_class_of(ModelEmptyFailure("x")) == "empty")
    check("failure_class_of_a_foreign_exception", failure_class_of(ValueError("boom")) == "ValueError")
    check("status_failure_carries_only_the_code", "401" in str(ModelStatusFailure(401)) and "http" not in str(ModelStatusFailure(401)).lower())
    check("transport_failure_names_no_url", "api.openai.com" not in str(ModelTransportFailure("ConnectError")))

    # ── the history window ────────────────────────────────────────────────
    def row(row_id: int, role: str, content: str, age_ms: int) -> Dict[str, Any]:
        return {"id": row_id, "role": role, "content": content, "ts_ms": now_value - age_ms, "credits_charged": 5}

    newest_first = [
        row(10, "assistant", "answer 4", 100),
        row(9, "user", "question 4", 200),
        row(8, "assistant", "answer 3", 300),
        row(7, "user", "question 3", 400),
        row(6, "system", "scaffolding", 500),
        row(5, "assistant", "answer 2", 600),
        row(4, "user", "question 2", 700),
        row(3, "assistant", "   ", 800),
        row(2, "user", "question 1", 900),
        row(1, "user", "outside the window", 400_000),
    ]
    history = select_history(newest_first, now_value=now_value, window_seconds=300, limit=10, before_id=11)
    check(
        "history_is_oldest_first",
        [m["content"] for m in history]
        == ["question 1", "question 2", "answer 2", "question 3", "answer 3", "question 4", "answer 4"],
    )
    check("history_alternates_by_id", [m["role"] for m in history] == ["user", "user", "assistant", "user", "assistant", "user", "assistant"])
    check("history_excludes_the_row_being_answered", all(m["content"] != "the current turn" for m in history))
    check("history_excludes_system_rows", all("scaffolding" != m["content"] for m in history))
    check("history_excludes_blank_rows", all(m["content"].strip() for m in history))
    check("history_excludes_rows_outside_the_window", all(m["content"] != "outside the window" for m in history))
    check("history_count", len(history) == 7)
    capped = select_history(newest_first, now_value=now_value, window_seconds=300, limit=2, before_id=11)
    check("history_cap_keeps_the_NEWEST_n", [m["content"] for m in capped] == ["question 4", "answer 4"])
    check("history_order_after_the_cap", capped[0]["role"] == "user" and capped[1]["role"] == "assistant")
    check("history_limit_zero_forgets_everything", select_history(newest_first, now_value=now_value, window_seconds=300, limit=0) == [])
    check("history_excludes_the_notice_text", "answer 4" not in [m["content"] for m in select_history(newest_first, now_value=now_value, window_seconds=300, limit=10, before_id=11, exclude_content="answer 4")])
    check("history_waits_for_a_valid_id", all(m["content"] != "answer 4" for m in select_history(newest_first, now_value=now_value, window_seconds=300, limit=10, before_id=10)))
    check("history_survives_a_garbage_id", len(select_history([{"id": "x", "role": "user", "content": "hi", "ts_ms": now_value}], now_value=now_value, window_seconds=300, limit=5, before_id=11)) == 1)
    check("history_roles_are_conversational", all(m["role"] in ("user", "assistant") for m in history))
    check("history_empty_input", select_history([], now_value=now_value, window_seconds=300, limit=10) == [])

    messages = build_model_messages("SYS", [{"role": "user", "content": "q"}, {"role": "assistant", "content": "a"}], "now")
    check("messages_start_with_the_system_prompt", messages[0] == {"role": "system", "content": "SYS"})
    check("messages_end_with_the_current_question", messages[-1] == {"role": "user", "content": "now"})
    check("messages_are_in_order", [m["role"] for m in messages] == ["system", "user", "assistant", "user"])
    check("messages_drop_an_unknown_role", len(build_model_messages("S", [{"role": "tool", "content": "x"}], "q")) == 2)
    check("messages_drop_blank_history", len(build_model_messages("S", [{"role": "user", "content": "  "}], "q")) == 2)
    check("messages_strip_markers_from_history", ECO_MARKER not in build_model_messages("S", [{"role": "user", "content": ECO_MARKER + "x"}], "q")[1]["content"])
    check("messages_clamp_a_long_history_row", len(build_model_messages("S", [{"role": "user", "content": "x" * 5000}], "q")[1]["content"]) == HISTORY_ROW_MAX_CHARS)
    check("messages_clamp_a_long_question", len(build_model_messages("S", [], "x" * 20_000)[-1]["content"]) == MAX_USER_TEXT_CHARS)
    check("messages_with_no_system_prompt", build_model_messages("", [], "q") == [{"role": "user", "content": "q"}])
    check("messages_with_an_empty_question", build_model_messages("S", [{"role": "user", "content": "a"}], "  ") == [{"role": "system", "content": "S"}, {"role": "user", "content": "a"}])

    payload = build_request_payload(cfg, messages)
    check("request_body_is_the_four_documented_keys", sorted(payload) == ["max_tokens", "messages", "model", "temperature"])
    check("request_body_carries_the_model", payload["model"] == "db-model" and payload["messages"][0]["role"] == "system")
    check("request_body_numbers_are_numbers", isinstance(payload["max_tokens"], int) and isinstance(payload["temperature"], float))

    # ── transcript rendering ──────────────────────────────────────────────
    text = render_transcript(contact_id=7, rows=[row(1, "user", "第一行\n第二行", 1000), row(2, "assistant", "好", 500)], generated_ms=now_value, service_name="测试号")
    check("transcript_names_the_contact", "contact_id: 7" in text)
    check("transcript_counts_messages", "messages: 2" in text)
    check("transcript_totals_the_credits", "credits_charged_total: 10" in text)
    check("transcript_labels_the_roles", "] 访客: 第一行" in text and "] 服务号: 好" in text)
    check("transcript_indents_a_continuation_line", "\n        第二行\n" in text)
    check("transcript_keeps_every_line_of_a_multiline_turn", "第一行" in text and "第二行" in text)
    check("transcript_states_the_zone", "generated_utc" in text)
    check("transcript_of_nothing_is_still_a_document", "messages: 0" in render_transcript(contact_id=1, rows=[], generated_ms=now_value))
    check("transcript_has_no_api_key", "sk-" not in text)
    check("transcript_is_a_string_ending_in_a_newline", text.endswith("\n"))
    solo = render_transcript(contact_id=7, rows=[row(1, "user", "一行", 1000)], generated_ms=now_value)
    check("transcript_gives_a_single_line_turn_one_line", len([ln for ln in solo.split("\n") if "访客" in ln]) == 1 and solo.rstrip("\n").split("\n")[-1].endswith("访客: 一行"))
    check("transcript_emits_no_whitespace_only_body_line", all(ln.strip() for ln in solo.split("---", 1)[1].split("\n") if ln != ""))

    return checks
