# Copyright (c) 2026 POPOPX (popopx.chat)
# SPDX-License-Identifier: AGPL-3.0-only
"""Polls: one question, at most four options, and a bar that moves in place.

The lifecycle this module implements

1. **create** — a merchant POSTs `{question, options[], mode, multi, ends_at_ms?, targets[]}`.
   The question becomes the card title, the options become the card's buttons, and the
   row lands in `polls` before anything is sent.
2. **fan-out** — exactly one card per *explicitly named* follower, delivered through
   `deps.eco.deliver_card`, which is what charges the `card` meter. Empty `targets`
   means nobody: a poll is an unrequested message to every follower, so the recipient
   list is an argument, never a default.
3. **vote** — the phone taps a `callback` action and `::CB::poll:vote:<poll_id>:<index>`
   arrives as `callback.kind == "card_callback"`. `handle_inbound` claims the `poll:`
   prefix and refuses everything else so the alert plugin and the merchant handler get
   their own traffic.
4. **progress** — the *voter's own* card is re-delivered in place with the new tally.
   Other followers' cards are deliberately not touched (see `_safe_update`, and the
   arithmetic behind `POST /{poll_id}/refresh`).
5. **close** — `closed = 1`, and every card gets its final tally plus an `et` in the
   past, which is the only mechanism the client actually has for retiring buttons.

Two correctness decisions, stated up front because they are the two places a
plausible-looking implementation is wrong.

**Vote dedupe happens inside one transaction.** A count-then-insert lets two
concurrent callbacks from the same follower both pass the count, so `handle_inbound`
takes `deps.db.transaction(immediate=True)` — `BEGIN IMMEDIATE` acquires the write
lock at BEGIN, not at the first write — and does *read existing row, decide, write,
re-tally* inside it. The tally the card shows is therefore the tally of the same
snapshot that the vote was written into, never a later one. The DDL also carries
`UNIQUE (poll_id, contact_id)` on `poll_votes`, which contradicts the brief's premise
that no such constraint exists; that constraint is a second line of defence for the
single-choice case and, because it forbids one row per option, it is also the reason
`multi` polls store their selection as a bitmask in `choice_index` rather than as
several rows. See `decide_vote_write`.

**A counted vote and a charged vote do not diverge silently.** The `poll` meter is
charged per counted vote with `idempotency_key = "poll:<poll_id>:<contact_id>"`
(`":<index>"` appended when `multi`), so a replayed `::CB::` line costs 0 CP and adds
0 rows. The order is charge → write, and the write re-checks the poll's state under
the write lock: if the poll closed or vanished between the two, the vote is *not*
counted and the charge is refunded with a distinct `":refund"` key, so the ledger and
`poll_votes` agree in every outcome. Refunds are issued only for that terminal case —
after an unexpected failure the original charge is left in place so the follower's
retry replays the existing key instead of paying twice. Refusing to count is also
never silent: the callback still answers (so the phone unlocks the button) and the
voter's own card carries the reason in its `progress.d` line.

What the shared schema actually gives this plugin, and what it does not (gaps are
reported, not patched): `polls` has no `status` column (only `closed`), no
`targets`/`roster` column, exactly one `card_id` for what is an N-card fan-out, and a
`mode` CHECK that accepts `'identified'` but not the brief's `'signed'`. `poll_votes`
unions on `(poll_id, contact_id)`, not on `(poll_id, contact_id, choice_index)`.

The wire limits this module refuses to exceed are the client's, not the gateway's
taste: `apps/ios/Shared/Features/ServiceAccount/PopopxEcoModels.swift:48-72`
(cardId 64, title 120, body 2000, label 80, value 240, payload 512, url 2048, ≤8
fields, **≤4 actions**, progress percent 0..100), enforced by
`PopopxServiceCard.isSane` (`PopopxEcoModels.swift:524-538`) and
`PopopxEcoStore.apply` (`PopopxEcoRouterAndDeepLink.swift:149`), which drops a card
that violates any of them *silently*. A poll with five options is therefore not an
error the phone reports; it is a poll nobody ever sees.
"""

from __future__ import annotations

import json
import re
import secrets
import sqlite3
import time
from typing import TYPE_CHECKING, Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

from app.billing_service import BillingError
from app.crypto_service import (
    EcoError,
    EcoLimits,
    build_action,
    build_card,
    now_ms,
)
from app.plugins import PluginUnavailable

if TYPE_CHECKING:  # types only: fastapi is not importable in this build
    from fastapi import APIRouter

    from app.agent_bridge import InboundMessage
    from app.plugins import PluginDeps

__all__ = [
    "PLUGIN_ID",
    "PollInputError",
    "claims_poll_payload",
    "parse_vote_payload",
    "render_vote_payload",
    "compute_tally",
    "create_router",
    "handle_inbound",
    "self_test",
]

PLUGIN_ID = "polls"

# ─────────────────────────────────────────────────────────────────────────────
# 1. The client's surface, as numbers and citations
# ─────────────────────────────────────────────────────────────────────────────

CLIENT_LIMITS = "PopopxEcoModels.swift:48-72"
CLIENT_CARD_SANE = "PopopxEcoModels.swift:524-538"
CLIENT_PROGRESS = "PopopxEcoModels.swift:572-595"
CLIENT_ACTION_SANE = "PopopxEcoModels.swift:685-702"
CLIENT_STORE = "PopopxEcoRouterAndDeepLink.swift:149"
CLIENT_MERGE = "PopopxEcoRouterAndDeepLink.swift:181-193"
CLIENT_EXPIRY = "ServiceCardBubbleView.swift:117-131"

#: `PopopxEcoLimits.maximumActions` (PopopxEcoModels.swift:60). Every option needs a
#: button, so this *is* the option cap. Not configurable, not raiseable by a setting:
#: a tunable that could produce an undeliverable payload is a bug with a config file.
MAX_OPTIONS = EcoLimits.max_actions
#: One option is not a vote, it is an announcement, and it makes the word "poll" a lie
#: in the merchant's own console. Two is the floor the product means.
MIN_OPTIONS = 2
#: An option's title travels as `PopopxEcoAction.title`, capped by
#: `maximumLabelCharacters` (PopopxEcoModels.swift:55, checked at :686).
OPTION_TITLE_CHARS = EcoLimits.field_label_chars
QUESTION_CHARS = EcoLimits.card_title_chars
BODY_CHARS = EcoLimits.card_body_chars
PROGRESS_LABEL_CHARS = EcoLimits.field_label_chars      # Progress.isSane, :591
PROGRESS_DETAIL_CHARS = EcoLimits.field_value_chars     # Progress.isSane, :593
FIELD_VALUE_CHARS = EcoLimits.field_value_chars         # Field.isSane, :567
VOTE_PAYLOAD_CHARS = EcoLimits.payload_chars            # action payload, :691
MAX_FIELDS = EcoLimits.max_fields                       # :530

#: `poll_id` is TEXT in the DDL but the payload grammar the brief fixes
#: (`poll:vote:<poll_id>:<index>`) and the declared pure-parser signature
#: (`Optional[Tuple[int, int]]`) are numeric, so ids are minted as canonical decimal
#: strings and `str(int(id)) == id` holds. 18 digits = a 13-digit ms clock plus a
#: 5-digit random suffix.
POLL_ID_MAX_DIGITS = 18
_VOTE_RE = re.compile(r"poll:vote:(0|[1-9][0-9]{0,%d}):(0|[1-9][0-9]?)" % (POLL_ID_MAX_DIGITS - 1))
_CANONICAL_DIGITS_RE = re.compile(r"\A(?:0|[1-9][0-9]{0,%d})\Z" % (POLL_ID_MAX_DIGITS - 1))

CLAIM_PREFIX = "poll"
VOTE_INFIX = "poll:vote:"

#: The DDL's `mode` CHECK is `('anonymous','identified')` (app/database.py:349-350).
#: The API name in the brief is `signed`. The mapping is the whole adaptation: nothing
#: else in this module knows the storage spelling.
MODE_ANONYMOUS = "anonymous"
MODE_SIGNED = "signed"
_MODE_STORE = {"anonymous": "anonymous", "signed": "identified", "identified": "identified"}
_MODE_API = {"anonymous": MODE_ANONYMOUS, "identified": MODE_SIGNED}

CARD_STYLE = "standard"

# Copy is server-authored because the client renders these strings verbatim
# (`Text(verbatim:)`, ServiceCardBubbleView.swift:294-301) — no localization table on
# the phone can rewrite a payload it never interprets.
NOTE_ANONYMOUS = "匿名投票：只公布各选项票数与占比，不公布投票人。"
NOTE_SIGNED = "实名投票：选项票数与投票人一并公布。"
NOTE_CLOSED = "已截止"
NOTE_MULTI = "可多选"
NOTE_SINGLE = "单选"
NOTE_DEADLINE = "截止"
NOTE_NO_VOTES = "尚无投票"
NOTE_VOTES = "票"
NOTE_LEADING = "领先"
NOTE_EXPIRED_DETAIL = "已截止 · %s"
NOTE_NOT_COUNTED_BILLING = "投票未计入：服务号余额不足，请稍后再试"
NOTE_NOT_COUNTED_CLOSED = "投票未计入：投票已截止"
ACTION_CLOSED_TITLE = NOTE_CLOSED
CLOSED_LABEL_SUFFIX = " · " + NOTE_CLOSED

#: Tunables. There is no poll field in `app/config.py`, so `settings` is the only
#: legitimate home. Both may only *tighten* a bound; neither can widen one, and
#: neither touches anything the client measures.
SETTING_MAX_TARGETS = "polls.max_targets"
SETTING_RESULTS_MAX_VOTERS = "polls.results_max_voters"
DEFAULT_MAX_TARGETS = 500
DEFAULT_RESULTS_MAX_VOTERS = 200
ROSTER_SETTING_PREFIX = "polls:"
ROSTER_SETTING_SUFFIX = ":roster"


class PollInputError(Exception):
    """A request this plugin will not serve, with the client rule that forces it.

    Deliberately not an `EcoError`: the gateway's codec complains about a payload it
    was handed, while this complains about a *poll* that could never be shown. It is
    raised by pure functions so `self_test` can assert on the wording without
    FastAPI, and the routes translate it 1:1 into a 4xx.
    """

    def __init__(self, code: str, message: str, *, http_status: int = 400) -> None:
        super().__init__("%s: %s" % (code, message))
        self.code = code
        self.message = message
        self.http_status = int(http_status)


# ─────────────────────────────────────────────────────────────────────────────
# 2. The payload grammar (pure)
# ─────────────────────────────────────────────────────────────────────────────


def claims_poll_payload(payload: Any) -> bool:
    """Whether a `card_callback` payload belongs to this plugin.

    The claim is on the `poll:` prefix alone, so a malformed poll payload is still
    consumed: falling through to the alert plugin or an AI because of a typo in one of
    *our* payloads would put a chat reply where a vote was recorded.
    """
    if not isinstance(payload, str):
        return False
    text = payload.strip()
    return text == CLAIM_PREFIX or text.startswith(CLAIM_PREFIX + ":")


def parse_vote_payload(payload: Any) -> Optional[Tuple[int, int]]:
    """`poll:vote:<poll_id>:<index>` → `(poll_id, index)`, else None. Never raises.

    Strict on purpose, and every refusal below is a case where a looser parser would
    silently move a vote to a different option:

    * `fullmatch`, not `search`/`match` + `$`: `$` also matches before a trailing
      newline, so `"poll:vote:1:0\\n"` would otherwise count as option 0 of poll 1.
    * canonical decimal only — no sign, no whitespace, no underscore, no leading zero
      (`int()` accepts all four, and `"01"` would resolve to a poll that `"1"` already
      owns), and `[0-9]` is a class, so `int()`'s tolerance of Arabic-Indic digits
      cannot leak in.
    * exactly four segments: a fifth is a payload someone built by concatenation.
    """
    if not isinstance(payload, str):
        return None
    match = _VOTE_RE.fullmatch(payload)
    if match is None:
        return None
    return (int(match.group(1)), int(match.group(2)))


def render_vote_payload(poll_id: Any, index: int) -> str:
    """The payload for one option button. `parse_vote_payload(render_*(...)) == (id, i)`.

    The round-trip is not a nicety: the phone sends this string back verbatim after
    `::CB::` (PopopxEcoRouterAndDeepLink.swift:494-498), so anything that survives
    `str` → wire → `parse` is a vote we can attribute; anything that does not is a
    button that silently does nothing.
    """
    text = str(poll_id)
    if not _CANONICAL_DIGITS_RE.match(text):
        raise PollInputError("poll_id_invalid", "poll id %r is not 1..%d canonical digits" % (poll_id, POLL_ID_MAX_DIGITS))
    if isinstance(index, bool) or not isinstance(index, int) or index < 0 or index > 99:
        raise PollInputError("option_index_invalid", "option index %r is outside 0..99" % (index,))
    payload = "%s%s:%d" % (VOTE_INFIX, text, index)
    if len(payload) > VOTE_PAYLOAD_CHARS:
        raise PollInputError(
            "option_index_invalid",
            "vote payload is %d characters over the client's action payload cap of %d (%s)"
            % (len(payload), VOTE_PAYLOAD_CHARS, CLIENT_LIMITS),
        )
    return payload


def mint_poll_id(now_value: int) -> str:
    """18 canonical digits: a millisecond clock plus 10^5 of randomness.

    Numeric because the payload grammar is (`parse_vote_payload` returns ints); the
    clock prefix makes ids roughly ordered for the console and the suffix makes a
    same-millisecond collision a 1-in-100000 event, which the create route retries on
    the `polls` primary key.
    """
    if isinstance(now_value, bool) or not isinstance(now_value, int) or now_value < 0:
        now_value = int(now_ms())
    return "%d%05d" % (now_value, secrets.randbelow(100000))


def card_id_for(poll_id: Any, contact_id: int) -> str:
    """The deterministic card id of one follower's copy of one poll.

    Deterministic because the schema gives `polls` a single `card_id` column for an
    N-card fan-out, so an id recomputed from `(poll_id, contact_id)` is the one piece
    of the roster that cannot be lost — the `settings` roster and `cards.topic` are
    extra copies of the same fact, not the authority. Capped at
    `maximumCardIdCharacters` (PopopxEcoModels.swift:52, checked at :526) because an
    over-long id deletes the card, not the id.
    """
    if isinstance(contact_id, bool) or not isinstance(contact_id, int) or contact_id < 0:
        raise PollInputError("contact_id_invalid", "contact id %r is not a non-negative integer" % (contact_id,))
    text = "poll-%s-%d" % (str(poll_id), contact_id)
    if len(text) > EcoLimits.card_id_chars:
        raise PollInputError(
            "card_id_too_long",
            "card id %r is %d characters over the client cap of %d (%s)"
            % (text, len(text), EcoLimits.card_id_chars, CLIENT_LIMITS),
        )
    return text


def topic_for(poll_id: Any) -> str:
    """The `cards.topic` this plugin stamps, so a later refresh can find its cards."""
    return "%s:%s" % (CLAIM_PREFIX, str(poll_id))


def idempotency_key_for_vote(poll_id: Any, contact_id: int, multi: bool, index: int) -> str:
    """The billing key of one counted vote.

    `poll:<poll_id>:<contact_id>` for single-choice — the identity of a vote there is
    the pair, so a second tap on any option replays to 0 CP. `multi` appends the
    option, because each additional selection is a separate human action and should be
    priced once and only once.

    All three fields are canonical digits, so the `:` separator cannot be confused
    across a boundary: `(1, 23)` and `(12, 3)` — the collision a naive join produces —
    yield different keys, which `self_test` asserts directly.
    """
    key = "%s:%s:%d" % (CLAIM_PREFIX, str(poll_id), int(contact_id))
    if multi:
        key = "%s:%d" % (key, int(index))
    return key


# ─────────────────────────────────────────────────────────────────────────────
# 3. Input validation (pure)
# ─────────────────────────────────────────────────────────────────────────────


def validate_question(question: Any) -> str:
    """The question is the card title: 1..120 characters, non-whitespace."""
    if not isinstance(question, str):
        raise PollInputError("question_type", "question must be a string, got %s" % type(question).__name__)
    text = question.strip()
    if not text:
        raise PollInputError("question_empty", "question must not be empty or whitespace")
    if len(text) > QUESTION_CHARS:
        raise PollInputError(
            "question_too_long",
            "question is %d characters: the client caps a card title at %d (%s, %s), so a longer "
            "question is not truncated on the phone, it is never rendered"
            % (len(text), QUESTION_CHARS, CLIENT_LIMITS, CLIENT_CARD_SANE),
        )
    return text


def normalise_options(raw: Any) -> List[str]:
    """Validate the option list against the client, refusing rather than trimming.

    The load-bearing branch is the count: a fifth option cannot be rendered
    (`maximumActions`, PopopxEcoModels.swift:60) and a card that carries five actions
    fails `isSane` at :533, so `PopopxEcoStore.apply` rejects the *whole* card
    (PopopxEcoRouterAndDeepLink.swift:149). Truncating to four would quietly drop one
    candidate — a voter would never learn a choice existed, and the merchant would
    never learn a candidate vanished. That is the worst failure this plugin can have,
    so it is a 400 that names the limit.
    """
    if isinstance(raw, (str, bytes)) or not isinstance(raw, (list, tuple)):
        raise PollInputError("options_type", "options must be a JSON array of strings")
    items = list(raw)
    if not items:
        raise PollInputError("options_empty", "a poll needs at least %d options, got 0" % MIN_OPTIONS)
    if len(items) < MIN_OPTIONS:
        raise PollInputError(
            "options_too_few",
            "a poll needs at least %d options, got %d; one option is an announcement, not a vote"
            % (MIN_OPTIONS, len(items)),
        )
    if len(items) > MAX_OPTIONS:
        raise PollInputError(
            "options_too_many",
            "%d options exceed the client's hard cap of %d actions per card "
            "(PopopxEcoLimits.maximumActions, %s — %s). A card with %d actions fails "
            "PopopxServiceCard.isSane and PopopxEcoStore drops it whole (%s), so the phone shows "
            "no poll at all. Options are never truncated to fit: silently deleting a candidate is "
            "worse than refusing the poll. Split the question into two polls, or list the extra "
            "candidates in an H5 page reached from the results."
            % (len(items), MAX_OPTIONS, CLIENT_LIMITS, CLIENT_CARD_SANE, len(items), CLIENT_STORE),
        )

    seen: Dict[str, int] = {}
    out: List[str] = []
    for position, item in enumerate(items):
        if not isinstance(item, str):
            raise PollInputError(
                "option_type", "option %d is %s; every option must be a string" % (position, type(item).__name__)
            )
        text = item.strip()
        if not text:
            raise PollInputError("option_empty", "option %d is empty or whitespace" % position)
        if len(text) > OPTION_TITLE_CHARS:
            raise PollInputError(
                "option_too_long",
                "option %d is %d characters: an option is a card action title, capped at %d "
                "(%s; enforced by PopopxEcoAction.isSane, %s)"
                % (position, len(text), OPTION_TITLE_CHARS, CLIENT_LIMITS, CLIENT_ACTION_SANE),
            )
        # Two spellings of one candidate map to one vote the merchant cannot attribute.
        key = text.casefold()
        if key in seen:
            raise PollInputError(
                "option_duplicate",
                "option %d duplicates option %d (%r); duplicate choices make a vote ambiguous and "
                "the client requires distinct ids within a card (%s)" % (position, seen[key], text, CLIENT_CARD_SANE),
            )
        seen[key] = position
        out.append(text)
    return out


def normalise_mode(raw: Any) -> str:
    """`anonymous` | `signed` → the API spelling, `identified` accepted as a synonym.

    `polls.mode` CHECK-lists `'identified'`, not `'signed'` (app/database.py:349-350),
    so the store/API vocabularies differ and `_MODE_STORE` is the only seam.
    """
    if raw is None:
        return MODE_ANONYMOUS
    if not isinstance(raw, str):
        raise PollInputError("mode_type", "mode must be a string, got %s" % type(raw).__name__)
    key = raw.strip().lower()
    if key not in _MODE_STORE:
        raise PollInputError(
            "mode_unknown",
            "mode %r is not one of %s" % (raw, sorted({"anonymous", "signed", "identified"})),
        )
    return _MODE_API[_MODE_STORE[key]]


def store_mode(mode: str) -> str:
    """The value `polls.mode` will accept for this API mode."""
    return _MODE_STORE[mode]


def api_mode(stored: Any) -> str:
    """The API name of a stored mode, defaulting to the schema's own default."""
    return _MODE_API.get(str(stored or "anonymous"), MODE_ANONYMOUS)


def validate_targets(raw: Any, max_targets: int) -> List[int]:
    """An explicit follower list, de-duplicated, order preserved.

    `None`/`[]` is a *valid* answer meaning "nobody", and it must stay that way: the
    alternative — fan out to every contact when the caller named none — turns one API
    call into an unbounded number of metered `card` charges and an unrequested message
    to everyone the account has ever met. The caller pays for the list it writes.
    """
    if raw is None:
        return []
    if isinstance(raw, (str, bytes)) or not isinstance(raw, (list, tuple)):
        raise PollInputError("targets_type", "targets must be a JSON array of contact ids")
    out: List[int] = []
    seen = set()
    for item in raw:
        if isinstance(item, bool) or not isinstance(item, int):
            raise PollInputError("targets_type", "target %r is not an integer contact id" % (item,))
        if item <= 0:
            # `contacts.contact_id` is the node's row id (app/database.py:86-87), which
            # is positive; a non-positive id is a client bug, never a follower.
            raise PollInputError("targets_type", "target %r is not a positive contact id" % (item,))
        if item in seen:
            continue
        seen.add(item)
        out.append(item)
    if len(out) > max_targets:
        raise PollInputError(
            "targets_too_many",
            "%d targets exceeds the configured cap of %d (setting %r): each one is a metered card"
            % (len(out), max_targets, SETTING_MAX_TARGETS),
            http_status=413,
        )
    return out


def validate_ends_at_ms(raw: Any, now_value: int) -> Optional[int]:
    """A deadline in the future, or none. `None` means the card stays live forever."""
    if raw is None:
        return None
    if isinstance(raw, bool) or not isinstance(raw, int):
        raise PollInputError("ends_at_type", "ends_at_ms must be an integer number of milliseconds")
    if raw < 1:
        raise PollInputError("ends_at_range", "ends_at_ms must be positive, got %d" % raw)
    if raw <= now_value:
        raise PollInputError(
            "ends_at_past",
            "ends_at_ms %d is not after now (%d): the poll would open already closed, and the "
            "client renders its buttons inert the moment `et` is in the past (%s)"
            % (raw, now_value, CLIENT_EXPIRY),
        )
    return raw


# ─────────────────────────────────────────────────────────────────────────────
# 4. State and eligibility (pure)
# ─────────────────────────────────────────────────────────────────────────────


def poll_state(row: Mapping[str, Any], now_value: int) -> str:
    """`closed` | `expired` | `open` — derived, because `polls` has no status column.

    `closed` wins over `expired`: an explicit close is a decision the merchant made
    and it must remain readable as such after the deadline passes.
    """
    if int(row.get("closed") or 0):
        return "closed"
    ends = row.get("ends_at_ms")
    if ends is not None and now_value > int(ends):
        return "expired"
    return "open"


def vote_gate(row: Optional[Mapping[str, Any]], index: int, now_value: int) -> Optional[str]:
    """Why this vote may not be counted, or None if it may.

    Reads only what `handle_inbound` has already loaded, so the same function can
    check the row before the charge and again under the write lock.
    """
    if row is None:
        return "poll_not_found"
    state = poll_state(row, now_value)
    if state == "closed":
        return "poll_closed"
    if state == "expired":
        return "poll_expired"
    options = row.get("options") or []
    if not isinstance(index, int) or isinstance(index, bool):
        return "option_index_type"
    if index < 0 or index >= len(options):
        return "option_out_of_range"
    return None


#: Reasons `vote_gate` refuses after the vote was already charged. Terminal for this
#: poll: no retry can turn them into an acceptance, which is what makes refunding safe.
TERMINAL_GATE_REFUSALS = ("poll_not_found", "poll_closed", "poll_expired")


def is_open(row: Mapping[str, Any], now_value: int) -> bool:
    return poll_state(row, now_value) == "open"


# ─────────────────────────────────────────────────────────────────────────────
# 5. Vote storage (pure)
# ─────────────────────────────────────────────────────────────────────────────


def stored_value_for_choice(multi: bool, index: int) -> int:
    """What goes in `poll_votes.choice_index` for a first vote of `index`.

    Single-choice stores the option index, so an operator reading the table (or a
    `GROUP BY choice_index` in a console) sees what the column name promises.
    Multi-choice stores a bitmask instead, because `UNIQUE (poll_id, contact_id)`
    (app/database.py:365) makes a second row for the same follower an integrity error:
    one row per (follower, option) — the design the brief names — is not a shape this
    schema can hold. The poll's own `multi` column says which encoding a row uses, so
    the decode is unambiguous here.
    """
    if isinstance(index, bool) or not isinstance(index, int) or index < 0:
        raise PollInputError("option_index_invalid", "option index %r is not a non-negative integer" % (index,))
    if multi:
        return 1 << index
    return index


def choice_indexes_for_stored(multi: bool, stored: Any) -> Tuple[int, ...]:
    """The inverse of :func:`stored_value_for_choice`, as an ordered tuple.

    Never raises: a row written by anything else is data to interpret, and the tally
    is the place that decides whether an index is real.
    """
    try:
        value = int(stored)
    except (TypeError, ValueError):
        return ()
    if value < 0:
        return ()
    if not multi:
        return (value,)
    return tuple(bit for bit in range(63) if value & (1 << bit))


def decide_vote_write(multi: bool, existing: Any, index: int) -> Tuple[str, Optional[int]]:
    """`(verb, new_stored_value)` for one tap, given the follower's current row.

    The dedupe predicate, isolated so it is testable without SQLite:

    * single-choice, no row → `("insert", index)`.
    * single-choice, any row → `("replay", None)`. A second tap is not a changed vote:
      `poll_votes` keeps at most one row per `(poll_id, contact_id)` and the vote's
      identity is that pair, so overwriting it would rewrite history the merchant has
      already reported. The callback is answered as a replay.
    * multi, no row → `("insert", 1 << index)`.
    * multi, row already carrying that bit → `("replay", None)`: the same option
      twiced, worth neither a second count nor a second charge.
    * multi, row without that bit → `("update", existing | bit)`.
    """
    if existing is None:
        return ("insert", stored_value_for_choice(multi, index))
    try:
        stored = int(existing)
    except (TypeError, ValueError):
        return ("replay", None)
    if not multi:
        return ("replay", None)
    bit = 1 << index
    if stored & bit:
        return ("replay", None)
    if stored < 0:
        # A row this module did not write; refuse to widen it with a guess.
        return ("replay", None)
    return ("update", stored | bit)


def _row_field(row: Any, key: str = "choice_index") -> Any:
    """One named column of a vote or card row, whatever shape the row arrived in.

    `sqlite3.Row` is neither a `Mapping` nor a `tuple`, so the subscript path is tried
    last rather than first; getting this wrong would read every vote as garbage and
    report a poll with 3 votes as 0, which is a *silent* wrong number.
    """
    if isinstance(row, Mapping):
        return row.get(key, row.get("stored"))
    if isinstance(row, (tuple, list)):
        return row[-1] if row else None
    try:
        return row[key]
    except (KeyError, IndexError, TypeError, ValueError):
        return row


def _contact_of(row: Any) -> Any:
    if isinstance(row, Mapping):
        return row.get("contact_id")
    if isinstance(row, (tuple, list)):
        return row[0] if row else None
    try:
        return row["contact_id"]
    except (KeyError, IndexError, TypeError, ValueError):
        return None


def decode_votes(rows: Iterable[Any], multi: bool) -> List[int]:
    """`(contact_id, choice_index)` pairs (or bare values) → one option index per selection."""
    out: List[int] = []
    for row in rows:
        for index in choice_indexes_for_stored(multi, _row_field(row)):
            out.append(index)
    return out


def voter_choices(rows: Iterable[Any], multi: bool, option_count: int) -> Dict[int, List[int]]:
    """contact id → the options that follower selected, for their own card."""
    out: Dict[int, List[int]] = {}
    for row in rows:
        contact_id = _as_int(_contact_of(row))
        if contact_id is None:
            continue
        chosen = out.setdefault(contact_id, [])
        for index in choice_indexes_for_stored(multi, _row_field(row)):
            if 0 <= index < option_count and index not in chosen:
                chosen.append(index)
    for indexes in out.values():
        indexes.sort()
    return out


# ─────────────────────────────────────────────────────────────────────────────
# 6. The tally, and percentages that sum to exactly 100 (pure)
# ─────────────────────────────────────────────────────────────────────────────


def distribute_percentages(counts: Sequence[int], total: int) -> List[int]:
    """Integer percentages summing to exactly 100, by largest remainder.

    Rule, written down because "just round it" is not one:
      1. floor each option's exact share with integer arithmetic
         (`q, r = divmod(count * 100, total)`) — no float, so no platform-dependent
         banker's rounding and no `0.1 + 0.2` residue;
      2. hand the `100 - sum(q)` leftover points to the options with the largest
         remainder `r`, breaking ties by the *lowest option index*.

    The tie-break is the part that makes the numbers reproducible: two options with
    equal remainders and one point left is a decision someone has to be able to
    re-derive from the counts alone, a year later, from a CSV.

    Rounding each share independently — the shape of least resistance here — does not
    sum to 100. 1/1/1: round(33.33) three times is 99. 2/2/3 of 7: 29+28+43 is 100 by
    luck, but round(28.571)=29 twice and round(42.857)=43 is 101; 4/4/3 of 11 gives
    36+36+27 = 99. Both directions are asserted in `self_test`.
    """
    if total <= 0:
        return [0 for _ in counts]
    floors: List[int] = []
    remainders: List[int] = []
    for count in counts:
        share, rest = divmod(int(count) * 100, total)
        floors.append(share)
        remainders.append(rest)
    short = 100 - sum(floors)
    # Deterministic order: biggest remainder first, then lowest index. `short` is in
    # practice 0..len(counts)-1 because every floor loses strictly less than 1.
    order = sorted(range(len(counts)), key=lambda i: (-remainders[i], i))
    position = 0
    while short > 0 and position < len(order):
        floors[order[position]] += 1
        short -= 1
        position += 1
    return floors


def compute_tally(rows: Iterable[Any], options: Sequence[Any]) -> Dict[str, Any]:
    """`{"counts": [...], "total": n, "percentages": [...]}`, index-aligned with `options`.

    Pure and total: no clock, no database, no exception for any input shape. A row
    whose index is negative, ≥ len(options) or not an int is counted **nowhere** —
    dropping it keeps `sum(counts) == total` true, which is what makes the card's
    arithmetic checkable by eye. Counting it in a bucket that does not exist would
    crash the render, and an unrenderable card is the failure this whole module is
    shaped around.
    """
    count = len(options)
    counts = [0 for _ in range(count)]
    total = 0
    for row in rows:
        index: Any = _row_field(row)
        if isinstance(index, bool):
            # `True` is not option 1. Silently coercing it would move a vote.
            continue
        if not isinstance(index, int):
            try:
                index = int(index)
            except (TypeError, ValueError):
                continue
        if 0 <= index < count:
            counts[index] += 1
            total += 1
    return {"counts": counts, "total": total, "percentages": distribute_percentages(counts, total)}


def leading_index(counts: Sequence[int]) -> Optional[int]:
    """The frontrunner, ties to the lowest index; None when nothing has been chosen."""
    best: Optional[int] = None
    for index, count in enumerate(counts):
        if count <= 0:
            continue
        if best is None or count > counts[best]:
            best = index
    return best


# ─────────────────────────────────────────────────────────────────────────────
# 7. Card content, cut to the client's measure (pure)
# ─────────────────────────────────────────────────────────────────────────────


def clip(text: str, limit: int) -> str:
    """At most `limit` characters, with an ellipsis inside the budget.

    The client counts grapheme clusters and Python counts code points; they agree for
    the BMP text a poll carries (`app/crypto_service.py:56-58` records the same
    reasoning), and where they cannot agree — a combining sequence or a ZWJ emoji split
    by this slice — the result is *fewer* graphemes than counted here, i.e. still
    inside the cap. Truncation is chosen over refusal for the tally lines because the
    alternative to a shortened `d` is a card nobody sees.
    """
    if limit <= 0:
        return ""
    if len(text) <= limit:
        return text
    if limit == 1:
        return "…"[:limit]
    return text[: limit - 1] + "…"


def format_deadline(ends_at_ms: Optional[int]) -> str:
    """`2026-11-21 15:30 UTC`, or an empty string when there is no deadline.

    UTC and `strftime` because a card is read on a phone in an unknown locale and this
    string is compared by eye against the bar's own movement; a locale-dependent
    format would make two followers of one poll see two different deadlines.
    """
    if ends_at_ms is None:
        return ""
    try:
        value = int(ends_at_ms)
    except (TypeError, ValueError):
        return ""
    if value <= 0:
        return ""
    return time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime(value / 1000.0))


def progress_for(
    tally: Mapping[str, Any],
    options: Sequence[str],
    *,
    closed: bool,
    ends_at_ms_value: Optional[int] = None,
    now_value: Optional[int] = None,
) -> Dict[str, str]:
    """The one bar a card has, showing the frontrunner's share of the vote.

    A `PopopxServiceCard.Progress` is a single label and a single percent
    (PopopxEcoModels.swift:572-581), so N options cannot each have a bar; the
    per-option breakdown goes in `fields` (see :func:`fields_for`), which the client
    renders as a grid above the same bar. Percent is the leader's share, so the bar
    animates on every vote — the motion is the point of an inline poll — and `d`
    carries the totals.

    The returned dict is already in wire form (`l`/`p`/`d`) and every value is inside
    the client's caps, so no caller has to re-measure it.
    """
    counts = list(tally.get("counts") or [])
    percentages = list(tally.get("percentages") or [])
    total = int(tally.get("total") or 0)
    leader = leading_index(counts) if counts else None
    if leader is None:
        label = NOTE_NO_VOTES if not closed else NOTE_CLOSED
        percent = 0
    else:
        share = percentages[leader] if leader < len(percentages) else 0
        label = "%s %s %d%%" % (NOTE_LEADING, clip(options[leader] if leader < len(options) else "", 40), int(share))
        percent = int(share)
    percent = max(EcoLimits.progress_percent_min, min(EcoLimits.progress_percent_max, percent))

    parts: List[str] = []
    if total:
        parts.append("%d %s" % (total, NOTE_VOTES))
    else:
        parts.append("0 %s" % (NOTE_VOTES,))
    if closed:
        parts.append(NOTE_CLOSED)
    else:
        deadline = format_deadline(ends_at_ms_value)
        if deadline:
            parts.append("%s %s" % (NOTE_DEADLINE, deadline))
        elif now_value is not None:
            parts.append(NOTE_NO_VOTES if total == 0 else "进行中")
    detail = " · ".join(parts)
    out: Dict[str, str] = {"l": clip(label, PROGRESS_LABEL_CHARS), "p": percent}
    detail = clip(detail, PROGRESS_DETAIL_CHARS)
    if detail:
        out["d"] = detail
    return out


def fields_for(
    tally: Mapping[str, Any],
    options: Sequence[str],
    *,
    multi: bool,
    mode: str,
    mine: Optional[Sequence[int]] = None,
    closed: bool = False,
) -> List[Dict[str, str]]:
    """One row per option (`"选项名" → "3 票 · 43%"`), plus the total, plus — on the
    voter's own card only — their own selection.

    `mine` is only ever supplied for the contact who just tapped, because a card is a
    pairwise message: marking that follower's choice on *their* bubble leaks nothing.
    Putting it on anyone else's card would be an anonymity breach with a payload to
    prove it, so the label says 仅你可见 and the caller (`_safe_update`) only ever
    renders a card to the follower whose id it is addressed to.
    """
    counts = list(tally.get("counts") or [])
    percentages = list(tally.get("percentages") or [])
    rows: List[Dict[str, str]] = []
    for index, option in enumerate(options):
        count = counts[index] if index < len(counts) else 0
        share = percentages[index] if index < len(percentages) else 0
        rows.append({"k": clip(option, EcoLimits.field_label_chars), "v": clip("%d %s · %d%%" % (int(count), NOTE_VOTES, int(share)), FIELD_VALUE_CHARS)})
    rows.append(
        {
            "k": clip("总票数%s" % ("（%s）" % (NOTE_MULTI if multi else NOTE_SINGLE) if multi else ""), EcoLimits.field_label_chars),
            "v": clip("%d %s" % (int(tally.get("total") or 0), NOTE_VOTES), FIELD_VALUE_CHARS),
            "mono": True,
        }
    )
    if mine:
        names = "、".join(clip(options[i], 40) for i in sorted(mine) if 0 <= i < len(options))
        if names:
            label = "你的选择" if mode != MODE_ANONYMOUS else "你的选择（仅你可见）"
            rows.append({"k": clip(label, EcoLimits.field_label_chars), "v": clip(names, FIELD_VALUE_CHARS)})
    if closed:
        rows.append({"k": "状态", "v": clip(NOTE_CLOSED, FIELD_VALUE_CHARS)})
    # 4 options + total + mine + status = 7 ≤ maximumActions' neighbour limit of 8
    # fields (PopopxEcoModels.swift:59, checked at :530). Trim from the front of the
    # option list rather than ship a card the store rejects.
    if len(rows) > MAX_FIELDS:
        rows = rows[-MAX_FIELDS:]
    return rows


def body_for(mode: str, multi: bool, ends_at_ms_value: Optional[int], options: Sequence[str]) -> str:
    """The card's note: what kind of vote this is, and until when."""
    parts = [mode == MODE_ANONYMOUS and NOTE_ANONYMOUS or NOTE_SIGNED, multi and NOTE_MULTI or NOTE_SINGLE]
    deadline = format_deadline(ends_at_ms_value)
    if deadline:
        parts.append("%s %s" % (NOTE_DEADLINE, deadline))
    parts.append("%d 个选项" % len(options))
    return clip(" · ".join(parts), BODY_CHARS)


def option_actions(poll_id: str, options: Sequence[str]) -> List[Dict[str, Any]]:
    """One `callback` button per option, ids unique within the card.

    `action_id` uniqueness is a client rule with a lethal failure mode
    (PopopxEcoModels.swift:535 → `Set(actions.map(\\.id)).count == actions.count`), and
    `crypto_service.build_card` re-checks it (`_assert_unique_action_ids`). The ids are
    positional (`opt0`..`opt3`) and stable across updates, which matters because the
    phone locks a button by `(cardId, actionId)` until the card changes
    (PopopxEcoRouterAndDeepLink.swift:57-59, 648-651).
    """
    actions: List[Dict[str, Any]] = []
    for index, option in enumerate(options):
        actions.append(
            build_action(
                action_id="opt%d" % index,
                title=clip(option, OPTION_TITLE_CHARS),
                kind="callback",
                style="primary" if index == 0 else "secondary",
                payload=render_vote_payload(poll_id, index),
            )
        )
    return actions


# NOTE ON "已截止" AS A BUTTON (requirement 5, decided against the client)
# The brief asks for the closed card to carry one `kind="none"` action reading 已截止.
# That payload cannot be shipped: `PopopxEcoAction.isSane` returns false for `.none`
# (PopopxEcoModels.swift:688-689, `case .none: return false`), `isSane` is required by
# the card's own `actions.allSatisfy(\\.isSane)` (:534), and `PopopxEcoStore.apply`
# answers `.rejected` for a card that is not sane (PopopxEcoRouterAndDeepLink.swift:149)
# — so a "disabled button" would delete the whole card from the phone, final tally
# included. `crypto_service.build_action` refuses it for the same reason
# (app/crypto_service.py:506-507). Nor can the buttons be *removed*: an update with an
# empty `actions` list means "unchanged" to the client (`PopopxEcoRouterAndDeepLink.swift:186`).
# The one mechanism the client does have is the card's deadline: past `et` the bubble
# drops every button (`ServiceCardBubbleView.swift:379`, `cardIsInert ? [] : …`), draws
# its own expired note (:325-326) and stops firing taps (:649). So close sets
# `expires_at_ms` to the closing instant and writes 已截止 into `progress.d` and a
# `状态` field, which is the visible outcome the requirement wanted, by the route the
# phone actually supports.
def closed_expires_at(now_value: int) -> int:
    """The `et` that retires a card's buttons: one millisecond past the close."""
    return max(1, int(now_value))


# ─────────────────────────────────────────────────────────────────────────────
# 8. Result rendering (pure) — the anonymity claim lives here
# ─────────────────────────────────────────────────────────────────────────────


def results_payload(
    poll: Mapping[str, Any],
    tally: Mapping[str, Any],
    *,
    choices_by_contact: Optional[Mapping[int, Sequence[int]]] = None,
    now_value: Optional[int] = None,
    max_voters: int = DEFAULT_RESULTS_MAX_VOTERS,
) -> Dict[str, Any]:
    """The results body for one poll, in its `mode`.

    In `anonymous` this returns counts, percentages and a total and **no contact id
    anywhere in it, in any code path** — not an empty `voters` key, not a hash, not a
    count-per-follower map that could be inverted. The guarantee is structural: the
    `choices_by_contact` argument is never even read unless the mode is `signed`, and
    `self_test` greps the serialised JSON for the fixture contact ids to prove it.
    This is the function the product's anonymity promise rests on, so it is the only
    place the decision is made; a route that built its own results body would be a
    second promise to keep.
    """
    options = list(poll.get("options") or [])
    mode = api_mode(poll.get("mode"))
    state = poll_state(poll, int(now_value if now_value is not None else now_ms()))
    out: Dict[str, Any] = {
        "ok": True,
        "poll_id": str(poll.get("poll_id") or ""),
        "mode": mode,
        "state": state,
        "multi": bool(poll.get("multi")),
        "question": poll.get("question") or "",
        "options": options,
        "counts": list(tally.get("counts") or [0 for _ in options]),
        "percentages": list(tally.get("percentages") or [0 for _ in options]),
        "total_votes": int(tally.get("total") or 0),
        "ends_at_ms": poll.get("ends_at_ms"),
        "created_at_ms": poll.get("created_at_ms"),
    }
    leader = leading_index(out["counts"])
    if leader is not None:
        out["leading_index"] = leader
    if mode == MODE_SIGNED:
        voters: List[Dict[str, Any]] = []
        for contact_id, indexes in sorted((choices_by_contact or {}).items()):
            for index in indexes:
                if 0 <= index < len(options):
                    voters.append({"contact_id": int(contact_id), "choice_index": int(index)})
            if len(voters) >= max_voters:
                break
        out["voters"] = voters[:max_voters]
        out["voters_truncated"] = len(choices_by_contact or {}) > max_voters
    return out


def poll_public(poll: Mapping[str, Any], tally: Mapping[str, Any], *, now_value: int, include_counts: bool = True) -> Dict[str, Any]:
    """The poll as the API shows it. Never carries a contact id, in either mode.

    (The roster of delivered cards is deliberately absent: in `anonymous` it would be
    the follower list, which is exactly the set the mode exists to protect.)
    """
    out: Dict[str, Any] = {
        "poll_id": str(poll.get("poll_id") or ""),
        "question": poll.get("question") or "",
        "options": list(poll.get("options") or []),
        "mode": api_mode(poll.get("mode")),
        "multi": bool(poll.get("multi")),
        "state": poll_state(poll, now_value),
        "closed": bool(int(poll.get("closed") or 0)),
        "ends_at_ms": poll.get("ends_at_ms"),
        "created_at_ms": poll.get("created_at_ms"),
        "total_votes": int(tally.get("total") or 0),
    }
    if include_counts:
        out["counts"] = list(tally.get("counts") or [])
        out["percentages"] = list(tally.get("percentages") or [])
    return out


# ─────────────────────────────────────────────────────────────────────────────
# 9. Row ↔ dict helpers (need no FastAPI, do touch SQLite)
# ─────────────────────────────────────────────────────────────────────────────


def _poll_from_row(row: Any) -> Dict[str, Any]:
    """A `polls` row (sqlite3.Row or Mapping) → the dict the pure half expects."""
    raw_options = row["options_json"] if not isinstance(row, Mapping) else row.get("options_json")
    try:
        options = json.loads(raw_options or "[]")
    except (TypeError, ValueError):
        options = []
    if not isinstance(options, list):
        options = []

    def field(name: str, default: Any = None) -> Any:
        try:
            value = row[name]
        except (KeyError, IndexError, TypeError):
            value = row.get(name, default)
        return default if value is None else value

    ends = field("ends_at_ms")
    created = field("created_at_ms", 0)
    return {
        "poll_id": str(field("poll_id", "")),
        "question": field("question", ""),
        "options": [str(o) for o in options],
        "card_id": field("card_id"),
        "mode": field("mode", "anonymous"),
        "multi": int(field("multi", 0) or 0),
        "ends_at_ms": None if ends is None else int(ends),
        "created_at_ms": int(created or 0),
        "closed": int(field("closed", 0) or 0),
    }


def _as_int(value: Any, default: Optional[int] = None) -> Optional[int]:
    if isinstance(value, bool):
        return default
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def settings_roster(deps: "PluginDeps", poll_id: Any) -> Dict[int, str]:
    """contact id → the card id this poll was delivered to that follower under.

    The roster lives in `settings` because `polls` has exactly one `card_id` column for
    what is an N-card fan-out (app/database.py:348) and no follower-list column at all.
    A missing or corrupt value degrades to an empty roster, which the callers survive by
    recomputing the deterministic id.
    """
    raw = deps.db.get_setting(ROSTER_SETTING_PREFIX + str(poll_id) + ROSTER_SETTING_SUFFIX, None)
    out: Dict[int, str] = {}
    if not isinstance(raw, Mapping):
        return out
    for contact, card_id in raw.items():
        contact_id = _as_int(contact)
        if contact_id is not None and isinstance(card_id, str) and card_id:
            out[contact_id] = card_id
    return out


def remember_roster(deps: "PluginDeps", poll_id: Any, roster: Mapping[int, str]) -> None:
    deps.db.set_setting(
        ROSTER_SETTING_PREFIX + str(poll_id) + ROSTER_SETTING_SUFFIX,
        {str(contact): card_id for contact, card_id in roster.items()},
    )


def vote_pairs(deps: "PluginDeps", poll_id: Any) -> List[Tuple[int, int]]:
    """Every recorded `(contact_id, choice_index)` of one poll, defensively.

    A row whose columns are not integers is dropped rather than raising: a poll that
    cannot be tallied would be a poll whose card can never be updated again, and the
    arithmetic (`compute_tally`) already refuses to count an index it cannot place.
    The reads go through the `UNIQUE (poll_id, contact_id)` index, so this is a seek
    per follower, not a scan.
    """
    try:
        rows = deps.db.query("SELECT contact_id, choice_index FROM poll_votes WHERE poll_id = ?", (str(poll_id),))
    except sqlite3.Error:
        return []
    out: List[Tuple[int, int]] = []
    for row in rows:
        contact = _as_int(_contact_of(row))
        stored = _as_int(_row_field(row))
        if contact is None or stored is None:
            continue
        out.append((contact, stored))
    return out


# ─────────────────────────────────────────────────────────────────────────────
# 10. The HTTP surface
# ─────────────────────────────────────────────────────────────────────────────


def create_router(deps: "PluginDeps") -> "APIRouter":
    """Merchant-facing routes. FastAPI is imported *here*: the module must stay
    importable (and its pure half executable) in a process with no wheels installed.
    """
    from fastapi import APIRouter, Body, HTTPException, Query

    router = APIRouter(prefix=deps.spec.url_prefix, tags=["plugin:polls"])

    def fail(status: int, code: str, message: str) -> "HTTPException":
        return HTTPException(
            status_code=status,
            detail={"ok": False, "plugin": PLUGIN_ID, "code": code, "detail": message},
        )

    def get_poll_or_404(poll_id_text: Any) -> Dict[str, Any]:
        digits = str(poll_id_text or "").strip()
        if not _CANONICAL_DIGITS_RE.match(digits):
            # A malformed path id is not "somebody else's 404": it names our grammar,
            # which is the only way a client discovers it got the id form wrong.
            raise fail(400, "poll_id_invalid", "poll id must be 1..%d canonical digits" % POLL_ID_MAX_DIGITS)
        row = deps.db.query_one("SELECT * FROM polls WHERE poll_id = ?", (digits,))
        if row is None:
            raise fail(404, "poll_not_found", "no poll %s" % digits)
        return _poll_from_row(row)

    def tally_of(poll: Mapping[str, Any]) -> Dict[str, Any]:
        pairs = vote_pairs(deps, poll["poll_id"])
        return compute_tally(decode_votes(pairs, bool(poll["multi"])), list(poll["options"] or []))

    def roster_of(poll: Mapping[str, Any]) -> List[Tuple[int, str]]:
        """Every `(contact_id, card_id)` this poll has an out on the wire for.

        Three sources, merged, because the schema records none of them properly: the
        `settings` roster written at create (authoritative for the fan-out list), the
        `cards` rows under this poll's `topic` (authoritative for the id the gateway
        actually stored, if `app.main` persists `topic`), and the deterministic id
        (always available). Union rather than trust-one, because a wrong card id means
        a follower's bubble never updates and no error surfaces anywhere.
        """
        poll_id = str(poll["poll_id"])
        found = settings_roster(deps, poll_id)
        try:
            rows = deps.db.query("SELECT card_id, contact_id FROM cards WHERE topic = ?", (topic_for(poll_id),))
        except sqlite3.Error:
            rows = []
        for row in rows:
            contact_id = _as_int(_contact_of(row))
            card_id = _row_field(row, "card_id")
            if contact_id is not None and isinstance(card_id, str) and card_id:
                found.setdefault(contact_id, card_id)
        return sorted(found.items(), key=lambda item: item[0])

    def eligible_targets(contact_ids: Sequence[int]) -> Tuple[List[int], List[Dict[str, Any]]]:
        """Contacts that can receive a card, and why the others cannot.

        A card is sealed with the follower's pairwise session secret, so a contact with
        no session (never completed the handshake) or a revoked one has nothing to
        deliver to. Skipping with a stated reason beats letting the gateway raise on a
        secret that does not exist.
        """
        ok: List[int] = []
        skipped: List[Dict[str, Any]] = []
        for contact_id in contact_ids:
            row = deps.db.query_one("SELECT blocked FROM contacts WHERE contact_id = ?", (contact_id,))
            if row is None:
                skipped.append({"contact_id": contact_id, "reason": "not_a_follower"})
                continue
            if int(row["blocked"] or 0):
                skipped.append({"contact_id": contact_id, "reason": "blocked"})
                continue
            session = deps.eco.session_for(contact_id)
            if session is None:
                skipped.append({"contact_id": contact_id, "reason": "no_session"})
                continue
            if not session.usable:
                skipped.append({"contact_id": contact_id, "reason": "session_unusable"})
                continue
            ok.append(contact_id)
        return ok, skipped

    async def push_card(
        poll: Mapping[str, Any],
        tally: Mapping[str, Any],
        *,
        closed: bool,
        now_value: int,
    ) -> List[Dict[str, Any]]:
        """Re-deliver this poll's cards in place. Same `cardId`, so the phone mutates
        the bubble it already shows instead of stacking a second one.
        """
        options = list(poll["options"])
        mode = api_mode(poll["mode"])
        multi = bool(poll["multi"])
        progress = progress_for(tally, options, closed=closed, ends_at_ms_value=poll["ends_at_ms"], now_value=now_value)
        pairs = vote_pairs(deps, poll["poll_id"])
        choices = voter_choices(pairs, multi, len(options))
        results: List[Dict[str, Any]] = []
        for contact_id, card_id in roster_of(poll):
            fields = fields_for(tally, options, multi=multi, mode=mode, mine=choices.get(contact_id), closed=closed)
            try:
                delivery = await deps.eco.update_card(
                    card_id,
                    contact_id,
                    progress=progress,
                    fields=fields,
                    expires_at_ms=closed_expires_at(now_value) if closed else None,
                )
            except EcoError as exc:
                results.append({"contact_id": contact_id, "card_id": card_id, "updated": False, "error": "%s: %s" % (exc.rule, exc.detail)})
                continue
            except BillingError as exc:
                # An update is a card send and the `card` meter is not this plugin's to
                # decide: the gateway refuses, the tally stays correct in the database,
                # and the merchant sees which follower did not get the new number.
                results.append({"contact_id": contact_id, "card_id": card_id, "updated": False, "error": "billing:%s" % exc.code})
                continue
            results.append(
                {
                    "contact_id": contact_id,
                    "card_id": card_id,
                    "updated": bool(getattr(delivery, "sent", False)) or bool(getattr(delivery, "queued", False)),
                    "queued": bool(getattr(delivery, "queued", False)),
                    "charged": int(getattr(delivery, "charged", 0) or 0),
                    "error": getattr(delivery, "error", None),
                }
            )
        return results

    # ── create ──────────────────────────────────────────────────────────────

    @router.post("", summary="Create a poll and deliver one card per named follower")
    async def create_poll(body: Dict[str, Any] = Body(...)) -> Dict[str, Any]:
        """`{question, options[], mode, multi, ends_at_ms?, targets?}` → poll + per-target report.

        Nothing is sent before the row exists: a poll whose cards could not all be
        delivered is still a poll with a durable question and a roster to retry from
        (`POST /{id}/refresh`), whereas cards with no poll behind them would be buttons
        that answer `poll_not_found` forever.
        """
        try:
            decision = deps.require()
        except PluginUnavailable as exc:
            raise HTTPException(status_code=exc.http_status, detail=exc.decision.as_body()) from exc
        if not isinstance(body, dict):
            raise fail(422, "body_type", "expected a JSON object")

        now_value = int(now_ms())
        try:
            question = validate_question(body.get("question"))
            options = normalise_options(body.get("options"))
            mode = normalise_mode(body.get("mode"))
            multi = bool(body.get("multi") or False)
            ends_at = validate_ends_at_ms(body.get("ends_at_ms"), now_value)
            max_targets = _as_int(deps.db.get_setting(SETTING_MAX_TARGETS, DEFAULT_MAX_TARGETS), DEFAULT_MAX_TARGETS) or DEFAULT_MAX_TARGETS
            targets = validate_targets(body.get("targets"), max_targets)
        except PollInputError as exc:
            raise fail(exc.http_status, exc.code, exc.message) from exc

        poll_id = ""
        row_written = False
        for _attempt in range(5):
            candidate = mint_poll_id(now_value)
            try:
                with deps.db.transaction(immediate=True) as conn:
                    conn.execute(
                        "INSERT INTO polls (poll_id, question, options_json, card_id, mode, multi, ends_at_ms, created_at_ms, closed)"
                        " VALUES (?,?,?,?,?,?,?,?,0)",
                        (candidate, question, json.dumps(options, ensure_ascii=False, separators=(",", ":")), None, store_mode(mode), 1 if multi else 0, ends_at, now_value),
                    )
                poll_id = candidate
                row_written = True
                break
            except sqlite3.IntegrityError:
                continue  # 1-in-100000 same-millisecond id collision: mint and retry
        if not row_written:
            raise fail(503, "poll_id_collision", "could not mint a unique poll id; retry")

        poll = {
            "poll_id": poll_id,
            "question": question,
            "options": options,
            "card_id": None,
            "mode": store_mode(mode),
            "multi": 1 if multi else 0,
            "ends_at_ms": ends_at,
            "created_at_ms": now_value,
            "closed": 0,
        }

        # Validate the payload before spending a single card charge: build_card is the
        # same function the gateway will use to seal the frame, so if it raises here,
        # no follower was billed for a card the phone would drop.
        body_text = body_for(mode, multi, ends_at, options)
        tally = compute_tally([], options)
        try:
            actions = option_actions(poll_id, options)
        except (PollInputError, EcoError) as exc:
            detail = exc.message if isinstance(exc, PollInputError) else "%s: %s" % (exc.rule, exc.detail)
            raise fail(400, "option_payload", detail) from exc

        eligible, skipped = eligible_targets(targets)
        deliveries: List[Dict[str, Any]] = []
        roster: Dict[int, str] = {}
        for contact_id in eligible:
            expected_id = card_id_for(poll_id, contact_id)
            try:
                card = build_card(
                    expected_id,
                    question,
                    style=CARD_STYLE,
                    body=body_text,
                    fields=fields_for(tally, options, multi=multi, mode=mode, closed=False),
                    progress=progress_for(tally, options, closed=False, ends_at_ms_value=ends_at, now_value=now_value),
                    actions=actions,
                    updated_at_ms=now_value,
                    expires_at_ms=ends_at,
                )
            except EcoError as exc:
                deliveries.append({"contact_id": contact_id, "card_id": expected_id, "sent": False, "charged": 0, "error": "%s: %s" % (exc.rule, exc.detail)})
                continue
            try:
                # The `card` meter is charged inside this call (see Eco.deliver_card);
                # charging it here too would bill the same send twice.
                delivery = await deps.eco.deliver_card(card, contact_id, topic=topic_for(poll_id))
            except EcoError as exc:
                deliveries.append({"contact_id": contact_id, "card_id": expected_id, "sent": False, "charged": 0, "error": "%s: %s" % (exc.rule, exc.detail)})
                continue
            except BillingError as exc:
                deliveries.append({"contact_id": contact_id, "card_id": expected_id, "sent": False, "charged": 0, "error": "billing:%s" % exc.code})
                continue
            stored_id = str(getattr(delivery, "card_id", "") or expected_id)
            roster[contact_id] = stored_id
            deliveries.append(
                {
                    "contact_id": contact_id,
                    "card_id": stored_id,
                    "sent": bool(getattr(delivery, "sent", False)),
                    "queued": bool(getattr(delivery, "queued", False)),
                    "charged": int(getattr(delivery, "charged", 0) or 0),
                    "balance_after": getattr(delivery, "balance_after", None),
                    "error": getattr(delivery, "error", None),
                }
            )

        if roster:
            remember_roster(deps, poll_id, roster)
            first_card = roster[min(roster)]
            # `polls.card_id` is a single column for what is N cards. The first
            # delivered id goes there so an operator reading the table sees a real
            # card; the complete roster is in `settings` (see `roster_of`).
            deps.db.execute("UPDATE polls SET card_id = ? WHERE poll_id = ?", (first_card, poll_id))
            poll["card_id"] = first_card

        sent = [d for d in deliveries if d.get("sent") or d.get("queued")]
        return {
            "ok": bool(sent) or not eligible,
            "plugin": PLUGIN_ID,
            "balance": decision.balance,
            "poll": poll_public(poll, tally, now_value=now_value),
            "deliveries": deliveries,
            "skipped": skipped,
            "delivered": len(sent),
            "fanout_is_explicit": True,
            "detail": (
                "delivered to %d of %d named follower(s); an empty targets list means nobody on "
                "purpose — fanning out to every follower is a metered card each and a message they "
                "did not ask for" % (len(sent), len(targets))
            ),
        }

    # ── read ────────────────────────────────────────────────────────────────

    @router.get("", summary="List polls with their live state")
    def list_polls(
        state: Optional[str] = Query(None, description="open | closed | expired"),
        limit: int = Query(50, ge=1, le=200),
    ) -> Dict[str, Any]:
        try:
            deps.require()
        except PluginUnavailable as exc:
            raise HTTPException(status_code=exc.http_status, detail=exc.decision.as_body()) from exc
        now_value = int(now_ms())
        rows = deps.db.query("SELECT * FROM polls ORDER BY created_at_ms DESC LIMIT ?", (limit,))
        out: List[Dict[str, Any]] = []
        for row in rows:
            poll = _poll_from_row(row)
            derived = poll_state(poll, now_value)
            if state and derived != state:
                continue
            out.append(poll_public(poll, tally_of(poll), now_value=now_value))
        return {"ok": True, "plugin": PLUGIN_ID, "count": len(out), "polls": out, "state_filter": state}

    @router.get("/status", summary="Plugin health for the console panel")
    def status() -> Dict[str, Any]:
        """Declared **above** `/{poll_id}`: that pattern also matches the literal
        `status`, and Starlette answers the first registration that fits, so the
        ordering is the difference between this panel and a 400 `poll_id_invalid`.
        The gateway's generic `GET /api/v1/plugins/{plugin_id}/status` cannot cover
        it either — plugin routers are mounted first, on purpose, so a plugin with a
        richer status of its own keeps it (`app/main.py`).

        The gate is *reported* here, not enforced: a fused account or a down node is
        exactly when an operator opens this panel.
        """
        decision = deps.gate.status(PLUGIN_ID)
        now_value = int(now_ms())
        states = {"open": 0, "closed": 0, "expired": 0}
        for row in deps.db.query("SELECT * FROM polls") or ():
            derived = poll_state(_poll_from_row(row), now_value)
            if derived in states:
                states[derived] += 1
        return {
            "ok": True,
            "plugin": PLUGIN_ID,
            "enabled": bool(getattr(deps.config.plugins, deps.spec.toggle, False)),
            "gate": decision.as_body(),
            "meter": deps.spec.meter,
            "url_prefix": deps.spec.url_prefix,
            "callback_kinds": list(deps.spec.callback_kinds),
            "polls": {"total": sum(states.values()), **states},
            "id_grammar": "1..%d canonical digits" % POLL_ID_MAX_DIGITS,
        }

    @router.get("/{poll_id}", summary="One poll, its state and its tally")
    def get_poll(poll_id: str) -> Dict[str, Any]:
        try:
            deps.require()
        except PluginUnavailable as exc:
            raise HTTPException(status_code=exc.http_status, detail=exc.decision.as_body()) from exc
        now_value = int(now_ms())
        poll = get_poll_or_404(poll_id)
        tally = tally_of(poll)
        return {
            "ok": True,
            "plugin": PLUGIN_ID,
            "poll": poll_public(poll, tally, now_value=now_value),
            "targets": len(roster_of(poll)),
            "card_id": poll.get("card_id"),
        }

    @router.get("/{poll_id}/results", summary="Tally, and voter ids only in signed mode")
    def get_results(poll_id: str) -> Dict[str, Any]:
        try:
            deps.require()
        except PluginUnavailable as exc:
            raise HTTPException(status_code=exc.http_status, detail=exc.decision.as_body()) from exc
        now_value = int(now_ms())
        poll = get_poll_or_404(poll_id)
        options = list(poll["options"])
        multi = bool(poll["multi"])
        # The same defensive read the card updates use: one source of truth for what a
        # `poll_votes` row means, so the number on a follower's card and the number here
        # cannot drift apart because two SELECTs interpreted `choice_index` differently.
        pairs = vote_pairs(deps, poll["poll_id"])
        tally = compute_tally(decode_votes(pairs, multi), options)
        max_voters = _as_int(deps.db.get_setting(SETTING_RESULTS_MAX_VOTERS, DEFAULT_RESULTS_MAX_VOTERS), DEFAULT_RESULTS_MAX_VOTERS) or DEFAULT_RESULTS_MAX_VOTERS
        payload = results_payload(
            poll,
            tally,
            choices_by_contact=voter_choices(pairs, multi, len(options)),
            now_value=now_value,
            max_voters=max_voters,
        )
        payload["plugin"] = PLUGIN_ID
        return payload

    # ── close / reopen / refresh ────────────────────────────────────────────

    @router.post("/{poll_id}/close", summary="Close a poll and retire its buttons in place")
    async def close_poll(poll_id: str) -> Dict[str, Any]:
        """State → closed, then every card updated with the final tally.

        Idempotent: closing a closed poll re-reads and re-reports without re-touching
        the wire, so a retried request cannot stack a second round of card sends.
        """
        try:
            deps.require()
        except PluginUnavailable as exc:
            raise HTTPException(status_code=exc.http_status, detail=exc.decision.as_body()) from exc
        now_value = int(now_ms())
        poll = get_poll_or_404(poll_id)
        already = bool(int(poll["closed"] or 0))
        if not already:
            deps.db.execute("UPDATE polls SET closed = 1 WHERE poll_id = ?", (str(poll["poll_id"]),))
            poll["closed"] = 1
        tally = tally_of(poll)
        updates = [] if already else await push_card(poll, tally, closed=True, now_value=now_value)
        return {
            "ok": True,
            "plugin": PLUGIN_ID,
            "poll": poll_public(poll, tally, now_value=now_value),
            "already_closed": already,
            "tally": tally,
            "updates": updates,
            "detail": "cards retired by expires_at_ms; the client has no renderable disabled action",
        }

    @router.post("/{poll_id}/reopen", summary="Re-open a closed poll, with a future deadline")
    async def reopen_poll(poll_id: str, body: Optional[Dict[str, Any]] = Body(default=None)) -> Dict[str, Any]:
        """Allowed, because nothing about it rewrites history — but only with a deadline.

        The DDL's `closed` is a plain `INTEGER NOT NULL DEFAULT 0` with no CHECK
        (app/database.py:354), and `poll_votes` rows are append-only, so 1→0 does not
        mutate or invalidate a single recorded vote: votes cast before the close stay
        counted, exactly as they were reported. What *would* be dishonest is reopening
        silently, because phones already show 已截止 and a follower who voted under a
        deadline they believed had passed is entitled to a new window they can see. So a
        future `ends_at_ms` is required — from the body, or the poll's own still-future
        deadline if it had one — and the answer says the old votes were retained.

        Client-side caveat, measured rather than assumed: `expiredNow` in the bubble is
        `@State` that is set true and never reset
        (ServiceCardBubbleView.swift:67, 117-131), so a card the user is *currently
        looking at* stays inert until that view is recreated (a scroll away and back, or
        a relaunch). The new `et` does reach the stored card
        (PopopxEcoRouterAndDeepLink.swift:188) and the buttons return on the next
        render; nothing this plugin sends can revive a live view in place.
        """
        try:
            deps.require()
        except PluginUnavailable as exc:
            raise HTTPException(status_code=exc.http_status, detail=exc.decision.as_body()) from exc
        now_value = int(now_ms())
        poll = get_poll_or_404(poll_id)
        if not int(poll["closed"] or 0):
            tally = tally_of(poll)
            return {"ok": True, "plugin": PLUGIN_ID, "already_open": True, "poll": poll_public(poll, tally, now_value=now_value)}
        requested = None
        if isinstance(body, dict):
            requested = body.get("ends_at_ms")
        ends_at = poll["ends_at_ms"] if requested is None else requested
        try:
            ends_at = validate_ends_at_ms(ends_at, now_value)
        except PollInputError as exc:
            raise fail(exc.http_status, exc.code, "%s — reopen needs a future ends_at_ms because every phone already shows this poll as 已截止" % exc.message) from exc
        deps.db.execute("UPDATE polls SET closed = 0, ends_at_ms = ? WHERE poll_id = ?", (ends_at, str(poll["poll_id"])))
        poll["closed"] = 0
        poll["ends_at_ms"] = ends_at
        tally = tally_of(poll)
        updates = await push_card(poll, tally, closed=False, now_value=now_value)
        return {
            "ok": True,
            "plugin": PLUGIN_ID,
            "poll": poll_public(poll, tally, now_value=now_value),
            "votes_retained": int(tally["total"]),
            "new_deadline_ms": ends_at,
            "updates": updates,
        }

    @router.post("/{poll_id}/refresh", summary="Re-push the live tally to every card")
    async def refresh_poll(poll_id: str) -> Dict[str, Any]:
        """The explicit, operator-triggered rebroadcast.

        Votes do **not** fan out. A per-vote broadcast is O(followers) card sends per
        tap, each one a `card`-meter debit: a 500-follower account and 200 votes is
        100 000 charged sends for a poll that was worth 200. So a vote updates the
        voter's own card only — the one bubble whose state actually changed — and
        everyone else's bar moves on close, or here, on request.
        """
        try:
            deps.require()
        except PluginUnavailable as exc:
            raise HTTPException(status_code=exc.http_status, detail=exc.decision.as_body()) from exc
        now_value = int(now_ms())
        poll = get_poll_or_404(poll_id)
        tally = tally_of(poll)
        closed = poll_state(poll, now_value) != "open"
        updates = await push_card(poll, tally, closed=closed, now_value=now_value)
        return {"ok": True, "plugin": PLUGIN_ID, "poll": poll_public(poll, tally, now_value=now_value), "tally": tally, "updated": len([u for u in updates if u.get("updated")]), "updates": updates}

    return router


# ─────────────────────────────────────────────────────────────────────────────
# 11. The inbound half: a tap becomes a counted, charged vote
# ─────────────────────────────────────────────────────────────────────────────


def _record_vote(deps: "PluginDeps", poll_id: int, contact_id: int, index: int, now_value: int) -> Dict[str, Any]:
    """The atomic dedupe-and-write. Returns `status` ∈ counted | replay | not_counted.

    One `BEGIN IMMEDIATE` covers: re-read the poll, re-check the gate, read this
    follower's existing row, decide, write, and re-tally. Two devices tapping the same
    contact cannot both win, because the second transaction cannot start until the
    first commits and therefore sees its row; and the card the second one renders
    carries the first one's result, which is the only state that is true.

    The write's own `IntegrityError` is also handled as a replay — the DDL's
    `UNIQUE (poll_id, contact_id)` is the belt to this brace, and if a future schema
    widens that index the transaction above already implements the same rule, so the
    behaviour does not silently change underneath.
    """
    text_id = str(poll_id)
    with deps.db.transaction(immediate=True) as conn:
        row = conn.execute("SELECT * FROM polls WHERE poll_id = ?", (text_id,)).fetchone()
        if row is None:
            return {"status": "not_counted", "reason": "poll_not_found"}
        poll = _poll_from_row(row)
        refusal = vote_gate(poll, index, now_value)
        if refusal is not None:
            return {"status": "not_counted", "reason": refusal, "poll": poll}

        existing = conn.execute(
            "SELECT choice_index FROM poll_votes WHERE poll_id = ? AND contact_id = ?", (text_id, contact_id)
        ).fetchone()
        existing_value = None
        if existing is not None:
            try:
                existing_value = existing["choice_index"]
            except (KeyError, IndexError, TypeError):
                existing_value = existing[0]
        multi = bool(poll["multi"])
        verb, stored = decide_vote_write(multi, existing_value, index)
        if verb == "insert":
            try:
                conn.execute(
                    "INSERT INTO poll_votes (poll_id, contact_id, choice_index, ts_ms) VALUES (?,?,?,?)",
                    (text_id, contact_id, int(stored or 0), now_value),
                )
            except sqlite3.IntegrityError:
                verb = "replay"
        elif verb == "update":
            conn.execute(
                "UPDATE poll_votes SET choice_index = ?, ts_ms = ? WHERE poll_id = ? AND contact_id = ?",
                (int(stored or 0), now_value, text_id, contact_id),
            )
        status = "counted" if verb in ("insert", "update") else "replay"
        return {
            "status": status,
            "reason": None,
            "poll": poll,
            "stored": None if verb == "replay" else int(stored or 0),
        }


async def handle_inbound(deps: "PluginDeps", message: "InboundMessage") -> bool:
    """Claim and apply `poll:vote:<poll_id>:<index>`. True means consumed.

    Only `card_callback` is examined — that is the kind this plugin's spec row owns
    (`callback_kinds=("card_callback",)` in `app/plugins/__init__.py:115-122`), so a
    text message never reaches this code, and anything whose payload does not begin
    `poll:` returns False so the caller falls through to the alert plugin and then the
    merchant handler.
    """
    callback = getattr(message, "callback", None)
    if callback is None or getattr(callback, "kind", "") != "card_callback":
        return False
    payload = getattr(callback, "payload", "") or ""
    if not claims_poll_payload(payload):
        return False

    parsed = parse_vote_payload(payload)
    if parsed is None:
        # Ours, and malformed. Consumed and ignored: the poll it half-names does not
        # exist, and replying to a control line with prose is how a protocol turns
        # into a chatbot.
        return True
    poll_id, index = parsed

    contact_id = _as_int(getattr(message, "contact_id", None))
    if contact_id is None or contact_id <= 0:
        return True

    decision = deps.gate.status(deps.plugin_id)
    if not decision.usable:
        # Disabled or fused: consume the callback anyway. Falling through here would
        # hand a vote to the alert plugin or to an AI, which answers a control line with
        # prose and tells the follower nothing about their vote.
        return True

    now_value = int(now_ms())
    row = deps.db.query_one("SELECT * FROM polls WHERE poll_id = ?", (str(poll_id),))
    if row is None:
        return True
    poll = _poll_from_row(row)
    refusal = vote_gate(poll, index, now_value)
    if refusal is not None:
        # The phone still thinks the poll is live: its clock said so. Push the truth
        # back in place, inert and with the final numbers, so the button cannot be
        # tapped again — this is the only cure for a stale bubble.
        await _safe_update(
            deps,
            poll,
            contact_id,
            closed=True,
            now_value=now_value,
            note=NOTE_NOT_COUNTED_CLOSED,
        )
        return True

    # Charge first, count second, and repair the one case that can diverge. The key is
    # derived from the vote's identity, so a replayed `::CB::` costs 0 CP
    # (`ChargeResult.idempotent_replay`) and adds 0 rows: nothing to double-count and
    # nothing to double-bill.
    multi = bool(poll["multi"])
    key = idempotency_key_for_vote(poll_id, contact_id, multi, index)
    try:
        result = deps.charge(
            contact_id=contact_id,
            ref=str(poll_id),
            idempotency_key=key,
            meta={"poll_id": str(poll_id), "choice_index": index, "multi": multi},
        )
    except BillingError:
        # Not counted, and not silent: the ledger refusal is written on the voter's own
        # card, the callback is still consumed, and nothing was debited, so there is no
        # divergence to reconcile — only a follower who must be told.
        await _safe_update(deps, poll, contact_id, closed=False, now_value=now_value, note=NOTE_NOT_COUNTED_BILLING)
        return True

    try:
        outcome = _record_vote(deps, poll_id, contact_id, index, int(now_ms()))
    except sqlite3.Error:
        # Unexpected (a vanished `contacts` row, a disk fault). The charge is left
        # standing on purpose: the follower's retry replays the same key, costs
        # nothing, and gets their vote counted. Refunding here would strand a retry
        # that bills the same key as already-paid and counts the vote for free.
        return True

    if outcome["status"] == "not_counted":
        # The poll closed, expired or disappeared between the gate above and the write
        # lock. Every one of those reasons is decided by the *stored row*, which a retry
        # re-reads and is refused on before any charge is attempted — so refunding this
        # key can never leave a counted vote backed by a refunded charge.
        charged = int(getattr(result, "charged", 0) or 0)
        reason = outcome.get("reason") or "not_counted"
        if charged:
            try:
                deps.billing.refund(
                    amount=charged,
                    reason="poll vote not counted (%s)" % reason,
                    idempotency_key="%s:refund" % key,
                    ref=str(poll_id),
                )
            except BillingError:
                # The vote is not counted either way, so a failed refund is the
                # merchant's credit to chase in the ledger, not a silent tally error.
                pass
        await _safe_update(
            deps,
            outcome.get("poll") or poll,
            contact_id,
            closed=True,
            now_value=now_value,
            note=NOTE_NOT_COUNTED_CLOSED if reason in TERMINAL_GATE_REFUSALS else "投票未计入：%s" % reason,
        )
        return True

    await _safe_update(
        deps,
        outcome.get("poll") or poll,
        contact_id,
        closed=poll_state(outcome.get("poll") or poll, now_value) != "open",
        now_value=now_value,
        note=None,
    )
    return True


async def _safe_update(
    deps: "PluginDeps",
    poll: Mapping[str, Any],
    contact_id: int,
    *,
    closed: bool,
    now_value: int,
    note: Optional[str],
) -> bool:
    """Refresh one follower's bubble; a failure here must not undo the vote.

    The row is already committed by the time this runs. An update that cannot be sent
    (link down, card never stored for this contact, an Eco limit on a tally line) is a
    cosmetic loss — the number is right in the database and every later refresh or
    close carries it — so it is swallowed after one attempt. The opposite ordering
    would let a delivery problem decide whether a human being voted.

    The tally is re-read here rather than passed in, so what the follower sees and what
    `poll_votes` says cannot disagree because one caller had a stale snapshot.
    """
    options = list(poll.get("options") or [])
    if not options:
        return False
    multi = bool(poll.get("multi"))
    pairs = vote_pairs(deps, poll["poll_id"])
    tally = compute_tally(decode_votes(pairs, multi), options)
    choices = voter_choices(pairs, multi, len(options))
    card_id = settings_roster(deps, poll["poll_id"]).get(contact_id) or card_id_for(str(poll["poll_id"]), contact_id)
    progress = progress_for(tally, options, closed=closed, ends_at_ms_value=poll.get("ends_at_ms"), now_value=now_value)
    if note:
        progress = dict(progress)
        progress["d"] = clip("%s · %s" % (note, progress["d"]) if progress.get("d") else note, PROGRESS_DETAIL_CHARS)
    fields = fields_for(tally, options, multi=multi, mode=api_mode(poll.get("mode")), mine=choices.get(contact_id), closed=closed)
    try:
        await deps.eco.update_card(
            card_id,
            contact_id,
            progress=progress,
            fields=fields,
            expires_at_ms=closed_expires_at(now_value) if closed else None,
        )
    except (EcoError, BillingError):
        # `EcoValidationError` is a subclass of `EcoError` (app/crypto_service.py:119),
        # so one clause covers a refused limit and a codec failure alike.
        return False
    except sqlite3.Error:
        return False
    return True


# ─────────────────────────────────────────────────────────────────────────────
# 12. Self-test: the pure half only, no FastAPI, no SQLite, no clock
# ─────────────────────────────────────────────────────────────────────────────


def self_test() -> List[str]:
    """Assertions on the code that can run without a web framework installed.

    Everything below executes under `/usr/bin/python3` with no third-party wheel, because
    the parts worth being certain of — the payload grammar, the client's limits, the
    arithmetic, the dedupe predicate, the anonymity guarantee — are pure functions that
    take their clock as an argument. The names state the arithmetic, so a failure says
    which numbers stopped adding up.
    """
    checks: List[str] = []

    def check(name: str, condition: bool) -> None:
        if not condition:
            raise AssertionError("self_test failed: %s" % name)
        checks.append(name)

    NOW = 1_700_000_000_000  # a fixed ms clock; nothing here reads the wall clock

    # ── the prefix claim ────────────────────────────────────────────────────
    check("claim_accepts_own_vote", claims_poll_payload("poll:vote:1:0") is True)
    check("claim_accepts_bare_poll", claims_poll_payload("poll") is True)
    check("claim_accepts_malformed_poll_child", claims_poll_payload("poll:vote:not-an-int:0") is True)
    check("claim_rejects_alert_payload", claims_poll_payload("alert:ack:9") is False)
    check("claim_rejects_pollish_prefix_that_is_not_ours", claims_poll_payload("pollution:x") is False)
    check("claim_rejects_empty_and_none", claims_poll_payload("") is False and claims_poll_payload(None) is False)
    check("claim_rejects_non_string", claims_poll_payload(b"poll:vote:1:0") is False)

    # ── the payload grammar: one valid case, then the six refusals ──────────
    check("parse_valid", parse_vote_payload("poll:vote:170000000000543210:3") == (170000000000543210, 3))
    check("parse_valid_zero_index", parse_vote_payload("poll:vote:170000000000543210:0") == (170000000000543210, 0))
    check("parse_refuses_wrong_segment_count", parse_vote_payload("poll:vote:170000000000543210") is None)
    check("parse_refuses_extra_segment", parse_vote_payload("poll:vote:1:0:extra") is None)
    check("parse_refuses_trailing_junk", parse_vote_payload("poll:vote:1:0x") is None)
    check("parse_refuses_trailing_colon", parse_vote_payload("poll:vote:1:0:") is None)
    # `$` would match before a final newline; `\A..\Z` via fullmatch does not.
    check("parse_refuses_trailing_newline", parse_vote_payload("poll:vote:1:0\n") is None)
    check("parse_refuses_leading_space", parse_vote_payload(" poll:vote:1:0") is None)
    check("parse_refuses_negative_index", parse_vote_payload("poll:vote:1:-1") is None)
    check("parse_refuses_negative_poll_id", parse_vote_payload("poll:vote:-1:0") is None)
    check("parse_refuses_plus_sign", parse_vote_payload("poll:vote:+1:0") is None)
    check("parse_refuses_non_numeric", parse_vote_payload("poll:vote:1:x") is None)
    check("parse_refuses_word_poll_id", parse_vote_payload("poll:vote:abc:1") is None)
    # int() accepts all three of these; a vote must not move because of one.
    check("parse_refuses_leading_zero_poll_id", parse_vote_payload("poll:vote:01:0") is None)
    check("parse_refuses_leading_zero_index", parse_vote_payload("poll:vote:1:01") is None)
    check("parse_refuses_underscore_digits", parse_vote_payload("poll:vote:1_0:0") is None)
    check("parse_refuses_unicode_digits", parse_vote_payload("poll:vote:١:0") is None)
    check("parse_refuses_overlong_poll_id", parse_vote_payload("poll:vote:%s:0" % ("9" * (POLL_ID_MAX_DIGITS + 1))) is None)
    check("parse_refuses_wrong_verb", parse_vote_payload("poll:close:1:0") is None)
    check("parse_refuses_non_string", parse_vote_payload(None) is None and parse_vote_payload(7) is None)
    check("parse_never_raises_on_garbage", all(parse_vote_payload(junk) is None for junk in ("::CB::", "poll:", "poll:vote::", "poll:vote: : ", "poll:vote:1:999")))
    minted = mint_poll_id(NOW)
    check("render_parse_roundtrip", parse_vote_payload(render_vote_payload(minted, 2)) == (int(minted), 2))
    check("minted_id_is_canonical_digits", _CANONICAL_DIGITS_RE.match(minted) is not None and str(int(minted)) == minted)
    check("minted_id_within_digit_budget", len(minted) <= POLL_ID_MAX_DIGITS)
    check("render_rejects_bad_index", isinstance(_raises(PollInputError, render_vote_payload, minted, 999), PollInputError))
    check("render_rejects_negative_index", isinstance(_raises(PollInputError, render_vote_payload, minted, -1), PollInputError))
    check("rendered_payload_within_client_cap", len(render_vote_payload(minted, MAX_OPTIONS - 1)) <= VOTE_PAYLOAD_CHARS)

    # ── option validation: the >4 case must name the client limit ───────────
    check("options_reject_empty", isinstance(_raises(PollInputError, normalise_options, []), PollInputError))
    check("options_reject_single", "at least 2" in _raises(PollInputError, normalise_options, ["only"]).message)
    five = normalise_options(["a", "b", "c", "d"])
    check("options_accept_four", five == ["a", "b", "c", "d"])
    err = _raises(PollInputError, normalise_options, ["a", "b", "c", "d", "e"])
    check("options_reject_five_names_the_cap", "exceed the client" in err.message and " of 4" in err.message)
    check("options_reject_five_cites_the_client", "PopopxEcoModels.swift:48-72" in err.message and "PopopxEcoModels.swift:524-538" in err.message)
    check("options_reject_five_names_the_drop", "no poll at all" in err.message and "never truncated" in err.message)
    check("options_reject_five_is_a_400", err.http_status == 400 and err.code == "options_too_many")
    check("options_reject_twelve", _raises(PollInputError, normalise_options, list("abcdefghijkl")).code == "options_too_many")
    check("options_reject_duplicate", _raises(PollInputError, normalise_options, ["A", "a"]).code == "option_duplicate")
    check("options_reject_duplicate_after_strip", _raises(PollInputError, normalise_options, [" x ", "x"]).code == "option_duplicate")
    check("options_reject_overlong", "80" in _raises(PollInputError, normalise_options, ["长" * 81, "b"]).message)
    check("options_reject_overlong_is_exactly_one_over", normalise_options(["长" * 80, "b"]) == ["长" * 80, "b"])
    check("options_reject_whitespace_option", _raises(PollInputError, normalise_options, ["   ", "b"]).code == "option_empty")
    check("options_reject_non_string_option", _raises(PollInputError, normalise_options, [1, 2]).code == "option_type")
    check("options_reject_a_bare_string", _raises(PollInputError, normalise_options, "ab").code == "options_type")
    check("options_strips_surrounding_space", normalise_options([" a ", " b"]) == ["a", "b"])
    check("question_rejects_empty", _raises(PollInputError, validate_question, "  \n").code == "question_empty")
    check("question_rejects_121_chars_naming_120", "120" in _raises(PollInputError, validate_question, "？" * 121).message)
    check("question_accepts_exactly_120", validate_question("？" * 120) == "？" * 120)
    check("mode_defaults_to_anonymous", normalise_mode(None) == MODE_ANONYMOUS)
    check("mode_signed_maps_to_the_schema_word", store_mode(normalise_mode("signed")) == "identified")
    check("mode_identified_is_accepted_as_signed", api_mode(store_mode(normalise_mode("identified"))) == MODE_SIGNED)
    check("mode_rejects_unknown", _raises(PollInputError, normalise_mode, "secret").code == "mode_unknown")
    check("targets_empty_means_nobody", validate_targets([], 10) == [] and validate_targets(None, 10) == [])
    check("targets_dedupe_preserves_order", validate_targets([3, 1, 3, 2], 10) == [3, 1, 2])
    check("targets_reject_nonpositive", _raises(PollInputError, validate_targets, [0], 10).code == "targets_type")
    check("targets_reject_over_cap", _raises(PollInputError, validate_targets, [1, 2, 3], 2).code == "targets_too_many")
    check("ends_at_rejects_the_past", _raises(PollInputError, validate_ends_at_ms, NOW - 1, NOW).code == "ends_at_past")
    check("ends_at_accepts_future_and_none", validate_ends_at_ms(NOW + 1, NOW) == NOW + 1 and validate_ends_at_ms(None, NOW) is None)

    # ── the tally: percentages that add up to 100, always ──────────────────
    tally0 = compute_tally([], ["a", "b"])
    check("tally_empty_is_all_zeros", tally0["counts"] == [0, 0] and tally0["total"] == 0 and tally0["percentages"] == [0, 0])
    tally1 = compute_tally([1], ["a", "b", "c"])
    check("tally_single_voter_100_on_the_right_option", tally1["counts"] == [0, 1, 0] and tally1["percentages"] == [0, 100, 0])
    # 1/1/1: exact shares are 33.333…, so `round()` three times is 33+33+33 = 99.
    three = compute_tally([0, 1, 2], ["a", "b", "c"])
    check("tally_1of3_each_floors_to_99_so_largest_remainder_fixes_it", three["percentages"] == [34, 33, 33])
    check("tally_1of3_each_sums_to_100_not_99", sum(three["percentages"]) == 100 and 3 * round(100 / 3) == 99)
    # 2/2/3 of 7: 28.571, 28.571, 42.857 → round() gives 29+29+43 = 101.
    seven = compute_tally([0, 0, 1, 1, 2, 2, 2], ["a", "b", "c"])
    check("tally_2of2of3_of_7_would_round_to_101", 2 * round(200 / 7) + round(300 / 7) == 101)
    check("tally_2of2of3_of_7_is_29_28_43", seven["counts"] == [2, 2, 3] and seven["percentages"] == [29, 28, 43])
    check("tally_2of2of3_of_7_sums_to_100", sum(seven["percentages"]) == 100)
    # 4/4/3 of 11: 36.36, 36.36, 27.27 → round() gives 36+36+27 = 99.
    eleven = compute_tally([0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2], ["a", "b", "c"])
    check("tally_4of4of3_of_11_would_round_to_99", 2 * round(400 / 11) + round(300 / 11) == 99)
    check("tally_4of4of3_of_11_is_37_36_27", eleven["percentages"] == [37, 36, 27] and sum(eleven["percentages"]) == 100)
    # The tie-break: equal remainders, one point, and it goes to the lowest index.
    tie = distribute_percentages([1, 1, 1], 3)
    check("tally_tie_breaks_to_lowest_index", tie == [34, 33, 33])
    check("tally_is_deterministic", compute_tally([0, 1, 2], ["a", "b", "c"])["percentages"] == three["percentages"])
    check("tally_counts_length_matches_options", len(compute_tally([0], ["a", "b", "c", "d"])["counts"]) == MAX_OPTIONS)
    # A row outside the option list is counted nowhere rather than crashing the render.
    junk = compute_tally([0, 9, -1, 4, None, "x", True, 1], ["a", "b"])
    check("tally_ignores_out_of_range_and_rubbish", junk["counts"] == [1, 1] and junk["total"] == 2)
    check("tally_sum_equals_total", sum(junk["counts"]) == junk["total"])
    check("tally_accepts_row_shapes", compute_tally([{"choice_index": 1}, (5, 0)], ["a", "b"])["counts"] == [1, 1])
    check("tally_100_percent_for_a_two_thirds_split", compute_tally([0, 0, 1], ["a", "b"])["percentages"] == [67, 33])
    check("leading_is_none_when_nothing_chosen", leading_index([0, 0]) is None)
    check("leading_ties_to_lowest", leading_index([3, 3, 1]) == 0 and leading_index([1, 4, 4]) == 1)
    # 100 votes over 3 options: the invariant must hold for a shape nobody hand-checked.
    grid = compute_tally([i % 3 for i in range(100)], ["a", "b", "c"])
    check("tally_100_votes_sums_to_100", sum(grid["percentages"]) == 100 and grid["total"] == 100 and grid["counts"] == [34, 33, 33])

    # ── the idempotency key: stable, and collision-free across the join ─────
    k1 = idempotency_key_for_vote(1, 23, False, 0)
    k2 = idempotency_key_for_vote(12, 3, False, 0)
    check("key_is_stable", k1 == idempotency_key_for_vote(1, 23, False, 2))
    check("key_single_ignores_the_option_as_designed", k1 == idempotency_key_for_vote(1, 23, False, 3))
    check("key_poll1_contact23_differs_from_poll12_contact3", k1 == "poll:1:23" and k2 == "poll:12:3" and k1 != k2)
    check("key_multi_appends_index", idempotency_key_for_vote(1, 23, True, 0) == "poll:1:23:0" and idempotency_key_for_vote(1, 23, True, 1) == "poll:1:23:1")
    keys = set()
    for pid in (1, 12, 123, 1234, 170000000000543210):
        for cid in (3, 23, 32, 233, 4):
            keys.add(idempotency_key_for_vote(pid, cid, False, 0))
            for idx in range(MAX_OPTIONS):
                keys.add(idempotency_key_for_vote(pid, cid, True, idx))
    check("keys_are_collision_free_over_the_grid", len(keys) == 5 * 5 * (1 + MAX_OPTIONS))
    check("key_never_exceeds_payload_cap", max(len(k) for k in keys) <= VOTE_PAYLOAD_CHARS)

    # ── the dedupe predicate ───────────────────────────────────────────────
    check("single_first_vote_inserts_plain_index", decide_vote_write(False, None, 2) == ("insert", 2))
    check("single_second_vote_same_option_is_replay", decide_vote_write(False, 2, 2) == ("replay", None))
    check("single_second_vote_other_option_is_replay_not_rewrite", decide_vote_write(False, 0, 3) == ("replay", None))
    check("multi_first_vote_inserts_a_bitmask", decide_vote_write(True, None, 1) == ("insert", 2))
    check("multi_same_option_is_replay", decide_vote_write(True, 2, 1) == ("replay", None))
    check("multi_other_option_is_update_union", decide_vote_write(True, 2, 0) == ("update", 3))
    check("multi_three_way_union", decide_vote_write(True, decide_vote_write(True, None, 0)[1], 3) == ("update", 9))
    check("multi_never_replays_a_lost_bit", decide_vote_write(True, 0, 0) == ("update", 1))
    check("stored_and_decode_roundtrip_single", choice_indexes_for_stored(False, stored_value_for_choice(False, 3)) == (3,))
    check("stored_and_decode_roundtrip_multi", choice_indexes_for_stored(True, stored_value_for_choice(True, 0) | stored_value_for_choice(True, 2)) == (0, 2))
    check("decode_of_rubbish_is_empty", choice_indexes_for_stored(True, "n/a") == () and choice_indexes_for_stored(False, None) == ())
    check("decode_votes_reads_pairs", decode_votes([(7, 1), (8, 2)], False) == [1, 2] and decode_votes([{"contact_id": 7, "choice_index": 3}], True) == [0, 1])
    picked = voter_choices([(7, 3), (8, 1), (7, 1)], True, 4)
    check("voter_choices_groups_by_contact", picked == {7: [0, 1], 8: [0]})
    check("voter_choices_single_mode_is_one_option_each", voter_choices([(7, 2), (7, 2)], False, 4) == {7: [2]})
    check("voter_choices_drops_indexes_with_no_option", voter_choices([(7, 8)], True, 2) == {7: []})

    # ── the open/closed/expired gate, at -1, 0 and +1 around now ───────────
    base = {"poll_id": "1", "options": ["a", "b"], "mode": "anonymous", "multi": 0, "closed": 0, "ends_at_ms": NOW, "created_at_ms": NOW - 1000}
    check("gate_open_one_ms_before_deadline", vote_gate(base, 0, NOW - 1) is None)
    check("gate_open_at_exactly_the_deadline", vote_gate(base, 1, NOW) is None and poll_state(base, NOW) == "open")
    check("gate_closed_one_ms_after_deadline", vote_gate(base, 0, NOW + 1) == "poll_expired" and poll_state(base, NOW + 1) == "expired")
    check("gate_refuses_out_of_range_option", vote_gate(base, 2, NOW) == "option_out_of_range" and vote_gate(base, -1, NOW) == "option_out_of_range")
    closed_row = dict(base, closed=1, ends_at_ms=NOW + 10_000)
    check("gate_refuses_closed_before_its_deadline", vote_gate(closed_row, 0, NOW) == "poll_closed")
    check("closed_beats_expired", poll_state(dict(base, closed=1, ends_at_ms=NOW - 1), NOW + 1) == "closed")
    check("gate_refuses_missing_poll", vote_gate(None, 0, NOW) == "poll_not_found")
    check("gate_open_forever_without_a_deadline", vote_gate(dict(base, ends_at_ms=None), 0, NOW + 10 ** 12) is None)
    check("terminal_refusals_are_the_ones_we_refund_for", set(TERMINAL_GATE_REFUSALS) == {"poll_not_found", "poll_closed", "poll_expired"} and "option_out_of_range" not in TERMINAL_GATE_REFUSALS)
    check("is_open_matches_the_gate", is_open(base, NOW - 1) and not is_open(closed_row, NOW))

    # ── card assembly, measured against the client ─────────────────────────
    options4 = ["苹果", "香蕉", "橙子", "葡萄"]
    empty = compute_tally([], options4)
    prog0 = progress_for(empty, options4, closed=False, ends_at_ms_value=NOW, now_value=NOW)
    check("progress_keys_are_exactly_the_wire_names", set(prog0) == {"l", "p"} or set(prog0) == {"l", "p", "d"})
    check("progress_zero_votes_is_zero_percent", prog0["p"] == 0 and prog0["l"] == NOTE_NO_VOTES)
    check("progress_closed_zero_votes_labels_the_close", progress_for(empty, options4, closed=True, ends_at_ms_value=None, now_value=NOW)["l"] == NOTE_CLOSED)
    full = compute_tally([0, 0, 1], options4)
    prog1 = progress_for(full, options4, closed=False, ends_at_ms_value=NOW + 60_000, now_value=NOW)
    check("progress_shows_the_leader_share", prog1["p"] == 67 and prog1["l"].startswith("领先"))
    check("progress_detail_carries_the_count", "3 票" in prog1.get("d", ""))
    prog2 = progress_for(full, options4, closed=True, ends_at_ms_value=NOW - 1, now_value=NOW)
    check("progress_closed_says_已截止", NOTE_CLOSED in prog2.get("d", "") and prog2["p"] == 67)
    long_option = "很" * 200
    progl = progress_for(compute_tally([0], [long_option, "b"]), [long_option, "b"], closed=False, ends_at_ms_value=None, now_value=NOW)
    check("progress_label_within_client_80", len(progl["l"]) <= PROGRESS_LABEL_CHARS)
    check("progress_detail_within_client_240", len(progl.get("d", "")) <= PROGRESS_DETAIL_CHARS)
    check("progress_percent_bounds_0_and_100", progress_for(compute_tally([0], ["a", "b"]), ["a", "b"], closed=True, ends_at_ms_value=None, now_value=NOW)["p"] == 100)
    check("progress_percent_never_negative", all(EcoLimits.progress_percent_min <= progress_for(compute_tally(v, ["a", "b", "c"]), ["a", "b", "c"], closed=False, ends_at_ms_value=None, now_value=NOW)["p"] <= EcoLimits.progress_percent_max for v in ([], [0], [0, 0, 0], list(range(30)))))
    plain = fields_for(full, options4, multi=False, mode=MODE_ANONYMOUS)
    flds = fields_for(full, options4, multi=False, mode=MODE_ANONYMOUS, mine=[1])
    check("fields_one_row_per_option_plus_total", len(plain) == len(options4) + 1 and plain[0]["v"].startswith("2 票") and "总票数" in plain[-1]["k"])
    check("fields_within_client_8", len(flds) <= MAX_FIELDS)
    check("field_labels_within_client_80", all(len(f["k"]) <= EcoLimits.field_label_chars for f in flds))
    check("field_values_within_client_240", all(0 < len(f["v"]) <= FIELD_VALUE_CHARS for f in flds))
    check("fields_add_the_voters_own_row_only_when_told", len(flds) == len(plain) + 1 and "仅你可见" in flds[-1]["k"] and flds[-1]["v"] == options4[1])
    check("fields_signed_labels_the_voters_row_without_a_caveat", "仅你可见" not in fields_for(full, options4, multi=False, mode=MODE_SIGNED, mine=[0])[-1]["k"])
    check("fields_never_empty_a_value", all(f["v"] for f in flds))
    check("fields_always_within_8_with_four_options_and_mine", len(fields_for(full, ["w", "x", "y", "z"], multi=True, mode=MODE_SIGNED, mine=[0, 1], closed=True)) <= MAX_FIELDS)
    check("body_within_client_2000", len(body_for(MODE_ANONYMOUS, True, NOW + 60_000, options4)) <= BODY_CHARS)
    check("body_names_the_mode", "匿名" in body_for(MODE_ANONYMOUS, False, None, options4) and "实名" in body_for(MODE_SIGNED, False, None, options4))
    acts = option_actions(minted, options4)
    check("actions_are_callbacks_with_unique_ids", len(acts) == MAX_OPTIONS and len({a["id"] for a in acts}) == MAX_OPTIONS)
    check("actions_wire_kind_under_action_key", all(a["action"] == "callback" and a["payload"].startswith(VOTE_INFIX) for a in acts))
    check("actions_count_never_exceeds_the_cap", len(acts) <= MAX_OPTIONS)
    check("closed_expires_is_positive_and_past_enough", closed_expires_at(NOW) == NOW + 0 and closed_expires_at(0) == 1)
    card = build_card(card_id_for(minted, 7), "？" * QUESTION_CHARS, style=CARD_STYLE, body=body_for(MODE_ANONYMOUS, False, NOW + 60_000, options4), fields=flds, progress=prog1, actions=acts, updated_at_ms=NOW, expires_at_ms=NOW + 60_000)
    check("assembled_card_carries_ut_and_et", card["ut"] == NOW and card["et"] == NOW + 60_000 and card["v"] == CARD_STYLE)
    check("assembled_card_id_within_client_64", len(card["id"]) <= EcoLimits.card_id_chars)
    other = mint_poll_id(NOW + 1)
    check("card_id_is_deterministic_per_pair", card_id_for(minted, 7) == card_id_for(minted, 7) and len({card_id_for(p, c) for p in (minted, other) for c in (1, 7, 23)}) == 6)
    check("card_id_rejects_a_huge_contact", isinstance(_raises(PollInputError, card_id_for, "9" * 70, 1), PollInputError))
    check("clip_never_exceeds_the_budget", all(len(clip("字" * n, 240)) <= 240 for n in (1, 239, 240, 241, 900)))

    # ── the anonymity claim ────────────────────────────────────────────────
    # Rows as `poll_votes` would hold them for a multi poll: one per follower, a
    # bitmask in `choice_index`. 9001 chose 苹果, 9002 chose 香蕉, 90021 chose both
    # 苹果 and 葡萄 → counts [2,1,0,1].
    vote_rows = [(9001, 1), (9002, 2), (90021, 9)]
    voters = voter_choices(vote_rows, True, len(options4))
    check("the_voter_fixture_decodes_as_intended", voters == {9001: [0], 9002: [1], 90021: [0, 3]})
    anonymous_poll = {"poll_id": "170000000000543210", "question": "午餐", "options": options4, "mode": "anonymous", "multi": 1, "closed": 0, "ends_at_ms": 1700000009000, "created_at_ms": 1700000000000}
    signed_poll = dict(anonymous_poll, mode="identified")
    anon_votes = compute_tally(decode_votes(vote_rows, True), options4)
    anon = results_payload(anonymous_poll, anon_votes, choices_by_contact=voters, now_value=NOW)
    anon_text = json.dumps(anon, ensure_ascii=False, sort_keys=True)
    check("anonymous_results_carry_counts_only", anon["counts"] == [2, 1, 0, 1] and anon["total_votes"] == 4 and anon["percentages"] == [50, 25, 0, 25])
    check("anonymous_results_percentages_still_sum_to_100", sum(anon["percentages"]) == 100)
    check("anonymous_results_have_no_voters_key", "voters" not in anon)
    for contact in (9001, 9002, 90021):
        check("anonymous_results_leak_no_contact_%d" % contact, str(contact) not in anon_text)
    check("anonymous_results_leak_no_poll_roster_key", not any(k in anon for k in ("contact_id", "targets", "roster", "card_id")))
    # The *fixture* is chosen so a leak is provable: created_at_ms and ends_at_ms
    # contain none of the digit strings above, so a substring hit could only be a leak.
    check("anonymous_fixture_ids_are_distinguishable_from_its_timestamps", all(str(c) not in str(1700000000000) + str(1700000009000) + "170000000000543210" for c in (9001, 9002, 90021)))
    signed = results_payload(signed_poll, anon_votes, choices_by_contact=voters, now_value=NOW)
    check("signed_results_do_list_voters", "voters" in signed and {v["contact_id"] for v in signed["voters"]} == {9001, 9002, 90021})
    check("signed_results_name_the_choice", sorted((v["contact_id"], v["choice_index"]) for v in signed["voters"]) == [(9001, 0), (9002, 1), (90021, 0), (90021, 3)])
    check("signed_and_anonymous_agree_on_the_counts", signed["counts"] == anon["counts"] and signed["percentages"] == anon["percentages"])
    check("signed_truncates_at_max_voters", len(results_payload(signed_poll, anon_votes, choices_by_contact=voters, now_value=NOW, max_voters=2)["voters"]) <= 2)
    check("anonymous_ignores_max_voters_entirely", "voters" not in results_payload(anonymous_poll, anon_votes, choices_by_contact=voters, now_value=NOW, max_voters=0))
    detail_text = json.dumps(poll_public(anonymous_poll, anon_votes, now_value=NOW), ensure_ascii=False, sort_keys=True)
    check("poll_detail_leaks_no_contact_either", all(str(c) not in detail_text for c in (9001, 9002, 90021)) and "card_id" not in json.loads(detail_text))
    check("results_state_is_derived", results_payload(dict(anonymous_poll, closed=1), anon_votes, now_value=NOW)["state"] == "closed")
    check("results_reports_the_api_mode_not_the_storage_word", anon["mode"] == MODE_ANONYMOUS and signed["mode"] == MODE_SIGNED)

    # ── row decoding (no SQLite needed: a Mapping stands in for a Row) ─────
    row_like = {"poll_id": "42", "question": "午餐", "options_json": json.dumps(options4, ensure_ascii=False), "card_id": None, "mode": "identified", "multi": 1, "ends_at_ms": NOW, "created_at_ms": NOW - 1, "closed": 0}
    decoded = _poll_from_row(row_like)
    check("poll_row_decodes_options_and_mode", decoded["options"] == options4 and api_mode(decoded["mode"]) == MODE_SIGNED and decoded["multi"] == 1)
    check("poll_row_survives_broken_json", _poll_from_row(dict(row_like, options_json="{oops"))["options"] == [])
    check("poll_row_survives_nulls", _poll_from_row(dict(row_like, ends_at_ms=None, created_at_ms=None))["ends_at_ms"] is None)
    check("topic_and_payload_prefixes_agree", topic_for("42").startswith(CLAIM_PREFIX + ":") and claims_poll_payload(topic_for("42")))

    # Two meta-assertions, so the printed count cannot be inflated or quiet: a duplicated
    # name means two checks share one label (and one of them is silently unreachable), and
    # the floor is the contract this function was asked to meet.
    check("check_names_are_unique", len(set(checks)) == len(checks))
    check("assertion_count_meets_the_contract", len(checks) >= 30)

    return checks


def _raises(expected, func, *args):  # type: ignore[no-untyped-def]
    """Run `func(*args)` and hand back the exception it raised, or an AssertionError.

    A helper rather than a try/except at forty call sites: the assertion a reader
    wants is about *which* refusal a case produces, and its message has to be
    inspectable (that is where the client's file:line lives).
    """
    try:
        func(*args)
    except expected as exc:
        return exc
    except Exception as exc:  # noqa: BLE001 - a wrong type is a failure, named as one
        raise AssertionError("expected %s from %r, got %s: %s" % (expected.__name__, getattr(func, "__name__", func), type(exc).__name__, exc)) from exc
    raise AssertionError("expected %s from %r, nothing raised" % (expected.__name__, getattr(func, "__name__", func)))
