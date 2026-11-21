# Copyright (c) 2026 POPOPX (popopx.chat)
# SPDX-License-Identifier: AGPL-3.0-only
"""DevOps alert plugin: a Grafana/Alertmanager webhook in, one red card out, acked in place.

The shape of the flow
---------------------

    POST /webhook  →  normalise (Grafana unified-alerting ∪ Alertmanager v4)
                   →  severity gate            →  below the floor: row only, no card
                   →  dedupe on fingerprint    →  repeat: UPDATE the row and its card IN PLACE
                   →  one card per (alert, target follower)
                   →  确认 on the phone  →  ::CB::alert:ack:<id>  →  status acknowledged
                                          →  progress 100% + a terminal button, same bubble
                   →  已解决 (webhook, console, or a whole-string keyword from the follower)

Everything is designed against one asymmetry: the client is shipped, and
`PopopxEcoParser.parse` answers `nil` for anything it cannot decode
(`PopopxEcoModels.swift:106-114`, and the same silent policy is stated at
`PopopxEcoModels.swift:45-47`). An over-long field is therefore not an error the
operator sees, it is an alert that never arrives — so every limit below is applied
before the frame leaves this process, and a violation is reported as a 4xx that
names the rule.

Two billing decisions, in prose
-------------------------------

First: **one `alert` charge per incident, keyed on the fingerprint.** An incident's
identity is its fingerprint (Grafana's, or a digest this module derives), so the
ledger key is `"alert:" + fingerprint` and is handed to
:func:`charge_request` from every path that can pay for the incident — a delivery
and an ack. Repeats of the same webhook, a resampled notification, an ack and a
second ack all produce the *same* string, and `billing_ledger.idempotency_key` is
`UNIQUE` (`database.py:275-285`), so the account is debited once however many
things fire. That is also why a re-fire of an already-resolved fingerprint costs
nothing new: it is the same incident by definition.

Second: **the `card` meter is never charged from here.** `deps.eco.deliver_card`
charges it as part of storing and sending the card
(`plugins/__init__.py:360-361` — "Store a card and deliver it as a `m=c` frame,
charging the `card` meter"), so a plugin that also charged `card` would bill every
alert notification twice, once for the product and once for the plugin's
impatience. `update_card` charges nothing at all, which is why flapping alerts move
a bubble without moving money: the money already paid for the incident.

What the measurements overrode (three times)
--------------------------------------------

1. The brief says an acked card's button becomes `kind="none"`. It cannot:
   `PopopxEcoAction.isSane` returns **false** for `.none`
   (`PopopxEcoModels.swift:688-689`), the card's own `isSane` requires
   `actions.allSatisfy(\.isSane)` (:534), and `PopopxEcoFrame.isSane` gates the
   parse (:148, :158-167) — one `none` action destroys the whole frame.
   `crypto_service.build_action` already refuses it for exactly that reason
   ("`'none' fails PopopxEcoAction.isSane (:685-702); omit the action`").
   Omitting the action is not available either: an update with an empty action list
   means *unchanged*, not cleared (`PopopxEcoRouterAndDeepLink.swift:178-186`), so
   the 确认 button would survive its own ack. The only wire-legal terminal state is
   a **non-empty list of legal actions**, so the acked card carries one
   `callback` button titled 已确认 whose payload is `alert:noop:<alert_id>` — a
   button the phone can press and the server answers with nothing. Self-test names:
   `terminal_action_is_not_none_kind`, `build_action_refuses_none_kind`.
2. "security is the red one" is not a field. `ServiceCardBubbleView.swift:219-227`
   derives the shield's colour from the card's own state: a `security` card reads
   red only when it is expired or carries a `destructive` action, and reads radar
   teal while a decision is pending. The brief asks for `style="security"` with a
   `primary` 确认 button, and that combination renders teal by the client's rule.
   This module does what was asked (style `security`, action `primary`) rather than
   styling an ack as destructive to buy a red badge; the colour note belongs to the
   client's derivation, and expiring the card to force red would also make it inert
   (`:175`, `:379` — `cardIsInert` drops every button, including 确认).
3. A callback payload is *not* free-form text: `sendCallback` requires a single
   token — non-empty, ≤512 characters, no whitespace, and no `::` inside it
   (`PopopxEcoRouterAndDeepLink.swift:496-498, 511-515`) — and refuses locally with
   `.malformedPayload` otherwise. So alert ids are minted from a restricted alphabet
   and every payload is checked by :func:`require_single_token` before a card is
   built.

The seams this file cannot close (reported, not patched)
--------------------------------------------------------

`app/main.py` does not exist yet in this checkout, so three things are assumptions
recorded here rather than verified: that the router is mounted, that console routes
sit behind the gateway's admin authentication (this module therefore re-checks the
admin bearer token itself — see :func:`_admin_refused`), and that plain text is
offered to :func:`resolve_keyword_match` before it is handed to the AI plugin
(the AI plugin owns `callback.kind == "text"`, `plugins/__init__.py:95-97`).
`alerts.card_id` is a single column while an alert is delivered to N followers, so
it stores the *primary* target's card and the full set is recoverable from
`cards.topic = 'alert:<alert_id>'`.

Module rule: stdlib + `app.*` at import time. FastAPI names are imported inside
:func:`create_router` — see the comment there for why they are also published into
module globals at runtime, which is a FastAPI annotation-resolution requirement and
not a style choice.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import math
import re
import secrets
import sqlite3
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any, Dict, List, Mapping, Optional, Sequence, Tuple

from app.crypto_service import (
    EcoError,
    EcoLimits,
    EcoValidationError,
    build_action,
    build_card,
    now_ms,
    validate_http_url,
)
from app.plugins import PluginDeps, PluginUnavailable

if TYPE_CHECKING:  # type-only; never imported at runtime
    from fastapi import APIRouter

    from app.agent_bridge import InboundMessage

__all__ = [
    "PLUGIN_ID",
    "SEVERITY_ORDER",
    "STATUS_FIRING",
    "STATUS_ACKNOWLEDGED",
    "STATUS_RESOLVED",
    "PAYLOAD_PREFIX",
    "SETTINGS_TARGETS_KEY",
    "AlertEvent",
    "AlertRecord",
    "AckPlan",
    "normalize_severity",
    "severity_rank",
    "passes_severity_gate",
    "parse_time_ms",
    "derive_fingerprint",
    "normalize_labels",
    "normalize_webhook_body",
    "plan_ingest",
    "plan_ack",
    "plan_resolve",
    "apply_ack",
    "apply_resolve",
    "truncate_for_card",
    "alert_display_title",
    "record_alertname",
    "build_alert_card",
    "card_fields",
    "card_progress",
    "card_actions",
    "status_label",
    "format_ms",
    "card_id_for",
    "new_alert_id",
    "sanitize_alert_id",
    "ack_payload",
    "terminal_payload",
    "claims_callback_payload",
    "parse_callback_payload",
    "require_single_token",
    "resolve_keyword_match",
    "resolve_by_keyword",
    "find_open_alert_for_contact",
    "authorize_webhook_token",
    "authorize_admin_token",
    "constant_compare",
    "charge_idempotency_key",
    "charge_request",
    "normalize_target_ids",
    "read_targets",
    "ingest_webhook",
    "ack_alert",
    "resolve_alert",
    "create_router",
    "handle_inbound",
    "self_test",
]

LOG = logging.getLogger("popopx.plugins.alert_ops")

PLUGIN_ID = "alert_ops"

#: The three strings the schema allows (`database.py:373-374`). Not "acked": the
#: CHECK constraint is the vocabulary, and a plugin that invents its own synonym
#: fails the insert on the merchant's box rather than on the developer's.
STATUS_FIRING = "firing"
STATUS_ACKNOWLEDGED = "acknowledged"
STATUS_RESOLVED = "resolved"
STATUS_VALUES = (STATUS_FIRING, STATUS_ACKNOWLEDGED, STATUS_RESOLVED)

#: Total order, weakest first (`silent` exists so an operator can park a meter
#: without switching the plugin off). Anything outside this vocabulary is mapped
#: in :func:`normalize_severity`.
SEVERITY_ORDER = ("silent", "debug", "info", "warning", "critical")

_SEVERITY_SYNONYMS: Dict[str, str] = {
    "silent": "silent",
    "suppress": "silent",
    "suppressed": "silent",
    "drop": "silent",
    "debug": "debug",
    "dbg": "debug",
    "trace": "debug",
    "verbose": "debug",
    "info": "info",
    "information": "info",
    "notice": "info",
    "low": "info",
    "p3": "info",
    "sev4": "info",
    "sev5": "info",
    "warning": "warning",
    "warn": "warning",
    "watch": "warning",
    "medium": "warning",
    "minor": "warning",
    "sev3": "warning",
    "p2": "warning",
    "critical": "critical",
    "crit": "critical",
    "fatal": "critical",
    "emergency": "critical",
    "disaster": "critical",
    "page": "critical",
    "high": "critical",
    "major": "critical",
    "error": "critical",
    "sev1": "critical",
    "sev2": "critical",
    "p1": "critical",
}

#: Labels excluded from a derived fingerprint. A digest that includes anything
#: time-varying would name the *notification* rather than the *incident*, and then
#: every resampled webhook would mint a fresh card and a fresh charge — which is
#: precisely the failure UNIQUE(fingerprint) exists to prevent.
#:
#: Deliberately a narrow, spelled-out blocklist rather than a "looks like a
#: timestamp" heuristic: `startsAt` and `endsAt` ride into a label map when a sender
#: templates them, `status`/`state` would make a resolve notification a different
#: incident, and the per-notification ids (`alert_instance_id`, Alertmanager's
#: `fingerprint` itself) name one delivery. `instance`, `job`, `cluster` and
#: `alertname` are identity and stay in — a heuristic keyed on the word "time" would
#: have quietly merged two different databases' alerts into one card.
#: Compared after :func:`_normalized_label_key`.
_VOLATILE_LABEL_KEYS = frozenset(
    {
        "startat",
        "startsats",
        "startsat",
        "start",
        "starttime",
        "endat",
        "endsat",
        "endsats",
        "end",
        "endtime",
        "firingat",
        "resolvedat",
        "silencestartsat",
        "timestamp",
        "time",
        "status",
        "state",
        "fingerprint",
        "alertinstanceid",
        "instanceid",
        "notificationid",
        "ruleid",
        "ruleuid",
        "dashboarduid",
        "dashboardurl",
        "panelid",
        "evalmatches",
        "groupkey",
        "receiver",
    }
)


def _normalized_label_key(key: str) -> str:
    """Case-fold a label name for comparison, without inventing a canonical spelling.

    Prometheus labels are case-sensitive, so this fold is used ONLY to decide
    exclusion from a digest — never to rename a key the operator sees on the card.
    """
    return key.strip().lower().replace("_", "").replace("-", "").replace(".", "")


PAYLOAD_PREFIX = "alert:"
PAYLOAD_VERB_ACK = "ack"
PAYLOAD_VERB_NOOP = "noop"
PAYLOAD_VERB_RESOLVE = "resolve"

#: `cards.topic` for every card this plugin delivers. The outbox/store index on
#: `cards(topic)` (`database.py:159`) is what lets a repeat webhook tell "this
#: follower already has this alert" from "this follower was added last week and has
#: never seen it", without a plugin-owned table.
TOPIC_PREFIX = "alert:"
SETTINGS_TARGETS_KEY = "alert_ops.targets"

#: One webhook may not schedule an unbounded number of cards: a flapping alert group
#: multiplied by every target is a bill and a flood, and the sender is a machine that
#: will simply try again. The excess is reported, never silently dropped.
MAX_ALERTS_PER_WEBHOOK = 50
MAX_TARGETS = 20
MAX_WEBHOOK_BYTES = 262_144
MAX_STORED_SUMMARY_CHARS = 4000
MAX_PAGE_LIMIT = 200
DEFAULT_PAGE_LIMIT = 50

#: Inclusive marker on a truncated string. Truncation must be *visible*: a body that
#: quietly ends mid-sentence reads like the alert itself was short.
TRUNCATION_MARKER = "…（截断）"

_ALERT_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,62}$")


# ─────────────────────────────────────────────────────────────────────────────
# 1. Severity
# ─────────────────────────────────────────────────────────────────────────────


def normalize_severity(raw: Any) -> str:
    """Map any spelling onto :data:`SEVERITY_ORDER`.

    The default is `warning`, deliberately *not* the lowest rank: an alert whose
    severity this module cannot read is an alert somebody configured badly, and the
    failure mode of guessing low is a page that never reaches a human — which is
    unrecoverable, where an unnecessary card is merely noise.
    """
    if raw is None:
        return "warning"
    text = str(raw).strip().lower()
    if not text:
        return "warning"
    return _SEVERITY_SYNONYMS.get(text, "warning" if text not in SEVERITY_ORDER else text)


def severity_rank(value: str) -> int:
    """Position in the total order; unknown names rank as `warning` (see above)."""
    normalized = value if value in SEVERITY_ORDER else normalize_severity(value)
    return SEVERITY_ORDER.index(normalized)


def passes_severity_gate(raw: Any, minimum: Any) -> bool:
    """The gate, with the boundary decided explicitly.

    `>=` and not `>`: an operator who sets `POPOPX_ALERT_MIN_SEVERITY=warning` means
    "warning and above", so a `warning` alert must pass. The equality case is the
    one a off-by-one gets wrong, and self_test names it
    (`gate_boundary_at_minimum_passes`).
    """
    return severity_rank(normalize_severity(raw)) >= severity_rank(normalize_severity(minimum))


# ─────────────────────────────────────────────────────────────────────────────
# 2. Time, labels, fingerprints — the normalisation half
# ─────────────────────────────────────────────────────────────────────────────

_TIME_FORMATS = (
    "%Y-%m-%dT%H:%M:%S%z",
    "%Y-%m-%dT%H:%M:%S.%f%z",
    "%Y-%m-%d %H:%M:%S%z",
    "%Y-%m-%dT%H:%M:%S",
    "%Y-%m-%d %H:%M:%S",
    "%Y-%m-%dT%H:%M",
)

#: A bare timestamp with no offset. Grafana and Alertmanager both emit UTC with an
#: explicit `Z`, so a naive value is what a hand-rolled sender produced; reading it
#: as UTC keeps this module's answers independent of the host's `TZ`, which a
#: merchant-manual interpretation would not be.
_DEFAULT_EPOCH_SECONDS = 1_000


def parse_time_ms(value: Any) -> Optional[int]:
    """ISO8601 (and epoch numbers) → epoch milliseconds, stdlib only.

    `datetime.fromisoformat` on 3.9 rejects a trailing `Z` and any offset without a
    colon, so the `Z` is rewritten and the remaining spellings fall through to
    `strptime`. Returns `None` for garbage rather than raising: one unparseable
    `startsAt` must not cost the operator the alert, and the caller substitutes
    arrival time (which is honest, and labelled as such in the card field).
    """
    if value is None:
        return None
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return _epoch_number(float(value))
    if isinstance(value, float):
        if math.isnan(value) or math.isinf(value):
            return None
        return _epoch_number(value)
    if not isinstance(value, str):
        return None
    text = value.strip()
    if not text or text in ("0001-01-01T00:00:00Z", "0001-01-01T00:00:00+00:00"):
        # Alertmanager's zero time for a firing alert's endsAt. Not a moment.
        return None
    candidate = text
    if candidate.endswith(("Z", "z")):
        candidate = candidate[:-1] + "+00:00"
    parsed: Optional[datetime] = None
    try:
        parsed = datetime.fromisoformat(candidate)
    except ValueError:
        parsed = None
    if parsed is None:
        for fmt in _TIME_FORMATS:
            try:
                parsed = datetime.strptime(candidate, fmt)
                break
            except ValueError:
                continue
    if parsed is None:
        # Last resort: a plain date, or milliseconds as digits in a string.
        if re.fullmatch(r"-?\d{10,16}", candidate):
            return _epoch_number(float(candidate))
        try:
            parsed = datetime.strptime(candidate[:10], "%Y-%m-%d")
        except ValueError:
            return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    try:
        return int(round(parsed.timestamp() * 1000))
    except (OverflowError, OSError, ValueError):
        return None


def _epoch_number(value: float) -> Optional[int]:
    """Accept seconds or milliseconds without asking the sender which it meant.

    The cutoff is 1e12 (about the year 33653 in seconds, 2001-09 in ms): anything
    below is seconds, anything at or above is already milliseconds. A sender that
    means microseconds gets truncated into the ms branch, which is off by exactly
    the factor a caller can see in the card's own 开始时间 field.
    """
    if value != value or value in (float("inf"), float("-inf")):
        return None
    if abs(value) < 1e12:
        value = value * 1000.0
    scaled = int(round(value))
    if scaled <= 0:
        return None
    return scaled


def _label_text(value: Any) -> str:
    """One label/annotation value as text, whatever JSON arrived with it.

    A Grafana template variable that resolved to a number, a bool, or a nested
    object is normal here. Non-scalars are re-serialised rather than rejected
    because the value is what the operator reads on the card.
    """
    if value is None:
        return ""
    if isinstance(value, str):
        return value.strip()
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return str(value)
    try:
        return json.dumps(value, ensure_ascii=False, separators=(",", ":"))
    except (TypeError, ValueError):
        return str(value)


def normalize_labels(raw: Any, *, drop_volatile: bool = False) -> Dict[str, str]:
    """`{k: v}` with string keys and values, in first-seen order.

    `drop_volatile` is for the fingerprint only: the card still shows everything the
    sender sent, it is the *identity* that must not move with the clock.
    """
    out: Dict[str, str] = {}
    if not isinstance(raw, Mapping):
        return out
    for key, value in raw.items():
        name = _label_text(key)
        if not name:
            continue
        if drop_volatile and _normalized_label_key(name) in _VOLATILE_LABEL_KEYS:
            continue
        text = _label_text(value)
        if not text:
            continue
        out[name] = text
    return out


def derive_fingerprint(alertname: str, labels: Mapping[str, str]) -> str:
    """A stable digest of (alertname, sorted labels) when the sender sent none.

    Why a *stable* digest is the whole trick: `alerts.fingerprint` is UNIQUE
    (`database.py:369-384`), and that constraint is what turns the second, third and
    hundredth notification of one incident into an UPDATE of one row and one card.
    A digest of anything time-varying would name the notification instead, so each
    resample would mint a new card, a new charge and a new ack the operator already
    gave. Sorting the pairs makes the digest independent of Go's map iteration
    order, which is why the pairs are sorted before they are joined and why the
    separator is a character that cannot appear in a normalised key.
    """
    pairs = sorted(
        "%s%c%s" % (key, 0x1F, value)
        for key, value in normalize_labels(labels, drop_volatile=True).items()
    )
    material = "%s\n%s" % (alertname or "", "|".join(pairs))
    digest = hashlib.sha256(material.encode("utf-8", "replace")).hexdigest()
    return digest[:32]


def _status_word(entry: Mapping[str, Any], fallback: str) -> str:
    """`firing|resolved` from an entry, else from the enclosing payload.

    Grafana's unified alerting puts `status` at the top level and may leave it out
    per alert; Alertmanager puts it on every alert and also spells `resolved`. The
    historical Prometheus webhook spells the resolved case `ok`. Anything
    unrecognised falls back to the envelope rather than guessing `firing`, because
    guessing firing on a resolved alert is a card that refuses to stop shouting.
    """
    raw = _label_text(entry.get("status")).lower()
    if raw in ("firing", "fired", "active", "triggered"):
        return STATUS_FIRING
    if raw in ("resolved", "ok", "success", "cleared", "inactive"):
        return STATUS_RESOLVED
    return fallback


# ─────────────────────────────────────────────────────────────────────────────
# 3. The normalised event and the stored record
# ─────────────────────────────────────────────────────────────────────────────


@dataclass(frozen=True, eq=False)
class AlertEvent:
    """One alert out of a webhook body, in this module's own vocabulary."""

    fingerprint: str
    status: str                # firing | resolved
    severity: str              # normalized, one of SEVERITY_ORDER
    alertname: str
    summary: str               # short line (annotations.summary, else description)
    description: str           # long line
    labels: Dict[str, str]
    starts_at_ms: Optional[int]
    ends_at_ms: Optional[int]
    source: str


@dataclass(frozen=True, eq=False)
class AlertRecord:
    """One `alerts` row, read defensively so a partially-written row still renders.

    `from_row` accepts any Mapping — a `sqlite3.Row`, a dict from the console, or
    the hand-built rows in self_test — and never raises for a NULL: every field has
    a value that means "not recorded", because the columns are nullable except the
    four the schema insists on.
    """

    alert_id: str
    fingerprint: str
    severity: str
    status: str
    title: str
    summary: str
    labels: Dict[str, str]
    card_id: Optional[str]
    source: str
    firing_at_ms: int
    ack_at_ms: Optional[int]
    ack_by_contact_id: Optional[int]
    resolved_at_ms: Optional[int]

    @property
    def is_terminal(self) -> bool:
        return self.status in (STATUS_ACKNOWLEDGED, STATUS_RESOLVED)

    @classmethod
    def from_row(cls, row: Mapping[str, Any]) -> "AlertRecord":
        def value(name: str) -> Any:
            try:
                return row[name]
            except (KeyError, IndexError, TypeError):
                return None

        labels_raw = value("labels_json")
        labels: Dict[str, str] = {}
        if isinstance(labels_raw, str) and labels_raw:
            try:
                decoded = json.loads(labels_raw)
            except ValueError:
                decoded = None
            if isinstance(decoded, Mapping):
                labels = {str(k): _label_text(v) for k, v in decoded.items()}
        elif isinstance(labels_raw, Mapping):
            labels = {str(k): _label_text(v) for k, v in labels_raw.items()}

        def as_int(name: str) -> Optional[int]:
            raw = value(name)
            if isinstance(raw, bool) or raw is None:
                return None
            try:
                return int(raw)
            except (TypeError, ValueError):
                return None

        severity = _label_text(value("severity")) or "warning"
        status = _label_text(value("status")).lower()
        if status not in STATUS_VALUES:
            status = STATUS_FIRING
        alert_id = _label_text(value("alert_id"))
        return cls(
            alert_id=alert_id,
            fingerprint=_label_text(value("fingerprint")),
            severity=severity,
            status=status,
            title=_label_text(value("title")) or alert_display_title(severity, alert_id),
            summary=_label_text(value("summary")),
            labels=labels,
            card_id=(None if value("card_id") in (None, "") else _label_text(value("card_id"))),
            source=_label_text(value("source")),
            firing_at_ms=as_int("firing_at_ms") or 0,
            ack_at_ms=as_int("ack_at_ms"),
            ack_by_contact_id=as_int("ack_by_contact_id"),
            resolved_at_ms=as_int("resolved_at_ms"),
        )

    @classmethod
    def from_event(
        cls,
        event: AlertEvent,
        alert_id: str,
        *,
        status: str,
        firing_at_ms: int,
        card_id: Optional[str] = None,
    ) -> "AlertRecord":
        """The row a webhook produces, before it has ever been acked."""
        return cls(
            alert_id=alert_id,
            fingerprint=event.fingerprint,
            severity=event.severity,
            status=status,
            title=alert_display_title(event.severity, event.alertname),
            summary=_clip(event.description or event.summary, MAX_STORED_SUMMARY_CHARS),
            labels=dict(event.labels),
            card_id=card_id,
            source=event.source,
            firing_at_ms=firing_at_ms,
            ack_at_ms=None,
            ack_by_contact_id=None,
            resolved_at_ms=None,
        )


def _clip(text: str, limit: int) -> str:
    return text if len(text) <= limit else text[:limit]


def truncate_for_card(text: str, limit: int, *, marker: str = TRUNCATION_MARKER) -> str:
    """Cut to the client's limit, and say so.

    The result is always ≤ `limit` characters *including* the marker, because the
    client compares `String.count` against the cap
    (`PopopxEcoModels.swift:524-538`) and a marker that pushes the total one over
    turns a truncated alert into a dropped one. A string already at the limit is
    returned untouched, so the marker means "bytes were lost here", not "this is
    long".
    """
    if not isinstance(text, str):
        text = _label_text(text)
    if limit <= 0:
        return ""
    if len(text) <= limit:
        return text
    if limit <= len(marker):
        return text[:limit]
    keep = limit - len(marker)
    body = text[:keep].rstrip()
    if not body:
        return marker[:limit]
    return body + marker


def format_ms(ms: Optional[int]) -> str:
    """A UTC minute stamp for a card field. Never host-local: two gateways, one text."""
    if not ms or ms <= 0:
        return ""
    try:
        return datetime.fromtimestamp(ms / 1000.0, tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    except (OverflowError, OSError, ValueError):
        return ""


def alert_display_title(severity: str, alertname: str) -> str:
    """`[severity] alertname` inside `card_title_chars`.

    The severity token is never sacrificed to the name: the prefix is the part a
    scanner reads at speed, so the *name* absorbs the truncation
    (`PopopxEcoModels.swift:53-53` title cap, enforced at :527-528).
    """
    label = _label_text(alertname) or "alert"
    prefix = "[%s] " % normalize_severity(severity)
    budget = EcoLimits.card_title_chars - len(prefix)
    if budget <= 0:
        return truncate_for_card(prefix, EcoLimits.card_title_chars)
    return prefix + truncate_for_card(label, budget)


# ─────────────────────────────────────────────────────────────────────────────
# 4. Webhook body → events
# ─────────────────────────────────────────────────────────────────────────────


def _detect_source(body: Mapping[str, Any]) -> str:
    """Which sender this looks like — recorded on the row for the operator, never trusted.

    Grafana's unified-alerting webhook and Alertmanager's v4 webhook share the
    `{status, alerts[]}` skeleton, so the discriminator is the envelope's own
    vocabulary: `state`/`ruleId`/`title` are Grafana's, `groupKey`/`externalURL`/
    `receiver` are Alertmanager's. The answer only decorates a row and a card field;
    nothing about dedupe or billing depends on it, because a sender that lies about
    what it is must still land on one row per incident.
    """
    if "state" in body or "ruleId" in body or "ruleUID" in body or "dashboardUrl" in body:
        return "grafana"
    if "groupKey" in body or "externalURL" in body or "receiver" in body:
        return "alertmanager"
    if "title" in body and "alerts" in body:
        return "grafana"
    return "webhook"


def normalize_alert_entry(entry: Mapping[str, Any], fallback_status: str, source: str) -> Optional[AlertEvent]:
    """One `alerts[]` element → :class:`AlertEvent`. `None` when there is nothing nameable.

    Missing `labels` is the normal case for a hand-built webhook, not an error: the
    alert name is then read from the top-level title (Grafana puts
    `"{alertname} firing"` there) and the fingerprint is derived, which is what the
    digest exists for.
    """
    if not isinstance(entry, Mapping):
        return None
    labels = normalize_labels(entry.get("labels"))
    annotations = normalize_labels(entry.get("annotations"))
    alertname = labels.get("alertname") or labels.get("Alertname") or ""
    if not alertname:
        alertname = annotations.get("alertname") or ""
    if not alertname:
        alertname = _label_text(entry.get("name")) or _label_text(entry.get("title"))
    alertname = _label_text(alertname)
    if not alertname:
        # An element with no name anywhere cannot be deduped, acked or usefully
        # shown. Counted by the caller rather than turned into an empty card.
        return None
    fingerprint = _label_text(entry.get("fingerprint"))
    if not fingerprint:
        fingerprint = derive_fingerprint(alertname, labels)
    summary = annotations.get("summary") or annotations.get("description") or ""
    description = annotations.get("description") or ""
    if not summary and not description:
        summary = annotations.get("message") or ""
    return AlertEvent(
        fingerprint=truncate_for_card(fingerprint, EcoLimits.payload_chars, marker=""),
        status=_status_word(entry, fallback_status),
        severity=normalize_severity(labels.get("severity") or entry.get("severity")),
        alertname=_clip(alertname, 240),
        summary=_clip(summary, MAX_STORED_SUMMARY_CHARS),
        description=_clip(description, MAX_STORED_SUMMARY_CHARS),
        labels=labels,
        starts_at_ms=parse_time_ms(entry.get("startsAt") or entry.get("firing_at") or entry.get("starts_at")),
        ends_at_ms=parse_time_ms(entry.get("endsAt") or entry.get("resolved_at") or entry.get("ends_at")),
        source=source,
    )


def normalize_webhook_body(body: Any) -> Tuple[List[AlertEvent], List[str], str]:
    """Grafana unified-alerting *and* Alertmanager v4 JSON → events + warnings.

    Both shapes are `{status, alerts: [...]}`, so one reader handles them; the
    warnings list is what the response carries instead of a stack trace when the
    body was JSON but not an alert payload. The top-level `status` is the fallback
    for elements that omit their own.
    """
    if not isinstance(body, Mapping):
        return [], ["body is a %s, expected a JSON object" % type(body).__name__], "webhook"
    source = _detect_source(body)
    top = _status_word(body, STATUS_FIRING)
    raw_alerts = body.get("alerts")
    if raw_alerts is None:
        # A single alert sent as the object itself is a common hand-rolled shape.
        if "labels" in body or "fingerprint" in body:
            raw_alerts = [body]
        else:
            return [], ["no 'alerts' array in the body"], source
    if not isinstance(raw_alerts, (list, tuple)):
        return [], ["'alerts' is a %s, expected an array" % type(raw_alerts).__name__], source
    events: List[AlertEvent] = []
    warnings: List[str] = []
    skipped = 0
    for entry in raw_alerts:
        event = normalize_alert_entry(entry if isinstance(entry, Mapping) else {}, top, source)
        if event is None:
            skipped += 1
            continue
        events.append(event)
    if skipped:
        warnings.append("%d element(s) had no alertname and were skipped" % skipped)
    return events, warnings, source


# ─────────────────────────────────────────────────────────────────────────────
# 5. The state machine, as pure functions
# ─────────────────────────────────────────────────────────────────────────────


def plan_ingest(existing_status: Optional[str], event_status: str) -> str:
    """What a webhook does to the stored status.

    Four cases, all decided on the side of not losing an operator's work:

    * `resolved` event → resolved, whatever the row said;
    * `firing` on a resolved row → firing again (a re-fire: the same incident by
      fingerprint, so no second card, no second charge, but the bubble wakes up);
    * `firing` on an acknowledged row → stays acknowledged. Grafana resamples; a
      resample is not evidence that the human's ack should be undone;
    * new row → the event's status.
    """
    if event_status == STATUS_RESOLVED:
        return STATUS_RESOLVED
    if existing_status == STATUS_ACKNOWLEDGED:
        return STATUS_ACKNOWLEDGED
    if existing_status == STATUS_RESOLVED:
        return STATUS_FIRING
    return STATUS_FIRING


@dataclass(frozen=True)
class AckPlan:
    """The decision about one ack, before anything is written.

    `replay` and `changed` are the two halves that matter to the ledger: only a
    `changed` transition may charge or re-deliver, so a double tap on a card whose
    update has not landed yet — the realistic case, since the phone locks the button
    only until the card changes (`PopopxEcoRouterAndDeepLink.swift:57`) — costs
    nothing and repaints nothing.
    """

    allowed: bool
    changed: bool
    replay: bool
    reason: str
    status: str
    at_ms: int
    idempotency_key: str


def charge_idempotency_key(fingerprint: str, alert_id: str) -> str:
    """`"alert:" + fingerprint`, or the row's own id when there is no fingerprint.

    The fingerprint is what makes the key mean *incident*; the alert_id fallback
    keeps the property "at most one charge per thing we can name" for the rows an
    older build wrote with the column NULL, rather than either refusing the ack or
    handing every retry a fresh debit.
    """
    text = _label_text(fingerprint)
    if text:
        return "alert:" + text
    return "alert:id:" + _label_text(alert_id)


def _transition(
    status: str,
    *,
    fingerprint: str,
    alert_id: str,
    actor_is_target: bool,
    require_actor: bool,
    now: int,
    to_status: str,
    illegal_reason: str,
) -> AckPlan:
    key = charge_idempotency_key(fingerprint, alert_id)
    if require_actor and not actor_is_target:
        return AckPlan(False, False, False, "not_a_target", status, 0, key)
    if status == to_status:
        return AckPlan(True, False, True, "already_" + to_status, status, 0, key)
    if status not in STATUS_VALUES:
        # A row written by something that is not this plugin. Refusing to invent a
        # transition keeps the CHECK constraint's vocabulary honest.
        return AckPlan(False, False, False, "unknown_status", status, 0, key)
    if status == STATUS_RESOLVED and to_status == STATUS_ACKNOWLEDGED:
        return AckPlan(False, False, False, illegal_reason, status, 0, key)
    return AckPlan(True, True, False, "ok", to_status, now, key)


def plan_ack(
    status: str,
    *,
    fingerprint: str = "",
    alert_id: str = "",
    actor_is_target: bool = True,
    require_actor: bool = True,
    now: Optional[int] = None,
) -> AckPlan:
    """`firing → acknowledged`, with a replay that is not a transition."""
    return _transition(
        status,
        fingerprint=fingerprint,
        alert_id=alert_id,
        actor_is_target=actor_is_target,
        require_actor=require_actor,
        now=now if now is not None else now_ms(),
        to_status=STATUS_ACKNOWLEDGED,
        illegal_reason="already_resolved",
    )


def plan_resolve(
    status: str,
    *,
    fingerprint: str = "",
    alert_id: str = "",
    now: Optional[int] = None,
) -> AckPlan:
    """`firing|acknowledged → resolved`. A resolved row replaying is a no-op."""
    return _transition(
        status,
        fingerprint=fingerprint,
        alert_id=alert_id,
        actor_is_target=True,
        require_actor=False,
        now=now if now is not None else now_ms(),
        to_status=STATUS_RESOLVED,
        illegal_reason="already_resolved",
    )


def apply_ack(record: AlertRecord, contact_id: Optional[int], at_ms: int) -> AlertRecord:
    return replace(
        record,
        status=STATUS_ACKNOWLEDGED,
        ack_at_ms=at_ms,
        ack_by_contact_id=contact_id,
    )


def apply_resolve(record: AlertRecord, at_ms: int) -> AlertRecord:
    return replace(record, status=STATUS_RESOLVED, resolved_at_ms=at_ms)


# ─────────────────────────────────────────────────────────────────────────────
# 6. Payloads, tokens, targets
# ─────────────────────────────────────────────────────────────────────────────


def new_alert_id() -> str:
    """`al-<16 hex>`.

    A restricted alphabet is not cosmetic: the id is embedded in a callback payload,
    and the phone refuses to send a payload containing whitespace or `::`
    (`PopopxEcoUplink.isSendablePayload`, enforced by `PopopxEcoUplink.wireString`). 8 bytes also keeps
    `alert:ack:<id>` comfortably inside the 512-character payload cap.
    """
    return "al-" + secrets.token_hex(8)


def sanitize_alert_id(raw: Any) -> str:
    """Validate an id that came back from a device. `""` when it is not one."""
    text = _label_text(raw)
    if not text or not _ALERT_ID_RE.match(text):
        return ""
    return text


def ack_payload(alert_id: str) -> str:
    return "%s%s:%s" % (PAYLOAD_PREFIX, PAYLOAD_VERB_ACK, alert_id)


def terminal_payload(verb: str, alert_id: str) -> str:
    return "%s%s:%s" % (PAYLOAD_PREFIX, verb, alert_id)


def require_single_token(text: str, what: str = "payload") -> str:
    """The client's own payload rule, applied before the frame is built.

    `PopopxEcoRouterAndDeepLink.swift:496-498` is a *local* refusal: the phone
    simply does not send the callback, so a payload this module built but the device
    will not emit is a dead button that looks alive. Raising here turns that into a
    4xx naming the rule.
    """
    if not isinstance(text, str) or not text:
        raise EcoValidationError("action_payload", "%s must be a non-empty string" % what)
    if len(text) > EcoLimits.payload_chars:
        raise EcoValidationError(
            "action_payload",
            "%s is %d characters, over the client's %d" % (what, len(text), EcoLimits.payload_chars),
        )
    if any(char.isspace() for char in text):
        raise EcoValidationError("action_payload", "%s must contain no whitespace: %r" % (what, text[:40]))
    if "::" in text:
        raise EcoValidationError("action_payload", "%s must not contain '::': %r" % (what, text[:40]))
    return text


def claims_callback_payload(payload: Any) -> bool:
    """The `alert:` claim. Anything else is somebody else's protocol step."""
    return isinstance(payload, str) and payload.startswith(PAYLOAD_PREFIX)


def parse_callback_payload(payload: Any) -> Optional[Tuple[str, str]]:
    """`alert:<verb>:<arg>` → `(verb, arg)`; `None` when the payload is not ours.

    Split with `maxsplit=2` so the argument keeps whatever it has inside it, and the
    verb is lower-cased because the phone sends exactly what we put in the card — a
    case difference would be a server bug, not a client one, but tolerating it costs
    nothing and turns it into a non-event.
    """
    if not claims_callback_payload(payload):
        return None
    parts = str(payload)[len(PAYLOAD_PREFIX):].split(":", 2)
    if not parts or not parts[0]:
        return None
    verb = parts[0].lower()
    arg = parts[1] if len(parts) > 1 else ""
    if verb not in (PAYLOAD_VERB_ACK, PAYLOAD_VERB_NOOP, PAYLOAD_VERB_RESOLVE):
        return None
    return verb, arg


def constant_compare(provided: str, expected: str) -> bool:
    """`hmac.compare_digest` on bytes — a length-varying early-out is an oracle."""
    if not isinstance(provided, str) or not isinstance(expected, str):
        return False
    return hmac.compare_digest(provided.encode("utf-8", "replace"), expected.encode("utf-8", "replace"))


def _bearer_or_header(headers: Mapping[str, str], header_name: str) -> str:
    """Case-insensitive header read, with the `Bearer ` prefix dropped."""
    wanted = header_name.lower()
    raw = ""
    for key, value in (headers.items() if isinstance(headers, Mapping) else ()):
        if str(key).lower() == wanted:
            raw = _label_text(value)
            break
    if not raw:
        for key, value in (headers.items() if isinstance(headers, Mapping) else ()):
            if str(key).lower() == "authorization":
                raw = _label_text(value)
                break
    if raw.lower().startswith("bearer "):
        raw = raw[7:].strip()
    return raw


def authorize_webhook_token(headers: Mapping[str, str], configured: str) -> Tuple[bool, str]:
    """The alert webhook's own credential.

    An unset token refuses everything and names the variable. A webhook that mints
    red cards on someone's phone must never be open by accident, and the accident
    that this guards is the one a deployment makes silently: `load_config` already
    appends a warning for this combination (`config.py:477-481`), and the warning is
    not a gate.
    """
    expected = configured if isinstance(configured, str) else ""
    if not expected.strip():
        return False, "POPOPX_ALERT_WEBHOOK_TOKEN is not configured; refusing to accept an unauthenticated webhook"
    provided = _bearer_or_header(headers, "X-Popopx-Alert-Token")
    if not provided:
        return False, "missing credential: send 'Authorization: Bearer <token>' or 'X-Popopx-Alert-Token: <token>'"
    if constant_compare(provided, expected.strip()):
        return True, "ok"
    return False, "alert webhook token does not match"


def authorize_admin_token(headers: Mapping[str, str], configured: str) -> Tuple[bool, str]:
    """The gateway's admin credential, re-checked here for the console routes.

    This module cannot see `app/main.py` (it does not exist in this checkout), so it
    cannot know that the console routes are already behind the gateway's admin
    middleware. The routes list and ack alerts for a whole deployment and expose
    contact ids, so the safe default is to require the token in-process: if the
    gateway also enforces it, this check is redundant and passes on the same header;
    if it does not, this is the only thing between an internal alert surface and the
    public interface.
    """
    expected = configured if isinstance(configured, str) else ""
    if not expected.strip():
        return False, "POPOPX_ADMIN_TOKEN is not configured; the alert console is refusing every request"
    # Both spellings, because the gateway's own refusal says *"provide the
    # X-Admin-Token header"*: a console route that rejects the header the core just
    # named is a trap for the operator following the error message. The shipped
    # console sends `x-admin-token`, `X-Popopx-Admin-Token` and `Authorization`
    # together, which is why this was invisible from a browser.
    provided = (
        _bearer_or_header(headers, "X-Popopx-Admin-Token")
        or _bearer_or_header(headers, "X-Admin-Token")
    )
    if not provided:
        return False, "missing admin credential"
    if constant_compare(provided, expected.strip()):
        return True, "ok"
    return False, "admin token does not match"


def normalize_target_ids(raw: Any) -> Tuple[List[int], List[str]]:
    """`[..., contact ids ...]` → ordered, de-duplicated, non-negative ints.

    JSON from `settings` may carry strings (an operator pasting ids from a
    `/_contacts` dump), and `contact_id` is an INTEGER primary key
    (`database.py:86-96`), so the coercion happens here rather than as a TypeError
    inside a delivery loop. Bools are rejected on purpose: `True` is a `1` to
    Python and a wrong contact to a node.
    """
    if raw is None:
        return [], []
    if not isinstance(raw, (list, tuple, set)):
        raw = [raw]
    out: List[int] = []
    warnings: List[str] = []
    for item in raw:
        if isinstance(item, bool):
            warnings.append("ignored boolean target")
            continue
        try:
            value = int(str(item).strip())
        except (TypeError, ValueError):
            warnings.append("ignored non-integer target %r" % (item,))
            continue
        if value <= 0:
            warnings.append("ignored non-positive target %d" % value)
            continue
        if value not in out:
            out.append(value)
    if len(out) > MAX_TARGETS:
        warnings.append("truncated %d targets to %d" % (len(out), MAX_TARGETS))
        out = out[:MAX_TARGETS]
    return out, warnings


def read_targets(deps: PluginDeps) -> Tuple[List[int], List[str]]:
    """The configured follower list, and the honest answer when it is empty.

    The default is nobody. That is the whole point: the worst possible default for
    an internal DevOps alert is to broadcast it to every follower of the service
    account, which would send a merchant's incident titles and fingerprint digests
    to their customers, cost one `card` charge per recipient, and teach those
    customers to mute the account. `db.get_setting` returns whatever the row held,
    so a corrupt value degrades to an empty list rather than to a broadcast.
    """
    raw = deps.db.get_setting(SETTINGS_TARGETS_KEY, [])
    return normalize_target_ids(raw)


# ─────────────────────────────────────────────────────────────────────────────
# 7. The card
# ─────────────────────────────────────────────────────────────────────────────


def _field(label: str, value: str, *, mono: bool = False) -> Dict[str, Any]:
    entry: Dict[str, Any] = {"k": label, "v": value}
    if mono:
        entry["mono"] = True
    return entry


def limit_fields(candidates: Sequence[Mapping[str, Any]]) -> List[Mapping[str, Any]]:
    """Drop rows the client would not accept, then cap at `max_fields`.

    `Field.isSane` requires a non-empty label **and** a non-empty value
    (`PopopxEcoModels.swift:565-568`), so an alert with no `instance` label must
    omit that row: sending `{"k":"实例","v":""}` does not render a blank, it makes
    the whole card undecodable. The count cap is :attr:`EcoLimits.max_fields`.
    """
    kept: List[Mapping[str, Any]] = []
    for candidate in candidates:
        label = _label_text(candidate.get("k"))
        value = _label_text(candidate.get("v"))
        if not label or not value:
            continue
        if len(label) > EcoLimits.field_label_chars:
            label = truncate_for_card(label, EcoLimits.field_label_chars, marker="…")
        if len(value) > EcoLimits.field_value_chars:
            value = truncate_for_card(value, EcoLimits.field_value_chars, marker="…")
        entry: Dict[str, Any] = {"k": label, "v": value}
        if candidate.get("mono"):
            entry["mono"] = True
        kept.append(entry)
        if len(kept) >= EcoLimits.max_fields:
            break
    return kept


def card_fields(record: AlertRecord) -> List[Mapping[str, Any]]:
    """alertname / severity / fingerprint / started, plus anything the sender labelled.

    The four required rows come first because `limit_fields` truncates from the
    end, and a label-heavy Alertmanager group must not push the fingerprint off the
    card — the fingerprint is the row an operator greps for in the sender's own UI.
    """
    candidates: List[Mapping[str, Any]] = [
        _field("告警名称", record_alertname(record)),
        _field("严重级别", record.severity),
        _field("状态", status_label(record.status)),
        _field("指纹", record.fingerprint, mono=True),
        _field("开始时间", format_ms(record.firing_at_ms), mono=True),
    ]
    for key in ("instance", "cluster", "job", "service", "team"):
        value = record.labels.get(key)
        if value:
            candidates.append(_field(key, value, mono=(key == "instance")))
    return limit_fields(candidates)


# The row stores the display title, not a separate alertname column (`alerts` has no
# such column — database.py:369-384), so the name a card shows is the title with the
# severity prefix this module added. Splitting the two would need a schema change.
def record_alertname(record: AlertRecord) -> str:
    text = _label_text(record.title)
    if text.startswith("["):
        _head, _sep, tail = text.partition("] ")
        return tail or text
    return text or "alert"


def status_label(status: str) -> str:
    return {
        STATUS_FIRING: "待确认",
        STATUS_ACKNOWLEDGED: "已确认",
        STATUS_RESOLVED: "已解决",
    }.get(status, "待确认")


def card_body(record: AlertRecord) -> Optional[str]:
    """The long line, cut to `card_body_chars` with a visible marker.

    Omitted entirely when there is nothing to say: an empty body renders as an empty
    paragraph in `ServiceCardBubbleView`, and a card whose body is a bare whitespace
    string is what `_text(..., required=False)` accepts but nobody can read.
    """
    text = _label_text(record.summary)
    if not text:
        return None
    return truncate_for_card(text, EcoLimits.card_body_chars)


def card_progress(record: AlertRecord, *, actor_label: str = "") -> Dict[str, Any]:
    """`{"l","p","d"}` — the key names and the 0..100 range the client decodes.

    `PopopxServiceCard.Progress.CodingKeys` is `label = "l"`, `percent = "p"`,
    `detail = "d"` (`PopopxEcoModels.swift:577-581`), and `isSane` requires a
    non-empty label within `maximumLabelCharacters` (80), a percent inside
    `0...maximumProgressPercent` = 100, and a detail within
    `maximumValueCharacters` (240) (`PopopxEcoModels.swift:589-594`, limits at
    :55-64). `crypto_service.build_card` re-checks all three with the same numbers
    (`crypto_service.py:636-648`), so an out-of-range percent is an exception here
    rather than a dropped frame.
    """
    if record.status == STATUS_FIRING:
        # Exactly the brief's `{"l":"状态","p":0,"d":"待确认"}`: nothing decorative
        # in the one string that is on screen before an operator decides.
        label, percent, text = "状态", 0, status_label(STATUS_FIRING)
    elif record.status == STATUS_RESOLVED:
        label, percent = "状态", EcoLimits.progress_percent_max
        when = format_ms(record.resolved_at_ms)
        text = "已解决" + (" · %s" % when if when else "")
    else:
        label, percent = "状态", EcoLimits.progress_percent_max
        when = format_ms(record.ack_at_ms)
        who = actor_label or ("联系人%d" % record.ack_by_contact_id if record.ack_by_contact_id else "")
        text = " · ".join([piece for piece in (status_label(STATUS_ACKNOWLEDGED), who, when) if piece])
    return {
        "l": truncate_for_card(label, EcoLimits.field_label_chars, marker="…"),
        "p": percent,
        "d": truncate_for_card(text, EcoLimits.field_value_chars, marker="…"),
    }


def card_actions(record: AlertRecord, detail_url: Optional[str] = None) -> List[Dict[str, Any]]:
    """The buttons, and the reason the terminal one is a callback and not `none`.

    Firing: 确认 (`callback`, `primary`) plus 详情 (`open_url`) when this follower
    has a usable session to sign it with. Acked or resolved: one inert-by-agreement
    button whose payload the server answers with nothing — see the module docstring
    for why `kind="none"` and an empty action list are both unavailable on the wire.
    Never more than two actions, well inside :attr:`EcoLimits.max_actions`.
    """
    actions: List[Dict[str, Any]] = []
    alert_id = sanitize_alert_id(record.alert_id)
    if not alert_id:
        # A row whose id is unusable cannot carry a callback: a payload the phone
        # refuses to send is a dead button, so the card ships without one.
        return actions
    if record.is_terminal:
        verb = PAYLOAD_VERB_NOOP
        title = status_label(record.status)
        payload = require_single_token(terminal_payload(verb, alert_id), "terminal payload")
        actions.append(build_action(action_id="alert-terminal", title=title, kind="callback", style="secondary", payload=payload))
    else:
        payload = require_single_token(ack_payload(alert_id), "ack payload")
        actions.append(
            build_action(action_id="alert-ack", title="确认", kind="callback", style="primary", payload=payload)
        )
    if detail_url and not record.is_terminal:
        # A terminal card carries exactly one action, per the brief's "the ack
        # action is replaced by one". The follow-up after an ack is the console,
        # not another H5 hop.
        try:
            checked = validate_http_url(detail_url)
        except EcoError:
            LOG.warning("alert %s: detail url rejected by the client url rule, action omitted", alert_id)
            return actions
        actions.append(
            build_action(
                action_id="alert-detail",
                title="详情",
                kind="open_url",
                style="secondary",
                url=checked,
            )
        )
    return actions


def card_id_for(alert_id: str, contact_id: int) -> str:
    """One card per (alert, follower), with an id stable across updates.

    `cards.card_id` is a primary key (`database.py:135-157`) and the client mutates
    a bubble by looking its id up, so an alert delivered to three followers is three
    cards with three ids — and the id must be *derivable* from (alert, contact), not
    random, or a repeat webhook could not find the bubbles it is supposed to update
    in place.
    """
    safe = sanitize_alert_id(alert_id) or "al-unknown"
    digits = re.sub(r"\D", "", str(int(contact_id))) if isinstance(contact_id, int) else "0"
    return truncate_for_card("alert.%s.%s" % (safe, digits or "0"), EcoLimits.card_id_chars, marker="")


def build_alert_card(record: AlertRecord, *, card_id: str, detail_url: Optional[str] = None, actor_label: str = "") -> Dict[str, Any]:
    """The wire card for a record, in whatever state the record is in.

    `style="security"` is the shield face (`PopopxEcoModels.swift:443-444`,
    rendered at `ServiceCardBubbleView.swift:230-239`), and `build_card` fills `ut`
    so the client's newest-wins comparison
    (`PopopxEcoRouterAndDeepLink.swift:151`) can order this frame against the one
    before it. `m` is not written here: the frame carries the mode, and the nested
    field is ignored on decode (`crypto_service.py:606-612`).
    """
    body = card_body(record)
    fields = card_fields(record)
    actions = card_actions(record, detail_url)
    return build_card(
        card_id,
        truncate_for_card(record.title, EcoLimits.card_title_chars),
        style="security",
        body=body,
        fields=fields or None,
        progress=card_progress(record, actor_label=actor_label),
        actions=actions or None,
    )


# ─────────────────────────────────────────────────────────────────────────────
# 8. The resolve keywords
# ─────────────────────────────────────────────────────────────────────────────


def resolve_keyword_match(text: Any, keywords: Sequence[str]) -> Optional[str]:
    """Whole-string keyword match. Pure, and self-tested.

    Returns the keyword that matched (normalised), or `None`.

    The comparison is equality of the whole trimmed string, lower-cased for the
    ASCII case-fold, deliberately **not** a substring search. A substring rule in
    CJK needs word segmentation that Chinese does not provide with spaces, and
    without it `请确认收货` ("please confirm the delivery") contains `确认` and would
    ack an unrelated production alert while a customer asked about a parcel. A
    merchant's fulfilment sentence must never reach an operator's state machine, so
    the safe default is equality and the price is that an operator has to send the
    keyword alone — which is what a canned reply or a button does anyway.

    Case-insensitivity is `str.lower()` and not `casefold()`: the configured list is
    already lower-cased by `config.load_config` (`config.py:431-432`), `lower()` is
    identity for CJK, and `casefold()` expands `ß` to `ss`, which would make the
    gateway's reading of a keyword differ from the operator's spelling of it.
    """
    if not isinstance(text, str):
        return None
    if not keywords:
        return None
    folded = text.strip().lower()
    if not folded:
        return None
    for keyword in keywords:
        if not isinstance(keyword, str):
            continue
        candidate = keyword.strip().lower()
        if candidate and folded == candidate:
            return candidate
    return None


# ─────────────────────────────────────────────────────────────────────────────
# 9. Billing shape
# ─────────────────────────────────────────────────────────────────────────────


def charge_request(*, fingerprint: str, alert_id: str, contact_id: Optional[int], severity: str = "") -> Dict[str, Any]:
    """The keyword arguments of the one `alert` charge for an incident.

    Split out as a pure function so "the key is a function of the fingerprint and
    nothing else" is something self_test can prove rather than something the reader
    has to trust. `meta` carries ids and a severity only — never a webhook body.
    """
    key = charge_idempotency_key(fingerprint, alert_id)
    meta: Dict[str, Any] = {"alert_id": alert_id, "plugin": PLUGIN_ID}
    if severity:
        meta["severity"] = severity
    return {
        "contact_id": contact_id,
        "ref": alert_id,
        "idempotency_key": key,
        "meta": meta,
    }


def _charge_incident(deps: PluginDeps, record: AlertRecord, contact_id: Optional[int]) -> Tuple[int, Optional[str]]:
    """Charge the incident. Returns `(credits, warning)`.

    `deps.charge` injects the meter name from the mount table positionally
    (`plugins/__init__.py:434-445`) — it takes **no** positional arguments, so the
    brief's `deps.charge("alert", ...)` form would be a TypeError. The correct call
    is keyword-only, and if this plugin was mounted with a spec whose meter is not
    `alert` the charge goes to `deps.billing.charge("alert", ...)` directly rather
    than silently pricing incidents on another plugin's meter.
    """
    kwargs = charge_request(
        fingerprint=record.fingerprint,
        alert_id=record.alert_id,
        contact_id=contact_id,
        severity=record.severity,
    )
    try:
        if getattr(deps.spec, "meter", None) == "alert":
            result = deps.charge(**kwargs)
        else:
            LOG.error("alert_ops mounted with meter %r; charging 'alert' explicitly", getattr(deps.spec, "meter", None))
            result = deps.billing.charge("alert", **kwargs)
    except Exception as exc:  # noqa: BLE001 - BillingError and anything the ledger raises
        code = getattr(exc, "code", "charge_failed")
        LOG.warning("alert %s: charge refused (%s)", record.alert_id, code)
        return 0, "计费未入账（%s）：告警与确认已记录，请稍后补账" % code
    charged = int(getattr(result, "charged", 0) or 0)
    return charged, None


# ─────────────────────────────────────────────────────────────────────────────
# 10. Delivery and the two entry points
# ─────────────────────────────────────────────────────────────────────────────


def _delivery_targets(deps: PluginDeps, alert_id: str) -> Dict[int, str]:
    """Which followers already hold a card for this alert, and which do not.

    Read from `cards.topic`, so "newly added target" and "repeat webhook" cannot be
    confused — the distinction that decides `deliver_card` versus `update_card`, and
    therefore whether the phone shows a second bubble.
    """
    rows = deps.db.query(
        "SELECT contact_id, card_id FROM cards WHERE topic = ? AND contact_id IS NOT NULL",
        (TOPIC_PREFIX + alert_id,),
    )
    out: Dict[int, str] = {}
    for row in rows:
        try:
            contact_id = int(row["contact_id"])
        except (TypeError, ValueError, IndexError, KeyError):
            continue
        card_id = _label_text(row["card_id"])
        if card_id:
            out[contact_id] = card_id
    return out


def _detail_url(deps: PluginDeps, contact_id: int, alert_id: str) -> Optional[str]:
    """A signed H5 link for *this* follower, or None.

    Never a URL signed with a missing or revoked session: `h5_url` needs the
    pairwise secret (`plugins/__init__.py:380-382`) and `EcoSession.usable` is the
    predicate that says the phone can still verify what it opens
    (`plugins/__init__.py:288-306`). No session therefore means no button — a card
    with a dead link is worse than a card without one, because the link looks tappable.
    """
    session = deps.eco.session_for(contact_id)
    if session is None or not session.usable:
        return None
    try:
        return deps.eco.h5_url(session, "/alerts/%s" % alert_id)
    except EcoError as exc:
        LOG.warning("alert %s: h5_url failed for contact %d (%s); detail action omitted", alert_id, contact_id, exc.rule)
        return None


def _actor_label(deps: PluginDeps, contact_id: Optional[int]) -> str:
    if contact_id is None:
        return "控制台"
    row = deps.db.query_one(
        "SELECT local_display_name, display_name FROM contacts WHERE contact_id = ?",
        (int(contact_id),),
    )
    if row is not None:
        try:
            for key in ("local_display_name", "display_name"):
                value = _label_text(row[key])
                if value:
                    return truncate_for_card(value, 40, marker="…")
        except (IndexError, KeyError, TypeError):
            pass
    return "联系人%d" % int(contact_id)


async def _sync_card(deps: PluginDeps, record: AlertRecord, targets: Sequence[int]) -> Dict[str, Any]:
    """Put the record's current state on every target's phone, in place where possible.

    `deliver_card` for a follower who has no card yet (including one added after the
    first webhook), `update_card` for everyone who has. Neither path is given a
    visible text: a card update may not carry prose at all
    (`crypto_service.py:705-710`), and an internal alert does not need a chat message
    on top of its own bubble.
    """
    delivered: List[int] = []
    updated: List[int] = []
    failed: List[str] = []
    existing = _delivery_targets(deps, record.alert_id)
    for contact_id in targets:
        card_id = existing.get(contact_id) or card_id_for(record.alert_id, contact_id)
        actor = ""
        if record.is_terminal:
            actor = _actor_label(deps, record.ack_by_contact_id if record.status == STATUS_ACKNOWLEDGED else None)
        card = build_alert_card(
            record,
            card_id=card_id,
            detail_url=_detail_url(deps, contact_id, record.alert_id),
            actor_label=actor,
        )
        try:
            if contact_id in existing:
                outcome = await deps.eco.update_card(
                    card_id,
                    contact_id,
                    title=card["title"],
                    body=card.get("body"),
                    fields=card.get("fields"),
                    progress=card.get("progress"),
                    actions=card.get("actions"),
                )
                if getattr(outcome, "error", None):
                    failed.append("contact %d: %s" % (contact_id, outcome.error))
                else:
                    updated.append(contact_id)
            else:
                outcome = await deps.eco.deliver_card(card, contact_id, topic=TOPIC_PREFIX + record.alert_id)
                if getattr(outcome, "error", None) and not getattr(outcome, "queued", False):
                    failed.append("contact %d: %s" % (contact_id, outcome.error))
                else:
                    delivered.append(contact_id)
                if getattr(outcome, "charged", 0):
                    LOG.info(
                        "alert %s: card meter moved %d CP for contact %d (charged by the gateway, not here)",
                        record.alert_id,
                        outcome.charged,
                        contact_id,
                    )
        except EcoError as exc:
            # The client rule that failed is the whole diagnosis, and EcoError names it.
            failed.append("contact %d: %s (%s)" % (contact_id, exc.rule, exc.detail))
            LOG.warning("alert %s: client rule %s blocked the card for contact %d", record.alert_id, exc.rule, contact_id)
        except Exception as exc:  # noqa: BLE001 - the node being down must not lose the row
            failed.append("contact %d: %s" % (contact_id, type(exc).__name__))
            LOG.exception("alert %s: delivery failed for contact %d", record.alert_id, contact_id)
    return {"delivered": delivered, "updated": updated, "failed": failed}


def _record_of(deps: PluginDeps, alert_id: str) -> Optional[AlertRecord]:
    row = deps.db.query_one("SELECT * FROM alerts WHERE alert_id = ?", (alert_id,))
    return None if row is None else AlertRecord.from_row(row)


async def ack_alert(
    deps: PluginDeps,
    alert_id: str,
    *,
    contact_id: Optional[int] = None,
    actor_is_target: bool = True,
    require_actor: bool = True,
) -> Dict[str, Any]:
    """One ack: transition, ledger, in-place card update. Idempotent.

    The write is a guarded UPDATE (`... AND status = 'firing'`), so two acks that
    race — a double tap, or a phone retrying a callback it never saw answered —
    cannot both see themselves as the transition. Whoever gets 1 row is the one who
    charges and repaints; the other takes the replay branch and does neither. That
    is the state machine enforced by the store rather than by a check-then-write
    that would race, in the same spirit as `poll_votes`' UNIQUE pair
    (`database.py:357-366`).
    """
    warnings: List[str] = []
    record = _record_of(deps, alert_id)
    if record is None:
        return {"ok": False, "reason": "unknown_alert", "alert_id": alert_id}
    plan = plan_ack(
        record.status,
        fingerprint=record.fingerprint,
        alert_id=record.alert_id,
        actor_is_target=actor_is_target,
        require_actor=require_actor,
    )
    if not plan.allowed:
        LOG.warning("alert %s: ack refused (%s)", alert_id, plan.reason)
        return {"ok": False, "reason": plan.reason, "alert_id": alert_id, "status": record.status}
    if plan.replay:
        LOG.info("alert %s: ack replay from %s, nothing written", alert_id, contact_id)
        return {
            "ok": True,
            "replay": True,
            "reason": plan.reason,
            "alert_id": alert_id,
            "status": record.status,
            "charged": 0,
        }

    actor = contact_id if require_actor else None
    try:
        cursor = deps.db.connection().execute(
            "UPDATE alerts SET status = ?, ack_at_ms = ?, ack_by_contact_id = ? "
            "WHERE alert_id = ? AND status = ?",
            (STATUS_ACKNOWLEDGED, plan.at_ms, actor, alert_id, STATUS_FIRING),
        )
    except sqlite3.IntegrityError:
        # `ack_by_contact_id` is a foreign key and `PRAGMA foreign_keys=ON`, so an
        # actor row that has been deleted since the card was delivered fails the
        # write outright. The alternative — storing an id no contact resolves to —
        # would make the card's own 已确认 line name a person the console cannot
        # show, which is a worse record than "no actor".
        LOG.warning("alert %s: ack actor %s is not a contact; recording the ack without one", alert_id, actor)
        cursor = deps.db.connection().execute(
            "UPDATE alerts SET status = ?, ack_at_ms = ?, ack_by_contact_id = NULL "
            "WHERE alert_id = ? AND status = ?",
            (STATUS_ACKNOWLEDGED, plan.at_ms, alert_id, STATUS_FIRING),
        )
        actor = None
        warnings.append("确认人已记录，但 contact_id %s 不存在，未写入姓名" % contact_id)
    won = int(getattr(cursor, "rowcount", 0) or 0)
    if not won:
        LOG.info("alert %s: ack lost a race, treating as replay", alert_id)
        return {"ok": True, "replay": True, "reason": "concurrent_ack", "alert_id": alert_id,
                "status": _status_after(deps, alert_id), "charged": 0}

    updated = apply_ack(record, actor, plan.at_ms)
    # An operator's ack outranks the ledger: the transition above is committed and
    # stays committed even if the charge is refused, because losing the ack is the
    # thing that costs a second human hour on the same incident.
    charged, charge_warning = _charge_incident(deps, updated, actor)
    if charge_warning:
        warnings.append(charge_warning)
    targets, target_warnings = read_targets(deps)
    warnings.extend(target_warnings)
    sync = await _sync_card(deps, updated, targets)
    warnings.extend(sync["failed"])
    LOG.info(
        "alert %s: acknowledged by %s (charged %d CP, %d created, %d updated)",
        alert_id,
        actor,
        charged,
        len(sync["delivered"]),
        len(sync["updated"]),
    )
    return {
        "ok": True,
        "alert_id": alert_id,
        "status": STATUS_ACKNOWLEDGED,
        "ack_at_ms": plan.at_ms,
        "ack_by_contact_id": actor,
        "charged": charged,
        "idempotency_key": plan.idempotency_key,
        "cards_created": sync["delivered"],
        "cards_updated": sync["updated"],
        "warnings": warnings,
    }


def _status_after(deps: PluginDeps, alert_id: str) -> str:
    record = _record_of(deps, alert_id)
    return record.status if record is not None else "unknown"


async def resolve_alert(deps: PluginDeps, alert_id: str, *, at_ms: Optional[int] = None) -> Dict[str, Any]:
    """`firing|acknowledged → resolved`, in place, and idempotent like the ack."""
    warnings: List[str] = []
    record = _record_of(deps, alert_id)
    if record is None:
        return {"ok": False, "reason": "unknown_alert", "alert_id": alert_id}
    plan = plan_resolve(record.status, fingerprint=record.fingerprint, alert_id=record.alert_id, now=at_ms)
    if plan.replay:
        return {"ok": True, "replay": True, "alert_id": alert_id, "status": record.status}
    if not plan.allowed:
        return {"ok": False, "reason": plan.reason, "alert_id": alert_id, "status": record.status}
    cursor = deps.db.connection().execute(
        "UPDATE alerts SET status = ?, resolved_at_ms = ? WHERE alert_id = ? AND status IN (?, ?)",
        (STATUS_RESOLVED, plan.at_ms, alert_id, STATUS_FIRING, STATUS_ACKNOWLEDGED),
    )
    if not int(getattr(cursor, "rowcount", 0) or 0):
        return {"ok": True, "replay": True, "reason": "concurrent_resolve", "alert_id": alert_id,
                "status": _status_after(deps, alert_id)}
    updated = apply_resolve(record, plan.at_ms)
    targets, target_warnings = read_targets(deps)
    warnings.extend(target_warnings)
    sync = await _sync_card(deps, updated, targets)
    warnings.extend(sync["failed"])
    LOG.info("alert %s: resolved (%d created, %d updated)", alert_id, len(sync["delivered"]), len(sync["updated"]))
    return {
        "ok": True,
        "alert_id": alert_id,
        "status": STATUS_RESOLVED,
        "resolved_at_ms": plan.at_ms,
        "cards_created": sync["delivered"],
        "cards_updated": sync["updated"],
        "warnings": warnings,
    }


def find_open_alert_for_contact(deps: PluginDeps, contact_id: int) -> Optional[AlertRecord]:
    """The most recent incident this follower is still holding a card for.

    Read through `cards.topic`, which is the only relation this plugin owns without
    a schema change: the join says "this contact received a card for that alert", so
    a keyword from a follower resolves *their* newest open incident and not whatever
    the deployment fired first. `status != 'resolved'` prefers an unacked page, and
    `firing_at_ms DESC` breaks ties towards the newer incident — an operator who
    types 确认 right after a page means that page.
    """
    rows = deps.db.query(
        "SELECT a.* FROM alerts a JOIN cards c ON c.topic = ? || a.alert_id "
        "WHERE c.contact_id = ? AND a.status != ? "
        "ORDER BY CASE a.status WHEN 'firing' THEN 0 ELSE 1 END, a.firing_at_ms DESC, a.alert_id DESC "
        "LIMIT 1",
        (TOPIC_PREFIX, int(contact_id), STATUS_RESOLVED),
    )
    if not rows:
        return None
    return AlertRecord.from_row(rows[0])


async def resolve_by_keyword(
    deps: PluginDeps, contact_id: int, text: str, keywords: Optional[Sequence[str]] = None
) -> Optional[Dict[str, Any]]:
    """The one call `app.main` makes on a *text* message, before the AI plugin sees it.

    Returns `None` when the text was not a keyword, which is the signal for main to
    carry on and route the message to the AI plugin as ordinary chat — the reason
    this is a separate entry point instead of a branch inside :func:`handle_inbound`:
    `handle_inbound` only ever receives callbacks, and claiming text here would take
    the AI plugin's own traffic (`plugins/__init__.py:95-97`).

    A keyword resolves the follower's newest open incident rather than acking it: by
    the time a human types 确认 into a chat window, the work is done. The console and
    the 确认 button remain the two paths to `acknowledged`, and the state machine
    allows `firing → acknowledged → resolved` either way.
    """
    configured = keywords if keywords is not None else getattr(deps.config, "alert_resolve_keywords", [])
    matched = resolve_keyword_match(text, list(configured or ()))
    if matched is None:
        return None
    record = find_open_alert_for_contact(deps, contact_id)
    if record is None:
        LOG.info("keyword %r from contact %d matched no open alert", matched, contact_id)
        return {"ok": False, "reason": "no_open_alert", "keyword": matched}
    outcome = await resolve_alert(deps, record.alert_id)
    outcome["keyword"] = matched
    return outcome


def _row_to_document(row: AlertRecord) -> Dict[str, Any]:
    return {
        "alert_id": row.alert_id,
        "fingerprint": row.fingerprint,
        "severity": row.severity,
        "status": row.status,
        "title": row.title,
        "summary": row.summary,
        "labels": dict(row.labels),
        "card_id": row.card_id,
        "source": row.source,
        "firing_at_ms": row.firing_at_ms,
        "ack_at_ms": row.ack_at_ms,
        "ack_by_contact_id": row.ack_by_contact_id,
        "resolved_at_ms": row.resolved_at_ms,
        "terminal": row.is_terminal,
    }


async def ingest_webhook(deps: PluginDeps, body: Any, *, source_hint: str = "") -> Dict[str, Any]:
    """Everything the webhook route does after it has decided it is allowed to.

    Per alert: gate → dedupe → row → cards. A below-threshold alert still gets its
    row, because the row is what makes the next repeat recognisable and what the
    console lists; it simply gets no card, and therefore no `card` charge and no
    incident charge (nothing was delivered to pay for).
    """
    events, warnings, detected = normalize_webhook_body(body)
    source = _label_text(source_hint) or detected
    results: List[Dict[str, Any]] = []
    minimum = getattr(deps.config, "alert_min_severity", "warning")
    targets, target_warnings = read_targets(deps)
    warnings.extend(target_warnings)
    if not targets:
        warnings.append("no targets configured (settings key %r): alerts are recorded but nobody is messaged" % SETTINGS_TARGETS_KEY)

    for index, event in enumerate(events):
        if index >= MAX_ALERTS_PER_WEBHOOK:
            warnings.append("%d further alert(s) beyond the %d-per-webhook cap were not processed" % (len(events) - index, MAX_ALERTS_PER_WEBHOOK))
            break
        entry = await _ingest_one(deps, event, minimum=minimum, targets=targets)
        results.append(entry)

    counts: Dict[str, int] = {}
    for entry in results:
        counts[entry["action"]] = counts.get(entry["action"], 0) + 1
    LOG.info(
        "webhook: %d alert(s) %s source=%s targets=%d",
        len(results),
        ",".join("%s=%d" % item for item in sorted(counts.items())) or "none",
        source,
        len(targets),
    )
    return {"ok": True, "received": len(results), "counts": counts, "results": results, "warnings": warnings}


_INSERT_ALERT_SQL = (
    "INSERT INTO alerts (alert_id, fingerprint, severity, status, title, summary, labels_json, "
    "card_id, source, firing_at_ms, ack_at_ms, ack_by_contact_id, resolved_at_ms) "
    "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)"
)

_UPDATE_ALERT_SQL = (
    "UPDATE alerts SET severity = ?, status = ?, title = ?, summary = ?, labels_json = ?, "
    "card_id = ?, source = ?, firing_at_ms = ?, resolved_at_ms = ?, ack_at_ms = ?, "
    "ack_by_contact_id = ? WHERE alert_id = ?"
)


def _alert_row_params(record: AlertRecord, *, for_insert: bool) -> tuple:
    """The column tuple for one write, in one place so the two statements cannot drift.

    `labels_json` is re-serialised here rather than stored on the record: the record
    carries a dict (which is what every reader in this module wants) and the column
    is TEXT, and the one place that converts is the one place that can get it wrong.
    """
    labels = json.dumps(record.labels, ensure_ascii=False, separators=(",", ":"))
    if for_insert:
        return (
            record.alert_id,
            record.fingerprint,
            record.severity,
            record.status,
            record.title,
            record.summary,
            labels,
            record.card_id,
            record.source,
            record.firing_at_ms,
            record.ack_at_ms,
            record.ack_by_contact_id,
            record.resolved_at_ms,
        )
    return (
        record.severity,
        record.status,
        record.title,
        record.summary,
        labels,
        record.card_id,
        record.source,
        record.firing_at_ms,
        record.resolved_at_ms,
        record.ack_at_ms,
        record.ack_by_contact_id,
        record.alert_id,
    )


def _read_alert_by_fingerprint(deps: PluginDeps, fingerprint: str) -> Optional[AlertRecord]:
    row = deps.db.query_one("SELECT * FROM alerts WHERE fingerprint = ?", (fingerprint,))
    return None if row is None else AlertRecord.from_row(row)


def _next_record(existing: Optional[AlertRecord], event: AlertEvent, targets: Sequence[int]) -> AlertRecord:
    """Merge one normalised event with the stored row, without touching the database.

    Split out as a pure function because this is where the two clocks meet — the
    sender's `startsAt` and our arrival time — and a mistake here (resetting
    `firing_at_ms` on a resample, or wiping an ack) is invisible until an operator
    notices their ack disappeared. self_test drives it directly.
    """
    status = plan_ingest(None if existing is None else existing.status, event.status)
    alert_id = existing.alert_id if existing is not None else new_alert_id()
    primary = int(targets[0]) if targets else None
    card_id = card_id_for(alert_id, primary) if primary is not None else (existing.card_id if existing else None)

    if existing is None:
        fired = event.starts_at_ms or now_ms()
        record = AlertRecord.from_event(event, alert_id, status=status, firing_at_ms=fired, card_id=card_id)
        if status == STATUS_RESOLVED:
            # A sender that only ever tells us after the fact still gets a resolved
            # row with a resolved time, not a firing timestamp in that column.
            record = replace(record, resolved_at_ms=event.ends_at_ms or now_ms())
        return record

    firing_at = existing.firing_at_ms
    if event.status == STATUS_FIRING and existing.status == STATUS_RESOLVED:
        # A re-fire restarts the clock on the same incident and the same card.
        firing_at = event.starts_at_ms or now_ms()
    elif not firing_at:
        firing_at = event.starts_at_ms or now_ms()

    if status != STATUS_RESOLVED:
        resolved_at: Optional[int] = None
    elif existing.status == STATUS_RESOLVED:
        resolved_at = existing.resolved_at_ms or event.ends_at_ms or now_ms()
    else:
        resolved_at = event.ends_at_ms or now_ms()

    return replace(
        existing,
        status=status,
        severity=event.severity,
        title=alert_display_title(event.severity, event.alertname),
        summary=_clip(event.description or event.summary, MAX_STORED_SUMMARY_CHARS) or existing.summary,
        labels=dict(event.labels) or dict(existing.labels),
        source=event.source or existing.source,
        firing_at_ms=firing_at,
        resolved_at_ms=resolved_at,
        card_id=card_id,
    )


async def _ingest_one(deps: PluginDeps, event: AlertEvent, *, minimum: str, targets: Sequence[int]) -> Dict[str, Any]:
    """One event → one row and at most one card per target."""
    existing = _read_alert_by_fingerprint(deps, event.fingerprint)
    action = "updated" if existing is not None else "created"
    record = _next_record(existing, event, targets)

    if existing is None:
        try:
            with deps.db.transaction(immediate=True) as conn:
                conn.execute(_INSERT_ALERT_SQL, _alert_row_params(record, for_insert=True))
        except sqlite3.IntegrityError:
            # Two webhooks for one fingerprint, concurrently: UNIQUE(fingerprint)
            # decided which one owns the incident, so the loser re-reads and updates
            # rather than writing a second row and a second card. This is the dedupe
            # the constraint is for, and it is the reason the key cannot be guessed
            # from the response body.
            LOG.info("alert fingerprint %s raced; falling back to update", event.fingerprint[:12])
            beaten = _read_alert_by_fingerprint(deps, event.fingerprint)
            if beaten is None:
                return {
                    "alert_id": record.alert_id,
                    "fingerprint": event.fingerprint,
                    "action": "failed",
                    "status": record.status,
                    "warnings": ["the row vanished between the insert and the re-read"],
                }
            action = "updated"
            record = _next_record(beaten, event, targets)
            with deps.db.transaction(immediate=True) as conn:
                conn.execute(_UPDATE_ALERT_SQL, _alert_row_params(record, for_insert=False))
    else:
        with deps.db.transaction(immediate=True) as conn:
            conn.execute(_UPDATE_ALERT_SQL, _alert_row_params(record, for_insert=False))

    if not passes_severity_gate(event.severity, minimum):
        # Recorded, not delivered: the row is what makes the next repeat
        # recognisable and what the console lists. No card means no `card` meter
        # movement and no incident charge, which is the point of a floor.
        LOG.info(
            "alert %s: severity %s below the %s floor, recorded without a card",
            record.alert_id, record.severity, minimum,
        )
        return {
            "alert_id": record.alert_id,
            "fingerprint": record.fingerprint,
            "action": "suppressed",
            "status": record.status,
            "severity": record.severity,
            "delivered": [],
            "updated": [],
            "charged": 0,
        }

    sync = await _sync_card(deps, record, targets)
    charged = 0
    charge_warning: Optional[str] = None
    if sync["delivered"] or sync["updated"]:
        # One charge per incident, and the key is the fingerprint, so a resample of
        # the same alert cannot add a second debit and an ack later cannot either.
        charged, charge_warning = _charge_incident(deps, record, None)
    entry: Dict[str, Any] = {
        "alert_id": record.alert_id,
        "fingerprint": record.fingerprint,
        "action": action,
        "status": record.status,
        "severity": record.severity,
        "delivered": sync["delivered"],
        "updated": sync["updated"],
        "charged": charged,
    }
    problems = list(sync["failed"])
    if charge_warning:
        problems.append(charge_warning)
    if problems:
        entry["warnings"] = problems
    return entry


async def handle_inbound(deps: PluginDeps, message: "InboundMessage") -> bool:
    """Claim `::CB::alert:...` and nothing else.

    Called only for `callback.kind == "card_callback"`
    (`plugins/__init__.py:100-105`), so the kind check here is a belt, not the
    harness. Two things this deliberately does not do: it never claims
    `kind == "text"` — the AI plugin owns plain chat
    (`plugins/__init__.py:95-97`), and `app.main` is expected to try
    :func:`resolve_keyword_match` on a text message *before* routing it there — and
    it never replies with prose. A callback is silent control traffic, so the answer
    is an in-place card update; an autoreply would both acknowledge a protocol
    message the user never sent and cost a chat frame.
    """
    callback = getattr(message, "callback", None)
    if callback is None:
        return False
    if getattr(callback, "kind", "") != "card_callback":
        return False
    payload = getattr(callback, "payload", "") or ""
    if not claims_callback_payload(payload):
        return False
    parsed = parse_callback_payload(payload)
    if parsed is None:
        # Ours by prefix, unknown by verb. Claimed anyway: falling through to the
        # merchant's handler would turn a typo in this module into an AI reply that
        # quotes an internal payload back at someone.
        LOG.warning("alert callback with unknown verb: %r", truncate_for_card(payload, 60, marker="…"))
        return True
    verb, argument = parsed
    contact_id = int(getattr(message, "contact_id", 0) or 0)
    alert_id = sanitize_alert_id(argument)
    if verb == PAYLOAD_VERB_NOOP:
        LOG.info("alert %s: terminal button pressed by contact %d, nothing to do", alert_id, contact_id)
        return True
    if not alert_id:
        LOG.warning("alert callback carried an unusable id from contact %d", contact_id)
        return True
    targets, _warnings = read_targets(deps)
    is_target = contact_id in targets
    if verb == PAYLOAD_VERB_ACK:
        try:
            outcome = await ack_alert(deps, alert_id, contact_id=contact_id, actor_is_target=is_target)
        except EcoError as exc:
            LOG.error("alert %s: ack blocked by client rule %s (%s)", alert_id, exc.rule, exc.detail)
        except Exception:  # noqa: BLE001
            LOG.exception("alert %s: ack failed", alert_id)
        else:
            for warning in outcome.get("warnings") or []:
                LOG.warning("alert %s: %s", alert_id, warning)
        return True
    if verb == PAYLOAD_VERB_RESOLVE:
        # Not offered as a button today; the payload grammar allows it, so an
        # operator who adds one by hand gets the same state machine.
        try:
            await resolve_alert(deps, alert_id)
        except EcoError as exc:
            LOG.error("alert %s: resolve blocked by client rule %s", alert_id, exc.rule)
        return True
    return True


# ─────────────────────────────────────────────────────────────────────────────
# 11. HTTP surface
# ─────────────────────────────────────────────────────────────────────────────


def create_router(deps: PluginDeps) -> "APIRouter":
    """The plugin's routes, all of them on `spec.url_prefix`.

    The import rule and FastAPI's annotation resolver disagree, and this function is
    where that gets settled. With `from __future__ import annotations`, every
    annotation below is a *string*, and FastAPI resolves those strings with
    `typing.get_type_hints(call, globalns=call.__globals__)` — the module's globals,
    not the enclosing function's locals. So the names the endpoints annotate with
    must exist in this module's global dict *at mount time*, which is exactly what
    the `globals()["Request"] = Request` below does: nothing is imported at import
    time, and the name appears only when a deployment actually mounts the plugin.
    `TYPE_CHECKING` above declares the same names for static checkers.

    Routes are declared with this plugin's own prefix because `url_prefix` is in the
    mount table and a plugin that trusted the gateway to supply it would answer at a
    path it did not choose. If the mount loop also passes `prefix=spec.url_prefix` to
    `include_router`, the two compose and every route moves — that is a one-line
    decision in `app/main.py`, which this file must not edit.
    """
    from fastapi import APIRouter, Request
    from fastapi.responses import JSONResponse

    globals()["Request"] = Request

    router = APIRouter(prefix=deps.spec.url_prefix, tags=["alert_ops"])

    def json_response(status: int, body: Mapping[str, Any]) -> "JSONResponse":
        return JSONResponse(status_code=int(status), content=dict(body))

    def gated() -> Tuple[Any, Optional[Any]]:
        """`(decision, refusal)` — the gate, before any of this module's own work.

        Disabled answers 404 and says which switch; unfunded answers 402 with the
        balance. A route that started with its business logic instead would let an
        unmounted plugin look like a broken one.
        """
        try:
            return deps.require(), None
        except PluginUnavailable as exc:
            return None, json_response(exc.http_status, exc.decision.as_body())

    def admin_refused(request: "Request") -> Optional[Any]:
        ok, reason = authorize_admin_token(request.headers, getattr(deps.config, "admin_token", ""))
        if ok:
            return None
        return json_response(401, {"ok": False, "plugin": PLUGIN_ID, "reason": "unauthorized", "detail": reason})

    async def read_json(request: "Request", *, allow_empty: bool = False) -> Tuple[Any, Optional[Any]]:
        """The body as a JSON value, and a 4xx explaining why it is not.

        Parsed from raw bytes rather than `request.json()` because Grafana posts
        `application/json` while a hand-rolled sender posts `text/plain`, and a
        content-type check that refuses a valid alert is a webhook that "randomly"
        loses pages. The body itself is never logged at INFO.

        `allow_empty` is for DELETE, where "no body" is the request "remove them
        all" and must not be confused with a malformed one: a 400 on a truncated body
        is correct, and silently emptying the target list would not be.
        """
        try:
            raw = await request.body()
        except Exception as exc:  # noqa: BLE001 - a broken body read is a client error
            return None, json_response(400, {"ok": False, "detail": "body could not be read: %s" % type(exc).__name__})
        if len(raw) > MAX_WEBHOOK_BYTES:
            return None, json_response(413, {"ok": False, "detail": "body over %d bytes" % MAX_WEBHOOK_BYTES})
        if not raw.strip():
            if allow_empty:
                return None, None
            return None, json_response(400, {"ok": False, "detail": "empty body"})
        try:
            return json.loads(raw.decode("utf-8", "replace")), None
        except ValueError:
            return None, json_response(400, {"ok": False, "detail": "body is not valid JSON"})

    # ── the webhook ─────────────────────────────────────────────────────────

    @router.post("/webhook")
    async def webhook(request: "Request") -> Any:
        """Grafana unified-alerting and Alertmanager v4, both, with no ceremony.

        Auth before the gate here, unlike the console routes: the 402 body carries
        the account balance, and this endpoint is reachable by whatever the
        merchant's Grafana is, so an unauthenticated prober must not be able to read
        it. The token check is the first thing that answers.
        """
        ok, reason = authorize_webhook_token(request.headers, getattr(deps.config, "alert_webhook_token", ""))
        if not ok:
            LOG.warning("alert webhook refused: %s", reason)
            return json_response(401, {"ok": False, "plugin": PLUGIN_ID, "reason": "unauthorized", "detail": reason})
        _decision, refusal = gated()
        if refusal is not None:
            return refusal
        body, error = await read_json(request)
        if error is not None:
            return error
        try:
            document = await ingest_webhook(deps, body, source_hint=request.query_params.get("source") or request.headers.get("X-Alert-Source") or "")
        except EcoError as exc:
            # The limit IS the reason: "card_fields 9 exceeds 8" is actionable, a 500 is not.
            return json_response(
                400,
                {"ok": False, "plugin": PLUGIN_ID, "reason": "client_rule", "rule": exc.rule, "detail": exc.detail},
            )
        return json_response(200, document)

    # ── targets ─────────────────────────────────────────────────────────────

    @router.get("/targets")
    async def get_targets(request: "Request") -> Any:
        _decision, refusal = gated()
        if refusal is not None:
            return refusal
        refused = admin_refused(request)
        if refused is not None:
            return refused
        targets, warnings = read_targets(deps)
        return json_response(200, {"ok": True, "key": SETTINGS_TARGETS_KEY, "targets": targets, "warnings": warnings})

    @router.post("/targets")
    async def post_targets(request: "Request") -> Any:
        """Replace or extend the list. `{"contact_ids": [...]}`, optionally `append`."""
        _decision, refusal = gated()
        if refusal is not None:
            return refusal
        refused = admin_refused(request)
        if refused is not None:
            return refused
        body, error = await read_json(request)
        if error is not None:
            return error
        if not isinstance(body, Mapping):
            return json_response(400, {"ok": False, "detail": "expected a JSON object with 'contact_ids'"})
        raw = body.get("contact_ids", body.get("targets", None))
        if raw is None:
            return json_response(400, {"ok": False, "detail": "'contact_ids' is required"})
        wanted, warnings = normalize_target_ids(raw)
        if not wanted and not isinstance(raw, (list, tuple, set)):
            return json_response(400, {"ok": False, "detail": "'contact_ids' must be an array of contact ids"})
        current, _ = read_targets(deps)
        merged = list(current)
        if bool(body.get("append", False)):
            merged.extend(wanted)
        else:
            merged = list(wanted)
        final, merge_warnings = normalize_target_ids(merged)
        warnings.extend(merge_warnings)
        deps.db.set_setting(SETTINGS_TARGETS_KEY, final)
        LOG.info("alert targets set to %d contact(s)", len(final))
        return json_response(200, {"ok": True, "targets": final, "warnings": warnings})

    @router.delete("/targets")
    async def delete_targets(request: "Request") -> Any:
        """Remove the listed contacts, or empty the list when none are given."""
        _decision, refusal = gated()
        if refusal is not None:
            return refusal
        refused = admin_refused(request)
        if refused is not None:
            return refused
        current, warnings = read_targets(deps)
        body, error = await read_json(request, allow_empty=True)
        if error is not None:
            return error
        removing: List[int] = []
        if isinstance(body, Mapping):
            removing, remove_warnings = normalize_target_ids(body.get("contact_ids", body.get("targets", [])))
            warnings.extend(remove_warnings)
            if not removing and body.get("contact_ids") not in (None, [], ""):
                return json_response(400, {"ok": False, "detail": "no usable contact id in the request"})
        if not removing:
            deps.db.set_setting(SETTINGS_TARGETS_KEY, [])
            LOG.warning("alert targets cleared (was %d)", len(current))
            return json_response(200, {"ok": True, "targets": [], "cleared": len(current), "warnings": warnings})
        kept = [item for item in current if item not in set(removing)]
        deps.db.set_setting(SETTINGS_TARGETS_KEY, kept)
        LOG.info("alert targets: removed %d, %d remain", len(current) - len(kept), len(kept))
        return json_response(200, {"ok": True, "targets": kept, "removed": removing, "warnings": warnings})

    # ── the console ─────────────────────────────────────────────────────────

    @router.get("")
    @router.get("/")
    async def list_alerts(request: "Request", status: Optional[str] = None, severity: Optional[str] = None,
                         limit: Optional[int] = None) -> Any:
        """Newest first. `alert_id` is the tiebreak because `firing_at_ms` is not unique,
        and a console that pages on a non-unique key can show the same incident twice —
        the same reasoning `billing_service.ledger` gives for ordering by `id`."""
        _decision, refusal = gated()
        if refusal is not None:
            return refusal
        refused = admin_refused(request)
        if refused is not None:
            return refused
        clause = ""
        params: List[Any] = []
        cleaned_status = _label_text(status).lower() if status else ""
        if cleaned_status:
            if cleaned_status not in STATUS_VALUES:
                return json_response(400, {"ok": False, "detail": "status must be one of %s" % (list(STATUS_VALUES),)})
            clause += " AND status = ?"
            params.append(cleaned_status)
        if severity:
            cleaned_severity = normalize_severity(severity)
            clause += " AND severity = ?"
            params.append(cleaned_severity)
        wanted = DEFAULT_PAGE_LIMIT
        if limit is not None:
            try:
                wanted = int(limit)
            except (TypeError, ValueError):
                return json_response(400, {"ok": False, "detail": "limit must be an integer"})
            wanted = max(1, min(wanted, MAX_PAGE_LIMIT))
        rows = deps.db.query(
            "SELECT * FROM alerts WHERE 1 = 1%s ORDER BY firing_at_ms DESC, alert_id DESC LIMIT ?" % clause,
            tuple(params) + (wanted,),
        )
        documents = [_row_to_document(AlertRecord.from_row(row)) for row in rows]
        return json_response(200, {"ok": True, "count": len(documents), "limit": wanted, "alerts": documents})

    @router.get("/status")
    async def get_status(request: "Request") -> Any:
        """Health, in the same shape the other four consoles answer with.

        Declared **above** `/{alert_id}` deliberately: Starlette dispatches to the
        first registration whose path matches, and `/{alert_id}` pattern-matches the
        literal `status`, so declared the other way round the console's health probe
        is answered with `unknown_alert`. The gateway's generic
        `GET /api/v1/plugins/{plugin_id}/status` cannot rescue it — that is
        registered after every plugin router on purpose, because two plugins have a
        richer `/status` of their own (see `app/main.py`) — so the contract this
        module keeps is simply: `GET <url_prefix>/status` answers here.
        """
        # `deps.gate.status()` below rather than this module's `gated()`: a fused or
        # node-down account is exactly when the operator needs to read this panel,
        # and a 402 refusal would hide the reason in its own status code. The
        # credential check still applies; only the money check becomes a report.
        refused = admin_refused(request)
        if refused is not None:
            return refused
        counts = {STATUS_FIRING: 0, STATUS_ACKNOWLEDGED: 0, STATUS_RESOLVED: 0}
        for row in deps.db.query("SELECT status, COUNT(*) AS n FROM alerts GROUP BY status") or ():
            key = _label_text(row["status"])
            if key in counts:
                counts[key] = int(row["n"] or 0)
        targets, _warnings = read_targets(deps)
        decision = deps.gate.status(PLUGIN_ID)
        return json_response(200, {
            "ok": True,
            "plugin": PLUGIN_ID,
            "enabled": bool(getattr(deps.config.plugins, deps.spec.toggle, False)),
            "gate": decision.as_body(),
            "meter": deps.spec.meter,
            "url_prefix": deps.spec.url_prefix,
            "callback_kinds": list(deps.spec.callback_kinds),
            "alerts": {
                "firing": counts[STATUS_FIRING],
                "acknowledged": counts[STATUS_ACKNOWLEDGED],
                "resolved": counts[STATUS_RESOLVED],
                "total": sum(counts.values()),
            },
            "targets": len(targets),
            "webhook_token_configured": bool(str(getattr(deps.config, "alert_webhook_token", "") or "").strip()),
        })

    @router.get("/{alert_id}")
    async def get_alert(alert_id: str, request: "Request") -> Any:
        """The row and the card the plugin last delivered for it."""
        _decision, refusal = gated()
        if refusal is not None:
            return refusal
        refused = admin_refused(request)
        if refused is not None:
            return refused
        clean = sanitize_alert_id(alert_id)
        if not clean:
            return json_response(400, {"ok": False, "detail": "alert_id is not a valid id"})
        record = _record_of(deps, clean)
        if record is None:
            return json_response(404, {"ok": False, "reason": "unknown_alert", "alert_id": clean})
        card_row = None
        if record.card_id:
            found = deps.db.query_one("SELECT * FROM cards WHERE card_id = ?", (record.card_id,))
            if found is not None:
                try:
                    card_row = {key: found[key] for key in found.keys()}
                except (AttributeError, IndexError, KeyError):
                    card_row = None
        document = _row_to_document(record)
        return json_response(
            200,
            {
                "ok": True,
                "alert": document,
                "card": card_row,
                "cards": _delivery_targets(deps, clean),
            },
        )

    @router.post("/{alert_id}/ack")
    async def ack_from_console(alert_id: str, request: "Request") -> Any:
        """The same transition as the phone's, and equally idempotent.

        `contact_id` is optional: the column it lands in is nullable
        (`database.py:382`), so an ack from a console with no logged-in follower is
        recorded with no actor rather than refused — and the actor requirement is
        switched off for exactly that case, because an operator is by definition not
        in the target list.
        """
        _decision, refusal = gated()
        if refusal is not None:
            return refusal
        refused = admin_refused(request)
        if refused is not None:
            return refused
        clean = sanitize_alert_id(alert_id)
        if not clean:
            return json_response(400, {"ok": False, "detail": "alert_id is not a valid id"})
        body, error = await read_json(request)
        actor: Optional[int] = None
        if error is None and isinstance(body, Mapping):
            raw_actor = body.get("contact_id")
            if raw_actor is not None:
                try:
                    actor = int(str(raw_actor).strip())
                except (TypeError, ValueError):
                    return json_response(400, {"ok": False, "detail": "contact_id must be an integer"})
                if actor <= 0:
                    return json_response(400, {"ok": False, "detail": "contact_id must be positive"})
        try:
            outcome = await ack_alert(deps, clean, contact_id=actor, actor_is_target=True, require_actor=(actor is not None))
        except EcoError as exc:
            return json_response(400, {"ok": False, "reason": "client_rule", "rule": exc.rule, "detail": exc.detail})
        status = 200 if outcome.get("ok") else (404 if outcome.get("reason") == "unknown_alert" else 409)
        return json_response(status, outcome)

    @router.post("/{alert_id}/resolve")
    async def resolve_from_console(alert_id: str, request: "Request") -> Any:
        _decision, refusal = gated()
        if refusal is not None:
            return refusal
        refused = admin_refused(request)
        if refused is not None:
            return refused
        clean = sanitize_alert_id(alert_id)
        if not clean:
            return json_response(400, {"ok": False, "detail": "alert_id is not a valid id"})
        try:
            outcome = await resolve_alert(deps, clean)
        except EcoError as exc:
            return json_response(400, {"ok": False, "reason": "client_rule", "rule": exc.rule, "detail": exc.detail})
        status = 200 if outcome.get("ok") else (404 if outcome.get("reason") == "unknown_alert" else 409)
        return json_response(status, outcome)

    return router


# ─────────────────────────────────────────────────────────────────────────────
# 12. Self-test — the pure half, no FastAPI, no node, no wheels
# ─────────────────────────────────────────────────────────────────────────────


def self_test() -> List[str]:
    """Assertions over normalisation, the state machine, and card assembly.

    What this proves is everything that is arithmetic: that both webhook shapes
    become the same event, that the identity used for dedupe does not move, that the
    ack machine cannot charge a replay, and that a card this module builds is inside
    every limit the phone enforces. What it cannot prove is anything that needs the
    gateway: delivery, `update_card` in place, and the ledger's UNIQUE constraint are
    code-reviewed here and exercised by the deployment smoke test, not by this
    function.
    """
    checks: List[str] = []

    def check(name: str, condition: bool) -> None:
        if not condition:
            raise AssertionError("self_test failed: %s" % name)
        checks.append(name)

    from app.plugins import plugin_for_id

    #: The mount table's own row for this plugin: the fakes below use the real spec,
    #: so a meter or prefix that drifted from `plugins/__init__.py` fails here.
    mounted = plugin_for_id(PLUGIN_ID)

    # ── both payload shapes ──────────────────────────────────────────────────
    grafana = {
        "status": "firing",
        "state": "alerting",
        "ruleId": 41,
        "title": "High latency firing",
        "alerts": [
            {
                "labels": {"alertname": "High latency", "severity": "CRITICAL", "instance": "api-3:8080"},
                "annotations": {"summary": "p99 超过 800ms", "description": "过去 5 分钟 p99 = 1.2s，影响下单"},
                "startsAt": "2024-01-02T03:04:05Z",
            }
        ],
    }
    events, warnings, source = normalize_webhook_body(grafana)
    check("grafana_one_event", len(events) == 1 and not warnings)
    check("grafana_status_inherited_from_envelope", events[0].status == STATUS_FIRING)
    check("grafana_severity_case_insensitive", events[0].severity == "critical")
    check("grafana_summary_and_description_split", events[0].summary.startswith("p99") and events[0].description.startswith("过去"))
    check("grafana_fingerprint_derived", bool(events[0].fingerprint) and not any(c.isspace() for c in events[0].fingerprint))
    check("source_detected_grafana", source == "grafana")

    am = {
        "version": "4",
        "status": "firing",
        "receiver": "popopx",
        "groupKey": '{}:{alertname="x"}',
        "alerts": [
            {"status": "resolved", "fingerprint": "abc123", "labels": {"alertname": "Disk"}, "startsAt": "2024-01-02T03:04:05+08:00"},
            {"status": "ok", "fingerprint": "def456", "labels": {"alertname": "Queue"}},
            {"status": "firing", "labels": {"alertname": "NoLabelsCase", "severity": "warning", "startsAt": "ignore me"}},
        ],
    }
    events, warnings, source = normalize_webhook_body(am)
    check("alertmanager_three_events", len(events) == 3)
    check("alertmanager_resolved_spelling", events[0].status == STATUS_RESOLVED)
    check("alertmanager_ok_spelling_is_resolved", events[1].status == STATUS_RESOLVED)
    check("alertmanager_provided_fingerprint_preferred", events[0].fingerprint == "abc123")
    check("alertmanager_severity_default_warning", events[2].severity == "warning")
    check("source_detected_alertmanager", source == "alertmanager")
    check("volatile_label_excluded_from_digest", events[2].fingerprint == derive_fingerprint("NoLabelsCase", {"alertname": "NoLabelsCase", "severity": "warning"}))
    check("card_labels_keep_what_the_sender_sent", events[2].labels.get("startsAt") == "ignore me")

    # Missing labels / wrong types / an element nobody can name.
    ragged = {"status": "firing", "alerts": [{"annotations": None}, None, "junk", {"labels": {"severity": "info"}},
                                              {"labels": {"alertname": "Weird", "count": 7, "on": True, "meta": {"a": [1, 2]}}}]}
    events, warnings, _source = normalize_webhook_body(ragged)
    check("ragged_body_yields_named_events", len(events) == 1)
    check("ragged_skips_are_reported", bool(warnings) and "skipped" in warnings[0])
    check("missing_labels_is_empty_map", isinstance(events[0].labels, dict))
    non_string = normalize_webhook_body({"status": "firing", "alerts": [{"labels": {"alertname": "T", "n": 5, "b": False, "z": None}}]})[0][0]
    check("non_string_label_values_stringified", non_string.labels.get("n") == "5" and non_string.labels.get("b") == "false" and "z" not in non_string.labels)
    check("normalize_labels_rejects_non_mapping", normalize_labels(["not", "a", "map"]) == {})
    top_level_object, warns, _ = normalize_webhook_body({"status": "resolved", "labels": {"alertname": "Solo", "severity": "critical"}})
    check("single_alert_as_object_accepted", len(top_level_object) == 1 and top_level_object[0].status == STATUS_RESOLVED)
    no_alerts, warns, _ = normalize_webhook_body({"status": "firing"})
    check("no_alerts_key_warns", no_alerts == [] and bool(warns))
    not_object, warns, _ = normalize_webhook_body(["array"])
    check("non_object_body_warns", not_object == [] and "JSON object" in warns[0])

    # ── fingerprint stability ────────────────────────────────────────────────
    base = {"alertname": "cpu", "severity": "critical", "instance": "host-1"}
    fp_one = derive_fingerprint("cpu", base)
    fp_reordered = derive_fingerprint("cpu", {"instance": "host-1", "severity": "critical", "alertname": "cpu"})
    check("fingerprint_stable_under_label_order", fp_one == fp_reordered)
    check("fingerprint_stable_under_repeat", derive_fingerprint("cpu", dict(base)) == fp_one)
    check("fingerprint_changes_with_alertname", derive_fingerprint("mem", dict(base)) != fp_one)
    check("fingerprint_changes_with_one_label", derive_fingerprint("cpu", dict(base, instance="host-2")) != fp_one)
    with_time = derive_fingerprint("cpu", dict(base, startsAt="2024-01-02T03:04:05Z", endsAt="2024-01-02T04:00:00Z", status="firing"))
    check("fingerprint_ignores_time_varying_labels", with_time == fp_one)
    check("fingerprint_length_bounded", len(fp_one) == 32 and len(fp_one) <= EcoLimits.payload_chars)

    # ── startsAt → ms ───────────────────────────────────────────────────────
    check("iso_z_exact_ms", parse_time_ms("2024-01-02T03:04:05Z") == 1704164645000)
    check("iso_offset_exact_ms", parse_time_ms("2024-01-02T03:04:05+08:00") == 1704135845000)
    check("iso_offset_no_colon_ms", parse_time_ms("2024-01-02T03:04:05+0800") == 1704135845000)
    check("iso_fractional_ms", parse_time_ms("2024-01-02T03:04:05.123Z") == 1704164645123)
    check("iso_same_instant_both_spellings", parse_time_ms("2024-01-02T11:04:05.123456+08:00") == parse_time_ms("2024-01-02T03:04:05.123Z"))
    check("iso_naive_read_as_utc_not_host_local", parse_time_ms("2024-01-02T03:04:05") == parse_time_ms("2024-01-02T03:04:05Z"))
    check("epoch_seconds_uplifted_to_ms", parse_time_ms(1704164645) == 1704164645000)
    check("epoch_milliseconds_passthrough", parse_time_ms(1704164645000) == 1704164645000)
    check("epoch_digits_in_string", parse_time_ms("1704164645000") == 1704164645000)
    check("garbage_time_is_none", parse_time_ms("not a time at all") is None)
    check("empty_time_is_none", parse_time_ms("") is None and parse_time_ms(None) is None)
    check("zero_time_is_none", parse_time_ms("0001-01-01T00:00:00Z") is None)
    check("negative_epoch_rejected", parse_time_ms(-5) is None)
    check("bool_is_not_a_time", parse_time_ms(True) is None)

    # ── severity ordering and the gate boundary ─────────────────────────────
    check("severity_order_is_total", [severity_rank(name) for name in SEVERITY_ORDER] == list(range(len(SEVERITY_ORDER))))
    check("severity_order_silent_below_debug", severity_rank("silent") < severity_rank("debug"))
    check("severity_synonym_error_is_critical", normalize_severity("error") == "critical")
    check("severity_synonym_watch_is_warning", normalize_severity("watch") == "warning")
    check("severity_unknown_defaults_warning", normalize_severity("mystery") == "warning")
    check("severity_absent_defaults_warning", normalize_severity(None) == "warning")
    check("gate_boundary_at_minimum_passes", passes_severity_gate("warning", "warning") is True)
    check("gate_boundary_critical_at_minimum_warning_passes", passes_severity_gate("critical", "warning") is True)
    check("gate_below_minimum_fails", passes_severity_gate("info", "warning") is False)
    check("gate_exact_minimum_info_passes", passes_severity_gate("info", "info") is True)
    check("gate_silent_minimum_passes_everything", all(passes_severity_gate(name, "silent") for name in SEVERITY_ORDER))
    check("gate_case_insensitive", passes_severity_gate("WARNING", "warning"))
    check("gate_synonym_recognised", passes_severity_gate("error", "warning") and not passes_severity_gate("debug", "warning"))

    # ── the ack / resolve state machine ─────────────────────────────────────
    plan = plan_ack(STATUS_FIRING, fingerprint="fp-1", alert_id="al-aaa", now=1704164645000)
    check("ack_from_firing_allowed_and_changed", plan.allowed and plan.changed and not plan.replay)
    check("ack_from_firing_timestamped", plan.status == STATUS_ACKNOWLEDGED and plan.at_ms == 1704164645000)
    check("ack_key_is_fingerprint_scoped", plan.idempotency_key == "alert:fp-1")
    replay = plan_ack(STATUS_ACKNOWLEDGED, fingerprint="fp-1", alert_id="al-aaa", now=1704164645999)
    check("ack_replay_is_allowed_but_not_a_transition", replay.allowed and not replay.changed and replay.replay)
    check("ack_replay_writes_no_timestamp", replay.at_ms == 0)
    check("ack_replay_reason_names_the_state", replay.reason == "already_acknowledged")
    resolved_plan = plan_ack(STATUS_RESOLVED, fingerprint="fp-1", alert_id="al-aaa")
    check("ack_of_resolved_refused", not resolved_plan.allowed and resolved_plan.reason == "already_resolved")
    stranger = plan_ack(STATUS_FIRING, fingerprint="fp-1", alert_id="al-aaa", actor_is_target=False)
    check("ack_by_non_target_refused", not stranger.allowed and stranger.reason == "not_a_target")
    console = plan_ack(STATUS_FIRING, fingerprint="fp-1", alert_id="al-aaa", actor_is_target=False, require_actor=False)
    check("console_ack_allowed_without_target_membership", console.allowed and console.changed)
    check("ack_without_fingerprint_falls_back_to_id", plan_ack(STATUS_FIRING, alert_id="al-zzz").idempotency_key == "alert:id:al-zzz")
    check("unknown_status_refused", plan_ack("weird").reason == "unknown_status")
    check("plan_ingest_resolved_wins", plan_ingest(STATUS_FIRING, STATUS_RESOLVED) == STATUS_RESOLVED)
    check("plan_ingest_resample_keeps_ack", plan_ingest(STATUS_ACKNOWLEDGED, STATUS_FIRING) == STATUS_ACKNOWLEDGED)
    check("plan_ingest_refire_wakes_row", plan_ingest(STATUS_RESOLVED, STATUS_FIRING) == STATUS_FIRING)
    check("plan_ingest_new_row", plan_ingest(None, STATUS_FIRING) == STATUS_FIRING)
    r_plan = plan_resolve(STATUS_ACKNOWLEDGED, fingerprint="fp-1", alert_id="al-aaa", now=1)
    check("resolve_from_acknowledged_allowed", r_plan.allowed and r_plan.changed and r_plan.status == STATUS_RESOLVED)
    check("resolve_replay_is_noop", plan_resolve(STATUS_RESOLVED).replay and not plan_resolve(STATUS_RESOLVED).changed)
    check("resolve_from_firing_allowed", plan_resolve(STATUS_FIRING).allowed)
    check("resolve_carries_the_incident_key", plan_resolve(STATUS_FIRING, fingerprint="fp-1", alert_id="al-aaa").idempotency_key == "alert:fp-1")
    check("resolve_from_unknown_status_refused", plan_resolve("weird").reason == "unknown_status")

    # ── truncation, at the exact limits ─────────────────────────────────────
    title = alert_display_title("critical", "LatencyBudgetBurned")
    check("title_carries_severity_and_name", title == "[critical] LatencyBudgetBurned")
    check("title_within_client_limit", len(title) <= EcoLimits.card_title_chars)
    long_name = "X" * 400
    long_title = alert_display_title("warning", long_name)
    check("long_title_hits_the_limit_exactly", len(long_title) == EcoLimits.card_title_chars)
    check("long_title_keeps_the_severity_prefix", long_title.startswith("[warning] "))
    check("long_title_shows_truncation", TRUNCATION_MARKER in long_title)
    body_2000 = "A" * 2000
    check("body_at_exact_limit_untouched", truncate_for_card(body_2000, EcoLimits.card_body_chars) == body_2000)
    over = truncate_for_card("A" * 2500, EcoLimits.card_body_chars)
    check("body_over_limit_is_cut_to_the_limit", len(over) == EcoLimits.card_body_chars)
    check("body_over_limit_is_marked", over.endswith(TRUNCATION_MARKER))
    check("body_one_over_is_marked", truncate_for_card("A" * 2001, EcoLimits.card_body_chars).endswith(TRUNCATION_MARKER))
    check("cjk_body_counts_characters", len(truncate_for_card("订单" * 1200, 2000)) == 2000)
    check("tiny_limit_returns_cut", truncate_for_card("ABCDEFGH", 2) == "AB")
    check("zero_limit_returns_empty", truncate_for_card("ABC", 0) == "")

    # ── card assembly ───────────────────────────────────────────────────────
    firing_record = AlertRecord(
        alert_id="al-0123456789abcdef",
        fingerprint="fp" + "0" * 30,
        severity="critical",
        status=STATUS_FIRING,
        title=alert_display_title("critical", "api-latency"),
        summary="p99 超过阈值",
        labels={"severity": "critical", "instance": "api-3:8080", "cluster": "prod", "alertname": "api-latency"},
        card_id=None,
        source="grafana",
        firing_at_ms=1704164645000,
        ack_at_ms=None,
        ack_by_contact_id=None,
        resolved_at_ms=None,
    )
    card = build_alert_card(firing_record, card_id="alert.al-0123456789abcdef.7", detail_url="https://h.example.com/alerts/al-0123456789abcdef?sig=abc")
    check("card_style_is_security", card["v"] == "security")
    check("card_has_ut_milliseconds", isinstance(card["ut"], int) and card["ut"] > 0)
    check("card_has_no_nested_mode", "m" not in card)
    check("card_title_within_limit", len(card["title"]) <= EcoLimits.card_title_chars)
    check("card_body_within_limit", len(card.get("body", "")) <= EcoLimits.card_body_chars)
    check("card_fields_within_limit", len(card.get("fields", [])) <= EcoLimits.max_fields)
    check("card_field_values_not_empty", all(f["k"] and f["v"] for f in card["fields"]))
    check("card_field_label_lengths", all(len(f["k"]) <= EcoLimits.field_label_chars for f in card["fields"]))
    check("card_field_value_lengths", all(len(f["v"]) <= EcoLimits.field_value_chars for f in card["fields"]))
    check("card_has_fingerprint_row", any(f["k"] == "指纹" for f in card["fields"]))
    check("card_has_started_row", any(f["k"] == "开始时间" for f in card["fields"]))
    check("card_actions_at_most_two", len(card["actions"]) <= 2)
    check("card_action_ids_unique", len({a["id"] for a in card["actions"]}) == len(card["actions"]))
    check("card_ack_action_is_callback_primary", card["actions"][0]["action"] == "callback" and card["actions"][0]["style"] == "primary")
    check("card_ack_title_is_chinese_confirm", card["actions"][0]["title"] == "确认")
    check("card_progress_zero_when_firing", card["progress"]["p"] == 0 and card["progress"]["l"] == "状态")
    check("card_progress_keys_are_l_p_d", set(card["progress"]) == {"l", "p", "d"})
    check("card_progress_detail_within_limit", len(card["progress"].get("d", "")) <= EcoLimits.field_value_chars)
    no_url_card = build_alert_card(firing_record, card_id="alert.x.7")
    check("no_detail_action_without_session_url", len(no_url_card["actions"]) == 1 and no_url_card["actions"][0]["id"] == "alert-ack")
    check("no_none_kind_action_anywhere", all(a["action"] != "none" for a in card["actions"] + no_url_card["actions"]))

    acked = apply_ack(firing_record, 7, 1704164700000)
    acked_card = build_alert_card(acked, card_id="alert.al-0123456789abcdef.7", actor_label="Ada")
    check("acked_progress_is_full", acked_card["progress"]["p"] == EcoLimits.progress_percent_max)
    check("acked_progress_detail_names_who_and_when", "Ada" in acked_card["progress"]["d"] and "2024-01-02" in acked_card["progress"]["d"])
    check("acked_card_has_one_action", len(acked_card["actions"]) == 1)
    check("acked_action_titled_confirmed", acked_card["actions"][0]["title"] == "已确认")
    check("acked_action_payload_is_noop_verb", ":noop:" in acked_card["actions"][0]["payload"])
    check("acked_action_payload_single_token", require_single_token(acked_card["actions"][0]["payload"]) == acked_card["actions"][0]["payload"])
    try:
        build_action(action_id="x", title="已确认", kind="none")
        check("build_action_refuses_none_kind", False)
    except EcoValidationError as exc:
        check("build_action_refuses_none_kind", exc.rule == "action_kind")

    resolved = apply_resolve(firing_record, 1704164800000)
    resolved_card = build_alert_card(resolved, card_id="alert.al-0123456789abcdef.7")
    check("resolved_progress_full", resolved_card["progress"]["p"] == 100)
    check("resolved_action_titled_resolved", resolved_card["actions"][0]["title"] == "已解决")

    # A row whose labels are missing entirely must still produce a decodable card:
    # empty values are dropped rather than sent (PopopxEcoModels.swift:565-568).
    thin = replace(firing_record, labels={}, summary="", source="", fingerprint="")
    thin_card = build_alert_card(thin, card_id="alert.thin.7")
    check("thin_card_has_no_empty_field", all(f["k"] and f["v"] for f in thin_card["fields"]))
    check("thin_card_has_no_body_key", "body" not in thin_card)
    flooded = replace(firing_record, labels={("k%02d" % i): ("v%02d" % i) for i in range(40)})
    check("field_cap_enforced_by_builder", len(card_fields(flooded)) <= EcoLimits.max_fields)
    check("field_cap_keeps_the_identity_rows", any(f["k"] == "指纹" for f in card_fields(flooded)))
    check("limit_fields_drops_blanks", len(limit_fields([{"k": "a", "v": ""}, {"k": "", "v": "b"}, {"k": "c", "v": "d"}])) == 1)

    # ── payload grammar and the claim predicate ─────────────────────────────
    payload = ack_payload("al-0123456789abcdef")
    check("ack_payload_shape", payload == "alert:ack:al-0123456789abcdef")
    check("claims_alert_prefix", claims_callback_payload(payload) is True)
    check("does_not_claim_polls_payload", claims_callback_payload("poll:vote:3") is False)
    check("does_not_claim_empty_payload", claims_callback_payload("") is False and claims_callback_payload(None) is False)
    check("parse_ack_verb_and_id", parse_callback_payload(payload) == ("ack", "al-0123456789abcdef"))
    check("parse_noop", parse_callback_payload("alert:noop:al-1")[0] == "noop")
    check("parse_resolve", parse_callback_payload("alert:resolve:al-1") == ("resolve", "al-1"))
    check("parse_unknown_verb_is_none", parse_callback_payload("alert:explode:al-1") is None)
    check("parse_bare_prefix_is_none", parse_callback_payload("alert:") is None)
    check("minted_id_is_single_token", require_single_token(ack_payload(new_alert_id())) .startswith("alert:ack:al-"))
    check("sanitize_rejects_whitespace_id", sanitize_alert_id("al 1") == "")
    check("sanitize_rejects_double_colon_id", sanitize_alert_id("al::1") == "")
    check("sanitize_rejects_overlong_id", sanitize_alert_id("a" * 80) == "")
    check("sanitize_accepts_real_id", sanitize_alert_id("al-0123456789abcdef") == "al-0123456789abcdef")
    try:
        require_single_token("alert:ack:has space")
        check("payload_with_whitespace_rejected", False)
    except EcoValidationError as exc:
        check("payload_with_whitespace_rejected", exc.rule == "action_payload")
    try:
        require_single_token("alert::nested")
        check("payload_with_double_colon_rejected", False)
    except EcoValidationError:
        check("payload_with_double_colon_rejected", True)
    try:
        require_single_token("alert:ack:" + "z" * 600)
        check("payload_over_512_rejected", False)
    except EcoValidationError:
        check("payload_over_512_rejected", True)
    check("card_id_within_limit", len(card_id_for("al-0123456789abcdef", 123456)) <= EcoLimits.card_id_chars)

    # ── resolve keywords ────────────────────────────────────────────────────
    keywords = ["确认", "已处理", "ack", "resolve"]
    check("cjk_keyword_matches", resolve_keyword_match("确认", keywords) == "确认")
    check("cjk_control_sentence_does_not_match", resolve_keyword_match("请确认收货", keywords) is None)
    check("cjk_control_prefix_does_not_match", resolve_keyword_match("确认一下发货", keywords) is None)
    check("ascii_case_control_matches", resolve_keyword_match("ACK", keywords) == "ack")
    check("ascii_control_inside_sentence_does_not_match", resolve_keyword_match("please ack the alert", keywords) is None)
    check("keyword_surrounded_by_spaces_matches", resolve_keyword_match("  resolve  ", keywords) == "resolve")
    check("keyword_result_is_normalised", resolve_keyword_match("Resolve", keywords) == "resolve")
    check("empty_text_no_match", resolve_keyword_match("", keywords) is None and resolve_keyword_match("   ", keywords) is None)
    check("empty_keywords_no_match", resolve_keyword_match("确认", []) is None)
    check("non_string_text_no_match", resolve_keyword_match(None, keywords) is None and resolve_keyword_match(7, keywords) is None)
    check("keywords_from_config_are_lowered", resolve_keyword_match("已处理", [k.lower() for k in ("确认", "已处理")]) == "已处理")

    # ── token comparison ────────────────────────────────────────────────────
    ok, reason = authorize_webhook_token({"Authorization": "Bearer secret-token"}, "secret-token")
    check("token_match_accepts", ok and reason == "ok")
    check("token_mismatch_refuses", authorize_webhook_token({"Authorization": "Bearer wrong"}, "secret-token")[0] is False)
    check("header_form_accepted", authorize_webhook_token({"X-Popopx-Alert-Token": "secret-token"}, "secret-token")[0] is True)
    check("header_names_case_insensitive", authorize_webhook_token({"x-popopx-alert-token": "secret-token"}, "secret-token")[0] is True)
    check("bearer_scheme_case_insensitive", authorize_webhook_token({"Authorization": "bearer secret-token"}, "secret-token")[0] is True)
    ok, reason = authorize_webhook_token({"Authorization": "Bearer whatever"}, "")
    check("empty_config_refuses_everything", not ok)
    check("empty_config_names_the_variable", "POPOPX_ALERT_WEBHOOK_TOKEN" in reason)
    check("missing_credential_refuses", authorize_webhook_token({}, "secret-token")[0] is False)
    check("prefix_only_credential_refuses", authorize_webhook_token({"Authorization": "Bearer "}, "secret-token")[0] is False)
    check("short_token_is_not_a_prefix_match", authorize_webhook_token({"X-Popopx-Alert-Token": "secret"}, "secret-token")[0] is False)
    check("admin_token_gate_works", authorize_admin_token({"Authorization": "Bearer adm"}, "adm")[0] is True)
    check("admin_token_unset_refuses", authorize_admin_token({"Authorization": "Bearer adm"}, "")[0] is False)
    # The gateway answers 401 with *"provide the X-Admin-Token header"*, so that
    # spelling has to work here too; it used to read only its own and `Authorization`,
    # which the shipped console papers over by sending all three at once.
    check("admin_token_reads_the_gateways_own_header", authorize_admin_token({"X-Admin-Token": "adm"}, "adm")[0] is True)
    check("admin_token_gateway_header_is_case_insensitive", authorize_admin_token({"x-admin-token": "adm"}, "adm")[0] is True)
    check("admin_token_unrelated_header_refuses", authorize_admin_token({"X-Admin-Key": "adm"}, "adm")[0] is False)
    check("admin_token_short_value_is_not_a_prefix_match", authorize_admin_token({"X-Admin-Token": "ad"}, "adm")[0] is False)

    # ── the one-charge-per-incident rule ────────────────────────────────────
    first = charge_request(fingerprint="fp-7", alert_id="al-1", contact_id=None, severity="critical")
    second = charge_request(fingerprint="fp-7", alert_id="al-1", contact_id=7, severity="critical")
    check("charge_key_is_a_function_of_fingerprint", first["idempotency_key"] == second["idempotency_key"] == "alert:fp-7")
    check("charge_key_differs_across_incidents", charge_request(fingerprint="fp-8", alert_id="al-2", contact_id=None)["idempotency_key"] != first["idempotency_key"])
    check("charge_ref_is_the_alert_id", first["ref"] == "al-1")
    check("charge_meta_has_no_body", set(first["meta"]) <= {"alert_id", "plugin", "severity"})

    class FakeLedger:
        """Mimics `billing_ledger.idempotency_key UNIQUE` so the billing rule is
        provable without the wheel. The real constraint is billing_service's own
        and is exercised there; what this proves is that this plugin hands every
        path the same key and therefore cannot mint a second debit."""

        def __init__(self) -> None:
            self.keys: set = set()
            self.debits: List[str] = []

        def consume(self, key: str) -> None:
            if key in self.keys:
                return
            self.keys.add(key)
            self.debits.append(key)

    ledger = FakeLedger()
    for event_index in range(3):
        record = AlertRecord.from_event(
            AlertEvent(
                fingerprint="fp-stable",
                status=STATUS_FIRING,
                severity="warning",
                alertname="flapping",
                summary="",
                description="",
                labels={},
                starts_at_ms=None,
                ends_at_ms=None,
                source="grafana",
            ),
            "al-stable",
            status=STATUS_FIRING,
            firing_at_ms=1704164645000 + event_index,
        )
        ledger.consume(charge_request(fingerprint=record.fingerprint, alert_id=record.alert_id, contact_id=None)["idempotency_key"])
    acked_key = plan_ack(STATUS_FIRING, fingerprint="fp-stable", alert_id="al-stable").idempotency_key
    ledger.consume(acked_key)
    ledger.consume(plan_ack(STATUS_ACKNOWLEDGED, fingerprint="fp-stable", alert_id="al-stable").idempotency_key)
    check("same_fingerprint_never_charges_twice", len(ledger.debits) == 1)
    check("the_one_debit_carries_the_fingerprint", ledger.debits[0] == "alert:fp-stable")

    # ── the merge, as a pure function ───────────────────────────────────────
    # This is where an ack can quietly be lost: a resampled webhook that rewrote
    # `status` would tell the next on-call that nobody had looked at the incident.
    merge_event = AlertEvent(
        fingerprint="fp-merge", status=STATUS_FIRING, severity="critical", alertname="merge",
        summary="短", description="长", labels={"a": "1"},
        starts_at_ms=1704164645000, ends_at_ms=None, source="grafana",
    )
    bare = _next_record(None, merge_event, [])
    check("merge_creates_a_new_id", bare.alert_id.startswith("al-") and bare.status == STATUS_FIRING)
    check("merge_without_targets_stores_no_card_id", bare.card_id is None)
    check("merge_summary_prefers_the_description", bare.summary == "长")
    check("record_alertname_recovers_the_name", record_alertname(bare) == "merge")
    primary_row = _next_record(None, merge_event, [7])
    check("merge_stores_the_primary_card_id", primary_row.card_id == card_id_for(primary_row.alert_id, 7))
    resampled = _next_record(primary_row, merge_event, [7])
    check("merge_resample_keeps_the_alert_id", resampled.alert_id == primary_row.alert_id)
    check("merge_resample_keeps_the_card_id", resampled.card_id == primary_row.card_id)
    check("merge_resample_keeps_firing_at", resampled.firing_at_ms == primary_row.firing_at_ms)
    acked_row = apply_ack(primary_row, 7, 1704165000000)
    after_resample = _next_record(acked_row, merge_event, [7])
    check("merge_resample_does_not_undo_an_ack", after_resample.status == STATUS_ACKNOWLEDGED)
    check("merge_resample_keeps_ack_time_and_actor",
          after_resample.ack_at_ms == 1704165000000 and after_resample.ack_by_contact_id == 7)
    resolve_event = replace(merge_event, status=STATUS_RESOLVED, ends_at_ms=1704166000000)
    after_resolve = _next_record(acked_row, resolve_event, [7])
    check("merge_resolve_moves_the_state", after_resolve.status == STATUS_RESOLVED)
    check("merge_resolve_uses_the_senders_time", after_resolve.resolved_at_ms == 1704166000000)
    check("merge_resolve_keeps_the_ack_trail", after_resolve.ack_by_contact_id == 7)
    refire = _next_record(after_resolve, merge_event, [7])
    check("merge_refire_restarts_the_clock", refire.status == STATUS_FIRING and refire.firing_at_ms == 1704164645000)
    check("merge_refire_clears_the_resolution", refire.resolved_at_ms is None)
    born_resolved = _next_record(None, replace(merge_event, status=STATUS_RESOLVED), [])
    check("merge_row_born_resolved_has_a_resolved_time",
          born_resolved.status == STATUS_RESOLVED and bool(born_resolved.resolved_at_ms))
    no_start = _next_record(None, replace(merge_event, starts_at_ms=None), [])
    check("merge_missing_start_time_falls_back_to_arrival", no_start.firing_at_ms > 0)

    # ── progress, exactly as specified ──────────────────────────────────────
    check("firing_progress_is_exactly_pending",
          card_progress(firing_record) == {"l": "状态", "p": 0, "d": "待确认"})
    terminal_with_url = build_alert_card(acked, card_id="alert.al-0123456789abcdef.7",
                                        detail_url="https://h.example.com/alerts/al-0123456789abcdef")
    check("terminal_card_carries_exactly_one_action", len(terminal_with_url["actions"]) == 1)
    check("terminal_card_drops_the_detail_action", terminal_with_url["actions"][0]["id"] == "alert-terminal")
    check("firing_card_with_url_has_two_actions", len(card["actions"]) == 2)

    # ── target coercion ─────────────────────────────────────────────────────
    coerced, coercion_warnings = normalize_target_ids(["7", 7, 9, "x", True, 0, -3, None])
    check("targets_coerce_strings_and_dedupe", coerced == [7, 9])
    check("targets_report_every_rejected_item", len(coercion_warnings) == 5)
    check("targets_empty_is_empty", normalize_target_ids([])[0] == [])
    check("targets_none_is_empty", normalize_target_ids(None)[0] == [])
    check("targets_scalar_becomes_one", normalize_target_ids(5)[0] == [5])
    check("targets_capped", len(normalize_target_ids(list(range(1, 60)))[0]) == MAX_TARGETS)
    check("targets_cap_is_reported", any("truncated" in w for w in normalize_target_ids(list(range(1, 60)))[1]))

    # ── the async half, against fakes ───────────────────────────────────────
    # `create_router` needs FastAPI, so the routes are code-reviewed. Everything
    # beneath them does not: `ingest_webhook`, `ack_alert`, `resolve_alert`,
    # `resolve_by_keyword` and `handle_inbound` only touch the seam documented in
    # `plugins/__init__.py`, so a fake of that seam turns the four claims that matter
    # most — one card per follower, one charge per incident, an ack by a stranger is
    # refused, and a below-floor alert costs nothing — into assertions this command
    # runs. The fakes are deliberately literal about the two constraints the real
    # deployment enforces in SQLite: `alerts.fingerprint UNIQUE` and
    # `billing_ledger.idempotency_key UNIQUE`.
    import asyncio
    import contextlib
    from types import SimpleNamespace

    from app.plugins import CardDelivery, EcoSession

    class FakeCursor:
        def __init__(self, rowcount: int) -> None:
            self.rowcount = rowcount

    class FakeDb:
        def __init__(self) -> None:
            self.alerts: Dict[str, Dict[str, Any]] = {}      # by fingerprint
            self.cards: Dict[str, Dict[str, Any]] = {}       # by card_id
            self.settings: Dict[str, Any] = {}
            self.contacts = {7: "Ada", 9: "Ben", 12: "Cai"}
            self.inserts = 0
            self.updates = 0

        def connection(self) -> "FakeDb":
            return self

        @contextlib.contextmanager
        def transaction(self, immediate: bool = True):
            yield self

        def get_setting(self, key: str, default: Any = None) -> Any:
            return self.settings.get(key, default)

        def set_setting(self, key: str, value: Any) -> None:
            self.settings[key] = value

        def query_one(self, sql: str, params: Sequence[Any] = ()) -> Optional[Dict[str, Any]]:
            found = self.query(sql, params)
            return found[0] if found else None

        def _by_alert_id(self, alert_id: str) -> Optional[Dict[str, Any]]:
            for row in self.alerts.values():
                if row["alert_id"] == alert_id:
                    return row
            return None

        def query(self, sql: str, params: Sequence[Any] = ()) -> List[Dict[str, Any]]:
            text = " ".join(sql.split())
            args = tuple(params)
            if text.startswith("SELECT * FROM alerts WHERE fingerprint"):
                row = self.alerts.get(args[0])
                return [dict(row)] if row else []
            if text.startswith("SELECT * FROM alerts WHERE alert_id"):
                for row in self.alerts.values():
                    if row["alert_id"] == args[0]:
                        return [dict(row)]
                return []
            if text.startswith("SELECT contact_id, card_id FROM cards WHERE topic"):
                return [
                    {"contact_id": row["contact_id"], "card_id": row["card_id"]}
                    for row in self.cards.values() if row["topic"] == args[0]
                ]
            if text.startswith("SELECT local_display_name"):
                name = self.contacts.get(args[0])
                if name is None:
                    return []
                return [{"local_display_name": name, "display_name": None}]
            if text.startswith("SELECT a.* FROM alerts a JOIN cards"):
                prefix, contact_id, not_status = args[0], int(args[1]), args[2]
                held: List[Dict[str, Any]] = []
                for card in self.cards.values():
                    if not card["topic"].startswith(prefix) or card["contact_id"] != contact_id:
                        continue
                    found = self._by_alert_id(card["topic"][len(prefix):])
                    if found is not None and found["status"] != not_status:
                        held.append(dict(found))
                held.sort(key=lambda row: (0 if row["status"] == STATUS_FIRING else 1,
                                           -int(row["firing_at_ms"] or 0)))
                return held[:1]
            raise AssertionError("FakeDb.query: unhandled statement %r" % text[:60])

        def execute(self, sql: str, params: Sequence[Any] = ()) -> FakeCursor:
            text = " ".join(sql.split())
            args = tuple(params)
            if text.startswith("INSERT INTO alerts"):
                columns = ("alert_id", "fingerprint", "severity", "status", "title", "summary", "labels_json",
                           "card_id", "source", "firing_at_ms", "ack_at_ms", "ack_by_contact_id", "resolved_at_ms")
                if len(args) != len(columns):
                    raise AssertionError("FakeDb: INSERT carries %d values, not %d" % (len(args), len(columns)))
                if args[1] in self.alerts:
                    # UNIQUE (alerts.fingerprint) — database.py:383
                    raise sqlite3.IntegrityError("UNIQUE constraint failed: alerts.fingerprint")
                self.alerts[args[1]] = dict(zip(columns, args))
                self.inserts += 1
                return FakeCursor(1)
            if text.startswith("UPDATE alerts SET severity"):
                columns = ("severity", "status", "title", "summary", "labels_json", "card_id", "source",
                           "firing_at_ms", "resolved_at_ms", "ack_at_ms", "ack_by_contact_id", "alert_id")
                if len(args) != len(columns):
                    raise AssertionError("FakeDb: UPDATE carries %d values, not %d" % (len(args), len(columns)))
                patch = dict(zip(columns[:-1], args[:-1]))
                for row in self.alerts.values():
                    if row["alert_id"] == args[-1]:
                        row.update(patch)
                        self.updates += 1
                        return FakeCursor(1)
                return FakeCursor(0)
            if text.startswith("UPDATE alerts SET status = ?, ack_at_ms = ?, ack_by_contact_id = NULL"):
                for row in self.alerts.values():
                    if row["alert_id"] == args[2] and row["status"] == args[3]:
                        row.update(status=args[0], ack_at_ms=args[1], ack_by_contact_id=None)
                        return FakeCursor(1)
                return FakeCursor(0)
            if text.startswith("UPDATE alerts SET status = ?, ack_at_ms"):
                _status, at_ms, actor, alert_id, expected = args
                for row in self.alerts.values():
                    if row["alert_id"] == alert_id and row["status"] == expected:
                        if actor is not None and actor not in self.contacts:
                            # FK on ack_by_contact_id with PRAGMA foreign_keys=ON
                            raise sqlite3.IntegrityError("FOREIGN KEY constraint failed")
                        row.update(status=_status, ack_at_ms=at_ms, ack_by_contact_id=actor)
                        return FakeCursor(1)
                return FakeCursor(0)
            if text.startswith("UPDATE alerts SET status = ?, resolved_at_ms"):
                _status, at_ms, alert_id = args[0], args[1], args[2]
                for row in self.alerts.values():
                    if row["alert_id"] == alert_id and row["status"] in args[3:]:
                        row.update(status=_status, resolved_at_ms=at_ms)
                        return FakeCursor(1)
                return FakeCursor(0)
            raise AssertionError("FakeDb.execute: unhandled statement %r" % text[:60])

    class FakeBilling:
        """`billing_ledger.idempotency_key UNIQUE`, which is the whole exact-once rule."""

        def __init__(self) -> None:
            self.keys: List[str] = []
            self.debits: List[str] = []
            self.meters: List[str] = []
            self.refuse: Optional[Exception] = None

        def charge(self, meter: str, **kwargs: Any) -> Any:
            self.meters.append(meter)
            key = kwargs.get("idempotency_key")
            self.keys.append(key)
            if self.refuse is not None:
                raise self.refuse
            if key not in self.debits:
                self.debits.append(key)
                return SimpleNamespace(charged=2, cost=2, idempotent_replay=False, balance_after=98)
            return SimpleNamespace(charged=0, cost=2, idempotent_replay=True, balance_after=98)

    class FakeEco:
        def __init__(self, db: FakeDb) -> None:
            self.db = db
            self.delivered: List[Dict[str, Any]] = []
            self.updated: List[Dict[str, Any]] = []
            self.sessions: Dict[int, Any] = {}

        def session_for(self, contact_id: int) -> Optional[Any]:
            return self.sessions.get(contact_id)

        def h5_url(self, session: Any, path: str) -> str:
            return "https://h5.invalid%s?popopx_uid=%s&sig=deadbeef" % (path, session.pairwise_uid)

        async def deliver_card(self, card: Mapping[str, Any], contact_id: int, *,
                               visible_text: Optional[str] = None, topic: str = "") -> CardDelivery:
            self.delivered.append({"card_id": card["id"], "contact_id": contact_id, "topic": topic,
                                   "visible_text": visible_text, "card": dict(card)})
            self.db.cards[card["id"]] = {"card_id": card["id"], "contact_id": contact_id, "topic": topic}
            return CardDelivery(card_id=card["id"], contact_id=contact_id, sent=True, charged=5,
                                balance_after=93, error=None, queued=False)

        async def update_card(self, card_id: str, contact_id: int, **kwargs: Any) -> CardDelivery:
            self.updated.append(dict(kwargs, card_id=card_id, contact_id=contact_id))
            return CardDelivery(card_id=card_id, contact_id=contact_id, sent=True, charged=0,
                                balance_after=98, error=None, queued=False)

    class FakeDeps:
        def __init__(self, db: FakeDb, billing: FakeBilling, eco: FakeEco, minimum: str = "warning") -> None:
            self.db = db
            self.billing = billing
            self.eco = eco
            self.spec = mounted
            self.plugin_id = mounted.plugin_id
            self.config = SimpleNamespace(alert_min_severity=minimum, alert_webhook_token="tok",
                                         admin_token="adm", alert_resolve_keywords=["确认", "ack"])

        def charge(self, **kwargs: Any) -> Any:
            return self.billing.charge(self.spec.meter, **kwargs)

    def webhook_body(fingerprint: str, severity: str = "critical", status: str = "firing") -> Dict[str, Any]:
        return {
            "status": status,
            "alerts": [{
                "status": status,
                "fingerprint": fingerprint,
                "labels": {"alertname": "pay-latency", "severity": severity, "instance": "api-3:8080"},
                "annotations": {"summary": "p99 over budget", "description": "checkout is slow"},
                "startsAt": "2024-01-02T03:04:05Z",
            }],
        }

    async def run_the_half_that_needs_no_fastapi() -> None:
        db = FakeDb()
        billing = FakeBilling()
        eco = FakeEco(db)
        deps = FakeDeps(db, billing, eco)
        db.settings[SETTINGS_TARGETS_KEY] = [7, 9]
        eco.sessions[7] = EcoSession(contact_id=7, pairwise_uid="u7", secret_hex="ab" * 32, service_id="svc")
        # Contact 9 follows the account but has no handshake yet: its card must not
        # carry a link signed with a session that does not exist.
        first = await ingest_webhook(deps, webhook_body("fp-live"))
        check("webhook_created_one_row", first["counts"].get("created") == 1 and db.inserts == 1)
        check("webhook_delivered_one_card_per_target", len(eco.delivered) == 2)
        check("webhook_cards_are_topic_tagged", {d["topic"] for d in eco.delivered} == {TOPIC_PREFIX + first["results"][0]["alert_id"]})
        check("webhook_charges_the_alert_meter_once", billing.debits == ["alert:fp-live"])
        check("webhook_never_charges_the_card_meter", set(billing.meters) == {"alert"})
        by_contact = {d["contact_id"]: d["card"] for d in eco.delivered}
        check("session_holder_gets_a_detail_action",
              [a["id"] for a in by_contact[7]["actions"]] == ["alert-ack", "alert-detail"])
        check("session_holder_detail_is_a_real_url", str(by_contact[7]["actions"][1]["url"]).startswith("https://h5.invalid/alerts/"))
        check("no_session_no_url_action", [a["id"] for a in by_contact[9]["actions"]] == ["alert-ack"])
        check("card_never_carries_visible_text", all(d["visible_text"] is None for d in eco.delivered))

        # A repeat of the same incident: the row is updated, the bubbles are updated,
        # no third card exists, and the ledger sees the key it has already seen.
        second = await ingest_webhook(deps, webhook_body("fp-live"))
        check("repeat_webhook_updates_the_row", second["counts"].get("updated") == 1 and db.inserts == 1)
        check("repeat_webhook_stacks_no_card", len(eco.delivered) == 2)
        check("repeat_webhook_moves_every_bubble", len(eco.updated) == 2)
        check("repeat_webhook_charges_nothing_new", billing.debits == ["alert:fp-live"] and len(billing.keys) == 2)
        check("one_incident_charge_attempt_per_webhook_not_per_target",
              billing.keys.count("alert:fp-live") == 2)
        check("repeat_webhook_keeps_the_card_ids", {d["card_id"] for d in eco.delivered} == {u["card_id"] for u in eco.updated})

        # A stranger may not ack: the ack button is on their screen, which is exactly
        # why the server has to decide instead of trusting the tap.
        stranger = await ack_alert(deps, second["results"][0]["alert_id"], contact_id=11, actor_is_target=False)
        check("stranger_ack_refused", not stranger["ok"] and stranger["reason"] == "not_a_target")
        check("stranger_ack_wrote_nothing", db.alerts["fp-live"]["status"] == STATUS_FIRING and len(eco.updated) == 2)

        acked = await ack_alert(deps, second["results"][0]["alert_id"], contact_id=7)
        check("target_ack_recorded", db.alerts["fp-live"]["status"] == STATUS_ACKNOWLEDGED)
        check("target_ack_stores_the_actor", db.alerts["fp-live"]["ack_by_contact_id"] == 7)
        check("target_ack_charges_nothing_new", billing.debits == ["alert:fp-live"])
        repaints = eco.updated[-2:]
        check("ack_repaints_both_bubbles", {r["contact_id"] for r in repaints} == {7, 9})
        check("ack_progress_is_full", all(r["progress"]["p"] == 100 for r in repaints))
        check("ack_progress_names_the_operator", all("Ada" in r["progress"]["d"] for r in repaints))
        check("ack_card_action_is_terminal", all(r["actions"][0]["payload"].startswith("alert:noop:") for r in repaints))
        check("ack_card_replaces_the_ack_button", all(len(r["actions"]) == 1 for r in repaints))

        again = await ack_alert(deps, second["results"][0]["alert_id"], contact_id=7)
        check("second_ack_is_a_replay", again["ok"] and again.get("replay") is True)
        check("second_ack_repaints_nothing", len(eco.updated) == 4)
        check("second_ack_charges_nothing", len(billing.keys) == 3 and billing.debits == ["alert:fp-live"])

        # A new follower added after the first webhook is backfilled, once.
        db.settings[SETTINGS_TARGETS_KEY] = [7, 9, 12]
        third = await ingest_webhook(deps, webhook_body("fp-live"))
        check("new_target_backfills_one_card", len(eco.delivered) == 3 and len(eco.updated) == 6)
        check("backfill_creates_no_second_row", db.inserts == 1 and third["counts"].get("updated") == 1)

        resolved = await ingest_webhook(deps, webhook_body("fp-live", status="resolved"))
        check("resolved_webhook_closes_the_row", db.alerts["fp-live"]["status"] == STATUS_RESOLVED)
        check("resolved_webhook_is_not_a_second_card", len(eco.delivered) == 3)
        check("resolved_webhook_carries_no_resolved_time_from_a_firing_field",
              resolved["results"][0]["status"] == STATUS_RESOLVED)

        # Below the floor: the row exists, the phone hears nothing, nothing is paid.
        quiet = await ingest_webhook(deps, webhook_body("fp-quiet", severity="info"))
        check("below_floor_records_the_row", db.alerts["fp-quiet"]["status"] == STATUS_FIRING)
        check("below_floor_delivers_no_card", quiet["counts"].get("suppressed") == 1 and len(eco.delivered) == 3)
        check("below_floor_charges_nothing", billing.debits == ["alert:fp-live"])

        # Refused billing must not lose the operator's ack.
        billing.refuse = RuntimeError("insufficient_credits")
        refused = await ack_alert(deps, db.alerts["fp-quiet"]["alert_id"], contact_id=9)
        check("charge_failure_keeps_the_ack", db.alerts["fp-quiet"]["status"] == STATUS_ACKNOWLEDGED)
        check("charge_failure_reports_a_warning", any("计费" in w for w in refused["warnings"]))
        billing.refuse = None

        # The keyword path, including the control sentence.
        await ingest_webhook(deps, webhook_body("fp-kw"))
        ignored = await resolve_by_keyword(deps, 7, "请确认收货")
        check("keyword_control_resolves_nothing", ignored is None)
        # A sentence that merely *contains* the keyword is somebody's shopping chat.
        # Nothing may move, and none of its text may end up in the log.
        prose = await resolve_by_keyword(deps, 7, "请确认收货 订单号 9007199254740993")
        check("keyword_inside_a_sentence_resolves_nothing", prose is None)
        check("chat_prose_stays_out_of_the_log", not any("9007199254740993" in line for line in captured))
        check("keyword_status_is_not_a_log_line", not any("请确认收货" in line for line in captured))
        matched = await resolve_by_keyword(deps, 7, "确认")
        check("keyword_resolves_the_open_incident", matched is not None and matched.get("ok") is True)
        check("keyword_resolution_names_the_newest", matched["alert_id"] == db.alerts["fp-kw"]["alert_id"])
        check("keyword_resolution_is_idempotent_on_state", db.alerts["fp-kw"]["status"] == STATUS_RESOLVED)

        # The inbound claim predicate, with a message shaped like the bridge's.
        alert_id = db.alerts["fp-live"]["alert_id"]
        claimed = SimpleNamespace(contact_id=7, display_name="Ada", callback=SimpleNamespace(
            kind="card_callback", raw="::CB::alert:noop:%s" % alert_id, payload="alert:noop:%s" % alert_id))
        foreign = SimpleNamespace(contact_id=7, display_name="Ada", callback=SimpleNamespace(
            kind="card_callback", raw="::CB::poll:vote:3", payload="poll:vote:3"))
        prose = SimpleNamespace(contact_id=7, display_name="Ada", callback=None)
        check("handle_inbound_claims_its_own_payload", await handle_inbound(deps, claimed) is True)
        check("handle_inbound_leaves_another_plugins_payload", await handle_inbound(deps, foreign) is False)
        check("handle_inbound_never_claims_plain_text", await handle_inbound(deps, prose) is False)

    # Log hygiene is a requirement ("never a webhook body, log ids and counts"), and a
    # requirement that can be *measured*: every line the module emits while the whole
    # async half runs — including the four deliberate failure paths — is captured here
    # and searched for the fixtures' secrets and payloads.
    captured: List[str] = []

    class _Capture(logging.Handler):
        def emit(self, record: logging.LogRecord) -> None:
            try:
                captured.append(record.getMessage())
            except Exception:  # a broken test harness must not break the module
                pass

    sink = _Capture()
    sink.setLevel(logging.DEBUG)
    LOG.addHandler(sink)
    previous_level = LOG.level
    LOG.setLevel(logging.DEBUG)
    try:
        asyncio.run(run_the_half_that_needs_no_fastapi())
    finally:
        LOG.setLevel(previous_level)
        LOG.removeHandler(sink)
    check("async_half_ran_to_completion", True)
    joined_logs = " | ".join(captured)
    check("refusals_are_logged_with_their_reason",
          "not_a_target" in joined_logs and "charge" in joined_logs)
    check("logs_never_carry_a_webhook_body",
          not any(word in joined_logs for word in ("pay-latency", "p99 over budget",
                                                  "api-3:8080", "checkout is slow", "summary")))
    check("logs_never_carry_a_credential",
          not any(word in joined_logs for word in ("sig=", "abababab", "u7", "tok")))
    check("logs_carry_ids", all("alert" in line or "alert_ops" in line or "targets" in line
                                for line in captured))
    check("the_module_did_log_something", len(captured) >= 4)

    # ── the module's own contract ───────────────────────────────────────────
    check("all_exported_names_exist", all(name in globals() for name in __all__))
    check("payload_prefix_is_the_claim_token", PAYLOAD_PREFIX == "alert:")
    check("url_prefix_matches_the_mount_table", mounted.url_prefix == "/api/v1/plugins/alerts")
    check("mounted_meter_is_alert", mounted.meter == "alert")
    check("mounted_callback_kind_is_card_callback", mounted.callback_kinds == ("card_callback",))
    check("mounted_module_name_is_this_file", mounted.module_name == "app.plugins.alert_ops_plugin")
    check("mounted_toggle_is_the_config_flag", mounted.toggle == "alert_ops")
    check("mounted_plugin_id_is_this_module", mounted.plugin_id == PLUGIN_ID)

    return checks
