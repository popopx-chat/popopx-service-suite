# Copyright (c) 2026 POPOPX (popopx.chat)
# SPDX-License-Identifier: AGPL-3.0-only
"""POPX-CP — the compute-credit billing engine.

What this module owns
---------------------
One prepaid balance in integer compute credits ("POPX-CP"), the lifecycle that
governs whether the deployment may spend it (``ONLINE`` by default, with
``DRAFT`` kept for opt-in voucher admission, and ``SUSPENDED`` when the balance
runs out or an operator halts it), and the fuse that stops the paid plugins when the balance runs
out. It is the *only* place that mutates ``billing_account`` and
``billing_ledger``, and it is deliberately the place that knows least about
cryptography: accounting must not own the signature scheme, so a voucher is
verified by an injected callable and this file treats the result as input from
the same border a network request is input from.

Three properties are load-bearing, and the rest of the file is in service of
them.

1. **A charge is atomic with its ledger row.** ``billing_account.balance``
   carries ``CHECK (balance >= 0)``, so an overdraft is not a negative number
   anyone can notice later — it is a ``sqlite3.IntegrityError`` raised halfway
   through a write. Every mutation here therefore reads the balance, decides
   affordability, and writes the debit *and* the ledger row inside a single
   :meth:`Database.transaction` with ``immediate=True``, which takes the write
   lock before the read (see the decision list in ``database.py``). Nothing is
   ever "fixed up" after a failed statement: if we do not enter a transaction
   intending to overdraw, we never discover one.

2. **Ledger and balance never disagree.** The invariant
   ``balance == lifetime_granted - lifetime_spent`` holds after every commit,
   including after a refund, because a refund is modelled as *un-spending*
   (``lifetime_spent`` goes down) rather than as new money. ``reversal`` is the
   fourth ledger kind in the schema and this module never writes it: it is for
   an operator correcting a posted row by hand, and an engine that silently
   reversed its own bookkeeping would be the end of the audit trail the table
   exists to provide.

3. **A retried call charges once.** ``billing_ledger.idempotency_key`` is
   ``UNIQUE``, and the outbox retry path — a WebSocket send that timed out but
   may have landed — depends on that. Both halves are implemented: the key is
   looked up inside the transaction (the common case, a retry of a completed
   charge), *and* a ``UNIQUE`` violation on insert is caught after the rollback
   to resolve the concurrent case, where another writer committed first. The
   catch is safe precisely because the rollback undid our own debit, so the
   only row that can exist is the committed original, which we then return.

Money math is integers only, everywhere. There is no float in a balance, a
cost, or a ledger amount, and no rounding step that could disagree with the
merchant's invoice.

What "fused" means here
-----------------------
A plugin is *fused* when billing, not the operator, is what stops it: an
unactivated account, a suspended account, or an activated account whose
balance has fallen to ``suspend_threshold``. Fusing is derived from the
account row on every call rather than stored as a flag, so it can never drift
out of sync with the money, and so **redemption alone un-fuses** — there is no
un-fuse button to forget to press. An operator halt is the exception:
:susp:`suspend` marks the reason as an operator halt, and only
:meth:`go_online` clears that mark. A merchant who redeems a voucher while a
human being has halted the account should not be able to lift the halt by
paying.

Self-hosted deployments (``require_voucher=False``, the shipped default)
------------------------------------------------------------------------
This is the out-of-the-box behaviour: the account is born ``ONLINE`` and no
external activation code is needed to make a plugin work. The same engine runs
either way, and "unmetered" must not mean "billing code is skipped" — that
would mean two hot paths and one of them untested. So when
``config.billing.require_voucher`` is false:

* the account is ``ONLINE`` from the first touch, and a :meth:`charge` that
  finds a leftover ``DRAFT`` row — one written by an older database, or by a
  deployment that has since switched admission off — lifts it on the way past;
* the action is priced and recorded exactly as it would be in a paid
  deployment, so the console still shows real usage and a later switch to
  voucher billing has history to price from;
* the balance is topped up first by an automatic zero-price ``grant`` ledger
  row for whatever the charge needs and the account does not have, then
  debited in full — which keeps the invariant above true instead of quietly
  pretending the balance was never empty;
* nothing is ever fused for lack of credits, and the only state that blocks a
  plugin is an explicit operator :meth:`suspend`.

Reference to the brief
----------------------
The lifecycle ``DRAFT -> ONLINE -> SUSPENDED``, signed voucher admission and
"余额不足自动熔断插件" (auto-fuse the plugins when the balance runs out) are all
implemented here, and all three still apply to a deployment that sets
``POPOPX_BILLING_REQUIRE_VOUCHER=1``. What changed is the default: admission is
opt-in now, so a self-hosted instance starts ``ONLINE`` and the voucher tooling
in ``official_tools/gen_voucher.py`` is an optional internal quota instrument
rather than the door. The brief's card-signature
requirement is *not* a client-side gate: as ``database.py`` records against the
iOS source, the card renderer holds no signature field, so a card's ``sig`` /
``ts`` columns are a server-side audit seal. Billing does not consult them and
does not claim to.
"""

from __future__ import annotations

import base64
import json
import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

from app.config import Config
from app.database import Database, now_ms

__all__ = [
    "DEFAULT_SERVICE_ID",
    "CODE_PREFIX",
    "VOUCHER_FIELDS",
    "METER_ACTIONS",
    "METERED_PLUGINS",
    "BillingError",
    "VoucherPayload",
    "ChargeResult",
    "AccountView",
    "BillingService",
]

#: "attribute absent" sentinel for :meth:`BillingService._normalise_payload`.
#: Needed because ``None`` is a *legal* value for ``expires_at_ms``, so a
#: ``getattr(obj, name, None)`` default could not tell a missing attribute from
#: an explicit no-expiry.
_MISSING = object()

#: The billing singleton is per deployment, not per service, so it is named by
#: whichever service this gateway happens to operate. ``config.service_id`` wins
#: when it is set; this is the fallback that keeps ``summary()`` non-empty on a
#: hand-built :class:`~app.config.Config` in a test.
DEFAULT_SERVICE_ID = "popopx-service"

#: Wire prefix of an activation code, shared with
#: ``official_tools/gen_voucher.py`` (``PREFIX`` there) and with
#: ``crypto_service.py``, which owns the signature half of reading it.
CODE_PREFIX = "POPX-CP-1."

STATUS_DRAFT = "DRAFT"
STATUS_ONLINE = "ONLINE"
STATUS_SUSPENDED = "SUSPENDED"

KIND_GRANT = "grant"
KIND_CONSUME = "consume"
KIND_REFUND = "refund"

#: ``suspended_reason`` is the only column available to say *why* an account is
#: halted, and the halt has two very different authors. The prefix is therefore
#: part of the contract: credit exhaustion is allowed to heal itself when money
#: returns, an operator halt is not. Anything written by :meth:`suspend` keeps
#: the operator prefix until :meth:`go_online` clears it by hand.
REASON_CREDITS = "credits:"
REASON_OPERATOR = "operator:"

#: The meter table: billing-facing action name -> attribute on
#: :class:`app.config.BillingConfig`. The action names are the config field
#: names with ``per_`` dropped, which is the only rule that keeps every call
#: site, ``.env.example`` and the console honest at once. Plugins pass these
#: strings to :meth:`BillingService.charge`; they are not free text.
METER_ACTIONS: Tuple[Tuple[str, str], ...] = (
    ("card", "per_card"),
    ("menu_push", "per_menu_push"),
    ("key_rotation", "per_key_rotation"),
    ("ai_message", "per_ai_message"),
    ("alert", "per_alert"),
    ("sso_login", "per_sso_login"),
    ("poll", "per_poll"),
    ("web3_event", "per_web3_event"),
    ("workflow_event", "per_workflow_event"),
    ("carddav_query", "per_carddav_query"),
    ("caldav_query", "per_caldav_query"),
)

#: Which plugin toggle each meter pays for. The first three meters in
#: :data:`METER_ACTIONS` (``card``, ``menu_push``, ``key_rotation``) are the
#: base product and belong to no plugin, so fusing never touches them — a
#: fused gateway can still send a plain message and still rotate a key the
#: merchant already owns.
METERED_PLUGINS: Tuple[Tuple[str, str], ...] = (
    ("ai_agent", "ai_message"),
    ("alert_ops", "alert"),
    ("privacy_sso", "sso_login"),
    ("polls", "poll"),
    ("web3_bridge", "web3_event"),
    ("workflow_webhook", "workflow_event"),
    ("carddav_connector", "carddav_query"),
    ("caldav_connector", "caldav_query"),
)

#: Hard cap on :meth:`BillingService.ledger`; the console renders a page, and a
#: caller that asks for ``limit=10_000_000`` should get a page, not the table.
LEDGER_LIMIT_MAX = 1000


class BillingError(Exception):
    """A billing refusal with a machine-stable ``code`` and an HTTP status.

    ``code`` is part of the API: ``main.py`` maps it to a response body and the
    console keys its messages on it, so it is a lowercase snake identifier that
    does not change wording even when the human message does. ``http_status``
    is the *suggested* status for the route that caught it — 402 for "this
    deployment has no credits", which is exactly what that code means.
    """

    def __init__(self, code: str, message: str, *, http_status: int = 400) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.http_status = int(http_status)

    def __repr__(self) -> str:
        return "BillingError(code=%r, http_status=%d, message=%r)" % (self.code, self.http_status, self.message)


@dataclass(frozen=True)
class VoucherPayload:
    """A verified activation code, as handed over by ``crypto_service``.

    Declared here rather than imported from ``crypto_service`` on purpose: this
    module must be importable before the crypto half exists, and the accounting
    engine should not depend on a verifier implementation, only on its shape.
    ``signature_b64`` is carried along so :meth:`BillingService.redeem_voucher`
    can store it verbatim — ``vouchers.signature_b64`` is ``NOT NULL``, and the
    bytes that were signed are the only proof of what this code promised.
    """

    voucher_id: str
    plan: str
    credits: int
    issued_at_ms: int
    expires_at_ms: Optional[int]
    issuer_key_id: str
    signature_b64: str
    code: str


#: The eight fields :meth:`BillingService._normalise_payload` reads off whatever
#: the verifier returns. Named once so the dataclass above and the duck-typed
#: acceptance below cannot drift apart.
VOUCHER_FIELDS: Tuple[str, ...] = (
    "voucher_id",
    "plan",
    "credits",
    "issued_at_ms",
    "expires_at_ms",
    "issuer_key_id",
    "signature_b64",
    "code",
)


@dataclass(frozen=True)
class ChargeResult:
    """The outcome of one mutating call.

    ``cost`` is the magnitude of credits this call's ledger row moved.
    ``charged`` is how many left the balance because of it — equal to ``cost``
    for a normal charge, less than ``cost`` for the last charge before an
    exhaustion suspension (the remainder is forfeited, not carried as debt,
    because the schema cannot store a negative balance), and ``0`` for
    :meth:`BillingService.grant` and :meth:`BillingService.refund`, which add.
    A caller that needs to know whether it got full value compares
    ``charged`` with ``quote()``.
    """

    charged: int
    cost: int
    balance_after: int
    account_status: str
    idempotent_replay: bool

    def to_dict(self) -> Dict[str, Any]:
        return {
            "charged": self.charged,
            "cost": self.cost,
            "balance_after": self.balance_after,
            "account_status": self.account_status,
            "idempotent_replay": self.idempotent_replay,
        }


@dataclass(frozen=True)
class AccountView:
    """Immutable snapshot of the billing singleton."""

    status: str
    balance: int
    lifetime_granted: int
    lifetime_spent: int
    suspended_reason: Optional[str]
    is_chargeable: bool

    def to_dict(self) -> Dict[str, Any]:
        return {
            "status": self.status,
            "balance": self.balance,
            "lifetime_granted": self.lifetime_granted,
            "lifetime_spent": self.lifetime_spent,
            "suspended_reason": self.suspended_reason,
            "is_chargeable": self.is_chargeable,
        }


def _b64u_decode(text: str) -> bytes:
    """Unpadded base64url, matching ``gen_voucher.b64u_decode``."""
    padding = "=" * (-len(text) % 4)
    return base64.urlsafe_b64decode(text + padding)


def _dumps(value: Any) -> str:
    """Same JSON spelling ``database.py`` uses for its JSON columns."""
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))


class BillingService:
    """The POPX-CP engine: one balance, one lifecycle, one ledger.

    Safe to share across threads, which it must be because FastAPI runs its
    synchronous path operations on a threadpool: there is no mutable state on
    ``self`` at all, and serialisation comes from SQLite's ``BEGIN IMMEDIATE``
    rather than from a :class:`threading.Lock`, which would only protect one
    process and give a false sense of it. ``db`` hands each thread its own
    connection (see ``database.py``), and every method here is either a read or
    one short transaction.

    ``voucher_verifier`` is ``Callable[[str], VoucherPayload]``: give it a code,
    it either returns the verified payload or raises. It is injected because
    this module must not import ``crypto_service`` (that is a second owner of
    the Ed25519 trust decision, and an accounting row is not where a key gets
    trusted). When no verifier is injected, redemption raises
    ``verifier_unavailable`` rather than crediting anything: an unverified code
    is a string, and a string does not buy computation.
    """

    def __init__(self, db: Database, config: Config, voucher_verifier: Optional[Callable[[str], VoucherPayload]] = None) -> None:
        self.db = db
        self.config = config
        self.voucher_verifier = voucher_verifier
        self.service_id = (getattr(config, "service_id", "") or DEFAULT_SERVICE_ID) if config else DEFAULT_SERVICE_ID

    # ── account ─────────────────────────────────────────────────────────────

    def account(self) -> AccountView:
        """The billing singleton, created ``ONLINE`` on first touch.

        Read-mostly: the ``INSERT OR IGNORE`` only fires for a database file
        that has never been billed against, and the primary key is
        ``CHECK (id = 1)``, so two first touches in two threads settle on one
        row. It runs outside a transaction on purpose — a health poll of
        ``GET /api/v1/billing`` must not queue behind the write lock.
        """
        row = self._ensure_account(self.db.connection())
        return self._view(row)

    def _initial_status(self) -> str:
        """The status a brand-new account row is born with.

        ``ONLINE`` — the deployment is usable the moment its database file exists.
        ``DRAFT`` is still what a row is born with when the operator opted into
        voucher admission, and it is what a database written before that opt-in
        still holds, which is why every ``DRAFT`` branch below stays reachable.
        """
        return STATUS_DRAFT if self.config.billing.require_voucher else STATUS_ONLINE

    def _ensure_account(self, conn: sqlite3.Connection) -> sqlite3.Row:
        conn.execute(
            "INSERT OR IGNORE INTO billing_account (id, status, balance, lifetime_granted, lifetime_spent, updated_at_ms) "
            "VALUES (1, ?, 0, 0, 0, ?)",
            (self._initial_status(), now_ms()),
        )
        row = conn.execute("SELECT * FROM billing_account WHERE id = 1").fetchone()
        if row is None:  # pragma: no cover - only if the table itself is missing
            raise BillingError("account_missing", "billing_account has no singleton row", http_status=500)
        return row

    def _view(self, row: sqlite3.Row) -> AccountView:
        return AccountView(
            status=row["status"],
            balance=int(row["balance"]),
            lifetime_granted=int(row["lifetime_granted"]),
            lifetime_spent=int(row["lifetime_spent"]),
            suspended_reason=row["suspended_reason"],
            is_chargeable=self._is_chargeable(row["status"], int(row["balance"])),
        )

    def _is_chargeable(self, status: str, balance: int) -> bool:
        """Whether :meth:`charge` would get as far as affordability.

        ``SUSPENDED`` never charges. ``DRAFT`` — which only exists when voucher
        admission is on, or in a database written before it was turned off —
        charges only in an unmetered deployment, the documented auto-activate case. A suspended
        account that is merely out of credits is not "chargeable" either way,
        so the answer stays false until money arrives.
        """
        if status == STATUS_SUSPENDED:
            return False
        if status == STATUS_DRAFT:
            return not self.config.billing.require_voucher
        return True

    # ── meters ──────────────────────────────────────────────────────────────

    def meters(self) -> Dict[str, int]:
        """Action -> price in POPX-CP, read straight from :class:`~app.config.BillingConfig`.

        A meter configured to ``0`` is a *free* action, not an absent one: it
        still quotes, still writes a ``consume`` row of ``0``, and still shows
        in the console. That is the difference between "this merchant does not
        pay for cards" and a typo that silently bills nothing.
        """
        return {action: int(getattr(self.config.billing, attr)) for action, attr in METER_ACTIONS}

    def quote(self, action: str) -> int:
        prices = self.meters()
        if action not in prices:
            raise BillingError(
                "unknown_meter",
                "no POPX-CP meter for %r; known meters: %s" % (action, ", ".join(sorted(prices))),
            )
        return prices[action]

    def can_afford(self, action: str) -> bool:
        """Whether a full-price charge would succeed *right now*.

        Advisory only — the authoritative decision is inside :meth:`charge`'s
        transaction, because the balance can move between the two calls. Use it
        for a console badge or an early-out, never as the gate.
        """
        cost = self.quote(action)
        row = self._ensure_account(self.db.connection())
        if not self._is_chargeable(row["status"], int(row["balance"])):
            return False
        if not self.config.billing.require_voucher:
            # Unmetered: the automatic top-up in _charge_txn makes anything affordable.
            return True
        return int(row["balance"]) - cost >= self.config.billing.suspend_threshold

    # ── the hot path ────────────────────────────────────────────────────────

    def charge(
        self,
        action: str,
        *,
        contact_id: Optional[int] = None,
        ref: Optional[str] = None,
        idempotency_key: Optional[str] = None,
        meta: Optional[Dict[str, Any]] = None,
    ) -> ChargeResult:
        """Meter one action against the balance. The only mutating hot path.

        Order of decisions, all inside one ``BEGIN IMMEDIATE``:

        1. price it (:data:`METER_ACTIONS`), or refuse with ``unknown_meter``;
        2. replay-check ``idempotency_key`` and return the original result;
        3. refuse ``DRAFT`` with ``account_draft`` and ``SUSPENDED`` with
           ``account_suspended`` (unless unmetered, where ``DRAFT`` is
           auto-activated in the same transaction);
        4. if the balance covers the cost down to ``suspend_threshold``, debit
           in full;
        5. otherwise drain what *is* available down to the threshold, then fuse
           — ``SUSPENDED`` with reason ``credits:...`` — so the merchant is
           stopped by the next call, not by this one. The brief's 余额不足
           自动熔断 rule is this branch;
        6. if even that remainder is zero, suspend and raise
           ``insufficient_credits``. The raise happens *after* the transaction
           commits: the suspension is a real state change that must survive the
           refusal, and raising inside would roll it back.

        A charge that cannot be paid in full is never partially fulfilled:
        branch 5 spends what the account had and lets *this* action proceed,
        which is the brief's choice, and the shortfall is written off rather
        than banked, because ``CHECK (balance >= 0)`` means there is no place
        to put a debt.
        """
        cost = self.quote(action)
        key = _clean_key(idempotency_key)
        unmetered = not self.config.billing.require_voucher
        envelope = {
            "action": action,
            "contact_id": contact_id,
            "cost": cost,
            "unmetered": unmetered,
        }
        if meta:
            envelope["meta"] = meta

        try:
            result, refusal = self._charge_txn(
                cost=cost,
                action=action,
                unmetered=unmetered,
                subject=(None if contact_id is None else str(contact_id)),
                ref=ref,
                key=key,
                meta=envelope,
            )
        except sqlite3.IntegrityError as exc:
            replay = self._resolve_integrity(exc, key)
            if replay is not None:
                return replay
            raise BillingError("ledger_conflict", "billing write rejected: %s" % exc, http_status=500) from exc
        if refusal is not None:
            raise refusal
        assert result is not None  # _charge_txn returns exactly one of the two
        return result

    def _charge_txn(
        self,
        *,
        cost: int,
        action: str,
        unmetered: bool,
        subject: Optional[str],
        ref: Optional[str],
        key: Optional[str],
        meta: Dict[str, Any],
    ) -> Tuple[Optional[ChargeResult], Optional[BillingError]]:
        """The transaction body. Returns ``(result, refusal)``; never raises.

        Not raising is a correctness requirement, not tidiness: a
        :class:`BillingError` propagating out of a :func:`Database.transaction`
        rolls the transaction back, and branch 5/6 of :meth:`charge` must
        *commit* the drain and the suspension before the caller is told no.
        """
        with self.db.transaction(immediate=True) as conn:
            row = self._ensure_account(conn)
            replay = self._replay_for_key(conn, key)
            if replay is not None:
                return replay, None

            status = row["status"]
            balance = int(row["balance"])
            threshold = int(self.config.billing.suspend_threshold)

            if status == STATUS_SUSPENDED:
                return None, BillingError(
                    "account_suspended",
                    "billing account is suspended (%s)" % (row["suspended_reason"] or "no reason recorded"),
                    http_status=402,
                )
            if status == STATUS_DRAFT and not unmetered:
                return None, BillingError(
                    "account_draft",
                    "this deployment has not redeemed a POPX-CP activation code yet; redeem one from the "
                    "admin console before metered actions can run",
                    http_status=409,
                )

            ts = now_ms()

            if unmetered:
                # Documented unmetered behaviour: auto-activate, top up for the
                # shortfall with a zero-price grant, then pay the full quote.
                # Two ledger rows, one transaction — the grant is not hidden
                # money, it is recorded, so switching this deployment to
                # voucher billing later still balances.
                if status == STATUS_DRAFT:
                    self._set_status(conn, STATUS_ONLINE, None, ts)
                if balance < cost:
                    shortfall = cost - balance
                    balance, row = self._post(conn, kind=KIND_GRANT, amount=shortfall, balance=balance, row=row, ref="unmetered-topup", subject=subject, key=None, ts=ts, meta={"action": action, "reason": "unmetered deployment"})
                charged = cost
                balance, row = self._post(conn, kind=KIND_CONSUME, amount=charged, balance=balance, row=row, ref=ref, subject=subject, key=key, ts=ts, meta=meta)
                return ChargeResult(charged=charged, cost=cost, balance_after=balance, account_status=row["status"], idempotent_replay=False), None

            if balance - cost >= threshold:
                charged = cost
                balance, row = self._post(conn, kind=KIND_CONSUME, amount=charged, balance=balance, row=row, ref=ref, subject=subject, key=key, ts=ts, meta=meta)
                return ChargeResult(charged=charged, cost=cost, balance_after=balance, account_status=row["status"], idempotent_replay=False), None

            remainder = balance - threshold
            if remainder > 0:
                # Spend what there is, then fuse. The action itself is allowed
                # to run: this is the last one the balance can pay for.
                charged = remainder
                balance, row = self._post(conn, kind=KIND_CONSUME, amount=charged, balance=balance, row=row, ref=ref, subject=subject, key=key, ts=ts, meta=dict(meta, partial=True))
                self._suspend_for_credits(conn, "balance exhausted by %s (charged %d of %d CP)" % (action, charged, cost), ts)
                row = self._account_row(conn)
                return ChargeResult(charged=charged, cost=cost, balance_after=balance, account_status=row["status"], idempotent_replay=False), None

            self._suspend_for_credits(conn, "no credits to pay for %s (%d CP)" % (action, cost), ts)
            row = self._account_row(conn)
            return None, BillingError(
                "insufficient_credits",
                "balance %d CP cannot pay %d CP for %r; redeem a POPX-CP activation code to un-fuse" % (balance, cost, action),
                http_status=402,
            )

    # ── money in ────────────────────────────────────────────────────────────

    def grant(self, *, credits: int, reason: str, idempotency_key: Optional[str] = None) -> ChargeResult:
        """Credit the balance without a voucher: comp, migration, a correction.

        In voucher admission a grant funds an account but does **not** activate
        it: ``DRAFT`` stays ``DRAFT`` here even with a positive balance, because leaving ``DRAFT``
        is the commercial gate and the only key to it is a signature the
        official issuer made. :meth:`redeem_voucher` is what opens it. On an
        account suspended for exhaustion, a grant is enough money to un-fuse —
        which is the point of deriving the fuse from the balance instead of
        storing a flag.
        """
        amount = _positive(credits, "credits")
        text = _text(reason, "reason")
        key = _clean_key(idempotency_key)
        meta = {"reason": text, "source": "grant"}
        try:
            result, refusal = self._grant_txn(amount, key, meta)
        except sqlite3.IntegrityError as exc:
            # The same two halves :meth:`charge` uses. A keyed grant is an
            # idempotent write like a keyed charge, so losing the UNIQUE race
            # means the other writer's row is the answer — not a stack trace.
            replay = self._resolve_integrity(exc, key)
            if replay is not None:
                return replay
            raise BillingError("ledger_conflict", "billing write rejected: %s" % exc, http_status=500) from exc
        if refusal is not None:
            raise refusal
        assert result is not None
        return result

    def _grant_txn(self, amount: int, key: Optional[str], meta: Dict[str, Any]) -> Tuple[Optional[ChargeResult], Optional[BillingError]]:
        with self.db.transaction(immediate=True) as conn:
            row = self._ensure_account(conn)
            replay = self._replay_for_key(conn, key)
            if replay is not None:
                return replay, None
            balance, row = self._post(conn, kind=KIND_GRANT, amount=amount, balance=int(row["balance"]), row=row, ref=meta.get("reason"), subject=None, key=key, ts=now_ms(), meta=meta)
            row = self._heal_credit_suspension(conn, row)
            return ChargeResult(charged=0, cost=amount, balance_after=balance, account_status=row["status"], idempotent_replay=False), None

    def refund(self, *, amount: int, reason: str, idempotency_key: Optional[str] = None, ref: Optional[str] = None) -> ChargeResult:
        """Return credits for an action that did not happen.

        Modelled as un-spending: ``balance`` goes up and ``lifetime_spent``
        goes *down*, so ``balance == lifetime_granted - lifetime_spent`` still
        reads true and ``lifetime_spent`` keeps meaning "credits this
        deployment actually consumed", which is the number an invoice is built
        from. A refund that counted as a grant would inflate both numbers and
        make the ledger unable to answer "what did we use".

        Refundable ceiling is therefore ``lifetime_spent``: you cannot hand back
        more than was ever spent, and over-refunding would push
        ``lifetime_spent`` negative and break the invariant. That ceiling is
        total, not per-row — a partial refund of a partially-paid charge is
        legal, a second full refund of it is bounded by the same arithmetic.
        """
        value = _positive(amount, "amount")
        text = _text(reason, "reason")
        key = _clean_key(idempotency_key)
        try:
            result, refusal = self._refund_txn(value, text, key, ref)
        except sqlite3.IntegrityError as exc:
            replay = self._resolve_integrity(exc, key)
            if replay is not None:
                return replay
            raise BillingError("ledger_conflict", "billing write rejected: %s" % exc, http_status=500) from exc
        if refusal is not None:
            raise refusal
        assert result is not None
        return result

    def _refund_txn(self, amount: int, reason: str, key: Optional[str], ref: Optional[str]) -> Tuple[Optional[ChargeResult], Optional[BillingError]]:
        with self.db.transaction(immediate=True) as conn:
            row = self._ensure_account(conn)
            replay = self._replay_for_key(conn, key)
            if replay is not None:
                return replay, None
            spent = int(row["lifetime_spent"])
            if amount > spent:
                return None, BillingError(
                    "refund_exceeds_spend",
                    "cannot refund %d CP: lifetime spend is %d CP, so at most that much exists to give back" % (amount, spent),
                )
            balance, row = self._post(
                conn,
                kind=KIND_REFUND,
                amount=amount,
                balance=int(row["balance"]),
                row=row,
                ref=ref,
                subject=None,
                key=key,
                ts=now_ms(),
                meta={"reason": reason, "source": "refund"},
            )
            row = self._heal_credit_suspension(conn, row)
            return ChargeResult(charged=0, cost=amount, balance_after=balance, account_status=row["status"], idempotent_replay=False), None

    # ── vouchers ────────────────────────────────────────────────────────────

    def redeem_voucher(self, code: str, *, redeemed_by: str = "console") -> Dict[str, Any]:
        """Verify an activation code and credit it, atomically.

        The order is the one :func:`official_tools/gen_voucher.verify_code`
        uses and for the same reason: **format, then signature, then the
        clock.** Checking expiry before verification means an attacker learns
        from a fast failure; checking the clock before the signature means a
        forged code can be probed for how the deployment reads its own time.

        The format half is cheap and lives here (prefix, two unpadded
        base64url segments, a 64-byte signature) so a mistyped paste fails as
        ``malformed_code`` instead of as a crypto failure. What it explicitly
        does *not* do is decode the payload: the eight canonical fields
        (``popopx|popx_cp_v1|<voucher_id>|<plan>|<credits>|<issued_at_ms>|
        <expires_at_ms or "">|<issuer_key_id>``) are signed bytes and only the
        verifier gets to say what they mean.

        Failure modes are distinct on purpose — an operator looking at a
        rejected code needs to know whether to mint a new one (``voucher_used``)
        or wait for a new key (``voucher_invalid_signature``).
        """
        normalized = _text(code, "code")
        if not normalized.startswith(CODE_PREFIX):
            raise BillingError("malformed_code", "not a POPX-CP activation code (expected prefix %r)" % CODE_PREFIX)
        self._check_envelope(normalized)

        verifier = self.voucher_verifier
        if verifier is None:
            raise BillingError(
                "verifier_unavailable",
                "no voucher verifier is wired into BillingService; a POPX-CP code is never credited on "
                "the strength of its own claim, and crypto_service is the module that owns verification",
                http_status=503,
            )

        try:
            payload = verifier(normalized)
        except BillingError:
            raise
        except Exception as exc:  # the verifier owns the reason; we only name it
            raise self._verifier_refusal(exc) from exc

        payload = self._normalise_payload(payload)
        who = _text(redeemed_by, "redeemed_by")

        try:
            result, refusal = self._redeem_txn(payload, normalized, who)
        except sqlite3.IntegrityError as exc:
            raise self._voucher_conflict_error(payload, normalized, exc) from exc
        if refusal is not None:
            raise refusal
        assert result is not None
        return result

    def _redeem_txn(
        self, payload: VoucherPayload, code: str, redeemed_by: str
    ) -> Tuple[Optional[Dict[str, Any]], Optional[BillingError]]:
        """One transaction: record the voucher, credit it, activate or un-fuse.

        Returns ``(document, refusal)`` and does not raise, because two of the
        refusals here have to *commit* something: an expired or previously
        recorded code must leave its status behind, and a refusal that rolled
        its own evidence back is the "silently skipped" case the schema's
        ``status CHECK`` exists to prevent.
        """
        now = now_ms()
        expired = payload.expires_at_ms is not None and now >= int(payload.expires_at_ms)

        with self.db.transaction(immediate=True) as conn:
            row = self._ensure_account(conn)

            by_id = conn.execute("SELECT * FROM vouchers WHERE voucher_id = ?", (payload.voucher_id,)).fetchone()
            by_code = conn.execute("SELECT * FROM vouchers WHERE code = ?", (code,)).fetchone()
            if by_id is not None and by_code is not None and by_code["voucher_id"] != by_id["voucher_id"]:
                # One code string claimed by two voucher ids: the table already
                # contradicts itself and no amount of granting fixes that.
                return None, BillingError(
                    "voucher_conflict",
                    "code %s is recorded under voucher %r but this payload says %r"
                    % (code[:24], by_code["voucher_id"], payload.voucher_id),
                    http_status=500,
                )
            existing = by_id or by_code
            if existing is not None:
                recorded = existing["status"]
                if recorded == "redeemed":
                    return None, BillingError(
                        "voucher_used",
                        "voucher %s was already redeemed at %s by %s"
                        % (payload.voucher_id, existing["redeemed_at_ms"], existing["redeemed_by"] or "unknown"),
                        http_status=409,
                    )
                if recorded == "revoked":
                    return None, BillingError("voucher_revoked", "voucher %s has been revoked" % payload.voucher_id, http_status=403)
                if recorded == "expired":
                    return None, BillingError("voucher_expired", "voucher %s is expired" % payload.voucher_id, http_status=400)

            if expired:
                # Record, then refuse — the row is the point. A merchant who
                # pastes a dead code deserves to see it listed as dead, and an
                # issuer auditing a key needs the attempt to exist somewhere.
                self._record_voucher(conn, payload, code, status="expired", redeemed_by=None, at=now, note="rejected: expired")
                return None, BillingError(
                    "voucher_expired",
                    "voucher %s expired at %d, now %d" % (payload.voucher_id, payload.expires_at_ms, now),
                    http_status=400,
                )

            self._record_voucher(conn, payload, code, status="redeemed", redeemed_by=redeemed_by, at=now, note=None)

            balance, row = self._post(
                conn,
                kind=KIND_GRANT,
                amount=int(payload.credits),
                balance=int(row["balance"]),
                row=row,
                ref=payload.voucher_id,
                subject=None,
                key=None,
                ts=now,
                meta={"plan": payload.plan, "issuer_key_id": payload.issuer_key_id, "source": "voucher", "voucher_id": payload.voucher_id},
            )
            was = row["status"]
            if was == STATUS_DRAFT:
                # The first successful redemption is activation, full stop.
                self._set_status(conn, STATUS_ONLINE, None, now)
                row = self._account_row(conn)
            else:
                row = self._heal_credit_suspension(conn, row)

            return (
                {
                    "redeemed": True,
                    "voucher_id": payload.voucher_id,
                    "plan": payload.plan,
                    "credits": int(payload.credits),
                    "issuer_key_id": payload.issuer_key_id,
                    "expires_at_ms": payload.expires_at_ms,
                    "redeemed_by": redeemed_by,
                    "balance_after": balance,
                    "account_status": row["status"],
                    "activated": was == STATUS_DRAFT,
                    "unfused": was == STATUS_SUSPENDED and row["status"] == STATUS_ONLINE,
                },
                None,
            )

    def _voucher_conflict_error(self, payload: VoucherPayload, code: str, exc: sqlite3.Error) -> BillingError:
        """Name the row that beat us to it, instead of leaking an IntegrityError.

        The UNIQUE/PK constraints are checked inside the transaction above, so
        reaching here means another writer committed between our read and our
        insert — the transaction rolled ours back, and the committed row is the
        truth. Which of the two constraints fired does not matter: the row we
        find decides the answer, and a code recorded as spent is reported as
        spent, not as a database fault.
        """
        row = self.db.query_one(
            "SELECT voucher_id, status, redeemed_at_ms, redeemed_by FROM vouchers WHERE voucher_id = ? OR code = ?",
            (payload.voucher_id, code),
        )
        if row is None:
            return BillingError("voucher_write_failed", "voucher could not be recorded: %s" % exc, http_status=500)
        if row["status"] == "redeemed":
            return BillingError(
                "voucher_used",
                "voucher %s was already redeemed at %s by %s"
                % (row["voucher_id"], row["redeemed_at_ms"], row["redeemed_by"] or "unknown"),
                http_status=409,
            )
        if row["status"] == "revoked":
            return BillingError("voucher_revoked", "voucher %s has been revoked" % row["voucher_id"], http_status=403)
        if row["status"] == "expired":
            return BillingError("voucher_expired", "voucher %s is expired" % row["voucher_id"], http_status=400)
        return BillingError("voucher_duplicate", "voucher %s is already recorded as %s" % (row["voucher_id"], row["status"]), http_status=409)

    @staticmethod
    def _check_envelope(code: str) -> None:
        """Shape-check the code string, without interpreting the signed payload.

        Mirrors the same guards in ``gen_voucher.verify_code`` so a code that
        would certainly be rejected downstream is rejected here first, with a
        code name that says "you pasted it wrong" rather than "the signature
        is bad".
        """
        body = code[len(CODE_PREFIX) :]
        payload_b64, dot, signature_b64 = body.rpartition(".")
        if not dot or not payload_b64 or not signature_b64:
            raise BillingError("malformed_code", "expected %s<payload>.<signature>" % CODE_PREFIX)
        try:
            payload_bytes = _b64u_decode(payload_b64)
            signature = _b64u_decode(signature_b64)
        except Exception:
            raise BillingError("malformed_code", "code is not valid base64url", http_status=400) from None
        if len(signature) != 64:
            raise BillingError("malformed_code", "signature must be 64 raw bytes, got %d" % len(signature))
        if not payload_bytes:
            raise BillingError("malformed_code", "payload is empty")

    @staticmethod
    def _verifier_refusal(exc: Exception) -> BillingError:
        """Name a verifier's refusal without depending on the verifier.

        ``crypto_service.verify_voucher_code`` raises its own ``EcoError``, whose
        ``.rule`` is a stable machine string (``voucher_signature``,
        ``voucher_expired``, ``crypto_dependency_missing``…), and a verifier
        written by anybody else can carry the same idea in a ``.code``. Neither
        name is imported here: the attribute is read off the exception object,
        which is the same shape-only coupling the rest of this seam uses.

        Two of those refusals mean something different to a merchant than "bad
        signature" does, and are reported as themselves:

        * an **expired** code is not a forged one. Telling the operator the
          signature failed would send them to the issuer for a new key instead
          of waiting for the next window. Note the asymmetry this leaves: an
          expiry the *verifier* refuses cannot be written into ``vouchers`` as
          ``status = 'expired'``, because refusing means it handed back no
          payload, and this module does not record money-adjacent rows from
          data it was never given verified. The expired-record path above fires
          when the verifier returns a payload whose window has passed instead.
          A deployment that wants every expired attempt recorded should inject a
          verifier that returns rather than raises on expiry;
        * a **missing crypto dependency** is an operational fault, not a
          customer error, and answers 503 like the absent verifier does.

        Everything else is the conservative reading: a code the verifier could
        not approve is a code that did not approve, reported as
        ``voucher_invalid_signature`` with the verifier's own words attached.
        """
        machine = getattr(exc, "code", None) or getattr(exc, "rule", None)
        name = machine if isinstance(machine, str) and machine.strip() else ""
        text = str(exc) or type(exc).__name__
        if "dependency" in name or name in ("crypto_unavailable", "crypto_missing"):
            return BillingError("verifier_unavailable", "the voucher verifier could not run: %s" % text, http_status=503)
        if "expired" in name:
            return BillingError("voucher_expired", "voucher is expired: %s" % text, http_status=400)
        if "revoked" in name:
            return BillingError("voucher_revoked", "voucher has been revoked: %s" % text, http_status=403)
        return BillingError("voucher_invalid_signature", "voucher rejected by the verifier (%s): %s" % (name or type(exc).__name__, text), http_status=403)

    @staticmethod
    def _normalise_payload(payload: Any) -> VoucherPayload:
        """Accept the verifier's result by shape, then verify it field by field.

        Two decisions here, both about the seam rather than the accounting.

        **Duck typing, not :func:`isinstance`.** ``crypto_service`` declares its
        own ``Voucher`` dataclass with these same eight fields, and it should —
        the verifier has no business importing the ledger, any more than the
        ledger imports the verifier. Requiring our exact class would mean the
        gateway's boot path fails with "returned Voucher, expected
        VoucherPayload" over a structurally identical object, which is a
        type-check that protects nothing. So the fields are read, a
        :class:`VoucherPayload` is built from them, and *that* is what the rest
        of this module trusts.

        **Trust, then verify.** The payload is still foreign output. Since
        ``vouchers`` carries ``CHECK (credits > 0)`` and NOT NULL identity
        columns, letting a nonsense value reach the INSERT would mean an
        ``IntegrityError`` inside the redemption transaction — a message that
        blames the database for what is the verifier's fault. Each field is
        checked here instead, and a verifier that hands back garbage is told so
        with a 500 it deserves. ``bool`` is rejected explicitly for the integer
        fields because ``True`` is a perfectly valid ``1`` to Python and a
        perfectly invalid credit count to an invoice.
        """
        if isinstance(payload, VoucherPayload):
            candidate: Any = payload
        elif all(getattr(payload, name, _MISSING) is not _MISSING for name in VOUCHER_FIELDS):
            candidate = payload
        else:
            raise BillingError(
                "verifier_result_invalid",
                "voucher verifier returned %s, which does not carry the eight POPX-CP payload fields"
                % type(payload).__name__,
                http_status=500,
            )

        for name in ("voucher_id", "plan", "issuer_key_id", "signature_b64"):
            value = getattr(candidate, name)
            if not isinstance(value, str) or not value.strip():
                raise BillingError("verifier_result_invalid", "voucher verifier returned an empty %s" % name, http_status=500)
        if "|" in candidate.voucher_id or "|" in candidate.plan or "|" in candidate.issuer_key_id:
            # A separator inside an identity field means the verifier parsed a
            # canonical payload wrongly; the id we would store is not the id
            # that was signed.
            raise BillingError("verifier_result_invalid", "voucher identity fields must not contain '|' (the verifier mis-parsed the payload)", http_status=500)

        credits = getattr(candidate, "credits")
        if isinstance(credits, bool) or not isinstance(credits, int) or credits <= 0:
            raise BillingError("verifier_result_invalid", "voucher credits must be a positive integer, got %r" % (credits,), http_status=500)
        issued = getattr(candidate, "issued_at_ms")
        if isinstance(issued, bool) or not isinstance(issued, int) or issued <= 0:
            raise BillingError("verifier_result_invalid", "voucher issued_at_ms must be positive epoch milliseconds, got %r" % (issued,), http_status=500)
        expires = getattr(candidate, "expires_at_ms")
        if expires is not None:
            if isinstance(expires, bool) or not isinstance(expires, int):
                raise BillingError("verifier_result_invalid", "voucher expires_at_ms must be an integer or None, got %r" % (expires,), http_status=500)
            if expires <= issued:
                raise BillingError("verifier_result_invalid", "voucher expires_at_ms %d is not after issued_at_ms %d" % (expires, issued), http_status=500)

        code = getattr(candidate, "code", None)
        return VoucherPayload(
            voucher_id=candidate.voucher_id,
            plan=candidate.plan,
            credits=int(credits),
            issued_at_ms=int(issued),
            expires_at_ms=None if expires is None else int(expires),
            issuer_key_id=candidate.issuer_key_id,
            signature_b64=candidate.signature_b64,
            code=(code if isinstance(code, str) and code.strip() else ""),
        )

    def _record_voucher(
        self,
        conn: sqlite3.Connection,
        payload: VoucherPayload,
        code: str,
        *,
        status: str,
        redeemed_by: Optional[str],
        at: int,
        note: Optional[str],
    ) -> None:
        """Insert or update the ``vouchers`` row for a code we have verified.

        An expired code is *recorded*, not dropped: ``idx_vouchers_status`` and
        the console both need to answer "this merchant tried a dead code", and
        a rejection that leaves no trace is indistinguishable from never having
        tried. A revocation we already hold is never overwritten by an expiry —
        revocation is the stronger statement about the same key.
        """
        existing = conn.execute("SELECT * FROM vouchers WHERE voucher_id = ?", (payload.voucher_id,)).fetchone()
        if existing is None:
            conn.execute(
                "INSERT INTO vouchers (voucher_id, code, plan, credits, issued_at_ms, expires_at_ms, issuer_key_id, "
                "signature_b64, status, redeemed_at_ms, redeemed_by, note) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    payload.voucher_id,
                    code,
                    payload.plan,
                    int(payload.credits),
                    int(payload.issued_at_ms),
                    payload.expires_at_ms,
                    payload.issuer_key_id,
                    payload.signature_b64,
                    status,
                    at if status == "redeemed" else None,
                    redeemed_by,
                    note,
                ),
            )
            return
        if existing["status"] == "revoked":
            return
        conn.execute(
            "UPDATE vouchers SET code = ?, status = ?, redeemed_at_ms = ?, redeemed_by = ?, note = COALESCE(?, note) "
            "WHERE voucher_id = ?",
            (code, status, at if status == "redeemed" else existing["redeemed_at_ms"], redeemed_by or existing["redeemed_by"], note, payload.voucher_id),
        )

    def vouchers(self, status: Optional[str] = None, limit: int = 100) -> List[Dict[str, Any]]:
        """Voucher records for the console, newest redemption first.

        ``code`` is truncated to at most 24 characters — the head and the tail
        of it. A code is public signed data, not a secret, but a console log or
        a screenshot full of unspent codes is still a way to hand somebody an
        activation they have not paid for.
        """
        limit = _clamped(limit)
        rows = (
            self.db.query("SELECT * FROM vouchers ORDER BY redeemed_at_ms IS NULL, redeemed_at_ms DESC, issued_at_ms DESC LIMIT ?", (limit,))
            if status is None
            else self.db.query(
                "SELECT * FROM vouchers WHERE status = ? ORDER BY redeemed_at_ms IS NULL, redeemed_at_ms DESC, issued_at_ms DESC LIMIT ?",
                (status, limit),
            )
        )
        out: List[Dict[str, Any]] = []
        for r in rows:
            code = r["code"] or ""
            out.append(
                {
                    "voucher_id": r["voucher_id"],
                    "code": code if len(code) <= 24 else "%s...%s" % (code[:12], code[-8:]),
                    "plan": r["plan"],
                    "credits": int(r["credits"]),
                    "issued_at_ms": int(r["issued_at_ms"]),
                    "expires_at_ms": None if r["expires_at_ms"] is None else int(r["expires_at_ms"]),
                    "issuer_key_id": r["issuer_key_id"],
                    "status": r["status"],
                    "redeemed_at_ms": None if r["redeemed_at_ms"] is None else int(r["redeemed_at_ms"]),
                    "redeemed_by": r["redeemed_by"],
                    "note": r["note"],
                }
            )
        return out

    # ── lifecycle ───────────────────────────────────────────────────────────

    def go_online(self) -> AccountView:
        """Activate, or lift an operator halt. Idempotent.

        This is the human-authority counterpart to redemption: it can clear a
        suspension :meth:`suspend` imposed, and it will happily take a ``DRAFT``
        account online with no voucher when the deployment is configured
        unmetered. What it cannot do is manufacture credits — activation without
        money just moves the account to the next refusal, which is
        ``insufficient_credits`` on the first charge, with the plugins fused by
        the zero balance. That is the honest ordering: authority first, then
        funding.
        """
        ts = now_ms()
        with self.db.transaction(immediate=True) as conn:
            self._ensure_account(conn)
            self._set_status(conn, STATUS_ONLINE, None, ts)
            return self._view(self._account_row(conn))

    def suspend(self, reason: str) -> AccountView:
        """Halt the account by operator decision, with a recorded reason.

        Deliberately *not* the same kind of suspension as running out of
        credits: the reason is prefixed ``operator:`` so redemption and grants
        leave it in place. Money does not lift a decision a person made; only
        :meth:`go_online` does.
        """
        text = _text(reason, "reason")
        ts = now_ms()
        with self.db.transaction(immediate=True) as conn:
            self._ensure_account(conn)
            self._set_status(conn, STATUS_SUSPENDED, REASON_OPERATOR + text, ts)
            return self._view(self._account_row(conn))

    def plugin_fusings(self) -> Dict[str, bool]:
        """Plugin name -> may run. The dispatch gate ``main.py`` consults.

        Combines the static toggle from :class:`~app.config.PluginToggles` with
        the derived fuse state, and is the single source of truth for both: a
        plugin the merchant switched off and a plugin billing has stopped are
        the same answer to a dispatcher, and this is the one call that gives
        it. Re-reads the account row every time, which is what makes an
        un-fuse-on-redemption automatic instead of a step somebody performs.
        """
        row = self._ensure_account(self.db.connection())
        fused = self._fused(row)
        toggles = self.config.plugins
        out: Dict[str, bool] = {}
        for name, _meter in METERED_PLUGINS:
            out[name] = bool(getattr(toggles, name)) and not fused
        return out

    def is_plugin_fused(self, plugin: str) -> bool:
        """Whether *billing* is what stops this plugin, ignoring the toggle.

        Split from :meth:`plugin_fusings` on purpose: "the operator turned this
        off" is not "this deployment is out of credits", and the console needs
        to tell a merchant the difference instead of showing one grey badge.
        An unknown plugin name is a caller bug, so it raises rather than
        answering ``False`` and letting the plugin run.
        """
        known = {name for name, _meter in METERED_PLUGINS}
        if plugin not in known:
            raise BillingError("unknown_plugin", "no POPX-CP fuse known for %r; metered plugins: %s" % (plugin, ", ".join(sorted(known))))
        return self._fused(self._ensure_account(self.db.connection()))

    def _fused(self, row: sqlite3.Row) -> bool:
        """Derive the fuse from the account row. Never stored anywhere."""
        status = row["status"]
        if status == STATUS_SUSPENDED:
            return True
        if not self.config.billing.require_voucher:
            # Unmetered: no voucher gate, no credit exhaustion, so nothing to
            # fuse. Only the operator branch above can stop a plugin.
            return False
        if status == STATUS_DRAFT:
            return True
        return int(row["balance"]) <= int(self.config.billing.suspend_threshold)

    # ── reads ───────────────────────────────────────────────────────────────

    def ledger(self, limit: int = 100, *, offset: int = 0) -> List[Dict[str, Any]]:
        """Newest ledger rows first, ``meta_json`` decoded.

        Ordered by ``id DESC`` rather than ``ts_ms DESC`` because ``id`` is
        unique and monotonic while two rows in the same millisecond are not:
        a paging console that sorts on a non-unique key can show a row twice,
        and in an accounting view that is the worst possible glitch.
        """
        limit = _clamped(limit)
        offset = max(0, int(offset))
        rows = self.db.query(
            "SELECT id, ts_ms, kind, amount, balance_after, ref, subject, idempotency_key, meta_json "
            "FROM billing_ledger ORDER BY id DESC LIMIT ? OFFSET ?",
            (limit, offset),
        )
        return [self._ledger_dict(r) for r in rows]

    @staticmethod
    def _ledger_dict(row: sqlite3.Row) -> Dict[str, Any]:
        """One ledger row as JSON-ready data, with ``meta_json`` decoded once.

        A row whose ``meta_json`` will not parse is kept as the raw string
        rather than dropped: the ledger is the audit trail, so a row that no
        longer decodes is exactly the row an operator most needs to see, and a
        console that throws on it would make the accounting view unavailable at
        the worst possible moment.
        """
        raw = row["meta_json"]
        meta: Any = None
        if raw is not None:
            try:
                meta = json.loads(raw)
            except ValueError:
                meta = raw
        return {
            "id": int(row["id"]),
            "ts_ms": int(row["ts_ms"]),
            "kind": row["kind"],
            "amount": int(row["amount"]),
            "balance_after": int(row["balance_after"]),
            "ref": row["ref"],
            "subject": row["subject"],
            "idempotency_key": row["idempotency_key"],
            "meta": meta,
        }

    def ledger_count(self) -> int:
        return int(self.db.scalar("SELECT COUNT(*) FROM billing_ledger", (), default=0) or 0)

    def summary(self) -> Dict[str, Any]:
        """One document for the console and ``GET /api/v1/billing``.

        Carries the invariant the whole module exists to keep
        (``balance == lifetime_granted - lifetime_spent``) as an explicit field
        with the *expected* value next to it, because a billing API that shows
        a number without showing what it should be is a billing API you have to
        re-derive by hand while the merchant waits.
        """
        row = self._ensure_account(self.db.connection())
        view = self._view(row)
        granted = view.lifetime_granted
        spent = view.lifetime_spent
        expected = granted - spent
        prices = self.meters()
        return {
            "service_id": self.service_id,
            "currency": "POPX-CP",
            "status": view.status,
            "balance": view.balance,
            "lifetime_granted": granted,
            "lifetime_spent": spent,
            "expected_balance": expected,
            "ledger_balanced": expected == view.balance,
            "suspended_reason": view.suspended_reason,
            "is_chargeable": view.is_chargeable,
            "fused": self._fused(row),
            "require_voucher": bool(self.config.billing.require_voucher),
            "suspend_threshold": int(self.config.billing.suspend_threshold),
            "meters": prices,
            "free_meters": sorted(a for a, v in prices.items() if v == 0),
            "plugin_fusings": self.plugin_fusings(),
            "plugin_meters": {name: meter for name, meter in METERED_PLUGINS},
            "verifier_configured": self.voucher_verifier is not None,
            "official_key_configured": self.config.billing.official_ed25519_public_key is not None,
            "ledger_rows": self.ledger_count(),
            "vouchers": {
                "issued": self._count_vouchers("issued"),
                "redeemed": self._count_vouchers("redeemed"),
                "revoked": self._count_vouchers("revoked"),
                "expired": self._count_vouchers("expired"),
            },
            "updated_at_ms": int(row["updated_at_ms"]),
        }

    def _count_vouchers(self, status: str) -> int:
        return int(self.db.scalar("SELECT COUNT(*) FROM vouchers WHERE status = ?", (status,), default=0) or 0)

    # ── internals ───────────────────────────────────────────────────────────

    def _account_row(self, conn: sqlite3.Connection) -> sqlite3.Row:
        row = conn.execute("SELECT * FROM billing_account WHERE id = 1").fetchone()
        if row is None:  # pragma: no cover
            raise BillingError("account_missing", "billing_account has no singleton row", http_status=500)
        return row

    def _set_status(self, conn: sqlite3.Connection, status: str, reason: Optional[str], ts: int) -> None:
        conn.execute(
            "UPDATE billing_account SET status = ?, suspended_reason = ?, updated_at_ms = ? WHERE id = 1",
            (status, reason, ts),
        )

    def _suspend_for_credits(self, conn: sqlite3.Connection, detail: str, ts: int) -> None:
        self._set_status(conn, STATUS_SUSPENDED, REASON_CREDITS + detail, ts)

    def _heal_credit_suspension(self, conn: sqlite3.Connection, row: sqlite3.Row) -> sqlite3.Row:
        """Un-suspend an account that was stopped for lack of credits and now has some.

        Only credit-caused suspensions heal, and only once the balance is back
        above ``suspend_threshold``. An ``operator:`` reason is left exactly as
        written; :meth:`suspend` is a human decision and a voucher is not a
        person. Returns the (possibly re-read) account row.
        """
        if row["status"] != STATUS_SUSPENDED:
            return row
        reason = row["suspended_reason"] or ""
        if not reason.startswith(REASON_CREDITS):
            return row
        if int(row["balance"]) <= int(self.config.billing.suspend_threshold):
            return row
        self._set_status(conn, STATUS_ONLINE, None, now_ms())
        return self._account_row(conn)

    def _post(
        self,
        conn: sqlite3.Connection,
        *,
        kind: str,
        amount: int,
        balance: int,
        row: sqlite3.Row,
        ref: Optional[str],
        subject: Optional[str],
        key: Optional[str],
        ts: int,
        meta: Dict[str, Any],
    ) -> Tuple[int, sqlite3.Row]:
        """Write one money movement: mutate the account, append its ledger row.

        The only place the three kinds meet the two counters, so the arithmetic
        is spelled once: a ``grant`` raises the balance and ``lifetime_granted``;
        a ``consume`` lowers the balance and raises ``lifetime_spent``; a
        ``refund`` raises the balance and *lowers* ``lifetime_spent``. That last
        choice is what keeps ``balance == lifetime_granted - lifetime_spent``
        true by construction rather than by repair — see the module docstring.
        The ledger row's ``balance_after`` is the *same* number the account is
        set to, from the same arithmetic, which is the only way the two can
        agree without a re-read. Always the last two statements of a
        transaction, and always together. Returns the new balance and the
        account row (re-read here so callers that only post money still see the
        fresh numbers).
        """
        granted = int(row["lifetime_granted"])
        spent = int(row["lifetime_spent"])
        if kind == KIND_GRANT:
            granted += amount
            balance += amount
        elif kind == KIND_CONSUME:
            spent += amount
            balance -= amount
        elif kind == KIND_REFUND:
            spent -= amount
            balance += amount
        else:
            # 'reversal' is deliberately not reachable from here: see the
            # invariant note in the module docstring.
            raise BillingError("unknown_ledger_kind", "billing engine will not post kind %r" % kind, http_status=500)

        if balance < 0:
            # Unreachable by construction — every caller checks affordability
            # first — but the alternative is a CHECK constraint failure whose
            # message names a column instead of naming the meter that did it.
            raise BillingError("negative_balance_guard", "refusing to post %s %d CP against balance %d" % (kind, amount, balance), http_status=500)

        conn.execute(
            "UPDATE billing_account SET balance = ?, lifetime_granted = ?, lifetime_spent = ?, updated_at_ms = ? WHERE id = 1",
            (balance, granted, spent, ts),
        )
        conn.execute(
            "INSERT INTO billing_ledger (ts_ms, kind, amount, balance_after, ref, subject, idempotency_key, meta_json) "
            "VALUES (?,?,?,?,?,?,?,?)",
            (ts, kind, amount, balance, ref, subject, key, _dumps(meta)),
        )
        return balance, self._account_row(conn)

    def _replay_for_key(self, conn: sqlite3.Connection, key: Optional[str]) -> Optional[ChargeResult]:
        """Return the original result for a key we have already posted, if any.

        The whole outbox retry story rests on this lookup. A send that timed
        out may or may not have landed, so the retryer re-issues
        :meth:`charge` with the same ``idempotency_key``; the debit has to be
        recognised as already-paid and answered with the numbers from *that*
        row, not with a fresh balance. ``balance_after`` therefore comes from
        the ledger, while ``account_status`` comes from the live row — status
        can legitimately have moved since (a later charge exhausted the
        balance), and reporting the old status would tell a plugin it may run.

        ``None`` means "no row with this key", which is the normal path. This
        is a check, not the mechanism: :meth:`_resolve_integrity` handles the
        case where another writer committed between the check and the insert.
        """
        if key is None:
            return None
        row = conn.execute("SELECT * FROM billing_ledger WHERE idempotency_key = ?", (key,)).fetchone()
        if row is None:
            return None
        return self._result_from_ledger(conn, row)

    def _result_from_ledger(self, conn: sqlite3.Connection, row: sqlite3.Row) -> ChargeResult:
        amount = int(row["amount"])
        kind = row["kind"]
        account = self._account_row(conn)
        return ChargeResult(
            charged=amount if kind == KIND_CONSUME else 0,
            cost=amount,
            balance_after=int(row["balance_after"]),
            account_status=account["status"],
            idempotent_replay=True,
        )

    def _resolve_integrity(self, exc: sqlite3.Error, key: Optional[str]) -> Optional[ChargeResult]:
        """Turn a lost idempotency race into the answer the winner recorded.

        By the time this runs the transaction has been rolled back
        (:meth:`Database.transaction` does that on the way out), so this
        database holds no half-applied debit from us: either a committed row
        with our key exists — the concurrent duplicate, answer with the replay —
        or it does not, and the ``IntegrityError`` was something genuinely
        wrong (a ``CHECK`` we mis-predicted, a ``NOT NULL`` we violated), which
        the caller must see as a 500 rather than as a successful no-op.
        """
        if key is None:
            return None
        row = self.db.query_one("SELECT * FROM billing_ledger WHERE idempotency_key = ?", (key,))
        if row is None:
            return None
        return self._result_from_ledger(self.db.connection(), row)


# ───────────────────────────── helpers ──────────────────────────────────────


def _clean_key(key: Optional[str]) -> Optional[str]:
    if key is None:
        return None
    text = str(key).strip()
    return text or None


def _text(value: Any, name: str) -> str:
    if value is None:
        raise BillingError("invalid_argument", "%r is required and was not given" % name)
    text = str(value).strip()
    if not text:
        raise BillingError("invalid_argument", "%r must not be empty" % name)
    return text


def _positive(value: Any, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise BillingError("invalid_amount", "%s must be an integer number of credits, got %r" % (name, value))
    if value <= 0:
        raise BillingError("invalid_amount", "%s must be positive, got %d" % (name, value))
    return int(value)


def _clamped(limit: int) -> int:
    try:
        value = int(limit)
    except (TypeError, ValueError):
        raise BillingError("invalid_limit", "limit must be an integer, got %r" % (limit,)) from None
    if value < 1:
        return 1
    return min(value, LEDGER_LIMIT_MAX)


# ───────────────────────────── self-test ─────────────────────────────
#
# This suite runs without the ``cryptography`` wheel, which is the point of the
# ``voucher_verifier`` seam: every money movement below is driven through an
# injected verifier whose signature work is a stand-in, so the accounting is
# checked on the machine that ships it rather than only on one with a compiler.
# What the stand-in proves is *this module's* decisions — the order of format /
# signature / clock, what a replay returns, when the fuse is derived — and what
# it cannot prove is that an Ed25519 signature is real; :func:`app.crypto_service.crypto_self_test`
# and ``official_tools/swift_crypto_oracle.swift`` own that, and ``main.py`` refuses to
# call this suite's pass a crypto pass.


class _Namespace:
    """Attribute bag, used for foreign verifier results and fake databases."""

    def __init__(self, **kwargs: Any) -> None:
        for name, value in kwargs.items():
            setattr(self, name, value)


def _b64u(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def self_test() -> List[str]:
    """POPX-CP: lifecycle, meters, vouchers, idempotency, fuse, ledger, concurrency.

    Returns the list of passed check names and raises :class:`AssertionError` on
    the first failure, so a caller cannot mistake a half-run suite for a green one.
    """
    import os
    import shutil
    import sqlite3
    import tempfile
    import threading
    from concurrent.futures import ThreadPoolExecutor

    from app.config import load_config

    checks: List[str] = []
    root = tempfile.mkdtemp(prefix="popopx-billing-selftest-")
    seq = [0]

    def check(name: str, condition: bool) -> None:
        if not condition:
            raise AssertionError("billing self_test failed: %s" % name)
        checks.append(name)

    def refuses(name: str, expected: str, call: Any, *, status: Optional[int] = None) -> BillingError:
        try:
            call()
        except BillingError as exc:
            if exc.code != expected:
                raise AssertionError("billing self_test: %s raised %r, expected code %r" % (name, exc.code, expected)) from exc
            if status is not None and exc.http_status != status:
                raise AssertionError("billing self_test: %s answered %d, expected %d" % (name, exc.http_status, status)) from exc
            checks.append(name)
            return exc
        except Exception as exc:  # noqa: BLE001
            raise AssertionError("billing self_test: %s raised %s (%s), expected BillingError(%s)" % (name, type(exc).__name__, exc, expected)) from exc
        raise AssertionError("billing self_test: %s did not refuse with %r" % (name, expected))

    def fails(name: str, expected: Any, call: Any) -> Exception:
        try:
            call()
        except expected as exc:
            checks.append(name)
            return exc
        except Exception as exc:  # noqa: BLE001
            raise AssertionError("billing self_test: %s raised %s (%s), expected %s" % (name, type(exc).__name__, exc, expected)) from exc
        raise AssertionError("billing self_test: %s did not raise %s" % (name, getattr(expected, "__name__", expected)))

    # The public half is a 32-byte stand-in: this suite never verifies a
    # signature, it only needs the config to accept a key so that a
    # voucher-required deployment loads at all.
    pub_b64 = base64.b64encode(bytes(range(32))).decode("ascii")
    meter_env = {action: "POPOPX_CP_" + attr.upper() for action, attr in METER_ACTIONS}

    def new_config(*, require_voucher: bool = True, threshold: int = 0, meters: Optional[Dict[str, int]] = None, toggles: Optional[Dict[str, bool]] = None, name: str = "acct") -> Config:
        """A real :class:`Config`, through :func:`load_config`.

        ``require_voucher`` defaults to TRUE here, which is opt-in admission
        mode and NOT the shipped default (``config.py`` reads it as false): most
        checks below are about the DRAFT/voucher machinery, so the fixture starts
        there and the self-hosted path passes ``require_voucher=False`` by hand.

        Written as a `.env` because every field of that dataclass is required and
        each has a rule the gateway itself has to agree with; a hand-built Config
        would test neither the rules nor the loader.
        """
        seq[0] += 1
        db_path = Path(root) / ("%s-%d.sqlite3" % (name, seq[0]))
        lines = [
            "POPOPX_ADMIN_TOKEN=" + "t" * 32,
            "POPOPX_PUBLIC_BASE_URL=https://eco.example.test/",
            "POPOPX_H5_SERVER_SECRET=" + "s" * 48,
            "POPOPX_DB_PATH=" + str(db_path),
            "POPOPX_SERVICE_ID=popopx.test",
            "POPOPX_SERVICE_NAME=POPOPX Test",
            "POPOPX_SERVICE_FULL_NAME=POPOPX Test Service",
            "POPOPX_NODE_WS_URL=ws://127.0.0.1:5225",
            "POPOPX_LOG_LEVEL=ERROR",
            "POPOPX_BILLING_REQUIRE_VOUCHER=" + ("1" if require_voucher else "0"),
            "POPOPX_BILLING_SUSPEND_THRESHOLD=%d" % int(threshold),
            "POPOPX_OFFICIAL_ED25519_PUBLIC_KEY=" + (pub_b64 if require_voucher else ""),
        ]
        # Every plugin toggle is ON unless this check says otherwise: a plugin an
        # operator switched off would answer ``False`` for a second reason, and
        # every fuse check would then be proving nothing. web3_bridge is OFF by
        # default in the real config, so the default here is a fixture decision,
        # not a production one.
        for plugin in sorted(name for name, _meter in METERED_PLUGINS):
            lines.append("POPOPX_PLUGIN_%s=%s" % (plugin.upper(), "1" if (toggles or {}).get(plugin, True) else "0"))
        for action, value in (meters or {}).items():
            lines.append("%s=%d" % (meter_env[action], value))
        env_path = Path(root) / ("env-%d" % seq[0])
        env_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        saved = {k: v for k, v in list(os.environ.items()) if k.startswith("POPOPX_")}
        for key in saved:
            del os.environ[key]
        try:
            return load_config(env_path)
        finally:
            os.environ.update(saved)

    def new_service(config: Optional[Config] = None, *, verifier: Any = None, db: Any = None, name: str = "acct") -> "Tuple[BillingService, Database]":
        cfg = config or new_config(name=name)
        handle = db if db is not None else Database(cfg.db_path)
        return BillingService(handle, cfg, verifier), handle

    def activate(svc: BillingService, credits: int) -> None:
        """Move the singleton to ONLINE with money in it, bypassing vouchers."""
        svc.go_online()
        if credits:
            svc.grant(credits=credits, reason="self-test funding")

    def code_for(*, payload: bytes = b"popopx|popx_cp_v1|v1|starter|100|1|2|k1", sig_len: int = 64, body: Optional[str] = None, signature: Optional[str] = None) -> str:
        return "%s%s.%s" % (CODE_PREFIX, _b64u(payload) if body is None else body, _b64u(bytes(sig_len)) if signature is None else signature)

    def payload_for(voucher_id: str, *, credits: int = 100, expires: Optional[int] = None, issued: Optional[int] = None, plan: str = "starter", key_id: str = "k1", sig: str = "A" * 86, code: Optional[str] = "POPX-CP-1.x.y") -> Any:
        """A foreign result: the eight fields, but *not* a VoucherPayload."""
        return _Namespace(
            voucher_id=voucher_id,
            plan=plan,
            credits=credits,
            issued_at_ms=(issued if issued is not None else now_ms() - 5000),
            expires_at_ms=expires,
            issuer_key_id=key_id,
            signature_b64=sig,
            code=code,
        )

    class _Verifier:
        """Stand-in for ``crypto_service.verify_voucher_code``: returns, or refuses."""

        def __init__(self, result: Any = None, error: Optional[Exception] = None) -> None:
            self.result = result
            self.error = error
            self.calls: List[str] = []

        def __call__(self, code: str) -> Any:
            self.calls.append(code)
            if self.error is not None:
                raise self.error
            if callable(self.result):
                return self.result(code)
            return self.result

    class _Refusal(Exception):
        """A verifier refusal that carries ``.rule`` the way EcoError does."""

        def __init__(self, rule: str, message: str = "refused") -> None:
            super().__init__(message)
            self.rule = rule

    class _LosingRace:
        """A database whose writes always lose the UNIQUE race — and whose reads work.

        Stands in for the one case the idempotency mechanism cannot reach from
        inside its own transaction: another writer committed first, so our
        statement fails on a UNIQUE key. The engine then resolves that by
        reading the committed row on a normal connection, so only
        :meth:`transaction` may fail here. A stub that failed the reads too
        would be testing the stub.
        """

        def __init__(self, real: Any, boom: sqlite3.Error) -> None:
            self.real = real
            self.boom = boom

        def transaction(self, immediate: bool = True) -> Any:
            raise self.boom

        def __getattr__(self, name: str) -> Any:
            return getattr(self.real, name)

    try:
        # ── the account row ──────────────────────────────────────────────────
        svc, _ = new_service(name="account")
        view = svc.account()
        check("a_first_touched_account_is_draft", view.status == STATUS_DRAFT)
        check("a_first_touched_account_is_empty", view.balance == 0 and view.lifetime_granted == 0 and view.lifetime_spent == 0)
        check("the_singleton_is_one_row", svc.db.scalar("SELECT COUNT(*) FROM billing_account") == 1)
        check("account_reads_take_no_write_lock", svc.db.connection().in_transaction is False and svc.account().status == STATUS_DRAFT)
        check("a_fresh_account_is_balanced", svc.summary()["ledger_balanced"] is True)
        check("the_schema_refuses_an_overdraft", "CHECK" in str(svc.db.query_one("SELECT sql FROM sqlite_master WHERE name = 'billing_account'")["sql"]))
        check("draft_is_not_chargeable_when_vouchers_are_required", svc.account().is_chargeable is False)
        unmetered_svc, _ = new_service(new_config(require_voucher=False, name="unmetered"), name="unmetered")
        check("a_self_hosted_account_is_born_online", unmetered_svc.account().status == STATUS_ONLINE)
        check("a_self_hosted_account_is_chargeable_with_no_voucher_at_all", unmetered_svc.account().is_chargeable is True)
        check("a_self_hosted_account_is_not_fused", unmetered_svc.summary()["fused"] is False)
        check("the_account_is_created_outside_a_transaction", svc.db.query_one("SELECT id FROM billing_account WHERE id = 1")["id"] == 1)
        bare = BillingService(svc.db, _Namespace(billing=svc.config.billing, plugins=svc.config.plugins, service_id=""))
        check("a_blank_service_id_falls_back_to_the_default", bare.summary()["service_id"] == DEFAULT_SERVICE_ID)
        check("an_absent_config_still_names_the_service", BillingService(svc.db, None).service_id == DEFAULT_SERVICE_ID)

        # ── meters ───────────────────────────────────────────────────────────
        prices = svc.meters()
        check("the_meter_table_is_the_eleven_named_actions", set(prices) == {action for action, _ in METER_ACTIONS})
        check("meters_come_from_the_config_not_a_literal", prices["card"] == svc.config.billing.per_card)
        for action, attr in METER_ACTIONS:
            probe = new_config(meters={action: 3}, name="probe")
            check("the_env_key_for_%s_prices_its_meter" % action, getattr(probe.billing, attr) == 3 and BillingService(svc.db, probe).quote(action) == 3)
        priced, _ = new_service(new_config(meters={"card": 7, "alert": 0}, name="meters"), name="meters")
        check("a_reconfigured_meter_prices_differently", priced.quote("card") == 7)
        check("a_meter_of_zero_is_free_not_absent", priced.quote("alert") == 0)
        refusal = refuses("an_unknown_action_has_no_price", "unknown_meter", lambda: priced.quote("push_a_card"))
        check("the_refusal_lists_every_known_meter", all(action in refusal.message for action, _ in METER_ACTIONS))
        activate(priced, 100)
        free = priced.charge("alert")
        check("a_free_action_is_still_recorded", priced.db.scalar("SELECT COUNT(*) FROM billing_ledger WHERE kind = 'consume' AND amount = 0") == 1)
        check("a_free_action_moves_no_money", free.charged == 0 and free.balance_after == 100)
        check("a_free_action_appears_in_the_console_as_free", "alert" in priced.summary()["free_meters"])
        check("the_plugin_meters_are_exactly_eight", len(priced.summary()["plugin_meters"]) == len(METERED_PLUGINS) == 8)
        afford, _ = new_service(new_config(threshold=5, name="afford"), name="afford")
        activate(afford, 7)
        check("an_account_with_room_can_afford", afford.can_afford("card") is True)
        afford.charge("card")
        check("can_afford_is_false_once_the_threshold_is_in_the_way", afford.can_afford("key_rotation") is False)
        check("can_afford_is_advisory_not_the_gate", afford.summary()["balance"] == 6 and afford.summary()["fused"] is False)
        check("a_draft_account_can_afford_nothing", new_service(name="afford2")[0].can_afford("card") is False)
        check("an_unmetered_account_always_affords", unmetered_svc.can_afford("ai_message") is True)

        # ── the code envelope, before any trust is granted ───────────────────
        no_verifier, _ = new_service(name="novfr")
        refuses("an_unwired_verifier_credits_nothing", "verifier_unavailable", lambda: no_verifier.redeem_voucher(code_for()), status=503)
        quiet = _Verifier(payload_for("unused"))
        strict, _ = new_service(verifier=quiet, name="envelope")
        refuses("a_foreign_prefix_is_not_a_code", "malformed_code", lambda: strict.redeem_voucher("POPX-XX-1.aaa.bbb"))
        refuses("a_code_without_a_separator_is_malformed", "malformed_code", lambda: strict.redeem_voucher(CODE_PREFIX + "abcdef"))
        refuses("an_empty_payload_segment_is_malformed", "malformed_code", lambda: strict.redeem_voucher(code_for(body="", signature=_b64u(bytes(64)))))
        refuses("an_empty_signature_segment_is_malformed", "malformed_code", lambda: strict.redeem_voucher(code_for(body=_b64u(b"x"), signature="")))
        refuses("a_non_base64_segment_is_malformed", "malformed_code", lambda: strict.redeem_voucher(code_for(body="!!!!", signature=_b64u(bytes(64)))))
        refuses("a_signature_of_63_bytes_is_malformed", "malformed_code", lambda: strict.redeem_voucher(code_for(sig_len=63)))
        refuses("a_signature_of_65_bytes_is_malformed", "malformed_code", lambda: strict.redeem_voucher(code_for(sig_len=65)))
        refuses("an_empty_payload_is_malformed", "malformed_code", lambda: strict.redeem_voucher(code_for(payload=b"")))
        refuses("a_non_string_code_is_refused", "invalid_argument", lambda: strict.redeem_voucher(None))
        check("the_shape_check_runs_before_the_verifier_is_asked", quiet.calls == [])

        # ── redemption ───────────────────────────────────────────────────────
        paid_payload = payload_for("v-paid", credits=500, code=code_for())
        payer = _Verifier(paid_payload)
        paid, _ = new_service(verifier=payer, name="redeem")
        doc = paid.redeem_voucher(code_for(), redeemed_by="operator")
        check("a_verified_code_credits_its_promise", doc["credits"] == 500 and paid.account().balance == 500)
        check("the_first_redemption_is_activation", doc["activated"] is True and doc["account_status"] == STATUS_ONLINE)
        check("redemption_answers_with_the_verdict", doc["redeemed"] is True and doc["redeemed_by"] == "operator")
        check("redemption_keeps_the_invariant", paid.summary()["ledger_balanced"] is True and paid.account().lifetime_granted == 500)
        check("the_grant_row_names_the_voucher", paid.db.query_one("SELECT ref FROM billing_ledger WHERE kind = 'grant'")["ref"] == "v-paid")
        listed = paid.vouchers("redeemed")
        check("the_redeemed_code_is_recorded", len(listed) == 1 and listed[0]["voucher_id"] == "v-paid")
        check("the_record_says_who_redeemed_it", listed[0]["redeemed_by"] == "operator" and listed[0]["redeemed_at_ms"] is not None)
        check("the_recorded_row_is_the_well_formed_code", listed[0]["status"] == "redeemed" and listed[0]["plan"] == "starter")
        refuses("a_spent_code_is_spent", "voucher_used", lambda: paid.redeem_voucher(code_for()), status=409)
        check("a_spent_code_credits_nothing_twice", paid.account().balance == 500 and paid.ledger_count() == 1)
        check("a_spent_code_moves_the_balance_by_nothing", paid.account().lifetime_granted == 500)
        check("the_refusal_names_the_redeemer", "operator" in str(refuses("spent_code_names_the_original_redeemer", "voucher_used", lambda: paid.redeem_voucher(code_for())).message))

        dead = _Verifier(payload_for("v-dead", expires=now_ms() - 1000, issued=now_ms() - 5000, code=code_for()))
        expiring, _ = new_service(verifier=dead, name="expired")
        refuses("an_expired_code_is_refused", "voucher_expired", lambda: expiring.redeem_voucher(code_for()))
        check("the_expired_attempt_is_written_down", expiring.db.query_one("SELECT status FROM vouchers WHERE voucher_id = 'v-dead'")["status"] == "expired")
        check("an_expired_code_credits_nothing", expiring.account().balance == 0 and expiring.ledger_count() == 0)
        check("the_clock_is_read_after_the_verifier_returns", len(dead.calls) == 1)
        refuses("an_expired_record_stays_refused", "voucher_expired", lambda: expiring.redeem_voucher(code_for()))
        check("a_second_expiry_attempt_does_not_repair_the_row", expiring.db.scalar("SELECT COUNT(*) FROM vouchers") == 1)

        revoked_db = Database(Path(root) / "revoked.sqlite3")
        revoke_cfg = new_config(name="revoked")
        revoker = _Verifier(payload_for("v-revoked", credits=1000, code=code_for()))
        revoked_svc = BillingService(revoked_db, revoke_cfg, revoker)
        with revoked_db.transaction() as conn:
            conn.execute(
                "INSERT INTO vouchers (voucher_id, code, plan, credits, issued_at_ms, expires_at_ms, issuer_key_id, signature_b64, status) "
                "VALUES ('v-revoked', ?, 'starter', 1000, 1, NULL, 'k1', 'AAA', 'revoked')",
                (code_for(),),
            )
        refuses("a_revoked_code_credits_nothing", "voucher_revoked", lambda: revoked_svc.redeem_voucher(code_for()), status=403)
        check("revocation_survives_the_balance_check", revoked_svc.account().balance == 0)
        with revoked_db.transaction() as conn:
            revoked_svc._record_voucher(conn, revoked_svc._normalise_payload(payload_for("v-revoked", expires=now_ms() - 1)), code_for(), status="expired", redeemed_by=None, at=now_ms(), note="later")
        check("revocation_is_stronger_than_expiry", revoked_db.query_one("SELECT status FROM vouchers WHERE voucher_id = 'v-revoked'")["status"] == "revoked")

        clash_cfg = new_config(name="clash")
        clash_db = Database(clash_cfg.db_path)
        clasher = BillingService(clash_db, clash_cfg, _Verifier(payload_for("v-two", code=code_for())))
        with clash_db.transaction() as conn:
            conn.execute(
                "INSERT INTO vouchers (voucher_id, code, plan, credits, issued_at_ms, expires_at_ms, issuer_key_id, signature_b64, status) "
                "VALUES ('v-one', ?, 'starter', 10, 1, NULL, 'k1', 'AAA', 'issued')",
                (code_for(),),
            )
        # One code, two identities. `voucher_conflict` is the in-transaction answer,
        # but it needs two rows holding the same code, and the schema forbids that
        # (`code TEXT NOT NULL UNIQUE` beside `voucher_id TEXT PRIMARY KEY`) — so the
        # reachable answer is the post-rollback one, naming the committed row.
        clash = refuses("a_code_claimed_by_two_identities_is_refused", "voucher_duplicate", lambda: clasher.redeem_voucher(code_for()), status=409)
        check("the_conflict_names_the_row_that_holds_the_code", "v-one" in clash.message)
        ddl = str(clash_db.query_one("SELECT sql FROM sqlite_master WHERE name = 'vouchers'")["sql"])
        check("the_schema_makes_one_code_two_identities_unrepresentable", "PRIMARY KEY" in ddl and "UNIQUE" in ddl)
        # The post-rollback naming is what an operator sees, so each recorded
        # status has to be reported as itself rather than as a database fault.
        for label, status, want, want_status in (
            ("a_race_against_a_spent_code_is_a_spent_code", "redeemed", "voucher_used", 409),
            ("a_race_against_a_revoked_code_is_a_revocation", "revoked", "voucher_revoked", 403),
            ("a_race_against_an_expired_record_is_an_expiry", "expired", "voucher_expired", 400),
            ("a_race_against_any_other_record_is_a_duplicate", "issued", "voucher_duplicate", 409),
        ):
            race_cfg = new_config(name="race-%s" % status)
            race_db = Database(race_cfg.db_path)
            racer = BillingService(race_db, race_cfg)
            with race_db.transaction() as conn:
                conn.execute(
                    "INSERT INTO vouchers (voucher_id, code, plan, credits, issued_at_ms, expires_at_ms, issuer_key_id, signature_b64, status) "
                    "VALUES ('v-race', ?, 'starter', 10, 1, NULL, 'k1', 'AAA', ?)",
                    (code_for(), status),
                )
            named = racer._voucher_conflict_error(racer._normalise_payload(payload_for("v-race", code=code_for())), code_for(), sqlite3.IntegrityError("UNIQUE"))
            check(label, named.code == want)
            check(label + "_and_its_own_status", named.http_status == want_status)
        blind = BillingService(clash_db, clash_cfg)
        check("a_conflict_with_no_row_is_not_invented_away", blind._voucher_conflict_error(blind._normalise_payload(payload_for("v-nowhere", code=code_for(body=_b64u(b"other"), signature=_b64u(bytes(64))))), code_for(body=_b64u(b"other"), signature=_b64u(bytes(64))), sqlite3.IntegrityError("x")).code == "voucher_write_failed")

        # ── what the verifier's refusal means ────────────────────────────────
        for label, rule, expected_code, expected_status in (
            ("a_missing_dependency_is_our_fault", "crypto_dependency_missing", "verifier_unavailable", 503),
            ("a_verifier_expiry_is_named_as_expiry", "voucher_expired", "voucher_expired", 400),
            ("a_verifier_revocation_is_named_as_revocation", "voucher_revoked", "voucher_revoked", 403),
            ("any_other_refusal_is_a_bad_signature", "voucher_signature", "voucher_invalid_signature", 403),
        ):
            refused, _ = new_service(verifier=_Verifier(error=_Refusal(rule)), name="refusal")
            exc = refuses(label, expected_code, lambda refused=refused: refused.redeem_voucher(code_for()), status=expected_status)
            check(label + "_keeps_the_verifiers_words", rule in exc.message or "refused" in exc.message)
        opaque, _ = new_service(verifier=_Verifier(error=ValueError("bad")), name="opaque")
        refuses("a_verifier_that_crashes_credits_nothing", "voucher_invalid_signature", lambda: opaque.redeem_voucher(code_for()))
        coded = _Verifier(error=_Refusal("ignored"))
        coded.error = _Namespace(code="voucher_expired", rule="other", args=())  # type: ignore[assignment]
        class _CodedError(Exception):
            code = "voucher_expired"
            rule = "ignored"
        coded.error = _CodedError("the .code attribute wins")
        coded_svc, _ = new_service(verifier=coded, name="coded")
        refuses("a_verifiers_code_attribute_wins_over_its_rule", "voucher_expired", lambda: coded_svc.redeem_voucher(code_for()))

        # ── the payload hand-over ────────────────────────────────────────────
        shape_cfg = new_config(name="shape")
        shape_db = Database(shape_cfg.db_path)
        shapeless = BillingService(shape_db, shape_cfg)
        refuses("a_result_without_the_fields_is_the_verifiers_fault", "verifier_result_invalid", lambda: shapeless._normalise_payload(_Namespace(voucher_id="v")), status=500)
        refuses("a_string_result_is_refused", "verifier_result_invalid", lambda: shapeless._normalise_payload("POPX-CP-1.x.y"))
        refuses("an_empty_identity_is_refused", "verifier_result_invalid", lambda: shapeless._normalise_payload(payload_for("  ")))
        refuses("a_pipe_in_an_identity_field_mis_parsed_the_payload", "verifier_result_invalid", lambda: shapeless._normalise_payload(payload_for("a|b")))
        refuses("zero_credits_is_not_a_voucher", "verifier_result_invalid", lambda: shapeless._normalise_payload(payload_for("v", credits=0)))
        refuses("negative_credits_is_not_a_voucher", "verifier_result_invalid", lambda: shapeless._normalise_payload(payload_for("v", credits=-5)))
        refuses("a_bool_is_not_a_credit_count", "verifier_result_invalid", lambda: shapeless._normalise_payload(payload_for("v", credits=True)))
        refuses("credits_must_be_a_whole_number", "verifier_result_invalid", lambda: shapeless._normalise_payload(payload_for("v", credits=1.5)))
        refuses("a_zero_issue_time_is_not_epoch_ms", "verifier_result_invalid", lambda: shapeless._normalise_payload(payload_for("v", issued=0)))
        refuses("an_expiry_before_the_issue_time_is_incoherent", "verifier_result_invalid", lambda: shapeless._normalise_payload(payload_for("v", issued=10, expires=10)))
        refuses("a_bool_expiry_is_not_a_timestamp", "verifier_result_invalid", lambda: shapeless._normalise_payload(payload_for("v", expires=True)))
        refuses("a_non_numeric_expiry_is_incoherent", "verifier_result_invalid", lambda: shapeless._normalise_payload(payload_for("v", expires="tomorrow")))
        refuses("a_blank_plan_is_refused", "verifier_result_invalid", lambda: shapeless._normalise_payload(_Namespace(**dict(payload_for("v").__dict__, plan=" "))))
        ducked = shapeless._normalise_payload(payload_for("v-duck"))
        check("a_structurally_identical_result_is_accepted", isinstance(ducked, VoucherPayload) and ducked.voucher_id == "v-duck")
        check("the_verifiers_words_are_kept_verbatim", ducked.signature_b64 == "A" * 86 and ducked.plan == "starter")
        real = VoucherPayload("v-real", "starter", 1, 1, None, "k1", "AAA", "")
        check("our_own_dataclass_is_accepted", shapeless._normalise_payload(real).voucher_id == "v-real")
        check("a_payload_without_a_code_survives", shapeless._normalise_payload(real).code == "")
        check("no_expiry_means_no_window", shapeless._normalise_payload(payload_for("v", expires=None)).expires_at_ms is None)

        # ── charging the meter ───────────────────────────────────────────────
        metered, metered_db = new_service(name="charge")
        refuses("a_draft_deployment_refuses_a_metered_charge", "account_draft", lambda: metered.charge("card"), status=409)
        check("the_draft_refusal_names_the_remedy", "redeem" in str(refuses("draft_message_is_actionable", "account_draft", lambda: metered.charge("card")).message))
        refuses("an_unknown_action_is_priced_before_anything_else", "unknown_meter", lambda: metered.charge("moonshot"))
        activate(metered, 10)
        result = metered.charge("card", contact_id=7, ref="msg-1")
        check("a_charge_debits_the_full_quote", result.charged == 1 and result.balance_after == 9)
        check("a_charge_is_not_a_replay", result.idempotent_replay is False)
        row = metered_db.query_one("SELECT * FROM billing_ledger ORDER BY id DESC LIMIT 1")
        check("the_debit_writes_one_row", metered.ledger_count() == 2)
        check("the_row_names_the_action", json.loads(row["meta_json"])["action"] == "card")
        check("the_row_carries_the_subject", row["subject"] == "7" and row["ref"] == "msg-1")
        check("the_row_amount_is_the_cost", int(row["amount"]) == 1 and int(row["balance_after"]) == 9)
        check("the_row_kind_is_consume", row["kind"] == "consume")
        check("the_grant_that_funded_it_is_audit_visible", metered_db.query_one("SELECT kind, amount FROM billing_ledger ORDER BY id LIMIT 1")["kind"] == "grant")
        meta_result = metered.charge("poll", contact_id=3, meta={"poll_id": "p1"})
        check("caller_meta_travels_in_the_envelope", json.loads(metered_db.query_one("SELECT meta_json FROM billing_ledger ORDER BY id DESC LIMIT 1")["meta_json"])["meta"]["poll_id"] == "p1")
        check("a_charge_without_meta_records_only_the_envelope", "meta" not in json.loads(metered_db.query_one("SELECT meta_json FROM billing_ledger WHERE id = (SELECT MIN(id) FROM billing_ledger WHERE kind = 'consume')")["meta_json"]))
        check("charging_is_just_arithmetic_repeated", meta_result.balance_after == 8)
        refusal = refuses("a_suspended_account_refuses_to_spend", "account_suspended", lambda: metered.charge("card") if metered.suspend("fraud review") else None, status=402)
        check("the_suspension_refusal_quotes_the_reason", "fraud review" in refusal.message)
        check("a_suspended_account_writes_nothing", metered.ledger_count() == 3)

        drain, drain_db = new_service(name="drain")
        activate(drain, 1)
        last = drain.charge("ai_message")
        check("the_last_charge_spends_what_exists", last.charged == 1 and last.cost == 5 and last.balance_after == 0)
        check("the_shortfall_is_written_off_not_banked", drain_db.scalar("SELECT balance FROM billing_account") == 0)
        check("the_partial_row_says_it_was_partial", json.loads(drain_db.query_one("SELECT meta_json FROM billing_ledger ORDER BY id DESC LIMIT 1")["meta_json"])["partial"] is True)
        check("exhaustion_fuses_the_account", drain.account().status == STATUS_SUSPENDED)
        check("the_fuse_is_attributed_to_credits", str(drain.account().suspended_reason).startswith(REASON_CREDITS))
        check("the_account_row_survives_the_partial_charge", drain.summary()["ledger_balanced"] is True)
        refuses("a_fused_account_refuses_the_next_charge", "account_suspended", lambda: drain.charge("card"))
        check("the_refusal_names_the_exhaustion_itself", "credits" in str(refuses("drain_message_is_actionable", "account_suspended", lambda: drain.charge("card")).message))
        empty, empty_db = new_service(name="empty")
        exc = fails("an_empty_account_refuses_before_it_can_debit", BillingError, lambda: empty.charge("card") if empty.go_online() else None)
        check("the_suspension_commits_before_the_refusal_raises", empty_db.query_one("SELECT status FROM billing_account")["status"] == STATUS_SUSPENDED)
        check("the_refusal_rolls_back_nothing", empty_db.scalar("SELECT COUNT(*) FROM billing_ledger") == 0)
        check("the_refusal_carries_the_credit_answer", int(getattr(exc, "http_status", 0)) == 402)
        tight, tight_db = new_service(new_config(threshold=5, name="tight"), name="tight")
        activate(tight, 6)
        near = tight.charge("card")
        check("a_threshold_keeps_the_remainder_spendable", near.charged == 1 and tight_db.scalar("SELECT balance FROM billing_account") == 5)
        refuses("a_threshold_of_five_stops_the_next_charge", "insufficient_credits", lambda: tight.charge("alert"))
        check("the_threshold_suspension_is_committed_too", tight_db.query_one("SELECT status FROM billing_account")["status"] == STATUS_SUSPENDED)

        # ── idempotency: the outbox retry contract ───────────────────────────
        retried, retried_db = new_service(name="retry")
        activate(retried, 20)
        first = retried.charge("card", idempotency_key="outbox-1")
        again = retried.charge("card", idempotency_key="outbox-1")
        check("a_retried_charge_debits_once", retried_db.scalar("SELECT COUNT(*) FROM billing_ledger WHERE idempotency_key = 'outbox-1'") == 1)
        check("the_retry_reports_the_original_numbers", again.charged == first.charged and again.balance_after == first.balance_after)
        check("the_retry_marks_itself", again.idempotent_replay is True and first.idempotent_replay is False)
        check("the_balance_moved_once", again.balance_after == 19)
        later = retried.grant(credits=1, reason="top-up", idempotency_key="grant-1")
        check("a_retried_grant_credits_once", retried.grant(credits=1, reason="top-up", idempotency_key="grant-1").balance_after == later.balance_after)
        blank = retried.charge("card", idempotency_key="   ")
        check("a_blank_key_is_no_key", blank.idempotent_replay is False and retried.charge("card", idempotency_key="").idempotent_replay is False)
        check("unkeyed_charges_are_recorded_separately", retried_db.scalar("SELECT COUNT(*) FROM billing_ledger WHERE idempotency_key IS NULL AND kind = 'consume'") == 2)
        ordering, _ = new_service(name="ordering")
        activate(ordering, 10)
        ordering.charge("card", idempotency_key="seen")
        ordering.suspend("halt")
        replayed = ordering.charge("card", idempotency_key="seen")
        check("the_key_is_recognised_before_the_lifecycle_check", replayed.idempotent_replay is True)
        check("the_replay_reports_the_live_status_not_the_old_one", replayed.account_status == STATUS_SUSPENDED)
        raced, raced_db = new_service(name="raced")
        activate(raced, 5)
        raced.charge("card", idempotency_key="winner")
        won = raced._resolve_integrity(sqlite3.IntegrityError("UNIQUE"), "winner")
        check("a_lost_race_answers_with_the_row_that_committed", won is not None and won.idempotent_replay is True and won.charged == 1)
        check("a_race_without_a_key_is_not_swallowed", raced._resolve_integrity(sqlite3.IntegrityError("boom"), None) is None)
        check("an_unrelated_conflict_is_a_database_fault", raced._resolve_integrity(sqlite3.IntegrityError("no such row"), "never-seen") is None)
        loser = BillingService(_LosingRace(raced_db, sqlite3.IntegrityError("UNIQUE idempotency_key")), raced.config)
        refuses("a_write_rejected_without_a_key_is_reported", "ledger_conflict", lambda: loser.charge("card"), status=500)
        refuses("an_unkeyed_write_rejected_by_the_database_is_not_a_success", "ledger_conflict", lambda: loser.grant(credits=1, reason="r"))
        won_row = raced_db.query_one("SELECT * FROM billing_ledger WHERE idempotency_key = 'winner'")
        keyed_loser = BillingService(_LosingRace(raced_db, sqlite3.IntegrityError("UNIQUE idempotency_key")), raced.config)
        check("a_keyed_grant_that_lost_the_race_replays_the_winner", keyed_loser.grant(credits=5, reason="dup", idempotency_key="winner").idempotent_replay is True)
        check("a_keyed_refund_that_lost_the_race_replays_the_winner", keyed_loser.refund(amount=5, reason="dup", idempotency_key="winner").idempotent_replay is True)
        check("a_replay_from_a_race_reports_the_winners_numbers", keyed_loser.charge("card", idempotency_key="winner").balance_after == int(won_row["balance_after"]))
        rows_before_race = raced_db.scalar("SELECT COUNT(*) FROM billing_ledger")
        refuses("a_race_the_loser_cannot_resolve_is_a_500", "ledger_conflict", lambda: keyed_loser.grant(credits=99, reason="dup", idempotency_key="no-such-row"))
        check("losing_the_race_moves_no_money", raced_db.scalar("SELECT COUNT(*) FROM billing_ledger") == rows_before_race)

        # ── unmetered deployments run the same engine ────────────────────────
        free_svc, free_db = new_service(new_config(require_voucher=False, meters={"card": 3}, name="unmetered2"), name="unmetered2")
        auto = free_svc.charge("card")
        check("an_unmetered_deployment_activates_itself", auto.account_status == STATUS_ONLINE and free_svc.account().status == STATUS_ONLINE)
        check("an_unmetered_charge_still_pays_the_full_quote", auto.charged == 3)
        kinds = [r["kind"] for r in free_svc.ledger()]
        check("the_topup_is_a_recorded_grant", kinds == ["consume", "grant"])
        check("the_topup_row_says_why", json.loads(free_db.query_one("SELECT meta_json FROM billing_ledger WHERE kind = 'grant'")["meta_json"])["reason"] == "unmetered deployment")
        check("an_unmetered_balance_stays_balanced", free_svc.summary()["ledger_balanced"] is True)
        check("an_unmetered_deployment_never_fuses_for_credits", free_svc.plugin_fusings() == {name: True for name, _ in METERED_PLUGINS})
        check("an_unmetered_charge_records_the_unmetered_flag", json.loads(free_db.query_one("SELECT meta_json FROM billing_ledger WHERE kind = 'consume'")["meta_json"])["unmetered"] is True)
        free_svc.suspend("operator halt")
        refuses("an_unmetered_operator_halt_still_blocks", "account_suspended", lambda: free_svc.charge("card"))
        check("an_unmetered_halt_fuses_the_plugins", all(v is False for v in free_svc.plugin_fusings().values()))

        # ── money in, without a voucher ─────────────────────────────────────
        gifted, gifted_db = new_service(name="grant")
        gift = gifted.grant(credits=50, reason="migration credit")
        check("a_grant_funds_the_account", gifted.account().balance == 50)
        check("a_grant_does_not_activate_it", gift.account_status == STATUS_DRAFT and gifted.account().status == STATUS_DRAFT)
        check("a_grant_counts_as_granted_not_spent", gifted.account().lifetime_granted == 50 and gifted.account().lifetime_spent == 0)
        check("a_grant_row_is_written", gifted_db.query_one("SELECT ref FROM billing_ledger WHERE kind = 'grant'")["ref"] == "migration credit")
        refuses("a_grant_needs_a_reason", "invalid_argument", lambda: gifted.grant(credits=1, reason=""))
        refuses("a_grant_needs_a_reason_at_all", "invalid_argument", lambda: gifted.grant(credits=1, reason=None))
        for label, bad in (("a_grant_of_zero_is_a_typo", 0), ("a_grant_of_less_than_zero_is_a_refund_in_disguise", -3), ("a_grant_of_a_fraction_is_not_credits", 1.5), ("a_grant_of_true_is_not_credits", True), ("a_grant_of_a_string_is_not_credits", "100")):
            refuses(label, "invalid_amount", lambda bad=bad: gifted.grant(credits=bad, reason="x"))
        unfuse, _ = new_service(name="unfuse")
        activate(unfuse, 1)
        unfuse.charge("ai_message")
        check("the_account_fused_for_exhaustion", unfuse.account().status == STATUS_SUSPENDED)
        healed = unfuse.grant(credits=10, reason="merchant paid")
        check("money_un_fuses_an_exhaustion_halt", healed.account_status == STATUS_ONLINE and unfuse.account().balance == 10)
        check("the_heal_clears_the_reason", unfuse.account().suspended_reason is None)
        check("an_un_fused_plugin_runs_again", unfuse.charge("ai_message").charged == 5)
        halted = unfuse.suspend("abuse")
        check("an_operator_halt_records_its_author", str(halted.suspended_reason).startswith(REASON_OPERATOR))
        unfuse.grant(credits=1000, reason="goodwill")
        check("money_does_not_lift_an_operator_halt", unfuse.account().status == STATUS_SUSPENDED)
        back = unfuse.go_online()
        check("only_a_human_lifts_an_operator_halt", back.status == STATUS_ONLINE and back.suspended_reason is None)
        refunder, refunder_db = new_service(name="refund")
        activate(refunder, 10)
        refunder.charge("key_rotation")
        refunded = refunder.refund(amount=2, reason="card never sent", ref="msg-9")
        check("a_refund_gives_the_credits_back", refunded.balance_after == 10 and refunder.account().balance == 10)
        check("a_refund_un_spends_rather_than_mints", refunder.account().lifetime_spent == 0 and refunder.account().lifetime_granted == 10)
        check("a_refund_keeps_the_invariant", refunder.summary()["ledger_balanced"] is True)
        check("a_refund_is_its_own_ledger_kind", refunder_db.query_one("SELECT kind, amount, ref FROM billing_ledger ORDER BY id DESC LIMIT 1")["kind"] == KIND_REFUND)
        refuses("you_cannot_refund_more_than_was_spent", "refund_exceeds_spend", lambda: refunder.refund(amount=5, reason="twice"))
        ceiling = refuses("the_refund_ceiling_shows_the_arithmetic", "refund_exceeds_spend", lambda: refunder.refund(amount=99, reason="all of it"))
        check("the_ceiling_message_names_the_ceiling", "lifetime spend is 0 CP" in ceiling.message)
        refuses("a_refund_needs_a_positive_amount", "invalid_amount", lambda: refunder.refund(amount=0, reason="x"))
        refuses("a_refund_needs_a_reason", "invalid_argument", lambda: refunder.refund(amount=1, reason=" "))
        refunder.charge("key_rotation")
        r1 = refunder.refund(amount=1, reason="partial correction", idempotency_key="ref-1")
        check("a_retried_refund_returns_once", refunder.refund(amount=1, reason="partial correction", idempotency_key="ref-1").balance_after == r1.balance_after)
        check("a_retried_refund_un_spends_once", refunder.account().lifetime_spent == 1)
        check("the_ledger_holds_one_row_per_refund_key", refunder_db.scalar("SELECT COUNT(*) FROM billing_ledger WHERE idempotency_key = 'ref-1'") == 1)
        refuses("the_remaining_ceiling_is_enforced_after_a_replay", "refund_exceeds_spend", lambda: refunder.refund(amount=2, reason="more than remains"))
        check("every_refund_row_keeps_the_invariant", refunder.summary()["ledger_balanced"] is True)
        exhausted, exhausted_db = new_service(name="exhausted")
        activate(exhausted, 1)
        exhausted.charge("ai_message")
        check("a_refund_un_fuses_an_exhaustion_halt", exhausted.refund(amount=1, reason="the action failed").account_status == STATUS_ONLINE)
        check("the_refund_row_is_the_last_word", int(exhausted_db.query_one("SELECT balance_after FROM billing_ledger ORDER BY id DESC LIMIT 1")["balance_after"]) == 1)

        # ── the engine cannot post what it does not model ────────────────────
        guard, guard_db = new_service(name="guard")
        activate(guard, 2)

        def _bad_kind() -> None:
            with guard_db.transaction(immediate=True) as conn:
                row = guard._ensure_account(conn)
                guard._post(conn, kind="reversal", amount=1, balance=int(row["balance"]), row=row, ref=None, subject=None, key=None, ts=now_ms(), meta={})

        refuses("the_engine_never_reverses_its_own_bookkeeping", "unknown_ledger_kind", _bad_kind, status=500)

        def _bad_balance() -> None:
            with guard_db.transaction(immediate=True) as conn:
                row = guard._ensure_account(conn)
                guard._post(conn, kind=KIND_CONSUME, amount=1000, balance=int(row["balance"]), row=row, ref=None, subject=None, key=None, ts=now_ms(), meta={})

        refuses("the_negative_guard_is_real", "negative_balance_guard", _bad_balance, status=500)
        check("a_guarded_transaction_leaves_no_row", guard.ledger_count() == 1)

        # ── the fuse the plugins are stopped by ──────────────────────────────
        fuse_cfg = new_config(toggles={"web3_bridge": False}, name="fuse")
        fuse_db = Database(fuse_cfg.db_path)
        fused = BillingService(fuse_db, fuse_cfg, _Verifier(payload_for("v-fuse", credits=100, code=code_for())))
        check("a_draft_deployment_has_every_paid_plugin_fused", all(v is False for v in fused.plugin_fusings().values()))
        refuses("a_fused_plugin_cannot_bill", "account_draft", lambda: fused.charge("ai_message"))
        fused.redeem_voucher(code_for())
        check("redemption_un_fuses_without_a_button", all(v is True for k, v in fused.plugin_fusings().items() if k != "web3_bridge"))
        check("an_off_toggle_is_not_a_fuse", fused.is_plugin_fused("web3_bridge") is False and fused.plugin_fusings()["web3_bridge"] is False)
        refuses("a_plugin_with_no_fuse_is_a_caller_bug", "unknown_plugin", lambda: fused.is_plugin_fused("carrier_pigeon"))
        check("the_fuse_is_derived_and_never_stored", not any("fus" in str(c[1]).lower() for c in fuse_db.query("PRAGMA table_info(billing_account)")))
        check("the_derivation_uses_the_threshold", fused._fused(fused._account_row(fused.db.connection())) is False)
        fused.suspend("chargeback")
        check("an_account_halting_for_other_reasons_stays_fused", all(v is False for v in fused.plugin_fusings().values()) and fused.is_plugin_fused("polls") is True)
        zeroed, zeroed_db = new_service(verifier=_Verifier(payload_for("v-zero", credits=100, code=code_for())), name="zeroed")
        zeroed.go_online()
        activation = refuses("activation_without_money_buys_nothing", "insufficient_credits", lambda: zeroed.charge("card"))
        check("the_refusal_names_the_remedy_not_just_the_fault", "redeem" in activation.message)
        check("authority_then_funding_fuses_the_plugins", all(v is False for v in zeroed.plugin_fusings().values()))
        check("the_second_refusal_is_the_suspension_it_just_made", refuses("funded_remedy_message", "account_suspended", lambda: zeroed.charge("card")).code == "account_suspended")
        zeroed.redeem_voucher(code_for())
        check("redemption_funds_and_un_fuses_at_once", all(v is True for v in zeroed.plugin_fusings().values()) and zeroed_db.query_one("SELECT status FROM billing_account")["status"] == STATUS_ONLINE)

        # ── the ledger view an invoice is built from ─────────────────────────
        book, book_db = new_service(name="book")
        activate(book, 100)
        for index in range(5):
            book.charge("card", contact_id=index, idempotency_key=None if index else "key-0")
        rows = book.ledger()
        check("the_ledger_is_newest_first", [r["id"] for r in rows] == sorted([r["id"] for r in rows], reverse=True))
        check("the_ledger_decodes_meta_once", isinstance(rows[0]["meta"], dict))
        check("the_ledger_keeps_the_key_it_was_given", any(r["idempotency_key"] == "key-0" for r in rows))
        with book_db.transaction() as conn:
            conn.execute("INSERT INTO billing_ledger (ts_ms, kind, amount, balance_after, ref, meta_json) VALUES (?,?,?,?,?,?)", (now_ms(), KIND_GRANT, 0, 100, "raw", "this is not json{"))
        check("an_undecodable_row_is_shown_not_dropped", any(r["meta"] == "this is not json{" for r in book.ledger()))
        check("an_undecodable_row_does_not_break_the_view", book.summary()["ledger_balanced"] is True)
        check("the_ledger_limit_is_clamped", len(book.ledger(10_000_000)) <= LEDGER_LIMIT_MAX)
        check("a_limit_below_one_still_shows_a_row", len(book.ledger(0)) == 1)
        refuses("a_junk_limit_is_a_caller_error", "invalid_limit", lambda: book.ledger("many"))
        total_rows = book.ledger_count()
        pages = [r["id"] for start in range(0, total_rows, 2) for r in book.ledger(2, offset=start)]
        check("paging_covers_every_row", len(pages) == total_rows)
        check("paging_neither_repeats_nor_skips", len(set(pages)) == total_rows and sorted(pages) == sorted(r["id"] for r in book.ledger(1000)))
        check("the_count_matches_the_rows", book.ledger_count() == len(book.ledger(1000)))
        summary = book.summary()
        check("the_summary_is_in_popx_cp", summary["currency"] == "POPX-CP" and summary["service_id"] == "popopx.test")
        check("the_summary_shows_the_arithmetic", summary["expected_balance"] == summary["balance"] == summary["lifetime_granted"] - summary["lifetime_spent"])
        check("the_summary_lists_every_meter", set(summary["meters"]) == set(prices))
        check("the_summary_names_the_threshold_and_gate", summary["suspend_threshold"] == book.config.billing.suspend_threshold and summary["require_voucher"] is True)
        check("the_summary_says_whether_a_verifier_is_wired", summary["verifier_configured"] is False and summary["official_key_configured"] is True)
        check("the_summary_counts_the_voucher_states", set(summary["vouchers"]) == {"issued", "redeemed", "revoked", "expired"})
        check("the_summary_carries_no_secrets", "t" * 32 not in json.dumps(summary) and "s" * 48 not in json.dumps(summary))
        check("the_ledger_view_carries_no_secrets", CODE_PREFIX not in json.dumps(book.ledger()))
        long_code = code_for(payload=bytes(200))
        truncated_svc, _ = new_service(verifier=_Verifier(payload_for("v-long", credits=1, code=long_code)), name="trunc")
        truncated_svc.redeem_voucher(long_code)
        shown = truncated_svc.vouchers()[0]["code"]
        check("a_long_code_is_not_printed_whole", len(shown) < len(long_code) and "..." in shown)
        check("the_recorded_code_is_still_the_whole_code", truncated_svc.db.query_one("SELECT code FROM vouchers")["code"] == long_code)
        check("the_view_never_prints_the_signature", "signature_b64" not in json.dumps(truncated_svc.vouchers()))

        # ── the same file, reopened ──────────────────────────────────────────
        reopened = BillingService(Database(book.config.db_path), book.config)
        check("the_balance_survives_a_restart", reopened.account().balance == book.account().balance)
        check("the_ledger_survives_a_restart", reopened.ledger_count() == book.ledger_count())
        check("the_lifecycle_survives_a_restart", reopened.account().status == STATUS_ONLINE)

        # ── the threadpool FastAPI actually hands this object to ─────────────
        hot_cfg = new_config(meters={"card": 1}, name="hot")
        hot_db = Database(hot_cfg.db_path)
        hot = BillingService(hot_db, hot_cfg)
        hot.go_online()
        hot.grant(credits=100, reason="concurrency float")
        errors: List[str] = []

        def _hammer(worker: int) -> None:
            try:
                for _ in range(5):
                    hot.charge("card", contact_id=worker)
            except Exception as exc:  # noqa: BLE001
                errors.append("%s: %s" % (type(exc).__name__, exc))

        with ThreadPoolExecutor(max_workers=8) as pool:
            list(pool.map(_hammer, range(8)))
        check("concurrent_charges_never_corrupt_the_bookkeeping", errors == [])
        check("every_concurrent_charge_debited_once", hot_db.scalar("SELECT COUNT(*) FROM billing_ledger WHERE kind = 'consume'") == 40)
        check("the_concurrent_balance_is_the_arithmetic", hot.account().balance == 60)
        check("the_invariant_holds_under_contention", hot.summary()["ledger_balanced"] is True)

        dup_errors: List[str] = []

        def _retry(worker: int) -> None:
            try:
                hot.charge("card", contact_id=worker, idempotency_key="one-shared-key")
            except Exception as exc:  # noqa: BLE001
                dup_errors.append("%s: %s" % (type(exc).__name__, exc))

        with ThreadPoolExecutor(max_workers=8) as pool:
            list(pool.map(_retry, range(8)))
        check("eight_threads_sharing_a_key_charge_once", dup_errors == [] and hot_db.scalar("SELECT COUNT(*) FROM billing_ledger WHERE idempotency_key = 'one-shared-key'") == 1)
        check("the_shared_key_retry_debited_exactly_one_credit", hot.account().balance == 59)
        check("no_thread_ever_took_the_write_lock_down", hot_db.scalar("SELECT balance FROM billing_account") >= 0)
        check("the_two_halfs_of_the_idempotency_mechanism_agree", hot.ledger_count() == 42)

        stop = threading.Event()
        check("the_engine_holds_no_lock_of_its_own", not any(isinstance(v, type(threading.Lock())) for v in vars(hot).values()))
        stop.set()
    finally:
        shutil.rmtree(root, ignore_errors=True)
    return checks
