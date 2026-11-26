# Copyright (c) 2026 POPOPX (popopx.chat)
# SPDX-License-Identifier: AGPL-3.0-only
"""SQLite persistence for the POPOPX service-account gateway.

Why SQLite and not a client/server database: this suite is meant to run on the
operator's own box, next to their own node, and the property that makes it worth
running there is that nothing leaves that box. A database that needs a
server is a second place secrets live and a second thing to secure. SQLite in
WAL mode handles the write rate of a service account — one writer at a time,
which is exactly the throughput of a single gateway process — with no
credentials to rotate.

Three decisions in here are load-bearing rather than stylistic:

1. **One connection per thread, created lazily.** FastAPI runs synchronous
   path operations on a threadpool, and a `sqlite3` connection is not safe to
   share across threads. :meth:`Database.connection` keeps a thread-local
   handle. The bridge, which lives on the event-loop thread, gets its own.
2. **``BEGIN IMMEDIATE`` for anything that reads-then-writes.** Balance
   mutation, voucher redemption and vote counting are all
   ``SELECT ... ; UPDATE`` pairs. Under the default deferred mode two such
   transactions can both read the old balance and one of them wins silently,
   which in a billing ledger is a customer who spent credits twice.
   :meth:`Database.transaction` takes the write lock up front and pays the
   serialisation cost deliberately.
3. **Foreign keys are on, and cascade is explicit.** ``PRAGMA foreign_keys``
   is off by default in SQLite, so the constraint that keeps a card from
   outliving its follower has to be switched on per connection — a per-
   connection setting, not a persistent one, so it belongs next to the connect
   call and not in the schema.

Nothing in this module knows what a compute credit is. Business rules live in
``billing_service.py``; this file owns the shape of the store and the safety of
the transaction.
"""

import os
import sqlite3
import threading
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, Sequence, Tuple

__all__ = ["Database", "now_ms", "SCHEMA_VERSION"]

#: Bumped when `_DDL` changes in a way an existing deployment must be told
#: about. Recorded in ``PRAGMA user_version``; see :meth:`Database._bootstrap`.
SCHEMA_VERSION = 1


def now_ms() -> int:
    """Epoch milliseconds.

    Every timestamp on the eco wire — ``ut``, ``et``, ``expiresAtMs`` — is
    milliseconds since the Unix epoch as an integer, because that is what the
    iOS codec decodes (`PopopxEcoCodec`, and `PopopxServiceCard.updatedAtMs`
    as `Int64`). Storing seconds anywhere would mean a conversion at every
    boundary, and a conversion is where an off-by-1000 lives.
    """
    return int(time.time() * 1000)


_DDL = """
-- ───────────────────────── deployment / identity ─────────────────────────
-- One row. Records the node-side identity this suite operates, so a restart
-- does not mint a second service account and orphan every follower.
CREATE TABLE IF NOT EXISTS service_identity (
    id                  INTEGER PRIMARY KEY CHECK (id = 1),
    node_user_id        INTEGER,
    address             TEXT,
    service_id          TEXT NOT NULL,
    display_name        TEXT NOT NULL,
    full_name           TEXT,
    auto_accept         INTEGER NOT NULL DEFAULT 1,
    created_at_ms       INTEGER NOT NULL,
    updated_at_ms       INTEGER NOT NULL
);

-- ───────────────────────── followers (contacts) ──────────────────────────
-- `contact_id` is the node's own row id for this contact: the value a send is
-- addressed to (`/_send @<contactId>`), which is why it is the primary key
-- rather than anything we mint. It is *local to this node*, so a merchant who
-- migrates their node database must re-pair — recorded here so the constraint
-- is visible instead of discovered.
CREATE TABLE IF NOT EXISTS contacts (
    contact_id          INTEGER PRIMARY KEY,
    pairwise_uid        TEXT,
    local_display_name  TEXT,
    display_name        TEXT,
    full_name           TEXT,
    first_seen_ms       INTEGER NOT NULL,
    last_seen_ms        INTEGER NOT NULL,
    blocked             INTEGER NOT NULL DEFAULT 0,
    tags                TEXT
);

-- The server half of the pairwise identity. The client indexes its copy by
-- local contact id and has no idea what ours is, so this table is the only
-- place `pairwise_uid` -> contact exists anywhere in the system.
-- `secret_hex` is 1..32 bytes of hex: the client's decoder rejects odd length,
-- non-hex characters and anything over 64 characters, and `PopopxEcoHex.decode`
-- refuses rather than truncating, so a longer secret is not "a strong one", it
-- is a frame the phone will silently drop.
CREATE TABLE IF NOT EXISTS eco_sessions (
    pairwise_uid        TEXT PRIMARY KEY,
    contact_id          INTEGER NOT NULL UNIQUE REFERENCES contacts(contact_id) ON DELETE CASCADE,
    service_id          TEXT NOT NULL,
    secret_hex          TEXT NOT NULL,
    created_at_ms       INTEGER NOT NULL,
    rotated_at_ms       INTEGER,
    revoked             INTEGER NOT NULL DEFAULT 0,
    UNIQUE (contact_id, secret_hex)
);
CREATE INDEX IF NOT EXISTS idx_eco_sessions_contact ON eco_sessions(contact_id, revoked);

-- ───────────────────────── menus ─────────────────────────────────────────
-- The menu is per service account, not per follower, so it is one row keyed by
-- `service_id`. `rev` is monotonic: `PopopxEcoMenu.revision` is the field the
-- client uses to drop an older frame instead of blinking the menu backwards.
CREATE TABLE IF NOT EXISTS menus (
    service_id          TEXT NOT NULL,
    rev                 INTEGER NOT NULL,
    payload_json        TEXT NOT NULL,
    updated_at_ms       INTEGER NOT NULL,
    last_delivered_ms   INTEGER,
    PRIMARY KEY (service_id, rev)
);

-- ───────────────────────── cards ─────────────────────────────────────────
-- `card_id` is minted here and is stable across updates, because the client
-- mutates the rendered bubble by looking this value up. The unique constraint
-- is what makes "in-place update, no second bubble" an enforced property
-- instead of a hope.
CREATE TABLE IF NOT EXISTS cards (
    card_id             TEXT PRIMARY KEY,
    service_id          TEXT NOT NULL,
    contact_id          INTEGER REFERENCES contacts(contact_id) ON DELETE SET NULL,
    style               TEXT NOT NULL CHECK (style IN ('standard','receipt','security')),
    title               TEXT NOT NULL,
    body                TEXT,
    fields_json         TEXT NOT NULL DEFAULT '[]',
    progress_json       TEXT,
    actions_json        TEXT NOT NULL DEFAULT '[]',
    updated_at_ms       INTEGER NOT NULL,
    expires_at_ms       INTEGER,
    state               TEXT NOT NULL DEFAULT 'created',
    -- Server-side seal. The iOS card renderer holds no signature field, so
    -- this verifies nothing on the phone; it is the audit trail that proves
    -- which key minted this card and when. See crypto_service.sign_card_payload
    -- for why shipping it as `sig` in the frame would be a lie.
    sig_hex             TEXT,
    sig_ts              INTEGER,
    topic               TEXT,
    created_at_ms       INTEGER NOT NULL,
    delivered_at_ms     INTEGER
);
CREATE INDEX IF NOT EXISTS idx_cards_contact ON cards(contact_id, updated_at_ms DESC);
CREATE INDEX IF NOT EXISTS idx_cards_topic ON cards(topic, state);

-- One row per button press, so a replayed `::CB::` cannot pay twice and an
-- operator can answer "who clicked this, when, and did it settle".
CREATE TABLE IF NOT EXISTS card_actions (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    card_id             TEXT NOT NULL REFERENCES cards(card_id) ON DELETE CASCADE,
    action_id           TEXT NOT NULL,
    contact_id          INTEGER NOT NULL REFERENCES contacts(contact_id) ON DELETE CASCADE,
    kind                TEXT NOT NULL,
    payload             TEXT,
    amount              INTEGER,
    -- The client's `:paid_<id>` suffix carries its local ledger row id, not a
    -- chain hash. Naming the column after what actually arrives is the
    -- difference between a dedupe key and a decorative string.
    paid_ref            TEXT,
    state               TEXT NOT NULL DEFAULT 'pending'
                        CHECK (state IN ('pending','paid','confirmed','failed','expired')),
    created_at_ms       INTEGER NOT NULL,
    settled_at_ms       INTEGER,
    UNIQUE (card_id, action_id, contact_id)
);
CREATE INDEX IF NOT EXISTS idx_card_actions_state ON card_actions(state, created_at_ms DESC);

-- ───────────────────────── zero-knowledge channels ───────────────────────
-- The gateway is the channel *issuer*: it holds the Ed25519 identity key pair
-- and every epoch key. That is not a leak of channel content — content is
-- encrypted by the publisher with the epoch key and the relay never sees a
-- plaintext — it is the property a rotation manager must have to hand out the
-- next key at all.
CREATE TABLE IF NOT EXISTS channels (
    channel_id          TEXT PRIMARY KEY,
    relay               TEXT NOT NULL,
    title               TEXT,
    identity_pub_b64url TEXT NOT NULL,
    identity_sec_b64url TEXT NOT NULL,
    current_epoch       INTEGER NOT NULL DEFAULT 1,
    node_group_id       INTEGER,
    created_at_ms       INTEGER NOT NULL,
    rotated_at_ms       INTEGER,
    -- 1 once the `#key=&pub=` fragment has been handed out; the fragment is
    -- what makes the channel unreadable to the relay, so re-minting it after a
    -- member joined would silently lock that member out.
    uri_published       INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS channel_epochs (
    channel_id          TEXT NOT NULL REFERENCES channels(channel_id) ON DELETE CASCADE,
    epoch               INTEGER NOT NULL,
    key_b64url          TEXT NOT NULL,
    created_at_ms       INTEGER NOT NULL,
    expires_at_ms       INTEGER,
    revoked             INTEGER NOT NULL DEFAULT 0,
    sealed_under_epoch  INTEGER,
    delivered_ms        INTEGER,
    PRIMARY KEY (channel_id, epoch)
);

-- Membership is what a paid channel is: a grant of a specific epoch to a
-- specific contact, with the payment reference that bought it.
CREATE TABLE IF NOT EXISTS channel_members (
    channel_id          TEXT NOT NULL REFERENCES channels(channel_id) ON DELETE CASCADE,
    contact_id          INTEGER NOT NULL REFERENCES contacts(contact_id) ON DELETE CASCADE,
    epoch               INTEGER NOT NULL,
    paid_ref            TEXT,
    credits_spent       INTEGER,
    granted_at_ms       INTEGER NOT NULL,
    expires_at_ms       INTEGER,
    status              TEXT NOT NULL DEFAULT 'active'
                        CHECK (status IN ('active','expired','revoked','pending_payment')),
    PRIMARY KEY (channel_id, contact_id)
);
CREATE INDEX IF NOT EXISTS idx_channel_members_status ON channel_members(status, expires_at_ms);

-- ───────────────────────── POPX-CP vouchers ──────────────────────────────
-- A code is `POPX-CP-1.<payload>.<signature>`: signed public data, not a
-- secret, which is why it is stored in the clear and matched on `voucher_id`
-- at redemption. Storing only a hash would be the right call for a password
-- and wrong here — verification needs the signed bytes themselves.
CREATE TABLE IF NOT EXISTS vouchers (
    voucher_id          TEXT PRIMARY KEY,
    code                TEXT NOT NULL UNIQUE,
    plan                TEXT NOT NULL,
    credits             INTEGER NOT NULL CHECK (credits > 0),
    issued_at_ms        INTEGER NOT NULL,
    expires_at_ms       INTEGER,
    issuer_key_id       TEXT,
    signature_b64       TEXT NOT NULL,
    status              TEXT NOT NULL DEFAULT 'issued'
                        CHECK (status IN ('issued','redeemed','revoked','expired')),
    redeemed_at_ms      INTEGER,
    redeemed_by         TEXT,
    note                TEXT
);
CREATE INDEX IF NOT EXISTS idx_vouchers_status ON vouchers(status, expires_at_ms);

-- ───────────────────────── billing ───────────────────────────────────────
-- The lifecycle POPX-CP hangs on: ONLINE (the default, usable immediately),
-- DRAFT (only when POPOPX_BILLING_REQUIRE_VOUCHER=1, or a row written by an older
-- database: no voucher yet, plugins fused), SUSPENDED (balance exhausted or
-- operator halt).
CREATE TABLE IF NOT EXISTS billing_account (
    id                  INTEGER PRIMARY KEY CHECK (id = 1),
    status              TEXT NOT NULL DEFAULT 'ONLINE'
                        CHECK (status IN ('DRAFT','ONLINE','SUSPENDED')),
    balance             INTEGER NOT NULL DEFAULT 0 CHECK (balance >= 0),
    lifetime_granted    INTEGER NOT NULL DEFAULT 0,
    lifetime_spent      INTEGER NOT NULL DEFAULT 0,
    suspended_reason    TEXT,
    updated_at_ms       INTEGER NOT NULL
);

-- Append-only. Nothing here updates or deletes: an accounting record that can
-- be edited is not an accounting record. `idempotency_key` is what lets a
-- retried plugin call charge once, and its UNIQUE constraint is the whole
-- mechanism — a check-then-insert would race two workers into a double charge.
CREATE TABLE IF NOT EXISTS billing_ledger (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    ts_ms               INTEGER NOT NULL,
    kind                TEXT NOT NULL CHECK (kind IN ('grant','consume','refund','reversal')),
    amount              INTEGER NOT NULL,
    balance_after       INTEGER NOT NULL,
    ref                 TEXT,
    subject             TEXT,
    idempotency_key     TEXT UNIQUE,
    meta_json           TEXT
);
CREATE INDEX IF NOT EXISTS idx_billing_ledger_ts ON billing_ledger(ts_ms DESC);
CREATE INDEX IF NOT EXISTS idx_billing_ledger_ref ON billing_ledger(ref);

-- ───────────────────────── upstream callbacks ────────────────────────────
-- Every silent `::CB::`, `::REF::`, `::SSO_SCAN::` and `::popopx_sys::` line
-- the gateway intercepts, before any handler touches it. This is the forensic
-- record for "the phone says it paid": the handler can be rewritten, the
-- inbound evidence cannot.
CREATE TABLE IF NOT EXISTS callbacks (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    ts_ms               INTEGER NOT NULL,
    contact_id          INTEGER REFERENCES contacts(contact_id) ON DELETE SET NULL,
    kind                TEXT NOT NULL,
    marker              TEXT NOT NULL,
    payload             TEXT,
    paid_ref            TEXT,
    raw                 TEXT NOT NULL,
    status              TEXT NOT NULL DEFAULT 'received'
                        CHECK (status IN ('received','handled','ignored','failed','duplicate')),
    handler             TEXT,
    error               TEXT,
    dedupe_key          TEXT UNIQUE,
    meta_json           TEXT
);
CREATE INDEX IF NOT EXISTS idx_callbacks_kind ON callbacks(kind, ts_ms DESC);

-- Article conversion counts from `::REF::<article_id>` — a tally per article
-- and per contact, so one follower reloading an article 200 times is 200 rows
-- and one number that can be defended.
CREATE TABLE IF NOT EXISTS article_refs (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    article_id          TEXT NOT NULL,
    contact_id          INTEGER REFERENCES contacts(contact_id) ON DELETE CASCADE,
    ts_ms               INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_article_refs_article ON article_refs(article_id, ts_ms);

-- ───────────────────────── privacy SSO ───────────────────────────────────
CREATE TABLE IF NOT EXISTS sso_sessions (
    session_id          TEXT PRIMARY KEY,
    state               TEXT NOT NULL DEFAULT 'pending'
                        CHECK (state IN ('pending','scanned','approved','denied','expired','consumed')),
    rp_uri              TEXT,
    rp_name             TEXT,
    scope               TEXT,
    nonce               TEXT,
    card_id             TEXT,
    contact_id          INTEGER REFERENCES contacts(contact_id) ON DELETE SET NULL,
    pairwise_uid        TEXT,
    created_at_ms       INTEGER NOT NULL,
    scanned_at_ms       INTEGER,
    confirmed_at_ms     INTEGER,
    expires_at_ms       INTEGER NOT NULL,
    token_hash          TEXT
);
CREATE INDEX IF NOT EXISTS idx_sso_state ON sso_sessions(state, expires_at_ms);

-- ───────────────────────── polls ─────────────────────────────────────────
CREATE TABLE IF NOT EXISTS polls (
    poll_id             TEXT PRIMARY KEY,
    question            TEXT NOT NULL,
    options_json        TEXT NOT NULL,
    card_id             TEXT,
    mode                TEXT NOT NULL DEFAULT 'anonymous'
                        CHECK (mode IN ('anonymous','identified')),
    multi               INTEGER NOT NULL DEFAULT 0,
    ends_at_ms          INTEGER,
    created_at_ms       INTEGER NOT NULL,
    closed              INTEGER NOT NULL DEFAULT 0
);

-- `UNIQUE (poll_id, contact_id)` *is* the anti-double-vote rule. A count query
-- plus an insert would let two simultaneous taps both pass the count.
CREATE TABLE IF NOT EXISTS poll_votes (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    poll_id             TEXT NOT NULL REFERENCES polls(poll_id) ON DELETE CASCADE,
    contact_id          INTEGER NOT NULL REFERENCES contacts(contact_id) ON DELETE CASCADE,
    choice_index        INTEGER NOT NULL,
    ts_ms               INTEGER NOT NULL,
    UNIQUE (poll_id, contact_id)
);

-- ───────────────────────── alert ops ─────────────────────────────────────
CREATE TABLE IF NOT EXISTS alerts (
    alert_id            TEXT PRIMARY KEY,
    fingerprint         TEXT UNIQUE,
    severity            TEXT NOT NULL,
    status              TEXT NOT NULL DEFAULT 'firing'
                        CHECK (status IN ('firing','acknowledged','resolved')),
    title               TEXT NOT NULL,
    summary             TEXT,
    labels_json         TEXT,
    card_id             TEXT,
    source              TEXT,
    firing_at_ms        INTEGER NOT NULL,
    ack_at_ms           INTEGER,
    ack_by_contact_id   INTEGER REFERENCES contacts(contact_id) ON DELETE SET NULL,
    resolved_at_ms      INTEGER
);
CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status, firing_at_ms DESC);

-- ───────────────────────── web3 bridge ───────────────────────────────────
CREATE TABLE IF NOT EXISTS web3_watch (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    chain               TEXT NOT NULL CHECK (chain IN ('evm','solana')),
    address             TEXT NOT NULL,
    label               TEXT,
    channel_id          TEXT REFERENCES channels(channel_id) ON DELETE SET NULL,
    min_delta           TEXT,
    active              INTEGER NOT NULL DEFAULT 1,
    last_block          INTEGER,
    created_at_ms       INTEGER NOT NULL,
    UNIQUE (chain, address)
);

CREATE TABLE IF NOT EXISTS web3_events (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    chain               TEXT NOT NULL,
    address             TEXT NOT NULL,
    tx_hash             TEXT NOT NULL,
    log_index           INTEGER,
    direction           TEXT,
    asset               TEXT,
    amount              TEXT,
    block_number        INTEGER,
    observed_at_ms      INTEGER NOT NULL,
    notified            INTEGER NOT NULL DEFAULT 0,
    UNIQUE (chain, tx_hash, log_index)
);

-- A whitelist row is a key grant promise: this address gets this channel's
-- rotation. `granted_epoch` records that it was honoured, which is what makes
-- a re-run of the poller idempotent instead of a second key drop.
CREATE TABLE IF NOT EXISTS web3_whitelist (
    chain               TEXT NOT NULL CHECK (chain IN ('evm','solana')),
    address             TEXT NOT NULL,
    channel_id          TEXT NOT NULL REFERENCES channels(channel_id) ON DELETE CASCADE,
    tag                 TEXT,
    granted_epoch       INTEGER,
    granted_at_ms       INTEGER,
    created_at_ms       INTEGER NOT NULL,
    PRIMARY KEY (chain, address, channel_id)
);

-- ───────────────────────── AI agent ──────────────────────────────────────
-- Conversation memory only, per pairwise uid. No name, no phone, no graph:
-- the plugin's whole selling point is that a chat with the bot does not build
-- a profile of the person.
CREATE TABLE IF NOT EXISTS ai_messages (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    pairwise_uid        TEXT NOT NULL,
    contact_id          INTEGER REFERENCES contacts(contact_id) ON DELETE CASCADE,
    role                TEXT NOT NULL CHECK (role IN ('system','user','assistant')),
    content             TEXT NOT NULL,
    credits_charged     INTEGER NOT NULL DEFAULT 0,
    ts_ms               INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_ai_messages_uid ON ai_messages(pairwise_uid, id);

-- ───────────────────────── outbound reliability ──────────────────────────
-- The node's WebSocket is loopback, unauthenticated and can be restarted
-- independently of this process. A card that was rendered by an operator but
-- died in a socket write is the worst failure mode of a notification product,
-- so every frame is committed here first and only marked `sent` once the node
-- answers `newChatItems`.
CREATE TABLE IF NOT EXISTS outbox (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    ts_ms               INTEGER NOT NULL,
    contact_id          INTEGER REFERENCES contacts(contact_id) ON DELETE CASCADE,
    frame_kind          TEXT NOT NULL,
    card_id             TEXT,
    body                TEXT NOT NULL,
    status              TEXT NOT NULL DEFAULT 'queued'
                        CHECK (status IN ('queued','in_flight','sent','failed','abandoned')),
    attempts            INTEGER NOT NULL DEFAULT 0,
    last_error          TEXT,
    corr_id             TEXT,
    credits_charged     INTEGER NOT NULL DEFAULT 0,
    sent_at_ms          INTEGER
);
CREATE INDEX IF NOT EXISTS idx_outbox_status ON outbox(status, id);

-- ───────────────────────── operator settings ─────────────────────────────
-- Anything the console can toggle at runtime, as JSON. A key/value table
-- rather than one column per knob so a plugin can store its own settings
-- without a migration.
CREATE TABLE IF NOT EXISTS settings (
    key                 TEXT PRIMARY KEY,
    value_json          TEXT NOT NULL,
    updated_at_ms       INTEGER NOT NULL
);

-- ───────────────────────── connector audit ───────────────────────────────
-- One narrow row per webhook/DAV operation. There is deliberately no URL, body,
-- contact text, token or exception-message column: the reason lives in `outcome`
-- as a stable code, so an audit dump cannot become a second copy of the data it
-- is meant to protect.
CREATE TABLE IF NOT EXISTS connector_audit (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    ts_ms               INTEGER NOT NULL,
    connector           TEXT NOT NULL,
    direction           TEXT NOT NULL CHECK (direction IN ('inbound','outbound')),
    action              TEXT NOT NULL,
    source              TEXT NOT NULL,
    scope               TEXT,
    status_code         INTEGER,
    outcome             TEXT NOT NULL,
    latency_ms          INTEGER
);
CREATE INDEX IF NOT EXISTS idx_connector_audit_connector ON connector_audit(connector, id DESC);

-- ───────────────────────── workflow webhook bridge ──────────────────────
-- A subscription is an operator-created destination. `secret` is the HMAC key
-- the receiver verifies; it is never returned by a GET. `scopes` is a JSON array
-- checked on every event, not a display hint.
CREATE TABLE IF NOT EXISTS workflow_subscriptions (
    id                  TEXT PRIMARY KEY,
    label               TEXT NOT NULL,
    url                 TEXT NOT NULL,
    secret              TEXT NOT NULL,
    scopes              TEXT NOT NULL,
    allow_private       INTEGER NOT NULL DEFAULT 0,
    active              INTEGER NOT NULL DEFAULT 1,
    created_at_ms       INTEGER NOT NULL,
    updated_at_ms       INTEGER NOT NULL,
    last_attempt_ms     INTEGER,
    last_success_ms     INTEGER,
    last_error          TEXT,
    failures            INTEGER NOT NULL DEFAULT 0,
    next_attempt_ms     INTEGER
);

-- The delivery queue has to retain the event body until the receiver accepts it,
-- which is why the body is bounded at the source and the row is pruned after 30
-- days. `UNIQUE (subscription_id, event_id)` makes a replayed inbound event
-- idempotent. `status` is one of pending/delivered/abandoned; there is no
-- 'failed' terminal state because the next attempt is always scheduled.
CREATE TABLE IF NOT EXISTS workflow_deliveries (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    subscription_id     TEXT NOT NULL REFERENCES workflow_subscriptions(id) ON DELETE CASCADE,
    event_id            TEXT NOT NULL,
    event_type          TEXT NOT NULL,
    payload_json        TEXT NOT NULL,
    status              TEXT NOT NULL DEFAULT 'pending'
                        CHECK (status IN ('pending','delivered','abandoned')),
    attempts            INTEGER NOT NULL DEFAULT 0,
    next_attempt_ms     INTEGER NOT NULL,
    last_status_code    INTEGER,
    last_error          TEXT,
    created_at_ms       INTEGER NOT NULL,
    delivered_at_ms     INTEGER,
    UNIQUE (subscription_id, event_id)
);
CREATE INDEX IF NOT EXISTS idx_workflow_deliveries_due
    ON workflow_deliveries(status, next_attempt_ms);

-- Inbound credentials: `token_hash` is SHA-256 hex, `token_prefix` is the only
-- part the console redisplay shows. Revocation is a column, not a delete, so an
-- old audit row still has something to point at.
CREATE TABLE IF NOT EXISTS workflow_tokens (
    id                  TEXT PRIMARY KEY,
    label               TEXT NOT NULL,
    token_hash          TEXT NOT NULL UNIQUE,
    token_prefix        TEXT NOT NULL,
    scopes              TEXT NOT NULL,
    created_at_ms       INTEGER NOT NULL,
    expires_at_ms       INTEGER,
    revoked             INTEGER NOT NULL DEFAULT 0,
    revoked_at_ms       INTEGER,
    last_used_at_ms     INTEGER
);

-- The approval row is the audit trail of a human decision, so a failed delivery
-- leaves a row with status='failed' rather than deleting it. `action_json` is
-- returned to the workflow engine only after the recipient decides; the gateway
-- never executes it.
CREATE TABLE IF NOT EXISTS workflow_approvals (
    id                  TEXT PRIMARY KEY,
    token_id            TEXT NOT NULL,
    contact_id          INTEGER NOT NULL REFERENCES contacts(contact_id) ON DELETE CASCADE,
    title               TEXT NOT NULL,
    summary             TEXT NOT NULL,
    action_json         TEXT,
    status              TEXT NOT NULL DEFAULT 'pending'
                        CHECK (status IN ('pending','approved','rejected','expired','failed','cancelled')),
    card_id             TEXT,
    created_at_ms       INTEGER NOT NULL,
    expires_at_ms       INTEGER NOT NULL,
    decided_at_ms       INTEGER,
    decision_source     TEXT
);

-- Trigger idempotency: a request_id is honoured once per token for seven days.
-- The cached response is the same JSON the caller received, so a retry cannot
-- create a second card.
CREATE TABLE IF NOT EXISTS workflow_triggers (
    request_key         TEXT PRIMARY KEY,
    token_id            TEXT NOT NULL,
    response_json       TEXT NOT NULL,
    status_code         INTEGER NOT NULL,
    created_at_ms       INTEGER NOT NULL
);

-- ───────────────────────── DAV endpoints ────────────────────────────────
-- One row per connector. `password` is a DAV app password, never a user's
-- primary password; the console returns only `password_set`. `field_allowlist`
-- is the CardDAV allowlist JSON; CalDAV leaves it empty because it never returns
-- an event field.
CREATE TABLE IF NOT EXISTS dav_endpoints (
    connector           TEXT PRIMARY KEY CHECK (connector IN ('carddav','caldav')),
    url                 TEXT NOT NULL,
    username            TEXT NOT NULL DEFAULT '',
    password            TEXT NOT NULL DEFAULT '',
    allow_private       INTEGER NOT NULL DEFAULT 0,
    field_allowlist     TEXT NOT NULL DEFAULT '',
    updated_at_ms       INTEGER NOT NULL,
    last_probe_ms       INTEGER,
    last_probe_status   INTEGER,
    last_probe_error    TEXT
);
"""


class Database:
    """Thread-safe handle on the gateway's SQLite file."""

    def __init__(self, path: Path, timeout_seconds: float = 10.0) -> None:
        self.path = Path(path)
        self.timeout_seconds = timeout_seconds
        self._local = threading.local()
        self._bootstrap_lock = threading.Lock()
        self._bootstrapped = False

    # ── connection management ───────────────────────────────────────────────

    def connection(self) -> sqlite3.Connection:
        """This thread's connection, opened on first use.

        ``check_same_thread`` is left at its default ``True`` on purpose: the
        thread-local dict already guarantees one handle per thread, and turning
        the check off would mean a genuine cross-thread misuse becomes a
        corrupt-transaction bug instead of the loud exception that names it.
        """
        existing = getattr(self._local, "conn", None)
        if existing is not None:
            return existing

        self.path.parent.mkdir(parents=True, exist_ok=True)
        fresh = not self.path.exists()
        conn = sqlite3.connect(str(self.path), timeout=self.timeout_seconds, isolation_level=None)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        # Per-connection, not persisted: without this the FK clauses in the
        # schema are comments.
        conn.execute("PRAGMA foreign_keys=ON")
        conn.execute("PRAGMA busy_timeout=%d" % int(self.timeout_seconds * 1000))
        # NORMAL rather than FULL: WAL+NORMAL survives a process crash and only
        # risks the last commit on a *power* loss. A service account that fsyncs
        # every ledger row spends most of its wall clock in the kernel, and the
        # rows it would lose on a hard reset are the ones in the last second —
        # which the outbox table already re-delivers from.
        conn.execute("PRAGMA synchronous=NORMAL")
        conn.execute("PRAGMA temp_store=MEMORY")

        if fresh:
            # The file holds pairwise session secrets and channel private keys.
            # SQLite creates it 0644 under a permissive umask, and on a shared
            # merchant host that is every other account on the box.
            try:
                os.chmod(self.path, 0o600)
            except OSError:
                pass

        self._local.conn = conn
        self._ensure_bootstrapped(conn)
        return conn

    def close(self) -> None:
        conn = getattr(self._local, "conn", None)
        if conn is not None:
            conn.close()
            self._local.conn = None

    def close_all(self) -> None:
        """Close only *this* thread's handle; other threads own theirs."""
        self.close()

    # ── schema ──────────────────────────────────────────────────────────────

    def _ensure_bootstrapped(self, conn: sqlite3.Connection) -> None:
        if self._bootstrapped:
            return
        with self._bootstrap_lock:
            if self._bootstrapped:
                return
            # `executescript` implicitly COMMITs the transaction it is handed
            # before running the script, so a BEGIN around it is not protection
            # but a bug: the COMMIT afterwards fails with "no transaction is
            # active" and the rollback in the except branch fails too, hiding
            # the real error. The DDL is therefore run on its own (every
            # statement is CREATE IF NOT EXISTS, so partial application is not
            # a state that needs rolling back) and only the version bookkeeping
            # gets a transaction.
            conn.executescript(_DDL)
            version = int(conn.execute("PRAGMA user_version").fetchone()[0])
            if version == 0:
                conn.execute("BEGIN IMMEDIATE")
                conn.execute("PRAGMA user_version=%d" % SCHEMA_VERSION)
                conn.execute("COMMIT")
            elif version > SCHEMA_VERSION:
                # A newer gateway already touched this file. Refusing is the
                # only honest answer: rolling the schema backwards would drop
                # columns the other process is still writing.
                raise RuntimeError(
                    "%s was written by a newer gateway (schema v%d > v%d); refusing to open it"
                    % (self.path, version, SCHEMA_VERSION)
                )
            self._bootstrapped = True

    # ── queries ─────────────────────────────────────────────────────────────

    def query(self, sql: str, params: Sequence[Any] = ()) -> List[sqlite3.Row]:
        return self.connection().execute(sql, tuple(params)).fetchall()

    def query_one(self, sql: str, params: Sequence[Any] = ()) -> Optional[sqlite3.Row]:
        return self.connection().execute(sql, tuple(params)).fetchone()

    def scalar(self, sql: str, params: Sequence[Any] = (), default: Any = None) -> Any:
        row = self.query_one(sql, params)
        if row is None or len(row) == 0:
            return default
        return row[0]

    def execute(self, sql: str, params: Sequence[Any] = ()) -> int:
        """Run one statement: the new row's id for an INSERT, affected rows otherwise.

        ``cursor.lastrowid`` must not be a fallback for a write, because SQLite
        leaves it at the value of the *previous* statement when this one changes no
        rows: an ``UPDATE … WHERE`` that matched nothing reports 1, and 1 is exactly
        what an outbox claim or a revoke reads as "I won". ``rowcount`` is the only
        honest answer for a write, so the verb decides which number to trust.
        """
        keyword = sql.lstrip().split(None, 1)[0].upper() if sql.strip() else ""
        cursor = self.connection().execute(sql, tuple(params))
        if keyword in ("INSERT", "REPLACE"):
            return int(cursor.lastrowid or 0)
        return int(cursor.rowcount) if cursor.rowcount > 0 else 0

    def execute_many(self, sql: str, seq: Sequence[Sequence[Any]]) -> int:
        return self.connection().executemany(sql, tuple(tuple(s) for s in seq)).rowcount

    @contextmanager
    def transaction(self, immediate: bool = True) -> Iterator[sqlite3.Connection]:
        """A real transaction; commits on clean exit, rolls back on anything else.

        ``immediate`` takes the write lock at ``BEGIN`` instead of at the first
        write, which is what makes a read-modify-write sequence atomic. Pass
        ``immediate=False`` only for a transaction that cannot write.
        """
        conn = self.connection()
        if conn.in_transaction:
            # Nested: hand the caller the same connection without a second
            # BEGIN, which sqlite would reject mid-transaction. The outer frame
            # still owns the commit.
            yield conn
            return
        conn.execute("BEGIN IMMEDIATE" if immediate else "BEGIN")
        try:
            yield conn
        except BaseException:
            conn.execute("ROLLBACK")
            raise
        conn.execute("COMMIT")

    # ── convenience: settings ───────────────────────────────────────────────

    def get_setting(self, key: str, default: Any = None) -> Any:
        import json

        row = self.query_one("SELECT value_json FROM settings WHERE key = ?", (key,))
        if row is None:
            return default
        try:
            return json.loads(row["value_json"])
        except ValueError:
            return default

    def set_setting(self, key: str, value: Any) -> None:
        import json

        self.execute(
            "INSERT INTO settings (key, value_json, updated_at_ms) VALUES (?,?,?) "
            "ON CONFLICT(key) DO UPDATE SET value_json = excluded.value_json, updated_at_ms = excluded.updated_at_ms",
            (key, json.dumps(value, ensure_ascii=False, separators=(",", ":")), now_ms()),
        )

    # ── diagnostics ─────────────────────────────────────────────────────────

    def integrity_report(self) -> Dict[str, Any]:
        """Cheap health facts for ``/healthz`` — sizes and PRAGMA, never rows."""
        conn = self.connection()
        counts: Dict[str, int] = {}
        for table in ("contacts", "eco_sessions", "cards", "channels", "vouchers", "outbox", "sso_sessions"):
            counts[table] = int(conn.execute("SELECT COUNT(*) FROM %s" % table).fetchone()[0])  # noqa: S608 - fixed names
        # `PRAGMA wal_checkpoint(PASSIVE)` answers (busy, log, checkpointed):
        # the useful number is the frames still in the log, which is the third
        # column subtracted from the second, not either one alone.
        busy, log_frames, checkpointed = conn.execute("PRAGMA wal_checkpoint(PASSIVE)").fetchone()
        return {
            "db_bytes": self.path.stat().st_size if self.path.exists() else 0,
            "journal_mode": conn.execute("PRAGMA journal_mode").fetchone()[0],
            "schema_version": int(conn.execute("PRAGMA user_version").fetchone()[0]),
            "wal_uncheckpointed_frames": max(0, int(log_frames or 0) - int(checkpointed or 0)),
            "wal_checkpoint_busy": bool(busy),
            "rows": counts,
        }

    def table_sizes(self) -> List[Tuple[str, int]]:
        rows = self.query("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name")
        return [(r["name"], int(self.connection().execute("SELECT COUNT(*) FROM %s" % r["name"]).fetchone()[0])) for r in rows]  # noqa: S608 - fixed names


# ───────────────────────────────── self-test ────────────────────────────────


def self_test() -> List[str]:
    """The store itself: pragmas, thread ownership, transactions, constraints.

    This is the layer everything else inherits, so the suite checks the four
    properties the rest of the gateway assumes without asking: that a connection
    belongs to exactly one thread, that a transaction really is atomic, that the
    foreign keys in the DDL are enforced rather than decorative, and that a file
    written by a *newer* gateway is refused instead of downgraded underneath it.

    Returns the list of passed check names and raises :class:`AssertionError` on
    the first failure, so a caller cannot mistake a half-run suite for a green one.
    """
    import json
    import os
    import re
    import shutil
    import stat
    import tempfile
    import threading
    import time

    checks: List[str] = []
    tmp = Path(tempfile.mkdtemp(prefix="popopx-db-selftest-")).resolve()
    seq = [0]

    def credit(name: str) -> None:
        if name in checks:
            raise AssertionError("database self_test: %r is credited twice — a name must carry exactly one assertion" % name)
        checks.append(name)

    def check(name: str, condition: bool) -> None:
        if not condition:
            raise AssertionError("database self_test failed: %s" % name)
        credit(name)

    def fails(name: str, expected, call):
        try:
            call()
        except expected as exc:
            credit(name)
            return exc
        except Exception as exc:  # noqa: BLE001
            raise AssertionError("database self_test: %s raised %s (%s), expected %s" % (name, type(exc).__name__, exc, expected.__name__)) from exc
        raise AssertionError("database self_test: %s did not raise %s" % (name, expected.__name__))

    def new_db(timeout_seconds: float = 10.0, name: Optional[str] = None) -> Database:
        seq[0] += 1
        return Database(tmp / (name or "gateway-%d.sqlite3" % seq[0]), timeout_seconds=timeout_seconds)

    def touch_contact(db: Database, contact_id: int) -> None:
        db.execute("INSERT INTO contacts (contact_id, first_seen_ms, last_seen_ms) VALUES (?,?,?)", (contact_id, now_ms(), now_ms()))

    # ── 1. opening the file, and what the pragmas are then ──────────────────
    db = new_db()
    deep = Database(tmp / "nested" / "deeper" / "gateway.sqlite3")
    check("constructing_a_handle_touches_nothing", not db.path.exists() and not deep.path.exists() and not deep.path.parent.exists())
    conn = db.connection()
    check("the_parent_directory_is_created_on_first_use", db.path.is_file() and db.path.parent.is_dir())
    check("a_missing_parent_chain_is_made_not_blamed", deep.connection() is not None and deep.path.is_file() and deep.path.parent.is_dir())
    deep.close()
    check("a_fresh_store_is_owner_only", stat.S_IMODE(os.stat(db.path).st_mode) == 0o600)
    check("the_journal_is_wal", conn.execute("PRAGMA journal_mode").fetchone()[0] == "wal")
    check("foreign_keys_are_on_for_this_connection", conn.execute("PRAGMA foreign_keys").fetchone()[0] == 1)
    check("synchronous_is_normal_not_full", conn.execute("PRAGMA synchronous").fetchone()[0] == 1)
    check("temp_store_is_memory", conn.execute("PRAGMA temp_store").fetchone()[0] == 2)
    check("the_busy_timeout_follows_the_constructor", conn.execute("PRAGMA busy_timeout").fetchone()[0] == 10000)
    check("a_short_timeout_is_a_short_busy_wait", new_db(timeout_seconds=0.2).connection().execute("PRAGMA busy_timeout").fetchone()[0] == 200)
    check("autocommit_is_off_so_transactions_are_explicit", conn.isolation_level is None)
    check("rows_are_reachable_by_name", db.query_one("SELECT 1 AS one").keys() == ["one"] and db.query_one("SELECT 1 AS one")["one"] == 1)
    check("the_schema_version_is_recorded_in_the_file", conn.execute("PRAGMA user_version").fetchone()[0] == SCHEMA_VERSION)
    check("a_write_lands_in_the_wal_sidecar", db.execute("INSERT INTO settings (key, value_json, updated_at_ms) VALUES ('probe','1',1)") > 0 and (Path(str(db.path) + "-wal")).exists())
    db.close()

    # ── 2. the DDL is the schema: nothing less, nothing more ────────────────
    declared = sorted(re.findall(r"CREATE TABLE IF NOT EXISTS (\w+)", _DDL))
    present = sorted(name for name, _rows in new_db().table_sizes())
    check("every_declared_table_exists", len(declared) >= 20 and declared == present)
    check("no_undeclared_table_slipped_into_the_schema", set(present) - set(declared) == set())
    twice = new_db()
    twice.connection().executescript(_DDL)
    touch_contact(twice, 11)
    twice.connection().executescript(_DDL)
    check("re_running_the_ddl_keeps_the_rows", twice.scalar("SELECT COUNT(*) FROM contacts") == 1)
    check("re_running_the_ddl_keeps_the_version", twice.connection().execute("PRAGMA user_version").fetchone()[0] == SCHEMA_VERSION)
    corrupt = tmp / "not-a-database.sqlite3"
    corrupt.write_bytes(b"this is a text file, not a SQLite database\n")
    corrupt.chmod(0o600)
    fails("a_file_that_is_not_a_database_is_refused", sqlite3.DatabaseError, lambda: Database(corrupt).connection())

    # ── 3. one connection per thread, and loudly so ─────────────────────────
    main_conn = db.connection()
    main_id = id(main_conn)
    check("the_same_thread_gets_the_same_handle", db.connection() is main_conn)
    handle_ids: List[int] = []
    errors: List[str] = []

    def worker() -> None:
        try:
            other = db.connection()
            handle_ids.append(id(other))
            if other is main_conn:
                errors.append("a thread was handed another thread's connection")
        except Exception as exc:  # noqa: BLE001
            errors.append("%s: %s" % (type(exc).__name__, exc))

    threads = [threading.Thread(target=worker) for _ in range(4)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    check("four_threads_opened_four_connections", errors == [] and len(set(handle_ids)) == 4 and all(value != main_id for value in handle_ids))
    crossed: List[str] = []

    def cross_use() -> None:
        try:
            main_conn.execute("SELECT 1")
            crossed.append("no exception")
        except sqlite3.ProgrammingError as exc:
            crossed.append(str(exc))

    other_thread = threading.Thread(target=cross_use)
    other_thread.start()
    other_thread.join()
    check("crossing_threads_with_a_handle_is_a_loud_error", crossed != [] and crossed[0] != "no exception" and "created in a thread" in crossed[0])
    check("close_all_releases_only_the_calling_thread", db.close_all() is None and db.connection() is not main_conn and db.connection() is db.connection())
    check("a_closed_handle_reopens_transparently", db.scalar("SELECT 1") == 1)
    main_conn_again = db.connection()
    reopened_in_thread: List[Any] = []

    def reopen_in_thread() -> None:
        try:
            db.close()
            reopened_in_thread.append(db.connection())
        except Exception as exc:  # noqa: BLE001
            reopened_in_thread.append(exc)

    thread = threading.Thread(target=reopen_in_thread)
    thread.start()
    thread.join()
    check("closing_from_another_thread_moves_that_threads_handle_only", len(reopened_in_thread) == 1 and not isinstance(reopened_in_thread[0], Exception) and reopened_in_thread[0] is not main_conn_again and db.connection() is main_conn_again)

    # ── 4. transactions: what commits, what does not ────────────────────────
    def write_in_transaction(handle: Database, key: str, value_json: str, error: Optional[BaseException] = None) -> None:
        """One transaction that writes ``key``, then raises ``error`` if given.

        Raising *inside* the block is the test: whatever escapes the ``with`` has
        to leave no trace, and the promise this module makes is about any
        :class:`BaseException`, not only the ones a caller thinks to catch.
        """
        with handle.transaction():
            handle.execute("INSERT INTO settings (key, value_json, updated_at_ms) VALUES (?,?,?)", (key, value_json, now_ms()))
            if error is not None:
                raise error

    tx = new_db()
    touch_contact(tx, 101)
    write_in_transaction(tx, "committed", '"yes"')
    check("a_clean_block_commits", tx.get_setting("committed") == "yes")
    fails("an_exception_rolls_the_block_back", ValueError, lambda: write_in_transaction(tx, "rolledback", '"no"', ValueError("the operator hit ctrl-c mid-write")))
    check("the_rolled_back_write_is_absent", tx.get_setting("rolledback", default="ABSENT") == "ABSENT")
    check("the_earlier_commit_survived_the_rollback", tx.get_setting("committed") == "yes")
    check("the_connection_is_usable_after_a_rollback", tx.scalar("SELECT COUNT(*) FROM settings") == 1)
    fails("a_base_exception_also_rolls_back", KeyboardInterrupt, lambda: write_in_transaction(tx, "interrupted", '"no"', KeyboardInterrupt()))
    check("the_interrupted_write_is_absent", tx.get_setting("interrupted", default="ABSENT") == "ABSENT" and tx.scalar("SELECT COUNT(*) FROM settings") == 1)
    check("no_transaction_is_left_open_after_the_interrupt", not tx.connection().in_transaction)

    # A nested frame *is* the outer transaction, so the only way to learn whether
    # it committed early is to look from a connection that is not inside it.
    viewer = Database(tx.path, timeout_seconds=1.0)
    viewer.connection()
    with tx.transaction():
        tx.execute("INSERT INTO settings (key, value_json, updated_at_ms) VALUES ('outer','1',1)")
        with tx.transaction() as inner_conn:
            inner_conn.execute("INSERT INTO settings (key, value_json, updated_at_ms) VALUES ('inner','2',1)")
        check("a_nested_frame_does_not_commit_early", viewer.get_setting("inner", default="ABSENT") == "ABSENT" and viewer.get_setting("outer", default="ABSENT") == "ABSENT")
    check("the_outer_commit_took_both_frames", tx.get_setting("inner") == 2 and tx.get_setting("outer") == 1)
    check("a_second_connection_sees_the_committed_pair", viewer.get_setting("inner") == 2 and viewer.get_setting("outer") == 1)
    viewer.close()
    with tx.transaction(immediate=False) as lazy:
        lazy.execute("INSERT INTO settings (key, value_json, updated_at_ms) VALUES ('deferred','3',1)")
    check("a_deferred_transaction_still_upgrades_to_a_write", tx.get_setting("deferred") == 3)
    refused = _blocked_writer(tx, 0.2)
    check("a_second_writer_on_a_held_lock_is_refused", any("locked" in line.lower() for line in refused))
    check("the_loser_wrote_nothing", tx.get_setting("blocked", default="ABSENT") == "ABSENT")
    check("the_winner_still_committed", tx.get_setting("holder") == 1)

    # ── 5. the constraints in the DDL are enforced, not comments ────────────
    fk = new_db()
    touch_contact(fk, 7)
    fails("a_session_for_a_missing_contact_is_refused", sqlite3.IntegrityError, lambda: fk.execute("INSERT INTO eco_sessions (pairwise_uid, contact_id, service_id, secret_hex, created_at_ms) VALUES ('p-missing',999,'popopx.official',?,?)", ("ab" * 16, now_ms())))
    fk.execute("INSERT INTO eco_sessions (pairwise_uid, contact_id, service_id, secret_hex, created_at_ms) VALUES ('p-one',7,'popopx.official',?,?)", ("ab" * 16, now_ms()))
    check("a_session_for_a_real_contact_is_accepted", fk.scalar("SELECT COUNT(*) FROM eco_sessions") == 1)
    check("deleting_the_contact_cascades_to_the_session", fk.execute("DELETE FROM contacts WHERE contact_id=7") == 1 and fk.scalar("SELECT COUNT(*) FROM eco_sessions") == 0)
    fails("one_service_identity_row_only", sqlite3.IntegrityError, lambda: fk.execute("INSERT INTO service_identity (id, service_id, display_name, created_at_ms, updated_at_ms) VALUES (2,'popopx.official','x',1,1)"))
    fk.execute("INSERT INTO service_identity (id, service_id, display_name, created_at_ms, updated_at_ms) VALUES (1,'popopx.official','POPOPX',1,1)")
    fails("a_second_identity_row_is_refused_by_the_primary_key", sqlite3.IntegrityError, lambda: fk.execute("INSERT INTO service_identity (id, service_id, display_name, created_at_ms, updated_at_ms) VALUES (1,'popopx.official','again',2,2)"))
    fails("an_identity_without_a_display_name_is_refused", sqlite3.IntegrityError, lambda: fk.execute("INSERT INTO service_identity (id, service_id, created_at_ms, updated_at_ms) VALUES (1,'popopx.official',3,3)"))
    touch_contact(fk, 8)
    fk.execute("INSERT INTO eco_sessions (pairwise_uid, contact_id, service_id, secret_hex, created_at_ms) VALUES ('p-two',8,'popopx.official',?,?)", ("cd" * 16, now_ms()))
    fails("the_same_secret_for_one_contact_is_a_conflict", sqlite3.IntegrityError, lambda: fk.execute("INSERT INTO eco_sessions (pairwise_uid, contact_id, service_id, secret_hex, created_at_ms) VALUES ('p-three',8,'popopx.official',?,?)", ("cd" * 16, now_ms())))
    touch_contact(fk, 9)
    # Contact 9 exists and `ef`… is a fresh secret for it, so the only rule the
    # next insert can break is the primary key on `pairwise_uid` — which is the
    # one being named. (A refusal that a foreign key would have raised anyway
    # would prove nothing about it.)
    fails("a_pairwise_uid_is_taken_once", sqlite3.IntegrityError, lambda: fk.execute("INSERT INTO eco_sessions (pairwise_uid, contact_id, service_id, secret_hex, created_at_ms) VALUES ('p-two',9,'popopx.official',?,?)", ("ab" * 16, now_ms())))
    fk.execute("INSERT INTO eco_sessions (pairwise_uid, contact_id, service_id, secret_hex, created_at_ms) VALUES ('p-four',9,'popopx.official',?,?)", ("ef" * 16, now_ms()))
    check("a_contact_may_hold_a_secret_another_contact_already_has", fk.scalar("SELECT COUNT(*) FROM eco_sessions WHERE contact_id=9") == 1)

    # ── 6. the verbs decide which number is trustworthy ─────────────────────
    ex = new_db()
    touch_contact(ex, 21)
    first_id = ex.execute("INSERT INTO contacts (contact_id, first_seen_ms, last_seen_ms) VALUES (22,1,1)")
    check("an_insert_answers_with_the_row_id", first_id == 22)
    check("an_insert_without_an_explicit_id_answers_with_the_new_rowid", ex.execute("INSERT INTO settings (key, value_json, updated_at_ms) VALUES ('rid','1',1)") > 0)
    check("a_lowercase_verb_is_still_a_verb", ex.execute("insert into settings (key, value_json, updated_at_ms) values ('lower','1',1)") > 0)
    check("a_leading_newline_does_not_hide_the_verb", ex.execute("\nINSERT INTO settings (key, value_json, updated_at_ms) VALUES ('nl','1',1)") > 0)
    check("an_update_that_matched_nothing_is_zero_not_one", ex.execute("UPDATE contacts SET blocked=1 WHERE contact_id=999") == 0)
    check("an_update_that_matched_is_the_row_count", ex.execute("UPDATE contacts SET blocked=1 WHERE contact_id=21") == 1)
    check("a_delete_reports_what_it_removed", ex.execute("DELETE FROM contacts WHERE contact_id=22") == 1)
    check("a_delete_of_nothing_is_zero", ex.execute("DELETE FROM contacts WHERE contact_id=22") == 0)
    check("a_read_through_execute_reports_nothing", ex.execute("SELECT 1") == 0)
    check("a_replace_reports_the_row_id", ex.execute("REPLACE INTO settings (key, value_json, updated_at_ms) VALUES ('rid','2',2)") > 0)
    inserted = ex.execute_many("INSERT INTO contacts (contact_id, first_seen_ms, last_seen_ms) VALUES (?,?,?)", [(31, 1, 1), (32, 1, 1), (33, 1, 1)])
    check("execute_many_reports_the_rows_it_touched", inserted == 3 and ex.scalar("SELECT COUNT(*) FROM contacts WHERE contact_id IN (31,32,33)") == 3)
    check("a_query_returns_rows_not_cursors", len(ex.query("SELECT contact_id FROM contacts")) == 4 and ex.query("SELECT contact_id FROM contacts")[0]["contact_id"] in (21, 31, 32, 33))
    check("a_list_of_params_is_accepted", ex.query_one("SELECT ? AS v", ["x"])["v"] == "x")
    check("query_one_of_no_rows_is_none", ex.query_one("SELECT 1 WHERE 0") is None)
    check("scalar_of_no_rows_is_the_default", ex.scalar("SELECT 1 WHERE 0", default="fallback") == "fallback")
    check("scalar_of_a_null_column_is_null_not_the_default", ex.scalar("SELECT NULL", default="fallback") is None)
    check("scalar_without_a_default_is_none", ex.scalar("SELECT 1 WHERE 0") is None)

    # ── 7. settings: JSON in one column, and what a bad row does ────────────
    st = new_db()
    for value in ({"a": [1, 2, "三"]}, [1, "two", None], 7, "text", True, None, 0.5):
        st.set_setting("probe", value)
        # The default is a sentinel, never ``None``: a read that fell through to
        # a missing row would otherwise answer ``None`` and agree with a stored
        # ``None``, and the round trip would be a tautology.
        check("a_%s_round_trips_through_the_settings_column" % type(value).__name__, st.get_setting("probe", default="ABSENT") == value)
    st.set_setting("cjk", "POPOPX 服务号")
    check("the_stored_json_is_not_backslash_escaped", st.scalar("SELECT value_json FROM settings WHERE key='cjk'") == '"POPOPX 服务号"')
    st.set_setting("cjk", "changed")
    check("setting_a_key_twice_updates_one_row", st.scalar("SELECT COUNT(*) FROM settings WHERE key='cjk'") == 1 and st.get_setting("cjk") == "changed")
    check("the_stamp_on_a_written_key_is_the_millisecond_clock", abs(int(st.scalar("SELECT updated_at_ms FROM settings WHERE key='cjk'")) - now_ms()) < 5000)
    st.execute("INSERT INTO settings (key, value_json, updated_at_ms) VALUES ('broken','{not json',1)")
    check("an_undecodable_row_answers_the_default_not_an_error", st.get_setting("broken", default="shrug") == "shrug")
    check("a_missing_key_answers_the_default", st.get_setting("never-set", default=42) == 42)
    check("a_missing_key_without_a_default_is_none", st.get_setting("never-set") is None)

    # ── 8. durability, versions and what a stranger file means ──────────────
    dur = new_db(name="durable.sqlite3")
    touch_contact(dur, 77)
    dur.set_setting("survives", "yes")
    schema_before = dur.connection().execute("PRAGMA schema_version").fetchone()[0]
    reopened = Database(dur.path)
    check("a_reopen_sees_the_rows", reopened.scalar("SELECT COUNT(*) FROM contacts WHERE contact_id=77") == 1 and reopened.get_setting("survives") == "yes")
    check("a_reopen_leaves_the_schema_alone", reopened.connection().execute("PRAGMA schema_version").fetchone()[0] == schema_before)
    check("a_reopen_keeps_the_version", reopened.connection().execute("PRAGMA user_version").fetchone()[0] == SCHEMA_VERSION)
    reopened.close()
    ahead = new_db(name="ahead.sqlite3")
    touch_contact(ahead, 5)
    ahead_rows = ahead.scalar("SELECT COUNT(*) FROM contacts")
    ahead.close()
    _set_user_version(ahead.path, SCHEMA_VERSION + 1)
    refusal = fails("a_schema_from_a_newer_gateway_is_refused", RuntimeError, lambda: Database(ahead.path).connection())
    check("the_refusal_says_which_way_is_newer", "newer gateway" in str(refusal) and str(SCHEMA_VERSION) in str(refusal) and str(SCHEMA_VERSION + 1) in str(refusal))
    check("the_newer_file_was_not_touched", _user_version(ahead.path) == SCHEMA_VERSION + 1)
    check("the_newer_file_kept_its_rows", _rows_of(ahead.path, "contacts") == ahead_rows)
    same_version = new_db(name="sameversion.sqlite3")
    same_version.close()
    _set_user_version(same_version.path, SCHEMA_VERSION)
    check("an_equal_version_reopens_quietly", Database(same_version.path).scalar("SELECT COUNT(*) FROM contacts") == 0)
    zeroed = new_db(name="zeroed.sqlite3")
    zeroed.close()
    _set_user_version(zeroed.path, 0)
    stamped = sqlite3.connect(str(zeroed.path), isolation_level=None)
    stamped.execute("CREATE TABLE only_upstream_has_this (a)")
    stamped.close()
    revived = Database(zeroed.path)
    revived.connection()
    check("a_file_with_no_version_recorded_is_bookmarked", _user_version(zeroed.path) == SCHEMA_VERSION)
    check("bookmarking_a_partial_file_keeps_its_tables", revived.scalar("SELECT COUNT(*) FROM only_upstream_has_this") == 0 and revived.scalar("SELECT COUNT(*) FROM contacts") == 0)
    check("the_bootstrap_runs_once_per_handle_not_per_query", revived._bootstrapped is True and revived.connection() is revived.connection() and Database(zeroed.path)._bootstrapped is False)
    revived.close()

    # ── 9. the health report, which is the only thing /healthz prints ───────
    rep = new_db()
    touch_contact(rep, 91)
    rep.set_setting("secret_probe", "SENTINEL-IN-A-ROW")
    report = rep.integrity_report()
    check("the_report_has_a_fixed_shape", set(report) == {"db_bytes", "journal_mode", "schema_version", "wal_uncheckpointed_frames", "wal_checkpoint_busy", "rows"})
    check("the_report_reads_the_pragmas_it_claims", report["journal_mode"] == "wal" and report["schema_version"] == SCHEMA_VERSION)
    check("the_report_counts_every_named_table", set(report["rows"]) == {"contacts", "eco_sessions", "cards", "channels", "vouchers", "outbox", "sso_sessions"} and report["rows"]["contacts"] == 1)
    check("the_row_counts_agree_with_the_table_sizes", dict(rep.table_sizes())["contacts"] == report["rows"]["contacts"])
    check("the_report_carries_numbers_and_flags_only", all(isinstance(value, (int, str, bool)) for key, value in report.items() if key != "rows") and all(isinstance(count, int) for count in report["rows"].values()) and isinstance(report["rows"], dict))
    check("no_row_of_data_is_in_the_report", "SENTINEL-IN-A-ROW" not in json.dumps(report) and "value_json" not in json.dumps(report))
    check("the_file_size_in_the_report_is_the_real_one", report["db_bytes"] == rep.path.stat().st_size and report["db_bytes"] > 0)
    check("the_uncheckpointed_frame_count_is_never_negative", report["wal_uncheckpointed_frames"] >= 0 and isinstance(report["wal_checkpoint_busy"], bool))
    check("the_report_is_cheap_and_repeatable", rep.integrity_report()["rows"] == report["rows"])
    check("now_ms_is_epoch_milliseconds", abs(now_ms() - int(time.time() * 1000)) < 2000 and len(str(now_ms())) == 13)

    shutil.rmtree(tmp, ignore_errors=True)
    return checks


def _blocked_writer(handle: Database, timeout_seconds: float) -> List[str]:
    """Try to start a second write transaction while ``handle`` holds one; report what came back.

    A *second* :class:`Database` is the point — one handle would reuse the same
    connection and prove nothing about the write lock. The other connection is
    opened before the outer transaction begins, because opening one bootstraps a
    schema, and bootstrap under a held lock is a different question from the one
    this answers.
    """
    other = Database(handle.path, timeout_seconds=timeout_seconds)
    other.connection()
    refused: List[str] = []
    try:
        with handle.transaction():
            handle.execute("INSERT INTO settings (key, value_json, updated_at_ms) VALUES ('holder','1',1)")
            try:
                with other.transaction():
                    other.execute("INSERT INTO settings (key, value_json, updated_at_ms) VALUES ('blocked','1',1)")
            except sqlite3.OperationalError as exc:
                refused.append(str(exc))
    finally:
        other.close()
    return refused


def _raw(path: Path) -> sqlite3.Connection:
    """A connection outside the :class:`Database` abstraction, for reading or rewriting what a gateway left behind.

    The version-number cases below have to be staged by something that is *not*
    this module — a file written by a different build is exactly the situation
    being tested — and ``isolation_level=None`` keeps SQLite in autocommit so a
    ``PRAGMA user_version`` lands without a transaction the fixture has to remember.
    """
    return sqlite3.connect(str(path), isolation_level=None)


def _set_user_version(path: Path, version: int) -> None:
    conn = _raw(path)
    conn.execute("PRAGMA user_version=%d" % int(version))
    conn.close()


def _user_version(path: Path) -> int:
    conn = _raw(path)
    try:
        return int(conn.execute("PRAGMA user_version").fetchone()[0])
    finally:
        conn.close()


def _rows_of(path: Path, table: str) -> int:
    conn = _raw(path)
    try:
        return int(conn.execute("SELECT COUNT(*) FROM %s" % table).fetchone()[0])  # noqa: S608 - fixed names
    finally:
        conn.close()
