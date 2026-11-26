# Copyright (c) 2026 POPOPX (popopx.chat)
# SPDX-License-Identifier: AGPL-3.0-only
"""Encryption at rest for the secrets the gateway itself has to keep.

The gateway is not zero-knowledge towards the machine it runs on: it holds the
pairwise session secrets, the channel identity private keys, every epoch key, the
per-subscription outbound signing keys and the DAV app passwords. This module is
the one place that turns those values into ciphertext before they reach SQLite,
and back again on the way out.

The key is ``POPOPX_VAULT_KEY`` and it belongs to the operator. It is *not*
derived from ``POPOPX_ADMIN_TOKEN``: rotating the console token must not make
every stored channel key unreadable, and an operator who keeps the vault key
off the gateway host can hand it over for one migration run and take it away
again.

Three properties are deliberate:

* **Mixed reads.** A value without the ``vault1:`` prefix is returned verbatim.
  A deployment that enables the key starts from a database written in
  plaintext, and refusing to read it would mean an upgrade required downtime.
  ``python3 -m app.main --migrate-secrets`` is the explicit, idempotent step
  that rewrites the existing rows.
* **Bound ciphertext.** The AAD names the table, the column and the row's own
  id, so a ciphertext copied from one row into another does not decrypt. Without
  it, an attacker with write access to the database could swap a channel's
  stored identity key for another channel's and have the gateway sign rotations
  with the wrong issuer.
* **Loud failure.** A ``vault1:`` value with no key configured — or with the
  wrong key — raises :class:`VaultError`. Returning the ciphertext as if it were
  the secret would make a session HMAC fail with a generic 401 and a channel
  rotation fail with an unreadable key, neither of which points at the vault.

The ``cryptography`` wheel is imported lazily, exactly like ``crypto_service``:
this module's self-test runs on a checkout that has no wheels yet, and the
deployment that has *not* configured a key must not need one.
"""

from __future__ import annotations

import base64
import binascii
import os
import re
import threading
from typing import Any, Dict, Iterable, List, Mapping, Optional, Tuple

__all__ = [
    "MIGRATION_TARGETS",
    "SecretBox",
    "VAULT_PREFIX",
    "VaultError",
    "VaultUnavailable",
    "is_sealed",
    "migrate_secrets",
    "parse_vault_key",
    "vault_for",
]

VAULT_PREFIX = "vault1:"
_KEY_BYTES = 32
_NONCE_BYTES = 12
_HKDF_SALT = b"popopx.vault.hkdf.v1"
_HKDF_INFO = b"popopx.vault.chacha20poly1305.v1"
_AAD_PREFIX = b"popopx.vault.v1"


class VaultError(RuntimeError):
    """A stored value cannot be read as the secret it is supposed to be."""


class VaultUnavailable(VaultError):
    """The vault is configured but the cryptography wheel is not installed."""


def _b64_url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _decode_key_text(text: str) -> List[bytes]:
    """Every reading of ``text`` that could be a 32-byte key.

    Both alphabets are tried and the one yielding 32 bytes wins: a 64-character
    hex key is also legal base64 and decodes to 48 bytes, so trying base64 first
    and falling back only on a decode *error* would reject a valid hex key.
    """
    candidate = re.sub(r"\s+", "", str(text or ""))
    if not candidate:
        return []
    readings: List[bytes] = []
    padded = candidate + "=" * (-len(candidate) % 4)
    for altchars in (None, b"-_"):
        try:
            readings.append(base64.b64decode(padded, altchars=altchars, validate=True))
        except (binascii.Error, ValueError):
            pass
    if len(candidate) % 2 == 0:
        try:
            readings.append(bytes.fromhex(candidate))
        except ValueError:
            pass
    return readings


def parse_vault_key(raw: Any) -> bytes:
    """The 32 raw key bytes named by ``POPOPX_VAULT_KEY``.

    Raises ``ValueError`` with an operator-readable reason. The config loader
    calls this at boot so a typo is a refusal to start, not a vault that silently
    produces ciphertext nobody can read.
    """
    readings = _decode_key_text(str(raw or ""))
    for decoded in readings:
        if len(decoded) == _KEY_BYTES:
            return decoded
    if not readings:
        raise ValueError("POPOPX_VAULT_KEY is neither valid base64 nor valid hex")
    raise ValueError(
        "POPOPX_VAULT_KEY must decode to exactly 32 bytes, got %s — "
        "generate one with: openssl rand -hex 32" % "/".join(str(len(item)) for item in readings)
    )


def is_sealed(value: Any) -> bool:
    return isinstance(value, str) and value.startswith(VAULT_PREFIX)


class SecretBox:
    """Seal and open strings for one operator-held master key.

    An empty master disables sealing entirely: every write stays plaintext and
    every read returns what it found. That is the shipped default, because a
    gateway that refused to run without a vault key would be a gateway that
    cannot be evaluated on a laptop.
    """

    def __init__(self, master: Any = "") -> None:
        self._raw = str(master or "").strip()
        self._master = parse_vault_key(self._raw) if self._raw else None
        self._key: Optional[bytes] = None
        self._lock = threading.Lock()

    @property
    def enabled(self) -> bool:
        return self._master is not None

    def _aead_key(self) -> bytes:
        if self._master is None:
            raise VaultError("the vault is disabled; set POPOPX_VAULT_KEY to use it")
        if self._key is not None:
            return self._key
        try:
            from cryptography.hazmat.primitives import hashes
            from cryptography.hazmat.primitives.kdf.hkdf import HKDF
        except ImportError as exc:  # pragma: no cover — deployment state
            raise VaultUnavailable(
                "POPOPX_VAULT_KEY is configured but the 'cryptography' wheel is not "
                "installed; install gateway/requirements.txt before storing secrets"
            ) from exc
        with self._lock:
            if self._key is None:
                self._key = HKDF(
                    algorithm=hashes.SHA256(),
                    length=_KEY_BYTES,
                    salt=_HKDF_SALT,
                    info=_HKDF_INFO,
                ).derive(self._master)
        return self._key

    @staticmethod
    def aad(table: str, column: str, subject: Any) -> bytes:
        return _AAD_PREFIX + b"|" + str(table).encode("utf-8") + b"|" + str(column).encode("utf-8") + b"|" + str(subject).encode("utf-8")

    def seal(self, plaintext: Any, *, table: str, column: str, subject: Any) -> str:
        text = "" if plaintext is None else str(plaintext)
        if not self.enabled or not text or is_sealed(text):
            return text
        # Resolve the key first: it is where a missing wheel becomes the named
        # VaultUnavailable error rather than a bare ModuleNotFoundError.
        key = self._aead_key()
        from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

        nonce = os.urandom(_NONCE_BYTES)
        sealed = ChaCha20Poly1305(key).encrypt(nonce, text.encode("utf-8"), self.aad(table, column, subject))
        return VAULT_PREFIX + _b64_url(nonce + sealed)

    def open(self, stored: Any, *, table: str, column: str, subject: Any) -> str:
        text = "" if stored is None else str(stored)
        if not is_sealed(text):
            return text
        if not self.enabled:
            raise VaultError(
                "%s.%s holds vault ciphertext but POPOPX_VAULT_KEY is not configured"
                % (table, column)
            )
        key = self._aead_key()
        from cryptography.exceptions import InvalidTag
        from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

        raw = text[len(VAULT_PREFIX):]
        try:
            blob = base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4))
        except (binascii.Error, ValueError) as exc:
            raise VaultError("stored vault value is not valid base64") from exc
        if len(blob) <= _NONCE_BYTES:
            raise VaultError("stored vault value is too short to hold a nonce and a tag")
        nonce, ciphertext = blob[:_NONCE_BYTES], blob[_NONCE_BYTES:]
        try:
            plain = ChaCha20Poly1305(key).decrypt(nonce, ciphertext, self.aad(table, column, subject))
        except InvalidTag as exc:
            raise VaultError(
                "stored vault value in %s.%s for %r does not decrypt: wrong "
                "POPOPX_VAULT_KEY or a ciphertext moved between rows"
                % (table, column, subject)
            ) from exc
        try:
            return plain.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise VaultError("stored vault value did not decrypt to text") from exc


#: Where a plaintext secret lives today. ``subject`` is the value bound into the
#: AAD, and ``key_columns`` is the row identity used to write it back.
MIGRATION_TARGETS: Tuple[Dict[str, Any], ...] = (
    {
        "table": "eco_sessions",
        "column": "secret_hex",
        "subject": "contact_id",
        "key_columns": ("pairwise_uid",),
    },
    {
        "table": "channels",
        "column": "identity_sec_b64url",
        "subject": "channel_id",
        "key_columns": ("channel_id",),
    },
    {
        "table": "channel_epochs",
        "column": "key_b64url",
        "subject_expr": "channel_id || ':' || epoch",
        "key_columns": ("channel_id", "epoch"),
    },
    {
        "table": "workflow_subscriptions",
        "column": "secret",
        "subject": "id",
        "key_columns": ("id",),
    },
    {
        "table": "dav_endpoints",
        "column": "password",
        "subject": "connector",
        "key_columns": ("connector",),
    },
    {
        "table": "slack_discord_workspaces",
        "column": "webhook_url",
        "subject": "id",
        "key_columns": ("id",),
    },
    {
        "table": "slack_discord_workspaces",
        "column": "secret",
        "subject": "id",
        "key_columns": ("id",),
    },
)


def _row_value(row: Any, name: str) -> Any:
    try:
        return row[name]
    except (KeyError, IndexError, TypeError):
        return getattr(row, name, None)


def migrate_secrets(db: Any, box: SecretBox, *, dry_run: bool = False) -> Dict[str, Any]:
    """Seal every plaintext value named by :data:`MIGRATION_TARGETS`.

    Idempotent: a row already carrying ``vault1:`` is counted as ``skipped``.
    Empty values are left alone — several columns use ``''`` to mean "not
    configured", and encrypting an empty string would turn that sentinel into a
    truthy value. The report contains counts and table/column names only; a
    secret never appears in it.
    """
    if not box.enabled:
        raise VaultError("POPOPX_VAULT_KEY is not configured; refusing to migrate")
    report: Dict[str, Any] = {"dry_run": bool(dry_run), "tables": [], "sealed": 0, "skipped": 0, "errors": 0}
    for target in MIGRATION_TARGETS:
        table = str(target["table"])
        column = str(target["column"])
        subject_expr = str(target.get("subject_expr") or target.get("subject") or "")
        key_columns = tuple(target["key_columns"])
        rows = db.query("SELECT %s AS __subject, %s AS __value%s FROM %s" % (
            subject_expr,
            column,
            "".join(", " + name for name in key_columns),
            table,
        ))
        sealed = 0
        skipped = 0
        errors = 0
        for row in rows:
            value = _row_value(row, "__value")
            if value is None or str(value) == "":
                skipped += 1
                continue
            if is_sealed(value):
                skipped += 1
                continue
            subject = _row_value(row, "__subject")
            try:
                ciphertext = box.seal(value, table=table, column=column, subject=subject)
            except VaultError:
                errors += 1
                continue
            if not dry_run:
                where = " AND ".join("%s = ?" % name for name in key_columns)
                params = tuple(_row_value(row, name) for name in key_columns) + (str(value),)
                # The plaintext comparison is the optimistic lock: if another
                # process rotated the secret between the SELECT and this UPDATE,
                # the row is left alone rather than overwritten with a seal of
                # the value that is no longer there.
                db.execute(
                    "UPDATE %s SET %s = ? WHERE %s AND %s = ?" % (table, column, where, column),
                    (ciphertext,) + params,
                )
            sealed += 1
        report["tables"].append({"table": table, "column": column, "sealed": sealed, "skipped": skipped, "errors": errors})
        report["sealed"] += sealed
        report["skipped"] += skipped
        report["errors"] += errors
    return report


_BOXES: Dict[str, SecretBox] = {}
_BOXES_LOCK = threading.Lock()


def vault_for(master: Any = "") -> SecretBox:
    """A cached box for one key string.

    Plugins ask for this per request; deriving the HKDF key is cheap but the
    cache also keeps every plugin pointed at the same instance if the operator
    never changes the key.
    """
    text = str(master or "").strip()
    with _BOXES_LOCK:
        box = _BOXES.get(text)
        if box is None:
            box = SecretBox(text)
            _BOXES[text] = box
        return box


# ───────────────────────────────── self-test ────────────────────────────────


def self_test() -> List[str]:
    """The vault's rules, with and without the wheel — one list, named checks."""
    import importlib.util

    checks: List[str] = []

    def check(name: str, condition: bool) -> None:
        if not condition:
            raise AssertionError("vault self_test failed: %s" % name)
        checks.append(name)

    def raises(name: str, error: Any, call) -> None:
        try:
            call()
        except error:
            checks.append(name)
            return
        except Exception as exc:  # noqa: BLE001
            raise AssertionError("%s raised %s (%s), expected %s" % (name, type(exc).__name__, exc, error)) from exc
        raise AssertionError("%s did not raise %s" % (name, error))

    master = bytes(range(32))
    hex_key = master.hex()
    b64_key = base64.b64encode(master).decode("ascii")

    check("the_hex_key_parses_to_thirty_two_bytes", parse_vault_key(hex_key) == master)
    check("the_base64_key_parses_to_the_same_bytes", parse_vault_key(b64_key) == master)
    for name, bad in (
        ("an_empty_key_is_refused", ""),
        ("a_non_base64_non_hex_key_is_refused", "nope!!!"),
        ("a_four_character_key_is_refused", "abcd"),
        ("a_thirty_one_byte_key_says_how_long_it_should_be", bytes(31).hex()),
    ):
        try:
            parse_vault_key(bad)
            check(name, False)
        except ValueError as exc:
            check(name, "32 bytes" in str(exc) or "neither valid" in str(exc))

    disabled = SecretBox("")
    check("a_disabled_box_writes_plaintext", disabled.seal("s3cret", table="t", column="c", subject="x") == "s3cret")
    check("a_disabled_box_reads_plaintext", disabled.open("s3cret", table="t", column="c", subject="x") == "s3cret")
    check("an_empty_value_stays_empty", disabled.seal("", table="t", column="c", subject="x") == "")
    check("the_prefix_is_the_only_marker", is_sealed(VAULT_PREFIX + "abc") and not is_sealed("plain"))
    raises("a_disabled_box_refuses_ciphertext", VaultError,
           lambda: disabled.open(VAULT_PREFIX + "AAAA", table="t", column="c", subject="x"))

    crypto_ready = importlib.util.find_spec("cryptography") is not None
    box = SecretBox(hex_key)
    if not crypto_ready:
        raises("an_enabled_box_without_the_wheel_refuses_to_seal", VaultUnavailable,
               lambda: box.seal("s3cret", table="t", column="c", subject="x"))
        raises("an_enabled_box_without_the_wheel_refuses_to_open", VaultUnavailable,
               lambda: box.open(VAULT_PREFIX + "AAAAAAAAAAAAAAAAAAAAAA==", table="t", column="c", subject="x"))
        return checks

    sealed = box.seal("s3cret", table="channels", column="identity_sec_b64url", subject="green")
    check("an_enabled_box_seals_with_the_prefix", is_sealed(sealed) and sealed != "s3cret")
    check("an_enabled_box_round_trips", box.open(sealed, table="channels", column="identity_sec_b64url", subject="green") == "s3cret")
    check("sealing_twice_is_idempotent", box.seal(sealed, table="channels", column="identity_sec_b64url", subject="green") == sealed)
    check("the_nonce_makes_two_seals_differ", box.seal("s3cret", table="t", column="c", subject="x") != box.seal("s3cret", table="t", column="c", subject="x"))
    raises("a_ciphertext_moved_to_another_row_does_not_open", VaultError,
           lambda: box.open(sealed, table="channels", column="identity_sec_b64url", subject="red"))
    raises("a_ciphertext_moved_to_another_column_does_not_open", VaultError,
           lambda: box.open(sealed, table="channels", column="key_b64url", subject="green"))
    raises("the_wrong_key_does_not_open", VaultError,
           lambda: SecretBox(bytes(range(1, 33)).hex()).open(sealed, table="channels", column="identity_sec_b64url", subject="green"))
    tampered = sealed[:-2] + ("AA" if sealed[-2:] != "AA" else "BB")
    raises("a_tampered_ciphertext_does_not_open", VaultError,
           lambda: box.open(tampered, table="channels", column="identity_sec_b64url", subject="green"))
    check("mixed_reads_leave_plaintext_alone",
          box.open("plain-value", table="channels", column="identity_sec_b64url", subject="green") == "plain-value")
    check("the_box_is_cached_per_key", vault_for(hex_key) is vault_for(hex_key) and vault_for(hex_key) is not vault_for(b64_key))

    # A real database, the real migration: plaintext rows become sealed, the
    # second run is a no-op, and an empty column stays the empty sentinel.
    import sqlite3
    import tempfile

    with tempfile.TemporaryDirectory(prefix="popopx-vault-selftest-") as folder:
        path = os.path.join(folder, "vault.db")
        conn = sqlite3.connect(path)
        conn.executescript(
            """
            CREATE TABLE eco_sessions (pairwise_uid TEXT PRIMARY KEY, contact_id INTEGER UNIQUE, secret_hex TEXT);
            CREATE TABLE channels (channel_id TEXT PRIMARY KEY, identity_sec_b64url TEXT);
            CREATE TABLE channel_epochs (channel_id TEXT, epoch INTEGER, key_b64url TEXT, PRIMARY KEY (channel_id, epoch));
            CREATE TABLE workflow_subscriptions (id TEXT PRIMARY KEY, secret TEXT);
            CREATE TABLE dav_endpoints (connector TEXT PRIMARY KEY, password TEXT);
            CREATE TABLE slack_discord_workspaces (id TEXT PRIMARY KEY, webhook_url TEXT, secret TEXT);
            """
        )
        conn.execute("INSERT INTO eco_sessions VALUES ('pw_a', 7, ?)", ("ab" * 32,))
        conn.execute("INSERT INTO channels VALUES ('green', 'sec-green')")
        conn.execute("INSERT INTO channel_epochs VALUES ('green', 1, 'key-one')")
        conn.execute("INSERT INTO channel_epochs VALUES ('green', 2, '')")
        conn.execute("INSERT INTO workflow_subscriptions VALUES ('sub_1', 'hmac-secret')")
        conn.execute("INSERT INTO dav_endpoints VALUES ('carddav', 'dav-pass')")
        conn.execute("INSERT INTO slack_discord_workspaces (id, webhook_url, secret) VALUES ('sdw_1', ?, 'sign-secret')",
                     ("https://hooks.slack.com/services/T/B/S",))
        conn.execute("INSERT INTO slack_discord_workspaces (id, webhook_url, secret) VALUES ('sdw_2', '', '')")
        conn.commit()

        class Handle:
            def __init__(self, connection: sqlite3.Connection) -> None:
                self._c = connection

            def query(self, sql: str, params: Any = ()) -> List[Any]:
                cur = self._c.execute(sql, params)
                names = [item[0] for item in cur.description or ()]
                return [dict(zip(names, row)) for row in cur.fetchall()]

            def execute(self, sql: str, params: Any = ()) -> int:
                cur = self._c.execute(sql, params)
                self._c.commit()
                return cur.rowcount

        handle = Handle(conn)
        first = migrate_secrets(handle, box)
        check("the_migration_seals_every_target", first["sealed"] == 7)
        check("the_migration_skips_the_empty_sentinel", first["skipped"] == 3 and first["errors"] == 0)
        stored = conn.execute("SELECT secret_hex FROM eco_sessions").fetchone()[0]
        check("the_session_secret_is_ciphertext_now", is_sealed(stored))
        check("the_ciphertext_is_bound_to_the_row",
              box.open(stored, table="eco_sessions", column="secret_hex", subject=7) == "ab" * 32)
        check("the_epoch_key_is_bound_to_its_epoch",
              box.open(conn.execute("SELECT key_b64url FROM channel_epochs WHERE epoch = 1").fetchone()[0],
                       table="channel_epochs", column="key_b64url", subject="green:1") == "key-one")
        check("the_webhook_url_is_bound_to_its_workspace",
              box.open(conn.execute("SELECT webhook_url FROM slack_discord_workspaces WHERE id = 'sdw_1'").fetchone()[0],
                       table="slack_discord_workspaces", column="webhook_url", subject="sdw_1")
              == "https://hooks.slack.com/services/T/B/S")
        second = migrate_secrets(handle, box)
        check("the_second_migration_changes_nothing", second["sealed"] == 0 and second["skipped"] == 10)
        check("an_empty_value_is_still_empty", conn.execute("SELECT key_b64url FROM channel_epochs WHERE epoch = 2").fetchone()[0] == "")
        conn.close()

    return checks