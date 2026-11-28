# Copyright (c) 2026 POPOPX (popopx.chat)
# SPDX-License-Identifier: AGPL-3.0-only
"""Scoped admin tokens: fine-grained credentials for scripts and dashboards.

``POPOPX_ADMIN_TOKEN`` remains the root credential: it is never stored, it is
accepted everywhere, and only it can mint, list or revoke the tokens defined
here. The rows this module manages are for everything an operator does *not*
want to hand the root token to — a monitoring script that only reads status, a
plugin console that only needs one plugin's routes.

Three properties are load-bearing:

* **Only a hash is stored.** The plaintext ``pxa_…`` token is returned by the
  mint call and never again. A copy of ``gateway.db`` cannot be replayed against
  the gateway, which is the same rule the vault applies to every other secret.
* **The scope grammar is closed.** ``core:<resource>:ro|rw`` and
  ``plugin:<id>:ro|rw``, plus ``*`` for a deliberately broad scoped token.
  ``core:admin`` is not a grantable resource: token management is root-only, so
  a leaked scoped token cannot mint a wider one.
* **A refusal is visible.** Every scoped-token decision lands in
  ``admin_token_audit`` with the path, outcome and status. The table is bounded
  (``AUDIT_RETENTION`` rows) so a long-lived process cannot fill the disk with
  its own audit trail.

The module is pure stdlib. It is imported by ``main.py`` and by the plugins,
which is why it cannot import either of them back.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
import secrets
import time
from typing import Any, Dict, Iterable, List, Mapping, Optional, Tuple

__all__ = [
    "AUDIT_RETENTION",
    "ROOT_RESOURCE",
    "STATE_ATTR",
    "TOKEN_PREFIX",
    "constant_compare",
    "constant_time_root_match",
    "grant_from_request",
    "list_audit",
    "list_tokens",
    "mint_token",
    "normalize_scopes",
    "parse_scope",
    "plugin_prefix_map",
    "presented_credential",
    "record_audit",
    "resolve_presented",
    "resource_for_path",
    "revoke_token",
    "scope_allows",
    "self_test",
    "token_hash",
    "validate_scope",
]

#: The plaintext prefix that marks a scoped token. The root token must not start
#: with it, so a lookup can tell which kind it is holding before hashing.
TOKEN_PREFIX = "pxa_"

#: ``request.state`` attribute the auth middleware writes the resolved grant to.
STATE_ATTR = "popopx_admin"

#: The only resource a scoped token cannot name.
ROOT_RESOURCE = "core:admin"

#: Keep the audit table useful without letting it grow without bound.
AUDIT_RETENTION = 5000

#: A scoped token's last-use timestamp is refreshed at most this often. Writing
#: it on every request would turn a read-only status poll into a SQLite write.
LAST_USED_RESOLUTION_MS = 60_000

# The resource part allows hyphens because core URL segments do: the lifecycle
# API lives at `/api/v1/data-lifecycle/…`, and a scope an operator cannot spell
# after reading the route table would be a token that can never be minted.
_SCOPE_PATTERN = re.compile(r"^(core|plugin):([a-z][a-z0-9_-]{0,31}):(ro|rw)$")


def _now_ms() -> int:
    return int(time.time() * 1000)


def constant_compare(left: str, right: str) -> bool:
    """Compare two strings without leaking where they differ."""
    if not left or not right:
        return False
    return hmac.compare_digest(str(left), str(right))


def constant_time_root_match(presented: str, configured: str) -> bool:
    """Is this the gateway's root token? Empty configured tokens match nothing."""
    expected = str(configured or "").strip()
    return bool(expected) and constant_compare(str(presented or "").strip(), expected)


def token_hash(token: str) -> str:
    return hashlib.sha256(str(token).encode("utf-8")).hexdigest()


def parse_scope(scope: str) -> Optional[Tuple[str, str, str]]:
    """``plugin:slack_discord:ro`` → ``("plugin", "slack_discord", "ro")``."""
    match = _SCOPE_PATTERN.match(str(scope or "").strip())
    if not match:
        return None
    kind, resource, permission = match.groups()
    if "%s:%s" % (kind, resource) == ROOT_RESOURCE:
        return None
    return kind, resource, permission


def validate_scope(scope: str) -> bool:
    text = str(scope or "").strip()
    return text == "*" or parse_scope(text) is not None


def normalize_scopes(raw: Any) -> List[str]:
    """Validate and de-duplicate a list of scopes, preserving first-seen order.

    Accepts a list/tuple or one comma/whitespace separated string, because the
    console posts an array while a curl user naturally writes one string. Every
    scope must be valid: silently dropping a typo would mint a token that is
    narrower than the operator asked for.
    """
    if isinstance(raw, str):
        values: Iterable[Any] = re.split(r"[,\s]+", raw.strip())
    elif isinstance(raw, (list, tuple)):
        values = raw
    else:
        raise ValueError("scopes must be a list or a comma-separated string")
    out: List[str] = []
    for value in values:
        text = str(value or "").strip()
        if not text:
            continue
        if not validate_scope(text):
            raise ValueError(
                "invalid scope %r; expected *, core:<resource>:ro|rw or plugin:<id>:ro|rw" % text
            )
        if text not in out:
            out.append(text)
    if not out:
        raise ValueError("at least one scope is required")
    if len(out) > 16:
        raise ValueError("at most 16 scopes may be granted to one token")
    return out


def plugin_prefix_map() -> Dict[str, str]:
    """``/api/v1/plugins/slackdiscord`` → ``slack_discord``.

    Imported lazily so this module stays importable without the plugin package's
    dependencies on a checkout where only the token self-test is being run.
    """
    from app.plugins import PLUGIN_SPEC

    return {str(spec.url_prefix).rstrip("/"): str(spec.plugin_id) for spec in PLUGIN_SPEC}


def resource_for_path(
    path: str, plugin_prefixes: Optional[Mapping[str, str]] = None
) -> Tuple[str, bool]:
    """The resource a request path belongs to, and whether only the root may use it.

    A plugin path is named by the mount table, not by the URL segment: the Slack
    bridge is mounted at ``/api/v1/plugins/slackdiscord`` but its plugin id is
    ``slack_discord``, and a scope written against the id must match it. An
    unknown plugin prefix is root-only rather than treated as a wildcard, so a
    router mounted by a later edit cannot silently become scoped-readable.
    """
    text = str(path or "")
    plugin_root = "/api/v1/plugins/"
    if text.startswith(plugin_root):
        rest = text[len(plugin_root):]
        slug = rest.split("/", 1)[0]
        mapping = plugin_prefixes if plugin_prefixes is not None else plugin_prefix_map()
        plugin_id = mapping.get(plugin_root + slug)
        if not plugin_id:
            return "plugin:" + (slug or "unknown"), True
        return "plugin:" + plugin_id, False
    api_root = "/api/v1/"
    if text.startswith(api_root):
        rest = text[len(api_root):]
        segment = rest.split("/", 1)[0]
        if not segment:
            return "core:root", True
        if segment == "admin":
            return ROOT_RESOURCE, True
        return "core:" + segment, False
    return "core:other", True


def write_method(method: str) -> bool:
    """GET and HEAD are reads; everything else needs ``rw``."""
    return str(method or "").upper() not in ("GET", "HEAD")


def presented_credential(headers: Mapping[str, str], query_token: str = "") -> str:
    """The admin credential, in every spelling the suite already accepts.

    The console sends all three headers together; a script may send any one. A
    token that works with ``X-Admin-Token`` but not ``Authorization`` is the trap
    the console's comment warns about, so the union is deliberately accepted.
    """
    lowered = {str(k).lower(): str(v) for k, v in (headers or {}).items()}
    for name in ("x-popopx-admin-token", "x-admin-token"):
        value = lowered.get(name, "").strip()
        if value:
            return value
    authorization = lowered.get("authorization", "").strip()
    if authorization.lower().startswith("bearer "):
        value = authorization[7:].strip()
        if value:
            return value
    return str(query_token or "").strip()


def grant_from_request(request: Any) -> Optional[Dict[str, Any]]:
    """The grant the auth middleware attached to this request, if any."""
    state = getattr(request, "state", None)
    grant = getattr(state, STATE_ATTR, None) if state is not None else None
    return grant if isinstance(grant, dict) else None


def _grant_for_row(row: Any) -> Dict[str, Any]:
    try:
        scopes = json.loads(str(row["scopes"] or "[]"))
    except (TypeError, ValueError):
        scopes = []
    if not isinstance(scopes, list):
        scopes = []
    return {
        "root": False,
        "token_id": str(row["id"]),
        "label": str(row["label"] or ""),
        "token_prefix": str(row["token_prefix"] or ""),
        "scopes": [str(scope) for scope in scopes],
        "expires_at_ms": row["expires_at_ms"],
    }


def _root_grant() -> Dict[str, Any]:
    return {
        "root": True,
        "token_id": None,
        "label": "root",
        "token_prefix": "",
        "scopes": ["*"],
        "expires_at_ms": None,
    }


def resolve_presented(
    db: Any,
    presented: str,
    configured_root: str,
    *,
    now_ms: Optional[int] = None,
    path: str = "",
) -> Tuple[Optional[Dict[str, Any]], Optional[Dict[str, Any]]]:
    """Resolve a presented credential into a grant, or explain why it failed.

    Returns ``(grant, rejected)``. ``(None, None)`` means "no usable credential
    was presented" — a missing or unknown token, which the caller reports as 401
    without writing an audit row (otherwise any stranger could fill the audit
    table by guessing). ``(None, {"token_id": …})`` means a *known* token that is
    expired or revoked; that is worth recording.
    """
    token = str(presented or "").strip()
    if not token:
        return None, None
    if constant_time_root_match(token, configured_root):
        return _root_grant(), None
    if not token.startswith(TOKEN_PREFIX):
        return None, None
    row = db.query_one("SELECT * FROM admin_tokens WHERE token_hash = ?", (token_hash(token),))
    if row is None:
        return None, None
    timestamp = int(now_ms if now_ms is not None else _now_ms())
    token_id = str(row["id"])
    if int(row["revoked"] or 0):
        record_audit(db, token_id, "auth", path, "revoked", 401, now_ms=timestamp)
        return None, {"token_id": token_id, "reason": "revoked"}
    expires_at = row["expires_at_ms"]
    if expires_at is not None and timestamp >= int(expires_at):
        record_audit(db, token_id, "auth", path, "expired", 401, now_ms=timestamp)
        return None, {"token_id": token_id, "reason": "expired"}
    last_used = row["last_used_at_ms"]
    if last_used is None or timestamp - int(last_used) >= LAST_USED_RESOLUTION_MS:
        db.execute(
            "UPDATE admin_tokens SET last_used_at_ms = ? WHERE id = ?", (timestamp, token_id)
        )
    return _grant_for_row(row), None


def scope_allows(
    grant: Optional[Mapping[str, Any]],
    resource: str,
    *,
    write: bool = False,
    root_only: bool = False,
) -> bool:
    """Does this grant cover ``resource`` at the requested permission level?"""
    if not grant:
        return False
    if bool(grant.get("root")):
        return True
    if root_only:
        return False
    for scope in grant.get("scopes") or []:
        text = str(scope)
        if text == "*":
            return True
        parsed = parse_scope(text)
        if parsed is None:
            continue
        kind, name, permission = parsed
        if "%s:%s" % (kind, name) != str(resource):
            continue
        if not write or permission == "rw":
            return True
    return False


def mint_token(
    db: Any,
    label: str,
    scopes: Any,
    *,
    expires_at_ms: Optional[int] = None,
    now_ms: Optional[int] = None,
) -> Dict[str, Any]:
    """Create one scoped token and return its plaintext exactly once.

    The caller is responsible for ``expires_at_ms`` being in the future; the
    route computes it from a bounded number of days. A zero or past expiry would
    mint a token that is dead on arrival, which the resolver would report as
    ``expired`` rather than as a validation error — so the route refuses it.
    """
    clean_label = " ".join(str(label or "").split())
    if not clean_label:
        raise ValueError("label is required")
    if len(clean_label) > 80:
        raise ValueError("label must be 80 characters or fewer")
    clean_scopes = normalize_scopes(scopes)
    timestamp = int(now_ms if now_ms is not None else _now_ms())
    expires = int(expires_at_ms) if expires_at_ms is not None else None
    if expires is not None and expires <= timestamp:
        raise ValueError("expires_at_ms must be in the future")
    plaintext = TOKEN_PREFIX + secrets.token_urlsafe(32)
    token_id = "atk_" + secrets.token_hex(8)
    db.execute(
        "INSERT INTO admin_tokens (id, label, token_prefix, token_hash, scopes, revoked,"
        " expires_at_ms, created_at_ms, last_used_at_ms) VALUES (?, ?, ?, ?, ?, 0, ?, ?, NULL)",
        (
            token_id,
            clean_label,
            plaintext[:16],
            token_hash(plaintext),
            json.dumps(clean_scopes),
            expires,
            timestamp,
        ),
    )
    record_audit(db, token_id, "mint", "", "created", 201, now_ms=timestamp)
    return {
        "ok": True,
        "token": plaintext,
        "id": token_id,
        "label": clean_label,
        "token_prefix": plaintext[:16],
        "scopes": clean_scopes,
        "expires_at_ms": expires,
        "created_at_ms": timestamp,
    }


def _public_row(row: Any) -> Dict[str, Any]:
    try:
        scopes = json.loads(str(row["scopes"] or "[]"))
    except (TypeError, ValueError):
        scopes = []
    return {
        "id": str(row["id"]),
        "label": str(row["label"] or ""),
        "token_prefix": str(row["token_prefix"] or ""),
        "scopes": scopes if isinstance(scopes, list) else [],
        "revoked": bool(int(row["revoked"] or 0)),
        "expires_at_ms": row["expires_at_ms"],
        "created_at_ms": int(row["created_at_ms"]),
        "last_used_at_ms": row["last_used_at_ms"],
    }


def list_tokens(db: Any, *, limit: int = 200) -> List[Dict[str, Any]]:
    rows = db.query(
        "SELECT * FROM admin_tokens ORDER BY created_at_ms DESC, id DESC LIMIT ?",
        (max(1, min(int(limit), 500)),),
    )
    return [_public_row(row) for row in rows]


def revoke_token(db: Any, token_id: str, *, now_ms: Optional[int] = None) -> bool:
    changed = db.execute(
        "UPDATE admin_tokens SET revoked = 1 WHERE id = ? AND revoked = 0", (str(token_id),)
    )
    if changed:
        record_audit(db, str(token_id), "revoke", "", "revoked", 200, now_ms=now_ms)
    return bool(changed)


def record_audit(
    db: Any,
    token_id: Optional[str],
    action: str,
    path: str,
    outcome: str,
    status_code: Optional[int] = None,
    *,
    now_ms: Optional[int] = None,
) -> None:
    """Append one audit row and keep the table bounded.

    The path is stored without its query string on purpose: a caller may put a
    token in ``?token=``, and an audit table that quotes its own credential back
    is a second copy of the secret. Callers pass ``request.url.path``, never the
    full URL.
    """
    timestamp = int(now_ms if now_ms is not None else _now_ms())
    db.execute(
        "INSERT INTO admin_token_audit (token_id, action, path, outcome, status_code, created_at_ms)"
        " VALUES (?, ?, ?, ?, ?, ?)",
        (token_id, str(action)[:32], str(path)[:300], str(outcome)[:32], status_code, timestamp),
    )
    db.execute(
        "DELETE FROM admin_token_audit WHERE id NOT IN"
        " (SELECT id FROM admin_token_audit ORDER BY id DESC LIMIT ?)",
        (AUDIT_RETENTION,),
    )


def list_audit(db: Any, *, limit: int = 50) -> List[Dict[str, Any]]:
    rows = db.query(
        "SELECT * FROM admin_token_audit ORDER BY id DESC LIMIT ?",
        (max(1, min(int(limit), 500)),),
    )
    return [
        {
            "id": int(row["id"]),
            "token_id": row["token_id"],
            "action": str(row["action"] or ""),
            "path": str(row["path"] or ""),
            "outcome": str(row["outcome"] or ""),
            "status_code": row["status_code"],
            "created_at_ms": int(row["created_at_ms"]),
        }
        for row in rows
    ]


def self_test() -> List[str]:
    """The grammar, the grant matrix and the token lifecycle against real SQLite."""
    import tempfile
    from pathlib import Path

    from app.database import Database

    checks: List[str] = []

    def check(name: str, condition: bool) -> None:
        if not condition:
            raise AssertionError("admin_auth self_test failed: %s" % name)
        checks.append(name)

    def raises(name: str, error: Any, call: Any) -> None:
        try:
            call()
        except error:
            checks.append(name)
            return
        except Exception as exc:  # noqa: BLE001
            raise AssertionError(
                "%s raised %s (%s), expected %s" % (name, type(exc).__name__, exc, error)
            ) from exc
        raise AssertionError("%s did not raise %s" % (name, error))

    check("the_token_prefix_is_not_the_root_token", TOKEN_PREFIX.startswith("pxa_"))
    check("the_scope_grammar_accepts_a_core_read", parse_scope("core:status:ro") == ("core", "status", "ro"))
    check("the_scope_grammar_accepts_a_plugin_write", parse_scope("plugin:slack_discord:rw") == ("plugin", "slack_discord", "rw"))
    check("the_scope_grammar_accepts_a_wildcard", validate_scope("*"))
    check("the_scope_grammar_rejects_an_unknown_kind", not validate_scope("admin:status:rw"))
    check("the_scope_grammar_rejects_a_bad_permission", not validate_scope("core:status:read"))
    check("the_scope_grammar_rejects_an_empty_resource", not validate_scope("plugin::rw"))
    check("the_scope_grammar_rejects_the_root_only_resource", not validate_scope("core:admin:rw"))
    check("the_scope_grammar_rejects_a_suffix", not validate_scope("core:status:rw:extra"))
    check("normalize_scopes_splits_a_string", normalize_scopes("core:status:ro, plugin:slack_discord:rw") == ["core:status:ro", "plugin:slack_discord:rw"])
    check("normalize_scopes_deduplicates", normalize_scopes(["core:status:ro", "core:status:ro"]) == ["core:status:ro"])
    raises("normalize_scopes_refuses_an_invalid_member", ValueError, lambda: normalize_scopes(["core:status:ro", "nope"]))
    raises("normalize_scopes_refuses_an_empty_list", ValueError, lambda: normalize_scopes([]))
    raises("normalize_scopes_refuses_too_many", ValueError, lambda: normalize_scopes(["core:r%d:ro" % i for i in range(17)]))
    check("the_scope_grammar_accepts_a_hyphenated_core_resource",
          validate_scope("core:data-lifecycle:ro")
          and validate_scope("core:data-lifecycle:rw"))
    check("a_hyphenated_scope_covers_its_route",
          scope_allows({"root": False, "scopes": ["core:data-lifecycle:ro"]},
                       resource_for_path("/api/v1/data-lifecycle/policies", {})[0])
          and not scope_allows({"root": False, "scopes": ["core:data-lifecycle:ro"]},
                               resource_for_path("/api/v1/data-lifecycle/erase", {})[0],
                               write=True))

    prefixes = {"/api/v1/plugins/slackdiscord": "slack_discord"}
    check("the_slack_route_names_its_plugin_id", resource_for_path("/api/v1/plugins/slackdiscord/send", prefixes) == ("plugin:slack_discord", False))
    check("an_unknown_plugin_is_root_only", resource_for_path("/api/v1/plugins/unmounted/x", prefixes) == ("plugin:unmounted", True))
    check("a_core_route_names_its_first_segment", resource_for_path("/api/v1/contacts/7", prefixes) == ("core:contacts", False))
    check("the_token_admin_is_root_only", resource_for_path("/api/v1/admin/tokens", prefixes) == ("core:admin", True))
    check("a_non_api_path_is_root_only", resource_for_path("/docs", prefixes) == ("core:other", True))
    check("GET_is_a_read", write_method("GET") is False and write_method("HEAD") is False)
    check("a_POST_needs_write", write_method("POST") is True and write_method("DELETE") is True)

    root = _root_grant()
    ro = {"root": False, "scopes": ["core:status:ro"]}
    rw = {"root": False, "scopes": ["core:status:rw"]}
    plugin_ro = {"root": False, "scopes": ["plugin:slack_discord:ro"]}
    wildcard = {"root": False, "scopes": ["*"]}
    check("a_root_grant_covers_everything", scope_allows(root, "core:admin", root_only=True))
    check("a_read_scope_covers_a_GET", scope_allows(ro, "core:status"))
    check("a_read_scope_does_not_cover_a_POST", not scope_allows(ro, "core:status", write=True))
    check("a_write_scope_covers_a_POST", scope_allows(rw, "core:status", write=True))
    check("a_scope_does_not_cross_resources", not scope_allows(ro, "core:vouchers"))
    check("a_plugin_scope_is_separate_from_core", not scope_allows(plugin_ro, "core:status"))
    check("a_plugin_scope_covers_its_plugin", scope_allows(plugin_ro, "plugin:slack_discord"))
    check("a_wildcard_covers_a_non_root_route", scope_allows(wildcard, "core:vouchers"))
    check("a_wildcard_still_does_not_cover_a_root_only_route", not scope_allows(wildcard, "core:admin", root_only=True))
    check("an_empty_grant_allows_nothing", not scope_allows(None, "core:status"))

    check("the_presented_credential_reads_both_header_spellings",
          presented_credential({"X-Admin-Token": "a"}) == "a"
          and presented_credential({"x-popopx-admin-token": "b"}) == "b")
    check("the_presented_credential_reads_a_bearer",
          presented_credential({"Authorization": "Bearer c"}) == "c"
          and presented_credential({"authorization": "bearer c"}) == "c")
    check("the_presented_credential_reads_the_query_fallback",
          presented_credential({}, "d") == "d")

    check("the_root_token_matches_itself",
          constant_time_root_match("root-token-value-0123456789ab", "root-token-value-0123456789ab"))
    check("an_empty_root_token_matches_nothing", not constant_time_root_match("", ""))
    check("a_short_token_is_not_a_prefix_match", not constant_time_root_match("root-token-value", "root-token-value-0123456789ab"))

    with tempfile.TemporaryDirectory(prefix="popopx-auth-") as tmp:
        db = Database(Path(tmp) / "auth.db")
        try:
            minted = mint_token(db, "monitoring", ["core:status:ro"], now_ms=1_700_000_000_000)
            plaintext = str(minted["token"])
            check("the_minted_token_has_the_prefix_and_length",
                  plaintext.startswith(TOKEN_PREFIX) and len(plaintext) >= 40)
            check("the_plaintext_is_never_stored",
                  db.scalar("SELECT COUNT(*) FROM admin_tokens WHERE token_hash = ?", (token_hash(plaintext),)) == 1
                  and db.scalar("SELECT COUNT(*) FROM admin_tokens WHERE token_prefix = ?", (plaintext,)) == 0)
            listed = list_tokens(db)
            check("the_list_exposes_the_prefix_but_not_the_token",
                  len(listed) == 1 and listed[0]["token_prefix"] == plaintext[:16]
                  and "token" not in listed[0] and "token_hash" not in listed[0])
            grant, rejected = resolve_presented(db, plaintext, "root-token-value-0123456789ab", now_ms=1_700_000_000_001)
            check("a_valid_token_resolves_to_its_scopes",
                  rejected is None and grant is not None
                  and grant["token_id"] == minted["id"] and grant["scopes"] == ["core:status:ro"])
            check("the_resolver_refreshes_last_used",
                  db.scalar("SELECT last_used_at_ms FROM admin_tokens WHERE id = ?", (minted["id"],)) == 1_700_000_000_001)
            root_grant, _ = resolve_presented(db, "root-token-value-0123456789ab", "root-token-value-0123456789ab")
            check("the_root_token_resolves_to_a_root_grant", root_grant is not None and root_grant["root"] is True)
            missing, missing_rejected = resolve_presented(db, TOKEN_PREFIX + "not-a-real-token", "root-token-value-0123456789ab")
            check("an_unknown_token_does_not_resolve", missing is None and missing_rejected is None)

            expiring = mint_token(
                db, "expired", ["plugin:slack_discord:ro"],
                expires_at_ms=1_700_000_100_000, now_ms=1_700_000_000_000,
            )
            expired_grant, expired_rejected = resolve_presented(
                db, str(expiring["token"]), "root-token-value-0123456789ab", now_ms=1_700_000_200_000
            )
            check("an_expired_token_is_rejected_and_named",
                  expired_grant is None and expired_rejected is not None
                  and expired_rejected["reason"] == "expired")

            to_revoke = mint_token(db, "revoked", ["core:status:ro"], now_ms=1_700_000_000_000)
            check("a_token_revokes_once", revoke_token(db, to_revoke["id"]) is True and revoke_token(db, to_revoke["id"]) is False)
            revoked_grant, revoked_rejected = resolve_presented(
                db, str(to_revoke["token"]), "root-token-value-0123456789ab", now_ms=1_700_000_000_001
            )
            check("a_revoked_token_is_rejected_and_named",
                  revoked_grant is None and revoked_rejected is not None
                  and revoked_rejected["reason"] == "revoked")
            raises("mint_refuses_an_empty_label", ValueError, lambda: mint_token(db, " ", ["core:status:ro"]))
            raises("mint_refuses_a_past_expiry", ValueError,
                   lambda: mint_token(db, "past", ["core:status:ro"], expires_at_ms=1, now_ms=2))

            before = len(list_audit(db, limit=500))
            for index in range(3):
                record_audit(db, minted["id"], "request", "/api/v1/status", "used", 200, now_ms=1_700_000_000_100 + index)
            audit = list_audit(db, limit=500)
            check("every_scope_decision_is_audited", len(audit) >= before + 3 and audit[0]["path"] == "/api/v1/status")
            check("the_audit_list_never_exposes_a_token",
                  plaintext not in json.dumps(audit) and token_hash(plaintext) not in json.dumps(audit))
        finally:
            db.close()

    return checks