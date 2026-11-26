# Copyright (c) 2026 POPOPX (popopx.chat)
# SPDX-License-Identifier: AGPL-3.0-only
"""Shared primitives for the workflow and DAV connectors.

Three things in this module are security boundaries rather than conveniences:

1. **The SSRF guard.** A merchant may point a webhook at their own Node-RED, and
   the same URL is later fetched by the gateway process. The guard therefore
   rejects the cloud metadata addresses *always* — even when the operator opted
   into private networks — and requires an explicit ``allow_private`` flag before
   a loopback/RFC1918 address may be used at all. A public endpoint must be
   HTTPS. DNS is resolved twice (at save and at request time), and the request
   connects to the validated address instead of re-resolving the hostname, which
   closes the DNS-rebinding window that a check-then-connect implementation
   leaves open.
2. **The audit row.** Every inbound webhook, outbound delivery and DAV query
   writes one row here. The row is deliberately narrow: no URL query, no body,
   no contact content, no token. A reason code is enough to operate the
   connector and cannot become a second copy of the data.
3. **XML input.** DAV servers are remote, so their XML is untrusted. External
   entities are refused before the parser sees them; the CalDAV reader in
   ``caldav_connector`` additionally streams so that a meeting's SUMMARY is
   never kept in a tree.

Module rule: stdlib only at import time. FastAPI is not needed here.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import http.client
import ipaddress
import json
import socket
import sqlite3
import ssl
import time
import urllib.parse
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

__all__ = [
    "ConnectorError",
    "Endpoint",
    "PinnedResponse",
    "audit_rows",
    "authorize_admin",
    "basic_auth_header",
    "constant_compare",
    "format_iso",
    "json_dumps",
    "new_id",
    "normalize_endpoint_url",
    "parse_iso_ms",
    "record_audit",
    "request_pinned",
    "sha256_hex",
    "stable_error",
    "text_or_empty",
    "xml_from_bytes",
]

#: Metadata / control-plane addresses. Blocked even for ``allow_private=True``:
#: an operator opting into a private LAN did not opt into letting a flow read
#: the cloud instance's credentials.
_ALWAYS_BLOCKED = {
    ipaddress.ip_address("169.254.169.254"),  # AWS/GCP/Azure/OpenStack metadata
    ipaddress.ip_address("169.254.170.2"),    # AWS ECS task metadata
    ipaddress.ip_address("100.100.100.200"),   # Alibaba Cloud metadata
    ipaddress.ip_address("192.0.0.192"),       # Oracle Cloud metadata
    ipaddress.ip_address("168.63.129.16"),     # Azure wireserver
    ipaddress.ip_address("fd00:ec2::254"),     # AWS IMDS over IPv6
}
_ALWAYS_BLOCKED_NAMES = {
    "metadata",
    "metadata.google.internal",
    "metadata.goog",
    "instance-data",
    "instance-data.ec2.internal",
}
_ALWAYS_BLOCKED_NETS = (
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("fe80::/10"),
)

#: A hostname this long is not a self-hosted endpoint; it is an attempt to make
#: a log line or an SNI field do something unexpected.
_MAX_HOST_CHARS = 253
_MAX_URL_CHARS = 2048
_MAX_RESPONSE_BYTES = 2 * 1024 * 1024


class ConnectorError(Exception):
    """A refused connector operation with a stable ``code``.

    ``code`` is what reaches the audit log and the HTTP body. The message is for
    a human and must never carry a secret: callers pass reason codes such as
    ``ssrf_blocked``, ``auth_failed`` or ``timeout``, not a URL or a token.
    """

    def __init__(self, code: str, message: str = "", *, http_status: int = 400) -> None:
        self.code = str(code)
        self.message = str(message or code)
        self.http_status = int(http_status)
        super().__init__("%s: %s" % (self.code, self.message))


@dataclass(frozen=True)
class Endpoint:
    scheme: str
    host: str
    port: int
    path: str
    query: str
    addresses: Tuple[str, ...]

    @property
    def origin(self) -> str:
        default = 443 if self.scheme == "https" else 80
        return "%s://%s%s" % (self.scheme, self.host, "" if self.port == default else ":%d" % self.port)

    @property
    def target(self) -> str:
        return (self.path or "/") + (("?" + self.query) if self.query else "")


@dataclass(frozen=True)
class PinnedResponse:
    status: int
    headers: Mapping[str, str]
    body: bytes

    def text(self) -> str:
        return self.body.decode("utf-8", "replace")


def text_or_empty(value: Any, limit: int = 2048) -> str:
    if value is None:
        return ""
    return str(value).replace("\x00", "").strip()[:limit]


def constant_compare(left: str, right: str) -> bool:
    return hmac.compare_digest(left.encode("utf-8", "replace"), right.encode("utf-8", "replace"))


def sha256_hex(value: Any) -> str:
    return hashlib.sha256(str(value).encode("utf-8", "replace")).hexdigest()


def new_id(prefix: str) -> str:
    """A URL-safe identifier with a type prefix, e.g. ``sub_…``.

    ``token_urlsafe`` rather than a counter: these values travel to a flow engine
    and one tenant's id must not reveal how many subscriptions another tenant
    has.
    """
    import secrets

    return "%s_%s" % (prefix, secrets.token_urlsafe(18).replace("-", "").replace("_", "")[:24])


def json_dumps(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=False)


def format_iso(ms_value: Optional[int]) -> Optional[str]:
    if ms_value is None:
        return None
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(int(ms_value) / 1000.0))


def parse_iso_ms(value: Any) -> int:
    """ISO-8601 (with ``Z`` or an offset) or epoch milliseconds → milliseconds.

    DAV's ``time-range`` is UTC and the iOS side stores milliseconds, so both
    spellings are accepted at the console boundary and normalised before any SQL
    or XML is built. A naive datetime is treated as UTC: this gateway has no
    per-connector timezone setting, and silently using the host's local zone
    would make a query depend on where the operator installed it.
    """
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return int(value)
    text = str(value or "").strip()
    if not text:
        raise ConnectorError("time_required", "pass start/end as ISO-8601 or epoch milliseconds")
    try:
        return int(text)
    except ValueError:
        pass
    candidate = text[:-1] + "+00:00" if text.endswith("Z") else text
    try:
        import datetime as _dt

        parsed = _dt.datetime.fromisoformat(candidate)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=_dt.timezone.utc)
        return int(parsed.timestamp() * 1000)
    except ValueError as exc:
        raise ConnectorError("time_invalid", "not an ISO-8601 timestamp: %s" % text[:40]) from exc


def _mapped_ipv4(ip: ipaddress._BaseAddress) -> Optional[ipaddress.IPv4Address]:
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        return ip.ipv4_mapped
    return None


def _ip_is_blocked(ip: ipaddress._BaseAddress) -> bool:
    mapped = _mapped_ipv4(ip)
    if mapped is not None:
        return _ip_is_blocked(mapped)
    # IPv6 ::1 carries is_reserved=True on CPython, but it is the loopback the
    # allow_private flag exists to permit. Loopback is still private, so the
    # opt-in check below is what decides whether it may be used.
    if ip.is_loopback:
        return False
    if ip in _ALWAYS_BLOCKED:
        return True
    if any(ip in network for network in _ALWAYS_BLOCKED_NETS):
        return True
    return bool(
        ip.is_link_local
        or ip.is_multicast
        or ip.is_unspecified
        or ip.is_reserved
    )


def _ip_is_private(ip: ipaddress._BaseAddress) -> bool:
    mapped = _mapped_ipv4(ip)
    if mapped is not None:
        return _ip_is_private(mapped)
    return bool(ip.is_loopback or ip.is_private)


def _classify_address(ip: str) -> str:
    try:
        parsed = ipaddress.ip_address(ip)
    except ValueError as exc:
        raise ConnectorError("host_invalid", "resolver returned a non-address") from exc
    if _ip_is_blocked(parsed):
        return "blocked"
    if _ip_is_private(parsed):
        return "private"
    return "public"


def _resolve(host: str, port: int) -> Tuple[str, ...]:
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise ConnectorError("resolve_failed", "hostname did not resolve") from exc
    except OSError as exc:
        raise ConnectorError("resolve_failed", "hostname lookup failed") from exc
    addresses: List[str] = []
    for info in infos:
        address = info[4][0]
        if address not in addresses:
            addresses.append(address)
    if not addresses:
        raise ConnectorError("resolve_failed", "hostname resolved to no address")
    return tuple(addresses)


def normalize_endpoint_url(url: Any, *, allow_private: bool = False, resolve: bool = True) -> Endpoint:
    """Validate one outbound endpoint and (by default) resolve every address.

    Rules, in the order they answer:

    * only ``https`` for public hosts; ``http`` is allowed only when the operator
      set ``allow_private`` *and* every resolved address is loopback/RFC1918;
    * metadata, link-local, multicast, reserved and unspecified addresses are
      refused even with ``allow_private``;
    * userinfo, fragments and non-ASCII hostnames are refused;
    * every DNS answer must pass. One private answer under a public-looking name
      is exactly the rebinding trick, so the whole endpoint is refused rather
      than "the first address looked fine".
    """
    text = text_or_empty(url, _MAX_URL_CHARS)
    if not text:
        raise ConnectorError("url_required", "endpoint URL is required")
    try:
        parts = urllib.parse.urlsplit(text)
    except ValueError as exc:
        raise ConnectorError("url_invalid", "URL could not be parsed") from exc
    scheme = parts.scheme.lower()
    if scheme not in ("http", "https"):
        raise ConnectorError("url_scheme", "endpoint must be http(s)")
    if parts.username is not None or parts.password is not None:
        raise ConnectorError("url_userinfo", "put credentials in the username/password fields, not the URL")
    if parts.fragment:
        raise ConnectorError("url_fragment", "endpoint URL must not carry a fragment")
    host = (parts.hostname or "").strip().lower().rstrip(".")
    if not host:
        raise ConnectorError("url_host", "endpoint URL has no host")
    if len(host) > _MAX_HOST_CHARS:
        raise ConnectorError("url_host", "hostname is too long")
    if any(ord(ch) < 33 or ord(ch) > 126 for ch in host):
        raise ConnectorError("url_host", "hostname must be ASCII and contain no whitespace")
    if host in _ALWAYS_BLOCKED_NAMES:
        raise ConnectorError("ssrf_blocked", "cloud metadata hostname is not a workflow endpoint")
    try:
        port = int(parts.port or (443 if scheme == "https" else 80))
    except ValueError as exc:
        raise ConnectorError("url_port", "endpoint port is not a number") from exc
    if not (1 <= port <= 65535):
        raise ConnectorError("url_port", "endpoint port is out of range")

    literal: Optional[ipaddress._BaseAddress] = None
    try:
        literal = ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        literal = None

    addresses: Tuple[str, ...]
    if literal is not None:
        addresses = (str(literal),)
    elif resolve:
        addresses = _resolve(host, port)
    else:
        addresses = ()

    kinds = {_classify_address(address) for address in addresses}
    if "blocked" in kinds:
        raise ConnectorError("ssrf_blocked", "endpoint resolves to a metadata/link-local address")
    if "private" in kinds and not allow_private:
        raise ConnectorError(
            "ssrf_blocked",
            "endpoint resolves to a private address; set allow_private=true to permit a self-hosted LAN",
        )
    # HTTP is permitted only as the self-hosting escape hatch: the operator opted
    # in *and* every address is private. A public destination keeps requiring TLS
    # even when allow_private is set, otherwise the flag would silently downgrade
    # an internet-facing webhook.
    if scheme == "http" and (not allow_private or "public" in kinds):
        raise ConnectorError("url_scheme", "public endpoints must use HTTPS")
    return Endpoint(
        scheme=scheme,
        host=host,
        port=port,
        path=parts.path or "/",
        query=parts.query,
        addresses=addresses,
    )


def _pinned_connection(endpoint: Endpoint, address: str, timeout: float) -> http.client.HTTPConnection:
    """A connection whose socket is the validated address, not a fresh lookup.

    ``HTTPConnection`` still writes the original host into the ``Host`` header,
    and ``HTTPSConnection`` still passes it as ``server_hostname`` for SNI and
    certificate verification. Only ``_create_connection`` is redirected.
    """
    if endpoint.scheme == "https":
        context = ssl.create_default_context()
        connection: http.client.HTTPConnection = http.client.HTTPSConnection(
            endpoint.host, endpoint.port, timeout=timeout, context=context
        )
    else:
        connection = http.client.HTTPConnection(endpoint.host, endpoint.port, timeout=timeout)

    def _connect(_address: Any, _timeout: Any, _source: Any = None) -> socket.socket:
        return socket.create_connection((address, endpoint.port), timeout=timeout)

    connection._create_connection = _connect  # type: ignore[attr-defined]
    return connection


def request_pinned(
    url: str,
    *,
    method: str = "GET",
    headers: Optional[Mapping[str, str]] = None,
    body: bytes = b"",
    timeout: float = 10.0,
    max_bytes: int = _MAX_RESPONSE_BYTES,
    allow_private: bool = False,
) -> PinnedResponse:
    """One HTTP request with no redirects and no proxy, pinned to a checked IP.

    Redirects are *returned*, not followed: a 302 is a refusal the caller turns
    into a failure code, because following it would let a permitted endpoint
    point the gateway at an address the guard never saw.
    """
    endpoint = normalize_endpoint_url(url, allow_private=allow_private, resolve=True)
    if not endpoint.addresses:
        raise ConnectorError("resolve_failed", "no address to connect to")
    last_error: Optional[BaseException] = None
    for address in endpoint.addresses:
        connection = _pinned_connection(endpoint, address, timeout)
        try:
            connection.request(
                method.upper(),
                endpoint.target,
                body=body if body else None,
                headers=dict(headers or {}),
            )
            response = connection.getresponse()
            payload = response.read(max_bytes + 1)
            if len(payload) > max_bytes:
                raise ConnectorError("response_too_large", "endpoint response exceeded the connector limit")
            lowered = {str(k).lower(): str(v) for k, v in response.getheaders()}
            return PinnedResponse(status=int(response.status), headers=lowered, body=payload)
        except ConnectorError:
            raise
        except socket.timeout as exc:
            last_error = exc
        except ssl.SSLError as exc:
            last_error = exc
        except (OSError, http.client.HTTPException) as exc:
            last_error = exc
        finally:
            try:
                connection.close()
            except Exception:  # noqa: BLE001 — close must not mask the real error
                pass
    if isinstance(last_error, socket.timeout):
        raise ConnectorError("timeout", "endpoint did not answer in time", http_status=504)
    if isinstance(last_error, ssl.SSLError):
        raise ConnectorError("tls_failed", "TLS handshake or certificate check failed", http_status=502)
    raise ConnectorError("connection_failed", "endpoint could not be reached", http_status=502)


def stable_error(exc: BaseException) -> str:
    """A reason code an audit row can hold instead of an exception string.

    Exception messages from ``http.client``/``ssl`` can contain the hostname and
    sometimes the URL. Those do not belong in an audit table which is explicitly
    allowed to be pasted into a ticket, so only a small vocabulary survives.
    """
    if isinstance(exc, ConnectorError):
        return exc.code
    if isinstance(exc, sqlite3.Error):
        return "storage_error"
    return "connector_error"


def basic_auth_header(username: str, password: str) -> str:
    raw = ("%s:%s" % (username or "", password or "")).encode("utf-8")
    return "Basic " + base64.b64encode(raw).decode("ascii")


def authorize_admin(headers: Mapping[str, str], configured: str) -> Tuple[bool, str]:
    expected = configured if isinstance(configured, str) else ""
    if not expected.strip():
        return False, "POPOPX_ADMIN_TOKEN is not configured"
    provided = (
        _bearer_or_header(headers, "X-Popopx-Admin-Token")
        or _bearer_or_header(headers, "X-Admin-Token")
    )
    if not provided:
        return False, "missing admin credential"
    if constant_compare(provided, expected.strip()):
        return True, "ok"
    return False, "admin token does not match"


def _bearer_or_header(headers: Mapping[str, str], name: str) -> str:
    lowered = {str(k).lower(): str(v) for k, v in (headers or {}).items()}
    direct = lowered.get(name.lower(), "")
    if direct:
        return direct.strip()
    authorization = lowered.get("authorization", "")
    if authorization.lower().startswith("bearer "):
        return authorization[7:].strip()
    return ""


def _audit_text(value: Any, limit: int) -> str:
    return " ".join(str(value or "").replace("\x00", "").split())[:limit]


def record_audit(
    db: Any,
    *,
    connector: str,
    direction: str,
    action: str,
    source: str,
    scope: Any = None,
    status_code: Optional[int] = None,
    outcome: str,
    latency_ms: Optional[int] = None,
) -> int:
    """Write one redacted connector audit row.

    The signature has no ``detail``/``error``/``body`` argument on purpose. If a
    caller needs to explain a failure it passes a reason code in ``outcome``;
    free text here is how a contact's note or a signing secret ends up in a log.
    """
    if direction not in ("inbound", "outbound"):
        raise ValueError("audit direction must be inbound or outbound")
    scope_text = ""
    if scope is not None:
        if isinstance(scope, (list, tuple, set)):
            scope_text = ",".join(sorted({_audit_text(item, 60) for item in scope}))
        else:
            scope_text = _audit_text(scope, 200)
    return int(
        db.execute(
            "INSERT INTO connector_audit"
            " (ts_ms, connector, direction, action, source, scope, status_code, outcome, latency_ms)"
            " VALUES (?,?,?,?,?,?,?,?,?)",
            (
                int(time.time() * 1000),
                _audit_text(connector, 40),
                direction,
                _audit_text(action, 80),
                _audit_text(source, 120),
                scope_text,
                None if status_code is None else int(status_code),
                _audit_text(outcome, 80),
                None if latency_ms is None else max(0, int(latency_ms)),
            ),
        )
    )


def audit_rows(db: Any, connector: str, limit: int = 100) -> List[Dict[str, Any]]:
    limit = max(1, min(int(limit or 100), 500))
    rows = db.query(
        "SELECT id, ts_ms, connector, direction, action, source, scope, status_code, outcome, latency_ms"
        " FROM connector_audit WHERE connector = ? ORDER BY id DESC LIMIT ?",
        (connector, limit),
    )
    return [dict(row) for row in rows]


def xml_from_bytes(raw: bytes) -> ET.Element:
    """Parse a DAV response after refusing entity declarations.

    ``xml.etree`` does not fetch external entities, but it does expand internal
    ones; a 2 MB response made of nested entity references is still a CPU
    problem. DAV responses never need a DTD, so the cheap lexical refusal is both
    sufficient and easier to reason about than a hardened parser dependency.
    """
    if not raw:
        raise ConnectorError("response_empty", "DAV server returned an empty body")
    # The whole body, not a prefix: padding with comments/whitespace before the
    # DTD would otherwise move the declaration past a fixed-size scan.
    upper = raw.upper()
    if b"<!DOCTYPE" in upper or b"<!ENTITY" in upper:
        raise ConnectorError("response_unsafe_xml", "DAV response carried a DTD/entity declaration")
    try:
        return ET.fromstring(raw)
    except ET.ParseError as exc:
        raise ConnectorError("response_malformed", "DAV response is not valid XML") from exc


# ───────────────────────────────── self-test ────────────────────────────────


def self_test() -> List[str]:
    checks: List[str] = []

    def check(name: str, condition: bool) -> None:
        if not condition:
            raise AssertionError("connectors self_test failed: %s" % name)
        checks.append(name)

    def refused(name: str, code: str, fn: Any) -> None:
        try:
            fn()
        except ConnectorError as exc:
            check(name, exc.code == code)
        else:
            check(name, False)

    # ── SSRF guard, with controls for every rule ───────────────────────────
    refused("the_metadata_ipv4_is_blocked", "ssrf_blocked",
            lambda: normalize_endpoint_url("https://169.254.169.254/latest/meta-data/", resolve=False))
    refused("the_metadata_ipv4_is_blocked_even_with_allow_private", "ssrf_blocked",
            lambda: normalize_endpoint_url("http://169.254.169.254/", allow_private=True, resolve=False))
    refused("the_metadata_ipv6_is_blocked", "ssrf_blocked",
            lambda: normalize_endpoint_url("https://[fd00:ec2::254]/", allow_private=True, resolve=False))
    refused("the_mapped_metadata_ipv6_is_blocked", "ssrf_blocked",
            lambda: normalize_endpoint_url("https://[::ffff:169.254.169.254]/", allow_private=True, resolve=False))
    refused("the_metadata_hostname_is_blocked_by_name", "ssrf_blocked",
            lambda: normalize_endpoint_url("https://metadata.google.internal/", allow_private=True, resolve=False))
    refused("a_loopback_endpoint_needs_the_private_opt_in", "ssrf_blocked",
            lambda: normalize_endpoint_url("http://127.0.0.1:1880/hook", resolve=False))
    check("a_loopback_endpoint_is_accepted_when_the_opt_in_is_set",
          normalize_endpoint_url("http://127.0.0.1:1880/hook", allow_private=True, resolve=False).scheme == "http")
    refused("a_public_endpoint_must_use_https", "url_scheme",
            lambda: normalize_endpoint_url("http://hooks.example.com/x", resolve=False))
    refused("allow_private_does_not_downgrade_a_public_literal_to_http", "url_scheme",
            lambda: normalize_endpoint_url("http://93.184.216.34/x", allow_private=True, resolve=False))
    check("an_https_public_literal_is_accepted",
          normalize_endpoint_url("https://93.184.216.34/hook", resolve=False).port == 443)
    refused("a_url_with_userinfo_is_refused", "url_userinfo",
            lambda: normalize_endpoint_url("https://user:pass@93.184.216.34/hook", resolve=False))
    refused("a_fragment_is_refused", "url_fragment",
            lambda: normalize_endpoint_url("https://93.184.216.34/hook#x", resolve=False))
    refused("a_non_ascii_host_is_refused", "url_host",
            lambda: normalize_endpoint_url("https://exаmple.com/hook", resolve=False))  # Cyrillic 'а'
    refused("an_unspecified_address_is_refused", "ssrf_blocked",
            lambda: normalize_endpoint_url("https://0.0.0.0/", allow_private=True, resolve=False))
    refused("a_reserved_address_is_refused", "ssrf_blocked",
            lambda: normalize_endpoint_url("https://240.0.0.1/", allow_private=True, resolve=False))
    check("allow_private_does_not_widen_public_https",
          normalize_endpoint_url("https://93.184.216.34/", allow_private=True, resolve=False).host == "93.184.216.34")

    # Resolution is the half a literal-IP test cannot cover: localhost has to be
    # classified as private and refused without the opt-in, and accepted with it.
    refused("a_resolved_loopback_needs_the_opt_in", "ssrf_blocked",
            lambda: normalize_endpoint_url("https://localhost:1880/x", resolve=True))
    check("a_resolved_loopback_is_accepted_with_the_opt_in",
          normalize_endpoint_url("https://localhost:1880/x", allow_private=True, resolve=True).addresses)
    refused("an_unresolvable_host_says_so", "resolve_failed",
            lambda: normalize_endpoint_url("https://does-not-exist.invalid/x", resolve=True))

    # ── XML boundary ───────────────────────────────────────────────────────
    refused("an_xml_dtd_is_refused", "response_unsafe_xml",
            lambda: xml_from_bytes(b'<?xml version="1.0"?><!DOCTYPE x [<!ENTITY y "z">]><x/>'))
    refused("an_empty_xml_body_says_so", "response_empty", lambda: xml_from_bytes(b""))
    refused("malformed_xml_is_a_refusal_not_a_crash", "response_malformed",
            lambda: xml_from_bytes(b"<not-closed>"))
    check("plain_xml_still_parses", xml_from_bytes(b"<d:multistatus xmlns:d='DAV:'/>").tag.endswith("multistatus"))

    # ── time and auth helpers ──────────────────────────────────────────────
    check("iso_z_and_epoch_ms_agree", parse_iso_ms("2026-11-26T00:00:00Z") == 1795651200000)
    check("epoch_ms_round_trips", parse_iso_ms(1795651200000) == 1795651200000)
    check("the_iso_formatter_is_utc", format_iso(1795651200000) == "2026-11-26T00:00:00Z")
    refused("a_non_time_is_a_refusal", "time_invalid", lambda: parse_iso_ms("tomorrow"))
    check("the_basic_header_is_the_standard_b64_form",
          basic_auth_header("alice", "s3cret") == "Basic YWxpY2U6czNjcmV0")
    check("constant_compare_matches_only_equal_strings",
          constant_compare("abc", "abc") and not constant_compare("abc", "abd"))
    check("stable_error_keeps_the_code_not_the_message",
          stable_error(ConnectorError("ssrf_blocked", "https://169.254.169.254/?token=x")) == "ssrf_blocked")
    check("stable_error_never_returns_an_exception_string",
          stable_error(RuntimeError("https://secret@example/x")) == "connector_error")

    # ── audit rows are structural: no content argument exists ──────────────
    import tempfile
    from pathlib import Path

    from app.database import Database

    root = Path(tempfile.mkdtemp(prefix="popopx-connectors-selftest-"))
    try:
        db = Database(root / "connector.db")
        row_id = record_audit(
            db, connector="workflow", direction="outbound", action="delivery",
            source="subscription:sub_1", scope=["message.received"], status_code=200,
            outcome="delivered", latency_ms=12,
        )
        stored = dict(db.query_one("SELECT * FROM connector_audit WHERE id = ?", (row_id,)))
        check("the_audit_row_lands_with_its_scope", stored["scope"] == "message.received"
              and stored["status_code"] == 200 and stored["outcome"] == "delivered")
        check("the_audit_schema_has_no_free_text_column",
              "detail" not in stored and "body" not in stored and "url" not in stored and "secret" not in stored)
        record_audit(db, connector="carddav", direction="inbound", action="query",
                     source="console", outcome="ok")
        check("the_audit_reader_filters_by_connector",
              [r["connector"] for r in audit_rows(db, "workflow")] == ["workflow"]
              and [r["connector"] for r in audit_rows(db, "carddav")] == ["carddav"])
    finally:
        import shutil

        shutil.rmtree(root, ignore_errors=True)

    return checks