# Copyright (c) 2026 POPOPX (popopx.chat)
# SPDX-License-Identifier: AGPL-3.0-only
"""CardDAV contacts, reduced to a work-contact card before it is returned.

The plugin is disabled by default and has no ambient address book: a query must
carry a name/tag keyword, the upstream `addressbook-query` asks the server for at
most a filtered set, and this module stops after five contacts even when the
server ignores the filter. Nothing is cached; the only durable row is the
endpoint configuration and the redacted audit line.

Field policy
------------
``field_allowlist`` defaults to FN/ORG/TITLE/TEL/EMAIL. A configuration that
tries to allow NOTE, ADR, BDAY, PHOTO, KEY, GEO, TZ, LABEL, GENDER or any
``X-`` extension is refused, not silently narrowed: an operator who believes an
allowlist was accepted must not later discover it was not. Even with a widened
allowlist, TEL/EMAIL entries typed ``home``/``private`` are dropped — the brief
asks for work contact details, not the whole personal card.

The response contains only display_name, a small list of labelled values and
tags. There is no raw vCard, no UID, no href, and no unbounded field text.
"""

from __future__ import annotations

import json
import logging
import quopri
import time
from typing import TYPE_CHECKING, Any, Dict, List, Mapping, Optional, Sequence, Tuple

from app import admin_auth
from app.connectors import (
    ConnectorError,
    audit_rows,
    authorize_admin,
    basic_auth_header,
    json_dumps,
    normalize_endpoint_url,
    record_audit,
    request_pinned,
    stable_error,
    xml_from_bytes,
)
from app.plugins import PluginDeps, PluginUnavailable

if TYPE_CHECKING:  # type-only
    from fastapi import APIRouter, Request

    from app.agent_bridge import InboundMessage

__all__ = [
    "PLUGIN_ID",
    "ENDPOINT_KIND",
    "CARDDAV_FIELDS",
    "FORBIDDEN_FIELDS",
    "DEFAULT_ALLOWLIST",
    "parse_allowlist",
    "parse_vcard",
    "contact_record",
    "search_records",
    "build_query_xml",
    "parse_report",
    "create_router",
    "handle_inbound",
    "self_test",
]

LOG = logging.getLogger(__name__)

PLUGIN_ID = "carddav_connector"
# dav_endpoints.connector is CHECKed to the protocol name, not the plugin id.
ENDPOINT_KIND = "carddav"

DEFAULT_ALLOWLIST: Tuple[str, ...] = ("FN", "ORG", "TITLE", "TEL", "EMAIL", "CATEGORIES")
CARDDAV_FIELDS: Tuple[str, ...] = (
    "FN", "N", "NICKNAME", "ORG", "TITLE", "ROLE", "TEL", "EMAIL", "URL", "IMPP", "CATEGORIES",
)
FORBIDDEN_FIELDS: Tuple[str, ...] = (
    "NOTE", "ADR", "BDAY", "ANNIVERSARY", "PHOTO", "LOGO", "KEY", "GEO", "TZ", "LABEL",
    "GENDER", "XML", "KIND", "MEMBER", "RELATED", "REV", "UID", "PRODID", "VERSION",
)
HOME_TYPES = frozenset({"home", "private", "personal"})
MAX_RESULTS = 5
MAX_TERM_CHARS = 80
MAX_BODY_BYTES = 64 * 1024
MAX_RESPONSE_BYTES = 4 * 1024 * 1024
MAX_FIELD_VALUE = 240
MAX_FIELDS = 8
MAX_TAGS = 10
DAV_NS = "DAV:"
CARD_NS = "urn:ietf:params:xml:ns:carddav"
CONTENT_TYPE_XML = 'application/xml; charset="utf-8"'


def _now_ms() -> int:
    return int(time.time() * 1000)


def parse_allowlist(raw: Any) -> Tuple[str, ...]:
    """Accept only known, non-private vCard properties. Empty means the default."""
    if raw is None or raw == "":
        return DEFAULT_ALLOWLIST
    if isinstance(raw, str):
        try:
            parsed = json.loads(raw)
        except ValueError:
            parsed = [part.strip() for part in raw.split(",")]
    else:
        parsed = raw
    if not isinstance(parsed, (list, tuple, set)):
        raise ConnectorError("field_allowlist_invalid", "field_allowlist must be a list of vCard property names")
    cleaned: List[str] = []
    for item in parsed:
        name = str(item).strip().upper()
        if not name:
            continue
        if name.startswith("X-") or name in FORBIDDEN_FIELDS:
            raise ConnectorError("field_forbidden", "%s may never be exposed" % name)
        if name not in CARDDAV_FIELDS:
            raise ConnectorError("field_unknown", "%s is not an allowlistable CardDAV field" % name)
        if name not in cleaned:
            cleaned.append(name)
    if not cleaned:
        raise ConnectorError("field_allowlist_empty", "field_allowlist must name at least one field")
    return tuple(cleaned)


# ─────────────────────────────────── vCard ──────────────────────────────────


def _unfold(text: str) -> List[str]:
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    lines: List[str] = []
    for raw in text.split("\n"):
        if raw.startswith((" ", "\t")) and lines:
            lines[-1] += raw[1:]
        elif raw:
            lines.append(raw)
    return lines


def _split_outside_quotes(text: str, delimiter: str) -> List[str]:
    parts: List[str] = []
    current: List[str] = []
    quoted = False
    escaped = False
    for char in text:
        if escaped:
            current.append(char)
            escaped = False
            continue
        if char == "\\":
            current.append(char)
            escaped = True
            continue
        if char == '"':
            quoted = not quoted
            current.append(char)
            continue
        if char == delimiter and not quoted:
            parts.append("".join(current))
            current = []
            continue
        current.append(char)
    parts.append("".join(current))
    return parts


def _unquote(value: str) -> str:
    value = value.strip()
    if len(value) >= 2 and value[0] == '"' and value[-1] == '"':
        value = value[1:-1]
    return value.replace('\\"', '"')


def _unescape_text(value: str) -> str:
    out: List[str] = []
    index = 0
    while index < len(value):
        char = value[index]
        if char == "\\" and index + 1 < len(value):
            nxt = value[index + 1]
            if nxt in ("n", "N"):
                out.append("\n")
            elif nxt in ("\\", ",", ";", ":"):
                out.append(nxt)
            else:
                out.append(nxt)
            index += 2
            continue
        out.append(char)
        index += 1
    return "".join(out)


def _decode_value(value: str, params: Mapping[str, Tuple[str, ...]]) -> str:
    encoding = " ".join(params.get("ENCODING", ())).upper()
    if "QUOTED-PRINTABLE" in encoding or "QUOTED-PRINTABLE" in params:
        try:
            raw = quopri.decodestring(value.encode("latin-1"))
        except Exception:  # noqa: BLE001
            raw = value.encode("utf-8", "replace")
        return raw.decode("utf-8", "replace")
    return value


def _parse_property_line(line: str) -> Optional[Tuple[str, Dict[str, Tuple[str, ...]], str]]:
    segments = _split_outside_quotes(line, ":")
    if len(segments) < 2:
        return None
    name_part = segments[0]
    value = ":".join(segments[1:])
    tokens = _split_outside_quotes(name_part, ";")
    raw_name = tokens[0].strip()
    if not raw_name:
        return None
    # A group prefix such as `item1.TEL` is not part of the property name.
    name = raw_name.rsplit(".", 1)[-1].strip().upper()
    if not name:
        return None
    params: Dict[str, Tuple[str, ...]] = {}
    for token in tokens[1:]:
        if not token:
            continue
        key, sep, raw_values = token.partition("=")
        key = key.strip().upper()
        if not key:
            continue
        if sep:
            values: List[str] = []
            for part in _split_outside_quotes(raw_values, ","):
                part_value = _unquote(part).strip().lower()
                if not part_value:
                    continue
                # ``TYPE="work,voice"`` is how some clients spell a multi-valued
                # parameter; the quotes group the list, they are not part of one
                # type. Other parameters keep a quoted comma intact.
                if key == "TYPE":
                    values.extend(piece.strip() for piece in part_value.split(",") if piece.strip())
                else:
                    values.append(part_value)
            params[key] = params.get(key, ()) + tuple(values)
        else:
            params[key] = params.get(key, ()) + (key.lower(),)
    return name, params, _decode_value(value, params)


def parse_vcard(raw: str) -> List[Tuple[str, Dict[str, Tuple[str, ...]], str]]:
    """One vCard -> a flat list of (PROPERTY, params, value).

    Parsing is deliberately property-agnostic; the privacy decision is made in
    :func:`contact_record` from the allowlist, so a property this module has
    never heard of still has to be named before it can escape.
    """
    if not isinstance(raw, str):
        return []
    props: List[Tuple[str, Dict[str, Tuple[str, ...]], str]] = []
    for line in _unfold(raw):
        if line.strip().upper() in ("BEGIN:VCARD", "END:VCARD"):
            continue
        parsed = _parse_property_line(line)
        if parsed is not None:
            props.append(parsed)
    return props


def _values(props: Sequence[Tuple[str, Dict[str, Tuple[str, ...]], str]], name: str) -> List[Tuple[Dict[str, Tuple[str, ...]], str]]:
    return [(params, value) for prop, params, value in props if prop == name]


def _work_contact_value(params: Mapping[str, Tuple[str, ...]], value: str) -> Optional[str]:
    types = set(params.get("TYPE", ()))
    if types & HOME_TYPES:
        return None
    text = _unescape_text(value).strip()
    if not text:
        return None
    if text.lower().startswith("tel:"):
        text = text[4:]
    if len(text) > MAX_FIELD_VALUE:
        text = text[:MAX_FIELD_VALUE]
    return text


def contact_record(props: Sequence[Tuple[str, Dict[str, Tuple[str, ...]], str]], allowlist: Sequence[str]) -> Optional[Dict[str, Any]]:
    allowed = [name for name in allowlist if name in CARDDAV_FIELDS and name not in FORBIDDEN_FIELDS]
    display_name = ""
    for _, value in _values(props, "FN"):
        display_name = _unescape_text(value).strip()
        if display_name:
            break
    if not display_name:
        return None
    fields: List[Dict[str, str]] = []
    tags: List[str] = []

    def add(label: str, value: str) -> None:
        if len(fields) >= MAX_FIELDS:
            return
        value = value.strip()[:MAX_FIELD_VALUE]
        if value and all(existing["v"] != value for existing in fields):
            fields.append({"k": label[:80], "v": value})

    for name in allowed:
        if name == "FN":
            continue
        if name == "CATEGORIES":
            for _, value in _values(props, name):
                for tag in _unescape_text(value).split(","):
                    tag = tag.strip()
                    if tag and tag not in tags and len(tags) < MAX_TAGS:
                        tags.append(tag[:40])
            continue
        if name == "ORG":
            for _, value in _values(props, name):
                add("组织", _unescape_text(value).replace(";", " / "))
            continue
        if name == "TITLE":
            for _, value in _values(props, name):
                add("职位", _unescape_text(value))
            continue
        if name == "ROLE":
            for _, value in _values(props, name):
                add("角色", _unescape_text(value))
            continue
        if name == "N":
            for _, value in _values(props, name):
                add("姓名结构", _unescape_text(value).replace(";", " "))
            continue
        if name == "NICKNAME":
            for _, value in _values(props, name):
                add("昵称", _unescape_text(value))
            continue
        if name == "URL":
            for _, value in _values(props, name):
                add("主页", _unescape_text(value))
            continue
        if name == "IMPP":
            for _, value in _values(props, name):
                add("即时通讯", _unescape_text(value))
            continue
        if name in ("TEL", "EMAIL"):
            values = _values(props, name)
            kept = 0
            for params, raw_value in values:
                if kept >= 2:
                    break
                value = _work_contact_value(params, raw_value)
                if value is None:
                    continue
                add("工作电话" if name == "TEL" else "工作邮箱", value)
                kept += 1
    return {"display_name": display_name[:120], "fields": fields[:MAX_FIELDS], "tags": tags[:MAX_TAGS]}


def _matches(record: Mapping[str, Any], term: str) -> bool:
    needle = term.casefold()
    if needle in str(record.get("display_name") or "").casefold():
        return True
    if any(needle in tag.casefold() for tag in record.get("tags") or []):
        return True
    return any(needle in str(field.get("v") or "").casefold() for field in record.get("fields") or [])


def search_records(raw_vcards: Sequence[str], term: str, allowlist: Sequence[str], *, limit: int = MAX_RESULTS) -> Tuple[List[Dict[str, Any]], int]:
    """Return (records, scanned). The cap is applied here, after the server, so a
    server that ignores the CardDAV filter cannot return the whole address book."""
    needle = str(term or "").strip()
    if not needle:
        return [], 0
    cap = max(1, min(MAX_RESULTS, int(limit)))
    out: List[Dict[str, Any]] = []
    scanned = 0
    for raw in raw_vcards:
        scanned += 1
        record = contact_record(parse_vcard(raw), allowlist)
        if record is None:
            continue
        if _matches(record, needle):
            out.append(record)
        if len(out) >= cap:
            break
    return out, scanned


def build_query_xml(term: str) -> bytes:
    needle = (
        str(term)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
    )
    body = (
        '<?xml version="1.0" encoding="utf-8"?>\n'
        '<C:addressbook-query xmlns:D="DAV:" xmlns:C="urn:ietf:params:xml:ns:carddav">\n'
        "  <D:prop><D:getetag/><C:address-data/></D:prop>\n"
        '  <C:filter test="anyof">\n'
        '    <C:prop-filter name="FN"><C:text-match collation="i;unicode-casemap" match-type="contains">%s</C:text-match></C:prop-filter>\n'
        '    <C:prop-filter name="ORG"><C:text-match collation="i;unicode-casemap" match-type="contains">%s</C:text-match></C:prop-filter>\n'
        '    <C:prop-filter name="NICKNAME"><C:text-match collation="i;unicode-casemap" match-type="contains">%s</C:text-match></C:prop-filter>\n'
        '    <C:prop-filter name="CATEGORIES"><C:text-match collation="i;unicode-casemap" match-type="contains">%s</C:text-match></C:prop-filter>\n'
        "  </C:filter>\n"
        "</C:addressbook-query>\n"
    ) % (needle, needle, needle, needle)
    return body.encode("utf-8")


def parse_report(raw: bytes) -> List[str]:
    root = xml_from_bytes(raw)
    cards: List[str] = []
    for response in root.iter("{%s}response" % DAV_NS):
        ok = False
        card_text = None
        for propstat in response.iter("{%s}propstat" % DAV_NS):
            status = propstat.find("{%s}status" % DAV_NS)
            if status is None or " 200 " not in (" %s " % (status.text or "")):
                continue
            for data in propstat.iter("{%s}address-data" % CARD_NS):
                if data.text and data.text.strip():
                    ok = True
                    card_text = data.text
        if ok and card_text:
            cards.append(card_text)
    return cards


# ─────────────────────────────────── config ─────────────────────────────────


def _config_row(deps: PluginDeps) -> Optional[Dict[str, Any]]:
    row = deps.db.query_one("SELECT * FROM dav_endpoints WHERE connector = ?", (ENDPOINT_KIND,))
    return dict(row) if row is not None else None


def _public_config(row: Optional[Mapping[str, Any]]) -> Dict[str, Any]:
    if row is None:
        return {"configured": False}
    try:
        allowlist = list(parse_allowlist(row.get("field_allowlist")))
    except ConnectorError:
        allowlist = list(DEFAULT_ALLOWLIST)
    return {
        "configured": True,
        "url": str(row.get("url") or ""),
        "username": str(row.get("username") or ""),
        "password_set": bool(row.get("password")),
        "allow_private": bool(row.get("allow_private")),
        "field_allowlist": allowlist,
        "updated_at_ms": row.get("updated_at_ms"),
        "last_probe_ms": row.get("last_probe_ms"),
        "last_probe_status": row.get("last_probe_status"),
        "last_probe_error": row.get("last_probe_error"),
    }


async def _dav_request(deps: PluginDeps, row: Mapping[str, Any], *, method: str, body: Optional[bytes], depth: str) -> Any:
    endpoint = normalize_endpoint_url(str(row.get("url") or ""), allow_private=bool(row.get("allow_private")))
    headers = {
        "Depth": depth,
        "Content-Type": CONTENT_TYPE_XML,
        "Accept": "application/xml, text/xml",
        "User-Agent": "POPOPX-CardDAV/1.0",
    }
    plain_password = deps.vault.open(str(row.get("password") or ""), table="dav_endpoints",
                                    column="password", subject=ENDPOINT_KIND)
    auth = basic_auth_header(str(row.get("username") or ""), plain_password)
    if auth:
        headers["Authorization"] = auth
    return await _run_pinned(method, endpoint.origin + endpoint.target, headers, body or b"", bool(row.get("allow_private")))


async def _run_pinned(method: str, url: str, headers: Mapping[str, str], body: bytes, allow_private: bool) -> Any:
    import asyncio

    return await asyncio.get_running_loop().run_in_executor(
        None,
        lambda: request_pinned(url, method=method, headers=headers, body=body, timeout=15.0,
                               max_bytes=MAX_RESPONSE_BYTES, allow_private=allow_private),
    )


def create_router(deps: PluginDeps) -> "APIRouter":
    from fastapi import APIRouter, Request
    from fastapi.responses import JSONResponse

    globals()["Request"] = Request
    router = APIRouter(prefix=deps.spec.url_prefix, tags=["carddav_connector"])

    def json_response(status: int, body: Mapping[str, Any]) -> "JSONResponse":
        return JSONResponse(status_code=int(status), content=dict(body))

    def admin_refused(request: "Request") -> Optional[Any]:
        if admin_auth.grant_from_request(request) is not None:
            return None
        ok, reason = authorize_admin(request.headers, getattr(deps.config, "admin_token", ""))
        if ok:
            return None
        return json_response(401, {"ok": False, "plugin": PLUGIN_ID, "reason": "unauthorized", "detail": reason})

    async def read_json(request: "Request") -> Tuple[Any, Optional[Any]]:
        try:
            raw = await request.body()
        except Exception:  # noqa: BLE001
            return None, json_response(400, {"ok": False, "error": "body_unreadable"})
        if len(raw) > MAX_BODY_BYTES:
            return None, json_response(413, {"ok": False, "error": "body_too_large"})
        if not raw.strip():
            return {}, None
        try:
            parsed = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            return None, json_response(400, {"ok": False, "error": "body_invalid_json"})
        if not isinstance(parsed, dict):
            return None, json_response(400, {"ok": False, "error": "body_not_object"})
        return parsed, None

    @router.get("/status")
    async def status(request: "Request") -> Any:
        refusal = admin_refused(request)
        if refusal is not None:
            return refusal
        row = _config_row(deps)
        return {"ok": True, "plugin": PLUGIN_ID, "config": _public_config(row), "gate": deps.gate.status(PLUGIN_ID).as_body()}

    @router.get("/config")
    async def config_get(request: "Request") -> Any:
        refusal = admin_refused(request)
        if refusal is not None:
            return refusal
        return {"ok": True, "plugin": PLUGIN_ID, "config": _public_config(_config_row(deps))}

    @router.put("/config")
    async def config_put(request: "Request") -> Any:
        refusal = admin_refused(request)
        if refusal is not None:
            return refusal
        body, error = await read_json(request)
        if error is not None:
            return error
        current = _config_row(deps)
        try:
            allowlist = parse_allowlist(body.get("field_allowlist", (current or {}).get("field_allowlist")))
            endpoint = normalize_endpoint_url(body.get("url", (current or {}).get("url")), allow_private=bool(body.get("allow_private", (current or {}).get("allow_private"))))
        except ConnectorError as exc:
            return json_response(exc.http_status, {"ok": False, "error": exc.code, "detail": exc.message})
        username = str(body.get("username", (current or {}).get("username") or ""))[:200]
        if body.get("password") is not None:
            password = str(body.get("password"))
            if len(password) > 512:
                return json_response(400, {"ok": False, "error": "password_too_long"})
            stored_password = deps.vault.seal(password, table="dav_endpoints",
                                              column="password", subject=ENDPOINT_KIND)
        else:
            # A reused value may already be sealed; pass it through untouched.
            stored_password = str((current or {}).get("password") or "")
        now = _now_ms()
        deps.db.execute(
            "INSERT INTO dav_endpoints (connector, url, username, password, allow_private, field_allowlist, updated_at_ms)"
            " VALUES (?,?,?,?,?,?,?)"
            " ON CONFLICT(connector) DO UPDATE SET url = excluded.url, username = excluded.username,"
            " password = excluded.password, allow_private = excluded.allow_private,"
            " field_allowlist = excluded.field_allowlist, updated_at_ms = excluded.updated_at_ms",
            (ENDPOINT_KIND, endpoint.origin + endpoint.target, username, stored_password, int(bool(body.get("allow_private", (current or {}).get("allow_private")))), json_dumps(list(allowlist)), now),
        )
        record_audit(deps.db, connector="carddav", direction="outbound", action="config.update",
                     source="admin", outcome="updated", status_code=200)
        return {"ok": True, "plugin": PLUGIN_ID, "config": _public_config(_config_row(deps))}

    @router.post("/probe")
    async def probe(request: "Request") -> Any:
        refusal = admin_refused(request)
        if refusal is not None:
            return refusal
        row = _config_row(deps)
        if row is None:
            return json_response(409, {"ok": False, "error": "not_configured"})
        started = _now_ms()
        body = (
            '<?xml version="1.0" encoding="utf-8"?>\n'
            '<D:propfind xmlns:D="DAV:"><D:prop><D:resourcetype/><D:displayname/></D:prop></D:propfind>\n'
        ).encode("utf-8")
        try:
            response = await _dav_request(deps, row, method="PROPFIND", body=body, depth="0")
            ok = 200 <= response.status < 300
            dav = False
            if ok:
                try:
                    root = xml_from_bytes(response.body)
                    dav = root.tag == "{%s}multistatus" % DAV_NS
                except ConnectorError:
                    dav = False
            deps.db.execute(
                "UPDATE dav_endpoints SET last_probe_ms = ?, last_probe_status = ?, last_probe_error = ? WHERE connector = ?",
                (_now_ms(), int(response.status), None if ok else "http_%d" % response.status, PLUGIN_ID),
            )
            record_audit(deps.db, connector="carddav", direction="outbound", action="probe",
                         source="admin", status_code=int(response.status),
                         outcome="ok" if ok and dav else "not_dav", latency_ms=_now_ms() - started)
            return {"ok": ok and dav, "status": int(response.status), "dav": dav,
                    "latency_ms": _now_ms() - started}
        except ConnectorError as exc:
            deps.db.execute(
                "UPDATE dav_endpoints SET last_probe_ms = ?, last_probe_status = ?, last_probe_error = ? WHERE connector = ?",
                (_now_ms(), exc.http_status, exc.code, PLUGIN_ID),
            )
            record_audit(deps.db, connector="carddav", direction="outbound", action="probe",
                         source="admin", status_code=exc.http_status, outcome=exc.code,
                         latency_ms=_now_ms() - started)
            return json_response(exc.http_status, {"ok": False, "error": exc.code, "detail": exc.message})
        except Exception as exc:  # noqa: BLE001
            code = stable_error(exc)
            record_audit(deps.db, connector="carddav", direction="outbound", action="probe",
                         source="admin", outcome=code, latency_ms=_now_ms() - started)
            return json_response(502, {"ok": False, "error": code})

    @router.post("/query")
    async def query(request: "Request") -> Any:
        refusal = admin_refused(request)
        if refusal is not None:
            return refusal
        body, error = await read_json(request)
        if error is not None:
            return error
        term = str(body.get("term") or "").strip()
        if not term:
            return json_response(400, {"ok": False, "error": "term_required",
                                       "detail": "a keyword is required; this connector never lists the address book"})
        if len(term) > MAX_TERM_CHARS:
            return json_response(400, {"ok": False, "error": "term_too_long"})
        try:
            limit = int(body.get("limit") or MAX_RESULTS)
        except (TypeError, ValueError):
            return json_response(400, {"ok": False, "error": "limit_invalid"})
        limit = max(1, min(MAX_RESULTS, limit))
        row = _config_row(deps)
        if row is None:
            return json_response(409, {"ok": False, "error": "not_configured"})
        try:
            deps.require()
        except PluginUnavailable as exc:
            record_audit(deps.db, connector="carddav", direction="outbound", action="query",
                         source="admin", outcome=exc.decision.reason, status_code=exc.http_status)
            return json_response(exc.http_status, exc.decision.as_body())
        allowlist = parse_allowlist(row.get("field_allowlist"))
        started = _now_ms()
        try:
            charge = deps.charge(ref="carddav:query")
            try:
                response = await _dav_request(deps, row, method="REPORT", body=build_query_xml(term), depth="1")
                if response.status not in (200, 207):
                    raise ConnectorError("dav_status", "DAV server answered %d" % response.status, http_status=502)
                cards = parse_report(response.body)
                results, scanned = search_records(cards, term, allowlist, limit=limit)
            except Exception:
                if int(getattr(charge, "charged", 0) or 0) > 0:
                    try:
                        deps.billing.refund(amount=int(charge.charged), reason="carddav query failed", ref="carddav:query")
                    except Exception:  # noqa: BLE001
                        LOG.exception("carddav refund failed")
                raise
            record_audit(deps.db, connector="carddav", direction="outbound", action="query",
                         source="admin", status_code=int(response.status), outcome="ok",
                         latency_ms=_now_ms() - started)
            return {
                "ok": True,
                "plugin": PLUGIN_ID,
                "term": term,
                "results": results,
                "returned": len(results),
                "scanned": scanned,
                "cap": MAX_RESULTS,
                "charged": int(charge.charged),
            }
        except ConnectorError as exc:
            record_audit(deps.db, connector="carddav", direction="outbound", action="query",
                         source="admin", status_code=exc.http_status, outcome=exc.code,
                         latency_ms=_now_ms() - started)
            return json_response(exc.http_status, {"ok": False, "error": exc.code, "detail": exc.message})
        except Exception as exc:  # noqa: BLE001
            code = stable_error(exc)
            record_audit(deps.db, connector="carddav", direction="outbound", action="query",
                         source="admin", outcome=code, latency_ms=_now_ms() - started)
            return json_response(502, {"ok": False, "error": code})

    @router.get("/audit")
    async def audit(request: "Request") -> Any:
        refusal = admin_refused(request)
        if refusal is not None:
            return refusal
        limit = int(request.query_params.get("limit") or 100)
        return {"ok": True, "plugin": PLUGIN_ID, "audit": audit_rows(deps.db, "carddav", limit)}

    return router


async def handle_inbound(deps: PluginDeps, message: "InboundMessage") -> bool:
    return False


# ───────────────────────────────── self-test ────────────────────────────────

_SAMPLE_VCARD = (
    "BEGIN:VCARD\r\n"
    "VERSION:3.0\r\n"
    "FN:张伟\r\n"
    "N:张;伟;;;\r\n"
    "ORG:Popopx;Platform\r\n"
    "TITLE:平台工程师\r\n"
    "TEL;TYPE=WORK,VOICE:+86 10 5555 0100\r\n"
    "TEL;TYPE=HOME:+86 138 0000 0000\r\n"
    "EMAIL;TYPE=WORK:zhang.wei@popopx.example\r\n"
    "EMAIL;TYPE=HOME:private@example.invalid\r\n"
    "ADR;TYPE=HOME:;;1 Private Road;Beijing;;100000;China\r\n"
    "NOTE:assistant note: prefers WhatsApp, do not share\r\n"
    "BDAY:19700101\r\n"
    "CATEGORIES:platform,oncall\r\n"
    "END:VCARD\r\n"
)


def self_test() -> List[str]:
    checks: List[str] = []

    def check(name: str, condition: bool) -> None:
        if not condition:
            raise AssertionError("carddav self_test failed: %s" % name)
        checks.append(name)

    def refused(name: str, code: str, fn: Any) -> None:
        try:
            fn()
        except ConnectorError as exc:
            check(name, exc.code == code)
        else:
            check(name, False)

    # ── vCard folding, groups, quoting and quoted-printable ────────────────
    folded = parse_vcard(
        "BEGIN:VCARD\r\nFN:Very Long \r\n Name\r\nitem1.TEL;TYPE=\"work,voice\":tel:+1-555\r\n"
        "NOTE;ENCODING=QUOTED-PRINTABLE:hello=20world\r\nEND:VCARD\r\n"
    )
    check("a_folded_line_is_joined", any(name == "FN" and value == "Very Long Name" for name, _, value in folded))
    check("a_group_prefix_is_not_the_property_name", any(name == "TEL" and value == "tel:+1-555" for name, _, value in folded))
    check("a_quoted_parameter_keeps_its_comma", any(name == "TEL" and params.get("TYPE") == ("work", "voice") for name, params, _ in folded))
    check("quoted_printable_is_decoded", any(name == "NOTE" and value == "hello world" for name, _, value in folded))

    # ── the privacy strip ──────────────────────────────────────────────────
    props = parse_vcard(_SAMPLE_VCARD)
    record = contact_record(props, DEFAULT_ALLOWLIST)
    check("a_card_with_four_fields_is_returned", record is not None and record["display_name"] == "张伟")
    serialized = json_dumps(record)
    check("the_private_note_is_gone", "assistant note" not in serialized and "WhatsApp" not in serialized)
    check("the_home_address_is_gone", "1 Private Road" not in serialized and "Beijing" not in serialized)
    check("the_birthday_is_gone", "1970" not in serialized)
    check("the_home_phone_is_gone", "138 0000 0000" not in serialized)
    check("the_home_email_is_gone", "private@example.invalid" not in serialized)
    check("the_work_phone_is_kept", "5555 0100" in serialized)
    check("the_work_email_is_kept", "zhang.wei@popopx.example" in serialized)
    check("the_org_is_kept_and_flattened", "Popopx / Platform" in serialized)
    check("the_tags_are_kept", record["tags"] == ["platform", "oncall"])
    check("no_forbidden_key_is_ever_present",
          not ({"NOTE", "ADR", "BDAY", "note", "adr", "bday"} & set(record)))

    # ── allowlist policy ───────────────────────────────────────────────────
    refused("note_may_not_be_allowlisted", "field_forbidden", lambda: parse_allowlist(["FN", "NOTE"]))
    refused("address_may_not_be_allowlisted", "field_forbidden", lambda: parse_allowlist(["ADR"]))
    refused("birthday_may_not_be_allowlisted", "field_forbidden", lambda: parse_allowlist(["BDAY"]))
    refused("an_unknown_property_may_not_be_allowlisted", "field_unknown", lambda: parse_allowlist(["FN", "SOCIAL"]))
    refused("the_allowlist_may_not_be_empty", "field_allowlist_empty", lambda: parse_allowlist([]))
    check("the_default_allowlist_is_the_six_work_fields", parse_allowlist(None) == DEFAULT_ALLOWLIST)
    check("a_json_string_allowlist_is_accepted", parse_allowlist('["fn","tel"]') == ("FN", "TEL"))
    widened = contact_record(props, ("FN", "N", "NICKNAME", "ORG", "TITLE", "ROLE", "TEL", "EMAIL", "URL", "IMPP"))
    check("a_wider_allowlist_still_drops_home_contacts",
          "138 0000 0000" not in json_dumps(widened) and "private@example.invalid" not in json_dumps(widened))
    check("a_wider_allowlist_still_has_no_note_or_address",
          not any(token in json_dumps(widened) for token in ("assistant note", "Private Road", "19700101")))

    # ── result cap and keyword scoping ─────────────────────────────────────
    many = [
        _SAMPLE_VCARD.replace("FN:张伟", "FN:Contact %d" % index).replace("CATEGORIES:platform,oncall", "CATEGORIES:team")
        for index in range(8)
    ]
    results, scanned = search_records(many, "contact", DEFAULT_ALLOWLIST)
    check("the_result_cap_is_five", len(results) == 5)
    check("the_scan_stops_at_the_cap", scanned == 5)
    check("a_smaller_limit_is_honoured", len(search_records(many, "contact", DEFAULT_ALLOWLIST, limit=2)[0]) == 2)
    check("a_limit_above_five_is_still_capped", len(search_records(many, "contact", DEFAULT_ALLOWLIST, limit=50)[0]) == 5)
    check("a_keyword_search_is_required", search_records(many, "   ", DEFAULT_ALLOWLIST) == ([], 0))
    check("a_tag_keyword_matches", len(search_records(many, "team", DEFAULT_ALLOWLIST)[0]) == 5)
    check("a_name_keyword_matches", len(search_records(many, "Contact 7", DEFAULT_ALLOWLIST)[0]) == 1)
    check("a_non_matching_keyword_returns_nothing", search_records(many, "payroll", DEFAULT_ALLOWLIST)[0] == [])

    # ── addressbook-query XML ──────────────────────────────────────────────
    xml = build_query_xml("R&D <ops>")
    check("the_query_is_an_addressbook_query", b"<C:addressbook-query" in xml)
    check("the_query_escapes_the_keyword", b"R&amp;D &lt;ops&gt;" in xml and b"<ops>" not in xml)
    check("the_query_asks_for_address_data", b"<C:address-data/>" in xml)
    check("the_query_filters_by_name", b'prop-filter name="FN"' in xml)

    report = (
        '<?xml version="1.0"?>\n'
        '<D:multistatus xmlns:D="DAV:" xmlns:C="urn:ietf:params:xml:ns:carddav">'
        "<D:response><D:href>/addressbooks/alice/team/1.vcf</D:href><D:propstat>"
        "<D:prop><C:address-data>" + _escape_xml(_SAMPLE_VCARD) + "</C:address-data></D:prop>"
        "<D:status>HTTP/1.1 200 OK</D:status></D:propstat></D:response>"
        "<D:response><D:href>/addressbooks/alice/team/2.vcf</D:href><D:propstat>"
        "<D:prop><C:address-data>BEGIN:VCARD\nFN:李娜\nTEL;TYPE=WORK:+1 555 0111\nEND:VCARD</C:address-data></D:prop>"
        "<D:status>HTTP/1.1 200 OK</D:status></D:propstat></D:response>"
        "</D:multistatus>"
    )
    cards = parse_report(report.encode("utf-8"))
    check("both_report_entries_produce_a_vcard", len(cards) == 2)
    check("a_report_vcard_is_parsed_not_returned", "BEGIN:VCARD" not in json_dumps(search_records(cards, "李娜", DEFAULT_ALLOWLIST)[0]))
    refused("a_report_with_a_dtd_is_refused", "response_unsafe_xml",
            lambda: parse_report(b'<!DOCTYPE x [<!ENTITY y "z">]><D:multistatus xmlns:D="DAV:"/>'))
    refused("a_malformed_report_is_refused", "response_malformed", lambda: parse_report(b"<not-xml"))

    # ── config and query helpers ───────────────────────────────────────────
    check("a_public_config_never_contains_the_password", "password" not in _public_config(
        {"connector": PLUGIN_ID, "url": "https://dav.example/x", "username": "u", "password": "p",
         "allow_private": 0, "field_allowlist": '["FN"]'}))
    check("a_public_config_reports_only_that_a_password_exists", _public_config(
        {"connector": PLUGIN_ID, "url": "https://dav.example/x", "username": "u", "password": "p",
         "allow_private": 0, "field_allowlist": '["FN"]'})["password_set"] is True)

    # ── the dav_endpoints CHECK names the protocol, not the plugin id ──────
    import tempfile
    from pathlib import Path

    from app.database import Database

    root = Path(tempfile.mkdtemp(prefix="popopx-carddav-selftest-"))
    try:
        db = Database(root / "dav.db")
        db.execute(
            "INSERT INTO dav_endpoints (connector,url,username,password,allow_private,field_allowlist,updated_at_ms)"
            " VALUES (?,?,?,?,?,?,?)",
            (ENDPOINT_KIND, "https://dav.example/x", "", "", 0, '["FN"]', 1),
        )
        check("the_config_row_is_read_by_the_schema_protocol_name",
              _config_row(type("D", (), {"db": db})())["url"] == "https://dav.example/x")
    finally:
        import shutil

        shutil.rmtree(root, ignore_errors=True)

    return checks


def _escape_xml(text: str) -> str:
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")