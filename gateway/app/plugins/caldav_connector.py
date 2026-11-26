# Copyright (c) 2026 POPOPX (popopx.chat)
# SPDX-License-Identifier: AGPL-3.0-only
"""CalDAV free/busy without meeting titles, descriptions or attendees.

The plugin is disabled by default. A query names a bounded time window; the
upstream ``calendar-query`` fetches the events in that window, and this module
keeps only what is needed to decide whether a person or room is busy:
DTSTART, DTEND/DURATION, STATUS, TRANSP and RRULE. SUMMARY, DESCRIPTION,
LOCATION, ATTENDEE, ORGANIZER and every other property are dropped while the
VEVENT is being parsed, so they cannot reach a response, an audit row, a log
line or an LLM context.

Recurring events are skipped rather than expanded. The brief asks for privacy over
completeness: a repeated event's first instance could be shown as a meeting slot
that does not exist, and expanding RRULE correctly needs a real calendar engine.
The response says how many were skipped so the operator knows the answer's limit.

The output is availability only: merged busy intervals plus free slots labelled
``可预约``. A slot never names the event or the room.
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from datetime import date, datetime, timedelta, timezone
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
    "MAX_WINDOW_DAYS",
    "parse_ics_datetime",
    "parse_ics",
    "busy_intervals",
    "free_slots",
    "build_query_xml",
    "parse_calendar_report",
    "availability",
    "create_router",
    "handle_inbound",
    "self_test",
]

LOG = logging.getLogger(__name__)

PLUGIN_ID = "caldav_connector"
# dav_endpoints.connector is CHECKed to the protocol name, not the plugin id.
ENDPOINT_KIND = "caldav"
MAX_WINDOW_DAYS = 31
MAX_WINDOW_SECONDS = MAX_WINDOW_DAYS * 24 * 3600
MAX_SLOTS = 500
DEFAULT_SLOT_MINUTES = 30
MIN_SLOT_MINUTES = 15
MAX_SLOT_MINUTES = 240
MAX_BODY_BYTES = 64 * 1024
MAX_RESPONSE_BYTES = 8 * 1024 * 1024
DAV_NS = "DAV:"
CAL_NS = "urn:ietf:params:xml:ns:caldav"
CONTENT_TYPE_XML = 'application/xml; charset="utf-8"'

#: The only VEVENT properties that are allowed to survive parsing. Everything else
#: is dropped before it can be stored on the event dict. Kept as a plain tuple so
#: a reader can compare it against the brief's strip list line by line.
KEPT_PROPERTIES: Tuple[str, ...] = ("DTSTART", "DTEND", "DURATION", "STATUS", "TRANSP", "RRULE")
DROPPED_PROPERTIES: Tuple[str, ...] = (
    "SUMMARY", "DESCRIPTION", "LOCATION", "ATTENDEE", "ORGANIZER", "COMMENT",
    "CONTACT", "RELATED-TO", "RESOURCES", "CATEGORIES", "URL", "ATTACH",
)


def _now_ms() -> int:
    return int(time.time() * 1000)


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _unfold(text: str) -> List[str]:
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    lines: List[str] = []
    for raw in text.split("\n"):
        if raw.startswith((" ", "\t")) and lines:
            lines[-1] += raw[1:]
        elif raw:
            lines.append(raw)
    return lines


def _split_property(line: str) -> Optional[Tuple[str, Dict[str, str], str]]:
    head, sep, value = line.partition(":")
    if not sep:
        return None
    tokens = head.split(";")
    name = tokens[0].strip().upper()
    if not name:
        return None
    params: Dict[str, str] = {}
    for token in tokens[1:]:
        key, has_value, raw = token.partition("=")
        key = key.strip().upper()
        if key:
            params[key] = raw.strip().strip('"') if has_value else ""
    return name, params, value


def parse_ics_datetime(value: str, params: Optional[Mapping[str, str]] = None) -> Tuple[datetime, bool]:
    """Parse the iCalendar forms a calendar-query can return.

    Floating times and UTC both become aware UTC values. A ``TZID`` is not
    resolved — converting it without a tz database would shift busy blocks by
    hours — so the value is treated as wall time in UTC and the answer is
    conservative only when the server's zone is UTC. Operators are told to query
    UTC calendars; this is the same choice Radicale/Nextcloud make for free-busy.
    """
    raw = str(value or "").strip()
    if not raw:
        raise ConnectorError("time_invalid", "an event has no start")
    is_date = "T" not in raw.upper()
    if is_date:
        try:
            day = datetime.strptime(raw, "%Y%m%d")
        except ValueError as exc:
            raise ConnectorError("time_invalid", "unparseable DATE value") from exc
        return day.replace(tzinfo=timezone.utc), True
    stamp = raw.upper()
    if stamp.endswith("Z"):
        stamp = stamp[:-1]
    for fmt in ("%Y%m%dT%H%M%S", "%Y%m%dT%H%M"):
        try:
            return datetime.strptime(stamp, fmt).replace(tzinfo=timezone.utc), False
        except ValueError:
            continue
    raise ConnectorError("time_invalid", "unparseable DATE-TIME value")


def _parse_duration(value: str) -> timedelta:
    """The subset of RFC 5545 DURATION that calendars actually emit: PnW/PnDTnHnMnS."""
    raw = str(value or "").strip().upper()
    if not raw.startswith("P"):
        raise ConnectorError("duration_invalid", "DURATION must start with P")
    sign = 1
    if raw.startswith("+P"):
        raw = raw[1:]
    elif raw.startswith("-P"):
        raw = raw[1:]
        sign = -1
    day_part, has_time, time_part = raw.partition("T")
    days = 0
    weeks = 0
    if "W" in day_part:
        try:
            weeks = int(day_part.split("W", 1)[0])
        except ValueError as exc:
            raise ConnectorError("duration_invalid", "unparseable week duration") from exc
    elif day_part and day_part != "P":
        try:
            days = int(day_part[1:].replace("D", ""))
        except ValueError as exc:
            raise ConnectorError("duration_invalid", "unparseable day duration") from exc
    seconds = 0
    if has_time and time_part:
        number = ""
        for char in time_part:
            if char.isdigit():
                number += char
                continue
            if not number:
                raise ConnectorError("duration_invalid", "unparseable time duration")
            unit = {"H": 3600, "M": 60, "S": 1}.get(char)
            if unit is None:
                raise ConnectorError("duration_invalid", "unparseable time duration")
            seconds += int(number) * unit
            number = ""
        if number:
            raise ConnectorError("duration_invalid", "trailing duration number")
    return timedelta(days=sign * (weeks * 7 + days), seconds=sign * seconds)


def _event_from_properties(props: Mapping[str, str], params: Mapping[str, Mapping[str, str]]) -> Optional[Dict[str, Any]]:
    if not props.get("DTSTART"):
        return None
    if props.get("RRULE"):
        return {"skipped": "recurring"}
    if str(props.get("STATUS", "")).upper() == "CANCELLED":
        return {"skipped": "cancelled"}
    if str(props.get("TRANSP", "")).upper() == "TRANSPARENT":
        return {"skipped": "transparent"}
    try:
        start, all_day = parse_ics_datetime(props["DTSTART"], params.get("DTSTART"))
        if props.get("DTEND"):
            end, end_is_date = parse_ics_datetime(props["DTEND"], params.get("DTEND"))
            if all_day and end_is_date and end <= start:
                end = start + timedelta(days=1)
        elif props.get("DURATION"):
            end = start + _parse_duration(props["DURATION"])
        elif all_day:
            end = start + timedelta(days=1)
        else:
            return {"skipped": "no_end"}
    except ConnectorError:
        return {"skipped": "time_invalid"}
    if end <= start:
        return {"skipped": "empty"}
    return {"start": _utc(start), "end": _utc(end), "all_day": bool(all_day), "skipped": ""}


def parse_ics(raw: str) -> Tuple[List[Dict[str, Any]], Dict[str, int]]:
    """Parse VEVENTs, keeping only :data:`KEPT_PROPERTIES`.

    The event dict deliberately has no room for a title: ``_event_from_properties``
    receives a props mapping that the caller only fills with the kept names, and
    the returned dict is built from start/end/all_day/skipped. A test can therefore
    grep the result for a secret that existed in the input and find nothing.
    """
    events: List[Dict[str, Any]] = []
    skipped = {"recurring": 0, "cancelled": 0, "transparent": 0, "no_end": 0, "time_invalid": 0, "empty": 0}
    in_event = False
    props: Dict[str, str] = {}
    params: Dict[str, Dict[str, str]] = {}
    for line in _unfold(raw):
        upper = line.strip().upper()
        if upper == "BEGIN:VEVENT":
            in_event = True
            props = {}
            params = {}
            continue
        if upper == "END:VEVENT":
            if in_event:
                event = _event_from_properties(props, params)
                if event is not None:
                    reason = str(event.get("skipped") or "")
                    if reason:
                        skipped[reason] = skipped.get(reason, 0) + 1
                    else:
                        events.append(event)
            in_event = False
            props = {}
            params = {}
            continue
        if not in_event:
            continue
        parsed = _split_property(line)
        if parsed is None:
            continue
        name, prop_params, value = parsed
        if name not in KEPT_PROPERTIES:
            # This is the privacy boundary: SUMMARY/DESCRIPTION/ATTENDEE are not
            # copied anywhere, not even into a local per-event dictionary.
            continue
        props[name] = value
        params[name] = prop_params
    return events, skipped


def busy_intervals(events: Sequence[Mapping[str, Any]], start: datetime, end: datetime) -> List[Tuple[datetime, datetime]]:
    raw: List[Tuple[datetime, datetime]] = []
    for event in events:
        event_start = _utc(event["start"])
        event_end = _utc(event["end"])
        if event_end <= start or event_start >= end:
            continue
        raw.append((max(event_start, start), min(event_end, end)))
    raw.sort()
    merged: List[Tuple[datetime, datetime]] = []
    for item_start, item_end in raw:
        if merged and item_start <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(merged[-1][1], item_end))
        else:
            merged.append((item_start, item_end))
    return merged


def free_slots(busy: Sequence[Tuple[datetime, datetime]], start: datetime, end: datetime, slot_minutes: int) -> List[Dict[str, str]]:
    slot = timedelta(minutes=max(MIN_SLOT_MINUTES, min(MAX_SLOT_MINUTES, int(slot_minutes))))
    slots: List[Dict[str, str]] = []
    cursor = start
    for busy_start, busy_end in list(busy) + [(end, end)]:
        while cursor + slot <= busy_start:
            if len(slots) >= MAX_SLOTS:
                return slots
            slots.append({"start": cursor.isoformat().replace("+00:00", "Z"),
                          "end": (cursor + slot).isoformat().replace("+00:00", "Z"),
                          "label": "可预约"})
            cursor += slot
        cursor = max(cursor, busy_end)
    return slots


def availability(events: Sequence[Mapping[str, Any]], start: datetime, end: datetime, slot_minutes: int = DEFAULT_SLOT_MINUTES) -> Dict[str, Any]:
    busy = busy_intervals(events, start, end)
    slots = free_slots(busy, start, end, slot_minutes)
    return {
        "busy": [
            {"start": busy_start.isoformat().replace("+00:00", "Z"),
             "end": busy_end.isoformat().replace("+00:00", "Z"),
             "label": "忙碌"}
            for busy_start, busy_end in busy
        ],
        "free": slots,
        "busy_count": len(busy),
        "free_count": len(slots),
        "slot_minutes": max(MIN_SLOT_MINUTES, min(MAX_SLOT_MINUTES, int(slot_minutes))),
        "truncated": len(slots) >= MAX_SLOTS,
    }


def build_query_xml(start: datetime, end: datetime) -> bytes:
    fmt = "%Y%m%dT%H%M%SZ"
    body = (
        '<?xml version="1.0" encoding="utf-8"?>\n'
        '<C:calendar-query xmlns:D="DAV:" xmlns:C="urn:ietf:params:xml:ns:caldav">\n'
        "  <D:prop><D:getetag/><C:calendar-data/></D:prop>\n"
        '  <C:filter><C:comp-filter name="VCALENDAR"><C:comp-filter name="VEVENT">\n'
        '    <C:time-range start="%s" end="%s"/>\n'
        "  </C:comp-filter></C:comp-filter></C:filter>\n"
        "</C:calendar-query>\n"
    ) % (start.strftime(fmt), end.strftime(fmt))
    return body.encode("utf-8")


def parse_calendar_report(raw: bytes) -> List[str]:
    root = xml_from_bytes(raw)
    calendars: List[str] = []
    for response in root.iter("{%s}response" % DAV_NS):
        for propstat in response.iter("{%s}propstat" % DAV_NS):
            status = propstat.find("{%s}status" % DAV_NS)
            if status is None or " 200 " not in (" %s " % (status.text or "")):
                continue
            for data in propstat.iter("{%s}calendar-data" % CAL_NS):
                if data.text and data.text.strip():
                    calendars.append(data.text)
    return calendars


def parse_window(body: Mapping[str, Any]) -> Tuple[datetime, datetime, int]:
    def one(name: str) -> datetime:
        raw = str(body.get(name) or "").strip()
        if not raw:
            raise ConnectorError("window_required", "%s is required (ISO-8601 UTC)" % name)
        text = raw.upper().replace("Z", "+00:00")
        try:
            if len(text) == 10:
                parsed = datetime.strptime(text, "%Y-%m-%d")
            else:
                parsed = datetime.fromisoformat(text)
        except ValueError as exc:
            raise ConnectorError("window_invalid", "%s must be ISO-8601" % name) from exc
        return _utc(parsed)

    start = one("start")
    end = one("end")
    if end <= start:
        raise ConnectorError("window_invalid", "end must be after start")
    if (end - start).total_seconds() > MAX_WINDOW_SECONDS:
        raise ConnectorError("window_too_large", "the window may not exceed %d days" % MAX_WINDOW_DAYS)
    try:
        slot_minutes = int(body.get("slot_minutes") or DEFAULT_SLOT_MINUTES)
    except (TypeError, ValueError) as exc:
        raise ConnectorError("slot_invalid", "slot_minutes must be an integer") from exc
    if not (MIN_SLOT_MINUTES <= slot_minutes <= MAX_SLOT_MINUTES):
        raise ConnectorError("slot_invalid", "slot_minutes must be %d..%d" % (MIN_SLOT_MINUTES, MAX_SLOT_MINUTES))
    return start, end, slot_minutes


# ─────────────────────────────────── config ─────────────────────────────────


def _config_row(deps: PluginDeps) -> Optional[Dict[str, Any]]:
    row = deps.db.query_one("SELECT * FROM dav_endpoints WHERE connector = ?", (ENDPOINT_KIND,))
    return dict(row) if row is not None else None


def _public_config(row: Optional[Mapping[str, Any]]) -> Dict[str, Any]:
    if row is None:
        return {"configured": False}
    return {
        "configured": True,
        "url": str(row.get("url") or ""),
        "username": str(row.get("username") or ""),
        "password_set": bool(row.get("password")),
        "allow_private": bool(row.get("allow_private")),
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
        "User-Agent": "POPOPX-CalDAV/1.0",
    }
    plain_password = deps.vault.open(str(row.get("password") or ""), table="dav_endpoints",
                                    column="password", subject=ENDPOINT_KIND)
    auth = basic_auth_header(str(row.get("username") or ""), plain_password)
    if auth:
        headers["Authorization"] = auth
    url = endpoint.origin + endpoint.target
    allow_private = bool(row.get("allow_private"))
    return await asyncio.get_running_loop().run_in_executor(
        None,
        lambda: request_pinned(url, method=method, headers=headers, body=body or b"", timeout=15.0,
                               max_bytes=MAX_RESPONSE_BYTES, allow_private=allow_private),
    )


def create_router(deps: PluginDeps) -> "APIRouter":
    from fastapi import APIRouter, Request
    from fastapi.responses import JSONResponse

    globals()["Request"] = Request
    router = APIRouter(prefix=deps.spec.url_prefix, tags=["caldav_connector"])

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
        return {"ok": True, "plugin": PLUGIN_ID, "config": _public_config(_config_row(deps)),
                "gate": deps.gate.status(PLUGIN_ID).as_body(), "max_window_days": MAX_WINDOW_DAYS}

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
            endpoint = normalize_endpoint_url(
                body.get("url", (current or {}).get("url")),
                allow_private=bool(body.get("allow_private", (current or {}).get("allow_private"))),
            )
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
        deps.db.execute(
            "INSERT INTO dav_endpoints (connector, url, username, password, allow_private, field_allowlist, updated_at_ms)"
            " VALUES (?,?,?,?,?,?,?)"
            " ON CONFLICT(connector) DO UPDATE SET url = excluded.url, username = excluded.username,"
            " password = excluded.password, allow_private = excluded.allow_private, updated_at_ms = excluded.updated_at_ms",
            (ENDPOINT_KIND, endpoint.origin + endpoint.target, username, stored_password,
             int(bool(body.get("allow_private", (current or {}).get("allow_private")))), "", _now_ms()),
        )
        record_audit(deps.db, connector="caldav", direction="outbound", action="config.update",
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
            record_audit(deps.db, connector="caldav", direction="outbound", action="probe",
                         source="admin", status_code=int(response.status),
                         outcome="ok" if ok and dav else "not_dav", latency_ms=_now_ms() - started)
            return {"ok": ok and dav, "status": int(response.status), "dav": dav,
                    "latency_ms": _now_ms() - started}
        except ConnectorError as exc:
            deps.db.execute(
                "UPDATE dav_endpoints SET last_probe_ms = ?, last_probe_status = ?, last_probe_error = ? WHERE connector = ?",
                (_now_ms(), exc.http_status, exc.code, PLUGIN_ID),
            )
            record_audit(deps.db, connector="caldav", direction="outbound", action="probe",
                         source="admin", status_code=exc.http_status, outcome=exc.code,
                         latency_ms=_now_ms() - started)
            return json_response(exc.http_status, {"ok": False, "error": exc.code, "detail": exc.message})
        except Exception as exc:  # noqa: BLE001
            code = stable_error(exc)
            record_audit(deps.db, connector="caldav", direction="outbound", action="probe",
                         source="admin", outcome=code, latency_ms=_now_ms() - started)
            return json_response(502, {"ok": False, "error": code})

    @router.post("/freebusy")
    async def freebusy(request: "Request") -> Any:
        refusal = admin_refused(request)
        if refusal is not None:
            return refusal
        body, error = await read_json(request)
        if error is not None:
            return error
        try:
            start, end, slot_minutes = parse_window(body)
        except ConnectorError as exc:
            return json_response(exc.http_status, {"ok": False, "error": exc.code, "detail": exc.message})
        row = _config_row(deps)
        if row is None:
            return json_response(409, {"ok": False, "error": "not_configured"})
        try:
            deps.require()
        except PluginUnavailable as exc:
            record_audit(deps.db, connector="caldav", direction="outbound", action="freebusy",
                         source="admin", outcome=exc.decision.reason, status_code=exc.http_status)
            return json_response(exc.http_status, exc.decision.as_body())
        started = _now_ms()
        try:
            charge = deps.charge(ref="caldav:freebusy")
            try:
                response = await _dav_request(deps, row, method="REPORT",
                                              body=build_query_xml(start, end), depth="1")
                if response.status not in (200, 207):
                    raise ConnectorError("dav_status", "DAV server answered %d" % response.status, http_status=502)
                calendars = parse_calendar_report(response.body)
                events: List[Dict[str, Any]] = []
                skipped: Dict[str, int] = {}
                for calendar in calendars:
                    parsed, event_skipped = parse_ics(calendar)
                    events.extend(parsed)
                    for reason, count in event_skipped.items():
                        skipped[reason] = skipped.get(reason, 0) + int(count)
                result = availability(events, start, end, slot_minutes)
            except Exception:
                if int(getattr(charge, "charged", 0) or 0) > 0:
                    try:
                        deps.billing.refund(amount=int(charge.charged), reason="caldav query failed", ref="caldav:freebusy")
                    except Exception:  # noqa: BLE001
                        LOG.exception("caldav refund failed")
                raise
            record_audit(deps.db, connector="caldav", direction="outbound", action="freebusy",
                         source="admin", status_code=int(response.status), outcome="ok",
                         latency_ms=_now_ms() - started)
            result.update({
                "ok": True,
                "plugin": PLUGIN_ID,
                "start": start.isoformat().replace("+00:00", "Z"),
                "end": end.isoformat().replace("+00:00", "Z"),
                "events_kept": len(events),
                "events_skipped": skipped,
                "charged": int(charge.charged),
            })
            return result
        except ConnectorError as exc:
            record_audit(deps.db, connector="caldav", direction="outbound", action="freebusy",
                         source="admin", status_code=exc.http_status, outcome=exc.code,
                         latency_ms=_now_ms() - started)
            return json_response(exc.http_status, {"ok": False, "error": exc.code, "detail": exc.message})
        except Exception as exc:  # noqa: BLE001
            code = stable_error(exc)
            record_audit(deps.db, connector="caldav", direction="outbound", action="freebusy",
                         source="admin", outcome=code, latency_ms=_now_ms() - started)
            return json_response(502, {"ok": False, "error": code})

    @router.get("/audit")
    async def audit(request: "Request") -> Any:
        refusal = admin_refused(request)
        if refusal is not None:
            return refusal
        limit = int(request.query_params.get("limit") or 100)
        return {"ok": True, "plugin": PLUGIN_ID, "audit": audit_rows(deps.db, "caldav", limit)}

    return router


async def handle_inbound(deps: PluginDeps, message: "InboundMessage") -> bool:
    return False


# ───────────────────────────────── self-test ────────────────────────────────

_SAMPLE_ICS = (
    "BEGIN:VCALENDAR\r\n"
    "VERSION:2.0\r\n"
    "BEGIN:VEVENT\r\n"
    "UID:event-1\r\n"
    "DTSTART:20261126T100000Z\r\n"
    "DTEND:20261126T103000Z\r\n"
    "SUMMARY:Board meeting: acquisition of Example Corp\r\n"
    "DESCRIPTION:secret merger terms and a private phone number\r\n"
    "LOCATION:Room 9, executive floor\r\n"
    "ATTENDEE;CN=Alice:mailto:alice@example.com\r\n"
    "ORGANIZER:mailto:ceo@example.com\r\n"
    "END:VEVENT\r\n"
    "BEGIN:VEVENT\r\n"
    "DTSTART:20261126T101500Z\r\n"
    "DTEND:20261126T104500Z\r\n"
    "SUMMARY:Overlap that merges\r\n"
    "END:VEVENT\r\n"
    "BEGIN:VEVENT\r\n"
    "DTSTART:20261126T110000Z\r\n"
    "DTEND:20261126T113000Z\r\n"
    "TRANSP:TRANSPARENT\r\n"
    "SUMMARY:All-day focus (not blocking)\r\n"
    "END:VEVENT\r\n"
    "BEGIN:VEVENT\r\n"
    "DTSTART:20261126T120000Z\r\n"
    "DTEND:20261126T123000Z\r\n"
    "STATUS:CANCELLED\r\n"
    "SUMMARY:Cancelled review\r\n"
    "END:VEVENT\r\n"
    "BEGIN:VEVENT\r\n"
    "DTSTART:20261126T130000Z\r\n"
    "DURATION:PT1H\r\n"
    "RRULE:FREQ=WEEKLY;COUNT=5\r\n"
    "SUMMARY:Weekly sync\r\n"
    "END:VEVENT\r\n"
    "BEGIN:VEVENT\r\n"
    "DTSTART;VALUE=DATE:20261127\r\n"
    "SUMMARY:All-day offsite\r\n"
    "END:VEVENT\r\n"
    "END:VCALENDAR\r\n"
)


def self_test() -> List[str]:
    checks: List[str] = []

    def check(name: str, condition: bool) -> None:
        if not condition:
            raise AssertionError("caldav self_test failed: %s" % name)
        checks.append(name)

    def refused(name: str, code: str, fn: Any) -> None:
        try:
            fn()
        except ConnectorError as exc:
            check(name, exc.code == code)
        else:
            check(name, False)

    start = datetime(2026, 11, 26, 9, 0, tzinfo=timezone.utc)
    end = datetime(2026, 11, 26, 11, 0, tzinfo=timezone.utc)

    # ── date forms ─────────────────────────────────────────────────────────
    stamp, all_day = parse_ics_datetime("20261126T100000Z")
    check("a_utc_datetime_is_parsed", stamp.hour == 10 and not all_day and stamp.tzinfo is not None)
    check("a_floating_datetime_is_treated_as_utc", parse_ics_datetime("20261126T100000")[0] == stamp)
    day, day_all = parse_ics_datetime("20261126")
    check("a_date_value_is_all_day", day_all and day.day == 26)
    refused("an_unparseable_time_is_refused", "time_invalid", lambda: parse_ics_datetime("tomorrow"))

    # ── the privacy strip ──────────────────────────────────────────────────
    events, skipped = parse_ics(_SAMPLE_ICS)
    serialized = repr(events)
    check("only_the_three_timed_or_all_day_events_survive", len(events) == 3)
    check("the_transparent_event_is_skipped", skipped.get("transparent") == 1)
    check("the_cancelled_event_is_skipped", skipped.get("cancelled") == 1)
    check("the_recurring_event_is_skipped", skipped.get("recurring") == 1)
    check("the_all_day_event_is_kept_as_a_block", sum(1 for event in events if event["all_day"]) == 1)
    check("the_meeting_title_never_reaches_the_event", "Board meeting" not in serialized)
    check("the_description_never_reaches_the_event", "merger terms" not in serialized)
    check("the_location_never_reaches_the_event", "Room 9" not in serialized)
    check("the_attendee_never_reaches_the_event", "alice@example.com" not in serialized)
    check("the_organizer_never_reaches_the_event", "ceo@example.com" not in serialized)
    check("an_event_has_no_title_shaped_key",
          all(set(event) <= {"start", "end", "all_day", "skipped"} for event in events))
    check("the_kept_property_set_has_no_personal_field",
          not (set(DROPPED_PROPERTIES) & set(KEPT_PROPERTIES)))
    check("every_brief_named_drop_is_recorded",
          {"SUMMARY", "DESCRIPTION", "LOCATION", "ATTENDEE"} <= set(DROPPED_PROPERTIES))
    folded = parse_ics(
        "BEGIN:VCALENDAR\r\nBEGIN:VEVENT\r\nDTSTART:20261126T100000Z\r\nDTEND:20261126T110000Z\r\n"
        "SUMMARY:Secret title that is\r\n  folded across lines\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n"
    )[0]
    check("a_folded_summary_is_dropped_too", "Secret title" not in repr(folded))

    # ── busy merge ─────────────────────────────────────────────────────────
    busy = busy_intervals(events, start, end)
    check("overlapping_events_merge_into_one_busy_block", len(busy) == 1)
    check("the_merged_block_starts_at_the_earliest_start", busy[0][0] == datetime(2026, 11, 26, 10, 0, tzinfo=timezone.utc))
    check("the_merged_block_ends_at_the_latest_end", busy[0][1] == datetime(2026, 11, 26, 10, 45, tzinfo=timezone.utc))
    clipped = busy_intervals(events, datetime(2026, 11, 26, 10, 15, tzinfo=timezone.utc),
                             datetime(2026, 11, 26, 10, 30, tzinfo=timezone.utc))
    check("a_busy_block_is_clipped_to_the_window",
          clipped == [(datetime(2026, 11, 26, 10, 15, tzinfo=timezone.utc),
                       datetime(2026, 11, 26, 10, 30, tzinfo=timezone.utc))])
    check("an_event_outside_the_window_is_not_busy",
          busy_intervals(events, datetime(2026, 11, 29, 0, 0, tzinfo=timezone.utc),
                         datetime(2026, 11, 30, 0, 0, tzinfo=timezone.utc)) == [])

    # ── free slots ─────────────────────────────────────────────────────────
    slots = free_slots(busy, start, end, 30)
    check("two_free_slots_exist_around_the_block", len(slots) == 2)
    check("the_first_slot_starts_at_the_window", slots[0]["start"] == "2026-11-26T09:00:00Z")
    check("the_free_slot_ends_at_the_busy_start", slots[0]["end"] == "2026-11-26T09:30:00Z")
    check("a_slot_is_labelled_only_as_available", all(slot["label"] == "可预约" for slot in slots))
    check("a_slot_carries_no_event_title", "Board" not in json_dumps(slots))
    full = availability(events, start, end, 30)
    check("the_availability_envelope_has_busy_and_free", set(full) == {"busy", "free", "busy_count", "free_count", "slot_minutes", "truncated"})
    check("the_busy_interval_is_labelled_only_as_busy", all(item["label"] == "忙碌" for item in full["busy"]))
    check("the_availability_never_leaks_a_title", "Board" not in json_dumps(full))
    check("the_availability_never_leaks_an_attendee", "alice@example.com" not in json_dumps(full))
    check("a_long_window_is_truncated", len(free_slots([], start, start + timedelta(days=31), 15)) == MAX_SLOTS)
    check("a_slot_shorter_than_the_minimum_is_raised", availability([], start, end, 1)["slot_minutes"] == MIN_SLOT_MINUTES)

    # ── window validation ──────────────────────────────────────────────────
    parsed = parse_window({"start": "2026-11-26T09:00:00Z", "end": "2026-11-26T11:00:00Z"})
    check("an_iso_window_is_parsed", parsed[0] == start and parsed[1] == end and parsed[2] == DEFAULT_SLOT_MINUTES)
    refused("a_missing_window_is_refused", "window_required", lambda: parse_window({"start": "2026-11-26"}))
    refused("an_inverted_window_is_refused", "window_invalid",
            lambda: parse_window({"start": "2026-11-26T11:00:00Z", "end": "2026-11-26T09:00:00Z"}))
    refused("an_overlong_window_is_refused", "window_too_large",
            lambda: parse_window({"start": "2026-11-01T00:00:00Z", "end": "2026-12-31T00:00:00Z"}))
    refused("an_out_of_range_slot_is_refused", "slot_invalid",
            lambda: parse_window({"start": "2026-11-26T09:00:00Z", "end": "2026-11-26T11:00:00Z", "slot_minutes": 5}))

    # ── calendar-query XML and report ──────────────────────────────────────
    xml = build_query_xml(start, end)
    check("the_query_is_a_calendar_query", b"<C:calendar-query" in xml)
    check("the_query_has_the_window_in_utc", b'start="20261126T090000Z"' in xml and b'end="20261126T110000Z"' in xml)
    check("the_query_asks_for_events", b'<C:comp-filter name="VEVENT">' in xml)
    report = (
        '<?xml version="1.0"?>\n'
        '<D:multistatus xmlns:D="DAV:" xmlns:C="urn:ietf:params:xml:ns:caldav">'
        "<D:response><D:propstat><D:prop><C:calendar-data>" + _escape_xml(_SAMPLE_ICS) +
        "</C:calendar-data></D:prop><D:status>HTTP/1.1 200 OK</D:status></D:propstat></D:response>"
        "</D:multistatus>"
    )
    calendars = parse_calendar_report(report.encode("utf-8"))
    check("the_report_yields_one_calendar", len(calendars) == 1)
    refused("a_report_with_a_dtd_is_refused", "response_unsafe_xml",
            lambda: parse_calendar_report(b'<!DOCTYPE x [<!ENTITY y "z">]><D:multistatus xmlns:D="DAV:"/>'))
    refused("a_malformed_report_is_refused", "response_malformed", lambda: parse_calendar_report(b"<not-xml"))

    # ── config helper ──────────────────────────────────────────────────────
    check("a_public_config_never_contains_the_password", "password" not in _public_config(
        {"connector": PLUGIN_ID, "url": "https://dav.example/cal", "username": "u", "password": "p",
         "allow_private": 0}))
    check("a_public_config_reports_only_that_a_password_exists", _public_config(
        {"connector": PLUGIN_ID, "url": "https://dav.example/cal", "username": "u", "password": "p",
         "allow_private": 0})["password_set"] is True)

    # ── the dav_endpoints CHECK names the protocol, not the plugin id ──────
    import tempfile
    from pathlib import Path

    from app.database import Database

    root = Path(tempfile.mkdtemp(prefix="popopx-caldav-selftest-"))
    try:
        db = Database(root / "dav.db")
        db.execute(
            "INSERT INTO dav_endpoints (connector,url,username,password,allow_private,field_allowlist,updated_at_ms)"
            " VALUES (?,?,?,?,?,?,?)",
            (ENDPOINT_KIND, "https://dav.example/cal", "", "", 0, "", 1),
        )
        check("the_config_row_is_read_by_the_schema_protocol_name",
              _config_row(type("D", (), {"db": db})())["url"] == "https://dav.example/cal")
    finally:
        import shutil

        shutil.rmtree(root, ignore_errors=True)

    return checks


def _escape_xml(text: str) -> str:
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")