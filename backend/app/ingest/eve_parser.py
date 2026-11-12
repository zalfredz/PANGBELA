"""Suricata EVE JSON to Alert (spec section 6).

Only event_type == "alert" is ingested. timestamp, src_ip, dest_ip and
alert.signature_id/signature/category are required; everything else is optional.
HTTP fields are attacker-controlled and are only ever stored or shown as data.
"""

from datetime import UTC, datetime
from ipaddress import ip_address
from typing import Any

from pydantic import BaseModel


class EveParseError(ValueError):
    pass


class Alert(BaseModel):
    ts: datetime  # UTC
    src_ip: str
    dest_ip: str
    signature_id: int
    signature: str
    category: str
    flow_id: int | None = None
    src_port: int | None = None
    dest_port: int | None = None
    proto: str | None = None
    severity: int | None = None
    http_hostname: str | None = None
    http_url: str | None = None
    http_method: str | None = None
    http_user_agent: str | None = None
    http_status: int | None = None
    raw: dict[str, Any]


def is_alert(event: Any) -> bool:
    return isinstance(event, dict) and event.get("event_type") == "alert"


def parse_timestamp(value: Any) -> datetime:
    if not isinstance(value, str):
        raise EveParseError("timestamp missing")
    try:
        ts = datetime.fromisoformat(value)
    except ValueError as e:
        raise EveParseError(f"bad timestamp: {value!r}") from e
    if ts.tzinfo is None:
        # Suricata always writes an offset; a naive value means a broken line, not local time.
        raise EveParseError(f"timestamp has no UTC offset: {value!r}")
    return ts.astimezone(UTC)


def _ip(event: dict, key: str) -> str:
    try:
        return str(ip_address(event[key]))
    except (KeyError, ValueError, TypeError) as e:
        raise EveParseError(f"bad or missing {key}") from e


def _int(value: Any) -> int | None:
    # bool is an int subclass; a JSON true is never a valid port or id.
    if isinstance(value, int) and not isinstance(value, bool):
        return value
    return None


def _str(value: Any) -> str | None:
    return value if isinstance(value, str) else None


def parse_alert(event: dict) -> Alert:
    """Parse one EVE alert event. Raises EveParseError if a required field is missing."""
    alert = event.get("alert")
    if not isinstance(alert, dict):
        raise EveParseError("alert object missing")
    signature_id = _int(alert.get("signature_id"))
    signature = _str(alert.get("signature"))
    category = _str(alert.get("category"))
    if signature_id is None or signature is None or category is None:
        raise EveParseError("alert.signature_id, signature or category missing")

    http = event.get("http") if isinstance(event.get("http"), dict) else {}
    return Alert(
        ts=parse_timestamp(event.get("timestamp")),
        src_ip=_ip(event, "src_ip"),
        dest_ip=_ip(event, "dest_ip"),
        signature_id=signature_id,
        signature=signature,
        category=category,
        flow_id=_int(event.get("flow_id")),
        src_port=_int(event.get("src_port")),
        dest_port=_int(event.get("dest_port")),
        proto=_str(event.get("proto")),
        severity=_int(alert.get("severity")),
        http_hostname=_str(http.get("hostname")),
        http_url=_str(http.get("url")),
        http_method=_str(http.get("http_method")),
        http_user_agent=_str(http.get("http_user_agent")),
        http_status=_int(http.get("status")),
        raw=event,
    )
