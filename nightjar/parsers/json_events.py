"""Parser for generic JSON events (one JSON object per line, aka JSONL).

This is the escape hatch for anything already structured — application audit
logs, cloud events, a shipper's output. We map a few well-known keys onto the
``Event`` shape and stash everything else in ``fields``.

    {"time": "2026-08-18T03:25:00Z", "type": "api_key_used", "ip": "198.51.100.9", "user": "svc-bot", "result": "denied"}
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

from ..models import Event

_TIME_KEYS = ("timestamp", "time", "@timestamp", "ts", "eventTime")
_TYPE_KEYS = ("event_type", "type", "event", "action")
_IP_KEYS = ("src_ip", "ip", "source_ip", "client_ip", "remote_addr")


def _first(d: dict[str, Any], keys: tuple[str, ...]) -> Any:
    for k in keys:
        if k in d and d[k] not in (None, ""):
            return d[k]
    return None


def _parse_time(value: Any) -> datetime:
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(value, tz=timezone.utc)
    if isinstance(value, str):
        try:
            dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
        except ValueError:
            pass
    return datetime.now(timezone.utc)


def parse_json_line(line: str) -> Event | None:
    line = line.strip()
    if not line or line[0] != "{":
        return None
    try:
        obj = json.loads(line)
    except json.JSONDecodeError:
        return None
    if not isinstance(obj, dict):
        return None

    ts = _parse_time(_first(obj, _TIME_KEYS))
    event_type = _first(obj, _TYPE_KEYS) or "json_event"
    src_ip = _first(obj, _IP_KEYS)

    consumed = set(_TIME_KEYS) | set(_TYPE_KEYS) | set(_IP_KEYS)
    fields = {k: v for k, v in obj.items() if k not in consumed}

    return Event(
        timestamp=ts,
        source="json",
        event_type=str(event_type),
        raw=line,
        src_ip=str(src_ip) if src_ip is not None else None,
        fields=fields,
    )
