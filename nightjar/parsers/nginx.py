"""Parser for the Nginx / Apache "combined" access log format.

    203.0.113.9 - - [18/Aug/2026:03:20:11 +0000] "GET /admin.php?id=1' OR '1'='1 HTTP/1.1" 403 512 "-" "sqlmap/1.7"

The parser splits the request line into method / path / query and keeps the
status, user-agent, and referrer as fields. Detection rules do the rest
(matching SQLi patterns, path traversal, scanner user-agents, etc.).
"""

from __future__ import annotations

import re
from datetime import datetime
from urllib.parse import unquote

from ..models import Event

_COMBINED_RE = re.compile(
    r"^(?P<ip>\S+)\s+\S+\s+\S+\s+"
    r"\[(?P<time>[^\]]+)\]\s+"
    r'"(?P<request>[^"]*)"\s+'
    r"(?P<status>\d{3})\s+(?P<size>\S+)"
    r'(?:\s+"(?P<referer>[^"]*)"\s+"(?P<agent>[^"]*)")?'
)

# 18/Aug/2026:03:20:11 +0000
_TIME_FMT = "%d/%b/%Y:%H:%M:%S %z"


def _parse_time(value: str) -> datetime:
    try:
        return datetime.strptime(value, _TIME_FMT)
    except ValueError:
        from datetime import timezone

        return datetime.now(timezone.utc)


def parse_nginx_line(line: str) -> Event | None:
    m = _COMBINED_RE.match(line)
    if not m:
        return None

    method = path = query = ""
    protocol = ""
    request = m["request"] or ""
    parts = request.split(" ")
    if len(parts) >= 2:
        method = parts[0]
        target = parts[1]
        protocol = parts[2] if len(parts) >= 3 else ""
        if "?" in target:
            path, query = target.split("?", 1)
        else:
            path = target

    # Decode percent-encoding so rules can match on the real payload
    # (e.g. %27 -> ' , ..%2f -> ../) without every rule repeating the trick.
    decoded_path = unquote(path)
    decoded_query = unquote(query)

    return Event(
        timestamp=_parse_time(m["time"]),
        source="nginx",
        event_type="http_request",
        raw=line,
        src_ip=m["ip"],
        fields={
            "method": method,
            "path": decoded_path,
            "query": decoded_query,
            "target": unquote(f"{path}?{query}" if query else path),
            "protocol": protocol,
            "status": int(m["status"]),
            "size": m["size"],
            "referer": m["referer"] or "",
            "user_agent": m["agent"] or "",
        },
    )
