"""Parser for Linux ``auth.log`` / ``secure`` SSH events.

Handles the common OpenSSH lines an SSH brute-force or spray produces::

    Aug 18 03:12:44 web01 sshd[2043]: Failed password for invalid user admin from 203.0.113.7 port 51244 ssh2
    Aug 18 03:12:47 web01 sshd[2044]: Failed password for root from 203.0.113.7 port 51290 ssh2
    Aug 18 03:13:01 web01 sshd[2051]: Accepted password for deploy from 198.51.100.4 port 40122 ssh2
"""

from __future__ import annotations

import re
from datetime import datetime, timezone

from ..models import Event

# "Aug 18 03:12:44 host sshd[2043]: <message>"
_SYSLOG_RE = re.compile(
    r"^(?P<month>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+"
    r"(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+sshd\[(?P<pid>\d+)\]:\s+(?P<msg>.*)$"
)

_FAILED_RE = re.compile(
    r"Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)"
)
_INVALID_USER_RE = re.compile(r"invalid user")
_ACCEPTED_RE = re.compile(
    r"Accepted (?P<method>\w+) for (?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)"
)

_MONTHS = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
    "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
}


def _parse_syslog_time(month: str, day: str, time_str: str) -> datetime:
    """Syslog timestamps carry no year; assume the current one, in UTC."""
    now = datetime.now(timezone.utc)
    hh, mm, ss = (int(x) for x in time_str.split(":"))
    return datetime(
        now.year, _MONTHS.get(month, 1), int(day), hh, mm, ss, tzinfo=timezone.utc
    )


def parse_auth_line(line: str) -> Event | None:
    m = _SYSLOG_RE.match(line)
    if not m:
        return None
    ts = _parse_syslog_time(m["month"], m["day"], m["time"])
    msg = m["msg"]
    host = m["host"]

    failed = _FAILED_RE.search(msg)
    if failed:
        return Event(
            timestamp=ts,
            source="auth.log",
            event_type="ssh_failed_login",
            raw=line,
            src_ip=failed["ip"],
            fields={
                "user": failed["user"],
                "port": int(failed["port"]),
                "host": host,
                "invalid_user": bool(_INVALID_USER_RE.search(msg)),
            },
        )

    accepted = _ACCEPTED_RE.search(msg)
    if accepted:
        return Event(
            timestamp=ts,
            source="auth.log",
            event_type="ssh_accepted_login",
            raw=line,
            src_ip=accepted["ip"],
            fields={
                "user": accepted["user"],
                "port": int(accepted["port"]),
                "method": accepted["method"],
                "host": host,
            },
        )
    return None
