"""Core data structures shared across parsers, the engine, and the API.

These are deliberately plain ``dataclasses`` (no pydantic) so the detection core
has zero third-party dependencies and runs anywhere Python does.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


def _now() -> datetime:
    return datetime.now(timezone.utc)


@dataclass
class Event:
    """A single normalized log event, whatever its original format.

    Parsers turn a raw log line into one of these. The engine only ever sees
    ``Event`` objects, so adding a new log source means adding a new parser —
    the rules and the engine don't change.
    """

    timestamp: datetime
    source: str  # which parser produced it, e.g. "auth.log", "nginx"
    event_type: str  # normalized type, e.g. "ssh_failed_login", "http_request"
    raw: str  # the original log line, kept as evidence
    src_ip: str | None = None
    fields: dict[str, Any] = field(default_factory=dict)  # parsed extras

    def get(self, key: str, default: Any = None) -> Any:
        """Look up ``key`` in the top-level attributes, then in ``fields``."""
        if key in ("timestamp", "source", "event_type", "raw", "src_ip"):
            return getattr(self, key)
        return self.fields.get(key, default)

    def to_dict(self) -> dict[str, Any]:
        return {
            "timestamp": self.timestamp.isoformat(),
            "source": self.source,
            "event_type": self.event_type,
            "src_ip": self.src_ip,
            "raw": self.raw,
            "fields": self.fields,
        }


SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


@dataclass
class Alert:
    """A detection that fired. Carries its evidence and MITRE mapping."""

    rule_id: str
    title: str
    severity: str
    timestamp: datetime
    src_ip: str | None = None
    mitre: list[str] = field(default_factory=list)
    description: str = ""
    count: int = 1  # how many events triggered it (for correlation rules)
    events: list[Event] = field(default_factory=list)  # the evidence
    id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])

    @property
    def severity_rank(self) -> int:
        return SEVERITY_ORDER.get(self.severity.lower(), 0)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity,
            "timestamp": self.timestamp.isoformat(),
            "src_ip": self.src_ip,
            "mitre": self.mitre,
            "description": self.description,
            "count": self.count,
            "events": [e.to_dict() for e in self.events],
        }
