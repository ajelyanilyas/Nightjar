"""Log parsers: raw text/JSON lines -> normalized :class:`~nightjar.models.Event`.

Each parser is a callable that takes a single line and returns an ``Event`` or
``None`` (line not recognized / not interesting). :func:`parse_file` picks the
right parser from a source name and streams events out in file order.
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

from ..models import Event
from .auth_log import parse_auth_line
from .json_events import parse_json_line
from .nginx import parse_nginx_line

# source name -> line parser
PARSERS = {
    "auth.log": parse_auth_line,
    "auth": parse_auth_line,
    "nginx": parse_nginx_line,
    "json": parse_json_line,
}

# filename hints -> source name, used by parse_file for auto-detection
_FILENAME_HINTS = {
    "auth": "auth.log",
    "secure": "auth.log",
    "ssh": "auth.log",
    "nginx": "nginx",
    "access": "nginx",
    "events": "json",
}


def detect_source(path: Path) -> str:
    """Guess a source name from a file name, defaulting to JSON."""
    name = path.name.lower()
    if name.endswith(".json") or name.endswith(".jsonl") or name.endswith(".ndjson"):
        return "json"
    for hint, source in _FILENAME_HINTS.items():
        if hint in name:
            return source
    return "json"


def parse_lines(lines: Iterator[str], source: str) -> Iterator[Event]:
    parser = PARSERS.get(source)
    if parser is None:
        raise ValueError(f"unknown log source: {source!r} (have {sorted(PARSERS)})")
    for line in lines:
        line = line.rstrip("\n")
        if not line.strip():
            continue
        event = parser(line)
        if event is not None:
            yield event


def parse_file(path: str | Path, source: str | None = None) -> Iterator[Event]:
    """Parse ``path`` into events. Source is auto-detected if not given."""
    path = Path(path)
    source = source or detect_source(path)
    with path.open("r", encoding="utf-8", errors="replace") as fh:
        yield from parse_lines(fh, source)


__all__ = ["parse_file", "parse_lines", "detect_source", "PARSERS"]
