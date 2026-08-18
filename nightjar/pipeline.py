"""High-level glue: load a directory of logs, run the engine, summarize alerts.

Both the CLI and the web API sit on top of this so they behave identically.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path

from .engine import Engine, load_rules_from_dir
from .engine.rules import Rule
from .models import Alert, Event
from .parsers import parse_file

_LOG_GLOBS = ("*.log", "*.json", "*.jsonl", "*.ndjson", "*.txt")


def load_events(logs_dir: str | Path) -> list[Event]:
    """Parse every recognized log file under ``logs_dir`` into events."""
    logs_dir = Path(logs_dir)
    if not logs_dir.exists():
        raise FileNotFoundError(f"logs directory not found: {logs_dir}")
    events: list[Event] = []
    seen: set[Path] = set()
    for pattern in _LOG_GLOBS:
        for path in sorted(logs_dir.glob(pattern)):
            if path in seen or not path.is_file():
                continue
            seen.add(path)
            events.extend(parse_file(path))
    events.sort(key=lambda e: e.timestamp)
    return events


@dataclass
class DetectionResult:
    alerts: list[Alert] = field(default_factory=list)
    events: list[Event] = field(default_factory=list)
    rules: list[Rule] = field(default_factory=list)
    rule_hits: dict[str, int] = field(default_factory=dict)

    # --- summaries the dashboard needs ------------------------------------ #

    def by_severity(self) -> dict[str, int]:
        counts = Counter(a.severity for a in self.alerts)
        order = ["critical", "high", "medium", "low", "info"]
        return {sev: counts.get(sev, 0) for sev in order if counts.get(sev, 0)}

    def top_offenders(self, limit: int = 10) -> list[dict]:
        counts: Counter[str] = Counter()
        worst: dict[str, int] = defaultdict(int)
        for a in self.alerts:
            if not a.src_ip:
                continue
            counts[a.src_ip] += 1
            worst[a.src_ip] = max(worst[a.src_ip], a.severity_rank)
        return [
            {"ip": ip, "alerts": n, "max_severity_rank": worst[ip]}
            for ip, n in counts.most_common(limit)
        ]

    def rule_hit_table(self) -> list[dict]:
        by_id = {r.id: r for r in self.rules}
        rows = [
            {
                "rule_id": rid,
                "title": by_id[rid].title if rid in by_id else rid,
                "severity": by_id[rid].severity if rid in by_id else "medium",
                "hits": n,
            }
            for rid, n in self.rule_hits.items()
        ]
        rows.sort(key=lambda r: r["hits"], reverse=True)
        return rows

    def timeline(self, buckets: int = 30) -> list[dict]:
        """Alert counts over time, split into ``buckets`` equal intervals."""
        if not self.alerts:
            return []
        times = sorted(a.timestamp for a in self.alerts)
        start, end = times[0], times[-1]
        span = (end - start).total_seconds() or 1.0
        width = span / buckets
        counts = [0] * buckets
        for a in self.alerts:
            idx = int((a.timestamp - start).total_seconds() / width)
            counts[min(idx, buckets - 1)] += 1
        return [
            {
                "t": (start.timestamp() + i * width),
                "count": counts[i],
            }
            for i in range(buckets)
        ]

    def summary(self) -> dict:
        return {
            "total_alerts": len(self.alerts),
            "total_events": len(self.events),
            "rules_loaded": len(self.rules),
            "by_severity": self.by_severity(),
            "top_offenders": self.top_offenders(),
            "rule_hits": self.rule_hit_table(),
            "timeline": self.timeline(),
        }


def run_detection(logs_dir: str | Path, rules_dir: str | Path) -> DetectionResult:
    """Load logs + rules, run the engine, and return a summarizable result."""
    rules = load_rules_from_dir(rules_dir)
    events = load_events(logs_dir)
    engine = Engine(rules)
    alerts = engine.run(events)
    alerts.sort(key=lambda a: a.timestamp, reverse=True)
    return DetectionResult(
        alerts=alerts,
        events=events,
        rules=rules,
        rule_hits=dict(engine.rule_hits),
    )
