"""The detection engine.

Feed it :class:`~nightjar.models.Event` objects (in time order) and it returns
:class:`~nightjar.models.Alert` objects. Two kinds of rules are supported:

* **Per-event rules** (no ``correlation`` block) fire once per matching event —
  e.g. "any request whose path contains a SQL-injection pattern".
* **Correlation rules** keep a per-group sliding window and fire when ``count``
  matches land within ``timeframe`` seconds — e.g. "≥5 failed SSH logins from
  one IP in 60s". After firing, the group's window is cleared so the next alert
  needs a fresh burst (no re-firing on every subsequent event).
"""

from __future__ import annotations

from collections import defaultdict, deque
from collections.abc import Iterable
from datetime import timedelta

from ..models import Alert, Event
from .rules import Rule


class Engine:
    def __init__(self, rules: Iterable[Rule]):
        self.rules: list[Rule] = list(rules)
        self._per_event = [r for r in self.rules if r.correlation is None]
        self._correlation = [r for r in self.rules if r.correlation is not None]
        # (rule_id, group_value) -> deque[Event] within the active window
        self._windows: dict[tuple[str, str], deque[Event]] = defaultdict(deque)
        self.rule_hits: dict[str, int] = defaultdict(int)

    def process(self, event: Event) -> list[Alert]:
        """Run all rules against one event and return any alerts it produces."""
        alerts: list[Alert] = []

        for rule in self._per_event:
            if rule.matches(event):
                self.rule_hits[rule.id] += 1
                alerts.append(self._make_alert(rule, event.timestamp, [event]))

        for rule in self._correlation:
            if not rule.matches(event):
                continue
            corr = rule.correlation  # not None by construction
            group_val = event.get(corr.group_by)
            if group_val is None:
                continue
            key = (rule.id, str(group_val))
            window = self._windows[key]
            window.append(event)

            # Drop events that fell out of the timeframe (relative to `event`).
            cutoff = event.timestamp - timedelta(seconds=corr.timeframe)
            while window and window[0].timestamp < cutoff:
                window.popleft()

            if len(window) >= corr.count:
                self.rule_hits[rule.id] += 1
                alerts.append(
                    self._make_alert(
                        rule,
                        event.timestamp,
                        list(window),
                        src_ip=str(group_val) if corr.group_by == "src_ip" else event.src_ip,
                    )
                )
                window.clear()  # require a fresh burst before firing again

        return alerts

    def run(self, events: Iterable[Event]) -> list[Alert]:
        """Process an iterable of events (sorted by time) and collect alerts."""
        ordered = sorted(events, key=lambda e: e.timestamp)
        alerts: list[Alert] = []
        for event in ordered:
            alerts.extend(self.process(event))
        return alerts

    def _make_alert(
        self,
        rule: Rule,
        timestamp,
        events: list[Event],
        src_ip: str | None = None,
    ) -> Alert:
        if src_ip is None:
            src_ip = events[-1].src_ip if events else None
        return Alert(
            rule_id=rule.id,
            title=rule.title,
            severity=rule.severity,
            timestamp=timestamp,
            src_ip=src_ip,
            mitre=list(rule.mitre),
            description=rule.description,
            count=len(events),
            events=list(events),
        )
