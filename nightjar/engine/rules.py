"""Rule loading and the field-matching grammar.

A rule is a small YAML document. The ``detection`` block is a map of
``field: matcher`` conditions that are AND-ed together. A matcher can be:

* a scalar         -> equals (numbers compared numerically, strings exactly)
* a list           -> matches if the field equals **any** item
* a map of ops     -> ``contains`` / ``icontains`` / ``re`` / ``startswith`` /
                      ``endswith`` / ``gte`` / ``lte`` / ``gt`` / ``lt`` / ``in``.
                      Each op's value may itself be a list, meaning "any of".

An optional ``correlation`` block turns a per-event match into a windowed one:
group matching events by a field and fire only when ``count`` of them land
inside ``timeframe`` seconds.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from ..models import Event


class RuleError(ValueError):
    """Raised when a rule file is malformed."""


def _as_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else [value]


def _match_op(op: str, spec: Any, actual: Any) -> bool:
    """Evaluate a single operator against a field's actual value."""
    if actual is None:
        return False

    if op in ("eq", "equals"):
        return any(_scalar_eq(actual, v) for v in _as_list(spec))
    if op == "in":
        return actual in _as_list(spec)
    if op == "contains":
        s = str(actual)
        return any(str(v) in s for v in _as_list(spec))
    if op == "icontains":
        s = str(actual).lower()
        return any(str(v).lower() in s for v in _as_list(spec))
    if op == "startswith":
        s = str(actual)
        return any(s.startswith(str(v)) for v in _as_list(spec))
    if op == "endswith":
        s = str(actual)
        return any(s.endswith(str(v)) for v in _as_list(spec))
    if op in ("re", "regex", "matches"):
        s = str(actual)
        return any(re.search(str(v), s, re.IGNORECASE) for v in _as_list(spec))
    if op == "gte":
        return _num(actual) is not None and _num(actual) >= _num(spec)
    if op == "lte":
        return _num(actual) is not None and _num(actual) <= _num(spec)
    if op == "gt":
        return _num(actual) is not None and _num(actual) > _num(spec)
    if op == "lt":
        return _num(actual) is not None and _num(actual) < _num(spec)
    raise RuleError(f"unknown match operator: {op!r}")


def _scalar_eq(actual: Any, expected: Any) -> bool:
    na, ne = _num(actual), _num(expected)
    if na is not None and ne is not None:
        return na == ne
    return str(actual) == str(expected)


def _num(value: Any) -> float | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return float(value)
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _match_field(spec: Any, actual: Any) -> bool:
    if isinstance(spec, dict):
        # every operator in the map must hold (AND)
        return all(_match_op(op, val, actual) for op, val in spec.items())
    if isinstance(spec, list):
        return any(_scalar_eq(actual, v) for v in spec)
    return _scalar_eq(actual, spec)


@dataclass
class Correlation:
    group_by: str = "src_ip"
    count: int = 1
    timeframe: int = 60  # seconds

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Correlation":
        return cls(
            group_by=d.get("group_by", "src_ip"),
            count=int(d.get("count", 1)),
            timeframe=int(d.get("timeframe", 60)),
        )


@dataclass
class Rule:
    id: str
    title: str
    detection: dict[str, Any]
    severity: str = "medium"
    mitre: list[str] = field(default_factory=list)
    description: str = ""
    correlation: Correlation | None = None
    enabled: bool = True

    def matches(self, event: Event) -> bool:
        """True if ``event`` satisfies every condition in ``detection``."""
        for field_name, spec in self.detection.items():
            if not _match_field(spec, event.get(field_name)):
                return False
        return True

    @classmethod
    def from_dict(cls, d: dict[str, Any], *, origin: str = "<dict>") -> "Rule":
        if not isinstance(d, dict):
            raise RuleError(f"{origin}: rule must be a mapping")
        missing = [k for k in ("id", "title", "detection") if k not in d]
        if missing:
            raise RuleError(f"{origin}: rule missing required key(s): {missing}")
        corr = d.get("correlation")
        return cls(
            id=str(d["id"]),
            title=str(d["title"]),
            detection=dict(d["detection"]),
            severity=str(d.get("severity", "medium")).lower(),
            mitre=[str(x) for x in _as_list(d.get("mitre", []))] if d.get("mitre") else [],
            description=str(d.get("description", "")),
            correlation=Correlation.from_dict(corr) if corr else None,
            enabled=bool(d.get("enabled", True)),
        )


def load_rules(path: str | Path) -> list[Rule]:
    """Load one YAML file. A file may hold a single rule or a list of rules."""
    path = Path(path)
    with path.open("r", encoding="utf-8") as fh:
        docs = list(yaml.safe_load_all(fh))
    rules: list[Rule] = []
    for doc in docs:
        if doc is None:
            continue
        items = doc if isinstance(doc, list) else [doc]
        for item in items:
            rules.append(Rule.from_dict(item, origin=str(path)))
    return rules


def load_rules_from_dir(directory: str | Path) -> list[Rule]:
    """Load and return every enabled rule under ``directory`` (``*.yml/.yaml``)."""
    directory = Path(directory)
    if not directory.exists():
        raise FileNotFoundError(f"rules directory not found: {directory}")
    rules: list[Rule] = []
    seen: dict[str, str] = {}
    for path in sorted([*directory.glob("*.yml"), *directory.glob("*.yaml")]):
        for rule in load_rules(path):
            if rule.id in seen:
                raise RuleError(
                    f"duplicate rule id {rule.id!r} in {path} "
                    f"(already defined in {seen[rule.id]})"
                )
            seen[rule.id] = str(path)
            if rule.enabled:
                rules.append(rule)
    return rules
