"""The detection engine: YAML rules + time-windowed correlation."""

from .rules import Rule, load_rules, load_rules_from_dir
from .engine import Engine

__all__ = ["Rule", "Engine", "load_rules", "load_rules_from_dir"]
