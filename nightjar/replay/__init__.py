"""Attack replayer — synthesizes realistic log files for demos and tests."""

from .generator import generate_scenario, SCENARIOS

__all__ = ["generate_scenario", "SCENARIOS"]
