"""End-to-end: generate a scenario, detect over it, assert the expected alerts."""

from nightjar.pipeline import run_detection
from nightjar.replay import generate_scenario


def test_full_scenario_fires_expected_rules(tmp_path):
    generate_scenario(tmp_path, "full", seed=7)
    result = run_detection(tmp_path, "rules")

    fired = {a.rule_id for a in result.alerts}
    # every attack the replayer stages should be detected
    for rule_id in (
        "ssh-bruteforce",
        "ssh-user-enumeration",
        "web-sqli-attempt",
        "web-path-traversal",
        "web-scanner-user-agent",
        "web-directory-scanning",
    ):
        assert rule_id in fired, f"expected {rule_id} to fire; got {sorted(fired)}"


def test_bruteforce_alert_has_mitre_and_evidence(tmp_path):
    generate_scenario(tmp_path, "ssh", seed=7)
    result = run_detection(tmp_path, "rules")
    bf = [a for a in result.alerts if a.rule_id == "ssh-bruteforce"]
    assert bf, "brute-force rule did not fire"
    alert = bf[0]
    assert "T1110" in alert.mitre
    assert alert.severity == "high"
    assert alert.count >= 5
    assert alert.events  # evidence attached


def test_summary_shape(tmp_path):
    generate_scenario(tmp_path, "full", seed=1)
    summary = run_detection(tmp_path, "rules").summary()
    assert summary["total_alerts"] > 0
    assert summary["by_severity"]
    assert summary["top_offenders"]
    assert len(summary["timeline"]) == 30
