"""Engine tests: rule matching and time-windowed correlation."""

from datetime import datetime, timedelta, timezone

from nightjar.engine import Engine
from nightjar.engine.rules import Rule
from nightjar.models import Event


def _evt(t, ip="1.2.3.4", etype="ssh_failed_login", **fields):
    return Event(timestamp=t, source="test", event_type=etype,
                 raw="raw", src_ip=ip, fields=fields)


def _rule(**kw):
    base = dict(id="r", title="R", detection={"event_type": "ssh_failed_login"})
    base.update(kw)
    return Rule.from_dict(base)


def test_per_event_rule_fires_each_time():
    eng = Engine([_rule()])
    t = datetime(2026, 8, 18, tzinfo=timezone.utc)
    alerts = eng.run([_evt(t), _evt(t + timedelta(seconds=1))])
    assert len(alerts) == 2


def test_correlation_needs_threshold_within_window():
    rule = _rule(correlation={"group_by": "src_ip", "count": 5, "timeframe": 60})
    eng = Engine([rule])
    t = datetime(2026, 8, 18, tzinfo=timezone.utc)
    events = [_evt(t + timedelta(seconds=i * 5)) for i in range(5)]  # 5 in 20s
    alerts = eng.run(events)
    assert len(alerts) == 1
    assert alerts[0].count == 5
    assert alerts[0].src_ip == "1.2.3.4"


def test_correlation_respects_timeframe():
    rule = _rule(correlation={"group_by": "src_ip", "count": 3, "timeframe": 10})
    eng = Engine([rule])
    t = datetime(2026, 8, 18, tzinfo=timezone.utc)
    # 3 events but spread over 40s -> never 3 inside any 10s window
    events = [_evt(t + timedelta(seconds=i * 20)) for i in range(3)]
    assert eng.run(events) == []


def test_correlation_groups_by_ip():
    rule = _rule(correlation={"group_by": "src_ip", "count": 3, "timeframe": 60})
    eng = Engine([rule])
    t = datetime(2026, 8, 18, tzinfo=timezone.utc)
    events = []
    for i in range(3):
        events.append(_evt(t + timedelta(seconds=i), ip="9.9.9.9"))
        events.append(_evt(t + timedelta(seconds=i), ip="8.8.8.8"))
    alerts = eng.run(events)
    assert len(alerts) == 2
    assert {a.src_ip for a in alerts} == {"9.9.9.9", "8.8.8.8"}


def test_window_resets_after_firing():
    rule = _rule(correlation={"group_by": "src_ip", "count": 3, "timeframe": 60})
    eng = Engine([rule])
    t = datetime(2026, 8, 18, tzinfo=timezone.utc)
    events = [_evt(t + timedelta(seconds=i)) for i in range(6)]  # 6 -> exactly 2 bursts
    alerts = eng.run(events)
    assert len(alerts) == 2


def test_regex_matcher_matches_decoded_payload():
    rule = Rule.from_dict({
        "id": "sqli", "title": "SQLi",
        "detection": {"event_type": "http_request", "target": {"re": ["union\\s+select"]}},
    })
    eng = Engine([rule])
    t = datetime(2026, 8, 18, tzinfo=timezone.utc)
    hit = _evt(t, etype="http_request", target="/x?q=1 UNION SELECT 1")
    miss = _evt(t, etype="http_request", target="/x?q=hello")
    assert len(eng.run([hit, miss])) == 1


def test_numeric_status_comparison():
    rule = Rule.from_dict({
        "id": "err", "title": "err",
        "detection": {"event_type": "http_request", "status": {"gte": 500}},
    })
    eng = Engine([rule])
    t = datetime(2026, 8, 18, tzinfo=timezone.utc)
    assert len(eng.run([
        _evt(t, etype="http_request", status=503),
        _evt(t, etype="http_request", status=404),
    ])) == 1
