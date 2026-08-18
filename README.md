# 🛡️ Nightjar — Detection-as-Code mini-SIEM

Nightjar ingests security logs, evaluates them against **version-controlled YAML
detection rules** (Sigma-style), and raises alerts mapped to **MITRE ATT&CK**.
It ships with an **attack replayer**, so it's alive and demoable on day one —
no server needs to actually be under attack.

> A nightjar is a nocturnal bird that hunts by sound in the dark. So does a SIEM.

## Why this exists

Real detection teams write their detections *as code*: rules live in Git, get
peer-reviewed, and are tested in CI. Nightjar is a compact, honest version of
that workflow you can run on a laptop.

## Pipeline

```
 attack replayer ─┐
   auth.log ──────┤
   nginx logs ────┼──►  parsers  ──►  events  ──►  detection engine  ──►  alerts  ──►  dashboard
   json events ───┘                                (YAML rules,          (severity,     (live feed,
                                                     time-windowed         MITRE ID,      charts,
                                                     correlation)          evidence)      timeline)
```

## Core pieces

1. **Log ingestion** — parses real formats: Linux `auth.log` (SSH), Nginx
   access logs (web scanning, SQLi, path traversal), and generic JSON events.
2. **Detection engine** — rules as YAML with time-windowed correlation, e.g.
   *"≥5 failed SSH logins from one IP in 60s → brute force."*
3. **Alerts** — severity, the triggering events as evidence, and a MITRE
   ATT&CK technique ID (e.g. `T1110` Brute Force).
4. **Dashboard** — alert feed, alerts-by-severity, top offending IPs, rule hit
   counts, and a timeline.
5. **Attack replayer** — generates realistic attack scenarios on demand.

## Quick start

```bash
python -m venv .venv
# Windows:  .venv\Scripts\activate
# Unix:     source .venv/bin/activate
pip install -r requirements.txt

# 1. Generate a realistic attack scenario into ./data
python -m nightjar.cli replay --out data

# 2. Run detections over it and print alerts
python -m nightjar.cli detect --logs data --rules rules

# 3. Launch the live dashboard  →  http://127.0.0.1:8000
python -m nightjar.cli serve
```

## Writing a rule

Rules live in `rules/*.yml` and look like this:

```yaml
id: ssh-bruteforce
title: SSH Brute Force
severity: high
mitre: [T1110]
description: Multiple failed SSH logins from a single source IP.
detection:
  event_type: ssh_failed_login
correlation:
  group_by: src_ip
  count: 5
  timeframe: 60   # seconds
```

See [`docs/RULES.md`](docs/RULES.md) for the full matching grammar.

## Roadmap

- [ ] Enrich alert source IPs against **ThreatPulse** (sibling project) so the
      two plug into each other — a platform, not two toys.
- [ ] CI job that lints rules and runs detections against fixture logs.
- [ ] More parsers (Windows Event Log, Suricata EVE JSON).

## License

MIT
