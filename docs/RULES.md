# Writing detection rules

Nightjar rules are YAML files in `rules/`. One file may hold a single rule or a
list of rules (`---`-separated documents also work). Every rule is loaded,
peer-reviewable, and diff-able in Git — that's the "detection as code" idea.

## Anatomy

```yaml
id: ssh-bruteforce          # required, unique across all rules
title: SSH Brute Force      # required, human-readable
severity: high              # info | low | medium | high | critical  (default: medium)
mitre: [T1110]              # list of MITRE ATT&CK technique IDs
description: >              # free text, shown in alerts
  Five or more failed SSH logins from one source IP within 60 seconds.
detection:                  # required — the matching conditions (AND-ed)
  event_type: ssh_failed_login
correlation:                # optional — turns per-event into time-windowed
  group_by: src_ip
  count: 5
  timeframe: 60             # seconds
enabled: true               # optional, default true
```

## The `detection` block

A map of `field: matcher`. **All** conditions must hold (logical AND). Fields are
looked up on the event's top-level attributes (`timestamp`, `source`,
`event_type`, `src_ip`, `raw`) first, then in its parsed `fields`.

A matcher is one of:

| Form | Meaning | Example |
|------|---------|---------|
| scalar | equals (numbers compared numerically) | `status: 404` |
| list | equals **any** item | `method: [POST, PUT]` |
| map of operators | all operators must hold | see below |

### Operators

Each operator's value may be a single value **or a list** (meaning "any of").
String operators are matched against the field's string value.

| Operator | True when… |
|----------|-----------|
| `eq` / `equals` | value equals (any of) |
| `in` | value is in the given list |
| `contains` | substring present (case-sensitive) |
| `icontains` | substring present (case-insensitive) |
| `startswith` / `endswith` | string prefix / suffix |
| `re` / `regex` / `matches` | regex search (case-insensitive) |
| `gte` / `lte` / `gt` / `lt` | numeric comparison |

Example — an HTTP request that looks like SQL injection:

```yaml
detection:
  event_type: http_request
  target:
    re:
      - "union\\s+select"
      - "'\\s*or\\s*'"
```

## The `correlation` block

Without it, a rule fires **once per matching event**. With it, matching events
are grouped by `group_by` and the rule fires only when `count` of them fall
inside `timeframe` seconds. After firing, the group's window resets, so the next
alert requires a fresh burst.

```yaml
correlation:
  group_by: src_ip   # any event field
  count: 15
  timeframe: 30
```

## Event fields by source

| Source | `event_type` | Useful fields |
|--------|-------------|---------------|
| `auth.log` | `ssh_failed_login`, `ssh_accepted_login` | `user`, `port`, `host`, `invalid_user` |
| `nginx` | `http_request` | `method`, `path`, `query`, `target`, `status`, `user_agent`, `referer` |
| `json` | whatever the event's `type` is | every key in the JSON object |

`target` is the decoded path + query (percent-decoding is applied by the parser),
which is what you almost always want to match web-attack payloads against.

## Testing a rule

```bash
python -m nightjar.cli replay --out data --seed 1
python -m nightjar.cli detect --logs data --rules rules
```

Add a fixture log line that should trip your rule, re-run `detect`, and confirm
the alert appears with the right severity and MITRE ID.
