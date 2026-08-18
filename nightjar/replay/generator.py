"""Generate realistic attack scenarios as log files.

The point of the replayer is that Nightjar is *alive on day one*: you don't need
a real server getting attacked to see detections fire. Each scenario writes to
three files under the output directory:

* ``auth.log``         — Linux SSH events (syslog format)
* ``nginx-access.log`` — Nginx combined access log
* ``events.json``      — generic JSON events (JSONL)

Benign traffic is mixed in with the attacks so the detection engine has to earn
its alerts rather than flagging everything.
"""

from __future__ import annotations

import json
import random
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import quote


def _enc(target: str) -> str:
    """URL-encode a request target the way a real client would before it hits
    the access log (spaces -> %20, ' -> %27, ...). The nginx parser decodes it
    again, so detection rules still match on the human-readable payload."""
    return quote(target, safe="/?=&:+.")

_MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun",
           "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]

BENIGN_USERS = ["deploy", "ubuntu", "admin", "www-data", "postgres"]
ENUM_USERS = ["admin", "root", "test", "oracle", "postgres", "git", "jenkins",
              "user", "guest", "backup", "ftp", "mysql", "ubnt", "pi"]
BENIGN_PATHS = ["/", "/index.html", "/about", "/api/health", "/static/app.css",
                "/static/app.js", "/favicon.ico", "/login", "/dashboard"]
BENIGN_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) Gecko/20100101 Firefox/124.0",
]
SQLI_PAYLOADS = [
    "/product?id=1' OR '1'='1",
    "/product?id=1 UNION SELECT username,password FROM users--",
    "/search?q=test'; DROP TABLE users--",
    "/item?id=1 AND SLEEP(5)",
    "/list?cat=1' UNION SELECT table_name FROM information_schema.tables--",
]
TRAVERSAL_PAYLOADS = [
    "/download?file=../../../../etc/passwd",
    "/static/..%2f..%2f..%2fetc%2fpasswd",
    "/view?page=..\\..\\..\\windows\\win.ini",
    "/img?f=....//....//etc/passwd",
]
SCAN_PATHS = ["/admin", "/wp-login.php", "/.env", "/config.php", "/backup.zip",
              "/.git/config", "/phpmyadmin", "/api/v1/users", "/server-status",
              "/xmlrpc.php", "/administrator", "/.aws/credentials", "/shell.php",
              "/vendor/phpunit", "/console", "/actuator/env", "/debug"]


def _syslog_ts(dt: datetime) -> str:
    return f"{_MONTHS[dt.month - 1]} {dt.day:2d} {dt:%H:%M:%S}"


def _nginx_ts(dt: datetime) -> str:
    return dt.strftime("%d/%b/%Y:%H:%M:%S %z")


@dataclass
class Scenario:
    auth: list[str] = field(default_factory=list)
    nginx: list[str] = field(default_factory=list)
    events: list[dict] = field(default_factory=list)


# --------------------------------------------------------------------------- #
# Individual attack builders. Each appends to the shared Scenario and returns
# the clock advanced past the events it emitted.
# --------------------------------------------------------------------------- #

def _ssh_line(dt: datetime, pid: int, msg: str, host: str = "web01") -> str:
    return f"{_syslog_ts(dt)} {host} sshd[{pid}]: {msg}"


def _ssh_bruteforce(sc: Scenario, t: datetime, ip: str, rnd: random.Random) -> datetime:
    """~8 rapid failed logins for 'root' then a success — a cracked password."""
    pid = rnd.randint(1000, 9000)
    for _ in range(8):
        sc.auth.append(_ssh_line(t, pid, f"Failed password for root from {ip} port {rnd.randint(30000, 60000)} ssh2"))
        t += timedelta(seconds=rnd.randint(2, 6))
    sc.auth.append(_ssh_line(t, pid, f"Accepted password for root from {ip} port {rnd.randint(30000, 60000)} ssh2"))
    return t + timedelta(seconds=5)


def _ssh_enumeration(sc: Scenario, t: datetime, ip: str, rnd: random.Random) -> datetime:
    """A spray across many invalid usernames — enumeration."""
    for user in ENUM_USERS:
        pid = rnd.randint(1000, 9000)
        sc.auth.append(_ssh_line(t, pid, f"Failed password for invalid user {user} from {ip} port {rnd.randint(30000, 60000)} ssh2"))
        t += timedelta(seconds=rnd.randint(3, 8))
    return t


def _web_sqli(sc: Scenario, t: datetime, ip: str, rnd: random.Random) -> datetime:
    for payload in SQLI_PAYLOADS:
        status = rnd.choice([403, 500, 200])
        sc.nginx.append(
            f'{ip} - - [{_nginx_ts(t)}] "GET {_enc(payload)} HTTP/1.1" {status} '
            f'{rnd.randint(200, 900)} "-" "sqlmap/1.7.2#stable"'
        )
        t += timedelta(seconds=rnd.randint(1, 4))
    return t


def _web_traversal(sc: Scenario, t: datetime, ip: str, rnd: random.Random) -> datetime:
    for payload in TRAVERSAL_PAYLOADS:
        status = rnd.choice([403, 404, 200])
        sc.nginx.append(
            f'{ip} - - [{_nginx_ts(t)}] "GET {_enc(payload)} HTTP/1.1" {status} '
            f'{rnd.randint(150, 500)} "-" "curl/8.4.0"'
        )
        t += timedelta(seconds=rnd.randint(1, 3))
    return t


def _web_scan(sc: Scenario, t: datetime, ip: str, rnd: random.Random) -> datetime:
    """A directory brute force: ~20 requests, almost all 404, tool user-agent."""
    for path in SCAN_PATHS + rnd.sample(SCAN_PATHS, 6):
        status = rnd.choice([404, 404, 404, 404, 404, 404, 403, 301])
        sc.nginx.append(
            f'{ip} - - [{_nginx_ts(t)}] "GET {path} HTTP/1.1" {status} '
            f'{rnd.randint(0, 300)} "-" "Mozilla/5.0 (Nikto/2.5.0)"'
        )
        t += timedelta(seconds=rnd.randint(1, 2))
    return t


def _benign_ssh(sc: Scenario, t: datetime, rnd: random.Random) -> datetime:
    ip = f"198.51.100.{rnd.randint(2, 40)}"
    user = rnd.choice(BENIGN_USERS)
    pid = rnd.randint(1000, 9000)
    sc.auth.append(_ssh_line(t, pid, f"Accepted publickey for {user} from {ip} port {rnd.randint(30000, 60000)} ssh2"))
    return t + timedelta(seconds=rnd.randint(30, 300))


def _benign_web(sc: Scenario, t: datetime, rnd: random.Random) -> datetime:
    ip = f"198.51.100.{rnd.randint(2, 60)}"
    path = rnd.choice(BENIGN_PATHS)
    agent = rnd.choice(BENIGN_AGENTS)
    status = rnd.choice([200, 200, 200, 304, 302])
    sc.nginx.append(
        f'{ip} - - [{_nginx_ts(t)}] "GET {path} HTTP/1.1" {status} '
        f'{rnd.randint(200, 4000)} "https://example.com/" "{agent}"'
    )
    return t + timedelta(seconds=rnd.randint(1, 20))


def _json_events(sc: Scenario, t: datetime, attacker_ip: str, rnd: random.Random) -> None:
    """A few structured app events, including denied API keys from an attacker."""
    for _ in range(5):
        sc.events.append({
            "time": t.isoformat(),
            "type": "api_request",
            "ip": f"198.51.100.{rnd.randint(2, 40)}",
            "user": rnd.choice(BENIGN_USERS),
            "result": "ok",
        })
        t += timedelta(seconds=rnd.randint(5, 60))
    for _ in range(6):
        sc.events.append({
            "time": t.isoformat(),
            "type": "api_key_invalid",
            "ip": attacker_ip,
            "user": "svc-bot",
            "result": "denied",
        })
        t += timedelta(seconds=rnd.randint(1, 4))


# --------------------------------------------------------------------------- #
# Public API
# --------------------------------------------------------------------------- #

SCENARIOS = ["full", "ssh", "web"]


def generate_scenario(
    out_dir: str | Path,
    scenario: str = "full",
    *,
    seed: int | None = None,
    start: datetime | None = None,
) -> dict[str, int]:
    """Write a scenario to ``out_dir`` and return a per-file line count.

    ``scenario`` is one of :data:`SCENARIOS`. ``seed`` makes output
    reproducible for tests.
    """
    if scenario not in SCENARIOS:
        raise ValueError(f"unknown scenario {scenario!r}; choose from {SCENARIOS}")

    rnd = random.Random(seed)
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    t0 = start or (datetime.now(timezone.utc) - timedelta(minutes=30))
    sc = Scenario()

    ssh_attacker = f"203.0.113.{rnd.randint(2, 250)}"
    enum_attacker = f"203.0.113.{rnd.randint(2, 250)}"
    web_attacker = f"185.220.101.{rnd.randint(2, 250)}"
    scan_attacker = f"45.155.205.{rnd.randint(2, 250)}"

    t = t0
    # Warm-up benign noise.
    for _ in range(15):
        t = _benign_web(sc, t, rnd)
    t = _benign_ssh(sc, t, rnd)

    if scenario in ("full", "ssh"):
        _ssh_bruteforce(sc, t0 + timedelta(minutes=2), ssh_attacker, rnd)
        _ssh_enumeration(sc, t0 + timedelta(minutes=6), enum_attacker, rnd)

    if scenario in ("full", "web"):
        _web_sqli(sc, t0 + timedelta(minutes=4), web_attacker, rnd)
        _web_traversal(sc, t0 + timedelta(minutes=5), web_attacker, rnd)
        _web_scan(sc, t0 + timedelta(minutes=8), scan_attacker, rnd)

    # More benign noise after the attacks.
    t = t0 + timedelta(minutes=12)
    for _ in range(20):
        t = _benign_web(sc, t, rnd)

    _json_events(sc, t0 + timedelta(minutes=10), web_attacker, rnd)

    # Sort each log by time so files look like real, chronologically-appended logs.
    sc.nginx.sort(key=_nginx_sort_key)
    sc.events.sort(key=lambda e: e["time"])

    (out_dir / "auth.log").write_text("\n".join(sc.auth) + "\n", encoding="utf-8")
    (out_dir / "nginx-access.log").write_text("\n".join(sc.nginx) + "\n", encoding="utf-8")
    (out_dir / "events.json").write_text(
        "\n".join(json.dumps(e) for e in sc.events) + "\n", encoding="utf-8"
    )

    return {
        "auth.log": len(sc.auth),
        "nginx-access.log": len(sc.nginx),
        "events.json": len(sc.events),
    }


def _nginx_sort_key(line: str) -> datetime:
    try:
        stamp = line.split("[", 1)[1].split("]", 1)[0]
        return datetime.strptime(stamp, "%d/%b/%Y:%H:%M:%S %z")
    except (IndexError, ValueError):
        return datetime.now(timezone.utc)
