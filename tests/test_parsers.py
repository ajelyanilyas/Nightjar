"""Parser tests: raw log lines -> normalized events."""

from nightjar.parsers.auth_log import parse_auth_line
from nightjar.parsers.nginx import parse_nginx_line
from nightjar.parsers.json_events import parse_json_line


def test_auth_failed_login():
    line = ("Aug 18 03:12:44 web01 sshd[2043]: Failed password for "
            "invalid user admin from 203.0.113.7 port 51244 ssh2")
    ev = parse_auth_line(line)
    assert ev is not None
    assert ev.event_type == "ssh_failed_login"
    assert ev.src_ip == "203.0.113.7"
    assert ev.get("user") == "admin"
    assert ev.get("invalid_user") is True


def test_auth_accepted_login():
    line = ("Aug 18 03:13:01 web01 sshd[2051]: Accepted password for "
            "deploy from 198.51.100.4 port 40122 ssh2")
    ev = parse_auth_line(line)
    assert ev is not None
    assert ev.event_type == "ssh_accepted_login"
    assert ev.get("user") == "deploy"


def test_auth_ignores_unrelated_lines():
    assert parse_auth_line("Aug 18 03:13:01 web01 CRON[1]: session opened") is None


def test_nginx_decodes_payload():
    line = ('203.0.113.9 - - [18/Aug/2026:03:20:11 +0000] '
            '"GET /product?id=1%27%20OR%20%271%27=%271 HTTP/1.1" 403 512 "-" "sqlmap/1.7"')
    ev = parse_nginx_line(line)
    assert ev is not None
    assert ev.event_type == "http_request"
    assert ev.get("status") == 403
    # percent-encoding is decoded so rules can match the real payload
    assert "OR '1'='1" in ev.get("target")
    assert ev.get("user_agent") == "sqlmap/1.7"


def test_nginx_path_and_query_split():
    line = ('10.0.0.1 - - [18/Aug/2026:03:20:11 +0000] "GET /a/b?x=1 HTTP/1.1" 200 5 "-" "curl"')
    ev = parse_nginx_line(line)
    assert ev.get("path") == "/a/b"
    assert ev.get("query") == "x=1"
    assert ev.get("method") == "GET"


def test_json_event_key_mapping():
    ev = parse_json_line('{"time": "2026-08-18T03:25:00Z", "type": "api_key_used", '
                         '"ip": "198.51.100.9", "user": "svc-bot"}')
    assert ev is not None
    assert ev.event_type == "api_key_used"
    assert ev.src_ip == "198.51.100.9"
    assert ev.get("user") == "svc-bot"


def test_json_ignores_non_object():
    assert parse_json_line("not json") is None
    assert parse_json_line("[1,2,3]") is None
