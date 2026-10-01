"""Basic tests for the 4 parsers. Uses lines just like generator output."""
from src.parsers import parse_auth, parse_web, parse_firewall, parse_endpoint


def test_parse_auth_failed():
    line = "2025-01-01T09:00:01Z web01 sshd[1000]: Failed password for alice from 10.10.10.5 port 52222 ssh2"
    e = parse_auth(line)
    assert e["source"] == "auth"
    assert e["event_type"] == "auth_failed"
    assert e["src_ip"] == "10.10.10.5"
    assert e["user"] == "alice"


def test_parse_web_404():
    line = '10.10.10.6 - - [2025-01-01T10:59:23Z] "GET /admin0 HTTP/1.1" 404 200'
    e = parse_web(line)
    assert e["source"] == "web"
    assert e["event_type"] == "http_404"
    assert e["src_ip"] == "10.10.10.6"


def test_parse_firewall_allow():
    line = "2025-01-01T10:51:40Z ALLOW 192.168.1.20 -> 203.0.113.99 bytes=3000000"
    e = parse_firewall(line)
    assert e["source"] == "firewall"
    assert e["event_type"] == "fw_allow"
    assert e["bytes_out"] == 3000000


def test_parse_endpoint_priv_esc():
    line = '2025-01-01T10:59:20Z host=workstation01 user=bob proc=sudo result=success cmd="sudo cat /etc/shadow"'
    e = parse_endpoint(line)
    assert e["source"] == "endpoint"
    assert e["event_type"] == "priv_esc"
    assert e["hostname"] == "workstation01"


def test_parse_bad_line_returns_none():
    assert parse_auth("not a log line") is None
    assert parse_web("not a log line") is None
    assert parse_firewall("not a log line") is None
    assert parse_endpoint("not a log line") is None
