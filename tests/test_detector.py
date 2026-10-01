"""Tests for 5 detector rules. Uses small hand-made event lists."""
from src.detector import (
    detect_brute_force,
    detect_lateral,
    detect_exfil,
    detect_priv_esc,
    detect_web_scan,
)


def ev(eid: int, ts: str, **kw) -> dict:
    """Make a minimal event dict. Only sets fields each rule needs."""
    base = {"id": eid, "timestamp": ts, "src_ip": "", "user": "",
            "hostname": "", "event_type": "", "bytes_out": 0}
    base.update(kw)
    return base


def test_brute_force_fires():
    events = [ev(i, f"2025-01-01T10:00:{i:02d}Z", src_ip="10.0.0.1", event_type="auth_failed") for i in range(1, 7)]
    hits = detect_brute_force(events)
    assert len(hits) == 1
    assert hits[0]["rule"] == "brute_force"
    assert len(hits[0]["event_ids"]) >= 5


def test_brute_force_quiet():
    events = [ev(i, f"2025-01-01T10:0{i}:00Z", src_ip="10.0.0.1", event_type="auth_failed") for i in range(4)]
    assert detect_brute_force(events) == []


def test_lateral_fires():
    events = [
        ev(1, "2025-01-01T10:00:00Z", src_ip="1.2.3.4", user="alice", hostname="h1", event_type="auth_success"),
        ev(2, "2025-01-01T10:05:00Z", src_ip="1.2.3.4", user="alice", hostname="h2", event_type="auth_success"),
    ]
    hits = detect_lateral(events)
    assert len(hits) == 1
    assert hits[0]["rule"] == "lateral_movement"


def test_exfil_fires():
    events = [ev(i, f"2025-01-01T10:0{i}:00Z", src_ip="1.2.3.4", event_type="fw_allow", bytes_out=3_000_000) for i in range(5)]
    hits = detect_exfil(events)
    assert len(hits) == 1
    assert hits[0]["rule"] == "data_exfiltration"


def test_priv_esc_fires():
    events = [ev(1, "2025-01-01T10:00:00Z", user="bob", hostname="h1", event_type="priv_esc")]
    hits = detect_priv_esc(events)
    assert len(hits) == 1
    assert hits[0]["rule"] == "privilege_escalation"


def test_web_scan_fires():
    events = [ev(i, "2025-01-01T10:00:00Z", src_ip="9.9.9.9", event_type="http_404") for i in range(1, 21)]
    # Spread 20 events over 1 min by reusing same timestamp (all inside 2-min window).
    hits = detect_web_scan(events)
    assert len(hits) == 1
    assert hits[0]["rule"] == "web_scanning"
