"""5 simple correlation rules. Each returns a list of incidents."""
from datetime import datetime, timezone

from src.database import get_connection, init_db


def parse_ts(s: str) -> datetime:
    """Parse 2025-01-01T09:00:00Z into a datetime."""
    return datetime.strptime(s, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


def detect_brute_force(events: list[dict], threshold: int = 5, window_min: int = 5) -> list[dict]:
    """Many auth_failed from one IP in a short window. 1 incident per IP max."""
    fails = [e for e in events if e["event_type"] == "auth_failed" and e["src_ip"]]
    by_ip: dict[str, list[dict]] = {}
    for e in fails:
        by_ip.setdefault(e["src_ip"], []).append(e)
    out = []
    for ip, lst in by_ip.items():
        lst.sort(key=lambda e: e["timestamp"])
        for i in range(len(lst)):
            start = parse_ts(lst[i]["timestamp"])
            window = [e for e in lst[i:] if (parse_ts(e["timestamp"]) - start).total_seconds() <= window_min * 60]
            if len(window) >= threshold:
                out.append({
                    "title": f"Brute force from {ip} ({len(window)} fails)",
                    "rule": "brute_force",
                    "severity": "high",
                    "event_ids": [e["id"] for e in window],
                })
                break  # Only 1 incident per IP, keeps demo clean.
    return out


def detect_lateral(events: list[dict], window_min: int = 10) -> list[dict]:
    """Same user + same IP logs into 2+ hosts in 10 min. 1 per user max."""
    oks = [e for e in events if e["event_type"] == "auth_success" and e["user"] and e["hostname"] and e["src_ip"]]
    by_key: dict[tuple, list[dict]] = {}
    for e in oks:
        by_key.setdefault((e["user"], e["src_ip"]), []).append(e)
    out = []
    for (user, ip), lst in by_key.items():
        lst.sort(key=lambda e: e["timestamp"])
        for i in range(len(lst)):
            start = parse_ts(lst[i]["timestamp"])
            window = [e for e in lst[i:] if (parse_ts(e["timestamp"]) - start).total_seconds() <= window_min * 60]
            hosts = {e["hostname"] for e in window}
            if len(hosts) >= 2:
                out.append({
                    "title": f"Lateral movement: {user} on {len(hosts)} hosts from {ip}",
                    "rule": "lateral_movement",
                    "severity": "high",
                    "event_ids": [e["id"] for e in window],
                })
                break
    return out


def detect_exfil(events: list[dict], threshold: int = 10_000_000, window_min: int = 10) -> list[dict]:
    """Large bytes_out from one IP in 10 min. 1 incident per IP max."""
    ups = [e for e in events if e["bytes_out"] > 0 and e["src_ip"]]
    by_ip: dict[str, list[dict]] = {}
    for e in ups:
        by_ip.setdefault(e["src_ip"], []).append(e)
    out = []
    for ip, lst in by_ip.items():
        lst.sort(key=lambda e: e["timestamp"])
        for i in range(len(lst)):
            start = parse_ts(lst[i]["timestamp"])
            window = [e for e in lst[i:] if (parse_ts(e["timestamp"]) - start).total_seconds() <= window_min * 60]
            total = sum(e["bytes_out"] for e in window)
            if total >= threshold:
                out.append({
                    "title": f"Possible exfil from {ip} ({total // 1_000_000} MB)",
                    "rule": "data_exfiltration",
                    "severity": "high",
                    "event_ids": [e["id"] for e in window if e["bytes_out"] > 100_000],
                })
                break
    return out


def detect_priv_esc(events: list[dict]) -> list[dict]:
    """Any successful sudo/su. 1 incident per user+host."""
    privs = [e for e in events if e["event_type"] == "priv_esc"]
    by_key: dict[tuple, list[dict]] = {}
    for e in privs:
        by_key.setdefault((e["user"], e["hostname"]), []).append(e)
    out = []
    for (user, host), lst in by_key.items():
        out.append({
            "title": f"Privilege escalation: {user} on {host}",
            "rule": "privilege_escalation",
            "severity": "medium",
            "event_ids": [e["id"] for e in lst],
        })
    return out


def detect_web_scan(events: list[dict], threshold: int = 20, window_min: int = 2) -> list[dict]:
    """Many 404s from one IP in 2 min. 1 incident per IP max."""
    notfounds = [e for e in events if e["event_type"] == "http_404" and e["src_ip"]]
    by_ip: dict[str, list[dict]] = {}
    for e in notfounds:
        by_ip.setdefault(e["src_ip"], []).append(e)
    out = []
    for ip, lst in by_ip.items():
        lst.sort(key=lambda e: e["timestamp"])
        for i in range(len(lst)):
            start = parse_ts(lst[i]["timestamp"])
            window = [e for e in lst[i:] if (parse_ts(e["timestamp"]) - start).total_seconds() <= window_min * 60]
            if len(window) >= threshold:
                out.append({
                    "title": f"Web scan from {ip} ({len(window)} 404s)",
                    "rule": "web_scanning",
                    "severity": "medium",
                    "event_ids": [e["id"] for e in window],
                })
                break
    return out


# All rules in one list so main() just loops.
ALL_RULES = [
    detect_brute_force,
    detect_lateral,
    detect_exfil,
    detect_priv_esc,
    detect_web_scan,
]


def load_events(db_path=None) -> list[dict]:
    """Load all events from SQLite, oldest first."""
    conn = get_connection(db_path)
    rows = conn.execute("SELECT * FROM events ORDER BY timestamp").fetchall()
    conn.close()
    return [dict(r) for r in rows]


def save_incidents(incidents: list[dict], db_path=None) -> int:
    """Clear old incidents and save new ones. Returns count saved."""
    init_db(db_path)
    conn = get_connection(db_path)
    cur = conn.cursor()
    cur.execute("DELETE FROM incident_events")
    cur.execute("DELETE FROM incidents")
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    for inc in incidents:
        cur.execute("""
            INSERT INTO incidents (title, rule, severity, status, created_at, updated_at)
            VALUES (?, ?, ?, 'open', ?, ?)
        """, (inc["title"], inc["rule"], inc["severity"], now, now))
        iid = cur.lastrowid
        for eid in inc["event_ids"]:
            cur.execute("INSERT INTO incident_events (incident_id, event_id) VALUES (?, ?)", (iid, eid))
    conn.commit()
    count = cur.execute("SELECT COUNT(*) FROM incidents").fetchone()[0]
    conn.close()
    return count


def main() -> int:
    """Run all rules and save. Use: python -m src.detector"""
    events = load_events()
    found = []
    for rule in ALL_RULES:
        hits = rule(events)
        print(f"{rule.__name__}: {len(hits)} incident(s)")
        found.extend(hits)
    total = save_incidents(found)
    print(f"Saved {total} incidents")
    for inc in found:
        print(f" - [{inc['rule']}] {inc['title']}")
    return total


if __name__ == "__main__":
    main()
