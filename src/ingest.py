"""Read 4 log files, normalize, save into SQLite."""
from pathlib import Path

from src.config import LOG_DIR, DB_PATH
from src.database import init_db, get_connection
from src.parsers import parse_auth, parse_web, parse_firewall, parse_endpoint


def load_file(path: Path, parser) -> list[dict]:
    """Parse each line in a file, skip lines that do not match."""
    events = []
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line:
            continue
        e = parser(line)
        if e:
            events.append(e)
    return events


def save_events(events: list[dict], db_path: Path | str | None = None) -> int:
    """Clear old events and insert new ones. Returns count saved."""
    init_db(db_path)
    conn = get_connection(db_path)
    cur = conn.cursor()
    cur.execute("DELETE FROM events")  # Fresh load each time, simple for prototype.
    for e in events:
        cur.execute("""
            INSERT INTO events
            (timestamp, source, src_ip, dst_ip, user, hostname, event_type, severity, bytes_out, raw, details)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (e["timestamp"], e["source"], e["src_ip"], e["dst_ip"], e["user"],
              e["hostname"], e["event_type"], e["severity"], e["bytes_out"],
              e["raw"], e["details"]))
    conn.commit()
    count = cur.execute("SELECT COUNT(*) FROM events").fetchone()[0]
    conn.close()
    return count


def main() -> int:
    """Load all 4 logs and save. Run with: python -m src.ingest"""
    files = [
        (LOG_DIR / "auth.log", parse_auth),
        (LOG_DIR / "web.log", parse_web),
        (LOG_DIR / "firewall.log", parse_firewall),
        (LOG_DIR / "endpoint.log", parse_endpoint),
    ]
    all_events = []
    for path, parser in files:
        if not path.exists():
            print(f"Missing {path}. Run python -m src.generator first.")
            continue
        found = load_file(path, parser)
        print(f"{path.name}: {len(found)} events")
        all_events.extend(found)
    total = save_events(all_events, DB_PATH)
    print(f"Saved {total} events to {DB_PATH}")
    return total


if __name__ == "__main__":
    main()
