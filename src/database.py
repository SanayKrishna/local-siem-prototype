"""SQLite setup. One file holds events and incidents."""
import sqlite3
from pathlib import Path

from src.config import DB_PATH


def get_connection(db_path: Path | str | None = None) -> sqlite3.Connection:
    """Open a SQLite connection. Makes folders if needed."""
    path = Path(db_path) if db_path else DB_PATH
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row  # Let rows act like dicts.
    return conn


def init_db(db_path: Path | str | None = None) -> Path:
    """Create tables if they do not exist. Safe to rerun."""
    path = Path(db_path) if db_path else DB_PATH
    conn = get_connection(path)
    cur = conn.cursor()

    # One common schema for all 4 log sources.
    cur.execute("""
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY,
            timestamp TEXT NOT NULL,
            source TEXT NOT NULL,       -- auth, web, firewall, endpoint
            src_ip TEXT DEFAULT '',
            dst_ip TEXT DEFAULT '',
            user TEXT DEFAULT '',
            hostname TEXT DEFAULT '',
            event_type TEXT DEFAULT '', -- e.g. auth_failed, http_404
            severity TEXT DEFAULT 'low',
            bytes_out INTEGER DEFAULT 0,
            raw TEXT DEFAULT '',
            details TEXT DEFAULT '{}'   -- extra fields as JSON string
        )
    """)

    # Incident workflow: open -> investigating -> resolved.
    cur.execute("""
        CREATE TABLE IF NOT EXISTS incidents (
            id INTEGER PRIMARY KEY,
            title TEXT NOT NULL,
            rule TEXT NOT NULL,         -- which detector rule fired
            severity TEXT DEFAULT 'medium',
            status TEXT DEFAULT 'open' CHECK(status IN ('open', 'investigating', 'resolved')),
            assignee TEXT DEFAULT '',
            notes TEXT DEFAULT '',
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
    """)

    # Links incidents to the events that caused them.
    cur.execute("""
        CREATE TABLE IF NOT EXISTS incident_events (
            incident_id INTEGER NOT NULL,
            event_id INTEGER NOT NULL,
            PRIMARY KEY (incident_id, event_id)
        )
    """)

    conn.commit()
    conn.close()
    return path


if __name__ == "__main__":
    # Lets you test with: python -m src.database
    db_file = init_db()
    print(f"DB ready at {db_file}")
