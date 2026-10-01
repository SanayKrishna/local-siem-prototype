"""Smoke test: checks the DB file and tables can be created."""
from src.database import init_db
import sqlite3


def test_init_db_creates_tables(tmp_path):
    # Use a temp file so the real data/siem.db is not touched.
    db_file = tmp_path / "test.db"
    init_db(db_file)

    conn = sqlite3.connect(db_file)
    cur = conn.cursor()
    cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
    tables = {row[0] for row in cur.fetchall()}
    conn.close()

    # These 3 tables are needed by later phases.
    assert {"events", "incidents", "incident_events"} <= tables
