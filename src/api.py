"""FastAPI for events search + incident workflow. Run: uvicorn src.api:app --reload"""
from datetime import datetime, timezone

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from src.database import get_connection, init_db

init_db()  # Make sure tables exist when the server starts.

app = FastAPI(title="SIEM Prototype")

OK_STATUS = ("open", "investigating", "resolved")  # Allowed workflow states.


@app.get("/")
def root():
    """Health check + where to go next."""
    return {"status": "ok", "docs": "/docs", "events": "/events", "incidents": "/incidents"}


def now() -> str:
    """Current time as 2025-01-01T09:00:00Z."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


@app.get("/events")
def list_events(search: str = "", source: str = "", severity: str = "", limit: int = 100):
    """Search events. Filters are optional, search matches raw/user/ip/host/type."""
    limit = max(1, min(limit, 500))  # Keep responses small.
    q = "SELECT * FROM events WHERE 1=1"
    args: list = []
    if source:
        q += " AND source = ?"
        args.append(source)
    if severity:
        q += " AND severity = ?"
        args.append(severity)
    if search:
        like = f"%{search}%"
        q += " AND (raw LIKE ? OR user LIKE ? OR src_ip LIKE ? OR hostname LIKE ? OR event_type LIKE ?)"
        args.extend([like] * 5)
    q += " ORDER BY timestamp DESC LIMIT ?"
    args.append(limit)
    conn = get_connection()
    rows = conn.execute(q, args).fetchall()
    conn.close()
    return [dict(r) for r in rows]


@app.get("/incidents")
def list_incidents(status: str = ""):
    """List incidents, optionally filter by status."""
    conn = get_connection()
    if status:
        rows = conn.execute("SELECT * FROM incidents WHERE status = ? ORDER BY id", (status,)).fetchall()
    else:
        rows = conn.execute("SELECT * FROM incidents ORDER BY id").fetchall()
    conn.close()
    return [dict(r) for r in rows]


@app.get("/incidents/{iid}")
def get_incident(iid: int):
    """Get one incident by id."""
    conn = get_connection()
    row = conn.execute("SELECT * FROM incidents WHERE id = ?", (iid,)).fetchone()
    conn.close()
    if not row:
        raise HTTPException(status_code=404, detail="Incident not found")
    return dict(row)


@app.get("/incidents/{iid}/timeline")
def incident_timeline(iid: int):
    """Get incident plus its linked events in time order (for drill-down)."""
    conn = get_connection()
    inc = conn.execute("SELECT * FROM incidents WHERE id = ?", (iid,)).fetchone()
    if not inc:
        conn.close()
        raise HTTPException(status_code=404, detail="Incident not found")
    events = conn.execute("""
        SELECT e.* FROM events e
        JOIN incident_events ie ON ie.event_id = e.id
        WHERE ie.incident_id = ?
        ORDER BY e.timestamp
    """, (iid,)).fetchall()
    conn.close()
    return {"incident": dict(inc), "events": [dict(r) for r in events]}


class IncidentCreate(BaseModel):
    """Body for POST /incidents."""
    title: str
    rule: str = "manual"
    severity: str = "medium"


@app.post("/incidents")
def create_incident(body: IncidentCreate):
    """Create a manual incident. Starts as open."""
    conn = get_connection()
    cur = conn.cursor()
    ts = now()
    cur.execute("""
        INSERT INTO incidents (title, rule, severity, status, created_at, updated_at)
        VALUES (?, ?, ?, 'open', ?, ?)
    """, (body.title, body.rule, body.severity, ts, ts))
    iid = cur.lastrowid
    conn.commit()
    row = conn.execute("SELECT * FROM incidents WHERE id = ?", (iid,)).fetchone()
    conn.close()
    return dict(row)


class IncidentUpdate(BaseModel):
    """Body for PATCH /incidents/{id}. All fields optional."""
    status: str | None = None
    assignee: str | None = None
    notes: str | None = None


@app.patch("/incidents/{iid}")
def update_incident(iid: int, body: IncidentUpdate):
    """Update status/assignee/notes. Status must stay in open/investigating/resolved."""
    conn = get_connection()
    row = conn.execute("SELECT * FROM incidents WHERE id = ?", (iid,)).fetchone()
    if not row:
        conn.close()
        raise HTTPException(status_code=404, detail="Incident not found")
    if body.status and body.status not in OK_STATUS:
        conn.close()
        raise HTTPException(status_code=400, detail=f"status must be one of {OK_STATUS}")
    cur = conn.cursor()
    cur.execute("""
        UPDATE incidents
        SET status = COALESCE(?, status),
            assignee = COALESCE(?, assignee),
            notes = COALESCE(?, notes),
            updated_at = ?
        WHERE id = ?
    """, (body.status, body.assignee, body.notes, now(), iid))
    conn.commit()
    updated = conn.execute("SELECT * FROM incidents WHERE id = ?", (iid,)).fetchone()
    conn.close()
    return dict(updated)
