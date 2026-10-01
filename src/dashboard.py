"""SOC console dashboard. Run: streamlit run src/dashboard.py"""
import sys
from datetime import datetime
from html import escape
from pathlib import Path

# Streamlit runs this file directly (not as python -m), so add project root to path.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import streamlit as st

from src.database import get_connection

# ---------------------------------------------------------------------------
# Look: cool paper, slate ink, red only for high severity, amber only for medium.
# Hanken Grotesk everywhere (self-hosted from src/static/fonts, works offline).
# Mono (system) only for raw log lines.
# ---------------------------------------------------------------------------
CSS = """
<style>
@font-face {
  font-family: 'Hanken Grotesk';
  src: url('/app/static/fonts/HankenGrotesk.woff2') format('woff2');
  font-weight: 100 900; font-style: normal; font-display: swap;
}

:root {
  --paper: #F2F3F1; --surface: #FFFFFF; --ink: #1E2833; --muted: #6B7682;
  --line: #DADFE2; --high: #B3352B; --medium: #B7791F; --low: #B4BCC2;
}

.stApp, .stApp p, .stApp label, .stApp input, .stApp textarea, .stApp button, .stApp li {
  font-family: 'Hanken Grotesk', system-ui, -apple-system, 'Segoe UI', sans-serif;
}
.block-container { max-width: 1180px; padding: 2.25rem 2rem 4rem; }
#MainMenu, footer { visibility: hidden; }
[data-testid="stHeader"] { background: transparent; }

.brand { font-size: 14px; font-weight: 600; color: var(--ink); margin-bottom: 0.75rem; }

/* Tabs: quiet underline, ink indicator */
[data-baseweb="tab-list"] { gap: 1.75rem; }
[data-baseweb="tab-highlight"] { background: var(--ink); }
[data-baseweb="tab"] p { font-size: 14px; }

/* Incident queue: rows with a severity edge, not cards */
.queue-count { font-size: 13px; color: var(--muted); margin: 0.5rem 0 0.4rem; }
[class*="st-key-inc_"] button {
  width: 100%; min-height: 0; padding: 0.6rem 0.9rem;
  background: transparent; color: var(--ink);
  border: 0; border-left: 3px solid var(--low); border-radius: 0 4px 4px 0;
}
[class*="st-key-inc_"] button > div { width: 100%; justify-content: flex-start; }
[class*="st-key-inc_"] button p { text-align: left; font-size: 14px; line-height: 1.4; }
[class*="st-key-inc_"] button:hover { background: rgba(255, 255, 255, 0.7); }
[class*="st-key-inc_"] button:focus-visible { outline: 2px solid var(--ink); outline-offset: 2px; }

/* Open case */
.case-title {
  font-family: 'Hanken Grotesk', system-ui, -apple-system, 'Segoe UI', sans-serif; font-weight: 500;
  font-size: 2.1rem; line-height: 1.15; letter-spacing: -0.025em;
  color: var(--ink); margin: 0 0 0.6rem;
}
.case-status { font-size: 15px; color: var(--ink); }
.case-sub { font-size: 13px; color: var(--muted); margin: 0.2rem 0 1.75rem; }

/* Lane timeline: one lane per log source, events placed in their lane */
.lanes { overflow-x: auto; padding-bottom: 0.5rem; }
.lane-grid { min-width: 560px; }
.lane-head, .lane-row {
  display: grid; grid-template-columns: 64px repeat(var(--n), 1fr); column-gap: 0.5rem;
}
.lane-head {
  font-size: 12px; color: var(--muted); padding-bottom: 0.5rem;
  border-bottom: 1px solid var(--line); margin-bottom: 0.25rem;
}
.lane-head span:not(:first-child) { padding-left: 18px; }
.off {
  font-size: 12px; color: var(--muted); text-align: right; padding-top: 7px;
  font-variant-numeric: tabular-nums;
}
.cell { position: relative; padding: 5px 0 7px 18px; min-height: 34px; }
.cell::before {
  content: ""; position: absolute; left: 5px; top: 0; bottom: 0; width: 1px; background: var(--line);
}
.dot {
  position: absolute; left: 0; top: 9px; width: 11px; height: 11px; border-radius: 50%;
  background: var(--low); outline: 3px solid var(--paper);
}
.dot.high { background: var(--high); }
.dot.medium { background: var(--medium); }
.lanes details summary { list-style: none; cursor: pointer; }
.lanes details summary::-webkit-details-marker { display: none; }
.lanes details summary:focus-visible { outline: 2px solid var(--ink); outline-offset: 2px; }
.ev-type { display: block; font-size: 13px; font-weight: 500; color: var(--ink); line-height: 1.3; }
.ev-meta { display: block; font-size: 12px; color: var(--muted); line-height: 1.3; word-break: break-word; }
.raw {
  font-family: Consolas, ui-monospace, 'SF Mono', Menlo, monospace;
  font-size: 11px; line-height: 1.5; color: var(--ink);
  background: var(--surface); border: 1px solid var(--line); border-radius: 4px;
  padding: 8px 10px; margin: 6px 0 2px; white-space: pre-wrap; word-break: break-all;
}

/* Workflow + messages */
.rule { border-top: 1px solid var(--line); margin: 2rem 0 1.25rem; }
.flash { font-size: 13px; color: var(--ink); border-left: 3px solid var(--ink); padding: 2px 10px; margin-bottom: 0.75rem; }
.empty { color: var(--muted); font-size: 14px; padding: 1rem 0; }

[data-baseweb="input"], [data-baseweb="textarea"], [data-baseweb="select"] > div {
  background: var(--surface); border-color: var(--line); border-radius: 4px;
}
[data-testid="stForm"] { border: 0; padding: 0; }
[data-testid="stFormSubmitButton"] button { background: var(--ink); border: 0; border-radius: 4px; padding: 0.45rem 1.1rem; }
[data-testid="stFormSubmitButton"] button p { color: #FFFFFF; }
</style>
"""

SEV_ORDER = "CASE severity WHEN 'high' THEN 0 WHEN 'medium' THEN 1 ELSE 2 END"
SEV_COLOR = {"high": "#B3352B", "medium": "#B7791F", "low": "#B4BCC2"}
LANES = ["auth", "web", "firewall", "endpoint"]
STATUS_ORDER = ["open", "investigating", "resolved"]


# ---------------------------------------------------------------------------
# Data layer (unchanged)
# ---------------------------------------------------------------------------
def query_events(search: str = "", source: str = "", severity: str = "", limit: int = 200) -> list[dict]:
    """Search events, newest first. Used by the events table."""
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
    rows = [dict(r) for r in conn.execute(q, args).fetchall()]
    conn.close()
    return rows


def query_incidents(status: str = "") -> list[dict]:
    """List incidents, high severity first (unequal weights, no equal cards)."""
    conn = get_connection()
    if status:
        rows = conn.execute(
            f"SELECT * FROM incidents WHERE status = ? ORDER BY {SEV_ORDER}, id", (status,)
        ).fetchall()
    else:
        rows = conn.execute(f"SELECT * FROM incidents ORDER BY {SEV_ORDER}, id").fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_timeline(iid: int) -> tuple[dict | None, list[dict]]:
    """One incident plus its events in time order."""
    conn = get_connection()
    inc = conn.execute("SELECT * FROM incidents WHERE id = ?", (iid,)).fetchone()
    if not inc:
        conn.close()
        return None, []
    events = conn.execute("""
        SELECT e.* FROM events e
        JOIN incident_events ie ON ie.event_id = e.id
        WHERE ie.incident_id = ? ORDER BY e.timestamp
    """, (iid,)).fetchall()
    conn.close()
    return dict(inc), [dict(r) for r in events]


def save_workflow(iid: int, status: str, assignee: str, notes: str) -> None:
    """Save status/assignee/notes for an incident."""
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    conn = get_connection()
    conn.execute("""
        UPDATE incidents SET status = ?, assignee = ?, notes = ?, updated_at = ?
        WHERE id = ?
    """, (status, assignee, notes, now, iid))
    conn.commit()
    conn.close()


# ---------------------------------------------------------------------------
# Presentation helpers
# ---------------------------------------------------------------------------
def safe(value) -> str:
    """Escape anything that goes into unsafe_allow_html. Log data is attacker-controlled.

    Also keeps the result on one line and neutralises '$' so Streamlit's markdown
    pass can't break the HTML block or treat log text as math.
    """
    text = escape("" if value is None else str(value), quote=True)
    return text.replace("\r", "").replace("\n", "&#10;").replace("$", "&#36;")


def md_escape(text: str) -> str:
    """Escape markdown control characters for button labels (no HTML there)."""
    out = []
    for ch in str(text):
        out.append("\\" + ch if ch in "\\`*_[]~$<>" else ch)
    return "".join(out)


def parse_ts(ts):
    try:
        return datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
    except ValueError:
        return None


def offset_label(t0, t) -> str:
    """Time since the first event in the incident, e.g. +0:41 or +1:02:09."""
    if t0 is None or t is None:
        return "-"
    try:
        total = max(int((t - t0).total_seconds()), 0)
    except TypeError:
        return "-"
    h, rem = divmod(total, 3600)
    m, s = divmod(rem, 60)
    return f"+{h}:{m:02d}:{s:02d}" if h else f"+{m}:{s:02d}"


def sev_class(sev) -> str:
    return sev if sev in ("high", "medium", "low") else "low"


def event_cell(e: dict) -> str:
    """One event dot with its label. Raw line is revealed on click."""
    sev = sev_class(e.get("severity"))
    label = str(e.get("event_type") or "event").replace("_", " ")
    meta = ", ".join(str(x) for x in (e.get("user"), e.get("src_ip"), e.get("hostname")) if x)
    detail = f"{e.get('timestamp') or ''}\n{e.get('raw') or ''}"
    return (
        f'<div class="cell"><span class="dot {sev}"></span><details><summary>'
        f'<span class="ev-type">{safe(label)}</span><span class="ev-meta">{safe(meta)}</span>'
        f'</summary><div class="raw">{safe(detail)}</div></details></div>'
    )


def build_lanes(events: list[dict]) -> str:
    """Lane timeline as one escaped HTML grid: a column per source, a row per event."""
    lanes = list(LANES)
    for e in events:
        if e["source"] not in lanes:
            lanes.append(e["source"])
    t0 = parse_ts(events[0]["timestamp"])

    head = "".join(f"<span>{safe(str(l).capitalize())}</span>" for l in lanes)
    parts = [
        f'<div class="lanes"><div class="lane-grid" style="--n:{len(lanes)}">',
        f'<div class="lane-head"><span></span>{head}</div>',
    ]
    for e in events:
        off = offset_label(t0, parse_ts(e["timestamp"]))
        cells = "".join(
            event_cell(e) if e["source"] == lane else '<div class="cell"></div>' for lane in lanes
        )
        parts.append(f'<div class="lane-row"><div class="off">{safe(off)}</div>{cells}</div>')
    parts.append("</div></div>")
    return "".join(parts)


def queue_css(incidents: list[dict], selected: int) -> str:
    """Per-row severity edge and selected state, keyed on each button's st-key class."""
    rules = []
    for i in incidents:
        iid = int(i["id"])
        color = SEV_COLOR[sev_class(i["severity"])]
        bg = "background: #FFFFFF;" if iid == selected else ""
        rules.append(f".st-key-inc_{iid} button {{ border-left-color: {color}; {bg} }}")
    return "<style>" + "\n".join(rules) + "</style>"


def show_table(rows: list[dict]) -> None:
    """st.dataframe full width across Streamlit versions."""
    try:
        st.dataframe(rows, width="stretch", hide_index=True)
    except Exception:
        st.dataframe(rows, use_container_width=True, hide_index=True)


def empty(message: str) -> None:
    st.markdown(f"<div class='empty'>{safe(message)}</div>", unsafe_allow_html=True)


# ---------------------------------------------------------------------------
# Views
# ---------------------------------------------------------------------------
def render_workflow(inc: dict) -> None:
    """Status, assignee and notes for the open incident."""
    iid = inc["id"]
    st.markdown("<div class='rule'></div>", unsafe_allow_html=True)
    flash = st.session_state.pop("flash", None)
    if flash:
        st.markdown(f"<div class='flash'>{safe(flash)}</div>", unsafe_allow_html=True)

    with st.form(f"workflow_{iid}"):
        c1, c2 = st.columns(2)
        new_status = c1.selectbox(
            "Status", STATUS_ORDER,
            index=STATUS_ORDER.index(inc["status"]) if inc["status"] in STATUS_ORDER else 0,
            key=f"status_{iid}",
        )
        new_assignee = c2.text_input("Assignee", inc["assignee"] or "", key=f"assignee_{iid}")
        new_notes = st.text_area("Notes", inc["notes"] or "", key=f"notes_{iid}")
        if st.form_submit_button("Save changes"):
            save_workflow(iid, new_status, new_assignee, new_notes)
            st.session_state["flash"] = "Changes saved."
            st.rerun()


def render_case(iid: int) -> None:
    """Right pane: title, status line, lane timeline, workflow."""
    inc, timeline = get_timeline(iid)
    if not inc:
        empty("That incident no longer exists. Pick another from the list.")
        return

    sev = sev_class(inc["severity"])
    who = f"assigned to {inc['assignee']}" if inc["assignee"] else "unassigned"
    st.markdown(
        f"<div class='case-title'>{safe(inc['title'])}</div>"
        f"<div class='case-status'>{safe(sev.capitalize())} severity, {safe(inc['status'])}, {safe(who)}</div>",
        unsafe_allow_html=True,
    )

    if timeline:
        sources = {e["source"] for e in timeline}
        start = parse_ts(timeline[0]["timestamp"])
        start_txt = start.strftime("%d %b %Y, %H:%M UTC") if start else str(timeline[0]["timestamp"])
        n = len(timeline)
        summary = (
            f"{n} event{'s' if n != 1 else ''} across {len(sources)} "
            f"source{'s' if len(sources) != 1 else ''}, starting {start_txt}"
        )
        st.markdown(f"<div class='case-sub'>{safe(summary)}</div>", unsafe_allow_html=True)
        st.markdown(build_lanes(timeline), unsafe_allow_html=True)
    else:
        empty("No events are linked to this incident.")

    render_workflow(inc)


def render_incidents() -> None:
    """Incidents view: queue on the left, open case on the right."""
    if not query_incidents():
        empty("No incidents yet. Run python -m src.detector to create them.")
        return

    queue, case = st.columns([1, 2.6], gap="large")

    with queue:
        shown = st.selectbox(
            "Show", ["All", "Open", "Investigating", "Resolved"],
            label_visibility="collapsed", key="inc_filter",
        )
        incidents = query_incidents("" if shown == "All" else shown.lower())
        count = len(incidents)
        st.markdown(
            f"<div class='queue-count'>{count} incident{'s' if count != 1 else ''}</div>",
            unsafe_allow_html=True,
        )
        if not incidents:
            empty("Nothing with that status.")

        # Default to the most severe unresolved incident.
        ids = [i["id"] for i in incidents]
        selected = st.session_state.get("sel")
        if selected not in ids and ids:
            unresolved = [i["id"] for i in incidents if i["status"] != "resolved"]
            selected = unresolved[0] if unresolved else ids[0]
            st.session_state["sel"] = selected

        if incidents:
            st.markdown(queue_css(incidents, selected), unsafe_allow_html=True)
        for i in incidents:
            who = i["assignee"] or "unassigned"
            label = (
                f"{md_escape(i['title'])}  \n"
                f":gray[{md_escape(str(i['severity']).capitalize())}, {md_escape(i['status'])}, {md_escape(who)}]"
            )
            if st.button(label, key=f"inc_{i['id']}"):
                st.session_state["sel"] = i["id"]
                st.rerun()

    with case:
        if incidents:
            render_case(selected)
        else:
            empty("Pick a different status to see incidents.")


def render_events() -> None:
    """Events view: one search row and a plain table."""
    c1, c2, c3 = st.columns([3, 1, 1])
    search = c1.text_input(
        "Search events", placeholder="Search user, IP, host, event type or raw line",
        label_visibility="collapsed",
    )
    source = c2.selectbox(
        "Source", ["All sources", "auth", "web", "firewall", "endpoint"], label_visibility="collapsed"
    )
    severity = c3.selectbox(
        "Severity", ["All severities", "low", "medium", "high"], label_visibility="collapsed"
    )

    events = query_events(
        search,
        "" if source == "All sources" else source,
        "" if severity == "All severities" else severity,
    )
    st.markdown(
        f"<div class='queue-count'>{len(events)} event{'s' if len(events) != 1 else ''}</div>",
        unsafe_allow_html=True,
    )
    if events:
        show_table([
            {"time": e["timestamp"], "source": e["source"], "event": e["event_type"],
             "ip": e["src_ip"], "user": e["user"], "host": e["hostname"],
             "severity": e["severity"]} for e in events
        ])
    else:
        empty("No events match. Clear the search or pick a different source.")


def main() -> None:
    """Page layout: wordmark, then Incidents and Events views."""
    st.set_page_config(page_title="SIEM prototype", layout="wide")
    st.markdown(CSS, unsafe_allow_html=True)
    st.markdown("<div class='brand'>SIEM prototype</div>", unsafe_allow_html=True)

    incidents_tab, events_tab = st.tabs(["Incidents", "Events"])
    with incidents_tab:
        render_incidents()
    with events_tab:
        render_events()


if __name__ == "__main__":
    main()  # streamlit run executes this; plain import does not (test-safe).