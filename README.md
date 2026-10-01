# SIEM Prototype (local only)

Small SIEM for learning detection workflows on a laptop. It makes fake logs, stores them in
one SQLite file, finds 5 attacks with simple rules, and shows everything in a
dashboard. No Docker, no cloud, no paid services.

## Stack

Python 3.11+, SQLite (`data/siem.db`), FastAPI (JSON API), Streamlit (dashboard).
Install: `pip install -r requirements.txt` (4 packages: fastapi, uvicorn, streamlit, pytest).

## Quickstart

```bash
pip install -r requirements.txt
python demo.py
```

That runs: generator (208 auth, 225 web, 205 firewall, 201 endpoint lines),
ingest (839 events), detector (5 incidents), pytest (12 passed).

Then pick an interface:

```bash
uvicorn src.api:app --reload      # API at http://127.0.0.1:8000/docs
streamlit run src/dashboard.py    # dashboard at http://localhost:8501
```

## Manual pipeline

```bash
python -m src.generator --seed 42 --count 200
python -m src.ingest
python -m src.detector
pytest -q
```

Same seed gives the same files, so reruns are comparable. `--count` sets the
normal background events per source. Attack traces are always added on top.

## API

| Method | Route | Use |
| ------ | ----- | --- |
| GET | `/` | health check, links to docs |
| GET | `/events?search=&source=&severity=&limit=` | search raw, user, IP, host, type |
| GET | `/incidents?status=` | list, filter open, investigating, resolved |
| GET | `/incidents/{id}` | one incident |
| GET | `/incidents/{id}/timeline` | incident plus ordered events |
| POST | `/incidents` | manual incident, starts open |
| PATCH | `/incidents/{id}` | set status, assignee, notes |

Example: `GET /events?search=10.10.10.5` returns the 6 brute force logins.

## Dashboard

Filter rail on the left (search, source, severity, incident status). Events table
shows the newest 200 matches. Incident picker is sorted high severity first.
Pick one to see its timeline as log lines, then save workflow to move it from
open to investigating to resolved with an assignee and notes.

## Rules and thresholds

| Rule | Logic |
| ---- | ----- |
| brute_force | 5+ auth_failed from one IP in 5 min |
| lateral_movement | same user and IP on 2+ hosts in 10 min |
| data_exfiltration | 10 MB+ bytes_out from one IP in 10 min |
| privilege_escalation | one sudo or su success |
| web_scanning | 20+ 404s from one IP in 2 min |

Background traffic is pinned so each client IP sticks to one host. Only the
injected attack logs into 2 hosts, so the lateral rule fires once per run.

## Tests

```bash
pytest -q            # 12 tests
python -m pytest -q  # same, other spelling
```

`tests/test_parsers.py` covers all 4 log formats. `tests/test_detector.py`
covers all 5 rules with hand made events. `conftest.py` keeps plain `pytest`
working on Windows.

## Layout

- `demo.py` — full pipeline in one command
- `src/config.py` — paths for data, logs, DB file
- `src/generator.py` — fake logs with `--seed` and `--count`
- `src/parsers.py` — 4 formats into one event dict
- `src/ingest.py` — log files into SQLite
- `src/detector.py` — 5 rules into incidents
- `src/api.py` — FastAPI app
- `src/dashboard.py` — Streamlit app (reads the DB directly)
- `.streamlit/config.toml` — dashboard theme
- `tests/` — pytest files
- `data/` — logs and `siem.db`, created on run, not in git

## Notes

All logs are synthetic. Detector thresholds live at the top of each function in
`src/detector.py` and take arguments, so they are easy to retune. The dashboard
loads web fonts when online and falls back to system fonts offline. Mention the
fallback in the writeup so the two looks are expected.
