"""Shared paths for the SIEM prototype. Keep all files under data/."""
from pathlib import Path

# Folder that holds this file's parent (project root).
BASE_DIR = Path(__file__).resolve().parent.parent

# Where generated logs and the SQLite file live.
DATA_DIR = BASE_DIR / "data"
LOG_DIR = DATA_DIR / "logs"

# Single SQLite file, no server needed.
DB_PATH = DATA_DIR / "siem.db"
