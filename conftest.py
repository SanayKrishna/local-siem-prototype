"""Make src/ importable when running plain `pytest -q`."""
import sys
from pathlib import Path

# Add project root to path so `from src.database import ...` works.
sys.path.insert(0, str(Path(__file__).resolve().parent))
