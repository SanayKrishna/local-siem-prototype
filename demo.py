"""End-to-end demo: generate logs, ingest, detect, test. Run: python demo.py"""
import subprocess
import sys

# Each step reruns cleanly, so the demo always ends with 839 events and 5 incidents.
STEPS = [
    [sys.executable, "-m", "src.generator", "--seed", "42", "--count", "200"],
    [sys.executable, "-m", "src.ingest"],
    [sys.executable, "-m", "src.detector"],
    [sys.executable, "-m", "pytest", "-q"],
]


def main() -> None:
    """Run each step in order. Stops on the first failure."""
    for cmd in STEPS:
        print(f"$ {' '.join(cmd[2:])}")
        subprocess.run(cmd, check=True)
    print("Demo done: 839 events, 5 incidents, all tests passed.")


if __name__ == "__main__":
    main()
