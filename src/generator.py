"""Make fake logs for 4 sources. Rerun anytime with --seed."""
import argparse
import random
from datetime import datetime, timedelta, timezone

from src.config import LOG_DIR

# Fixed start so reruns with same seed give same files.
START = datetime(2025, 1, 1, 9, 0, 0, tzinfo=timezone.utc)

USERS = ["alice", "bob", "carol", "dave"]
INTERNAL_IPS = ["192.168.1.20", "192.168.1.21", "192.168.1.22"]
HOSTS = ["workstation01", "workstation02", "web01"]  # Used for endpoint logs only.

# Pin each client IP to one host so background logins don't look like lateral movement.
# Only the injected attack (same IP on 2 hosts) will trigger that rule.
IP_HOST = {
    "192.168.1.20": "workstation01",
    "192.168.1.21": "workstation02",
    "192.168.1.22": "web01",
}


def fmt(dt: datetime) -> str:
    """Format time as 2025-01-01T09:00:00Z."""
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def make_background(rnd: random.Random, start: datetime, count: int):
    """Make normal traffic. Split evenly over 4 sources."""
    auth, web, fw, ep = [], [], [], []
    t = start
    for i in range(count):
        t = t + timedelta(seconds=30)  # Keep order sorted.
        user = rnd.choice(USERS)
        ip = rnd.choice(INTERNAL_IPS)
        host = IP_HOST[ip]  # Background: each IP sticks to one host.
        ep_host = rnd.choice(HOSTS)  # Endpoint host stays random, no rule uses it.

        # Auth: mostly success, some fails.
        if rnd.random() < 0.2:
            auth.append(f"{fmt(t)} {host} sshd[1000]: Failed password for {user} from {ip} port 51234 ssh2")
        else:
            auth.append(f"{fmt(t)} {host} sshd[1000]: Accepted password for {user} from {ip} port 51234 ssh2")

        # Web: normal pages, status 200.
        path = rnd.choice(["/index.html", "/about", "/api/data"])
        web.append(f'{ip} - {user} [{fmt(t)}] "GET {path} HTTP/1.1" 200 {rnd.randint(500, 2000)}')

        # Firewall: mostly ALLOW with small bytes.
        fw.append(f"{fmt(t)} ALLOW {ip} -> 93.184.216.34 bytes={rnd.randint(500, 5000)}")

        # Endpoint: normal programs, no sudo.
        proc = rnd.choice(["chrome.exe", "explorer.exe", "notepad.exe"])
        ep.append(f"{fmt(t)} host={ep_host} user={user} proc={proc} result=success cmd=\"run {proc}\"")
    return auth, web, fw, ep, t


def add_attacks(auth, web, fw, ep, t):
    """Add 5 attack traces that later rules can find."""
    # 1. Brute force: 6 fails from one IP in 4 min.
    atk_ip = "10.10.10.5"
    for i in range(6):
        t = t + timedelta(seconds=40)
        auth.append(f"{fmt(t)} web01 sshd[1000]: Failed password for alice from {atk_ip} port 52222 ssh2")

    # 2. Lateral movement: same user logs into 2 hosts in 8 min.
    t = t + timedelta(minutes=1)
    auth.append(f"{fmt(t)} workstation01 sshd[1000]: Accepted password for alice from 192.168.1.20 port 51234 ssh2")
    t = t + timedelta(minutes=5)
    auth.append(f"{fmt(t)} workstation02 sshd[1000]: Accepted password for alice from 192.168.1.20 port 51234 ssh2")

    # 3. Exfil: 5 big uploads = 15 MB in ~8 min.
    for i in range(5):
        t = t + timedelta(seconds=100)
        fw.append(f"{fmt(t)} ALLOW 192.168.1.20 -> 203.0.113.99 bytes=3000000")

    # 4. Privilege escalation: one sudo success.
    t = t + timedelta(minutes=1)
    ep.append(f"{fmt(t)} host=workstation01 user=bob proc=sudo result=success cmd=\"sudo cat /etc/shadow\"")

    # 5. Web scan: 25 404s from one IP in ~80 sec.
    scan_ip = "10.10.10.6"
    for i in range(25):
        t = t + timedelta(seconds=3)
        web.append(f'{scan_ip} - - [{fmt(t)}] "GET /admin{i} HTTP/1.1" 404 200')
    return t


def main():
    """Parse flags, generate files, print where they went."""
    p = argparse.ArgumentParser(description="Generate synthetic SIEM logs.")
    p.add_argument("--seed", type=int, default=42, help="Random seed for reruns.")
    p.add_argument("--count", type=int, default=200, help="Normal events per source.")
    args = p.parse_args()

    rnd = random.Random(args.seed)
    auth, web, fw, ep, t = make_background(rnd, START, args.count)
    add_attacks(auth, web, fw, ep, t)

    LOG_DIR.mkdir(parents=True, exist_ok=True)
    (LOG_DIR / "auth.log").write_text("\n".join(auth) + "\n")
    (LOG_DIR / "web.log").write_text("\n".join(web) + "\n")
    (LOG_DIR / "firewall.log").write_text("\n".join(fw) + "\n")
    (LOG_DIR / "endpoint.log").write_text("\n".join(ep) + "\n")
    print(f"Wrote {len(auth)} auth, {len(web)} web, {len(fw)} fw, {len(ep)} endpoint lines to {LOG_DIR}")


if __name__ == "__main__":
    main()
