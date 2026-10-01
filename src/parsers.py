"""Parse 4 log formats into one common event dict."""
import json
import re

# Auth: 2025-01-01T09:00:01Z web01 sshd[1000]: Failed password for alice from 1.2.3.4 port 51234 ssh2
AUTH_RE = re.compile(r"(\S+) (\S+) sshd\[\d+\]: (Failed|Accepted) password for (\S+) from (\S+) port")

# Web: 1.2.3.4 - bob [2025-01-01T09:00:01Z] "GET /index.html HTTP/1.1" 200 512
WEB_RE = re.compile(r'(\S+) - (\S+) \[(.*?)\] "(\S+) (\S+) .*?" (\d+) (\d+)')

# Firewall: 2025-01-01T09:00:01Z ALLOW 1.2.3.4 -> 5.6.7.8 bytes=1500
FW_RE = re.compile(r"(\S+) (ALLOW|DENY) (\S+) -> (\S+) bytes=(\d+)")

# Endpoint: 2025-01-01T09:00:01Z host=h user=alice proc=sudo result=success cmd="sudo cat /etc/shadow"
EP_RE = re.compile(r'(\S+) host=(\S+) user=(\S+) proc=(\S+) result=(\S+) cmd="(.*)"')


def parse_auth(line: str) -> dict | None:
    """Parse one auth.log line. Returns None if it does not match."""
    m = AUTH_RE.search(line)
    if not m:
        return None
    ts, host, result, user, ip = m.groups()
    ok = result == "Accepted"  # Accepted = success, Failed = fail.
    return {
        "timestamp": ts,
        "source": "auth",
        "src_ip": ip,
        "dst_ip": "",
        "user": user,
        "hostname": host,
        "event_type": "auth_success" if ok else "auth_failed",
        "severity": "low" if ok else "medium",
        "bytes_out": 0,
        "raw": line,
        "details": json.dumps({"result": result}),
    }


def parse_web(line: str) -> dict | None:
    """Parse one web.log line. Returns None if it does not match."""
    m = WEB_RE.search(line)
    if not m:
        return None
    ip, user, ts, method, path, status, size = m.groups()
    is_404 = status == "404"  # Many 404s = scanner.
    return {
        "timestamp": ts,
        "source": "web",
        "src_ip": ip,
        "dst_ip": "",
        "user": "" if user == "-" else user,
        "hostname": "web01",  # All web logs come from our web server.
        "event_type": "http_404" if is_404 else "http_access",
        "severity": "medium" if is_404 else "low",
        "bytes_out": int(size),
        "raw": line,
        "details": json.dumps({"method": method, "path": path, "status": int(status)}),
    }


def parse_firewall(line: str) -> dict | None:
    """Parse one firewall.log line. Returns None if it does not match."""
    m = FW_RE.search(line)
    if not m:
        return None
    ts, action, src, dst, nbytes = m.groups()
    denied = action == "DENY"  # Denied = someone tried a blocked connection.
    return {
        "timestamp": ts,
        "source": "firewall",
        "src_ip": src,
        "dst_ip": dst,
        "user": "",
        "hostname": "",
        "event_type": "fw_deny" if denied else "fw_allow",
        "severity": "medium" if denied else "low",
        "bytes_out": int(nbytes),
        "raw": line,
        "details": json.dumps({"action": action}),
    }


def parse_endpoint(line: str) -> dict | None:
    """Parse one endpoint.log line. Returns None if it does not match."""
    m = EP_RE.search(line)
    if not m:
        return None
    ts, host, user, proc, result, cmd = m.groups()
    is_admin = proc in ("sudo", "su")  # sudo/su = privilege change.
    is_success = result == "success"
    return {
        "timestamp": ts,
        "source": "endpoint",
        "src_ip": "",
        "dst_ip": "",
        "user": user,
        "hostname": host,
        "event_type": "priv_esc" if (is_admin and is_success) else "proc_start",
        "severity": "high" if (is_admin and is_success) else "low",
        "bytes_out": 0,
        "raw": line,
        "details": json.dumps({"proc": proc, "result": result, "cmd": cmd}),
    }
