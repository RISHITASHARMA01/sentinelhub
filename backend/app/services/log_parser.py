"""
Log Parsers
-----------
This is the piece that turns messy real-world log lines into our clean
LogEvent schema. Start with two of the most common sources:

  1. Linux auth.log (SSH login attempts) - great for brute-force detection
  2. Nginx/Apache combined log format - great for web attack detection

Each parser function takes one raw line and returns a dict matching the
LogEvent fields, or None if the line doesn't match (so the caller can skip
or log it as "unparsed").
"""

import re
from datetime import datetime
from typing import Optional, Dict, Any

# --- SSH / auth.log parsing -------------------------------------------------

# Example line:
# Jul  5 10:23:41 myserver sshd[1234]: Failed password for invalid user admin from 203.0.113.5 port 51514 ssh2
SSH_FAILED_RE = re.compile(
    r"(?P<month>\w{3})\s+(?P<day>\d+)\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+sshd\[\d+\]:\s+Failed password for "
    r"(invalid user )?(?P<user>\S+) from (?P<src_ip>[\d\.]+) port \d+"
)

SSH_ACCEPTED_RE = re.compile(
    r"(?P<month>\w{3})\s+(?P<day>\d+)\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+sshd\[\d+\]:\s+Accepted password for "
    r"(?P<user>\S+) from (?P<src_ip>[\d\.]+) port \d+"
)


def _parse_syslog_timestamp(month: str, day: str, time_str: str) -> datetime:
    """Syslog timestamps don't include a year, so we assume current year."""
    year = datetime.utcnow().year
    dt_str = f"{year} {month} {day} {time_str}"
    return datetime.strptime(dt_str, "%Y %b %d %H:%M:%S")


def parse_ssh_log_line(line: str) -> Optional[Dict[str, Any]]:
    match = SSH_FAILED_RE.search(line)
    if match:
        g = match.groupdict()
        return {
            "source": "system",
            "source_host": g["host"],
            "src_ip": g["src_ip"],
            "username": g["user"],
            "event_type": "auth_failure",
            "raw_message": line.strip(),
            "timestamp": _parse_syslog_timestamp(g["month"], g["day"], g["time"]),
            "parsed_fields": {"service": "sshd"},
        }

    match = SSH_ACCEPTED_RE.search(line)
    if match:
        g = match.groupdict()
        return {
            "source": "system",
            "source_host": g["host"],
            "src_ip": g["src_ip"],
            "username": g["user"],
            "event_type": "auth_success",
            "raw_message": line.strip(),
            "timestamp": _parse_syslog_timestamp(g["month"], g["day"], g["time"]),
            "parsed_fields": {"service": "sshd"},
        }

    return None


# --- Nginx / Apache combined log format --------------------------------------

# Example line:
# 203.0.113.5 - - [05/Jul/2026:10:23:41 +0000] "GET /wp-login.php HTTP/1.1" 404 162 "-" "Mozilla/5.0"
WEB_LOG_RE = re.compile(
    r'(?P<src_ip>[\d\.]+)\s+\S+\s+\S+\s+\[(?P<timestamp>[^\]]+)\]\s+'
    r'"(?P<method>[A-Z]+)\s+(?P<path>\S+)\s+\S+"\s+'
    r'(?P<status>\d{3})\s+(?P<size>\S+)'
)


def parse_web_log_line(line: str, source_host: str = "webserver") -> Optional[Dict[str, Any]]:
    match = WEB_LOG_RE.search(line)
    if not match:
        return None

    g = match.groupdict()
    try:
        ts = datetime.strptime(g["timestamp"].split()[0], "%d/%b/%Y:%H:%M:%S")
    except ValueError:
        ts = datetime.utcnow()

    return {
        "source": "web_server",
        "source_host": source_host,
        "src_ip": g["src_ip"],
        "username": None,
        "event_type": "http_request",
        "raw_message": line.strip(),
        "timestamp": ts,
        "parsed_fields": {
            "method": g["method"],
            "path": g["path"],
            "status": int(g["status"]),
        },
    }


# --- Dispatcher --------------------------------------------------------------

def parse_log_line(line: str, source_hint: str = "auto") -> Optional[Dict[str, Any]]:
    """
    Try parsers in order. In production you'd pick the parser based on
    which log file/stream the line came from rather than guessing, but
    this auto-detection is handy for testing with mixed sample data.
    """
    if source_hint in ("auto", "system"):
        result = parse_ssh_log_line(line)
        if result:
            return result

    if source_hint in ("auto", "web_server"):
        result = parse_web_log_line(line)
        if result:
            return result

    return None
