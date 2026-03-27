"""
CyberScope — Multi-Format Log Parser
Parses auth logs, web access logs, CSV, and JSON lines.

Author: Dusty (Akshat Singh Mehrotra)
GitHub: https://github.com/YOUR_USERNAME/cyberscope
License: MIT
© 2026 Dusty — Built by DUSTY | dusty@dustyhive.com
"""

import re
import csv
import json
import os
from datetime import datetime
from typing import List, Dict, Optional


# ── Auth/Syslog pattern ──────────────────────────────────
AUTH_PATTERN = re.compile(
    r"(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<hostname>\S+)\s+"
    r"(?P<service>\S+?)(?:\[(?P<pid>\d+)\])?:\s+"
    r"(?P<message>.*)"
)

# ── Apache/Nginx Combined Log Format ─────────────────────
WEB_PATTERN = re.compile(
    r"(?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+\S+\s+\S+\s+"
    r"\[(?P<timestamp>[^\]]+)\]\s+"
    r'"(?P<method>\w+)\s+(?P<path>\S+)\s+\S+"\s+'
    r"(?P<status>\d{3})\s+"
    r"(?P<size>\d+|-)"
)

# ── Auth message sub-patterns ─────────────────────────────
FAILED_LOGIN = re.compile(r"[Ff]ailed\s+password\s+for\s+(?:invalid\s+user\s+)?(?P<user>\S+)\s+from\s+(?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})")
SUCCESS_LOGIN = re.compile(r"[Aa]ccepted\s+(?:password|publickey)\s+for\s+(?P<user>\S+)\s+from\s+(?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})")
SESSION_OPEN = re.compile(r"session\s+opened\s+for\s+user\s+(?P<user>\S+)")
SESSION_CLOSE = re.compile(r"session\s+closed\s+for\s+user\s+(?P<user>\S+)")
SUDO_COMMAND = re.compile(r"(?P<user>\S+)\s+:\s+.*COMMAND=(?P<command>.*)")


def detect_format(filepath: str) -> str:
    """Auto-detect log file format."""
    ext = os.path.splitext(filepath)[1].lower()
    
    if ext == ".csv":
        return "csv"
    if ext == ".jsonl" or ext == ".json":
        return "jsonl"
    
    # Read first few lines to detect
    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
        lines = [f.readline() for _ in range(5)]
    
    for line in lines:
        if not line.strip():
            continue
        if AUTH_PATTERN.match(line):
            return "auth"
        if WEB_PATTERN.match(line):
            return "web"
        try:
            json.loads(line)
            return "jsonl"
        except (json.JSONDecodeError, ValueError):
            pass
    
    return "unknown"


def parse_auth_line(line: str, year: int = 2026) -> Optional[Dict]:
    """Parse a syslog/auth.log line."""
    match = AUTH_PATTERN.match(line.strip())
    if not match:
        return None
    
    entry = {
        "raw": line.strip(),
        "hostname": match.group("hostname"),
        "service": match.group("service"),
        "pid": match.group("pid"),
        "message": match.group("message"),
        "ip": None,
        "user": None,
        "event_type": "other",
        "status": "info",
    }
    
    # Parse timestamp
    ts_str = match.group("timestamp")
    try:
        dt = datetime.strptime(f"{year} {ts_str}", "%Y %b %d %H:%M:%S")
        entry["timestamp"] = dt
    except ValueError:
        entry["timestamp"] = datetime.now()
    
    msg = match.group("message")
    
    # Classify event
    failed = FAILED_LOGIN.search(msg)
    success = SUCCESS_LOGIN.search(msg)
    sudo = SUDO_COMMAND.search(msg)
    sess_open = SESSION_OPEN.search(msg)
    sess_close = SESSION_CLOSE.search(msg)
    
    if failed:
        entry["event_type"] = "failed_login"
        entry["status"] = "failure"
        entry["user"] = failed.group("user")
        entry["ip"] = failed.group("ip")
    elif success:
        entry["event_type"] = "success_login"
        entry["status"] = "success"
        entry["user"] = success.group("user")
        entry["ip"] = success.group("ip")
    elif sudo:
        entry["event_type"] = "sudo_command"
        entry["status"] = "info"
        entry["user"] = sudo.group("user")
        entry["command"] = sudo.group("command")
    elif sess_open:
        entry["event_type"] = "session_open"
        entry["user"] = sess_open.group("user")
    elif sess_close:
        entry["event_type"] = "session_close"
        entry["user"] = sess_close.group("user")
    
    # Extract IP if not already found
    if not entry["ip"]:
        ip_match = re.search(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", msg)
        if ip_match:
            entry["ip"] = ip_match.group(1)
    
    return entry


def parse_web_line(line: str) -> Optional[Dict]:
    """Parse an Apache/Nginx access log line."""
    match = WEB_PATTERN.match(line.strip())
    if not match:
        return None
    
    entry = {
        "raw": line.strip(),
        "ip": match.group("ip"),
        "method": match.group("method"),
        "path": match.group("path"),
        "http_status": int(match.group("status")),
        "size": int(match.group("size")) if match.group("size") != "-" else 0,
        "event_type": "web_request",
    }
    
    # Parse timestamp
    ts_str = match.group("timestamp")
    try:
        dt = datetime.strptime(ts_str, "%d/%b/%Y:%H:%M:%S %z")
        entry["timestamp"] = dt.replace(tzinfo=None)
    except ValueError:
        try:
            dt = datetime.strptime(ts_str, "%d/%b/%Y:%H:%M:%S")
            entry["timestamp"] = dt
        except ValueError:
            entry["timestamp"] = datetime.now()
    
    # Classify status
    if entry["http_status"] >= 400:
        entry["status"] = "failure"
    else:
        entry["status"] = "success"
    
    return entry


def parse_csv_file(filepath: str) -> List[Dict]:
    """Parse a CSV log file."""
    entries = []
    with open(filepath, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            entry = dict(row)
            entry["raw"] = str(row)
            
            # Try to parse timestamp from common column names
            for ts_col in ["timestamp", "time", "datetime", "date", "created_at"]:
                if ts_col in entry:
                    try:
                        entry["timestamp"] = datetime.fromisoformat(entry[ts_col])
                    except (ValueError, TypeError):
                        try:
                            entry["timestamp"] = datetime.strptime(
                                entry[ts_col], "%Y-%m-%d %H:%M:%S"
                            )
                        except (ValueError, TypeError):
                            entry["timestamp"] = datetime.now()
                    break
            else:
                entry["timestamp"] = datetime.now()
            
            # Normalize common fields
            entry.setdefault("ip", entry.get("source_ip", entry.get("src_ip", entry.get("ip_address", "0.0.0.0"))))
            entry.setdefault("event_type", entry.get("action", entry.get("type", "unknown")))
            entry.setdefault("status", entry.get("result", entry.get("outcome", "info")))
            
            entries.append(entry)
    
    return entries


def parse_jsonl_file(filepath: str) -> List[Dict]:
    """Parse a JSON Lines log file."""
    entries = []
    with open(filepath, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
                entry["raw"] = line
                
                # Parse timestamp
                for ts_key in ["timestamp", "time", "@timestamp", "datetime"]:
                    if ts_key in entry:
                        try:
                            entry["timestamp"] = datetime.fromisoformat(
                                str(entry[ts_key]).replace("Z", "+00:00")
                            ).replace(tzinfo=None)
                        except (ValueError, TypeError):
                            entry["timestamp"] = datetime.now()
                        break
                else:
                    entry["timestamp"] = datetime.now()
                
                entry.setdefault("ip", entry.get("source_ip", "0.0.0.0"))
                entry.setdefault("event_type", entry.get("action", "unknown"))
                entry.setdefault("status", entry.get("result", "info"))
                
                entries.append(entry)
            except json.JSONDecodeError:
                continue
    
    return entries


def parse_log_file(filepath: str) -> List[Dict]:
    """
    Parse a log file, auto-detecting format.
    Returns a list of normalized log entry dictionaries.
    """
    if not os.path.exists(filepath):
        raise FileNotFoundError(f"Log file not found: {filepath}")
    
    fmt = detect_format(filepath)
    
    if fmt == "csv":
        return parse_csv_file(filepath)
    
    if fmt == "jsonl":
        return parse_jsonl_file(filepath)
    
    # Line-by-line parsing for auth/web logs
    entries = []
    parse_func = parse_auth_line if fmt == "auth" else parse_web_line
    
    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            entry = parse_func(line)
            if entry:
                entries.append(entry)
    
    # Fallback: try both parsers
    if not entries:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                entry = parse_auth_line(line) or parse_web_line(line)
                if entry:
                    entries.append(entry)
    
    return entries


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        filepath = sys.argv[1]
        fmt = detect_format(filepath)
        print(f"Detected format: {fmt}")
        entries = parse_log_file(filepath)
        print(f"Parsed {len(entries)} entries")
        if entries:
            print(f"\nSample entry:")
            for k, v in entries[0].items():
                if k != "raw":
                    print(f"  {k}: {v}")
