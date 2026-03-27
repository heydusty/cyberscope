"""
CyberScope — Log Feature Extractor
Extracts 25+ features from parsed log entries for anomaly detection.

Author: Dusty (Akshat Singh Mehrotra)
GitHub: https://github.com/YOUR_USERNAME/cyberscope
License: MIT
© 2026 Dusty — Built by DUSTY | dusty@dustyhive.com
"""

import math
from datetime import datetime, timedelta
from collections import Counter, defaultdict
from typing import List, Dict


def calculate_entropy(values: list) -> float:
    """Calculate Shannon entropy of a list of values."""
    if not values:
        return 0.0
    freq = Counter(values)
    total = len(values)
    return -sum(
        (count / total) * math.log2(count / total)
        for count in freq.values()
    )


def is_internal_ip(ip: str) -> bool:
    """Check if IP is internal/private."""
    if not ip:
        return False
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    try:
        first = int(parts[0])
        second = int(parts[1])
    except ValueError:
        return False
    
    return (
        first == 10
        or (first == 172 and 16 <= second <= 31)
        or (first == 192 and second == 168)
        or first == 127
    )


def extract_features_from_entries(entries: List[Dict]) -> List[Dict]:
    """
    Extract features from a list of log entries using sliding window context.
    Returns a list of feature dictionaries, one per entry.
    """
    if not entries:
        return []
    
    # Sort by timestamp
    entries = sorted(entries, key=lambda e: e.get("timestamp", datetime.min))
    
    # Pre-compute global stats for context
    all_ips = [e.get("ip", "0.0.0.0") for e in entries if e.get("ip")]
    ip_counts = Counter(all_ips)
    all_users = [e.get("user", "unknown") for e in entries if e.get("user")]
    user_counts = Counter(all_users)
    
    total_entries = len(entries)
    
    # Build time-window lookups
    ip_events = defaultdict(list)  # ip -> list of timestamps
    user_events = defaultdict(list)  # user -> list of timestamps
    
    for e in entries:
        ip = e.get("ip", "0.0.0.0")
        user = e.get("user", "unknown")
        ts = e.get("timestamp", datetime.now())
        ip_events[ip].append(ts)
        user_events[user].append(ts)
    
    features_list = []
    
    for i, entry in enumerate(entries):
        features = {}
        ts = entry.get("timestamp", datetime.now())
        ip = entry.get("ip") or "0.0.0.0"
        user = entry.get("user") or "unknown"
        event_type = entry.get("event_type", "unknown")
        status = entry.get("status", "info")
        
        # ── Temporal Features ─────────────────────────
        features["hour_of_day"] = ts.hour
        features["day_of_week"] = ts.weekday()
        features["is_off_hours"] = int(ts.hour < 6 or ts.hour > 22)
        features["is_weekend"] = int(ts.weekday() >= 5)
        features["minute_of_hour"] = ts.minute
        
        # Time since last event
        if i > 0:
            prev_ts = entries[i - 1].get("timestamp", ts)
            delta = (ts - prev_ts).total_seconds()
            features["seconds_since_last"] = min(delta, 86400)  # cap at 1 day
        else:
            features["seconds_since_last"] = 0.0
        
        # Events in last N minutes (velocity)
        window_1min = sum(
            1 for t in ip_events.get(ip, [])
            if 0 <= (ts - t).total_seconds() <= 60
        )
        window_5min = sum(
            1 for t in ip_events.get(ip, [])
            if 0 <= (ts - t).total_seconds() <= 300
        )
        window_15min = sum(
            1 for t in ip_events.get(ip, [])
            if 0 <= (ts - t).total_seconds() <= 900
        )
        
        features["ip_events_1min"] = window_1min
        features["ip_events_5min"] = window_5min
        features["ip_events_15min"] = window_15min
        
        # ── Source Features ───────────────────────────
        features["is_internal_ip"] = int(is_internal_ip(ip))
        features["ip_frequency"] = ip_counts.get(ip, 0) / max(total_entries, 1)
        features["is_rare_ip"] = int(ip_counts.get(ip, 0) <= 2)
        
        # IP octets for pattern detection
        ip = ip or "0.0.0.0"
        octets = ip.split(".")
        if len(octets) == 4:
            try:
                features["ip_first_octet"] = int(octets[0])
                features["ip_class"] = (
                    0 if int(octets[0]) < 128
                    else 1 if int(octets[0]) < 192
                    else 2
                )
            except ValueError:
                features["ip_first_octet"] = 0
                features["ip_class"] = 0
        else:
            features["ip_first_octet"] = 0
            features["ip_class"] = 0
        
        # ── Authentication Features ───────────────────
        features["is_failed_login"] = int(event_type == "failed_login")
        features["is_success_login"] = int(event_type == "success_login")
        features["is_sudo"] = int(event_type == "sudo_command")
        features["is_session_event"] = int(event_type in ("session_open", "session_close"))
        
        # Failed logins from this IP in window
        failed_from_ip = sum(
            1 for j in range(max(0, i - 100), i + 1)
            if entries[j].get("ip") == ip
            and entries[j].get("event_type") == "failed_login"
            and 0 <= (ts - entries[j].get("timestamp", ts)).total_seconds() <= 300
        )
        features["failed_logins_5min"] = failed_from_ip
        
        # Is root/admin user
        features["is_privileged_user"] = int(
            user in ("root", "admin", "administrator", "sudo", "system")
        )
        
        # User frequency
        features["user_frequency"] = user_counts.get(user, 0) / max(total_entries, 1)
        features["is_rare_user"] = int(user_counts.get(user, 0) <= 2)
        
        # ── Web-specific Features ─────────────────────
        if event_type == "web_request":
            http_status = entry.get("http_status", 200)
            features["http_status_class"] = http_status // 100
            features["is_error_response"] = int(http_status >= 400)
            features["is_server_error"] = int(http_status >= 500)
            features["response_size"] = entry.get("size", 0)
            
            path = entry.get("path", "/")
            features["path_depth"] = len([p for p in path.split("/") if p])
            features["has_admin_path"] = int(
                any(seg in path.lower() for seg in [
                    "admin", "wp-admin", "phpmyadmin", "manager",
                    "console", "dashboard", ".env", "config"
                ])
            )
        else:
            features["http_status_class"] = 0
            features["is_error_response"] = 0
            features["is_server_error"] = 0
            features["response_size"] = 0
            features["path_depth"] = 0
            features["has_admin_path"] = 0
        
        # ── Behavioral Features ───────────────────────
        # Unique event types from this IP recently
        recent_events = [
            entries[j].get("event_type", "unknown")
            for j in range(max(0, i - 50), i + 1)
            if entries[j].get("ip") == ip
        ]
        features["event_type_entropy"] = round(calculate_entropy(recent_events), 4)
        features["unique_event_types"] = len(set(recent_events))
        
        # Store index for reference
        features["_index"] = i
        features["_timestamp"] = ts.isoformat()
        features["_ip"] = ip
        features["_event_type"] = event_type
        features["_raw"] = entry.get("raw", "")[:200]
        
        features_list.append(features)
    
    return features_list


def get_feature_names() -> List[str]:
    """Return sorted list of numeric feature names (excludes metadata)."""
    return [
        "day_of_week",
        "event_type_entropy",
        "failed_logins_5min",
        "has_admin_path",
        "hour_of_day",
        "http_status_class",
        "ip_class",
        "ip_events_1min",
        "ip_events_5min",
        "ip_events_15min",
        "ip_first_octet",
        "ip_frequency",
        "is_error_response",
        "is_failed_login",
        "is_internal_ip",
        "is_off_hours",
        "is_privileged_user",
        "is_rare_ip",
        "is_rare_user",
        "is_server_error",
        "is_session_event",
        "is_sudo",
        "is_success_login",
        "is_weekend",
        "minute_of_hour",
        "path_depth",
        "response_size",
        "seconds_since_last",
        "unique_event_types",
        "user_frequency",
    ]


def features_to_matrix(features_list: List[Dict]) -> list:
    """Convert feature dicts to a 2D list for model input."""
    names = get_feature_names()
    return [[f.get(name, 0) for name in names] for f in features_list]
