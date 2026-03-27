"""
CyberScope — Report Generator
Formats anomaly detection results for CLI and JSON output.

Author: Dusty (Akshat Singh Mehrotra)
GitHub: https://github.com/YOUR_USERNAME/cyberscope
License: MIT
© 2026 Dusty — Built by DUSTY | dusty@dustyhive.com
"""

import json
from typing import List, Dict
from datetime import datetime


SEVERITY_COLORS = {
    "CRITICAL": "\033[91m",  # Red
    "HIGH": "\033[93m",      # Yellow
    "MEDIUM": "\033[33m",    # Orange
    "LOW": "\033[36m",       # Cyan
    "NORMAL": "\033[92m",    # Green
}
RESET = "\033[0m"
BOLD = "\033[1m"


def print_banner():
    """Print CyberScope banner."""
    print(f"""
{BOLD}╔══════════════════════════════════════════════════════════╗
║  🔭 CyberScope — Log Anomaly Detection                  ║
║  Powered by Unsupervised Machine Learning                ║
║                                                          ║
║  Built by DUSTY (Akshat Singh Mehrotra)                  ║
║  github.com/YOUR_USERNAME/cyberscope                     ║
╚══════════════════════════════════════════════════════════╝{RESET}
    """)


def format_anomaly_description(anomaly: Dict) -> str:
    """Generate human-readable description of an anomaly."""
    event = anomaly.get("_event_type", "unknown")
    ip = anomaly.get("_ip", "unknown")
    descriptions = []
    
    if anomaly.get("failed_logins_5min", 0) > 10:
        descriptions.append(
            f"Brute force pattern — {anomaly['failed_logins_5min']} "
            f"failed logins from {ip} in 5 minutes"
        )
    
    if anomaly.get("is_off_hours") and anomaly.get("is_privileged_user"):
        descriptions.append(
            f"Privileged access at unusual hour (hour={anomaly.get('hour_of_day')})"
        )
    
    if anomaly.get("is_rare_ip") and event in ("success_login", "sudo_command"):
        descriptions.append(f"Rare/unknown IP {ip} performed {event}")
    
    if anomaly.get("ip_events_1min", 0) > 50:
        descriptions.append(
            f"High velocity — {anomaly['ip_events_1min']} events/min from {ip}"
        )
    
    if anomaly.get("has_admin_path"):
        descriptions.append("Admin/sensitive path access detected")
    
    if anomaly.get("is_server_error"):
        descriptions.append("Server error response (5xx)")
    
    if anomaly.get("event_type_entropy", 0) > 2.0:
        descriptions.append("Unusual diversity of actions from this source")
    
    if not descriptions:
        descriptions.append(f"Anomalous {event} event from {ip}")
    
    return " | ".join(descriptions)


def print_report(stats: Dict, anomalies: List[Dict], top_n: int = 15):
    """Print formatted CLI report."""
    print(f"""
{BOLD}╔══════════════════════════════════════════════════════════╗
║  🔭 CyberScope — Log Anomaly Detection Report           ║
╠══════════════════════════════════════════════════════════╣
║  Total log entries analyzed:  {stats['total_entries']:>6,}                    ║
║  Anomalies detected:         {stats['anomalies_detected']:>6,}                    ║
║  Anomaly rate:               {stats['anomaly_rate']:>6.2f}%                   ║
╚══════════════════════════════════════════════════════════╝{RESET}
    """)
    
    # Severity breakdown
    sev = stats.get("severity_breakdown", {})
    if any(s != "NORMAL" for s in sev):
        print(f"  {BOLD}Severity Breakdown:{RESET}")
        for level in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            count = sev.get(level, 0)
            if count > 0:
                color = SEVERITY_COLORS.get(level, "")
                print(f"    {color}● {level:10s}{RESET} {count}")
        print()
    
    # Top anomalies
    if anomalies:
        print(f"  {BOLD}🚨 Top Anomalies:{RESET}\n")
        for i, anomaly in enumerate(anomalies[:top_n]):
            severity = anomaly.get("severity", "UNKNOWN")
            color = SEVERITY_COLORS.get(severity, "")
            timestamp = anomaly.get("_timestamp", "unknown")
            score = anomaly.get("anomaly_score", 0)
            description = format_anomaly_description(anomaly)
            
            print(f"    {BOLD}#{i+1}{RESET}  [{color}{severity}{RESET}] {timestamp}")
            print(f"        → {description}")
            print(f"        → Anomaly score: {score:.4f}")
            print()
    else:
        print(f"  {SEVERITY_COLORS['NORMAL']}✅ No significant anomalies detected.{RESET}\n")
    
    # Top contributing features
    top_features = stats.get("top_contributing_features", [])
    if top_features:
        print(f"  {BOLD}🏆 Top Contributing Features:{RESET}")
        for fname, importance in top_features[:5]:
            bar = "█" * int(importance * 3)
            print(f"    {fname:30s} {bar} ({importance:.2f})")
        print()


def generate_json_report(stats: Dict, anomalies: List[Dict]) -> Dict:
    """Generate a JSON-serializable report."""
    clean_anomalies = []
    for a in anomalies:
        clean = {
            "timestamp": a.get("_timestamp"),
            "ip": a.get("_ip"),
            "event_type": a.get("_event_type"),
            "severity": a.get("severity"),
            "anomaly_score": a.get("anomaly_score"),
            "description": format_anomaly_description(a),
            "raw_log": a.get("_raw", ""),
        }
        clean_anomalies.append(clean)
    
    return {
        "tool": "CyberScope — AI Log Anomaly Detector",
        "author": "Dusty (Akshat Singh Mehrotra)",
        "github": "https://github.com/YOUR_USERNAME/cyberscope",
        "signature": "Built by DUSTY | dusty@dustyhive.com",
        "report_generated": datetime.now().isoformat(),
        "summary": stats,
        "anomalies": clean_anomalies,
    }


def save_json_report(report: Dict, output_path: str):
    """Save report as JSON file."""
    with open(output_path, "w") as f:
        json.dump(report, f, indent=2, default=str)
    print(f"  💾 Report saved to: {output_path}")
