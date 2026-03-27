#!/usr/bin/env python3
"""
CyberScope — CLI Log Anomaly Detection Tool

Author: Dusty (Akshat Singh Mehrotra)
GitHub: https://github.com/YOUR_USERNAME/cyberscope
License: MIT
© 2026 Dusty — Built by DUSTY | dusty@dustyhive.com

Usage:
    python detect.py --file <logfile>                    # Scan a log file
    python detect.py --file <logfile> --threshold 0.03   # Custom sensitivity
    python detect.py --file <logfile> --json -o report   # Export JSON report
    python detect.py --interactive                       # Interactive mode
    python detect.py --generate                          # Generate sample logs
"""

import sys
import os
import argparse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from src.parser import parse_log_file, detect_format
from src.detector import AnomalyDetector
from src.reporter import (
    print_banner,
    print_report,
    generate_json_report,
    save_json_report,
)


def scan_file(filepath, threshold=0.05, top_n=15):
    """Scan a log file for anomalies."""
    print_banner()
    
    # Detect format
    fmt = detect_format(filepath)
    print(f"  📂 File: {filepath}")
    print(f"  📋 Detected format: {fmt}")
    
    # Parse logs
    print(f"  📥 Parsing logs...")
    entries = parse_log_file(filepath)
    print(f"  ✅ Parsed {len(entries)} log entries")
    
    if len(entries) < 10:
        print("  ❌ Not enough log entries (need at least 10)")
        return None, None, None
    
    # Run detection
    print(f"  🧠 Running anomaly detection (threshold={threshold})...")
    detector = AnomalyDetector(contamination=threshold)
    results = detector.fit_predict(entries)
    
    # Get results
    anomalies = detector.get_anomalies(results, min_severity="LOW")
    stats = detector.get_stats(results)
    
    # Print report
    print_report(stats, anomalies, top_n=top_n)
    
    return detector, results, stats


def interactive_mode():
    """Interactive log scanning mode."""
    print_banner()
    print("  Type a log file path to scan, or 'quit' to exit.\n")
    
    while True:
        try:
            filepath = input("  📁 Log file > ").strip()
        except (KeyboardInterrupt, EOFError):
            print("\n\n  👋 Goodbye!")
            break
        
        if filepath.lower() in ("quit", "exit", "q"):
            print("\n  👋 Goodbye!")
            break
        
        if not filepath:
            continue
        
        if not os.path.exists(filepath):
            print(f"  ❌ File not found: {filepath}\n")
            continue
        
        try:
            scan_file(filepath)
        except Exception as e:
            print(f"  ❌ Error: {e}\n")
        
        print()


def main():
    parser = argparse.ArgumentParser(
        description="🔭 CyberScope — AI Log Anomaly Detector | Built by DUSTY (Akshat Singh Mehrotra)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="© 2026 Dusty | dusty@dustyhive.com | github.com/YOUR_USERNAME/cyberscope",
    )
    parser.add_argument("--file", "-f", metavar="PATH", help="Log file to scan")
    parser.add_argument(
        "--threshold", "-t", type=float, default=0.05,
        help="Anomaly sensitivity (0.01=strict, 0.1=lenient, default=0.05)"
    )
    parser.add_argument("--json", action="store_true", help="Export report as JSON")
    parser.add_argument("--output", "-o", metavar="PATH", help="Output path for JSON report")
    parser.add_argument("--top", type=int, default=15, help="Number of top anomalies to show")
    parser.add_argument("--interactive", "-i", action="store_true", help="Interactive mode")
    parser.add_argument("--generate", "-g", action="store_true", help="Generate sample logs")
    parser.add_argument("--credits", action="store_true", help="Show credits")
    
    args = parser.parse_args()
    
    # Credits easter egg
    if args.credits:
        print("""
    ╔═══════════════════════════════════════════════════════╗
    ║                                                       ║
    ║   🔭  CyberScope — AI Log Anomaly Detector            ║
    ║                                                       ║
    ║   Designed & Developed by:                            ║
    ║   DUSTY (Akshat Singh Mehrotra)                       ║
    ║                                                       ║
    ║   📧 dusty@dustyhive.com                              ║
    ║   🌐 github.com/YOUR_USERNAME                         ║
    ║   🏢 DUSTYHIVE LLP                                    ║
    ║                                                       ║
    ║   If you're using this, give credit where it's due.   ║
    ║   Star the repo ⭐ — it means a lot.                  ║
    ║                                                       ║
    ╚═══════════════════════════════════════════════════════╝
        """)
        return
    
    # Generate sample logs
    if args.generate:
        from data.generate_logs import generate_logs, generate_csv_logs
        generate_logs()
        generate_csv_logs()
        return
    
    # Interactive mode
    if args.interactive:
        interactive_mode()
        return
    
    # File scan mode
    if args.file:
        if not os.path.exists(args.file):
            print(f"❌ File not found: {args.file}")
            sys.exit(1)
        
        detector, results, stats = scan_file(
            args.file,
            threshold=args.threshold,
            top_n=args.top,
        )
        
        if results and args.json:
            anomalies = detector.get_anomalies(results)
            report = generate_json_report(stats, anomalies)
            
            output_path = args.output or "cyberscope_report.json"
            if not output_path.endswith(".json"):
                output_path += ".json"
            
            save_json_report(report, output_path)
        
        return
    
    # No args
    parser.print_help()


if __name__ == "__main__":
    main()
