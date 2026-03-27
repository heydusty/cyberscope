"""
CyberScope — Unit Tests

Author: Dusty (Akshat Singh Mehrotra)
GitHub: https://github.com/YOUR_USERNAME/cyberscope
© 2026 Dusty — Built by DUSTY | dusty@dustyhive.com
"""

import sys
import os
import unittest
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.parser import parse_auth_line, parse_web_line, detect_format
from src.feature_extractor import (
    extract_features_from_entries,
    features_to_matrix,
    get_feature_names,
    calculate_entropy,
    is_internal_ip,
)
from src.detector import AnomalyDetector


class TestParser(unittest.TestCase):
    
    def test_parse_failed_login(self):
        line = "Mar 15 03:14:22 server01 sshd[1234]: Failed password for root from 192.168.1.105 port 22 ssh2"
        entry = parse_auth_line(line)
        self.assertIsNotNone(entry)
        self.assertEqual(entry["event_type"], "failed_login")
        self.assertEqual(entry["user"], "root")
        self.assertEqual(entry["ip"], "192.168.1.105")
    
    def test_parse_success_login(self):
        line = "Mar 15 10:00:00 server01 sshd[5678]: Accepted password for alice from 10.0.0.5 port 40000 ssh2"
        entry = parse_auth_line(line)
        self.assertIsNotNone(entry)
        self.assertEqual(entry["event_type"], "success_login")
        self.assertEqual(entry["user"], "alice")
    
    def test_parse_sudo(self):
        line = "Mar 15 12:00:00 server01 sudo[9999]: bob : TTY=pts/0 ; PWD=/home/bob ; USER=root ; COMMAND=/bin/ls"
        entry = parse_auth_line(line)
        self.assertIsNotNone(entry)
        self.assertEqual(entry["event_type"], "sudo_command")
    
    def test_parse_session(self):
        line = "Mar 15 08:00:00 server01 systemd-logind[100]: session opened for user charlie"
        entry = parse_auth_line(line)
        self.assertIsNotNone(entry)
        self.assertEqual(entry["event_type"], "session_open")
    
    def test_parse_web_log(self):
        line = '192.168.1.1 - - [15/Mar/2026:10:00:00] "GET /admin HTTP/1.1" 200 1234'
        entry = parse_web_line(line)
        self.assertIsNotNone(entry)
        self.assertEqual(entry["ip"], "192.168.1.1")
        self.assertEqual(entry["method"], "GET")
        self.assertEqual(entry["path"], "/admin")
        self.assertEqual(entry["http_status"], 200)
    
    def test_parse_invalid_line(self):
        entry = parse_auth_line("this is not a log line")
        self.assertIsNone(entry)
    
    def test_parse_web_invalid(self):
        entry = parse_web_line("random garbage")
        self.assertIsNone(entry)


class TestFeatureExtractor(unittest.TestCase):
    
    def setUp(self):
        self.sample_entries = [
            {
                "timestamp": datetime(2026, 3, 15, 10, i, 0),
                "ip": "192.168.1.10",
                "user": "alice",
                "event_type": "success_login",
                "status": "success",
                "raw": f"sample log line {i}",
            }
            for i in range(20)
        ]
        # Add some anomalous entries
        self.sample_entries.extend([
            {
                "timestamp": datetime(2026, 3, 15, 3, 0, 0),
                "ip": "45.33.32.156",
                "user": "root",
                "event_type": "failed_login",
                "status": "failure",
                "raw": "anomalous entry",
            }
            for _ in range(5)
        ])
    
    def test_extract_features(self):
        features = extract_features_from_entries(self.sample_entries)
        self.assertEqual(len(features), len(self.sample_entries))
    
    def test_feature_has_required_keys(self):
        features = extract_features_from_entries(self.sample_entries)
        required = ["hour_of_day", "day_of_week", "is_off_hours", "ip_events_1min"]
        for key in required:
            self.assertIn(key, features[0])
    
    def test_off_hours_detection(self):
        features = extract_features_from_entries(self.sample_entries)
        # The 3 AM entries should be flagged
        off_hours = [f for f in features if f["hour_of_day"] == 3]
        for f in off_hours:
            self.assertEqual(f["is_off_hours"], 1)
    
    def test_features_to_matrix(self):
        features = extract_features_from_entries(self.sample_entries)
        matrix = features_to_matrix(features)
        names = get_feature_names()
        self.assertEqual(len(matrix[0]), len(names))
    
    def test_entropy_calculation(self):
        self.assertEqual(calculate_entropy([]), 0.0)
        self.assertGreater(calculate_entropy(["a", "b", "c"]), 0)
        low = calculate_entropy(["a", "a", "a", "a"])
        high = calculate_entropy(["a", "b", "c", "d"])
        self.assertLess(low, high)
    
    def test_internal_ip_check(self):
        self.assertTrue(is_internal_ip("192.168.1.1"))
        self.assertTrue(is_internal_ip("10.0.0.1"))
        self.assertTrue(is_internal_ip("172.16.0.1"))
        self.assertFalse(is_internal_ip("8.8.8.8"))
        self.assertFalse(is_internal_ip("45.33.32.156"))
        self.assertFalse(is_internal_ip(""))


class TestDetector(unittest.TestCase):
    
    def setUp(self):
        # Create entries with clear anomalies
        self.entries = []
        
        # Normal entries (business hours, internal IPs)
        for i in range(200):
            self.entries.append({
                "timestamp": datetime(2026, 3, 15, 9 + (i % 9), i % 60, 0),
                "ip": f"192.168.1.{10 + (i % 5)}",
                "user": ["alice", "bob", "charlie"][i % 3],
                "event_type": "success_login",
                "status": "success",
                "raw": f"normal entry {i}",
            })
        
        # Anomalous entries (3 AM, external IPs, failed logins)
        for i in range(15):
            self.entries.append({
                "timestamp": datetime(2026, 3, 15, 3, i, 0),
                "ip": "45.33.32.156",
                "user": "root",
                "event_type": "failed_login",
                "status": "failure",
                "raw": f"anomaly entry {i}",
            })
    
    def test_detector_runs(self):
        detector = AnomalyDetector(contamination=0.05)
        results = detector.fit_predict(self.entries)
        self.assertEqual(len(results), len(self.entries))
    
    def test_anomalies_detected(self):
        detector = AnomalyDetector(contamination=0.1)
        results = detector.fit_predict(self.entries)
        anomalies = detector.get_anomalies(results)
        self.assertGreater(len(anomalies), 0)
    
    def test_stats_generated(self):
        detector = AnomalyDetector(contamination=0.05)
        results = detector.fit_predict(self.entries)
        stats = detector.get_stats(results)
        self.assertIn("total_entries", stats)
        self.assertIn("anomalies_detected", stats)
        self.assertIn("anomaly_rate", stats)
    
    def test_severity_classification(self):
        detector = AnomalyDetector()
        self.assertEqual(detector._classify_severity(-0.5), "CRITICAL")
        self.assertEqual(detector._classify_severity(-0.3), "HIGH")
        self.assertEqual(detector._classify_severity(-0.15), "MEDIUM")
        self.assertEqual(detector._classify_severity(-0.05), "LOW")
        self.assertEqual(detector._classify_severity(0.1), "NORMAL")
    
    def test_min_entries_check(self):
        detector = AnomalyDetector()
        with self.assertRaises(ValueError):
            detector.fit_predict([{"timestamp": datetime.now()}] * 5)


class TestEdgeCases(unittest.TestCase):
    
    def test_empty_entries(self):
        features = extract_features_from_entries([])
        self.assertEqual(len(features), 0)
    
    def test_feature_names_stable(self):
        names1 = get_feature_names()
        names2 = get_feature_names()
        self.assertEqual(names1, names2)
    
    def test_single_ip_entries(self):
        entries = [
            {
                "timestamp": datetime(2026, 3, 15, 10, i, 0),
                "ip": "192.168.1.10",
                "user": "alice",
                "event_type": "success_login",
                "status": "success",
                "raw": f"entry {i}",
            }
            for i in range(50)
        ]
        features = extract_features_from_entries(entries)
        self.assertEqual(len(features), 50)


if __name__ == "__main__":
    unittest.main(verbosity=2)
