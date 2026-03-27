# 🔭 CyberScope — AI Log Anomaly Detector

![Python](https://img.shields.io/badge/Python-3.8%2B-blue?logo=python)
![ML](https://img.shields.io/badge/ML-Scikit--Learn-orange?logo=scikit-learn)
![License](https://img.shields.io/badge/License-MIT-green)
![Stars](https://img.shields.io/github/stars/YOUR_USERNAME/cyberscope?style=social)
![Forks](https://img.shields.io/github/forks/YOUR_USERNAME/cyberscope?style=social)
![Issues](https://img.shields.io/github/issues/YOUR_USERNAME/cyberscope)

> 🧠 An unsupervised machine learning tool that detects anomalies in server/application logs using Isolation Forest — **no labeled data required, no API keys, fully offline.**

<p align="center">
  <img src="https://img.shields.io/badge/Detection-Unsupervised%20ML-purple?style=for-the-badge" />
  <img src="https://img.shields.io/badge/Features-25%2B-blue?style=for-the-badge" />
  <img src="https://img.shields.io/badge/Zero-API%20Keys-red?style=for-the-badge" />
</p>

---

## 📸 Demo

```
$ python detect.py --file sample_logs/auth.log

╔══════════════════════════════════════════════════════════╗
║  🔭 CyberScope — Log Anomaly Detection Report          ║
╠══════════════════════════════════════════════════════════╣
║  Total log entries analyzed:  5,000                     ║
║  Anomalies detected:         23                         ║
║  Anomaly rate:               0.46%                      ║
╚══════════════════════════════════════════════════════════╝

🚨 Top Anomalies:

  #1  [CRITICAL] 2026-03-15 03:14:22 — Brute force pattern
      → 847 failed logins from 192.168.1.105 in 2 minutes
      → Anomaly score: -0.89

  #2  [HIGH] 2026-03-15 04:02:11 — Privilege escalation
      → Root access from unknown IP 10.0.0.99 at unusual hour
      → Anomaly score: -0.76

  #3  [MEDIUM] 2026-03-15 12:33:45 — Data exfiltration signal
      → 4.2 GB outbound transfer to external IP
      → Anomaly score: -0.61
```

---

## 🧠 How It Works

CyberScope uses **unsupervised anomaly detection** — it learns what "normal" looks like from your logs, then flags anything unusual. No labeled training data needed.

### Pipeline

```
Raw Logs → Parser → Feature Extraction (25+ features) → Isolation Forest → Anomaly Scores → Alert Report
```

### Feature Categories

| Category | Features |
|----------|----------|
| **Temporal** | Hour of day, day of week, time since last event, events per minute, off-hours flag |
| **Source** | IP entropy, unique IPs per window, geo-distance anomaly, internal vs external |
| **Auth** | Failed login count, success/fail ratio, privilege level changes, new user flag |
| **Payload** | Request size, response size, error code frequency, path depth, param count |
| **Behavioral** | Session duration, action sequence entropy, request velocity, resource access pattern |

### Why Isolation Forest?

Unlike other algorithms, Isolation Forest doesn't need to learn "normal" first — it directly isolates anomalies by randomly partitioning data. Anomalies are **easier to isolate**, so they get shorter path lengths in the trees.

---

## 🚀 Quick Start

### 1. Clone & Install

```bash
git clone https://github.com/YOUR_USERNAME/cyberscope.git
cd cyberscope
pip install -r requirements.txt
```

### 2. Generate Sample Logs (for testing)

```bash
python data/generate_logs.py
```

### 3. Run Detection

```bash
# Scan a log file
python detect.py --file sample_logs/auth.log

# Scan with custom sensitivity (lower = more sensitive)
python detect.py --file sample_logs/auth.log --threshold 0.05

# Export report as JSON
python detect.py --file sample_logs/auth.log --json --output report.json

# Scan a CSV log
python detect.py --file sample_logs/web_access.csv
```

### 4. Interactive Mode

```bash
python detect.py --interactive
```

### 5. Run Tests

```bash
python -m pytest tests/ -v
```

---

## 📁 Project Structure

```
cyberscope/
├── data/
│   └── generate_logs.py       # Generates realistic synthetic logs
├── sample_logs/
│   └── .gitkeep               # Sample logs generated here
├── models/
│   └── .gitkeep               # Trained models saved here
├── src/
│   ├── parser.py              # Multi-format log parser
│   ├── feature_extractor.py   # Extracts 25+ features per log entry
│   ├── detector.py            # Isolation Forest anomaly detector
│   └── reporter.py            # Formats detection reports
├── tests/
│   └── test_cyberscope.py     # Unit tests
├── detect.py                  # CLI detection tool
├── requirements.txt
├── LICENSE
└── README.md
```

---

## 📊 Supported Log Formats

| Format | Example |
|--------|---------|
| **Auth/Syslog** | `Mar 15 03:14:22 server sshd[1234]: Failed password for root from 192.168.1.105` |
| **Apache/Nginx** | `192.168.1.1 - - [15/Mar/2026:10:00:00] "GET /admin HTTP/1.1" 200 1234` |
| **CSV** | Structured CSV logs with timestamp, IP, action, status columns |
| **JSON Lines** | One JSON object per line (common in modern logging) |

---

## 🎯 Use Cases

- **SOC Analysts** — Detect threats in server logs without writing custom rules
- **DevOps** — Find unusual patterns in application logs
- **Bug Bounty** — Analyze access logs for suspicious reconnaissance
- **Incident Response** — Quickly triage large log files during an incident
- **Students/Research** — Learn unsupervised anomaly detection with real-world application

---

## 🤝 Contributing

Contributions are welcome! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

Ideas:
- Add more log format parsers
- Real-time streaming mode
- Web dashboard (Streamlit/Flask)
- MITRE ATT&CK mapping for detected anomalies
- Elasticsearch integration

---

## 📜 License

MIT License — see [LICENSE](LICENSE) for details.

---

## 👨‍💻 Author

**Dusty (Akshat Singh Mehrotra)**

- GitHub: [@YOUR_USERNAME](https://github.com/YOUR_USERNAME)
- Email: dusty@dustyhive.com
- LinkedIn: [Your LinkedIn](https://linkedin.com/in/YOUR_LINKEDIN)

> *"Built by DUSTY — if you found this useful, drop a ⭐"*

---

## 🔗 Related Projects

- [PhishGuard AI](https://github.com/YOUR_USERNAME/phishguard-ai) — ML-powered phishing URL detector

---

<p align="center">Built with ❤️ by <b>DUSTY</b> (Akshat Singh Mehrotra) for the cybersecurity community</p>
