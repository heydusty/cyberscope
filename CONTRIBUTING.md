# Contributing to CyberScope

Thanks for your interest in contributing! Here's how to get started.

## Setup

```bash
git clone https://github.com/YOUR_USERNAME/cyberscope.git
cd cyberscope
pip install -r requirements.txt
python data/generate_logs.py
python detect.py --file sample_logs/auth.log
```

## Running Tests

```bash
pip install pytest
python -m pytest tests/ -v
```

## Ideas for Contribution

- Add new log format parsers (Windows Event Log, AWS CloudTrail)
- Implement real-time streaming detection
- Add a web dashboard (Streamlit/Flask)
- MITRE ATT&CK mapping for detected anomalies
- Elasticsearch/Splunk integration
- Docker support
- More anomaly detection algorithms (LOF, DBSCAN, Autoencoders)
- Visualization of anomaly patterns over time

## Pull Request Process

1. Fork the repo and create your branch from `main`
2. Add tests for any new features
3. Ensure all tests pass
4. Update README if needed
5. Submit your PR with a clear description
