# CyberShield IDS (Network Intrusion Detection System)

CyberShield IDS is a real-time network intrusion detection system that captures packets, detects suspicious/malicious activity (signatures + anomaly detection), logs alerts, and visualizes them in a SOC-style web dashboard. It also supports Telegram notifications for alert management.

## Features
- Real-time packet capture (Scapy)
- Signature-based detection via YAML rules:
  - ICMP Flood
  - Port Scan
  - SYN Flood
  - DNS traffic volume (UDP/53)
- Anomaly detection (Isolation Forest) using window-based traffic statistics
- Alert logging:
  - `alerts.log`
  - `data/alerts.csv`
- Dashboard (Flask + Chart.js): tables + charts + filtering
- Optional Telegram alert notifications (creativity/alert management)

## Project Structure
- `ids.py` : IDS core (capture + detection + logging)
- `rules/attacks.yml` : signature rules (thresholds, windows, severity)
- `detection/anomaly.py` : ML anomaly detector
- `interface/app.py` : Flask dashboard backend
- `interface/templates/dashboard.html` : dashboard UI
- `data/alerts.csv` : alerts storage
- `data/flow_stats.csv` : traffic stats per window (for ML training)
- `alerts.log` : raw alerts log

## Requirements
- Python 3
- Linux recommended (VM lab)
- Root privileges for packet capture

Install dependencies:
```bash
pip install scapy flask pandas scikit-learn pyyaml requests python-dotenv
