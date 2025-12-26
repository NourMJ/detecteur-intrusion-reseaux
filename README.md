# Network Intrusion Detection System (NIDS)

This project implements a **Network Intrusion Detection System** capable of monitoring
network traffic in real time, detecting suspicious or malicious activities, and
alerting administrators.

## Features
- ICMP Flood detection
- TCP Port Scan detection
- Suspicious activity vs real attack distinction
- Alert deduplication (cooldown)
- CSV & log storage
- Web dashboard (Flask)

## Technologies
- Python
- Scapy
- Pandas
- Flask
- VirtualBox (Kali + Ubuntu)

## Architecture
- `ids.py` : packet capture & detection engine
- `data/alerts.csv` : alerts storage
- `interface/` : web dashboard

## How to Run
```bash
sudo venv/bin/python3 ids.py

