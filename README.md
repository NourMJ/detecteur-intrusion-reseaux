🛡️ CYBERSHIELD IDS
Network Intrusion Detection System (NIDS)
📌 Project Overview

CyberShield IDS is a real-time Network Intrusion Detection System (NIDS) designed to monitor network traffic, detect suspicious or malicious activities, and alert administrators through multiple channels.

The system combines:

Signature-based detection (rule-based attacks)

Anomaly-based detection (machine learning)

Real-time alerting & visualization

It is developed entirely in Python, using packet-level inspection and a modern web-based dashboard.

🎯 Learning Objectives

This project aims to:

Understand network protocols (IP, ICMP, TCP, UDP) and common attack patterns

Capture and analyze live network traffic in real time

Implement signature-based intrusion detection using configurable rules

Apply machine learning (Isolation Forest) for anomaly detection

Build an alert management system with logs, dashboard, and notifications

Simulate and validate attacks in a controlled lab environment

🧱 System Architecture
Attacker VM (Kali Linux)
        |
        |  Network Traffic (ICMP / TCP / UDP)
        v
Victim VM (CyberShield IDS)
 ├── Packet Capture (Scapy)
 ├── Signature Detection (YAML Rules)
 ├── Anomaly Detection (Isolation Forest)
 ├── Logging (CSV + LOG)
 ├── Telegram Alerting
 └── Web Dashboard (Flask + Chart.js)

🗂️ Project Structure
Detecteur_intrusion_reseaux/
│
├── ids.py                     # Main IDS engine
├── alerts.log                 # Text log of alerts
├── capture.pcap               # Sample traffic capture
│
├── rules/
│   └── attacks.yml            # Signature-based detection rules
│
├── detection/
│   └── anomaly.py             # Anomaly detection (Isolation Forest)
│
├── interface/
│   ├── app.py                 # Flask dashboard backend
│   ├── telegram_notifier.py   # Telegram alert sender
│   └── templates/
│       └── dashboard.html     # Web dashboard (SOC-style UI)
│
├── data/
│   ├── alerts.csv             # Structured alert storage
│   └── flow_stats.csv         # Window-based traffic statistics
│
├── venv/                      # Python virtual environment
└── README.md                  # Project documentation

⚙️ Technologies & Tools

Python 3

Scapy – packet capture & inspection

PyYAML – rule configuration

Pandas – data processing

Scikit-learn – Isolation Forest (anomaly detection)

Flask – web dashboard backend

Chart.js – data visualization

Telegram Bot API – real-time alert notifications

VirtualBox / VMware – lab environment (2 VMs)

🚨 Detected Attacks
Signature-Based Detection

Configured in rules/attacks.yml:

ICMP Flood (DoS)

TCP Port Scan

TCP SYN Flood

DNS Amplification (UDP/53 volume)

Each rule defines:

Protocol

Threshold

Time window

Severity

Confidence level

Anomaly-Based Detection

Uses Isolation Forest

Learns normal traffic behavior from windowed statistics

Detects abnormal traffic spikes and unknown attack patterns

📊 Dashboard Features

Real-time alert table

Severity filtering (HIGH / MEDIUM / LOW)

Attack type distribution chart

Severity breakdown chart

Auto-refresh every 30 seconds

SOC-style UI

Accessible at:

http://<IDS_VM_IP>:5000

📲 Telegram Alert Management (Creativity Feature)

High and medium severity alerts are automatically sent to Telegram, allowing:

Instant notification

Remote monitoring

Alert escalation

Security best practices applied:

Tokens stored in .env

No secrets hardcoded

Anti-spam cooldown mechanism

🧪 Testing & Attack Simulation

All tests are performed in a controlled lab environment.

ICMP Flood
sudo ping -f <IDS_IP>

Port Scan
nmap -sS <IDS_IP> -p 1-200

SYN Flood
sudo hping3 -S -p 80 --flood <IDS_IP>

UDP / DNS Traffic
nping --udp -p 53 --rate 50 <IDS_IP>


Each attack produces:

Console alert

CSV + log entry

Dashboard update

Telegram notification (if enabled)

📁 Logs & Data

alerts.log → Human-readable log

data/alerts.csv → Structured alerts (dashboard)

data/flow_stats.csv → Traffic statistics (ML training)

🔒 Limitations

Possible false positives under heavy legitimate traffic

IDS only (no automatic traffic blocking)

Single-interface monitoring

Basic DNS amplification heuristic (lab-oriented)

🚀 Future Improvements

Distributed IDS architecture

IPS (automatic mitigation)

Deep learning models

GeoIP-based attack mapping

Role-based dashboard access

Alert acknowledgment workflow (ACK / RESOLVE)

🎓 Conclusion

CyberShield IDS demonstrates how real-time packet analysis, rule-based detection, and machine learning can be combined to build an effective intrusion detection system.
The project reflects real-world SOC practices while remaining lightweight and educational.

👨‍💻 Author

CyberShield IDS
Academic project – Network Security
2024 / 2025
