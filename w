from scapy.all import sniff, IP, ICMP, TCP
from collections import defaultdict
from datetime import datetime
import csv
import os

# ---------------- CONFIG ----------------
PING_SUSPICIOUS = 3
PING_ATTACK = 8

PORT_SUSPICIOUS = 3
PORT_ATTACK = 8

WINDOW_SECONDS = 10
INTERFACE = "enp0s8"

# ---------------- STORAGE ----------------
icmp_packets = defaultdict(list)
tcp_ports = defaultdict(set)

# ---------------- LOGGER ----------------
def log_alert(alert):
    msg = (
        f"[{alert['severity']}] {alert['type']} | "
        f"Source={alert['source_ip']} | "
        f"Count={alert['count']} | "
        f"Window={WINDOW_SECONDS}s | "
        f"Confidence={alert['confidence']}% | "
        f"Reason={alert['reason']}"
    )
    print(msg)
    with open("data/alerts.csv", "a") as f:
        f.write(f"{datetime.now()} - {msg}\n")

# ---------------- DETECTION ----------------
def process_packet(pkt):
    if IP not in pkt:
        return

    src = pkt[IP].src
    now = datetime.now()

    # -------- ICMP DETECTION --------
    if ICMP in pkt:
        icmp_packets[src].append(now)

        # keep only recent packets
        icmp_packets[src] = [
            t for t in icmp_packets[src]
            if (now - t).seconds <= WINDOW_SECONDS
        ]

        count = len(icmp_packets[src])

        if count >= PING_ATTACK:
            log_alert({
                "type": "ICMP_FLOOD",
                "source_ip": src,
                "count": count,
                "confidence": 90,
                "severity": "HIGH",
                "reason": f"{count} ICMP packets in {WINDOW_SECONDS} seconds"
            })

        elif count >= PING_SUSPICIOUS:
            log_alert({
                "type": "ICMP_ACTIVITY",
                "source_ip": src,
                "count": count,
                "confidence": 50,
                "severity": "MEDIUM",
                "reason": "Unusual ICMP rate (suspicious)"
            })

    # -------- TCP PORT SCAN DETECTION --------
    if TCP in pkt:
        dport = pkt[TCP].dport
        tcp_ports[src].add(dport)
        count = len(tcp_ports[src])

        if count >= PORT_ATTACK:
            log_alert({
                "type": "PORT_SCAN",
                "source_ip": src,
                "count": count,
                "confidence": 85,
                "severity": "HIGH",
                "reason": f"Scanned {count} different ports"
            })

        elif count >= PORT_SUSPICIOUS:
            log_alert({
                "type": "PORT_ACTIVITY",
                "source_ip": src,
                "count": count,
                "confidence": 45,
                "severity": "MEDIUM",
                "reason": "Multiple ports accessed (suspicious)"
            })




CSV_FILE = "data/alerts.csv"
def save_alert_csv(alert):
    file_exists = os.path.isfile(CSV_FILE)

    with open(CSV_FILE, "a", newline="") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=["time", "type", "source_ip", "severity", "confidence", "reason"]
        )

        if not file_exists:
            writer.writeheader()

        writer.writerow({
            "time": datetime.now(),
            "type": alert["type"],
            "source_ip": alert["source_ip"],
            "severity": alert["severity"],
            "confidence": alert["confidence"],
            "reason": alert["reason"]
        })

# ---------------- MAIN ----------------
if __name__ == "__main__":
    print(f"[*] IDS running on {INTERFACE}")
    sniff(iface=INTERFACE, prn=process_packet, store=False)

