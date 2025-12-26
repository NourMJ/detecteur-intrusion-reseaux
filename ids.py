from scapy.all import sniff, IP, ICMP, TCP
from collections import defaultdict
from datetime import datetime
import csv
import os
import time

# ================= PATHS =================
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")
CSV_FILE = os.path.join(DATA_DIR, "alerts.csv")
LOG_FILE = os.path.join(BASE_DIR, "alerts.log")

# ================= CONFIG =================
INTERFACE = "enp0s8"  # Make sure this is correct
WINDOW_SECONDS = 10

PING_SUSPICIOUS = 3
PING_ATTACK = 8

PORT_SUSPICIOUS = 3
PORT_ATTACK = 8

ALERT_COOLDOWN = 30  # seconds

# ================= STORAGE =================
icmp_packets = defaultdict(list)
tcp_ports = defaultdict(set)
LAST_ALERT = {}

# ================= UTILS =================
def should_log(alert_type, source_ip):
    key = f"{alert_type}_{source_ip}"
    now = time.time()

    if key not in LAST_ALERT:
        LAST_ALERT[key] = now
        return True

    if now - LAST_ALERT[key] > ALERT_COOLDOWN:
        LAST_ALERT[key] = now
        return True

    return False

# ================= LOGGER =================
def log_alert(alert):
    os.makedirs(DATA_DIR, exist_ok=True)

    terminal_msg = (
        f"[{alert['severity']}] {alert['type']} | "
        f"{alert['source_ip']} | "
        f"Confidence={alert['confidence']}% | "
        f"{alert['reason']}"
    )

    # ---- TERMINAL ----
    print(terminal_msg)

    # ---- LOG FILE ----
    with open(LOG_FILE, "a") as f:
        f.write(f"{datetime.now()} - {terminal_msg}\n")

    # ---- CSV ----
    file_exists = os.path.isfile(CSV_FILE)

    with open(CSV_FILE, "a", newline="") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=[ "time", "type", "source_ip", "severity", "confidence", "reason"]
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

# ================= DETECTION =================
def process_packet(pkt):
    if IP not in pkt:
        return

    src = pkt[IP].src
    now = datetime.now()

    # ---------- ICMP ----------
    if ICMP in pkt:
        icmp_packets[src].append(now)
        icmp_packets[src] = [
            t for t in icmp_packets[src]
            if (now - t).seconds <= WINDOW_SECONDS
        ]
        count = len(icmp_packets[src])

        # --- ATTACK ---
        if count >= PING_ATTACK:
            if should_log("ICMP_FLOOD", src):
                log_alert({
                    "type": "ICMP_FLOOD",
                    "source_ip": src,
                    "severity": "HIGH",
                    "confidence": 90,
                    "reason": f"{count} ICMP packets in {WINDOW_SECONDS}s"
                })

        # --- SUSPICIOUS ---
        elif count >= PING_SUSPICIOUS:
            if should_log("ICMP_ACTIVITY", src):
                log_alert({
                    "type": "ICMP_ACTIVITY",
                    "source_ip": src,
                    "severity": "MEDIUM",
                    "confidence": 50,
                    "reason": f"{count} ICMP packets in {WINDOW_SECONDS}s"
                })

    # ---------- TCP ----------
    if TCP in pkt:
        dport = pkt[TCP].dport
        tcp_ports[src].add(dport)

        count = len(tcp_ports[src])

        # --- ATTACK ---
        if count >= PORT_ATTACK:
            if should_log("PORT_SCAN", src):
                log_alert({
                    "type": "PORT_SCAN",
                    "source_ip": src,
                    "severity": "MEDIUM",
                    "confidence": 80,
                    "reason": f"Scanned ports: {sorted(tcp_ports[src])}"
                })

        # --- SUSPICIOUS ---
        elif count >= PORT_SUSPICIOUS:
            if should_log("PORT_ACTIVITY", src):
                log_alert({
                    "type": "PORT_ACTIVITY",
                    "source_ip": src,
                    "severity": "LOW",
                    "confidence": 45,
                    "reason": f"Multiple ports accessed ({count})"
                })

    # ---------- SYN FLOOD ----------
    if TCP in pkt and pkt[TCP].flags == "S":  # SYN flag set
        # Track SYN packets from each source
        if src not in tcp_ports:
            tcp_ports[src] = {"SYN": 0}

        tcp_ports[src]["SYN"] += 1

        count = tcp_ports[src]["SYN"]

        # --- ATTACK ---
        if count >= 15:  # Threshold for SYN flood attack
            if should_log("SYN_FLOOD", src):
                log_alert({
                    "type": "SYN_FLOOD",
                    "source_ip": src,
                    "severity": "HIGH",
                    "confidence": 95,
                    "reason": f"{count} SYN packets detected in {WINDOW_SECONDS}s"
                })


# ================= MAIN =================
if __name__ == "__main__":
    try:
        print(f"[*] IDS running on interface {INTERFACE}")
        sniff(
            iface=INTERFACE,
            prn=process_packet,
            store=False
        )
    except Exception as e:
        print(f"Error occurred: {e}")
        with open(LOG_FILE, "a") as f:
            f.write(f"{datetime.now()} - Error: {e}\n")
