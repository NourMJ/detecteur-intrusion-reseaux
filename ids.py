from scapy.all import sniff, IP, ICMP, TCP, UDP
from interface.telegram_alerts import send_telegram_alert
from dotenv import load_dotenv
from collections import defaultdict
from datetime import datetime
import csv
import os
import time
import yaml
load_dotenv()

# Import anomaly detector (your file: detection/anomaly.py)
try:
    from detection.anomaly import AnomalyDetector
except Exception:
    AnomalyDetector = None


# ================= PATHS =================
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")
RULES_FILE = os.path.join(BASE_DIR, "rules", "attacks.yml")

CSV_ALERTS = os.path.join(DATA_DIR, "alerts.csv")
CSV_STATS = os.path.join(DATA_DIR, "flow_stats.csv")
LOG_FILE = os.path.join(BASE_DIR, "alerts.log")

# ================= CONFIG =================
INTERFACE = "enp0s8"
ALERT_COOLDOWN = 30  # seconds
DEFAULT_WINDOW = 10  # fallback if rule doesn't provide

# anomaly config
ENABLE_ANOMALY = True
ANOMALY_TRAIN_MIN_WINDOWS = 30  # minimum rows in flow_stats.csv to train
ANOMALY_TRAIN_EVERY_WINDOWS = 20  # retrain every N windows
ANOMALY_ALERT_THRESHOLD = 1       # if predict==anomaly -> alert

# ================= RUNTIME STORAGE =================
LAST_ALERT = {}  # rate-limit per (type+src)

# For rule-based windows
rule_times = defaultdict(lambda: defaultdict(list))     # rule -> src -> [datetime]
portscan_events = defaultdict(list)                     # src -> [(dport, datetime)]

# For per-window flow stats
window_start = time.time()
window_stats = {
    "total_packets": 0,
    "icmp_count": 0,
    "syn_count": 0,
    "udp53_count": 0,
    "unique_dst_ports": set(),  # within window
}

# anomaly model
anomaly_model = AnomalyDetector() if (AnomalyDetector and ENABLE_ANOMALY) else None
trained = False
windows_seen = 0


# ================= UTILS =================
def should_log(alert_type: str, source_ip: str) -> bool:
    key = f"{alert_type}_{source_ip}"
    now = time.time()
    last = LAST_ALERT.get(key)
    if last is None or (now - last) > ALERT_COOLDOWN:
        LAST_ALERT[key] = now
        return True
    return False


def cleanup_times(times, now, window_seconds: int):
    return [t for t in times if (now - t).total_seconds() <= window_seconds]


def cleanup_portscan_events(events, now, window_seconds: int):
    return [(p, t) for (p, t) in events if (now - t).total_seconds() <= window_seconds]


def get_dst_ip(pkt):
    try:
        return pkt[IP].dst if IP in pkt else ""
    except Exception:
        return ""


def load_rules():
    if not os.path.exists(RULES_FILE):
        raise FileNotFoundError(f"Rules file not found: {RULES_FILE}")

    with open(RULES_FILE, "r", encoding="utf-8") as f:
        rules = yaml.safe_load(f)

    if not isinstance(rules, dict):
        raise ValueError("attacks.yml must be a dictionary of rules")

    # Normalize + defaults
    for name, r in rules.items():
        r.setdefault("window_seconds", DEFAULT_WINDOW)
        r.setdefault("threshold", 10)
        r.setdefault("severity", "MEDIUM")
        r.setdefault("confidence", 70)
        r.setdefault("description", "")
    return rules


# ================= LOGGER =================
def log_alert(alert: dict):
    os.makedirs(DATA_DIR, exist_ok=True)

    ts = datetime.now().isoformat(timespec="seconds")
    dest_ip = alert.get("dest_ip", "")

    terminal_msg = (
        f"[{alert['severity']}] {alert['type']} | "
        f"src={alert['source_ip']} | dst={dest_ip} | "
        f"Conf={alert['confidence']}% | {alert['reason']}"
    )

    print(terminal_msg)
    msg = (
        f"🛡️ <b>CYBERSHIELD IDS ALERT</b>\n"
        f"⚠️ <b>{alert['type']}</b>\n"
        f"📌 <b>Severity:</b> {alert['severity']}\n"
        f"🧾 <b>Confidence:</b> {alert['confidence']}%\n"
        f"🌐 <b>Source:</b> {alert['source_ip']}\n"
        f"🎯 <b>Dest:</b> {alert.get('dest_ip','')}\n"
        f"🕒 <b>Time:</b> {datetime.now().isoformat(timespec='seconds')}\n"
        f"📝 <b>Reason:</b> {alert['reason']}"
        )
    if alert["severity"] in ["HIGH", "MEDIUM"]:
        send_telegram_alert(msg)


    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(f"{ts} - {terminal_msg}\n")

    file_exists = os.path.isfile(CSV_ALERTS)
    with open(CSV_ALERTS, "a", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=["time", "type", "source_ip", "dest_ip", "severity", "confidence", "reason"]
        )
        if not file_exists:
            writer.writeheader()

        writer.writerow({
            "time": ts,
            "type": alert["type"],
            "source_ip": alert["source_ip"],
            "dest_ip": dest_ip,
            "severity": alert["severity"],
            "confidence": alert["confidence"],
            "reason": alert["reason"]
        })


def append_flow_stats(row: dict):
    """Append one window row to flow_stats.csv for anomaly training."""
    os.makedirs(DATA_DIR, exist_ok=True)
    file_exists = os.path.isfile(CSV_STATS)

    with open(CSV_STATS, "a", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=["time", "icmp_count", "syn_count", "udp53_count", "unique_dst_ports", "total_packets"]
        )
        if not file_exists:
            writer.writeheader()
        writer.writerow(row)


def maybe_rotate_window_and_anomaly_check(rules):
    """
    Every DEFAULT_WINDOW seconds, we finalize window stats:
    - write flow_stats.csv
    - optionally train and predict anomaly
    """
    global window_start, window_stats, trained, windows_seen

    now_ts = time.time()
    elapsed = now_ts - window_start
    if elapsed < DEFAULT_WINDOW:
        return

    # finalize window row
    windows_seen += 1
    row = {
        "time": datetime.now().isoformat(timespec="seconds"),
        "icmp_count": int(window_stats["icmp_count"]),
        "syn_count": int(window_stats["syn_count"]),
        "udp53_count": int(window_stats["udp53_count"]),
        "unique_dst_ports": int(len(window_stats["unique_dst_ports"])),
        "total_packets": int(window_stats["total_packets"]),
    }
    append_flow_stats(row)

    # anomaly train + predict
    if anomaly_model is not None:
        try:
            # Train if not trained and enough windows collected
            if (not trained):
                # check file length quickly
                import pandas as pd
                df = pd.read_csv(CSV_STATS)
                if len(df) >= ANOMALY_TRAIN_MIN_WINDOWS:
                    anomaly_model.train(CSV_STATS)
                    trained = True

            # periodic retraining
            if trained and (windows_seen % ANOMALY_TRAIN_EVERY_WINDOWS == 0):
                anomaly_model.train(CSV_STATS)

            # anomaly decision for this window
            if trained:
                is_anom = anomaly_model.predict(row)
                if is_anom:
                    # avoid spamming anomaly alerts: key by "ANOMALY_TRAFFIC_GLOBAL"
                    if should_log("ANOMALY_TRAFFIC", "GLOBAL"):
                        log_alert({
                            "type": "ANOMALY_TRAFFIC",
                            "source_ip": "GLOBAL",
                            "dest_ip": "",
                            "severity": "MEDIUM",
                            "confidence": 60,
                            "reason": (
                                f"Traffic anomaly detected (window {DEFAULT_WINDOW}s) | "
                                f"icmp={row['icmp_count']}, syn={row['syn_count']}, "
                                f"udp53={row['udp53_count']}, ports={row['unique_dst_ports']}, "
                                f"pkts={row['total_packets']}"
                            )
                        })
        except Exception as e:
            # don't kill IDS if anomaly fails
            with open(LOG_FILE, "a", encoding="utf-8") as f:
                f.write(f"{datetime.now().isoformat(timespec='seconds')} - Anomaly error: {e}\n")

    # reset window
    window_start = now_ts
    window_stats = {
        "total_packets": 0,
        "icmp_count": 0,
        "syn_count": 0,
        "udp53_count": 0,
        "unique_dst_ports": set(),
    }


# ================= SIGNATURE DETECTION =================
def check_rule_trigger(rule_name, rule, src, dst, now):
    """
    Generic counter-based rule trigger using timestamps list.
    """
    w = int(rule.get("window_seconds", DEFAULT_WINDOW))
    thr = int(rule.get("threshold", 10))

    # cleanup & count
    rule_times[rule_name][src] = cleanup_times(rule_times[rule_name][src], now, w)
    count = len(rule_times[rule_name][src])

    if count >= thr and should_log(rule_name, src):
        log_alert({
            "type": rule_name,
            "source_ip": src,
            "dest_ip": dst,
            "severity": rule.get("severity", "MEDIUM"),
            "confidence": int(rule.get("confidence", 70)),
            "reason": f"{rule.get('description','')} (count={count} in {w}s)"
        })


def check_port_scan(rule_name, rule, src, dst, dport, now):
    w = int(rule.get("window_seconds", 5))
    thr = int(rule.get("threshold", 8))

    portscan_events[src].append((int(dport), now))
    portscan_events[src] = cleanup_portscan_events(portscan_events[src], now, w)

    ports = {p for (p, t) in portscan_events[src]}
    if len(ports) >= thr and should_log(rule_name, src):
        log_alert({
            "type": rule_name,
            "source_ip": src,
            "dest_ip": dst,
            "severity": rule.get("severity", "MEDIUM"),
            "confidence": int(rule.get("confidence", 80)),
            "reason": f"{rule.get('description','')} (ports={sorted(ports)} in {w}s)"
        })


# ================= PACKET PROCESSOR =================
def process_packet(pkt, rules):
    if IP not in pkt:
        return

    now = datetime.now()
    src = pkt[IP].src
    dst = get_dst_ip(pkt)

    # update window stats
    window_stats["total_packets"] += 1

    # ---- ICMP ----
    if ICMP in pkt:
        window_stats["icmp_count"] += 1
        if "ICMP_FLOOD" in rules:
            rule_times["ICMP_FLOOD"][src].append(now)
            check_rule_trigger("ICMP_FLOOD", rules["ICMP_FLOOD"], src, dst, now)

    # ---- TCP ----
    if TCP in pkt:
        dport = int(pkt[TCP].dport)
        window_stats["unique_dst_ports"].add(dport)

        # PORT_SCAN rule
        if "PORT_SCAN" in rules:
            check_port_scan("PORT_SCAN", rules["PORT_SCAN"], src, dst, dport, now)

        # SYN_FLOOD rule
        flags = str(pkt[TCP].flags)
        if flags == "S" and "SYN_FLOOD" in rules:
            window_stats["syn_count"] += 1
            rule_times["SYN_FLOOD"][src].append(now)
            check_rule_trigger("SYN_FLOOD", rules["SYN_FLOOD"], src, dst, now)

    # ---- UDP ----
    if UDP in pkt:
        # For DNS amplification (simple heuristic)
        # Many UDP packets where sport=53 (DNS response) or dport=53 (DNS request)
        sport = int(pkt[UDP].sport)
        dport = int(pkt[UDP].dport)

        if sport == 53 or dport == 53:
            window_stats["udp53_count"] += 1

        if "DNS_AMPLIFICATION" in rules:
            # Interpret the rule "port: 53" as DNS traffic volume threshold
            if (sport == 53 or dport == 53):
                rule_times["DNS_AMPLIFICATION"][src].append(now)
                check_rule_trigger("DNS_AMPLIFICATION", rules["DNS_AMPLIFICATION"], src, dst, now)

    # finalize window + anomaly checks periodically
    maybe_rotate_window_and_anomaly_check(rules)


# ================= MAIN =================
if __name__ == "__main__":
    os.makedirs(DATA_DIR, exist_ok=True)

    try:
        rules = load_rules()
        print(f"[*] CYBERSHIELD IDS running on: {INTERFACE}")
        print(f"[*] Rules loaded from: {RULES_FILE}")
        print(f"[*] Alerts -> {CSV_ALERTS} | Stats -> {CSV_STATS}")
        print("[*] Press Ctrl+C to stop.\n")

        sniff(
            iface=INTERFACE,
            filter="ip",
            store=False,
            prn=lambda pkt: process_packet(pkt, rules)
        )

    except KeyboardInterrupt:
        print("\n[!] IDS stopped by user.")
    except Exception as e:
        err = f"{datetime.now().isoformat(timespec='seconds')} - Error: {e}"
        print(f"[!] {err}")
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(err + "\n")
