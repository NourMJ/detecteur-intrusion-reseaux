import datetime
from scapy.all import sniff, IP, ICMP, TCP, wrpcap

ping_count = {}
port_scan = {}
captured_packets = []

PING_THRESHOLD = 20
PORT_THRESHOLD = 15
MAX_CAPTURE = 500

def log(msg):
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{now}] {msg}"
    print(line)
    with open("alerts.log", "a") as f:
        f.write(line + "\n")

def handle(pkt):
    global captured_packets
    
    # Ajouter le paquet à la liste de capture
    captured_packets.append(pkt)
    if len(captured_packets) >= MAX_CAPTURE:
        wrpcap("capture.pcap", captured_packets)
        log(f"[INFO] Captured {MAX_CAPTURE} packets to capture.pcap")
        captured_packets.clear()
    
    if IP not in pkt:
        return

    src = pkt[IP].src

    if ICMP in pkt:
        ping_count[src] = ping_count.get(src, 0) + 1
        if ping_count[src] == PING_THRESHOLD:
            log(f"[ALERT] Possible ICMP flood from {src}")

    if TCP in pkt:
        dport = pkt[TCP].dport
        ports = port_scan.get(src, set())
        ports.add(dport)
        port_scan[src] = ports
        if len(ports) == PORT_THRESHOLD:
            log(f"[ALERT] Possible TCP port scan from {src}, ports: {sorted(ports)}")

sniff(store=False, prn=handle)

