import sqlite3
from datetime import datetime
from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.http import HTTPRequest

# --- Database Setup ---
def init_db():
    conn = sqlite3.connect("packets.db")
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS packets (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT,
        protocol TEXT,
        src_ip TEXT,
        dst_ip TEXT,
        detail TEXT
    )''')
    conn.commit()
    conn.close()

def log_packet(protocol, src_ip, dst_ip, detail):
    conn = sqlite3.connect("packets.db")
    c = conn.cursor()
    c.execute("INSERT INTO packets (timestamp, protocol, src_ip, dst_ip, detail) VALUES (?, ?, ?, ?, ?)",
              (datetime.now().isoformat(), protocol, src_ip, dst_ip, detail))
    conn.commit()
    conn.close()
    print(f"[{datetime.now().strftime('%H:%M:%S')}] {protocol} | {src_ip} -> {dst_ip} | {detail}")

# --- Packet Parser ---
def process_packet(packet):
    if not packet.haslayer(IP):
        return

    src_ip = packet[IP].src
    dst_ip = packet[IP].dst

    # DNS — domain lookups
    if packet.haslayer(DNS) and packet.haslayer(DNSQR):
        query = packet[DNSQR].qname.decode(errors="ignore").rstrip(".")
        log_packet("DNS", src_ip, dst_ip, f"Query: {query}")

    # HTTP — unencrypted web requests
    elif packet.haslayer(HTTPRequest):
        host = packet[HTTPRequest].Host.decode(errors="ignore")
        path = packet[HTTPRequest].Path.decode(errors="ignore")
        method = packet[HTTPRequest].Method.decode(errors="ignore")
        log_packet("HTTP", src_ip, dst_ip, f"{method} {host}{path}")

    # TCP — general TCP traffic
    elif packet.haslayer(TCP):
        sport = packet[TCP].sport
        dport = packet[TCP].dport
        flags = packet[TCP].flags
        log_packet("TCP", src_ip, dst_ip, f"Port {sport} -> {dport} | Flags: {flags}")

    # UDP — general UDP traffic
    elif packet.haslayer(UDP):
        sport = packet[UDP].sport
        dport = packet[UDP].dport
        log_packet("UDP", src_ip, dst_ip, f"Port {sport} -> {dport}")

# --- Start Sniffing ---
if __name__ == "__main__":
    init_db()
    print("[*] Starting packet capture... (Ctrl+C to stop)")
    print("[*] Tip: Browse the web to generate traffic\n")
    sniff(prn=process_packet, store=False)