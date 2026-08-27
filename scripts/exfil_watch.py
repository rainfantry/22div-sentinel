#!/usr/bin/env python3
"""
Exfil Watchdog - monitors for connections to known attacker infrastructure
Starts packet capture when connection detected
"""
import os
import json
import time
import socket
import subprocess
from datetime import datetime, timezone
from urllib.request import Request, urlopen

# === CONFIGURE THESE ===
WEBHOOK = "YOUR_DISCORD_WEBHOOK_URL"

# Add attacker C2 domains/IPs here when you identify them
WATCHLIST_DOMAINS = [
    # "attacker-c2.example.com",
]

WATCHLIST_IPS = [
    # "1.2.3.4",
]

LOG_DIR = "/var/log/exfil_captures"
os.makedirs(LOG_DIR, exist_ok=True)

def resolve_domain(domain):
    try:
        return socket.gethostbyname_ex(domain)[2]
    except:
        return []

def get_all_watched_ips():
    ips = set(WATCHLIST_IPS)
    for domain in WATCHLIST_DOMAINS:
        ips.update(resolve_domain(domain))
    return ips

def send_alert(title, desc, color=16711680):
    embed = {"title": title, "description": desc, "color": color, "timestamp": datetime.now(timezone.utc).isoformat(), "footer": {"text": "22div-sentinel • Exfil Watchdog"}}
    data = json.dumps({"embeds": [embed]}).encode('utf-8')
    try:
        req = Request(WEBHOOK, data=data, headers={"Content-Type": "application/json", "User-Agent": "22div-sentinel/1.0"})
        urlopen(req, timeout=10)
    except Exception as e:
        print(f"[-] Webhook error: {e}")

def start_capture(ip, duration=60):
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    pcap_file = f"{LOG_DIR}/exfil_{ip}_{timestamp}.pcap"
    subprocess.Popen(f"timeout {duration} tcpdump -i any host {ip} -w {pcap_file} &", shell=True)
    return pcap_file

def check_connections():
    watched_ips = get_all_watched_ips()
    try:
        result = subprocess.run(["ss", "-tunp"], capture_output=True, text=True, timeout=10)
        for line in result.stdout.split('\n'):
            for ip in watched_ips:
                if ip in line:
                    return ip, line
    except:
        pass
    return None, None

def get_process_for_connection(ip):
    try:
        result = subprocess.run(["ss", "-tunp"], capture_output=True, text=True, timeout=10)
        for line in result.stdout.split('\n'):
            if ip in line and 'users:' in line:
                return line.split('users:')[1].strip()
    except:
        pass
    return "Unknown"

def monitor():
    print(f"[*] Exfil Watchdog started")
    print(f"[*] Watching domains: {WATCHLIST_DOMAINS}")
    print(f"[*] Watching IPs: {WATCHLIST_IPS}")
    if not WATCHLIST_DOMAINS and not WATCHLIST_IPS:
        print("[!] No domains or IPs configured")

    alerted = set()
    while True:
        try:
            ip, conn_info = check_connections()
            if ip and ip not in alerted:
                alerted.add(ip)
                pcap_file = start_capture(ip)
                desc = f"**🚨 ATTACKER INFRASTRUCTURE CONTACT**\n\n**IP:** `{ip}`\n**Connection:** `{conn_info[:200]}`\n**Process:** `{get_process_for_connection(ip)}`\n**Capture:** `{pcap_file}`\n\n**Immediate action:** Check process, may be active exfil!"
                send_alert("🚨 EXFIL DETECTED - ATTACKER C2 CONTACT", desc)
                print(f"[!] ALERT: Connection to {ip} detected!")
            if len(alerted) > 100:
                alerted.clear()
            time.sleep(5)
        except Exception as e:
            print(f"[-] Error: {e}")
            time.sleep(10)

if __name__ == "__main__":
    for domain in WATCHLIST_DOMAINS:
        print(f"    {domain} -> {resolve_domain(domain)}")
    monitor()
