#!/usr/bin/env python3
"""
Connection Monitor - detects suspicious outbound TCP connections
Catches reverse shells, C2 beacons, data exfil
"""
import os
import json
import time
import socket
from datetime import datetime, timezone
from urllib.request import Request, urlopen

# === CONFIGURE THESE ===
WEBHOOK = "YOUR_DISCORD_WEBHOOK_URL"

WHITELIST_IPS = {
    "127.0.0.1", "::1",
    "104.16.", "104.17.", "104.18.", "104.19.", "104.20.", "104.21.", "104.22.", "104.23.", "104.24.", "104.25.",
    "172.67.", "173.245.", "103.21.", "103.22.", "103.31.", "141.101.", "108.162.", "190.93.", "188.114.",
    "162.159.", "172.64.",
    "142.250.", "172.217.", "216.58.", "74.125.", "35.190.", "35.191.", "35.192.", "35.193.", "35.194.",
    "160.79.", "2607:6bc0:", "2600:1901:",
    "140.82.", "185.199.",
    "91.189.", "185.125.",
    # "YOUR_HOME_IP_PREFIX.",
}

WHITELIST_PORTS = {80, 443, 53, 22}
LOCAL_SERVICE_PORTS = {22, 80, 443, 8000, 5001}
SUSPICIOUS_PORTS = {4444, 4445, 4446, 5555, 6666, 7777, 8888, 9999, 1234, 1337, 31337, 2222, 3333, 8080, 8443, 8000, 8001, 8889, 443}

seen_connections = set()

def get_ip_info(ip):
    try:
        req = Request(f"http://ip-api.com/json/{ip}?fields=status,country,city,isp,org,as")
        with urlopen(req, timeout=5) as resp:
            return json.loads(resp.read().decode())
    except:
        return None

def get_process_info(inode):
    for pid in os.listdir('/proc'):
        if not pid.isdigit():
            continue
        try:
            for fd in os.listdir(f'/proc/{pid}/fd'):
                if f'socket:[{inode}]' in os.readlink(f'/proc/{pid}/fd/{fd}'):
                    cmdline = open(f'/proc/{pid}/cmdline').read().replace('\x00', ' ').strip()
                    comm = open(f'/proc/{pid}/comm').read().strip()
                    uid = os.stat(f'/proc/{pid}').st_uid
                    import pwd
                    try:
                        user = pwd.getpwuid(uid).pw_name
                    except:
                        user = str(uid)
                    return {'pid': pid, 'comm': comm, 'cmdline': cmdline[:200], 'user': user}
        except:
            continue
    return None

def hex_to_ip(hex_ip):
    return socket.inet_ntoa(int(hex_ip, 16).to_bytes(4, 'little'))

def hex_to_port(hex_port):
    return int(hex_port, 16)

def parse_tcp_connections():
    connections = []
    try:
        with open('/proc/net/tcp', 'r') as f:
            for line in f.readlines()[1:]:
                parts = line.split()
                if len(parts) < 10 or parts[3] != '01':
                    continue
                local_ip, local_port = parts[1].split(':')
                remote_ip, remote_port = parts[2].split(':')
                remote_ip = hex_to_ip(remote_ip)
                if remote_ip.startswith('127.') or remote_ip == '0.0.0.0':
                    continue
                connections.append({'local_ip': hex_to_ip(local_ip), 'local_port': hex_to_port(local_port), 'remote_ip': remote_ip, 'remote_port': hex_to_port(remote_port), 'inode': parts[9]})
    except Exception as e:
        print(f"[-] Error: {e}")
    return connections

def is_whitelisted(ip, port):
    return any(ip.startswith(prefix) for prefix in WHITELIST_IPS)

def is_suspicious(port):
    return port in SUSPICIOUS_PORTS or port > 10000

def is_inbound(local_port, remote_port):
    return (local_port in LOCAL_SERVICE_PORTS and remote_port > 1024) or (local_port in {80, 443, 22} and remote_port > 10000)

def send_alert(conn, proc_info, ip_info):
    hostname = socket.gethostname()
    whoami = os.popen('whoami').read().strip()
    if conn['remote_port'] in {4444, 4445, 5555, 6666, 1337, 31337}:
        color, title = 16711680, "🚨 REVERSE SHELL DETECTED"
    elif conn['remote_port'] in SUSPICIOUS_PORTS:
        color, title = 16744256, "⚠️ Suspicious Outbound Connection"
    else:
        color, title = 16776960, "🔗 New Outbound Connection"

    desc = f"**Destination:** `{conn['remote_ip']}:{conn['remote_port']}`\n**Local:** `{conn['local_ip']}:{conn['local_port']}`\n"
    if proc_info:
        desc += f"\n**Process:** `{proc_info['comm']}` (PID: {proc_info['pid']})\n**User:** `{proc_info['user']}`\n**Cmdline:** `{proc_info['cmdline'][:100]}`\n"
    if ip_info and ip_info.get('status') == 'success':
        desc += f"\n**Target Location:** {ip_info.get('city', '?')}, {ip_info.get('country', '?')}\n**Target ISP:** {ip_info.get('isp', '?')}\n**Target ASN:** {ip_info.get('as', '?')}\n"
    desc += f"\n**Victim Host:** `{hostname}`\n**Victim User:** `{whoami}`\n"
    if proc_info:
        desc += f"\n**👁️ WATCH LIVE:**\n`strace -p {proc_info['pid']} -e read,write -s 9999`"

    embed = {"title": title, "description": desc, "color": color, "timestamp": datetime.now(timezone.utc).isoformat(), "footer": {"text": "22div-sentinel • Connection Monitor"}}
    data = json.dumps({"embeds": [embed]}).encode('utf-8')
    try:
        req = Request(WEBHOOK, data=data, headers={"Content-Type": "application/json", "User-Agent": "22div-sentinel/1.0"})
        urlopen(req, timeout=10)
        print(f"[+] Alert sent: {conn['remote_ip']}:{conn['remote_port']}")
    except Exception as e:
        print(f"[-] Webhook error: {e}")

def monitor():
    global seen_connections
    print(f"[*] Connection Monitor started")
    while True:
        try:
            for conn in parse_tcp_connections():
                conn_key = f"{conn['remote_ip']}:{conn['remote_port']}"
                if conn_key in seen_connections:
                    continue
                if is_whitelisted(conn['remote_ip'], conn['remote_port']) or is_inbound(conn['local_port'], conn['remote_port']):
                    seen_connections.add(conn_key)
                    continue
                if is_suspicious(conn['remote_port']) or conn['remote_port'] not in WHITELIST_PORTS:
                    seen_connections.add(conn_key)
                    proc_info = get_process_info(conn['inode'])
                    if proc_info and 'conn_alert' in proc_info.get('cmdline', ''):
                        continue
                    send_alert(conn, proc_info, get_ip_info(conn['remote_ip']))
            if len(seen_connections) > 10000:
                seen_connections = set()
            time.sleep(2)
        except Exception as e:
            print(f"[-] Error: {e}")
            time.sleep(5)

if __name__ == "__main__":
    monitor()
