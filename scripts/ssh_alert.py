#!/usr/bin/env python3
"""
SSH Alert - watches auth.log for bruteforce attempts, webhooks to Discord
Full version with live feed, XOR encoding, and IP redaction
"""
import os
import re
import json
import time
import subprocess
from datetime import datetime, timezone
from urllib.request import Request, urlopen

# === CONFIGURE THESE ===
DISCORD_WEBHOOK = "YOUR_DISCORD_WEBHOOK_URL"
AUTH_LOG = "/var/log/auth.log"

ip_fail_count = {}
ip_last_alert = {}
ALERT_THRESHOLD = 1   # Alert on FIRST failed attempt
ALERT_COOLDOWN = 30   # Seconds cooldown per IP

# Live feed for frontend (set to None to disable)
LIVE_FEED_FILE = "/var/www/html/api/scanner-feed.json"
MAX_FEED_ENTRIES = 30

# IPs to redact - known testers (partial prefix)
REDACT_IPS = [
    # 'YOUR_TESTER_IP_PREFIX.',
]

# Usernames to always redact
REDACT_USERS = [
    # 'your_test_username',
]

# IPs to XOR encode (owner activity - visible but obfuscated)
XOR_IPS = [
    # 'YOUR_SERVER_IP_PREFIX.',
    # 'YOUR_HOME_IP_PREFIX.',
]

def xor_encode(text, key=0x41):
    return ''.join(chr(ord(c) ^ key) if c.isalnum() else c for c in text)

def should_xor(ip):
    return any(ip.startswith(prefix) for prefix in XOR_IPS)

def should_redact(ip):
    return any(ip.startswith(prefix) for prefix in REDACT_IPS)

def redact_username(username):
    if username.lower() in [u.lower() for u in REDACT_USERS]:
        return '[REDACTED]'
    return username

def update_live_feed(entry):
    if not LIVE_FEED_FILE:
        return
    try:
        os.makedirs(os.path.dirname(LIVE_FEED_FILE), exist_ok=True)
        feed = {"entries": [], "stats": {"total_24h": 0, "blocked": 0}, "stats_date": ""}
        if os.path.exists(LIVE_FEED_FILE):
            with open(LIVE_FEED_FILE, 'r') as f:
                feed = json.load(f)
        today = datetime.now().strftime("%Y-%m-%d")
        if feed.get("stats_date") != today:
            feed["stats"] = {"total_24h": 0, "blocked": 0}
            feed["stats_date"] = today
        feed["entries"].insert(0, entry)
        feed["entries"] = feed["entries"][:MAX_FEED_ENTRIES]
        feed["stats"]["total_24h"] = feed["stats"].get("total_24h", 0) + 1
        feed["stats"]["blocked"] = feed["stats"].get("blocked", 0) + 1
        feed["updated"] = datetime.now(timezone.utc).isoformat()
        with open(LIVE_FEED_FILE, 'w') as f:
            json.dump(feed, f)
    except Exception as e:
        print(f"[-] Feed write error: {e}")

def get_ip_info(ip):
    try:
        req = Request(f"http://ip-api.com/json/{ip}?fields=status,country,regionName,city,isp,org,as,query")
        with urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read().decode())
            if data.get('status') == 'success':
                return data
    except:
        pass
    return None

def get_whois_abuse(ip):
    try:
        result = subprocess.run(['whois', ip], capture_output=True, text=True, timeout=10)
        abuse = re.search(r'(abuse[^@]*@\S+)', result.stdout, re.I)
        return abuse.group(0) if abuse else None
    except:
        return None

def send_discord(ip, username, alert_type, fail_count):
    ip_last_alert[ip] = time.time()
    redacted = should_redact(ip)
    xor_it = should_xor(ip)
    display_user = redact_username(username)
    ip_info = None

    if redacted:
        feed_entry = {"ip": "[REDACTED]", "type": f"SSH {alert_type}", "country": "", "city": "", "isp": "", "ua": f"user: {display_user}", "blocked": True}
    elif xor_it:
        ip_info = get_ip_info(ip)
        feed_entry = {"ip": f"XOR:{xor_encode(ip)}", "type": f"SSH {alert_type}", "country": ip_info.get("country", "??") if ip_info else "??", "city": ip_info.get("city", "Unknown") if ip_info else "Unknown", "isp": "OWNER/INFRA", "ua": f"user: {display_user}", "blocked": False}
    else:
        ip_info = get_ip_info(ip)
        feed_entry = {"ip": ip, "type": f"SSH {alert_type}", "country": ip_info.get("country", "??") if ip_info else "??", "city": ip_info.get("city", "Unknown") if ip_info else "Unknown", "isp": ip_info.get("isp", "Unknown") if ip_info else "Unknown", "ua": f"user: {display_user}", "asn": ip_info.get("as", "")[:20] if ip_info else "", "blocked": True}
    update_live_feed(feed_entry)

    if not redacted:
        if ip_info is None:
            ip_info = get_ip_info(ip)
        abuse = get_whois_abuse(ip)
    else:
        abuse = None

    if redacted:
        desc = f"**IP:** `[REDACTED - Known Tester]`\n"
    elif xor_it:
        desc = f"**IP:** `XOR:{xor_encode(ip)}` (OWNER/INFRA)\n"
    else:
        desc = f"**IP:** `{ip}`\n"
    desc += f"**Username:** `{display_user}`\n"
    desc += f"**Failed attempts:** {fail_count}\n"
    desc += f"**Type:** {alert_type}\n"

    if ip_info:
        desc += f"\n**Location:** {ip_info.get('city', '?')}, {ip_info.get('regionName', '?')}, {ip_info.get('country', '?')}\n"
        desc += f"**ISP:** {ip_info.get('isp', '?')}\n"
        desc += f"**ASN:** {ip_info.get('as', '?')}\n"
    if abuse:
        desc += f"**Abuse:** `{abuse}`\n"

    msg = f"🔐 **SSH BRUTEFORCE** | {alert_type}\n{desc}"
    data = json.dumps({"content": msg[:2000]}).encode('utf-8')
    try:
        req = Request(DISCORD_WEBHOOK, data=data, headers={"Content-Type": "application/json", "User-Agent": "22div-sentinel/1.0"})
        urlopen(req, timeout=10)
        print(f"[+] SSH Alert: {ip} - {fail_count} fails")
    except Exception as e:
        print(f"[-] Webhook error: {e}")

def send_success_alert(ip, username, auth_type):
    ip_info = get_ip_info(ip)
    abuse = get_whois_abuse(ip)
    import glob
    session_files = sorted(glob.glob(f"/var/log/sessions/*_{ip}.log"), key=os.path.getmtime, reverse=True)
    session_file = os.path.basename(session_files[0]) if session_files else "check /var/log/sessions/"

    desc = f"**IP:** `{ip}`\n**Username:** `{username}`\n**Auth:** {auth_type}\n\n**👁️ WATCH LIVE:**\n`tail -f /var/log/sessions/{session_file}`\n"
    if ip_info:
        desc += f"\n**Location:** {ip_info.get('city', '?')}, {ip_info.get('regionName', '?')}, {ip_info.get('country', '?')}\n**ISP:** {ip_info.get('isp', '?')}\n**ASN:** {ip_info.get('as', '?')}\n"
    if abuse:
        desc += f"**Abuse:** `{abuse}`\n"

    msg = f"✅ **SSH LOGIN** | {auth_type}\n{desc}"
    data = json.dumps({"content": msg[:2000]}).encode('utf-8')
    try:
        req = Request(DISCORD_WEBHOOK, data=data, headers={"Content-Type": "application/json", "User-Agent": "22div-sentinel/1.0"})
        urlopen(req, timeout=10)
        print(f"[+] SSH Login: {username}@{ip} via {auth_type}")
    except Exception as e:
        print(f"[-] Webhook error: {e}")

def watch_log():
    if not os.path.exists(AUTH_LOG):
        print(f"[-] Log not found: {AUTH_LOG}")
        return
    with open(AUTH_LOG, 'r') as f:
        f.seek(0, 2)
        print(f"[*] SSH Alert watching {AUTH_LOG}")
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.5)
                continue
            match = re.search(r'Failed password for (?:invalid user )?(\S+) from (\d+\.\d+\.\d+\.\d+)', line)
            if match:
                username, ip = match.groups()
                ip_fail_count[ip] = ip_fail_count.get(ip, 0) + 1
                if ip_fail_count[ip] == ALERT_THRESHOLD:
                    send_discord(ip, username, "Failed password", ip_fail_count[ip])
                continue
            match = re.search(r'Invalid user (.+?) from (\d+\.\d+\.\d+\.\d+)', line)
            if match:
                username, ip = match.groups()
                ip_fail_count[ip] = ip_fail_count.get(ip, 0) + 1
                if ip_fail_count[ip] == ALERT_THRESHOLD:
                    send_discord(ip, username, "Invalid user", ip_fail_count[ip])
                continue
            match = re.search(r'Connection closed by authenticating user (\S+) (\d+\.\d+\.\d+\.\d+)', line)
            if match:
                username, ip = match.groups()
                ip_fail_count[ip] = ip_fail_count.get(ip, 0) + 1
                if ip_fail_count[ip] == ALERT_THRESHOLD:
                    send_discord(ip, username, "Failed key auth", ip_fail_count[ip])
                continue
            match = re.search(r'Disconnected from authenticating user (\S+) (\d+\.\d+\.\d+\.\d+)', line)
            if match:
                username, ip = match.groups()
                ip_fail_count[ip] = ip_fail_count.get(ip, 0) + 1
                if ip_fail_count[ip] == ALERT_THRESHOLD:
                    send_discord(ip, username, "Failed key auth", ip_fail_count[ip])
                continue
            match = re.search(r'Accepted (\S+) for (\S+) from (\d+\.\d+\.\d+\.\d+)', line)
            if match:
                auth_type, username, ip = match.groups()
                send_success_alert(ip, username, auth_type)

if __name__ == "__main__":
    print("[*] SSH Alert starting...")
    watch_log()
