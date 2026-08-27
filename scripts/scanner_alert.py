#!/usr/bin/env python3
"""
Scanner Alert v4 - Intel-rich logging with full header capture
Watches nginx logs for suspicious patterns, sends rich Discord alerts
"""
import os
import re
import json
import time
import subprocess
from datetime import datetime, timezone
from urllib.request import Request, urlopen
from collections import defaultdict

# === CONFIGURE THESE ===
DISCORD_WEBHOOK = "YOUR_DISCORD_WEBHOOK_URL"
INTEL_LOG = "/var/log/nginx/intel.log"
ACCESS_LOG = "/var/log/nginx/access.log"

SUSPICIOUS_PATTERNS = [
    r'\.env', r'\.git', r'\.aws', r'\.ssh', r'wp-', r'wordpress',
    r'phpmyadmin', r'login', r'config', r'backup',
    r'\.sql', r'\.zip', r'\.tar', r'\.gz', r'shell', r'eval',
    r'base64', r'passwd', r'shadow', r'\.htaccess', r'\.htpasswd',
    r'actuator', r'metrics', r'debug', r'trace', r'graphql',
    r'swagger', r'console', r'manager', r'jenkins',
    r'\.php', r'cgi-bin', r'\.asp', r'\.jsp', r'\.do',
    r'\.DS_Store', r'\.vscode', r'node_modules',
    r'vendor/', r'composer', r'package\.json', r'\.yaml', r'\.yml',
    r'\.bak', r'\.old', r'\.orig', r'\.save', r'\.swp',
    r'xmlrpc', r'wlwmanifest', r'wp-includes', r'wp-content',
]

WHITELIST_PATHS = [
    r'^/$', r'^/index\.html?$', r'^/favicon', r'^/apple-touch-icon',
    r'^/sw\.js$', r'^/manifest\.json$', r'^/robots\.txt$', r'^/sitemap',
    r'^/css/', r'^/js/', r'^/images/', r'^/fonts/', r'^/api/', r'^/assets/',
    r'\.(png|jpg|jpeg|gif|svg|ico|webp)$', r'\.(css|js|mjs)$', r'\.(woff2?|ttf|eot)$',
]

LEGIT_BROWSERS = [r'Mozilla/5\.0.*AppleWebKit.*Safari', r'Mozilla/5\.0.*Firefox/', r'Mozilla/5\.0.*Chrome/', r'Mozilla/5\.0.*Edg/']

CONTROL_CHAR_PATTERN = re.compile(r'[\x00-\x1f\x7f]|%00|%0[aAdD]|\.\./|\x00')

def is_whitelisted(path):
    return any(re.search(p, path, re.I) for p in WHITELIST_PATHS)

def is_legit_browser(ua):
    return any(re.search(p, ua) for p in LEGIT_BROWSERS)

ip_request_count = defaultdict(int)
ip_attempt_today = defaultdict(int)
ip_last_alert = {}
ALERT_THRESHOLD = 1
ALERT_COOLDOWN = 30
last_daily_reset = datetime.now().strftime("%Y-%m-%d")

REDACT_IPS = []
XOR_IPS = []
LIVE_FEED_FILE = "/var/www/html/api/scanner-feed.json"
MAX_FEED_ENTRIES = 30

def xor_encode(text, key=0x41):
    return ''.join(chr(ord(c) ^ key) if c.isalnum() else c for c in text)

def should_xor(ip):
    return any(ip.startswith(prefix) for prefix in XOR_IPS)

def should_redact(ip):
    return any(ip.startswith(prefix) for prefix in REDACT_IPS)

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
        if entry.get("blocked"):
            feed["stats"]["blocked"] = feed["stats"].get("blocked", 0) + 1
        feed["updated"] = datetime.now(timezone.utc).isoformat()
        with open(LIVE_FEED_FILE, 'w') as f:
            json.dump(feed, f)
    except Exception as e:
        print(f"[-] Feed write error: {e}")

def get_ip_info(ip):
    try:
        req = Request(f"http://ip-api.com/json/{ip}?fields=status,country,city,isp,org,as")
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
        for line in result.stdout.split('\n'):
            if 'abuse' in line.lower() and '@' in line:
                return line.strip()
    except:
        pass
    return None

def is_suspicious(path):
    return any(re.search(p, path.lower()) for p in SUSPICIOUS_PATTERNS)

def has_control_chars(s):
    return bool(CONTROL_CHAR_PATTERN.search(s))

def classify_threat(path, user_agent, headers):
    if is_whitelisted(path):
        return None, None
    if has_control_chars(path):
        return "suspicious", "Path traversal"
    ua_lower = user_agent.lower()
    scanners = [('sqlmap', 'SQLMap'), ('nikto', 'Nikto'), ('nmap', 'Nmap'), ('masscan', 'Masscan'), ('nuclei', 'Nuclei'), ('gobuster', 'Gobuster'), ('dirbuster', 'DirBuster'), ('wfuzz', 'WFuzz'), ('burp', 'Burp Suite'), ('zap', 'OWASP ZAP'), ('httpx', 'HTTPX'), ('zgrab', 'ZGrab'), ('censys', 'Censys')]
    for pattern, name in scanners:
        if pattern in ua_lower:
            return "scanner", f"{name} detected"
    bots = [('guzzle', 'PHP Guzzle'), ('go-http', 'Go HTTP'), ('python', 'Python script'), ('curl', 'cURL'), ('wget', 'wget')]
    for pattern, name in bots:
        if pattern in ua_lower:
            return "bot", name
    if user_agent == '-' or not user_agent:
        return "suspicious", "No User-Agent"
    if is_suspicious(path):
        return "scanner", "Suspicious path probe" if not is_legit_browser(user_agent) else "Suspicious path"
    if is_legit_browser(user_agent):
        return None, None
    return None, None

def parse_intel_line(line):
    pattern = r'^(\S+) - \S+ \[([^\]]+)\] "([^"]*)" (\d+) \d+ "([^"]*)" "([^"]*)" "([^"]*)" "([^"]*)" "([^"]*)" "([^"]*)" "([^"]*)" "([^"]*)" "([^"]*)"'
    match = re.match(pattern, line)
    if not match:
        return None
    ip, timestamp, request, status, referer, ua, lang, accept, cookie, auth, tls, xff, xrealip = match.groups()
    req_parts = request.split(' ')
    return {'ip': ip, 'timestamp': timestamp, 'method': req_parts[0] if req_parts else '-', 'path': req_parts[1] if len(req_parts) > 1 else '/', 'status': status, 'referer': referer, 'user_agent': ua, 'language': lang, 'accept': accept, 'cookie': cookie if cookie != '-' else None, 'authorization': auth if auth != '-' else None, 'tls': tls, 'xff': xff if xff != '-' else None, 'xrealip': xrealip if xrealip != '-' else None}

def send_alert(ip, intel_data, threat_type, threat_detail):
    global last_daily_reset
    ip_last_alert[ip] = time.time()
    today = datetime.now().strftime("%Y-%m-%d")
    if last_daily_reset != today:
        ip_attempt_today.clear()
        last_daily_reset = today
    ip_attempt_today[ip] += 1
    attempts = ip_attempt_today[ip]
    redacted = should_redact(ip)
    xor_it = should_xor(ip)
    path_display = intel_data.get('path', '/')[:80]
    ip_info = None

    if redacted:
        feed_entry = {"ip": "[REDACTED]", "type": threat_detail, "time": datetime.now().strftime("%H:%M:%S"), "country": "", "city": "", "isp": "", "path": path_display, "blocked": True}
    elif xor_it:
        ip_info = get_ip_info(ip)
        feed_entry = {"ip": f"XOR:{xor_encode(ip)}", "type": threat_detail, "time": datetime.now().strftime("%H:%M:%S"), "country": ip_info.get("country", "??") if ip_info else "??", "city": ip_info.get("city", "Unknown") if ip_info else "Unknown", "isp": "OWNER/INFRA", "path": path_display, "attempts": attempts, "blocked": False}
    else:
        ip_info = get_ip_info(ip)
        feed_entry = {"ip": ip, "type": threat_detail, "time": datetime.now().strftime("%H:%M:%S"), "country": ip_info.get("country", "??") if ip_info else "??", "city": ip_info.get("city", "Unknown") if ip_info else "Unknown", "isp": ip_info.get("isp", "Unknown") if ip_info else "Unknown", "asn": ip_info.get("as", "")[:30] if ip_info else "", "path": path_display, "ua": intel_data.get('user_agent', '-')[:80], "attempts": attempts, "blocked": threat_type in ("scanner", "suspicious")}
    update_live_feed(feed_entry)

    if not redacted:
        if ip_info is None:
            ip_info = get_ip_info(ip)
        abuse_contact = get_whois_abuse(ip)
    else:
        abuse_contact = None

    desc = f"**Type:** {threat_type}\n"
    desc += f"**IP:** `{'[REDACTED - Known Tester]' if redacted else ('XOR:' + xor_encode(ip) + ' (OWNER/INFRA)' if xor_it else ip)}`\n"
    desc += f"**Details:** {threat_detail}\n**Path:** `{intel_data.get('path', '/')}`\n**UA:** `{intel_data.get('user_agent', '-')[:60]}`\n"
    if not redacted and ip_info:
        desc += f"\n**Location:** {ip_info.get('city', '?')}, {ip_info.get('country', '?')}\n**ISP:** {ip_info.get('isp', '?')}\n**ASN:** {ip_info.get('as', '?')}\n"
    if abuse_contact:
        desc += f"**Abuse:** `{abuse_contact}`\n"

    emoji = {'scanner': '🔍', 'suspicious': '☠️', 'bot': '🤖', 'unknown': '❓'}
    msg = f"{emoji.get(threat_type, '⚠️')} **{threat_type.upper()}** | {threat_detail}\n{desc}"
    data = json.dumps({"content": msg[:2000]}).encode('utf-8')
    try:
        req = Request(DISCORD_WEBHOOK, data=data, headers={"Content-Type": "application/json", "User-Agent": "22div-sentinel/1.0"})
        urlopen(req, timeout=10)
        print(f"[+] Alert: {threat_type} from {ip} - {threat_detail}")
    except Exception as e:
        print(f"[-] Webhook error: {e}")

def watch_log():
    log_file = INTEL_LOG if os.path.exists(INTEL_LOG) else ACCESS_LOG
    use_intel = log_file == INTEL_LOG
    if not os.path.exists(log_file):
        print(f"[-] Log not found: {log_file}")
        return
    print(f"[*] Scanner Alert v4 watching {log_file}")
    with open(log_file, 'r') as f:
        f.seek(0, 2)
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.5)
                continue
            if use_intel:
                intel = parse_intel_line(line)
                if not intel:
                    continue
                ip, path, ua, status = intel['ip'], intel['path'], intel['user_agent'], intel['status']
                threat_type, threat_detail = classify_threat(path, ua, intel)
                if threat_type in ('scanner', 'suspicious', 'bot'):
                    ip_request_count[ip] += 1
                    if ip_request_count[ip] >= ALERT_THRESHOLD:
                        send_alert(ip, intel, threat_type, threat_detail)
                        ip_request_count[ip] = 0
                elif status in ('403', '404') and not is_whitelisted(path):
                    send_alert(ip, intel, 'scanner', f'Random {status} - {path[:50]}')
            else:
                match = re.match(r'(\S+) .* "(GET|POST|PUT|DELETE|HEAD|OPTIONS) ([^"]*)" (\d+)', line)
                if match:
                    ip, method, path, status = match.groups()
                    if status in ('403', '404') and is_suspicious(path):
                        ip_request_count[ip] += 1
                        if ip_request_count[ip] == ALERT_THRESHOLD:
                            send_alert(ip, {'path': path, 'user_agent': '-'}, 'scanner', 'Suspicious path')

if __name__ == "__main__":
    print("[*] Scanner Alert v4 starting...")
    watch_log()
