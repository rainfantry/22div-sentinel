# 22div-sentinel

Real-time security monitoring for Linux servers. Get instant Discord alerts when someone attacks your infrastructure.

![SSH](https://img.shields.io/badge/SSH-Bruteforce_Detection-red)
![Scanner](https://img.shields.io/badge/Web-Scanner_Detection-orange)
![C2](https://img.shields.io/badge/Outbound-C2_Detection-purple)
![Shell](https://img.shields.io/badge/Reverse-Shell_Detection-critical)
![License](https://img.shields.io/badge/License-MIT-green)

## What It Does

| Monitor | Detects | Alert Contains |
|---------|---------|----------------|
| **SSH Alert** | Failed logins, bruteforce, successful auth | IP, geo, username, ISP, ASN, abuse contact |
| **Scanner Alert** | 403/404 probes, path traversal, SQLi attempts | Full request, headers, user-agent, TLS info |
| **Connection Monitor** | Reverse shells, C2 callbacks, suspicious outbound | Process, PID, destination, cmdline, user |
| **Exfil Watch** | Connections to known attacker IPs/domains | Connection details, packet capture |
| **Command Logger** | Every command typed on server | User, TTY, working dir, full command |
| **Session Record** | Full TTY capture for forensics | Playback-ready log file |

## Screenshots

**SSH Bruteforce Alert:**
```
🔐 SSH BRUTEFORCE | Failed password

IP: 45.142.120.xxx
Username: root
Failed attempts: 47

Location: St Petersburg, Russia
ISP: SELECTEL-MSK
ASN: AS49505
Abuse: abuse@selectel.ru
```

**Reverse Shell Detected:**
```
🚨 REVERSE SHELL DETECTED

Destination: 10.10.14.50:4444
Local: 192.168.1.100:54321

Process: bash (PID: 12345)
User: www-data
Cmdline: /bin/bash -i

Target Location: Attacker City, Country
Target ISP: Attacker ISP

👁️ WATCH LIVE:
strace -p 12345 -e read,write -s 9999
```

**Web Scanner Detected:**
```
🔍 SCANNER | Nuclei scanner

IP: 185.220.101.xxx
Path: /.env
UA: Mozilla/5.0 (compatible; Nuclei)

Location: Amsterdam, Netherlands
ISP: TOR Exit Node
```

## Quick Install

```bash
git clone https://github.com/rainfantry/22div-sentinel.git
cd 22div-sentinel
chmod +x setup.sh
sudo ./setup.sh
```

The setup script will:
1. Prompt for your Discord webhook URLs
2. Install scripts to `/opt/22div-sentinel/`
3. Create and enable systemd services
4. Set up command logging via profile.d
5. Configure SSH session recording

## Manual Install

1. Copy scripts to `/opt/22div-sentinel/`
2. Edit each script and replace `YOUR_DISCORD_WEBHOOK_URL` with your webhook
3. Copy service files to `/etc/systemd/system/`
4. Enable services:

```bash
systemctl daemon-reload
systemctl enable --now ssh-alert scanner-alert conn-alert exfil-watch
```

## Configuration

### Whitelist Your IPs

Edit `conn_alert.py` and `ssh_alert.py`:
```python
# IPs that won't trigger alerts
XOR_IPS = [
    'YOUR_HOME_IP_PREFIX.',     # e.g. '192.168.1.'
    'YOUR_SERVER_IP_PREFIX.',   # e.g. '10.0.0.'
]

# IPs shown as [REDACTED] in logs
REDACT_IPS = [
    'YOUR_TESTER_IP_PREFIX.',
]
```

### Scanner Whitelist

Edit `scanner_alert.py` to add legitimate paths:
```python
WHITELIST_PATHS = [
    r'^/your-app/',
    r'^/api/health',
]
```

### Attacker Watchlist

Edit `exfil_watch.py` to add known C2 infrastructure:
```python
WATCHLIST_DOMAINS = [
    "attacker-c2.example.com",
]

WATCHLIST_IPS = [
    "1.2.3.4",
]
```

## Live Feed (Optional)

The scripts can write to a JSON file for a web dashboard:

```python
LIVE_FEED_FILE = "/var/www/html/api/scanner-feed.json"
```

Set to `None` to disable.

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                      YOUR SERVER                            │
├─────────────────────────────────────────────────────────────┤
│  /var/log/auth.log ────────→ ssh_alert.py ────→ Discord    │
│  /var/log/nginx/*.log ─────→ scanner_alert.py ─→ Discord   │
│  /proc/net/tcp (poll) ─────→ conn_alert.py ────→ Discord   │
│  ss -tunp (poll) ──────────→ exfil_watch.py ───→ Discord   │
│  PROMPT_COMMAND ───────────→ cmd_alert.sh ─────→ Discord   │
│  ForceCommand script ──────→ session logs ─────→ /var/log  │
└─────────────────────────────────────────────────────────────┘
```

## Requirements

- Python 3.8+
- systemd
- Linux (tested on Ubuntu 22.04, Debian 12)
- nginx (for scanner alerts)
- `whois` command (for abuse contact lookup)

## Use Cases

- **Honeypot operators** - Watch attackers in real-time
- **Blue team / SOC** - Get instant alerts on compromise indicators
- **Red team** - Learn what defenders see
- **DevOps** - Know when your servers are being probed
- **CTF infrastructure** - Monitor challenge boxes
- **VPS security** - Catch bruteforce before it succeeds

## Managed Service

Don't want to run it yourself?

- **Web Dashboard** - Visualize attacks across all your servers
- **API Access** - Query attack data programmatically
- **Multi-server** - One view for your entire fleet
- **SIEM Export** - Send to Splunk, Elastic, etc.

**Contact:** contact@22div.com.au

## Contributing

PRs welcome:
- [ ] Slack integration
- [ ] Telegram integration
- [ ] REST API endpoint
- [ ] Elasticsearch export
- [ ] Windows Event Log support

## Credits

Built by [22nd Survey Division](https://22div.com.au) - Security research & pentesting from Sydney, Australia.

## License

MIT
