#!/bin/bash
#
# 22div-sentinel setup script
# Installs real-time security monitoring with Discord webhooks
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INSTALL_DIR="/opt/22div-sentinel"

echo "╔══════════════════════════════════════════════════════════════╗"
echo "║              22div-sentinel Installation                     ║"
echo "║          Real-time Security Monitoring for VPS               ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""

if [[ $EUID -ne 0 ]]; then
    echo "[-] This script must be run as root"
    exit 1
fi

echo "[*] Create Discord webhooks: Server Settings > Integrations > Webhooks"
echo ""
read -p "Discord Webhook URL: " WEBHOOK_MAIN
[[ -z "$WEBHOOK_MAIN" ]] && { echo "[-] Webhook required"; exit 1; }

echo ""
echo "[*] Installing to $INSTALL_DIR..."

mkdir -p "$INSTALL_DIR" /var/log/sessions /var/log/exfil_captures
chmod 700 /var/log/sessions

cp "$SCRIPT_DIR/scripts/"*.py "$INSTALL_DIR/" 2>/dev/null || true
cp "$SCRIPT_DIR/scripts/"*.sh "$INSTALL_DIR/" 2>/dev/null || true
chmod +x "$INSTALL_DIR/"* 2>/dev/null || true

sed -i "s|YOUR_DISCORD_WEBHOOK_URL|$WEBHOOK_MAIN|g" "$INSTALL_DIR/"*.py "$INSTALL_DIR/"*.sh 2>/dev/null || true

echo "[+] Scripts installed"

for svc in ssh-alert scanner-alert conn-alert exfil-watch; do
    script="${svc//-/_}.py"
    [[ "$svc" == "exfil-watch" ]] && script="exfil_watch.py"
    cat > "/etc/systemd/system/${svc}.service" << EOF
[Unit]
Description=22div-sentinel ${svc}
After=network.target

[Service]
Type=simple
Environment=PYTHONUNBUFFERED=1
ExecStart=/usr/bin/python3 -u $INSTALL_DIR/$script
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
done

echo "[+] Systemd services created"

cat > /etc/profile.d/sentinel-cmd.sh << 'PROFILE'
#!/bin/bash
[[ $- != *i* ]] && return
source /opt/22div-sentinel/cmd_alert.sh 2>/dev/null || return
if [[ -z "$SENTINEL_LOADED" ]]; then
    export SENTINEL_LOADED=1
    session_alert
fi
_sentinel_monitor() {
    local last_cmd=$(history 1 | sed 's/^[ ]*[0-9]*[ ]*//')
    [[ -n "$last_cmd" && "$last_cmd" != "$_LAST_CMD" ]] && { export _LAST_CMD="$last_cmd"; check_cmd "$last_cmd"; }
}
PROMPT_COMMAND="_sentinel_monitor${PROMPT_COMMAND:+; $PROMPT_COMMAND}"
PROFILE
chmod +x /etc/profile.d/sentinel-cmd.sh
echo "[+] Command monitor installed"

cat > /usr/local/bin/sentinel-session.sh << 'WRAPPER'
#!/bin/bash
SESSION_FILE="/var/log/sessions/$(date +%Y%m%d_%H%M%S)_${USER}_${SSH_CLIENT%% *}.log"
echo "[*] Session recorded: $SESSION_FILE"
exec /usr/bin/script -q -f "$SESSION_FILE" -c "/bin/bash -l"
WRAPPER
chmod +x /usr/local/bin/sentinel-session.sh
echo "[+] Session wrapper installed"

systemctl daemon-reload
systemctl enable ssh-alert scanner-alert conn-alert exfil-watch 2>/dev/null
systemctl start ssh-alert scanner-alert conn-alert exfil-watch 2>/dev/null

echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║                  Installation Complete!                      ║"
echo "╠══════════════════════════════════════════════════════════════╣"
echo "║  Services:                                                   ║"
echo "║    • ssh-alert      - SSH login/bruteforce alerts            ║"
echo "║    • scanner-alert  - Web scanner detection                  ║"
echo "║    • conn-alert     - Reverse shell/C2 detection             ║"
echo "║    • exfil-watch    - Attacker C2 watchlist                  ║"
echo "║    • cmd monitor    - Command logging (profile.d)            ║"
echo "║                                                              ║"
echo "║  Optional: Add ForceCommand to /etc/ssh/sshd_config:         ║"
echo "║    ForceCommand /usr/local/bin/sentinel-session.sh           ║"
echo "║                                                              ║"
echo "║  Test: SSH in again to see alerts in Discord                 ║"
echo "╚══════════════════════════════════════════════════════════════╝"
