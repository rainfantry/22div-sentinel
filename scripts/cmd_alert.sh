#!/bin/bash
# Command Alert - logs critical commands to Discord
# Source this in .bashrc with: source /opt/22div-sentinel/cmd_alert.sh

# === CONFIGURE THIS ===
WEBHOOK="YOUR_DISCORD_WEBHOOK_URL"

CRITICAL_PATTERNS="^sudo |^rm |^wget |^curl |^nc |^ncat |^netcat |^scp |^rsync |^chmod |^chown |^useradd |^userdel |^passwd|^ssh-keygen|^iptables |^ufw |^systemctl |^python|^perl|^ruby|^node |^php |base64|/etc/passwd|/etc/shadow|\.ssh/|^crontab|^nohup |^screen |^tmux |^pkill |^killall |^mkfifo|/dev/tcp|/dev/udp|^cat |^nano |^vim |^vi |^touch |^mkdir |^cp |^mv |^echo .*>|^tee |^dd |^tar |^zip |^unzip |^gzip |^gunzip |^head |^tail |^grep |^find |^which |^whoami|^id$|^id |^w$|^who|^last|^history|^export |^source |^eval |^exec |^git |^docker |^kubectl |^apt |^apt-get |^dpkg |^pip |^npm |^service |^journalctl |^dmesg|^mount |^umount |^fdisk |^lsblk|^ss |^netstat |^ip |^ifconfig |^tcpdump |^nmap |^masscan "

send_alert() {
    local title="$1"
    local desc="$2"
    local color="$3"
    local payload=$(cat <<EOF
{"embeds": [{"title": "$title", "description": "$desc", "color": $color, "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)", "footer": {"text": "22div-sentinel • CMD Monitor"}}]}
EOF
)
    (curl -s -X POST -H "Content-Type: application/json" -d "$payload" "$WEBHOOK" >/dev/null 2>&1 &) 2>/dev/null
}

session_alert() {
    local user=$(whoami)
    local tty=$(tty 2>/dev/null | sed 's|/dev/||')
    local ip="${SSH_CLIENT%% *}"
    [[ -z "$ip" ]] && ip="local"
    send_alert "🖥️ Shell Session Started" "**User:** \`$user\`\n**TTY:** \`$tty\`\n**From:** \`$ip\`\n**Host:** \`$(hostname)\`" 3447003
}

cmd_alert() {
    local cmd="$1"
    local user=$(whoami)
    local ip="${SSH_CLIENT%% *}"
    [[ -z "$ip" ]] && ip="local"
    cmd=$(echo "$cmd" | sed 's/\\/\\\\/g; s/"/\\"/g; s/`/\\`/g' | head -c 500)
    send_alert "⚠️ Critical Command" "**User:** \`$user\`\n**From:** \`$ip\`\n**PWD:** \`$(pwd)\`\n**Command:**\n\`\`\`bash\n$cmd\n\`\`\`" 16744256
}

check_cmd() {
    local cmd="$1"
    echo "$cmd" | grep -qiE "$CRITICAL_PATTERNS" && cmd_alert "$cmd"
}

export -f send_alert cmd_alert check_cmd
export WEBHOOK CRITICAL_PATTERNS
