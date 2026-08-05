#!/bin/bash
# Removes Mabure: daemon, agent, plists, binaries, config. Log files are kept
# by default (pass --purge-logs to delete them too). Idempotent and safe to
# interrupt at any point — `disable` runs first, before any bootout/rm, so a
# partial run can never leave the services able to auto-resurrect at the
# next boot/login.
set -euo pipefail
cd "$(dirname "$0")"

if [[ $EUID -ne 0 ]]; then
    echo "Re-running with sudo..."
    exec sudo "$0" "$@"
fi

PURGE_LOGS=false
[[ "${1:-}" == "--purge-logs" ]] && PURGE_LOGS=true

echo "==> Disabling services (prevents auto-restart even if this script is interrupted below)"
launchctl disable system/com.mabure.daemon 2>/dev/null || true
for uid in $(ps -Ac -o uid,command | awk '$2=="loginwindow"{print $1}' | sort -u); do
    launchctl disable "gui/$uid/com.mabure.agent" 2>/dev/null || true
done

echo "==> Stopping services"
launchctl bootout system/com.mabure.daemon 2>/dev/null || true
for uid in $(ps -Ac -o uid,command | awk '$2=="loginwindow"{print $1}' | sort -u); do
    launchctl bootout "gui/$uid/com.mabure.agent" 2>/dev/null || true
done

echo "==> Removing plists"
rm -f /Library/LaunchDaemons/com.mabure.daemon.plist /Library/LaunchAgents/com.mabure.agent.plist

echo "==> Killing any stragglers by resolved path"
pkill -f /usr/local/libexec/mabure/mabured 2>/dev/null || true
pkill -f /Applications/Mabure.app/Contents/MacOS/Mabure 2>/dev/null || true

echo "==> Removing binaries and config"
rm -rf /usr/local/libexec/mabure
rm -rf /Applications/Mabure.app
rm -f /etc/newsyslog.d/mabure.conf
rm -rf "/Library/Application Support/Mabure"

if $PURGE_LOGS; then
    echo "==> Purging logs (--purge-logs)"
    rm -rf /Library/Logs/Mabure /var/log/mabure
else
    echo "==> Keeping logs at /Library/Logs/Mabure and /var/log/mabure (pass --purge-logs to delete)"
fi

echo ""
echo "==> Optional manual step: reset the notification permission Mabure was granted:"
echo "      sudo tccutil reset Notifications com.mabure.agent"
echo ""
echo "==> Self-check (both should be empty):"
launchctl list 2>/dev/null | grep -i mabure && echo "    WARNING: still loaded" || echo "    launchctl: clean"
ps aux | grep -i mabure | grep -v grep && echo "    WARNING: still running" || echo "    ps: clean"
