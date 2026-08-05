#!/bin/bash
# Installs Mabure system-wide: a root LaunchDaemon (mabured) that detects and
# kills `node -e`/`--eval` processes for every user, and a per-user
# LaunchAgent (Mabure.app) that shows a menu-bar dropdown + notifications.
#
# Idempotent — safe to re-run (e.g. after an upgrade). Requires sudo.
set -euo pipefail
cd "$(dirname "$0")"

if [[ $EUID -ne 0 ]]; then
    echo "Re-running with sudo (this installs root-owned files/services)..."
    exec sudo "$0" "$@"
fi

# The user who invoked sudo, not root — needed for group membership and for
# loading the agent into their current GUI session.
REAL_USER="${SUDO_USER:-$(stat -f%Su /dev/console)}"

# A downloaded release ships prebuilt universal2 binaries (see
# .github/workflows/release.yml) marked with build/.prebuilt, so installing
# from a release zip doesn't require Xcode/Swift on the target Mac at all.
# Deliberately gated on that marker file (not just "binaries already
# exist") so a local source checkout's `sudo ./install.sh` always rebuilds
# by default, same as before this existed — pass --rebuild to force
# building from source even when a release's prebuilt marker is present.
FORCE_REBUILD=false
[[ "${1:-}" == "--rebuild" ]] && FORCE_REBUILD=true

if ! $FORCE_REBUILD && [[ -f build/.prebuilt && -x build/mabured && -d build/Mabure.app ]]; then
    echo "==> Using prebuilt binaries from this release (pass --rebuild to build from source instead)"
else
    echo "==> Building from source"
    sudo -u "$REAL_USER" ./build.sh
fi

echo "==> Removing quarantine attribute (defensive, in case build artifacts were copied between Macs)"
xattr -dr com.apple.quarantine build 2>/dev/null || true

echo "==> Ad-hoc code-signing"
codesign --force --sign - --identifier com.mabure.agent build/Mabure.app
codesign --force --sign - --identifier com.mabure.daemon build/mabured

echo "==> Creating _mabure group (for passwordless pause/resume access)"
dseditgroup -o create -q _mabure 2>/dev/null || true
dseditgroup -o edit -a "$REAL_USER" -t user _mabure 2>/dev/null || true

echo "==> Creating directories"
install -d -o root -g wheel -m 755 /usr/local/libexec/mabure /var/log/mabure
install -d -o root -g wheel -m 755 "/Library/Logs/Mabure"
install -d -o root -g wheel -m 700 "/Library/Logs/Mabure/git-guard-backups"
install -d -o root -g _mabure -m 2775 "/Library/Application Support/Mabure/control"

echo "==> Installing binaries"
install -o root -g wheel -m 755 build/mabured /usr/local/libexec/mabure/mabured
rm -rf /Applications/Mabure.app
cp -R build/Mabure.app /Applications/
chown -R root:wheel /Applications/Mabure.app

echo "==> Seeding log files (correct ownership/permissions; daemon also self-enforces on open)"
for f in "/Library/Logs/Mabure/events.full.jsonl:600" "/Library/Logs/Mabure/events.jsonl:644"; do
    path="${f%%:*}"; mode="${f##*:}"
    [[ -f "$path" ]] || touch "$path"
    chown root:wheel "$path"
    chmod "$mode" "$path"
done

echo "==> Installing config (only if not already present — preserves tuning across upgrades)"
CONFIG_DIR="/Library/Application Support/Mabure"
[[ -f "$CONFIG_DIR/config.json" ]] || install -o root -g wheel -m 644 Config/default-config.json "$CONFIG_DIR/config.json"
[[ -f "$CONFIG_DIR/allowlist.json" ]] || install -o root -g wheel -m 600 Config/default-allowlist.json "$CONFIG_DIR/allowlist.json"

echo "==> Installing launchd plists"
install -o root -g wheel -m 644 Resources/launchd/com.mabure.daemon.plist /Library/LaunchDaemons/com.mabure.daemon.plist
install -o root -g wheel -m 644 Resources/launchd/com.mabure.agent.plist /Library/LaunchAgents/com.mabure.agent.plist

echo "==> Installing log rotation config"
install -o root -g wheel -m 644 Resources/newsyslog/mabure.conf /etc/newsyslog.d/mabure.conf

echo "==> Loading the daemon (bootout-before-bootstrap so re-running this script is always safe)"
launchctl bootout system/com.mabure.daemon 2>/dev/null || true
launchctl enable system/com.mabure.daemon
launchctl bootstrap system /Library/LaunchDaemons/com.mabure.daemon.plist

echo "==> Loading the agent for every currently active GUI session"
for uid in $(ps -Ac -o uid,command | awk '$2=="loginwindow"{print $1}' | sort -u); do
    launchctl bootout "gui/$uid/com.mabure.agent" 2>/dev/null || true
    launchctl enable "gui/$uid/com.mabure.agent"
    launchctl bootstrap "gui/$uid" /Library/LaunchAgents/com.mabure.agent.plist 2>/dev/null || true
done

echo ""
echo "==> Install complete."
launchctl print system/com.mabure.daemon >/dev/null 2>&1 && echo "    daemon: loaded" || echo "    daemon: NOT loaded (check the command above for errors)"
echo ""
echo "IMPORTANT:"
echo "  - '$REAL_USER' was just added to the _mabure group, but macOS caches group"
echo "    membership in your login session's credential. The Pause/Resume menu item"
echo "    will NOT work until you log out and back in (or open a fresh terminal for"
echo "    command-line use). This is expected on first install, not a bug."
echo "  - System Settings > Login Items & Extensions may show a 'Background Items"
echo "    Added' banner for Mabure. That's expected."
echo "  - Config: kill_enabled=true, dry_run=false (default). Edit"
echo "    '$CONFIG_DIR/config.json' to tune, or set dry_run=true to trial it first."
