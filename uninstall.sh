#!/bin/bash
# Останавливает и удаляет LaunchAgent и TouchPass.app.
set -euo pipefail
LABEL="com.arsidian.touchpass"
PLIST_DST="$HOME/Library/LaunchAgents/${LABEL}.plist"
APP_DST="$HOME/Applications/TouchPass.app"
BIN_LINK="$HOME/.local/bin/touchpass"
UID_NUM="$(id -u)"

launchctl bootout "gui/$UID_NUM/$LABEL" 2>/dev/null || true
rm -f "$PLIST_DST" "$BIN_LINK"
rm -rf "$APP_DST"
echo "TouchPass удалён (приложение, симлинк, LaunchAgent)."
echo "Пароль в Keychain (service com.arsidian.touchpass) оставлен."
echo "  Полностью убрать пароль: security delete-generic-password -s com.arsidian.touchpass"
