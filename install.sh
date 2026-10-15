#!/bin/bash
# Собирает TouchPass.app и ставит его как LaunchAgent (автозапуск при логине).
# ЗАПУСКАТЬ НА ТОМ Mac, к чьему датчику Touch ID прикладываешь палец.
set -euo pipefail
cd "$(dirname "$0")"

LABEL="com.arsidian.touchpass"
APP_SRC="$(pwd)/TouchPass.app"
APP_DST="$HOME/Applications/TouchPass.app"
BIN_DST="$APP_DST/Contents/MacOS/touchpass"
BIN_LINK="$HOME/.local/bin/touchpass"
PLIST_DST="$HOME/Library/LaunchAgents/${LABEL}.plist"
UID_NUM="$(id -u)"

if [ ! -d "$APP_SRC" ] || [ ! -x "$APP_SRC/Contents/MacOS/touchpass" ]; then
    echo "==> Бандл не найден, собираю..."
    ./build.sh
fi

echo "==> Устанавливаю $APP_DST"
mkdir -p "$HOME/Applications"
rm -rf "$APP_DST"
cp -R "$APP_SRC" "$APP_DST"

LSREGISTER="/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister"
[ -x "$LSREGISTER" ] && "$LSREGISTER" -f "$APP_DST" || true

echo "==> Симлинк для CLI: $BIN_LINK"
mkdir -p "$(dirname "$BIN_LINK")"
ln -sf "$BIN_DST" "$BIN_LINK"

echo "==> Устанавливаю LaunchAgent в $PLIST_DST"
mkdir -p "$(dirname "$PLIST_DST")"
mkdir -p "$HOME/Library/Logs"
sed -e "s|__TOUCHPASS_BIN__|$BIN_DST|g" \
    -e "s|__TOUCHPASS_LOGS__|$HOME/Library/Logs|g" \
    com.arsidian.touchpass.plist > "$PLIST_DST"

echo "==> Загружаю агент..."
launchctl bootout "gui/$UID_NUM/$LABEL" 2>/dev/null || true
sleep 1
launchctl bootstrap "gui/$UID_NUM" "$PLIST_DST"

echo ""
echo "Готово. TouchPass работает и стартует при входе."
echo "  Если пароль ещё не сохранён — окно настроек откроется само;"
echo "  открыть настройки вручную: touchpass  (или пункт «Настройки…» в меню-баре)."
echo "  Статус:  touchpass --status"
echo "  Логи:    tail -f \$HOME/Library/Logs/touchpass.err.log"
echo "  Права:   Настройки → Конфиденциальность → Универсальный доступ → добавить TouchPass"
echo "  Удалить: ./uninstall.sh"
