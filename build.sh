#!/bin/bash
# Пересобирает бинарь touchpass и app-бандл TouchPass.app.
# Бандл нужен для стабильной идентичности (Touch ID / Keychain / статус-бар).
set -euo pipefail
cd "$(dirname "$0")"

# Version lives in VERSION (MAJOR.MINOR.PATCH) and goes into the bundle's
# Info.plist. A new VERSION pushed to the public mirror triggers a CI release
# that every installed copy auto-updates to, so bumping is deliberate:
# plain ./build.sh builds the version as-is; ./build.sh --bump increments PATCH.
if [ "${1:-}" = "--bump" ]; then
    PREV="$(tr -d '[:space:]' < VERSION)"
    MAJOR="${PREV%%.*}"
    MINOR="$(echo "$PREV" | cut -d. -f2)"
    PATCH="$(echo "$PREV" | cut -d. -f3)"
    VERSION="$MAJOR.$MINOR.$((PATCH + 1))"
    printf '%s\n' "$VERSION" > VERSION
else
    VERSION="$(tr -d '[:space:]' < VERSION)"
fi

echo "==> Компиляция touchpass $VERSION (swift build)..."
swift build -c release
BIN=".build/release/touchpass"

echo "==> Сборка TouchPass.app..."
APP="TouchPass.app"
rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"
sed "s|__VERSION__|$VERSION|g" assets/Info.plist > "$APP/Contents/Info.plist"
cp "$BIN" "$APP/Contents/MacOS/touchpass"
cp assets/AppIcon.icns "$APP/Contents/Resources/AppIcon.icns"

# Signing. With the ARSIDIAN Developer ID certificate in the keychain and the
# provisioning profile in assets/, the bundle is signed by the team: a stable
# identity, so Accessibility / Screen Recording grants and Keychain access
# survive updates, and the 2FA items can live in iCloud Keychain. Without them
# (another machine, CI) it falls back to the old ad-hoc signature, with no
# entitlements — restricted entitlements without a profile would kill the app.
TEAM_ID="K8ZZA5DA72"
PROFILE="assets/TouchPass.provisionprofile"
IDENTITY="$(security find-identity -v -p codesigning 2>/dev/null \
    | sed -n "s/.*\"\(Developer ID Application: .*($TEAM_ID)\)\"/\1/p" | head -1)"
if [ -n "$IDENTITY" ] && [ -f "$PROFILE" ] && [ "${TOUCHPASS_ADHOC:-}" != "1" ]; then
    echo "==> Signing with $IDENTITY"
    cp "$PROFILE" "$APP/Contents/embedded.provisionprofile"
    codesign --force --options runtime --timestamp \
        --entitlements assets/TouchPass.entitlements --sign "$IDENTITY" "$APP"
    codesign --verify --strict "$APP"
else
    echo "==> Ad-hoc signature (no Developer ID certificate or profile here)"
    codesign --force --sign - "$APP" 2>/dev/null || echo "⚠️ codesign failed (not critical)"
fi

echo "==> Готово: $(pwd)/$APP (версия $VERSION)"
echo "    Настройка (GUI): ./$APP/Contents/MacOS/touchpass"
