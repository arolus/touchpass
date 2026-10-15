#!/bin/bash
# Builds, signs (ARSIDIAN Developer ID), notarizes and publishes TouchPass as a
# GitHub Release of the public mirror arolus/touchpass — what every installed
# copy auto-updates to. Runs on the maintainer's Mac: the certificate and the
# App Store Connect key stay there, never in CI.
#
#   ./build.sh --bump        # or edit VERSION by hand
#   git commit + push        # publish-touchpass mirrors the source
#   ./release.sh             # waits for the mirror to show VERSION, then releases
#
# Needs: the "Developer ID Application: … (K8ZZA5DA72)" identity in the login
# keychain, assets/TouchPass.provisionprofile, the App Store Connect API key
# used by ~/.appstoreconnect/asc.js (for notarytool), and `gh` logged in as arolus.
set -euo pipefail
cd "$(dirname "$0")"

REPO="arolus/touchpass"
TEAM_ID="K8ZZA5DA72"
VERSION="$(tr -d '[:space:]' < VERSION)"
ZIP="TouchPass.app.zip"
ASC="$HOME/.appstoreconnect/asc.js"

die() { echo "release: $*" >&2; exit 1; }

if gh release view "v$VERSION" --repo "$REPO" >/dev/null 2>&1; then
    die "v$VERSION is already released — bump VERSION first (./build.sh --bump)."
fi

./build.sh
TEAM="$(codesign -dv TouchPass.app 2>&1 | sed -n 's/^TeamIdentifier=//p')"
[ "$TEAM" = "$TEAM_ID" ] || die "TouchPass.app is not signed by $TEAM_ID (got '${TEAM:-ad-hoc}') — a release must be."

echo "==> Notarizing $VERSION…"
KEY_ID="$(sed -n 's/^const KEY_ID = "\(.*\)";/\1/p' "$ASC")"
ISSUER="$(sed -n 's/^const ISSUER = "\(.*\)";/\1/p' "$ASC")"
KEY="$HOME/.appstoreconnect/private_keys/AuthKey_$KEY_ID.p8"
[ -n "$KEY_ID" ] && [ -n "$ISSUER" ] && [ -f "$KEY" ] || die "no App Store Connect API key (see $ASC)."
rm -f "$ZIP"
ditto -c -k --keepParent TouchPass.app "$ZIP"
xcrun notarytool submit "$ZIP" --key "$KEY" --key-id "$KEY_ID" --issuer "$ISSUER" --wait
xcrun stapler staple TouchPass.app
spctl -a -t exec -vv TouchPass.app
rm -f "$ZIP"
ditto -c -k --keepParent TouchPass.app "$ZIP"

# The tag should point at the source of this version: wait for the mirror.
echo "==> Waiting for $REPO to show VERSION $VERSION…"
for _ in $(seq 1 30); do
    REMOTE="$(gh api "repos/$REPO/contents/VERSION" --jq .content 2>/dev/null | base64 -d 2>/dev/null | tr -d '[:space:]' || true)"
    [ "$REMOTE" = "$VERSION" ] && break
    sleep 10
done
[ "$REMOTE" = "$VERSION" ] || die "the mirror has VERSION '${REMOTE:-?}', not $VERSION — push dotfiles and retry."

gh release create "v$VERSION" "$ZIP" --repo "$REPO" --target main \
    --title "TouchPass $VERSION" \
    --notes "Signed with the ARSIDIAN Developer ID and notarized. Unzip and run, or let the in-app updater install it."
rm -f "$ZIP"
echo "==> Released https://github.com/$REPO/releases/tag/v$VERSION"
