#!/bin/sh
# One-shot release pipeline: archive + sign + notarize + dmg + sign appcast.
#
# Run this once you've already done the one-time setup:
#   1. Stored notary credentials in keychain:
#        xcrun notarytool store-credentials NOTARY_PROFILE ...
#   2. Generated Sparkle's signing keypair:
#        ./Distribution/generate-sparkle-keys.sh
#      and pasted the public key into SSHKeychainApp/project.yml.
#   3. Set TEAM_ID and NOTARY_PROFILE in your environment.
#
# Usage:
#   TEAM_ID=ABCDEF1234 NOTARY_PROFILE=ssh-keychain ./release.sh
set -eu

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BUILD_DIR="${BUILD_DIR:-$ROOT/build}"

: "${TEAM_ID:?TEAM_ID env var required (see codesign-and-archive.sh)}"
: "${NOTARY_PROFILE:?NOTARY_PROFILE env var required (see notarize.sh)}"

echo "==> [1/4] codesign + archive"
"$ROOT/Distribution/codesign-and-archive.sh"

APP="$BUILD_DIR/Export/SSH Keychain.app"

echo "==> [2/4] notarize app"
"$ROOT/Distribution/notarize.sh" "$APP"

echo "==> [3/4] create DMG"
VERSION=$(plutil -extract CFBundleShortVersionString raw "$APP/Contents/Info.plist")
DMG="$BUILD_DIR/SSH-Keychain-$VERSION.dmg"
"$ROOT/Distribution/create-dmg.sh" "$APP" "$DMG"

echo "==> [4/4] notarize DMG (so first-launch from the DMG works offline)"
"$ROOT/Distribution/notarize.sh" "$DMG"

echo
echo "==> Sparkle appcast fragment"
"$ROOT/Distribution/sign-update.sh" "$DMG"

cat <<EOF

Done.

Next steps:
  1. Upload $DMG to GitHub Releases under tag v$VERSION.
  2. Take the sparkle:edSignature + length above, paste into
     Distribution/appcast.xml.template with the other tokens filled in,
     and publish the result to the SUFeedURL host.
  3. Tag the release in git:
       git tag -a v$VERSION -m "Release v$VERSION"
       git push origin v$VERSION
EOF
