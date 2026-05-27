#!/bin/sh
# Build a DMG containing the signed .app with the conventional
# "drag to Applications" layout.
#
# Two implementations: `create-dmg` (Homebrew) if available, plain hdiutil
# otherwise. The hdiutil fallback produces a usable but visually plainer DMG
# (no background image, no positioned icons).
#
# Usage:
#   ./create-dmg.sh path/to/SSH\ Keychain.app [output.dmg]
set -eu

if [ "$#" -lt 1 ]; then
  echo "usage: $0 path/to/SSH\\ Keychain.app [output.dmg]" >&2
  exit 1
fi

APP="$1"
if [ ! -d "$APP" ]; then
  echo "$APP: not a directory" >&2
  exit 1
fi

VERSION=$(plutil -extract CFBundleShortVersionString raw "$APP/Contents/Info.plist")
DEFAULT_OUTPUT="$(dirname "$APP")/SSH-Keychain-$VERSION.dmg"
OUTPUT="${2:-$DEFAULT_OUTPUT}"

# create-dmg gives us a nice Mac-conventional layout (icons positioned, an
# /Applications shortcut, a background image if we ever ship one).
if command -v create-dmg >/dev/null 2>&1; then
  echo "==> create-dmg (Homebrew)"
  rm -f "$OUTPUT"
  create-dmg \
    --volname "SSH Keychain $VERSION" \
    --window-pos 200 120 \
    --window-size 600 360 \
    --icon-size 96 \
    --icon "SSH Keychain.app" 150 180 \
    --app-drop-link 450 180 \
    --no-internet-enable \
    "$OUTPUT" \
    "$APP"
else
  echo "==> hdiutil fallback (install create-dmg via 'brew install create-dmg' for a nicer layout)"
  STAGING="$(mktemp -d)"
  cp -R "$APP" "$STAGING/"
  ln -s /Applications "$STAGING/Applications"
  rm -f "$OUTPUT"
  hdiutil create \
    -volname "SSH Keychain $VERSION" \
    -srcfolder "$STAGING" \
    -ov \
    -format UDZO \
    "$OUTPUT"
  rm -rf "$STAGING"
fi

echo "==> wrote $OUTPUT"
echo "==> next: ./notarize.sh \"$OUTPUT\""
