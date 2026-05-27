#!/bin/sh
# Sign a built DMG with the Sparkle EdDSA private key (from macOS Keychain)
# and emit the appcast XML fragment to embed in the published feed.
#
# Usage:
#   ./sign-update.sh path/to/SSH-Keychain-X.Y.Z.dmg
set -eu

if [ "$#" -ne 1 ]; then
  echo "usage: $0 path/to/SSH-Keychain-X.Y.Z.dmg" >&2
  exit 1
fi

DMG="$1"
if [ ! -f "$DMG" ]; then
  echo "$DMG: not a file" >&2
  exit 1
fi

SPARKLE_BIN="${SPARKLE_BIN:-}"
if [ -z "$SPARKLE_BIN" ]; then
  candidate=$(find "$HOME/Library/Developer/Xcode/DerivedData" \
    -type f -name 'sign_update' -path '*/artifacts/*' 2>/dev/null \
    | head -1)
  if [ -n "$candidate" ]; then
    SPARKLE_BIN="$(dirname "$candidate")"
  fi
fi

if [ ! -x "$SPARKLE_BIN/sign_update" ]; then
  echo "sign_update not found; see Distribution/generate-sparkle-keys.sh for setup." >&2
  exit 1
fi

# Sparkle's sign_update prints `sparkle:edSignature="..." length="..."` ready
# to drop into an <enclosure> tag.
"$SPARKLE_BIN/sign_update" "$DMG"
