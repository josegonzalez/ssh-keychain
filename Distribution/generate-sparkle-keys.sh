#!/bin/sh
# Generate the Sparkle EdDSA signing keypair.
#
# Run once per project. The PUBLIC key goes into the app's Info.plist (the
# SUPublicEDKey field is already wired in project.yml). The PRIVATE key stays
# in macOS Keychain (Sparkle's tool stores it under "Private key for signing
# Sparkle updates") and must NEVER land in this repository.
#
# Usage:
#   ./generate-sparkle-keys.sh
#
# The Sparkle binary tools live inside the Sparkle SwiftPM checkout once the
# Xcode project has fetched packages. We locate them dynamically; if you've
# built the Sparkle CLI tools separately (e.g. via Homebrew) just set
# SPARKLE_BIN to that directory.
set -eu

SPARKLE_BIN="${SPARKLE_BIN:-}"
if [ -z "$SPARKLE_BIN" ]; then
  # Look inside the SPM artifact cache. The directory layout is
  # .../SourcePackages/artifacts/sparkle/Sparkle/bin/{generate_keys,sign_update}.
  candidate=$(find "$HOME/Library/Developer/Xcode/DerivedData" \
    -type f -name 'generate_keys' -path '*/artifacts/*' 2>/dev/null \
    | head -1)
  if [ -n "$candidate" ]; then
    SPARKLE_BIN="$(dirname "$candidate")"
  fi
fi

if [ ! -x "$SPARKLE_BIN/generate_keys" ]; then
  cat <<EOF
Could not find Sparkle's generate_keys binary.

Options:
  - Open the Xcode project once so SPM fetches Sparkle, then re-run.
  - Or install Sparkle's tools via Homebrew: brew install --cask sparkle
    and set SPARKLE_BIN to the directory containing 'generate_keys'.
EOF
  exit 1
fi

"$SPARKLE_BIN/generate_keys"

cat <<EOF

------------------------------------------------------------------------
Copy the public key printed above and paste it into:
  SSHKeychainApp/project.yml -> info.properties.SUPublicEDKey

Then regenerate the Xcode project:
  cd SSHKeychainApp && xcodegen

The private key now lives in your macOS keychain under the item
"Private key for signing Sparkle updates". Distribution/sign-update.sh reads
it from there at release time - do not export it.
------------------------------------------------------------------------
EOF
