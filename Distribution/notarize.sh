#!/bin/sh
# Submit a Developer-ID-signed .app (or .dmg) to Apple's notary service and
# staple the resulting ticket. Stapled tickets let macOS verify the app's
# notarization status offline (no internet required at first launch).
#
# Required env vars (preferred path: notarytool credentials profile):
#   NOTARY_PROFILE         Name of the credentials profile stored in keychain
#                          via: xcrun notarytool store-credentials NOTARY_PROFILE
#                                  --apple-id you@example.com
#                                  --team-id ABCDEF1234
#                                  --password "<app-specific-password>"
#
# OR direct credentials (less ergonomic; secrets in env):
#   APPLE_ID, APPLE_TEAM_ID, APP_SPECIFIC_PASSWORD
#
# Usage:
#   ./notarize.sh path/to/SSH-Keychain-0.1.0.dmg
set -eu

if [ "$#" -ne 1 ]; then
  echo "usage: $0 path/to/app-or-dmg" >&2
  exit 1
fi
TARGET="$1"

if [ ! -e "$TARGET" ]; then
  echo "$TARGET: not found" >&2
  exit 1
fi

# Build the credential arguments for notarytool.
if [ -n "${NOTARY_PROFILE:-}" ]; then
  CRED_ARGS="--keychain-profile $NOTARY_PROFILE"
elif [ -n "${APPLE_ID:-}" ] && [ -n "${APPLE_TEAM_ID:-}" ] && [ -n "${APP_SPECIFIC_PASSWORD:-}" ]; then
  CRED_ARGS="--apple-id $APPLE_ID --team-id $APPLE_TEAM_ID --password $APP_SPECIFIC_PASSWORD"
else
  cat >&2 <<EOF
Notarization credentials not set. Pick one:

  a) Store a credentials profile in your keychain (recommended):
       xcrun notarytool store-credentials NOTARY_PROFILE_NAME \\
         --apple-id you@example.com \\
         --team-id ABCDEF1234 \\
         --password '<app-specific-password from appleid.apple.com>'
     then re-run with:
       NOTARY_PROFILE=NOTARY_PROFILE_NAME $0 $TARGET

  b) Or pass each credential as an env var:
       APPLE_ID=you@example.com APPLE_TEAM_ID=ABCDEF1234 \\
         APP_SPECIFIC_PASSWORD=xxxx-xxxx-xxxx-xxxx $0 $TARGET
EOF
  exit 1
fi

# notarytool requires a zipped .app or a .dmg/.pkg directly.
case "$TARGET" in
  *.dmg|*.pkg)
    UPLOAD="$TARGET"
    CLEANUP=""
    ;;
  *.app|*)
    TMP_ZIP="$(mktemp -t notarize).zip"
    rm -f "$TMP_ZIP"
    ditto -c -k --keepParent "$TARGET" "$TMP_ZIP"
    UPLOAD="$TMP_ZIP"
    CLEANUP="$TMP_ZIP"
    ;;
esac

echo "==> submitting $UPLOAD to Apple notary service (this can take 5-30 minutes)"
# shellcheck disable=SC2086 # CRED_ARGS is a space-separated argument list
xcrun notarytool submit "$UPLOAD" $CRED_ARGS --wait

# Cleanup the temp zip; notarytool only needs it during the submit window.
[ -n "$CLEANUP" ] && rm -f "$CLEANUP"

echo "==> stapling notarization ticket"
case "$TARGET" in
  *.dmg|*.pkg)
    xcrun stapler staple "$TARGET"
    ;;
  *.app|*)
    xcrun stapler staple "$TARGET"
    ;;
esac

echo "==> stapled: $TARGET"
echo "==> verifying gatekeeper acceptance"
spctl --assess --type execute --verbose=4 "$TARGET" || true
