#!/bin/sh
# Build a Developer-ID-signed .app via xcodebuild archive + exportArchive.
#
# Required env vars:
#   TEAM_ID                Apple Developer Team ID (10-char) for codesigning.
#                          Find via: security find-identity -v -p codesigning
#
# Optional env vars:
#   CONFIGURATION          Release (default) or Debug
#   BUILD_DIR              Output directory (default: ./build)
#
# Produces:
#   $BUILD_DIR/Archive/SSHKeychainApp.xcarchive
#   $BUILD_DIR/Export/SSH Keychain.app
set -eu

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PROJECT="$ROOT/SSHKeychainApp/SSHKeychainApp.xcodeproj"
SCHEME="SSHKeychainApp"
CONFIGURATION="${CONFIGURATION:-Release}"
BUILD_DIR="${BUILD_DIR:-$ROOT/build}"

if [ -z "${TEAM_ID:-}" ]; then
  cat >&2 <<EOF
TEAM_ID is not set. Find your team ID with:

  security find-identity -v -p codesigning

then re-run with:
  TEAM_ID=ABCDEF1234 $0
EOF
  exit 1
fi

# Regenerate the Xcode project so any project.yml edits land in the build.
if command -v xcodegen >/dev/null 2>&1; then
  (cd "$ROOT/SSHKeychainApp" && xcodegen >/dev/null)
fi

ARCHIVE_PATH="$BUILD_DIR/Archive/SSHKeychainApp.xcarchive"
EXPORT_PATH="$BUILD_DIR/Export"
EXPORT_OPTIONS_TEMPLATE="$ROOT/Distribution/ExportOptions.plist"
EXPORT_OPTIONS="$BUILD_DIR/ExportOptions.expanded.plist"

mkdir -p "$BUILD_DIR"
# Expand $TEAM_ID in the template since plists aren't natively templated.
sed "s/\$TEAM_ID/$TEAM_ID/g" "$EXPORT_OPTIONS_TEMPLATE" > "$EXPORT_OPTIONS"

echo "==> xcodebuild archive ($CONFIGURATION)"
xcodebuild \
  -project "$PROJECT" \
  -scheme "$SCHEME" \
  -configuration "$CONFIGURATION" \
  -archivePath "$ARCHIVE_PATH" \
  DEVELOPMENT_TEAM="$TEAM_ID" \
  CODE_SIGN_STYLE=Manual \
  CODE_SIGN_IDENTITY="Developer ID Application" \
  archive

echo "==> xcodebuild -exportArchive (Developer ID)"
xcodebuild \
  -exportArchive \
  -archivePath "$ARCHIVE_PATH" \
  -exportPath "$EXPORT_PATH" \
  -exportOptionsPlist "$EXPORT_OPTIONS"

APP_PATH="$EXPORT_PATH/SSH Keychain.app"
if [ ! -d "$APP_PATH" ]; then
  echo "Expected $APP_PATH to exist after exportArchive. Check exportArchive output above." >&2
  exit 1
fi

echo "==> verifying signature"
codesign --verify --deep --strict --verbose=2 "$APP_PATH"
spctl --assess --type execute --verbose=4 "$APP_PATH" || echo "(spctl rejection here is normal until notarization completes)"

echo "==> signed: $APP_PATH"
