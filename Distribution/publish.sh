#!/bin/sh
# Publish a notarized DMG: create a GitHub release, update the Sparkle appcast,
# commit + tag, then bump the in-tree version for the next cycle.
#
# Prerequisites (run release.sh first):
#   - build/SSH-Keychain-$VERSION.dmg exists and has already been notarized
#   - release-notes/$VERSION.md exists with the release notes
#   - git working tree is clean
#   - gh is authenticated
#   - uv is installed (used to run convert-md-to-html.py with its deps)
#
# Order of operations is chosen so the irreversible bits happen last:
#   1. Make a GitHub DRAFT release with the DMG attached (uploads but stays hidden).
#   2. Insert the new <item> into docs/appcast.xml.
#   3. Commit the appcast change and create the v$VERSION tag.
#   4. Bump MARKETING_VERSION + CURRENT_PROJECT_VERSION in project.yml.
#   5. Commit the version bump.
#   6. Promote the draft release to published.
#   7. Print the final `git push --follow-tags` for the human to run.
#
# If anything before step 6 fails, the draft can be deleted via
# `gh release delete v$VERSION` and the local commits/tag can be unwound;
# nothing is visible to users until step 6.
#
# Bump policy: defaults to patch (0.1.0 -> 0.1.1). Override with:
#   BUMP=minor ./publish.sh    # 0.1.0 -> 0.2.0
#   BUMP=major ./publish.sh    # 0.1.0 -> 1.0.0
#   BUMP=none  ./publish.sh    # don't bump; useful when re-publishing a fix
set -eu

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PROJECT_YML="$ROOT/SSHKeychainApp/project.yml"
APPCAST="$ROOT/docs/appcast.xml"
BUMP="${BUMP:-patch}"
MIN_OS="${MIN_OS:-14.0}"

die() { printf 'publish: %s\n' "$*" >&2; exit 1; }

# Bump a semver-style "X.Y.Z" version. Mode is patch | minor | major.
bump_version() {
    _v="$1"
    _mode="$2"
    _major=${_v%%.*}
    _rest=${_v#*.}
    _minor=${_rest%%.*}
    _patch=${_rest#*.}
    case "$_mode" in
        patch) printf '%s.%s.%s\n' "$_major" "$_minor" $((_patch + 1)) ;;
        minor) printf '%s.%s.0\n' "$_major" $((_minor + 1)) ;;
        major) printf '%s.0.0\n' $((_major + 1)) ;;
        *) die "unknown BUMP mode '$_mode' (expected patch|minor|major|none)" ;;
    esac
}

VERSION=$(awk -F'"' '/^[[:space:]]*MARKETING_VERSION:/{print $2; exit}' "$PROJECT_YML")
BUILD=$(awk -F'"' '/^[[:space:]]*CURRENT_PROJECT_VERSION:/{print $2; exit}' "$PROJECT_YML")
[ -n "$VERSION" ] || die "could not parse MARKETING_VERSION from $PROJECT_YML"
[ -n "$BUILD" ] || die "could not parse CURRENT_PROJECT_VERSION from $PROJECT_YML"

DMG="$ROOT/build/SSH-Keychain-$VERSION.dmg"
NOTES_MD="$ROOT/release-notes/$VERSION.md"

echo "==> publishing v$VERSION (build $BUILD)"

# Preconditions
[ -f "$DMG" ] || die "no DMG at $DMG - run ./Distribution/release.sh first"
[ -f "$NOTES_MD" ] || die "no release notes at $NOTES_MD - create one before publishing"
command -v uv >/dev/null 2>&1 || die "uv not found; install from https://astral.sh/uv"
command -v gh >/dev/null 2>&1 || die "gh not found; install via brew install gh"
gh auth status >/dev/null 2>&1 || die "gh is not authenticated; run 'gh auth login'"
(cd "$ROOT" && git diff --quiet HEAD) || die "git working tree has uncommitted changes; commit or stash first"
grep -qF '<!-- ITEMS_BELOW' "$APPCAST" || die "appcast missing the ITEMS_BELOW sentinel comment; cannot insert"

# Sparkle signature + DMG length
echo "==> [1/6] computing Sparkle signature"
SIG_LINE=$("$ROOT/Distribution/sign-update.sh" "$DMG")
SIG=$(printf '%s\n' "$SIG_LINE" | sed -nE 's/.*sparkle:edSignature="([^"]+)".*/\1/p')
[ -n "$SIG" ] || die "could not extract sparkle:edSignature from sign-update.sh output: $SIG_LINE"
LENGTH=$(stat -f%z "$DMG")

# Markdown -> HTML (uv runs convert-md-to-html.py in an isolated venv).
NOTES_HTML=$(uv run "$ROOT/Distribution/convert-md-to-html.py" "$NOTES_MD")
[ -n "$NOTES_HTML" ] || die "convert-md-to-html.py produced no output for $NOTES_MD"

echo "==> [2/6] creating GitHub draft release v$VERSION"
gh release create "v$VERSION" "$DMG" \
    --title "v$VERSION" \
    --notes-file "$NOTES_MD" \
    --draft \
    --repo josegonzalez/ssh-keychain

# Resolve the canonical download URL Apple will see. We use the
# `browser_download_url` from the asset, not the API-internal URL.
DMG_URL=$(gh release view "v$VERSION" \
    --repo josegonzalez/ssh-keychain \
    --json assets \
    --jq ".assets[] | select(.name == \"SSH-Keychain-$VERSION.dmg\") | .url")
[ -n "$DMG_URL" ] || die "could not resolve DMG download URL from gh release"
echo "    DMG URL: $DMG_URL"

echo "==> [3/6] inserting <item> into docs/appcast.xml"
PUB_DATE=$(date -u "+%a, %d %b %Y %H:%M:%S +0000")

# BSD awk rejects newlines in `-v` values, so stage the new item in a temp
# file and have awk slurp it on the line following the sentinel.
ITEM_FILE=$(mktemp -t ssh-keychain-publish-item)
trap 'rm -f "$ITEM_FILE"' EXIT
cat > "$ITEM_FILE" <<EOF
        <item>
            <title>Version $VERSION</title>
            <pubDate>$PUB_DATE</pubDate>
            <sparkle:version>$BUILD</sparkle:version>
            <sparkle:shortVersionString>$VERSION</sparkle:shortVersionString>
            <sparkle:minimumSystemVersion>$MIN_OS</sparkle:minimumSystemVersion>
            <description><![CDATA[$NOTES_HTML]]></description>
            <enclosure
                url="$DMG_URL"
                length="$LENGTH"
                type="application/octet-stream"
                sparkle:edSignature="$SIG"/>
        </item>
EOF

awk -v item_file="$ITEM_FILE" '
    /<!-- ITEMS_BELOW/ {
        print
        while ((getline line < item_file) > 0) print line
        close(item_file)
        next
    }
    { print }
' "$APPCAST" > "$APPCAST.new"
mv "$APPCAST.new" "$APPCAST"

# Re-validate XML before committing - cheap sanity check.
if command -v xmllint >/dev/null 2>&1; then
    xmllint --noout "$APPCAST" || die "appcast became invalid XML after insertion"
fi

echo "==> [4/6] commit + tag v$VERSION"
(cd "$ROOT" && git add docs/appcast.xml)
(cd "$ROOT" && git commit -m "release: v$VERSION")
(cd "$ROOT" && git tag -a "v$VERSION" -m "Release v$VERSION")

# Version bump for the next release.
if [ "$BUMP" != "none" ]; then
    NEW_VERSION=$(bump_version "$VERSION" "$BUMP")
    NEW_BUILD=$((BUILD + 1))
    echo "==> [5/6] bumping version: $VERSION -> $NEW_VERSION (build $BUILD -> $NEW_BUILD)"

    # In-place edit, BSD sed compatible
    sed -i.bak \
        -e "s/MARKETING_VERSION: \"$VERSION\"/MARKETING_VERSION: \"$NEW_VERSION\"/" \
        -e "s/CURRENT_PROJECT_VERSION: \"$BUILD\"/CURRENT_PROJECT_VERSION: \"$NEW_BUILD\"/" \
        "$PROJECT_YML"
    rm "$PROJECT_YML.bak"

    (cd "$ROOT" && git add SSHKeychainApp/project.yml)
    (cd "$ROOT" && git commit -m "bump: $VERSION -> $NEW_VERSION (build $NEW_BUILD)")
else
    echo "==> [5/6] skipping version bump (BUMP=none)"
fi

echo "==> [6/6] promoting draft release to published"
gh release edit "v$VERSION" --draft=false --repo josegonzalez/ssh-keychain

cat <<EOF

Published v$VERSION.

Final manual step:
  cd "$ROOT" && git push --follow-tags

To roll back BEFORE pushing:
  gh release delete v$VERSION --yes --repo josegonzalez/ssh-keychain
  cd "$ROOT" && git tag -d v$VERSION && git reset --hard HEAD~2  # or ~1 if BUMP=none

EOF
