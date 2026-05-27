# Distribution

Scripts for cutting a signed, notarized release of SSH Keychain.

## One-time setup

You need each of these before any release:

1. **Apple Developer Program membership** ($99/year). Without it, `codesign` can only do ad-hoc signing, which Gatekeeper rejects on machines other than your own.

2. **A "Developer ID Application" certificate** in your login keychain. Issue one from <https://developer.apple.com/account/resources/certificates> and download it; double-clicking installs it.

   Verify with:
   ```sh
   security find-identity -v -p codesigning
   ```
   You should see a line like
   `Developer ID Application: Your Name (ABCDEF1234)`.
   Note the 10-character team ID (`ABCDEF1234`) for `TEAM_ID` below.

3. **An app-specific password** for notarization. Generate at <https://appleid.apple.com> → Sign-In and Security → App-Specific Passwords. Save the result to your keychain as a `notarytool` profile so it doesn't sit in your shell history:
   ```sh
   xcrun notarytool store-credentials ssh-keychain \
     --apple-id you@example.com \
     --team-id ABCDEF1234 \
     --password 'xxxx-xxxx-xxxx-xxxx'
   ```
   Use the profile name (`ssh-keychain`) as `NOTARY_PROFILE` below.

4. **Sparkle EdDSA signing keypair** for verifying updates:
   ```sh
   ./Distribution/generate-sparkle-keys.sh
   ```
   This prints a public key. Paste it into
   `SSHKeychainApp/project.yml` under `SUPublicEDKey` and regen the project
   (`cd SSHKeychainApp && xcodegen`). The private key stays in your macOS
   Keychain and never leaves your machine.

## Cutting a release

The release flow is two scripts. **`release.sh` produces the artifact** (slow,
~25 min, mostly Apple's notary). **`publish.sh` ships it** (~10 sec, but
irreversible side effects like GitHub Releases). Splitting them means a bad
notarization doesn't yield a half-published release, and a bad publish doesn't
waste 25 minutes redoing notarization.

### Step 1: Write release notes

Create `release-notes/<VERSION>.md` with the notes for this version. Plain
markdown — `publish.sh` converts to HTML via uv at publish time. The file is
also fed verbatim to `gh release create --notes-file` so it shows up on the
GitHub Releases page.

### Step 2: Build + notarize the artifact

```sh
TEAM_ID=2H4U2XX239 NOTARY_PROFILE=ssh-keychain ./Distribution/release.sh
```

Runs, in order:

1. **`codesign-and-archive.sh`** — `xcodebuild archive` with Developer ID identity, then `xcodebuild -exportArchive` to produce `build/Export/SSH Keychain.app`. Both Sparkle.framework and our embedded `ssh-keychain` binary inherit hardened runtime + Developer ID signing automatically because they're inside the archive.

2. **`notarize.sh build/Export/SSH Keychain.app`** — zip + upload to Apple's notary, wait (5-30 min), then `stapler staple` the ticket into the bundle so Gatekeeper can verify offline.

3. **`create-dmg.sh build/Export/SSH Keychain.app`** — produces `build/SSH-Keychain-<VERSION>.dmg`. Uses `create-dmg` (Homebrew) if installed for the conventional "drag to Applications" layout; falls back to `hdiutil` for a plain DMG.

4. **`notarize.sh build/SSH-Keychain-<VERSION>.dmg`** — notarize and staple the DMG too. Without this, first-launch from the DMG would require an internet round-trip to Apple.

5. **`sign-update.sh build/SSH-Keychain-<VERSION>.dmg`** — prints the `sparkle:edSignature="..." length="..."` fragment (informational; `publish.sh` re-derives it).

You can also stop after step 1 to validate codesigning without involving
Apple's notary at all:
```sh
TEAM_ID=2H4U2XX239 ./Distribution/codesign-and-archive.sh
```

### Step 3 (recommended): Smoke-test the DMG locally

Mount `build/SSH-Keychain-<VERSION>.dmg`, drag the app to `/Applications`, run
it, confirm "Check for Updates…" succeeds (you'll be told you're up to date),
exit. If anything's wrong, rerun `release.sh` after fixing — nothing is
public yet.

### Step 4: Publish

```sh
./Distribution/publish.sh
```

(No env vars needed; the script reads `MARKETING_VERSION` and
`CURRENT_PROJECT_VERSION` from `project.yml` and finds the matching DMG in
`build/`.)

Runs, in order:

1. **Compute the Sparkle signature** for the DMG via `sign-update.sh`.
2. **Convert release notes** from `release-notes/<VERSION>.md` to HTML using `uv run Distribution/convert-md-to-html.py` (auto-installs the `markdown` library in an isolated venv on first run).
3. **Create a GitHub *draft* release** with `gh release create --draft`, uploading the DMG. The release isn't visible to users yet.
4. **Resolve the canonical DMG download URL** from the GitHub API.
5. **Insert a new `<item>`** into `docs/appcast.xml`, immediately after the `<!-- ITEMS_BELOW -->` sentinel. Validates with `xmllint`.
6. **Commit `docs/appcast.xml`** as `release: v<VERSION>` and create an annotated `v<VERSION>` git tag.
7. **Bump `MARKETING_VERSION` + `CURRENT_PROJECT_VERSION`** in `project.yml` (default patch bump; override with `BUMP=minor` or `BUMP=major` env var, or `BUMP=none` to skip). Commit as `bump: <OLD> -> <NEW>`.
8. **Promote the GitHub release** from draft to published. This is the moment users can see the release on GitHub.

`publish.sh` ends by printing the final manual command:
```sh
git push --follow-tags
```
(Optional — the script leaves the push to you so you can `git log -p` and verify the commits + tag before broadcasting.)

### Rolling back BEFORE you push

Everything between steps 1-8 is reversible:

```sh
gh release delete v<VERSION> --yes --repo josegonzalez/ssh-keychain
git tag -d v<VERSION>
git reset --hard HEAD~2     # ~1 if you used BUMP=none
```

After `git push`, rollback is socially costly (people may have already pulled
the tag, fetched the appcast, etc.) — possible but not advisable.

### Version bump policy

`publish.sh`'s default is a patch bump. Override per release:

```sh
BUMP=minor ./Distribution/publish.sh   # 0.1.0 -> 0.2.0
BUMP=major ./Distribution/publish.sh   # 0.1.0 -> 1.0.0
BUMP=none  ./Distribution/publish.sh   # don't bump; useful when re-publishing a fix
```

The build number (`CURRENT_PROJECT_VERSION`) always increments by 1 unless
`BUMP=none`. Sparkle compares this as a monotonic integer — it MUST go up for
existing installations to see the new release as an update.

## Smoke testing without a Developer ID

If you don't yet have a paid Apple Developer Program membership, the scripts
fail cleanly when you run them - they refuse to start without `TEAM_ID` or
`NOTARY_PROFILE`. The ad-hoc-signed debug build from `xcodebuild build` (or
running the scheme from Xcode) still works for local testing; it just won't
launch on anyone else's machine because Gatekeeper requires a Developer ID
identity for distributed apps.

## Reproducibility notes

- `xcodebuild archive` pins to whichever Xcode version is selected via
  `xcode-select`. CI should pin a known Xcode version explicitly with
  `xcversion` / `xcodes` for reproducible builds.
- The Sparkle private key is intentionally non-portable. If you lose access to
  the macOS Keychain entry, you have to issue a new keypair, update
  `SUPublicEDKey`, and ship at least one signed update with the OLD key first
  so existing installs can transition. Don't lose this key.
- `notarytool store-credentials` writes the app-specific password into the
  login keychain - it's never readable as plaintext after that. To rotate,
  generate a new app-specific password at appleid.apple.com, then
  `xcrun notarytool store-credentials <profile>` again to overwrite.
