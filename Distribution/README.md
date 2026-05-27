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

```sh
TEAM_ID=ABCDEF1234 NOTARY_PROFILE=ssh-keychain ./Distribution/release.sh
```

That runs, in order:

1. **`codesign-and-archive.sh`** — `xcodebuild archive` with Developer ID identity, then `xcodebuild -exportArchive` to produce `build/Export/SSH Keychain.app`. Both Sparkle.framework and our embedded `ssh-keychain` binary inherit hardened runtime + Developer ID signing automatically because they're inside the archive.

2. **`notarize.sh build/Export/SSH Keychain.app`** — zip + upload to Apple's notary, wait (5-30 min), then `stapler staple` the ticket into the bundle so Gatekeeper can verify offline.

3. **`create-dmg.sh build/Export/SSH Keychain.app`** — produces `build/SSH-Keychain-<VERSION>.dmg`. Uses `create-dmg` (Homebrew) if installed for the conventional "drag to Applications" layout; falls back to `hdiutil` for a plain DMG.

4. **`notarize.sh build/SSH-Keychain-<VERSION>.dmg`** — notarize and staple the DMG too. Without this, first-launch from the DMG would require an internet round-trip to Apple.

5. **`sign-update.sh build/SSH-Keychain-<VERSION>.dmg`** — print the
   `sparkle:edSignature="..." length="..."` fragment to paste into the
   appcast.

## After the script finishes

Manual finishing steps (not yet scripted):

1. Upload the notarized DMG to GitHub Releases under tag `v<VERSION>`.

2. Edit `appcast.xml` (hosted at `SUFeedURL`) using
   `appcast.xml.template` as the starting point. Replace `{VERSION}`,
   `{PUB_DATE}`, `{DMG_URL}`, `{DMG_LENGTH}`, `{ED_SIGNATURE}`, `{MIN_OS}`,
   `{RELEASE_NOTES}`. Push to whatever host serves the SUFeedURL (GitHub Pages
   if you go with the default).

3. Tag the commit and push:
   ```sh
   git tag -a v<VERSION> -m "Release v<VERSION>"
   git push origin v<VERSION>
   ```

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
