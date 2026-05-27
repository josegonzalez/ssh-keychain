# SSH Keychain

Dynamic SSH key retrieval for `~/.ssh/config`. Keep private keys inside the macOS Keychain (with biometric ACLs or the Secure Enclave), HashiCorp Vault, 1Password, or 1Password's legacy OPVault format — and have `ssh` fetch them on demand instead of reading plaintext files from disk.

## Status

- **Platform**: macOS 14 (Sonoma) or later. Apple Silicon required for Secure-Enclave-backed key generation; everything else works on Intel.
- **Algorithms**: ed25519, ECDSA P-256/P-384/P-521. RSA reading-from-existing-keys is on the roadmap.
- **Encrypted key import**: not yet — encrypted PEM/OpenSSH private keys are deferred. Unencrypted imports work.

## Installation

### macOS app

Download the latest signed DMG from [Releases](https://github.com/josegonzalez/ssh-keychain/releases) and drag `SSH Keychain.app` to `/Applications`. Launch it; the menu bar icon appears at the top right and the onboarding wizard opens.

To put the `ssh-keychain` CLI on your `$PATH`: **Settings → Advanced → Install command-line tool**. This symlinks `/usr/local/bin/ssh-keychain` to the binary inside the app bundle (admin prompt the first time).

### Homebrew Cask

Not yet shipped. A Cask would be ~15 lines of Ruby once a release is up on GitHub:

```ruby
cask "ssh-keychain" do
  version "0.1.0"
  sha256 "..."
  url "https://github.com/josegonzalez/ssh-keychain/releases/download/v#{version}/SSH-Keychain-#{version}.dmg"
  name "SSH Keychain"
  desc "Dynamic SSH key retrieval from pluggable backends"
  homepage "https://github.com/josegonzalez/ssh-keychain"
  depends_on macos: ">= :sonoma"
  app "SSH Keychain.app"
  binary "#{appdir}/SSH Keychain.app/Contents/MacOS/ssh-keychain"
  auto_updates true   # Sparkle drives updates; brew skips its own version checks
  zap trash: [
    "~/Library/Application Support/com.josegonzalez.ssh-keychain",
    "~/Library/LaunchAgents/com.josegonzalez.ssh-keychain.plist",
    "~/Library/Preferences/com.josegonzalez.ssh-keychain.plist",
  ]
end
```

Submitting to `homebrew/cask` requires the app to be live on GitHub Releases for at least one version, fully notarized — both true once the first release is cut. PRs welcome.

## Quick start

1. Generate a Secure-Enclave-backed ECDSA P-256 key:
   ```sh
   ssh-keychain gen --source=keychain:github --algorithm=ecdsa-p256 --secure-enclave
   ```
   The output is the public key in OpenSSH format. Copy it to your GitHub SSH settings (or wherever).

2. Configure `~/.ssh/config` to route through the agent:
   ```ssh-config
   Host github.com
     IdentityAgent ~/.ssh/ssh-keychain.sock
   ```

3. Enable the launch agent from **SSH Keychain.app → Settings → Advanced → Launch agent → Enable**. macOS prompts you to approve once.

4. SSH:
   ```sh
   ssh -T git@github.com
   ```
   Touch ID prompts the first time it signs. The cached signer lasts for `cacheTTL` seconds after that (default `0`, configurable in Settings → Agent).

## CLI reference

All identity-bearing commands take `--source=BACKEND:KEY[,KEY...]`. `BACKEND` is the name of a backend instance from the config file (or one of the implicit names `keychain` / `file` for the default setups).

| Command | Purpose |
|---|---|
| `ssh-keychain add` | Import an existing private key file into a writable backend |
| `ssh-keychain gen` | Generate a new key (keychain + Secure Enclave only in v1) |
| `ssh-keychain list` | List keys in a backend, optionally filtered by name/wildcard |
| `ssh-keychain remove` | Delete a key from a backend |
| `ssh-keychain get` | Print a key's public form to stdout or a file |
| `ssh-keychain load` | Push a key into the running `$SSH_AUTH_SOCK` agent |
| `ssh-keychain run` | Run a command with an ephemeral agent serving the chosen key |
| `ssh-keychain agent` | Run the agent daemon (typically launchd-managed via the app) |
| `ssh-keychain status` | Show the running daemon's status via XPC |
| `ssh-keychain doctor` | Diagnose config, ssh_config, codesigning, launch agent state |

Run `ssh-keychain <command> --help` for command-specific flags.

## SSH integration patterns

Four ways to wire `ssh` (and any other SSH-agent client) up to keys served by this project. Pick whichever fits the host or environment.

### Pattern 1: Daemon agent — *recommended*

A long-lived agent process serves every host via `IdentityAgent`. The agent is registered with macOS as a Login Item (via SMAppService) so it starts at login and survives reboots. This is the default state after onboarding.

```ssh-config
Host *
  IdentityAgent ~/.ssh/ssh-keychain.sock
```

Or scope it to specific hosts:
```ssh-config
Host github.com gitlab.com
  IdentityAgent ~/.ssh/ssh-keychain.sock

Host *.legacy-corp.example
  # use the system ssh-agent for these
```

### Pattern 2: Per-connection short-lived agent (`--once`)

The agent only runs for the duration of one SSH connection. Useful when you want a different agent (with different keys) per host pattern, and don't want a persistent daemon hosting everything.

```ssh-config
Match host *.work-corp.example
  Exec "ssh-keychain agent --once --socket=/tmp/ssk-%h.sock --source=keychain:%h"
  IdentityAgent /tmp/ssk-%h.sock
```

The `Match exec` clause spawns the agent (race-free: it doesn't return until the socket is bound). The agent self-terminates after 30 seconds of no live connections.

### Pattern 3: Match-exec preload (`load`)

For users who already run the system `ssh-agent` and want this project's keys pushed into it (rather than running a separate agent). Slow first connection (the `Match exec` blocks while the agent client pushes); free thereafter.

```ssh-config
Host github.com
  Exec "ssh-keychain load --source=keychain:github"
```

`load` dials `$SSH_AUTH_SOCK`, checks if the key is already present, and pushes via `AddIdentity` if not. Subsequent connections see the key already loaded and skip the push.

**Caveat**: incompatible with hardware-bound keys (Secure Enclave, future YubiKey backends) — those can't leave their hardware. Use Pattern 1 instead.

### Pattern 4: Run wrapper (`run`)

Spawns an ephemeral agent serving exactly one key, sets `SSH_AUTH_SOCK` in the wrapped command's environment, then cleans up when the command exits. No SSH config changes needed.

```sh
ssh-keychain run --source=keychain:github -- ssh -T git@github.com
ssh-keychain run --source=keychain:work-bastion -- scp report.csv user@bastion:/tmp/
ssh-keychain run --source=op:work-1p:prod-readonly -- git clone git@github.com:org/repo
```

Works with any tool that honors `SSH_AUTH_SOCK`: `ssh`, `scp`, `sftp`, `git`, `rsync`, Ansible, etc.

## Backends

Five backends in v1. All implement the same `Backend` protocol; users pick whichever matches their secret-storage setup.

### `keychain` — macOS Keychain

The headline backend. Two storage modes:

- **Mode A — Generic-password** (default for imported keys). Item lives in your login keychain as a `kSecClassGenericPassword`. Reads trigger a Touch ID prompt when `--require-biometric` is set at creation. Any key algorithm.
- **Mode B — Secure Enclave** (for newly-generated ECDSA P-256 keys). Private key is generated *inside* the Secure Enclave and never exists outside it; signing happens via `SecKeyCreateSignature`. `ssh-keychain gen --source=keychain:NAME --algorithm=ecdsa-p256 --secure-enclave`.

Listing keys never triggers ACL prompts thanks to a public-key sidecar item.

### `file` — Plain files

For testing and trivial setups. Files at `~/Library/Application Support/com.josegonzalez.ssh-keychain/file-backend/<key>` (mode 0600) with a `<key>.pub` sidecar. Configurable root path. Cross-platform if you ever port the Core library.

### `vault` — HashiCorp Vault (KV v2)

Reads/writes keys at `<address>/v1/<mount>/data/<prefix>/<key>` using the `private_key` field by default. Tokens come from an `AuthProvider`:

- **`static`** — token from a `secretref` (e.g. `keychain:vault-prod-token`) or `VAULT_TOKEN` env var
- **`oidc`** — browser PKCE flow + Vault's OIDC auth method. *Roadmap (v1.1)*; stub in v1 so config schema is forward-compatible.

403 responses trigger one automatic retry after refreshing the token.

### `op` — 1Password 8+ CLI

Shells out to `op read op://<account>/<vault>/<item>/<field>`. Trusts `op`'s session and biometric handling — no master-password plumbing on our side. Read-only.

### `opvault` — 1Password OPVault (legacy 4-7 format)

Reads keys directly out of a `.opvault` directory. Implements the [OPVault crypto spec](https://support.1password.com/opvault-design/) (PBKDF2-HMAC-SHA512 → AES-256-CBC + HMAC-SHA256). Master password comes from a `secretref` (typically `keychain:opvault-master` so it inherits Touch ID via the keychain item's ACL). Read-only.

## Configuration

Lives at `~/Library/Application Support/com.josegonzalez.ssh-keychain/config.json`. The daemon watches it via FSEvents and reloads atomically on save. Example:

```json
{
  "version": 1,
  "agent": {
    "socketPath": "~/.ssh/ssh-keychain.sock",
    "cacheTTL": 900,
    "cacheMaxKeys": 32,
    "cacheTokensToKeychain": false
  },
  "backends": {
    "primary": { "type": "keychain" },
    "personal-1p": {
      "type": "opvault",
      "path": "/Users/jose/Dropbox/1Password.opvault",
      "masterRef": "keychain:opvault-master",
      "lockAfter": 900
    },
    "work-1p": { "type": "op", "account": "my-team", "vault": "Personal" },
    "vault-prod": {
      "type": "vault",
      "address": "https://vault.internal:8200",
      "mount": "secret",
      "prefix": "ssh",
      "auth": { "type": "static", "tokenRef": "keychain:vault-prod-token" }
    }
  },
  "sources": [
    { "backend": "primary", "key": "*" },
    { "backend": "personal-1p", "key": "github-personal", "item": "GitHub Personal" },
    { "backend": "work-1p", "key": "prod-bastion", "item": "Prod Bastion", "field": "private_key" },
    { "backend": "vault-prod", "key": "db-readonly" }
  ]
}
```

`secretref` schemes used by backend credentials:
- `keychain:NAME` — macOS Keychain item under the reserved service `com.josegonzalez.ssh-keychain.secrets`
- `file:/path` — a `0600`-mode file containing the raw secret
- `env:VAR_NAME` — an environment variable
- `prompt:Message` — TTY prompt with no-echo (CLI only; not valid in the daemon)

## Development

```sh
git clone https://github.com/josegonzalez/ssh-keychain
cd ssh-keychain

# Build + test the Swift package (Core lib + CLI)
swift build
swift test

# Build the macOS app
cd SSHKeychainApp
xcodegen                       # regenerate the Xcode project from project.yml
xcodebuild -scheme SSHKeychainApp -configuration Debug build
```

Source layout:

```
Sources/
  SSHKeychainCore/       Backends, agent protocol, IPC types, config, secret-ref DSL
  ssh-keychain/          CLI executable (10 subcommands)
Tests/
  SSHKeychainCoreTests/  68 unit + integration tests
SSHKeychainApp/
  project.yml            XcodeGen spec - source of truth for the Xcode project
  SSHKeychainApp/        SwiftUI app sources: MenuBarExtra, Settings, Activity, Onboarding
docs/
  appcast.xml            Sparkle feed (hosted via GitHub Pages)
Distribution/            Release pipeline: codesign, notarize, dmg, publish
release-notes/           Per-version markdown notes consumed by publish.sh
```

The Xcode project (`SSHKeychainApp.xcodeproj`) is generated from `project.yml` via [XcodeGen](https://github.com/yonaskolb/XcodeGen) and **isn't** checked in. Install XcodeGen via `brew install xcodegen` and run it whenever you edit `project.yml`.

See [`Distribution/README.md`](Distribution/README.md) for the release pipeline (codesign + notarize + Sparkle + publish).

## Architecture

The daemon (`ssh-keychain agent`) speaks two protocols:

1. **SSH agent protocol** on `~/.ssh/ssh-keychain.sock` (Unix domain socket) for `ssh`/`ssh-add`/`ssh-keygen -Y` to dial.
2. **XPC over `NSXPCConnection`** on a Mach service (`com.josegonzalez.ssh-keychain.daemon`) for the macOS app and `ssh-keychain status`/`doctor` to introspect/control the daemon.

Identities load lazily: on startup or `SIGHUP`, the daemon enumerates configured sources via `Backend.list(publicKeysOnly: true)` — *no* private material touched. Signing requests trigger `Backend.get(key:)` per Sign request; the resulting `SSHSigner` lives in an in-process `KeyCache` for `cacheTTL` seconds.

Hardware-bound signers (Secure Enclave) don't expose private bytes at all — `SSHSigner.sign(data:)` calls into `SecKeyCreateSignature` so the key never leaves the enclave.

## License

MIT. See [LICENSE](LICENSE).
