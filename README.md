<p align="center">
  <img src="docs/assets/yara-banner.png" alt="Yara over a moonlit rainforest river" width="100%" />
</p>

# yara

A password manager with a built-in authenticator and a safe way to hand
credentials to AI agents.

> Early development, but past the point where the interesting parts are
> hypothetical: the core, the desktop app, the agent broker and sync are
> implemented and tested. See [Status](#status) for what is not.

## Why

Three things, in order of how much they motivated the project:

**Agents need credentials and there is no good way to give them any.** Pasting a
secret into a chat puts it in the model's context forever. Putting it in a
`.txt` and telling the agent "it's in there" just moves the plaintext to disk.
yara gives agents an approval-gated broker that runs commands with credentials
injected, so the value never enters the agent's context at all. See
[docs/agent-access.md](docs/agent-access.md).

**Reaching for your phone for a 6-digit code is tedious.** yara generates TOTP
codes on the desktop, next to the password they go with. Opt-in per account — if
you would rather keep second factors on a separate device, don't turn it on.

**And it is a password manager.** Local-first, encrypted, no account required.

## Security design

| | |
| --- | --- |
| Key derivation | Argon2id, 64 MiB / 3 passes / 4 lanes |
| Encryption | XChaCha20-Poly1305 |
| Key hierarchy | Master password wraps a vault key; items are encrypted under the vault key |
| Header integrity | KDF parameters are authenticated as associated data |
| Memory | Keys and secrets are zeroized on drop |

Envelope encryption means changing the master password re-wraps 32 bytes rather
than rewriting every item, and the expensive KDF runs once per unlock.

The KDF parameters live in the file header in the clear, because an existing
vault has to stay openable after the defaults are raised. They are fed to the
AEAD as associated data, so editing them down to `iterations = 1` produces an
authentication failure rather than a cheaper attack. There is a test for that.

Wrong password and tampered file are the same error. Callers cannot tell them
apart.

## Layout

```
crates/yara-core     crypto, vault format, TOTP, health checks — no UI, no I/O
crates/yara-broker   approval-gated credential access for agents
crates/yara-cli      the `yara` command an agent runs
crates/yara-mcp      MCP server, for agents that speak it natively
apps/desktop          Tauri v2 app (React + TypeScript frontend)
docs/                 design notes
```

`yara-core` deliberately has no dependency on Tauri or on the filesystem. It
takes bytes and passwords and returns bytes, which keeps the part that matters
small enough to audit and testable on its own.

## Build

Requires Rust, Node 20+, and on Windows the MSVC build tools.

```bash
cargo test -p yara-core
```

```bash
cd apps/desktop && npm install && npm run tauri dev
```

`npm run dev` on its own serves the interface in an ordinary browser against a
fake IPC layer with invented data, which is faster to iterate on than a full
Tauri rebuild. The mock is dev-only and cannot reach a release build.

## Status

- [x] Argon2id + XChaCha20-Poly1305 core, 170 tests
- [x] Vault format with envelope encryption and tamper detection
- [x] TOTP (RFC 6238) verified against the RFC test vectors, `otpauth://` parsing
- [x] QR enrollment by paste, drag-and-drop, or file, decoded in Rust
- [x] Import two-factor codes from a Proton Authenticator backup
- [x] Offline password health checks: reuse, strength, missing second factors
- [x] Desktop UI, auto-lock, clipboard that clears itself
- [x] Agent broker: protocol, grants, audit log, named pipe transport
- [x] Approval prompt, permissions screen, and the `yara` command line client
- [x] MCP server, so any MCP-capable agent can use the vault directly
- [x] Signed auto-update, served from `yara.lat`
- [x] Sync service: signed requests, ciphertext the server cannot read
- [x] Sync in the desktop app: enrol, recovery kit, reconcile
- [ ] Web app

**Windows only, deliberately.** The broker's transport is named pipes and its
caller identification is a Win32 call; porting those is not planned. `yara-core`
stays free of platform dependencies anyway, and CI builds it on Linux to keep
that honest — but the application is not coming to macOS or Linux.

The same is true of `yara-broker`, `yara-cli` and `yara-mcp`: every piece that
actually needs Windows sits behind its own `cfg(windows)`, and the rest — the
protocol, the grant store, the audit log — has no reason not to compile
anywhere else, so CI checks it on Linux too rather than leaving that claim
unverified.

## Reporting a vulnerability

Privately, through GitHub — the **Report a vulnerability** button under
**Security**, not a public issue. [SECURITY.md](SECURITY.md) has the channel,
what is in scope, and how long an answer takes, written to be met by one person
rather than to sound reassuring.

## License

MIT
