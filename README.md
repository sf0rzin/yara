# lapse

A password manager with a built-in authenticator and a safe way to hand
credentials to AI agents.

> Early development. The cryptographic core is implemented and tested; the
> desktop UI and the agent broker are in progress.

## Why

Three things, in order of how much they motivated the project:

**Agents need credentials and there is no good way to give them any.** Pasting a
secret into a chat puts it in the model's context forever. Putting it in a
`.txt` and telling the agent "it's in there" just moves the plaintext to disk.
lapse gives agents an approval-gated broker that runs commands with credentials
injected, so the value never enters the agent's context at all. See
[docs/agent-access.md](docs/agent-access.md).

**Reaching for your phone for a 6-digit code is tedious.** lapse generates TOTP
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
crates/lapse-core     crypto, vault format, TOTP — no UI, no I/O
apps/desktop          Tauri v2 app (React + TypeScript frontend)
docs/                 design notes
```

`lapse-core` deliberately has no dependency on Tauri or on the filesystem. It
takes bytes and passwords and returns bytes, which keeps the part that matters
small enough to audit and testable on its own.

## Build

Requires Rust, Node 20+, and on Windows the MSVC build tools.

```bash
cargo test -p lapse-core
```

```bash
cd apps/desktop && npm install && npm run tauri dev
```

## Status

- [x] Argon2id + XChaCha20-Poly1305 core, 52 tests
- [x] Vault format with envelope encryption and tamper detection
- [x] TOTP (RFC 6238) verified against the RFC test vectors, `otpauth://` parsing
- [ ] Desktop UI
- [ ] Agent broker and MCP server
- [ ] Web app

## License

MIT
