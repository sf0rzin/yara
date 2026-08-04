# Hosting

`yara.rindexx.cc` serves the update manifest the desktop app polls, the sync
service that lets a vault follow you between machines, and a static site. Scope
is a handful of invited people, and the design leans on that.

The organising principle is that no hop is trusted. Update artifacts are signed
with a key no server here has ever seen. The sync service stores ciphertext it
has no key for, and requests are signed rather than bearing a token, so neither
the CDN nor the front proxy can act as a user. A full compromise of this
infrastructure costs availability and a set of metadata. It does not cost
anyone their vault, and it does not let an attacker ship a malicious update.

The second principle is that the server is optional. A vault works completely
offline, with no account, exactly as it does today. Sync is a layer on top.
Invert that — make the account mandatory — and downtime becomes somebody locked
out of a production database.

## Topology

```
client → Cloudflare → beta:443 → DNAT → edge:443 → 10.10.1.21:80
         (TLS #1)     (dedicated)       (Caddy,    (Caddy, origin)
                                         TLS #2)
```

| | |
| --- | --- |
| **beta** | Hetzner dedicated, Falkenstein. `142.132.199.184`, Proxmox VE 9 |
| **edge** | VM 104, `10.10.1.2`. Routes 80/443 by hostname; holds every cert |
| **ayla** | VM 101, `10.10.1.20`. Fastify + Postgres, a peer service |
| **anglis** | VM 103, `10.10.1.22`. Another peer service |
| **yara** | VM 102, `10.10.1.21`. This project's origin |

The origin runs on VM 102: Debian 13, 2 vCPU, 4 GB RAM, 40 GB, on `vmbr1`, the
private NAT bridge. It has no public address and no forwarded port. Reach it
with `ssh yara`, which jumps through beta.

Why this is small: a conventional login service runs the password KDF itself
and needs `64 MiB × concurrent logins` of headroom. Here the expensive
derivation happens on the client, and the server verifies signatures. Sync
payloads are encrypted items measured in kilobytes; a few dozen users with a
few hundred items each is a database of a few megabytes.

### Why it goes through a shared edge

Only one machine can hold `142.132.199.184:443`, and there are three services
behind it. Giving yara its own public IPv4 would cost about €1.70/month and buy
isolation; sharing the proxy that has to exist anyway costs nothing. The second
was chosen deliberately, and the signed-request protocol below is what makes it
safe.

Two things about that edge are load-bearing rather than incidental:

**The origin declares its site as `http://yara.rindexx.cc`.** Drop the scheme
and Caddy turns on automatic HTTPS, answers 308 on port 80, and the edge hands
that redirect back to a client who follows it into the same 308 — a loop that
reads as a working proxy right up until someone follows it. Peers that do want
their own TLS get reached over `https://` with an explicit `tls_server_name`,
since the SNI would otherwise be an IP address no certificate matches.

**The origin trusts exactly one address for `X-Forwarded-For`.** If the edge
moves, `trusted_proxies` moves with it or `{client_ip}` silently becomes either
the proxy's address or something any caller can forge.

### What each hop can see

Cloudflare terminates TLS, so it sees plaintext HTTP: paths, headers, timings,
and bodies. It cannot read vault items — those are ciphertext at the
application layer — and it cannot act as a user, because requests are signed
with a key that never crosses the wire. Ayla sees the same and no more.

The honest residue is metadata: how many items an account holds, roughly how
large each is, when each changed, and which addresses connected when. That
belongs in the user-facing threat model, not only here.

Client addresses survive both hops. Cloudflare sends `CF-Connecting-IP`, ayla's
global `trusted_proxies` block believes it and only it, and ayla forwards the
resolved value as a single `X-Forwarded-For` entry that the origin accepts from
`10.10.1.20/32` alone. Break either half and `{client_ip}` becomes forgeable by
any caller — it is the one audit field that has to be true.

## DNS

```
A  yara.rindexx.cc → 142.132.199.184   proxied
```

Proxied is not optional: grey-clouding this record points it at a host whose
firewall will not answer a non-Cloudflare address. `deploy/dns.ps1` creates it
idempotently and reads its token from the environment rather than an argument.

There is no `AAAA`. IPv6 forwarding to guests is off on beta and ayla has no
public v6 either; adding it later is a separate piece of work.

**A new hostname is public the moment it has a certificate.** Let's Encrypt
publishes every issuance to Certificate Transparency, and scanners read those
logs continuously — this host took its first unsolicited crawl within two
seconds of issuance. Nothing here should ever depend on an endpoint being
unknown, and rate limiting matters from day one rather than at launch.

## Layout

| Path | Serves |
| --- | --- |
| `/` | static site |
| `/updates/latest.json` | Tauri update manifest |
| `/downloads/*` | installers, if self-hosted |
| `/api/v1/*` | sync service on `127.0.0.1:8787` |

```
/srv/yara/site/            landing page
/srv/yara/updates/         latest.json
/srv/yara/downloads/       installers and .sig files, if self-hosting them
/var/lib/yara-sync/        sync.db
```

`deploy/Caddyfile` is the origin's config. It does not speak ACME and names its
host rather than binding `:80` generally, so it will not answer for anything
else that reaches the bridge.

One operational footgun, learned the hard way: do not run `caddy validate` as
root when the config declares a file log. It creates the log file as
`root:root 0600` and the service, which runs as `caddy`, then fails to start
with a permission error that points at the directory rather than the file.

## Auto-update

Wired up. `tauri-plugin-updater` and `tauri-plugin-process` are registered for
desktop targets in `apps/desktop/src-tauri/src/lib.rs`, the pubkey and endpoint
live in `tauri.conf.json`, and `createUpdaterArtifacts` is on so a build emits
the `.sig` files.

The client side is `src/lib/updates.ts` and `src/components/UpdateNotice.tsx`:
one check at launch, an offer the user can dismiss, and no modal. The check is
silent on failure — an unreachable server is indistinguishable from being
current — but a failed *install*, which the user asked for, says so.

The notice only ever renders behind the unlock screen. Answering an update
prompt is not something to do before proving you own the vault, and installing
restarts the process, which locks it. The button says so.

### Keys

`tauri signer generate` produced the pair. The private half lives at
`~/.tauri/yara-updater.key`, ACL-restricted to the owner, and **must never be
placed on this infrastructure**. That separation is the entire security
argument for the update channel: the machine that serves updates cannot sign
one. An attacker holding root on beta can withhold or corrupt an update; it
cannot get code onto a user's machine, because the client verifies the minisign
signature against the public key compiled into it before executing anything.

CI needs it as `TAURI_SIGNING_PRIVATE_KEY`, plus
`TAURI_SIGNING_PRIVATE_KEY_PASSWORD` — currently empty, because the key was
generated without a passphrase. A passphrase would mean two secrets instead of
one, which is worth little when both would sit in the same GitHub secrets
store; set one if the key ever leaves that store.

Rotating the key is a breaking change: clients verify against the key they
shipped with, so an installed 0.1.x cannot be updated to something signed by a
new key. Rotation means shipping a build that trusts the new key and getting
everyone onto it manually first.

### Manifest

A static `latest.json` is enough at this scale. Both Windows bundle targets are
updater-compatible — NSIS produces `yara_x.y.z_x64-setup.exe` plus a `.sig`,
WiX produces `.msi` plus a `.sig`. Ship NSIS as the update artifact and keep MSI
for anyone deploying by policy. `deploy/latest.json.example` is the shape.

`tauri-action` generates the manifest and uploads it as a release asset, with
its `url` fields pointing at the installers on GitHub Releases. The origin
mirrors that asset — see [Deployment](#deployment). Serving the manifest here
and the installers there is deliberate: the manifest is a few hundred bytes and
you want control over when a release becomes visible, while the installers are
~10 MB each and there is no reason to pay for that egress when the signature
already makes the download host untrusted.

`/updates/latest.json` answers **204** while no manifest exists, which the
updater reads as "you are current". A 404 would work too but puts a failed
check in every client's log before the first release is even cut.

## Sync

Implemented in `crates/yara-sync`, which mirrors the broker's split: `auth`
decides who gets in and is pure, `store` is the only module that touches a
database, `api` is the only one that knows about HTTP.

The desktop client is not written yet, so nothing pushes to it — but the
service itself is complete and tested against real signed requests.

### Two secrets, not one

An account has a password *and* a 128-bit **secret key** generated on the
client at enrolment, shown once, and required when authorising a new device.

Once you host encrypted vaults you become a target, and the realistic attack is
not against XChaCha20 — it is running Argon2id offline against the stored blob
of whoever chose a weak password. Mixing 128 bits of generated entropy into the
derivation makes that infeasible regardless of what the user typed. It is the
same reasoning behind 1Password's Secret Key.

This is also the recovery kit. A single printed artifact authorises a new
device and restores access to an account, and it exists exactly once in the
design rather than twice.

### Key hierarchy

Entirely on the client:

```
master_key = Argon2id(password ‖ secret_key, account_salt)   64 MiB / 3 / 4
enc_key    = HKDF(master_key, "yara.enc.v1")
```

`enc_key` never leaves the machine. It wraps two things, both stored
server-side as opaque blobs:

- the **vault key**, the same 32 bytes `yara-core` already wraps under the
  master password, wrapped a second time under a different key
- the account's **Ed25519 signing key**, which is what proves identity

### Nothing secret crosses the wire

There is no password hash on the wire, no bearer token, and no shared secret
the server could replay. Authentication is a signature.

Each device generates its own Ed25519 keypair at enrolment and registers the
public half; the registration is itself signed by the account key, which a new
device obtains by downloading the wrapped blob and unwrapping it locally with
the password and secret key. Every request then carries:

```
Authorization:      yara1 <account_id>/<device_id>
X-Yara-Timestamp:   <unix seconds>
X-Yara-Nonce:       <16 random bytes, base64>
X-Yara-Signature:   Ed25519(device_key, method ‖ path ‖ ts ‖ nonce ‖ SHA256(body))
```

The server verifies against the stored public key, rejects a timestamp outside
±60 seconds, and rejects a nonce it has already seen inside that window.

This is what makes the Cloudflare hop acceptable. A passive observer with full
plaintext gets signatures over requests that already happened; it cannot mint a
new one, and the replay window is a minute wide with nonce tracking behind it.
A bearer token would hand that observer the account.

It also means a compromised server cannot impersonate a user to anyone, and
that revoking a lost laptop is deleting one public key.

SRP would have removed a password-derived value from the wire. This removes the
concept entirely, and is less code.

### Enrolment

No public signup, no email, no verification flow. You generate an invite code,
it is good once, and it expires. That removes deliverability, SPF/DKIM/DMARC,
bounce handling, and an entire class of abuse from the operational surface.

### Protocol

Items are already encrypted individually under the vault key, so sync ships
opaque per-item records rather than a whole file. The server assigns a
monotonic revision to every write:

```
GET  /api/v1/health                                 → {service, version}
GET  /api/v1/account/{id}                           → {salt, kdf, wrappedVaultKey, wrappedAccountKey, revision}
POST /api/v1/devices   {accountId, deviceId, publicKey, invite?}
GET  /api/v1/items?since=<revision>                 → {revision, items[]}
POST /api/v1/items     {expectedRevision, items[]}  → {revision} | 409
```

Signed requests carry:

```
Authorization:      yara1 <account_id>/<device_id>
X-Yara-Timestamp:   <unix seconds>
X-Yara-Nonce:       <at least 16 bytes, base64>
X-Yara-Signature:   Ed25519 over  method \n path \n ts \n nonce \n sha256(body)
```

The signature is checked against the **raw body bytes before they are parsed**.
Verifying a re-serialised body would cover something the client never sent,
which is the quiet way a signing scheme stops meaning anything.

`since` is not signed and does not need to be: it can only narrow what the
account may already read, so a tampered value costs the caller a re-fetch and
nothing else. Nothing that changes meaning is allowed in a query string for
exactly that reason.

Operators get one command, because invites are the only thing that needs a
human:

```bash
yara-sync invite    # a single-use code, valid 48 hours, stored hashed
yara-sync purge     # drop tombstones older than 30 days
```

Each item is `{id, revision, ciphertext, deleted}`. The client pulls everything
above the revision it last saw and pushes with optimistic concurrency; a 409
means pull and retry. Conflicts resolve last-write-wins per item, keeping the
loser as a conflict copy — do not reach for CRDTs, the write rate of a password
manager does not justify them.

Deletes are tombstones, purged after 30 days. Without them a delete on one
machine is silently undone by the next sync from another.

`/account` returns blobs that are useless without the password and secret key,
so it needs no signature — but it does need a rate limit, because it is the one
endpoint that hands an attacker something to grind against. Rate limiting lives
in the service, not in Caddy: stock Caddy has no rate limiter and adding one
means maintaining a custom `xcaddy` build.

### Storage

A few dozen accounts with a few hundred items each is single-digit megabytes.
SQLite in WAL mode is correct and will stay correct well past the point this
project needs it to; Postgres would be operational cost bought for nothing.

Back it up with Litestream replicating continuously to S3-compatible object
storage — that is what buys point-in-time restore without running a database
server. Rehearse a restore before you need one; an unverified backup is a
belief, not a backup.

The saving grace: every client holds a full local vault. The server is a
convenience, not the only copy. Keep it that way and losing this VM entirely is
an inconvenience rather than a catastrophe.

## Continuous integration

`.github/workflows/ci.yml` runs on every push and pull request:

| Job | Runner | What it defends |
| --- | --- | --- |
| Workspace | windows-latest | `fmt`, `clippy -D warnings`, the whole test suite |
| Core | ubuntu-latest | that `yara-core` still has no platform dependency |
| Supply chain | ubuntu-latest | `cargo-deny`: advisories, licences, sources |

The Linux job exists for one reason. `yara-core` claims to be free of UI and
platform entanglement — that is the claim that keeps the part worth auditing
small — and a claim nothing enforces decays. The rest of the workspace has no
Linux build to run: the broker's transport is named pipes and its caller
identification is a Win32 call.

`deny.toml`'s licence allowlist was derived from the tree as it actually is, so
a new entry appearing there is a real change in what the project depends on.

## Deployment

CI builds, signs, and publishes to GitHub Releases. Nothing here compiles
anything and nothing here holds a signing key. Cut a release by pushing a tag
that matches the version in `tauri.conf.json`.

The origin then **pulls**. `yara-manifest.timer` runs every five minutes,
fetches the `latest.json` asset from the newest release, parses it, and renames
it into place — same filesystem, so a client polling mid-write reads either the
old manifest or the new one and never half of either.

Pull rather than push, deliberately. The origin has no public port, so pushing
from CI would have to jump through beta, which means putting a key that opens
the Proxmox host into GitHub Actions secrets in order to publish a 300-byte
JSON file. That is a large grant for a small errand, and it points the wrong
way: a compromised workflow would reach the infrastructure rather than just the
release. Pulling costs a few minutes of latency before a release becomes
visible and buys the absence of that credential entirely.

Nothing the mirror fetches is trusted. A hostile manifest cannot produce a
hostile update, because the installer it names still has to carry a signature
the client accepts, and the signing key is not on GitHub's side of this either.
The worst it achieves is withholding an update or offering one that fails
verification on the client.

The mirror is also quiet about the ordinary states — no releases yet, rate
limited, GitHub down — because none of them are reasons to stop serving the
manifest already on disk.

## Obligations

Holding other people's data, even encrypted and even for friends, brings a
short list worth an afternoon rather than a surprise: a privacy notice saying
what is stored and what is visible, a route to delete an account and have it
actually deleted, and incident notification if the machine is breached. LGPD
and GDPR both apply at this scale; neither is onerous when the honest answer to
"what did they get" is "wrapped blobs and timestamps".

## When to resize

- **Public signup.** Different problem entirely — abuse handling, email, and a
  storage curve that stops being a rounding error.
- **Attachments or file storage.** Disk and bandwidth start to matter.
- **A second web service on beta.** 80/443 are ayla's; that is the point at
  which the €1.70 IPv4 stops being avoidable.

Traffic growth alone will not do it. This workload does not compute on secrets.
