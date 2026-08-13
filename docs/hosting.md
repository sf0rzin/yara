# Hosting

`yara.lat` serves the update manifest the desktop app polls and the sync
service that lets a vault follow you between machines. Nothing else — the root
answers 404, because there is no landing page in this repository and a domain
that serves three paths has three things to get wrong. Scope is a handful of
invited people, and the design leans on that.

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
client → Cloudflare → cloudflared → caddy:8080 → sync:8787
         (TLS)        (outbound     (container)   (container)
                       tunnel)
```

| | |
| --- | --- |
| **sforzin** | Dedicated, Amsterdam. `131.153.158.241`, Ubuntu 24.04, shared with other projects |
| **cloudflared** | Dials out to Cloudflare. Nothing dials in |
| **caddy** | Routes by path, serves the two static trees |
| **sync** | The API and the icon proxy, on the `app` network only |

Everything runs as one compose project, `yara`, on a host that carries several
unrelated projects. The rule that makes that work is one compose project and
one tunnel per project, publishing no port — see
`Workspace/docs/servers/sforzin.md`. Reach the host with
`ssh -i keys/ssh/nora-host/nora-host ubuntu@131.153.158.241`, or `ssh
nora-direct`.

There is no inbound port anywhere in that chain. The host listens on 22 and
nothing else that belongs to this project; traffic arrives down a connection
cloudflared opened outwards.

Why this is small: a conventional login service runs the password KDF itself
and needs `64 MiB × concurrent logins` of headroom. Here the expensive
derivation happens on the client, and the server verifies signatures. Sync
payloads are encrypted items measured in kilobytes; a few dozen users with a
few hundred items each is a database of a few megabytes.

### The topology this replaced

An earlier version of this document described a Hetzner dedicated host running
Proxmox, with the origin on a private bridge behind a shared edge proxy. That
infrastructure is gone — the host answers on no port — and it is worth being
explicit that it was never serving anyone: every update check every released
client ever made failed silently against it.

One consequence outlives it. Releases up to v0.3.2 have
`https://yara.rindexx.cc/updates/latest.json` compiled into the binary, and
that hostname is not served here. Those installs cannot be updated remotely;
the endpoint is not something a server can move. Anyone on 0.3.2 or earlier has
to install the next release by hand, after which the endpoint is `yara.lat` and
the updater works normally.

### Why it goes through a tunnel

The host has no free 443 and should not grow one. Every project on it reaches
the outside the same way: its own `cloudflared`, dialling out, with an internal
Caddy behind it routing by hostname. Two projects with different domains
therefore never contend for a port, and neither one's ingress dies with the
other.

Three things about that arrangement are load-bearing rather than incidental:

**The origin declares its site as `http://yara.lat:8080`.** Drop the scheme and
Caddy turns on automatic HTTPS, answers 308, and cloudflared hands that
redirect back to a client who follows it into the same 308 — a loop that reads
as a working proxy right up until someone follows it.

**Caddy trusts exactly one subnet, and that subnet is pinned in compose.** Let
Docker allocate it and `trusted_proxies` either stops matching, in which case
every audit record carries the tunnel's address instead of the client's, or
starts covering a range some later project also lands in.

**The unmatched-host block is not decoration.** Caddy answers a request that
matches no route with an empty 200 and its own `Server` header. The host
matcher does keep such a request away from the sync service — that was tested,
not assumed — but the bare 200 is a lie and a free banner, so an explicit
catch-all returns 404 instead.

### What each hop can see

Cloudflare terminates TLS, so it sees plaintext HTTP: paths, headers, timings,
and bodies. It cannot read vault items — those are ciphertext at the
application layer — and it cannot act as a user, because requests are signed
with a key that never crosses the wire.

The honest residue is metadata: how many items an account holds, roughly how
large each is, when each changed, and which addresses connected when. That
belongs in the user-facing threat model, not only here.

Client addresses survive the hop. Cloudflare sets `CF-Connecting-IP`,
cloudflared passes it through untouched, and Caddy reads it as `{client_ip}`
because the tunnel's subnet is in `trusted_proxies`. Trusting a header like
that is only safe because the listener is unpublished: there is no path to it
that skips the tunnel. Break that and `{client_ip}` becomes forgeable by any
caller — it is the one audit field that has to be true.

## DNS

```
CNAME  yara.lat → <tunnel-id>.cfargotunnel.com   proxied
```

The zone lives on Cloudflare and the registrar is Namecheap, whose nameservers
have to be set to `elma.ns.cloudflare.com` and `micah.ns.cloudflare.com` —
the pair this account uses for every zone. Order matters when standing this up:
create the zone first, then move the nameservers. Point a registrar at
Cloudflare for a zone that does not exist yet and the domain simply stops
resolving.

Proxied is not a choice here. A `cfargotunnel.com` target only resolves inside
Cloudflare, so grey-clouding the record leaves it aimed at a name the public
internet cannot look up. There is no origin address being hidden either way:
the host has no inbound port to find.

The apex is a CNAME, which is only legal because Cloudflare flattens it at the
edge and answers with addresses of its own.

There is no `AAAA` and none is needed — Cloudflare answers on both families
regardless of what the tunnel speaks.

There is no script for this. The old `deploy/dns.ps1` maintained an A record
against a host whose address could change; a tunnel's DNS target is derived
from the tunnel id and never moves, so the record is written once when the
tunnel is created and the script was deleted rather than left to rot.

**A new hostname is public the moment it has a certificate.** Let's Encrypt
publishes every issuance to Certificate Transparency, and scanners read those
logs continuously — this host took its first unsolicited crawl within two
seconds of issuance. Nothing here should ever depend on an endpoint being
unknown, and rate limiting matters from day one rather than at launch.

## Layout

| Path | Serves |
| --- | --- |
| `/` | 404 |
| `/updates/latest.json` | Tauri update manifest |
| `/downloads/*` | installers, if self-hosted |
| `/api/v1/*` | sync service, `sync:8787` on the `app` network |

On the host:

```
/opt/yara/                 the git clone; deploy/ is read straight out of it
/srv/yara/data/            sync.db and the icon cache, owned by uid 10001
/srv/yara/updates/         latest.json
/srv/yara/downloads/       installers and .sig files, if self-hosting them
/srv/yara/logs/            caddy's access log
/srv/yara/secrets/         tunnel.env, mode 0600, root
```

`deploy/Caddyfile` is the origin's config, bind-mounted read-only into the
container. It does not speak ACME, and the two site blocks between them mean
every request either matches `yara.lat` or gets a 404.

The state directory is a bind mount rather than a named volume so that a
backup, an operator, and `yara-sync purge` all find the database at the path
this table names. It is owned by uid 10001 because the container declares that
uid rather than looking a name up — a name would resolve to whatever the base
image happened to allocate, and the ownership of a bind mount has to survive a
base image change.

## Auto-update

Wired up. `tauri-plugin-updater` and `tauri-plugin-process` are registered for
desktop targets in `apps/desktop/src-tauri/src/lib.rs`, the pubkey and endpoint
live in `tauri.conf.json`, and `createUpdaterArtifacts` is on so a build emits
the `.sig` files.

The client side is `src/lib/updates.ts` and `src/components/UpdateNotice.tsx`:
one check, an offer the user can dismiss, and no modal. The check is silent on
failure — an unreachable server is indistinguishable from being current — but a
failed *install*, which the user asked for, says so.

**The check runs on unlock, not on launch.** `checkForUpdate` fires from
`UpdateNotice`'s effect, `UpdateNotice` renders inside the item list, and
`App.tsx` mounts `Vault` only when the screen is `unlocked` — a locked app makes
no request at all. This paragraph used to say "at launch" and to describe the
notice as rendering *behind* the unlock screen, as though the vault were mounted
underneath it. It is not, and the difference is visible from the server: launch
the app and leave it locked, and `/updates/latest.json` records nothing.

The behaviour is the intended one either way. Answering an update prompt is not
something to do before proving you own the vault, and installing restarts the
process, which locks it. The button says so.

It also means the update path cannot be exercised without a real vault and its
password, which is worth knowing before trying to verify a release from the
outside.

### Keys

`tauri signer generate` produced the pair. The private half lives at
`~/.tauri/yara-updater.key`, ACL-restricted to the owner, and **must never be
placed on this infrastructure**. That separation is the entire security
argument for the update channel: the machine that serves updates cannot sign
one. An attacker holding root on sforzin can withhold or corrupt an update; it
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

**There is no server-side backup, on purpose.** Every client holds a complete
local vault; the server carries a copy for machines to meet at, not the copy.
Losing this VM costs the ability to sync until it is rebuilt, and the next push
from any device refills it.

Be clear about where that stops being true. It holds while at least one device
still has the vault. An account whose only machine dies *and* whose server
copy is gone has lost the data, and no recovery kit helps — the kit unwraps
ciphertext, it does not conjure it. That is the trade, and it is a reasonable
one for a handful of people who each have more than one machine.

If it ever stops being reasonable, Litestream replicating the SQLite file to
S3-compatible storage is the answer, and it is an afternoon.

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

Pull rather than push, deliberately. The host has no inbound port but 22, so
pushing from CI would mean putting an SSH key for a machine that also runs
somebody else's production into GitHub Actions secrets in order to publish a
300-byte JSON file. That is a large grant for a small errand, and it points the
wrong way: a compromised workflow would reach the infrastructure rather than
just the release. Pulling costs a few minutes of latency before a release
becomes visible and buys the absence of that credential entirely.

Nothing the mirror fetches is trusted. A hostile manifest cannot produce a
hostile update, because the installer it names still has to carry a signature
the client accepts, and the signing key is not on GitHub's side of this either.
The worst it achieves is withholding an update or offering one that fails
verification on the client.

The mirror is also quiet about the ordinary states — no releases yet, rate
limited, GitHub down — because none of them are reasons to stop serving the
manifest already on disk.

## Site icons

The origin proxies favicons so the client never asks a site directly. Asking
github.com for its icon tells github.com that a vault holds a GitHub account,
and doing it per row puts the shape of the vault on the wire. Bitwarden runs
the same arrangement for the same reason.

What it costs, stated rather than buried: this server learns which domains are
asked about. Requests carry no signature and no account id, so it learns the
domain and not whose vault — thin cover on a server with few users, which is
why the app has a setting to turn icons off, and why turning it off deletes
what was cached.

The endpoint fetches on behalf of an unauthenticated caller, which makes it an
SSRF vector by construction. Two things hold it:

- The domain is validated identically in the client and the server. It becomes
  both a URL to fetch and a filename to write, so a slash or a dot-dot would be
  a path traversal and a scheme or a port would aim the fetch elsewhere.
- A packet filter denies the private address ranges outright. String validation
  cannot catch `10-3-0-11.nip.io` — that is a real name that resolves to a
  private address — and an application-level resolve-then-connect check is racy
  against DNS rebinding by construction.

That filter used to be systemd's `IPAddressDeny`. There is no container
equivalent, so `deploy/egress-guard.sh` rebuilds it in iptables against the
`app` subnet, which is pinned in compose for exactly this reason.

**It hooks `INPUT` as well as `DOCKER-USER`.** This is the part that is easy to
get wrong. `DOCKER-USER` filters traffic being forwarded onward; traffic
addressed to one of the host's own addresses is delivered locally and never
reaches the FORWARD chain at all. With only the `DOCKER-USER` hook, a container
that resolves a name to the host's public address still reaches sshd on it.

**The deny list stands alone, with no allow list beside it.** In the systemd
form an `IPAddressAllow` entry wins over a deny entry, so the paired form
matched everything on the allow side and never consulted the deny list — found
by testing the running service rather than by reading. The iptables form keeps
the same shape for the same reason: one `RETURN` for the subnet Caddy needs,
then denials, then fall-through.

Re-run the guard after `docker compose up`. Docker rebuilds its own chains when
it creates networks, and that can drop the hooks.

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
- **Anything that needs an inbound port.** A tunnel carries HTTP well and
  arbitrary TCP awkwardly. That is the point at which this host stops being the
  right shape, not the point at which it needs to be bigger.

Traffic growth alone will not do it. This workload does not compute on secrets.
