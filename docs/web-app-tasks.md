# Building the web app — task pack

The README has one unchecked box, and this is it. Ten slices, split between two
contributors, that end with a vault you can open in a browser.

This document is written to be read by an AI assistant working on behalf of a
contributor. It is deliberately specific about what to build, what not to
build, and what "finished" means, because the reviewer is one person and a pull
request that has to be explained twice costs more than it gives.

This is the more speculative of the two task packs.
[contributor-tasks.md](contributor-tasks.md) lists ten gaps in code that already
exists, each one scoped down to the files it touches; take those first if you
would rather start somewhere the ground is known to hold.

---

## The one rule

**Do not reimplement any cryptography in JavaScript.**

`yara-core` is a Rust crate with no platform and no UI dependency — the CI
builds it on Linux specifically to keep it that way. It already contains the
key derivation, the vault format, the AEAD, the item sealing and the TOTP
engine, and all of it is tested. The web app compiles that crate to
WebAssembly and calls it.

A second implementation of Argon2id or XChaCha20-Poly1305 in TypeScript would
be a second thing to audit, a second thing to get wrong, and a second place for
the two to drift apart. If you find yourself reaching for a JS crypto library,
stop and ask.

The same rule applies to the wire protocol. Requests are signed, and
`crates/yara-sync-client/src/signing.rs` already defines the exact bytes that
get signed. `crates/yara-sync-client/tests/interop.rs` exists because two
independently correct halves can still disagree on the wire; anything you add
that talks to the server belongs in that file too.

---

## Scope of version one: read-only

The web app **opens a vault and shows what is in it**. It does not create
items, edit them, delete them, or push anything.

That is a real product — your vault from any machine, without installing
anything — and it stops short of the part that is genuinely hard. Writing means
optimistic concurrency, conflict resolution, and sealed deletion proofs, and
getting any of those subtly wrong loses somebody's data rather than
inconveniencing them. It is not the right first contribution to a password
manager.

What must stay true, and what the reviewer will check first:

- The server never receives the master password, the recovery kit, or anything
  derived from either. It stores ciphertext and cannot read it. This is the
  entire security argument of the project, stated in `docs/hosting.md`.
- Keys live in memory for the length of a session and are wiped when it ends.
  Nothing goes in `localStorage`, `sessionStorage`, `IndexedDB` or a cookie —
  not the password, not the kit, not the derived keys, not the decrypted items.
- The interface is monochrome. There is no accent colour and no status colour
  anywhere in yara: danger and success are carried by wording, weight and
  placement. Read `apps/desktop/src/styles/tokens.css`, which states the rule
  and the reasoning.

---

## Before you start

```bash
# Fork github.com/sf0rzin/yara on GitHub, then:
git clone https://github.com/<your-username>/yara.git
cd yara
git remote add upstream https://github.com/sf0rzin/yara.git
```

Requirements: Rust, Node 20+, and on Windows the MSVC build tools. The wasm
work also needs `rustup target add wasm32-unknown-unknown` and
[`wasm-pack`](https://rustwasm.github.io/wasm-pack/).

Confirm the tree is green before you change anything, so that a failure later
is yours and you know it:

```bash
cargo test --workspace --locked
cd apps/desktop && npm ci && npx tsc --noEmit && npm run lint && npm test
```

Expect 444 Rust tests and 20 frontend tests to pass.

One branch per slice, named for what it does:

```bash
git switch -c web-wasm-core     # not "fix", not "task-1"
```

---

## Track A — getting the vault into the browser

Five slices. Each one ends with something demonstrable, and the first is the
one everything else rests on.

### A1. Make `yara-core` compile to `wasm32-unknown-unknown`

The whole plan rests on this, so it is the first slice rather than something
discovered in week three.

It does not compile today. This is measured, not guessed —
`cargo build -p yara-core --target wasm32-unknown-unknown` stops at:

```
error: the wasm*-unknown-unknown targets are not supported by default,
       you may need to enable the "js" feature.
  --> getrandom-0.2.17/src/lib.rs:346:9
error: could not compile `getrandom` (lib) due to 1 previous error
```

That is the first error and the build aborts on it, so whether anything behind
it also fails is still unknown. Finding out is part of this slice.

The crate depends on `argon2`, `chacha20poly1305`, `hkdf`, `hmac`, `sha1`,
`sha2`, `subtle`, `ed25519-dalek`, `uuid`, `zeroize` — all pure Rust and all
expected to work — plus `image` and `rqrr`, which exist only to decode QR
codes for TOTP enrolment. A read-only web app never scans a QR code.

- Fix the randomness first, because nothing else can be observed until it
  builds past this point. `uuid`'s `v4` and `crypto::random_bytes` both reach
  `getrandom`, which needs its `js` backend on this target. Solve it **for the
  wasm target only** — enabling that feature unconditionally would change where
  randomness comes from on Windows and Linux too, which is not a thing to do as
  a side effect of a browser build.
- Then build again and deal with whatever the next error is. Write down each
  one in the pull request, including any that turn out to be trivial; the point
  of this slice is a record of what the claim "no platform dependency" actually
  costs.
- Put `image` and `rqrr` behind a default-on Cargo feature (`qr`, say) so a
  wasm build can leave them out. Everything that uses them — `qr.rs` and its
  callers — moves behind the same feature.
- `cargo test -p yara-core` must still pass with default features, and the CI
  job that builds the crate on Linux must still pass.

**Done when:** the crate builds for wasm32 without the QR feature, the existing
suite is untouched and green, and the pull request lists every error you hit
and what each one needed.

**Teaches:** that "no platform dependency" is a claim a build either supports
or does not, and how Cargo features carve a crate down for a target that cannot
have all of it.

### A2. A `yara-wasm` crate exposing the vault to JavaScript

A new workspace member wrapping `yara-core` with `wasm-bindgen`. Keep the
surface small — every function here is a place a secret could escape into the
JS heap where nothing wipes it.

Enough for a read-only client:

- derive account keys from a password and a recovery kit, given the salt and
  KDF parameters the server returned
- unwrap the vault key from the wrapped blob
- open one sealed item, returning a plain object with no secret in it unless
  it was asked for by name

Return errors as values with the same non-oracle wording the vault uses. A
wrong password and a tampered blob are one event to a caller: `yara-core`
deliberately reports them identically and the wrapper must not undo that.

**Done when:** `wasm-pack build` produces a package, and a test in the crate
proves a round trip — seal an item with `yara-core`, open it through the
wrapper, get the same value back.

**Teaches:** designing an FFI boundary around secrets, and why the smallest
surface is the right one.

### A3. Talk to the sync service from the browser

The client half of the protocol, in TypeScript, calling into A2 for anything
cryptographic. Signing lives in the wasm crate — the Ed25519 key must never
cross into JS.

Read `crates/yara-sync-client/src/client.rs` first. You are building the same
two unsigned requests a joining device makes — fetch the account blobs, and
that is it, because a read-only client never registers a device.

Treat everything the server returns as hostile. The KDF parameters come from
it, and `yara-core` bounds them for exactly that reason.

**Done when:** given a base URL and an account id, the browser fetches the
account blobs and reports a failure honestly when it cannot.

**Teaches:** that "the server is not trusted" is a set of specific checks, not
a slogan.

### A4. Pull and decrypt the item list

`GET /api/v1/items?since=0` returns every item as opaque ciphertext. Decrypt
each through A2 into a typed list the interface can render.

- An item that will not decrypt is skipped, not fatal. One unreadable record —
  written by a newer build, corrupted in transit — must not stop the other
  ninety-nine from appearing. The desktop does this in
  `apps/desktop/src-tauri/src/sync.rs`; match the behaviour.
- Tombstones are records with `deleted: true` and no ciphertext. A read-only
  client simply does not show them. Do **not** implement deletion proofs; that
  is the write path.

**Done when:** a real account's items appear as a typed array, and a
deliberately corrupted record costs exactly one row.

**Teaches:** partial failure as a design choice rather than an accident.

### A5. Make the session end

Keys and decrypted items exist only while the tab is open and unlocked.

- Wipe on explicit lock, on tab close, and after an idle timeout matching the
  desktop's default.
- Nothing in any browser storage, ever. Verify it: open the application panel
  in devtools after unlocking and show it is empty in the pull request.
- JavaScript cannot reliably zero memory, and pretending otherwise would be the
  kind of claim this project does not make. Say so in a comment: drop the
  references, and be honest that the garbage collector decides the rest.

**Done when:** locking clears the interface and the data behind it, a reload
returns to the unlock screen, and storage is empty at every point.

**Teaches:** the difference between wiping a secret and dropping a reference to
it — and that documenting the limit is better than implying a guarantee.

---

## Track B — making it something a person can use

Five slices. The first three need nothing from Track A: build them against
invented data, the way `apps/desktop/src/lib/devMock.ts` does for the desktop,
and swap the real pipeline in at B4.

### B1. Scaffold `apps/web`

Vite, React and TypeScript, matching the desktop's setup closely enough that
someone who knows one knows the other. Reuse `tokens.css` rather than copying
values out of it — the desktop's palette is documented, measured against WCAG,
and one of the things this project got wrong before was two stylesheets
disagreeing about the same colour.

Wire up vitest, testing-library and the same flat ESLint config the desktop
uses. The desktop went a long time with no tests and no lint; do not repeat it
in a new directory.

**Done when:** `npm run dev`, `npm run build`, `npm test` and `npm run lint`
all work in `apps/web`, and CI runs them.

**Teaches:** that a new package's first commit is where its standards are set.

### B2. The unlock screen

A read-only client has no vault of its own, so opening one means: server,
account id, master password, recovery kit. `apps/desktop/src/components/SyncView.tsx`
has a `Join` form doing exactly this — read it, and match its wording.

Be careful with the copy. This is not a password reset: the kit is one half of
what unwraps the account and the password is the other. Say so.

Errors here must not tell the user which half was wrong.

**Done when:** the form validates shape before submitting, refuses with one
message for every kind of failure, and reads clearly to someone who has not
seen the desktop app.

**Teaches:** interface copy as part of a security boundary.

### B3. The list and the detail

Items on the left, the selected one on the right. Read-only: no edit, no
delete, no new.

- Keyboard first. Arrow keys move the selection and the selection moves focus,
  because a visual highlight is not something a screen reader can observe.
  `apps/desktop/src/components/CommandPalette.tsx` implements the listbox
  pattern correctly — follow it rather than inventing a second one.
- A password is hidden until asked for, and asking for it is a separate,
  explicit action. Never render a secret into the DOM because the row happened
  to be selected.
- TOTP codes tick. `apps/desktop/src/components/TotpBadge.tsx` shows the
  countdown treatment.

**Done when:** the list is operable entirely by keyboard, secrets appear only
on request, and tests cover the keyboard path.

**Teaches:** the listbox pattern, and treating "reveal" as an event rather than
a render.

### B4. Copy, honestly

A browser cannot exclude a value from the OS clipboard history, and it cannot
reliably read the clipboard back to clear it. The desktop app went through this
and now uses a Win32 path; the web app has no equivalent and must not pretend
it does.

So: copy the value, and say exactly what that means — it is on the system
clipboard, this page cannot take it off, clear it yourself. That sentence is
the deliverable. `apps/desktop/src/lib/clipboard.ts` shows the shape of an
honest announcement; the content here is different because the capability is.

**Done when:** copying works, the message is true, and a test asserts the
wording does not promise a clear that cannot happen.

**Teaches:** that the honest version of a feature is sometimes the smaller one,
and that saying so is the work.

### B5. Ship it

The web app is static files. `deploy/Caddyfile` serves `yara.lat` and currently
answers 404 at the root; serving the app from a path there is the smallest
change that puts it in front of someone.

- Build in CI and fail the build on a type error, a lint error or a failing
  test — the same gates as the desktop.
- The Content-Security-Policy matters more here than in the desktop, where the
  webview enforces one already. No inline scripts, no external origins. The
  desktop's CSP is in `apps/desktop/src-tauri/tauri.conf.json`.
- Do not add the route to the Caddyfile without saying so in the pull request:
  it changes what the production origin serves, and that is the maintainer's
  call.

**Done when:** CI builds and publishes the bundle, the CSP is stated and
justified, and `docs/hosting.md` describes the new path the way it describes
the others.

**Teaches:** that shipping is part of the feature, and that a change to what
production serves is announced rather than slipped in.

---

## Before you open a pull request

Every one of these must pass. A red pull request is a review the maintainer
cannot start.

```bash
cargo test --workspace --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo fmt --all -- --check

cd apps/web && npx tsc --noEmit && npm run lint && npm test
```

If you touched `apps/desktop`, run its checks too. If you touched
`crates/yara-core`, remember the Linux CI job exists to prove the crate has no
platform dependency, and that your feature flags have not quietly broken it.

---

## House style, which the reviewer does care about

Read a few existing commits and a few existing comments before writing either.
This codebase is unusual in a specific way: **comments and commit messages
explain why, usually by naming the failure that motivated the code.** They are
plain declarative prose, not bullet points, and not a restatement of the diff.

A comment that says `// increment the counter` above `counter += 1` will be
asked about. A comment that says why the counter exists will not.

Commit messages: a short imperative subject, a blank line, then prose
explaining what was wrong and why this is the fix. Look at
`git log --format=%B -n 5` for the shape.

Never leave a `TODO`. If something is unfinished, either finish it or say in
the pull request that it is out of scope and why.

Write a test for every behaviour you change. A slice without tests will be sent
back, not because of a coverage rule, but because this project has 464 of them
across the workspace and the frontend, and the next person needs yours to know
they have not broken your work.

```bash
git push origin web-wasm-core
gh pr create --repo sf0rzin/yara --base main \
  --title "Prove yara-core builds for wasm32" \
  --body "..."
```

In the pull request body: what you changed, how you verified it, and anything
you could not finish and why. That last part is not a confession — it is the
most useful paragraph in the whole thing.

---

## Things not to do

- Do not reimplement cryptography, in any language, for any reason.
- Do not add write, edit or delete. Version one reads.
- Do not put anything in browser storage.
- Do not introduce an accent colour or a status colour.
- Do not refactor code you are not changing. A pull request that fixes one
  thing and tidies four others cannot be reviewed as either.
- Do not edit `apps/desktop/src-tauri`, `crates/yara-broker`, `crates/yara-cli`
  or `crates/yara-mcp`. None of them are part of this.
