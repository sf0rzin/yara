# Contributor tasks

Ten pieces of work in this repository, split into two tracks of five. Each one
is a real gap that exists in the code today, not an exercise. Each is one pull
request.

This file is written to be handed to a coding assistant along with the
repository. If you are that assistant: **you are implementing exactly one task
per branch.** Read the whole task before touching anything, and do not do work
belonging to another task, even if you notice it needs doing.

There is a second task pack, [web-app-tasks.md](web-app-tasks.md), which builds
the one unchecked box in the README from nothing. It is the larger and less
certain of the two — its first slice is finding out whether the approach works
at all. Start here if you want work whose shape is already known.

The upstream repository is `sf0rzin/yara`. You do not have write access to it.
Everything below assumes you work in a fork.

---

## Before you start

### Toolchain

- Rust (stable, at least 1.82 — the workspace sets `rust-version = "1.82"`)
- Node 20 or newer
- On Windows: the MSVC build tools. They are required even for `cargo check`,
  because build scripts have to link.

The desktop application is Windows-only and that is deliberate. `yara-core` and
`yara-sync` build anywhere, and CI builds them on Linux to keep that honest. If
you are not on Windows you can still do every task in Track A except the parts
that touch `apps/desktop/src-tauri`, and you can do all of Track B's frontend
work — but you cannot run the app, so say so in your PR rather than claiming you
tested it.

### Fork and clone

```bash
gh repo fork sf0rzin/yara --clone --remote
```

That gives you `origin` pointing at your fork and `upstream` pointing at
`sf0rzin/yara`. If you cloned by hand instead:

```bash
git clone https://github.com/<your-username>/yara.git
```

```bash
git remote add upstream https://github.com/sf0rzin/yara.git
```

### Prove the baseline is green before you change anything

Run this first. If something is already failing, that is information you need
before you write a line, and it is not your fault.

```bash
cargo test --workspace --locked
```

```bash
cd apps/desktop && npm install && npm test
```

At the time this file was written the workspace had 444 Rust tests and the
frontend had 20, and all of them passed. If your numbers are lower, you are on
an older commit — pull from `upstream/main`.

---

## How every task ends

The same five steps every time.

**1. Branch from an up-to-date main.**

```bash
git fetch upstream && git checkout -b <branch-name> upstream/main
```

**2. Do the work.** One task. Nothing else.

**3. Run the full gate.** Not just the tests for your change — all of it. This
is exactly what CI runs, so a failure here is a failure there.

```bash
cargo fmt --all --check
```

```bash
cargo clippy --workspace --all-targets --locked -- -D warnings
```

```bash
cargo test --workspace --locked
```

```bash
cd apps/desktop && npm run build && npm run lint && npm test
```

`npm run build` runs `tsc` before Vite, so it is the type check as well.

**4. Commit.** Each task below gives you the exact message. Use it. If your
implementation ended up different from the description, change the message to
describe what you actually did — a commit message that describes code that is
not there is worse than a vague one.

**5. Push and open the PR.**

```bash
git push -u origin <branch-name>
```

```bash
gh pr create --repo sf0rzin/yara --base main --title "<title from the task>" --body-file <your-body-file>
```

---

## House rules

These are not style preferences. They are how the rest of this codebase is
written, and a PR that ignores them will not read like it belongs.

**Comments explain why, never what.** Look at any file before writing in it.
`// increment the counter` above `count += 1` is noise. `// Recorded only after
the write succeeded. Remembering a secret that never reached the clipboard
would make the next clear compare against something that was never there.` is a
comment. If nothing surprising is happening, write no comment.

**Never leave a TODO, FIXME, or a stub.** There are currently zero in this
repository and it stays that way. If you cannot finish something, say so in the
pull request; do not leave a marker in the code.

**Do not reimplement cryptography.** Randomness comes from
`yara_core::crypto::random_bytes`. Sealing and opening come from
`yara_core::crypto`. If you find yourself reaching for a new crypto dependency
or writing a loop over bytes that looks like a cipher, stop and ask.

**Tests are named as sentences that state the rule.** Look at the existing ones:
`a_wipe_that_failed_is_tried_again_at_the_next_chance`,
`an_earlier_timer_does_not_wipe_a_later_copy`. Not `test_clipboard_2`. The name
is what a future reader sees when it breaks.

**A test with a non-obvious reason gets a doc comment saying what regression it
guards.** Several existing tests do this. Copy the habit.

**English.** Every comment, doc, test name and commit message in this repository
is in English. Keep it that way even if you are thinking in another language.

**No drive-by refactors.** If you see something unrelated that is wrong, note it
in the PR description. Do not fix it in the same branch.

**No new dependencies without asking first.** `deny.toml` gates the supply chain
and the CI job that enforces it will fail you. If a task genuinely needs a new
crate, open the PR without it and explain why, or ask in an issue before
starting.

---

# Track A — what the vault knows

Five tasks in Rust, working outward from `yara-core`. Four of them end with a
small piece of frontend wiring so the feature is actually reachable; that wiring
is part of the task, not optional.

---

## A1 — There is no way to generate a password

**Branch:** `generate-passwords`

### The gap

This is a password manager that cannot make a password. Search the repository
for a generator and you find nothing: `NewItemDialog.tsx` has a plain
`<input type="password">` and that is the whole story. Every password in the
vault was typed by a person or pasted from somewhere else.

`StrengthMeter` will tell you the password you typed is weak. Nothing offers a
better one.

### Files

- `crates/yara-core/src/generate.rs` — new
- `crates/yara-core/src/lib.rs` — declare and re-export the module
- `crates/yara-core/src/error.rs` — one new variant
- `crates/yara-core/src/health.rs` — make the length floor public
- `apps/desktop/src-tauri/src/lib.rs` — the command, and register it
- `apps/desktop/src/api.ts` — the binding
- `apps/desktop/src/lib/devMock.ts` — a handler, or the dev server breaks
- `apps/desktop/src/components/NewItemDialog.tsx` — the button

### What to build

**1. The recipe and the entry point.**

```rust
pub struct Recipe {
    pub length: usize,
    pub lowercase: bool,
    pub uppercase: bool,
    pub digits: bool,
    pub symbols: bool,
}

pub fn password(recipe: &Recipe) -> Result<SecretString>
```

Return a `SecretString`, not a `String`. `SecretString` zeroizes on drop and
compares in constant time, and a generated password is as sensitive as a stored
one from the moment it exists.

**2. Uniform selection, with the bias removed on purpose.**

This is the part of the task that matters. The obvious implementation is

```rust
let index = byte as usize % alphabet.len();  // WRONG
```

and it is biased: 256 is not divisible by 26, 62, or 94, so the first few
characters of the alphabet come up more often than the rest. On a 94-character
alphabet that is a measurable skew in a value whose only job is to be
unpredictable.

Use rejection sampling. Compute the largest multiple of `len` that fits in 256,
discard any byte at or above it, and take the modulus of what survives. Draw
bytes from `crypto::random_bytes`.

Write it behind a seam so the rejection itself can be tested:

```rust
fn index(len: usize, bytes: &mut impl Iterator<Item = u8>) -> Option<usize>
```

A test can then feed a known byte sequence and prove the biased ones are thrown
away instead of used.

**3. Guarantee every enabled class appears — without biasing positions.**

The naive fix is to overwrite positions 0, 1, 2, 3 with one character from each
class. That makes the first four positions predictable in class, which is worse
than the problem it solves.

Instead: draw one character from each enabled class, fill the remaining length
from the union of all enabled classes, then shuffle the whole thing with
Fisher–Yates using the same unbiased `index` helper. Constant time, no retry
loop, no positional structure.

**4. Bounds.**

- Minimum length: the same floor `health::strength` uses. `MINIMUM_LENGTH` in
  `health.rs` is currently private — make it `pub` and use it here, so the
  generator cannot produce a password its own strength meter calls weak.
- Maximum length: 128. Pick a number and say in a comment why it exists (a
  bound on how much a caller can ask this to allocate), not what it is.
- No classes enabled is an error, not an empty string.

**5. The error variant.** Add to `crates/yara-core/src/error.rs`:

```rust
#[error("cannot generate a password: {0}")]
InvalidRecipe(&'static str),
```

`&'static str` rather than `String`, matching `Malformed` and `DamagedFile`
above it — these messages are written by this crate, never by a caller.

**6. The command.** In `apps/desktop/src-tauri/src/lib.rs`:

```rust
#[tauri::command]
fn generate_password(recipe: Recipe) -> CommandResult<String>
```

Register it in the `tauri::generate_handler!` list at the bottom of the file.
Note that it takes no `State` — generating a password does not need the vault
open, and it must work while the user is filling in the create form.

**7. The button.** In `NewItemDialog.tsx`, beside the password input. Clicking
it fills the field, sets `passwordTouched`, and leaves the value visible long
enough for the user to see what they got. Do not add a full options panel —
defaults of 20 characters with all four classes are right for almost everyone,
and a settings sheet is a separate PR.

### Tests that must exist

In `crates/yara-core/src/generate.rs`:

- A generated password has the requested length.
- Over many draws, every enabled class appears in every password.
- A disabled class never appears — not once, over many draws.
- Two calls do not return the same password.
- A recipe with no classes enabled is an error.
- A length below the floor is an error; a length above the ceiling is an error.
- `index` never returns a value at or above `len`.
- `index` discards a byte in the rejection zone and takes the next one. Feed it
  a fixed sequence; this is the test that proves the bias is gone.

### Verification

```bash
cargo test -p yara-core generate
```

Then the full gate from **How every task ends**.

### Commit

```
Give the vault a way to make a password

This is a password manager that could not generate one. The new-item
dialog had a password box and a strength meter that would tell you what
you typed was weak, and nothing that would offer you better. Every
password in a vault got there by being typed or pasted from somewhere
else, which is the failure mode the meter exists to warn about.

Selection is rejection-sampled rather than taken modulo the alphabet
length. 256 divides by neither 26 nor 62 nor 94, so a modulus skews the
front of the alphabet upward, and skew in the one value whose whole job
is to be unpredictable is not a rounding error. The sampler takes an
iterator so a test can feed it a byte inside the rejection zone and
prove it is discarded rather than used.

The class guarantee is a shuffle, not four fixed positions. Writing one
character from each enabled class into slots zero through three makes
those slots predictable in class, which trades a small bias for a
larger one.

The floor is the same constant `health::strength` measures against, now
public, so the generator cannot hand back something its own meter calls
weak.
```

### Pull request

**Title:** `Give the vault a way to make a password`

**Body:** the commit body, plus a line saying how you tested the button in the
running app (or that you could not, if you are not on Windows).

---

## A2 — The README claims two health checks that do not exist

**Branch:** `password-health`

### The gap

`README.md` line 90 says:

> - [x] Offline password health checks: reuse, strength, missing second factors

`crates/yara-core/src/health.rs` contains `estimate_bits` and `strength`. That
is all of it. There is no reuse detection anywhere in the repository, and
nothing anywhere notices that a login has a password and no second factor.

Two of the three claimed checks do not exist. The task is to make the sentence
true.

### Files

- `crates/yara-core/src/health.rs`
- `crates/yara-core/src/vault.rs` — a method on `UnlockedVault`
- `apps/desktop/src-tauri/src/lib.rs` — two fields on `ItemSummary`, filled at
  the listing sites
- `apps/desktop/src/api.ts`
- `apps/desktop/src/lib/devMock.ts`
- `apps/desktop/src/components/ItemDetail.tsx` — where it is shown

### What to build

**1. Reuse, in `health.rs`.**

```rust
pub fn reused(items: &[Item]) -> HashSet<Uuid>
```

Returns the ids of every item that shares its password with at least one other
item. Items with no password are never in the set.

**Do not build a map keyed by the password.** That produces a structure holding
every plaintext password in the vault at once, which is exactly the thing this
program spends the rest of its effort avoiding. Key the map on
`sha256(salt || password)` with a fresh `crypto::random_bytes(32)` salt drawn
per call, and hold the digests in `Zeroizing`. The salt costs nothing, is thrown
away when the function returns, and means the intermediate is not a
precomputable digest of the vault if it ever reached a crash dump.

Comparison is exact. `Hunter2` and `hunter2` are different passwords.

**2. Missing second factor.**

```rust
pub fn missing_second_factor(item: &Item) -> bool
```

True when the item is a login, has a password, and has no `totp`. Not for cards
and not for notes — a note has nowhere to put a second factor and flagging it
would train the user to ignore the flag.

**3. On the vault.** In `vault.rs`, so callers do not have to reach into the
item list themselves:

```rust
pub fn reused_passwords(&self) -> HashSet<Uuid>
```

**4. On the summary.** `ItemSummary` in `apps/desktop/src-tauri/src/lib.rs`
gains:

```rust
pub reused: bool,
pub missing_second_factor: bool,
```

`From<&Item>` cannot compute `reused` — one item does not know about the
others — so leave it `false` there and fill it at the two sites that build a
list (`list_items` and `recent_items`). Add a comment saying why the conversion
cannot do it; the next person will otherwise try to move it.

**5. In the interface.** `ItemDetail.tsx` shows the two facts on the item, where
the password is. One line each, in the same quiet register as the rest of the
detail view. There is no accent colour in this app — do not introduce one for a
warning. Do not build a separate "Security" screen: `views.ts` says explicitly
why that idea was removed, and re-adding it would undo a decision that was made
on purpose.

### Tests that must exist

- Two items with the same password are both in the set.
- An item whose password is unique is not.
- Items with no password are never in the set, however many of them there are.
- Three items sharing one password are all three in the set.
- `Hunter2` and `hunter2` are not a reuse.
- The digests do not survive the call — assert on the API shape, not on memory,
  but write the test that proves the returned value carries ids and nothing
  else.
- A login with a password and no TOTP is missing a second factor.
- A login with a TOTP is not.
- A note with no password is not, regardless.

### Verification

```bash
cargo test -p yara-core health
```

Then the full gate.

### Commit

```
Make the health checks the README promises exist

The status list claimed reuse, strength and missing second factors.
`health.rs` had strength. The other two were never written, so a vault
where the same password protects six accounts said nothing at all, and
the one claim the interface could have made about an item's safety was
the one it never made.

Reuse is grouped by digest rather than by password. A map keyed on the
plaintext would assemble every password in the vault into one structure
in memory, which is the thing the rest of this program is arranged to
avoid; a per-call random salt in front of the hash keeps the
intermediate from being a precomputable digest of the vault if it ever
landed in a crash dump.

Missing second factors are only reported for logins. A note has
nowhere to put one, and flagging things that cannot be fixed teaches
people to stop reading the flags.

The counts cannot be computed in `From<&Item>` — one item does not know
what the others hold — so the listing sites fill them and the
conversion says why it does not.
```

### Pull request

**Title:** `Make the health checks the README promises exist`

---

## A3 — A vault created two versions ago keeps two-versions-ago security forever

**Branch:** `upgrade-kdf-on-unlock`

### The gap

`crates/yara-core/src/vault.rs` opens with this, at the top of the module:

> The KDF parameters and salt sit in the header in the clear — an existing vault
> must stay openable after the defaults are raised.

The reason that flexibility exists is so the defaults can be raised. Nothing in
the codebase ever raises them. `change_password_with_params` exists and is only
called when the user changes their master password. A vault created when the
defaults were lower stays at the lower parameters for the rest of its life, and
the user is never told.

`KdfParams::default()` is currently 64 MiB / 3 passes / 4 lanes. `MIN_MEMORY_KIB`
is 8 MiB — a vault sitting at that floor is eight times cheaper to attack than a
vault created today, and nothing will ever move it.

### Files

- `crates/yara-core/src/vault.rs`
- `apps/desktop/src-tauri/src/lib.rs` — the unlock path

### What to build

**1. The question.**

```rust
pub fn needs_kdf_upgrade(&self) -> bool
```

True when any of `memory_kib`, `iterations` or `parallelism` in the stored
header is strictly below the corresponding field of `KdfParams::default()`.

Strictly below, per field. A vault whose parameters are *higher* than the
current defaults must not be touched — someone raised them deliberately, and
"upgrade" must never mean "downgrade".

**2. The upgrade.**

```rust
pub fn upgrade_kdf(&mut self, password: &str) -> Result<()>
```

Re-derives the master key from the same password at the current defaults with a
fresh salt, and re-wraps the vault key under it. `change_password_with_params`
already does exactly this; the new method should be a thin, well-commented
wrapper rather than a second copy of the logic. Say in the comment why passing
the *same* password to a "change password" routine is the right call here, or
the next reader will think it is a bug.

Record it in the audit log with `record_audit`. A silent change to how a file is
protected is not a thing this program does.

**3. The call site.** In `unlock_vault` in `apps/desktop/src-tauri/src/lib.rs`,
after the vault opens successfully: if `needs_kdf_upgrade()`, upgrade and save
once.

Two things about the ordering, and get them right:

- The upgrade happens **after** a successful unlock, never before. It needs the
  correct password and it needs the vault key already in hand.
- If the upgrade or the save fails, the unlock still succeeded. The user gets
  into their vault. Do not turn a security improvement into a lockout — log it
  and carry on. Write that reasoning as a comment.

### Tests that must exist

- A vault created at `MIN_MEMORY_KIB` reports `needs_kdf_upgrade`.
- A vault created at `KdfParams::default()` does not.
- A vault created *above* the defaults does not, and its header is untouched
  after an unlock. This is the downgrade guard; it deserves a doc comment saying
  so.
- After an upgrade the header holds the defaults, and the vault opens with the
  same password.
- After an upgrade the salt is different from the old one.
- After an upgrade the items are all still there and still readable. Re-wrapping
  the key must not disturb what the key opens.
- The audit log has an entry.

### Verification

```bash
cargo test -p yara-core vault
```

Then the full gate.

### Commit

```
Raise an old vault's parameters when it is opened

The module comment explains that the KDF parameters live in the header
in the clear so an existing vault stays openable after the defaults are
raised. Nothing ever raised one. `change_password_with_params` had a
single caller, behind the master-password screen, so a vault created at
the 8 MiB floor stayed eight times cheaper to attack than one created
today for as long as its owner kept using it, and was never told.

The upgrade runs after the unlock succeeds, because it needs the
correct password and the unwrapped key, and its failure does not fail
the unlock. Turning a silent improvement into a lockout would be a
worse bug than the one being fixed.

Parameters above the current defaults are left alone. Somebody chose
those, and an upgrade path that quietly lowers them is not an upgrade
path.
```

### Pull request

**Title:** `Raise an old vault's parameters when it is opened`

---

## A4 — Replacing a password destroys the old one with no way back

**Branch:** `password-history`

### The gap

`update_item` in `apps/desktop/src-tauri/src/lib.rs`, around line 573:

```rust
if let Some(password) = edit.password {
    item.password = (!password.is_empty()).then(|| password.into());
}
```

The previous value is gone. If a rotation half-succeeded — the new password
saved here, the change rejected at the other end — the old one is not recoverable
from the vault, and the vault was the only place it was written down.

**Before you start this one, get the owner's agreement.** It is the only task in
this file that makes the program keep a secret it currently discards, and that
is a design decision, not an implementation detail. Open an issue describing
what you intend and wait for an answer.

### Files

- `crates/yara-core/src/vault.rs`
- `apps/desktop/src-tauri/src/lib.rs`
- `apps/desktop/src/api.ts`
- `apps/desktop/src/lib/devMock.ts`
- `apps/desktop/src/components/ItemDetail.tsx`

### What to build

**1. The record.**

```rust
pub struct PastPassword {
    pub password: SecretString,
    /// When it stopped being the current one.
    pub replaced_at: u64,
}
```

**2. On the item.**

```rust
#[serde(default, skip_serializing_if = "Vec::is_empty")]
pub history: Vec<PastPassword>,
```

Both attributes matter and for different reasons. `default` is what lets a vault
written before this field existed still open — every other optional field on
`Item` carries it for the same reason, and there is a test in `vault.rs` that
opens an old vault. `skip_serializing_if` keeps items with no history from
growing by a key, which matters because the entire vault is re-encrypted on
every write.

**3. The cap.** Five, as a named constant with a comment explaining that the
whole file is rewritten on every save. `AUDIT_CAPACITY` and
`TOMBSTONE_CAPACITY` further down the same file are bounded for exactly this
reason and already say so — match their voice. Oldest dropped first.

**4. The transition.**

```rust
pub fn replace_password(&mut self, next: Option<SecretString>, now: u64)
```

on `Item`. Pushes the current password onto the history if there is one and it
differs from the new one, then sets the new one. An item that had no password
pushes nothing. Setting the same password again pushes nothing — a save with no
change is not a rotation.

Call it from `update_item` instead of the assignment above.

**5. The commands.** Two, and the split is the point:

```rust
#[tauri::command]
fn password_history(state: ..., id: Uuid) -> CommandResult<Vec<u64>>
```

returns timestamps only, no values.

```rust
#[tauri::command]
fn reveal_past_password(state: ..., id: Uuid, replaced_at: u64) -> CommandResult<String>
```

returns one value, for one entry, on request. This mirrors how `reveal_field`
and `reveal_password` already work: **a secret crosses the IPC boundary only
when the user asked for that specific one.** Read the doc comment on
`reveal_password` before you write these, and match it.

Also add:

```rust
#[tauri::command]
fn forget_password_history(state: ..., id: Uuid) -> CommandResult<()>
```

Keeping old secrets has to be reversible by the person whose secrets they are.

**6. Not reachable by an agent.** History is not a custom field and must never
resolve as one. `Field::Custom(label)` in the broker matches against
`item.fields`; history is a separate list, so this already holds — write the
test that pins it, because the next person to touch field resolution needs to
break a test rather than quietly open a door.

**7. In the interface.** A collapsed "Previous passwords" section on
`ItemDetail`, listing dates. Each row reveals on click, the same way the
password itself does. A "Forget these" action at the bottom.

### Tests that must exist

- Replacing a password puts the old one in the history.
- Replacing again puts both in, newest first.
- The cap holds at five and drops the oldest.
- Setting the same password twice records nothing.
- Setting a password on an item that had none records nothing.
- Removing a password (empty string through `update_item`) records the old one —
  this is the case most likely to be wanted back.
- A vault serialised without a `history` key deserialises.
- An item with empty history serialises without the key at all.
- The broker cannot reach a history entry through `Field::Custom`.

### Verification

```bash
cargo test -p yara-core vault
```

```bash
cargo test -p yara-broker
```

Then the full gate.

### Commit

```
Keep the password an edit replaced

Saving a new password overwrote the old one and that was the end of it.
A rotation that half-succeeded — new password saved here, change
rejected at the other end — left the old value recoverable from
nowhere, and the vault was the only place it had ever been written
down.

Five entries, oldest dropped, because the whole file is re-encrypted on
every save and a list that only grows is a vault that gets slower
forever. The same reasoning is already written above `AUDIT_CAPACITY`
and `TOMBSTONE_CAPACITY`.

Listing hands back timestamps; a value takes its own request for its
own entry, the same way `reveal_password` and `reveal_field` already
work. An agent cannot reach any of it: history is not a custom field,
which was already true and is now a test, because the next person to
touch field resolution should have to break something visible rather
than quietly open a door.

Retaining a secret the program used to discard is reversible. Forget
clears the list.
```

### Pull request

**Title:** `Keep the password an edit replaced`

**Body:** the commit body, and link the issue where the owner agreed to the
design.

---

## A5 — You cannot revoke a device because nothing will tell you its id

**Branch:** `sync-operator-listing`

### The gap

`crates/yara-sync/src/main.rs` documents the operator surface:

```
yara-sync invite            print a fresh single-use code
yara-sync purge             drop tombstones older than 30 days
yara-sync revoke            drop one device's key
yara-sync delete-account    remove an account and everything it holds
```

`revoke` takes `<account-id> <device-id>`. `delete-account` takes
`<account-id>`. There is no command that prints an account id and no command
that prints a device id. The two destructive operations both require arguments
the tool will not give you.

The server is running in production. Right now, revoking a lost laptop means
opening the SQLite file by hand.

### Files

- `crates/yara-sync/src/store.rs` — the queries
- `crates/yara-sync/src/main.rs` — parsing, dispatch, and the usage text

### What to build

**1. Two queries on `Store`.** The schema is in `store.rs`:

```sql
accounts (id, salt, kdf, wrapped_vault_key, wrapped_account_key,
          revision, created_at, account_public_key)
devices  (id, account_id, public_key, label, created_at, last_seen)
items    (account_id, id, revision, ciphertext, deleted, updated_at)
```

```rust
pub fn accounts(&self) -> Result<Vec<AccountRow>>
pub fn devices(&self, account: &str) -> Result<Vec<DeviceRow>>
```

`AccountRow`: id, device count, live item count, tombstone count, revision,
created_at. The two item counts separately — an operator looking at storage
wants to know how much of it is deletions waiting for `purge`.

`DeviceRow`: id, label, created_at, last_seen.

**2. Print no key material.** Not the public keys, not the wrapped keys, not the
salt, not the invite hashes. A public key is not a secret, but an operator
listing that dumps key material trains people to paste it into issues. If you
want a device to be identifiable at a glance, print the first eight hex
characters of a SHA-256 of the public key and call the column `fingerprint` —
never the key.

**3. Output.** Tab-separated, one row per line, no headers, timestamps as ISO
8601 UTC. Same shape as `yara-cli`'s `item_row`, and for the same reason: this
is output that gets piped into `cut` and `awk`. Read the comment above `item_row`
in `crates/yara-cli/src/main.rs` before you choose a format.

An account with no devices still prints its row. An empty result prints nothing
and exits 0 — nothing is not an error.

**4. Parse before you open the database.** `parse_command` in `main.rs` has a
doc comment explaining why arguments are settled before anything touches the
disk. Your two subcommands go through the same path. `yara-sync devices` with no
account id is a usage error, and it must be caught before the database is
opened.

**5. Update `USAGE`.** The constant at the top of `main.rs`. It is the only
documentation this tool has.

### Tests that must exist

In `main.rs`, alongside the existing `parse_command` tests:

- `accounts` parses with no arguments and is a usage error with any.
- `devices <id>` parses; `devices` alone is a usage error; `devices a b` is a
  usage error.

In `store.rs`, against a temporary database:

- An account with two devices reports two.
- Live items and tombstones are counted separately.
- `devices` on an unknown account id returns empty rather than erroring.
- An account with no devices appears in `accounts`.
- No row contains any byte of a stored public key.

### Verification

```bash
cargo test -p yara-sync
```

Then the full gate. `yara-sync` builds on Linux, so you can do this task on any
platform.

### Commit

```
Let an operator see the ids the destructive commands demand

`revoke` takes an account id and a device id. `delete-account` takes an
account id. Nothing printed either one. Revoking a lost laptop meant
opening the SQLite file by hand on the production host, which is not a
procedure — it is the absence of one.

Both listings print counts, not contents. Live items and tombstones are
counted apart because an operator looking at disk usage wants to know
how much of it is deletions that `purge` has not reached yet.

No key material in either. A device public key is not a secret, but a
listing that prints one teaches whoever runs it that pasting the output
into an issue is fine, and the next listing might not be so harmless. A
truncated fingerprint identifies a device without handing over the
thing it is derived from.

Arguments are still settled before the database is opened, for the
reason already written above `parse_command`: a typo in a destructive
command has to be caught before it can reach anything.
```

### Pull request

**Title:** `Let an operator see the ids the destructive commands demand`

---

# Track B — what the app does with it

Five tasks in the desktop application: robustness, accessibility, coverage, and
one real feature. Four are TypeScript; one is Rust in a file Track A never
touches.

---

## B1 — A render error blanks the window and leaves the vault unlocked

**Branch:** `error-boundary`

### The gap

There is no error boundary in this application. Search for `componentDidCatch`
or `getDerivedStateFromError` and you get nothing.

`main.tsx` mounts `<App />` inside `<React.StrictMode>` and that is the whole
tree. In React 19, an error thrown during render with no boundary above it
unmounts the entire tree — the user gets a white window with no explanation.

The part that matters: **the backend does not know.** `AppState` still holds the
unlocked vault. The auto-lock timer lives in `useAutoLock`, which is a React
hook, so it went down with the tree. The vault key sits in memory with nothing
counting down against it and no interface to notice.

There is already a comment in `lib.rs` about exactly this class of problem, on
`on_page_load`:

> A reload must not leave the vault unlocked behind a screen that says it is
> locked.

A crash is the same hazard through a different door.

### Files

- `apps/desktop/src/components/ErrorBoundary.tsx` — new
- `apps/desktop/src/components/ErrorBoundary.test.tsx` — new
- `apps/desktop/src/main.tsx`

### What to build

**1. A class component.** React has no hook for this; `getDerivedStateFromError`
and `componentDidCatch` are class-only. This is the one place in the codebase
where a class is correct, and the comment should say so, because every other
component here is a function and the next reader will wonder.

**2. On catching:**

- Call `lockVault()` from `../api`. Do it in `componentDidCatch`, not in
  `getDerivedStateFromError` — the latter must be pure, and React may call it
  more than once.
- If `lockVault()` itself rejects, do not throw from the handler. You are
  already in the failure path; a throw here loses the message the user was about
  to be shown. Catch it and fold it into what you render.

**3. What to render.** Not "Something went wrong". Say the three things the user
needs:

- The app hit an error and stopped.
- The vault has been locked. (Or, if the lock call failed, that it could not be
  locked and they should close the app.)
- The error text itself, so a bug report can contain something useful.

Plus a button that calls `window.location.reload()`. That path is already safe:
`on_page_load` in `lib.rs` locks on reload by design.

**4. Where it goes.** In `main.tsx`, wrapping `<App />` — outside, not inside.
A boundary rendered by `App` cannot catch an error thrown by `App`.

Keep it inside `<React.StrictMode>`.

### Tests that must exist

In `ErrorBoundary.test.tsx`, mocking `../api`:

- A child that throws renders the fallback rather than propagating.
- A child that throws causes `lockVault` to be called exactly once.
- A child that does not throw renders its children untouched, and `lockVault` is
  never called.
- When `lockVault` rejects, the fallback still renders and says the vault could
  not be locked.
- The rendered fallback contains the error's message.

React logs caught errors to the console; that is expected and your test should
not assert against it. Do not silence it globally.

### Verification

```bash
cd apps/desktop && npm test
```

Then the full gate.

### Commit

```
Lock the vault when the interface crashes

There was no error boundary. An error thrown during render unmounted
the tree and left a white window, which is bad, and left the vault
unlocked in the backend, which is worse. `useAutoLock` is a React hook,
so the idle timer went down with the tree it lived in: the key stayed
in memory with nothing counting against it and no interface left to
notice.

`lib.rs` already carries the same reasoning for a reload — a reload must
not leave the vault unlocked behind a screen that says it is locked. A
crash is the same hazard through a different door, and now it takes the
same action.

The fallback says what happened, whether the lock succeeded, and what
the error was. "Something went wrong" would leave the user unable to
tell a rendering bug from a vault they should assume is exposed.

A class component, which nothing else in this codebase is, because
`getDerivedStateFromError` and `componentDidCatch` have no hook form.
```

### Pull request

**Title:** `Lock the vault when the interface crashes`

---

## B2 — The dialogs are not modal to anything but the mouse

**Branch:** `modal-dialogs`

### The gap

`NewItemDialog.tsx` renders `<form className="dialog" aria-label="New item">`.
No `role="dialog"`, no `aria-modal`. To a screen reader it is a form that
happens to be in front of other content, and the vault list behind it is still
part of the document.

Every dialog in the app has the same problem in a different degree:

| | `role` | `aria-modal` | focus trap | focus restored |
| --- | --- | --- | --- | --- |
| `NewItemDialog` | — | — | no | no |
| `ImportPanel` | yes | yes | no | no |
| `ApprovalDialog` | `alertdialog` | — | no | no |
| `CommandPalette` | yes | — | no | no |

None of them trap Tab. Press it enough times in the new-item dialog and focus
walks out into the sidebar behind the overlay — which is still clickable by
keyboard while the overlay makes it look disabled. None of them restore focus
when they close, so dismissing a dialog drops the keyboard user back at the top
of the document.

`ApprovalDialog` is the one that matters most: it is the prompt that authorises
an agent to use a credential, and it is the one where "focus escaped into the
page behind" is a security question rather than an inconvenience.

### Files

- `apps/desktop/src/lib/useModalDialog.ts` — new
- `apps/desktop/src/lib/useModalDialog.test.ts` — new
- `apps/desktop/src/components/NewItemDialog.tsx`
- `apps/desktop/src/components/ImportPanel.tsx`
- `apps/desktop/src/components/ApprovalDialog.tsx`
- `apps/desktop/src/components/CommandPalette.tsx`

### What to build

**1. One hook, used four times.** Not four implementations.

```ts
export function useModalDialog<T extends HTMLElement>(): RefObject<T | null>
```

On mount it records `document.activeElement`. On unmount it restores focus to
it, if that element is still in the document — check, because the trigger may
have been removed by the very action that closed the dialog.

While mounted it handles `keydown` for Tab: query the focusable descendants of
the ref, and when Tab would leave the last one, send it to the first; when
Shift+Tab would leave the first, send it to the last.

**2. Focusable means focusable.** Query for
`a[href], button, input, textarea, select, [tabindex]` and then filter out
anything `disabled`, `hidden`, `[tabindex="-1"]`, or with a zero-size bounding
box. A disabled submit button in the tab ring is a trap that appears to do
nothing.

Recompute the list on each Tab rather than caching it on mount. These dialogs
add and remove controls as you use them — `NewItemDialog` grows a row every time
you add a field, and `ImportPanel` swaps its whole body between steps.

**3. Do not touch Escape.** Every dialog already handles it, and
`ApprovalDialog` has a comment explaining that Escape there means *deny* and
why the listener is written the way it is. Leave that alone entirely.

**4. Then apply it.** `NewItemDialog` gets `role="dialog"` and
`aria-modal="true"` alongside its existing `aria-label`. `ApprovalDialog` keeps
`role="alertdialog"` and gains `aria-modal="true"`. `CommandPalette` already has
`role="dialog"` and needs only `aria-modal="true"`. All four get the ref.

`NewItemDialog` already focuses its first field on mount and should keep doing
so — the hook restores focus on the way out, it does not decide where focus
starts.

### Tests that must exist

- Tab from the last focusable element wraps to the first.
- Shift+Tab from the first wraps to the last.
- Disabled controls are skipped.
- A control added after mount is in the ring on the next Tab. (This is the one
  that fails if you cache the list. Give it a doc comment.)
- Unmounting restores focus to whatever had it before.
- Unmounting when the previously focused element has been removed does not
  throw.

Use `@testing-library/user-event` for the tabbing, not synthetic key events —
jsdom does not move focus on a raw `keydown`.

### Verification

```bash
cd apps/desktop && npm test
```

Then the full gate.

### Commit

```
Make the dialogs modal to the keyboard as well as the mouse

The overlay stopped the mouse and nothing else. Tab out of the new-item
dialog enough times and focus walked into the sidebar behind it, which
looks disabled and is not; none of the four dialogs restored focus on
close, so dismissing one dropped a keyboard user back at the top of the
document.

`NewItemDialog` had no `role` and no `aria-modal` at all, so to a
screen reader it was a form in front of a vault list that was still
part of the page.

The one that mattered most was the approval prompt. That dialog decides
whether an agent gets a credential, and "focus escaped into the page
behind" is a different kind of problem there than it is in an import
sheet.

One hook rather than four implementations, and it recomputes the
focusable set on every Tab — these dialogs grow and shrink while you
use them, and a ring captured at mount goes stale the first time
someone adds a field.

Escape is untouched. Every dialog already handles it and the approval
prompt's handler is written the way it is on purpose.
```

### Pull request

**Title:** `Make the dialogs modal to the keyboard as well as the mouse`

---

## B3 — The rule that decides whether a password survives an edit has no test

**Branch:** `new-item-dialog-tests`

### The gap

`NewItemDialog.tsx` is 381 lines, handles both creating and editing, and has no
test file. It is the largest untested component in the application.

The specific thing that worries me is at line 130:

```tsx
password: passwordTouched ? password : null,
```

with the interface promising, at lines 237–242:

> Left empty, the stored password stays as it is. Type to replace it; clear it
> after typing to remove it.

That contract spans two languages. The frontend sends `null` for untouched and
`""` for typed-then-cleared; `update_item` in `lib.rs` reads `Option<String>`
and treats `Some("")` as removal and `None` as no change. It is correct today —
I checked. It is also three lines in two files with nothing pinning them
together, and the failure mode is silently destroying a password the user meant
to keep.

There are other untested behaviours in the same file worth the same treatment:
the scanned-TOTP cleanup on dismissal, and the blank-label filter.

### Files

- `apps/desktop/src/components/NewItemDialog.test.tsx` — new

Nothing else. If you find a bug while writing these, **do not fix it in this
branch** — write the test as `.skip` with a comment saying what it proves, open
an issue, and say so in the PR. A branch that adds tests and changes behaviour
makes it impossible to tell which one the tests were written against.

### What to test

Look at `ItemDetail.test.tsx` and `SyncView.test.tsx` first. They already mock
`../api` and set up `@testing-library/react`; match how they do it rather than
inventing a second pattern.

**The password contract, which is the reason this task exists:**

1. Editing an item and saving without touching the password calls `updateItem`
   with `password: null`.
2. Editing, typing a new password, and saving sends that password.
3. Editing, typing, clearing the box, and saving sends `""` — not `null`. Give
   this one a doc comment: `null` here would silently keep a password the user
   deliberately erased.
4. The hint about the empty box is shown while the password is untouched and
   disappears once it is typed in.

**Creating:**

5. Name is trimmed before it is sent.
6. Empty optional fields are sent as `null`, not as `""`.
7. Save is disabled while the name is blank.
8. Save is disabled while a save is in flight.

**Fields:**

9. A field with a blank label is dropped on save; the ones beside it are kept.
10. A field's secret toggle changes the input's type and the button's
    `aria-pressed`.

**The dismissal rule:**

11. Closing with Escape calls `clearScannedTotp`.
12. Closing with the X calls `clearScannedTotp`.
13. Clicking the overlay calls `clearScannedTotp`, and clicking inside the
    dialog does not close it.

That last group is guarding the comment at line 101: *abandoning the dialog must
not leave a scanned secret parked in the backend.* A scanned TOTP seed is
sitting in `AppState` until something clears it.

**Loading an edit:**

14. Opening on an item with secret custom fields calls `revealField` once per
    secret field and puts the values in the inputs.
15. A failure from `itemExtras` shows the error instead of an empty form.

### Verification

```bash
cd apps/desktop && npm test
```

Then the full gate.

### Commit

```
Pin the rule that decides whether an edit keeps a password

`NewItemDialog` is the biggest component in the app, it is the only one
that both creates and edits, and it had no tests. The rule I care about
most is the one spanning two languages: an untouched password box sends
`null` and means "leave it", a box typed into and then cleared sends
`""` and means "remove it", and `update_item` reads those as
`Option<String>` on the other side. Three lines in two files, correct
today, with nothing holding them together and silent destruction of a
password as the failure.

The dismissal tests guard the comment already in the file — abandoning
the dialog must not leave a scanned secret parked in the backend. That
seed sits in `AppState` until something clears it, and every one of the
four ways out of this dialog has to be that something.

Tests only. No behaviour changed, so anything these catch is a report
rather than a fix in the same breath.
```

### Pull request

**Title:** `Pin the rule that decides whether an edit keeps a password`

---

## B4 — You cannot bring your passwords in from anywhere

**Branch:** `csv-password-import`

### The gap

`crates/yara-core/src/import.rs` reads one format: a Proton Authenticator
backup, which contains TOTP seeds. There is no way to import a *password* into
this vault from anything.

Someone leaving Chrome, Bitwarden, or 1Password has to retype their entire
vault. That is the whole adoption story, and it currently ends here.

### Files

- `crates/yara-core/src/import.rs`
- `crates/yara-core/src/csv.rs` — new, or a private module inside `import.rs`
- `apps/desktop/src-tauri/src/lib.rs` — `preview_import` and `run_import`
- `apps/desktop/src/api.ts`
- `apps/desktop/src/lib/devMock.ts`
- `apps/desktop/src/components/ImportPanel.tsx`

This is Rust, in a file no Track A task touches.

### What to build

**1. A CSV reader.** Write one, RFC 4180, roughly sixty lines. Do not reach for
the `csv` crate without asking: `deny.toml` gates the supply chain, `yara-core`
is deliberately small and dependency-light, and there is a CI job that will
argue with you. If you think the dependency is the right call, open the PR
without it and make the case.

It must handle, because real exports contain all of these:

- Quoted fields containing commas
- `""` as an escaped quote inside a quoted field
- Newlines inside quoted fields — password manager notes are full of them
- CRLF and LF line endings in the same file
- A trailing empty field
- A trailing newline, or none

Getting any of these wrong does not fail loudly. It shifts every column after
the mistake by one and imports somebody's note as their password.

**2. Two dialects, detected by header row.** Never by filename.

Chrome and Edge:

```
name,url,username,password,note
```

Bitwarden:

```
folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp
```

Match on the header, not on column count, and not on order — exporters reorder
columns between versions. An unrecognised header is a clear error naming what
was found, not "could not read that file".

**3. Reuse `Imported` and `Skipped`.** They exist and the report shape is
already what `ImportPanel` renders. Extend `Imported` to carry a password,
username and URL rather than inventing a parallel type.

**4. Nothing is imported silently.** This is stated at the top of `import.rs`
and it is the rule for this task too:

> an import that quietly drops three of twenty-three codes is worse than one
> that fails outright: the user finds out months later, locked out, with the
> original export long gone.

Every row that does not become an item goes into `skipped` with a reason naming
the row. A row with too few columns is skipped, not padded. A row with no
password still imports — plenty of vault entries are a username and a URL.

**5. Bitwarden's `login_totp`** is an `otpauth://` URI or a bare base32 secret.
`TotpConfig::from_uri` handles the first; the second needs the bare-secret path.
A TOTP that will not parse skips *the TOTP*, not the item — importing the
password and reporting the code as skipped is far better than dropping both.

**6. The dialog.** `ImportPanel` already does preview-then-confirm and its
warning about the export file sitting in Downloads applies at least as much to a
file full of plaintext passwords. Extend it rather than adding a second import
flow. The dialog must say which format was detected before the user confirms.

### Tests that must exist

For the CSV reader, one test per hazard in the list above. These are cheap and
they are the entire correctness of the feature.

For the importers:

- A Chrome export produces items with name, url, username and password.
- A Bitwarden export produces the same, plus a TOTP where present.
- A quoted note containing a comma and a newline arrives intact.
- A row with too few columns is skipped with a reason naming it.
- A row with an empty password becomes an item.
- A Bitwarden row with an unparseable `login_totp` imports the password and
  skips the code with a reason.
- An unknown header is an error naming what it found.
- An empty file is an error, not an empty successful import.
- `total()` equals imported plus skipped for every fixture. Nothing vanishes.

### Verification

```bash
cargo test -p yara-core import
```

```bash
cargo test -p yara-core csv
```

Then the full gate.

### Commit

```
Read passwords out of a Chrome or Bitwarden export

`import.rs` read one format and it held TOTP seeds. There was no way to
bring a password into this vault from anywhere, so leaving another
manager meant retyping everything, which is where most people stop.

The CSV reader is written here rather than pulled in, because
`yara-core` is small on purpose and `deny.toml` is not a formality. It
handles quoted commas, escaped quotes, newlines inside fields and mixed
line endings — every one of which appears in real exports, and none of
which fails loudly when it is wrong. A misread quote shifts every
column after it and files somebody's note as their password.

Dialect comes from the header row, never the filename, and never the
column count: exporters reorder columns between versions and a
positional guess that is wrong imports a username into a password
field.

Nothing is imported silently, which is the rule already written at the
top of this file. A row that cannot be read is reported with a reason
naming it, a row with no password still becomes an item, and a TOTP
that will not parse skips the code rather than the login it belongs to.
```

### Pull request

**Title:** `Read passwords out of a Chrome or Bitwarden export`

---

## B5 — The dev mock drifts from the backend and nothing notices

**Branch:** `dev-mock-conformance`

### The gap

`npm run dev` serves the interface in a browser against `devMock.ts`, a fake IPC
layer with invented data. It is how the UI is developed — a full Tauri rebuild
is far slower — so if a command exists in `api.ts` and has no handler in the
mock, that screen is broken in development and nobody finds out until they open
it.

This has already happened. There is a commit in the history called *"Bring the
dev mock back in step with the backend"* and a comment inside `devMock.ts`
around line 792 referring to the same failure happening twice.

`api.ts` makes 51 `invoke` calls. `devMock.ts` has a `handlers` record. Nothing
compares the two.

### Files

- `apps/desktop/src/lib/devMock.ts` — export what the test needs
- `apps/desktop/src/lib/devMock.test.ts` — new

### What to build

**1. Export the command names.** `handlers` is a module-level `const` at line
416. Either export it, or export a small helper:

```ts
export function mockedCommands(): string[]
```

A helper is better: the test needs the names and nothing else, and exporting the
whole record invites someone to reach into it from application code.

**2. Read `api.ts` at test time.** Not by importing it — by reading the source.
The test runs under Node, so `node:fs` works and vitest resolves paths relative
to the config root.

```ts
const source = readFileSync(new URL("../api.ts", import.meta.url), "utf8");
```

Extract every command string with a regex. Every call in the file is currently
spelled `invoke<Type>("name"`, with no bare `invoke("name")` anywhere — but
match both, because the day someone writes one without a type parameter is
exactly the day you want the test to still see it.

**3. Assert both directions.**

- Every command `api.ts` invokes has a handler. This is the one that has broken
  before.
- Every handler corresponds to a command `api.ts` invokes. A handler for a
  command nothing calls is dead code that looks like coverage, and it is how the
  mock drifts in the other direction.

**4. Allow the plugin channels explicitly.** `plugin:event|listen` and
`plugin:event|unlisten` are handled inside the `invoke` shim rather than in
`handlers`, and the updater plugin has its own path. Put the exemptions in a
named constant with a comment saying why each one is there — not a loose filter
that quietly swallows a real miss.

**5. Fail with a useful message.** When this breaks, whoever sees it should not
have to go read the test. Assert on sorted arrays, or build the message
yourself:

```
api.ts invokes commands the dev mock does not handle: sync_join, password_history
```

### Tests that must exist

Three, and that is the whole file:

- Every command in `api.ts` has a mock handler.
- Every mock handler is a command `api.ts` invokes.
- The regex found a plausible number of commands — assert it found more than
  forty. Without this, a regex that silently matches nothing makes the other two
  tests pass forever while checking nothing at all. Give it a doc comment saying
  exactly that.

### Verification

```bash
cd apps/desktop && npm test
```

Then the full gate.

### Commit

```
Catch the dev mock drifting from the backend

`npm run dev` runs the interface against `devMock.ts`, which is how the
UI actually gets built — a Tauri rebuild is too slow to iterate in. A
command that exists in `api.ts` with no handler in the mock breaks that
screen in development, and it breaks it silently: nobody finds out
until they open it.

This has happened before. There is a commit called "Bring the dev mock
back in step with the backend" and a comment inside the mock about the
same failure recurring. Both were caught by a person noticing, which is
not a mechanism.

The test reads `api.ts` as source rather than importing it, because the
question is which command names the file mentions, not what its exports
do at runtime. It checks both directions: a missing handler is the
break that has happened, and a handler for a command nothing calls is
dead code that reads as coverage.

The third test asserts the regex matched a plausible number of names. A
pattern that quietly matches nothing would make the other two pass
forever while checking nothing at all, which is the failure this file
exists to prevent, one level up.
```

### Pull request

**Title:** `Catch the dev mock drifting from the backend`

---

# Where the two tracks touch

Work in parallel, but three files are reachable from both sides. If both of you
edit one, whoever merges second resolves it — these are all appends, so the
resolution is mechanical.

| File | Track A | Track B |
| --- | --- | --- |
| `apps/desktop/src-tauri/src/lib.rs` | A1, A2, A3, A4 | B4 |
| `apps/desktop/src/api.ts` | A1, A2, A4 | B4 |
| `apps/desktop/src/lib/devMock.ts` | A1, A2, A4 | B4, B5 |

Two consequences worth knowing before they surprise you:

**B5 will fail on a branch that adds a command without a mock handler.** That is
the test doing its job. Whoever merges second adds the handler.

**Everything else is disjoint.** Track A owns `crates/yara-core/src/{generate,
health,vault,error}.rs` and `crates/yara-sync/**`. Track B owns
`apps/desktop/src/components/**`, `apps/desktop/src/lib/**`, and
`crates/yara-core/src/import.rs`. Nobody needs to wait for anybody.

Rebase on `upstream/main` before you push if the other track has landed
something:

```bash
git fetch upstream && git rebase upstream/main
```

---

# A warm-up, if you want one first

Not one of the ten. A genuine but small cleanup, useful for learning the fork
and PR mechanics against something low-stakes.

`Item.tags` is dead. `migrate_tags_into_folders` in `vault.rs` folds tags into
folders when a vault opens and then clears them, and nothing ever writes one
again — the comment at line 453 says so. But `ItemSummary` still carries
`tags: Vec<String>` across the IPC boundary, `api.ts` still declares it,
`devMock.ts` still invents them, and `ItemDetail.tsx` line 392 renders a Tags row
that cannot ever appear.

Remove it from `ItemSummary`, from `api.ts`, from the mock fixtures, from
`ItemDetail.test.tsx`, and delete the row. **Keep `Item.tags` and the migration
exactly as they are** — that field is how a vault written under the old model
still opens, and deleting it would strand those vaults. Add a test that a vault
serialised with tags still folds them into folders, if there is not one already.

Branch `drop-the-dead-tags-field`. One commit.

---

# What gets a pull request sent back

- It does more than one task.
- It has a TODO, a FIXME, a commented-out block, or a stub.
- A comment restates what the line below it does.
- A test is named `test_thing_works`.
- The full gate was not run, or was run and not fixed.
- It adds a dependency without asking.
- It reimplements something `yara-core` already does.
- The commit message describes code that is not in the diff.
- It claims the app was tested when the app was never built.

That last one is the only item on this list that is about honesty rather than
craft, and it is the one that matters most. If you could not run something, say
which thing and why. Nobody minds. A green claim over an untested change is a
different situation entirely.
