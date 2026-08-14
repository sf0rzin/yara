# Agent access

The feature yara exists for.

## The problem

An AI coding agent needs real credentials to do real work — a database URL, a
deploy token, an SSH key. Today there are two options and both are bad:

1. **Paste the secret into the chat.** It is now in the model's context window,
   the transcript, the provider's logs, and any local session file. It cannot be
   un-pasted.
2. **Put it in a `.env` or a `.txt` and tell the agent "it's in there".** The
   secret sits in plaintext on disk, every process running as you can read it,
   and the agent can `cat` the file anyway the moment it decides that would help.

Option 2 is the common workaround precisely because agents are built to refuse
handling plaintext passwords. The refusal is correct, but it pushes people into a
worse arrangement — the secret ends up less protected than if the tooling had
just handled it properly.

yara is that tooling.

## The model

An agent never receives a secret by default. It receives an *outcome*.

Three access modes, in increasing order of exposure:

### 1. Run — the agent sees an outcome

The agent asks yara to run a command with a credential injected into the child
process environment. **The broker spawns the process itself**, so the value is
never handed to the client to be used on trust: it receives an exit code and
captured output.

Three things make that hold up, and it is worth being precise because the
obvious version of this feature does not.

**A grant is for a command, not for the idea of running commands.** Approving
`npm run migrate` for fifteen minutes authorises that command, with those
arguments, in that directory — nothing else. Anything different goes back to
the user, even from the same program against the same item inside the window.
Without this, one approval buys the caller a free choice of command, and the
useful choice is the one that prints the credential.

**A command that would print the value is priced as a disclosure.** A shell, or
an interpreter handed a program to evaluate, is a reveal wearing a run's
clothes. Those requests get the heavier confirmation, are labelled in the
prompt as handing the value over, and never earn a standing grant.

**The captured output is scrubbed of the value before it is returned.** This is
for the ordinary accident — a migration tool that prints its connection string
when it fails — where the credential would otherwise land in the agent's
context having been kept out of it by design.

None of this is a sandbox, and the third is not a filter that survives an
adversary. A caller determined to see the value can write a program that prints
its environment, or encodes it on the way out, and ask to run that. What the
three buy together is that the cheap, obvious path is no longer the leaky one:
seeing the value costs a disclosure prompt every single time, which is exactly
what it costs to ask for it honestly.

```
agent → broker: run `npm run migrate` with item "db-prod" as $DATABASE_URL
user  → approves in the yara window
broker: spawns the child with the variable set, returns exit code and output
```

The agent's context ends up holding the command and its output. Not the secret.
This is the default mode and it covers most of what agents actually need.

### 2. Reveal — the agent sees the value

Sometimes there is no alternative. This mode exists, it requires a distinct and
deliberately heavier confirmation, and it is recorded prominently in the audit
log. It is not the path of least resistance, by design.

## Approval

The broker listens on a local named pipe, `\\.\pipe\yara.broker`. That is the
whole transport list — Windows only, and not a placeholder for something
portable, because the identification below is a Win32 call on the same pipe.

Messages are newline-delimited JSON, one per line, so the channel is readable
in a log. A request to run a command with a credential injected is:

```json
{
  "request": "access",
  "item": "db-prod",
  "field": "password",
  "mode": "run",
  "command": "npm",
  "args": ["run", "migrate"],
  "env_var": "DATABASE_URL",
  "reason": "run database migration"
}
```

`"mode": "reveal"` is the other intent, and it carries no command: `request`,
`item`, `field`, `mode` and `reason`, and nothing else.

Note what is absent: nothing in the message names the caller. An earlier version
of this document showed a `"client": "claude-code"` field, which the broker has
never had — it would be ignored as an unknown key, which is the more misleading
outcome of the two, since it reads as though a caller announces who it is. An
identity the caller fills in itself is not an identity; the real one comes off
the pipe, below.

That example was not a message the broker would accept either way. It had no
`"request": "access"` tag, and `"mode": "inject"` matches neither intent. Both
are the kind of thing a first client is written against, so the wire format is
worth reading from `crates/yara-broker/src/protocol.rs`, which is where these
examples now come from.

If the vault is locked, the user is prompted to unlock. Then the yara window
raises a modal naming the requesting process, the item, the mode, and the stated
reason, offering: **allow once**, **allow for 15 minutes**, or **deny**.

There is no "allow everything forever" setting. A grant is scoped to an item, a
set of fields, a mode, an expiry, and a use count.

## Client identity

Any process running as the user can connect to the pipe. The broker therefore
records the peer process id (`GetNamedPipeClientProcessId` on Windows), resolves
the image path, and shows it in the approval prompt — so the user is approving a
specific binary, not an anonymous "something".

## Threat model

Being precise about this matters more than sounding strong.

**What yara protects against:**

- Secrets landing in an agent's context window, transcripts, or provider logs
- Secrets sitting in plaintext on disk in `.env` and scratch files
- Silent access — every request is approved by a human and written to an audit log
- A stolen vault file: it is useless without the master password
- Tampering with a vault file, including downgrading the KDF work factor

**What yara does not protect against:**

- An attacker who already has code execution as your user. They can read yara's
  memory while it is unlocked, or impersonate a client on the pipe. No user-space
  password manager solves this, and claiming otherwise would be dishonest.
- A malicious agent that asks for something reasonable-sounding and gets approved.
  The human in the loop is the control, so the prompt has to be legible enough
  for that human to make a real decision.
- Whatever the agent does with an injected credential once the process is running.
- A caller that writes its own program to print the environment and asks to run
  that. Shell detection catches the obvious spellings, not the determined ones,
  and the output scrub catches accidental echoes rather than deliberate
  encoding. What both do is make disclosure cost a disclosure prompt, so the
  dishonest route is never cheaper than the honest one.

The guarantee is about *disclosure surface and accountability*, not about
defeating a local attacker who already owns the machine.

## Interface for agents

`yara-mcp` exposes the broker as an MCP server — JSON-RPC over stdio — so any
MCP-capable agent can use it without special integration:

```json
{ "mcpServers": { "yara": { "command": "yara-mcp" } } }
```

| Tool | Returns |
| --- | --- |
| `yara_list_items` | Names, usernames, ids. Never secrets. |
| `yara_run_with_credential` | Exit code and output of a command run with the secret injected. |
| `yara_reveal_credential` | The plaintext, after heavy confirmation. |
| `yara_status` | Whether yara is running and unlocked. |

`yara_list_items` is deliberately unprivileged: an agent needs to be able to
discover that `db-prod` exists in order to ask for it, and item names are not
secrets.

The tool *descriptions* are load-bearing. They are what an agent reads when
choosing between using a credential and asking to see one, and that choice
happens before the user is ever prompted. `run_with_credential` is described as
the default; `reveal_credential` says plainly that it is a last resort, that the
value cannot be taken back, and that it never earns a standing approval.

Both access tools require a `reason`, and it is shown to the user verbatim.
A request with no stated purpose is not a request the user can evaluate.

## Grants

Approving "run the migration" should not mean answering a prompt once per query,
so an approval can produce a grant. A grant is pinned to one item, one field,
one requesting executable, a deadline, and a use count. There is no "always
allow" and no way to widen a grant after the fact.

Three rules are worth stating because they are the ones that would be tempting
to relax:

- **Permission to run is not permission to reveal.** A grant covering `Run` never
  authorises `Reveal`; being allowed to *use* a password is not being allowed to
  *see* it. Reveal always goes back to the user.
- **Permission to run one thing is not permission to run another.** The grant
  pins the command, its arguments, and its working directory. `npm run migrate`
  somewhere else is somebody else's `package.json`, and a grant that covered any
  command would be worth more than the credential it guards — the holder could
  name one that prints it.
- **A command that discloses is not eligible for a grant at all.** Shells and
  `node -e` style invocations are treated as reveals however the request was
  labelled, so they are asked every time.
- **Identity is the executable, not the process id.** A pid is reused and means
  nothing across invocations. If the caller cannot be identified at all, it
  never matches a stored grant, so it is prompted every time.
- **Locking the vault destroys every grant.** A permission that outlived the key
  it unlocks would be a permission with nothing behind it.

## Using it

The broker runs inside the yara app. Point an agent at the `yara` command:

```bash
yara run --item db-prod --env DATABASE_URL --reason "run the migration" -- npm run migrate
```

The yara window comes forward and asks. On approval the broker spawns `npm run
migrate` with `DATABASE_URL` set, and the agent gets the output — not the value.

```bash
yara list
yara get --item db-prod --reason "paste into a config file"
```

`list` needs no approval and returns no secrets. `get` prints plaintext and asks
every single time.

## Status

| Piece | State |
| --- | --- |
| Wire protocol | Done |
| Grants: scope, expiry, use counts, revocation | Done |
| Audit log | Done, inside the encrypted vault |
| Named pipe transport | Done |
| Caller identification | Done, Windows only |
| Approval prompt and the Agent access screen | Done |
| `yara` command line client | Done |
| `yara-mcp` MCP server | Done |
| macOS and Linux | Not planned — see the README |

The audit log lives *inside* the encrypted vault. A log naming every credential
an agent touched is itself sensitive, and writing it next to the vault in the
clear would describe the shape of a vault nobody could otherwise read.

It is bounded at 500 records and drops the oldest, so it cannot grow without
limit inside a file that is re-encrypted whole on every write. Locking clears
the copy the interface reads from — the key is gone, and continuing to show
what the vault is meant to be hiding would be an odd way to lock something.

There is deliberately **no hash chain** over the records. It is the first thing
that suggests itself for an audit log, and here it would prove nothing: the
file is authenticated as a whole by the AEAD, and anyone able to rewrite a
record holds the key that would let them recompute a chain over it too.
