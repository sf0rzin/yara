# Agent access

The feature lapse exists for.

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

lapse is that tooling.

## The model

An agent never receives a secret by default. It receives an *outcome*.

Three access modes, in increasing order of exposure:

### 1. Run — the agent sees nothing

The agent asks lapse to run a command with a credential injected into the child
process environment. **The broker spawns the process itself**, so this is
enforced rather than promised: the client receives an exit code and captured
output, and there is no code path that returns the value to it.

```
agent → broker: run `npm run migrate` with item "db-prod" as $DATABASE_URL
user  → approves in the lapse window
broker: spawns the child with the variable set, returns exit code and output
```

The agent's context ends up holding the command and its output. Not the secret.
This is the default mode and it covers most of what agents actually need.

### 2. Reveal — the agent sees the value

Sometimes there is no alternative. This mode exists, it requires a distinct and
deliberately heavier confirmation, and it is recorded prominently in the audit
log. It is not the path of least resistance, by design.

## Approval

The broker listens on a local named pipe (`\\.\pipe\lapse.broker` on Windows; a
Unix domain socket elsewhere). A request looks like:

```json
{
  "client": "claude-code",
  "item": "db-prod",
  "field": "password",
  "mode": "inject",
  "reason": "run database migration"
}
```

If the vault is locked, the user is prompted to unlock. Then the lapse window
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

**What lapse protects against:**

- Secrets landing in an agent's context window, transcripts, or provider logs
- Secrets sitting in plaintext on disk in `.env` and scratch files
- Silent access — every request is approved by a human and written to an audit log
- A stolen vault file: it is useless without the master password
- Tampering with a vault file, including downgrading the KDF work factor

**What lapse does not protect against:**

- An attacker who already has code execution as your user. They can read lapse's
  memory while it is unlocked, or impersonate a client on the pipe. No user-space
  password manager solves this, and claiming otherwise would be dishonest.
- A malicious agent that asks for something reasonable-sounding and gets approved.
  The human in the loop is the control, so the prompt has to be legible enough
  for that human to make a real decision.
- Whatever the agent does with an injected credential once the process is running.

The guarantee is about *disclosure surface and accountability*, not about
defeating a local attacker who already owns the machine.

## Interface for agents

`lapse-mcp` exposes the broker as an MCP server, so any MCP-capable agent can use
it without special integration:

| Tool | Returns |
| --- | --- |
| `lapse_list_items` | Names, usernames, ids. Never secrets. |
| `lapse_run_with` | Exit code and output of a command run with the secret injected. |
| `lapse_reveal` | The plaintext, after heavy confirmation. |

`lapse_list_items` is deliberately unprivileged: an agent needs to be able to
discover that `db-prod` exists in order to ask for it, and item names are not
secrets.

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
- **Identity is the executable, not the process id.** A pid is reused and means
  nothing across invocations. If the caller cannot be identified at all, it
  never matches a stored grant, so it is prompted every time.
- **Locking the vault destroys every grant.** A permission that outlived the key
  it unlocks would be a permission with nothing behind it.

## Status

Built and tested, not yet wired into the desktop app:

| Piece | State |
| --- | --- |
| Wire protocol | Done |
| Grants: scope, expiry, use counts, revocation | Done |
| Audit log | Done, in memory |
| Named pipe transport | Done |
| Caller identification | Done, Windows only |
| Approval UI in the desktop app | Not started |
| Client (CLI and MCP server) | Not started |

Until the last two exist there is nothing for an agent to talk to. The broker is
a tested library at this point, not a running feature.

The audit log is held in memory. Persisting it belongs *inside* the encrypted
vault — a log naming every credential an agent touched is itself sensitive, and
writing it next to the vault in the clear would leak the shape of a vault nobody
could otherwise read.
