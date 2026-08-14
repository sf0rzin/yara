# Security

yara holds passwords, one-time-code seeds and an audit log of every credential
an agent has touched. A defect here costs more than a defect in most software,
so this document says where to send one, what happens then, and how long it
takes — in numbers one person can actually meet.

## Reporting a vulnerability

**Use GitHub's private vulnerability reporting:**
[Report a vulnerability](https://github.com/sf0rzin/yara/security/advisories/new),
or the **Report a vulnerability** button under the repository's **Security**
tab. The report is visible only to the maintainer, it carries a private fork to
develop a fix in, and it becomes an advisory when the fix ships.

Please do not open a public issue for anything that looks exploitable, and
please do not describe it in a pull request. A public description of a working
attack on a password manager is useful to an attacker on the day it is
published and to a user only after they have updated.

If that button is not there, private reporting has not been switched on. The
owner turns it on under **Settings → Advanced Security → Private vulnerability
reporting → Enable**, which takes about ten seconds and needs no plan or
paperwork. In the meantime, open an issue that says you have something to
report privately and **nothing else about it** — no version, no component, no
reproduction — and it will be enabled so you can file properly.

There is deliberately no email address in this file. Publishing one that later
bounces is worse than publishing none, and GitHub's channel is already
authenticated, already private, and already attached to the code. A maintainer
address can be added here if reporters ask for one.

## What happens then

yara is maintained by one person, in their own time, and the windows below say
so rather than pretending otherwise. They are deliberately wider than a company
would print and are meant to be met rather than missed.

| Stage | Window |
| --- | --- |
| Acknowledgement that the report arrived and is being read | 5 days |
| An assessment: whether it reproduces, what it affects, how severe | 14 days |
| A fix, or a written plan with dates, for anything confirmed | 30 days |
| Public advisory and credit, once a release carrying the fix exists | with the release |

If a report goes unacknowledged past 14 days, assume it has been lost rather
than ignored — say so in the same thread, and if there is still no answer, you
are free to disclose publicly. Ninety days from the acknowledged report is the
default coordinated-disclosure horizon; an actively exploited issue is not held
to any of it.

Reports that turn out to be already known, out of scope, or not exploitable get
an answer saying which, and why. A dismissed report should still tell you
something.

## Supported versions

Only the newest release. There is no long-term branch and nothing is
back-ported: a fix goes out as a new release and the update channel carries it.

One historical wrinkle, because it changes who a fix actually reaches.
Installations of **0.3.2 and earlier** have an update endpoint compiled in that
is no longer served — see `docs/hosting.md` — so they will never be offered an
update, security or otherwise. Anyone still on one of those has to install the
current release by hand.

## In scope

Reports about any of these are wanted:

**The vault format and the cryptographic core** (`crates/yara-core`) — key
derivation and its parameters, the envelope encryption, the authenticated
header, tamper detection, anything that lets a vault file be read, downgraded
or silently modified without the master password. Key material surviving in
memory after a lock, or reaching disk, counts.

**The broker and the grant model** (`crates/yara-broker`, `crates/yara-cli`,
`crates/yara-mcp`) — anything that gets a credential out of the broker without
the approval the user was shown, that widens a grant beyond the item, field,
command and executable it was pinned to, that survives a lock, or that
misidentifies the calling process in the approval prompt. Approval prompts that
misrepresent what is being approved are in scope too: the prompt is the control,
so a misleading one is a vulnerability rather than a wording problem.

**The sync protocol and service** (`crates/yara-sync`,
`crates/yara-sync-client`) — signature verification, replay and nonce handling,
the enrolment endpoint and its invites, anything that lets one account read or
write another's items, anything that lets the server or an observer act as a
user, and SSRF in the icon proxy.

**The update channel** — the signing arrangement, the release workflow,
`deploy/pull-manifest.sh`, and anything that could get an installer onto a
user's machine that the client should not have accepted.

**The deployment configuration in `deploy/`** — the egress filter, the Caddy
configuration, the container's privileges, anything that exposes the origin's
own host or another project on it.

## Not in scope

These are known, deliberate, and documented in `docs/agent-access.md`. A report
about one of them will get a polite pointer back here.

- **An attacker who already runs code as your user.** They can read the
  process's memory while the vault is unlocked, or impersonate a client on the
  named pipe. No user-space password manager solves this, and pretending
  otherwise would be the actual security failure.
- **A malicious agent that asks for something plausible and is approved.** The
  human in the loop is the control. Making the prompt clearer is a bug worth
  filing; the existence of the decision is the design.
- **A caller that writes a program to print its own environment and asks to run
  it.** Disclosure costs a disclosure prompt by design, not a technical barrier.
- **Physical access to an unlocked machine**, and anything that follows from an
  attacker holding the master password or the recovery kit.
- **Metadata visible to the sync host or to Cloudflare** — item counts, sizes,
  change times, connecting addresses. Stated in `docs/hosting.md`; report it if
  something *beyond* that is visible.
- **Missing security headers, TLS configuration ratings, or version banners**
  on `yara.lat` with no path to impact, and findings from an automated scanner
  pasted without one.
- **Denial of service by flooding**, and rate-limit tuning.
- **Absence of macOS or Linux support.** Windows-only is deliberate.

## Testing, and where not to point it

Test against your own vault, on your own machine, with an account you enrolled.

`yara.lat` serves a handful of invited people and their real data. Do not run
scanners against it, do not attempt to reach another account, and do not test
availability. If a bug hands you something that belongs to somebody else, stop
there, do not save it, and say so in the report — what you did after noticing
is the part that matters.

Testing done that way will not be treated as an attack, and a report made in
good faith will not be met with a lawyer. There is no bounty programme; there
is no money in this project to fund one. Credit in the advisory and the release
notes is offered to every reporter who wants it.

## A useful report

Enough to reproduce beats a severity score:

- the yara version, and Windows version if it is relevant
- what you did, in order, and what happened
- what an attacker gets out of it, and what they need first — particularly
  whether it needs code execution on the machine already, since that line is
  what separates a finding from the threat model above
- a proof of concept if you have one, and what to look for if you do not

## Design documents worth reading first

They will save you time, and they say plainly where the guarantees stop:

- [`docs/agent-access.md`](docs/agent-access.md) — the broker, grants, and the
  threat model in full
- [`docs/hosting.md`](docs/hosting.md) — the sync service, the update channel,
  what each hop can see
- [`README.md`](README.md) — the cryptographic design in one table
