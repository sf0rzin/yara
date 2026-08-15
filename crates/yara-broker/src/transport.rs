//! The broker itself: decides, executes, records, and speaks over a pipe.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::sync::oneshot;
use uuid::Uuid;
use yara_core::SecretString;

use crate::audit::{Action, AuditLog, Entry, Outcome};
use crate::grant::{ClientId, Grant, GrantStore, Scope};
#[cfg(windows)]
use crate::platform::PeerHandle;
use crate::protocol::{
    self, AccessRequest, CommandOutput, Field, Intent, ItemRef, Refusal, Request, Response,
};

/// Where the broker listens.
#[cfg(windows)]
pub const DEFAULT_PIPE_NAME: &str = r"\\.\pipe\yara.broker";

/// How long a request waits for the user before giving up.
///
/// A prompt that waits forever leaves the agent hanging and, worse, leaves an
/// approval dialog on screen long after the user has forgotten what it was for
/// — which is exactly when people click yes to make it go away.
const APPROVAL_TIMEOUT: Duration = Duration::from_secs(120);

/// Output captured from a spawned command, truncated to keep a runaway process
/// from filling the agent's context with megabytes of log.
const MAX_OUTPUT_BYTES: usize = 64 * 1024;

/// Looking up an item by the name an agent supplied.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Resolution {
    Found(ItemRef),
    NotFound,
    /// Several items share the name, so guessing would be worse than asking.
    Ambiguous(Vec<String>),
}

/// The broker's read-only view of the vault.
///
/// A trait so the broker can be tested without a real vault, and so this crate
/// never needs to know how the vault is stored.
pub trait VaultBridge: Send + Sync + 'static {
    fn is_unlocked(&self) -> bool;
    fn list(&self, query: Option<&str>) -> Vec<ItemRef>;
    fn resolve(&self, needle: &str) -> Resolution;
    /// The value, or `None` if that field is empty.
    fn secret(&self, id: Uuid, field: &Field) -> Option<SecretString>;

    /// Writes an audit record into the vault.
    ///
    /// Required rather than defaulted: a no-op default would let an
    /// implementation lose the log by forgetting to write one, and silently
    /// is the only way an audit log ever fails.
    fn record_audit(&self, entry: &Entry);

    /// The records already in the vault, oldest first.
    ///
    /// Only readable while unlocked, which is why the broker asks for it at
    /// unlock rather than holding it across the lock.
    fn load_audit(&self) -> Vec<Entry>;
}

/// What the user is being asked to approve.
#[derive(Clone, Debug)]
pub struct ApprovalRequest {
    pub client: ClientId,
    pub item: ItemRef,
    pub field: Field,
    pub intent: Intent,
    pub reason: String,
    /// The command would hand the value back rather than use it, so this is a
    /// disclosure however it is labelled. The interface has to say so: the
    /// user is answering a different question than the wording suggests.
    pub discloses: bool,
}

/// The user's answer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Decision {
    Deny,
    /// This one time.
    AllowOnce,
    /// For a window, up to a number of uses.
    AllowFor {
        seconds: u64,
        uses: u32,
    },
}

/// Asks the user. Implemented by the desktop app.
pub trait Approver: Send + Sync + 'static {
    fn ask(&self, request: ApprovalRequest) -> oneshot::Receiver<Decision>;
}

pub struct Broker {
    vault: Arc<dyn VaultBridge>,
    approver: Arc<dyn Approver>,
    grants: Mutex<GrantStore>,
    audit: Mutex<AuditLog>,
}

impl Broker {
    pub fn new(vault: Arc<dyn VaultBridge>, approver: Arc<dyn Approver>) -> Arc<Self> {
        Arc::new(Self {
            vault,
            approver,
            grants: Mutex::new(GrantStore::new()),
            audit: Mutex::new(AuditLog::new()),
        })
    }

    /// Snapshot of live grants, for the interface.
    pub fn live_grants(&self, now: u64) -> Vec<Grant> {
        self.grants
            .lock()
            .map(|store| store.live(now).into_iter().cloned().collect())
            .unwrap_or_default()
    }

    /// Every grant the store holds, spent ones included.
    ///
    /// The interface wants [`Broker::live_grants`]; this exists so the store
    /// can be shown not to grow, which it used to do by one grant per approval
    /// until the vault locked.
    pub fn grant_count(&self) -> usize {
        self.grants.lock().map(|store| store.len()).unwrap_or(0)
    }

    pub fn recent_audit(&self, limit: usize) -> Vec<Entry> {
        self.audit
            .lock()
            .map(|log| log.recent(limit).into_iter().cloned().collect())
            .unwrap_or_default()
    }

    pub fn revoke(&self, id: Uuid) -> bool {
        self.grants
            .lock()
            .map(|mut store| store.revoke(id))
            .unwrap_or(false)
    }

    /// Called when the vault locks.
    ///
    /// Grants go because a permission that outlives the key behind it is a
    /// permission to nothing. The audit log goes because it lives in the
    /// vault now — keeping a readable copy in memory after the key is gone
    /// would leave the interface showing what the vault is meant to be
    /// hiding.
    pub fn forget_grants(&self) {
        if let Ok(mut store) = self.grants.lock() {
            store.clear();
        }
        if let Ok(mut log) = self.audit.lock() {
            *log = AuditLog::new();
        }
    }

    /// Loads the log out of the vault. Called on unlock, which is the first
    /// moment the history is readable.
    pub fn restore_audit(&self) {
        let entries = self.vault.load_audit();
        if let Ok(mut log) = self.audit.lock() {
            *log = AuditLog::new();
            for entry in entries {
                log.record(entry);
            }
        }
    }

    pub async fn handle(&self, request: Request, client: &ClientId) -> Response {
        match request {
            Request::Status => Response::Status {
                unlocked: self.vault.is_unlocked(),
                version: env!("CARGO_PKG_VERSION").to_string(),
            },

            Request::List { query } => {
                if !self.vault.is_unlocked() {
                    return Response::refused(Refusal::VaultLocked);
                }

                let items = self.vault.list(query.as_deref());

                // The query is a search term, not an item, and the client gave
                // no reason because listing needs none. Writing it into those
                // fields rendered a history row saying an item called "git"
                // had been accessed, for a reason the broker made up.
                self.record(Entry::listing(
                    client.clone(),
                    crate::now(),
                    query,
                    items.len(),
                ));

                Response::Items { items }
            }

            Request::Access(access) => self.handle_access(access, client).await,
        }
    }

    async fn handle_access(&self, access: AccessRequest, client: &ClientId) -> Response {
        if !self.vault.is_unlocked() {
            return Response::refused(Refusal::VaultLocked);
        }

        let item = match self.vault.resolve(&access.item) {
            Resolution::Found(item) => item,
            Resolution::NotFound => return Response::refused(Refusal::ItemNotFound),
            Resolution::Ambiguous(matches) => {
                return Response::refused(Refusal::Ambiguous { matches })
            }
        };

        // Refuse an empty field before bothering the user with a prompt they
        // would only be approving access to nothing.
        let has_field = match &access.field {
            Field::Password => item.has_password,
            Field::Totp => item.has_totp,
            Field::Username => item.username.is_some(),
            // Compared exactly, not case-insensitively. A grant is pinned to
            // the label it names, so "API key" and "api key" resolving to the
            // same field here would let one grant redeem against the other.
            Field::Custom(label) => item.fields.iter().any(|f| f == label),
        };
        if !has_field {
            return Response::refused(Refusal::FieldEmpty);
        }

        let now = crate::now();
        let existing = self.grants.lock().ok().and_then(|mut store| {
            // Pruning here rather than on a timer, because this is the one
            // place the store is already locked and already being walked. Left
            // alone it only ever grew: every one-shot approval leaves behind a
            // grant that was spent the moment it was issued.
            store.prune(now);
            store.redeem(item.id, &access.field, &access.intent, client, now)
        });

        let allowed = match existing {
            Some(grant) => Outcome::Reused { grant },
            None => match self.seek_approval(&access, &item, client, now).await {
                Ok(outcome) => outcome,
                Err(refusal) => {
                    self.record_access(
                        client,
                        &item,
                        &access,
                        Outcome::Refused {
                            reason: refusal.clone(),
                        },
                    );
                    return Response::refused(refusal);
                }
            },
        };

        // Nothing is written until the action has happened. Recording first
        // logged a command that never ran three different ways — the field
        // turned out to be empty, the spawn failed, or the vault locked while
        // the prompt sat on screen for up to two minutes — and the Agent
        // access screen then told the user their production password had gone
        // to a process that never started.
        let response = self.dispatch(&item, &access).await;

        // A grant minted as the vault was locking is a permission with nothing
        // behind it. `forget_grants` runs at the lock, which can be before the
        // user's answer arrives, so this one would have outlived the key and
        // been redeemable without a prompt at the next unlock.
        if matches!(
            &response,
            Response::Refused {
                reason: Refusal::VaultLocked,
                ..
            }
        ) {
            if let Some(grant) = allowed.grant() {
                self.revoke(grant);
            }
        }

        let outcome = match &response {
            Response::Refused { reason, .. } => Outcome::Refused {
                reason: reason.clone(),
            },
            Response::Error { message } => Outcome::Failed {
                error: message.clone(),
            },
            _ => allowed,
        };
        self.record_access(client, &item, &access, outcome);

        response
    }

    /// Fetches the value and does the thing that was approved.
    async fn dispatch(&self, item: &ItemRef, access: &AccessRequest) -> Response {
        // Checked again after the wait, not only before it. An approval
        // answered as the vault locks authorises access to a key that is no
        // longer there, and the reason the value is missing must not read as
        // "that field is empty".
        if !self.vault.is_unlocked() {
            return Response::refused(Refusal::VaultLocked);
        }

        let Some(secret) = self.vault.secret(item.id, &access.field) else {
            return Response::refused(Refusal::FieldEmpty);
        };

        match &access.intent {
            Intent::Reveal => Response::Revealed {
                value: secret.expose().to_string(),
            },
            Intent::Run {
                command,
                args,
                env_var,
                cwd,
            } => run_command(command, args, env_var, cwd.as_deref(), &secret).await,
        }
    }

    /// Puts the request to the user and turns the answer into a grant.
    async fn seek_approval(
        &self,
        access: &AccessRequest,
        item: &ItemRef,
        client: &ClientId,
        now: u64,
    ) -> Result<Outcome, Refusal> {
        let discloses = access.intent.discloses_secret();

        let receiver = self.approver.ask(ApprovalRequest {
            client: client.clone(),
            item: item.clone(),
            field: access.field.clone(),
            intent: access.intent.clone(),
            reason: access.reason.clone(),
            discloses,
        });

        let decision = match tokio::time::timeout(APPROVAL_TIMEOUT, receiver).await {
            Ok(Ok(decision)) => decision,
            // A dropped sender means the window went away without an answer,
            // which is not consent.
            Ok(Err(_)) => return Err(Refusal::Denied),
            Err(_) => return Err(Refusal::TimedOut),
        };

        // The grant is for this command, not for the idea of running commands.
        let scope = Scope::for_intent(&access.intent);

        // A disclosure never earns a standing grant, however the request was
        // answered. Once the value is out there is no technical limit on what
        // happens to it, so each one is its own decision.
        //
        // This covers a `Run` whose command would print the value as well as an
        // outright reveal: the two differ in wording, not in consequence, and
        // pricing them differently is what let the cheap path be the leaky one.
        // Enforced here rather than by omitting a button, so no interface can
        // widen it.
        let decision = match decision {
            Decision::AllowFor { .. } if discloses => Decision::AllowOnce,
            other => other,
        };

        let grant = match decision {
            Decision::Deny => return Err(Refusal::Denied),
            Decision::AllowOnce => Grant::once(
                item.id,
                &item.name,
                access.field.clone(),
                scope,
                client.clone(),
                now,
            ),
            Decision::AllowFor { seconds, uses } => Grant::new(
                item.id,
                &item.name,
                access.field.clone(),
                scope,
                client.clone(),
                now,
                seconds,
                uses,
            ),
        };

        // Store it and charge this request against it, so an approval for one
        // use is not immediately spendable a second time.
        let issued = self.grants.lock().ok().map(|mut store| {
            let id = store.issue(grant);
            store.redeem(item.id, &access.field, &access.intent, client, now);
            // A one-shot grant is spent by the line above and will never be
            // read again; dropping it here keeps the store from growing by one
            // per approval for the life of the unlock.
            store.prune(now);
            id
        });

        // The id goes on the record. Without it the later `Reused` entries
        // named a uuid that appeared nowhere else, so a chain of them traced
        // back to "some approval, earlier" and the terms the user actually
        // consented to were unrecoverable once the grant expired.
        Ok(Outcome::Approved { grant: issued })
    }

    fn record_access(
        &self,
        client: &ClientId,
        item: &ItemRef,
        access: &AccessRequest,
        outcome: Outcome,
    ) {
        self.record(Entry {
            id: Uuid::new_v4(),
            at: crate::now(),
            client: client.clone(),
            item: item.name.clone(),
            field: Some(access.field.clone()),
            action: Action::from_intent(&access.intent),
            outcome,
            reason: access.reason.clone(),
            query: None,
        });
    }

    fn record(&self, entry: Entry) {
        // The vault first. An entry that only reached memory is gone at the
        // next lock, and a log that does not survive the session that made it
        // is not a log.
        self.vault.record_audit(&entry);

        if let Ok(mut log) = self.audit.lock() {
            log.record(entry);
        }
    }
}

/// Spawns a command with the credential in its environment.
///
/// The broker runs the process rather than handing the value to the client and
/// trusting it to do so, which is what makes "the agent never sees it" a
/// property of the system instead of a promise.
async fn run_command(
    command: &str,
    args: &[String],
    env_var: &str,
    cwd: Option<&str>,
    secret: &SecretString,
) -> Response {
    let mut process = tokio::process::Command::new(command);
    process.args(args).env(env_var, secret.expose());

    if let Some(dir) = cwd {
        process.current_dir(dir);
    }

    match process.output().await {
        Ok(output) => Response::Ran(CommandOutput {
            exit_code: output.status.code().unwrap_or(-1),
            stdout: clean(&output.stdout, secret),
            stderr: clean(&output.stderr, secret),
        }),
        Err(error) => Response::Error {
            message: format!("could not run {command}: {error}"),
        },
    }
}

/// What replaces the credential when a child prints it.
const REDACTED: &str = "[redacted by yara]";

/// Below this length a value matches too much ordinary text, and redacting it
/// would mangle the output into uselessness. Anything that short is already
/// flagged as weak by the health audit.
const MIN_REDACTABLE: usize = 6;

/// Removes the credential if the child echoed it, then truncates.
///
/// In that order, deliberately: truncating first can cut through the middle of
/// the value and leave half of it behind.
///
/// This exists for the common accident — a migration tool that prints its
/// connection string on failure — where the value would land in the agent's
/// context having been kept out of it by design. It is not a defence against a
/// caller that wants the value and can encode it on the way out. That request
/// is handled by pricing it correctly instead; see [`crate::exposure`].
fn clean(raw: &[u8], secret: &SecretString) -> String {
    let text = String::from_utf8_lossy(raw).into_owned();
    let value = secret.expose();

    let text = if value.len() >= MIN_REDACTABLE && text.contains(value) {
        text.replace(value, REDACTED)
    } else {
        text
    };

    truncate(text)
}

fn truncate(mut text: String) -> String {
    if text.len() <= MAX_OUTPUT_BYTES {
        return text;
    }

    // Cut on a character boundary so the result is still valid UTF-8.
    let mut cut = MAX_OUTPUT_BYTES;
    while cut > 0 && !text.is_char_boundary(cut) {
        cut -= 1;
    }
    text.truncate(cut);
    text.push_str("\n… output truncated");
    text
}

/// Why the broker stopped listening.
///
/// A value rather than an `io::Error` because the only caller is a windowed
/// application with no console: whatever comes back here has to be sayable to
/// the person looking at the app, and "os error 5" is not. Every variant is
/// terminal — the transient cases never reach the caller at all.
#[derive(Debug, thiserror::Error)]
pub enum ServeError {
    /// The name was already taken, which all but always means a second copy of
    /// yara is running and owns it.
    #[error("another copy of yara is already handling agent requests")]
    AlreadyRunning,

    /// The listener could not be opened at all.
    #[error("agent access could not be started ({0})")]
    Unavailable(#[source] std::io::Error),

    /// It was listening and is not any more: the instance could not be put
    /// back. Fatal on purpose. While no instance of the name exists any
    /// process can create it and answer the CLI and the MCP server in yara's
    /// place, so this has to be said out loud rather than retried forever.
    #[error(
        "agent access has stopped and could not be restarted after {attempts} attempts ({source})"
    )]
    Lost {
        attempts: u32,
        #[source]
        source: std::io::Error,
    },

    /// Connection after connection failed to complete, with no successful one
    /// in between.
    #[error("agent access is not working: {failures} connections in a row failed ({source})")]
    Unstable {
        failures: u32,
        #[source]
        source: std::io::Error,
    },
}

/// How many times to try putting the listener back before giving up.
#[cfg(windows)]
const CREATE_ATTEMPTS: u32 = 8;

/// How many connections may fail in a row before the pipe is called broken.
#[cfg(windows)]
const ACCEPT_FAILURES: u32 = 16;

/// First wait between retries; each one doubles up to [`BACKOFF_CAP`].
#[cfg(windows)]
const BACKOFF_START_MS: u64 = 20;

#[cfg(windows)]
const BACKOFF_CAP: Duration = Duration::from_secs(2);

/// Exponential, capped. Capped because an unbounded backoff on a pipe nobody
/// owns is indistinguishable from having given up, and the cap is short
/// because every wait is a window in which the name is unclaimed.
#[cfg(windows)]
fn backoff(attempt: u32) -> Duration {
    let doublings = attempt.saturating_sub(1).min(16);
    Duration::from_millis(BACKOFF_START_MS.saturating_mul(1 << doublings)).min(BACKOFF_CAP)
}

/// Where trouble that is not fatal goes.
///
/// Deliberately not returned: ending the accept loop over one bad connection
/// is what used to take agent access down for the rest of the session, leaving
/// the CLI saying "is yara running and unlocked?" while yara sat there
/// unlocked.
#[cfg(windows)]
fn report(message: &str) {
    eprintln!("yara: {message}");
}

/// Whether a connection simply ended.
///
/// The CLI opens the pipe, asks one question and closes it, which surfaces
/// here as a broken pipe. Logging those would put a line of noise on every
/// single request and bury the failures worth reading.
#[cfg(windows)]
fn is_hangup(error: &std::io::Error) -> bool {
    use std::io::ErrorKind::*;

    matches!(
        error.kind(),
        BrokenPipe | UnexpectedEof | ConnectionAborted | ConnectionReset
    )
}

/// Opens another instance of the pipe, retrying with backoff.
#[cfg(windows)]
async fn listen_again(
    pipe_name: &str,
) -> Result<tokio::net::windows::named_pipe::NamedPipeServer, ServeError> {
    use tokio::net::windows::named_pipe::ServerOptions;

    let mut attempt = 1;
    loop {
        let error = match ServerOptions::new().create(pipe_name) {
            Ok(server) => return Ok(server),
            Err(error) => error,
        };

        if attempt >= CREATE_ATTEMPTS {
            return Err(ServeError::Lost {
                attempts: attempt,
                source: error,
            });
        }

        report(&format!(
            "could not reopen the agent pipe on attempt {attempt} ({error}); retrying"
        ));
        tokio::time::sleep(backoff(attempt)).await;
        attempt += 1;
    }
}

/// Listens for clients until cancelled.
///
/// Only a fatal condition ends this. A single failed connection used to end
/// it, which had two consequences: agent access was gone for the life of the
/// process, and — worse — with no instance of the pipe left open, any process
/// could create the name and answer in yara's place, fabricating an unlocked
/// status and collecting the item names and stated reasons agents send.
#[cfg(windows)]
pub async fn serve(broker: Arc<Broker>, pipe_name: &str) -> Result<(), ServeError> {
    use tokio::net::windows::named_pipe::ServerOptions;

    let mut server = ServerOptions::new()
        .first_pipe_instance(true)
        .create(pipe_name)
        .map_err(|error| match error.kind() {
            // What Windows says when the name exists and someone else claimed
            // it first. Retrying would not help and would spin.
            std::io::ErrorKind::PermissionDenied => ServeError::AlreadyRunning,
            _ => ServeError::Unavailable(error),
        })?;

    let mut failures = 0u32;

    loop {
        if let Err(error) = server.connect().await {
            failures += 1;
            if failures >= ACCEPT_FAILURES {
                return Err(ServeError::Unstable {
                    failures,
                    source: error,
                });
            }

            report(&format!(
                "a client connection failed ({error}); still listening"
            ));
            tokio::time::sleep(backoff(failures)).await;

            // Replace the instance that failed. Assigning only once the new
            // one exists means the name is never unowned, which is the whole
            // point: a gap here is a gap anyone can step into.
            server = listen_again(pipe_name).await?;
            continue;
        }
        failures = 0;

        // Hand this connection off and immediately start listening again, so a
        // client sitting on an unanswered prompt cannot block every other one.
        let connected = server;
        server = listen_again(pipe_name).await?;

        let broker = Arc::clone(&broker);
        tokio::spawn(async move {
            let client = connected.identify();
            if let Err(error) = serve_connection(broker, connected, client).await {
                if !is_hangup(&error) {
                    report(&format!("a client connection failed ({error})"));
                }
            }
        });
    }
}

#[cfg(all(windows, test))]
mod serve_tests {
    use super::*;

    /// A client that closes the pipe when it is finished is the normal case.
    #[test]
    fn an_ordinary_disconnect_is_not_reported_as_trouble() {
        use std::io::{Error, ErrorKind};

        assert!(is_hangup(&Error::from(ErrorKind::BrokenPipe)));
        assert!(is_hangup(&Error::from(ErrorKind::UnexpectedEof)));
        assert!(!is_hangup(&Error::from(ErrorKind::PermissionDenied)));
    }

    #[test]
    fn the_backoff_grows_and_then_stops_growing() {
        assert_eq!(backoff(1), Duration::from_millis(BACKOFF_START_MS));
        assert_eq!(backoff(2), Duration::from_millis(BACKOFF_START_MS * 2));
        assert_eq!(backoff(3), Duration::from_millis(BACKOFF_START_MS * 4));

        // Capped, and never longer than the cap however many attempts have
        // gone by: a long wait is a long window in which the pipe name is
        // unclaimed, and a saturating shift must not turn into a stall.
        assert_eq!(backoff(20), BACKOFF_CAP);
        assert_eq!(backoff(u32::MAX), BACKOFF_CAP);
    }

    /// Every retry has to be short enough that a user watching the app does
    /// not experience the gap as the feature being gone.
    #[test]
    fn giving_up_on_the_listener_takes_seconds_not_minutes() {
        let total: Duration = (1..CREATE_ATTEMPTS).map(backoff).sum();
        assert!(total < Duration::from_secs(15), "waited {total:?}");
    }
}

/// Reads requests from one client until it disconnects.
pub async fn serve_connection<S>(
    broker: Arc<Broker>,
    stream: S,
    client: ClientId,
) -> std::io::Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let (reader, mut writer) = tokio::io::split(stream);
    let mut lines = BufReader::new(reader).lines();

    while let Some(line) = lines.next_line().await? {
        if line.trim().is_empty() {
            continue;
        }

        let response = match protocol::decode::<Request>(&line) {
            Ok(request) => broker.handle(request, &client).await,
            Err(error) => Response::Error {
                message: format!("could not understand that request: {error}"),
            },
        };

        let encoded = protocol::encode(&response).unwrap_or_else(|_| {
            "{\"response\":\"error\",\"message\":\"encoding failed\"}\n".into()
        });
        writer.write_all(encoded.as_bytes()).await?;
        writer.flush().await?;
    }

    Ok(())
}
