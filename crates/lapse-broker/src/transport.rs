//! The broker itself: decides, executes, records, and speaks over a pipe.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use lapse_core::SecretString;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::sync::oneshot;
use uuid::Uuid;

use crate::audit::{Action, AuditLog, Entry, Outcome};
use crate::grant::{ClientId, Grant, GrantStore, Scope};
use crate::platform::PeerHandle;
use crate::protocol::{
    self, AccessRequest, CommandOutput, Field, Intent, ItemRef, Refusal, Request, Response,
};

/// Where the broker listens.
#[cfg(windows)]
pub const DEFAULT_PIPE_NAME: &str = r"\\.\pipe\lapse.broker";

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
    fn secret(&self, id: Uuid, field: Field) -> Option<SecretString>;
}

/// What the user is being asked to approve.
#[derive(Clone, Debug)]
pub struct ApprovalRequest {
    pub client: ClientId,
    pub item: ItemRef,
    pub field: Field,
    pub intent: Intent,
    pub reason: String,
}

/// The user's answer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Decision {
    Deny,
    /// This one time.
    AllowOnce,
    /// For a window, up to a number of uses.
    AllowFor { seconds: u64, uses: u32 },
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
    pub fn forget_grants(&self) {
        if let Ok(mut store) = self.grants.lock() {
            store.clear();
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
                self.record(Entry {
                    id: Uuid::new_v4(),
                    at: crate::now(),
                    client: client.clone(),
                    item: query.unwrap_or_else(|| "*".into()),
                    field: Field::Username,
                    action: Action::Listed {
                        matches: items.len(),
                    },
                    outcome: Outcome::Approved,
                    reason: "listing item names".into(),
                });

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
        let has_field = match access.field {
            Field::Password => item.has_password,
            Field::Totp => item.has_totp,
            Field::Username => item.username.is_some(),
        };
        if !has_field {
            return Response::refused(Refusal::FieldEmpty);
        }

        let now = crate::now();
        let existing = self.grants.lock().ok().and_then(|mut store| {
            store.redeem(item.id, access.field, &access.intent, client, now)
        });

        let outcome = match existing {
            Some(grant) => Outcome::Reused { grant },
            None => match self.seek_approval(&access, &item, client, now).await {
                Ok(outcome) => outcome,
                Err(refusal) => {
                    self.record_access(client, &item, &access, Outcome::Refused { reason: refusal.clone() });
                    return Response::refused(refusal);
                }
            },
        };

        self.record_access(client, &item, &access, outcome);

        let Some(secret) = self.vault.secret(item.id, access.field) else {
            return Response::refused(Refusal::FieldEmpty);
        };

        match access.intent {
            Intent::Reveal => Response::Revealed {
                value: secret.expose().to_string(),
            },
            Intent::Run {
                command,
                args,
                env_var,
                cwd,
            } => run_command(&command, &args, &env_var, cwd.as_deref(), &secret).await,
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
        let receiver = self.approver.ask(ApprovalRequest {
            client: client.clone(),
            item: item.clone(),
            field: access.field,
            intent: access.intent.clone(),
            reason: access.reason.clone(),
        });

        let decision = match tokio::time::timeout(APPROVAL_TIMEOUT, receiver).await {
            Ok(Ok(decision)) => decision,
            // A dropped sender means the window went away without an answer,
            // which is not consent.
            Ok(Err(_)) => return Err(Refusal::Denied),
            Err(_) => return Err(Refusal::TimedOut),
        };

        let scope = if access.intent.is_reveal() {
            Scope::Reveal
        } else {
            Scope::Run
        };

        let grant = match decision {
            Decision::Deny => return Err(Refusal::Denied),
            Decision::AllowOnce => {
                Grant::once(item.id, &item.name, access.field, scope, client.clone(), now)
            }
            Decision::AllowFor { seconds, uses } => Grant::new(
                item.id,
                &item.name,
                access.field,
                scope,
                client.clone(),
                now,
                seconds,
                uses,
            ),
        };

        // Store it and charge this request against it, so an approval for one
        // use is not immediately spendable a second time.
        if let Ok(mut store) = self.grants.lock() {
            store.issue(grant);
            store.redeem(item.id, access.field, &access.intent, client, now);
        }

        Ok(Outcome::Approved)
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
            field: access.field,
            action: Action::from_intent(&access.intent),
            outcome,
            reason: access.reason.clone(),
        });
    }

    fn record(&self, entry: Entry) {
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
            stdout: truncate(String::from_utf8_lossy(&output.stdout).into_owned()),
            stderr: truncate(String::from_utf8_lossy(&output.stderr).into_owned()),
        }),
        Err(error) => Response::Error {
            message: format!("could not run {command}: {error}"),
        },
    }
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

/// Listens for clients until cancelled.
#[cfg(windows)]
pub async fn serve(broker: Arc<Broker>, pipe_name: &str) -> std::io::Result<()> {
    use tokio::net::windows::named_pipe::ServerOptions;

    let mut server = ServerOptions::new()
        .first_pipe_instance(true)
        .create(pipe_name)?;

    loop {
        server.connect().await?;

        // Hand this connection off and immediately start listening again, so a
        // client sitting on an unanswered prompt cannot block every other one.
        let connected = server;
        server = ServerOptions::new().create(pipe_name)?;

        let broker = Arc::clone(&broker);
        tokio::spawn(async move {
            let client = connected.identify();
            let _ = serve_connection(broker, connected, client).await;
        });
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

        let encoded = protocol::encode(&response)
            .unwrap_or_else(|_| "{\"response\":\"error\",\"message\":\"encoding failed\"}\n".into());
        writer.write_all(encoded.as_bytes()).await?;
        writer.flush().await?;
    }

    Ok(())
}
