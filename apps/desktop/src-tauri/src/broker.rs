//! Wires the broker to the vault and to the user.
//!
//! Two implementations live here. [`VaultView`] is how the broker reads the
//! vault, and [`UiApprover`] is how it asks the person sitting in front of the
//! app. Neither belongs in `yara-broker` itself, which stays free of both Tauri
//! and any knowledge of how the vault is stored.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use serde::Serialize;
use tauri::{AppHandle, Emitter, Manager};
use tokio::sync::oneshot;
use uuid::Uuid;
use yara_broker::audit::Entry;
use yara_broker::protocol::{Field, Intent, ItemRef};
use yara_broker::transport::{
    ApprovalRequest, Approver, Broker, Decision, Resolution, VaultBridge,
};
use yara_core::SecretString;

use crate::state::AppState;

/// Event name the frontend listens on for approval prompts.
pub const APPROVAL_EVENT: &str = "broker://approval";

/// The broker's read-only view of the vault.
pub struct VaultView(Arc<AppState>);

impl VaultView {
    pub fn new(state: Arc<AppState>) -> Self {
        Self(state)
    }
}

fn to_ref(item: &yara_core::Item) -> ItemRef {
    ItemRef {
        id: item.id,
        name: item.name.clone(),
        username: item.username.clone(),
        has_password: item.password.is_some(),
        has_totp: item.totp.is_some(),
        // Labels, never values.
        fields: item.fields.iter().map(|f| f.label.clone()).collect(),
    }
}

impl VaultBridge for VaultView {
    fn is_unlocked(&self) -> bool {
        self.0.is_unlocked()
    }

    fn list(&self, query: Option<&str>) -> Vec<ItemRef> {
        self.0
            .with_vault(|vault| {
                Ok(vault
                    .search(query.unwrap_or(""))
                    .into_iter()
                    .map(to_ref)
                    .collect())
            })
            .unwrap_or_default()
    }

    fn resolve(&self, needle: &str) -> Resolution {
        self.0
            .with_vault(|vault| {
                // An id is unambiguous, so try that first.
                if let Ok(id) = Uuid::parse_str(needle) {
                    return Ok(match vault.get(id) {
                        Some(item) => Resolution::Found(to_ref(item)),
                        None => Resolution::NotFound,
                    });
                }

                let matches: Vec<&yara_core::Item> = vault
                    .items()
                    .iter()
                    .filter(|item| item.name.eq_ignore_ascii_case(needle.trim()))
                    .collect();

                Ok(match matches.as_slice() {
                    [] => Resolution::NotFound,
                    [only] => Resolution::Found(to_ref(only)),
                    // Guessing between two items called "db" is exactly the
                    // kind of helpfulness that hands over the wrong password.
                    several => Resolution::Ambiguous(
                        several.iter().map(|item| item.id.to_string()).collect(),
                    ),
                })
            })
            .unwrap_or(Resolution::NotFound)
    }

    fn secret(&self, id: Uuid, field: &Field) -> Option<SecretString> {
        self.0
            .with_vault(|vault| {
                let Some(item) = vault.get(id) else {
                    return Ok(None);
                };

                Ok(match field {
                    Field::Password => item.password.clone(),
                    Field::Username => item.username.clone().map(SecretString::new),
                    // Generated fresh, and never the seed behind it.
                    Field::Totp => item
                        .totp
                        .as_ref()
                        .and_then(|totp| totp.generate().ok())
                        .map(SecretString::new),
                    // Matched on the exact label the grant names.
                    Field::Custom(label) => item
                        .fields
                        .iter()
                        .find(|f| &f.label == label)
                        .map(|f| f.value.clone()),
                })
            })
            .unwrap_or(None)
    }

    /// Appends to the vault and writes it out.
    ///
    /// A whole re-encryption per record, which sounds wasteful and is not: a
    /// record only exists because a human answered a prompt or an agent
    /// touched a credential, and neither happens at a rate a 64 MiB KDF would
    /// notice. Sealing reuses the vault key already in memory — the expensive
    /// derivation ran once, at unlock.
    ///
    /// A failure here is swallowed on purpose. Refusing the request because
    /// the log could not be written would turn a full disk into an outage of
    /// the thing the log exists to describe.
    fn record_audit(&self, entry: &Entry) {
        let Ok(payload) = serde_json::to_string(entry) else {
            return;
        };

        let _ = self.0.with_vault_mut(|vault| {
            vault.record_audit(payload);
            Ok(())
        });
        let _ = self.0.save();
    }

    fn load_audit(&self) -> Vec<Entry> {
        self.0
            .with_vault(|vault| {
                Ok(vault
                    .audit()
                    .iter()
                    // A record written by a newer build may not parse here.
                    // Skipping it beats refusing to show any history at all.
                    .filter_map(|payload| serde_json::from_str(payload).ok())
                    .collect())
            })
            .unwrap_or_default()
    }
}

/// What the approval dialog is told.
///
/// Contains no secret — the user is being asked whether to release one, and the
/// prompt does not need to show it to ask.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ApprovalPrompt {
    pub id: Uuid,
    /// File name of the requesting program, or a note that it is unidentified.
    pub program: String,
    /// Full image path, so a suspicious user can check where it came from.
    pub program_path: Option<String>,
    pub pid: u32,
    pub item: String,
    pub field: String,
    /// `run` or `reveal`.
    pub mode: String,
    /// The command line, when the request is to run something.
    pub command: Option<String>,
    pub env_var: Option<String>,
    pub reason: String,
    /// The command would hand the value back rather than use it — a shell, or
    /// an interpreter given a program to evaluate. The prompt says so plainly,
    /// because otherwise the user is answering "may it use this?" when the
    /// question is "may it see this?".
    pub discloses: bool,
}

impl ApprovalPrompt {
    fn new(id: Uuid, request: &ApprovalRequest) -> Self {
        let (mode, command, env_var) = match &request.intent {
            Intent::Run {
                command,
                args,
                env_var,
                ..
            } => (
                "run",
                Some(if args.is_empty() {
                    command.clone()
                } else {
                    format!("{} {}", command, args.join(" "))
                }),
                Some(env_var.clone()),
            ),
            Intent::Reveal => ("reveal", None, None),
        };

        Self {
            id,
            program: request.client.display_name(),
            program_path: request.client.executable.clone(),
            pid: request.client.pid,
            item: request.item.name.clone(),
            field: request.field.label().into_owned(),
            mode: mode.to_string(),
            command,
            env_var,
            reason: request.reason.clone(),
            discloses: request.discloses,
        }
    }
}

/// Asks the user by raising a dialog in the app window.
pub struct UiApprover {
    app: AppHandle,
    pending: Mutex<HashMap<Uuid, oneshot::Sender<Decision>>>,
}

impl UiApprover {
    pub fn new(app: AppHandle) -> Arc<Self> {
        Arc::new(Self {
            app,
            pending: Mutex::new(HashMap::new()),
        })
    }

    /// Delivers the user's answer. Returns false if the request already went
    /// away, which happens when the broker's timeout fired first.
    pub fn resolve(&self, id: Uuid, decision: Decision) -> bool {
        let sender = self.pending.lock().ok().and_then(|mut map| map.remove(&id));
        match sender {
            Some(sender) => sender.send(decision).is_ok(),
            None => false,
        }
    }

    /// Abandons every outstanding prompt. Called when the vault locks.
    ///
    /// Dropping the senders makes each waiting request fail closed rather than
    /// sit there until it times out.
    pub fn abandon_all(&self) {
        if let Ok(mut map) = self.pending.lock() {
            map.clear();
        }
    }
}

impl Approver for UiApprover {
    fn ask(&self, request: ApprovalRequest) -> oneshot::Receiver<Decision> {
        let (sender, receiver) = oneshot::channel();
        let id = Uuid::new_v4();

        if let Ok(mut map) = self.pending.lock() {
            map.insert(id, sender);
        }

        let _ = self
            .app
            .emit(APPROVAL_EVENT, ApprovalPrompt::new(id, &request));

        // A prompt behind another window is a prompt nobody answers, and the
        // agent is blocked until they do.
        if let Some(window) = self.app.get_webview_window("main") {
            let _ = window.unminimize();
            let _ = window.set_focus();
        }

        receiver
    }
}

/// Everything the app needs to hold on to.
pub struct BrokerHandle {
    pub broker: Arc<Broker>,
    pub approver: Arc<UiApprover>,
}

impl BrokerHandle {
    /// Called when the vault locks: outstanding prompts are abandoned and every
    /// grant is destroyed.
    pub fn on_lock(&self) {
        self.approver.abandon_all();
        self.broker.forget_grants();
    }
}

/// Builds the broker and starts listening.
///
/// A failure to bind is reported rather than fatal: the vault is perfectly
/// usable without agent access, and the usual cause is a second copy of yara
/// already running.
pub fn start(app: &AppHandle, state: Arc<AppState>) -> BrokerHandle {
    let approver = UiApprover::new(app.clone());
    let broker = Broker::new(Arc::new(VaultView::new(state)), approver.clone());

    #[cfg(windows)]
    {
        let serving = Arc::clone(&broker);
        tauri::async_runtime::spawn(async move {
            let pipe = yara_broker::transport::DEFAULT_PIPE_NAME;
            if let Err(error) = yara_broker::transport::serve(serving, pipe).await {
                eprintln!("yara: agent access is unavailable ({error})");
            }
        });
    }

    BrokerHandle { broker, approver }
}

/// Turns the frontend's answer into a decision.
///
/// `minutes` is only honoured for a plain allow; there is no way to ask for a
/// standing grant to reveal plaintext from here.
pub fn decision_from(choice: &str, minutes: Option<u64>) -> Option<Decision> {
    match choice {
        "deny" => Some(Decision::Deny),
        "once" => Some(Decision::AllowOnce),
        "window" => Some(Decision::AllowFor {
            seconds: minutes.unwrap_or(15).clamp(1, 60) * 60,
            uses: 25,
        }),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_unknown_choice_is_not_treated_as_approval() {
        assert!(decision_from("", None).is_none());
        assert!(decision_from("yes", None).is_none());
        assert!(decision_from("ALLOW", None).is_none());
    }

    #[test]
    fn a_window_grant_is_capped_to_an_hour() {
        match decision_from("window", Some(9999)) {
            Some(Decision::AllowFor { seconds, .. }) => assert_eq!(seconds, 3600),
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn a_window_grant_cannot_be_zero_length() {
        match decision_from("window", Some(0)) {
            Some(Decision::AllowFor { seconds, .. }) => assert_eq!(seconds, 60),
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn the_choices_map_to_the_expected_decisions() {
        assert_eq!(decision_from("deny", None), Some(Decision::Deny));
        assert_eq!(decision_from("once", None), Some(Decision::AllowOnce));
    }
}
