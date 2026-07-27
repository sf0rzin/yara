//! The wire format between an agent-side client and the broker.
//!
//! Newline-delimited JSON. Not the most compact choice, but a local IPC channel
//! carrying a handful of messages does not need compactness, and a protocol
//! people can read in a log is one they can audit.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Which part of an item is being asked for.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Field {
    Password,
    Username,
    /// A generated one-time code. Short-lived and single-use, so materially
    /// less sensitive than the seed behind it, which is never released.
    Totp,
}

impl Field {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Password => "password",
            Self::Username => "username",
            Self::Totp => "one-time code",
        }
    }

    /// Whether handing this out gives away something long-lived.
    pub fn is_durable_secret(&self) -> bool {
        matches!(self, Self::Password)
    }
}

/// What the client wants done with the credential.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case")]
pub enum Intent {
    /// Run a command with the credential in its environment.
    ///
    /// The broker spawns the process itself, so this is enforced rather than
    /// promised: the client receives the exit code and output, never the value.
    Run {
        command: String,
        #[serde(default)]
        args: Vec<String>,
        /// Environment variable to place the credential in.
        env_var: String,
        #[serde(default)]
        cwd: Option<String>,
    },
    /// Hand the plaintext to the client.
    ///
    /// The escape hatch, for when nothing else will do. Approved separately and
    /// recorded prominently.
    Reveal,
}

impl Intent {
    pub fn is_reveal(&self) -> bool {
        matches!(self, Self::Reveal)
    }
}

/// A request for access to one item.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccessRequest {
    /// Item name or id. Names are what an agent can discover, so both work.
    pub item: String,
    pub field: Field,
    #[serde(flatten)]
    pub intent: Intent,
    /// Why the client says it needs this. Shown to the user verbatim.
    pub reason: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "request", rename_all = "snake_case")]
pub enum Request {
    /// Whether the broker is up and the vault is unlocked.
    Status,
    /// Item names and usernames. Never secrets.
    ///
    /// Unprivileged on purpose: an agent has to be able to discover that
    /// `db-prod` exists in order to ask for it, and item names are not secrets.
    List {
        #[serde(default)]
        query: Option<String>,
    },
    Access(AccessRequest),
}

/// An item as an unapproved client may see it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ItemRef {
    pub id: Uuid,
    pub name: String,
    pub username: Option<String>,
    pub has_password: bool,
    pub has_totp: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommandOutput {
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
}

/// Why a request did not succeed.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Refusal {
    VaultLocked,
    ItemNotFound,
    /// The item exists but has nothing in the requested field.
    FieldEmpty,
    /// The user said no.
    Denied,
    /// The user did not answer in time.
    TimedOut,
    /// More than one item matched the name, so which one was meant is unclear.
    Ambiguous { matches: Vec<String> },
}

impl Refusal {
    /// A sentence to show the agent. Deliberately uninformative about vault
    /// contents when the vault is locked or the user declined.
    pub fn message(&self) -> String {
        match self {
            Self::VaultLocked => "The vault is locked.".into(),
            Self::ItemNotFound => "No such item.".into(),
            Self::FieldEmpty => "That item has nothing stored in that field.".into(),
            Self::Denied => "The request was declined.".into(),
            Self::TimedOut => "The request was not answered in time.".into(),
            Self::Ambiguous { matches } => {
                format!("That name matches {} items. Use the id.", matches.len())
            }
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "response", rename_all = "snake_case")]
pub enum Response {
    Status {
        unlocked: bool,
        version: String,
    },
    Items {
        items: Vec<ItemRef>,
    },
    /// A command ran. The credential stayed in the child's environment.
    Ran(CommandOutput),
    /// The plaintext, after an explicit reveal approval.
    Revealed {
        value: String,
    },
    Refused {
        reason: Refusal,
        message: String,
    },
    Error {
        message: String,
    },
}

impl Response {
    pub fn refused(reason: Refusal) -> Self {
        let message = reason.message();
        Self::Refused { reason, message }
    }
}

/// Encodes a message as one protocol line, newline included.
pub fn encode<T: Serialize>(message: &T) -> Result<String, serde_json::Error> {
    Ok(format!("{}\n", serde_json::to_string(message)?))
}

pub fn decode<T: for<'de> Deserialize<'de>>(line: &str) -> Result<T, serde_json::Error> {
    serde_json::from_str(line.trim())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn round_trip(request: &Request) -> Request {
        decode(&encode(request).unwrap()).unwrap()
    }

    #[test]
    fn a_run_request_survives_the_wire() {
        let request = Request::Access(AccessRequest {
            item: "db-prod".into(),
            field: Field::Password,
            intent: Intent::Run {
                command: "npm".into(),
                args: vec!["run".into(), "migrate".into()],
                env_var: "DATABASE_URL".into(),
                cwd: None,
            },
            reason: "run database migration".into(),
        });

        assert_eq!(round_trip(&request), request);
    }

    #[test]
    fn a_reveal_request_survives_the_wire() {
        let request = Request::Access(AccessRequest {
            item: "db-prod".into(),
            field: Field::Password,
            intent: Intent::Reveal,
            reason: "paste into a config file".into(),
        });

        assert_eq!(round_trip(&request), request);
    }

    #[test]
    fn list_and_status_survive_the_wire() {
        assert_eq!(round_trip(&Request::Status), Request::Status);
        let list = Request::List {
            query: Some("git".into()),
        };
        assert_eq!(round_trip(&list), list);
    }

    #[test]
    fn every_encoded_message_is_exactly_one_line() {
        let encoded = encode(&Request::Access(AccessRequest {
            item: "has\nnewline".into(),
            field: Field::Password,
            intent: Intent::Reveal,
            reason: "multi\nline\nreason".into(),
        }))
        .unwrap();

        // Embedded newlines must be escaped by the JSON encoder, or framing
        // breaks and a single request is read as several malformed ones.
        assert_eq!(encoded.matches('\n').count(), 1);
        assert!(encoded.ends_with('\n'));
    }

    #[test]
    fn responses_survive_the_wire() {
        let response = Response::Ran(CommandOutput {
            exit_code: 0,
            stdout: "done".into(),
            stderr: String::new(),
        });
        let encoded = encode(&response).unwrap();
        assert_eq!(decode::<Response>(&encoded).unwrap(), response);
    }

    #[test]
    fn a_refusal_carries_its_own_message() {
        let response = Response::refused(Refusal::VaultLocked);
        match response {
            Response::Refused { message, .. } => assert_eq!(message, "The vault is locked."),
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn only_the_password_counts_as_a_durable_secret() {
        assert!(Field::Password.is_durable_secret());
        // A one-time code expires in seconds and a username is not a secret.
        assert!(!Field::Totp.is_durable_secret());
        assert!(!Field::Username.is_durable_secret());
    }

    #[test]
    fn garbage_does_not_panic_the_decoder() {
        assert!(decode::<Request>("not json").is_err());
        assert!(decode::<Request>("{}").is_err());
        assert!(decode::<Request>(r#"{"request":"nonexistent"}"#).is_err());
    }
}
