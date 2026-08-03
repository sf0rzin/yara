//! A record of every request the broker handled.
//!
//! Approval is only half of accountability. If a user has to reconstruct what
//! an agent did from memory, the approval prompt was theatre. Every decision
//! lands here, including the refusals, because "something asked for the
//! production password and I said no" is exactly the event worth noticing.
//!
//! Held in memory for now. Persisting it belongs inside the encrypted vault —
//! an audit log naming every credential an agent touched is itself sensitive,
//! and writing it beside the vault in the clear would leak the shape of a
//! vault nobody could otherwise read.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::grant::ClientId;
use crate::protocol::{Field, Intent, Refusal};

/// How many entries are kept before the oldest are dropped.
const CAPACITY: usize = 500;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum Action {
    Listed { matches: usize },
    Ran { command: String, env_var: String },
    Revealed,
}

impl Action {
    pub fn from_intent(intent: &Intent) -> Self {
        match intent {
            Intent::Run {
                command,
                args,
                env_var,
                ..
            } => Action::Ran {
                command: if args.is_empty() {
                    command.clone()
                } else {
                    format!("{} {}", command, args.join(" "))
                },
                env_var: env_var.clone(),
            },
            Intent::Reveal => Action::Revealed,
        }
    }

    /// Whether this entry deserves to stand out in the interface.
    ///
    /// Revealing plaintext is the one action with no technical limit on what
    /// happens next, so it is the one the user should be able to spot.
    pub fn is_notable(&self) -> bool {
        matches!(self, Action::Revealed)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum Outcome {
    /// Allowed after the user approved it just now.
    Approved,
    /// Allowed by a grant issued earlier.
    Reused {
        grant: Uuid,
    },
    Refused {
        reason: Refusal,
    },
}

impl Outcome {
    pub fn was_allowed(&self) -> bool {
        matches!(self, Self::Approved | Self::Reused { .. })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Entry {
    pub id: Uuid,
    pub at: u64,
    pub client: ClientId,
    pub item: String,
    pub field: Field,
    pub action: Action,
    pub outcome: Outcome,
    /// The justification the client supplied, kept verbatim.
    pub reason: String,
}

/// A bounded, append-only log.
#[derive(Debug, Default)]
pub struct AuditLog {
    entries: Vec<Entry>,
}

impl AuditLog {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn record(&mut self, entry: Entry) {
        self.entries.push(entry);

        // Drop from the front so the log stays bounded without ever rewriting
        // an entry that was already written.
        if self.entries.len() > CAPACITY {
            let excess = self.entries.len() - CAPACITY;
            self.entries.drain(..excess);
        }
    }

    /// Most recent first.
    pub fn recent(&self, limit: usize) -> Vec<&Entry> {
        self.entries.iter().rev().take(limit).collect()
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Entries the user might want to look at twice.
    pub fn notable(&self) -> Vec<&Entry> {
        self.entries
            .iter()
            .rev()
            .filter(|entry| entry.action.is_notable() || !entry.outcome.was_allowed())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(at: u64, outcome: Outcome, action: Action) -> Entry {
        Entry {
            id: Uuid::new_v4(),
            at,
            client: ClientId::unknown(1),
            item: "db-prod".into(),
            field: Field::Password,
            action,
            outcome,
            reason: "because".into(),
        }
    }

    #[test]
    fn entries_come_back_most_recent_first() {
        let mut log = AuditLog::new();
        for at in 0..3 {
            log.record(entry(at, Outcome::Approved, Action::Revealed));
        }

        let recent = log.recent(3);
        assert_eq!(recent[0].at, 2);
        assert_eq!(recent[2].at, 0);
    }

    #[test]
    fn the_log_stays_bounded_and_drops_the_oldest() {
        let mut log = AuditLog::new();
        for at in 0..(CAPACITY as u64 + 50) {
            log.record(entry(at, Outcome::Approved, Action::Revealed));
        }

        assert_eq!(log.len(), CAPACITY);
        // The 50 oldest are gone, so the earliest surviving entry is at = 50.
        assert_eq!(log.recent(CAPACITY).last().unwrap().at, 50);
    }

    #[test]
    fn refusals_are_recorded_too() {
        let mut log = AuditLog::new();
        log.record(entry(
            1,
            Outcome::Refused {
                reason: Refusal::Denied,
            },
            Action::Revealed,
        ));

        assert_eq!(log.len(), 1);
        assert!(!log.recent(1)[0].outcome.was_allowed());
    }

    #[test]
    fn notable_entries_are_reveals_and_anything_refused() {
        let mut log = AuditLog::new();
        log.record(entry(
            1,
            Outcome::Approved,
            Action::Ran {
                command: "npm run migrate".into(),
                env_var: "DATABASE_URL".into(),
            },
        ));
        log.record(entry(2, Outcome::Approved, Action::Revealed));
        log.record(entry(
            3,
            Outcome::Refused {
                reason: Refusal::Denied,
            },
            Action::Ran {
                command: "rm -rf /".into(),
                env_var: "X".into(),
            },
        ));

        let notable = log.notable();
        assert_eq!(notable.len(), 2);
        // A plain approved run is routine and stays out of the way.
        assert!(notable.iter().all(|entry| entry.at != 1));
    }

    #[test]
    fn an_action_records_the_full_command_line() {
        let action = Action::from_intent(&Intent::Run {
            command: "npm".into(),
            args: vec!["run".into(), "migrate".into()],
            env_var: "DATABASE_URL".into(),
            cwd: None,
        });

        match action {
            Action::Ran { command, env_var } => {
                assert_eq!(command, "npm run migrate");
                assert_eq!(env_var, "DATABASE_URL");
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn a_command_with_no_arguments_is_not_left_with_a_trailing_space() {
        let action = Action::from_intent(&Intent::Run {
            command: "make".into(),
            args: vec![],
            env_var: "X".into(),
            cwd: None,
        });

        match action {
            Action::Ran { command, .. } => assert_eq!(command, "make"),
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn reused_grants_are_distinguishable_from_fresh_approvals() {
        let reused = Outcome::Reused {
            grant: Uuid::new_v4(),
        };
        assert!(reused.was_allowed());
        assert_ne!(reused, Outcome::Approved);
    }
}
