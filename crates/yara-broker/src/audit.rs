//! A record of every request the broker handled.
//!
//! Approval is only half of accountability. If a user has to reconstruct what
//! an agent did from memory, the approval prompt was theatre. Every decision
//! lands here, including the refusals, because "something asked for the
//! production password and I said no" is exactly the event worth noticing.
//!
//! Stored inside the encrypted vault, through [`crate::transport::VaultBridge`].
//! A log naming every credential an agent touched is itself sensitive, and
//! writing it beside the vault in the clear would describe the shape of a
//! vault nobody could otherwise read.
//!
//! The copy held here is a read cache for the interface, filled at unlock and
//! dropped at lock. The vault is the record.

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
    Approved {
        /// The grant the approval minted, when it minted one.
        ///
        /// Without it a chain of `Reused` entries traced back to "some
        /// approval, earlier": the uuid they name appeared in no other record,
        /// so once the grant expired the terms the user consented to were
        /// unrecoverable.
        ///
        /// Optional and defaulted rather than required, because
        /// `VaultBridge::load_audit` silently drops records it cannot parse —
        /// a required field here would erase every entry written before it.
        #[serde(default)]
        grant: Option<Uuid>,
    },
    /// Allowed by a grant issued earlier.
    Reused {
        grant: Uuid,
    },
    Refused {
        reason: Refusal,
    },
    /// Allowed, and then the action did not happen: the process could not be
    /// started. Recorded because the log used to say the command ran, which
    /// told the user their production password had gone to a process that
    /// never existed.
    Failed {
        error: String,
    },
}

impl Outcome {
    /// A fresh approval that issued no grant, or whose grant is not worth
    /// naming.
    pub fn approved() -> Self {
        Self::Approved { grant: None }
    }

    pub fn was_allowed(&self) -> bool {
        matches!(self, Self::Approved { .. } | Self::Reused { .. })
    }

    /// The grant this entry was authorised by, whichever way it was
    /// authorised. What makes a chain of reuses traceable to the prompt that
    /// started it.
    pub fn grant(&self) -> Option<Uuid> {
        match self {
            Self::Approved { grant } => *grant,
            Self::Reused { grant } => Some(*grant),
            Self::Refused { .. } | Self::Failed { .. } => None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Entry {
    pub id: Uuid,
    pub at: u64,
    pub client: ClientId,
    /// The item that was accessed, or empty when the request was not about one.
    ///
    /// A listing names a search term, not an item, and putting the term here
    /// rendered a history row saying an item called "git" had been accessed
    /// when no such item exists. Use [`Entry::listing`] for those.
    pub item: String,
    /// The field that was asked for, or `None` when the request named none.
    ///
    /// A listing asks for no field at all; recording it as `Username` said the
    /// agent had been through the usernames, which it had not. Defaulted so
    /// records written before this was optional still parse.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub field: Option<Field>,
    pub action: Action,
    pub outcome: Outcome,
    /// The justification the client supplied, kept verbatim. Empty when the
    /// request needed none, which is every request that is not an access.
    pub reason: String,
    /// What the client searched for, when it searched. `None` for everything
    /// else, and defaulted so records written before this field parse.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub query: Option<String>,
}

impl Entry {
    /// A record of a listing, which touches no item and needs no reason.
    ///
    /// Deliberately a constructor rather than an [`Entry`] literal: the fields
    /// this leaves empty were being filled with text the broker invented —
    /// `Field::Username` and "listing item names" — and read back as though a
    /// client had supplied them.
    pub fn listing(client: ClientId, at: u64, query: Option<String>, matches: usize) -> Self {
        Self {
            id: Uuid::new_v4(),
            at,
            client,
            item: String::new(),
            field: None,
            action: Action::Listed { matches },
            outcome: Outcome::approved(),
            reason: String::new(),
            query,
        }
    }
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
            field: Some(Field::Password),
            action,
            outcome,
            reason: "because".into(),
            query: None,
        }
    }

    #[test]
    fn entries_come_back_most_recent_first() {
        let mut log = AuditLog::new();
        for at in 0..3 {
            log.record(entry(at, Outcome::approved(), Action::Revealed));
        }

        let recent = log.recent(3);
        assert_eq!(recent[0].at, 2);
        assert_eq!(recent[2].at, 0);
    }

    #[test]
    fn the_log_stays_bounded_and_drops_the_oldest() {
        let mut log = AuditLog::new();
        for at in 0..(CAPACITY as u64 + 50) {
            log.record(entry(at, Outcome::approved(), Action::Revealed));
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
            Outcome::approved(),
            Action::Ran {
                command: "npm run migrate".into(),
                env_var: "DATABASE_URL".into(),
            },
        ));
        log.record(entry(2, Outcome::approved(), Action::Revealed));
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
        assert_ne!(reused, Outcome::approved());
    }

    /// A spawn that never happened is not an access that did.
    #[test]
    fn a_failed_action_is_not_an_allowed_one() {
        let failed = Outcome::Failed {
            error: "could not run npm: not found".into(),
        };
        assert!(!failed.was_allowed());
        assert!(failed.grant().is_none());
    }

    /// The record a chain of reuses has to be traceable to.
    #[test]
    fn an_approval_can_name_the_grant_it_minted() {
        let id = Uuid::new_v4();
        let approved = Outcome::Approved { grant: Some(id) };

        assert_eq!(approved.grant(), Some(id));
        assert_eq!(Outcome::Reused { grant: id }.grant(), Some(id));
        assert!(approved.was_allowed());
    }

    /// History written before the grant id existed has to keep parsing.
    ///
    /// `VaultBridge::load_audit` drops records it cannot read, so a required
    /// field would have quietly emptied the Agent access screen of everything
    /// recorded by an earlier build.
    #[test]
    fn an_approval_without_a_grant_id_still_parses() {
        let old = r#"{"outcome":"approved"}"#;
        let parsed: Outcome = serde_json::from_str(old).unwrap();

        assert_eq!(parsed, Outcome::Approved { grant: None });
    }

    /// The same argument for the entry itself: the fields added since have to
    /// be optional or the whole record goes.
    #[test]
    fn an_entry_written_before_the_query_and_optional_field_still_parses() {
        let old = r#"{
            "id": "00000000-0000-0000-0000-000000000001",
            "at": 1,
            "client": { "pid": 7, "executable": null },
            "item": "db-prod",
            "field": "password",
            "action": { "action": "revealed" },
            "outcome": { "outcome": "approved" },
            "reason": "because"
        }"#;

        let parsed: Entry = serde_json::from_str(old).unwrap();
        assert_eq!(parsed.field, Some(Field::Password));
        assert_eq!(parsed.query, None);
        assert_eq!(parsed.outcome, Outcome::Approved { grant: None });
    }

    /// A listing is about a search term, not an item.
    #[test]
    fn a_listing_names_no_item_no_field_and_no_reason() {
        let entry = Entry::listing(ClientId::unknown(3), 1, Some("git".into()), 2);

        assert!(
            entry.item.is_empty(),
            "putting the query here read as though an item called git had been \
             accessed, and no such item exists"
        );
        assert!(entry.field.is_none());
        assert!(entry.reason.is_empty(), "the client supplied none");
        assert_eq!(entry.query.as_deref(), Some("git"));
        assert_eq!(entry.action, Action::Listed { matches: 2 });
    }
}
