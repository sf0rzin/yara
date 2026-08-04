//! Deciding what wins when two machines changed the same thing.
//!
//! Last-write-wins per item, with the loser kept as a copy. Not a CRDT: the
//! write rate of a password manager does not justify one, and the failure mode
//! of getting a CRDT subtly wrong is silently merging two passwords into
//! neither.
//!
//! "Changed locally" means changed since the last successful sync. That is why
//! the timestamp of that sync is an argument here rather than something this
//! module goes looking for — the decision is a function of what both sides
//! know, and nothing else.

use uuid::Uuid;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LocalItem {
    pub id: Uuid,
    pub updated_at: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RemoteItem {
    pub id: Uuid,
    pub updated_at: u64,
    pub deleted: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Resolution {
    /// Nothing here yet, or the remote is simply newer. Take it.
    ApplyRemote,
    /// Only this machine changed it. Keep it and push.
    KeepLocal,
    /// Somebody deleted it and this machine has not touched it since.
    ApplyDelete,
    /// Both changed. The newer one wins and the other is kept beside it,
    /// because throwing away a password to resolve a tie is not a resolution.
    Conflict { remote_wins: bool },
}

/// Decides one item.
pub fn reconcile(local: Option<LocalItem>, remote: RemoteItem, last_sync_at: u64) -> Resolution {
    let Some(local) = local else {
        // A delete for something never seen is already satisfied.
        return if remote.deleted {
            Resolution::ApplyDelete
        } else {
            Resolution::ApplyRemote
        };
    };

    // Strictly greater: an edit in the same second as the sync is treated as
    // already synced. The alternative — treating equality as local change —
    // turns every quiet item into a conflict on a fast machine.
    let changed_locally = local.updated_at > last_sync_at;

    match (changed_locally, remote.deleted) {
        (false, true) => Resolution::ApplyDelete,
        (false, false) => Resolution::ApplyRemote,
        // A local edit outranks a remote delete. Restoring something someone
        // is still editing is recoverable; deleting it is not.
        (true, true) => Resolution::KeepLocal,
        (true, false) => Resolution::Conflict {
            remote_wins: remote.updated_at > local.updated_at,
        },
    }
}

/// Items this machine should push: everything it changed since the last sync.
pub fn to_push(local: &[LocalItem], last_sync_at: u64) -> Vec<Uuid> {
    local
        .iter()
        .filter(|item| item.updated_at > last_sync_at)
        .map(|item| item.id)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const SYNCED_AT: u64 = 1_000;

    fn id() -> Uuid {
        Uuid::new_v4()
    }

    fn local(updated_at: u64) -> LocalItem {
        LocalItem {
            id: Uuid::nil(),
            updated_at,
        }
    }

    fn remote(updated_at: u64, deleted: bool) -> RemoteItem {
        RemoteItem {
            id: Uuid::nil(),
            updated_at,
            deleted,
        }
    }

    #[test]
    fn something_new_from_elsewhere_is_taken() {
        assert_eq!(
            reconcile(None, remote(1_500, false), SYNCED_AT),
            Resolution::ApplyRemote
        );
    }

    #[test]
    fn a_delete_for_something_never_seen_is_already_satisfied() {
        assert_eq!(
            reconcile(None, remote(1_500, true), SYNCED_AT),
            Resolution::ApplyDelete
        );
    }

    #[test]
    fn an_untouched_local_item_takes_the_remote_version() {
        assert_eq!(
            reconcile(Some(local(500)), remote(1_500, false), SYNCED_AT),
            Resolution::ApplyRemote
        );
    }

    #[test]
    fn an_untouched_local_item_accepts_a_delete() {
        assert_eq!(
            reconcile(Some(local(500)), remote(1_500, true), SYNCED_AT),
            Resolution::ApplyDelete
        );
    }

    #[test]
    fn a_local_edit_survives_a_remote_delete() {
        // Restoring something someone is still editing is recoverable.
        // Deleting it is not, so the ambiguity resolves towards keeping it.
        assert_eq!(
            reconcile(Some(local(1_500)), remote(1_400, true), SYNCED_AT),
            Resolution::KeepLocal
        );
    }

    #[test]
    fn two_edits_resolve_to_the_newer_one() {
        assert_eq!(
            reconcile(Some(local(1_200)), remote(1_800, false), SYNCED_AT),
            Resolution::Conflict { remote_wins: true }
        );
        assert_eq!(
            reconcile(Some(local(1_800)), remote(1_200, false), SYNCED_AT),
            Resolution::Conflict { remote_wins: false }
        );
    }

    #[test]
    fn a_tie_keeps_the_local_copy() {
        // Arbitrary but deterministic, and it means a machine never watches
        // its own edit disappear.
        assert_eq!(
            reconcile(Some(local(1_500)), remote(1_500, false), SYNCED_AT),
            Resolution::Conflict { remote_wins: false }
        );
    }

    #[test]
    fn an_edit_in_the_same_second_as_the_sync_counts_as_synced() {
        // Otherwise every quiet item becomes a conflict on a fast machine.
        assert_eq!(
            reconcile(Some(local(SYNCED_AT)), remote(1_500, false), SYNCED_AT),
            Resolution::ApplyRemote
        );
    }

    #[test]
    fn only_locally_changed_items_are_pushed() {
        let stale = LocalItem {
            id: id(),
            updated_at: 500,
        };
        let fresh = LocalItem {
            id: id(),
            updated_at: 1_500,
        };

        assert_eq!(to_push(&[stale, fresh], SYNCED_AT), vec![fresh.id]);
    }

    #[test]
    fn a_first_sync_pushes_everything() {
        let items: Vec<LocalItem> = (1..=3)
            .map(|n| LocalItem {
                id: id(),
                updated_at: n,
            })
            .collect();

        assert_eq!(to_push(&items, 0).len(), 3);
    }
}
