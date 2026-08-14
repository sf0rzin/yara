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

/// One item as this machine has it — or the record that it deleted one.
///
/// A deletion is a local change like any other, and modelling it as the
/// absence of an item was the whole bug: sync pushes what it can see, an
/// absent item looks exactly like one this machine has not been told about
/// yet, and the next pull hands the deleted credential straight back.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LocalItem {
    pub id: Uuid,
    /// When it last changed. For a deletion, when it was deleted.
    pub updated_at: u64,
    pub deleted: bool,
}

impl LocalItem {
    pub fn present(id: Uuid, updated_at: u64) -> Self {
        Self {
            id,
            updated_at,
            deleted: false,
        }
    }

    /// A deletion this machine recorded, from the vault's own tombstone.
    pub fn deleted(id: Uuid, deleted_at: u64) -> Self {
        Self {
            id,
            updated_at: deleted_at,
            deleted: true,
        }
    }
}

/// One item as the server offered it.
///
/// `deleted` here means a deletion this machine has *already authenticated*.
/// The flag arrives from the server as ordinary JSON, and the server is
/// explicitly not trusted, so the caller proves it before it gets this far —
/// see [`crate::deletes`]. A tombstone nobody can prove never reaches these
/// rules at all.
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
///
/// One principle underneath all of it: what this machine did since the last
/// sync wins, and the remote is applied only where this machine has been
/// quiet. That is why a local edit survives a remote delete *and* a local
/// delete survives a remote edit, which look like opposite answers and are the
/// same rule read from either side.
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

    match (changed_locally, local.deleted, remote.deleted) {
        // Both sides agree it is gone. Nothing to apply, and the tombstone
        // this machine holds is already the right answer.
        (_, true, true) => Resolution::KeepLocal,
        // This machine deleted it since the last sync and the other one has
        // not heard yet. Taking the remote copy here would resurrect a
        // credential the user deleted, which is exactly what happened for as
        // long as a deletion had no record to be pushed from.
        (true, true, false) => Resolution::KeepLocal,
        // The deletion was already pushed, so a live record newer than it is
        // not an echo — somebody created this id again on another machine.
        (false, true, false) => Resolution::ApplyRemote,
        (false, false, true) => Resolution::ApplyDelete,
        (false, false, false) => Resolution::ApplyRemote,
        // A local edit outranks a remote delete. Restoring something someone
        // is still editing is recoverable; deleting it is not.
        (true, false, true) => Resolution::KeepLocal,
        (true, false, false) => Resolution::Conflict {
            remote_wins: remote.updated_at > local.updated_at,
        },
    }
}

/// What this machine should push: everything it changed since the last sync,
/// deletions included.
///
/// Returns the records rather than their ids, because the caller has to seal
/// an item and a deletion differently and "which of these is a tombstone" is
/// not something it should have to work out again.
pub fn to_push(local: &[LocalItem], last_sync_at: u64) -> Vec<LocalItem> {
    local
        .iter()
        .filter(|item| item.updated_at > last_sync_at)
        .copied()
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
        LocalItem::present(Uuid::nil(), updated_at)
    }

    fn buried(deleted_at: u64) -> LocalItem {
        LocalItem::deleted(Uuid::nil(), deleted_at)
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
    fn a_local_delete_is_not_resurrected_by_a_later_pull() {
        // The bug this whole record exists for. The item was deleted here
        // after the last sync; the server still has the live copy because it
        // has not been told yet. Applying it hands the credential back.
        assert_eq!(
            reconcile(Some(buried(1_500)), remote(1_400, false), SYNCED_AT),
            Resolution::KeepLocal
        );
        // And it holds even when the remote copy is the newer of the two: the
        // remote cannot be reacting to a deletion it has not received.
        assert_eq!(
            reconcile(Some(buried(1_500)), remote(1_900, false), SYNCED_AT),
            Resolution::KeepLocal
        );
    }

    #[test]
    fn an_id_created_again_elsewhere_after_the_delete_was_synced_comes_back() {
        // The deletion went out before the last sync, so a live record newer
        // than that is not an echo of it — somebody made this item again.
        assert_eq!(
            reconcile(Some(buried(500)), remote(1_500, false), SYNCED_AT),
            Resolution::ApplyRemote
        );
    }

    #[test]
    fn two_machines_deleting_the_same_item_agree_without_applying_anything() {
        assert_eq!(
            reconcile(Some(buried(1_500)), remote(1_500, true), SYNCED_AT),
            Resolution::KeepLocal
        );
        assert_eq!(
            reconcile(Some(buried(500)), remote(1_500, true), SYNCED_AT),
            Resolution::KeepLocal
        );
    }

    #[test]
    fn only_locally_changed_items_are_pushed() {
        let stale = LocalItem::present(id(), 500);
        let fresh = LocalItem::present(id(), 1_500);

        assert_eq!(to_push(&[stale, fresh], SYNCED_AT), vec![fresh]);
    }

    #[test]
    fn a_deletion_since_the_last_sync_is_pushed_like_any_other_change() {
        // Without this a delete never left the machine, and the server's
        // tombstone rows had nothing to hold.
        let stale = LocalItem::deleted(id(), 500);
        let fresh = LocalItem::deleted(id(), 1_500);

        assert_eq!(to_push(&[stale, fresh], SYNCED_AT), vec![fresh]);
    }

    #[test]
    fn a_first_sync_pushes_everything() {
        let items: Vec<LocalItem> = (1..=3).map(|n| LocalItem::present(id(), n)).collect();

        assert_eq!(to_push(&items, 0).len(), 3);
    }
}
