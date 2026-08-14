//! Proving that a deletion came from a device holding the vault key.
//!
//! A tombstone on the wire is an id and a boolean, both of them ordinary JSON
//! from a server the design treats as hostile. Item bodies are sealed, so a
//! compromised host cannot read or forge one — but it could answer a single
//! pull with a deleted record for every id it stores, and every enrolled
//! machine would obediently erase every credential on it. There is no trash to
//! recover them from.
//!
//! So a deletion has to be provable. `yara-core` seals a tiny AEAD over the
//! tombstone under the vault key — which never leaves the client — bound to
//! the item id and tagged so it cannot be confused with a sealed item. This
//! module is the wire form of that: how a proof is written into a push, and
//! how one is checked before a delete is obeyed.
//!
//! An unproven tombstone is ignored rather than obeyed. That is the direction
//! the failure has to fall: ignoring a real delete leaves an item on one
//! machine that the user removed on another, which is visible and fixable;
//! obeying a forged one destroys credentials everywhere at once.

use uuid::Uuid;
use yara_core::{Sealed, Tombstone, UnlockedVault};

use crate::client::SyncItem;

/// Writes the proof for `tombstone` in the form a [`SyncItem`] carries.
///
/// JSON rather than raw bytes, matching how a sealed item travels, so the two
/// are stored and logged the same way by everything between here and the
/// database.
pub fn seal_proof(vault: &UnlockedVault, tombstone: &Tombstone) -> Result<String, crate::Error> {
    let sealed = vault.seal_deletion(tombstone)?;
    serde_json::to_string(&sealed)
        .map_err(|_| crate::Error::Refused("could not encode a deletion proof".into()))
}

/// The deletion a record proves, or `None` if it proves nothing.
///
/// `None` covers every way this can fail — no proof attached, unparseable,
/// sealed under another key, sealed for another item, or the record simply not
/// claiming a deletion at all — because the caller does the same thing with
/// all of them: nothing.
pub fn proven_deletion(vault: &UnlockedVault, id: Uuid, record: &SyncItem) -> Option<Tombstone> {
    if !record.deleted {
        return None;
    }

    let sealed: Sealed = serde_json::from_str(record.proof.as_deref()?).ok()?;
    // The id is the associated data, so a proof lifted from one item's
    // deletion and filed under another fails here rather than being noticed
    // afterwards by code that might forget to look.
    vault.open_deletion(id, &sealed).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    use yara_core::{Item, KdfParams};

    /// The cheapest parameters a vault will open with. These tests are about
    /// the proof, not the KDF.
    fn fast() -> KdfParams {
        KdfParams {
            memory_kib: yara_core::crypto::MIN_MEMORY_KIB,
            iterations: 1,
            parallelism: 1,
        }
    }

    fn vault() -> UnlockedVault {
        UnlockedVault::create_with_params("master", fast()).unwrap()
    }

    /// A vault that deleted one item, and the tombstone it kept.
    fn vault_with_a_deletion() -> (UnlockedVault, Tombstone) {
        let mut vault = vault();
        let id = vault.add(Item::new("GitHub").with_password("hunter2"));
        vault.remove(id).unwrap();
        let tombstone = vault.tombstone(id).expect("the deletion was recorded");
        (vault, tombstone)
    }

    fn record(id: Uuid, proof: Option<String>) -> SyncItem {
        SyncItem {
            id: id.to_string(),
            revision: 0,
            ciphertext: None,
            deleted: true,
            proof,
        }
    }

    #[test]
    fn a_deletion_this_vault_sealed_is_proven() {
        let (vault, tombstone) = vault_with_a_deletion();
        let proof = seal_proof(&vault, &tombstone).unwrap();

        assert_eq!(
            proven_deletion(&vault, tombstone.id, &record(tombstone.id, Some(proof))),
            Some(tombstone)
        );
    }

    #[test]
    fn a_tombstone_with_no_proof_proves_nothing() {
        // A hostile server answering one pull with a deleted record per item
        // is the whole reason this function exists.
        let (vault, tombstone) = vault_with_a_deletion();
        assert_eq!(
            proven_deletion(&vault, tombstone.id, &record(tombstone.id, None)),
            None
        );
    }

    #[test]
    fn a_proof_that_is_not_a_proof_is_refused_rather_than_fatal() {
        let (vault, tombstone) = vault_with_a_deletion();

        for nonsense in ["", "null", "{}", "not json at all"] {
            assert_eq!(
                proven_deletion(
                    &vault,
                    tombstone.id,
                    &record(tombstone.id, Some(nonsense.into()))
                ),
                None,
                "{nonsense:?} was accepted"
            );
        }
    }

    #[test]
    fn a_proof_from_another_account_is_refused() {
        // The server holds proofs from every account it serves. Handing one to
        // the wrong vault must not delete anything.
        let (mine, tombstone) = vault_with_a_deletion();
        let (theirs, _) = vault_with_a_deletion();
        let proof = seal_proof(&theirs, &tombstone).unwrap();

        assert_eq!(
            proven_deletion(&mine, tombstone.id, &record(tombstone.id, Some(proof))),
            None
        );
    }

    #[test]
    fn a_proof_cannot_be_replayed_against_a_different_item() {
        // The one attack a compromised server is best placed to try: take a
        // deletion the user really did make and file it under the id of
        // something they still want.
        let (vault, tombstone) = vault_with_a_deletion();
        let proof = seal_proof(&vault, &tombstone).unwrap();

        let other = Uuid::new_v4();
        assert_eq!(
            proven_deletion(&vault, other, &record(other, Some(proof))),
            None
        );
    }

    #[test]
    fn a_record_that_does_not_claim_a_deletion_is_not_one() {
        let (vault, tombstone) = vault_with_a_deletion();
        let proof = seal_proof(&vault, &tombstone).unwrap();

        let live = SyncItem {
            deleted: false,
            ..record(tombstone.id, Some(proof))
        };
        assert_eq!(proven_deletion(&vault, tombstone.id, &live), None);
    }
}
