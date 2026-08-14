//! Sync, from the app's side.
//!
//! Three things happen here and nothing else: enrolling a first machine,
//! joining a later one, and reconciling. The decisions live elsewhere on
//! purpose — `yara-core` owns the keys, `yara-sync-client` owns the wire and
//! the merge rules — so this module is the wiring and can be read as such.
//!
//! What the server gets, at every step, is ciphertext and a public key.

use std::sync::Arc;

use base64::Engine as _;
use serde::Serialize;
use uuid::Uuid;
use yara_core::{AccountKeypair, AccountKeys, Item, KdfParams, SecretKey, SyncState};
use yara_sync_client::{deletes, merge, Client, Enrolment, SyncItem};

use crate::state::AppState;

fn b64(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// What the interface shows about sync.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SyncStatus {
    pub enrolled: bool,
    pub base_url: Option<String>,
    pub account_id: Option<String>,
    pub device_id: Option<String>,
    pub last_synced_at: Option<u64>,
}

/// Shown once, at enrolment, and never again.
///
/// The kit is not stored: it is derivable from nothing this machine keeps, and
/// storing it would undo the reason for having a second factor at all. If the
/// user closes this window without writing it down, the answer is a new
/// account, and the interface has to say so before it shows this.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RecoveryKit {
    pub account_id: String,
    pub kit: String,
}

/// The result of one reconciliation, for the interface to report.
#[derive(Debug, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SyncReport {
    pub pulled: usize,
    pub pushed: usize,
    pub conflicts: usize,
    /// Deletions the server offered without a proof that this account made
    /// them. Ignored, and counted so the interface can say so — a run of these
    /// is what a compromised server trying to wipe the account looks like.
    pub unproven_deletes: usize,
    pub revision: i64,
}

/// Enrols this machine as a brand new account.
pub async fn enrol(
    state: Arc<AppState>,
    base_url: String,
    invite: String,
    password: String,
    label: Option<String>,
) -> Result<RecoveryKit, String> {
    if state.with_vault(|vault| Ok(vault.sync_state().is_some()))? {
        return Err("this vault is already syncing".into());
    }

    let secret = SecretKey::generate();
    let salt = yara_core::crypto::random_bytes(32);
    let params = KdfParams::default();

    let keys = AccountKeys::derive(&password, &secret, &salt, params).map_err(|e| e.to_string())?;

    // The two things the server stores and cannot read.
    let account_key = AccountKeypair::generate();
    let device_key = AccountKeypair::generate();

    let wrapped_account = keys.wrap(&account_key.seed()).map_err(|e| e.to_string())?;
    let wrapped_vault = state.with_vault(|vault| {
        // The vault key itself, so a second machine can open what this one
        // wrote. Wrapped under enc_key, which came from the password and the
        // kit — neither of which the server has.
        keys.wrap(vault.vault_key_bytes())
            .map_err(|e| e.to_string())
    })?;

    let account_id = Uuid::new_v4().to_string();
    let device_id = Uuid::new_v4().to_string();

    Client::enrol(
        &base_url,
        Enrolment {
            account_id: &account_id,
            salt: &b64(&salt),
            kdf: &serde_json::to_string(&params).map_err(|e| e.to_string())?,
            wrapped_vault_key: &sealed_to_string(&wrapped_vault)?,
            wrapped_account_key: &sealed_to_string(&wrapped_account)?,
            account_public_key: account_key.public().as_bytes(),
            device_id: &device_id,
            public_key: device_key.public().as_bytes(),
            label: label.as_deref(),
            invite: &invite,
        },
    )
    .await
    .map_err(|e| e.to_string())?;

    state.with_vault_mut(|vault| {
        vault.set_sync_state(Some(SyncState {
            base_url: base_url.trim_end_matches('/').to_string(),
            account_id: account_id.clone(),
            device_id,
            device_seed: b64(&device_key.seed()),
            last_revision: 0,
            last_synced_at: 0,
        }));
        Ok(())
    })?;
    state.save()?;

    Ok(RecoveryKit {
        account_id,
        kit: secret.to_kit(),
    })
}

/// Joins an account this machine has never seen, using the recovery kit.
///
/// The other half of enrolment, and the half that did not exist. Enrolment
/// generated a kit, wrapped both keys under it, uploaded them and told the user
/// to write the kit down — and nothing in the codebase could consume one, so a
/// second machine could not join and a printed kit was decoration.
///
/// The order matters. The account blobs are public by design, so anyone can
/// fetch them; they are useless without the password and the kit, and this is
/// the only place the two come back together. Only after unwrapping does this
/// machine hold the account key, and only that key can register a device — a
/// device key cannot, or revoking a stolen laptop would be theatre.
///
/// Everything the server returns is treated as hostile. The KDF parameters in
/// particular arrive from it, which is why `AccountKeys::derive` bounds them:
/// unchecked, a hostile `memory_kib` is an allocation that aborts the process.
pub async fn join(
    state: Arc<AppState>,
    base_url: String,
    account_id: String,
    password: String,
    kit: String,
    label: Option<String>,
) -> Result<SyncReport, String> {
    if state.with_vault(|vault| Ok(vault.sync_state().is_some()))? {
        return Err("this vault is already syncing".into());
    }

    let base_url = base_url.trim_end_matches('/').to_string();
    let account_id = account_id.trim().to_string();

    // Every failure from here to the unwrap reads the same to the caller.
    // A wrong kit, a wrong password and a tampered blob are the same event as
    // far as anyone outside is concerned; telling them apart would turn this
    // into an oracle for which half somebody got right.
    let opaque = || "that account, password and recovery kit do not go together".to_string();

    let secret = SecretKey::from_kit(&kit).map_err(|_| opaque())?;
    let account = Client::account(&base_url, &account_id)
        .await
        .map_err(|e| e.to_string())?;

    let salt = base64::engine::general_purpose::STANDARD
        .decode(&account.salt)
        .map_err(|_| opaque())?;
    let params: KdfParams = serde_json::from_str(&account.kdf).map_err(|_| opaque())?;

    let keys = AccountKeys::derive(&password, &secret, &salt, params).map_err(|_| opaque())?;

    let wrapped_account: yara_core::Sealed =
        serde_json::from_str(&account.wrapped_account_key).map_err(|_| opaque())?;
    let account_key =
        AccountKeypair::from_seed(&keys.unwrap(&wrapped_account).map_err(|_| opaque())?)
            .map_err(|_| opaque())?;

    // The vault key, so this machine can read what the others wrote. Unwrapping
    // it here also proves the kit and the password are right before anything is
    // registered anywhere.
    let wrapped_vault: yara_core::Sealed =
        serde_json::from_str(&account.wrapped_vault_key).map_err(|_| opaque())?;
    let vault_key = keys.unwrap(&wrapped_vault).map_err(|_| opaque())?;

    let device_key = AccountKeypair::generate();
    let device_id = Uuid::new_v4().to_string();

    Client::register_as_account(
        &base_url,
        &account_id,
        &device_id,
        device_key.public().as_bytes(),
        label.as_deref(),
        |message| account_key.sign(message),
    )
    .await
    .map_err(|e| e.to_string())?;

    state.with_vault_mut(|vault| {
        vault
            .adopt_vault_key(&password, &vault_key)
            .map_err(|_| opaque())?;
        vault.set_sync_state(Some(SyncState {
            base_url: base_url.clone(),
            account_id: account_id.clone(),
            device_id,
            device_seed: b64(&device_key.seed()),
            // Nothing has been seen yet, so the first sync pulls everything.
            last_revision: 0,
            last_synced_at: 0,
        }));
        Ok(())
    })?;
    state.save()?;

    sync_now(state).await
}

/// Reconciles once: pull, apply, push.
pub async fn sync_now(state: Arc<AppState>) -> Result<SyncReport, String> {
    let Some(sync) = state.with_vault(|vault| Ok(vault.sync_state().cloned()))? else {
        return Err("this vault is not syncing".into());
    };

    let seed = base64::engine::general_purpose::STANDARD
        .decode(&sync.device_seed)
        .map_err(|_| "the stored device key is unreadable".to_string())?;
    let device_key = AccountKeypair::from_seed(&seed).map_err(|e| e.to_string())?;

    let client = Client::new(
        &sync.base_url,
        &sync.account_id,
        &sync.device_id,
        device_key,
    )
    .map_err(|e| e.to_string())?;

    let page = client
        .pull(sync.last_revision)
        .await
        .map_err(|e| e.to_string())?;

    let mut report = SyncReport {
        revision: page.revision,
        ..Default::default()
    };

    // Everything that arrived, decided one at a time against what is here.
    for record in &page.items {
        let Ok(id) = Uuid::parse_str(&record.id) else {
            continue;
        };

        // A deletion is obeyed only when this account can prove it made it.
        // The flag is ordinary JSON from a server the design treats as
        // hostile, and one pull answered with a deleted record per item would
        // otherwise erase every credential on every enrolled machine.
        let proof = state.with_vault(|vault| Ok(deletes::proven_deletion(vault, id, record)))?;
        if record.deleted && proof.is_none() {
            report.unproven_deletes += 1;
            continue;
        }

        let local = state.with_vault(|vault| {
            Ok(vault
                .get(id)
                .map(|item| merge::LocalItem::present(id, item.updated_at))
                // No item, but a record that this machine deleted one. Passing
                // `None` here is what let a pull hand a deleted credential
                // straight back.
                .or_else(|| {
                    vault
                        .tombstone(id)
                        .map(|grave| merge::LocalItem::deleted(id, grave.deleted_at))
                }))
        })?;

        let remote_item = decode_item(&state, id, record)?;
        let remote = merge::RemoteItem {
            id,
            updated_at: proof
                .map(|grave| grave.deleted_at)
                .or_else(|| remote_item.as_ref().map(|i| i.updated_at))
                .unwrap_or(0),
            deleted: proof.is_some(),
        };

        match merge::reconcile(local, remote, sync.last_synced_at) {
            merge::Resolution::ApplyRemote => {
                if let Some(item) = remote_item {
                    state.with_vault_mut(|vault| {
                        vault.upsert(item);
                        Ok(())
                    })?;
                    report.pulled += 1;
                }
            }
            merge::Resolution::ApplyDelete => {
                state.with_vault_mut(|vault| {
                    let _ = vault.remove(id);
                    Ok(())
                })?;
                report.pulled += 1;
            }
            merge::Resolution::KeepLocal => {}
            merge::Resolution::Conflict { remote_wins } => {
                report.conflicts += 1;
                if let Some(mut item) = remote_item {
                    if remote_wins {
                        // Keep the local one beside it rather than dropping a
                        // password to settle a tie.
                        state.with_vault_mut(|vault| {
                            if let Some(mine) = vault.get(id).cloned() {
                                let mut copy = mine;
                                copy.id = Uuid::new_v4();
                                copy.name = format!("{} (this machine)", copy.name);
                                vault.upsert(copy);
                            }
                            vault.upsert(item);
                            Ok(())
                        })?;
                        report.pulled += 1;
                    } else {
                        item.id = Uuid::new_v4();
                        item.name = format!("{} (other machine)", item.name);
                        state.with_vault_mut(|vault| {
                            vault.upsert(item);
                            Ok(())
                        })?;
                        report.pulled += 1;
                    }
                }
            }
        }
    }

    // Then everything this machine changed since the last sync — deletions
    // included. They were invisible here for as long as `to_push` walked only
    // the items that still existed, which is why a delete on one machine was
    // silently undone by the next sync from another.
    let outgoing = state.with_vault(|vault| {
        let local: Vec<merge::LocalItem> = vault
            .items()
            .iter()
            .map(|item| merge::LocalItem::present(item.id, item.updated_at))
            .chain(
                vault
                    .tombstones()
                    .iter()
                    .map(|grave| merge::LocalItem::deleted(grave.id, grave.deleted_at)),
            )
            .collect();

        let mut records = Vec::new();
        for change in merge::to_push(&local, sync.last_synced_at) {
            if change.deleted {
                let Some(grave) = vault.tombstone(change.id) else {
                    continue;
                };
                records.push(SyncItem {
                    id: change.id.to_string(),
                    revision: 0,
                    // No body: the delete has to travel, the contents do not.
                    // The proof is what makes the other machine believe it.
                    ciphertext: None,
                    deleted: true,
                    proof: Some(deletes::seal_proof(vault, &grave).map_err(|e| e.to_string())?),
                });
            } else if let Some(item) = vault.get(change.id) {
                let sealed = vault.seal_item(item).map_err(|e| e.to_string())?;
                records.push(SyncItem {
                    id: change.id.to_string(),
                    revision: 0,
                    ciphertext: Some(serde_json::to_string(&sealed).map_err(|e| e.to_string())?),
                    deleted: false,
                    proof: None,
                });
            }
        }
        Ok(records)
    })?;

    let mut revision = page.revision;
    if !outgoing.is_empty() {
        revision = client
            .push(page.revision, &outgoing)
            .await
            .map_err(|e| e.to_string())?;
        report.pushed = outgoing.len();
    }
    report.revision = revision;

    state.with_vault_mut(|vault| {
        if let Some(mut updated) = vault.sync_state().cloned() {
            updated.last_revision = revision;
            updated.last_synced_at = now();
            vault.set_sync_state(Some(updated));
        }
        Ok(())
    })?;
    state.save()?;

    Ok(report)
}

pub fn status(state: &AppState) -> Result<SyncStatus, String> {
    state.with_vault(|vault| {
        Ok(match vault.sync_state() {
            Some(sync) => SyncStatus {
                enrolled: true,
                base_url: Some(sync.base_url.clone()),
                account_id: Some(sync.account_id.clone()),
                device_id: Some(sync.device_id.clone()),
                last_synced_at: Some(sync.last_synced_at).filter(|at| *at > 0),
            },
            None => SyncStatus {
                enrolled: false,
                base_url: None,
                account_id: None,
                device_id: None,
                last_synced_at: None,
            },
        })
    })
}

/// Stops syncing and forgets the device key.
///
/// Local items stay. Leaving sync should never be a way to lose a vault, and
/// the server keeps its copy until the device is revoked there too — which is
/// a separate act, on a different machine, by someone who still has access.
pub fn forget(state: &AppState) -> Result<(), String> {
    state.with_vault_mut(|vault| {
        vault.set_sync_state(None);
        Ok(())
    })?;
    state.save()
}

fn sealed_to_string(sealed: &yara_core::Sealed) -> Result<String, String> {
    serde_json::to_string(sealed).map_err(|e| e.to_string())
}

/// Decrypts one incoming record, or `None` for a tombstone.
///
/// A record that will not decrypt is skipped rather than fatal: one unreadable
/// item — written by a newer build, or corrupted in transit — should not stop
/// every other item from syncing.
fn decode_item(state: &AppState, id: Uuid, record: &SyncItem) -> Result<Option<Item>, String> {
    let Some(ciphertext) = record.ciphertext.as_deref() else {
        return Ok(None);
    };

    let Ok(sealed) = serde_json::from_str(ciphertext) else {
        return Ok(None);
    };

    state.with_vault(|vault| Ok(vault.open_item(id, &sealed).ok()))
}
