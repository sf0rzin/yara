//! Tauri bindings over `yara-core`.
//!
//! The frontend never receives a secret as part of normal data flow. Listing
//! items returns [`ItemSummary`], which has no password field at all, so there
//! is no way to leak one by accident into a render, a log, or devtools. Getting
//! a plaintext value requires an explicit, separate call for one named item.

mod broker;
mod state;

use std::sync::Arc;

use broker::BrokerHandle;
use serde::{Deserialize, Serialize};
use state::AppState;
use tauri::{Manager, State};
use uuid::Uuid;
use yara_core::{
    Item, ItemKind, Strength, TotpConfig, UnlockedVault, VaultCounts, VaultFile, VaultHealth,
};

/// An item as the frontend sees it: everything except the secrets.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ItemSummary {
    pub id: Uuid,
    pub name: String,
    pub kind: ItemKind,
    pub username: Option<String>,
    pub url: Option<String>,
    pub tags: Vec<String>,
    pub has_password: bool,
    pub has_totp: bool,
    pub updated_at: u64,
}

impl From<&Item> for ItemSummary {
    fn from(item: &Item) -> Self {
        Self {
            id: item.id,
            name: item.name.clone(),
            kind: item.kind,
            username: item.username.clone(),
            url: item.url.clone(),
            tags: item.tags.clone(),
            has_password: item.password.is_some(),
            has_totp: item.totp.is_some(),
            updated_at: item.updated_at,
        }
    }
}

/// A TOTP code plus how long it stays valid, so the UI can draw the countdown.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TotpCode {
    pub code: String,
    pub seconds_remaining: u64,
    pub period: u64,
}

/// What a scanned QR code turned out to contain.
///
/// Everything the user needs to confirm they scanned the right thing, and
/// nothing that would let the frontend reconstruct the secret. `sample_code` is
/// a live code, which proves the enrollment works without disclosing the seed
/// that produced it.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TotpPreview {
    pub issuer: Option<String>,
    pub account: Option<String>,
    pub algorithm: String,
    pub digits: u32,
    pub period: u64,
    pub sample_code: String,
}

impl TryFrom<&TotpConfig> for TotpPreview {
    type Error = String;

    fn try_from(config: &TotpConfig) -> Result<Self, String> {
        Ok(Self {
            issuer: config.issuer.clone(),
            account: config.account.clone(),
            algorithm: config.algorithm.as_str().to_string(),
            digits: config.digits,
            period: config.period,
            sample_code: config.generate().map_err(to_message)?,
        })
    }
}

#[derive(Debug, Deserialize)]
pub struct NewItem {
    pub name: String,
    #[serde(default)]
    pub kind: ItemKind,
    pub username: Option<String>,
    pub password: Option<String>,
    pub url: Option<String>,
    pub notes: Option<String>,
    /// An `otpauth://` URI typed or pasted by hand.
    pub totp_uri: Option<String>,
    /// Attach the enrollment most recently read from a QR code instead.
    #[serde(default)]
    pub use_scanned_totp: bool,
    #[serde(default)]
    pub tags: Vec<String>,
}

type CommandResult<T> = Result<T, String>;

fn to_message(error: impl std::fmt::Display) -> String {
    error.to_string()
}

#[tauri::command]
fn vault_exists(state: State<'_, Arc<AppState>>) -> bool {
    state.vault_path().exists()
}

#[tauri::command]
fn is_unlocked(state: State<'_, Arc<AppState>>) -> bool {
    state.is_unlocked()
}

#[tauri::command]
fn create_vault(state: State<'_, Arc<AppState>>, password: String) -> CommandResult<()> {
    if state.vault_path().exists() {
        return Err("a vault already exists at this location".into());
    }
    let vault = UnlockedVault::create(&password).map_err(to_message)?;
    state.persist(&vault)?;
    state.set_vault(vault);
    Ok(())
}

#[tauri::command]
fn unlock_vault(
    state: State<'_, Arc<AppState>>,
    broker: State<'_, BrokerHandle>,
    password: String,
) -> CommandResult<()> {
    let bytes = std::fs::read(state.vault_path()).map_err(to_message)?;
    let file = VaultFile::from_bytes(&bytes).map_err(to_message)?;
    let vault = UnlockedVault::open(&file, &password).map_err(to_message)?;
    state.set_vault(vault);

    // The audit log lives in the vault, so this is the first moment it can be
    // read back. Without it the Agent access screen would show only what
    // happened since this unlock and look like a fresh install every time.
    broker.broker.restore_audit();
    Ok(())
}

/// Drops the vault, which zeroizes the vault key.
///
/// Also tears down agent access: outstanding approval prompts are abandoned and
/// every grant is destroyed, since a permission that outlives the key behind it
/// is a permission to nothing.
#[tauri::command]
fn lock_vault(state: State<'_, Arc<AppState>>, broker: State<'_, BrokerHandle>) {
    state.clear();
    broker.on_lock();
}

#[tauri::command]
fn list_items(
    state: State<'_, Arc<AppState>>,
    query: Option<String>,
    kind: Option<ItemKind>,
    with_totp: Option<bool>,
) -> CommandResult<Vec<ItemSummary>> {
    state.with_vault(|vault| {
        Ok(vault
            .search(query.as_deref().unwrap_or(""))
            .into_iter()
            .filter(|item| kind.is_none_or(|wanted| item.kind == wanted))
            .filter(|item| with_totp != Some(true) || item.totp.is_some())
            .map(ItemSummary::from)
            .collect())
    })
}

#[tauri::command]
fn recent_items(
    state: State<'_, Arc<AppState>>,
    limit: Option<usize>,
) -> CommandResult<Vec<ItemSummary>> {
    state.with_vault(|vault| {
        Ok(vault
            .recent(limit.unwrap_or(5))
            .into_iter()
            .map(ItemSummary::from)
            .collect())
    })
}

#[tauri::command]
fn vault_counts(state: State<'_, Arc<AppState>>) -> CommandResult<VaultCounts> {
    state.with_vault(|vault| Ok(vault.counts()))
}

#[tauri::command]
fn vault_health(state: State<'_, Arc<AppState>>) -> CommandResult<VaultHealth> {
    state.with_vault(|vault| Ok(vault.health()))
}

/// Reads a two-factor QR code from an image file.
#[tauri::command]
fn scan_qr_from_path(state: State<'_, Arc<AppState>>, path: String) -> CommandResult<TotpPreview> {
    let bytes = std::fs::read(&path).map_err(|_| "could not read that file".to_string())?;
    let config = yara_core::qr::decode_enrollment(&bytes).map_err(to_message)?;

    let preview = TotpPreview::try_from(&config)?;
    state.set_pending_totp(config);
    Ok(preview)
}

/// Reads a two-factor QR code from an image on the clipboard.
///
/// This is the path that makes Win+Shift+S work: snip the QR code off the
/// screen, press paste, done.
#[tauri::command]
fn scan_qr_from_clipboard(
    app: tauri::AppHandle,
    state: State<'_, Arc<AppState>>,
) -> CommandResult<TotpPreview> {
    use tauri_plugin_clipboard_manager::ClipboardExt;

    let image = app
        .clipboard()
        .read_image()
        .map_err(|_| "there is no image on the clipboard".to_string())?;

    let config = yara_core::qr::decode_enrollment_rgba(image.rgba(), image.width(), image.height())
        .map_err(to_message)?;

    let preview = TotpPreview::try_from(&config)?;
    state.set_pending_totp(config);
    Ok(preview)
}

/// Discards a scanned enrollment the user decided not to keep.
#[tauri::command]
fn clear_scanned_totp(state: State<'_, Arc<AppState>>) {
    state.clear_pending_totp();
}

#[tauri::command]
fn add_item(state: State<'_, Arc<AppState>>, item: NewItem) -> CommandResult<Uuid> {
    let totp = if item.use_scanned_totp {
        let scanned = state.take_pending_totp();
        if scanned.is_none() {
            return Err("the scanned code is no longer available — scan it again".into());
        }
        scanned
    } else {
        item.totp_uri
            .as_deref()
            .filter(|uri| !uri.trim().is_empty())
            .map(TotpConfig::from_uri)
            .transpose()
            .map_err(to_message)?
    };

    let mut entry = Item::new(item.name);
    entry.kind = item.kind;
    entry.username = item.username;
    entry.password = item.password.map(Into::into);
    entry.url = item.url;
    entry.notes = item.notes.map(Into::into);
    entry.totp = totp;
    entry.tags = item.tags;

    let id = state.with_vault_mut(|vault| Ok(vault.add(entry)))?;
    state.save()?;
    Ok(id)
}

#[tauri::command]
fn delete_item(state: State<'_, Arc<AppState>>, id: Uuid) -> CommandResult<()> {
    state.with_vault_mut(|vault| vault.remove(id).map(|_| ()).map_err(to_message))?;
    state.save()
}

/// Returns a password in plaintext.
///
/// Separate from [`list_items`] on purpose: a secret only crosses the IPC
/// boundary when the user has asked for that specific one.
#[tauri::command]
fn reveal_password(state: State<'_, Arc<AppState>>, id: Uuid) -> CommandResult<String> {
    state.with_vault(|vault| {
        let item = vault
            .get(id)
            .ok_or_else(|| format!("item {id} not found"))?;
        item.password
            .as_ref()
            .map(|password| password.expose().to_string())
            .ok_or_else(|| "this item has no password".to_string())
    })
}

#[tauri::command]
fn totp_code(state: State<'_, Arc<AppState>>, id: Uuid) -> CommandResult<TotpCode> {
    state.with_vault(|vault| {
        let item = vault
            .get(id)
            .ok_or_else(|| format!("item {id} not found"))?;
        let totp = item
            .totp
            .as_ref()
            .ok_or_else(|| "this item has no authenticator".to_string())?;

        Ok(TotpCode {
            code: totp.generate().map_err(to_message)?,
            seconds_remaining: totp.seconds_remaining().map_err(to_message)?,
            period: totp.period,
        })
    })
}

/// Rates a candidate password for the strength meter.
///
/// Goes through the backend rather than being reimplemented in TypeScript so
/// the meter shown while choosing a password and the audit that later flags it
/// as weak can never disagree.
#[tauri::command]
fn estimate_strength(password: String) -> Strength {
    yara_core::health::strength(&password)
}

#[tauri::command]
fn change_master_password(
    state: State<'_, Arc<AppState>>,
    new_password: String,
) -> CommandResult<()> {
    state.with_vault_mut(|vault| vault.change_password(&new_password).map_err(to_message))?;
    state.save()
}

/// A live grant, as the "Agent access" screen shows it.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GrantView {
    pub id: Uuid,
    pub item: String,
    pub field: String,
    pub program: String,
    /// `run` or `reveal`.
    pub scope: String,
    /// The exact thing it authorises, e.g. ``run `npm run migrate` ``.
    pub permits: String,
    pub seconds_remaining: u64,
    pub remaining_uses: u32,
}

/// One line of the audit log.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuditView {
    pub id: Uuid,
    pub at: u64,
    pub program: String,
    pub item: String,
    pub summary: String,
    pub reason: String,
    pub allowed: bool,
    /// Worth the user's attention: a reveal, or anything refused.
    pub notable: bool,
}

#[tauri::command]
fn list_grants(broker: State<'_, BrokerHandle>) -> Vec<GrantView> {
    broker
        .broker
        .live_grants(yara_broker::now())
        .into_iter()
        .map(|grant| GrantView {
            id: grant.id,
            item: grant.item_name.clone(),
            field: grant.field.as_str().to_string(),
            program: grant.client.display_name(),
            scope: if grant.scope.is_reveal() {
                "reveal".into()
            } else {
                "run".into()
            },
            // What the grant actually permits, which is one command and not
            // the category. Shown so a live permission can be read for what it
            // is rather than trusted for what it was asked for.
            permits: grant.scope.summary(),
            seconds_remaining: grant.seconds_remaining(yara_broker::now()),
            remaining_uses: grant.remaining_uses(),
        })
        .collect()
}

#[tauri::command]
fn revoke_grant(broker: State<'_, BrokerHandle>, id: Uuid) -> bool {
    broker.broker.revoke(id)
}

#[tauri::command]
fn audit_entries(broker: State<'_, BrokerHandle>, limit: Option<usize>) -> Vec<AuditView> {
    broker
        .broker
        .recent_audit(limit.unwrap_or(50))
        .into_iter()
        .map(|entry| {
            let summary = match &entry.action {
                yara_broker::Action::Listed { matches } => {
                    format!("listed {matches} items")
                }
                yara_broker::Action::Ran { command, env_var } => {
                    format!("ran `{command}` with ${env_var}")
                }
                yara_broker::Action::Revealed => "revealed the plaintext".to_string(),
            };

            AuditView {
                id: entry.id,
                at: entry.at,
                program: entry.client.display_name(),
                item: entry.item.clone(),
                summary,
                reason: entry.reason.clone(),
                allowed: entry.outcome.was_allowed(),
                notable: entry.action.is_notable() || !entry.outcome.was_allowed(),
            }
        })
        .collect()
}

/// Delivers the user's answer to a waiting agent request.
#[tauri::command]
fn resolve_approval(
    broker: State<'_, BrokerHandle>,
    id: Uuid,
    choice: String,
    minutes: Option<u64>,
) -> CommandResult<()> {
    let decision = broker::decision_from(&choice, minutes)
        .ok_or_else(|| format!("unrecognised choice {choice:?}"))?;

    // A request that is no longer waiting has already timed out; saying so is
    // better than silently doing nothing.
    if !broker.approver.resolve(id, decision) {
        return Err("that request is no longer waiting for an answer".into());
    }
    Ok(())
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let builder = tauri::Builder::default()
        .plugin(tauri_plugin_clipboard_manager::init())
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_opener::init());

    // Updates are verified against a public key compiled into this binary, so
    // the server that offers one cannot forge it. Desktop only: there is no
    // mobile implementation to register.
    #[cfg(desktop)]
    let builder = builder
        .plugin(tauri_plugin_process::init())
        .plugin(tauri_plugin_updater::Builder::new().build());

    builder
        .setup(|app| {
            let dir = app.path().app_data_dir()?;
            std::fs::create_dir_all(&dir)?;

            let state = Arc::new(AppState::new(dir.join("vault.yara")));
            app.manage(Arc::clone(&state));
            app.manage(broker::start(app.handle(), state));
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            vault_exists,
            is_unlocked,
            create_vault,
            unlock_vault,
            lock_vault,
            list_items,
            recent_items,
            vault_counts,
            vault_health,
            add_item,
            delete_item,
            scan_qr_from_path,
            scan_qr_from_clipboard,
            clear_scanned_totp,
            reveal_password,
            totp_code,
            estimate_strength,
            change_master_password,
            list_grants,
            revoke_grant,
            audit_entries,
            resolve_approval,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
