//! Tauri bindings over `lapse-core`.
//!
//! The frontend never receives a secret as part of normal data flow. Listing
//! items returns [`ItemSummary`], which has no password field at all, so there
//! is no way to leak one by accident into a render, a log, or devtools. Getting
//! a plaintext value requires an explicit, separate call for one named item.

mod state;

use lapse_core::{
    Item, ItemKind, Strength, TotpConfig, UnlockedVault, VaultCounts, VaultFile, VaultHealth,
};
use serde::{Deserialize, Serialize};
use state::AppState;
use tauri::{Manager, State};
use uuid::Uuid;

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
fn vault_exists(state: State<'_, AppState>) -> bool {
    state.vault_path().exists()
}

#[tauri::command]
fn is_unlocked(state: State<'_, AppState>) -> bool {
    state.is_unlocked()
}

#[tauri::command]
fn create_vault(state: State<'_, AppState>, password: String) -> CommandResult<()> {
    if state.vault_path().exists() {
        return Err("a vault already exists at this location".into());
    }
    let vault = UnlockedVault::create(&password).map_err(to_message)?;
    state.persist(&vault)?;
    state.set_vault(vault);
    Ok(())
}

#[tauri::command]
fn unlock_vault(state: State<'_, AppState>, password: String) -> CommandResult<()> {
    let bytes = std::fs::read(state.vault_path()).map_err(to_message)?;
    let file = VaultFile::from_bytes(&bytes).map_err(to_message)?;
    let vault = UnlockedVault::open(&file, &password).map_err(to_message)?;
    state.set_vault(vault);
    Ok(())
}

/// Drops the vault, which zeroizes the vault key.
#[tauri::command]
fn lock_vault(state: State<'_, AppState>) {
    state.clear();
}

#[tauri::command]
fn list_items(
    state: State<'_, AppState>,
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
fn recent_items(state: State<'_, AppState>, limit: Option<usize>) -> CommandResult<Vec<ItemSummary>> {
    state.with_vault(|vault| {
        Ok(vault
            .recent(limit.unwrap_or(5))
            .into_iter()
            .map(ItemSummary::from)
            .collect())
    })
}

#[tauri::command]
fn vault_counts(state: State<'_, AppState>) -> CommandResult<VaultCounts> {
    state.with_vault(|vault| Ok(vault.counts()))
}

#[tauri::command]
fn vault_health(state: State<'_, AppState>) -> CommandResult<VaultHealth> {
    state.with_vault(|vault| Ok(vault.health()))
}

/// Reads a two-factor QR code from an image file.
#[tauri::command]
fn scan_qr_from_path(state: State<'_, AppState>, path: String) -> CommandResult<TotpPreview> {
    let bytes = std::fs::read(&path).map_err(|_| "could not read that file".to_string())?;
    let config = lapse_core::qr::decode_enrollment(&bytes).map_err(to_message)?;

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
    state: State<'_, AppState>,
) -> CommandResult<TotpPreview> {
    use tauri_plugin_clipboard_manager::ClipboardExt;

    let image = app
        .clipboard()
        .read_image()
        .map_err(|_| "there is no image on the clipboard".to_string())?;

    let config =
        lapse_core::qr::decode_enrollment_rgba(image.rgba(), image.width(), image.height())
            .map_err(to_message)?;

    let preview = TotpPreview::try_from(&config)?;
    state.set_pending_totp(config);
    Ok(preview)
}

/// Discards a scanned enrollment the user decided not to keep.
#[tauri::command]
fn clear_scanned_totp(state: State<'_, AppState>) {
    state.clear_pending_totp();
}

#[tauri::command]
fn add_item(state: State<'_, AppState>, item: NewItem) -> CommandResult<Uuid> {
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
fn delete_item(state: State<'_, AppState>, id: Uuid) -> CommandResult<()> {
    state.with_vault_mut(|vault| vault.remove(id).map(|_| ()).map_err(to_message))?;
    state.save()
}

/// Returns a password in plaintext.
///
/// Separate from [`list_items`] on purpose: a secret only crosses the IPC
/// boundary when the user has asked for that specific one.
#[tauri::command]
fn reveal_password(state: State<'_, AppState>, id: Uuid) -> CommandResult<String> {
    state.with_vault(|vault| {
        let item = vault.get(id).ok_or_else(|| format!("item {id} not found"))?;
        item.password
            .as_ref()
            .map(|password| password.expose().to_string())
            .ok_or_else(|| "this item has no password".to_string())
    })
}

#[tauri::command]
fn totp_code(state: State<'_, AppState>, id: Uuid) -> CommandResult<TotpCode> {
    state.with_vault(|vault| {
        let item = vault.get(id).ok_or_else(|| format!("item {id} not found"))?;
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
    lapse_core::health::strength(&password)
}

#[tauri::command]
fn change_master_password(state: State<'_, AppState>, new_password: String) -> CommandResult<()> {
    state.with_vault_mut(|vault| vault.change_password(&new_password).map_err(to_message))?;
    state.save()
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_clipboard_manager::init())
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_opener::init())
        .setup(|app| {
            let dir = app.path().app_data_dir()?;
            std::fs::create_dir_all(&dir)?;
            app.manage(AppState::new(dir.join("vault.lapse")));
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
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
