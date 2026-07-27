//! Tauri bindings over `lapse-core`.
//!
//! The frontend never receives a secret as part of normal data flow. Listing
//! items returns [`ItemSummary`], which has no password field at all, so there
//! is no way to leak one by accident into a render, a log, or devtools. Getting
//! a plaintext value requires an explicit, separate call.

mod state;

use lapse_core::{Item, TotpConfig, UnlockedVault, VaultFile};
use serde::{Deserialize, Serialize};
use state::AppState;
use tauri::{Manager, State};
use uuid::Uuid;

/// An item as the frontend sees it: everything except the secrets.
#[derive(Debug, Serialize)]
pub struct ItemSummary {
    pub id: Uuid,
    pub name: String,
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
pub struct TotpCode {
    pub code: String,
    pub seconds_remaining: u64,
    pub period: u64,
}

#[derive(Debug, Deserialize)]
pub struct NewItem {
    pub name: String,
    pub username: Option<String>,
    pub password: Option<String>,
    pub url: Option<String>,
    pub notes: Option<String>,
    /// An `otpauth://` URI, as scanned from a QR code.
    pub totp_uri: Option<String>,
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
fn list_items(state: State<'_, AppState>, query: Option<String>) -> CommandResult<Vec<ItemSummary>> {
    state.with_vault(|vault| {
        Ok(vault
            .search(query.as_deref().unwrap_or(""))
            .into_iter()
            .map(ItemSummary::from)
            .collect())
    })
}

#[tauri::command]
fn add_item(state: State<'_, AppState>, item: NewItem) -> CommandResult<Uuid> {
    let totp = item
        .totp_uri
        .as_deref()
        .map(TotpConfig::from_uri)
        .transpose()
        .map_err(to_message)?;

    let mut entry = Item::new(item.name);
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

#[tauri::command]
fn change_master_password(state: State<'_, AppState>, new_password: String) -> CommandResult<()> {
    state.with_vault_mut(|vault| vault.change_password(&new_password).map_err(to_message))?;
    state.save()
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
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
            add_item,
            delete_item,
            reveal_password,
            totp_code,
            change_master_password,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
