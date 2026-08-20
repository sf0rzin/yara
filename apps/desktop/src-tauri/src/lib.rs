//! Tauri bindings over `yara-core`.
//!
//! The frontend never receives a secret as part of normal data flow. Listing
//! items returns [`ItemSummary`], which has no password field at all, so there
//! is no way to leak one by accident into a render, a log, or devtools. Getting
//! a plaintext value requires an explicit, separate call for one named item.

mod broker;
mod clipboard;
mod remembered;
mod state;
mod sync;

use std::sync::Arc;

use broker::BrokerHandle;
use clipboard::SecretClipboard;
use serde::{Deserialize, Serialize};
use state::{AppState, Startup, VaultProfile};
use tauri::{Emitter, Manager, State};
use uuid::Uuid;
use yara_core::{
    Cadence, Field, Item, ItemKind, Recipe, SecretString, Strength, Subscription, TotpConfig,
    UnlockedVault, VaultCounts, VaultFile,
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
    pub folder: Option<String>,
    pub tags: Vec<String>,
    pub has_password: bool,
    pub has_totp: bool,
    pub reused: bool,
    pub missing_second_factor: bool,
    pub updated_at: u64,
    pub created_at: u64,
}

impl From<&Item> for ItemSummary {
    fn from(item: &Item) -> Self {
        Self {
            id: item.id,
            name: item.name.clone(),
            kind: item.kind,
            username: item.username.clone(),
            url: item.url.clone(),
            folder: item.folder.clone(),
            tags: item.tags.clone(),
            has_password: item.password.is_some(),
            has_totp: item.totp.is_some(),
            // Reuse is a relationship between items. One item cannot know it,
            // so list_items and recent_items fill this after seeing the vault.
            reused: false,
            missing_second_factor: yara_core::health::missing_second_factor(item),
            updated_at: item.updated_at,
            created_at: item.created_at,
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

/// A custom field as the frontend sees it.
///
/// `value` is present only when the field is not a secret. A secret's value
/// takes an explicit reveal, the same as the password does — otherwise
/// selecting an item would push every secret it holds into the webview, which
/// is precisely what [`ItemSummary`] exists to avoid.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FieldView {
    pub label: String,
    pub value: Option<String>,
    pub secret: bool,
}

/// The parts of an item that are too big or too sensitive for a listing.
///
/// Fetched per item rather than carried on every summary: most items have
/// neither, and a field that is empty for nine rows in ten does not belong in
/// a list payload.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ItemExtras {
    pub has_notes: bool,
    pub fields: Vec<FieldView>,
}

/// An edit. Every field is optional in the wire sense but total in meaning:
/// what arrives replaces what is there, so a cleared box clears the value.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ItemEdit {
    pub name: String,
    pub kind: ItemKind,
    pub username: Option<String>,
    /// `None` leaves the stored password alone; `Some("")` clears it. The
    /// difference matters because the edit form never receives the current
    /// password, so "unchanged" and "emptied" cannot be told apart by value.
    pub password: Option<String>,
    pub url: Option<String>,
    pub notes: Option<String>,
    #[serde(default)]
    pub fields: Vec<NewField>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NewField {
    pub label: String,
    pub value: String,
    #[serde(default)]
    pub secret: bool,
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
    pub fields: Vec<NewField>,
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

/// Which of the three startup situations this machine is in.
///
/// What [`vault_exists`] cannot say: a vault file that is missing while a
/// backup sits beside it is an interrupted save, not a first run, and offering
/// setup there is how the last surviving copy used to get overwritten.
#[tauri::command]
fn vault_startup(state: State<'_, Arc<AppState>>, broker: State<'_, BrokerHandle>) -> Startup {
    let startup = state.startup();
    if startup != Startup::Locked || state.resume_is_suppressed() {
        return startup;
    }

    let Ok(Some(password)) = state.remembered_password() else {
        return Startup::Locked;
    };
    match open_selected_vault(&state, password.expose()) {
        Ok(vault) => {
            state.set_vault(vault);
            state.allow_resume();
            broker.broker.restore_audit();
            Startup::Unlocked
        }
        Err(_) => {
            // The vault changed or Credential Manager held a stale entry. Do
            // not keep retrying a credential that no longer opens this file.
            let _ = state.forget_selected_remembered();
            Startup::Locked
        }
    }
}

#[tauri::command]
fn list_vaults(state: State<'_, Arc<AppState>>) -> Vec<VaultProfile> {
    state.profiles()
}

#[tauri::command]
fn select_vault(state: State<'_, Arc<AppState>>, id: String) -> CommandResult<()> {
    state.select_profile(&id)
}

/// Returns to the picker without revoking a remembered credential. This is a
/// switch, not a log-out; choosing the vault again may still resume it.
#[tauri::command]
fn choose_another_vault(app: tauri::AppHandle) -> CommandResult<()> {
    lock_everything(&app);
    let state = app
        .try_state::<Arc<AppState>>()
        .ok_or_else(|| "vault state is unavailable".to_string())?;
    state.deselect_profile()
}

/// Permanently removes one local vault, its recovery copies and any remembered
/// credential. The picker confirms the consequence before calling this.
#[tauri::command]
fn remove_vault(app: tauri::AppHandle, id: String, confirmation: String) -> CommandResult<()> {
    lock_everything(&app);
    let state = app
        .try_state::<Arc<AppState>>()
        .ok_or_else(|| "vault state is unavailable".to_string())?;
    state.suppress_resume();
    state.remove_profile(&id, &confirmation)
}

/// Puts a surviving copy back at the live path after an interrupted save.
#[tauri::command]
fn recover_vault(state: State<'_, Arc<AppState>>) -> CommandResult<()> {
    state.recover()
}

#[tauri::command]
fn is_unlocked(state: State<'_, Arc<AppState>>) -> bool {
    state.is_unlocked()
}

#[tauri::command]
fn create_vault(
    state: State<'_, Arc<AppState>>,
    password: String,
    name: Option<String>,
    remember: Option<bool>,
) -> CommandResult<()> {
    let vault = UnlockedVault::create(&password).map_err(to_message)?;
    state.add_profile(name.as_deref().unwrap_or("Personal"), &vault)?;
    state.set_remembered(&password, remember.unwrap_or(false))?;
    state.set_vault(vault);
    state.allow_resume();
    Ok(())
}

#[tauri::command]
fn unlock_vault(
    state: State<'_, Arc<AppState>>,
    broker: State<'_, BrokerHandle>,
    password: String,
    remember: Option<bool>,
) -> CommandResult<()> {
    let vault = open_selected_vault(&state, &password)?;
    state.set_remembered(&password, remember.unwrap_or(false))?;
    state.set_vault(vault);
    state.allow_resume();

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
/// is a permission to nothing. And it takes any copied secret off the
/// clipboard — a vault that locks while a password is still there has not
/// locked anything.
#[tauri::command]
fn lock_vault(app: tauri::AppHandle) {
    lock_everything(&app);
    if let Some(state) = app.try_state::<Arc<AppState>>() {
        state.suppress_resume();
    }
}

/// A log-out is stronger than a lock: it revokes the remembered credential
/// and leaves no vault selected, so the next screen is the picker.
#[tauri::command]
fn logout_vault(app: tauri::AppHandle) -> CommandResult<()> {
    lock_everything(&app);
    let state = app
        .try_state::<Arc<AppState>>()
        .ok_or_else(|| "vault state is unavailable".to_string())?;
    state.suppress_resume();
    state.forget_selected_remembered()?;
    state.deselect_profile()
}

fn open_selected_vault(state: &AppState, password: &str) -> CommandResult<UnlockedVault> {
    let bytes = std::fs::read(state.vault_path()).map_err(to_message)?;
    let file = VaultFile::from_bytes(&bytes).map_err(to_message)?;
    UnlockedVault::open(&file, password).map_err(to_message)
}

/// Locks the vault and everything that depends on it holding a key.
///
/// Written against an [`AppHandle`](tauri::AppHandle) rather than taking the
/// three pieces of state as arguments because the callers are three different
/// shapes: a command, a page-load hook, and the exit event.
fn lock_everything(app: &tauri::AppHandle) {
    if let Some(state) = app.try_state::<Arc<AppState>>() {
        state.clear();
    }
    if let Some(broker) = app.try_state::<BrokerHandle>() {
        broker.on_lock();
    }
    if let Some(clipboard) = app.try_state::<Arc<SecretClipboard>>() {
        clipboard.clear_now();
    }
}

/// Locks the vault because the webview reloaded. Says whether it had to.
///
/// A reload — F5, which WebView2 honours, a renderer crash, a dev-server
/// reload — remounts the frontend with empty state while the backend is still
/// holding the vault key. The user is shown the unlock screen and reasonably
/// concludes the vault is locked. It was not: the broker went on serving
/// agents from the same live state, and approval events were delivered to a
/// webview that no longer had a listener, so an agent's request sat blocked
/// until it timed out with no dialog ever appearing.
///
/// Locking is the answer rather than restoring the session, because it is the
/// safer of the two and because it is what the screen already claims. Done
/// here, on the Rust side, so it holds whatever the frontend does or forgets
/// to do.
///
/// The return value is what tells the first page load of a launch from a
/// genuine reload: at launch there is nothing unlocked, so nothing else needs
/// tearing down either.
fn lock_on_reload(state: &AppState) -> bool {
    if !state.is_unlocked() {
        return false;
    }
    state.clear();
    true
}

#[tauri::command]
fn list_items(
    state: State<'_, Arc<AppState>>,
    query: Option<String>,
    kind: Option<ItemKind>,
    with_totp: Option<bool>,
    folder: Option<String>,
) -> CommandResult<Vec<ItemSummary>> {
    state.with_vault(|vault| {
        let reused = vault.reused_passwords();
        Ok(vault
            .search(query.as_deref().unwrap_or(""))
            .into_iter()
            .filter(|item| match kind {
                // An entry with a code and no password is not a login. The
                // sidebar offers Logins and Authenticator as two places, and
                // a two-factor seed imported on its own belongs in the second
                // one only — it has nothing to log in with.
                //
                // Decided here rather than by adding ItemKind::Authenticator,
                // because the distinction is already in the data and a new
                // variant would mean migrating vaults to record something
                // their contents already say. A login that has both a
                // password and a code stays a login, and still appears under
                // Authenticator, because that screen answers "show me my
                // codes" rather than "show me a kind".
                Some(ItemKind::Login) => item.kind == ItemKind::Login && item.password.is_some(),
                Some(wanted) => item.kind == wanted,
                None => true,
            })
            .filter(|item| with_totp != Some(true) || item.totp.is_some())
            .filter(|item| match &folder {
                Some(wanted) => item.folder.as_ref() == Some(wanted),
                None => true,
            })
            .map(|item| {
                let mut summary = ItemSummary::from(item);
                summary.reused = reused.contains(&item.id);
                summary
            })
            .collect())
    })
}

#[tauri::command]
fn recent_items(
    state: State<'_, Arc<AppState>>,
    limit: Option<usize>,
) -> CommandResult<Vec<ItemSummary>> {
    state.with_vault(|vault| {
        let reused = vault.reused_passwords();
        Ok(vault
            .recent(limit.unwrap_or(5))
            .into_iter()
            .map(|item| {
                let mut summary = ItemSummary::from(item);
                summary.reused = reused.contains(&item.id);
                summary
            })
            .collect())
    })
}

#[tauri::command]
fn folders(state: State<'_, Arc<AppState>>) -> CommandResult<Vec<String>> {
    state.with_vault(|vault| Ok(vault.folders().to_vec()))
}

#[tauri::command]
fn create_folder(state: State<'_, Arc<AppState>>, name: String) -> CommandResult<()> {
    state.with_vault_mut(|vault| {
        vault.create_folder(name.trim());
        Ok(())
    })?;
    state.save()
}

#[tauri::command]
fn rename_folder(state: State<'_, Arc<AppState>>, from: String, to: String) -> CommandResult<()> {
    state.with_vault_mut(|vault| vault.rename_folder(&from, to.trim()).map_err(to_message))?;
    state.save()
}

/// Removes a folder. Its items stay in the vault, without a folder.
#[tauri::command]
fn delete_folder(state: State<'_, Arc<AppState>>, name: String) -> CommandResult<usize> {
    let freed = state.with_vault_mut(|vault| Ok(vault.delete_folder(&name)))?;
    state.save()?;
    Ok(freed)
}

#[tauri::command]
fn reorder_folders(state: State<'_, Arc<AppState>>, names: Vec<String>) -> CommandResult<()> {
    state.with_vault_mut(|vault| {
        vault.reorder_folders(&names);
        Ok(())
    })?;
    state.save()
}

#[tauri::command]
fn set_item_folder(
    state: State<'_, Arc<AppState>>,
    id: Uuid,
    folder: Option<String>,
) -> CommandResult<()> {
    state.with_vault_mut(|vault| vault.set_folder(id, folder).map_err(to_message))?;
    state.save()
}

#[tauri::command]
fn reorder_items(state: State<'_, Arc<AppState>>, ids: Vec<Uuid>) -> CommandResult<()> {
    state.with_vault_mut(|vault| {
        vault.reorder_items(&ids);
        Ok(())
    })?;
    state.save()
}

#[tauri::command]
fn vault_counts(state: State<'_, Arc<AppState>>) -> CommandResult<VaultCounts> {
    state.with_vault(|vault| Ok(vault.counts()))
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
    entry.fields = item.fields.into_iter().map(Field::from).collect();
    entry.tags = item.tags;

    let id = state.with_vault_mut(|vault| Ok(vault.add(entry)))?;
    state.save()?;
    Ok(id)
}

impl From<NewField> for Field {
    fn from(field: NewField) -> Self {
        Field {
            label: field.label,
            value: field.value.into(),
            secret: field.secret,
        }
    }
}

/// Everything an item holds that a listing deliberately leaves out.
#[tauri::command]
fn item_extras(state: State<'_, Arc<AppState>>, id: Uuid) -> CommandResult<ItemExtras> {
    state.with_vault(|vault| {
        let item = vault
            .get(id)
            .ok_or_else(|| format!("item {id} not found"))?;

        Ok(ItemExtras {
            // Whether there are notes, not what they say. Reading them is a
            // separate, deliberate call.
            has_notes: item.notes.as_ref().is_some_and(|n| !n.is_empty()),
            fields: item
                .fields
                .iter()
                .map(|field| FieldView {
                    label: field.label.clone(),
                    value: (!field.secret).then(|| field.value.expose().to_string()),
                    secret: field.secret,
                })
                .collect(),
        })
    })
}

#[tauri::command]
fn reveal_field(state: State<'_, Arc<AppState>>, id: Uuid, label: String) -> CommandResult<String> {
    state.with_vault(|vault| {
        let item = vault
            .get(id)
            .ok_or_else(|| format!("item {id} not found"))?;
        item.fields
            .iter()
            .find(|field| field.label == label)
            .map(|field| field.value.expose().to_string())
            .ok_or_else(|| format!("this item has no field called {label}"))
    })
}

#[tauri::command]
fn reveal_notes(state: State<'_, Arc<AppState>>, id: Uuid) -> CommandResult<String> {
    state.with_vault(|vault| {
        let item = vault
            .get(id)
            .ok_or_else(|| format!("item {id} not found"))?;
        item.notes
            .as_ref()
            .map(|notes| notes.expose().to_string())
            .ok_or_else(|| "this item has no notes".to_string())
    })
}

/// Applies an edit.
///
/// The password is the one value the form cannot round-trip, because it is
/// never sent to the frontend in the first place. `None` therefore means
/// "leave it", and an empty string means "clear it" — the two are different
/// intentions and guessing between them would either lose a password or
/// refuse to remove one.
#[tauri::command]
fn update_item(state: State<'_, Arc<AppState>>, id: Uuid, edit: ItemEdit) -> CommandResult<()> {
    state.with_vault_mut(|vault| {
        vault
            .update(id, |item| {
                item.name = edit.name;
                item.kind = edit.kind;
                item.username = blank_to_none(edit.username);
                item.url = blank_to_none(edit.url);
                item.notes = blank_to_none(edit.notes).map(Into::into);
                item.fields = edit
                    .fields
                    .into_iter()
                    .filter(|field| !field.label.trim().is_empty())
                    .map(Field::from)
                    .collect();

                if let Some(password) = edit.password {
                    item.password = (!password.is_empty()).then(|| password.into());
                }
            })
            .map_err(to_message)
    })?;
    state.save()
}

/// An empty box means no value, not a value that is the empty string.
fn blank_to_none(value: Option<String>) -> Option<String> {
    value.filter(|text| !text.trim().is_empty())
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

/// Deliberately takes no [`State`]: this is needed while the create form is
/// still being filled, whether or not a vault is already open.
#[tauri::command]
fn generate_password(recipe: Recipe) -> CommandResult<String> {
    let generated = yara_core::generate::password(&recipe).map_err(to_message)?;
    Ok(generated.expose().to_string())
}

/// Re-wraps the vault key under a new master password.
///
/// The current password is required and checked first. Without that this
/// command re-keyed the vault on the word of whoever called it, so anything
/// executing in the webview — an injected script, a compromised dependency in
/// the frontend bundle — could have silently changed the master password and
/// locked the user out of their own vault while it was sitting unlocked in
/// front of them.
#[tauri::command]
fn change_master_password(
    state: State<'_, Arc<AppState>>,
    current_password: String,
    new_password: String,
) -> CommandResult<()> {
    verify_master_password(&state, &current_password)?;
    state.with_vault_mut(|vault| vault.change_password(&new_password).map_err(to_message))?;
    state.save()?;
    state.refresh_remembered(&new_password)
}

/// Proves the caller knows the current master password.
///
/// By re-opening the file on disk, because that is the only thing that can
/// prove it: the unlocked vault in memory holds the vault key, and nothing
/// about it depends on the password any more. The file cannot be stale in the
/// way that matters — the wrapped key changes only when the password does, and
/// that path always writes.
///
/// The vault this opens is dropped immediately, which zeroizes the second copy
/// of the key it made. Failure says "wrong password or corrupted data" and
/// means either, as everywhere else.
fn verify_master_password(state: &AppState, password: &str) -> CommandResult<()> {
    let bytes = std::fs::read(state.vault_path()).map_err(to_message)?;
    let file = VaultFile::from_bytes(&bytes).map_err(to_message)?;
    UnlockedVault::open(&file, password)
        .map(|_| ())
        .map_err(to_message)
}

// ---- clipboard ---------------------------------------------------------

/// Event carrying the outcome of a timed clipboard clear.
pub const CLIPBOARD_CLEARED_EVENT: &str = "clipboard://cleared";

/// What the frontend is told once a copy's time is up.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ClipboardCleared {
    /// The copy this is about, matching [`clipboard::Copied::token`].
    pub token: u64,
    pub result: clipboard::Cleared,
}

/// Copies a secret, and owns the clearing of it.
///
/// Everything the frontend used to do by hand — write, wait, read back,
/// overwrite — happens here instead, because the webview clipboard can do
/// neither half properly: it cannot set the formats that keep an entry out of
/// Clipboard History and the Cloud Clipboard, and its `readText` is
/// permission-gated, so the clear could fail forever and invisibly while the
/// interface promised it had happened.
///
/// Returns immediately with what the interface is allowed to claim. The clear
/// arrives later as a [`CLIPBOARD_CLEARED_EVENT`], carrying whether it worked.
#[tauri::command]
fn copy_secret(
    app: tauri::AppHandle,
    clipboard: State<'_, Arc<SecretClipboard>>,
    value: String,
) -> CommandResult<clipboard::Copied> {
    let clipboard = Arc::clone(clipboard.inner());
    let copied = clipboard.copy(SecretString::new(value))?;

    let token = copied.token;
    tauri::async_runtime::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_secs(copied.clears_in)).await;
        let result = clipboard.clear_copy(token);
        let _ = app.emit(CLIPBOARD_CLEARED_EVENT, ClipboardCleared { token, result });
    });

    Ok(copied)
}

/// Takes a copied secret off the clipboard now rather than on the timer.
#[tauri::command]
fn clear_clipboard(clipboard: State<'_, Arc<SecretClipboard>>) -> clipboard::Cleared {
    clipboard.clear_now()
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
            field: grant.field.label().into_owned(),
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

// ---- icons -------------------------------------------------------------

/// Where icons are fetched from when this vault has no sync server of its own.
const DEFAULT_ICON_ORIGIN: &str = "https://yara.lat";

/// The icon for a domain, as a data URL, or `None` if there is not one.
///
/// Fetched through a proxy rather than from the site. Asking github.com
/// directly tells github.com that this machine holds a GitHub account, and
/// doing it for every row puts the shape of the vault on the wire — which the
/// interface promises does not happen.
///
/// Cached on disk, so the exposure is once per domain rather than once per
/// launch. Failures are cached too, as an empty file: a domain with no icon
/// should not be re-fetched on every render for the rest of time.
#[tauri::command]
async fn icon_for(
    state: State<'_, Arc<AppState>>,
    domain: String,
) -> CommandResult<Option<String>> {
    if !state.with_vault(|vault| Ok(vault.icons_enabled()))? {
        return Ok(None);
    }

    // The same validation the proxy applies, repeated here so a malformed
    // domain never becomes a filename on this machine either.
    let domain = match sanitise_domain(&domain) {
        Some(domain) => domain,
        None => return Ok(None),
    };

    let dir = state.icon_cache_dir();
    let cached = dir.join(format!("{domain}.ico"));

    if let Ok(bytes) = std::fs::read(&cached) {
        return Ok(as_data_url(&bytes));
    }

    // The origin this vault syncs with, so an account on a private server does
    // not quietly reach out to the public one.
    let origin = state
        .with_vault(|vault| {
            Ok(vault
                .sync_state()
                .map(|sync| sync.base_url.clone())
                .unwrap_or_else(|| DEFAULT_ICON_ORIGIN.to_string()))
        })
        .unwrap_or_else(|_| DEFAULT_ICON_ORIGIN.to_string());

    let url = format!("{}/api/v1/icons/{domain}", origin.trim_end_matches('/'));
    let bytes = match reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(8))
        .build()
        .map_err(to_message)?
        .get(&url)
        .send()
        .await
    {
        Ok(response) if response.status().is_success() => response
            .bytes()
            .await
            .map(|b| b.to_vec())
            .unwrap_or_default(),
        // A miss is remembered as an empty file. Anything else — the server
        // down, no network — is not, because it will be true again later.
        Ok(_) => Vec::new(),
        Err(_) => return Ok(None),
    };

    let _ = std::fs::create_dir_all(&dir);
    let _ = std::fs::write(&cached, &bytes);

    Ok(as_data_url(&bytes))
}

fn as_data_url(bytes: &[u8]) -> Option<String> {
    use base64::Engine as _;
    if bytes.is_empty() {
        return None;
    }
    Some(format!(
        "data:image/x-icon;base64,{}",
        base64::engine::general_purpose::STANDARD.encode(bytes)
    ))
}

fn sanitise_domain(input: &str) -> Option<String> {
    let domain = input.trim().trim_end_matches('.').to_ascii_lowercase();
    if domain.is_empty() || domain.len() > 253 || !domain.contains('.') {
        return None;
    }
    domain
        .split('.')
        .all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
        .then_some(domain)
}

#[tauri::command]
fn icons_enabled(state: State<'_, Arc<AppState>>) -> CommandResult<bool> {
    state.with_vault(|vault| Ok(vault.icons_enabled()))
}

/// Turns icons on or off, and forgets what was fetched when turning them off.
///
/// Deleting the cache matters: leaving it would keep a list of the domains in
/// this vault sitting in app data after the user asked for exactly that not to
/// exist.
#[tauri::command]
fn set_icons_enabled(state: State<'_, Arc<AppState>>, enabled: bool) -> CommandResult<()> {
    state.with_vault_mut(|vault| {
        vault.set_icons_enabled(enabled);
        Ok(())
    })?;
    if !enabled {
        let _ = std::fs::remove_dir_all(state.icon_cache_dir());
    }
    state.save()
}

// ---- billing -----------------------------------------------------------

/// A subscription as the interface reads it.
///
/// `paid_with` is resolved to a name here rather than in the frontend. The
/// interface would otherwise have to hold the card list to render one row, and
/// a card that has since been deleted would render as a bare uuid.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SubscriptionView {
    pub item_id: Uuid,
    pub item_name: String,
    pub plan: Option<String>,
    pub amount_minor: i64,
    pub currency: String,
    pub cadence: String,
    pub next_charge: Option<u64>,
    pub paid_with: Option<Uuid>,
    /// The card's name, or `None` if it points at something no longer here.
    pub paid_with_name: Option<String>,
    /// Cost per month in minor units; `None` for usage-based plans.
    pub monthly_minor: Option<i64>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SubscriptionInput {
    pub plan: Option<String>,
    pub amount_minor: i64,
    pub currency: String,
    pub cadence: Cadence,
    pub next_charge: Option<u64>,
    pub paid_with: Option<Uuid>,
}

fn view_of(
    item: &Item,
    cards: &std::collections::HashMap<Uuid, String>,
) -> Option<SubscriptionView> {
    let sub = item.subscription.as_ref()?;
    Some(SubscriptionView {
        item_id: item.id,
        item_name: item.name.clone(),
        plan: sub.plan.clone(),
        amount_minor: sub.amount_minor,
        currency: sub.currency.clone(),
        cadence: sub.cadence.as_str().to_string(),
        next_charge: sub.next_charge,
        paid_with: sub.paid_with,
        paid_with_name: sub.paid_with.and_then(|id| cards.get(&id).cloned()),
        monthly_minor: sub.monthly_minor(),
    })
}

/// Every subscription in the vault, soonest charge first.
#[tauri::command]
fn list_subscriptions(state: State<'_, Arc<AppState>>) -> CommandResult<Vec<SubscriptionView>> {
    state.with_vault(|vault| {
        let cards: std::collections::HashMap<Uuid, String> = vault
            .items()
            .iter()
            .filter(|item| item.kind == ItemKind::Card)
            .map(|item| (item.id, item.name.clone()))
            .collect();

        let mut views: Vec<SubscriptionView> = vault
            .items()
            .iter()
            .filter_map(|item| view_of(item, &cards))
            .collect();

        // Undated last rather than first. A charge with no date cannot be
        // planned around, so it belongs after everything that can.
        views.sort_by_key(|view| (view.next_charge.is_none(), view.next_charge));
        Ok(views)
    })
}

/// The subscription on one item, if it has one.
#[tauri::command]
fn item_subscription(
    state: State<'_, Arc<AppState>>,
    id: Uuid,
) -> CommandResult<Option<SubscriptionView>> {
    state.with_vault(|vault| {
        let cards: std::collections::HashMap<Uuid, String> = vault
            .items()
            .iter()
            .filter(|item| item.kind == ItemKind::Card)
            .map(|item| (item.id, item.name.clone()))
            .collect();

        Ok(vault.get(id).and_then(|item| view_of(item, &cards)))
    })
}

/// Attaches or replaces a subscription. `None` detaches it.
#[tauri::command]
fn set_subscription(
    state: State<'_, Arc<AppState>>,
    id: Uuid,
    subscription: Option<SubscriptionInput>,
) -> CommandResult<()> {
    let built = match subscription {
        None => None,
        Some(input) => {
            if input.amount_minor < 0 {
                return Err("an amount cannot be negative".into());
            }
            // Pointing at something that is not a card would render as a blank
            // row later, which reads as "no card" rather than "wrong card".
            if let Some(card) = input.paid_with {
                let ok = state.with_vault(|vault| {
                    Ok(vault
                        .get(card)
                        .is_some_and(|item| item.kind == ItemKind::Card))
                })?;
                if !ok {
                    return Err("that card is not in this vault".into());
                }
            }

            Some(Subscription {
                plan: input.plan.filter(|plan| !plan.trim().is_empty()),
                amount_minor: input.amount_minor,
                currency: input.currency.trim().to_uppercase(),
                cadence: input.cadence,
                next_charge: input.next_charge,
                paid_with: input.paid_with,
            })
        }
    };

    state.with_vault_mut(|vault| {
        let item = vault
            .get_mut(id)
            .ok_or_else(|| format!("item {id} not found"))?;
        item.subscription = built;
        item.updated_at = yara_core::unix_now();
        Ok(())
    })?;
    state.save()
}

// ---- auto-lock ---------------------------------------------------------

/// Idle seconds before the vault locks itself, or `None` for never.
#[tauri::command]
fn auto_lock_seconds(state: State<'_, Arc<AppState>>) -> CommandResult<Option<u64>> {
    state.with_vault(|vault| Ok(vault.auto_lock_seconds()))
}

/// Changes it, and writes the vault so the choice survives a restart.
///
/// The value is clamped rather than trusted. It arrives from the frontend and
/// ends up governing when a key is zeroized; a rounding error or a stray zero
/// should not be able to turn that into "immediately" or "in a decade".
#[tauri::command]
fn set_auto_lock_seconds(
    state: State<'_, Arc<AppState>>,
    seconds: Option<u64>,
) -> CommandResult<()> {
    let clamped = seconds.map(|value| value.clamp(30, 24 * 60 * 60));
    state.with_vault_mut(|vault| {
        vault.set_auto_lock_seconds(clamped);
        Ok(())
    })?;
    state.save()
}

// ---- import ------------------------------------------------------------

/// What an import would do, before it does any of it.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ImportPreview {
    /// Which parser recognised the file, so the interface can describe the
    /// plaintext it is asking the user to clean up afterwards.
    pub source: ImportSource,
    /// Commits the confirmation to the exact bytes that were reviewed. The
    /// export is read again at confirmation time, but a replacement file at
    /// the same path is refused rather than importing unseen contents.
    pub file_token: String,
    /// Editable, non-secret metadata only. No password, card number, note or
    /// seed crosses the IPC boundary: everything sensitive stays in the
    /// backend and goes straight into the encrypted vault.
    pub ready: Vec<ImportCandidate>,
    /// Already in the vault. Authenticator entries are matched by seed;
    /// password-manager items by their credential-bearing fields.
    pub duplicates: Vec<String>,
    pub skipped: Vec<ImportProblem>,
    /// Items that can be imported but have one recoverable part the user needs
    /// to inspect, such as a malformed TOTP URI.
    pub warnings: Vec<ImportProblem>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ImportCandidate {
    /// Position among the successfully parsed entries. It remains stable when
    /// malformed rows before it are skipped and lets equal names be edited
    /// independently.
    pub index: usize,
    pub name: String,
    pub folder: Option<String>,
}

#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum ImportSource {
    ProtonAuthenticator,
    ProtonPass,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ImportProblem {
    pub name: String,
    pub reason: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ImportEdit {
    pub index: usize,
    pub name: String,
    pub folder: Option<String>,
}

/// Reads an export and reports what it holds, importing nothing.
///
/// Separate from the write on purpose. The file contains plaintext secrets,
/// and a user is entitled to see what is about to enter their vault — and what
/// will be skipped — before it happens rather than after.
#[tauri::command]
fn preview_import(state: State<'_, Arc<AppState>>, path: String) -> CommandResult<ImportPreview> {
    let read = read_import(&path)?;
    match read.file {
        ImportFile::Authenticator(import) => {
            let mut existing = state.with_vault(|vault| {
                Ok(vault
                    .items()
                    .iter()
                    .filter_map(|item| item.totp.as_ref())
                    .map(|totp| totp.secret.expose().to_string())
                    .collect::<std::collections::HashSet<_>>())
            })?;
            let mut preview = ImportPreview {
                source: ImportSource::ProtonAuthenticator,
                file_token: read.file_token,
                ready: Vec::new(),
                duplicates: Vec::new(),
                skipped: problems(&import.skipped),
                warnings: Vec::new(),
            };

            for (index, entry) in import.entries.iter().enumerate() {
                if existing.insert(entry.totp.secret.expose().to_string()) {
                    preview.ready.push(ImportCandidate {
                        index,
                        name: entry.name.clone(),
                        folder: None,
                    });
                } else {
                    preview.duplicates.push(entry.name.clone());
                }
            }
            Ok(preview)
        }
        ImportFile::ProtonPass(import) => {
            // Clones keep the read lock short. SecretString's Debug output is
            // redacted and its equality is constant-time, so neither preview
            // nor duplicate detection discloses what it compares.
            let mut existing = state.with_vault(|vault| Ok(vault.items().to_vec()))?;
            let mut preview = ImportPreview {
                source: ImportSource::ProtonPass,
                file_token: read.file_token,
                ready: Vec::new(),
                duplicates: Vec::new(),
                skipped: problems(&import.skipped),
                warnings: problems(&import.warnings),
            };

            for (index, item) in import.entries.iter().enumerate() {
                if existing.iter().any(|held| same_import_item(held, item)) {
                    preview.duplicates.push(item.name.clone());
                } else {
                    preview.ready.push(ImportCandidate {
                        index,
                        name: item.name.clone(),
                        folder: item.folder.clone(),
                    });
                    // Also catches a duplicate repeated inside the CSV itself.
                    existing.push(item.clone());
                }
            }
            Ok(preview)
        }
    }
}

/// Writes everything the preview called ready.
#[tauri::command]
fn run_import(
    state: State<'_, Arc<AppState>>,
    path: String,
    expected_file_token: String,
    edits: Vec<ImportEdit>,
) -> CommandResult<usize> {
    let edits = checked_import_edits(edits)?;
    let read = read_import(&path)?;
    if read.file_token != expected_file_token {
        return Err(
            "that export changed after the preview; choose it again to review the current contents"
                .into(),
        );
    }

    let added = match read.file {
        ImportFile::Authenticator(import) => state.with_vault_mut(|vault| {
            let mut existing = vault
                .items()
                .iter()
                .filter_map(|item| item.totp.as_ref())
                .map(|totp| totp.secret.expose().to_string())
                .collect::<std::collections::HashSet<_>>();
            let mut added = 0;

            for (index, entry) in import.entries.into_iter().enumerate() {
                if !existing.insert(entry.totp.secret.expose().to_string()) {
                    continue;
                }
                let mut item = Item::new(entry.name);
                item.kind = ItemKind::Login;
                item.username = entry.totp.account.clone();
                item.notes = entry.note.map(Into::into);
                item.totp = Some(entry.totp);
                apply_import_edit(&mut item, index, &edits);
                vault.add(item);
                added += 1;
            }
            Ok(added)
        })?,
        ImportFile::ProtonPass(import) => state.with_vault_mut(|vault| {
            let mut added = 0;
            for (index, mut item) in import.entries.into_iter().enumerate() {
                apply_import_edit(&mut item, index, &edits);
                if vault
                    .items()
                    .iter()
                    .any(|held| same_import_item(held, &item))
                {
                    continue;
                }
                if let Some(folder) = item.folder.clone() {
                    vault.create_folder(folder);
                }
                vault.add(item);
                added += 1;
            }
            Ok(added)
        })?,
    };

    if added > 0 {
        state.save()?;
    }
    Ok(added)
}

fn checked_import_edits(
    edits: Vec<ImportEdit>,
) -> CommandResult<std::collections::HashMap<usize, ImportEdit>> {
    let mut checked = std::collections::HashMap::new();
    for mut edit in edits {
        edit.name = edit.name.trim().to_string();
        if edit.name.is_empty() {
            return Err("every imported item needs a name".into());
        }
        edit.folder = edit
            .folder
            .take()
            .and_then(|folder| (!folder.trim().is_empty()).then(|| folder.trim().to_string()));
        let index = edit.index;
        if checked.insert(index, edit).is_some() {
            return Err("the import contains the same edit more than once".into());
        }
    }
    Ok(checked)
}

fn apply_import_edit(
    item: &mut Item,
    index: usize,
    edits: &std::collections::HashMap<usize, ImportEdit>,
) {
    let Some(edit) = edits.get(&index) else {
        return;
    };
    item.name.clone_from(&edit.name);
    item.folder.clone_from(&edit.folder);
}

enum ImportFile {
    Authenticator(yara_core::Import),
    ProtonPass(yara_core::ItemImport),
}

struct ReadImport {
    file: ImportFile,
    file_token: String,
}

/// Detects the export by both extension and header. The header path means a
/// `.csv` renamed to `.txt` still imports, while an arbitrary text file cannot
/// be mistaken for a password export merely because of its name.
fn read_import(path: &str) -> CommandResult<ReadImport> {
    // The export is plaintext credentials. Wipe the complete input buffer as
    // soon as parsing finishes instead of waiting for allocator reuse.
    let text = zeroize::Zeroizing::new(
        std::fs::read_to_string(path).map_err(|_| "could not read that file".to_string())?,
    );
    let file_token = import_file_token(&text);
    let header = text
        .trim_start_matches('\u{feff}')
        .lines()
        .next()
        .unwrap_or_default();
    let csv_header =
        header.starts_with("type,") && header.split(',').any(|part| part == "password");
    let csv_extension = std::path::Path::new(path)
        .extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| extension.eq_ignore_ascii_case("csv"));

    if csv_header || csv_extension {
        let file = yara_core::from_proton_pass(&text)
            .map(ImportFile::ProtonPass)
            .map_err(to_message)?;
        return Ok(ReadImport { file, file_token });
    }

    let file = yara_core::from_proton_authenticator(&text)
        .map(ImportFile::Authenticator)
        .map_err(to_message)?;
    Ok(ReadImport { file, file_token })
}

fn import_file_token(text: &str) -> String {
    use sha2::Digest as _;
    format!("{:x}", sha2::Sha256::digest(text.as_bytes()))
}

fn problems(skipped: &[yara_core::Skipped]) -> Vec<ImportProblem> {
    skipped
        .iter()
        .map(|problem| ImportProblem {
            name: problem.name.clone(),
            reason: problem.reason.clone(),
        })
        .collect()
}

/// The identity of an imported credential, without ids, timestamps, notes or
/// filing choices. Re-importing the same export stays idempotent even after the
/// user moves an item or annotates it inside Yara. A note-only item has no
/// credential-bearing identity, so its encrypted note joins the comparison.
fn same_import_item(held: &Item, candidate: &Item) -> bool {
    let credential_bearing = candidate.username.is_some()
        || candidate.password.is_some()
        || candidate.url.is_some()
        || candidate.totp.is_some()
        || !candidate.fields.is_empty();

    held.name == candidate.name
        && held.kind == candidate.kind
        && held.username == candidate.username
        && held.password == candidate.password
        && held.url == candidate.url
        && held.totp == candidate.totp
        && held.fields == candidate.fields
        && (credential_bearing || held.notes == candidate.notes)
}

// ---- sync --------------------------------------------------------------

#[tauri::command]
fn sync_status(state: State<'_, Arc<AppState>>) -> CommandResult<sync::SyncStatus> {
    sync::status(&state)
}

/// Enrols this machine as a new account and returns the recovery kit.
///
/// The kit is shown once and never stored. It is the only path back into an
/// account, so the interface has to make the user acknowledge having it before
/// this screen can be closed.
#[tauri::command]
async fn sync_enrol(
    state: State<'_, Arc<AppState>>,
    base_url: String,
    invite: String,
    password: String,
    label: Option<String>,
) -> CommandResult<sync::RecoveryKit> {
    sync::enrol(Arc::clone(&state), base_url, invite, password, label).await
}

/// Joins an account this machine has never seen, with the recovery kit.
///
/// The other direction from `sync_enrol`: that one creates an account and hands
/// back a kit, this one consumes a kit somebody wrote down. Until it existed a
/// second machine could not join at all, and the kit the first machine printed
/// authorised nothing.
#[tauri::command]
async fn sync_join(
    state: State<'_, Arc<AppState>>,
    base_url: String,
    account_id: String,
    password: String,
    kit: String,
    label: Option<String>,
) -> CommandResult<sync::SyncReport> {
    sync::join(
        Arc::clone(&state),
        base_url,
        account_id,
        password,
        kit,
        label,
    )
    .await
}

#[tauri::command]
async fn sync_now(state: State<'_, Arc<AppState>>) -> CommandResult<sync::SyncReport> {
    sync::sync_now(Arc::clone(&state)).await
}

#[tauri::command]
fn sync_forget(state: State<'_, Arc<AppState>>) -> CommandResult<()> {
    sync::forget(&state)
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

    let app = builder
        .setup(|app| {
            let dir = app.path().app_data_dir()?;
            std::fs::create_dir_all(&dir)?;

            let state = Arc::new(AppState::new(dir.join("vault.yara")));
            app.manage(Arc::clone(&state));
            app.manage(Arc::new(SecretClipboard::platform()));
            app.manage(broker::start(app.handle(), state));
            Ok(())
        })
        // A reload must not leave the vault unlocked behind a screen that says
        // it is locked. See `lock_on_reload` for what that used to cost.
        .on_page_load(|webview, payload| {
            if !matches!(payload.event(), tauri::webview::PageLoadEvent::Started) {
                return;
            }
            let app = webview.app_handle();
            let unlocked = app
                .try_state::<Arc<AppState>>()
                .is_some_and(|state| lock_on_reload(&state));
            if unlocked {
                lock_everything(app);
            }
        })
        .invoke_handler(tauri::generate_handler![
            vault_exists,
            vault_startup,
            list_vaults,
            select_vault,
            choose_another_vault,
            remove_vault,
            recover_vault,
            is_unlocked,
            create_vault,
            unlock_vault,
            lock_vault,
            logout_vault,
            list_items,
            recent_items,
            vault_counts,
            add_item,
            update_item,
            item_extras,
            folders,
            create_folder,
            rename_folder,
            delete_folder,
            reorder_folders,
            set_item_folder,
            reorder_items,
            reveal_field,
            reveal_notes,
            delete_item,
            scan_qr_from_path,
            scan_qr_from_clipboard,
            clear_scanned_totp,
            reveal_password,
            totp_code,
            estimate_strength,
            generate_password,
            change_master_password,
            copy_secret,
            clear_clipboard,
            list_grants,
            revoke_grant,
            audit_entries,
            resolve_approval,
            icon_for,
            icons_enabled,
            set_icons_enabled,
            list_subscriptions,
            item_subscription,
            set_subscription,
            auto_lock_seconds,
            set_auto_lock_seconds,
            preview_import,
            run_import,
            sync_status,
            sync_enrol,
            sync_join,
            sync_now,
            sync_forget,
        ])
        .build(tauri::generate_context!())
        .expect("error while running tauri application");

    // Built rather than run outright so there is somewhere to answer the exit
    // event. A password copied thirty seconds before the window closes would
    // otherwise outlive the program that promised to take it off the
    // clipboard. Nothing here can help with a kill or a power cut — with
    // `panic = "abort"` there is no unwinding to hook either — but an ordinary
    // quit is the common case and it can be handled.
    app.run(|app, event| {
        if matches!(event, tauri::RunEvent::Exit) {
            lock_everything(app);
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    use yara_core::KdfParams;

    /// The cheapest parameters `yara-core` will open a vault with; these tests
    /// are not about the KDF.
    fn fast() -> KdfParams {
        KdfParams {
            memory_kib: yara_core::crypto::MIN_MEMORY_KIB,
            iterations: 1,
            parallelism: 1,
        }
    }

    fn state() -> AppState {
        AppState::new(
            std::env::temp_dir()
                .join(format!("yara-lib-{}", Uuid::new_v4()))
                .join("vault.yara"),
        )
    }

    #[test]
    fn a_reload_locks_a_vault_that_was_open() {
        let state = state();
        state.set_vault(UnlockedVault::create_with_params("master", fast()).unwrap());

        assert!(lock_on_reload(&state), "the reload interrupted a session");
        assert!(
            !state.is_unlocked(),
            "the vault must not stay open behind a screen that says it is locked"
        );
    }

    #[test]
    fn the_first_page_load_of_a_launch_has_nothing_to_lock() {
        // `on_page_load` fires for the first load too, and tearing down the
        // broker and wiping the clipboard on startup would be wrong.
        assert!(!lock_on_reload(&state()));
    }

    #[test]
    fn a_reload_after_a_lock_is_still_a_no_op() {
        let state = state();
        state.set_vault(UnlockedVault::create_with_params("master", fast()).unwrap());
        state.clear();

        assert!(!lock_on_reload(&state));
    }

    #[test]
    fn reimporting_a_credential_ignores_notes_and_filing_changes() {
        let mut held = Item::new("GitHub")
            .with_username("me")
            .with_password("hunter2");
        held.notes = Some("annotated inside Yara".into());
        held.folder = Some("Work".into());

        let mut incoming = Item::new("GitHub")
            .with_username("me")
            .with_password("hunter2");
        incoming.notes = Some("the old exported note".into());
        incoming.folder = Some("Proton".into());

        assert!(same_import_item(&held, &incoming));
    }

    #[test]
    fn a_changed_password_is_not_hidden_as_a_duplicate() {
        let held = Item::new("GitHub").with_username("me").with_password("old");
        let incoming = Item::new("GitHub").with_username("me").with_password("new");

        assert!(!same_import_item(&held, &incoming));
    }

    #[test]
    fn note_only_items_compare_their_encrypted_note() {
        let mut held = Item::new("Recovery codes").with_kind(ItemKind::Note);
        held.notes = Some("one two three".into());
        let mut same = Item::new("Recovery codes").with_kind(ItemKind::Note);
        same.notes = Some("one two three".into());
        let mut changed = Item::new("Recovery codes").with_kind(ItemKind::Note);
        changed.notes = Some("four five six".into());

        assert!(same_import_item(&held, &same));
        assert!(!same_import_item(&held, &changed));
    }

    #[test]
    fn import_edits_change_only_the_reviewable_metadata() {
        let edits = checked_import_edits(vec![ImportEdit {
            index: 4,
            name: "  Renamed login  ".into(),
            folder: Some("  Personal  ".into()),
        }])
        .unwrap();
        let mut item = Item::new("Original")
            .with_username("me")
            .with_password("still secret");

        apply_import_edit(&mut item, 4, &edits);

        assert_eq!(item.name, "Renamed login");
        assert_eq!(item.folder.as_deref(), Some("Personal"));
        assert_eq!(item.username.as_deref(), Some("me"));
        assert_eq!(item.password.as_ref().unwrap().expose(), "still secret");
    }

    #[test]
    fn an_import_edit_cannot_erase_the_name() {
        let result = checked_import_edits(vec![ImportEdit {
            index: 0,
            name: "   ".into(),
            folder: None,
        }]);

        assert!(result.is_err());
    }

    #[test]
    fn changing_the_export_changes_its_confirmation_token() {
        assert_ne!(
            import_file_token("the reviewed export"),
            import_file_token("a replacement export")
        );
    }
}
