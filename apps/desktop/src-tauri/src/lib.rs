//! Tauri bindings over `yara-core`.
//!
//! The frontend never receives a secret as part of normal data flow. Listing
//! items returns [`ItemSummary`], which has no password field at all, so there
//! is no way to leak one by accident into a render, a log, or devtools. Getting
//! a plaintext value requires an explicit, separate call for one named item.

mod broker;
mod state;
mod sync;

use std::sync::Arc;

use broker::BrokerHandle;
use serde::{Deserialize, Serialize};
use state::AppState;
use tauri::{Manager, State};
use uuid::Uuid;
use yara_core::{
    Cadence, Item, ItemKind, Strength, Subscription, TotpConfig, UnlockedVault, VaultCounts,
    VaultFile,
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
            tags: item.tags.clone(),
            has_password: item.password.is_some(),
            has_totp: item.totp.is_some(),
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
                Some(ItemKind::Login) => {
                    item.kind == ItemKind::Login && item.password.is_some()
                }
                Some(wanted) => item.kind == wanted,
                None => true,
            })
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

// ---- icons -------------------------------------------------------------

/// Where icons are fetched from when this vault has no sync server of its own.
const DEFAULT_ICON_ORIGIN: &str = "https://yara.rindexx.cc";

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
    /// Names only. No seed crosses the IPC boundary at any point: the codes
    /// are parsed, held in the backend, and written straight into the vault.
    pub ready: Vec<String>,
    /// Already in the vault, matched by seed. Importing twice should not leave
    /// two items generating the same code — the authenticator screen becomes
    /// a guessing game about which one is real.
    pub duplicates: Vec<String>,
    pub skipped: Vec<ImportProblem>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ImportProblem {
    pub name: String,
    pub reason: String,
}

/// Reads an export and reports what it holds, importing nothing.
///
/// Separate from the write on purpose. The file is plaintext seeds, and a
/// user is entitled to see what is about to enter their vault — and what will
/// be skipped — before it happens rather than after.
#[tauri::command]
fn preview_import(state: State<'_, Arc<AppState>>, path: String) -> CommandResult<ImportPreview> {
    let (import, existing) = read_import(&state, &path)?;

    let mut preview = ImportPreview {
        ready: Vec::new(),
        duplicates: Vec::new(),
        skipped: import
            .skipped
            .iter()
            .map(|skip| ImportProblem {
                name: skip.name.clone(),
                reason: skip.reason.clone(),
            })
            .collect(),
    };

    for entry in &import.entries {
        if existing.contains(entry.totp.secret.expose()) {
            preview.duplicates.push(entry.name.clone());
        } else {
            preview.ready.push(entry.name.clone());
        }
    }

    Ok(preview)
}

/// Writes everything the preview called ready.
#[tauri::command]
fn run_import(state: State<'_, Arc<AppState>>, path: String) -> CommandResult<usize> {
    let (import, existing) = read_import(&state, &path)?;

    let mut added = 0;
    for entry in import.entries {
        if existing.contains(entry.totp.secret.expose()) {
            continue;
        }

        let mut item = Item::new(entry.name);
        item.kind = ItemKind::Login;
        item.username = entry.totp.account.clone();
        item.notes = entry.note.map(Into::into);
        item.totp = Some(entry.totp);

        state.with_vault_mut(|vault| Ok(vault.add(item)))?;
        added += 1;
    }

    if added > 0 {
        state.save()?;
    }
    Ok(added)
}

/// Parses the file and collects the seeds already held, so both commands agree
/// on what counts as a duplicate.
fn read_import(
    state: &AppState,
    path: &str,
) -> CommandResult<(yara_core::Import, std::collections::HashSet<String>)> {
    let text = std::fs::read_to_string(path).map_err(|_| "could not read that file".to_string())?;
    let import = yara_core::from_proton_authenticator(&text).map_err(to_message)?;

    let existing = state.with_vault(|vault| {
        Ok(vault
            .items()
            .iter()
            .filter_map(|item| item.totp.as_ref())
            .map(|totp| totp.secret.expose().to_string())
            .collect::<std::collections::HashSet<_>>())
    })?;

    Ok((import, existing))
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
            sync_now,
            sync_forget,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
