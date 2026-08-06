//! The on-disk vault format and the in-memory unlocked vault.
//!
//! # Envelope encryption
//!
//! The master password never encrypts vault contents directly. Instead:
//!
//! ```text
//! master password --Argon2id--> master key (KEK) --wraps--> vault key (DEK) --encrypts--> items
//! ```
//!
//! Two properties fall out of this. Changing the master password only re-wraps
//! 32 bytes rather than rewriting every item, and the expensive KDF runs exactly
//! once per unlock.
//!
//! The KDF parameters and salt sit in the header in the clear — an existing
//! vault must stay openable after the defaults are raised. They are fed to the
//! AEAD as associated data, so an attacker who edits the header down to
//! `iterations = 1` gets an authentication failure rather than a cheaper attack.

use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;

use crate::crypto::{self, KdfParams, Key, Sealed, SALT_LEN};
use crate::error::{Error, Result};
use crate::secret::SecretString;
use crate::totp::TotpConfig;

/// Current on-disk format version.
pub const FORMAT_VERSION: u32 = 1;

/// Idle seconds before the vault locks itself, when nothing else is chosen.
const DEFAULT_AUTO_LOCK: u64 = 15 * 60;
const KDF_ALGORITHM: &str = "argon2id";

/// Plaintext header describing how the master key is derived.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct KdfHeader {
    pub algorithm: String,
    #[serde(with = "crate::b64")]
    pub salt: Vec<u8>,
    pub params: KdfParams,
}

/// The associated data bound into both ciphertexts.
///
/// Serialized as canonical JSON. Any edit to the format version or the KDF
/// header changes these bytes and therefore breaks authentication.
#[derive(Serialize)]
struct AssociatedData<'a> {
    format: u32,
    kdf: &'a KdfHeader,
}

fn associated_data(format: u32, kdf: &KdfHeader) -> Result<Vec<u8>> {
    Ok(serde_json::to_vec(&AssociatedData { format, kdf })?)
}

/// A vault as it exists on disk. Contains no plaintext beyond the KDF header.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VaultFile {
    pub format: u32,
    pub kdf: KdfHeader,
    /// The vault key, encrypted under the master key.
    pub wrapped_key: Sealed,
    /// The item list, encrypted under the vault key.
    pub payload: Sealed,
}

impl VaultFile {
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        Ok(serde_json::to_vec_pretty(self)?)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let file: Self = serde_json::from_slice(bytes)?;
        if file.format != FORMAT_VERSION {
            return Err(Error::UnsupportedFormat(file.format));
        }
        if file.kdf.algorithm != KDF_ALGORITHM {
            return Err(Error::UnsupportedKdf(file.kdf.algorithm.clone()));
        }
        Ok(file)
    }
}

/// What kind of thing an item is, which drives how the UI groups it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ItemKind {
    #[default]
    Login,
    Card,
    Note,
}

impl ItemKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Login => "login",
            Self::Card => "card",
            Self::Note => "note",
        }
    }
}

/// An extra field on an item, under a name of the user's choosing.
///
/// "Password" is not the only name a secret goes by. An API key, a PIN, a
/// recovery code and a second account password are all things people keep
/// beside a login, and forcing them into the notes field means they cannot be
/// copied cleanly or masked on screen.
///
/// The value is a [`SecretString`] whether or not `secret` is set — that costs
/// nothing and means a field promoted to secret later was never sitting in
/// plain memory. What `secret` decides is whether the value is masked on
/// screen, kept out of search, and withheld from listings.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Field {
    pub label: String,
    pub value: SecretString,
    #[serde(default)]
    pub secret: bool,
}

impl Field {
    pub fn new(label: impl Into<String>, value: impl Into<SecretString>) -> Self {
        Self {
            label: label.into(),
            value: value.into(),
            secret: false,
        }
    }

    pub fn secret(mut self) -> Self {
        self.secret = true;
        self
    }
}

/// One stored credential.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Item {
    pub id: Uuid,
    pub name: String,
    /// Defaulted so vaults written before kinds existed still load.
    #[serde(default)]
    pub kind: ItemKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<SecretString>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notes: Option<SecretString>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub totp: Option<TotpConfig>,
    /// Defaulted so vaults written before fields existed still load.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub fields: Vec<Field>,
    /// Which folder this item is filed in, or `None` for none.
    ///
    /// One folder, not many. Folders are where a thing lives; the many-valued
    /// version of that idea is a tag, and having both would ask the user to
    /// keep two mental models of the same vault.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub folder: Option<String>,
    /// Kept only to migrate vaults written when this was the organising idea.
    /// Read on open, folded into `folder`, and never written again.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
    /// What this login charges you, if it charges you.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subscription: Option<Subscription>,
    pub created_at: u64,
    pub updated_at: u64,
}

/// How often a subscription charges.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Cadence {
    #[default]
    Monthly,
    Yearly,
    /// Charged, but not on a schedule anyone can predict — metered usage, or
    /// a plan that bills when you cross a threshold.
    Usage,
}

impl Cadence {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Monthly => "monthly",
            Self::Yearly => "yearly",
            Self::Usage => "usage",
        }
    }
}

/// A recurring charge attached to a login.
///
/// An attachment rather than a kind of item, and the distinction is the whole
/// design: a charge with no account behind it is trivia a spreadsheet handles
/// better. What makes this belong in a password manager is `paid_with` — the
/// card it lands on is already here, so the vault can answer "if I cancel this
/// card, what breaks?"
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Subscription {
    /// What the plan is called, in the vendor's words.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub plan: Option<String>,
    /// Minor units — cents — so arithmetic on money never rounds.
    pub amount_minor: i64,
    /// ISO 4217, uppercased on the way in.
    pub currency: String,
    pub cadence: Cadence,
    /// Unix seconds of the next charge, when there is a date to know.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_charge: Option<u64>,
    /// The Card item this lands on.
    ///
    /// A pointer rather than a copy of the last four digits: a copy goes stale
    /// the moment the card is replaced, and the question worth answering is
    /// which stored card this is, not what it looked like once.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub paid_with: Option<Uuid>,
}

impl Subscription {
    /// What this costs in a month, in minor units.
    ///
    /// Yearly plans are spread rather than shown in the month they land, so a
    /// total means "what this costs to keep" rather than "what leaves the
    /// account in August". Usage-based plans return `None`: their amount is a
    /// guess, and adding a guess to a total makes the whole total a guess.
    pub fn monthly_minor(&self) -> Option<i64> {
        match self.cadence {
            Cadence::Monthly => Some(self.amount_minor),
            Cadence::Yearly => Some(self.amount_minor / 12),
            Cadence::Usage => None,
        }
    }
}

impl Item {
    pub fn new(name: impl Into<String>) -> Self {
        let now = unix_now();
        Self {
            id: Uuid::new_v4(),
            name: name.into(),
            kind: ItemKind::Login,
            username: None,
            password: None,
            url: None,
            notes: None,
            totp: None,
            fields: Vec::new(),
            folder: None,
            tags: Vec::new(),
            subscription: None,
            created_at: now,
            updated_at: now,
        }
    }

    pub fn with_kind(mut self, kind: ItemKind) -> Self {
        self.kind = kind;
        self
    }

    pub fn with_username(mut self, username: impl Into<String>) -> Self {
        self.username = Some(username.into());
        self
    }

    pub fn with_password(mut self, password: impl Into<SecretString>) -> Self {
        self.password = Some(password.into());
        self
    }

    pub fn with_url(mut self, url: impl Into<String>) -> Self {
        self.url = Some(url.into());
        self
    }

    pub fn with_totp(mut self, totp: TotpConfig) -> Self {
        self.totp = Some(totp);
        self
    }

    pub fn with_field(mut self, field: Field) -> Self {
        self.fields.push(field);
        self
    }

    /// True if `query` matches any non-secret field.
    ///
    /// Secret fields are never searched: a match would tell the caller something
    /// about a value they have not been granted.
    pub fn matches(&self, query: &str) -> bool {
        let query = query.trim().to_lowercase();
        if query.is_empty() {
            return true;
        }
        let haystacks = [
            Some(self.name.to_lowercase()),
            self.username.as_ref().map(|s| s.to_lowercase()),
            self.url.as_ref().map(|s| s.to_lowercase()),
        ];
        haystacks
            .iter()
            .flatten()
            .any(|field| field.contains(&query))
            || self
                .tags
                .iter()
                .any(|tag| tag.to_lowercase().contains(&query))
            // A field's label is always searchable — that is how you find the
            // item you filed an API key under. Its value is searchable only
            // when it is not a secret, for the same reason the password above
            // is absent from this list: a vault where typing a password finds
            // the item holding it is an oracle for anyone at the keyboard.
            || self.fields.iter().any(|field| {
                field.label.to_lowercase().contains(&query)
                    || (!field.secret && field.value.expose().to_lowercase().contains(&query))
            })
    }
}

/// Item counts by kind, for the sidebar.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VaultCounts {
    pub total: usize,
    pub logins: usize,
    pub cards: usize,
    pub notes: usize,
    /// Items carrying a second factor. Cuts across kinds rather than being one.
    pub authenticator: usize,
}

/// How many audit records a vault keeps before the oldest are dropped.
///
/// Bounded so the log cannot grow without limit inside a file that is
/// re-encrypted in full on every write.
const AUDIT_CAPACITY: usize = 500;

/// The decrypted contents of a vault.
///
/// Both fields default, so a vault written by an older build still opens: a
/// missing field reads as empty rather than as a corrupt file.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct VaultData {
    #[serde(default)]
    pub items: Vec<Item>,
    /// Audit records, oldest first, as opaque strings.
    ///
    /// Opaque on purpose. The schema belongs to `yara-broker`, which is the
    /// only thing that produces or reads one, and teaching the crypto core
    /// what an agent request looks like would buy nothing but a dependency
    /// pointing the wrong way.
    #[serde(default)]
    pub audit: Vec<String>,
    /// Where this machine syncs to, if it does. `None` until enrolled.
    #[serde(default)]
    pub sync: Option<SyncState>,
    /// Idle seconds before the vault locks itself, or `None` to never.
    ///
    /// Inside the vault rather than beside it, because how long this machine
    /// stays unlocked is a fact about the vault worth the same protection as
    /// the rest — and because a setting stored in the clear could be edited to
    /// `never` by anything running as the user.
    ///
    /// Absent in files written before the setting existed, which is why the
    /// accessor supplies the default rather than serde.
    #[serde(default)]
    pub auto_lock_seconds: Option<Option<u64>>,
    /// Whether to fetch site icons. Absent means never asked.
    #[serde(default)]
    pub icons_enabled: Option<bool>,
    /// Folder names, in the order the user put them.
    ///
    /// Stored rather than derived from the items, for two reasons: a folder
    /// has to be able to exist while empty, and the order is a decision the
    /// user made that nothing in the items records.
    #[serde(default)]
    pub folders: Vec<String>,
}

/// Folds a vault written when tags were the organising idea into folders.
///
/// Runs on every open and is idempotent: an item that already has a folder is
/// left alone, and tags are cleared once read so the next write drops them.
///
/// The first tag wins when there are several. Nothing in the old model said
/// which of an item's tags was the important one, so there is no better answer
/// than "the one it was given first" — and taking one is better than dropping
/// the item into no folder at all, which is what ignoring the field would do.
fn migrate_tags_into_folders(data: &mut VaultData) {
    for item in &mut data.items {
        if item.folder.is_none() {
            item.folder = item.tags.first().cloned();
        }
        item.tags.clear();
    }

    // Folders discovered this way still need an order, and the only one
    // available is the order the items themselves are in.
    for item in &data.items {
        if let Some(folder) = &item.folder {
            if !data.folders.contains(folder) {
                data.folders.push(folder.clone());
            }
        }
    }
}

/// What this machine needs to remember between syncs.
///
/// Lives in the vault because it identifies the account and carries the
/// device's signing seed — and because a vault that syncs should not need a
/// second file beside it that says where to.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SyncState {
    pub base_url: String,
    pub account_id: String,
    pub device_id: String,
    /// The device's Ed25519 seed, base64.
    ///
    /// Stored plainly *inside* the encrypted vault rather than wrapped again.
    /// The whole file is sealed under the vault key; a second wrapping under
    /// that same key would protect it from nobody who could not already read
    /// the first.
    pub device_seed: String,
    /// The newest revision this machine has seen.
    #[serde(default)]
    pub last_revision: i64,
    /// When the last sync finished, which is what tells a later one which
    /// items changed here in the meantime.
    #[serde(default)]
    pub last_synced_at: u64,
}

/// An open vault, holding the vault key in memory.
///
/// Dropping this wipes the key. The caller is responsible for dropping it on
/// lock, on idle timeout, and on process exit.
pub struct UnlockedVault {
    kdf: KdfHeader,
    wrapped_key: Sealed,
    vault_key: Key,
    data: VaultData,
}

/// Written by hand rather than derived: a derived implementation would print
/// every stored password the first time someone logs this struct.
impl std::fmt::Debug for UnlockedVault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UnlockedVault")
            .field("items", &self.data.items.len())
            .field("kdf", &self.kdf.params)
            .finish_non_exhaustive()
    }
}

impl UnlockedVault {
    /// Creates a brand new empty vault protected by `password`.
    pub fn create(password: &str) -> Result<Self> {
        Self::create_with_params(password, KdfParams::default())
    }

    pub fn create_with_params(password: &str, params: KdfParams) -> Result<Self> {
        let kdf = KdfHeader {
            algorithm: KDF_ALGORITHM.to_string(),
            salt: crypto::random_bytes(SALT_LEN),
            params,
        };

        let aad = associated_data(FORMAT_VERSION, &kdf)?;
        let master_key = crypto::derive_key(password.as_bytes(), &kdf.salt, params)?;
        let vault_key = Key::generate();
        let wrapped_key = crypto::seal(&master_key, vault_key.expose(), &aad)?;

        Ok(Self {
            kdf,
            wrapped_key,
            vault_key,
            data: VaultData::default(),
        })
    }

    /// Opens an existing vault.
    ///
    /// Returns [`Error::Decrypt`] for a wrong password and for a tampered file
    /// alike — the two are not distinguishable to the caller.
    pub fn open(file: &VaultFile, password: &str) -> Result<Self> {
        if file.format != FORMAT_VERSION {
            return Err(Error::UnsupportedFormat(file.format));
        }
        if file.kdf.algorithm != KDF_ALGORITHM {
            return Err(Error::UnsupportedKdf(file.kdf.algorithm.clone()));
        }

        let aad = associated_data(file.format, &file.kdf)?;
        let master_key = crypto::derive_key(password.as_bytes(), &file.kdf.salt, file.kdf.params)?;

        let vault_key_bytes = crypto::open(&master_key, &file.wrapped_key, &aad)?;
        let vault_key = Key::from_slice(&vault_key_bytes)?;

        let plaintext = crypto::open(&vault_key, &file.payload, &aad)?;
        let mut data: VaultData = serde_json::from_slice(&plaintext)?;
        migrate_tags_into_folders(&mut data);

        Ok(Self {
            kdf: file.kdf.clone(),
            wrapped_key: file.wrapped_key.clone(),
            vault_key,
            data,
        })
    }

    /// Re-encrypts the current contents into a serializable [`VaultFile`].
    pub fn seal(&self) -> Result<VaultFile> {
        let aad = associated_data(FORMAT_VERSION, &self.kdf)?;
        let plaintext = serde_json::to_vec(&self.data)?;
        let payload = crypto::seal(&self.vault_key, &plaintext, &aad)?;

        Ok(VaultFile {
            format: FORMAT_VERSION,
            kdf: self.kdf.clone(),
            wrapped_key: self.wrapped_key.clone(),
            payload,
        })
    }

    /// Changes the master password.
    ///
    /// Only the wrapped key is re-derived; items are untouched, so this is fast
    /// regardless of vault size. Call [`UnlockedVault::seal`] afterwards to
    /// persist — the new KDF header also changes the payload's associated data.
    pub fn change_password(&mut self, new_password: &str) -> Result<()> {
        let kdf = KdfHeader {
            algorithm: KDF_ALGORITHM.to_string(),
            salt: crypto::random_bytes(SALT_LEN),
            params: self.kdf.params,
        };

        let aad = associated_data(FORMAT_VERSION, &kdf)?;
        let master_key = crypto::derive_key(new_password.as_bytes(), &kdf.salt, kdf.params)?;
        let wrapped_key = crypto::seal(&master_key, self.vault_key.expose(), &aad)?;

        self.kdf = kdf;
        self.wrapped_key = wrapped_key;
        Ok(())
    }

    pub fn items(&self) -> &[Item] {
        &self.data.items
    }

    /// Item counts by kind, for the sidebar.
    pub fn counts(&self) -> VaultCounts {
        let items = &self.data.items;
        VaultCounts {
            total: items.len(),
            // A login is something you log in to, which means it has a
            // password. A bare two-factor seed has the Login kind only because
            // ItemKind has nowhere else to put it, and counting it here would
            // promise a row that the Logins list does not show.
            logins: items
                .iter()
                .filter(|i| i.kind == ItemKind::Login && i.password.is_some())
                .count(),
            cards: items.iter().filter(|i| i.kind == ItemKind::Card).count(),
            notes: items.iter().filter(|i| i.kind == ItemKind::Note).count(),
            // Not a kind — any item can carry a second factor.
            authenticator: items.iter().filter(|i| i.totp.is_some()).count(),
        }
    }

    /// The most recently updated items first.
    pub fn recent(&self, limit: usize) -> Vec<&Item> {
        let mut items: Vec<&Item> = self.data.items.iter().collect();
        items.sort_by_key(|item| std::cmp::Reverse(item.updated_at));
        items.truncate(limit);
        items
    }

    pub fn get(&self, id: Uuid) -> Option<&Item> {
        self.data.items.iter().find(|item| item.id == id)
    }

    /// The same item, to be edited in place.
    ///
    /// Callers are responsible for stamping `updated_at`. Doing it here would
    /// mark an item changed for a caller that only looked at it, and sync
    /// decides what to push by that timestamp.
    pub fn get_mut(&mut self, id: Uuid) -> Option<&mut Item> {
        self.data.items.iter_mut().find(|item| item.id == id)
    }

    /// Appends an audit record.
    ///
    /// Inside the vault rather than beside it, because a log naming every
    /// credential an agent touched is itself sensitive — writing it in the
    /// clear next to the file would describe the shape of a vault nobody
    /// could otherwise read.
    ///
    /// There is no hash chain over these. The file is authenticated as a
    /// whole, and anyone able to rewrite a record holds the key that would
    /// let them recompute a chain too, so one would prove nothing the AEAD
    /// does not already prove.
    pub fn record_audit(&mut self, payload: impl Into<String>) {
        self.data.audit.push(payload.into());

        // Drop from the front, so an entry that was written is never edited.
        if self.data.audit.len() > AUDIT_CAPACITY {
            let excess = self.data.audit.len() - AUDIT_CAPACITY;
            self.data.audit.drain(..excess);
        }
    }

    /// Audit records, oldest first.
    pub fn audit(&self) -> &[String] {
        &self.data.audit
    }

    /// The vault key itself, for wrapping under something else.
    ///
    /// There is exactly one caller and one reason: sync has to give a second
    /// machine the ability to read what this one wrote, which means wrapping
    /// this key under one derived from the password and the recovery kit.
    ///
    /// It is deliberately awkward to reach and never serialised. Anything else
    /// that wants it is almost certainly a mistake — the vault already offers
    /// sealing and opening, and a caller holding raw key bytes is a caller who
    /// can leak them.
    pub fn vault_key_bytes(&self) -> &[u8; crypto::KEY_LEN] {
        self.vault_key.expose()
    }

    /// Idle seconds before locking, or `None` to never.
    ///
    /// Fifteen minutes when the vault has never been asked. Long enough to
    /// read a page and come back, short enough that a walked-away-from desk
    /// does not stay open all afternoon.
    pub fn auto_lock_seconds(&self) -> Option<u64> {
        self.data
            .auto_lock_seconds
            .unwrap_or(Some(DEFAULT_AUTO_LOCK))
    }

    pub fn set_auto_lock_seconds(&mut self, seconds: Option<u64>) {
        self.data.auto_lock_seconds = Some(seconds);
    }

    /// Whether site icons are fetched. On unless turned off.
    ///
    /// A default worth stating: it means a fresh vault reaches the icon proxy
    /// the first time it shows a login. That is the trade every password
    /// manager with icons makes, and the setting is one click away.
    pub fn icons_enabled(&self) -> bool {
        self.data.icons_enabled.unwrap_or(true)
    }

    pub fn set_icons_enabled(&mut self, enabled: bool) {
        self.data.icons_enabled = Some(enabled);
    }

    pub fn sync_state(&self) -> Option<&SyncState> {
        self.data.sync.as_ref()
    }

    pub fn set_sync_state(&mut self, state: Option<SyncState>) {
        self.data.sync = state;
    }

    /// Seals one item for a server that must not be able to read it.
    ///
    /// Under the vault key, which never leaves this machine, so what travels
    /// is opaque to every hop between here and storage. The item id is the
    /// associated data: it is the one field the server *does* see, so binding
    /// it stops a ciphertext being replayed under a different id.
    pub fn seal_item(&self, item: &Item) -> Result<Sealed> {
        let plaintext = serde_json::to_vec(item)?;
        crypto::seal(&self.vault_key, &plaintext, item.id.as_bytes())
    }

    /// Opens an item that arrived from the server.
    ///
    /// The id is checked by the AEAD rather than after the fact: a record
    /// filed under one id whose contents claim another fails to decrypt at
    /// all, instead of being noticed later by code that might forget to look.
    pub fn open_item(&self, id: Uuid, sealed: &Sealed) -> Result<Item> {
        let plaintext = crypto::open(&self.vault_key, sealed, id.as_bytes())?;
        Ok(serde_json::from_slice(&plaintext)?)
    }

    /// Inserts or replaces an item wholesale, keeping its id.
    ///
    /// What applying a remote change amounts to. Separate from `add` because
    /// that one mints a new id, which is exactly wrong here.
    pub fn upsert(&mut self, item: Item) {
        match self.data.items.iter_mut().find(|held| held.id == item.id) {
            Some(existing) => *existing = item,
            None => self.data.items.push(item),
        }
    }

    pub fn search(&self, query: &str) -> Vec<&Item> {
        self.data
            .items
            .iter()
            .filter(|item| item.matches(query))
            .collect()
    }

    pub fn add(&mut self, item: Item) -> Uuid {
        let id = item.id;
        self.data.items.push(item);
        id
    }

    /// Applies `edit` to the item and bumps its `updated_at`.
    pub fn update(&mut self, id: Uuid, edit: impl FnOnce(&mut Item)) -> Result<()> {
        let item = self
            .data
            .items
            .iter_mut()
            .find(|item| item.id == id)
            .ok_or(Error::ItemNotFound(id))?;
        edit(item);
        item.updated_at = unix_now();
        Ok(())
    }

    pub fn folders(&self) -> &[String] {
        &self.data.folders
    }

    /// Creates a folder, or does nothing if one by that name exists.
    ///
    /// Returns whether it was new, so a caller can tell "created" from
    /// "already there" without comparing lengths.
    pub fn create_folder(&mut self, name: impl Into<String>) -> bool {
        let name = name.into();
        if name.trim().is_empty() || self.data.folders.contains(&name) {
            return false;
        }
        self.data.folders.push(name);
        true
    }

    /// Renames a folder and every item filed in it.
    ///
    /// Both halves or neither: an item pointing at a folder name that no
    /// longer exists is an item that has quietly left its folder.
    pub fn rename_folder(&mut self, from: &str, to: impl Into<String>) -> Result<()> {
        let to = to.into();
        if to.trim().is_empty() {
            return Err(Error::InvalidFolder("a folder needs a name".into()));
        }
        if self.data.folders.iter().any(|f| f == &to) {
            return Err(Error::InvalidFolder(format!("{to} already exists")));
        }
        let Some(slot) = self.data.folders.iter_mut().find(|f| f.as_str() == from) else {
            return Err(Error::InvalidFolder(format!("no folder called {from}")));
        };

        *slot = to.clone();
        for item in &mut self.data.items {
            if item.folder.as_deref() == Some(from) {
                item.folder = Some(to.clone());
                item.updated_at = unix_now();
            }
        }
        Ok(())
    }

    /// Removes a folder. Its items are not removed — they leave the folder.
    ///
    /// Deleting a container must never delete its contents. The folder is a
    /// filing decision; the credentials are the thing worth keeping, and a
    /// misclick on a folder cannot be allowed to cost them.
    pub fn delete_folder(&mut self, name: &str) -> usize {
        self.data.folders.retain(|f| f != name);
        let mut freed = 0;
        for item in &mut self.data.items {
            if item.folder.as_deref() == Some(name) {
                item.folder = None;
                item.updated_at = unix_now();
                freed += 1;
            }
        }
        freed
    }

    /// Reorders folders to match `names`.
    ///
    /// Anything the caller did not mention keeps its relative order at the
    /// end, so a stale list from a client that has not seen a new folder
    /// cannot delete it by omission.
    pub fn reorder_folders(&mut self, names: &[String]) {
        let mut ordered: Vec<String> = names
            .iter()
            .filter(|name| self.data.folders.contains(name))
            .cloned()
            .collect();
        for existing in &self.data.folders {
            if !ordered.contains(existing) {
                ordered.push(existing.clone());
            }
        }
        self.data.folders = ordered;
    }

    pub fn set_folder(&mut self, id: Uuid, folder: Option<String>) -> Result<()> {
        if let Some(name) = &folder {
            if !self.data.folders.contains(name) {
                return Err(Error::InvalidFolder(format!("no folder called {name}")));
            }
        }
        self.update(id, |item| item.folder = folder)
    }

    /// Reorders items to match `ids`, by the same rule as folders: what is not
    /// mentioned keeps its relative order at the end rather than disappearing.
    pub fn reorder_items(&mut self, ids: &[Uuid]) {
        let mut ordered: Vec<Item> = Vec::with_capacity(self.data.items.len());
        for id in ids {
            if let Some(at) = self.data.items.iter().position(|item| item.id == *id) {
                ordered.push(self.data.items.remove(at));
            }
        }
        ordered.append(&mut self.data.items);
        self.data.items = ordered;
    }

    pub fn remove(&mut self, id: Uuid) -> Result<Item> {
        let index = self
            .data
            .items
            .iter()
            .position(|item| item.id == id)
            .ok_or(Error::ItemNotFound(id))?;
        Ok(self.data.items.remove(index))
    }
}

/// Seconds since the Unix epoch.
pub fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Weak parameters keep the suite fast; production uses the defaults.
    fn fast() -> KdfParams {
        KdfParams {
            memory_kib: 8,
            iterations: 1,
            parallelism: 1,
        }
    }

    fn subscription(amount_minor: i64, cadence: Cadence) -> Subscription {
        Subscription {
            plan: None,
            amount_minor,
            currency: "USD".into(),
            cadence,
            next_charge: None,
            paid_with: None,
        }
    }

    #[test]
    fn a_yearly_plan_is_spread_across_the_year() {
        // A total should mean "what this costs to keep", not "what leaves the
        // account in the month it lands".
        assert_eq!(
            subscription(24_000, Cadence::Yearly).monthly_minor(),
            Some(2_000)
        );
        assert_eq!(
            subscription(1_500, Cadence::Monthly).monthly_minor(),
            Some(1_500)
        );
    }

    #[test]
    fn a_usage_plan_contributes_nothing_to_a_total() {
        // Its amount is a guess, and one guess makes the whole total a guess.
        assert_eq!(subscription(9_999, Cadence::Usage).monthly_minor(), None);
    }

    #[test]
    fn money_is_held_in_minor_units_so_it_does_not_drift() {
        // £9.99 a year is not a round number of pence a month. Storing pounds
        // as a float would accumulate error; integers just truncate once.
        let yearly = subscription(999, Cadence::Yearly);
        assert_eq!(yearly.monthly_minor(), Some(83));
    }

    #[test]
    fn a_subscription_survives_a_seal_and_open() {
        let mut vault = UnlockedVault::create_with_params("pw", fast()).unwrap();
        let card = vault.add(Item::new("Visa").with_kind(ItemKind::Card));

        let mut login = Item::new("GitHub");
        login.subscription = Some(Subscription {
            plan: Some("GitHub Pro".into()),
            amount_minor: 400,
            currency: "USD".into(),
            cadence: Cadence::Monthly,
            next_charge: Some(1_800_000_000),
            paid_with: Some(card),
        });
        let id = vault.add(login);

        let reopened = UnlockedVault::open(&vault.seal().unwrap(), "pw").unwrap();
        let sub = reopened.get(id).unwrap().subscription.as_ref().unwrap();

        assert_eq!(sub.plan.as_deref(), Some("GitHub Pro"));
        assert_eq!(sub.paid_with, Some(card));
    }

    #[test]
    fn an_item_without_a_subscription_writes_no_field() {
        // Most items have none. Serialising a null for each would grow every
        // vault for nothing.
        let item = Item::new("Plain");
        let json = serde_json::to_string(&item).unwrap();
        assert!(!json.contains("subscription"));
    }

    #[test]
    fn a_vault_written_before_subscriptions_still_opens() {
        let mut vault = UnlockedVault::create_with_params("pw", fast()).unwrap();
        vault.add(Item::new("Old"));
        let file = vault.seal().unwrap();

        // The field is absent from anything written by an earlier build; it
        // has to read as "no subscription" rather than as a corrupt file.
        let reopened = UnlockedVault::open(&file, "pw").unwrap();
        assert!(reopened.items()[0].subscription.is_none());
    }

    #[test]
    fn a_sealed_item_round_trips() {
        let vault = UnlockedVault::create_with_params("pw", fast()).unwrap();
        let mut item = Item::new("GitHub");
        item.password = Some("hunter2".into());

        let sealed = vault.seal_item(&item).unwrap();
        let recovered = vault.open_item(item.id, &sealed).unwrap();

        assert_eq!(recovered.name, "GitHub");
        assert_eq!(
            recovered.password.as_ref().map(|p| p.expose()),
            Some("hunter2")
        );
    }

    #[test]
    fn a_sealed_item_shows_the_server_nothing() {
        let vault = UnlockedVault::create_with_params("pw", fast()).unwrap();
        let mut item = Item::new("Stripe");
        item.password = Some("sk_live_do_not_leak".into());
        item.username = Some("billing@example.com".into());

        let wire = serde_json::to_string(&vault.seal_item(&item).unwrap()).unwrap();

        // Everything the server stores is in here, and none of it is readable.
        assert!(!wire.contains("Stripe"));
        assert!(!wire.contains("sk_live_do_not_leak"));
        assert!(!wire.contains("billing@example.com"));
    }

    #[test]
    fn an_item_cannot_be_refiled_under_another_id() {
        let vault = UnlockedVault::create_with_params("pw", fast()).unwrap();
        let item = Item::new("GitHub");
        let sealed = vault.seal_item(&item).unwrap();

        // The id is the associated data, so a server that swapped two records
        // produces a decryption failure rather than a silent mix-up.
        assert!(vault.open_item(Uuid::new_v4(), &sealed).is_err());
    }

    #[test]
    fn another_vault_cannot_open_the_item() {
        let mine = UnlockedVault::create_with_params("pw", fast()).unwrap();
        let theirs = UnlockedVault::create_with_params("pw", fast()).unwrap();

        let item = Item::new("GitHub");
        let sealed = mine.seal_item(&item).unwrap();
        assert!(theirs.open_item(item.id, &sealed).is_err());
    }

    #[test]
    fn upsert_replaces_rather_than_duplicating() {
        let mut vault = UnlockedVault::create_with_params("pw", fast()).unwrap();
        let mut item = Item::new("GitHub");
        vault.upsert(item.clone());

        item.name = "GitHub (work)".into();
        vault.upsert(item.clone());

        assert_eq!(vault.items().len(), 1);
        assert_eq!(vault.get(item.id).unwrap().name, "GitHub (work)");
    }

    #[test]
    fn sync_state_survives_a_seal_and_open() {
        let mut vault = UnlockedVault::create_with_params("pw", fast()).unwrap();
        assert!(vault.sync_state().is_none(), "a fresh vault does not sync");

        vault.set_sync_state(Some(SyncState {
            base_url: "https://yara.rindexx.cc".into(),
            account_id: "acct-1".into(),
            device_id: "dev-1".into(),
            device_seed: "c2VlZA==".into(),
            last_revision: 7,
            last_synced_at: 1_800_000_000,
        }));

        let file = vault.seal().unwrap();
        let reopened = UnlockedVault::open(&file, "pw").unwrap();
        let state = reopened.sync_state().unwrap();

        assert_eq!(state.account_id, "acct-1");
        assert_eq!(state.last_revision, 7);
    }

    #[test]
    fn the_device_seed_is_not_readable_in_the_file() {
        let mut vault = UnlockedVault::create_with_params("pw", fast()).unwrap();
        vault.set_sync_state(Some(SyncState {
            base_url: "https://yara.rindexx.cc".into(),
            account_id: "acct-1".into(),
            device_id: "dev-1".into(),
            device_seed: "c2VjcmV0LXNlZWQtaGVyZQ==".into(),
            last_revision: 0,
            last_synced_at: 0,
        }));

        // Stored plainly inside the vault, which is the whole point: the file
        // around it is what keeps it secret.
        let bytes = vault.seal().unwrap().to_bytes().unwrap();
        assert!(!String::from_utf8_lossy(&bytes).contains("c2VjcmV0LXNlZWQtaGVyZQ"));
    }

    fn vault_with_one_item(password: &str) -> UnlockedVault {
        let mut vault = UnlockedVault::create_with_params(password, fast()).unwrap();
        vault.add(
            Item::new("GitHub")
                .with_username("anthony")
                .with_password("correct horse battery staple")
                .with_url("https://github.com"),
        );
        vault
    }

    #[test]
    fn a_sealed_vault_reopens_with_the_right_password() {
        let vault = vault_with_one_item("master");
        let file = vault.seal().unwrap();

        let reopened = UnlockedVault::open(&file, "master").unwrap();
        assert_eq!(reopened.items().len(), 1);
        assert_eq!(reopened.items()[0].name, "GitHub");
        assert_eq!(
            reopened.items()[0].password.as_ref().unwrap().expose(),
            "correct horse battery staple"
        );
    }

    #[test]
    fn the_wrong_password_fails_to_open() {
        let file = vault_with_one_item("master").seal().unwrap();
        assert!(matches!(
            UnlockedVault::open(&file, "Master"),
            Err(Error::Decrypt)
        ));
    }

    #[test]
    fn the_serialized_file_leaks_no_plaintext() {
        let bytes = vault_with_one_item("master")
            .seal()
            .unwrap()
            .to_bytes()
            .unwrap();
        let text = String::from_utf8_lossy(&bytes);

        for secret in [
            "correct horse battery staple",
            "GitHub",
            "anthony",
            "github.com",
        ] {
            assert!(!text.contains(secret), "{secret:?} leaked into the file");
        }
    }

    #[test]
    fn the_file_round_trips_through_bytes() {
        let file = vault_with_one_item("master").seal().unwrap();
        let parsed = VaultFile::from_bytes(&file.to_bytes().unwrap()).unwrap();
        let reopened = UnlockedVault::open(&parsed, "master").unwrap();
        assert_eq!(reopened.items()[0].name, "GitHub");
    }

    #[test]
    fn downgrading_the_kdf_parameters_is_detected() {
        // Built with a real work factor so there is something to downgrade to.
        let costly = KdfParams {
            memory_kib: 64,
            iterations: 3,
            parallelism: 1,
        };
        let vault = UnlockedVault::create_with_params("master", costly).unwrap();
        let mut file = vault.seal().unwrap();

        // An attacker weakening the work factor to make brute force cheaper.
        file.kdf.params = KdfParams {
            memory_kib: 8,
            iterations: 1,
            parallelism: 1,
        };

        assert!(matches!(
            UnlockedVault::open(&file, "master"),
            Err(Error::Decrypt)
        ));
    }

    #[test]
    fn swapping_the_salt_is_detected() {
        let mut file = vault_with_one_item("master").seal().unwrap();
        file.kdf.salt = crypto::random_bytes(SALT_LEN);
        assert!(matches!(
            UnlockedVault::open(&file, "master"),
            Err(Error::Decrypt)
        ));
    }

    #[test]
    fn tampering_with_the_payload_is_detected() {
        let mut file = vault_with_one_item("master").seal().unwrap();
        file.payload.ciphertext[0] ^= 0x01;
        assert!(matches!(
            UnlockedVault::open(&file, "master"),
            Err(Error::Decrypt)
        ));
    }

    #[test]
    fn a_payload_from_another_vault_cannot_be_grafted_in() {
        let mut mine = vault_with_one_item("master").seal().unwrap();
        let theirs = vault_with_one_item("other").seal().unwrap();
        mine.payload = theirs.payload;

        assert!(matches!(
            UnlockedVault::open(&mine, "master"),
            Err(Error::Decrypt)
        ));
    }

    #[test]
    fn an_unknown_format_version_is_rejected() {
        let mut file = vault_with_one_item("master").seal().unwrap();
        file.format = 99;
        assert!(matches!(
            UnlockedVault::open(&file, "master"),
            Err(Error::UnsupportedFormat(99))
        ));
    }

    #[test]
    fn changing_the_password_keeps_the_contents_readable() {
        let mut vault = vault_with_one_item("old password");
        vault.change_password("new password").unwrap();
        let file = vault.seal().unwrap();

        let reopened = UnlockedVault::open(&file, "new password").unwrap();
        assert_eq!(
            reopened.items()[0].password.as_ref().unwrap().expose(),
            "correct horse battery staple"
        );
    }

    #[test]
    fn the_old_password_stops_working_after_a_change() {
        let mut vault = vault_with_one_item("old password");
        vault.change_password("new password").unwrap();
        let file = vault.seal().unwrap();

        assert!(matches!(
            UnlockedVault::open(&file, "old password"),
            Err(Error::Decrypt)
        ));
    }

    #[test]
    fn changing_the_password_does_not_change_the_vault_key() {
        // The point of the envelope: items are never re-encrypted, so the
        // wrapped key must still unwrap to the same DEK.
        let mut vault = vault_with_one_item("old password");
        let before = vault.seal().unwrap();
        vault.change_password("new password").unwrap();
        let after = vault.seal().unwrap();

        assert_ne!(before.kdf.salt, after.kdf.salt);
        assert_ne!(before.wrapped_key, after.wrapped_key);

        let a = UnlockedVault::open(&before, "old password").unwrap();
        let b = UnlockedVault::open(&after, "new password").unwrap();
        assert_eq!(a.vault_key.expose(), b.vault_key.expose());
    }

    #[test]
    fn sealing_twice_produces_different_ciphertext() {
        let vault = vault_with_one_item("master");
        let a = vault.seal().unwrap();
        let b = vault.seal().unwrap();
        assert_ne!(a.payload.ciphertext, b.payload.ciphertext);
    }

    #[test]
    fn items_can_be_added_updated_and_removed() {
        let mut vault = UnlockedVault::create_with_params("master", fast()).unwrap();
        let id = vault.add(Item::new("Example").with_username("me"));
        assert_eq!(vault.items().len(), 1);

        vault
            .update(id, |item| item.username = Some("someone else".into()))
            .unwrap();
        assert_eq!(
            vault.get(id).unwrap().username.as_deref(),
            Some("someone else")
        );

        let removed = vault.remove(id).unwrap();
        assert_eq!(removed.id, id);
        assert!(vault.items().is_empty());
    }

    #[test]
    fn updating_a_missing_item_reports_not_found() {
        let mut vault = UnlockedVault::create_with_params("master", fast()).unwrap();
        let missing = Uuid::new_v4();
        assert!(matches!(
            vault.update(missing, |_| {}),
            Err(Error::ItemNotFound(id)) if id == missing
        ));
    }

    #[test]
    fn search_matches_visible_fields_but_never_secrets() {
        let mut vault = UnlockedVault::create_with_params("master", fast()).unwrap();
        vault.add(
            Item::new("GitHub")
                .with_username("anthony")
                .with_password("zebra-secret")
                .with_url("https://github.com"),
        );

        assert_eq!(vault.search("git").len(), 1);
        assert_eq!(vault.search("ANTHONY").len(), 1);
        assert_eq!(vault.search("github.com").len(), 1);
        assert_eq!(vault.search("").len(), 1);

        // The password must not be reachable through search.
        assert_eq!(vault.search("zebra").len(), 0);
    }

    #[test]
    fn deleting_a_folder_keeps_everything_that_was_in_it() {
        // The rule worth writing down. A folder is a filing decision; the
        // credentials are the thing worth keeping, and a misclick on a
        // container must never cost its contents.
        let mut vault = UnlockedVault::create_with_params("master", fast()).unwrap();
        vault.create_folder("Work");
        let a = vault.add(Item::new("GitHub"));
        let b = vault.add(Item::new("Figma"));
        vault.set_folder(a, Some("Work".into())).unwrap();
        vault.set_folder(b, Some("Work".into())).unwrap();

        assert_eq!(vault.delete_folder("Work"), 2);
        assert_eq!(vault.items().len(), 2, "the items outlive the folder");
        assert!(vault.get(a).unwrap().folder.is_none());
        assert!(vault.folders().is_empty());
    }

    #[test]
    fn renaming_a_folder_carries_its_items_with_it() {
        let mut vault = UnlockedVault::create_with_params("master", fast()).unwrap();
        vault.create_folder("Wrok");
        let id = vault.add(Item::new("GitHub"));
        vault.set_folder(id, Some("Wrok".into())).unwrap();

        vault.rename_folder("Wrok", "Work").unwrap();

        assert_eq!(vault.folders(), ["Work"]);
        // The half that is easy to forget: an item still pointing at the old
        // name is an item that has quietly left its folder.
        assert_eq!(vault.get(id).unwrap().folder.as_deref(), Some("Work"));
    }

    #[test]
    fn reordering_never_loses_what_the_caller_did_not_mention() {
        // A client with a stale list must not be able to delete by omission.
        let mut vault = UnlockedVault::create_with_params("master", fast()).unwrap();
        let a = vault.add(Item::new("A"));
        let b = vault.add(Item::new("B"));
        let c = vault.add(Item::new("C"));

        vault.reorder_items(&[c, a]);

        let order: Vec<&str> = vault.items().iter().map(|i| i.name.as_str()).collect();
        assert_eq!(order, ["C", "A", "B"], "B keeps its place at the end");
        assert_eq!(vault.items().len(), 3);
        let _ = b;
    }

    #[test]
    fn a_vault_filed_by_tags_opens_filed_by_folders() {
        let mut vault = UnlockedVault::create_with_params("master", fast()).unwrap();
        let id = vault.add(Item::new("GitHub"));
        // Written the way an older build would have.
        vault.get_mut(id).unwrap().tags = vec!["Work".into(), "Ignored".into()];

        let file = vault.seal().unwrap();
        let reopened = UnlockedVault::open(&file, "master").unwrap();

        assert_eq!(reopened.get(id).unwrap().folder.as_deref(), Some("Work"));
        assert!(reopened.get(id).unwrap().tags.is_empty());
        assert_eq!(reopened.folders(), ["Work"], "and the folder exists");
    }

    #[test]
    fn a_secret_field_is_findable_by_its_label_but_never_by_its_value() {
        let item = Item::new("Stripe")
            .with_field(Field::new("Merchant ID", "acct_1M2n3O"))
            .with_field(Field::new("Restricted key", "rk_live_zebra").secret());

        // Labels are how you find the item you filed something under.
        assert!(item.matches("restricted"));
        assert!(item.matches("merchant"));

        // A plain field's value is fair game, the same as a username.
        assert!(item.matches("acct_1M2n3O"));

        // A secret's is not. Typing a secret and having the vault light up the
        // item holding it turns search into an oracle for whoever is at the
        // keyboard, which is the same reason `password` is not searched.
        assert!(!item.matches("rk_live_zebra"));
        assert!(!item.matches("zebra"));
    }

    #[test]
    fn fields_survive_the_round_trip() {
        let mut vault = UnlockedVault::create_with_params("master", fast()).unwrap();
        vault.add(
            Item::new("Stripe")
                .with_field(Field::new("Merchant ID", "acct_1M2n3O"))
                .with_field(Field::new("Restricted key", "rk_live_zebra").secret()),
        );

        let file = vault.seal().unwrap();
        let reopened = UnlockedVault::open(&file, "master").unwrap();
        let fields = &reopened.items()[0].fields;

        assert_eq!(fields.len(), 2);
        assert_eq!(fields[0].label, "Merchant ID");
        assert!(!fields[0].secret);
        assert_eq!(fields[1].value.expose(), "rk_live_zebra");
        assert!(fields[1].secret);
    }

    #[test]
    fn a_vault_written_before_fields_existed_still_opens() {
        // The guarantee `#[serde(default)]` is there to make. Kept as a test
        // because the failure mode is a vault that will not open, and nobody
        // finds that out until it is the only copy.
        let json = r#"{
            "id": "8f14e45f-ea1c-4f2a-9f2b-1c3d4e5f6a7b",
            "name": "GitHub",
            "username": "anthony",
            "created_at": 1,
            "updated_at": 1
        }"#;

        let item: Item = serde_json::from_str(json).unwrap();
        assert!(item.fields.is_empty());
        assert_eq!(item.name, "GitHub");
    }

    #[test]
    fn a_bare_two_factor_seed_is_not_counted_as_a_login() {
        // What arrives from an authenticator export: a name and a code, with
        // nothing to log in to. It takes ItemKind::Login because there is no
        // other variant, and it must not show up under Logins for that.
        let mut vault = UnlockedVault::create_with_params("master", fast()).unwrap();
        let totp = TotpConfig::new("GEZDGNBVGY3TQOJQ");

        vault.add(Item::new("Bank 2FA").with_totp(totp.clone()));
        vault.add(Item::new("GitHub").with_password("hunter2"));
        // Both at once is still a login: it is the password that decides.
        vault.add(
            Item::new("Fastmail")
                .with_password("hunter2")
                .with_totp(totp),
        );

        let counts = vault.counts();
        assert_eq!(counts.total, 3);
        assert_eq!(counts.logins, 2, "the bare seed is not a login");
        assert_eq!(counts.authenticator, 2, "but it does carry a code");
    }

    #[test]
    fn a_totp_enrollment_survives_the_round_trip() {
        let mut vault = UnlockedVault::create_with_params("master", fast()).unwrap();
        let totp = TotpConfig::from_uri(
            "otpauth://totp/GitHub:anthony?secret=GEZDGNBVGY3TQOJQ&issuer=GitHub",
        )
        .unwrap();
        vault.add(Item::new("GitHub").with_totp(totp.clone()));

        let file = vault.seal().unwrap();
        let reopened = UnlockedVault::open(&file, "master").unwrap();

        assert_eq!(reopened.items()[0].totp.as_ref().unwrap(), &totp);
        assert_eq!(
            reopened.items()[0]
                .totp
                .as_ref()
                .unwrap()
                .generate_at(59)
                .unwrap(),
            TotpConfig::new("GEZDGNBVGY3TQOJQ").generate_at(59).unwrap()
        );
    }

    #[test]
    fn an_empty_vault_round_trips() {
        let vault = UnlockedVault::create_with_params("master", fast()).unwrap();
        let file = vault.seal().unwrap();
        assert!(UnlockedVault::open(&file, "master")
            .unwrap()
            .items()
            .is_empty());
    }
}
