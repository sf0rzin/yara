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
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
    pub created_at: u64,
    pub updated_at: u64,
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
            tags: Vec::new(),
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

/// The decrypted contents of a vault.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct VaultData {
    #[serde(default)]
    pub items: Vec<Item>,
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
        let data: VaultData = serde_json::from_slice(&plaintext)?;

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
            logins: items.iter().filter(|i| i.kind == ItemKind::Login).count(),
            cards: items.iter().filter(|i| i.kind == ItemKind::Card).count(),
            notes: items.iter().filter(|i| i.kind == ItemKind::Note).count(),
            // Not a kind — any item can carry a second factor.
            authenticator: items.iter().filter(|i| i.totp.is_some()).count(),
        }
    }

    /// Audits the vault's passwords. See [`crate::health`].
    pub fn health(&self) -> crate::health::VaultHealth {
        crate::health::audit(&self.data.items)
    }

    /// The most recently updated items first.
    pub fn recent(&self, limit: usize) -> Vec<&Item> {
        let mut items: Vec<&Item> = self.data.items.iter().collect();
        items.sort_by(|a, b| b.updated_at.cmp(&a.updated_at));
        items.truncate(limit);
        items
    }

    pub fn get(&self, id: Uuid) -> Option<&Item> {
        self.data.items.iter().find(|item| item.id == id)
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

fn unix_now() -> u64 {
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
