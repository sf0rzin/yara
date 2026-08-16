//! Cryptographic core for yara.
//!
//! This crate knows nothing about Tauri, the UI, or the filesystem. It takes
//! bytes and passwords and returns bytes, which keeps the security-critical code
//! small enough to audit and testable without a running application.
//!
//! ```
//! use yara_core::{Item, UnlockedVault, VaultFile};
//!
//! let mut vault = UnlockedVault::create("master password")?;
//! vault.add(Item::new("GitHub").with_username("anthony").with_password("hunter2"));
//!
//! let bytes = vault.seal()?.to_bytes()?;
//!
//! let reopened = UnlockedVault::open(&VaultFile::from_bytes(&bytes)?, "master password")?;
//! assert_eq!(reopened.items()[0].name, "GitHub");
//! # Ok::<(), yara_core::Error>(())
//! ```

#![forbid(unsafe_code)]
#![warn(missing_debug_implementations)]

pub mod account;
pub mod crypto;
mod csv;
pub mod error;
pub mod health;
pub mod import;
pub mod qr;
pub mod secret;
pub mod totp;
pub mod vault;

pub use account::{AccountKeypair, AccountKeys, SecretKey};
pub use crypto::{KdfParams, Key, Sealed};
pub use error::{Error, Result};
pub use health::Strength;
pub use import::{
    from_bitwarden_csv, from_chrome_csv, from_csv, from_proton_authenticator, Import, Imported,
    Skipped,
};
pub use qr::decode_enrollment;
pub use secret::SecretString;
pub use totp::{TotpAlgorithm, TotpConfig};
pub use vault::unix_now;
pub use vault::{
    Cadence, Field, Item, ItemKind, KdfHeader, Subscription, SyncState, Tombstone, UnlockedVault,
    VaultCounts, VaultData, VaultFile, FORMAT_VERSION,
};

/// Serde helper that stores byte arrays as base64 strings, so a vault file stays
/// readable enough to inspect and diff.
pub(crate) mod b64 {
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine as _;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&STANDARD.encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<u8>, D::Error> {
        let encoded = String::deserialize(deserializer)?;
        STANDARD.decode(encoded).map_err(serde::de::Error::custom)
    }
}
