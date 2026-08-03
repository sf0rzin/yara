//! Process-wide vault state and durable writes.

use std::path::{Path, PathBuf};
use std::sync::Mutex;

use yara_core::{TotpConfig, UnlockedVault};

/// Holds the unlocked vault, if there is one.
///
/// Locking is just dropping the [`UnlockedVault`], which zeroizes the vault key.
pub struct AppState {
    vault_path: PathBuf,
    vault: Mutex<Option<UnlockedVault>>,
    /// A scanned enrollment waiting to be attached to an item being created.
    ///
    /// Parked here rather than handed to the frontend so the shared secret from
    /// a QR code never becomes a JavaScript string. The interface gets a
    /// description of it and a reference by absence: "use what was scanned".
    pending_totp: Mutex<Option<TotpConfig>>,
}

impl AppState {
    pub fn new(vault_path: PathBuf) -> Self {
        Self {
            vault_path,
            vault: Mutex::new(None),
            pending_totp: Mutex::new(None),
        }
    }

    pub fn set_pending_totp(&self, totp: TotpConfig) {
        if let Ok(mut guard) = self.pending_totp.lock() {
            *guard = Some(totp);
        }
    }

    /// Removes and returns the scanned enrollment, if any.
    pub fn take_pending_totp(&self) -> Option<TotpConfig> {
        self.pending_totp.lock().ok().and_then(|mut g| g.take())
    }

    pub fn clear_pending_totp(&self) {
        if let Ok(mut guard) = self.pending_totp.lock() {
            *guard = None;
        }
    }

    pub fn vault_path(&self) -> &Path {
        &self.vault_path
    }

    pub fn is_unlocked(&self) -> bool {
        self.vault
            .lock()
            .map(|guard| guard.is_some())
            .unwrap_or(false)
    }

    pub fn set_vault(&self, vault: UnlockedVault) {
        if let Ok(mut guard) = self.vault.lock() {
            *guard = Some(vault);
        }
    }

    /// Locks the vault, dropping and thereby wiping the key.
    ///
    /// Also discards any scanned enrollment: a secret left parked here across a
    /// lock would outlive the vault key it was going to be stored under.
    pub fn clear(&self) {
        if let Ok(mut guard) = self.vault.lock() {
            *guard = None;
        }
        self.clear_pending_totp();
    }

    pub fn with_vault<T>(
        &self,
        f: impl FnOnce(&UnlockedVault) -> Result<T, String>,
    ) -> Result<T, String> {
        let guard = self.vault.lock().map_err(|_| poisoned())?;
        let vault = guard.as_ref().ok_or_else(locked)?;
        f(vault)
    }

    pub fn with_vault_mut<T>(
        &self,
        f: impl FnOnce(&mut UnlockedVault) -> Result<T, String>,
    ) -> Result<T, String> {
        let mut guard = self.vault.lock().map_err(|_| poisoned())?;
        let vault = guard.as_mut().ok_or_else(locked)?;
        f(vault)
    }

    /// Re-encrypts and writes the currently unlocked vault.
    pub fn save(&self) -> Result<(), String> {
        let guard = self.vault.lock().map_err(|_| poisoned())?;
        let vault = guard.as_ref().ok_or_else(locked)?;
        self.persist(vault)
    }

    /// Writes `vault` to disk without going through the lock.
    ///
    /// The write is staged through a temporary file and the previous vault is
    /// kept as `.bak`, so an interrupted write cannot leave the user with a
    /// truncated file and no way back into their passwords.
    pub fn persist(&self, vault: &UnlockedVault) -> Result<(), String> {
        let file = vault.seal().map_err(|e| e.to_string())?;
        let bytes = file.to_bytes().map_err(|e| e.to_string())?;

        let temp = self.vault_path.with_extension("yara.tmp");
        std::fs::write(&temp, &bytes).map_err(|e| e.to_string())?;

        if self.vault_path.exists() {
            let backup = self.vault_path.with_extension("yara.bak");
            let _ = std::fs::remove_file(&backup);
            std::fs::rename(&self.vault_path, &backup).map_err(|e| e.to_string())?;
        }

        std::fs::rename(&temp, &self.vault_path).map_err(|e| e.to_string())
    }
}

fn locked() -> String {
    "the vault is locked".to_string()
}

fn poisoned() -> String {
    "vault state is unavailable".to_string()
}
