//! Process-wide vault state and durable writes.

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use serde::Serialize;
use yara_core::{TotpConfig, UnlockedVault, VaultFile};

/// What the app should put on screen when it starts.
///
/// Three states rather than the boolean `vault_exists` used to answer with,
/// because the missing third one was being read as the first: after a save was
/// interrupted there was no file at the live path, the app offered first-run
/// setup, and creating a vault there overwrote the only surviving copy on the
/// next save.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum Startup {
    /// Nothing here at all. First run.
    Setup,
    /// A vault is there. Ask for the password.
    Locked,
    /// No vault at the live path, but a copy of one beside it. Offer to put it
    /// back; do not offer to replace it.
    Recover,
}

/// Reads the three paths and says which of the three situations this is.
///
/// A free function taking the live path so it can be tested against a
/// directory rather than against an [`AppState`], which owns a mutex and a
/// vault key it does not need for this.
pub fn startup_for(vault_path: &Path) -> Startup {
    if vault_path.exists() {
        return Startup::Locked;
    }
    if backup_of(vault_path).exists() || temp_of(vault_path).exists() {
        return Startup::Recover;
    }
    Startup::Setup
}

fn backup_of(vault_path: &Path) -> PathBuf {
    vault_path.with_extension("yara.bak")
}

fn temp_of(vault_path: &Path) -> PathBuf {
    vault_path.with_extension("yara.tmp")
}

/// Writes `bytes` to `path` and does not return until they are on the disk.
///
/// The fsync is the point. Without it a rename can land while the bytes it
/// points at are still in the page cache, so a machine that loses power
/// between the two comes back with a live path naming an empty file.
fn write_durably(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let mut file = std::fs::File::create(path).map_err(|e| e.to_string())?;
    file.write_all(bytes).map_err(|e| e.to_string())?;
    file.sync_all().map_err(|e| e.to_string())
}

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

    /// Where fetched icons live: beside the vault, not inside it.
    ///
    /// Outside the encrypted file on purpose. They are public images, they
    /// would bloat a payload that is rewritten in full on every save, and the
    /// setting that disables them deletes this directory outright.
    pub fn icon_cache_dir(&self) -> std::path::PathBuf {
        self.vault_path()
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .join("icons")
    }

    pub fn vault_path(&self) -> &Path {
        &self.vault_path
    }

    /// Which of the three startup situations this machine is in.
    pub fn startup(&self) -> Startup {
        startup_for(&self.vault_path)
    }

    /// Puts a surviving copy back at the live path.
    ///
    /// The temporary file is tried first: it is the newer of the two by
    /// construction, being the write that was interrupted. It is also the only
    /// one that can be half-written, which is why it has to parse as a vault
    /// before it is trusted — a truncated JSON document does not.
    ///
    /// The candidate is copied rather than moved, so an interruption during
    /// recovery still leaves something to recover from next time.
    pub fn recover(&self) -> Result<(), String> {
        if self.vault_path.exists() {
            return Err("there is already a vault here".into());
        }

        for candidate in [temp_of(&self.vault_path), backup_of(&self.vault_path)] {
            let Ok(bytes) = std::fs::read(&candidate) else {
                continue;
            };
            if VaultFile::from_bytes(&bytes).is_err() {
                continue;
            }
            return write_durably(&self.vault_path, &bytes);
        }

        Err("there is nothing here to recover".into())
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
    /// The order matters more than it looks. This used to delete the backup,
    /// rename the live file onto it, and then rename the temporary file into
    /// place — which left a window two syscalls wide with no file at the live
    /// path at all. A process death inside that window made the app believe
    /// there was no vault, so it offered first-run setup, and the vault
    /// created there deleted the last surviving copy on its own first save.
    ///
    /// So: the temporary file is written and fsynced, the live file is
    /// **copied** to `.bak` rather than moved, and only then is the temporary
    /// file renamed over the live path. Rename is atomic here — Windows
    /// implements it as `MoveFileEx` with `MOVEFILE_REPLACE_EXISTING` — so at
    /// every instant `vault.yara` is a complete vault, either the old one or
    /// the new one.
    pub fn persist(&self, vault: &UnlockedVault) -> Result<(), String> {
        let file = vault.seal().map_err(|e| e.to_string())?;
        let bytes = file.to_bytes().map_err(|e| e.to_string())?;

        let temp = temp_of(&self.vault_path);
        write_durably(&temp, &bytes)?;

        if self.vault_path.exists() {
            let backup = backup_of(&self.vault_path);
            std::fs::copy(&self.vault_path, &backup).map_err(|e| e.to_string())?;
            // A backup still in the page cache is not a backup. `fs::copy`
            // makes no promise about that, so ask for one.
            std::fs::OpenOptions::new()
                .write(true)
                .open(&backup)
                .and_then(|file| file.sync_all())
                .map_err(|e| e.to_string())?;
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

#[cfg(test)]
mod tests {
    use super::*;

    use yara_core::{Item, KdfParams};

    /// The cheapest parameters `yara-core` will open a vault with. These tests
    /// are about file layout, and paying for two production derivations each
    /// would make them slow enough that nobody runs them.
    fn fast() -> KdfParams {
        KdfParams {
            memory_kib: yara_core::crypto::MIN_MEMORY_KIB,
            iterations: 1,
            parallelism: 1,
        }
    }

    /// A directory of its own per test, so two running at once cannot see each
    /// other's vault.
    struct Scratch(PathBuf);

    impl Scratch {
        fn new() -> Self {
            let dir = std::env::temp_dir().join(format!("yara-state-{}", uuid::Uuid::new_v4()));
            std::fs::create_dir_all(&dir).unwrap();
            Self(dir)
        }

        fn vault_path(&self) -> PathBuf {
            self.0.join("vault.yara")
        }

        fn state(&self) -> AppState {
            AppState::new(self.vault_path())
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn vault(name: &str) -> UnlockedVault {
        let mut vault = UnlockedVault::create_with_params("master", fast()).unwrap();
        vault.add(Item::new(name).with_password("hunter2"));
        vault
    }

    #[test]
    fn an_empty_directory_asks_for_setup() {
        let scratch = Scratch::new();
        assert_eq!(startup_for(&scratch.vault_path()), Startup::Setup);
    }

    #[test]
    fn a_vault_that_is_there_asks_for_the_password() {
        let scratch = Scratch::new();
        scratch.state().persist(&vault("GitHub")).unwrap();
        assert_eq!(startup_for(&scratch.vault_path()), Startup::Locked);
    }

    #[test]
    fn a_missing_vault_with_a_backup_beside_it_offers_recovery() {
        // The state an interrupted save used to leave behind, and the one the
        // app read as "no vault, offer to make one".
        let scratch = Scratch::new();
        let state = scratch.state();
        state.persist(&vault("GitHub")).unwrap();
        state.persist(&vault("GitHub")).unwrap();
        std::fs::remove_file(scratch.vault_path()).unwrap();

        assert_eq!(startup_for(&scratch.vault_path()), Startup::Recover);
    }

    #[test]
    fn a_missing_vault_with_only_a_temporary_file_offers_recovery() {
        let scratch = Scratch::new();
        std::fs::write(temp_of(&scratch.vault_path()), b"{}").unwrap();
        assert_eq!(startup_for(&scratch.vault_path()), Startup::Recover);
    }

    #[test]
    fn a_save_leaves_the_live_file_and_no_temporary_one() {
        let scratch = Scratch::new();
        scratch.state().persist(&vault("GitHub")).unwrap();

        assert!(scratch.vault_path().exists());
        assert!(
            !temp_of(&scratch.vault_path()).exists(),
            "the staging file must not survive a completed save"
        );
    }

    #[test]
    fn the_backup_holds_what_the_live_file_held_before() {
        let scratch = Scratch::new();
        let state = scratch.state();

        state.persist(&vault("first")).unwrap();
        state.persist(&vault("second")).unwrap();

        let backup = std::fs::read(backup_of(&scratch.vault_path())).unwrap();
        let opened =
            UnlockedVault::open(&VaultFile::from_bytes(&backup).unwrap(), "master").unwrap();
        assert_eq!(opened.items()[0].name, "first");
    }

    #[test]
    fn recovery_puts_the_backup_back() {
        let scratch = Scratch::new();
        let state = scratch.state();
        state.persist(&vault("first")).unwrap();
        state.persist(&vault("second")).unwrap();
        std::fs::remove_file(scratch.vault_path()).unwrap();

        state.recover().unwrap();

        assert_eq!(startup_for(&scratch.vault_path()), Startup::Locked);
        let bytes = std::fs::read(scratch.vault_path()).unwrap();
        let opened =
            UnlockedVault::open(&VaultFile::from_bytes(&bytes).unwrap(), "master").unwrap();
        assert_eq!(opened.items()[0].name, "first");
    }

    #[test]
    fn a_half_written_temporary_file_is_not_recovered_over_a_good_backup() {
        // The temporary file is preferred because it is newer, but it is also
        // the one that can be a partial write. It has to parse as a vault
        // before it is trusted.
        let scratch = Scratch::new();
        let state = scratch.state();
        state.persist(&vault("first")).unwrap();
        state.persist(&vault("second")).unwrap();
        std::fs::remove_file(scratch.vault_path()).unwrap();
        std::fs::write(temp_of(&scratch.vault_path()), b"{\"format\":1,\"kdf\"").unwrap();

        state.recover().unwrap();

        let bytes = std::fs::read(scratch.vault_path()).unwrap();
        let opened =
            UnlockedVault::open(&VaultFile::from_bytes(&bytes).unwrap(), "master").unwrap();
        assert_eq!(opened.items()[0].name, "first");
    }

    #[test]
    fn recovery_prefers_the_newer_temporary_file_when_it_is_whole() {
        let scratch = Scratch::new();
        let state = scratch.state();
        state.persist(&vault("first")).unwrap();
        state.persist(&vault("second")).unwrap();
        std::fs::remove_file(scratch.vault_path()).unwrap();

        let newer = vault("third").seal().unwrap().to_bytes().unwrap();
        std::fs::write(temp_of(&scratch.vault_path()), &newer).unwrap();

        state.recover().unwrap();

        let bytes = std::fs::read(scratch.vault_path()).unwrap();
        let opened =
            UnlockedVault::open(&VaultFile::from_bytes(&bytes).unwrap(), "master").unwrap();
        assert_eq!(opened.items()[0].name, "third");
    }

    #[test]
    fn recovery_refuses_to_overwrite_a_vault_that_is_there() {
        let scratch = Scratch::new();
        let state = scratch.state();
        state.persist(&vault("first")).unwrap();
        state.persist(&vault("second")).unwrap();

        assert!(state.recover().is_err());
        let bytes = std::fs::read(scratch.vault_path()).unwrap();
        let opened =
            UnlockedVault::open(&VaultFile::from_bytes(&bytes).unwrap(), "master").unwrap();
        assert_eq!(opened.items()[0].name, "second");
    }

    #[test]
    fn there_is_nothing_to_recover_in_an_empty_directory() {
        let scratch = Scratch::new();
        assert!(scratch.state().recover().is_err());
    }
}
