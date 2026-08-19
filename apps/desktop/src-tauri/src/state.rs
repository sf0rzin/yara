//! Process-wide vault state and durable writes.

use std::collections::HashSet;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;

use serde::{Deserialize, Serialize};
use uuid::Uuid;
use yara_core::{SecretString, TotpConfig, UnlockedVault, VaultFile};

use crate::remembered;

const REGISTRY_FILE: &str = "vaults.json";
const DEFAULT_VAULT_ID: &str = "default";
const DEFAULT_VAULT_NAME: &str = "Personal";
const REMEMBER_SECONDS: u64 = 14 * 24 * 60 * 60;

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
    /// Vaults exist, but none is selected. Let the user choose one.
    Select,
    /// A remembered credential resumed the selected vault.
    Unlocked,
}

/// One local vault as the interface is allowed to know it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VaultProfile {
    pub id: String,
    pub name: String,
    pub selected: bool,
    pub remembered_until: Option<u64>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct VaultRecord {
    id: String,
    name: String,
    file: String,
    #[serde(default)]
    remembered_until: Option<u64>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
struct VaultRegistry {
    #[serde(default)]
    selected: Option<String>,
    #[serde(default)]
    vaults: Vec<VaultRecord>,
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

fn deletion_tombstone(path: &Path, operation: &Uuid) -> PathBuf {
    let file = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("vault");
    path.with_file_name(format!("{file}.delete-{operation}"))
}

fn rollback_staged_files(staged: &[(PathBuf, PathBuf)]) {
    for (source, tombstone) in staged.iter().rev() {
        let _ = std::fs::rename(tombstone, source);
    }
}

/// Finishes or rolls back a Vault deletion interrupted by process termination.
/// The durable registry is the commit record: a path still owned by a profile
/// is restored, while a tombstone whose profile is gone is finished deleting.
fn reconcile_deletion_tombstones(app_dir: &Path, registry: &VaultRegistry) {
    let Ok(entries) = std::fs::read_dir(app_dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let Some(file) = path.file_name().and_then(|name| name.to_str()) else {
            continue;
        };
        let Some((original_file, operation)) = file.rsplit_once(".delete-") else {
            continue;
        };
        if original_file.is_empty() || Uuid::parse_str(operation).is_err() {
            continue;
        }

        let original = app_dir.join(original_file);
        let still_registered = registry.vaults.iter().any(|record| {
            let live = app_dir.join(&record.file);
            [live.clone(), backup_of(&live), temp_of(&live)].contains(&original)
        });
        if still_registered && !original.exists() {
            let _ = std::fs::rename(&path, &original);
        } else {
            let _ = std::fs::remove_file(&path);
        }
    }
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
    app_dir: PathBuf,
    default_vault_file: String,
    registry_path: PathBuf,
    registry: Mutex<VaultRegistry>,
    vault: Mutex<Option<UnlockedVault>>,
    /// A manual lock lasts for the rest of this process. A renderer reload may
    /// resume a remembered vault; pressing Lock now must not undo itself when
    /// the webview happens to reload afterwards.
    resume_suppressed: AtomicBool,
    /// A scanned enrollment waiting to be attached to an item being created.
    ///
    /// Parked here rather than handed to the frontend so the shared secret from
    /// a QR code never becomes a JavaScript string. The interface gets a
    /// description of it and a reference by absence: "use what was scanned".
    pending_totp: Mutex<Option<TotpConfig>>,
}

impl AppState {
    pub fn new(vault_path: PathBuf) -> Self {
        let app_dir = vault_path
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .to_path_buf();
        let default_vault_file = vault_path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("vault.yara")
            .to_string();
        let registry_path = app_dir.join(REGISTRY_FILE);
        let registry = load_registry(&registry_path, &vault_path);
        reconcile_deletion_tombstones(&app_dir, &registry);

        Self {
            app_dir,
            default_vault_file,
            registry_path,
            registry: Mutex::new(registry),
            vault: Mutex::new(None),
            resume_suppressed: AtomicBool::new(false),
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
        self.app_dir.join("icons")
    }

    pub fn vault_path(&self) -> PathBuf {
        self.selected_vault_path()
            .unwrap_or_else(|| self.app_dir.join(&self.default_vault_file))
    }

    /// Which startup situation this machine is in before remembered unlock is
    /// attempted by the command layer.
    pub fn startup(&self) -> Startup {
        if self.is_unlocked() {
            return Startup::Unlocked;
        }

        let Ok(registry) = self.registry.lock() else {
            return Startup::Select;
        };
        let Some(selected) = registry.selected.as_ref() else {
            return if registry.vaults.is_empty() {
                Startup::Setup
            } else {
                Startup::Select
            };
        };
        let Some(record) = registry.vaults.iter().find(|record| &record.id == selected) else {
            return Startup::Select;
        };
        startup_for(&self.app_dir.join(&record.file))
    }

    pub fn profiles(&self) -> Vec<VaultProfile> {
        let Ok(registry) = self.registry.lock() else {
            return Vec::new();
        };
        registry
            .vaults
            .iter()
            .map(|record| VaultProfile {
                id: record.id.clone(),
                name: record.name.clone(),
                selected: registry.selected.as_ref() == Some(&record.id),
                remembered_until: record.remembered_until,
            })
            .collect()
    }

    pub fn select_profile(&self, id: &str) -> Result<(), String> {
        if self.is_unlocked() {
            return Err("lock the current vault before choosing another one".into());
        }
        self.update_registry(|registry| {
            if !registry.vaults.iter().any(|record| record.id == id) {
                return Err("that vault is not on this device".into());
            }
            registry.selected = Some(id.to_string());
            Ok(())
        })?;
        self.allow_resume();
        Ok(())
    }

    pub fn deselect_profile(&self) -> Result<(), String> {
        if self.is_unlocked() {
            return Err("lock the current vault before choosing another one".into());
        }
        self.update_registry(|registry| {
            registry.selected = None;
            Ok(())
        })
    }

    /// Permanently removes one local vault and every recovery copy belonging
    /// to it, without exposing the other profiles to a half-finished delete.
    ///
    /// The files first move to opaque tombstone names in the same directory.
    /// Only then is the registry committed. If that metadata write fails, the
    /// moves are rolled back; if the process stops after it succeeds, the
    /// encrypted tombstones are no longer discoverable as Vaults and can be
    /// cleaned up without bringing the deleted profile back on next launch.
    pub fn remove_profile(&self, id: &str, confirmation: &str) -> Result<(), String> {
        if self.is_unlocked() {
            return Err("lock the current vault before removing it".into());
        }

        let mut registry = self.registry.lock().map_err(|_| poisoned())?;
        let record = registry
            .vaults
            .iter()
            .find(|record| record.id == id)
            .cloned()
            .ok_or_else(|| "that vault is not on this device".to_string())?;
        if record.name != confirmation {
            return Err("type the Vault name exactly to confirm removal".into());
        }

        let live = self.app_dir.join(&record.file);
        let operation = Uuid::new_v4();
        let mut staged = Vec::new();
        for source in [live.clone(), backup_of(&live), temp_of(&live)] {
            let metadata = match std::fs::symlink_metadata(&source) {
                Ok(metadata) => metadata,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(error) => {
                    rollback_staged_files(&staged);
                    return Err(error.to_string());
                }
            };
            if !metadata.file_type().is_file() {
                rollback_staged_files(&staged);
                return Err("refusing to remove a vault path that is not a file".into());
            }

            let tombstone = deletion_tombstone(&source, &operation);
            if tombstone.exists() {
                rollback_staged_files(&staged);
                return Err("a vault deletion is already waiting to be cleaned up".into());
            }
            if let Err(error) = std::fs::rename(&source, &tombstone) {
                rollback_staged_files(&staged);
                return Err(error.to_string());
            }
            staged.push((source, tombstone));
        }

        let mut next = registry.clone();
        next.vaults.retain(|candidate| candidate.id != id);
        if next.selected.as_deref() == Some(id) {
            next.selected = None;
        }
        if let Err(error) = self.write_registry(&next) {
            rollback_staged_files(&staged);
            return Err(error);
        }
        *registry = next;
        drop(registry);

        // The profile and its expiry are gone, so this credential is no longer
        // addressable by Yara even if Windows refuses the best-effort cleanup.
        let _ = remembered::forget(id);

        let mut cleanup_error = None;
        for (_, tombstone) in staged {
            if let Err(error) = std::fs::remove_file(&tombstone) {
                cleanup_error.get_or_insert(error);
            }
        }
        if let Some(error) = cleanup_error {
            return Err(format!(
                "the Vault was removed, but an encrypted file could not be deleted: {error}"
            ));
        }
        Ok(())
    }

    /// Writes a new, separate vault and registers it only after its encrypted
    /// file is durable. The legacy first vault keeps `vault.yara`; later ones
    /// get an opaque id in their filename so names can change without moving
    /// the data they describe.
    pub fn add_profile(&self, name: &str, vault: &UnlockedVault) -> Result<VaultProfile, String> {
        let name = name.trim();
        if name.is_empty() {
            return Err("give this vault a name".into());
        }
        if name.chars().count() > 64 {
            return Err("a vault name cannot be longer than 64 characters".into());
        }

        let mut registry = self.registry.lock().map_err(|_| poisoned())?;
        if registry
            .vaults
            .iter()
            .any(|record| record.name.eq_ignore_ascii_case(name))
        {
            return Err("a vault with that name already exists".into());
        }

        let first = registry.vaults.is_empty();
        let id = if first {
            DEFAULT_VAULT_ID.to_string()
        } else {
            Uuid::new_v4().to_string()
        };
        let file = if first {
            self.default_vault_file.clone()
        } else {
            format!("vault-{id}.yara")
        };
        let path = self.app_dir.join(&file);
        if startup_for(&path) != Startup::Setup {
            return Err("a vault already exists at that location".into());
        }

        self.persist_at(&path, vault)?;

        let record = VaultRecord {
            id: id.clone(),
            name: name.to_string(),
            file,
            remembered_until: None,
        };
        let mut next = registry.clone();
        next.vaults.push(record);
        next.selected = Some(id.clone());
        if let Err(error) = self.write_registry(&next) {
            // This file was created by this call and is not reachable from the
            // registry if the metadata write failed. Leaving it behind would
            // make a retry fail while showing no vault that could be opened.
            let _ = std::fs::remove_file(&path);
            return Err(error);
        }
        *registry = next;
        self.allow_resume();

        Ok(VaultProfile {
            id,
            name: name.to_string(),
            selected: true,
            remembered_until: None,
        })
    }

    pub fn suppress_resume(&self) {
        self.resume_suppressed.store(true, Ordering::SeqCst);
    }

    pub fn allow_resume(&self) {
        self.resume_suppressed.store(false, Ordering::SeqCst);
    }

    pub fn resume_is_suppressed(&self) -> bool {
        self.resume_suppressed.load(Ordering::SeqCst)
    }

    /// Stores or revokes the selected vault's master password in Credential
    /// Manager. Only the expiry is written to `vaults.json`.
    pub fn set_remembered(&self, password: &str, remember: bool) -> Result<(), String> {
        let id = self
            .selected_profile_id()
            .ok_or_else(|| "no vault is selected".to_string())?;

        if !remember {
            return self.forget_remembered(&id);
        }

        remembered::store(&id, password)?;
        let expires = yara_core::unix_now().saturating_add(REMEMBER_SECONDS);
        if let Err(error) = self.update_registry(|registry| {
            let record = registry
                .vaults
                .iter_mut()
                .find(|record| record.id == id)
                .ok_or_else(|| "the selected vault is no longer registered".to_string())?;
            record.remembered_until = Some(expires);
            Ok(())
        }) {
            let _ = remembered::forget(&id);
            return Err(error);
        }
        Ok(())
    }

    pub fn remembered_password(&self) -> Result<Option<SecretString>, String> {
        let Some(id) = self.selected_profile_id() else {
            return Ok(None);
        };
        let expires = self
            .profiles()
            .into_iter()
            .find(|profile| profile.id == id)
            .and_then(|profile| profile.remembered_until);
        let Some(expires) = expires else {
            return Ok(None);
        };
        if expires <= yara_core::unix_now() {
            self.forget_remembered(&id)?;
            return Ok(None);
        }

        match remembered::read(&id)? {
            Some(password) => Ok(Some(SecretString::new(password))),
            None => {
                self.clear_remembered_expiry(&id)?;
                Ok(None)
            }
        }
    }

    pub fn forget_selected_remembered(&self) -> Result<(), String> {
        let Some(id) = self.selected_profile_id() else {
            return Ok(());
        };
        self.forget_remembered(&id)
    }

    pub fn refresh_remembered(&self, password: &str) -> Result<(), String> {
        let remembered = self
            .profiles()
            .into_iter()
            .find(|profile| profile.selected)
            .and_then(|profile| profile.remembered_until)
            .is_some_and(|expires| expires > yara_core::unix_now());
        if remembered {
            self.set_remembered(password, true)?;
        }
        Ok(())
    }

    fn forget_remembered(&self, id: &str) -> Result<(), String> {
        self.clear_remembered_expiry(id)?;
        // Once the expiry is gone this credential can no longer be read by
        // Yara. Credential Manager deletion is still attempted, but a store
        // error must not turn an explicit log-out into a selected session.
        let _ = remembered::forget(id);
        Ok(())
    }

    fn clear_remembered_expiry(&self, id: &str) -> Result<(), String> {
        self.update_registry(|registry| {
            if let Some(record) = registry.vaults.iter_mut().find(|record| record.id == id) {
                record.remembered_until = None;
            }
            Ok(())
        })
    }

    fn selected_profile_id(&self) -> Option<String> {
        self.registry
            .lock()
            .ok()
            .and_then(|registry| registry.selected.clone())
    }

    fn selected_vault_path(&self) -> Option<PathBuf> {
        let registry = self.registry.lock().ok()?;
        let selected = registry.selected.as_ref()?;
        let record = registry
            .vaults
            .iter()
            .find(|record| &record.id == selected)?;
        Some(self.app_dir.join(&record.file))
    }

    fn update_registry<T>(
        &self,
        update: impl FnOnce(&mut VaultRegistry) -> Result<T, String>,
    ) -> Result<T, String> {
        let mut registry = self.registry.lock().map_err(|_| poisoned())?;
        let mut next = registry.clone();
        let result = update(&mut next)?;
        self.write_registry(&next)?;
        *registry = next;
        Ok(result)
    }

    fn write_registry(&self, registry: &VaultRegistry) -> Result<(), String> {
        let bytes = serde_json::to_vec_pretty(registry).map_err(|error| error.to_string())?;
        let temp = self.registry_path.with_extension("json.tmp");
        write_durably(&temp, &bytes)?;
        std::fs::rename(&temp, &self.registry_path).map_err(|error| error.to_string())
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
        let vault_path = self.vault_path();
        if vault_path.exists() {
            return Err("there is already a vault here".into());
        }

        for candidate in [temp_of(&vault_path), backup_of(&vault_path)] {
            let Ok(bytes) = std::fs::read(&candidate) else {
                continue;
            };
            if VaultFile::from_bytes(&bytes).is_err() {
                continue;
            }
            return write_durably(&vault_path, &bytes);
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

    pub fn persist(&self, vault: &UnlockedVault) -> Result<(), String> {
        self.persist_at(&self.vault_path(), vault)
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
    fn persist_at(&self, vault_path: &Path, vault: &UnlockedVault) -> Result<(), String> {
        let file = vault.seal().map_err(|e| e.to_string())?;
        let bytes = file.to_bytes().map_err(|e| e.to_string())?;

        let temp = temp_of(vault_path);
        write_durably(&temp, &bytes)?;

        if vault_path.exists() {
            let backup = backup_of(vault_path);
            std::fs::copy(vault_path, &backup).map_err(|e| e.to_string())?;
            // A backup still in the page cache is not a backup. `fs::copy`
            // makes no promise about that, so ask for one.
            std::fs::OpenOptions::new()
                .write(true)
                .open(&backup)
                .and_then(|file| file.sync_all())
                .map_err(|e| e.to_string())?;
        }

        std::fs::rename(&temp, vault_path).map_err(|e| e.to_string())
    }
}

fn load_registry(registry_path: &Path, legacy_path: &Path) -> VaultRegistry {
    if let Ok(bytes) = std::fs::read(registry_path) {
        if let Ok(mut registry) = serde_json::from_slice::<VaultRegistry>(&bytes) {
            let mut ids = HashSet::new();
            let mut files = HashSet::new();
            registry.vaults.retain(|record| {
                valid_record(record)
                    && ids.insert(record.id.clone())
                    && files.insert(record.file.clone())
            });
            add_legacy_profile_if_present(&mut registry, legacy_path);
            if registry
                .selected
                .as_ref()
                .is_some_and(|id| !registry.vaults.iter().any(|record| &record.id == id))
            {
                registry.selected = None;
            }
            return registry;
        }
    }

    // No registry is the upgrade path from every release before multi-vault.
    // Keep the old file exactly where it is and describe it as Personal.
    let mut registry = VaultRegistry::default();
    add_legacy_profile_if_present(&mut registry, legacy_path);

    // If the registry alone was lost, do not make the separately encrypted
    // vault files disappear with it. Their human names are gone, so use a
    // stable short id that can be renamed in a later settings iteration.
    if let Some(dir) = legacy_path.parent() {
        if let Ok(entries) = std::fs::read_dir(dir) {
            for entry in entries.flatten() {
                let Some(file) = entry.file_name().to_str().map(str::to_string) else {
                    continue;
                };
                let Some(id) = file
                    .strip_prefix("vault-")
                    .and_then(|rest| rest.strip_suffix(".yara"))
                    .filter(|id| Uuid::parse_str(id).is_ok())
                else {
                    continue;
                };
                if registry.vaults.iter().any(|record| record.file == file) {
                    continue;
                }
                registry.vaults.push(VaultRecord {
                    id: id.to_string(),
                    name: format!("Vault {}", &id[..8]),
                    file,
                    remembered_until: None,
                });
            }
        }
    }

    registry.selected = registry
        .vaults
        .iter()
        .find(|record| record.id == DEFAULT_VAULT_ID)
        .or_else(|| (registry.vaults.len() == 1).then(|| &registry.vaults[0]))
        .map(|record| record.id.clone());
    registry
}

fn add_legacy_profile_if_present(registry: &mut VaultRegistry, legacy_path: &Path) {
    if startup_for(legacy_path) == Startup::Setup
        || registry
            .vaults
            .iter()
            .any(|record| record.id == DEFAULT_VAULT_ID || legacy_path.ends_with(&record.file))
    {
        return;
    }
    registry.vaults.insert(
        0,
        VaultRecord {
            id: DEFAULT_VAULT_ID.to_string(),
            name: DEFAULT_VAULT_NAME.to_string(),
            file: legacy_path
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or("vault.yara")
                .to_string(),
            remembered_until: None,
        },
    );
    if registry.selected.is_none() {
        registry.selected = Some(DEFAULT_VAULT_ID.to_string());
    }
}

fn valid_record(record: &VaultRecord) -> bool {
    !record.id.trim().is_empty()
        && !record.name.trim().is_empty()
        && record.name.chars().count() <= 64
        && Path::new(&record.file).components().count() == 1
        && Path::new(&record.file)
            .extension()
            .and_then(|ext| ext.to_str())
            == Some("yara")
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

    #[test]
    fn a_legacy_vault_becomes_the_selected_personal_profile() {
        let scratch = Scratch::new();
        scratch.state().persist(&vault("legacy")).unwrap();

        let reopened = scratch.state();
        assert_eq!(
            reopened.profiles(),
            vec![VaultProfile {
                id: DEFAULT_VAULT_ID.to_string(),
                name: DEFAULT_VAULT_NAME.to_string(),
                selected: true,
                remembered_until: None,
            }]
        );
        assert_eq!(reopened.startup(), Startup::Locked);
    }

    #[test]
    fn another_profile_uses_another_file_without_replacing_the_first() {
        let scratch = Scratch::new();
        let state = scratch.state();

        let first = state.add_profile("Personal", &vault("first")).unwrap();
        let second = state.add_profile("Work", &vault("second")).unwrap();

        assert_ne!(first.id, second.id);
        assert_eq!(state.profiles().len(), 2);
        assert_eq!(
            state
                .profiles()
                .into_iter()
                .find(|profile| profile.selected)
                .unwrap()
                .name,
            "Work"
        );

        let original = std::fs::read(scratch.vault_path()).unwrap();
        let opened =
            UnlockedVault::open(&VaultFile::from_bytes(&original).unwrap(), "master").unwrap();
        assert_eq!(opened.items()[0].name, "first");

        let current = std::fs::read(state.vault_path()).unwrap();
        let opened =
            UnlockedVault::open(&VaultFile::from_bytes(&current).unwrap(), "master").unwrap();
        assert_eq!(opened.items()[0].name, "second");
    }

    #[test]
    fn deselecting_a_profile_opens_the_picker() {
        let scratch = Scratch::new();
        let state = scratch.state();
        state.add_profile("Personal", &vault("first")).unwrap();

        state.deselect_profile().unwrap();

        assert_eq!(state.startup(), Startup::Select);
        assert!(state.profiles().iter().all(|profile| !profile.selected));
    }

    #[test]
    fn removing_a_profile_deletes_its_live_backup_and_temporary_files() {
        let scratch = Scratch::new();
        let state = scratch.state();
        let profile = state.add_profile("Personal", &vault("first")).unwrap();

        // A second save produces the recovery copy; the temporary file models
        // an interrupted later save. Removing the Vault owns all three.
        state.persist(&vault("second")).unwrap();
        std::fs::write(temp_of(&scratch.vault_path()), b"partial").unwrap();
        assert!(scratch.vault_path().exists());
        assert!(backup_of(&scratch.vault_path()).exists());
        assert!(temp_of(&scratch.vault_path()).exists());

        state.clear();
        state.remove_profile(&profile.id, "Personal").unwrap();

        assert!(!scratch.vault_path().exists());
        assert!(!backup_of(&scratch.vault_path()).exists());
        assert!(!temp_of(&scratch.vault_path()).exists());
        assert!(state.profiles().is_empty());
        assert_eq!(state.startup(), Startup::Setup);
        assert!(std::fs::read_dir(&scratch.0)
            .unwrap()
            .flatten()
            .all(|entry| !entry.file_name().to_string_lossy().contains(".delete-")));
    }

    #[test]
    fn removing_one_profile_leaves_every_other_vault_untouched() {
        let scratch = Scratch::new();
        let state = scratch.state();
        let first = state.add_profile("Personal", &vault("first")).unwrap();
        let second = state.add_profile("Work", &vault("second")).unwrap();
        let second_path = state.vault_path();

        state.clear();
        state.deselect_profile().unwrap();
        state.remove_profile(&second.id, "Work").unwrap();

        assert!(!second_path.exists());
        assert_eq!(state.profiles().len(), 1);
        assert_eq!(state.profiles()[0].id, first.id);
        assert!(scratch.vault_path().exists());
        let bytes = std::fs::read(scratch.vault_path()).unwrap();
        let opened =
            UnlockedVault::open(&VaultFile::from_bytes(&bytes).unwrap(), "master").unwrap();
        assert_eq!(opened.items()[0].name, "first");
        assert_eq!(state.startup(), Startup::Select);
    }

    #[test]
    fn startup_rolls_back_a_delete_interrupted_before_the_registry_commit() {
        let scratch = Scratch::new();
        let state = scratch.state();
        let profile = state.add_profile("Personal", &vault("first")).unwrap();
        let operation = Uuid::new_v4();
        let tombstone = deletion_tombstone(&scratch.vault_path(), &operation);
        std::fs::rename(scratch.vault_path(), &tombstone).unwrap();
        drop(state);

        let reopened = scratch.state();

        assert!(scratch.vault_path().exists());
        assert!(!tombstone.exists());
        assert_eq!(reopened.profiles()[0].id, profile.id);
        assert_eq!(reopened.startup(), Startup::Locked);
    }

    #[test]
    fn startup_finishes_a_delete_interrupted_after_the_registry_commit() {
        let scratch = Scratch::new();
        let state = scratch.state();
        let profile = state.add_profile("Personal", &vault("first")).unwrap();
        let operation = Uuid::new_v4();
        let tombstone = deletion_tombstone(&scratch.vault_path(), &operation);
        std::fs::rename(scratch.vault_path(), &tombstone).unwrap();

        let mut next = state.registry.lock().unwrap().clone();
        next.vaults.retain(|record| record.id != profile.id);
        next.selected = None;
        state.write_registry(&next).unwrap();
        drop(state);

        let reopened = scratch.state();

        assert!(!tombstone.exists());
        assert!(reopened.profiles().is_empty());
        assert_eq!(reopened.startup(), Startup::Setup);
    }

    #[test]
    fn removing_a_profile_requires_its_exact_name() {
        let scratch = Scratch::new();
        let state = scratch.state();
        let profile = state.add_profile("Personal", &vault("first")).unwrap();

        assert!(state.remove_profile(&profile.id, "personal").is_err());
        assert!(scratch.vault_path().exists());
        assert_eq!(state.profiles().len(), 1);
    }

    #[test]
    fn profile_names_are_unique_without_case_sensitivity() {
        let scratch = Scratch::new();
        let state = scratch.state();
        state.add_profile("Personal", &vault("first")).unwrap();

        assert!(state.add_profile("personal", &vault("second")).is_err());
        assert_eq!(state.profiles().len(), 1);
    }
}
