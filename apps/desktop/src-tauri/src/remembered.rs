//! Master-password persistence in the operating system's credential store.
//!
//! The expiry lives with the non-secret vault profile metadata. The password
//! itself never does: on Windows it is a Generic Credential protected for the
//! signed-in user by Credential Manager.

const SERVICE: &str = "pro.yara.desktop";

#[cfg(windows)]
fn entry(vault_id: &str) -> Result<keyring::Entry, String> {
    keyring::Entry::new(SERVICE, vault_id).map_err(|error| error.to_string())
}

#[cfg(windows)]
pub fn store(vault_id: &str, password: &str) -> Result<(), String> {
    entry(vault_id)?
        .set_password(password)
        .map_err(|error| error.to_string())
}

#[cfg(windows)]
pub fn read(vault_id: &str) -> Result<Option<String>, String> {
    match entry(vault_id)?.get_password() {
        Ok(password) => Ok(Some(password)),
        Err(keyring::Error::NoEntry) => Ok(None),
        Err(error) => Err(error.to_string()),
    }
}

#[cfg(windows)]
pub fn forget(vault_id: &str) -> Result<(), String> {
    match entry(vault_id)?.delete_credential() {
        Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
        Err(error) => Err(error.to_string()),
    }
}

// The desktop product is Windows-only, but keeping the non-Windows build
// honest makes `cargo check` useful on CI and prevents a mock credential store
// from silently becoming persistence on an unsupported platform.
#[cfg(not(windows))]
pub fn store(_vault_id: &str, _password: &str) -> Result<(), String> {
    Err("remembering a vault is available only on Windows".into())
}

#[cfg(not(windows))]
pub fn read(_vault_id: &str) -> Result<Option<String>, String> {
    Ok(None)
}

#[cfg(not(windows))]
pub fn forget(_vault_id: &str) -> Result<(), String> {
    Ok(())
}
