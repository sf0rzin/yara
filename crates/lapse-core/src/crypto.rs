//! Primitives: Argon2id key derivation and XChaCha20-Poly1305 authenticated
//! encryption.
//!
//! Everything above this module treats these as opaque. Nothing here knows what
//! a vault or an item is.

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::rand_core::RngCore;
use chacha20poly1305::aead::{Aead, OsRng, Payload};
use chacha20poly1305::{AeadCore, Key as CipherKey, KeyInit, XChaCha20Poly1305, XNonce};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::{Error, Result};

/// Symmetric key length, in bytes.
pub const KEY_LEN: usize = 32;
/// Argon2id salt length, in bytes.
pub const SALT_LEN: usize = 32;
/// XChaCha20-Poly1305 nonce length, in bytes.
pub const NONCE_LEN: usize = 24;

/// A 256-bit symmetric key, wiped on drop.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Key([u8; KEY_LEN]);

impl Key {
    /// Draws a fresh key from the operating system CSPRNG.
    pub fn generate() -> Self {
        let mut bytes = [0u8; KEY_LEN];
        OsRng.fill_bytes(&mut bytes);
        Self(bytes)
    }

    pub fn from_bytes(bytes: [u8; KEY_LEN]) -> Self {
        Self(bytes)
    }

    pub fn from_slice(bytes: &[u8]) -> Result<Self> {
        let bytes: [u8; KEY_LEN] = bytes
            .try_into()
            .map_err(|_| Error::Malformed("key is not 32 bytes"))?;
        Ok(Self(bytes))
    }

    pub fn expose(&self) -> &[u8; KEY_LEN] {
        &self.0
    }
}

impl std::fmt::Debug for Key {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Key(<redacted>)")
    }
}

/// Argon2id cost parameters.
///
/// These live in the vault header in plaintext so an existing vault can still be
/// opened after the defaults are raised. They are covered by the AEAD's
/// associated data, so an attacker cannot weaken them without invalidating the
/// vault.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct KdfParams {
    /// Memory cost in kibibytes.
    pub memory_kib: u32,
    /// Number of passes.
    pub iterations: u32,
    /// Degree of parallelism.
    pub parallelism: u32,
}

impl Default for KdfParams {
    /// 64 MiB, 3 passes, 4 lanes — the higher of the two OWASP-recommended
    /// Argon2id configurations, which a desktop machine handles comfortably.
    fn default() -> Self {
        Self {
            memory_kib: 65_536,
            iterations: 3,
            parallelism: 4,
        }
    }
}

/// Derives a 256-bit key from a password using Argon2id.
pub fn derive_key(password: &[u8], salt: &[u8], params: KdfParams) -> Result<Key> {
    if salt.len() < 8 {
        return Err(Error::Kdf("salt must be at least 8 bytes".into()));
    }

    let params = Params::new(
        params.memory_kib,
        params.iterations,
        params.parallelism,
        Some(KEY_LEN),
    )
    .map_err(|e| Error::Kdf(e.to_string()))?;

    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut out = [0u8; KEY_LEN];
    argon
        .hash_password_into(password, salt, &mut out)
        .map_err(|e| Error::Kdf(e.to_string()))?;

    Ok(Key::from_bytes(out))
}

/// Fills a buffer with cryptographically secure random bytes.
pub fn random_bytes(len: usize) -> Vec<u8> {
    let mut buf = vec![0u8; len];
    OsRng.fill_bytes(&mut buf);
    buf
}

/// A nonce and ciphertext pair. The Poly1305 tag is appended to `ciphertext`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Sealed {
    #[serde(with = "crate::b64")]
    pub nonce: Vec<u8>,
    #[serde(with = "crate::b64")]
    pub ciphertext: Vec<u8>,
}

/// Encrypts `plaintext` under `key`, binding `aad` to the result.
///
/// A fresh random 192-bit nonce is drawn per call. At that width, random nonces
/// carry no meaningful collision risk, so there is no counter to persist.
pub fn seal(key: &Key, plaintext: &[u8], aad: &[u8]) -> Result<Sealed> {
    let cipher = XChaCha20Poly1305::new(CipherKey::from_slice(key.expose()));
    let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);

    let ciphertext = cipher
        .encrypt(
            &nonce,
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| Error::Encrypt)?;

    Ok(Sealed {
        nonce: nonce.to_vec(),
        ciphertext,
    })
}

/// Decrypts and authenticates `sealed`.
///
/// Fails identically for a wrong key, a modified ciphertext, and modified
/// associated data — the caller cannot tell which.
pub fn open(key: &Key, sealed: &Sealed, aad: &[u8]) -> Result<Vec<u8>> {
    if sealed.nonce.len() != NONCE_LEN {
        return Err(Error::Malformed("nonce is not 24 bytes"));
    }

    let cipher = XChaCha20Poly1305::new(CipherKey::from_slice(key.expose()));
    let nonce = XNonce::from_slice(&sealed.nonce);

    cipher
        .decrypt(
            nonce,
            Payload {
                msg: &sealed.ciphertext,
                aad,
            },
        )
        .map_err(|_| Error::Decrypt)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Deliberately weak parameters so the test suite stays fast. Production
    /// code uses `KdfParams::default`.
    fn test_params() -> KdfParams {
        KdfParams {
            memory_kib: 8,
            iterations: 1,
            parallelism: 1,
        }
    }

    #[test]
    fn seal_then_open_returns_the_plaintext() {
        let key = Key::generate();
        let sealed = seal(&key, b"attack at dawn", b"header").unwrap();
        assert_eq!(open(&key, &sealed, b"header").unwrap(), b"attack at dawn");
    }

    #[test]
    fn ciphertext_does_not_contain_the_plaintext() {
        let key = Key::generate();
        let sealed = seal(&key, b"attack at dawn", b"").unwrap();
        assert!(!sealed
            .ciphertext
            .windows(6)
            .any(|w| w == b"attack"));
    }

    #[test]
    fn a_different_key_cannot_open_it() {
        let sealed = seal(&Key::generate(), b"secret", b"").unwrap();
        assert!(matches!(
            open(&Key::generate(), &sealed, b""),
            Err(Error::Decrypt)
        ));
    }

    #[test]
    fn tampering_with_the_ciphertext_is_detected() {
        let key = Key::generate();
        let mut sealed = seal(&key, b"secret", b"").unwrap();
        sealed.ciphertext[0] ^= 0x01;
        assert!(matches!(open(&key, &sealed, b""), Err(Error::Decrypt)));
    }

    #[test]
    fn tampering_with_the_nonce_is_detected() {
        let key = Key::generate();
        let mut sealed = seal(&key, b"secret", b"").unwrap();
        sealed.nonce[0] ^= 0x01;
        assert!(matches!(open(&key, &sealed, b""), Err(Error::Decrypt)));
    }

    #[test]
    fn changing_the_associated_data_is_detected() {
        let key = Key::generate();
        let sealed = seal(&key, b"secret", b"iterations=3").unwrap();
        assert!(matches!(
            open(&key, &sealed, b"iterations=1"),
            Err(Error::Decrypt)
        ));
    }

    #[test]
    fn each_call_draws_a_fresh_nonce() {
        let key = Key::generate();
        let a = seal(&key, b"same plaintext", b"").unwrap();
        let b = seal(&key, b"same plaintext", b"").unwrap();
        assert_ne!(a.nonce, b.nonce);
        assert_ne!(a.ciphertext, b.ciphertext);
    }

    #[test]
    fn derivation_is_deterministic_for_the_same_inputs() {
        let salt = [7u8; SALT_LEN];
        let a = derive_key(b"password", &salt, test_params()).unwrap();
        let b = derive_key(b"password", &salt, test_params()).unwrap();
        assert_eq!(a.expose(), b.expose());
    }

    #[test]
    fn a_different_salt_yields_a_different_key() {
        let a = derive_key(b"password", &[1u8; SALT_LEN], test_params()).unwrap();
        let b = derive_key(b"password", &[2u8; SALT_LEN], test_params()).unwrap();
        assert_ne!(a.expose(), b.expose());
    }

    #[test]
    fn a_different_password_yields_a_different_key() {
        let salt = [7u8; SALT_LEN];
        let a = derive_key(b"password", &salt, test_params()).unwrap();
        let b = derive_key(b"Password", &salt, test_params()).unwrap();
        assert_ne!(a.expose(), b.expose());
    }

    #[test]
    fn different_cost_parameters_yield_a_different_key() {
        let salt = [7u8; SALT_LEN];
        let a = derive_key(b"password", &salt, test_params()).unwrap();
        let b = derive_key(
            b"password",
            &salt,
            KdfParams {
                iterations: 2,
                ..test_params()
            },
        )
        .unwrap();
        assert_ne!(a.expose(), b.expose());
    }

    #[test]
    fn a_short_salt_is_rejected() {
        assert!(matches!(
            derive_key(b"password", b"abc", test_params()),
            Err(Error::Kdf(_))
        ));
    }

    #[test]
    fn key_debug_output_is_redacted() {
        let key = Key::generate();
        assert_eq!(format!("{key:?}"), "Key(<redacted>)");
    }

    #[test]
    fn default_parameters_meet_the_owasp_floor() {
        let params = KdfParams::default();
        assert!(params.memory_kib >= 19_456);
        assert!(params.iterations >= 2);
    }
}
