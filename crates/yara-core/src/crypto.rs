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
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

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
/// vault — but that catch only arrives once the derivation they describe has
/// already run, which is why [`KdfParams::validate`] judges them first.
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

/// The narrowest derivation this program will run: 8 MiB.
///
/// Below the OWASP floor, deliberately — this is not the recommendation, it is
/// the point past which a header is not describing a vault yara wrote.
pub const MIN_MEMORY_KIB: u32 = 8_192;
/// The widest: 1 GiB, which is already far past anything a desktop should ask
/// a user to wait for.
pub const MAX_MEMORY_KIB: u32 = 1_048_576;
pub const MAX_ITERATIONS: u32 = 16;
pub const MAX_PARALLELISM: u32 = 16;

impl KdfParams {
    /// Refuses parameters that no build of this program ever wrote.
    ///
    /// These arrive from two places that cannot be trusted. A vault header is
    /// plaintext, and the associated data that would catch an edit to it is
    /// only checked *after* the derivation has already run — so a flipped byte
    /// making `memory_kib` 268435455 asks Argon2 for a ~256 GiB allocation
    /// first and fails authentication afterwards, except that with
    /// `panic = "abort"` there is no afterwards. The other is sync: the
    /// parameters a joining device derives with come from the server, which is
    /// exactly the party they are meant to be protected from.
    ///
    /// Checking costs nothing and answers in microseconds, which is the
    /// property that matters: the caller learns the file is damaged instead of
    /// the process learning it is out of memory.
    pub fn validate(&self) -> Result<()> {
        if !(MIN_MEMORY_KIB..=MAX_MEMORY_KIB).contains(&self.memory_kib) {
            return Err(Error::DamagedFile("key derivation memory is out of range"));
        }
        if !(1..=MAX_ITERATIONS).contains(&self.iterations) {
            return Err(Error::DamagedFile(
                "key derivation iterations are out of range",
            ));
        }
        if !(1..=MAX_PARALLELISM).contains(&self.parallelism) {
            return Err(Error::DamagedFile(
                "key derivation parallelism is out of range",
            ));
        }
        Ok(())
    }

    /// True when `self` is at least as costly as `other` on every axis.
    ///
    /// Used to decide whether raising a vault to the current defaults would be
    /// an upgrade. Every axis, because a swap that doubles the memory and
    /// halves the passes is not obviously an improvement, and guessing wrong
    /// silently weakens somebody's vault.
    pub fn at_least_as_strong_as(&self, other: &Self) -> bool {
        self.memory_kib >= other.memory_kib
            && self.iterations >= other.iterations
            && self.parallelism >= other.parallelism
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
///
/// Wrapped in [`Zeroizing`] because most of what this produces is key
/// material: `SecretKey::generate` and `AccountKeypair::generate` both copy out
/// of it into an array they wipe, which left the copy they were made from
/// sitting in freed heap for the rest of the process's life. A caller that
/// wants plain bytes — a salt, a nonce — can still take them, and pays nothing
/// for a wipe of something that was never secret.
pub fn random_bytes(len: usize) -> Zeroizing<Vec<u8>> {
    let mut buf = vec![0u8; len];
    OsRng.fill_bytes(&mut buf);
    Zeroizing::new(buf)
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
///
/// The plaintext comes back in [`Zeroizing`]. Everything this decrypts is
/// secret by construction — the vault key, the whole item list, one item's
/// password — and a plain `Vec` handed back to the allocator keeps all of it
/// legible in freed heap until something happens to overwrite it. A crash dump
/// or a hibernation file taken in between contains the vault in the clear.
pub fn open(key: &Key, sealed: &Sealed, aad: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
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
        .map(Zeroizing::new)
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
        assert_eq!(
            open(&key, &sealed, b"header").unwrap().as_slice(),
            b"attack at dawn"
        );
    }

    #[test]
    fn ciphertext_does_not_contain_the_plaintext() {
        let key = Key::generate();
        let sealed = seal(&key, b"attack at dawn", b"").unwrap();
        assert!(!sealed.ciphertext.windows(6).any(|w| w == b"attack"));
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

    #[test]
    fn what_open_hands_back_wipes_itself() {
        // The annotation is the test: `open` must not return a bare `Vec`,
        // because everything it decrypts is secret and a bare `Vec` is handed
        // back to the allocator with the plaintext still in it.
        let key = Key::generate();
        let sealed = seal(&key, b"attack at dawn", b"").unwrap();
        let plaintext: Zeroizing<Vec<u8>> = open(&key, &sealed, b"").unwrap();
        assert_eq!(plaintext.as_slice(), b"attack at dawn");
    }

    #[test]
    fn random_bytes_hands_back_something_that_wipes_itself() {
        // Same reason: this is where `SecretKey::generate` gets the recovery
        // kit from, and the copy it was made from used to outlive it.
        let bytes: Zeroizing<Vec<u8>> = random_bytes(KEY_LEN);
        assert_eq!(bytes.len(), KEY_LEN);
        assert_ne!(bytes.as_slice(), random_bytes(KEY_LEN).as_slice());
    }

    #[test]
    fn the_real_defaults_are_accepted() {
        // The bound has to leave the parameters every existing vault was
        // written with untouched, or it is not a check, it is a data loss bug.
        KdfParams::default().validate().unwrap();
    }

    #[test]
    fn a_header_asking_for_an_impossible_allocation_is_refused_at_once() {
        // One flipped byte in the plaintext header. Argon2 would try for
        // ~256 GiB, and under `panic = "abort"` that is a crash rather than an
        // error — so the answer has to come back before the KDF is reached.
        let params = KdfParams {
            memory_kib: 268_435_455,
            ..KdfParams::default()
        };

        let started = std::time::Instant::now();
        assert!(matches!(params.validate(), Err(Error::DamagedFile(_))));
        assert!(
            started.elapsed() < std::time::Duration::from_secs(1),
            "the check must not do the work it is refusing"
        );
    }

    #[test]
    fn parameters_outside_the_accepted_range_are_refused() {
        let base = KdfParams::default();

        for params in [
            KdfParams {
                memory_kib: 8,
                ..base
            },
            KdfParams {
                memory_kib: MAX_MEMORY_KIB + 1,
                ..base
            },
            KdfParams {
                iterations: 0,
                ..base
            },
            KdfParams {
                iterations: MAX_ITERATIONS + 1,
                ..base
            },
            KdfParams {
                parallelism: 0,
                ..base
            },
            KdfParams {
                parallelism: MAX_PARALLELISM + 1,
                ..base
            },
        ] {
            assert!(
                matches!(params.validate(), Err(Error::DamagedFile(_))),
                "{params:?} should be refused"
            );
        }
    }

    #[test]
    fn the_edges_of_the_accepted_range_are_accepted() {
        for params in [
            KdfParams {
                memory_kib: MIN_MEMORY_KIB,
                iterations: 1,
                parallelism: 1,
            },
            KdfParams {
                memory_kib: MAX_MEMORY_KIB,
                iterations: MAX_ITERATIONS,
                parallelism: MAX_PARALLELISM,
            },
        ] {
            params.validate().unwrap();
        }
    }

    #[test]
    fn strength_is_compared_on_every_axis() {
        let defaults = KdfParams::default();

        assert!(defaults.at_least_as_strong_as(&KdfParams {
            memory_kib: MIN_MEMORY_KIB,
            iterations: 1,
            parallelism: 1,
        }));
        assert!(defaults.at_least_as_strong_as(&defaults));

        // Stronger on one axis is not stronger. Someone who deliberately chose
        // ten passes must not have them taken away by a default of three.
        assert!(!defaults.at_least_as_strong_as(&KdfParams {
            iterations: 10,
            ..defaults
        }));
    }
}
