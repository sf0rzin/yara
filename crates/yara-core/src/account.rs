//! The key hierarchy behind sync.
//!
//! An account is protected by two things, not one: the password the user
//! chose, and a 128-bit **secret key** generated here and shown once.
//!
//! The second exists because hosting encrypted vaults makes you a target, and
//! the realistic attack is not against the cipher — it is running Argon2id
//! offline against a stored blob whose password was weak. Mixing generated
//! entropy into the derivation makes that infeasible regardless of what the
//! user typed. It is the same reasoning behind 1Password's Secret Key, and it
//! is also the recovery kit: one printed artifact authorises a new device and
//! restores access, rather than two things to lose.
//!
//! ```text
//! master_key = Argon2id(password ‖ secret_key, account_salt)
//! enc_key    = HKDF(master_key, "yara.enc.v1")
//! ```
//!
//! `enc_key` never leaves the machine. It wraps two things, and both are
//! stored on the server as blobs it cannot read: the vault key, and the
//! account's Ed25519 signing key.
//!
//! Nothing derived from the password is ever sent anywhere. Identity on the
//! wire is a signature — see `yara-sync`.

use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::crypto::{self, KdfParams, Key, Sealed};
use crate::error::{Error, Result};

/// Bytes in a secret key. 128 bits is past the point where guessing is a
/// strategy, and short enough to print on one line.
pub const SECRET_KEY_LEN: usize = 16;

/// Characters a printed kit is written in.
///
/// No `i`, `l`, `o`, `0` or `1`. The kit is read off one screen and typed into
/// another, and a recovery that fails because of a look-alike is a recovery
/// that fails at the worst possible moment.
const ALPHABET: &[u8] = b"abcdefghjkmnpqrstuvwxyz23456789";

/// Domain separation for the two things derived from the master key. Distinct
/// labels are what stop one from being computable from the other.
const ENC_INFO: &[u8] = b"yara.enc.v1";

/// The half of an account that is generated rather than chosen.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SecretKey([u8; SECRET_KEY_LEN]);

/// Never printed. A `Debug` that showed this would put half the account into
/// the first log line someone adds.
impl std::fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SecretKey(hidden)")
    }
}

impl SecretKey {
    pub fn generate() -> Self {
        let bytes = crypto::random_bytes(SECRET_KEY_LEN);
        let mut fixed = [0u8; SECRET_KEY_LEN];
        fixed.copy_from_slice(&bytes);
        Self(fixed)
    }

    pub fn from_bytes(bytes: [u8; SECRET_KEY_LEN]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; SECRET_KEY_LEN] {
        &self.0
    }

    /// The printed form: groups of five, hyphenated.
    ///
    /// Base-31 over 128 bits needs 26 characters, which lands as five groups
    /// with the last one short. Encoding is most-significant first so the
    /// string reads as one number rather than as reversed chunks.
    pub fn to_kit(&self) -> String {
        let mut value = u128::from_be_bytes(self.0);
        let base = ALPHABET.len() as u128;

        let mut chars = Vec::with_capacity(26);
        for _ in 0..26 {
            chars.push(ALPHABET[(value % base) as usize] as char);
            value /= base;
        }
        chars.reverse();

        chars
            .chunks(5)
            .map(|chunk| chunk.iter().collect::<String>())
            .collect::<Vec<_>>()
            .join("-")
    }

    /// Reads a printed kit back.
    ///
    /// Hyphens, spaces and case are all forgiven: someone typing this from
    /// paper should not be defeated by formatting.
    pub fn from_kit(kit: &str) -> Result<Self> {
        let cleaned: Vec<u8> = kit
            .chars()
            .filter(|c| !c.is_whitespace() && *c != '-')
            .map(|c| c.to_ascii_lowercase() as u8)
            .collect();

        if cleaned.len() != 26 {
            return Err(Error::InvalidRecoveryKit);
        }

        let base = u128::from(ALPHABET.len() as u32);
        let mut value: u128 = 0;
        for byte in cleaned {
            let digit = ALPHABET
                .iter()
                .position(|c| *c == byte)
                .ok_or(Error::InvalidRecoveryKit)?;
            value = value
                .checked_mul(base)
                .and_then(|v| v.checked_add(digit as u128))
                .ok_or(Error::InvalidRecoveryKit)?;
        }

        Ok(Self(value.to_be_bytes()))
    }
}

/// What a password and a secret key unlock.
///
/// Holds `enc_key` and nothing else. The master key it came from is dropped
/// immediately: keeping it would mean holding a value that can regenerate
/// every other one, for no benefit.
pub struct AccountKeys {
    enc_key: Key,
}

impl std::fmt::Debug for AccountKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("AccountKeys(hidden)")
    }
}

impl AccountKeys {
    /// Runs the expensive derivation. Once per unlock, never per request.
    pub fn derive(
        password: &str,
        secret: &SecretKey,
        salt: &[u8],
        params: KdfParams,
    ) -> Result<Self> {
        // Concatenated, not mixed: the secret key is fixed-length, so there is
        // no boundary a caller could shift to make two different inputs derive
        // the same key.
        let mut material = Vec::with_capacity(password.len() + SECRET_KEY_LEN);
        material.extend_from_slice(password.as_bytes());
        material.extend_from_slice(secret.as_bytes());

        let master = crypto::derive_key(&material, salt, params);
        material.zeroize();
        let master = master?;

        let hkdf = Hkdf::<Sha256>::new(Some(salt), master.expose());
        let mut enc = [0u8; crypto::KEY_LEN];
        hkdf.expand(ENC_INFO, &mut enc)
            .map_err(|_| Error::Kdf("HKDF expand failed".into()))?;

        let enc_key = Key::from_bytes(enc);
        enc.zeroize();
        Ok(Self { enc_key })
    }

    /// Wraps something for the server to hold and not read.
    pub fn wrap(&self, plaintext: &[u8]) -> Result<Sealed> {
        crypto::seal(&self.enc_key, plaintext, ENC_INFO)
    }

    pub fn unwrap(&self, sealed: &Sealed) -> Result<Vec<u8>> {
        crypto::open(&self.enc_key, sealed, ENC_INFO)
    }
}

/// An account's long-term identity.
///
/// Every device registration is signed by this, which is how a second machine
/// proves it belongs without anything password-derived crossing the wire. The
/// private half is wrapped under `enc_key` and stored on the server, so a new
/// device recovers it with the password and the kit.
pub struct AccountKeypair(SigningKey);

impl std::fmt::Debug for AccountKeypair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("AccountKeypair(hidden)")
    }
}

impl AccountKeypair {
    pub fn generate() -> Self {
        let bytes = crypto::random_bytes(32);
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&bytes);
        let key = SigningKey::from_bytes(&seed);
        seed.zeroize();
        Self(key)
    }

    pub fn from_seed(seed: &[u8]) -> Result<Self> {
        let fixed: [u8; 32] = seed
            .try_into()
            .map_err(|_| Error::Malformed("account key seed is not 32 bytes"))?;
        Ok(Self(SigningKey::from_bytes(&fixed)))
    }

    /// The 32 bytes to wrap and store. Never sent unwrapped.
    pub fn seed(&self) -> [u8; 32] {
        self.0.to_bytes()
    }

    pub fn public(&self) -> VerifyingKey {
        self.0.verifying_key()
    }

    pub fn sign(&self, message: &[u8]) -> [u8; 64] {
        self.0.sign(message).to_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn params() -> KdfParams {
        // The real parameters take a second each; these tests are about the
        // hierarchy, not about how slow Argon2id is.
        KdfParams {
            memory_kib: 8,
            iterations: 1,
            parallelism: 1,
        }
    }

    fn secret() -> SecretKey {
        SecretKey::from_bytes([7u8; SECRET_KEY_LEN])
    }

    #[test]
    fn a_kit_round_trips() {
        let key = SecretKey::generate();
        let kit = key.to_kit();
        assert_eq!(
            SecretKey::from_kit(&kit).unwrap().as_bytes(),
            key.as_bytes()
        );
    }

    #[test]
    fn a_kit_is_read_back_however_it_was_typed() {
        let key = secret();
        let kit = key.to_kit();

        for variant in [
            kit.to_uppercase(),
            kit.replace('-', ""),
            kit.replace('-', " "),
            format!("  {kit}  "),
        ] {
            assert_eq!(
                SecretKey::from_kit(&variant).unwrap().as_bytes(),
                key.as_bytes(),
                "{variant:?} should read back"
            );
        }
    }

    #[test]
    fn a_kit_has_no_look_alike_characters() {
        let kit = SecretKey::generate().to_kit();
        for confusable in ['i', 'l', 'o', '0', '1'] {
            assert!(
                !kit.contains(confusable),
                "{kit} contains {confusable}, which someone will mistype"
            );
        }
    }

    #[test]
    fn a_damaged_kit_is_refused_rather_than_guessed() {
        let kit = secret().to_kit();

        assert!(SecretKey::from_kit("").is_err());
        assert!(
            SecretKey::from_kit(&kit[..kit.len() - 2]).is_err(),
            "truncated"
        );
        assert!(SecretKey::from_kit(&format!("{kit}a")).is_err(), "too long");
        assert!(
            SecretKey::from_kit(&kit.replacen('a', "!", 1)).is_err() || !kit.contains('a'),
            "a character outside the alphabet"
        );
    }

    #[test]
    fn the_same_password_and_secret_give_the_same_keys() {
        let salt = [3u8; 32];
        let a = AccountKeys::derive("hunter2", &secret(), &salt, params()).unwrap();
        let b = AccountKeys::derive("hunter2", &secret(), &salt, params()).unwrap();

        let sealed = a.wrap(b"payload").unwrap();
        assert_eq!(b.unwrap(&sealed).unwrap(), b"payload");
    }

    #[test]
    fn the_password_alone_is_not_enough() {
        let salt = [3u8; 32];
        let right = AccountKeys::derive("hunter2", &secret(), &salt, params()).unwrap();
        let sealed = right.wrap(b"payload").unwrap();

        // This is the whole point of the second factor: an attacker who
        // guesses the password still cannot open the blob.
        let other = SecretKey::from_bytes([9u8; SECRET_KEY_LEN]);
        let wrong = AccountKeys::derive("hunter2", &other, &salt, params()).unwrap();
        assert!(wrong.unwrap(&sealed).is_err());
    }

    #[test]
    fn the_secret_key_alone_is_not_enough_either() {
        let salt = [3u8; 32];
        let right = AccountKeys::derive("hunter2", &secret(), &salt, params()).unwrap();
        let sealed = right.wrap(b"payload").unwrap();

        let wrong = AccountKeys::derive("wrong-password", &secret(), &salt, params()).unwrap();
        assert!(wrong.unwrap(&sealed).is_err());
    }

    #[test]
    fn a_different_salt_gives_a_different_account() {
        let a = AccountKeys::derive("hunter2", &secret(), &[1u8; 32], params()).unwrap();
        let b = AccountKeys::derive("hunter2", &secret(), &[2u8; 32], params()).unwrap();

        let sealed = a.wrap(b"payload").unwrap();
        assert!(b.unwrap(&sealed).is_err());
    }

    #[test]
    fn a_wrapped_blob_does_not_contain_what_it_wraps() {
        let keys = AccountKeys::derive("hunter2", &secret(), &[3u8; 32], params()).unwrap();
        let sealed = keys.wrap(b"the-vault-key-in-the-clear").unwrap();

        let bytes = serde_json::to_vec(&sealed).unwrap();
        assert!(!String::from_utf8_lossy(&bytes).contains("the-vault-key"));
    }

    #[test]
    fn an_account_keypair_survives_being_wrapped_and_recovered() {
        let keys = AccountKeys::derive("hunter2", &secret(), &[3u8; 32], params()).unwrap();

        let original = AccountKeypair::generate();
        let wrapped = keys.wrap(&original.seed()).unwrap();

        // What a new device does: fetch the blob, unwrap it, and it can now
        // sign as the account.
        let recovered = AccountKeypair::from_seed(&keys.unwrap(&wrapped).unwrap()).unwrap();
        assert_eq!(recovered.public().as_bytes(), original.public().as_bytes());

        let message = b"register device dev-2";
        assert_eq!(recovered.sign(message), original.sign(message));
    }

    #[test]
    fn two_generated_secret_keys_differ() {
        assert_ne!(
            SecretKey::generate().as_bytes(),
            SecretKey::generate().as_bytes()
        );
    }

    #[test]
    fn neither_secret_prints_itself() {
        let key = SecretKey::from_bytes([0xAB; SECRET_KEY_LEN]);
        assert_eq!(format!("{key:?}"), "SecretKey(hidden)");
        assert!(!format!("{key:?}").contains("171"));

        let keys = AccountKeys::derive("p", &key, &[1u8; 32], params()).unwrap();
        assert_eq!(format!("{keys:?}"), "AccountKeys(hidden)");
    }
}
