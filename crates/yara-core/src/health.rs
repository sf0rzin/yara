//! Health checks over passwords and the items that carry them.
//!
//! These run offline. There is deliberately no
//! breach-database lookup: that would mean sending something derived from the
//! user's passwords to a third party, which is not a thing a password manager
//! should do quietly. If breach checking is added later it belongs behind an
//! explicit opt-in.

use std::collections::{HashMap, HashSet};
use std::hash::{Hash, Hasher};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::{crypto, Item, ItemKind};

/// A password's salted digest while one reuse check is in flight.
///
/// The digest is the key rather than the password itself, so the grouping map
/// never assembles the vault's plaintext passwords into one structure. It is
/// wiped when the map drops just like every other short-lived secret buffer.
#[derive(Eq, PartialEq)]
struct PasswordDigest(Zeroizing<[u8; 32]>);

impl Hash for PasswordDigest {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0[..].hash(state);
    }
}

impl PasswordDigest {
    fn new(salt: &[u8], password: &str) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(salt);
        hasher.update(password.as_bytes());
        Self(Zeroizing::new(hasher.finalize().into()))
    }
}

/// The ids of every item whose password appears on at least one other item.
///
/// A fresh salt makes the in-memory keys useless as a precomputed digest of
/// the vault if they ever land in a crash dump. Equality still compares the
/// complete SHA-256 output, so a hash-table collision cannot mark two different
/// passwords as reused.
pub fn reused(items: &[Item]) -> HashSet<Uuid> {
    let salt = crypto::random_bytes(32);
    let mut first_by_digest = HashMap::<PasswordDigest, Uuid>::new();
    let mut reused = HashSet::new();

    for item in items {
        let Some(password) = item.password.as_ref() else {
            continue;
        };
        let digest = PasswordDigest::new(&salt, password.expose());

        if let Some(first) = first_by_digest.get(&digest) {
            reused.insert(*first);
            reused.insert(item.id);
        } else {
            first_by_digest.insert(digest, item.id);
        }
    }

    reused
}

/// Whether a login has a password but no stored second factor.
pub fn missing_second_factor(item: &Item) -> bool {
    item.kind == ItemKind::Login && item.password.is_some() && item.totp.is_none()
}

/// How resistant a password is to guessing, from a character-set estimate.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Strength {
    Weak,
    Fair,
    Strong,
}

/// Estimated bits of entropy, assuming the attacker knows the character set but
/// nothing else.
///
/// This is a floor, not a guarantee: it cannot tell that `Password123!` is
/// weaker than its length and variety suggest. It is here to catch the obvious
/// cases, and it never reports a short password as strong.
pub fn estimate_bits(password: &str) -> f64 {
    if password.is_empty() {
        return 0.0;
    }

    let mut charset = 0u32;
    if password.chars().any(|c| c.is_ascii_lowercase()) {
        charset += 26;
    }
    if password.chars().any(|c| c.is_ascii_uppercase()) {
        charset += 26;
    }
    if password.chars().any(|c| c.is_ascii_digit()) {
        charset += 10;
    }
    if password.chars().any(|c| !c.is_ascii_alphanumeric()) {
        charset += 33;
    }

    if charset <= 1 {
        return 0.0;
    }

    password.chars().count() as f64 * (charset as f64).log2()
}

/// Shortest password that can score above [`Strength::Weak`].
///
/// Character variety is a much weaker defence than length, and a short password
/// is within reach of offline cracking however many symbol classes it mixes.
/// Modern guidance leans on length, so length gets a hard floor here rather
/// than being allowed to trade against variety.
pub const MINIMUM_LENGTH: usize = 12;

pub fn strength(password: &str) -> Strength {
    if password.chars().count() < MINIMUM_LENGTH {
        return Strength::Weak;
    }

    let bits = estimate_bits(password);
    if bits < 50.0 {
        Strength::Weak
    } else if bits < 75.0 {
        Strength::Fair
    } else {
        Strength::Strong
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::TotpConfig;

    #[test]
    fn short_passwords_are_weak_however_varied() {
        assert_eq!(strength("aB3$"), Strength::Weak);
        // ~52 bits by character-set arithmetic alone, but 8 characters is
        // within offline-cracking reach, so the length floor takes over.
        assert!(estimate_bits("aB3$xY9!") > 50.0);
        assert_eq!(strength("aB3$xY9!"), Strength::Weak);
    }

    #[test]
    fn the_length_floor_applies_at_the_boundary() {
        assert_eq!(strength("aB3$xY9!kL2"), Strength::Weak);
        assert_ne!(strength("aB3$xY9!kL2m"), Strength::Weak);
    }

    #[test]
    fn a_long_varied_password_is_strong() {
        assert_eq!(strength("7Gk!pQ2vXm#9Lz@4Rw"), Strength::Strong);
    }

    #[test]
    fn a_long_passphrase_is_not_flagged_as_weak() {
        assert_ne!(strength("correct horse battery staple"), Strength::Weak);
    }

    #[test]
    fn an_empty_password_has_no_entropy() {
        assert_eq!(estimate_bits(""), 0.0);
        assert_eq!(strength(""), Strength::Weak);
    }

    #[test]
    fn a_single_repeated_character_class_still_scores_by_length() {
        // 26-character alphabet, so ~4.7 bits per character.
        assert!(estimate_bits("abcdefgh") < 50.0);
        assert!(estimate_bits("abcdefghijklmnopqrstuvwx") > 75.0);
    }

    #[test]
    fn two_items_with_the_same_password_are_both_reused() {
        let first = Item::new("First").with_password("same password");
        let second = Item::new("Second").with_password("same password");

        assert_eq!(
            reused(&[first.clone(), second.clone()]),
            HashSet::from([first.id, second.id])
        );
    }

    #[test]
    fn a_unique_password_is_not_reused() {
        let unique = Item::new("Unique").with_password("only here");
        let other = Item::new("Other").with_password("somewhere else");

        assert!(reused(&[unique, other]).is_empty());
    }

    #[test]
    fn items_without_passwords_are_never_reused() {
        let items = vec![Item::new("One"), Item::new("Two"), Item::new("Three")];

        assert!(reused(&items).is_empty());
    }

    #[test]
    fn three_items_sharing_a_password_are_all_reused() {
        let first = Item::new("First").with_password("same password");
        let second = Item::new("Second").with_password("same password");
        let third = Item::new("Third").with_password("same password");

        assert_eq!(
            reused(&[first.clone(), second.clone(), third.clone()]),
            HashSet::from([first.id, second.id, third.id])
        );
    }

    #[test]
    fn password_reuse_is_case_sensitive() {
        let upper = Item::new("Upper").with_password("Hunter2");
        let lower = Item::new("Lower").with_password("hunter2");

        assert!(reused(&[upper, lower]).is_empty());
    }

    #[test]
    fn the_reuse_api_returns_item_ids_only() {
        let first = Item::new("First").with_password("same password");
        let second = Item::new("Second").with_password("same password");

        // This annotation is the API-shape assertion: digests stay private to
        // the call and only item ids can survive it.
        let ids: HashSet<Uuid> = reused(&[first.clone(), second.clone()]);
        assert_eq!(ids, HashSet::from([first.id, second.id]));
    }

    #[test]
    fn a_login_with_a_password_and_no_totp_is_missing_a_second_factor() {
        let login = Item::new("Login").with_password("password");

        assert!(missing_second_factor(&login));
    }

    #[test]
    fn a_login_with_totp_is_not_missing_a_second_factor() {
        let login = Item::new("Login")
            .with_password("password")
            .with_totp(TotpConfig::new("JBSWY3DPEHPK3PXP"));

        assert!(!missing_second_factor(&login));
    }

    #[test]
    fn a_note_without_a_password_is_not_missing_a_second_factor() {
        let note = Item::new("Note").with_kind(ItemKind::Note);

        assert!(!missing_second_factor(&note));
    }
}
