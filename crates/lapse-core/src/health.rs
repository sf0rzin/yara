//! Local analysis of how healthy a vault's passwords are.
//!
//! Everything here runs offline against the decrypted vault. There is
//! deliberately no breach-database lookup: that would mean sending something
//! derived from the user's passwords to a third party, which is not a thing a
//! password manager should do quietly. If breach checking is added later it
//! belongs behind an explicit opt-in.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::vault::Item;

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
const MINIMUM_LENGTH: usize = 12;

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

/// A set of items that all share one password.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReusedGroup {
    pub items: Vec<Uuid>,
}

/// The result of auditing a vault.
///
/// Serialized in camelCase: this is a report type meant for the UI, not part of
/// the on-disk format.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VaultHealth {
    /// Items whose password lands below the `Fair` threshold.
    pub weak: Vec<Uuid>,
    /// Groups of items sharing an identical password.
    pub reused: Vec<ReusedGroup>,
    /// Login items with a password but no second factor enrolled.
    pub missing_totp: Vec<Uuid>,
    /// How many items were examined, so the UI can say "of N".
    pub items_with_passwords: usize,
}

impl VaultHealth {
    /// True when there is nothing for the user to act on.
    pub fn is_clean(&self) -> bool {
        self.weak.is_empty() && self.reused.is_empty()
    }

    /// Total number of items implicated in at least one finding.
    pub fn affected_items(&self) -> usize {
        let mut ids: Vec<Uuid> = self.weak.clone();
        ids.extend(self.reused.iter().flat_map(|group| group.items.iter().copied()));
        ids.sort_unstable();
        ids.dedup();
        ids.len()
    }
}

/// Audits every item that has a password.
///
/// Reuse is detected by comparing SHA-256 digests rather than the passwords
/// themselves, so no second plaintext copy is built up in a map along the way.
pub fn audit(items: &[Item]) -> VaultHealth {
    let mut health = VaultHealth::default();
    let mut by_digest: HashMap<[u8; 32], Vec<Uuid>> = HashMap::new();

    for item in items {
        let Some(password) = item.password.as_ref() else {
            continue;
        };
        if password.is_empty() {
            continue;
        }

        health.items_with_passwords += 1;

        if strength(password.expose()) == Strength::Weak {
            health.weak.push(item.id);
        }

        if item.totp.is_none() {
            health.missing_totp.push(item.id);
        }

        let digest: [u8; 32] = Sha256::digest(password.expose().as_bytes()).into();
        by_digest.entry(digest).or_default().push(item.id);
    }

    health.reused = by_digest
        .into_values()
        .filter(|ids| ids.len() > 1)
        .map(|mut items| {
            items.sort_unstable();
            ReusedGroup { items }
        })
        .collect();

    // Stable ordering so the UI does not reshuffle between refreshes.
    health.reused.sort_by_key(|group| group.items[0]);
    health.weak.sort_unstable();
    health.missing_totp.sort_unstable();

    health
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::Item;

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
    fn reuse_is_detected_across_items() {
        let items = vec![
            Item::new("A").with_password("7Gk!pQ2vXm#9Lz@4Rw"),
            Item::new("B").with_password("7Gk!pQ2vXm#9Lz@4Rw"),
            Item::new("C").with_password("differentQ2vXm#9Lz@4"),
        ];

        let health = audit(&items);
        assert_eq!(health.reused.len(), 1);
        assert_eq!(health.reused[0].items.len(), 2);
    }

    #[test]
    fn unique_passwords_produce_no_reuse_findings() {
        let items = vec![
            Item::new("A").with_password("7Gk!pQ2vXm#9Lz@4Rw"),
            Item::new("B").with_password("differentQ2vXm#9Lz@4"),
        ];
        assert!(audit(&items).reused.is_empty());
    }

    #[test]
    fn weak_passwords_are_reported() {
        let items = vec![
            Item::new("A").with_password("hunter2"),
            Item::new("B").with_password("7Gk!pQ2vXm#9Lz@4Rw"),
        ];

        let health = audit(&items);
        assert_eq!(health.weak.len(), 1);
        assert_eq!(health.weak[0], items[0].id);
    }

    #[test]
    fn items_without_passwords_are_skipped_entirely() {
        let items = vec![Item::new("A"), Item::new("B").with_password("")];
        let health = audit(&items);
        assert_eq!(health.items_with_passwords, 0);
        assert!(health.is_clean());
    }

    #[test]
    fn a_healthy_vault_is_clean() {
        let items = vec![
            Item::new("A").with_password("7Gk!pQ2vXm#9Lz@4Rw"),
            Item::new("B").with_password("differentQ2vXm#9Lz@4"),
        ];
        assert!(audit(&items).is_clean());
    }

    #[test]
    fn missing_second_factors_are_reported_separately_from_cleanliness() {
        let items = vec![Item::new("A").with_password("7Gk!pQ2vXm#9Lz@4Rw")];
        let health = audit(&items);
        // Not having 2FA is worth surfacing but is not a defect in the vault.
        assert_eq!(health.missing_totp.len(), 1);
        assert!(health.is_clean());
    }

    #[test]
    fn affected_items_counts_each_item_once() {
        // One password that is both weak and reused across two items.
        let items = vec![
            Item::new("A").with_password("hunter2"),
            Item::new("B").with_password("hunter2"),
        ];
        let health = audit(&items);
        assert_eq!(health.weak.len(), 2);
        assert_eq!(health.reused.len(), 1);
        assert_eq!(health.affected_items(), 2);
    }
}
