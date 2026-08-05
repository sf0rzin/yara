//! How resistant a single password is to guessing.
//!
//! This runs offline, on one password at a time. There is deliberately no
//! breach-database lookup: that would mean sending something derived from the
//! user's passwords to a third party, which is not a thing a password manager
//! should do quietly. If breach checking is added later it belongs behind an
//! explicit opt-in.

use serde::{Deserialize, Serialize};

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

#[cfg(test)]
mod tests {
    use super::*;

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
}
