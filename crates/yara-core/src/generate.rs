//! Password generation from the operating system's cryptographic randomness.

use serde::Deserialize;
use zeroize::Zeroizing;

use crate::{crypto, Error, Result, SecretString};

const LOWERCASE: &[u8] = b"abcdefghijklmnopqrstuvwxyz";
const UPPERCASE: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const DIGITS: &[u8] = b"0123456789";
const SYMBOLS: &[u8] = b"!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~";

/// A caller's constraints for one generated password.
#[derive(Clone, Copy, Debug, Deserialize)]
pub struct Recipe {
    pub length: usize,
    pub lowercase: bool,
    pub uppercase: bool,
    pub digits: bool,
    pub symbols: bool,
}

/// The longest password a caller may ask this crate to allocate.
///
/// A password has no practical need to be larger than this, and bounding the
/// request keeps an untrusted caller from turning generation into an arbitrary
/// allocation.
const MAXIMUM_LENGTH: usize = 128;

/// The shuffle draws an index over the whole password, so raising the maximum
/// past what one random byte can select from would make `index` refuse and
/// `draw` panic. The two numbers are coupled and nothing else says so.
const _: () = assert!(MAXIMUM_LENGTH <= 256);

struct RandomBytes {
    bytes: Zeroizing<Vec<u8>>,
    at: usize,
}

impl RandomBytes {
    fn new() -> Self {
        Self {
            bytes: crypto::random_bytes(64),
            at: 0,
        }
    }
}

impl Iterator for RandomBytes {
    type Item = u8;

    fn next(&mut self) -> Option<Self::Item> {
        if self.at == self.bytes.len() {
            self.bytes = crypto::random_bytes(64);
            self.at = 0;
        }
        let byte = self.bytes[self.at];
        self.at += 1;
        Some(byte)
    }
}

fn index(len: usize, bytes: &mut impl Iterator<Item = u8>) -> Option<usize> {
    if len == 0 || len > 256 {
        return None;
    }

    let accepted = 256 - (256 % len);
    for byte in bytes {
        let value = byte as usize;
        if value < accepted {
            return Some(value % len);
        }
    }
    None
}

fn draw(len: usize, bytes: &mut RandomBytes) -> usize {
    // `RandomBytes` never ends, so the only way `index` declines is a `len`
    // outside a byte's range — which the assertion above `MAXIMUM_LENGTH`
    // rules out. Naming that here rather than the byte source, so a panic
    // sends the next reader to the two constants instead of to `crypto`.
    index(len, bytes).expect("every length drawn from is within a byte's range")
}

/// Generates a password that contains every enabled character class.
pub fn password(recipe: &Recipe) -> Result<SecretString> {
    if recipe.length < crate::health::MINIMUM_LENGTH {
        return Err(Error::InvalidRecipe("length is below the minimum"));
    }
    if recipe.length > MAXIMUM_LENGTH {
        return Err(Error::InvalidRecipe("length is above the maximum"));
    }

    let mut classes = Vec::with_capacity(4);
    if recipe.lowercase {
        classes.push(LOWERCASE);
    }
    if recipe.uppercase {
        classes.push(UPPERCASE);
    }
    if recipe.digits {
        classes.push(DIGITS);
    }
    if recipe.symbols {
        classes.push(SYMBOLS);
    }
    if classes.is_empty() {
        return Err(Error::InvalidRecipe("no character classes are enabled"));
    }

    let mut alphabet = Vec::with_capacity(94);
    for class in &classes {
        alphabet.extend_from_slice(class);
    }

    let mut random = RandomBytes::new();
    let mut characters = Zeroizing::new(Vec::with_capacity(recipe.length));
    for class in classes {
        characters.push(class[draw(class.len(), &mut random)]);
    }
    while characters.len() < recipe.length {
        characters.push(alphabet[draw(alphabet.len(), &mut random)]);
    }

    for upper in (1..characters.len()).rev() {
        let other = draw(upper + 1, &mut random);
        characters.swap(upper, other);
    }

    let value = String::from_utf8(std::mem::take(&mut *characters))
        .expect("the generator's alphabets contain only ASCII");
    Ok(SecretString::new(value))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn all_classes(length: usize) -> Recipe {
        Recipe {
            length,
            lowercase: true,
            uppercase: true,
            digits: true,
            symbols: true,
        }
    }

    #[test]
    fn a_generated_password_has_the_requested_length() {
        let generated = password(&all_classes(37)).unwrap();
        assert_eq!(generated.len(), 37);
    }

    #[test]
    fn every_enabled_class_appears_in_every_password() {
        for _ in 0..256 {
            let generated = password(&all_classes(20)).unwrap();
            let value = generated.expose();
            assert!(value.bytes().any(|byte| byte.is_ascii_lowercase()));
            assert!(value.bytes().any(|byte| byte.is_ascii_uppercase()));
            assert!(value.bytes().any(|byte| byte.is_ascii_digit()));
            assert!(value.bytes().any(|byte| byte.is_ascii_punctuation()));
        }
    }

    #[test]
    fn a_disabled_class_never_appears() {
        let recipe = Recipe {
            length: 40,
            lowercase: true,
            uppercase: false,
            digits: true,
            symbols: false,
        };
        for _ in 0..256 {
            let generated = password(&recipe).unwrap();
            assert!(generated
                .expose()
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit()));
        }
    }

    #[test]
    fn two_calls_do_not_return_the_same_password() {
        assert_ne!(
            password(&all_classes(20)).unwrap(),
            password(&all_classes(20)).unwrap()
        );
    }

    #[test]
    fn a_recipe_with_no_classes_enabled_is_an_error() {
        let recipe = Recipe {
            length: 20,
            lowercase: false,
            uppercase: false,
            digits: false,
            symbols: false,
        };
        assert!(matches!(password(&recipe), Err(Error::InvalidRecipe(_))));
    }

    #[test]
    fn a_length_outside_the_bounds_is_an_error() {
        let below = all_classes(crate::health::MINIMUM_LENGTH - 1);
        let above = all_classes(MAXIMUM_LENGTH + 1);
        assert!(matches!(password(&below), Err(Error::InvalidRecipe(_))));
        assert!(matches!(password(&above), Err(Error::InvalidRecipe(_))));
    }

    #[test]
    fn an_index_is_always_inside_the_requested_range() {
        for len in 1..=MAXIMUM_LENGTH {
            for byte in 0..=u8::MAX {
                if let Some(selected) = index(len, &mut [byte].into_iter()) {
                    assert!(selected < len);
                }
            }
        }
    }

    #[test]
    fn an_index_discards_the_rejection_zone() {
        let mut bytes = [188, 7].into_iter();
        assert_eq!(index(94, &mut bytes), Some(7));
    }

    /// The one property none of the tests above can see.
    ///
    /// Every enabled class is pushed into the first few slots and only the
    /// shuffle scatters them. Delete the Fisher-Yates loop and every other
    /// test here still passes — the length is right, each class is present,
    /// no disabled class appears, two calls still differ — while the class of
    /// the leading characters becomes fixed and knowable. That is the failure
    /// this exists to catch, and an unbiased shuffle quietly becoming biased
    /// has no other symptom.
    ///
    /// The bound is deliberately loose. Natural spread here is a few per cent;
    /// a shuffle that does not run puts every digit on one position, which is
    /// several hundred per cent out. Anything between the two would be a bug
    /// nobody has written yet.
    #[test]
    fn the_guaranteed_characters_do_not_stay_where_they_were_placed() {
        const LENGTH: usize = 12;
        const DRAWS: usize = 4_000;
        const TOLERANCE: f64 = 0.35;

        // Digits are the third class pushed, so a dead shuffle parks every one
        // of them at index 2.
        let mut digits_at = [0usize; LENGTH];
        for _ in 0..DRAWS {
            let generated = password(&all_classes(LENGTH)).unwrap();
            for (at, byte) in generated.expose().bytes().enumerate() {
                if byte.is_ascii_digit() {
                    digits_at[at] += 1;
                }
            }
        }

        let mean = digits_at.iter().sum::<usize>() as f64 / LENGTH as f64;
        assert!(mean > 0.0, "no digits were generated at all");
        for (at, count) in digits_at.iter().enumerate() {
            let deviation = (*count as f64 - mean).abs() / mean;
            assert!(
                deviation < TOLERANCE,
                "position {at} held {count} digits against a mean of {mean:.0}"
            );
        }
    }
}
