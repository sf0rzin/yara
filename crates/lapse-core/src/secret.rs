use std::fmt;

use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// A string that is wiped from memory on drop and never printed.
///
/// `Debug` and `Display` are deliberately redacted so a stray `dbg!`, log line,
/// or panic message can never leak a secret. Reading the value requires an
/// explicit [`SecretString::expose`] call, which makes leaks greppable.
#[derive(Clone, Default, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(transparent)]
pub struct SecretString(String);

impl SecretString {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// Returns the underlying secret. Every call site is an intentional
    /// disclosure — keep them few and short-lived.
    pub fn expose(&self) -> &str {
        &self.0
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }
}

impl From<&str> for SecretString {
    fn from(value: &str) -> Self {
        Self::new(value)
    }
}

impl From<String> for SecretString {
    fn from(value: String) -> Self {
        Self(value)
    }
}

impl fmt::Debug for SecretString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretString(<redacted>)")
    }
}

/// Constant-time equality, for comparing secrets without leaking a timing
/// signal about how many leading bytes matched.
impl PartialEq for SecretString {
    fn eq(&self, other: &Self) -> bool {
        use subtle::ConstantTimeEq;
        if self.0.len() != other.0.len() {
            return false;
        }
        self.0.as_bytes().ct_eq(other.0.as_bytes()).into()
    }
}

impl Eq for SecretString {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_output_is_redacted() {
        let secret = SecretString::new("hunter2");
        assert_eq!(format!("{secret:?}"), "SecretString(<redacted>)");
        assert!(!format!("{secret:?}").contains("hunter2"));
    }

    #[test]
    fn equality_compares_contents() {
        assert_eq!(SecretString::new("abc"), SecretString::new("abc"));
        assert_ne!(SecretString::new("abc"), SecretString::new("abd"));
        assert_ne!(SecretString::new("abc"), SecretString::new("abcd"));
    }

    #[test]
    fn secret_survives_a_round_trip_through_json() {
        let secret = SecretString::new("correct horse battery staple");
        let encoded = serde_json::to_string(&secret).unwrap();
        assert_eq!(encoded, "\"correct horse battery staple\"");
        let decoded: SecretString = serde_json::from_str(&encoded).unwrap();
        assert_eq!(decoded, secret);
    }
}
