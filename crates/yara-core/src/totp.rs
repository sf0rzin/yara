//! HOTP (RFC 4226) and TOTP (RFC 6238), plus `otpauth://` URI parsing.
//!
//! This is what lets yara replace reaching for your phone.

use std::time::{SystemTime, UNIX_EPOCH};

use data_encoding::BASE32_NOPAD;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha1::Sha1;
use sha2::{Sha256, Sha512};
use url::Url;
use zeroize::Zeroizing;

use crate::error::{Error, Result};
use crate::secret::SecretString;

/// Hash function backing the OTP.
///
/// Practically every issuer uses SHA-1; the other two exist because RFC 6238
/// defines them and a handful of services emit them.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum TotpAlgorithm {
    #[default]
    #[serde(rename = "SHA1")]
    Sha1,
    #[serde(rename = "SHA256")]
    Sha256,
    #[serde(rename = "SHA512")]
    Sha512,
}

impl TotpAlgorithm {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Sha1 => "SHA1",
            Self::Sha256 => "SHA256",
            Self::Sha512 => "SHA512",
        }
    }

    fn parse(value: &str) -> Result<Self> {
        match value.to_ascii_uppercase().as_str() {
            "SHA1" => Ok(Self::Sha1),
            "SHA256" => Ok(Self::Sha256),
            "SHA512" => Ok(Self::Sha512),
            other => Err(Error::UnsupportedOtpAlgorithm(other.to_string())),
        }
    }
}

const DEFAULT_DIGITS: u32 = 6;
const DEFAULT_PERIOD: u64 = 30;

/// The widest verification window on offer: ten steps, five minutes at the
/// usual period.
///
/// A window is a tolerance for a clock that is wrong, and past a few steps it
/// stops being that and becomes "accept anything this account was ever issued".
/// Bounded here rather than trusted to the caller, because the caller is
/// eventually a command handler passing a number through from somewhere else,
/// and an unbounded one also means an unbounded loop.
const MAX_SKEW: u64 = 10;

/// Everything needed to generate codes for one account.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TotpConfig {
    /// The shared secret, base32-encoded as it appears in an `otpauth://` URI.
    pub secret: SecretString,
    #[serde(default)]
    pub algorithm: TotpAlgorithm,
    #[serde(default = "default_digits")]
    pub digits: u32,
    #[serde(default = "default_period")]
    pub period: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account: Option<String>,
}

fn default_digits() -> u32 {
    DEFAULT_DIGITS
}

fn default_period() -> u64 {
    DEFAULT_PERIOD
}

impl TotpConfig {
    /// Builds a config with the near-universal defaults: SHA-1, 6 digits, 30s.
    pub fn new(secret: impl Into<SecretString>) -> Self {
        Self {
            secret: secret.into(),
            algorithm: TotpAlgorithm::Sha1,
            digits: DEFAULT_DIGITS,
            period: DEFAULT_PERIOD,
            issuer: None,
            account: None,
        }
    }

    /// Checks the parameters and that the secret is decodable, so a bad
    /// enrollment fails at save time rather than silently producing codes that
    /// never work.
    pub fn validate(&self) -> Result<()> {
        if !(6..=10).contains(&self.digits) {
            return Err(Error::InvalidDigits(self.digits));
        }
        if self.period == 0 {
            return Err(Error::InvalidPeriod);
        }
        self.decode_secret()?;
        Ok(())
    }

    /// Decodes the base32 secret, tolerating lowercase, padding, and the spaces
    /// that services often put in secrets shown for manual entry.
    fn decode_secret(&self) -> Result<Zeroizing<Vec<u8>>> {
        let normalized: String = self
            .secret
            .expose()
            .chars()
            .filter(|c| !c.is_whitespace() && *c != '-' && *c != '=')
            .map(|c| c.to_ascii_uppercase())
            .collect();

        if normalized.is_empty() {
            return Err(Error::InvalidBase32);
        }

        BASE32_NOPAD
            .decode(normalized.as_bytes())
            .map(Zeroizing::new)
            .map_err(|_| Error::InvalidBase32)
    }

    /// Generates the code for a specific Unix timestamp.
    pub fn generate_at(&self, unix_seconds: u64) -> Result<String> {
        if !(6..=10).contains(&self.digits) {
            return Err(Error::InvalidDigits(self.digits));
        }
        if self.period == 0 {
            return Err(Error::InvalidPeriod);
        }

        let key = self.decode_secret()?;
        let counter = unix_seconds / self.period;
        Ok(hotp(&key, counter, self.digits, self.algorithm))
    }

    /// Generates the code for right now.
    pub fn generate(&self) -> Result<String> {
        self.generate_at(unix_now()?)
    }

    /// Seconds until the current code rolls over, for the countdown ring.
    pub fn seconds_remaining_at(&self, unix_seconds: u64) -> u64 {
        if self.period == 0 {
            return 0;
        }
        self.period - (unix_seconds % self.period)
    }

    pub fn seconds_remaining(&self) -> Result<u64> {
        Ok(self.seconds_remaining_at(unix_now()?))
    }

    /// Verifies a user-supplied code, allowing `skew` steps of clock drift on
    /// either side. Comparison is constant-time.
    ///
    /// Everything is checked before any arithmetic happens. `period` is
    /// `#[serde(default)]`, which supplies 30 only when the field is *absent*,
    /// and nothing revalidates a config on load — so a hand-edited vault, or
    /// an item that arrived over sync, can carry `"period": 0` and reach the
    /// division here. Dividing by it panics, the release profile is
    /// `panic = "abort"`, and the dump of an aborted yara is a dump of a
    /// process holding the whole vault in memory.
    pub fn verify_at(&self, code: &str, unix_seconds: u64, skew: u64) -> Result<bool> {
        use subtle::ConstantTimeEq;

        self.validate()?;
        if skew > MAX_SKEW {
            return Err(Error::InvalidSkew {
                got: skew,
                max: MAX_SKEW,
            });
        }

        let key = self.decode_secret()?;
        let candidate = code.trim();
        let mut matched = false;

        // Counters, not timestamps. The old loop multiplied each step back
        // into seconds only for `generate_at` to divide it out again, and that
        // multiply is what overflowed — a panic in debug, a wrapped counter
        // that silently checks the wrong codes in release.
        let current = unix_seconds / self.period;
        for counter in current.saturating_sub(skew)..=current.saturating_add(skew) {
            let expected = hotp(&key, counter, self.digits, self.algorithm);
            // Keep going after a match so the loop runs a fixed number of times.
            matched |= bool::from(expected.as_bytes().ct_eq(candidate.as_bytes()));
        }

        Ok(matched)
    }

    /// Parses an `otpauth://totp/...` URI, the format QR codes encode.
    pub fn from_uri(uri: &str) -> Result<Self> {
        let url = Url::parse(uri).map_err(|_| Error::InvalidOtpUri("not a valid URI"))?;

        if url.scheme() != "otpauth" {
            return Err(Error::InvalidOtpUri("scheme must be otpauth"));
        }
        if url.host_str().map(str::to_ascii_lowercase).as_deref() != Some("totp") {
            return Err(Error::InvalidOtpUri("only totp is supported"));
        }

        let mut config = Self {
            secret: SecretString::default(),
            algorithm: TotpAlgorithm::Sha1,
            digits: DEFAULT_DIGITS,
            period: DEFAULT_PERIOD,
            issuer: None,
            account: None,
        };

        let mut has_secret = false;
        for (key, value) in url.query_pairs() {
            match key.as_ref() {
                "secret" => {
                    config.secret = SecretString::new(value.as_ref());
                    has_secret = true;
                }
                "algorithm" => config.algorithm = TotpAlgorithm::parse(value.as_ref())?,
                "digits" => {
                    config.digits = value
                        .parse()
                        .map_err(|_| Error::InvalidOtpUri("digits is not a number"))?;
                }
                "period" => {
                    config.period = value
                        .parse()
                        .map_err(|_| Error::InvalidOtpUri("period is not a number"))?;
                }
                "issuer" => config.issuer = Some(value.into_owned()),
                _ => {}
            }
        }

        if !has_secret {
            return Err(Error::InvalidOtpUri("missing secret parameter"));
        }

        // The label is `Issuer:Account` or just `Account`. An issuer in the
        // label is only used when the query parameter did not supply one.
        let label = percent_decode(url.path().trim_start_matches('/'));
        if !label.is_empty() {
            match label.split_once(':') {
                Some((issuer, account)) => {
                    if config.issuer.is_none() && !issuer.is_empty() {
                        config.issuer = Some(issuer.trim().to_string());
                    }
                    config.account = Some(account.trim().to_string());
                }
                None => config.account = Some(label),
            }
        }

        config.validate()?;
        Ok(config)
    }

    /// Renders this config back to an `otpauth://` URI.
    pub fn to_uri(&self) -> String {
        let account = self.account.as_deref().unwrap_or("");
        let label = match &self.issuer {
            Some(issuer) => format!("{issuer}:{account}"),
            None => account.to_string(),
        };

        let mut url = format!(
            "otpauth://totp/{}?secret={}",
            percent_encode(&label),
            self.secret.expose()
        );
        if let Some(issuer) = &self.issuer {
            url.push_str(&format!("&issuer={}", percent_encode(issuer)));
        }
        url.push_str(&format!(
            "&algorithm={}&digits={}&period={}",
            self.algorithm.as_str(),
            self.digits,
            self.period
        ));
        url
    }
}

macro_rules! hmac_digest {
    ($hash:ty, $key:expr, $message:expr) => {{
        let mut mac =
            <Hmac<$hash> as Mac>::new_from_slice($key).expect("HMAC accepts keys of any length");
        mac.update($message);
        mac.finalize().into_bytes().to_vec()
    }};
}

/// RFC 4226 HOTP with the RFC 6238 hash options.
fn hotp(key: &[u8], counter: u64, digits: u32, algorithm: TotpAlgorithm) -> String {
    let message = counter.to_be_bytes();

    let digest: Vec<u8> = match algorithm {
        TotpAlgorithm::Sha1 => hmac_digest!(Sha1, key, &message),
        TotpAlgorithm::Sha256 => hmac_digest!(Sha256, key, &message),
        TotpAlgorithm::Sha512 => hmac_digest!(Sha512, key, &message),
    };

    // Dynamic truncation: the low nibble of the last byte picks a 4-byte window.
    let offset = (digest[digest.len() - 1] & 0x0f) as usize;
    let binary = (u64::from(digest[offset] & 0x7f) << 24)
        | (u64::from(digest[offset + 1]) << 16)
        | (u64::from(digest[offset + 2]) << 8)
        | u64::from(digest[offset + 3]);

    let code = binary % 10u64.pow(digits);
    format!("{code:0width$}", width = digits as usize)
}

fn unix_now() -> Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|_| Error::ClockBeforeEpoch)
}

fn percent_decode(input: &str) -> String {
    percent_encoding::percent_decode_str(input)
        .decode_utf8_lossy()
        .into_owned()
}

fn percent_encode(input: &str) -> String {
    const ESCAPED: &percent_encoding::AsciiSet = &percent_encoding::NON_ALPHANUMERIC
        .remove(b'-')
        .remove(b'.')
        .remove(b'_')
        .remove(b'~');
    percent_encoding::utf8_percent_encode(input, ESCAPED).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use data_encoding::BASE32_NOPAD as B32;

    /// RFC 6238 Appendix B uses the ASCII seed "12345678901234567890", extended
    /// by repetition to the hash's block-adjacent length for SHA-256/512.
    fn rfc_secret(len: usize) -> String {
        let seed: Vec<u8> = b"1234567890".iter().copied().cycle().take(len).collect();
        B32.encode(&seed)
    }

    fn rfc_config(algorithm: TotpAlgorithm) -> TotpConfig {
        let len = match algorithm {
            TotpAlgorithm::Sha1 => 20,
            TotpAlgorithm::Sha256 => 32,
            TotpAlgorithm::Sha512 => 64,
        };
        TotpConfig {
            secret: SecretString::new(rfc_secret(len)),
            algorithm,
            digits: 8,
            period: 30,
            issuer: None,
            account: None,
        }
    }

    #[test]
    fn matches_rfc6238_sha1_vectors() {
        let config = rfc_config(TotpAlgorithm::Sha1);
        for (time, expected) in [
            (59u64, "94287082"),
            (1_111_111_109, "07081804"),
            (1_111_111_111, "14050471"),
            (1_234_567_890, "89005924"),
            (2_000_000_000, "69279037"),
            (20_000_000_000, "65353130"),
        ] {
            assert_eq!(config.generate_at(time).unwrap(), expected, "at t={time}");
        }
    }

    #[test]
    fn matches_rfc6238_sha256_vectors() {
        let config = rfc_config(TotpAlgorithm::Sha256);
        for (time, expected) in [
            (59u64, "46119246"),
            (1_111_111_109, "68084774"),
            (1_111_111_111, "67062674"),
            (1_234_567_890, "91819424"),
            (2_000_000_000, "90698825"),
            (20_000_000_000, "77737706"),
        ] {
            assert_eq!(config.generate_at(time).unwrap(), expected, "at t={time}");
        }
    }

    #[test]
    fn matches_rfc6238_sha512_vectors() {
        let config = rfc_config(TotpAlgorithm::Sha512);
        for (time, expected) in [
            (59u64, "90693936"),
            (1_111_111_109, "25091201"),
            (1_111_111_111, "99943326"),
            (1_234_567_890, "93441116"),
            (2_000_000_000, "38618901"),
            (20_000_000_000, "47863826"),
        ] {
            assert_eq!(config.generate_at(time).unwrap(), expected, "at t={time}");
        }
    }

    #[test]
    fn six_digit_codes_are_the_default_and_are_zero_padded() {
        let config = TotpConfig::new(rfc_secret(20));
        let code = config.generate_at(59).unwrap();
        assert_eq!(code.len(), 6);
        // Truncated from the 8-digit vector 94287082.
        assert_eq!(code, "287082");
    }

    /// A timestamp that is an exact multiple of the 30 second period, so the
    /// window boundaries land where the arithmetic below expects them.
    const WINDOW_START: u64 = 1_000_000_020;

    #[test]
    fn the_code_is_stable_across_one_period_and_changes_at_the_boundary() {
        let config = TotpConfig::new(rfc_secret(20));
        let at_start = config.generate_at(WINDOW_START).unwrap();
        let at_end = config.generate_at(WINDOW_START + 29).unwrap();
        let next_window = config.generate_at(WINDOW_START + 30).unwrap();
        assert_eq!(at_start, at_end);
        assert_ne!(at_start, next_window);
    }

    #[test]
    fn seconds_remaining_counts_down_to_the_boundary() {
        let config = TotpConfig::new(rfc_secret(20));
        assert_eq!(config.seconds_remaining_at(WINDOW_START), 30);
        assert_eq!(config.seconds_remaining_at(WINDOW_START + 1), 29);
        assert_eq!(config.seconds_remaining_at(WINDOW_START + 29), 1);
        assert_eq!(config.seconds_remaining_at(WINDOW_START + 30), 30);
    }

    #[test]
    fn verify_accepts_the_current_code_and_rejects_others() {
        let config = TotpConfig::new(rfc_secret(20));
        let now = 1_234_567_890;
        let code = config.generate_at(now).unwrap();
        assert!(config.verify_at(&code, now, 1).unwrap());
        assert!(!config.verify_at("000000", now, 1).unwrap());
    }

    #[test]
    fn verify_tolerates_clock_drift_within_the_allowed_skew() {
        let config = TotpConfig::new(rfc_secret(20));
        let now = 1_234_567_890;
        let previous = config.generate_at(now - 30).unwrap();
        assert!(config.verify_at(&previous, now, 1).unwrap());
        assert!(!config.verify_at(&previous, now, 0).unwrap());
    }

    #[test]
    fn verifying_against_a_zero_period_is_an_error_rather_than_a_crash() {
        // `#[serde(default)]` fills in 30 only when the field is absent, and
        // nothing revalidates a config on load — so a hand-edited vault or an
        // item that arrived over sync can carry this. The division used to
        // happen before anything looked at it, and under `panic = "abort"` a
        // divide by zero is a crash dump of a process holding the vault.
        let mut config = TotpConfig::new(rfc_secret(20));
        config.period = 0;

        assert!(matches!(
            config.verify_at("123456", 1_234_567_890, 1),
            Err(Error::InvalidPeriod)
        ));
    }

    #[test]
    fn verifying_with_absurd_digits_is_an_error_too() {
        let mut config = TotpConfig::new(rfc_secret(20));
        config.digits = 20;
        assert!(matches!(
            config.verify_at("123456", 1_234_567_890, 1),
            Err(Error::InvalidDigits(20))
        ));
    }

    #[test]
    fn an_absurd_skew_is_refused_rather_than_attempted() {
        // The old range expression overflowed on the way to a loop that would
        // have run for the rest of the decade. A window this wide is not
        // clock drift, it is "accept every code this account ever had".
        let config = TotpConfig::new(rfc_secret(20));

        let started = std::time::Instant::now();
        assert!(matches!(
            config.verify_at("123456", 1_234_567_890, u64::MAX),
            Err(Error::InvalidSkew {
                got: u64::MAX,
                max: _
            })
        ));
        assert!(started.elapsed() < std::time::Duration::from_secs(1));
    }

    #[test]
    fn verifying_at_the_end_of_time_does_not_overflow() {
        // The counter for the last representable second, with the window
        // running off the end of it. Adding the skew unsaturated panics in
        // debug and wraps in release, and a wrapped counter checks codes from
        // 1970 against a code from now.
        let mut config = TotpConfig::new(rfc_secret(20));
        config.period = 1;

        assert!(!config.verify_at("123456", u64::MAX, 10).unwrap());

        let code = config.generate_at(u64::MAX).unwrap();
        assert!(config.verify_at(&code, u64::MAX, 10).unwrap());
    }

    #[test]
    fn secrets_with_spaces_padding_and_lowercase_still_decode() {
        let canonical = TotpConfig::new("GEZDGNBVGY3TQOJQ");
        let messy = TotpConfig::new("gezd gnbv-gy3t qojq====");
        assert_eq!(
            canonical.generate_at(59).unwrap(),
            messy.generate_at(59).unwrap()
        );
    }

    #[test]
    fn parses_a_full_otpauth_uri() {
        let config = TotpConfig::from_uri(
            "otpauth://totp/GitHub:anthony?secret=GEZDGNBVGY3TQOJQ&issuer=GitHub&algorithm=SHA256&digits=8&period=60",
        )
        .unwrap();

        assert_eq!(config.secret.expose(), "GEZDGNBVGY3TQOJQ");
        assert_eq!(config.issuer.as_deref(), Some("GitHub"));
        assert_eq!(config.account.as_deref(), Some("anthony"));
        assert_eq!(config.algorithm, TotpAlgorithm::Sha256);
        assert_eq!(config.digits, 8);
        assert_eq!(config.period, 60);
    }

    #[test]
    fn parsing_applies_defaults_for_omitted_parameters() {
        let config =
            TotpConfig::from_uri("otpauth://totp/anthony?secret=GEZDGNBVGY3TQOJQ").unwrap();
        assert_eq!(config.algorithm, TotpAlgorithm::Sha1);
        assert_eq!(config.digits, 6);
        assert_eq!(config.period, 30);
        assert_eq!(config.account.as_deref(), Some("anthony"));
        assert_eq!(config.issuer, None);
    }

    #[test]
    fn parsing_decodes_percent_escapes_in_the_label() {
        let config = TotpConfig::from_uri(
            "otpauth://totp/ACME%20Co:john%40example.com?secret=GEZDGNBVGY3TQOJQ",
        )
        .unwrap();
        assert_eq!(config.issuer.as_deref(), Some("ACME Co"));
        assert_eq!(config.account.as_deref(), Some("john@example.com"));
    }

    #[test]
    fn a_uri_without_a_secret_is_rejected() {
        assert!(matches!(
            TotpConfig::from_uri("otpauth://totp/anthony"),
            Err(Error::InvalidOtpUri(_))
        ));
    }

    #[test]
    fn hotp_uris_are_rejected() {
        assert!(matches!(
            TotpConfig::from_uri("otpauth://hotp/anthony?secret=GEZDGNBVGY3TQOJQ&counter=1"),
            Err(Error::InvalidOtpUri(_))
        ));
    }

    #[test]
    fn a_uri_with_an_undecodable_secret_is_rejected() {
        assert!(matches!(
            TotpConfig::from_uri("otpauth://totp/anthony?secret=not!valid!base32"),
            Err(Error::InvalidBase32)
        ));
    }

    #[test]
    fn uri_round_trips() {
        let original = TotpConfig::from_uri(
            "otpauth://totp/ACME%20Co:john%40example.com?secret=GEZDGNBVGY3TQOJQ&issuer=ACME%20Co&algorithm=SHA512&digits=8&period=45",
        )
        .unwrap();
        let reparsed = TotpConfig::from_uri(&original.to_uri()).unwrap();
        assert_eq!(original, reparsed);
    }

    #[test]
    fn validation_rejects_out_of_range_parameters() {
        let mut config = TotpConfig::new(rfc_secret(20));
        config.digits = 5;
        assert!(matches!(config.validate(), Err(Error::InvalidDigits(5))));

        config.digits = 6;
        config.period = 0;
        assert!(matches!(config.validate(), Err(Error::InvalidPeriod)));
    }
}
