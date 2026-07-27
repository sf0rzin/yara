use thiserror::Error;

/// Errors returned by the lapse core.
///
/// Variants are deliberately coarse around cryptographic failures: callers must
/// not be able to distinguish "wrong password" from "tampered ciphertext", since
/// both surface as an AEAD authentication failure.
#[derive(Debug, Error)]
pub enum Error {
    #[error("key derivation failed: {0}")]
    Kdf(String),

    #[error("encryption failed")]
    Encrypt,

    #[error("could not decrypt: wrong password or corrupted data")]
    Decrypt,

    #[error("unsupported vault format version {0}")]
    UnsupportedFormat(u32),

    #[error("unsupported KDF algorithm {0:?}")]
    UnsupportedKdf(String),

    #[error("malformed vault: {0}")]
    Malformed(&'static str),

    #[error("invalid base32 secret")]
    InvalidBase32,

    #[error("invalid otpauth URI: {0}")]
    InvalidOtpUri(&'static str),

    #[error("could not read that image")]
    ImageDecode,

    #[error("no QR code found in that image")]
    NoQrCode,

    #[error("that QR code is not a two-factor setup code")]
    QrNotOtpauth,

    #[error("unsupported OTP algorithm {0:?}")]
    UnsupportedOtpAlgorithm(String),

    #[error("OTP digits must be between 6 and 10, got {0}")]
    InvalidDigits(u32),

    #[error("OTP period must be greater than zero")]
    InvalidPeriod,

    #[error("item {0} not found")]
    ItemNotFound(uuid::Uuid),

    #[error("serialization failed: {0}")]
    Serde(#[from] serde_json::Error),

    #[error("system clock is before the Unix epoch")]
    ClockBeforeEpoch,
}

pub type Result<T> = std::result::Result<T, Error>;
