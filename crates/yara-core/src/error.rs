use thiserror::Error;

/// Errors returned by the yara core.
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

    /// An import that could not be matched to any known format.
    ///
    /// Carries the header it actually found rather than a fixed message: the
    /// person reading this is being asked to explain why their export failed,
    /// and "could not read that file" tells them nothing they did not already
    /// know.
    #[error("{0}")]
    UnrecognisedFormat(String),

    /// A header asking for work nobody's software ever wrote.
    ///
    /// Separate from [`Error::Decrypt`] on purpose, and not an oracle: the KDF
    /// parameters sit in the clear in the file, so naming them tells an
    /// attacker only what they could already read. Returning in milliseconds is
    /// the whole point — the alternative is attempting the allocation the
    /// header asked for, and a flipped byte turning 64 MiB into 256 GiB takes
    /// the process down rather than failing.
    #[error("that file is damaged: {0}")]
    DamagedFile(&'static str),

    #[error("cannot generate a password: {0}")]
    InvalidRecipe(&'static str),

    #[error("{0}")]
    InvalidFolder(String),

    /// Says nothing about which character was wrong.
    ///
    /// Someone typing a kit from paper wants to know it did not work, and an
    /// attacker guessing at one should learn nothing about how close they got.
    #[error("that recovery kit is not valid")]
    InvalidRecoveryKit,

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

    /// A verification window wider than a handful of steps is not clock drift,
    /// it is a caller asking for every code ever issued to be accepted.
    #[error("OTP verification skew must be at most {max} steps, got {got}")]
    InvalidSkew { got: u64, max: u64 },

    #[error("item {0} not found")]
    ItemNotFound(uuid::Uuid),

    #[error("serialization failed: {0}")]
    Serde(#[from] serde_json::Error),

    #[error("system clock is before the Unix epoch")]
    ClockBeforeEpoch,
}

pub type Result<T> = std::result::Result<T, Error>;
