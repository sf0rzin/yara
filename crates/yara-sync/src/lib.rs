//! Encrypted vault sync.
//!
//! This server stores ciphertext it cannot read and verifies signatures it
//! cannot forge. It never sees a password, a password hash, or any value that
//! would let it act as a user — see [`auth`] for why that is possible without
//! the client keeping a secret on the wire.
//!
//! What it does learn is metadata: how many items an account holds, roughly
//! how large each one is, when each changed, and which addresses connected
//! when. That is written down in `docs/hosting.md` where users read it, not
//! only here.
//!
//! The split mirrors `yara-broker`: [`auth`] decides who gets in and is pure,
//! [`store`] is the only module that touches a database, and [`api`] is the
//! only one that knows about HTTP.

#![deny(unsafe_code)]

pub mod api;
pub mod auth;
pub mod store;

use std::time::{SystemTime, UNIX_EPOCH};

/// Seconds since the Unix epoch.
///
/// Taken as an argument by every decision function rather than read inside
/// one, so expiry and replay windows can be tested without waiting.
pub fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}
