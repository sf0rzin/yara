//! The approval-gated credential broker.
//!
//! Agents ask this for credentials instead of being handed them. Every request
//! is answered by a human, scoped to one item and one purpose, and written to
//! an audit log.
//!
//! See `docs/agent-access.md` for the design and, more importantly, for what
//! the threat model does not cover.
//!
//! The crate is split so the parts that make security decisions carry no I/O:
//! [`grant`] and [`audit`] are pure and exhaustively tested, and [`transport`]
//! is the only module that touches the operating system.

//! Unsafe code is denied everywhere except [`platform`], which is the handful
//! of Win32 calls needed to find out which program is on the other end of the
//! pipe. Isolating it keeps the rest of the crate provably safe.
#![deny(unsafe_code)]

pub mod audit;
pub mod client;
pub mod grant;
pub mod platform;
pub mod protocol;
pub mod transport;

pub use audit::{Action, AuditLog, Entry, Outcome};
pub use grant::{ClientId, Grant, GrantStore, Scope};
pub use protocol::{AccessRequest, Field, Intent, ItemRef, Refusal, Request, Response};

use std::time::{SystemTime, UNIX_EPOCH};

/// Seconds since the Unix epoch.
///
/// Every decision function takes the time as an argument rather than reading it
/// internally, so expiry can be tested without waiting for it.
pub fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
