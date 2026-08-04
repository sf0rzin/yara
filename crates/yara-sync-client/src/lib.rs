//! Talking to `yara-sync`.
//!
//! Split so the two parts that are easy to get quietly wrong carry no I/O:
//! [`signing`] produces the exact bytes the server verifies, and [`merge`]
//! decides what wins when two machines changed the same item. Both are pure
//! and tested against their own truth tables; [`client`] is the only module
//! that opens a socket.
//!
//! What never happens here: sending anything derived from the password. The
//! client proves who it is by signing, and the server holds only a public key.

#![deny(unsafe_code)]

pub mod client;
pub mod merge;
pub mod signing;

pub use client::{Account, Client, Enrolment, Error, ItemPage, Result, SyncItem};
pub use merge::{reconcile, Resolution};
