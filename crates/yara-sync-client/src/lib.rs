//! Talking to `yara-sync`.
//!
//! Split so the parts that are easy to get quietly wrong carry no I/O:
//! [`signing`] produces the exact bytes the server verifies, [`merge`] decides
//! what wins when two machines changed the same item, and [`deletes`] decides
//! whether an incoming deletion is one this account actually made. All three
//! are tested against their own truth tables; [`client`] is the only module
//! that opens a socket.
//!
//! What never happens here: sending anything derived from the password. The
//! client proves who it is by signing, and the server holds only a public key.

#![deny(unsafe_code)]

pub mod client;
pub mod deletes;
pub mod merge;
pub mod signing;

pub use client::{Account, Client, Enrolment, Error, ItemPage, Result, SyncItem};
pub use deletes::{proven_deletion, seal_proof};
pub use merge::{reconcile, Resolution};
