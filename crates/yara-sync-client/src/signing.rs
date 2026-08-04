//! Signing a request the way `yara-sync` verifies one.
//!
//! Kept apart from the HTTP so it can be tested against the server's own
//! verifier without a socket. The two sides agree on exactly one thing — the
//! bytes that get signed — and if they ever disagree the failure is a 401 with
//! no explanation, which is the worst kind of bug to debug at the wire.
//!
//! ```text
//! method \n path \n timestamp \n nonce \n sha256(body)
//! ```
//!
//! The body is committed to by hash rather than by value, so a large push does
//! not have to be held twice. The path is the path only: a query string is not
//! covered, so nothing that changes meaning may live in one.

use base64::Engine as _;
use sha2::{Digest, Sha256};
use yara_core::crypto;

/// Bytes of randomness in a nonce. The server requires at least sixteen.
const NONCE_BYTES: usize = 16;

/// The headers that carry a signature.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedHeaders {
    pub authorization: String,
    pub timestamp: String,
    pub nonce: String,
    pub signature: String,
}

impl SignedHeaders {
    /// As `(name, value)` pairs, ready to hang on a request.
    pub fn pairs(&self) -> [(&'static str, &str); 4] {
        [
            ("authorization", self.authorization.as_str()),
            ("x-yara-timestamp", self.timestamp.as_str()),
            ("x-yara-nonce", self.nonce.as_str()),
            ("x-yara-signature", self.signature.as_str()),
        ]
    }
}

/// The exact bytes both sides sign over.
pub fn canonical(method: &str, path: &str, timestamp: i64, nonce: &str, body: &[u8]) -> Vec<u8> {
    let digest = Sha256::digest(body);
    let mut hex = String::with_capacity(digest.len() * 2);
    for byte in digest {
        use std::fmt::Write as _;
        let _ = write!(hex, "{byte:02x}");
    }

    format!("{method}\n{path}\n{timestamp}\n{nonce}\n{hex}").into_bytes()
}

/// A fresh nonce. Random rather than a counter: a counter that resets — a
/// reinstall, a restored backup — starts replaying its own history.
pub fn fresh_nonce() -> String {
    base64::engine::general_purpose::STANDARD.encode(crypto::random_bytes(NONCE_BYTES))
}

/// Everything a signature covers, plus who is making it.
///
/// A struct rather than a parameter list because these are three different
/// things — who is asking, what they are asking, and when — and a call site
/// with eight positional arguments is a call site where two of them get
/// swapped eventually.
pub struct RequestToSign<'a> {
    pub account_id: &'a str,
    pub device_id: &'a str,
    pub method: &'a str,
    pub path: &'a str,
    pub body: &'a [u8],
    pub timestamp: i64,
    pub nonce: String,
}

/// Signs one request.
///
/// `sign` is a closure rather than a key so the caller can hold the device key
/// however it likes, and so this module never needs to own key material.
pub fn sign_request(
    request: RequestToSign<'_>,
    sign: impl FnOnce(&[u8]) -> [u8; 64],
) -> SignedHeaders {
    let message = canonical(
        request.method,
        request.path,
        request.timestamp,
        &request.nonce,
        request.body,
    );
    let signature = base64::engine::general_purpose::STANDARD.encode(sign(&message));

    SignedHeaders {
        authorization: format!("yara1 {}/{}", request.account_id, request.device_id),
        timestamp: request.timestamp.to_string(),
        nonce: request.nonce,
        signature,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_canonical_form_separates_every_field() {
        let signed = canonical("POST", "/api/v1/items", 1_800_000_000, "abc", b"body");
        let text = String::from_utf8(signed).unwrap();
        let lines: Vec<&str> = text.split('\n').collect();

        assert_eq!(lines.len(), 5);
        assert_eq!(lines[0], "POST");
        assert_eq!(lines[1], "/api/v1/items");
        assert_eq!(lines[2], "1800000000");
        assert_eq!(lines[3], "abc");
        assert_eq!(lines[4].len(), 64, "a sha256 in hex");
    }

    #[test]
    fn changing_any_field_changes_what_is_signed() {
        let base = canonical("POST", "/api/v1/items", 1, "n", b"b");

        for other in [
            canonical("GET", "/api/v1/items", 1, "n", b"b"),
            canonical("POST", "/api/v1/account", 1, "n", b"b"),
            canonical("POST", "/api/v1/items", 2, "n", b"b"),
            canonical("POST", "/api/v1/items", 1, "m", b"b"),
            canonical("POST", "/api/v1/items", 1, "n", b"c"),
        ] {
            assert_ne!(base, other);
        }
    }

    #[test]
    fn the_body_is_committed_to_by_hash_not_by_value() {
        let big = vec![b'x'; 10_000];
        let signed = canonical("POST", "/p", 1, "n", &big);
        assert!(signed.len() < 200, "the payload must not be inlined");
    }

    #[test]
    fn a_nonce_is_long_enough_and_never_repeats() {
        let a = fresh_nonce();
        let b = fresh_nonce();

        assert_ne!(a, b);
        // The server rejects anything shorter than sixteen characters.
        assert!(a.len() >= 16, "{a} is too short");
    }

    #[test]
    fn the_authorization_header_is_the_shape_the_server_parses() {
        let headers = sign_request(
            RequestToSign {
                account_id: "acct-1",
                device_id: "dev-2",
                method: "GET",
                path: "/api/v1/items",
                body: b"",
                timestamp: 1_800_000_000,
                nonce: "nonce-0000000000000000".into(),
            },
            |_| [7u8; 64],
        );

        assert_eq!(headers.authorization, "yara1 acct-1/dev-2");
        assert_eq!(headers.timestamp, "1800000000");
        assert_eq!(headers.pairs().len(), 4);
    }
}
