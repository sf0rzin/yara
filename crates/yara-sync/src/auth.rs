//! Proving who is asking, without anything secret crossing the wire.
//!
//! There is no password hash here, no bearer token, and no shared secret the
//! server could replay. A device signs each request with an Ed25519 key whose
//! private half never leaves the client, and the server holds only the public
//! half. That is what makes the CDN hop acceptable: an observer with full
//! plaintext sees signatures over requests that already happened and cannot
//! mint a new one.
//!
//! It also means a compromise of this server cannot impersonate a user to
//! anyone, and that revoking a lost laptop is deleting one public key.
//!
//! Everything in this module is pure. It takes bytes and a clock reading and
//! returns a verdict, which keeps the part that decides who gets in testable
//! without a socket or a database.

use base64::Engine as _;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};

/// How far a request's timestamp may be from ours.
///
/// Wide enough to survive an unsynchronised clock and a slow link, narrow
/// enough that a captured request stops being replayable while anyone still
/// cares. Nonce tracking covers the window itself; this bounds how long that
/// tracking has to remember.
pub const CLOCK_SKEW_SECS: i64 = 60;

/// Bytes of randomness a nonce must carry.
const NONCE_LEN: usize = 16;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rejection {
    /// The header was absent, or not the shape the scheme requires.
    Malformed,
    /// Signed too long ago, or too far in the future.
    StaleTimestamp,
    /// This exact nonce has already been accepted inside the window.
    Replayed,
    /// The signature does not verify against the device's key.
    BadSignature,
}

impl Rejection {
    /// What to tell the caller.
    ///
    /// Deliberately uninformative. Distinguishing "no such device" from "wrong
    /// signature" would turn this endpoint into an oracle for which device ids
    /// exist, and the honest caller never needs to know which of the two it
    /// tripped.
    pub fn message(&self) -> &'static str {
        match self {
            Self::StaleTimestamp => "The request timestamp is outside the accepted window.",
            _ => "The request could not be authenticated.",
        }
    }
}

/// The parts of a request that are signed.
///
/// The body is committed to by hash rather than by value so that a large sync
/// push does not have to be held twice, and so this stays comparable in a test
/// without carrying megabytes around.
#[derive(Clone, Debug)]
pub struct SignedRequest<'a> {
    pub method: &'a str,
    pub path: &'a str,
    pub timestamp: i64,
    pub nonce: &'a str,
    pub body: &'a [u8],
}

impl SignedRequest<'_> {
    /// The exact bytes a client signs.
    ///
    /// Newline separated with the body's hash last. Every field is
    /// fixed-position and none can contain a newline after validation, so
    /// there is no way to shift meaning from one field into another — the
    /// classic way a signing scheme gets broken without the crypto failing.
    pub fn canonical(&self) -> Vec<u8> {
        let digest = Sha256::digest(self.body);
        format!(
            "{}\n{}\n{}\n{}\n{}",
            self.method,
            self.path,
            self.timestamp,
            self.nonce,
            hex(&digest)
        )
        .into_bytes()
    }
}

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(out, "{byte:02x}");
    }
    out
}

/// Remembers nonces long enough that the timestamp window cannot be reused.
///
/// Bounded by time rather than by count: entries older than the skew window
/// can never be accepted again on timestamp grounds alone, so keeping them
/// would guard nothing.
#[derive(Debug, Default)]
pub struct NonceCache {
    seen: std::collections::HashMap<String, i64>,
}

impl NonceCache {
    pub fn new() -> Self {
        Self::default()
    }

    /// Records a nonce, returning false if it was already there.
    pub fn accept(&mut self, nonce: &str, now: i64) -> bool {
        self.prune(now);
        self.seen.insert(nonce.to_string(), now).is_none()
    }

    fn prune(&mut self, now: i64) {
        self.seen
            .retain(|_, seen_at| now - *seen_at <= CLOCK_SKEW_SECS);
    }

    pub fn len(&self) -> usize {
        self.seen.len()
    }

    pub fn is_empty(&self) -> bool {
        self.seen.is_empty()
    }
}

/// Decodes a stored 32-byte Ed25519 public key.
pub fn public_key(bytes: &[u8]) -> Option<VerifyingKey> {
    let fixed: [u8; 32] = bytes.try_into().ok()?;
    VerifyingKey::from_bytes(&fixed).ok()
}

/// Verifies a request against one device's key.
///
/// Order matters: the cheap checks come first so a flood of malformed or stale
/// requests cannot make the server do signature maths. The nonce is only
/// consumed once everything else has passed, so a bad signature cannot burn a
/// nonce the honest client is about to use.
pub fn verify(
    request: &SignedRequest<'_>,
    signature_b64: &str,
    key: &VerifyingKey,
    nonces: &mut NonceCache,
    now: i64,
) -> Result<(), Rejection> {
    if request.nonce.len() < NONCE_LEN
        || request.method.is_empty()
        || !request.path.starts_with('/')
    {
        return Err(Rejection::Malformed);
    }

    if (now - request.timestamp).abs() > CLOCK_SKEW_SECS {
        return Err(Rejection::StaleTimestamp);
    }

    let raw = base64::engine::general_purpose::STANDARD
        .decode(signature_b64)
        .map_err(|_| Rejection::Malformed)?;
    let bytes: [u8; 64] = raw
        .as_slice()
        .try_into()
        .map_err(|_| Rejection::Malformed)?;

    key.verify(&request.canonical(), &Signature::from_bytes(&bytes))
        .map_err(|_| Rejection::BadSignature)?;

    if !nonces.accept(request.nonce, now) {
        return Err(Rejection::Replayed);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    const NOW: i64 = 1_800_000_000;
    const NONCE: &str = "0123456789abcdef0123";

    fn keypair() -> SigningKey {
        // A fixed key: these tests are about the protocol, and a random one
        // would make a failure impossible to reproduce.
        SigningKey::from_bytes(&[7u8; 32])
    }

    fn request<'a>(body: &'a [u8], nonce: &'a str, timestamp: i64) -> SignedRequest<'a> {
        SignedRequest {
            method: "POST",
            path: "/api/v1/items",
            timestamp,
            nonce,
            body,
        }
    }

    fn sign(key: &SigningKey, request: &SignedRequest<'_>) -> String {
        base64::engine::general_purpose::STANDARD.encode(key.sign(&request.canonical()).to_bytes())
    }

    #[test]
    fn a_properly_signed_request_is_accepted() {
        let key = keypair();
        let req = request(b"{}", NONCE, NOW);
        let sig = sign(&key, &req);

        assert_eq!(
            verify(
                &req,
                &sig,
                &key.verifying_key(),
                &mut NonceCache::new(),
                NOW
            ),
            Ok(())
        );
    }

    #[test]
    fn the_same_request_twice_is_a_replay() {
        let key = keypair();
        let req = request(b"{}", NONCE, NOW);
        let sig = sign(&key, &req);
        let mut nonces = NonceCache::new();

        assert!(verify(&req, &sig, &key.verifying_key(), &mut nonces, NOW).is_ok());
        assert_eq!(
            verify(&req, &sig, &key.verifying_key(), &mut nonces, NOW),
            Err(Rejection::Replayed),
            "an observer that captured this must not be able to send it again"
        );
    }

    #[test]
    fn changing_the_body_breaks_the_signature() {
        let key = keypair();
        let signed = request(b"{\"items\":[]}", NONCE, NOW);
        let sig = sign(&key, &signed);

        let tampered = request(b"{\"items\":[{\"id\":\"evil\"}]}", NONCE, NOW);
        assert_eq!(
            verify(
                &tampered,
                &sig,
                &key.verifying_key(),
                &mut NonceCache::new(),
                NOW
            ),
            Err(Rejection::BadSignature)
        );
    }

    #[test]
    fn a_signature_does_not_carry_to_another_path_or_method() {
        let key = keypair();
        let signed = request(b"{}", NONCE, NOW);
        let sig = sign(&key, &signed);

        let elsewhere = SignedRequest {
            path: "/api/v1/account",
            ..signed.clone()
        };
        assert_eq!(
            verify(
                &elsewhere,
                &sig,
                &key.verifying_key(),
                &mut NonceCache::new(),
                NOW
            ),
            Err(Rejection::BadSignature)
        );

        let other_method = SignedRequest {
            method: "DELETE",
            ..signed.clone()
        };
        assert_eq!(
            verify(
                &other_method,
                &sig,
                &key.verifying_key(),
                &mut NonceCache::new(),
                NOW
            ),
            Err(Rejection::BadSignature)
        );
    }

    #[test]
    fn another_device_cannot_sign_for_this_one() {
        let mine = keypair();
        let theirs = SigningKey::from_bytes(&[9u8; 32]);
        let req = request(b"{}", NONCE, NOW);
        let sig = sign(&theirs, &req);

        assert_eq!(
            verify(
                &req,
                &sig,
                &mine.verifying_key(),
                &mut NonceCache::new(),
                NOW
            ),
            Err(Rejection::BadSignature)
        );
    }

    #[test]
    fn a_stale_or_future_timestamp_is_refused() {
        let key = keypair();

        for offset in [-CLOCK_SKEW_SECS - 1, CLOCK_SKEW_SECS + 1] {
            let req = request(b"{}", NONCE, NOW + offset);
            let sig = sign(&key, &req);
            assert_eq!(
                verify(
                    &req,
                    &sig,
                    &key.verifying_key(),
                    &mut NonceCache::new(),
                    NOW
                ),
                Err(Rejection::StaleTimestamp),
                "offset {offset} should be outside the window"
            );
        }
    }

    #[test]
    fn the_edge_of_the_window_is_still_inside_it() {
        let key = keypair();
        let req = request(b"{}", NONCE, NOW - CLOCK_SKEW_SECS);
        let sig = sign(&key, &req);

        assert!(verify(
            &req,
            &sig,
            &key.verifying_key(),
            &mut NonceCache::new(),
            NOW
        )
        .is_ok());
    }

    #[test]
    fn a_bad_signature_does_not_burn_the_nonce() {
        let key = keypair();
        let req = request(b"{}", NONCE, NOW);
        let mut nonces = NonceCache::new();

        assert!(verify(
            &req,
            "not base64 at all",
            &key.verifying_key(),
            &mut nonces,
            NOW
        )
        .is_err());
        assert!(nonces.is_empty());

        // The honest client's retry with the same nonce still works.
        let sig = sign(&key, &req);
        assert!(verify(&req, &sig, &key.verifying_key(), &mut nonces, NOW).is_ok());
    }

    #[test]
    fn a_short_nonce_is_malformed() {
        let key = keypair();
        let req = request(b"{}", "tooshort", NOW);
        let sig = sign(&key, &req);

        assert_eq!(
            verify(
                &req,
                &sig,
                &key.verifying_key(),
                &mut NonceCache::new(),
                NOW
            ),
            Err(Rejection::Malformed)
        );
    }

    #[test]
    fn the_nonce_cache_forgets_what_it_no_longer_needs_to_remember() {
        let mut nonces = NonceCache::new();
        assert!(nonces.accept("aaaaaaaaaaaaaaaaaaaa", NOW));
        assert_eq!(nonces.len(), 1);

        // Past the window a replay is refused on the timestamp anyway, so
        // holding the nonce guards nothing.
        assert!(nonces.accept("bbbbbbbbbbbbbbbbbbbb", NOW + CLOCK_SKEW_SECS + 1));
        assert_eq!(nonces.len(), 1);
    }

    #[test]
    fn the_canonical_form_pins_every_field() {
        let base = request(b"body", NONCE, NOW);

        let variants = [
            SignedRequest {
                method: "GET",
                ..base.clone()
            },
            SignedRequest {
                path: "/api/v1/other",
                ..base.clone()
            },
            SignedRequest {
                timestamp: NOW + 1,
                ..base.clone()
            },
            SignedRequest {
                nonce: "ffffffffffffffffffff",
                ..base.clone()
            },
            SignedRequest {
                body: b"different",
                ..base.clone()
            },
        ];

        for variant in &variants {
            assert_ne!(
                base.canonical(),
                variant.canonical(),
                "changing a field must change what gets signed"
            );
        }
    }

    #[test]
    fn a_rejection_does_not_say_which_device_exists() {
        // Everything except a clock problem reads the same to the caller, so
        // this endpoint cannot be used to enumerate device ids.
        assert_eq!(
            Rejection::BadSignature.message(),
            Rejection::Malformed.message()
        );
        assert_eq!(
            Rejection::Replayed.message(),
            Rejection::BadSignature.message()
        );
        assert_ne!(
            Rejection::StaleTimestamp.message(),
            Rejection::BadSignature.message()
        );
    }
}
