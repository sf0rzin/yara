//! The client and the server agree on exactly one thing: the bytes that get
//! signed. This is the test that says so.
//!
//! Both sides construct that string independently, and nothing but a test like
//! this would notice them drifting apart. The symptom of drift is a 401 with
//! no explanation — every request refused, both implementations looking
//! correct in isolation, and no log line anywhere saying why.

use base64::Engine as _;
use ed25519_dalek::{Signer, SigningKey};

use yara_sync::auth::{self, NonceCache, Rejection, SignedRequest};
use yara_sync_client::signing;

const NOW: i64 = 1_800_000_000;

fn key() -> SigningKey {
    SigningKey::from_bytes(&[13u8; 32])
}

fn b64(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

/// Signs the way the client does, verifies the way the server does.
fn round_trip(method: &str, path: &str, body: &[u8], nonce: &str) -> Result<(), Rejection> {
    let key = key();

    let client_message = signing::canonical(method, path, NOW, nonce, body);
    let signature = b64(&key.sign(&client_message).to_bytes());

    let server_view = SignedRequest {
        method,
        path,
        timestamp: NOW,
        nonce,
        body,
    };

    auth::verify(
        &server_view,
        &signature,
        &key.verifying_key(),
        &mut NonceCache::new(),
        NOW,
    )
}

#[test]
fn both_sides_build_the_same_canonical_string() {
    let client = signing::canonical(
        "POST",
        "/api/v1/items",
        NOW,
        "nonce-0000000000000000",
        b"{}",
    );

    let server = SignedRequest {
        method: "POST",
        path: "/api/v1/items",
        timestamp: NOW,
        nonce: "nonce-0000000000000000",
        body: b"{}",
    }
    .canonical();

    assert_eq!(
        String::from_utf8(client).unwrap(),
        String::from_utf8(server).unwrap()
    );
}

#[test]
fn a_signature_from_the_client_verifies_on_the_server() {
    assert_eq!(
        round_trip("GET", "/api/v1/items", b"", "nonce-0000000000000000"),
        Ok(())
    );
}

#[test]
fn it_holds_for_every_request_the_client_makes() {
    let cases: [(&str, &str, &[u8]); 3] = [
        ("GET", "/api/v1/items", b""),
        ("POST", "/api/v1/items", br#"{"expectedRevision":0,"items":[]}"#),
        (
            "POST",
            "/api/v1/items",
            br#"{"expectedRevision":7,"items":[{"id":"a","ciphertext":"b3BhcXVl","deleted":false}]}"#,
        ),
    ];

    for (index, (method, path, body)) in cases.iter().enumerate() {
        let nonce = format!("nonce-{index:0>20}");
        assert_eq!(
            round_trip(method, path, body, &nonce),
            Ok(()),
            "{method} {path} did not verify"
        );
    }
}

#[test]
fn a_body_the_client_did_not_sign_is_refused() {
    let key = key();
    let nonce = "nonce-0000000000000000";

    let signed_for = br#"{"expectedRevision":0,"items":[]}"#;
    let message = signing::canonical("POST", "/api/v1/items", NOW, nonce, signed_for);
    let signature = b64(&key.sign(&message).to_bytes());

    let tampered = SignedRequest {
        method: "POST",
        path: "/api/v1/items",
        timestamp: NOW,
        nonce,
        body: br#"{"expectedRevision":0,"items":[{"id":"smuggled"}]}"#,
    };

    assert_eq!(
        auth::verify(
            &tampered,
            &signature,
            &key.verifying_key(),
            &mut NonceCache::new(),
            NOW
        ),
        Err(Rejection::BadSignature)
    );
}

#[test]
fn the_nonce_the_client_generates_is_long_enough_for_the_server() {
    // The server rejects anything under sixteen characters as malformed, and
    // the client is the only thing that decides how long one is.
    for _ in 0..20 {
        let nonce = signing::fresh_nonce();
        assert_eq!(
            round_trip("GET", "/api/v1/items", b"", &nonce),
            Ok(()),
            "{nonce} was refused"
        );
    }
}
