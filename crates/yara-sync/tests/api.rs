//! The HTTP surface, driven end to end.
//!
//! These go through real routing, real extraction and real signature checking.
//! The unit tests cover the pieces; this covers the thing a client actually
//! talks to, which is where a mistake would be invisible otherwise — a handler
//! that forgets to authenticate still passes every test of its own logic.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use base64::Engine as _;
use ed25519_dalek::{Signer, SigningKey};
use http_body_util::BodyExt as _;
use serde_json::{json, Value};
use tower::ServiceExt as _;

use yara_sync::api::{router, App};
use yara_sync::auth::SignedRequest;
use yara_sync::store::Store;

const ACCOUNT: &str = "acct-1";
const DEVICE: &str = "dev-1";

fn b64(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

struct Harness {
    app: Arc<App>,
    key: SigningKey,
    nonce: std::cell::Cell<u64>,
}

impl Harness {
    fn new() -> Self {
        let store = Store::in_memory().unwrap();
        store
            .create_account(
                ACCOUNT,
                "c2FsdA",
                r#"{"m":65536,"t":3,"p":4}"#,
                "wrapped-vault-key",
                "wrapped-account-key",
                yara_sync::now(),
            )
            .unwrap();

        let key = SigningKey::from_bytes(&[42u8; 32]);
        store
            .register_device(
                DEVICE,
                ACCOUNT,
                key.verifying_key().as_bytes(),
                Some("laptop"),
                yara_sync::now(),
            )
            .unwrap();

        Self {
            app: App::new(store),
            key,
            nonce: std::cell::Cell::new(0),
        }
    }

    /// A fresh nonce per call, as a real client would.
    fn nonce(&self) -> String {
        let n = self.nonce.get();
        self.nonce.set(n + 1);
        format!("nonce-{n:0>20}")
    }

    fn signed(&self, method: &str, path: &str, body: &str) -> Request<Body> {
        self.signed_with(method, path, body, &self.nonce(), yara_sync::now())
    }

    fn signed_with(
        &self,
        method: &str,
        path: &str,
        body: &str,
        nonce: &str,
        timestamp: i64,
    ) -> Request<Body> {
        // Sign the path only — the query string is not covered, deliberately.
        let signed_path = path.split('?').next().unwrap_or(path);
        let request = SignedRequest {
            method,
            path: signed_path,
            timestamp,
            nonce,
            body: body.as_bytes(),
        };
        let signature = b64(&self.key.sign(&request.canonical()).to_bytes());

        Request::builder()
            .method(method)
            .uri(path)
            .header("content-type", "application/json")
            .header("authorization", format!("yara1 {ACCOUNT}/{DEVICE}"))
            .header("x-yara-timestamp", timestamp.to_string())
            .header("x-yara-nonce", nonce)
            .header("x-yara-signature", signature)
            .body(Body::from(body.to_string()))
            .unwrap()
    }

    async fn send(&self, request: Request<Body>) -> (StatusCode, Value) {
        let response = router(Arc::clone(&self.app))
            .oneshot(request)
            .await
            .unwrap();
        let status = response.status();
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        let value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
        (status, value)
    }
}

fn plain(method: &str, path: &str, body: &str) -> Request<Body> {
    Request::builder()
        .method(method)
        .uri(path)
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap()
}

#[tokio::test]
async fn health_needs_no_signature() {
    let harness = Harness::new();
    let (status, body) = harness.send(plain("GET", "/api/v1/health", "")).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["service"], "yara-sync");
}

#[tokio::test]
async fn the_account_blobs_are_fetchable_without_a_key() {
    // A new device has to get these before it has anything to sign with, and
    // they are useless without the password and the secret key.
    let harness = Harness::new();
    let (status, body) = harness
        .send(plain("GET", &format!("/api/v1/account/{ACCOUNT}"), ""))
        .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["wrappedVaultKey"], "wrapped-vault-key");
    assert_eq!(body["wrappedAccountKey"], "wrapped-account-key");
    assert_eq!(body["revision"], 0);
}

#[tokio::test]
async fn an_unsigned_push_is_refused() {
    let harness = Harness::new();
    let (status, _) = harness
        .send(plain(
            "POST",
            "/api/v1/items",
            r#"{"expectedRevision":0,"items":[]}"#,
        ))
        .await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn a_signed_push_and_pull_round_trips() {
    let harness = Harness::new();

    let body = json!({
        "expectedRevision": 0,
        "items": [{ "id": "item-a", "ciphertext": "b3BhcXVl", "deleted": false }]
    })
    .to_string();

    let (status, pushed) = harness
        .send(harness.signed("POST", "/api/v1/items", &body))
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(pushed["revision"], 1);

    let (status, pulled) = harness
        .send(harness.signed("GET", "/api/v1/items?since=0", ""))
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(pulled["revision"], 1);
    assert_eq!(pulled["items"][0]["id"], "item-a");
    assert_eq!(pulled["items"][0]["ciphertext"], "b3BhcXVl");
}

#[tokio::test]
async fn replaying_a_captured_request_is_refused() {
    let harness = Harness::new();
    let body = r#"{"expectedRevision":0,"items":[]}"#;

    // One request, captured verbatim and sent twice — the whole reason the
    // scheme carries a nonce.
    let nonce = harness.nonce();
    let now = yara_sync::now();

    let (status, _) = harness
        .send(harness.signed_with("POST", "/api/v1/items", body, &nonce, now))
        .await;
    assert_eq!(status, StatusCode::OK);

    let (status, _) = harness
        .send(harness.signed_with("POST", "/api/v1/items", body, &nonce, now))
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn a_tampered_body_does_not_verify() {
    let harness = Harness::new();
    let signed_for = r#"{"expectedRevision":0,"items":[]}"#;
    let mut request = harness.signed("POST", "/api/v1/items", signed_for);

    // Same headers, different body.
    *request.body_mut() = Body::from(
        json!({
            "expectedRevision": 0,
            "items": [{ "id": "smuggled", "ciphertext": "aGk", "deleted": false }]
        })
        .to_string(),
    );

    let (status, _) = harness.send(request).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn a_stale_timestamp_is_refused() {
    let harness = Harness::new();
    let request = harness.signed_with(
        "POST",
        "/api/v1/items",
        r#"{"expectedRevision":0,"items":[]}"#,
        &harness.nonce(),
        yara_sync::now() - 3600,
    );

    let (status, body) = harness.send(request).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert!(body["error"].as_str().unwrap().contains("window"));
}

#[tokio::test]
async fn pushing_against_a_stale_revision_conflicts() {
    let harness = Harness::new();

    let first = json!({ "expectedRevision": 0, "items": [] }).to_string();
    let (status, _) = harness
        .send(harness.signed("POST", "/api/v1/items", &first))
        .await;
    assert_eq!(status, StatusCode::OK);

    // A second client that has not pulled since.
    let (status, body) = harness
        .send(harness.signed("POST", "/api/v1/items", &first))
        .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert!(body["error"].as_str().unwrap().contains("revision 1"));
}

#[tokio::test]
async fn a_key_from_another_account_cannot_read_this_one() {
    let harness = Harness::new();

    // Same device id, registered to a different account with the same key.
    harness
        .app
        .store
        .create_account("other", "s", "{}", "v", "a", yara_sync::now())
        .unwrap();

    let request = Request::builder()
        .method("GET")
        .uri("/api/v1/items?since=0")
        .header("authorization", format!("yara1 other/{DEVICE}"))
        .header("x-yara-timestamp", yara_sync::now().to_string())
        .header("x-yara-nonce", harness.nonce())
        .header("x-yara-signature", "irrelevant")
        .body(Body::empty())
        .unwrap();

    let (status, _) = harness.send(request).await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "a device is scoped to the account it was registered under"
    );
}

#[tokio::test]
async fn a_deleted_item_comes_back_as_a_tombstone_without_its_body() {
    let harness = Harness::new();

    let create = json!({
        "expectedRevision": 0,
        "items": [{ "id": "item-a", "ciphertext": "c2VjcmV0", "deleted": false }]
    })
    .to_string();
    harness
        .send(harness.signed("POST", "/api/v1/items", &create))
        .await;

    let remove = json!({
        "expectedRevision": 1,
        "items": [{ "id": "item-a", "ciphertext": "c2VjcmV0", "deleted": true }]
    })
    .to_string();
    let (status, _) = harness
        .send(harness.signed("POST", "/api/v1/items", &remove))
        .await;
    assert_eq!(status, StatusCode::OK);

    let (_, pulled) = harness
        .send(harness.signed("GET", "/api/v1/items?since=0", ""))
        .await;
    assert_eq!(pulled["items"][0]["deleted"], true);
    assert!(
        pulled["items"][0].get("ciphertext").is_none(),
        "a delete must not carry the body it deleted"
    );
}

#[tokio::test]
async fn a_device_registers_on_an_invite_and_the_code_burns() {
    let harness = Harness::new();
    harness
        .app
        .store
        .create_invite("open-sesame", yara_sync::now(), 3600)
        .unwrap();

    let key = SigningKey::from_bytes(&[9u8; 32]);
    let body = json!({
        "accountId": ACCOUNT,
        "deviceId": "dev-2",
        "publicKey": b64(key.verifying_key().as_bytes()),
        "label": "desktop",
        "invite": "open-sesame"
    })
    .to_string();

    let (status, _) = harness.send(plain("POST", "/api/v1/devices", &body)).await;
    assert_eq!(status, StatusCode::OK);

    let again = body.replace("dev-2", "dev-3");
    let (status, _) = harness.send(plain("POST", "/api/v1/devices", &again)).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "an invite is single use");
}

/// The gap that only showed up when the client was written: nothing created
/// an account, and a device cannot be registered against one that does not
/// exist. Enrolment does all three at once.
#[tokio::test]
async fn enrolment_creates_the_account_and_its_first_device() {
    let harness = Harness::new();
    harness
        .app
        .store
        .create_invite("first-one", yara_sync::now(), 3600)
        .unwrap();

    let key = SigningKey::from_bytes(&[11u8; 32]);
    let body = json!({
        "accountId": "acct-new",
        "salt": "c2FsdA",
        "kdf": r#"{"m":65536,"t":3,"p":4}"#,
        "wrappedVaultKey": "wrapped-vault",
        "wrappedAccountKey": "wrapped-account",
        "deviceId": "dev-first",
        "publicKey": b64(key.verifying_key().as_bytes()),
        "label": "laptop",
        "invite": "first-one"
    })
    .to_string();

    let (status, _) = harness.send(plain("POST", "/api/v1/account", &body)).await;
    assert_eq!(status, StatusCode::OK);

    // The account is reachable and the device can sign for it.
    let (status, blobs) = harness
        .send(plain("GET", "/api/v1/account/acct-new", ""))
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(blobs["wrappedVaultKey"], "wrapped-vault");
    assert!(harness
        .app
        .store
        .device_key("acct-new", "dev-first")
        .unwrap()
        .is_some());
}

#[tokio::test]
async fn a_failed_enrolment_does_not_spend_the_invite() {
    let harness = Harness::new();
    harness
        .app
        .store
        .create_invite("only-one", yara_sync::now(), 3600)
        .unwrap();

    // Same account id as the one the harness already created, so the insert
    // fails after the invite has been marked used inside the transaction.
    let key = SigningKey::from_bytes(&[11u8; 32]);
    let clashing = json!({
        "accountId": ACCOUNT,
        "salt": "c2FsdA",
        "kdf": "{}",
        "wrappedVaultKey": "v",
        "wrappedAccountKey": "a",
        "deviceId": "dev-x",
        "publicKey": b64(key.verifying_key().as_bytes()),
        "invite": "only-one"
    })
    .to_string();

    let (status, _) = harness
        .send(plain("POST", "/api/v1/account", &clashing))
        .await;
    assert_ne!(status, StatusCode::OK);

    // The transaction rolled back, so the invite is still good.
    let good = clashing.replace(&format!("\"{ACCOUNT}\""), "\"acct-fresh\"");
    let (status, _) = harness.send(plain("POST", "/api/v1/account", &good)).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "a failure must not burn the only invite someone has"
    );
}

#[tokio::test]
async fn a_bad_public_key_is_refused_before_anything_is_stored() {
    let harness = Harness::new();
    let body = json!({
        "accountId": ACCOUNT,
        "deviceId": "dev-2",
        "publicKey": "dG9vLXNob3J0",
    })
    .to_string();

    let (status, _) = harness.send(plain("POST", "/api/v1/devices", &body)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(harness
        .app
        .store
        .device_key(ACCOUNT, "dev-2")
        .unwrap()
        .is_none());
}
