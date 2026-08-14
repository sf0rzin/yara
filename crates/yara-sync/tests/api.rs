//! The HTTP surface, driven end to end.
//!
//! These go through real routing, real extraction and real signature checking.
//! The unit tests cover the pieces; this covers the thing a client actually
//! talks to, which is where a mistake would be invisible otherwise — a handler
//! that forgets to authenticate still passes every test of its own logic.

use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

use axum::body::Body;
use axum::http::{HeaderMap, Request, StatusCode};
use base64::Engine as _;
use ed25519_dalek::{Signer, SigningKey};
use http_body_util::BodyExt as _;
use serde_json::{json, Value};
use tower::ServiceExt as _;

use yara_sync::api::{router, App};
use yara_sync::auth::SignedRequest;
use yara_sync::store::{NewAccount, Store};

const ACCOUNT: &str = "acct-1";
const DEVICE: &str = "dev-1";

/// Matches `api::UNSIGNED_PER_MINUTE`, which is not public.
const UNSIGNED_PER_MINUTE: usize = 20;

/// Matches `api::MAX_BODY`, which is not public either.
const MAX_BODY: usize = 4 * 1024 * 1024;

fn b64(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

/// A directory of this test binary's own, one per harness.
fn scratch() -> PathBuf {
    static NEXT: AtomicU32 = AtomicU32::new(0);
    let dir = std::env::temp_dir().join(format!(
        "yara-sync-api-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

struct Harness {
    app: Arc<App>,
    /// This account's device key. Signs everything that reads or writes items.
    key: SigningKey,
    /// The account key. Signs the two requests about which devices exist.
    account_key: SigningKey,
    icons: PathBuf,
    nonce: std::cell::Cell<u64>,
}

impl Harness {
    fn new() -> Self {
        let store = Store::in_memory().unwrap();
        let account_key = SigningKey::from_bytes(&[7u8; 32]);

        store
            .create_account(
                NewAccount {
                    id: ACCOUNT,
                    salt: "c2FsdA",
                    kdf: r#"{"m":65536,"t":3,"p":4}"#,
                    wrapped_vault_key: "wrapped-vault-key",
                    wrapped_account_key: "wrapped-account-key",
                    public_key: Some(account_key.verifying_key().as_bytes()),
                },
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

        // Never the real cache path: a test that writes an icon should write
        // it somewhere a test owns.
        let icons = scratch();

        Self {
            app: App::with_icon_cache(store, icons.clone()),
            key,
            account_key,
            icons,
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
        let signature = self.sign(&self.key, method, path, body, nonce, timestamp);

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

    /// A request signed by the account key rather than a device key, which is
    /// what registering and revoking a device require.
    fn account_signed(&self, method: &str, path: &str, body: &str) -> Request<Body> {
        self.account_signed_by(&self.account_key, ACCOUNT, method, path, body)
    }

    fn account_signed_by(
        &self,
        key: &SigningKey,
        account: &str,
        method: &str,
        path: &str,
        body: &str,
    ) -> Request<Body> {
        let nonce = self.nonce();
        let timestamp = yara_sync::now();
        let signature = self.sign(key, method, path, body, &nonce, timestamp);

        Request::builder()
            .method(method)
            .uri(path)
            .header("content-type", "application/json")
            .header("authorization", format!("yara1-account {account}"))
            .header("x-yara-timestamp", timestamp.to_string())
            .header("x-yara-nonce", nonce)
            .header("x-yara-signature", signature)
            .body(Body::from(body.to_string()))
            .unwrap()
    }

    fn sign(
        &self,
        key: &SigningKey,
        method: &str,
        path: &str,
        body: &str,
        nonce: &str,
        timestamp: i64,
    ) -> String {
        // Sign the path only — the query string is not covered, deliberately.
        let request = SignedRequest {
            method,
            path: path.split('?').next().unwrap_or(path),
            timestamp,
            nonce,
            body: body.as_bytes(),
        };
        b64(&key.sign(&request.canonical()).to_bytes())
    }

    async fn send(&self, request: Request<Body>) -> (StatusCode, Value) {
        let (status, _, bytes) = self.send_raw(request).await;
        let value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
        (status, value)
    }

    /// For the icon proxy, whose body is not JSON and whose headers are the
    /// point of half the behaviour.
    async fn send_raw(&self, request: Request<Body>) -> (StatusCode, HeaderMap, Vec<u8>) {
        let response = router(Arc::clone(&self.app))
            .oneshot(request)
            .await
            .unwrap();
        let status = response.status();
        let headers = response.headers().clone();
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        (status, headers, bytes.to_vec())
    }
}

impl Drop for Harness {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.icons);
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

/// The body of an enrolment: a new account and its first device at once.
fn enrolment(
    account_id: &str,
    device_id: &str,
    key: &SigningKey,
    account_key: &SigningKey,
    invite: &str,
) -> String {
    json!({
        "accountId": account_id,
        "salt": "c2FsdA",
        "kdf": r#"{"m":65536,"t":3,"p":4}"#,
        "wrappedVaultKey": "wrapped-vault",
        "wrappedAccountKey": "wrapped-account",
        "accountPublicKey": b64(account_key.verifying_key().as_bytes()),
        "deviceId": device_id,
        "publicKey": b64(key.verifying_key().as_bytes()),
        "label": "laptop",
        "invite": invite
    })
    .to_string()
}

/// A second account on the same store, with or without a key on record.
fn other_account<'a>(id: &'a str, public_key: Option<&'a [u8]>) -> NewAccount<'a> {
    NewAccount {
        id,
        salt: "s",
        kdf: "{}",
        wrapped_vault_key: "v",
        wrapped_account_key: "a",
        public_key,
    }
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
        .create_account(other_account("other", None), yara_sync::now())
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

/// The body of a registration, for the account the harness owns.
fn registration(device_id: &str, key: &SigningKey, invite: Option<&str>) -> String {
    let mut body = json!({
        "accountId": ACCOUNT,
        "deviceId": device_id,
        "publicKey": b64(key.verifying_key().as_bytes()),
        "label": "desktop",
    });
    if let Some(code) = invite {
        body["invite"] = json!(code);
    }
    body.to_string()
}

/// The hole this endpoint used to be: no headers, no signature, no rate
/// limit, and account ids are not secret. One POST bought read access to
/// another account's ciphertext and write access to its items.
#[tokio::test]
async fn an_unsigned_registration_is_refused() {
    let harness = Harness::new();
    let key = SigningKey::from_bytes(&[9u8; 32]);

    let (status, _) = harness
        .send(plain(
            "POST",
            "/api/v1/devices",
            &registration("dev-2", &key, None),
        ))
        .await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert!(
        harness
            .app
            .store
            .device_key(ACCOUNT, "dev-2")
            .unwrap()
            .is_none(),
        "nothing may be attached to an account without proof"
    );
}

#[tokio::test]
async fn a_registration_signed_by_the_account_key_is_accepted() {
    let harness = Harness::new();
    let key = SigningKey::from_bytes(&[9u8; 32]);
    let body = registration("dev-2", &key, None);

    let (status, response) = harness
        .send(harness.account_signed("POST", "/api/v1/devices", &body))
        .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(response["deviceId"], "dev-2");

    // And the new device can immediately sign for the account.
    let stored = harness.app.store.device_key(ACCOUNT, "dev-2").unwrap();
    assert_eq!(
        stored.as_deref(),
        Some(key.verifying_key().as_bytes().as_slice())
    );
}

#[tokio::test]
async fn a_registration_signed_by_a_key_that_is_not_the_accounts_is_refused() {
    let harness = Harness::new();
    let new_device = SigningKey::from_bytes(&[9u8; 32]);
    let body = registration("dev-2", &new_device, None);

    // Signed by a key of the caller's own choosing, presented as ours.
    let impostor = SigningKey::from_bytes(&[13u8; 32]);
    let request = harness.account_signed_by(&impostor, ACCOUNT, "POST", "/api/v1/devices", &body);
    let (status, _) = harness.send(request).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // And signed properly, but by the wrong account: an account key must not
    // reach past its own account.
    harness
        .app
        .store
        .create_account(
            other_account("other", Some(impostor.verifying_key().as_bytes())),
            yara_sync::now(),
        )
        .unwrap();
    let request = harness.account_signed_by(&impostor, "other", "POST", "/api/v1/devices", &body);
    let (status, _) = harness.send(request).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    assert!(harness
        .app
        .store
        .device_key(ACCOUNT, "dev-2")
        .unwrap()
        .is_none());
}

/// An account written before there was a column to keep its key in still has
/// to be able to bring up its first device.
#[tokio::test]
async fn an_invite_bootstraps_an_account_with_no_key_and_no_devices() {
    let harness = Harness::new();
    harness
        .app
        .store
        .create_account(other_account("legacy", None), yara_sync::now())
        .unwrap();
    harness
        .app
        .store
        .create_invite("open-sesame", yara_sync::now(), 3600)
        .unwrap();

    let key = SigningKey::from_bytes(&[9u8; 32]);
    let body = registration("dev-legacy", &key, Some("open-sesame"))
        .replace(&format!("\"{ACCOUNT}\""), "\"legacy\"");

    let (status, _) = harness.send(plain("POST", "/api/v1/devices", &body)).await;
    assert_eq!(status, StatusCode::OK);
    assert!(harness
        .app
        .store
        .device_key("legacy", "dev-legacy")
        .unwrap()
        .is_some());

    // One bootstrap only: with a device on the account, a second invite must
    // not attach another key to it.
    harness
        .app
        .store
        .create_invite("second", yara_sync::now(), 3600)
        .unwrap();
    let again = body
        .replace("dev-legacy", "dev-two")
        .replace("open-sesame", "second");
    let (status, _) = harness.send(plain("POST", "/api/v1/devices", &again)).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn an_invite_cannot_stand_in_for_the_account_key() {
    // The harness account has a key on record, so a signature is the only way
    // in — however good the invite is.
    let harness = Harness::new();
    harness
        .app
        .store
        .create_invite("open-sesame", yara_sync::now(), 3600)
        .unwrap();

    let key = SigningKey::from_bytes(&[9u8; 32]);
    let body = registration("dev-2", &key, Some("open-sesame"));

    let (status, _) = harness.send(plain("POST", "/api/v1/devices", &body)).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert!(harness
        .app
        .store
        .device_key(ACCOUNT, "dev-2")
        .unwrap()
        .is_none());

    // And the refusal must not have spent the code, which belongs to whoever
    // it was issued to.
    assert!(harness
        .app
        .store
        .redeem_invite("open-sesame", "someone", yara_sync::now())
        .is_ok());
}

#[tokio::test]
async fn an_invite_is_still_single_use() {
    let harness = Harness::new();
    for id in ["one", "two"] {
        harness
            .app
            .store
            .create_account(other_account(id, None), yara_sync::now())
            .unwrap();
    }
    harness
        .app
        .store
        .create_invite("open-sesame", yara_sync::now(), 3600)
        .unwrap();

    let key = SigningKey::from_bytes(&[9u8; 32]);
    let body = registration("dev-a", &key, Some("open-sesame"))
        .replace(&format!("\"{ACCOUNT}\""), "\"one\"");
    let (status, _) = harness.send(plain("POST", "/api/v1/devices", &body)).await;
    assert_eq!(status, StatusCode::OK);

    let again = body.replace("\"one\"", "\"two\"").replace("dev-a", "dev-b");
    let (status, _) = harness.send(plain("POST", "/api/v1/devices", &again)).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "an invite is single use");
}

#[tokio::test]
async fn registering_a_device_is_rate_limited() {
    let harness = Harness::new();
    let key = SigningKey::from_bytes(&[9u8; 32]);
    let body = registration("dev-2", &key, None);

    // Unsigned and refused, but each attempt still costs the caller a request
    // — otherwise this endpoint is a free oracle for whichever check comes
    // first, and it makes the server hit the database every time.
    for i in 0..UNSIGNED_PER_MINUTE {
        let (status, _) = harness.send(plain("POST", "/api/v1/devices", &body)).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "attempt {i}");
    }

    // Twice the budget again, so a window rolling over mid-test cannot make
    // this pass by accident.
    let mut refused = 0;
    for _ in 0..=UNSIGNED_PER_MINUTE {
        let (status, _) = harness.send(plain("POST", "/api/v1/devices", &body)).await;
        if status == StatusCode::TOO_MANY_REQUESTS {
            refused += 1;
        }
    }
    assert!(refused > 0, "the endpoint must have a ceiling");
}

#[tokio::test]
async fn a_revoked_device_cannot_sign_anything_again() {
    let harness = Harness::new();

    // It works before.
    let (status, _) = harness
        .send(harness.signed("GET", "/api/v1/items?since=0", ""))
        .await;
    assert_eq!(status, StatusCode::OK);

    let (status, body) = harness
        .send(harness.account_signed("DELETE", &format!("/api/v1/devices/{DEVICE}"), ""))
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["revoked"], true);

    // And the lost laptop is a stranger from here on.
    let (status, _) = harness
        .send(harness.signed("GET", "/api/v1/items?since=0", ""))
        .await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "a revoked key must stop being accepted"
    );
    assert!(harness
        .app
        .store
        .device_key(ACCOUNT, DEVICE)
        .unwrap()
        .is_none());
}

#[tokio::test]
async fn a_device_cannot_revoke_anything_with_its_own_key() {
    // Otherwise a stolen laptop simply revokes the machine that would have
    // revoked it, or registers a spare and survives.
    let harness = Harness::new();

    let (status, _) = harness
        .send(harness.signed("DELETE", &format!("/api/v1/devices/{DEVICE}"), ""))
        .await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert!(harness
        .app
        .store
        .device_key(ACCOUNT, DEVICE)
        .unwrap()
        .is_some());
}

#[tokio::test]
async fn a_revocation_cannot_be_re_aimed_at_another_device() {
    let harness = Harness::new();
    harness
        .app
        .store
        .register_device("dev-2", ACCOUNT, &[5u8; 32], None, yara_sync::now())
        .unwrap();

    // Signed for dev-1, sent at dev-2. The path is inside the signature.
    let signed_for_one = harness.account_signed("DELETE", &format!("/api/v1/devices/{DEVICE}"), "");
    let mut aimed_elsewhere = Request::builder()
        .method("DELETE")
        .uri("/api/v1/devices/dev-2")
        .body(Body::empty())
        .unwrap();
    *aimed_elsewhere.headers_mut() = signed_for_one.headers().clone();

    let (status, _) = harness.send(aimed_elsewhere).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert!(harness
        .app
        .store
        .device_key(ACCOUNT, "dev-2")
        .unwrap()
        .is_some());
}

#[tokio::test]
async fn revoking_a_device_that_is_not_there_says_so() {
    let harness = Harness::new();
    let (status, _) = harness
        .send(harness.account_signed("DELETE", "/api/v1/devices/never-existed", ""))
        .await;

    assert_eq!(status, StatusCode::NOT_FOUND);
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
    let account_key = SigningKey::from_bytes(&[12u8; 32]);
    let body = enrolment("acct-new", "dev-first", &key, &account_key, "first-one");

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

    // And the account key it enrolled with is what later registrations are
    // checked against.
    assert_eq!(
        harness
            .app
            .store
            .account_key("acct-new")
            .unwrap()
            .as_deref(),
        Some(account_key.verifying_key().as_bytes().as_slice())
    );
}

/// Without it the account has nothing on record to prove anything with, and
/// could never add a second device.
#[tokio::test]
async fn enrolment_without_an_account_key_is_refused() {
    let harness = Harness::new();
    harness
        .app
        .store
        .create_invite("first-one", yara_sync::now(), 3600)
        .unwrap();

    let key = SigningKey::from_bytes(&[11u8; 32]);
    let account_key = SigningKey::from_bytes(&[12u8; 32]);
    let full = enrolment("acct-new", "dev-first", &key, &account_key, "first-one");

    let value: Value = serde_json::from_str(&full).unwrap();
    for missing in ["", "dG9vLXNob3J0"] {
        let mut body = value.clone();
        body["accountPublicKey"] = json!(missing);
        let (status, _) = harness
            .send(plain("POST", "/api/v1/account", &body.to_string()))
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{missing:?}");
    }

    let mut absent = value.clone();
    absent.as_object_mut().unwrap().remove("accountPublicKey");
    let (status, _) = harness
        .send(plain("POST", "/api/v1/account", &absent.to_string()))
        .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);

    assert!(harness.app.store.account("acct-new").unwrap().is_none());
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
    let account_key = SigningKey::from_bytes(&[12u8; 32]);
    let clashing = enrolment(ACCOUNT, "dev-x", &key, &account_key, "only-one");

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

// ---- body limit --------------------------------------------------------

/// A push whose serialised length is exactly `total`.
fn push_of(total: usize) -> String {
    let head = r#"{"expectedRevision":0,"items":[{"id":"big","ciphertext":""#;
    let tail = r#"","deleted":false}]}"#;
    let filler = total - head.len() - tail.len();
    format!("{head}{}{tail}", "A".repeat(filler))
}

/// A first sync from a large vault is one unchunked body. Axum's own default
/// is 2MB, so everything between 2MB and the ceiling this service documents
/// was refused before `push_items` ran and the caller never saw the readable
/// error it writes.
#[tokio::test]
async fn a_push_just_under_the_ceiling_is_accepted() {
    let harness = Harness::new();
    let body = push_of(MAX_BODY - 1024);
    assert!(body.len() > 2 * 1024 * 1024, "the point is to clear 2MB");

    let (status, pushed) = harness
        .send(harness.signed("POST", "/api/v1/items", &body))
        .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(pushed["revision"], 1);
}

#[tokio::test]
async fn a_push_just_over_the_ceiling_is_refused() {
    let harness = Harness::new();
    let body = push_of(MAX_BODY + 1024);

    let (status, _) = harness
        .send(harness.signed("POST", "/api/v1/items", &body))
        .await;

    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(harness.app.store.revision(ACCOUNT).unwrap(), 0);
}

// ---- icons -------------------------------------------------------------

const PNG: &[u8] = &[0x89, b'P', b'N', b'G', 0x0d, 0x0a, 0x1a, 0x0a, 1, 2, 3, 4];

fn cached_icon(harness: &Harness, domain: &str, bytes: &[u8]) -> PathBuf {
    let path = harness.icons.join(format!("{domain}.ico"));
    std::fs::write(&path, bytes).unwrap();
    path
}

fn backdate(path: &PathBuf, seconds: u64) {
    let when = std::time::SystemTime::now() - std::time::Duration::from_secs(seconds);
    std::fs::OpenOptions::new()
        .write(true)
        .open(path)
        .unwrap()
        .set_modified(when)
        .unwrap();
}

#[tokio::test]
async fn a_cached_icon_is_served_without_asking_the_network() {
    let harness = Harness::new();
    cached_icon(&harness, "example.com", PNG);

    let (status, headers, body) = harness
        .send_raw(plain("GET", "/api/v1/icons/example.com", ""))
        .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, PNG, "these exact bytes can only have come from disk");
    assert_eq!(headers["x-yara-cache"], "hit");
    assert_eq!(headers["cache-control"], "public, max-age=2592000");
    assert_eq!(headers["content-type"], "image/x-icon");
}

#[tokio::test]
async fn an_icon_past_the_cut_off_is_not_served_from_the_cache() {
    let harness = Harness::new();
    // `.invalid` never resolves, so the fetch this falls through to fails and
    // the staleness is what the result turns on.
    let path = cached_icon(&harness, "stale.invalid", PNG);

    let (status, _, body) = harness
        .send_raw(plain("GET", "/api/v1/icons/stale.invalid", ""))
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, PNG);

    backdate(&path, 31 * 24 * 60 * 60);

    let (status, _, _) = harness
        .send_raw(plain("GET", "/api/v1/icons/stale.invalid", ""))
        .await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "a month-old icon must be fetched again rather than served"
    );
}

#[tokio::test]
async fn a_domain_with_no_icon_is_remembered_as_having_none() {
    let harness = Harness::new();

    let (status, _, _) = harness
        .send_raw(plain("GET", "/api/v1/icons/nothing.invalid", ""))
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    // Whatever was written landed inside the cache directory and nowhere else,
    // and it is the negative entry: without it every ask for a domain that has
    // no icon costs two more outbound attempts, forever.
    let written: Vec<PathBuf> = std::fs::read_dir(&harness.icons)
        .unwrap()
        .flatten()
        .map(|entry| entry.path())
        .collect();
    assert_eq!(written.len(), 1, "{written:?}");
    assert_eq!(written[0].parent(), Some(harness.icons.as_path()));
    assert_eq!(written[0].file_name().unwrap(), "nothing.invalid.none");

    let (status, _, _) = harness
        .send_raw(plain("GET", "/api/v1/icons/nothing.invalid", ""))
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn a_domain_the_proxy_refuses_writes_nothing() {
    let harness = Harness::new();

    for domain in ["localhost", "evil.com:8080", "..", "-bad.com"] {
        let (status, _, _) = harness
            .send_raw(plain("GET", &format!("/api/v1/icons/{domain}"), ""))
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{domain}");
    }

    assert_eq!(
        std::fs::read_dir(&harness.icons).unwrap().count(),
        0,
        "a refused domain must not leave a file behind"
    );
}

#[tokio::test]
async fn the_icon_proxy_is_rate_limited() {
    // Unsigned, and it makes this server fetch things on request.
    let harness = Harness::new();
    cached_icon(&harness, "example.com", PNG);

    for i in 0..UNSIGNED_PER_MINUTE {
        let (status, _, _) = harness
            .send_raw(plain("GET", "/api/v1/icons/example.com", ""))
            .await;
        assert_eq!(status, StatusCode::OK, "request {i}");
    }

    let mut refused = 0;
    for _ in 0..=UNSIGNED_PER_MINUTE {
        let (status, _, _) = harness
            .send_raw(plain("GET", "/api/v1/icons/example.com", ""))
            .await;
        if status == StatusCode::TOO_MANY_REQUESTS {
            refused += 1;
        }
    }
    assert!(refused > 0, "the proxy must have a ceiling");
}
