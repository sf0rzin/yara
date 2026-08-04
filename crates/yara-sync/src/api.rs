//! The HTTP surface, and the only module that knows what a request is.
//!
//! Two endpoints are reachable without a signature, and both deliberately:
//! `/health`, which says nothing, and `/account`, which returns blobs a new
//! device must fetch before it has a key to sign with. Those blobs are useless
//! without the password and the secret key, so the exposure is a rate limit
//! problem rather than a disclosure one — and it is rate limited here rather
//! than in Caddy, which ships no limiter.
//!
//! Everything else carries an Ed25519 signature over the request. See [`auth`].

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};

use axum::body::Bytes;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, Method, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::auth::{self, NonceCache, Rejection, SignedRequest};
use crate::store::{Error as StoreError, ItemRecord, Store};

/// Requests per minute an address may make to the unsigned endpoints.
///
/// `/account` is the one endpoint that hands an attacker something to grind
/// against offline, so the ceiling is low enough to make enumeration tedious
/// and high enough that a person setting up three machines never sees it.
const UNSIGNED_PER_MINUTE: u32 = 20;

/// Largest sync push accepted, matching the ceiling Caddy applies in front.
const MAX_BODY: usize = 4 * 1024 * 1024;

pub struct App {
    pub store: Store,
    nonces: Mutex<NonceCache>,
    limiter: Mutex<RateLimiter>,
}

impl App {
    pub fn new(store: Store) -> Arc<Self> {
        Arc::new(Self {
            store,
            nonces: Mutex::new(NonceCache::new()),
            limiter: Mutex::new(RateLimiter::default()),
        })
    }
}

/// A fixed window per address. Crude, and correct enough: the thing being
/// prevented is grinding, not a precisely fair share.
#[derive(Debug, Default)]
struct RateLimiter {
    windows: HashMap<IpAddr, (i64, u32)>,
}

impl RateLimiter {
    fn allow(&mut self, addr: IpAddr, now: i64) -> bool {
        let window = now / 60;
        let entry = self.windows.entry(addr).or_insert((window, 0));

        if entry.0 != window {
            *entry = (window, 0);
        }
        entry.1 += 1;

        // Drop other addresses' stale windows so this cannot grow unbounded.
        if self.windows.len() > 4096 {
            self.windows.retain(|_, (seen, _)| *seen == window);
        }

        self.windows
            .get(&addr)
            .map(|(_, hits)| *hits <= UNSIGNED_PER_MINUTE)
            .unwrap_or(true)
    }
}

pub fn router(app: Arc<App>) -> Router {
    Router::new()
        .route("/api/v1/health", get(health))
        .route("/api/v1/account", post(enrol))
        .route("/api/v1/account/{id}", get(account))
        .route("/api/v1/devices", post(register_device))
        .route("/api/v1/items", get(pull_items).post(push_items))
        .with_state(app)
}

// ---- errors ------------------------------------------------------------

struct ApiError(StatusCode, String);

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.0, Json(json!({ "error": self.1 }))).into_response()
    }
}

impl From<Rejection> for ApiError {
    fn from(rejection: Rejection) -> Self {
        ApiError(StatusCode::UNAUTHORIZED, rejection.message().to_string())
    }
}

impl From<StoreError> for ApiError {
    fn from(error: StoreError) -> Self {
        match error {
            // The only error a client can act on: pull and retry.
            StoreError::Conflict { revision } => ApiError(
                StatusCode::CONFLICT,
                format!("the vault is at revision {revision}; pull and retry"),
            ),
            StoreError::BadInvite => {
                ApiError(StatusCode::FORBIDDEN, "that invite is not usable".into())
            }
            StoreError::NoAccount => ApiError(StatusCode::NOT_FOUND, "no such account".into()),
            // Never surfaced verbatim: a SQL error can name columns, and the
            // caller can do nothing with it either way.
            StoreError::Db(_) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "the request could not be completed".to_string(),
            )
                .into(),
        }
    }
}

impl From<(StatusCode, String)> for ApiError {
    fn from((status, message): (StatusCode, String)) -> Self {
        ApiError(status, message)
    }
}

// ---- unsigned ----------------------------------------------------------

async fn health() -> Json<serde_json::Value> {
    Json(json!({ "service": "yara-sync", "version": env!("CARGO_PKG_VERSION") }))
}

async fn account(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let now = crate::now();

    if !app
        .limiter
        .lock()
        .map(|mut limiter| limiter.allow(client_ip(&headers), now))
        .unwrap_or(true)
    {
        return Err(ApiError(
            StatusCode::TOO_MANY_REQUESTS,
            "too many requests".into(),
        ));
    }

    match app.store.account(&id)? {
        Some(blobs) => Ok(Json(serde_json::to_value(blobs).unwrap_or_default())),
        // Same shape as a wrong id would give, so this does not enumerate.
        None => Err(ApiError(
            StatusCode::NOT_FOUND,
            "no such account".to_string(),
        )),
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Enrol {
    account_id: String,
    salt: String,
    kdf: String,
    wrapped_vault_key: String,
    wrapped_account_key: String,
    device_id: String,
    /// Base64, 32 bytes.
    public_key: String,
    label: Option<String>,
    invite: String,
}

/// Creates an account and its first device, against one invite.
///
/// Unsigned because there is nothing to sign with yet — this request is what
/// brings the first key into existence. The invite is the whole gate, which is
/// why it is spent inside the same transaction that writes the account: a
/// failure in between would burn it on an account nobody can reach or finish.
async fn enrol(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Json(body): Json<Enrol>,
) -> Result<Json<serde_json::Value>, ApiError> {
    use base64::Engine as _;

    let now = crate::now();

    if !app
        .limiter
        .lock()
        .map(|mut limiter| limiter.allow(client_ip(&headers), now))
        .unwrap_or(true)
    {
        return Err(ApiError(
            StatusCode::TOO_MANY_REQUESTS,
            "too many requests".into(),
        ));
    }

    let key = base64::engine::general_purpose::STANDARD
        .decode(&body.public_key)
        .ok()
        .filter(|bytes| bytes.len() == 32)
        .ok_or_else(|| {
            ApiError(
                StatusCode::BAD_REQUEST,
                "the public key must be 32 base64 bytes".into(),
            )
        })?;

    app.store.enrol(
        &body.invite,
        crate::store::NewAccount {
            id: &body.account_id,
            salt: &body.salt,
            kdf: &body.kdf,
            wrapped_vault_key: &body.wrapped_vault_key,
            wrapped_account_key: &body.wrapped_account_key,
        },
        &body.device_id,
        &key,
        body.label.as_deref(),
        now,
    )?;

    Ok(Json(json!({
        "accountId": body.account_id,
        "deviceId": body.device_id,
    })))
}

// ---- signed ------------------------------------------------------------

/// Pulls the caller's identity out of the headers and checks the signature.
///
/// Returns the account and device so a handler cannot forget to scope its
/// query to them: there is no way to reach the data without going through
/// this, and it hands back the only two values a query is allowed to use.
fn authenticate(
    app: &App,
    method: &Method,
    uri: &Uri,
    headers: &HeaderMap,
    body: &[u8],
    now: i64,
) -> Result<(String, String), ApiError> {
    let header = |name: &str| headers.get(name).and_then(|v| v.to_str().ok());

    let authorization = header("authorization").ok_or(Rejection::Malformed)?;
    let (account_id, device_id) = parse_authorization(authorization).ok_or(Rejection::Malformed)?;

    let timestamp: i64 = header("x-yara-timestamp")
        .and_then(|t| t.parse().ok())
        .ok_or(Rejection::Malformed)?;
    let nonce = header("x-yara-nonce").ok_or(Rejection::Malformed)?;
    let signature = header("x-yara-signature").ok_or(Rejection::Malformed)?;

    let stored = app
        .store
        .device_key(&account_id, &device_id)?
        .ok_or(Rejection::BadSignature)?;
    let key = auth::public_key(&stored).ok_or(Rejection::BadSignature)?;

    let request = SignedRequest {
        method: method.as_str(),
        // The path only. A query string is not signed, so nothing that
        // changes meaning may live there — see `pull_items`.
        path: uri.path(),
        timestamp,
        nonce,
        body,
    };

    let mut nonces = app.nonces.lock().map_err(|e| {
        let _ = e;
        ApiError(
            StatusCode::INTERNAL_SERVER_ERROR,
            "the request could not be completed".to_string(),
        )
    })?;

    auth::verify(&request, signature, &key, &mut nonces, now)?;
    drop(nonces);

    let _ = app.store.touch_device(&device_id, now);
    Ok((account_id, device_id))
}

/// `yara1 <account>/<device>`
fn parse_authorization(value: &str) -> Option<(String, String)> {
    let rest = value.strip_prefix("yara1 ")?;
    let (account, device) = rest.trim().split_once('/')?;

    if account.is_empty() || device.is_empty() {
        return None;
    }
    Some((account.to_string(), device.to_string()))
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RegisterDevice {
    account_id: String,
    device_id: String,
    /// Base64, 32 bytes.
    public_key: String,
    label: Option<String>,
    /// Signed by the account key, which a new device gets by unwrapping the
    /// blob from `/account` with the password and secret key.
    invite: Option<String>,
}

async fn register_device(
    State(app): State<Arc<App>>,
    Json(body): Json<RegisterDevice>,
) -> Result<Json<serde_json::Value>, ApiError> {
    use base64::Engine as _;

    let now = crate::now();
    let key = base64::engine::general_purpose::STANDARD
        .decode(&body.public_key)
        .ok()
        .filter(|bytes| bytes.len() == 32)
        .ok_or_else(|| {
            ApiError(
                StatusCode::BAD_REQUEST,
                "the public key must be 32 base64 bytes".into(),
            )
        })?;

    // First device on an account comes in on an invite; later ones are
    // authorised by an existing device, which is the flow the desktop app
    // drives. Either way the caller has proven it can unwrap the account.
    if let Some(code) = body.invite.as_deref() {
        app.store.redeem_invite(code, &body.account_id, now)?;
    }

    app.store.register_device(
        &body.device_id,
        &body.account_id,
        &key,
        body.label.as_deref(),
        now,
    )?;

    Ok(Json(json!({ "deviceId": body.device_id })))
}

#[derive(Debug, Deserialize)]
struct Since {
    #[serde(default)]
    since: i64,
}

async fn pull_items(
    State(app): State<Arc<App>>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    Query(query): Query<Since>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let now = crate::now();
    let (account_id, _device) = authenticate(&app, &method, &uri, &headers, b"", now)?;

    // `since` is not covered by the signature, and does not need to be: it can
    // only narrow what this account already has the right to read, so the
    // worst a tampered value achieves is making the caller re-fetch.
    let items = app.store.items_since(&account_id, query.since)?;
    let revision = app.store.revision(&account_id)?;

    Ok(Json(json!({ "revision": revision, "items": items })))
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Push {
    expected_revision: i64,
    items: Vec<ItemRecord>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct Pushed {
    revision: i64,
}

async fn push_items(
    State(app): State<Arc<App>>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<Pushed>, ApiError> {
    if body.len() > MAX_BODY {
        return Err(ApiError(
            StatusCode::PAYLOAD_TOO_LARGE,
            "that push is too large".into(),
        ));
    }

    let now = crate::now();
    // Verified against the raw bytes before they are parsed: a signature over
    // a re-serialised body would cover something the client never sent.
    let (account_id, _device) = authenticate(&app, &method, &uri, &headers, &body, now)?;

    let push: Push = serde_json::from_slice(&body)
        .map_err(|_| ApiError(StatusCode::BAD_REQUEST, "malformed body".into()))?;

    let revision = app
        .store
        .push_items(&account_id, push.expected_revision, &push.items, now)?;

    Ok(Json(Pushed { revision }))
}

/// The caller's address, as restored by the proxies in front.
///
/// Only meaningful because both hops are configured to pass it: Cloudflare
/// sends `CF-Connecting-IP`, ayla's Caddy trusts that and forwards a single
/// `X-Forwarded-For`, and this reads the first entry. Break either half and
/// this becomes attacker-controlled, which for a rate limit means the limit
/// stops applying.
fn client_ip(headers: &HeaderMap) -> IpAddr {
    headers
        .get("x-forwarded-for")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(',').next())
        .and_then(|first| first.trim().parse().ok())
        .unwrap_or(IpAddr::from([127, 0, 0, 1]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_authorization_header_parses() {
        assert_eq!(
            parse_authorization("yara1 acct-1/dev-2"),
            Some(("acct-1".into(), "dev-2".into()))
        );
    }

    #[test]
    fn a_malformed_authorization_header_is_rejected() {
        for value in [
            "",
            "yara1",
            "yara1 ",
            "yara1 no-slash",
            "yara1 /device",
            "yara1 account/",
            "Bearer something",
            "yara2 acct/dev",
        ] {
            assert_eq!(
                parse_authorization(value),
                None,
                "{value:?} should not parse"
            );
        }
    }

    #[test]
    fn the_client_ip_comes_from_the_forwarded_header() {
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", "203.0.113.7".parse().unwrap());
        assert_eq!(
            client_ip(&headers),
            "203.0.113.7".parse::<IpAddr>().unwrap()
        );
    }

    #[test]
    fn only_the_first_forwarded_entry_is_used() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-forwarded-for",
            "203.0.113.7, 10.10.1.20".parse().unwrap(),
        );
        assert_eq!(
            client_ip(&headers),
            "203.0.113.7".parse::<IpAddr>().unwrap()
        );
    }

    #[test]
    fn a_missing_or_junk_header_falls_back_to_loopback() {
        assert_eq!(client_ip(&HeaderMap::new()).to_string(), "127.0.0.1");

        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", "not-an-address".parse().unwrap());
        assert_eq!(client_ip(&headers).to_string(), "127.0.0.1");
    }

    #[test]
    fn the_rate_limiter_lets_a_normal_setup_through_and_stops_grinding() {
        let mut limiter = RateLimiter::default();
        let addr: IpAddr = "203.0.113.7".parse().unwrap();
        let now = 1_800_000_000;

        for i in 1..=UNSIGNED_PER_MINUTE {
            assert!(limiter.allow(addr, now), "request {i} should pass");
        }
        assert!(!limiter.allow(addr, now), "the next one should not");
    }

    #[test]
    fn the_window_resets() {
        let mut limiter = RateLimiter::default();
        let addr: IpAddr = "203.0.113.7".parse().unwrap();
        let now = 1_800_000_000;

        for _ in 0..=UNSIGNED_PER_MINUTE {
            limiter.allow(addr, now);
        }
        assert!(!limiter.allow(addr, now));
        assert!(limiter.allow(addr, now + 60));
    }

    #[test]
    fn one_address_does_not_spend_anothers_budget() {
        let mut limiter = RateLimiter::default();
        let now = 1_800_000_000;
        let noisy: IpAddr = "203.0.113.7".parse().unwrap();
        let quiet: IpAddr = "198.51.100.4".parse().unwrap();

        for _ in 0..=UNSIGNED_PER_MINUTE {
            limiter.allow(noisy, now);
        }
        assert!(!limiter.allow(noisy, now));
        assert!(limiter.allow(quiet, now));
    }
}
