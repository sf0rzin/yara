//! The HTTP surface, and the only module that knows what a request is.
//!
//! Everything that reads or writes vault data carries an Ed25519 signature
//! over the request. See [`auth`]. What is reachable without one is a short
//! list, and every entry on it is a deliberate exception:
//!
//!   - `/health`, which says nothing.
//!   - `GET /account/{id}`, which returns blobs a new device must fetch before
//!     it has a key to sign with. Useless without the password and the secret
//!     key, so the exposure is a rate limit problem rather than a disclosure
//!     one.
//!   - `POST /account`, which brings the first key on an account into
//!     existence and so has nothing to sign with. The invite is the gate.
//!   - `POST /devices`, but only to bootstrap an account that has no key on
//!     record and no device yet — see [`register_device`], which is where this
//!     service's worst bug lived.
//!   - `/icons/{domain}`, which carries no account id on purpose.
//!
//! All of them are rate limited here rather than in Caddy, which ships no
//! limiter. That limit is load-bearing, so read [`client_ip`] before trusting
//! anything about who a request came from.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Arc, Mutex};

use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, Path, Query, State};
use axum::http::{HeaderMap, Method, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post};
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
    pub(crate) limiter: Mutex<RateLimiter>,
    /// Where fetched favicons are kept. Beside the database, since both are
    /// state this service owns and neither survives a fresh install.
    pub icon_cache: std::path::PathBuf,
}

impl App {
    pub fn new(store: Store) -> Arc<Self> {
        Self::with_icon_cache(store, std::path::PathBuf::from("/var/lib/yara-sync/icons"))
    }

    pub fn with_icon_cache(store: Store, icon_cache: std::path::PathBuf) -> Arc<Self> {
        Arc::new(Self {
            store,
            nonces: Mutex::new(NonceCache::new()),
            limiter: Mutex::new(RateLimiter::default()),
            icon_cache,
        })
    }
}

/// Distinct addresses tracked inside one window.
///
/// A hard cap, because the alternative was worse than unbounded growth: the
/// sweep this replaces ran whenever the map held more than 4096 entries and
/// only dropped entries from *other* windows, so past 4096 addresses in one
/// minute it scanned the whole map on every single request and removed
/// nothing — while holding the mutex every unsigned request has to take.
const MAX_TRACKED: usize = 65_536;

/// A fixed window per address. Crude, and correct enough: the thing being
/// prevented is grinding, not a precisely fair share.
#[derive(Debug, Default)]
pub(crate) struct RateLimiter {
    /// Hits so far. Describes exactly one window — the one in `window` — so
    /// expiring the lot is a single `clear` rather than a scan.
    hits: HashMap<IpAddr, u32>,
    window: i64,
}

impl RateLimiter {
    pub(crate) fn allow(&mut self, addr: IpAddr, now: i64) -> bool {
        let window = now / 60;

        if window != self.window {
            // Everything in the map belongs to a window that has passed, so
            // this is the whole sweep: once per minute, not once per request.
            self.hits.clear();
            self.window = window;
        }

        if let Some(hits) = self.hits.get_mut(&addr) {
            *hits = hits.saturating_add(1);
            return *hits <= UNSIGNED_PER_MINUTE;
        }

        // At the cap a new address is refused rather than remembered. Getting
        // here means tens of thousands of distinct addresses inside one minute
        // against a service with a few dozen invited accounts, which is an
        // attack and not a Monday: refusing costs a stranger a minute, and the
        // map cannot be grown past a size that would matter.
        if self.hits.len() >= MAX_TRACKED {
            return false;
        }
        self.hits.insert(addr, 1);
        true
    }

    #[cfg(test)]
    fn tracked(&self) -> usize {
        self.hits.len()
    }
}

/// Refuses a caller that is over the unsigned budget for this minute.
pub(crate) fn rate_limit(app: &App, headers: &HeaderMap, now: i64) -> Result<(), ApiError> {
    let allowed = app
        .limiter
        .lock()
        // A poisoned lock means an earlier request panicked while holding it.
        // Letting this one through beats refusing every request from here on.
        .map(|mut limiter| limiter.allow(client_ip(headers), now))
        .unwrap_or(true);

    if allowed {
        return Ok(());
    }
    Err(ApiError(
        StatusCode::TOO_MANY_REQUESTS,
        "too many requests".into(),
    ))
}

pub fn router(app: Arc<App>) -> Router {
    Router::new()
        .route("/api/v1/health", get(health))
        .route("/api/v1/icons/{domain}", get(crate::icons::favicon))
        .route("/api/v1/account", post(enrol))
        .route("/api/v1/account/{id}", get(account))
        .route("/api/v1/devices", post(register_device))
        .route("/api/v1/devices/{id}", delete(revoke_device))
        .route(
            "/api/v1/items",
            get(pull_items)
                .post(push_items)
                // Axum's own default is 2MB, so a push between 2MB and the
                // ceiling `push_items` enforces was refused before the handler
                // ran and the caller never saw the readable error it writes.
                // A first push from a large vault is one unchunked body.
                .layer(DefaultBodyLimit::max(MAX_BODY)),
        )
        .with_state(app)
}

// ---- errors ------------------------------------------------------------

pub struct ApiError(pub StatusCode, pub String);

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
    rate_limit(&app, &headers, now)?;

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
    /// Base64, 32 bytes: the public half of the account key, whose private
    /// half the client just wrapped into `wrappedAccountKey`.
    ///
    /// Required, and the reason every later device registration can be proved.
    /// Without it the account would have nothing on record to check a
    /// signature against and could never add a second device.
    account_public_key: String,
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
    let now = crate::now();
    rate_limit(&app, &headers, now)?;

    let key = decode_public_key(&body.public_key, "public key")?;
    let account_key = decode_public_key(&body.account_public_key, "account public key")?;

    app.store.enrol(
        &body.invite,
        crate::store::NewAccount {
            id: &body.account_id,
            salt: &body.salt,
            kdf: &body.kdf,
            wrapped_vault_key: &body.wrapped_vault_key,
            wrapped_account_key: &body.wrapped_account_key,
            public_key: Some(&account_key),
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

/// `yara1-account <account>`, for the two requests a device may not make.
///
/// A different label from the device form deliberately. The two are checked
/// against different keys, and a header one could read as either is how a
/// signature made for one ends up accepted as the other.
fn parse_account_authorization(value: &str) -> Option<String> {
    let account = value.strip_prefix("yara1-account ")?.trim();

    if account.is_empty() || account.contains('/') {
        return None;
    }
    Some(account.to_string())
}

/// Checks a signature made by an account key rather than a device key, and
/// hands back the account it belongs to.
///
/// Adding and removing a device are the two requests a device key must not be
/// able to make on its own. A stolen laptop whose key could register a second
/// device would simply survive being revoked, and revocation would be theatre.
///
/// Same scheme as [`authenticate`] and the same [`auth`] code underneath —
/// only the key it verifies against differs, and which key that is comes from
/// the route rather than from anything the caller sends.
fn account_signer(
    app: &App,
    method: &Method,
    uri: &Uri,
    headers: &HeaderMap,
    body: &[u8],
    now: i64,
) -> Result<String, ApiError> {
    let header = |name: &str| headers.get(name).and_then(|v| v.to_str().ok());

    let authorization = header("authorization").ok_or(Rejection::Malformed)?;
    let account_id = parse_account_authorization(authorization).ok_or(Rejection::Malformed)?;

    let timestamp: i64 = header("x-yara-timestamp")
        .and_then(|t| t.parse().ok())
        .ok_or(Rejection::Malformed)?;
    let nonce = header("x-yara-nonce").ok_or(Rejection::Malformed)?;
    let signature = header("x-yara-signature").ok_or(Rejection::Malformed)?;

    // An account with no key on record reads exactly like a wrong signature,
    // so this cannot be used to ask which account ids exist.
    let stored = app
        .store
        .account_key(&account_id)?
        .ok_or(Rejection::BadSignature)?;
    let key = auth::public_key(&stored).ok_or(Rejection::BadSignature)?;

    let request = SignedRequest {
        method: method.as_str(),
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

    Ok(account_id)
}

/// A 32-byte Ed25519 public key, or a 400.
///
/// Only the length is checked here: every 32-byte string is a syntactically
/// valid key, and whether it is the right one is what the first signature
/// settles.
fn decode_public_key(value: &str, what: &str) -> Result<Vec<u8>, ApiError> {
    use base64::Engine as _;

    base64::engine::general_purpose::STANDARD
        .decode(value)
        .ok()
        .filter(|bytes| bytes.len() == 32)
        .ok_or_else(|| {
            ApiError(
                StatusCode::BAD_REQUEST,
                format!("the {what} must be 32 base64 bytes"),
            )
        })
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RegisterDevice {
    account_id: String,
    device_id: String,
    /// Base64, 32 bytes.
    public_key: String,
    label: Option<String>,
    /// Only for the bootstrap below. An account that has a key on record
    /// cannot be joined with an invite, however good the invite is.
    invite: Option<String>,
}

/// Attaches a device's public key to an account.
///
/// This used to take a body and nothing else — no headers, no signature, no
/// rate limit — so one unauthenticated POST attached any key to any account
/// id, and account ids are not secret: they travel in every Authorization
/// header, sit in the client config, and `/account/{id}` answers to them
/// unauthenticated. That bought read access to another account's whole
/// ciphertext and write access to its items. The proof it always claimed to
/// carry is now actually required.
///
/// The body is read raw and parsed after, because the signature covers the
/// bytes the client sent rather than a re-serialisation of them.
async fn register_device(
    State(app): State<Arc<App>>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<serde_json::Value>, ApiError> {
    let now = crate::now();
    rate_limit(&app, &headers, now)?;

    let request: RegisterDevice = serde_json::from_slice(&body)
        .map_err(|_| ApiError(StatusCode::BAD_REQUEST, "malformed body".into()))?;
    let key = decode_public_key(&request.public_key, "public key")?;

    // Which proof this request offers is the caller's choice, and safely so.
    // The two paths do not overlap: an invite cannot get into an account that
    // has a key on record, because the store checks for one inside the
    // transaction that spends it, and a signature cannot be produced without
    // that key. So there is no weaker path to pick.
    //
    // Branching on what the caller presented rather than on what the account
    // looks like also keeps this from answering "does that account have a key
    // yet?" to anyone who asks.
    if headers.contains_key("x-yara-signature") {
        let signer = account_signer(&app, &method, &uri, &headers, &body, now)?;
        if signer != request.account_id {
            // A key that is not this account's. Being able to sign for your
            // own account must not register a device on somebody else's.
            return Err(Rejection::BadSignature.into());
        }

        app.store.register_device(
            &request.device_id,
            &request.account_id,
            &key,
            request.label.as_deref(),
            now,
        )?;
    } else {
        // The bootstrap: an account written before there was a column to keep
        // a key in still has to be able to bring up its first device. The
        // store checks "no key, no device yet, unspent invite" as one step.
        let invite = request.invite.as_deref().ok_or(Rejection::BadSignature)?;
        app.store.register_device_on_invite(
            invite,
            &request.account_id,
            &request.device_id,
            &key,
            request.label.as_deref(),
            now,
        )?;
    }

    Ok(Json(json!({ "deviceId": request.device_id })))
}

/// Revokes a device, on the account key's say-so.
///
/// The device id is in the path and the path is inside the signature, so a
/// captured revocation cannot be re-aimed at a different device.
async fn revoke_device(
    State(app): State<Arc<App>>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    Path(device_id): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let now = crate::now();
    rate_limit(&app, &headers, now)?;

    let account_id = account_signer(&app, &method, &uri, &headers, b"", now)?;

    if !app.store.remove_device(&account_id, &device_id)? {
        // Safe to be specific: the caller has already proved it holds the
        // account key, so this tells it nothing about anyone else's devices.
        return Err(ApiError(StatusCode::NOT_FOUND, "no such device".into()));
    }

    Ok(Json(json!({ "deviceId": device_id, "revoked": true })))
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

/// The bucket a request lands in when no proxy restored its address.
///
/// Every such caller shares one budget, which is a decision and not a
/// leftover: giving unattributed requests a bucket each would make "send no
/// header" the way around the only rate limit this service has. It reads as
/// loopback because an unproxied request to this process genuinely is one —
/// it binds loopback, and Caddy on the same machine is the only thing that
/// should ever reach it.
const UNATTRIBUTED: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);

/// The caller's address, as restored by the proxies in front.
///
/// `X-Real-IP` first, because that is the only value in the request a caller
/// cannot choose: Caddy *sets* it from its own `trusted_proxies` chain
/// (`header_up X-Real-IP {client_ip}` in deploy/Caddyfile), replacing anything
/// that arrived under that name.
///
/// `X-Forwarded-For` is a fallback and only its last entry. Cloudflare appends
/// the visitor's address to a visitor-supplied header rather than replacing
/// it, and Caddy appends to whatever it received, so the *first* entry is
/// simply what the caller typed. Reading it meant anyone could pick their own
/// rate limit bucket — on the endpoint that hands out the KDF salt and both
/// wrapped keys, which is the one thing here worth grinding at.
pub(crate) fn client_ip(headers: &HeaderMap) -> IpAddr {
    let parse = |value: &str| value.trim().parse::<IpAddr>().ok();
    let header = |name: &str| headers.get(name).and_then(|value| value.to_str().ok());

    if let Some(real) = header("x-real-ip").and_then(parse) {
        return real;
    }

    header("x-forwarded-for")
        // The last entry, and only the last entry. Falling back through the
        // list on a junk value would hand the choice back to the caller, who
        // wrote everything to the left of what the proxy appended.
        .and_then(|value| value.split(',').next_back())
        .and_then(parse)
        .unwrap_or(UNATTRIBUTED)
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

    fn addr(value: &str) -> IpAddr {
        value.parse().unwrap()
    }

    #[test]
    fn the_account_authorization_header_parses() {
        assert_eq!(
            parse_account_authorization("yara1-account acct-1"),
            Some("acct-1".into())
        );
    }

    #[test]
    fn the_two_authorization_forms_cannot_be_read_as_each_other() {
        // A device-signed header must never be taken for an account-signed
        // one: they are checked against different keys.
        assert_eq!(parse_account_authorization("yara1 acct-1/dev-2"), None);
        assert_eq!(
            parse_account_authorization("yara1-account acct-1/dev-2"),
            None
        );
        assert_eq!(parse_authorization("yara1-account acct-1"), None);

        for value in ["", "yara1-account", "yara1-account ", "Bearer acct-1"] {
            assert_eq!(
                parse_account_authorization(value),
                None,
                "{value:?} should not parse"
            );
        }
    }

    #[test]
    fn the_client_ip_comes_from_the_header_the_proxy_sets() {
        let mut headers = HeaderMap::new();
        headers.insert("x-real-ip", "203.0.113.7".parse().unwrap());
        assert_eq!(client_ip(&headers), addr("203.0.113.7"));
    }

    #[test]
    fn a_caller_cannot_displace_the_address_the_proxy_wrote() {
        // Both hops append to X-Forwarded-For rather than replacing it, so
        // everything to the left of the last entry is whatever the caller
        // typed. Caddy sets X-Real-IP itself, so it is the one to believe.
        let mut headers = HeaderMap::new();
        headers.insert("x-real-ip", "203.0.113.7".parse().unwrap());
        headers.insert("x-forwarded-for", "10.0.0.1, 198.51.100.9".parse().unwrap());

        assert_eq!(
            client_ip(&headers),
            addr("203.0.113.7"),
            "a forged X-Forwarded-For must not pick the bucket"
        );
    }

    #[test]
    fn without_x_real_ip_the_last_forwarded_entry_wins() {
        // The last entry is the one the nearest proxy appended; the first is
        // free text. Reading the first was how a caller chose its own bucket.
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-forwarded-for",
            "203.0.113.7, 198.51.100.9".parse().unwrap(),
        );
        assert_eq!(client_ip(&headers), addr("198.51.100.9"));
    }

    #[test]
    fn a_junk_last_entry_does_not_fall_back_to_a_caller_supplied_one() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-forwarded-for",
            "203.0.113.7, not-an-address".parse().unwrap(),
        );
        assert_eq!(
            client_ip(&headers),
            UNATTRIBUTED,
            "walking left past junk hands the choice back to the caller"
        );
    }

    #[test]
    fn an_unproxied_request_shares_one_bucket_rather_than_getting_its_own() {
        assert_eq!(client_ip(&HeaderMap::new()), UNATTRIBUTED);

        let mut headers = HeaderMap::new();
        headers.insert("x-real-ip", "not-an-address".parse().unwrap());
        assert_eq!(client_ip(&headers), UNATTRIBUTED);
        assert_eq!(UNATTRIBUTED.to_string(), "127.0.0.1");
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

    /// Well past the 4096 entries that used to make this re-scan the whole map
    /// on every request while removing nothing.
    #[test]
    fn many_distinct_addresses_in_one_window_stay_correct_and_bounded() {
        let mut limiter = RateLimiter::default();
        let now = 1_800_000_000;

        for i in 0..20_000u32 {
            let addr = IpAddr::from(i.to_be_bytes());
            assert!(limiter.allow(addr, now), "address {i} should pass once");
        }

        assert_eq!(limiter.tracked(), 20_000);

        // Each of them still has its own budget rather than a shared one.
        let addr = IpAddr::from(7u32.to_be_bytes());
        for _ in 1..UNSIGNED_PER_MINUTE {
            assert!(limiter.allow(addr, now));
        }
        assert!(!limiter.allow(addr, now));

        // And the next window costs one clear, not a scan per request.
        assert!(limiter.allow(addr, now + 60));
        assert_eq!(limiter.tracked(), 1, "the old window should be gone whole");
    }

    #[test]
    fn the_map_cannot_be_grown_past_its_cap() {
        let mut limiter = RateLimiter::default();
        let now = 1_800_000_000;

        for i in 0..MAX_TRACKED as u32 {
            limiter.allow(IpAddr::from(i.to_be_bytes()), now);
        }
        assert_eq!(limiter.tracked(), MAX_TRACKED);

        // A stranger arriving during a flood of that size is refused rather
        // than remembered; an address already tracked is still counted.
        assert!(!limiter.allow(IpAddr::from([203, 0, 113, 7]), now));
        assert_eq!(limiter.tracked(), MAX_TRACKED);
        assert!(limiter.allow(IpAddr::from(0u32.to_be_bytes()), now));

        // It clears the moment the window turns over.
        assert!(limiter.allow(IpAddr::from([203, 0, 113, 7]), now + 60));
        assert_eq!(limiter.tracked(), 1);
    }
}
