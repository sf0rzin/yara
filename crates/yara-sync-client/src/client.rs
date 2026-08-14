//! The HTTP half.
//!
//! Every request that reads or writes vault data is signed. The two that are
//! not — fetching the account blobs and registering a device — are the
//! chicken-and-egg cases: a machine has no key until it has unwrapped one, and
//! it cannot unwrap one without the blobs. Those blobs are useless without the
//! password and the recovery kit, so the exposure is a rate limit rather than
//! a disclosure, and the server treats it as one.

use std::time::Duration;

use serde::{Deserialize, Serialize};
use yara_core::AccountKeypair;

use crate::signing::{fresh_nonce, sign_request, RequestToSign};

/// Long enough for a slow link, short enough that a hung server does not hang
/// the app. Sync is a background courtesy; it is never worth blocking on.
const TIMEOUT: Duration = Duration::from_secs(20);

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("could not reach the sync service")]
    Unreachable,
    /// The signature was refused. Usually a clock more than a minute out.
    #[error("the sync service did not accept this device")]
    Unauthenticated,
    /// Somebody else pushed first. Pull and retry.
    #[error("the vault moved on; pull and retry")]
    Conflict,
    #[error("no such account")]
    NoAccount,
    #[error("the sync service said: {0}")]
    Refused(String),
    #[error(transparent)]
    Crypto(#[from] yara_core::Error),
}

pub type Result<T> = std::result::Result<T, Error>;

/// The blobs a device needs before it can unwrap anything.
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Account {
    pub salt: String,
    pub kdf: String,
    pub wrapped_vault_key: String,
    pub wrapped_account_key: String,
    pub revision: i64,
}

/// One item as it travels: opaque, and that is the point.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SyncItem {
    pub id: String,
    #[serde(default)]
    pub revision: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ciphertext: Option<String>,
    #[serde(default)]
    pub deleted: bool,
    /// A sealed proof that a device holding the vault key deleted this item.
    ///
    /// Separate from `ciphertext` because the server drops the body of a
    /// tombstone on purpose — the delete has to propagate, the contents do
    /// not — and this is the one part of a delete that has to survive the
    /// round trip. Without it a `deleted` flag is just a boolean from a server
    /// the design does not trust, and [`crate::deletes::proven_deletion`]
    /// refuses to act on one.
    ///
    /// Absent on a live item, and absent on a tombstone written before proofs
    /// existed. Both read as unproven.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proof: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct ItemPage {
    pub revision: i64,
    pub items: Vec<SyncItem>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Push<'a> {
    expected_revision: i64,
    items: &'a [SyncItem],
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Register<'a> {
    account_id: &'a str,
    device_id: &'a str,
    public_key: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    label: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    invite: Option<&'a str>,
}

#[derive(Deserialize)]
struct ApiError {
    error: String,
}

/// Everything a brand new account needs, computed on this machine.
///
/// Every field the server keeps is already opaque by the time it gets here:
/// the two wrapped keys came out of `enc_key`, and `enc_key` came from a
/// password and a kit the server has never seen.
pub struct Enrolment<'a> {
    pub account_id: &'a str,
    pub salt: &'a str,
    pub kdf: &'a str,
    pub wrapped_vault_key: &'a str,
    pub wrapped_account_key: &'a str,
    pub device_id: &'a str,
    pub public_key: &'a [u8],
    pub label: Option<&'a str>,
    pub invite: &'a str,
}

pub struct Client {
    base: String,
    http: reqwest::Client,
    account_id: String,
    device_id: String,
    device_key: AccountKeypair,
}

impl std::fmt::Debug for Client {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Client")
            .field("base", &self.base)
            .field("account_id", &self.account_id)
            .field("device_id", &self.device_id)
            .finish_non_exhaustive()
    }
}

impl Client {
    pub fn new(
        base: impl Into<String>,
        account_id: impl Into<String>,
        device_id: impl Into<String>,
        device_key: AccountKeypair,
    ) -> Result<Self> {
        Ok(Self {
            base: base.into().trim_end_matches('/').to_string(),
            http: reqwest::Client::builder()
                .timeout(TIMEOUT)
                .build()
                .map_err(|_| Error::Unreachable)?,
            account_id: account_id.into(),
            device_id: device_id.into(),
            device_key,
        })
    }

    /// Creates an account and this machine as its first device.
    ///
    /// One request, because the server does the three writes in one
    /// transaction: an invite spent on an account with no device is an account
    /// nobody can reach and nobody can finish.
    ///
    /// Unsigned, because this is the request that brings the first key into
    /// existence. The invite is the gate.
    pub async fn enrol(base: &str, request: Enrolment<'_>) -> Result<()> {
        use base64::Engine as _;

        let http = reqwest::Client::builder()
            .timeout(TIMEOUT)
            .build()
            .map_err(|_| Error::Unreachable)?;

        let body = serde_json::json!({
            "accountId": request.account_id,
            "salt": request.salt,
            "kdf": request.kdf,
            "wrappedVaultKey": request.wrapped_vault_key,
            "wrappedAccountKey": request.wrapped_account_key,
            "deviceId": request.device_id,
            "publicKey": base64::engine::general_purpose::STANDARD.encode(request.public_key),
            "label": request.label,
            "invite": request.invite,
        });

        let url = format!("{}/api/v1/account", base.trim_end_matches('/'));
        let response = http
            .post(url)
            .json(&body)
            .send()
            .await
            .map_err(|_| Error::Unreachable)?;

        interpret::<serde_json::Value>(response).await.map(|_| ())
    }

    /// Fetches the wrapped blobs. No signature: a new device has none yet.
    pub async fn account(base: &str, account_id: &str) -> Result<Account> {
        let http = reqwest::Client::builder()
            .timeout(TIMEOUT)
            .build()
            .map_err(|_| Error::Unreachable)?;

        let url = format!("{}/api/v1/account/{account_id}", base.trim_end_matches('/'));
        let response = http.get(url).send().await.map_err(|_| Error::Unreachable)?;
        interpret(response).await
    }

    /// Registers this device's public key.
    ///
    /// The first device on an account comes in on an invite. A later one is
    /// authorised by the account key, which it only has because it already
    /// unwrapped the blob with the password and the kit — so possession of
    /// that key is the proof, and nothing derived from the password is sent.
    pub async fn register(
        base: &str,
        account_id: &str,
        device_id: &str,
        public_key: &[u8],
        label: Option<&str>,
        invite: Option<&str>,
    ) -> Result<()> {
        use base64::Engine as _;

        let http = reqwest::Client::builder()
            .timeout(TIMEOUT)
            .build()
            .map_err(|_| Error::Unreachable)?;

        let body = Register {
            account_id,
            device_id,
            public_key: base64::engine::general_purpose::STANDARD.encode(public_key),
            label,
            invite,
        };

        let url = format!("{}/api/v1/devices", base.trim_end_matches('/'));
        let response = http
            .post(url)
            .json(&body)
            .send()
            .await
            .map_err(|_| Error::Unreachable)?;

        interpret::<serde_json::Value>(response).await.map(|_| ())
    }

    /// Everything above the revision this machine last saw.
    pub async fn pull(&self, since: i64) -> Result<ItemPage> {
        let path = "/api/v1/items";
        let response = self
            .http
            .get(format!("{}{path}?since={since}", self.base))
            .headers(self.headers("GET", path, b""))
            .send()
            .await
            .map_err(|_| Error::Unreachable)?;

        interpret(response).await
    }

    /// Writes a batch. A [`Error::Conflict`] means pull and try again.
    pub async fn push(&self, expected_revision: i64, items: &[SyncItem]) -> Result<i64> {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct Pushed {
            revision: i64,
        }

        let path = "/api/v1/items";
        // Serialised once and signed as those exact bytes. Letting the HTTP
        // client re-serialise would sign something the server never sees.
        let body = serde_json::to_vec(&Push {
            expected_revision,
            items,
        })
        .map_err(|_| Error::Refused("could not encode the push".into()))?;

        let response = self
            .http
            .post(format!("{}{path}", self.base))
            .header("content-type", "application/json")
            .headers(self.headers("POST", path, &body))
            .body(body)
            .send()
            .await
            .map_err(|_| Error::Unreachable)?;

        interpret::<Pushed>(response).await.map(|p| p.revision)
    }

    fn headers(&self, method: &str, path: &str, body: &[u8]) -> reqwest::header::HeaderMap {
        let signed = sign_request(
            RequestToSign {
                account_id: &self.account_id,
                device_id: &self.device_id,
                method,
                path,
                body,
                timestamp: now(),
                nonce: fresh_nonce(),
            },
            |message| self.device_key.sign(message),
        );

        let mut headers = reqwest::header::HeaderMap::new();
        for (name, value) in signed.pairs() {
            if let Ok(parsed) = value.parse() {
                headers.insert(name, parsed);
            }
        }
        headers
    }
}

/// Turns a response into a value or the most useful error available.
async fn interpret<T: for<'de> Deserialize<'de>>(response: reqwest::Response) -> Result<T> {
    use reqwest::StatusCode;

    let status = response.status();
    if status.is_success() {
        return response
            .json()
            .await
            .map_err(|_| Error::Refused("the sync service returned something unreadable".into()));
    }

    // The server's own message is more useful than a status code, when there
    // is one — it is the only thing that distinguishes a clock problem from a
    // wrong key, and that distinction is the difference between a five-second
    // fix and an hour.
    let message = response
        .json::<ApiError>()
        .await
        .map(|body| body.error)
        .unwrap_or_else(|_| status.to_string());

    Err(match status {
        StatusCode::UNAUTHORIZED => Error::Unauthenticated,
        StatusCode::CONFLICT => Error::Conflict,
        StatusCode::NOT_FOUND => Error::NoAccount,
        _ => Error::Refused(message),
    })
}

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn client() -> Client {
        Client::new(
            "https://yara.lat/",
            "acct-1",
            "dev-1",
            AccountKeypair::generate(),
        )
        .unwrap()
    }

    #[test]
    fn a_trailing_slash_does_not_become_a_double_one() {
        assert_eq!(client().base, "https://yara.lat");
    }

    #[test]
    fn every_signed_request_carries_the_four_headers() {
        let headers = client().headers("GET", "/api/v1/items", b"");

        for name in [
            "authorization",
            "x-yara-timestamp",
            "x-yara-nonce",
            "x-yara-signature",
        ] {
            assert!(headers.contains_key(name), "{name} is missing");
        }
    }

    #[test]
    fn two_requests_never_reuse_a_nonce() {
        let client = client();
        let a = client.headers("GET", "/api/v1/items", b"");
        let b = client.headers("GET", "/api/v1/items", b"");

        assert_ne!(
            a.get("x-yara-nonce").unwrap(),
            b.get("x-yara-nonce").unwrap()
        );
        // And therefore never the same signature either.
        assert_ne!(
            a.get("x-yara-signature").unwrap(),
            b.get("x-yara-signature").unwrap()
        );
    }

    #[test]
    fn the_client_does_not_print_its_key() {
        let text = format!("{:?}", client());
        assert!(text.contains("acct-1"));
        assert!(!text.contains("device_key"));
    }
}
