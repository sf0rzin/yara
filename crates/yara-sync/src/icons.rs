//! A favicon proxy.
//!
//! The client never asks a site for its icon. It asks this, and this asks the
//! site — so github.com learns that *some* yara origin wanted its favicon, not
//! that a particular person keeps a GitHub account, and nobody watching a
//! user's network sees the shape of their vault go past in the clear.
//!
//! It is the same arrangement Bitwarden uses, for the same reason. The cost is
//! honest and worth stating: this server learns which domains are being asked
//! about. Requests carry no signature and no account id precisely so that it
//! learns the domain and not whose vault it came from — but on an origin with
//! few users that is thin cover, and the setting to turn icons off exists
//! because for some people it will not be enough.
//!
//! Responses are cached on disk. A cached icon is one the network never sees
//! asked for twice.

use std::path::Path;
use std::time::{Duration, SystemTime};

use axum::body::Bytes;
use axum::extract::{Path as AxumPath, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::IntoResponse;
use std::sync::Arc;

use crate::api::ApiError;
use crate::api::App;

/// How long a cached icon is served before it is fetched again.
const MAX_AGE: Duration = Duration::from_secs(30 * 24 * 60 * 60);

/// Ceiling on what will be fetched and stored. A favicon is kilobytes; this is
/// generous enough for a large PNG and small enough that a hostile origin
/// cannot fill the disk.
const MAX_BYTES: usize = 256 * 1024;

/// Serves the icon for one domain.
pub async fn favicon(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    AxumPath(domain): AxumPath<String>,
) -> Result<impl IntoResponse, ApiError> {
    // Unsigned, and it makes this server fetch something. Without a ceiling
    // anyone could point it at a third party and let it do the hammering.
    if !app
        .limiter
        .lock()
        .map(|mut limiter| limiter.allow(crate::api::client_ip(&headers), crate::now()))
        .unwrap_or(true)
    {
        return Err(ApiError(
            StatusCode::TOO_MANY_REQUESTS,
            "too many requests".into(),
        ));
    }

    let domain = normalise(&domain)
        .ok_or_else(|| ApiError(StatusCode::BAD_REQUEST, "not a domain".into()))?;

    let dir = app.icon_cache.clone();
    let cached = dir.join(format!("{domain}.ico"));

    if let Some(bytes) = read_fresh(&cached) {
        return Ok(respond(bytes, true));
    }

    let bytes = fetch(&domain)
        .await
        .ok_or_else(|| ApiError(StatusCode::NOT_FOUND, "no icon for that domain".into()))?;

    // Written before responding so a burst of clients asking at once ends up
    // fetching once rather than once each.
    let _ = std::fs::create_dir_all(&dir);
    let _ = std::fs::write(&cached, &bytes);

    Ok(respond(bytes, false))
}

fn respond(bytes: Vec<u8>, cached: bool) -> impl IntoResponse {
    let mut headers = HeaderMap::new();
    headers.insert(
        header::CONTENT_TYPE,
        "image/x-icon".parse().expect("static header value"),
    );
    headers.insert(
        header::CACHE_CONTROL,
        "public, max-age=2592000"
            .parse()
            .expect("static header value"),
    );
    headers.insert(
        "x-yara-cache",
        if cached { "hit" } else { "miss" }
            .parse()
            .expect("static header value"),
    );
    (headers, Bytes::from(bytes))
}

fn read_fresh(path: &Path) -> Option<Vec<u8>> {
    let meta = std::fs::metadata(path).ok()?;
    let age = SystemTime::now()
        .duration_since(meta.modified().ok()?)
        .ok()?;
    if age > MAX_AGE {
        return None;
    }
    std::fs::read(path).ok()
}

/// Lowercased, stripped of anything that is not a hostname.
///
/// Strict on purpose: this string becomes both a URL the server fetches and a
/// filename it writes. A dot-dot or a slash getting through would be a path
/// traversal, and a scheme or a port would let a caller aim the fetch at
/// something that is not a website.
fn normalise(input: &str) -> Option<String> {
    let domain = input.trim().trim_end_matches('.').to_ascii_lowercase();

    if domain.is_empty() || domain.len() > 253 {
        return None;
    }
    if !domain.contains('.') {
        return None;
    }

    let ok = domain.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
    });

    ok.then_some(domain)
}

async fn fetch(domain: &str) -> Option<Vec<u8>> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(6))
        // A redirect chain is how a small fetch becomes a large one, and how a
        // public hostname becomes an internal address.
        .redirect(reqwest::redirect::Policy::limited(3))
        .user_agent("yara-icons/1")
        .build()
        .ok()?;

    for url in [
        format!("https://{domain}/favicon.ico"),
        format!("https://www.{domain}/favicon.ico"),
    ] {
        let Ok(response) = client.get(&url).send().await else {
            continue;
        };
        if !response.status().is_success() {
            continue;
        }
        // Checked before reading, so a lying or absent length still cannot
        // make this buffer more than the ceiling.
        if response
            .content_length()
            .is_some_and(|n| n as usize > MAX_BYTES)
        {
            continue;
        }
        let Ok(bytes) = response.bytes().await else {
            continue;
        };
        if bytes.is_empty() || bytes.len() > MAX_BYTES {
            continue;
        }
        return Some(bytes.to_vec());
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ordinary_domains_pass() {
        assert_eq!(normalise("GitHub.com").as_deref(), Some("github.com"));
        assert_eq!(
            normalise(" sub.example.co.uk. ").as_deref(),
            Some("sub.example.co.uk")
        );
    }

    #[test]
    fn a_path_cannot_escape_the_cache_directory() {
        // This string becomes a filename. If it could contain a separator the
        // proxy would write wherever the caller pointed it.
        for attempt in ["../../etc/passwd", "a/b.com", "a\\b.com", ".."] {
            assert!(normalise(attempt).is_none(), "{attempt} must be refused");
        }
    }

    #[test]
    fn a_url_cannot_be_smuggled_in_as_a_domain() {
        for attempt in [
            "https://evil.com",
            "evil.com:8080",
            "evil.com/path",
            "user@evil.com",
            "evil.com?x=1",
        ] {
            assert!(normalise(attempt).is_none(), "{attempt} must be refused");
        }
    }

    #[test]
    fn a_bare_hostname_is_refused() {
        // No dot means it could be an internal name — "localhost", or a host
        // that resolves differently inside the network than outside it.
        assert!(normalise("localhost").is_none());
        assert!(normalise("router").is_none());
    }

    #[test]
    fn nonsense_is_refused_rather_than_fetched() {
        assert!(normalise("").is_none());
        assert!(normalise("-bad.com").is_none());
        assert!(normalise("bad-.com").is_none());
        assert!(normalise("a..b.com").is_none());
        assert!(normalise(&format!("{}.com", "x".repeat(64))).is_none());
    }
}
