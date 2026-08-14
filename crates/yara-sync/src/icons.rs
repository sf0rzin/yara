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
//!
//! The cache is bounded, and that is not tidiness. It lives in the state
//! directory this service keeps its database in, the endpoint carries no
//! signature, and a wildcard domain answers on every subdomain anyone cares to
//! invent — so an unbounded cache is a way to fill the disk out from under
//! `sync.db` and stop sync for every account on the host.

use std::path::{Path, PathBuf};
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

/// How long a domain that had no icon is remembered as having none.
///
/// Without this, every request for a domain with no favicon costs two outbound
/// attempts, forever, because nothing ever records that the answer is already
/// known.
///
/// Far shorter than a hit, because a failure to fetch is not proof of much: a
/// timeout or a DNS blip is remembered here the same as a genuine 404, and
/// pinning that wrong answer for a month would be worse than paying for the
/// retry. An hour is long enough to flatten a burst, short enough that nobody
/// files a bug about it.
const MISS_AGE: Duration = Duration::from_secs(60 * 60);

/// Ceiling on what will be fetched and stored. A favicon is kilobytes; this is
/// generous enough for a large PNG and small enough that a hostile origin
/// cannot fill the disk.
const MAX_BYTES: usize = 256 * 1024;

/// Ceiling on the whole cache.
///
/// At 256KB an entry this is a few hundred icons, which is far more than the
/// vaults on one origin hold, and it is the number that matters: the disk
/// underneath also holds the database.
const MAX_CACHE_BYTES: u64 = 64 * 1024 * 1024;

/// Ceiling on how many entries the cache may hold.
///
/// A negative entry is an empty file, so bytes alone would not bound them —
/// and it is the negative ones a wildcard domain can mint fastest.
const MAX_CACHE_ENTRIES: usize = 4096;

/// What this module writes, and the only files it will ever delete.
const ICON_EXT: &str = "ico";
const MISS_EXT: &str = "none";

/// Serves the icon for one domain.
pub async fn favicon(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    AxumPath(domain): AxumPath<String>,
) -> Result<impl IntoResponse, ApiError> {
    // Unsigned, and it makes this server fetch something. Without a ceiling
    // anyone could point it at a third party and let it do the hammering.
    crate::api::rate_limit(&app, &headers, crate::now())?;

    let domain = normalise(&domain)
        .ok_or_else(|| ApiError(StatusCode::BAD_REQUEST, "not a domain".into()))?;

    let dir = app.icon_cache.clone();
    let cached = entry_path(&dir, &domain, ICON_EXT);
    let missing = entry_path(&dir, &domain, MISS_EXT);
    let now = SystemTime::now();

    if let Some(bytes) = read_fresh(&cached, MAX_AGE, now) {
        return Ok(respond(bytes, true));
    }
    if read_fresh(&missing, MISS_AGE, now).is_some() {
        return Err(no_icon());
    }

    let Some(bytes) = fetch(&domain).await else {
        // Remembered, so the next ask for a domain with no icon costs a file
        // read rather than two more outbound attempts.
        write_entry(&dir, &missing, &[]);
        return Err(no_icon());
    };

    // Written before responding so a burst of clients asking at once ends up
    // fetching once rather than once each.
    write_entry(&dir, &cached, &bytes);

    Ok(respond(bytes, false))
}

fn no_icon() -> ApiError {
    ApiError(StatusCode::NOT_FOUND, "no icon for that domain".into())
}

/// Where one domain's entry lives.
///
/// The domain has been through [`normalise`], which is what makes this safe to
/// join: a separator or a dot-dot getting this far would be a path traversal
/// with a file write on the end of it.
fn entry_path(dir: &Path, domain: &str, extension: &str) -> PathBuf {
    dir.join(format!("{domain}.{extension}"))
}

fn write_entry(dir: &Path, path: &Path, bytes: &[u8]) {
    let _ = std::fs::create_dir_all(dir);
    if std::fs::write(path, bytes).is_ok() {
        evict(dir, MAX_CACHE_BYTES, MAX_CACHE_ENTRIES);
    }
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

/// The entry's contents, if it exists and is younger than `max_age`.
///
/// `now` is passed in rather than read here for the same reason the auth code
/// takes a clock reading: an expiry that can only be tested by waiting is an
/// expiry nobody tests.
fn read_fresh(path: &Path, max_age: Duration, now: SystemTime) -> Option<Vec<u8>> {
    let meta = std::fs::metadata(path).ok()?;
    let age = now.duration_since(meta.modified().ok()?).ok()?;
    if age > max_age {
        return None;
    }
    std::fs::read(path).ok()
}

/// Keeps the cache under both ceilings by dropping its oldest entries.
///
/// Only files this module writes are ever considered, let alone deleted. The
/// cache sits in the service's state directory, and a sweep that went by age
/// alone would eventually decide `sync.db` was the oldest thing in it.
///
/// The ceilings are arguments so a test can reach them without writing four
/// thousand files to prove it.
fn evict(dir: &Path, max_bytes: u64, max_entries: usize) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };

    let mut ours: Vec<(SystemTime, u64, PathBuf)> = entries
        .flatten()
        .filter(|entry| {
            entry
                .path()
                .extension()
                .is_some_and(|ext| ext == ICON_EXT || ext == MISS_EXT)
        })
        .filter_map(|entry| {
            let meta = entry.metadata().ok()?;
            if !meta.is_file() {
                return None;
            }
            Some((
                meta.modified().unwrap_or(SystemTime::UNIX_EPOCH),
                meta.len(),
                entry.path(),
            ))
        })
        .collect();

    let mut total: u64 = ours.iter().map(|(_, size, _)| size).sum();
    let mut count = ours.len();
    if total <= max_bytes && count <= max_entries {
        return;
    }

    // Oldest first. Least recently written rather than least recently read:
    // reading does not touch mtime, and a cache that had to be written to on
    // every hit would be a write amplifier pointed at the same disk.
    ours.sort_by_key(|(modified, _, _)| *modified);

    for (_, size, path) in ours {
        if total <= max_bytes && count <= max_entries {
            break;
        }
        if std::fs::remove_file(&path).is_ok() {
            total = total.saturating_sub(size);
            count -= 1;
        }
    }
}

/// Whether these bytes begin like an image this proxy is willing to store.
///
/// A 200 carrying an HTML error page used to be written straight to the cache
/// and pinned as that domain's icon for thirty days. Checking the magic number
/// also means the apex returning a soft 404 lets the `www.` attempt be tried
/// instead of ending the search.
fn looks_like_an_image(bytes: &[u8]) -> bool {
    const MAGIC: [&[u8]; 5] = [
        &[0x00, 0x00, 0x01, 0x00],                         // ICO
        &[0x89, b'P', b'N', b'G', 0x0d, 0x0a, 0x1a, 0x0a], // PNG
        b"GIF8",                                           // GIF
        &[0xff, 0xd8, 0xff],                               // JPEG
        b"BM",                                             // BMP
    ];

    if MAGIC.iter().any(|magic| bytes.starts_with(magic)) {
        return true;
    }
    // WebP carries its own length between the two halves of the marker.
    bytes.len() > 12 && bytes.starts_with(b"RIFF") && &bytes[8..12] == b"WEBP"
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
        // Plenty of sites answer 200 with an HTML page for a missing icon.
        if !looks_like_an_image(&bytes) {
            continue;
        }
        return Some(bytes.to_vec());
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    const PNG: &[u8] = &[0x89, b'P', b'N', b'G', 0x0d, 0x0a, 0x1a, 0x0a, 0, 0, 0, 0];

    /// A directory of this test's own, so a sweep in one cannot delete
    /// another's entries.
    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("yara-icons-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn age(path: &Path, seconds: u64) {
        let when = SystemTime::now() - Duration::from_secs(seconds);
        std::fs::OpenOptions::new()
            .write(true)
            .open(path)
            .unwrap()
            .set_modified(when)
            .unwrap();
    }

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

    #[test]
    fn an_entry_lands_inside_the_cache_directory() {
        let dir = Path::new("/var/lib/yara-sync/icons");
        let path = entry_path(dir, &normalise("GitHub.com").unwrap(), ICON_EXT);

        assert_eq!(path.parent(), Some(dir));
        assert_eq!(path.file_name().unwrap(), "github.com.ico");
    }

    #[test]
    fn a_fresh_entry_is_read_and_a_stale_one_is_not() {
        let dir = scratch("freshness");
        let path = entry_path(&dir, "example.com", ICON_EXT);
        std::fs::write(&path, PNG).unwrap();
        // A negative entry is empty and still counts as an answer, on its own
        // much shorter clock.
        let marker = entry_path(&dir, "example.com", MISS_EXT);
        std::fs::write(&marker, []).unwrap();

        // Read after both writes: an entry stamped later than the clock says
        // is treated as absent rather than fresh, which is the safe way round
        // and would otherwise make this depend on which line ran first.
        let now = SystemTime::now();

        assert_eq!(read_fresh(&path, MAX_AGE, now).as_deref(), Some(PNG));
        assert!(
            read_fresh(&path, MAX_AGE, now + MAX_AGE + Duration::from_secs(1)).is_none(),
            "past the cut-off a cached icon must be fetched again"
        );
        assert!(read_fresh(&dir.join("absent.ico"), MAX_AGE, now).is_none());

        assert!(read_fresh(&marker, MISS_AGE, now).is_some());
        assert!(read_fresh(&marker, MISS_AGE, now + MISS_AGE + Duration::from_secs(1)).is_none());
        assert!(
            MISS_AGE < MAX_AGE,
            "a failed fetch is weaker evidence than a successful one"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_html_error_page_is_not_stored_as_an_icon() {
        // A 200 carrying this used to be pinned as the domain's icon for a
        // month, and served to every client that asked.
        assert!(!looks_like_an_image(b"<!DOCTYPE html><html><body>404"));
        assert!(!looks_like_an_image(b"{\"error\":\"not found\"}"));
        assert!(!looks_like_an_image(b""));
        assert!(!looks_like_an_image(b"RIFF"));

        assert!(looks_like_an_image(PNG));
        assert!(looks_like_an_image(&[0x00, 0x00, 0x01, 0x00, 1, 0]));
        assert!(looks_like_an_image(b"GIF89a..."));
        assert!(looks_like_an_image(&[0xff, 0xd8, 0xff, 0xe0]));
        assert!(looks_like_an_image(b"RIFF\0\0\0\0WEBPVP8 "));
    }

    #[test]
    fn the_cache_is_swept_back_under_its_ceiling_oldest_first() {
        let dir = scratch("eviction");

        // Four entries, each a second older than the next.
        for i in 0..4 {
            let path = entry_path(&dir, &format!("d{i}.example.com"), ICON_EXT);
            std::fs::write(&path, PNG).unwrap();
            age(&path, (10 - i) as u64);
        }

        evict(&dir, MAX_CACHE_BYTES, 2);

        assert!(!entry_path(&dir, "d0.example.com", ICON_EXT).exists());
        assert!(!entry_path(&dir, "d1.example.com", ICON_EXT).exists());
        assert!(entry_path(&dir, "d2.example.com", ICON_EXT).exists());
        assert!(entry_path(&dir, "d3.example.com", ICON_EXT).exists());

        // And by size, for the case that actually fills a disk.
        evict(&dir, PNG.len() as u64, MAX_CACHE_ENTRIES);
        assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 1);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_sweep_never_touches_a_file_this_module_did_not_write() {
        // The cache shares a state directory with the database. A sweep that
        // went by age alone would decide sync.db was the oldest thing in it.
        let dir = scratch("neighbours");
        let db = dir.join("sync.db");
        std::fs::write(&db, b"not an icon").unwrap();
        age(&db, 10 * 365 * 24 * 3600);

        for i in 0..3 {
            std::fs::write(
                entry_path(&dir, &format!("d{i}.example.com"), ICON_EXT),
                PNG,
            )
            .unwrap();
        }

        evict(&dir, 0, 0);

        assert!(db.exists(), "the database must survive a cache sweep");
        assert_eq!(std::fs::read(&db).unwrap(), b"not an icon");
        assert_eq!(
            std::fs::read_dir(&dir).unwrap().count(),
            1,
            "everything this module wrote should have gone, and only that"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_flood_of_negative_entries_is_bounded_too() {
        // Empty files weigh nothing, so a byte ceiling alone would let a
        // wildcard domain mint one per subdomain until the inodes ran out.
        let dir = scratch("negatives");
        for i in 0..8 {
            std::fs::write(entry_path(&dir, &format!("d{i}.example.com"), MISS_EXT), []).unwrap();
        }

        evict(&dir, MAX_CACHE_BYTES, 3);

        assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 3);

        let _ = std::fs::remove_dir_all(&dir);
    }
}
