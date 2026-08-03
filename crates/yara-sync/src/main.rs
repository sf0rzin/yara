//! The sync server.
//!
//! Binds loopback only. Caddy on the same machine is the only thing that
//! should reach it, and the systemd unit denies outbound addresses besides,
//! so a compromise here cannot phone anywhere.
//!
//!   YARA_SYNC_ADDR   default 127.0.0.1:8787
//!   YARA_SYNC_DB     default /var/lib/yara-sync/sync.db
//!
//! One subcommand, because invites are the only thing an operator has to do
//! by hand:
//!
//!   yara-sync invite            print a fresh single-use code
//!   yara-sync purge             drop tombstones older than 30 days

use std::path::PathBuf;

use yara_sync::api::{router, App};
use yara_sync::store::Store;

/// How long a tombstone is kept. Long enough that a machine which was off for
/// a month still learns about the delete rather than resurrecting the item.
const TOMBSTONE_DAYS: i64 = 30;

/// How long an invite stays usable.
const INVITE_HOURS: i64 = 48;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let db = std::env::var("YARA_SYNC_DB")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("/var/lib/yara-sync/sync.db"));

    if let Some(parent) = db.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let store = Store::open(&db)?;
    let now = yara_sync::now();

    match std::env::args().nth(1).as_deref() {
        Some("invite") => {
            let code = fresh_code();
            store.create_invite(&code, now, INVITE_HOURS * 3600)?;
            // The only time this value exists in readable form. It is stored
            // hashed, so losing it means issuing another rather than looking
            // it up.
            println!("{code}");
            println!("valid for {INVITE_HOURS} hours, one use");
            Ok(())
        }

        Some("purge") => {
            let dropped = store.purge_tombstones(now - TOMBSTONE_DAYS * 86400)?;
            println!("purged {dropped} tombstones");
            Ok(())
        }

        Some(other) => {
            eprintln!("unknown command {other:?}; expected `invite` or `purge`");
            std::process::exit(2);
        }

        None => serve(store),
    }
}

fn serve(store: Store) -> Result<(), Box<dyn std::error::Error>> {
    let addr = std::env::var("YARA_SYNC_ADDR").unwrap_or_else(|_| "127.0.0.1:8787".into());

    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?
        .block_on(async move {
            let listener = tokio::net::TcpListener::bind(&addr).await?;
            eprintln!("yara-sync listening on {addr}");
            axum::serve(listener, router(App::new(store))).await
        })?;

    Ok(())
}

/// A code that is awkward to guess and tolerable to type once.
///
/// No look-alike characters: this gets read off one screen and typed into
/// another, and an invite that fails because of an l/1 is a support message.
fn fresh_code() -> String {
    use rand::Rng as _;
    const ALPHABET: &[u8] = b"abcdefghjkmnpqrstuvwxyz23456789";

    let mut rng = rand::thread_rng();
    let pick = |rng: &mut rand::rngs::ThreadRng| {
        (0..5)
            .map(|_| ALPHABET[rng.gen_range(0..ALPHABET.len())] as char)
            .collect::<String>()
    };

    // ~74 bits over five groups, which is far past what a 48-hour single-use
    // code needs and still fits on one line.
    let groups: Vec<String> = (0..3).map(|_| pick(&mut rng)).collect();
    groups.join("-")
}
