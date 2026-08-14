//! The sync server.
//!
//! Binds loopback only. Caddy on the same machine is the only thing that
//! should reach it, and the systemd unit denies outbound addresses besides,
//! so a compromise here cannot phone anywhere.
//!
//!   YARA_SYNC_ADDR   default 127.0.0.1:8787
//!   YARA_SYNC_DB     default /var/lib/yara-sync/sync.db
//!
//! The subcommands are the things an operator has to do by hand, and nothing
//! else:
//!
//!   yara-sync invite            print a fresh single-use code
//!   yara-sync purge             drop tombstones older than 30 days
//!   yara-sync revoke            drop one device's key
//!   yara-sync delete-account    remove an account and everything it holds

use std::path::PathBuf;

use yara_sync::api::{router, App};
use yara_sync::store::Store;

/// How long a tombstone is kept. Long enough that a machine which was off for
/// a month still learns about the delete rather than resurrecting the item.
const TOMBSTONE_DAYS: i64 = 30;

/// How long an invite stays usable.
const INVITE_HOURS: i64 = 48;

const USAGE: &str = "\
yara-sync — encrypted vault sync

    yara-sync                                    serve on $YARA_SYNC_ADDR (default 127.0.0.1:8787)
    yara-sync invite                             print a fresh single-use enrolment code
    yara-sync purge                              drop tombstones older than 30 days
    yara-sync revoke <account-id> <device-id>    drop one device's key
    yara-sync delete-account <account-id>        remove an account, its devices and its items

    $YARA_SYNC_DB                                default /var/lib/yara-sync/sync.db
";

/// What the arguments asked for.
#[derive(Debug, PartialEq, Eq)]
enum Command {
    Serve,
    Invite,
    Purge,
    Revoke { account: String, device: String },
    DeleteAccount { account: String },
    Help,
}

/// Settles the arguments before anything touches the disk.
///
/// Opening the database first meant `--help` needed write access to the state
/// directory, so asking a question failed for anyone who was not the service
/// user — and now that there is a command which deletes an account, a typo in
/// its arguments has to be caught before that too.
fn parse_command(args: &[String]) -> Result<Command, String> {
    // How many arguments follow the subcommand itself.
    let operands = args.len().saturating_sub(1);

    match args.first().map(String::as_str) {
        None => Ok(Command::Serve),
        Some("-h" | "--help" | "help") => Ok(Command::Help),
        Some("invite") if operands == 0 => Ok(Command::Invite),
        Some("purge") if operands == 0 => Ok(Command::Purge),
        Some("revoke") if operands == 2 => Ok(Command::Revoke {
            account: args[1].clone(),
            device: args[2].clone(),
        }),
        Some("delete-account") if operands == 1 => Ok(Command::DeleteAccount {
            account: args[1].clone(),
        }),
        Some(name @ ("invite" | "purge" | "revoke" | "delete-account")) => {
            Err(format!("wrong number of arguments for {name:?}"))
        }
        Some(other) => Err(format!("unknown command {other:?}")),
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let command = match parse_command(&args) {
        Ok(Command::Help) => {
            print!("{USAGE}");
            return Ok(());
        }
        Ok(command) => command,
        Err(problem) => {
            eprintln!("{problem}\n\n{USAGE}");
            std::process::exit(2);
        }
    };

    let db = std::env::var("YARA_SYNC_DB")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("/var/lib/yara-sync/sync.db"));

    if let Some(parent) = db.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let store = Store::open(&db)?;
    let now = yara_sync::now();

    match command {
        Command::Invite => {
            let code = fresh_code();
            store.create_invite(&code, now, INVITE_HOURS * 3600)?;
            // The only time this value exists in readable form. It is stored
            // hashed, so losing it means issuing another rather than looking
            // it up.
            println!("{code}");
            println!("valid for {INVITE_HOURS} hours, one use");
            Ok(())
        }

        Command::Purge => {
            let dropped = store.purge_tombstones(now - TOMBSTONE_DAYS * 86400)?;
            println!("purged {dropped} tombstones");
            Ok(())
        }

        // For the machine that was lost rather than retired, when whoever
        // lost it cannot sign the request themselves. The device's key stops
        // being accepted the moment this returns.
        Command::Revoke { account, device } => {
            if store.remove_device(&account, &device)? {
                println!("revoked {device}");
                Ok(())
            } else {
                eprintln!("no device {device:?} on account {account:?}");
                std::process::exit(1);
            }
        }

        // docs/hosting.md promises that asking for an account to be deleted
        // deletes it. This is that promise, and it is not reversible: the
        // items are ciphertext this server cannot read and cannot reproduce.
        Command::DeleteAccount { account } => {
            if store.delete_account(&account)? {
                println!("deleted {account} and everything it held");
                Ok(())
            } else {
                eprintln!("no account {account:?}");
                std::process::exit(1);
            }
        }

        Command::Serve => serve(store),
        // Handled before the database was opened.
        Command::Help => Ok(()),
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

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(args: &[&str]) -> Result<Command, String> {
        parse_command(&args.iter().map(|a| a.to_string()).collect::<Vec<_>>())
    }

    #[test]
    fn no_arguments_means_serve() {
        assert_eq!(parse(&[]), Ok(Command::Serve));
    }

    #[test]
    fn the_operator_commands_parse() {
        assert_eq!(parse(&["invite"]), Ok(Command::Invite));
        assert_eq!(parse(&["purge"]), Ok(Command::Purge));
        assert_eq!(
            parse(&["revoke", "acct-1", "dev-2"]),
            Ok(Command::Revoke {
                account: "acct-1".into(),
                device: "dev-2".into()
            })
        );
        assert_eq!(
            parse(&["delete-account", "acct-1"]),
            Ok(Command::DeleteAccount {
                account: "acct-1".into()
            })
        );
    }

    /// Both of these destroy something, so a mistyped invocation has to be a
    /// refusal rather than a guess at what was meant.
    #[test]
    fn a_destructive_command_with_the_wrong_arguments_is_refused() {
        for args in [
            vec!["revoke"],
            vec!["revoke", "acct-1"],
            vec!["revoke", "acct-1", "dev-2", "dev-3"],
            vec!["delete-account"],
            vec!["delete-account", "acct-1", "acct-2"],
            vec!["purge", "acct-1"],
        ] {
            assert!(parse(&args).is_err(), "{args:?} should not parse");
        }
    }

    #[test]
    fn help_and_nonsense_are_told_apart() {
        for flag in ["-h", "--help", "help"] {
            assert_eq!(parse(&[flag]), Ok(Command::Help));
        }
        assert!(parse(&["serve"]).is_err());
        assert!(parse(&["--version"]).is_err());
    }
}
