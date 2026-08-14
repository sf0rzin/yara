//! `yara` — what an agent actually runs.
//!
//! Every subcommand is one round trip to the broker. Nothing is cached, no
//! credential is written anywhere, and `run` never has the value to print in the
//! first place: the broker spawns the process, so this program only ever sees
//! the output.

use std::process::ExitCode;

use clap::{Parser, Subcommand};
use yara_broker::client::send;
use yara_broker::protocol::{AccessRequest, Field, Intent, Request, Response};

#[derive(Parser)]
#[command(
    name = "yara",
    about = "Ask the yara vault for a credential, with the owner's approval",
    version
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Check whether the broker is reachable and the vault is unlocked.
    Status,

    /// List item names. Never returns secrets, and needs no approval.
    ///
    /// One tab-separated line per item: id, name, username, and the labels of
    /// any custom fields. The labels are what `--field` takes.
    List {
        /// Filter by name, username or address.
        query: Option<String>,
    },

    /// Run a command with a credential in its environment.
    ///
    /// The broker runs it, so the credential never passes through this process.
    Run {
        /// Item name or id.
        #[arg(long)]
        item: String,

        /// Environment variable to place the credential in.
        #[arg(long, default_value = "YARA_SECRET")]
        env: String,

        /// Which field to use: password, username, totp, or the exact label of
        /// a custom field as shown by `yara list`. Labels are matched exactly,
        /// including case.
        #[arg(long, default_value = "password")]
        field: String,

        /// Why you need it. Shown to the owner verbatim.
        #[arg(long)]
        reason: String,

        /// Working directory for the command.
        #[arg(long)]
        cwd: Option<String>,

        /// The command, after `--`.
        #[arg(last = true, required = true)]
        argv: Vec<String>,
    },

    /// Print a credential in plaintext.
    ///
    /// Needs its own approval every time and is recorded prominently. Prefer
    /// `run`, which never discloses the value at all.
    Get {
        #[arg(long)]
        item: String,

        /// Which field to reveal: password, username, totp, or the exact label
        /// of a custom field as shown by `yara list`. Labels are matched
        /// exactly, including case.
        #[arg(long, default_value = "password")]
        field: String,

        #[arg(long)]
        reason: String,
    },
}

/// Parses `--field`.
///
/// The built-in names are reserved; anything else is the label of a custom
/// field. The vault, the protocol, the broker and the MCP server have all
/// supported those for a while — only this program did not, so the same item
/// was reachable from an agent and not from the documented command, and the
/// error said the field did not exist.
///
/// No case folding, deliberately, and this used to fold. A grant is pinned to
/// the exact label, so lowercasing here would send "API Key" to the broker as
/// "api key", which matches no field and cannot be approved. It also has to
/// agree with the MCP server, which does not fold either: the two must ask the
/// same question or a grant issued through one will not cover the other.
fn parse_field(value: &str) -> Result<Field, String> {
    match value {
        "password" => Ok(Field::Password),
        "username" => Ok(Field::Username),
        "totp" | "otp" | "code" => Ok(Field::Totp),
        "" => Err("--field cannot be empty".into()),
        label => Ok(Field::Custom(label.to_string())),
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    let cli = Cli::parse();

    match run(cli).await {
        Ok(code) => code,
        Err(message) => {
            eprintln!("yara: {message}");
            ExitCode::FAILURE
        }
    }
}

async fn run(cli: Cli) -> Result<ExitCode, String> {
    let request = match &cli.command {
        Command::Status => Request::Status,

        Command::List { query } => Request::List {
            query: query.clone(),
        },

        Command::Run {
            item,
            env,
            field,
            reason,
            cwd,
            argv,
        } => {
            let (command, args) = argv
                .split_first()
                .ok_or_else(|| "no command given after --".to_string())?;

            Request::Access(AccessRequest {
                item: item.clone(),
                field: parse_field(field)?,
                intent: Intent::Run {
                    command: command.clone(),
                    args: args.to_vec(),
                    env_var: env.clone(),
                    cwd: cwd.clone(),
                },
                reason: reason.clone(),
            })
        }

        Command::Get {
            item,
            field,
            reason,
        } => Request::Access(AccessRequest {
            item: item.clone(),
            field: parse_field(field)?,
            intent: Intent::Reveal,
            reason: reason.clone(),
        }),
    };

    let response = send(&request).await?;
    Ok(report(response))
}

/// One item as a tab-separated line: id, name, username, custom field labels.
///
/// The labels are here because `--field` accepts them and nothing else in the
/// shell reports them. Without this column the only way to name a custom field
/// from the command line was to already know it was there.
///
/// Labels are joined with a comma rather than given a column each, because the
/// number of them varies per item and a ragged table cannot be cut into
/// fields.
fn item_row(item: &yara_broker::protocol::ItemRef) -> String {
    format!(
        "{}\t{}\t{}\t{}",
        item.id,
        item.name,
        item.username.clone().unwrap_or_default(),
        item.fields.join(", ")
    )
}

/// Prints the response and decides this program's exit code.
fn report(response: Response) -> ExitCode {
    match response {
        Response::Status { unlocked, version } => {
            println!(
                "broker {version} · vault {}",
                if unlocked { "unlocked" } else { "locked" }
            );
            if unlocked {
                ExitCode::SUCCESS
            } else {
                ExitCode::FAILURE
            }
        }

        Response::Items { items } => {
            if items.is_empty() {
                eprintln!("no matching items");
            }
            for item in &items {
                println!("{}", item_row(item));
            }
            ExitCode::SUCCESS
        }

        Response::Ran(output) => {
            // Passed through as the child produced it, so the caller sees what
            // it would have seen running the command directly.
            print!("{}", output.stdout);
            eprint!("{}", output.stderr);

            u8::try_from(output.exit_code)
                .map(ExitCode::from)
                .unwrap_or(ExitCode::FAILURE)
        }

        Response::Revealed { value } => {
            // No trailing newline: this is usually being captured.
            print!("{value}");
            ExitCode::SUCCESS
        }

        Response::Refused { message, .. } => {
            eprintln!("yara: {message}");
            ExitCode::FAILURE
        }

        Response::Error { message } => {
            eprintln!("yara: {message}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_built_in_names_stay_reserved() {
        for (name, expected) in [
            ("password", Field::Password),
            ("username", Field::Username),
            ("totp", Field::Totp),
            ("otp", Field::Totp),
            ("code", Field::Totp),
        ] {
            assert_eq!(parse_field(name).unwrap(), expected, "{name}");
        }
    }

    /// The same vault item was reachable through the MCP server and not
    /// through the documented command, which rejected every custom label and
    /// said those fields did not exist.
    #[test]
    fn an_unknown_name_is_the_label_of_a_custom_field() {
        assert_eq!(
            parse_field("Deploy key").unwrap(),
            Field::Custom("Deploy key".into())
        );
    }

    /// Verbatim, with its capital letters. A grant is pinned to the exact
    /// label, so folding the case here would ask for a field no item has —
    /// and would disagree with the MCP server, which does not fold.
    #[test]
    fn a_label_is_never_case_folded() {
        assert_eq!(
            parse_field("API Key").unwrap(),
            Field::Custom("API Key".into())
        );
        assert_eq!(
            parse_field("PASSWORD").unwrap(),
            Field::Custom("PASSWORD".into()),
            "the built-in names are the lowercase spellings and nothing else"
        );
    }

    #[test]
    fn an_empty_field_name_is_rejected() {
        assert!(parse_field("").is_err());
    }

    /// The labels have to be discoverable from the shell, or `--field` accepts
    /// names there is no way to learn.
    #[test]
    fn a_listed_item_shows_its_custom_field_labels() {
        let row = item_row(&yara_broker::protocol::ItemRef {
            id: uuid::Uuid::nil(),
            name: "db-prod".into(),
            username: Some("app".into()),
            has_password: true,
            has_totp: false,
            fields: vec!["Deploy key".into(), "Billing key".into()],
        });

        let columns: Vec<&str> = row.split('\t').collect();
        assert_eq!(columns.len(), 4);
        assert_eq!(columns[1], "db-prod");
        assert_eq!(columns[3], "Deploy key, Billing key");
    }

    /// An item with no custom fields still has to produce the same shape, or
    /// `cut -f4` reads the wrong column on some lines.
    #[test]
    fn a_row_has_the_same_number_of_columns_however_empty_the_item_is() {
        let row = item_row(&yara_broker::protocol::ItemRef {
            id: uuid::Uuid::nil(),
            name: "empty".into(),
            username: None,
            has_password: false,
            has_totp: false,
            fields: Vec::new(),
        });

        assert_eq!(row.split('\t').count(), 4);
    }

    #[test]
    fn run_requires_a_reason_and_a_command() {
        // Both are mandatory, so an agent cannot ask for something without
        // saying why, and the prompt is never blank.
        assert!(Cli::try_parse_from(["yara", "run", "--item", "x", "--", "ls"]).is_err());
        assert!(Cli::try_parse_from(["yara", "run", "--item", "x", "--reason", "y"]).is_err());
        assert!(
            Cli::try_parse_from(["yara", "run", "--item", "x", "--reason", "y", "--", "ls"])
                .is_ok()
        );
    }

    #[test]
    fn get_requires_a_reason() {
        assert!(Cli::try_parse_from(["yara", "get", "--item", "x"]).is_err());
        assert!(Cli::try_parse_from(["yara", "get", "--item", "x", "--reason", "y"]).is_ok());
    }

    #[test]
    fn the_command_after_the_separator_keeps_its_own_flags() {
        let cli = Cli::try_parse_from([
            "yara", "run", "--item", "db", "--reason", "r", "--", "npm", "run", "--silent",
            "migrate",
        ])
        .unwrap();

        match cli.command {
            Command::Run { argv, .. } => {
                assert_eq!(argv, ["npm", "run", "--silent", "migrate"]);
            }
            _ => panic!("expected run"),
        }
    }

    #[test]
    fn the_default_environment_variable_is_explicit_rather_than_guessed() {
        let cli = Cli::try_parse_from(["yara", "run", "--item", "db", "--reason", "r", "--", "ls"])
            .unwrap();

        match cli.command {
            Command::Run { env, field, .. } => {
                assert_eq!(env, "YARA_SECRET");
                assert_eq!(field, "password");
            }
            _ => panic!("expected run"),
        }
    }
}
