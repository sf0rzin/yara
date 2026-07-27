//! `lapse` — what an agent actually runs.
//!
//! Every subcommand is one round trip to the broker. Nothing is cached, no
//! credential is written anywhere, and `run` never has the value to print in the
//! first place: the broker spawns the process, so this program only ever sees
//! the output.

use std::process::ExitCode;

use clap::{Parser, Subcommand};
use lapse_broker::client::send;
use lapse_broker::protocol::{AccessRequest, Field, Intent, Request, Response};

#[derive(Parser)]
#[command(
    name = "lapse",
    about = "Ask the lapse vault for a credential, with the owner's approval",
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
        #[arg(long, default_value = "LAPSE_SECRET")]
        env: String,

        /// Which field to use.
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

        #[arg(long, default_value = "password")]
        field: String,

        #[arg(long)]
        reason: String,
    },
}

fn parse_field(value: &str) -> Result<Field, String> {
    match value.to_ascii_lowercase().as_str() {
        "password" => Ok(Field::Password),
        "username" => Ok(Field::Username),
        "totp" | "otp" | "code" => Ok(Field::Totp),
        other => Err(format!(
            "unknown field {other:?}; expected password, username or totp"
        )),
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    let cli = Cli::parse();

    match run(cli).await {
        Ok(code) => code,
        Err(message) => {
            eprintln!("lapse: {message}");
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
            for item in items {
                let username = item.username.unwrap_or_default();
                println!("{}\t{}\t{}", item.id, item.name, username);
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
            eprintln!("lapse: {message}");
            ExitCode::FAILURE
        }

        Response::Error { message } => {
            eprintln!("lapse: {message}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn field_names_are_accepted_in_the_forms_people_type() {
        assert_eq!(parse_field("password").unwrap(), Field::Password);
        assert_eq!(parse_field("PASSWORD").unwrap(), Field::Password);
        assert_eq!(parse_field("totp").unwrap(), Field::Totp);
        assert_eq!(parse_field("otp").unwrap(), Field::Totp);
        assert_eq!(parse_field("code").unwrap(), Field::Totp);
    }

    #[test]
    fn an_unknown_field_explains_the_valid_ones() {
        let error = parse_field("secret").unwrap_err();
        assert!(error.contains("password"));
        assert!(error.contains("totp"));
    }

    #[test]
    fn run_requires_a_reason_and_a_command() {
        // Both are mandatory, so an agent cannot ask for something without
        // saying why, and the prompt is never blank.
        assert!(Cli::try_parse_from(["lapse", "run", "--item", "x", "--", "ls"]).is_err());
        assert!(Cli::try_parse_from(["lapse", "run", "--item", "x", "--reason", "y"]).is_err());
        assert!(
            Cli::try_parse_from(["lapse", "run", "--item", "x", "--reason", "y", "--", "ls"])
                .is_ok()
        );
    }

    #[test]
    fn get_requires_a_reason() {
        assert!(Cli::try_parse_from(["lapse", "get", "--item", "x"]).is_err());
        assert!(Cli::try_parse_from(["lapse", "get", "--item", "x", "--reason", "y"]).is_ok());
    }

    #[test]
    fn the_command_after_the_separator_keeps_its_own_flags() {
        let cli =
            Cli::try_parse_from(["lapse", "run", "--item", "db", "--reason", "r", "--", "npm", "run", "--silent", "migrate"])
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
        let cli =
            Cli::try_parse_from(["lapse", "run", "--item", "db", "--reason", "r", "--", "ls"])
                .unwrap();

        match cli.command {
            Command::Run { env, field, .. } => {
                assert_eq!(env, "LAPSE_SECRET");
                assert_eq!(field, "password");
            }
            _ => panic!("expected run"),
        }
    }
}
