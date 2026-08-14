//! Whether running a command amounts to disclosing the value.
//!
//! `Run` promises the agent receives an outcome rather than a secret, and that
//! promise is only ever as good as the command. `cmd /c echo %SECRET%` is a
//! reveal wearing a run's clothes, and without this the broker prices it as
//! the cheaper of the two — one prompt, and eligible for a standing grant.
//!
//! What this is not: a sandbox. A caller determined to see the value can write
//! a program that prints its environment and ask to run that, and no amount of
//! name matching will catch it. The threat model in `docs/agent-access.md` says
//! as much and continues to.
//!
//! What it buys is that the *obvious* route is priced correctly. Reaching for a
//! shell costs the heavier reveal confirmation and never earns a standing
//! grant, so the cheapest path through the broker stops being the leakiest one.

/// Hand one of these a string and it will do anything, including echo.
const SHELLS: &[&str] = &[
    "cmd",
    "command",
    "powershell",
    "pwsh",
    "sh",
    "bash",
    "zsh",
    "fish",
    "dash",
    "ash",
    "ksh",
    "csh",
    "tcsh",
    "busybox",
    "wsl",
    "xargs",
    "env",
];

/// These disclose only when handed a program on the command line. Running a
/// *script file* is not in this category: that is code which already existed,
/// same as `npm run migrate`, and the line has to fall somewhere.
const INTERPRETERS: &[&str] = &[
    "node",
    "deno",
    "bun",
    "python",
    "python3",
    "py",
    "ruby",
    "perl",
    "php",
    "lua",
    "osascript",
    "awk",
    "gawk",
    "mawk",
    "nawk",
];

/// Interpreters that take the program as an ordinary argument rather than
/// behind a flag. `awk '{print ENVIRON["S"]}'` names no flag at all, so the
/// scan below can never see it — which is how awk used to be priced as an
/// ordinary run while printing the environment on request.
const POSITIONAL_PROGRAM: &[&str] = &["awk", "gawk", "mawk", "nawk"];

/// Flags meaning "the program is here": either as the next argument, joined
/// straight on (`perl -eprint(...)`), or after an `=` (`node --eval=...`).
///
/// `-r` is php's spelling. Ruby uses the same letter for "load this library",
/// which is not quite evaluation — but a library is code that can print the
/// environment, and over-warning about `ruby -rjson` is the harmless direction
/// to be wrong in.
const EVAL_FLAGS: &[&str] = &["-e", "-c", "-p", "-r", "--eval", "--print", "--command"];

/// Subcommands meaning the same thing. `deno eval '...'` spells as a verb what
/// node spells as a flag.
const EVAL_SUBCOMMANDS: &[&str] = &["eval"];

/// Makes a positional-program interpreter read its program from a file
/// instead, which is code that already existed — the same carve-out
/// `node build.js` gets.
const PROGRAM_FILE_FLAGS: &[&str] = &["-f", "--file"];

/// The executable's name, lowercased, without directory or extension.
fn base_name(command: &str) -> String {
    let file = command
        .rsplit(['\\', '/'])
        .next()
        .unwrap_or(command)
        .to_ascii_lowercase();

    match file.rsplit_once('.') {
        Some((stem, "exe" | "com" | "bat" | "cmd")) => stem.to_string(),
        _ => file,
    }
}

/// Whether `arg` names `flag`, in any of the spellings a caller may reach for.
///
/// Matching only the exact flag was the hole: every one of `perl -eprint(...)`,
/// `ruby -e'...'` and `node --eval=...` is a standard way to write it, and each
/// one used to be priced as an ordinary run.
///
/// Case-sensitive. Callers that should fold go through [`names_flag_folded`];
/// awk deliberately does not, because `-F` sets the field separator while `-f`
/// names a program file, and treating the two as one would let
/// `awk -F, '{print ENVIRON["S"]}'` pass as reading its program from disk.
fn names_flag(arg: &str, flag: &str) -> bool {
    if arg == flag {
        return true;
    }

    let Some(rest) = arg.strip_prefix(flag) else {
        return false;
    };

    if flag.starts_with("--") {
        // `--eval=program`. Without the `=` this is a different flag that
        // merely starts the same way, such as `--evaluate-later`.
        rest.starts_with('=')
    } else {
        // `-eprogram`. What follows a dash is far more likely to be another
        // flag than a program, so that case is left to its own comparison.
        !rest.is_empty() && !rest.starts_with('-')
    }
}

/// The same match, ignoring case. Nothing stops a caller from shouting, and
/// PowerShell's own `-Command` is capitalised.
fn names_flag_folded(arg: &str, flag: &str) -> bool {
    names_flag(&arg.to_ascii_lowercase(), flag)
}

fn carries_program(arg: &str) -> bool {
    EVAL_FLAGS.iter().any(|flag| names_flag_folded(arg, flag))
}

/// The first argument that is not a flag, which is where a subcommand lives.
fn first_verb(args: &[String]) -> Option<String> {
    args.iter()
        .find(|arg| !arg.starts_with('-'))
        .map(|arg| arg.to_ascii_lowercase())
}

/// Whether approving this command should be treated as approving a disclosure.
pub fn can_disclose(command: &str, args: &[String]) -> bool {
    let name = base_name(command);

    if SHELLS.contains(&name.as_str()) {
        return true;
    }

    if !INTERPRETERS.contains(&name.as_str()) {
        return false;
    }

    if args.iter().any(|arg| carries_program(arg)) {
        return true;
    }

    if first_verb(args).is_some_and(|verb| EVAL_SUBCOMMANDS.contains(&verb.as_str())) {
        return true;
    }

    if POSITIONAL_PROGRAM.contains(&name.as_str()) {
        // Its program is an ordinary argument, so there is no flag to find.
        // Every invocation carries one unless it was told to read from a file.
        return !args
            .iter()
            .any(|arg| PROGRAM_FILE_FLAGS.iter().any(|flag| names_flag(arg, flag)));
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(list: &[&str]) -> Vec<String> {
        list.iter().map(|a| a.to_string()).collect()
    }

    #[test]
    fn a_bare_shell_discloses() {
        assert!(can_disclose("cmd", &args(&["/c", "echo %SECRET%"])));
        assert!(can_disclose("bash", &args(&["-c", "echo $SECRET"])));
        assert!(can_disclose(
            "powershell",
            &args(&["-Command", "$env:SECRET"])
        ));
    }

    #[test]
    fn the_path_and_extension_do_not_hide_it() {
        assert!(can_disclose(r"C:\Windows\System32\cmd.exe", &[]));
        assert!(can_disclose("/bin/bash", &[]));
        assert!(can_disclose("CMD.EXE", &[]));
        assert!(can_disclose(
            r"c:\windows\system32\WindowsPowerShell\v1.0\powershell.EXE",
            &[]
        ));
    }

    #[test]
    fn an_ordinary_command_does_not() {
        assert!(!can_disclose("npm", &args(&["run", "migrate"])));
        assert!(!can_disclose("psql", &args(&["-f", "schema.sql"])));
        assert!(!can_disclose("cargo", &args(&["test"])));
    }

    #[test]
    fn an_interpreter_discloses_only_with_a_program_argument() {
        assert!(can_disclose(
            "node",
            &args(&["-e", "console.log(process.env.SECRET)"])
        ));
        assert!(can_disclose(
            "python3",
            &args(&["-c", "import os; print(os.environ)"])
        ));

        // Running a file is running code that already existed, which is no
        // different from `npm run migrate`.
        assert!(!can_disclose("node", &args(&["build.js"])));
        assert!(!can_disclose("python3", &args(&["manage.py", "migrate"])));
    }

    #[test]
    fn eval_flags_are_matched_case_insensitively() {
        // PowerShell accepts -Command; the rest are conventionally lowercase,
        // but nothing stops a caller from shouting.
        assert!(can_disclose("node", &args(&["-E", "..."])));
        assert!(can_disclose("perl", &args(&["--EVAL", "..."])));
    }

    #[test]
    fn env_counts_because_it_launches_whatever_it_is_given() {
        assert!(can_disclose("env", &args(&["sh", "-c", "echo $SECRET"])));
        assert!(can_disclose("xargs", &args(&["echo"])));
    }

    /// php's eval flag is not one of the letters the others use, and it was
    /// missing from the list entirely — so the most direct way there is to
    /// print an environment variable was priced as an ordinary run.
    #[test]
    fn php_evaluates_with_dash_r() {
        assert!(can_disclose(
            "php",
            &args(&["-r", "echo getenv('SECRET');"])
        ));
        assert!(can_disclose("php", &args(&["-recho getenv('SECRET');"])));
        // A script file is still a script file.
        assert!(!can_disclose("php", &args(&["artisan", "migrate"])));
    }

    /// awk's program is a positional argument, so a scan for flags could never
    /// find it and every awk invocation looked like an ordinary run.
    #[test]
    fn awk_carries_its_program_without_a_flag() {
        assert!(can_disclose("awk", &args(&["{print ENVIRON[\"SECRET\"]}"])));
        assert!(can_disclose(
            "gawk",
            &args(&["BEGIN{print ENVIRON[\"S\"]}"])
        ));

        // Reading the program from a file is code that already existed.
        assert!(!can_disclose("awk", &args(&["-f", "report.awk", "in.csv"])));
        assert!(!can_disclose("awk", &args(&["-freport.awk", "in.csv"])));

        // `-F` sets the field separator and `-f` names a file. Folding their
        // case together would have let this one through as a file read.
        assert!(can_disclose(
            "awk",
            &args(&["-F,", "{print ENVIRON[\"SECRET\"]}"])
        ));
    }

    /// perl and ruby both accept the program joined straight onto the flag,
    /// which is how most people write it by hand.
    #[test]
    fn a_program_joined_onto_the_flag_still_counts() {
        assert!(can_disclose("perl", &args(&["-eprint $ENV{SECRET}"])));
        assert!(can_disclose("ruby", &args(&["-e'puts ENV[\"SECRET\"]'"])));
        assert!(can_disclose("python3", &args(&["-cprint(1)"])));

        // A switch that carries nothing is still just a switch.
        assert!(!can_disclose("ruby", &args(&["-w", "build.rb"])));
    }

    #[test]
    fn a_flag_with_its_value_after_an_equals_still_counts() {
        assert!(can_disclose(
            "node",
            &args(&["--eval=console.log(process.env.SECRET)"])
        ));
        assert!(can_disclose("perl", &args(&["--EVAL=print"])));

        // A longer flag that merely starts the same way is a different flag.
        assert!(!can_disclose(
            "node",
            &args(&["--evaluate-later", "app.js"])
        ));
    }

    #[test]
    fn a_subcommand_that_means_eval_counts_too() {
        assert!(can_disclose(
            "deno",
            &args(&["eval", "console.log(Deno.env.get('SECRET'))"])
        ));
        // Flags before the verb do not hide it.
        assert!(can_disclose("deno", &args(&["--quiet", "eval", "1"])));

        // `deno run script.ts` is the ordinary case and stays ordinary.
        assert!(!can_disclose("deno", &args(&["run", "server.ts"])));
    }
}
