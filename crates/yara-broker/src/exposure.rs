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
];

/// Flags meaning "the next argument is the program".
const EVAL_FLAGS: &[&str] = &["-e", "-c", "-p", "--eval", "--print", "--command"];

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

fn is_eval_flag(arg: &str) -> bool {
    let lowered = arg.to_ascii_lowercase();
    EVAL_FLAGS.iter().any(|flag| lowered == *flag)
}

/// Whether approving this command should be treated as approving a disclosure.
pub fn can_disclose(command: &str, args: &[String]) -> bool {
    let name = base_name(command);

    if SHELLS.contains(&name.as_str()) {
        return true;
    }

    if INTERPRETERS.contains(&name.as_str()) {
        return args.iter().any(|arg| is_eval_flag(arg));
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
}
