//! Reading two-factor codes out of another authenticator's export.
//!
//! Pure, like the rest of this crate: it takes the text of an export and
//! returns what was in it. Nothing here opens a file, and nothing decides what
//! to do with the result.
//!
//! The exports these read are plaintext seeds. That is not a flaw in the
//! export — it is the only way to move a TOTP seed between programs at all —
//! but it does mean the file is as sensitive as the accounts behind it, and it
//! outlives the import unless someone deletes it. The interface says so.
//!
//! Nothing is imported silently. Every entry that cannot be read comes back in
//! `skipped` with a reason, because an import that quietly drops three of
//! twenty-three codes is worse than one that fails outright: the user finds
//! out months later, locked out, with the original export long gone.

use serde::Deserialize;

use crate::error::{Error, Result};
use crate::totp::TotpConfig;

/// One code that was read successfully.
#[derive(Debug, Clone)]
pub struct Imported {
    /// What to call the item. The export's own label, falling back to the
    /// issuer and then the account, so an entry never arrives unnamed.
    pub name: String,
    pub totp: TotpConfig,
    pub note: Option<String>,
}

/// One that was not, and why.
///
/// The reason is for the user, not for a log: it names the entry and says what
/// was wrong with it, so the fix is obvious.
#[derive(Debug, Clone)]
pub struct Skipped {
    pub name: String,
    pub reason: String,
}

#[derive(Debug, Default)]
pub struct Import {
    pub entries: Vec<Imported>,
    pub skipped: Vec<Skipped>,
}

impl Import {
    pub fn total(&self) -> usize {
        self.entries.len() + self.skipped.len()
    }
}

// ---- Proton Authenticator ----------------------------------------------

#[derive(Deserialize)]
struct ProtonBackup {
    #[allow(dead_code)]
    version: u32,
    entries: Vec<ProtonEntry>,
}

#[derive(Deserialize)]
struct ProtonEntry {
    content: ProtonContent,
    #[serde(default)]
    note: Option<String>,
}

#[derive(Deserialize)]
struct ProtonContent {
    /// A complete `otpauth://` URI, which is the whole reason this importer is
    /// short: the seed, algorithm, digits and period are all in there, and
    /// `TotpConfig::from_uri` already knows how to read it.
    uri: String,
    #[serde(default)]
    entry_type: String,
    #[serde(default)]
    name: String,
}

/// Reads a Proton Authenticator plaintext backup.
///
/// The file is JSON despite arriving named `.json.txt`.
pub fn from_proton_authenticator(text: &str) -> Result<Import> {
    // A byte order mark is common on Windows exports and would otherwise make
    // the first parse fail on a file that is perfectly fine.
    let text = text.trim_start_matches('\u{feff}').trim();

    let backup: ProtonBackup =
        serde_json::from_str(text).map_err(|_| Error::Malformed("not a Proton backup"))?;

    let mut import = Import::default();

    for entry in backup.entries {
        let label = pick_name(&entry.content);

        // Only time-based codes. Proton also stores Steam entries, which use a
        // different alphabet for the generated code — importing one as an
        // ordinary TOTP would produce six digits that look right and never
        // work, which is the worst kind of wrong.
        if !entry.content.entry_type.eq_ignore_ascii_case("totp") {
            import.skipped.push(Skipped {
                name: label,
                reason: format!("{} codes are not supported yet", entry.content.entry_type),
            });
            continue;
        }

        match TotpConfig::from_uri(&entry.content.uri) {
            Ok(totp) => import.entries.push(Imported {
                name: label,
                totp,
                note: entry.note.filter(|note| !note.trim().is_empty()),
            }),
            Err(error) => import.skipped.push(Skipped {
                name: label,
                reason: error.to_string(),
            }),
        }
    }

    Ok(import)
}

/// The export's own label first, because it is what the user recognises.
///
/// The URI's issuer and account are the fallback rather than the default: they
/// are frequently a service's internal name, and an import that renames
/// everything the user carefully labelled is an import they have to undo.
fn pick_name(content: &ProtonContent) -> String {
    let trimmed = content.name.trim();
    if !trimmed.is_empty() {
        return trimmed.to_string();
    }

    if let Ok(totp) = TotpConfig::from_uri(&content.uri) {
        if let Some(issuer) = totp
            .issuer
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            return issuer.to_string();
        }
        if let Some(account) = totp
            .account
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            return account.to_string();
        }
    }

    "Untitled".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Seeds here are the RFC 4226 test vector and other public throwaways.
    /// Nothing in this file is a real second factor.
    const SEED: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

    fn backup(entries: &str) -> String {
        format!(r#"{{"version":1,"entries":[{entries}]}}"#)
    }

    fn entry(name: &str, kind: &str, uri: &str) -> String {
        format!(
            r#"{{"id":"a","content":{{"uri":"{uri}","entry_type":"{kind}","name":"{name}"}},"note":null}}"#
        )
    }

    #[test]
    fn it_reads_a_backup() {
        let uri = format!("otpauth://totp/GitHub:me?secret={SEED}&issuer=GitHub&algorithm=SHA1&digits=6&period=30");
        let import = from_proton_authenticator(&backup(&entry("GitHub", "Totp", &uri))).unwrap();

        assert_eq!(import.entries.len(), 1);
        assert!(import.skipped.is_empty());

        let first = &import.entries[0];
        assert_eq!(first.name, "GitHub");
        assert_eq!(first.totp.digits, 6);
        assert_eq!(first.totp.period, 30);
        // The code it produces is what proves the seed survived the trip.
        assert_eq!(first.totp.generate().unwrap().len(), 6);
    }

    #[test]
    fn the_entry_type_is_matched_loosely() {
        // The export writes "Totp"; other versions may not.
        let uri = format!("otpauth://totp/a?secret={SEED}");
        for kind in ["Totp", "totp", "TOTP"] {
            let import = from_proton_authenticator(&backup(&entry("x", kind, &uri))).unwrap();
            assert_eq!(import.entries.len(), 1, "{kind} should be accepted");
        }
    }

    #[test]
    fn a_steam_entry_is_skipped_rather_than_mangled() {
        // Steam codes use a different alphabet. Imported as an ordinary TOTP
        // they would generate six digits that look right and never work.
        let uri = format!("otpauth://totp/steam?secret={SEED}");
        let import = from_proton_authenticator(&backup(&entry("Steam", "Steam", &uri))).unwrap();

        assert!(import.entries.is_empty());
        assert_eq!(import.skipped.len(), 1);
        assert_eq!(import.skipped[0].name, "Steam");
        assert!(import.skipped[0].reason.contains("Steam"));
    }

    #[test]
    fn one_bad_entry_does_not_lose_the_others() {
        let good = format!("otpauth://totp/a?secret={SEED}");
        let import = from_proton_authenticator(&backup(&format!(
            "{},{},{}",
            entry("First", "Totp", &good),
            entry("Broken", "Totp", "otpauth://totp/b?secret=not-base32!!"),
            entry("Third", "Totp", &good),
        )))
        .unwrap();

        assert_eq!(import.entries.len(), 2, "the good ones still come through");
        assert_eq!(import.skipped.len(), 1);
        assert_eq!(import.skipped[0].name, "Broken");
        assert_eq!(import.total(), 3, "every entry is accounted for");
    }

    #[test]
    fn an_unnamed_entry_falls_back_to_the_issuer() {
        let uri = format!("otpauth://totp/Fastmail:me@example.com?secret={SEED}&issuer=Fastmail");
        let import = from_proton_authenticator(&backup(&entry("", "Totp", &uri))).unwrap();
        assert_eq!(import.entries[0].name, "Fastmail");
    }

    #[test]
    fn an_entry_with_nothing_to_call_it_still_arrives() {
        let uri = format!("otpauth://totp/?secret={SEED}");
        let import = from_proton_authenticator(&backup(&entry("", "Totp", &uri))).unwrap();
        assert_eq!(import.entries.len(), 1);
        assert_eq!(import.entries[0].name, "Untitled");
    }

    #[test]
    fn a_note_comes_across_but_an_empty_one_does_not() {
        let uri = format!("otpauth://totp/a?secret={SEED}");
        let with = format!(
            r#"{{"id":"a","content":{{"uri":"{uri}","entry_type":"Totp","name":"x"}},"note":"backup codes in the safe"}}"#
        );
        let blank = format!(
            r#"{{"id":"b","content":{{"uri":"{uri}","entry_type":"Totp","name":"y"}},"note":"   "}}"#
        );

        let import = from_proton_authenticator(&backup(&format!("{with},{blank}"))).unwrap();
        assert_eq!(
            import.entries[0].note.as_deref(),
            Some("backup codes in the safe")
        );
        assert_eq!(import.entries[1].note, None);
    }

    #[test]
    fn a_byte_order_mark_does_not_defeat_it() {
        let uri = format!("otpauth://totp/a?secret={SEED}");
        let text = format!("\u{feff}{}", backup(&entry("x", "Totp", &uri)));
        assert_eq!(from_proton_authenticator(&text).unwrap().entries.len(), 1);
    }

    #[test]
    fn something_that_is_not_a_backup_is_refused() {
        assert!(from_proton_authenticator("").is_err());
        assert!(from_proton_authenticator("not json").is_err());
        assert!(from_proton_authenticator(r#"{"hello":"world"}"#).is_err());
    }

    #[test]
    fn an_empty_backup_is_valid_and_empty() {
        let import = from_proton_authenticator(&backup("")).unwrap();
        assert_eq!(import.total(), 0);
    }
}
