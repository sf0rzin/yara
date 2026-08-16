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

use std::collections::HashMap;

use serde::Deserialize;

use crate::csv;
use crate::error::{Error, Result};
use crate::totp::TotpConfig;

/// One entry that was read successfully.
#[derive(Debug, Clone)]
pub struct Imported {
    /// What to call the item. The export's own label, falling back to the
    /// issuer and then the account, so an entry never arrives unnamed.
    pub name: String,
    /// Absent for a password-only entry, and for a Bitwarden row whose
    /// `login_totp` could not be read — the row still becomes an item, and
    /// the failure is reported separately in [`Import::skipped`] rather than
    /// costing the entry its password too.
    pub totp: Option<TotpConfig>,
    pub note: Option<String>,
    pub password: Option<String>,
    pub username: Option<String>,
    pub url: Option<String>,
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

/// The envelope, and nothing more than the envelope.
///
/// `entries` stays unparsed at this stage so one unreadable row cannot fail
/// the file around it. The export's own `version` is not read at all: nothing
/// here behaves differently for one, and insisting it be a number failed whole
/// backups written by an exporter that wrote `"version": "1"` — the report for
/// which was "not a Proton backup", with no indication of which field.
#[derive(Deserialize)]
struct ProtonBackup {
    entries: Vec<serde_json::Value>,
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

    for (position, raw) in backup.entries.into_iter().enumerate() {
        // One entry at a time, because the alternative loses the file. A
        // single row missing its `uri` used to fail the whole import with
        // "not a Proton backup", and the obvious next thing to do after a
        // failed import is delete the plaintext export — which destroys the
        // twenty-two entries that would have read perfectly.
        let fallback = raw_name(&raw, position + 1);
        let entry: ProtonEntry = match serde_json::from_value(raw) {
            Ok(entry) => entry,
            Err(error) => {
                import.skipped.push(Skipped {
                    name: fallback,
                    reason: error.to_string(),
                });
                continue;
            }
        };

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
                totp: Some(totp),
                note: entry.note.filter(|note| !note.trim().is_empty()),
                password: None,
                username: None,
                url: None,
            }),
            Err(error) => import.skipped.push(Skipped {
                name: label,
                reason: error.to_string(),
            }),
        }
    }

    Ok(import)
}

/// What to call an entry that could not be parsed at all.
///
/// Its own label if there is one that survived, and its position in the file
/// if there is not. A position is a better fallback than "Untitled": the user
/// is being told to go and look at a row in a file they cannot read, and
/// "entry 2" says which row while "Untitled" says nothing.
fn raw_name(raw: &serde_json::Value, position: usize) -> String {
    raw.get("content")
        .and_then(|content| content.get("name"))
        .and_then(serde_json::Value::as_str)
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .map_or_else(|| format!("entry {position}"), str::to_string)
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

// ---- Password exports ---------------------------------------------------

const CHROME_COLUMNS: &[&str] = &["name", "url", "username", "password"];
const BITWARDEN_COLUMNS: &[&str] = &["name", "login_uri", "login_username", "login_password"];

/// Reads a Chrome or Edge password export.
///
/// Both write the same header, `name,url,username,password[,note]` — the
/// note column is a newer addition some versions omit, so it is not part of
/// what identifies the format.
pub fn from_chrome_csv(text: &str) -> Result<Import> {
    let mut rows = csv::parse_rows(text).into_iter();
    let header = rows
        .next()
        .ok_or_else(|| Error::UnrecognisedFormat("the file is empty".to_string()))?;
    let index = csv::header_index(&header);

    if !csv::has_columns(&index, CHROME_COLUMNS) {
        return Err(unrecognised("Chrome", CHROME_COLUMNS, &header));
    }

    let mut import = Import::default();
    for (position, row) in rows.enumerate() {
        match parse_chrome_row(&index, &row) {
            Ok(entry) => import.entries.push(entry),
            Err(reason) => import.skipped.push(Skipped {
                name: row_label(&index, &row, position + 2),
                reason,
            }),
        }
    }

    Ok(import)
}

fn parse_chrome_row(
    index: &HashMap<String, usize>,
    row: &[String],
) -> std::result::Result<Imported, String> {
    let name =
        trimmed(csv::field(index, row, "name")).ok_or_else(|| "missing a name".to_string())?;

    Ok(Imported {
        name,
        totp: None,
        // Kept as written, not trimmed: a note can carry meaningful
        // indentation, the same reasoning `from_proton_authenticator` already
        // applies to its own note field.
        note: kept_if_present(csv::field(index, row, "note")),
        // Never trimmed or otherwise touched: this is a secret, not text
        // meant for display, and altering it would import the wrong password.
        password: csv::field(index, row, "password")
            .filter(|value| !value.is_empty())
            .map(str::to_string),
        username: trimmed(csv::field(index, row, "username")),
        url: trimmed(csv::field(index, row, "url")),
    })
}

/// Reads a Bitwarden password export.
///
/// Matched on the four `login_*` columns rather than the full header
/// Bitwarden happens to write today: `folder`, `favorite`, `fields` and
/// `reprompt` describe organisation and vault behaviour this importer has no
/// use for, and requiring them would break on the export the moment
/// Bitwarden adds or drops one.
pub fn from_bitwarden_csv(text: &str) -> Result<Import> {
    let mut rows = csv::parse_rows(text).into_iter();
    let header = rows
        .next()
        .ok_or_else(|| Error::UnrecognisedFormat("the file is empty".to_string()))?;
    let index = csv::header_index(&header);

    if !csv::has_columns(&index, BITWARDEN_COLUMNS) {
        return Err(unrecognised("Bitwarden", BITWARDEN_COLUMNS, &header));
    }

    let mut import = Import::default();
    for (position, row) in rows.enumerate() {
        match parse_bitwarden_row(&index, &row) {
            Ok((entry, totp_failure)) => {
                // The row still becomes an item even when its 2FA code could
                // not be read — losing the password over an unrelated field
                // failing to parse would be a worse outcome than the field
                // simply being missing.
                if let Some(reason) = totp_failure {
                    import.skipped.push(Skipped {
                        name: format!("{} (2FA code)", entry.name),
                        reason,
                    });
                }
                import.entries.push(entry);
            }
            Err(reason) => import.skipped.push(Skipped {
                name: row_label(&index, &row, position + 2),
                reason,
            }),
        }
    }

    Ok(import)
}

fn parse_bitwarden_row(
    index: &HashMap<String, usize>,
    row: &[String],
) -> std::result::Result<(Imported, Option<String>), String> {
    let name =
        trimmed(csv::field(index, row, "name")).ok_or_else(|| "missing a name".to_string())?;

    // Bitwarden exports every item type through the same file — secure notes,
    // cards, identities — and for all of those the `login_*` columns this
    // importer reads are empty. Without this check such a row would still
    // become a login item, just one with no password and no URL: silent
    // corruption of exactly the kind the rest of this file exists to avoid.
    if let Some(kind) = csv::field(index, row, "type") {
        if !kind.eq_ignore_ascii_case("login") {
            return Err(format!("{kind} entries are not supported yet"));
        }
    }

    let raw_totp = csv::field(index, row, "login_totp").filter(|value| !value.trim().is_empty());
    let (totp, totp_failure) = match raw_totp {
        None => (None, None),
        Some(raw) => match parse_bitwarden_totp(raw) {
            Ok(totp) => (Some(totp), None),
            Err(reason) => (None, Some(reason)),
        },
    };

    let entry = Imported {
        name,
        totp,
        note: kept_if_present(csv::field(index, row, "notes")),
        password: csv::field(index, row, "login_password")
            .filter(|value| !value.is_empty())
            .map(str::to_string),
        username: trimmed(csv::field(index, row, "login_username")),
        url: trimmed(csv::field(index, row, "login_uri")),
    };

    Ok((entry, totp_failure))
}

/// Bitwarden writes `login_totp` as either a complete `otpauth://` URI or a
/// bare base32 secret, depending on how the code was originally added to the
/// entry. `validate` is what catches the bare case: `TotpConfig::new` cannot
/// fail on its own, since it only wraps whatever string it is given.
fn parse_bitwarden_totp(raw: &str) -> std::result::Result<TotpConfig, String> {
    if raw.starts_with("otpauth://") {
        return TotpConfig::from_uri(raw).map_err(|error| error.to_string());
    }

    let totp = TotpConfig::new(raw.to_string());
    totp.validate().map_err(|error| error.to_string())?;
    Ok(totp)
}

/// Reads a password export, detecting Chrome or Bitwarden by header.
///
/// Tries Chrome first, arbitrarily — the two headers do not overlap enough
/// for a real file to match both, so the order only matters for which
/// format's parse failure is discarded in favour of the other's.
pub fn from_csv(text: &str) -> Result<Import> {
    if let Ok(import) = from_chrome_csv(text) {
        return Ok(import);
    }
    if let Ok(import) = from_bitwarden_csv(text) {
        return Ok(import);
    }

    let header = csv::parse_rows(text).into_iter().next().unwrap_or_default();
    Err(if header.is_empty() {
        Error::UnrecognisedFormat("the file is empty".to_string())
    } else {
        Error::UnrecognisedFormat(format!(
            "not a Chrome or Bitwarden export: found a header of {}",
            header.join(", ")
        ))
    })
}

/// The error for a header that named neither dialect's required columns.
fn unrecognised(format: &str, required: &[&str], header: &[String]) -> Error {
    Error::UnrecognisedFormat(format!(
        "not a {format} export: expected a header naming {}, found {}",
        required.join(", "),
        header.join(", "),
    ))
}

/// What to call a row that did not become an item — its own name if the row
/// reached that column at all, its position in the file otherwise.
///
/// A position beats "Untitled" the way it does for the Proton importer: the
/// user has to go find this row in a spreadsheet, and "row 14" says where
/// while "Untitled" says nothing. Counted from 2 because the header is line 1
/// in the file the user has open.
fn row_label(index: &HashMap<String, usize>, row: &[String], position: usize) -> String {
    trimmed(csv::field(index, row, "name")).unwrap_or_else(|| format!("row {position}"))
}

/// `field`'s value, trimmed, or `None` if nothing but whitespace is left.
///
/// For cosmetic fields — a name, a URL, a username — where surrounding
/// whitespace is never meaningful and is more likely a copy-paste accident
/// than part of the value.
fn trimmed(value: Option<&str>) -> Option<String> {
    value
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

/// `field`'s value as written, or `None` if it is empty once whitespace is
/// disregarded. Unlike [`trimmed`], the stored value itself is never altered
/// — the same reasoning `from_proton_authenticator` applies to its own note
/// field applies here too.
fn kept_if_present(value: Option<&str>) -> Option<String> {
    value.filter(|s| !s.trim().is_empty()).map(str::to_string)
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
        let totp = first.totp.as_ref().unwrap();
        assert_eq!(totp.digits, 6);
        assert_eq!(totp.period, 30);
        // The code it produces is what proves the seed survived the trip.
        assert_eq!(totp.generate().unwrap().len(), 6);
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
    fn an_entry_missing_its_uri_does_not_take_the_file_with_it() {
        // The failure that motivated all of this. One row without a `uri`
        // failed the parse of the whole file, which was reported as "not a
        // Proton backup" with no indication of which row — and the natural
        // next step, deleting the plaintext export, destroys the entries that
        // would have read perfectly. A TOTP seed is the hardest thing in a
        // vault to get back.
        let good = format!("otpauth://totp/a?secret={SEED}");
        let broken = r#"{"id":"b","content":{"entry_type":"Totp","name":"Missing"},"note":null}"#;

        let import = from_proton_authenticator(&backup(&format!(
            "{},{},{}",
            entry("First", "Totp", &good),
            broken,
            entry("Third", "Totp", &good),
        )))
        .unwrap();

        assert_eq!(import.entries.len(), 2);
        assert_eq!(import.entries[0].name, "First");
        assert_eq!(import.entries[1].name, "Third");

        assert_eq!(import.skipped.len(), 1);
        assert_eq!(import.skipped[0].name, "Missing");
        assert!(
            import.skipped[0].reason.contains("uri"),
            "the reason has to name the field: {}",
            import.skipped[0].reason
        );
        assert_eq!(import.total(), 3, "every entry is accounted for");
    }

    #[test]
    fn an_unreadable_entry_with_no_name_is_reported_by_its_position() {
        // "Untitled" would tell the user nothing about which of twenty-three
        // rows to go and look at.
        let import = from_proton_authenticator(&backup(r#"{"id":"a"},{"id":"b"}"#)).unwrap();

        assert_eq!(import.skipped.len(), 2);
        assert_eq!(import.skipped[0].name, "entry 1");
        assert_eq!(import.skipped[1].name, "entry 2");
    }

    #[test]
    fn a_version_that_is_not_a_number_does_not_fail_the_file() {
        // Nothing here reads the version, so nothing here should be able to
        // reject a file over it. An exporter writing `"1"` instead of `1`
        // used to cost the user every code in the export.
        let uri = format!("otpauth://totp/a?secret={SEED}");
        let text = format!(
            r#"{{"version":"1","entries":[{}]}}"#,
            entry("GitHub", "Totp", &uri)
        );

        let import = from_proton_authenticator(&text).unwrap();
        assert_eq!(import.entries.len(), 1);
        assert!(import.skipped.is_empty());
    }

    #[test]
    fn a_backup_with_no_version_at_all_still_reads() {
        let uri = format!("otpauth://totp/a?secret={SEED}");
        let text = format!(r#"{{"entries":[{}]}}"#, entry("GitHub", "Totp", &uri));
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

    // ---- Password exports ------------------------------------------------

    const BITWARDEN_HEADER: &str =
        "folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp";

    #[test]
    fn a_chrome_export_produces_items_with_name_url_username_and_password() {
        let text = "name,url,username,password,note\nGitHub,https://github.com,me,hunter2,\n";
        let import = from_chrome_csv(text).unwrap();

        assert_eq!(import.entries.len(), 1);
        let entry = &import.entries[0];
        assert_eq!(entry.name, "GitHub");
        assert_eq!(entry.url.as_deref(), Some("https://github.com"));
        assert_eq!(entry.username.as_deref(), Some("me"));
        assert_eq!(entry.password.as_deref(), Some("hunter2"));
        assert!(entry.totp.is_none());
    }

    #[test]
    fn a_bitwarden_export_produces_the_same_plus_a_totp_where_present() {
        let seed = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
        let text = format!(
            "{BITWARDEN_HEADER}\n,,login,GitHub,,,0,https://github.com,me,hunter2,{seed}\n"
        );

        let import = from_bitwarden_csv(&text).unwrap();

        assert_eq!(import.entries.len(), 1);
        assert!(import.skipped.is_empty());
        let entry = &import.entries[0];
        assert_eq!(entry.name, "GitHub");
        assert_eq!(entry.url.as_deref(), Some("https://github.com"));
        assert_eq!(entry.username.as_deref(), Some("me"));
        assert_eq!(entry.password.as_deref(), Some("hunter2"));
        assert_eq!(entry.totp.as_ref().unwrap().secret.expose(), seed);
    }

    #[test]
    fn a_bitwarden_row_for_a_non_login_item_is_skipped_with_a_reason_naming_its_type() {
        // Bitwarden exports secure notes, cards and identities through the
        // same file. All of them leave login_uri/login_username/login_password
        // blank, which — unfiltered — would still become a login item with
        // no password and no URL.
        let text = format!("{BITWARDEN_HEADER}\n,,secure_note,Wifi key,the actual key,,0,,,,\n");
        let import = from_bitwarden_csv(&text).unwrap();

        assert!(import.entries.is_empty());
        assert_eq!(import.skipped.len(), 1);
        // The row is rejected, but its own name still made it through — the
        // caller re-derives the label from the row rather than losing it
        // along with the reason.
        assert_eq!(import.skipped[0].name, "Wifi key");
        assert!(
            import.skipped[0].reason.contains("secure_note"),
            "the reason has to name the type: {}",
            import.skipped[0].reason
        );
    }

    #[test]
    fn a_quoted_note_containing_a_comma_and_a_newline_arrives_intact() {
        let text = "name,url,username,password,note\n\
                     GitHub,https://github.com,me,hunter2,\"shared with the team, see #secrets\nrotate quarterly\"\n";
        let import = from_chrome_csv(text).unwrap();

        assert_eq!(
            import.entries[0].note.as_deref(),
            Some("shared with the team, see #secrets\nrotate quarterly")
        );
    }

    #[test]
    fn a_row_with_too_few_columns_is_skipped_with_a_reason_naming_it() {
        // Two fields, nowhere near enough to reach `name` at index 3.
        let text = format!("{BITWARDEN_HEADER}\nsomething,else\n");
        let import = from_bitwarden_csv(&text).unwrap();

        assert!(import.entries.is_empty());
        assert_eq!(import.skipped.len(), 1);
        assert_eq!(import.skipped[0].name, "row 2");
        assert!(
            import.skipped[0].reason.contains("name"),
            "the reason has to name the field: {}",
            import.skipped[0].reason
        );
    }

    #[test]
    fn a_row_with_an_empty_password_becomes_an_item() {
        let text = "name,url,username,password,note\nGitHub,https://github.com,me,,\n";
        let import = from_chrome_csv(text).unwrap();

        assert_eq!(import.entries.len(), 1);
        assert_eq!(import.entries[0].password, None);
    }

    #[test]
    fn a_bitwarden_row_with_an_unparseable_login_totp_imports_the_password_and_skips_the_code() {
        let text = format!(
            "{BITWARDEN_HEADER}\n,,login,GitHub,,,0,https://github.com,me,hunter2,not-a-valid-secret!!\n"
        );
        let import = from_bitwarden_csv(&text).unwrap();

        assert_eq!(import.entries.len(), 1, "the password still comes through");
        let entry = &import.entries[0];
        assert_eq!(entry.password.as_deref(), Some("hunter2"));
        assert!(entry.totp.is_none());

        assert_eq!(import.skipped.len(), 1);
        assert_eq!(import.skipped[0].name, "GitHub (2FA code)");
    }

    #[test]
    fn an_unknown_header_is_an_error_naming_what_it_found() {
        let text = "favourite_colour,shoe_size\nblue,9\n";
        let message = from_csv(text).unwrap_err().to_string();

        assert!(message.contains("favourite_colour"), "{message}");
        assert!(message.contains("shoe_size"), "{message}");
    }

    #[test]
    fn an_empty_file_is_an_error_not_an_empty_successful_import() {
        assert!(from_csv("").is_err());
        assert!(from_chrome_csv("").is_err());
        assert!(from_bitwarden_csv("").is_err());
    }

    #[test]
    fn total_accounts_for_every_row_nothing_vanishes() {
        let text = "name,url,username,password,note\n\
                     GitHub,https://github.com,me,hunter2,\n\
                     ,https://example.com,nobody,secret,\n\
                     GitLab,https://gitlab.com,me,,\n";
        let import = from_chrome_csv(text).unwrap();

        assert_eq!(import.entries.len(), 2, "GitHub and GitLab both read");
        assert_eq!(import.skipped.len(), 1, "the nameless row is skipped");
        assert_eq!(import.total(), 3, "every row is accounted for");
    }

    #[test]
    fn from_csv_recognises_either_dialect() {
        let chrome = "name,url,username,password,note\nGitHub,https://github.com,me,hunter2,\n";
        assert_eq!(from_csv(chrome).unwrap().entries.len(), 1);

        let bitwarden =
            format!("{BITWARDEN_HEADER}\n,,login,GitHub,,,0,https://github.com,me,hunter2,\n");
        assert_eq!(from_csv(&bitwarden).unwrap().entries.len(), 1);
    }
}
