//! SQLite, and the only module that touches it.
//!
//! Everything stored here is opaque. The blobs are wrapped under a key derived
//! on the client from a password and a secret key this server has never seen,
//! so a copy of this database is worth the metadata and nothing else.
//!
//! One connection behind a mutex. At the scale this is built for — a few dozen
//! invited accounts, a handful of items each, writes measured in kilobytes —
//! a pool would be machinery bought for nothing, and serialising writes is
//! what makes the revision counter trivially correct.

use std::path::Path;
use std::sync::Mutex;

use rusqlite::{params, Connection, OptionalExtension};
use sha2::{Digest, Sha256};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("database: {0}")]
    Db(#[from] rusqlite::Error),
    /// Someone else wrote first. The client pulls and retries.
    #[error("the vault moved on; pull and retry")]
    Conflict { revision: i64 },
    #[error("no such account")]
    NoAccount,
    #[error("that invite is not usable")]
    BadInvite,
}

pub type Result<T> = std::result::Result<T, Error>;

/// The blobs a client needs before it can unwrap anything.
///
/// Useless without the password and the secret key, which is why this is
/// reachable without a signature — a new device has to fetch it before it has
/// a key to sign with.
#[derive(Clone, Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AccountBlobs {
    pub salt: String,
    pub kdf: String,
    pub wrapped_vault_key: String,
    pub wrapped_account_key: String,
    pub revision: i64,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ItemRecord {
    pub id: String,
    #[serde(default)]
    pub revision: i64,
    /// Base64 ciphertext. Absent for a tombstone.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ciphertext: Option<String>,
    #[serde(default)]
    pub deleted: bool,
}

pub struct Store {
    conn: Mutex<Connection>,
}

impl Store {
    pub fn open(path: &Path) -> Result<Self> {
        let conn = Connection::open(path)?;
        Self::prepare(conn)
    }

    pub fn in_memory() -> Result<Self> {
        Self::prepare(Connection::open_in_memory()?)
    }

    fn prepare(conn: Connection) -> Result<Self> {
        // WAL so a reader is never blocked by the writer, and foreign keys so
        // a device cannot outlive the account it belongs to.
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "foreign_keys", "ON")?;
        conn.pragma_update(None, "synchronous", "NORMAL")?;

        conn.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS accounts (
              id                  TEXT PRIMARY KEY,
              salt                TEXT NOT NULL,
              kdf                 TEXT NOT NULL,
              wrapped_vault_key   TEXT NOT NULL,
              wrapped_account_key TEXT NOT NULL,
              revision            INTEGER NOT NULL DEFAULT 0,
              created_at          INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS devices (
              id         TEXT PRIMARY KEY,
              account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
              public_key BLOB NOT NULL,
              label      TEXT,
              created_at INTEGER NOT NULL,
              last_seen  INTEGER
            );
            CREATE INDEX IF NOT EXISTS devices_by_account ON devices(account_id);

            CREATE TABLE IF NOT EXISTS items (
              account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
              id         TEXT NOT NULL,
              revision   INTEGER NOT NULL,
              ciphertext TEXT,
              deleted    INTEGER NOT NULL DEFAULT 0,
              updated_at INTEGER NOT NULL,
              PRIMARY KEY (account_id, id)
            );
            CREATE INDEX IF NOT EXISTS items_by_revision ON items(account_id, revision);

            -- Invite codes are stored hashed for the same reason passwords are:
            -- a copy of this table should not be a copy of the invites.
            CREATE TABLE IF NOT EXISTS invites (
              code_hash  BLOB PRIMARY KEY,
              created_at INTEGER NOT NULL,
              expires_at INTEGER NOT NULL,
              used_by    TEXT
            );
            "#,
        )?;

        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Connection> {
        // A poisoned mutex means a previous request panicked mid-write. The
        // transaction rolled back, so the data is consistent and refusing
        // every later request would be worse than carrying on.
        self.conn.lock().unwrap_or_else(|e| e.into_inner())
    }

    // ---- invites -------------------------------------------------------

    /// Hashed, because a leaked table should not be a leaked invite.
    fn hash_code(code: &str) -> Vec<u8> {
        Sha256::digest(code.trim().as_bytes()).to_vec()
    }

    pub fn create_invite(&self, code: &str, now: i64, valid_secs: i64) -> Result<()> {
        self.lock().execute(
            "INSERT INTO invites (code_hash, created_at, expires_at) VALUES (?1, ?2, ?3)",
            params![Self::hash_code(code), now, now + valid_secs],
        )?;
        Ok(())
    }

    /// Spends an invite, or refuses. Unused, unexpired, and exactly once.
    pub fn redeem_invite(&self, code: &str, account_id: &str, now: i64) -> Result<()> {
        let changed = self.lock().execute(
            "UPDATE invites SET used_by = ?2
             WHERE code_hash = ?1 AND used_by IS NULL AND expires_at > ?3",
            params![Self::hash_code(code), account_id, now],
        )?;

        if changed == 0 {
            return Err(Error::BadInvite);
        }
        Ok(())
    }

    // ---- accounts ------------------------------------------------------

    #[allow(clippy::too_many_arguments)]
    pub fn create_account(
        &self,
        id: &str,
        salt: &str,
        kdf: &str,
        wrapped_vault_key: &str,
        wrapped_account_key: &str,
        now: i64,
    ) -> Result<()> {
        self.lock().execute(
            "INSERT INTO accounts
               (id, salt, kdf, wrapped_vault_key, wrapped_account_key, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![id, salt, kdf, wrapped_vault_key, wrapped_account_key, now],
        )?;
        Ok(())
    }

    pub fn account(&self, id: &str) -> Result<Option<AccountBlobs>> {
        Ok(self
            .lock()
            .query_row(
                "SELECT salt, kdf, wrapped_vault_key, wrapped_account_key, revision
                 FROM accounts WHERE id = ?1",
                params![id],
                |row| {
                    Ok(AccountBlobs {
                        salt: row.get(0)?,
                        kdf: row.get(1)?,
                        wrapped_vault_key: row.get(2)?,
                        wrapped_account_key: row.get(3)?,
                        revision: row.get(4)?,
                    })
                },
            )
            .optional()?)
    }

    // ---- devices -------------------------------------------------------

    pub fn register_device(
        &self,
        id: &str,
        account_id: &str,
        public_key: &[u8],
        label: Option<&str>,
        now: i64,
    ) -> Result<()> {
        self.lock().execute(
            "INSERT INTO devices (id, account_id, public_key, label, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![id, account_id, public_key, label, now],
        )?;
        Ok(())
    }

    /// The key to check a signature against, if that device belongs to that
    /// account. Returning `None` for both "no such device" and "wrong account"
    /// is deliberate — see [`crate::auth::Rejection::message`].
    pub fn device_key(&self, account_id: &str, device_id: &str) -> Result<Option<Vec<u8>>> {
        Ok(self
            .lock()
            .query_row(
                "SELECT public_key FROM devices WHERE id = ?1 AND account_id = ?2",
                params![device_id, account_id],
                |row| row.get(0),
            )
            .optional()?)
    }

    pub fn touch_device(&self, device_id: &str, now: i64) -> Result<()> {
        self.lock().execute(
            "UPDATE devices SET last_seen = ?2 WHERE id = ?1",
            params![device_id, now],
        )?;
        Ok(())
    }

    /// Revoking a lost machine is deleting one public key.
    pub fn remove_device(&self, account_id: &str, device_id: &str) -> Result<bool> {
        let removed = self.lock().execute(
            "DELETE FROM devices WHERE id = ?1 AND account_id = ?2",
            params![device_id, account_id],
        )?;
        Ok(removed > 0)
    }

    // ---- items ---------------------------------------------------------

    pub fn revision(&self, account_id: &str) -> Result<i64> {
        self.lock()
            .query_row(
                "SELECT revision FROM accounts WHERE id = ?1",
                params![account_id],
                |row| row.get(0),
            )
            .optional()?
            .ok_or(Error::NoAccount)
    }

    /// Everything that changed above the revision the client last saw.
    pub fn items_since(&self, account_id: &str, since: i64) -> Result<Vec<ItemRecord>> {
        let conn = self.lock();
        let mut statement = conn.prepare(
            "SELECT id, revision, ciphertext, deleted
             FROM items WHERE account_id = ?1 AND revision > ?2
             ORDER BY revision, id",
        )?;

        let rows = statement.query_map(params![account_id, since], |row| {
            Ok(ItemRecord {
                id: row.get(0)?,
                revision: row.get(1)?,
                ciphertext: row.get(2)?,
                deleted: row.get::<_, i64>(3)? != 0,
            })
        })?;

        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    /// Writes a batch under optimistic concurrency.
    ///
    /// The whole batch takes one new revision rather than one each: a client
    /// pushes what changed since it last synced, and splitting that into
    /// several revisions would only give other clients more round trips to
    /// discover the same set.
    pub fn push_items(
        &self,
        account_id: &str,
        expected: i64,
        items: &[ItemRecord],
        now: i64,
    ) -> Result<i64> {
        let mut conn = self.lock();
        let tx = conn.transaction()?;

        let current: i64 = tx
            .query_row(
                "SELECT revision FROM accounts WHERE id = ?1",
                params![account_id],
                |row| row.get(0),
            )
            .optional()?
            .ok_or(Error::NoAccount)?;

        if current != expected {
            return Err(Error::Conflict { revision: current });
        }

        let next = current + 1;

        for item in items {
            tx.execute(
                "INSERT INTO items (account_id, id, revision, ciphertext, deleted, updated_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)
                 ON CONFLICT(account_id, id) DO UPDATE SET
                   revision   = excluded.revision,
                   ciphertext = excluded.ciphertext,
                   deleted    = excluded.deleted,
                   updated_at = excluded.updated_at",
                params![
                    account_id,
                    item.id,
                    next,
                    // A tombstone keeps no ciphertext: the delete has to
                    // propagate, the contents do not.
                    if item.deleted {
                        None
                    } else {
                        item.ciphertext.clone()
                    },
                    item.deleted as i64,
                    now
                ],
            )?;
        }

        tx.execute(
            "UPDATE accounts SET revision = ?2 WHERE id = ?1",
            params![account_id, next],
        )?;
        tx.commit()?;

        Ok(next)
    }

    /// Drops tombstones nobody needs any more.
    ///
    /// Without tombstones a delete on one machine is silently undone by the
    /// next sync from another; without purging them the database only grows.
    pub fn purge_tombstones(&self, before: i64) -> Result<usize> {
        Ok(self.lock().execute(
            "DELETE FROM items WHERE deleted = 1 AND updated_at < ?1",
            params![before],
        )?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: i64 = 1_800_000_000;
    const ACCOUNT: &str = "acct-1";

    fn store() -> Store {
        let store = Store::in_memory().unwrap();
        store
            .create_account(
                ACCOUNT,
                "salt",
                "{}",
                "wrapped-vault",
                "wrapped-account",
                NOW,
            )
            .unwrap();
        store
    }

    fn item(id: &str, ciphertext: &str) -> ItemRecord {
        ItemRecord {
            id: id.into(),
            revision: 0,
            ciphertext: Some(ciphertext.into()),
            deleted: false,
        }
    }

    #[test]
    fn a_new_account_starts_at_revision_zero() {
        assert_eq!(store().revision(ACCOUNT).unwrap(), 0);
    }

    #[test]
    fn a_push_advances_the_revision_once_for_the_batch() {
        let store = store();
        let next = store
            .push_items(ACCOUNT, 0, &[item("a", "x"), item("b", "y")], NOW)
            .unwrap();

        assert_eq!(next, 1);
        assert_eq!(store.revision(ACCOUNT).unwrap(), 1);
    }

    #[test]
    fn a_client_pulls_only_what_it_has_not_seen() {
        let store = store();
        store
            .push_items(ACCOUNT, 0, &[item("a", "x")], NOW)
            .unwrap();
        store
            .push_items(ACCOUNT, 1, &[item("b", "y")], NOW)
            .unwrap();

        assert_eq!(store.items_since(ACCOUNT, 0).unwrap().len(), 2);
        let fresh = store.items_since(ACCOUNT, 1).unwrap();
        assert_eq!(fresh.len(), 1);
        assert_eq!(fresh[0].id, "b");
        assert!(store.items_since(ACCOUNT, 2).unwrap().is_empty());
    }

    #[test]
    fn pushing_against_a_stale_revision_conflicts_and_writes_nothing() {
        let store = store();
        store
            .push_items(ACCOUNT, 0, &[item("a", "x")], NOW)
            .unwrap();

        match store.push_items(ACCOUNT, 0, &[item("b", "y")], NOW) {
            Err(Error::Conflict { revision }) => assert_eq!(revision, 1),
            other => panic!("expected a conflict, got {other:?}"),
        }

        // The loser's items must not have landed.
        assert!(store
            .items_since(ACCOUNT, 0)
            .unwrap()
            .iter()
            .all(|record| record.id != "b"));
    }

    #[test]
    fn an_update_replaces_rather_than_duplicates() {
        let store = store();
        store
            .push_items(ACCOUNT, 0, &[item("a", "first")], NOW)
            .unwrap();
        store
            .push_items(ACCOUNT, 1, &[item("a", "second")], NOW)
            .unwrap();

        let all = store.items_since(ACCOUNT, 0).unwrap();
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].ciphertext.as_deref(), Some("second"));
    }

    #[test]
    fn a_tombstone_keeps_no_ciphertext_but_still_propagates() {
        let store = store();
        store
            .push_items(ACCOUNT, 0, &[item("a", "secret")], NOW)
            .unwrap();
        store
            .push_items(
                ACCOUNT,
                1,
                &[ItemRecord {
                    id: "a".into(),
                    revision: 0,
                    ciphertext: Some("secret".into()),
                    deleted: true,
                }],
                NOW,
            )
            .unwrap();

        let all = store.items_since(ACCOUNT, 0).unwrap();
        assert_eq!(all.len(), 1);
        assert!(all[0].deleted);
        assert_eq!(all[0].ciphertext, None, "a delete should not keep the body");
    }

    #[test]
    fn tombstones_are_purged_once_every_client_has_had_time_to_see_them() {
        let store = store();
        store
            .push_items(
                ACCOUNT,
                0,
                &[ItemRecord {
                    id: "a".into(),
                    revision: 0,
                    ciphertext: None,
                    deleted: true,
                }],
                NOW,
            )
            .unwrap();

        assert_eq!(store.purge_tombstones(NOW - 1).unwrap(), 0);
        assert_eq!(store.purge_tombstones(NOW + 1).unwrap(), 1);
        assert!(store.items_since(ACCOUNT, 0).unwrap().is_empty());
    }

    #[test]
    fn an_invite_works_exactly_once() {
        let store = store();
        store.create_invite("open-sesame", NOW, 3600).unwrap();

        assert!(store.redeem_invite("open-sesame", ACCOUNT, NOW).is_ok());
        assert!(matches!(
            store.redeem_invite("open-sesame", ACCOUNT, NOW),
            Err(Error::BadInvite)
        ));
    }

    #[test]
    fn an_expired_invite_is_refused() {
        let store = store();
        store.create_invite("late", NOW, 60).unwrap();

        assert!(matches!(
            store.redeem_invite("late", ACCOUNT, NOW + 61),
            Err(Error::BadInvite)
        ));
    }

    #[test]
    fn an_unknown_invite_is_refused_the_same_way() {
        assert!(matches!(
            store().redeem_invite("never-issued", ACCOUNT, NOW),
            Err(Error::BadInvite)
        ));
    }

    #[test]
    fn the_invite_is_not_stored_in_the_clear() {
        let store = store();
        store.create_invite("plaintext-code", NOW, 3600).unwrap();

        let found: i64 = store
            .lock()
            .query_row(
                "SELECT COUNT(*) FROM invites WHERE CAST(code_hash AS TEXT) LIKE '%plaintext-code%'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(found, 0);
    }

    #[test]
    fn a_device_key_is_only_visible_to_its_own_account() {
        let store = store();
        store
            .create_account("other", "s", "{}", "v", "a", NOW)
            .unwrap();
        store
            .register_device("dev-1", ACCOUNT, &[1u8; 32], Some("laptop"), NOW)
            .unwrap();

        assert!(store.device_key(ACCOUNT, "dev-1").unwrap().is_some());
        assert!(store.device_key("other", "dev-1").unwrap().is_none());
    }

    #[test]
    fn revoking_a_device_removes_its_key() {
        let store = store();
        store
            .register_device("dev-1", ACCOUNT, &[1u8; 32], None, NOW)
            .unwrap();

        assert!(store.remove_device(ACCOUNT, "dev-1").unwrap());
        assert!(store.device_key(ACCOUNT, "dev-1").unwrap().is_none());
        assert!(!store.remove_device(ACCOUNT, "dev-1").unwrap());
    }

    #[test]
    fn pushing_to_an_account_that_does_not_exist_is_refused() {
        assert!(matches!(
            store().push_items("nobody", 0, &[item("a", "x")], NOW),
            Err(Error::NoAccount)
        ));
    }

    #[test]
    fn the_account_blobs_come_back_as_stored() {
        let blobs = store().account(ACCOUNT).unwrap().unwrap();
        assert_eq!(blobs.wrapped_vault_key, "wrapped-vault");
        assert_eq!(blobs.wrapped_account_key, "wrapped-account");
        assert_eq!(blobs.revision, 0);
        assert!(store().account("nobody").unwrap().is_none());
    }
}
