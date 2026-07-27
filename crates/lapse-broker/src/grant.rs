//! Standing permission, scoped and expiring.
//!
//! A grant exists so that approving "run the migration" does not mean answering
//! a prompt once per query. It never becomes a general permission: every grant
//! is pinned to one item, one field, one requesting executable, a deadline, and
//! a use count.
//!
//! There is deliberately no "always allow" and no way to widen a grant after
//! the fact. Anything a grant does not cover goes back to the user.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::protocol::{Field, Intent};

/// Who is asking.
///
/// Identity is the executable path, not the process id: a pid is reused and
/// means nothing across invocations, whereas the binary on disk is the thing
/// the user actually agreed to trust.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClientId {
    pub pid: u32,
    /// Resolved image path. `None` when it could not be determined.
    pub executable: Option<String>,
}

impl ClientId {
    pub fn unknown(pid: u32) -> Self {
        Self {
            pid,
            executable: None,
        }
    }

    /// A short name for the approval prompt.
    pub fn display_name(&self) -> String {
        match &self.executable {
            Some(path) => path
                .rsplit(['\\', '/'])
                .next()
                .unwrap_or(path.as_str())
                .to_string(),
            None => format!("unidentified process {}", self.pid),
        }
    }

    /// Whether a grant issued to `self` may be reused by `other`.
    ///
    /// Fails closed when either side is unidentified: an unidentifiable caller
    /// gets a fresh prompt every time rather than inheriting someone's grant.
    fn same_program_as(&self, other: &ClientId) -> bool {
        match (&self.executable, &other.executable) {
            (Some(a), Some(b)) => a.eq_ignore_ascii_case(b),
            _ => false,
        }
    }
}

/// What a grant permits.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Scope {
    /// Run commands with the credential injected. Never covers reveal.
    Run,
    /// Hand over the plaintext.
    Reveal,
}

impl Scope {
    fn covers(&self, intent: &Intent) -> bool {
        match (self, intent) {
            (Self::Run, Intent::Run { .. }) => true,
            (Self::Reveal, Intent::Reveal) => true,
            // A grant to run something is not consent to be shown the value.
            // Reveal always goes back to the user.
            (Self::Run, Intent::Reveal) => false,
            (Self::Reveal, Intent::Run { .. }) => false,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Grant {
    pub id: Uuid,
    pub item_id: Uuid,
    pub item_name: String,
    pub field: Field,
    pub scope: Scope,
    pub client: ClientId,
    pub issued_at: u64,
    pub expires_at: u64,
    pub max_uses: u32,
    pub uses: u32,
}

impl Grant {
    pub fn new(
        item_id: Uuid,
        item_name: impl Into<String>,
        field: Field,
        scope: Scope,
        client: ClientId,
        issued_at: u64,
        duration_secs: u64,
        max_uses: u32,
    ) -> Self {
        Self {
            id: Uuid::new_v4(),
            item_id,
            item_name: item_name.into(),
            field,
            scope,
            client,
            issued_at,
            expires_at: issued_at.saturating_add(duration_secs),
            max_uses,
            uses: 0,
        }
    }

    /// A grant good for exactly one use, expiring shortly after.
    ///
    /// The short window exists so an approval the user forgot about cannot be
    /// redeemed an hour later.
    pub fn once(
        item_id: Uuid,
        item_name: impl Into<String>,
        field: Field,
        scope: Scope,
        client: ClientId,
        now: u64,
    ) -> Self {
        Self::new(item_id, item_name, field, scope, client, now, 60, 1)
    }

    pub fn is_expired(&self, now: u64) -> bool {
        now >= self.expires_at
    }

    pub fn is_spent(&self) -> bool {
        self.uses >= self.max_uses
    }

    pub fn is_live(&self, now: u64) -> bool {
        !self.is_expired(now) && !self.is_spent()
    }

    pub fn remaining_uses(&self) -> u32 {
        self.max_uses.saturating_sub(self.uses)
    }

    pub fn seconds_remaining(&self, now: u64) -> u64 {
        self.expires_at.saturating_sub(now)
    }

    /// Whether this grant authorises a specific request.
    fn authorises(
        &self,
        item_id: Uuid,
        field: Field,
        intent: &Intent,
        client: &ClientId,
        now: u64,
    ) -> bool {
        self.is_live(now)
            && self.item_id == item_id
            && self.field == field
            && self.scope.covers(intent)
            && self.client.same_program_as(client)
    }
}

/// The set of grants currently outstanding.
#[derive(Debug, Default)]
pub struct GrantStore {
    grants: Vec<Grant>,
}

impl GrantStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn issue(&mut self, grant: Grant) -> Uuid {
        let id = grant.id;
        self.grants.push(grant);
        id
    }

    /// Finds a grant covering this request and charges one use to it.
    ///
    /// Consuming here rather than in a separate step means a caller cannot
    /// check authorisation and then forget to record that it was used.
    pub fn redeem(
        &mut self,
        item_id: Uuid,
        field: Field,
        intent: &Intent,
        client: &ClientId,
        now: u64,
    ) -> Option<Uuid> {
        let grant = self
            .grants
            .iter_mut()
            .find(|grant| grant.authorises(item_id, field, intent, client, now))?;

        grant.uses += 1;
        Some(grant.id)
    }

    /// Grants still worth showing the user.
    pub fn live(&self, now: u64) -> Vec<&Grant> {
        self.grants.iter().filter(|g| g.is_live(now)).collect()
    }

    /// Drops grants that are expired or used up.
    pub fn prune(&mut self, now: u64) {
        self.grants.retain(|grant| grant.is_live(now));
    }

    pub fn revoke(&mut self, id: Uuid) -> bool {
        let before = self.grants.len();
        self.grants.retain(|grant| grant.id != id);
        self.grants.len() != before
    }

    /// Drops everything. Called when the vault locks: a grant that outlived the
    /// key it unlocks would be a permission with nothing behind it.
    pub fn clear(&mut self) {
        self.grants.clear();
    }

    pub fn is_empty(&self) -> bool {
        self.grants.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: u64 = 1_800_000_000;

    fn client(exe: &str) -> ClientId {
        ClientId {
            pid: 1234,
            executable: Some(exe.into()),
        }
    }

    fn run_intent() -> Intent {
        Intent::Run {
            command: "npm".into(),
            args: vec![],
            env_var: "SECRET".into(),
            cwd: None,
        }
    }

    fn grant_for(item: Uuid, scope: Scope, exe: &str) -> Grant {
        Grant::new(
            item,
            "db-prod",
            Field::Password,
            scope,
            client(exe),
            NOW,
            900,
            5,
        )
    }

    #[test]
    fn a_matching_request_is_authorised() {
        let item = Uuid::new_v4();
        let mut store = GrantStore::new();
        store.issue(grant_for(item, Scope::Run, "C:\\bin\\claude.exe"));

        assert!(store
            .redeem(
                item,
                Field::Password,
                &run_intent(),
                &client("C:\\bin\\claude.exe"),
                NOW
            )
            .is_some());
    }

    #[test]
    fn a_grant_does_not_cover_a_different_item() {
        let mut store = GrantStore::new();
        store.issue(grant_for(Uuid::new_v4(), Scope::Run, "C:\\bin\\a.exe"));

        assert!(store
            .redeem(
                Uuid::new_v4(),
                Field::Password,
                &run_intent(),
                &client("C:\\bin\\a.exe"),
                NOW
            )
            .is_none());
    }

    #[test]
    fn a_grant_does_not_cover_a_different_field() {
        let item = Uuid::new_v4();
        let mut store = GrantStore::new();
        store.issue(grant_for(item, Scope::Run, "C:\\bin\\a.exe"));

        assert!(store
            .redeem(
                item,
                Field::Totp,
                &run_intent(),
                &client("C:\\bin\\a.exe"),
                NOW
            )
            .is_none());
    }

    #[test]
    fn permission_to_run_is_not_permission_to_reveal() {
        let item = Uuid::new_v4();
        let mut store = GrantStore::new();
        store.issue(grant_for(item, Scope::Run, "C:\\bin\\a.exe"));

        assert!(store
            .redeem(
                item,
                Field::Password,
                &Intent::Reveal,
                &client("C:\\bin\\a.exe"),
                NOW
            )
            .is_none());
    }

    #[test]
    fn permission_to_reveal_is_not_permission_to_run() {
        let item = Uuid::new_v4();
        let mut store = GrantStore::new();
        store.issue(grant_for(item, Scope::Reveal, "C:\\bin\\a.exe"));

        assert!(store
            .redeem(
                item,
                Field::Password,
                &run_intent(),
                &client("C:\\bin\\a.exe"),
                NOW
            )
            .is_none());
    }

    #[test]
    fn a_different_program_cannot_use_someone_elses_grant() {
        let item = Uuid::new_v4();
        let mut store = GrantStore::new();
        store.issue(grant_for(item, Scope::Run, "C:\\bin\\claude.exe"));

        assert!(store
            .redeem(
                item,
                Field::Password,
                &run_intent(),
                &client("C:\\bin\\something-else.exe"),
                NOW
            )
            .is_none());
    }

    #[test]
    fn an_unidentifiable_client_never_matches_a_grant() {
        let item = Uuid::new_v4();
        let mut store = GrantStore::new();
        store.issue(grant_for(item, Scope::Run, "C:\\bin\\a.exe"));

        assert!(store
            .redeem(
                item,
                Field::Password,
                &run_intent(),
                &ClientId::unknown(1234),
                NOW
            )
            .is_none());
    }

    #[test]
    fn a_grant_issued_to_an_unidentifiable_client_is_never_reusable() {
        let item = Uuid::new_v4();
        let mut store = GrantStore::new();
        store.issue(Grant::new(
            item,
            "x",
            Field::Password,
            Scope::Run,
            ClientId::unknown(1234),
            NOW,
            900,
            5,
        ));

        assert!(store
            .redeem(
                item,
                Field::Password,
                &run_intent(),
                &ClientId::unknown(1234),
                NOW
            )
            .is_none());
    }

    #[test]
    fn an_expired_grant_is_not_authorised() {
        let item = Uuid::new_v4();
        let mut store = GrantStore::new();
        store.issue(grant_for(item, Scope::Run, "C:\\bin\\a.exe"));

        assert!(store
            .redeem(
                item,
                Field::Password,
                &run_intent(),
                &client("C:\\bin\\a.exe"),
                NOW + 901
            )
            .is_none());
    }

    #[test]
    fn a_grant_expires_exactly_at_its_deadline() {
        let grant = grant_for(Uuid::new_v4(), Scope::Run, "C:\\bin\\a.exe");
        assert!(!grant.is_expired(NOW + 899));
        assert!(grant.is_expired(NOW + 900));
    }

    #[test]
    fn uses_are_counted_and_run_out() {
        let item = Uuid::new_v4();
        let mut store = GrantStore::new();
        store.issue(Grant::new(
            item,
            "x",
            Field::Password,
            Scope::Run,
            client("C:\\bin\\a.exe"),
            NOW,
            900,
            2,
        ));

        let redeem = |store: &mut GrantStore| {
            store.redeem(
                item,
                Field::Password,
                &run_intent(),
                &client("C:\\bin\\a.exe"),
                NOW,
            )
        };

        assert!(redeem(&mut store).is_some());
        assert!(redeem(&mut store).is_some());
        assert!(redeem(&mut store).is_none(), "third use must be refused");
    }

    #[test]
    fn a_single_use_grant_is_spent_after_one_redemption() {
        let item = Uuid::new_v4();
        let mut store = GrantStore::new();
        store.issue(Grant::once(
            item,
            "x",
            Field::Password,
            Scope::Run,
            client("C:\\bin\\a.exe"),
            NOW,
        ));

        assert!(store
            .redeem(
                item,
                Field::Password,
                &run_intent(),
                &client("C:\\bin\\a.exe"),
                NOW
            )
            .is_some());
        assert!(store
            .redeem(
                item,
                Field::Password,
                &run_intent(),
                &client("C:\\bin\\a.exe"),
                NOW
            )
            .is_none());
    }

    #[test]
    fn a_one_shot_approval_cannot_be_redeemed_much_later() {
        let item = Uuid::new_v4();
        let grant = Grant::once(item, "x", Field::Password, Scope::Run, client("a"), NOW);
        assert!(grant.is_expired(NOW + 3600));
    }

    #[test]
    fn pruning_removes_expired_and_spent_grants() {
        let mut store = GrantStore::new();
        store.issue(grant_for(Uuid::new_v4(), Scope::Run, "C:\\bin\\a.exe"));
        assert_eq!(store.live(NOW).len(), 1);

        store.prune(NOW + 901);
        assert!(store.is_empty());
    }

    #[test]
    fn locking_clears_every_grant() {
        let mut store = GrantStore::new();
        store.issue(grant_for(Uuid::new_v4(), Scope::Run, "C:\\bin\\a.exe"));
        store.issue(grant_for(Uuid::new_v4(), Scope::Reveal, "C:\\bin\\b.exe"));

        store.clear();
        assert!(store.is_empty());
    }

    #[test]
    fn a_revoked_grant_stops_working_immediately() {
        let item = Uuid::new_v4();
        let mut store = GrantStore::new();
        let id = store.issue(grant_for(item, Scope::Run, "C:\\bin\\a.exe"));

        assert!(store.revoke(id));
        assert!(store
            .redeem(
                item,
                Field::Password,
                &run_intent(),
                &client("C:\\bin\\a.exe"),
                NOW
            )
            .is_none());
    }

    #[test]
    fn executable_matching_ignores_case_as_windows_paths_do() {
        let item = Uuid::new_v4();
        let mut store = GrantStore::new();
        store.issue(grant_for(item, Scope::Run, "C:\\Bin\\Claude.exe"));

        assert!(store
            .redeem(
                item,
                Field::Password,
                &run_intent(),
                &client("c:\\bin\\claude.exe"),
                NOW
            )
            .is_some());
    }

    #[test]
    fn the_display_name_is_the_file_name() {
        assert_eq!(client("C:\\bin\\claude.exe").display_name(), "claude.exe");
        assert_eq!(
            ClientId::unknown(99).display_name(),
            "unidentified process 99"
        );
    }
}
