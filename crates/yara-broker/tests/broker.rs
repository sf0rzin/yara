//! End-to-end behaviour of the broker, with a fake vault and a scripted user.

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use tokio::sync::oneshot;
use uuid::Uuid;
use yara_broker::audit::{Action, Entry, Outcome};
use yara_broker::grant::ClientId;
use yara_broker::protocol::{AccessRequest, Field, Intent, ItemRef, Refusal, Request, Response};
use yara_broker::transport::{
    ApprovalRequest, Approver, Broker, Decision, Resolution, VaultBridge,
};
use yara_core::SecretString;

const SECRET: &str = "s3cr3t-value-not-in-output";

struct FakeVault {
    unlocked: AtomicBool,
    item: ItemRef,
    ambiguous: bool,
    /// The item says it has a password and the vault hands back nothing —
    /// which is what an item edited between the prompt and the fetch looks
    /// like from here.
    emptied: bool,
    /// Stands in for the encrypted vault the real bridge writes to, so a test
    /// can tell "the broker recorded it" from "the broker remembered it".
    stored_audit: Mutex<Vec<Entry>>,
}

impl FakeVault {
    fn new() -> Self {
        Self {
            unlocked: AtomicBool::new(true),
            item: ItemRef {
                id: Uuid::new_v4(),
                name: "db-prod".into(),
                username: Some("app".into()),
                has_password: true,
                has_totp: false,
                fields: Vec::new(),
            },
            ambiguous: false,
            emptied: false,
            stored_audit: Mutex::new(Vec::new()),
        }
    }

    fn locked() -> Self {
        let vault = Self::new();
        vault.lock();
        vault
    }

    fn lock(&self) {
        self.unlocked.store(false, Ordering::SeqCst);
    }
}

impl VaultBridge for FakeVault {
    fn is_unlocked(&self) -> bool {
        self.unlocked.load(Ordering::SeqCst)
    }

    fn list(&self, _query: Option<&str>) -> Vec<ItemRef> {
        vec![self.item.clone()]
    }

    fn resolve(&self, needle: &str) -> Resolution {
        if self.ambiguous {
            return Resolution::Ambiguous(vec!["db-prod (a)".into(), "db-prod (b)".into()]);
        }
        if needle == self.item.name {
            Resolution::Found(self.item.clone())
        } else {
            Resolution::NotFound
        }
    }

    fn secret(&self, _id: Uuid, field: &Field) -> Option<SecretString> {
        if self.emptied {
            return None;
        }

        match field {
            Field::Password => Some(SecretString::new(SECRET)),
            Field::Username => self.item.username.clone().map(SecretString::new),
            Field::Totp => None,
            // Echoes the label, so a test can tell which field it was handed.
            Field::Custom(label) => Some(SecretString::new(format!("value-of-{label}"))),
        }
    }

    fn record_audit(&self, entry: &Entry) {
        if let Ok(mut stored) = self.stored_audit.lock() {
            stored.push(entry.clone());
        }
    }

    fn load_audit(&self) -> Vec<Entry> {
        self.stored_audit
            .lock()
            .map(|stored| stored.clone())
            .unwrap_or_default()
    }
}

/// A user who always answers the same way, and counts how often they were asked.
struct ScriptedUser {
    decision: Decision,
    asked: AtomicUsize,
    last: Mutex<Option<ApprovalRequest>>,
}

impl ScriptedUser {
    fn new(decision: Decision) -> Arc<Self> {
        Arc::new(Self {
            decision,
            asked: AtomicUsize::new(0),
            last: Mutex::new(None),
        })
    }

    fn times_asked(&self) -> usize {
        self.asked.load(Ordering::SeqCst)
    }
}

impl Approver for ScriptedUser {
    fn ask(&self, request: ApprovalRequest) -> oneshot::Receiver<Decision> {
        self.asked.fetch_add(1, Ordering::SeqCst);
        *self.last.lock().unwrap() = Some(request);

        let (tx, rx) = oneshot::channel();
        let _ = tx.send(self.decision);
        rx
    }
}

/// A user who closes the window without answering.
struct SilentUser;

impl Approver for SilentUser {
    fn ask(&self, _request: ApprovalRequest) -> oneshot::Receiver<Decision> {
        let (tx, rx) = oneshot::channel();
        drop(tx);
        rx
    }
}

/// A user who walks away and locks the vault, then answers yes.
///
/// The prompt waits up to two minutes, which is plenty of time for an
/// auto-lock to fire underneath it.
struct UserWhoLocksFirst(Arc<FakeVault>);

impl Approver for UserWhoLocksFirst {
    fn ask(&self, _request: ApprovalRequest) -> oneshot::Receiver<Decision> {
        self.0.lock();

        let (tx, rx) = oneshot::channel();
        let _ = tx.send(Decision::AllowOnce);
        rx
    }
}

fn broker_with(vault: FakeVault, user: Arc<dyn Approver>) -> Arc<Broker> {
    Broker::new(Arc::new(vault), user)
}

fn client() -> ClientId {
    ClientId {
        pid: 4242,
        executable: Some("C:\\bin\\claude.exe".into()),
    }
}

fn reveal(item: &str) -> Request {
    Request::Access(AccessRequest {
        item: item.into(),
        field: Field::Password,
        intent: Intent::Reveal,
        reason: "paste into a config file".into(),
    })
}

fn run(item: &str, command: &str, args: &[&str]) -> Request {
    Request::Access(AccessRequest {
        item: item.into(),
        field: Field::Password,
        intent: Intent::Run {
            command: command.into(),
            args: args.iter().map(|a| a.to_string()).collect(),
            env_var: "TEST_SECRET".into(),
            cwd: None,
        },
        reason: "run the migration".into(),
    })
}

/// The log has to outlive the session that produced it.
///
/// Held only in memory it vanished at every lock, which made the Agent access
/// screen read like a fresh install each morning — and an accountability
/// record that forgets overnight is not one.
#[tokio::test]
async fn the_log_survives_a_lock_because_it_lives_in_the_vault() {
    let vault = Arc::new(FakeVault::new());
    let broker = Broker::new(
        Arc::clone(&vault) as Arc<dyn VaultBridge>,
        ScriptedUser::new(Decision::AllowOnce),
    );

    broker.handle(reveal("db-prod"), &client()).await;
    assert_eq!(broker.recent_audit(10).len(), 1);
    assert_eq!(vault.load_audit().len(), 1, "it must reach the vault");

    // Locking wipes what is in memory, as it should: the key is gone and the
    // interface must not keep showing what the vault is meant to be hiding.
    broker.forget_grants();
    assert!(broker.recent_audit(10).is_empty());

    // Unlocking reads it back.
    broker.restore_audit();
    assert_eq!(broker.recent_audit(10).len(), 1);
}

#[tokio::test]
async fn refusals_reach_the_vault_too() {
    let vault = Arc::new(FakeVault::new());
    let broker = Broker::new(
        Arc::clone(&vault) as Arc<dyn VaultBridge>,
        ScriptedUser::new(Decision::Deny),
    );

    broker.handle(reveal("db-prod"), &client()).await;

    let stored = vault.load_audit();
    assert_eq!(stored.len(), 1);
    assert!(
        !stored[0].outcome.was_allowed(),
        "\"something asked for the production password and I said no\" is \
         exactly the event worth keeping"
    );
}

#[tokio::test]
async fn an_approved_reveal_returns_the_value() {
    let user = ScriptedUser::new(Decision::AllowOnce);
    let broker = broker_with(FakeVault::new(), user.clone());

    match broker.handle(reveal("db-prod"), &client()).await {
        Response::Revealed { value } => assert_eq!(value, SECRET),
        other => panic!("unexpected {other:?}"),
    }
    assert_eq!(user.times_asked(), 1);
}

#[tokio::test]
async fn a_declined_request_returns_nothing() {
    let user = ScriptedUser::new(Decision::Deny);
    let broker = broker_with(FakeVault::new(), user.clone());

    match broker.handle(reveal("db-prod"), &client()).await {
        Response::Refused { reason, .. } => assert_eq!(reason, Refusal::Denied),
        other => panic!("unexpected {other:?}"),
    }
}

#[tokio::test]
async fn closing_the_prompt_without_answering_is_not_consent() {
    let broker = broker_with(FakeVault::new(), Arc::new(SilentUser));

    match broker.handle(reveal("db-prod"), &client()).await {
        Response::Refused { reason, .. } => assert_eq!(reason, Refusal::Denied),
        other => panic!("unexpected {other:?}"),
    }
}

#[tokio::test]
async fn a_locked_vault_refuses_before_asking_anyone() {
    let user = ScriptedUser::new(Decision::AllowOnce);
    let broker = broker_with(FakeVault::locked(), user.clone());

    match broker.handle(reveal("db-prod"), &client()).await {
        Response::Refused { reason, .. } => assert_eq!(reason, Refusal::VaultLocked),
        other => panic!("unexpected {other:?}"),
    }
    assert_eq!(user.times_asked(), 0, "the user must not be prompted");
}

#[tokio::test]
async fn an_unknown_item_never_reaches_the_user() {
    let user = ScriptedUser::new(Decision::AllowOnce);
    let broker = broker_with(FakeVault::new(), user.clone());

    match broker.handle(reveal("does-not-exist"), &client()).await {
        Response::Refused { reason, .. } => assert_eq!(reason, Refusal::ItemNotFound),
        other => panic!("unexpected {other:?}"),
    }
    assert_eq!(user.times_asked(), 0);
}

#[tokio::test]
async fn an_ambiguous_name_asks_the_agent_to_be_specific() {
    let user = ScriptedUser::new(Decision::AllowOnce);
    let vault = FakeVault {
        ambiguous: true,
        ..FakeVault::new()
    };
    let broker = broker_with(vault, user.clone());

    match broker.handle(reveal("db-prod"), &client()).await {
        Response::Refused {
            reason: Refusal::Ambiguous { matches },
            ..
        } => assert_eq!(matches.len(), 2),
        other => panic!("unexpected {other:?}"),
    }
    assert_eq!(user.times_asked(), 0);
}

#[tokio::test]
async fn asking_for_an_empty_field_does_not_prompt() {
    let user = ScriptedUser::new(Decision::AllowOnce);
    let broker = broker_with(FakeVault::new(), user.clone());

    let request = Request::Access(AccessRequest {
        item: "db-prod".into(),
        field: Field::Totp,
        intent: Intent::Reveal,
        reason: "x".into(),
    });

    match broker.handle(request, &client()).await {
        Response::Refused { reason, .. } => assert_eq!(reason, Refusal::FieldEmpty),
        other => panic!("unexpected {other:?}"),
    }
    assert_eq!(user.times_asked(), 0);
}

#[tokio::test]
async fn listing_items_works_without_approval_and_exposes_no_secrets() {
    let user = ScriptedUser::new(Decision::Deny);
    let broker = broker_with(FakeVault::new(), user.clone());

    match broker
        .handle(Request::List { query: None }, &client())
        .await
    {
        Response::Items { items } => {
            assert_eq!(items.len(), 1);
            let encoded = serde_json::to_string(&items).unwrap();
            assert!(!encoded.contains(SECRET));
        }
        other => panic!("unexpected {other:?}"),
    }
    assert_eq!(user.times_asked(), 0, "names are not secrets");
}

#[tokio::test]
async fn listing_is_refused_while_the_vault_is_locked() {
    let broker = broker_with(FakeVault::locked(), ScriptedUser::new(Decision::Deny));

    match broker
        .handle(Request::List { query: None }, &client())
        .await
    {
        Response::Refused { reason, .. } => assert_eq!(reason, Refusal::VaultLocked),
        other => panic!("unexpected {other:?}"),
    }
}

#[tokio::test]
async fn a_standing_grant_stops_the_prompts() {
    let user = ScriptedUser::new(Decision::AllowFor {
        seconds: 900,
        uses: 5,
    });
    let broker = broker_with(FakeVault::new(), user.clone());

    // Uses run rather than reveal: reveal deliberately never earns a standing
    // grant, so a reveal here would pass for the wrong reason.
    for _ in 0..3 {
        broker
            .handle(run("db-prod", "hostname", &[]), &client())
            .await;
    }

    assert_eq!(user.times_asked(), 1, "only the first should prompt");
}

#[tokio::test]
async fn a_reveal_never_earns_a_standing_grant() {
    // The user asked for a fifteen minute window; reveal does not get one.
    let user = ScriptedUser::new(Decision::AllowFor {
        seconds: 900,
        uses: 10,
    });
    let broker = broker_with(FakeVault::new(), user.clone());

    broker.handle(reveal("db-prod"), &client()).await;
    broker.handle(reveal("db-prod"), &client()).await;

    assert_eq!(
        user.times_asked(),
        2,
        "each disclosure must be its own decision"
    );
}

#[tokio::test]
async fn a_one_time_approval_prompts_again_next_time() {
    let user = ScriptedUser::new(Decision::AllowOnce);
    let broker = broker_with(FakeVault::new(), user.clone());

    broker.handle(reveal("db-prod"), &client()).await;
    broker.handle(reveal("db-prod"), &client()).await;

    assert_eq!(user.times_asked(), 2);
}

#[tokio::test]
async fn a_grant_to_run_does_not_silently_authorise_a_reveal() {
    let user = ScriptedUser::new(Decision::AllowFor {
        seconds: 900,
        uses: 10,
    });
    let broker = broker_with(FakeVault::new(), user.clone());

    broker
        .handle(run("db-prod", "hostname", &[]), &client())
        .await;
    assert_eq!(user.times_asked(), 1);

    // Being allowed to use the password is not being allowed to see it.
    broker.handle(reveal("db-prod"), &client()).await;
    assert_eq!(user.times_asked(), 2, "reveal must ask separately");
}

#[tokio::test]
async fn another_program_cannot_ride_on_an_existing_grant() {
    let user = ScriptedUser::new(Decision::AllowFor {
        seconds: 900,
        uses: 10,
    });
    let broker = broker_with(FakeVault::new(), user.clone());

    let request = run("db-prod", "hostname", &[]);
    broker.handle(request.clone(), &client()).await;
    assert_eq!(user.times_asked(), 1);

    let other = ClientId {
        pid: 999,
        executable: Some("C:\\tmp\\something-else.exe".into()),
    };
    broker.handle(request, &other).await;
    assert_eq!(user.times_asked(), 2);
}

#[tokio::test]
async fn locking_the_vault_invalidates_outstanding_grants() {
    let user = ScriptedUser::new(Decision::AllowFor {
        seconds: 900,
        uses: 10,
    });
    let broker = broker_with(FakeVault::new(), user.clone());

    let request = run("db-prod", "hostname", &[]);
    broker.handle(request.clone(), &client()).await;
    assert_eq!(user.times_asked(), 1);

    broker.forget_grants();

    broker.handle(request, &client()).await;
    assert_eq!(user.times_asked(), 2);
}

/// Proves two things at once, and it has to.
///
/// The only way to show the child received the value is to have it print the
/// value, and printing it is precisely what the redaction removes. So the
/// marker appearing in the output *is* the evidence that the child held the
/// real thing — and its absence from the response is the property that matters.
#[cfg(windows)]
#[tokio::test]
async fn the_child_gets_the_secret_and_the_client_does_not() {
    let broker = broker_with(FakeVault::new(), ScriptedUser::new(Decision::AllowOnce));

    let request = run("db-prod", "cmd", &["/C", "echo %TEST_SECRET%"]);
    match broker.handle(request, &client()).await {
        Response::Ran(output) => {
            assert_eq!(output.exit_code, 0);
            assert!(
                output.stdout.contains("[redacted by yara]"),
                "the child should have echoed the value and had it removed: {output:?}"
            );
            assert!(!output.stdout.contains(SECRET));
            assert!(!serde_json::to_string(&output).unwrap().contains(SECRET));
        }
        other => panic!("unexpected {other:?}"),
    }
}

/// A shell is a reveal in a run's clothes, so it is priced like one: the user
/// is asked every time, no matter how generously they answered before.
#[tokio::test]
async fn a_shell_command_never_earns_a_standing_grant() {
    let user = ScriptedUser::new(Decision::AllowFor {
        seconds: 900,
        uses: 5,
    });
    let broker = broker_with(FakeVault::new(), user.clone());

    for _ in 0..3 {
        broker
            .handle(run("db-prod", "cmd", &["/C", "exit"]), &client())
            .await;
    }

    assert_eq!(user.times_asked(), 3, "every shell request must be asked");
    assert!(broker.live_grants(yara_broker::now()).is_empty());
}

/// The escalation the command scoping exists to stop, end to end through the
/// broker rather than only at the grant store.
#[tokio::test]
async fn a_grant_does_not_carry_over_to_a_different_command() {
    let user = ScriptedUser::new(Decision::AllowFor {
        seconds: 900,
        uses: 5,
    });
    let broker = broker_with(FakeVault::new(), user.clone());

    broker
        .handle(run("db-prod", "hostname", &[]), &client())
        .await;
    assert_eq!(user.times_asked(), 1);

    // Same item, same field, same program, live grant — different command.
    broker
        .handle(run("db-prod", "whoami", &[]), &client())
        .await;
    assert_eq!(
        user.times_asked(),
        2,
        "a grant for one command must not authorise another"
    );
}

#[cfg(windows)]
#[tokio::test]
async fn a_run_that_does_not_print_the_secret_returns_nothing_secret() {
    let broker = broker_with(FakeVault::new(), ScriptedUser::new(Decision::AllowOnce));

    let request = run("db-prod", "cmd", &["/C", "echo migration complete"]);
    match broker.handle(request, &client()).await {
        Response::Ran(output) => {
            assert!(output.stdout.contains("migration complete"));
            // This is the point of the whole feature.
            assert!(!output.stdout.contains(SECRET));
            assert!(!output.stderr.contains(SECRET));
            assert!(!serde_json::to_string(&output).unwrap().contains(SECRET));
        }
        other => panic!("unexpected {other:?}"),
    }
}

#[cfg(windows)]
#[tokio::test]
async fn a_failing_command_reports_its_exit_code_rather_than_erroring() {
    let broker = broker_with(FakeVault::new(), ScriptedUser::new(Decision::AllowOnce));

    match broker
        .handle(run("db-prod", "cmd", &["/C", "exit 3"]), &client())
        .await
    {
        Response::Ran(output) => assert_eq!(output.exit_code, 3),
        other => panic!("unexpected {other:?}"),
    }
}

#[tokio::test]
async fn a_command_that_does_not_exist_is_reported_without_leaking() {
    let broker = broker_with(FakeVault::new(), ScriptedUser::new(Decision::AllowOnce));

    match broker
        .handle(
            run("db-prod", "definitely-not-a-real-binary", &[]),
            &client(),
        )
        .await
    {
        Response::Error { message } => assert!(!message.contains(SECRET)),
        other => panic!("unexpected {other:?}"),
    }
}

/// The record has to describe what happened, not what was about to be tried.
///
/// It used to be written before the spawn, so a command that could not start
/// was logged as having run — the Agent access screen told the user their
/// production password had gone to a process that never existed.
#[tokio::test]
async fn a_command_that_could_not_start_is_not_logged_as_having_run() {
    let vault = Arc::new(FakeVault::new());
    let broker = Broker::new(
        Arc::clone(&vault) as Arc<dyn VaultBridge>,
        ScriptedUser::new(Decision::AllowOnce),
    );

    broker
        .handle(
            run("db-prod", "definitely-not-a-real-binary", &[]),
            &client(),
        )
        .await;

    let stored = vault.load_audit();
    assert_eq!(stored.len(), 1);
    match &stored[0].outcome {
        Outcome::Failed { error } => assert!(!error.contains(SECRET)),
        other => panic!("the spawn failed, so this must not read as an access: {other:?}"),
    }
    assert!(!stored[0].outcome.was_allowed());
    // The command line is still worth keeping: what was attempted matters.
    assert!(matches!(stored[0].action, Action::Ran { .. }));
}

/// The same argument for a field that turns out to hold nothing.
#[tokio::test]
async fn an_emptied_field_is_logged_as_refused_rather_than_revealed() {
    let vault = Arc::new(FakeVault {
        emptied: true,
        ..FakeVault::new()
    });
    let broker = Broker::new(
        Arc::clone(&vault) as Arc<dyn VaultBridge>,
        ScriptedUser::new(Decision::AllowOnce),
    );

    match broker.handle(reveal("db-prod"), &client()).await {
        Response::Refused { reason, .. } => assert_eq!(reason, Refusal::FieldEmpty),
        other => panic!("unexpected {other:?}"),
    }

    let stored = vault.load_audit();
    assert_eq!(stored.len(), 1);
    assert_eq!(
        stored[0].outcome,
        Outcome::Refused {
            reason: Refusal::FieldEmpty
        },
        "nothing was disclosed, so nothing may be recorded as disclosed"
    );
}

/// An approval answered as the vault locks authorises access to a key that is
/// no longer there.
#[tokio::test]
async fn locking_during_the_prompt_refuses_and_says_so_in_the_log() {
    let vault = Arc::new(FakeVault::new());
    let broker = Broker::new(
        Arc::clone(&vault) as Arc<dyn VaultBridge>,
        Arc::new(UserWhoLocksFirst(Arc::clone(&vault))),
    );

    match broker.handle(reveal("db-prod"), &client()).await {
        Response::Refused { reason, .. } => assert_eq!(reason, Refusal::VaultLocked),
        other => panic!("unexpected {other:?}"),
    }

    let stored = vault.load_audit();
    assert_eq!(stored.len(), 1);
    assert!(!stored[0].outcome.was_allowed());

    assert_eq!(
        broker.grant_count(),
        0,
        "a grant minted as the vault locked would outlive the key and be \
         redeemable without a prompt at the next unlock"
    );
}

/// A chain of reuses has to lead back to the prompt that started it.
#[tokio::test]
async fn a_reused_grant_names_the_approval_that_minted_it() {
    let broker = broker_with(
        FakeVault::new(),
        ScriptedUser::new(Decision::AllowFor {
            seconds: 900,
            uses: 5,
        }),
    );

    for _ in 0..3 {
        broker
            .handle(run("db-prod", "hostname", &[]), &client())
            .await;
    }

    // recent() is newest first, so the approval is last.
    let entries = broker.recent_audit(10);
    assert_eq!(entries.len(), 3);

    let approved = entries.last().unwrap().outcome.grant();
    assert!(
        approved.is_some(),
        "the approval must record the grant it issued, or the uuid the reuses \
         name appears in no other record"
    );

    for reused in &entries[..2] {
        match reused.outcome {
            Outcome::Reused { grant } => assert_eq!(Some(grant), approved),
            ref other => panic!("unexpected {other:?}"),
        }
    }
}

/// Grants used to accumulate for the life of the unlock: nothing ever called
/// prune, and a one-shot approval is spent the instant it is issued.
#[tokio::test]
async fn one_shot_approvals_do_not_pile_up_in_the_store() {
    let broker = broker_with(FakeVault::new(), ScriptedUser::new(Decision::AllowOnce));

    for _ in 0..5 {
        broker.handle(reveal("db-prod"), &client()).await;
    }

    assert_eq!(
        broker.grant_count(),
        0,
        "each grant was spent on the request that created it"
    );

    // A grant that is still worth something stays, of course.
    let broker = broker_with(
        FakeVault::new(),
        ScriptedUser::new(Decision::AllowFor {
            seconds: 900,
            uses: 5,
        }),
    );
    broker
        .handle(run("db-prod", "hostname", &[]), &client())
        .await;
    assert_eq!(broker.grant_count(), 1);
}

/// A listing is a search, not an access.
#[tokio::test]
async fn a_listing_records_the_query_without_inventing_an_item() {
    let vault = Arc::new(FakeVault::new());
    let broker = Broker::new(
        Arc::clone(&vault) as Arc<dyn VaultBridge>,
        ScriptedUser::new(Decision::Deny),
    );

    broker
        .handle(
            Request::List {
                query: Some("git".into()),
            },
            &client(),
        )
        .await;

    let stored = vault.load_audit();
    assert_eq!(stored.len(), 1);
    assert!(
        stored[0].item.is_empty(),
        "a row saying an item called git was accessed describes an item that \
         does not exist"
    );
    assert!(
        stored[0].reason.is_empty(),
        "the reason is the client's words, and the client supplied none"
    );
    assert!(stored[0].field.is_none());
    assert_eq!(stored[0].query.as_deref(), Some("git"));
    assert_eq!(stored[0].action, Action::Listed { matches: 1 });
}

#[tokio::test]
async fn every_decision_lands_in_the_audit_log() {
    let broker = broker_with(FakeVault::new(), ScriptedUser::new(Decision::Deny));

    broker.handle(reveal("db-prod"), &client()).await;
    broker.handle(reveal("db-prod"), &client()).await;

    let entries = broker.recent_audit(10);
    assert_eq!(entries.len(), 2);
    assert!(entries.iter().all(|entry| !entry.outcome.was_allowed()));
    assert!(!serde_json::to_string(&entries).unwrap().contains(SECRET));
}

#[tokio::test]
async fn granted_access_shows_up_as_a_live_grant() {
    let broker = broker_with(
        FakeVault::new(),
        ScriptedUser::new(Decision::AllowFor {
            seconds: 900,
            uses: 5,
        }),
    );

    broker
        .handle(run("db-prod", "hostname", &[]), &client())
        .await;

    let grants = broker.live_grants(yara_broker::now());
    assert_eq!(grants.len(), 1);
    assert_eq!(grants[0].item_name, "db-prod");
    // One of the five was spent by the request that created it.
    assert_eq!(grants[0].remaining_uses(), 4);
}

#[tokio::test]
async fn revoking_a_grant_makes_the_next_request_prompt_again() {
    let user = ScriptedUser::new(Decision::AllowFor {
        seconds: 900,
        uses: 10,
    });
    let broker = broker_with(FakeVault::new(), user.clone());

    let request = run("db-prod", "hostname", &[]);
    broker.handle(request.clone(), &client()).await;
    let grant = broker.live_grants(yara_broker::now())[0].id;
    assert!(broker.revoke(grant));

    broker.handle(request, &client()).await;
    assert_eq!(user.times_asked(), 2);
}

#[tokio::test]
async fn the_approval_prompt_names_the_program_and_the_reason() {
    let user = ScriptedUser::new(Decision::Deny);
    let broker = broker_with(FakeVault::new(), user.clone());

    broker.handle(reveal("db-prod"), &client()).await;

    let asked = user.last.lock().unwrap().clone().unwrap();
    assert_eq!(asked.client.display_name(), "claude.exe");
    assert_eq!(asked.reason, "paste into a config file");
    assert_eq!(asked.item.name, "db-prod");
}

/// The transport itself, over a real pipe.
#[cfg(windows)]
#[tokio::test]
async fn a_client_can_talk_to_the_broker_over_a_named_pipe() {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::net::windows::named_pipe::{ClientOptions, ServerOptions};

    let pipe = format!(r"\\.\pipe\yara-test-{}", Uuid::new_v4());
    let broker = broker_with(FakeVault::new(), ScriptedUser::new(Decision::AllowOnce));

    let server = ServerOptions::new()
        .first_pipe_instance(true)
        .create(&pipe)
        .unwrap();

    let serving = tokio::spawn({
        let broker = Arc::clone(&broker);
        async move {
            server.connect().await.unwrap();
            yara_broker::transport::serve_connection(broker, server, client())
                .await
                .unwrap();
        }
    });

    let stream = ClientOptions::new().open(&pipe).unwrap();
    let (reader, mut writer) = tokio::io::split(stream);
    let mut lines = BufReader::new(reader).lines();

    // Status, then a real access request, over the same connection.
    for request in [Request::Status, reveal("db-prod")] {
        let encoded = yara_broker::protocol::encode(&request).unwrap();
        writer.write_all(encoded.as_bytes()).await.unwrap();
        writer.flush().await.unwrap();

        let line = lines.next_line().await.unwrap().unwrap();
        let response: Response = yara_broker::protocol::decode(&line).unwrap();

        match (&request, response) {
            (Request::Status, Response::Status { unlocked, .. }) => assert!(unlocked),
            (Request::Access(_), Response::Revealed { value }) => assert_eq!(value, SECRET),
            (_, other) => panic!("unexpected {other:?}"),
        }
    }

    drop(writer);
    drop(lines);
    let _ = tokio::time::timeout(std::time::Duration::from_secs(5), serving).await;
}

/// The accept loop has to outlive its clients.
///
/// It used to end on the first transport error, and once it ended nobody
/// owned the pipe: any process could create the name and answer the CLI and
/// the MCP server in yara's place, fabricating an unlocked status and
/// harvesting the item names and stated reasons agents send. Meanwhile the
/// real CLI reported "could not reach the vault" with yara running and
/// unlocked in front of the user.
#[cfg(windows)]
#[tokio::test]
async fn the_accept_loop_survives_clients_that_hang_up_mid_conversation() {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::net::windows::named_pipe::{ClientOptions, NamedPipeClient};

    /// Opens the pipe once the listener has it. A client can arrive before the
    /// first instance exists, or in the moment between one being handed off
    /// and its replacement being created.
    async fn open_when_ready(pipe: &str) -> NamedPipeClient {
        for _ in 0..200 {
            if let Ok(stream) = ClientOptions::new().open(pipe) {
                return stream;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        panic!("the broker never opened {pipe}");
    }

    let pipe = format!(r"\\.\pipe\yara-test-{}", Uuid::new_v4());
    let broker = broker_with(FakeVault::new(), ScriptedUser::new(Decision::AllowOnce));

    let serving = tokio::spawn({
        let broker = Arc::clone(&broker);
        let pipe = pipe.clone();
        async move { yara_broker::transport::serve(broker, &pipe).await }
    });

    // Connect and vanish, several times over, including mid-request.
    for _ in 0..3 {
        drop(open_when_ready(&pipe).await);

        let mut stream = open_when_ready(&pipe).await;
        stream.write_all(b"{\"request\":\"sta").await.unwrap();
        drop(stream);
    }

    // A well-behaved client afterwards must still be answered.
    let stream = open_when_ready(&pipe).await;
    let (reader, mut writer) = tokio::io::split(stream);
    let mut lines = BufReader::new(reader).lines();

    let encoded = yara_broker::protocol::encode(&Request::Status).unwrap();
    writer.write_all(encoded.as_bytes()).await.unwrap();
    writer.flush().await.unwrap();

    let line = tokio::time::timeout(std::time::Duration::from_secs(5), lines.next_line())
        .await
        .expect("the broker stopped listening")
        .unwrap()
        .unwrap();

    assert!(matches!(
        yara_broker::protocol::decode::<Response>(&line).unwrap(),
        Response::Status { unlocked: true, .. }
    ));

    assert!(!serving.is_finished(), "it must still be listening");
    serving.abort();
}

/// The one genuinely fatal case, and the reason it is a value rather than a
/// line on a stdout nobody is reading: a windowed app has to be able to say
/// this to the person in front of it.
#[cfg(windows)]
#[tokio::test]
async fn a_second_listener_reports_that_one_is_already_running() {
    use tokio::net::windows::named_pipe::ServerOptions;
    use yara_broker::transport::ServeError;

    let pipe = format!(r"\\.\pipe\yara-test-{}", Uuid::new_v4());
    let _held = ServerOptions::new()
        .first_pipe_instance(true)
        .create(&pipe)
        .unwrap();

    let broker = broker_with(FakeVault::new(), ScriptedUser::new(Decision::Deny));

    match yara_broker::transport::serve(broker, &pipe).await {
        Err(error @ ServeError::AlreadyRunning) => {
            assert!(!error.to_string().contains("os error"), "{error}");
        }
        other => panic!("unexpected {other:?}"),
    }
}

#[cfg(windows)]
#[tokio::test]
async fn malformed_input_gets_an_error_rather_than_killing_the_connection() {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::net::windows::named_pipe::{ClientOptions, ServerOptions};

    let pipe = format!(r"\\.\pipe\yara-test-{}", Uuid::new_v4());
    let broker = broker_with(FakeVault::new(), ScriptedUser::new(Decision::AllowOnce));

    let server = ServerOptions::new()
        .first_pipe_instance(true)
        .create(&pipe)
        .unwrap();

    tokio::spawn({
        let broker = Arc::clone(&broker);
        async move {
            server.connect().await.unwrap();
            let _ = yara_broker::transport::serve_connection(broker, server, client()).await;
        }
    });

    let stream = ClientOptions::new().open(&pipe).unwrap();
    let (reader, mut writer) = tokio::io::split(stream);
    let mut lines = BufReader::new(reader).lines();

    writer.write_all(b"absolute nonsense\n").await.unwrap();
    writer.flush().await.unwrap();

    let line = lines.next_line().await.unwrap().unwrap();
    assert!(matches!(
        yara_broker::protocol::decode::<Response>(&line).unwrap(),
        Response::Error { .. }
    ));

    // The connection must still be usable afterwards.
    let encoded = yara_broker::protocol::encode(&Request::Status).unwrap();
    writer.write_all(encoded.as_bytes()).await.unwrap();
    writer.flush().await.unwrap();

    let line = lines.next_line().await.unwrap().unwrap();
    assert!(matches!(
        yara_broker::protocol::decode::<Response>(&line).unwrap(),
        Response::Status { .. }
    ));
}
