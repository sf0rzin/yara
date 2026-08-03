//! End-to-end behaviour of the broker, with a fake vault and a scripted user.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use tokio::sync::oneshot;
use uuid::Uuid;
use yara_broker::grant::ClientId;
use yara_broker::protocol::{AccessRequest, Field, Intent, ItemRef, Refusal, Request, Response};
use yara_broker::transport::{
    ApprovalRequest, Approver, Broker, Decision, Resolution, VaultBridge,
};
use yara_core::SecretString;

const SECRET: &str = "s3cr3t-value-not-in-output";

struct FakeVault {
    unlocked: bool,
    item: ItemRef,
    ambiguous: bool,
}

impl FakeVault {
    fn new() -> Self {
        Self {
            unlocked: true,
            item: ItemRef {
                id: Uuid::new_v4(),
                name: "db-prod".into(),
                username: Some("app".into()),
                has_password: true,
                has_totp: false,
            },
            ambiguous: false,
        }
    }
}

impl VaultBridge for FakeVault {
    fn is_unlocked(&self) -> bool {
        self.unlocked
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

    fn secret(&self, _id: Uuid, field: Field) -> Option<SecretString> {
        match field {
            Field::Password => Some(SecretString::new(SECRET)),
            Field::Username => self.item.username.clone().map(SecretString::new),
            Field::Totp => None,
        }
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
    let vault = FakeVault {
        unlocked: false,
        ..FakeVault::new()
    };
    let broker = broker_with(vault, user.clone());

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
    let vault = FakeVault {
        unlocked: false,
        ..FakeVault::new()
    };
    let broker = broker_with(vault, ScriptedUser::new(Decision::Deny));

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
