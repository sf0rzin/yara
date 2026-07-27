//! Translating MCP calls into broker requests.
//!
//! This module is the whole server minus the pipes: it takes a decoded JSON-RPC
//! message and returns the reply, which makes every path testable without a
//! running vault or a real stdio stream.

use lapse_broker::protocol::{AccessRequest, Field, Intent, Request, Response};
use serde_json::{json, Value};

use crate::rpc::{codes, Incoming, Outgoing};

/// MCP revisions this server understands, newest first.
const SUPPORTED_VERSIONS: [&str; 3] = ["2025-06-18", "2025-03-26", "2024-11-05"];

/// How the server reaches the vault. A trait so the dispatch logic can be
/// tested against a scripted broker instead of a live one.
#[allow(async_fn_in_trait)]
pub trait BrokerLink {
    async fn send(&self, request: Request) -> Result<Response, String>;
}

/// The real link, over the named pipe.
pub struct PipeLink;

impl BrokerLink for PipeLink {
    async fn send(&self, request: Request) -> Result<Response, String> {
        lapse_broker::client::send(&request).await
    }
}

/// Handles one message. Returns `None` for notifications, which get no reply.
pub async fn dispatch<L: BrokerLink>(link: &L, incoming: Incoming) -> Option<Outgoing> {
    if incoming.is_notification() {
        // `notifications/initialized` and friends are acknowledged by silence.
        return None;
    }

    let id = incoming.id.clone().unwrap_or(Value::Null);
    let params = incoming.params.clone().unwrap_or(Value::Null);

    Some(match incoming.method.as_str() {
        "initialize" => Outgoing::result(id, initialize(&params)),
        "ping" => Outgoing::result(id, json!({})),
        "tools/list" => Outgoing::result(id, json!({ "tools": tools() })),
        "tools/call" => match call_tool(link, &params).await {
            Ok(result) => Outgoing::result(id, result),
            Err(message) => Outgoing::error(id, codes::INVALID_PARAMS, message),
        },
        other => Outgoing::error(
            id,
            codes::METHOD_NOT_FOUND,
            format!("unknown method {other:?}"),
        ),
    })
}

/// The handshake.
///
/// Echoes the client's protocol revision when it is one we speak, and otherwise
/// answers with our newest — which is what lets the client decide whether to
/// continue rather than having the connection fail outright.
fn initialize(params: &Value) -> Value {
    let requested = params
        .get("protocolVersion")
        .and_then(Value::as_str)
        .unwrap_or("");

    let version = if SUPPORTED_VERSIONS.contains(&requested) {
        requested
    } else {
        SUPPORTED_VERSIONS[0]
    };

    json!({
        "protocolVersion": version,
        "capabilities": { "tools": {} },
        "serverInfo": {
            "name": "lapse",
            "version": env!("CARGO_PKG_VERSION"),
        },
        "instructions": "Credentials from the user's lapse vault. Prefer \
lapse_run_with_credential, which uses a secret without ever disclosing it to \
you. Every request is approved by the vault owner in the lapse window and \
written to an audit log.",
    })
}

/// The tool catalogue.
///
/// The descriptions do real work here: they are what an agent reads when
/// choosing between using a credential and asking to see one. `run` is
/// described as the default and `reveal` as the exception, because the wording
/// is the only thing steering that choice before the user is ever asked.
fn tools() -> Value {
    json!([
        {
            "name": "lapse_list_items",
            "description": "List the credentials stored in the user's lapse vault. \
Returns names, usernames, and ids only — never secret values. This needs no \
approval, so use it first to find out what exists before requesting access to \
anything.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string",
                        "description": "Filter by name, username, or address.",
                    },
                },
            },
        },
        {
            "name": "lapse_run_with_credential",
            "description": "Run a command with a credential from the vault placed in \
its environment. This is the preferred way to use a credential: lapse runs the \
command itself and returns only the exit code and output, so the secret never \
enters this conversation and cannot leak through it. The vault owner is shown \
the exact command and your stated reason, and must approve.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "item": {
                        "type": "string",
                        "description": "Item name or id, as returned by lapse_list_items.",
                    },
                    "field": {
                        "type": "string",
                        "enum": ["password", "username", "totp"],
                        "description": "Which field to use. Defaults to password.",
                    },
                    "env_var": {
                        "type": "string",
                        "description": "Environment variable to place the credential in, \
for example DATABASE_URL.",
                    },
                    "command": {
                        "type": "string",
                        "description": "Program to run.",
                    },
                    "args": {
                        "type": "array",
                        "items": { "type": "string" },
                        "description": "Arguments to the program.",
                    },
                    "cwd": {
                        "type": "string",
                        "description": "Working directory for the command.",
                    },
                    "reason": {
                        "type": "string",
                        "description": "Why you need this, in one sentence. Shown to the \
vault owner verbatim — write it for them, not for a log.",
                    },
                },
                "required": ["item", "env_var", "command", "reason"],
            },
        },
        {
            "name": "lapse_reveal_credential",
            "description": "Return a credential in plaintext. Last resort — prefer \
lapse_run_with_credential, which accomplishes most tasks without disclosing the \
value. Anything returned here enters this conversation permanently and cannot be \
taken back. The vault owner must approve every single disclosure; a standing \
approval is never granted for this.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "item": {
                        "type": "string",
                        "description": "Item name or id, as returned by lapse_list_items.",
                    },
                    "field": {
                        "type": "string",
                        "enum": ["password", "username", "totp"],
                        "description": "Which field to reveal. Defaults to password.",
                    },
                    "reason": {
                        "type": "string",
                        "description": "Why nothing short of the plaintext will do. Shown \
to the vault owner verbatim.",
                    },
                },
                "required": ["item", "reason"],
            },
        },
        {
            "name": "lapse_status",
            "description": "Check whether lapse is running and the vault is unlocked. \
Use this when another lapse tool cannot reach the vault.",
            "inputSchema": { "type": "object", "properties": {} },
        },
    ])
}

async fn call_tool<L: BrokerLink>(link: &L, params: &Value) -> Result<Value, String> {
    let name = params
        .get("name")
        .and_then(Value::as_str)
        .ok_or("tools/call requires a tool name")?;

    let args = params.get("arguments").cloned().unwrap_or(json!({}));

    let request = match name {
        "lapse_status" => Request::Status,

        "lapse_list_items" => Request::List {
            query: args
                .get("query")
                .and_then(Value::as_str)
                .map(str::to_string),
        },

        "lapse_run_with_credential" => Request::Access(AccessRequest {
            item: required_str(&args, "item")?,
            field: field_from(&args)?,
            intent: Intent::Run {
                command: required_str(&args, "command")?,
                args: args
                    .get("args")
                    .and_then(Value::as_array)
                    .map(|list| {
                        list.iter()
                            .filter_map(Value::as_str)
                            .map(str::to_string)
                            .collect()
                    })
                    .unwrap_or_default(),
                env_var: required_str(&args, "env_var")?,
                cwd: args.get("cwd").and_then(Value::as_str).map(str::to_string),
            },
            reason: required_str(&args, "reason")?,
        }),

        "lapse_reveal_credential" => Request::Access(AccessRequest {
            item: required_str(&args, "item")?,
            field: field_from(&args)?,
            intent: Intent::Reveal,
            reason: required_str(&args, "reason")?,
        }),

        other => return Err(format!("unknown tool {other:?}")),
    };

    // A broker that is unreachable, or a request the user declined, is a tool
    // failure the agent should see and react to — not a JSON-RPC error, which
    // some clients surface as a transport fault and hide from the model.
    Ok(match link.send(request).await {
        Ok(response) => render(response),
        Err(message) => failure(message),
    })
}

fn required_str(args: &Value, key: &str) -> Result<String, String> {
    args.get(key)
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .map(str::to_string)
        .ok_or_else(|| format!("{key} is required"))
}

fn field_from(args: &Value) -> Result<Field, String> {
    match args.get("field").and_then(Value::as_str).unwrap_or("password") {
        "password" => Ok(Field::Password),
        "username" => Ok(Field::Username),
        "totp" => Ok(Field::Totp),
        other => Err(format!(
            "unknown field {other:?}; expected password, username or totp"
        )),
    }
}

fn text(body: impl Into<String>, is_error: bool) -> Value {
    json!({
        "content": [{ "type": "text", "text": body.into() }],
        "isError": is_error,
    })
}

fn failure(body: impl Into<String>) -> Value {
    text(body, true)
}

/// Turns a broker answer into MCP tool output.
fn render(response: Response) -> Value {
    match response {
        Response::Status { unlocked, version } => text(
            format!(
                "lapse {version} is running and the vault is {}.",
                if unlocked { "unlocked" } else { "locked" }
            ),
            false,
        ),

        Response::Items { items } => {
            if items.is_empty() {
                return text("No matching items.", false);
            }
            let listing = items
                .iter()
                .map(|item| {
                    let username = item.username.as_deref().unwrap_or("—");
                    format!(
                        "{}\t{}\t{}\t{}",
                        item.id,
                        item.name,
                        username,
                        if item.has_totp { "has 2FA" } else { "" }
                    )
                })
                .collect::<Vec<_>>()
                .join("\n");
            text(format!("id\tname\tusername\n{listing}"), false)
        }

        Response::Ran(output) => {
            let mut body = format!("Exit code {}.", output.exit_code);
            if !output.stdout.is_empty() {
                body.push_str(&format!("\n\nstdout:\n{}", output.stdout));
            }
            if !output.stderr.is_empty() {
                body.push_str(&format!("\n\nstderr:\n{}", output.stderr));
            }
            // A non-zero exit is a real result, not a tool failure — the agent
            // needs the output to work out what went wrong.
            text(body, false)
        }

        Response::Revealed { value } => text(value, false),

        Response::Refused { message, .. } => failure(message),

        Response::Error { message } => failure(message),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lapse_broker::protocol::{CommandOutput, ItemRef, Refusal};
    use std::sync::Mutex;
    use uuid::Uuid;

    /// A broker that records what it was asked and replies from a script.
    struct FakeBroker {
        reply: Response,
        seen: Mutex<Option<Request>>,
    }

    impl FakeBroker {
        fn new(reply: Response) -> Self {
            Self {
                reply,
                seen: Mutex::new(None),
            }
        }

        fn last(&self) -> Request {
            self.seen.lock().unwrap().clone().expect("nothing was sent")
        }
    }

    impl BrokerLink for FakeBroker {
        async fn send(&self, request: Request) -> Result<Response, String> {
            *self.seen.lock().unwrap() = Some(request);
            Ok(self.reply.clone())
        }
    }

    struct UnreachableBroker;

    impl BrokerLink for UnreachableBroker {
        async fn send(&self, _request: Request) -> Result<Response, String> {
            Err("could not reach the vault".into())
        }
    }

    fn message(method: &str, params: Value) -> Incoming {
        serde_json::from_value(json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": method,
            "params": params,
        }))
        .unwrap()
    }

    fn call(tool: &str, arguments: Value) -> Incoming {
        message("tools/call", json!({ "name": tool, "arguments": arguments }))
    }

    async fn result_of<L: BrokerLink>(link: &L, incoming: Incoming) -> Value {
        dispatch(link, incoming)
            .await
            .expect("expected a reply")
            .result
            .expect("expected a result, got an error")
    }

    fn body(result: &Value) -> String {
        result["content"][0]["text"].as_str().unwrap().to_string()
    }

    fn is_error(result: &Value) -> bool {
        result["isError"].as_bool().unwrap()
    }

    #[tokio::test]
    async fn initialize_echoes_a_protocol_version_it_speaks() {
        let result = result_of(
            &UnreachableBroker,
            message("initialize", json!({ "protocolVersion": "2024-11-05" })),
        )
        .await;

        assert_eq!(result["protocolVersion"], "2024-11-05");
        assert_eq!(result["serverInfo"]["name"], "lapse");
        assert!(result["capabilities"]["tools"].is_object());
    }

    #[tokio::test]
    async fn initialize_offers_its_newest_version_for_one_it_does_not_speak() {
        let result = result_of(
            &UnreachableBroker,
            message("initialize", json!({ "protocolVersion": "1999-01-01" })),
        )
        .await;

        assert_eq!(result["protocolVersion"], SUPPORTED_VERSIONS[0]);
    }

    #[tokio::test]
    async fn a_notification_is_never_answered() {
        let notification: Incoming = serde_json::from_value(json!({
            "jsonrpc": "2.0",
            "method": "notifications/initialized",
        }))
        .unwrap();

        assert!(dispatch(&UnreachableBroker, notification).await.is_none());
    }

    #[tokio::test]
    async fn an_unknown_method_is_a_method_not_found_error() {
        let reply = dispatch(&UnreachableBroker, message("nonsense", json!({})))
            .await
            .unwrap();

        assert_eq!(reply.error.unwrap().code, codes::METHOD_NOT_FOUND);
    }

    #[tokio::test]
    async fn every_tool_is_listed_with_a_schema() {
        let result = result_of(&UnreachableBroker, message("tools/list", json!({}))).await;
        let tools = result["tools"].as_array().unwrap();

        assert_eq!(tools.len(), 4);
        for tool in tools {
            assert!(tool["name"].is_string());
            assert!(!tool["description"].as_str().unwrap().is_empty());
            assert_eq!(tool["inputSchema"]["type"], "object");
        }
    }

    #[tokio::test]
    async fn both_access_tools_require_a_reason() {
        for tool in ["lapse_run_with_credential", "lapse_reveal_credential"] {
            let result = result_of(&UnreachableBroker, message("tools/list", json!({}))).await;
            let listed = result["tools"]
                .as_array()
                .unwrap()
                .iter()
                .find(|entry| entry["name"] == tool)
                .unwrap()
                .clone();

            let required = listed["inputSchema"]["required"].as_array().unwrap();
            assert!(
                required.iter().any(|value| value == "reason"),
                "{tool} must require a reason"
            );
        }
    }

    #[tokio::test]
    async fn a_run_call_becomes_a_run_request() {
        let broker = FakeBroker::new(Response::Ran(CommandOutput {
            exit_code: 0,
            stdout: "done".into(),
            stderr: String::new(),
        }));

        let result = result_of(
            &broker,
            call(
                "lapse_run_with_credential",
                json!({
                    "item": "db-prod",
                    "env_var": "DATABASE_URL",
                    "command": "npm",
                    "args": ["run", "migrate"],
                    "reason": "run the migration",
                }),
            ),
        )
        .await;

        match broker.last() {
            Request::Access(access) => {
                assert_eq!(access.item, "db-prod");
                assert_eq!(access.field, Field::Password);
                assert_eq!(access.reason, "run the migration");
                match access.intent {
                    Intent::Run {
                        command,
                        args,
                        env_var,
                        ..
                    } => {
                        assert_eq!(command, "npm");
                        assert_eq!(args, ["run", "migrate"]);
                        assert_eq!(env_var, "DATABASE_URL");
                    }
                    other => panic!("unexpected {other:?}"),
                }
            }
            other => panic!("unexpected {other:?}"),
        }

        assert!(!is_error(&result));
        assert!(body(&result).contains("done"));
    }

    #[tokio::test]
    async fn a_failing_command_is_reported_as_a_result_not_a_tool_error() {
        // The agent needs the output to diagnose it; flagging the whole call as
        // failed would hide that behind a transport-level error in some clients.
        let broker = FakeBroker::new(Response::Ran(CommandOutput {
            exit_code: 1,
            stdout: String::new(),
            stderr: "migration failed".into(),
        }));

        let result = result_of(
            &broker,
            call(
                "lapse_run_with_credential",
                json!({
                    "item": "db", "env_var": "X", "command": "npm", "reason": "why",
                }),
            ),
        )
        .await;

        assert!(!is_error(&result));
        assert!(body(&result).contains("Exit code 1"));
        assert!(body(&result).contains("migration failed"));
    }

    #[tokio::test]
    async fn a_declined_request_is_a_tool_error_the_agent_can_read() {
        let broker = FakeBroker::new(Response::refused(Refusal::Denied));

        let result = result_of(
            &broker,
            call(
                "lapse_reveal_credential",
                json!({ "item": "db", "reason": "why" }),
            ),
        )
        .await;

        assert!(is_error(&result));
        assert!(body(&result).contains("declined"));
    }

    #[tokio::test]
    async fn an_unreachable_vault_is_a_tool_error_not_a_protocol_error() {
        let reply = dispatch(
            &UnreachableBroker,
            call("lapse_status", json!({})),
        )
        .await
        .unwrap();

        assert!(reply.error.is_none(), "must not be a JSON-RPC error");
        assert!(is_error(&reply.result.unwrap()));
    }

    #[tokio::test]
    async fn a_missing_required_argument_is_an_invalid_params_error() {
        let reply = dispatch(
            &UnreachableBroker,
            call("lapse_reveal_credential", json!({ "item": "db" })),
        )
        .await
        .unwrap();

        let error = reply.error.unwrap();
        assert_eq!(error.code, codes::INVALID_PARAMS);
        assert!(error.message.contains("reason"));
    }

    #[tokio::test]
    async fn a_blank_reason_does_not_count_as_supplied() {
        let reply = dispatch(
            &UnreachableBroker,
            call(
                "lapse_reveal_credential",
                json!({ "item": "db", "reason": "   " }),
            ),
        )
        .await
        .unwrap();

        assert_eq!(reply.error.unwrap().code, codes::INVALID_PARAMS);
    }

    #[tokio::test]
    async fn listing_items_needs_no_reason_and_exposes_no_secrets() {
        let broker = FakeBroker::new(Response::Items {
            items: vec![ItemRef {
                id: Uuid::nil(),
                name: "db-prod".into(),
                username: Some("app".into()),
                has_password: true,
                has_totp: false,
            }],
        });

        let result = result_of(&broker, call("lapse_list_items", json!({}))).await;

        assert!(!is_error(&result));
        assert!(body(&result).contains("db-prod"));
        assert!(matches!(broker.last(), Request::List { .. }));
    }

    #[tokio::test]
    async fn an_unknown_field_name_is_rejected_before_reaching_the_vault() {
        let reply = dispatch(
            &UnreachableBroker,
            call(
                "lapse_reveal_credential",
                json!({ "item": "db", "field": "secret", "reason": "why" }),
            ),
        )
        .await
        .unwrap();

        assert_eq!(reply.error.unwrap().code, codes::INVALID_PARAMS);
    }

    #[tokio::test]
    async fn an_unknown_tool_is_rejected() {
        let reply = dispatch(&UnreachableBroker, call("lapse_do_anything", json!({})))
            .await
            .unwrap();

        assert_eq!(reply.error.unwrap().code, codes::INVALID_PARAMS);
    }

    #[tokio::test]
    async fn the_reveal_description_steers_towards_running_instead() {
        let result = result_of(&UnreachableBroker, message("tools/list", json!({}))).await;
        let reveal = result["tools"]
            .as_array()
            .unwrap()
            .iter()
            .find(|tool| tool["name"] == "lapse_reveal_credential")
            .unwrap()
            .clone();

        let description = reveal["description"].as_str().unwrap();
        assert!(description.contains("lapse_run_with_credential"));
        assert!(description.contains("Last resort"));
    }
}
