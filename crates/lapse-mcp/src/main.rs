//! `lapse-mcp` — the lapse vault as an MCP server.
//!
//! Speaks JSON-RPC 2.0 over stdio, one message per line, and forwards each tool
//! call to the broker running inside the lapse app. It holds no state and no
//! credentials of its own: every request still goes to the vault owner for
//! approval and lands in the audit log.
//!
//! Point an MCP-capable agent at this binary:
//!
//! ```json
//! { "mcpServers": { "lapse": { "command": "lapse-mcp" } } }
//! ```

mod rpc;
mod server;

use serde_json::Value;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

use rpc::{codes, Incoming, Outgoing};
use server::PipeLink;

#[tokio::main(flavor = "current_thread")]
async fn main() -> std::io::Result<()> {
    let link = PipeLink;

    let mut lines = BufReader::new(tokio::io::stdin()).lines();
    let mut stdout = tokio::io::stdout();

    while let Some(line) = lines.next_line().await? {
        if line.trim().is_empty() {
            continue;
        }

        let reply = match serde_json::from_str::<Incoming>(&line) {
            Ok(incoming) => server::dispatch(&link, incoming).await,

            // A malformed message still needs an answer, but it has no id to
            // answer against — null is what JSON-RPC specifies for that case.
            Err(error) => Some(Outgoing::error(
                Value::Null,
                codes::PARSE_ERROR,
                format!("could not parse that message: {error}"),
            )),
        };

        let Some(reply) = reply else {
            continue;
        };

        // stdout carries the protocol and nothing else. Every diagnostic goes
        // to stderr — a stray print here corrupts the stream and the client
        // drops the connection with no useful explanation.
        let mut encoded = serde_json::to_string(&reply).unwrap_or_else(|_| {
            r#"{"jsonrpc":"2.0","id":null,"error":{"code":-32603,"message":"encoding failed"}}"#
                .to_string()
        });
        encoded.push('\n');

        stdout.write_all(encoded.as_bytes()).await?;
        stdout.flush().await?;
    }

    Ok(())
}
