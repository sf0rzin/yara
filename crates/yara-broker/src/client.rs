//! Talking to the broker from another process.
//!
//! One request, one response, one connection. Nothing is cached and no
//! credential is ever written to disk on this side.

#[cfg(windows)]
use crate::protocol;
use crate::protocol::{Request, Response};

/// Sends one request to a running yara and returns its answer.
#[cfg(windows)]
pub async fn send(request: &Request) -> Result<Response, String> {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::net::windows::named_pipe::ClientOptions;

    let stream = ClientOptions::new()
        .open(crate::transport::DEFAULT_PIPE_NAME)
        .map_err(|error| {
            format!("could not reach the vault ({error}). Is yara running and unlocked?")
        })?;

    let (reader, mut writer) = tokio::io::split(stream);
    let mut lines = BufReader::new(reader).lines();

    let encoded = protocol::encode(request).map_err(|e| e.to_string())?;
    writer
        .write_all(encoded.as_bytes())
        .await
        .map_err(|e| e.to_string())?;
    writer.flush().await.map_err(|e| e.to_string())?;

    let line = lines
        .next_line()
        .await
        .map_err(|e| e.to_string())?
        .ok_or_else(|| "the vault closed the connection without answering".to_string())?;

    protocol::decode(&line).map_err(|e| format!("could not understand the reply: {e}"))
}

#[cfg(not(windows))]
pub async fn send(_request: &Request) -> Result<Response, String> {
    Err("agent access is only supported on Windows so far".into())
}
