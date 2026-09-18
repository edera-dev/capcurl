//! Daemon side: mint a descriptor, then serve the one request it is good for.

use std::time::Duration;

use capcurl_grant::{Denied, Grant};
use capcurl_http::{
    decode_chunked, find_head_end, is_hop_by_hop, ChunkedOutcome, Framing, HttpError, RequestHead,
    ResponseHead, MAX_HEAD_LEN,
};
use capsudo_proto::{FieldType, Message};
use capsudo_transport::{FdSpec, Transport};
use nix::sys::socket::{socketpair, AddressFamily, SockFlag, SockType};
use reqwest::Client;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use url::Url;

use crate::error::{CoreError, Result};
use crate::exchange::into_stream;
use crate::upstream;

/// Headers that belong to the descriptor leg rather than to the client's
/// intent.
///
/// Any HTTP client computes these — ours writes a placeholder `Host` — so
/// treating them as "the client set a forbidden header" would refuse every
/// well-formed request. They are dropped silently and
/// recomputed for the origin leg. Headers a client had to *choose* to send
/// (`Authorization`, `Cookie`, the `Proxy-*` pair) are left in place so the
/// grant's policy can refuse them out loud.
const DESCRIPTOR_LEG_HEADERS: &[&str] = &[
    "connection",
    "content-length",
    "expect",
    "host",
    "keep-alive",
    "proxy-connection",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];

/// Daemon-side policy for an endpoint.
pub struct DaemonConfig {
    /// What this endpoint is a capability for.
    pub grant: Grant,
    /// How long the upstream request may take.
    pub timeout: Duration,
}

impl DaemonConfig {
    /// Wraps a grant with the default 30-second upstream timeout.
    pub fn new(grant: Grant) -> DaemonConfig {
        DaemonConfig {
            grant,
            timeout: Duration::from_secs(30),
        }
    }
}

/// Serves one client: read the mint request, hand back a descriptor, relay the
/// single request it carries.
pub async fn serve_connection(
    transport: &mut dyn Transport,
    config: &DaemonConfig,
    client: &Client,
) -> Result<()> {
    let (method, target) = match read_mint_request(transport).await {
        Ok(pair) => pair,
        Err(e) => {
            // Answer anyway: the client is waiting on a descriptor that will
            // never come.
            let _ = transport.send(&Message::error(e.to_string()), &[]).await;
            return Err(e);
        }
    };

    let (bound_method, url) = match config.grant.resolve(&method, &target) {
        Ok(resolved) => resolved,
        Err(denied) => {
            transport
                .send(&Message::error(denied.to_string()), &[])
                .await?;
            return Err(CoreError::Denied(denied));
        }
    };

    // What the daemon actually bound, which for a pinned endpoint is not what
    // the client asked for.
    let bound_target = match config.grant.fixed_request() {
        Some(fixed) => fixed.target.clone(),
        None => target,
    };

    let (theirs, ours) = socketpair(
        AddressFamily::Unix,
        SockType::Stream,
        None,
        SockFlag::empty(),
    )
    .map_err(std::io::Error::from)?;

    transport.send(&Message::arg(&bound_method), &[]).await?;
    transport.send(&Message::arg(&bound_target), &[]).await?;
    transport
        .send(
            &Message::fds(1),
            &[FdSpec::read_write(std::os::fd::AsFd::as_fd(&theirs))],
        )
        .await?;

    // Both transports take their own reference to a delegated descriptor — the
    // Unix one via SCM_RIGHTS, the multiplexing one via `dup`. Ours has to go,
    // or our end never sees the client's half-close and the exchange below
    // waits forever for a request that has already arrived in full.
    drop(theirs);

    let mut stream = into_stream(ours)?;
    let outcome = serve_request(
        &mut stream,
        config,
        client,
        &bound_method,
        &bound_target,
        &url,
    )
    .await;

    // A refusal is reported on the descriptor as an HTTP response, because by
    // now the client is an HTTP client and has stopped listening to the mint
    // channel.
    if let Err(e) = &outcome {
        let (head, body) = refusal_for(e);
        let _ = write_response(&mut stream, &head, &body).await;
    }
    let _ = stream.shutdown().await;

    outcome
}

/// Reads the mint handshake: method, target, `End`.
async fn read_mint_request(transport: &mut dyn Transport) -> Result<(String, String)> {
    let mut args: Vec<String> = Vec::new();

    loop {
        let received = transport
            .recv()
            .await?
            .ok_or_else(|| CoreError::Handshake("client closed the channel".into()))?;

        match received.message.field_type() {
            FieldType::Arg => {
                if args.len() >= 2 {
                    return Err(CoreError::Handshake(
                        "a mint takes exactly a method and a target".into(),
                    ));
                }
                args.push(received.message.as_str()?.to_string());
            }
            FieldType::End => break,
            other => {
                return Err(CoreError::Handshake(format!(
                    "unexpected {other:?} message during mint"
                )));
            }
        }
    }

    match args.len() {
        2 => Ok((args.remove(0), args.remove(0))),
        _ => Err(CoreError::Handshake(
            "a mint takes exactly a method and a target".into(),
        )),
    }
}

/// Reads the request off the descriptor, relays it, writes the response back.
async fn serve_request(
    stream: &mut tokio::net::UnixStream,
    config: &DaemonConfig,
    client: &Client,
    bound_method: &str,
    bound_target: &str,
    url: &Url,
) -> Result<()> {
    let (head, leftover) = read_head(stream).await?;

    // The descriptor was minted for one request. Serving a different one
    // because the request line says so would make the mint advisory.
    if !head.method.eq_ignore_ascii_case(bound_method) || head.target != bound_target {
        return Err(CoreError::Denied(Denied::NotFixedRequest));
    }

    let body = read_body(stream, &head, leftover, config.grant.max_request_body()).await?;

    let client_headers: Vec<(String, String)> = head
        .headers
        .iter()
        .filter(|(name, _)| {
            let lower = name.to_ascii_lowercase();
            !DESCRIPTOR_LEG_HEADERS.contains(&lower.as_str())
        })
        .cloned()
        .collect();

    let headers = config.grant.apply_headers(&client_headers)?;

    let response =
        upstream::fetch(client, &config.grant, bound_method, url, &headers, body).await?;

    let connection = response
        .headers
        .get("connection")
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);

    let mut out_headers: Vec<(String, String)> = Vec::new();
    for (name, value) in response.headers.iter() {
        if is_hop_by_hop(name.as_str(), connection.as_deref()) {
            continue;
        }
        if let Ok(value) = value.to_str() {
            out_headers.push((name.as_str().to_string(), value.to_string()));
        }
    }

    let head = ResponseHead {
        status: response.status,
        reason: response.reason,
        headers: out_headers,
    };
    write_response(stream, &head, &response.body).await
}

/// Reads until the end of the request head, returning it and any body bytes
/// that arrived with it.
async fn read_head(stream: &mut tokio::net::UnixStream) -> Result<(RequestHead, Vec<u8>)> {
    let mut buf = Vec::with_capacity(8192);
    loop {
        if let Some(end) = find_head_end(&buf) {
            let head = RequestHead::parse(&buf[..end])?;
            return Ok((head, buf[end..].to_vec()));
        }
        if buf.len() > MAX_HEAD_LEN {
            return Err(CoreError::Http(HttpError::HeadTooLarge));
        }
        let mut chunk = [0u8; 8192];
        let n = stream.read(&mut chunk).await?;
        if n == 0 {
            return Err(CoreError::Handshake(
                "capability closed before a complete request head".into(),
            ));
        }
        buf.extend_from_slice(&chunk[..n]);
    }
}

/// Reads the body according to the framing the head declared.
async fn read_body(
    stream: &mut tokio::net::UnixStream,
    head: &RequestHead,
    mut buf: Vec<u8>,
    limit: u64,
) -> Result<Vec<u8>> {
    match head.framing {
        Framing::None => Ok(Vec::new()),
        Framing::Length(len) => {
            if len > limit {
                return Err(CoreError::Denied(Denied::TooLarge {
                    what: "request",
                    limit,
                }));
            }
            let len = len as usize;
            while buf.len() < len {
                let mut chunk = [0u8; 8192];
                let n = stream.read(&mut chunk).await?;
                if n == 0 {
                    return Err(CoreError::Handshake(format!(
                        "capability closed after {} of {} body bytes",
                        buf.len(),
                        len
                    )));
                }
                buf.extend_from_slice(&chunk[..n]);
            }
            buf.truncate(len);
            Ok(buf)
        }
        Framing::Chunked => loop {
            match decode_chunked(&buf, limit)? {
                ChunkedOutcome::Complete { body, .. } => return Ok(body),
                ChunkedOutcome::NeedMore => {
                    if buf.len() as u64 > limit.saturating_mul(2).saturating_add(4096) {
                        // Chunk framing overhead is bounded; far past the limit
                        // means the peer is not going to stop.
                        return Err(CoreError::Denied(Denied::TooLarge {
                            what: "request",
                            limit,
                        }));
                    }
                    let mut chunk = [0u8; 8192];
                    let n = stream.read(&mut chunk).await?;
                    if n == 0 {
                        return Err(CoreError::Http(HttpError::BadChunk));
                    }
                    buf.extend_from_slice(&chunk[..n]);
                }
            }
        },
    }
}

/// Writes a response head and body to the descriptor.
async fn write_response(
    stream: &mut tokio::net::UnixStream,
    head: &ResponseHead,
    body: &[u8],
) -> Result<()> {
    stream.write_all(&head.encode(body.len())).await?;
    stream.write_all(body).await?;
    stream.flush().await?;
    Ok(())
}

/// Maps an internal error onto the HTTP response the client sees.
///
/// The status describes *who* was refused and why in policy terms. Nothing here
/// reveals the origin, the resolved URL, or an injected credential.
fn refusal_for(error: &CoreError) -> (ResponseHead, Vec<u8>) {
    match error {
        CoreError::Denied(denied @ Denied::TooLarge { what, .. }) => {
            let status = if *what == "request" { 413 } else { 502 };
            let reason = if *what == "request" {
                "Content Too Large"
            } else {
                "Bad Gateway"
            };
            ResponseHead::refusal(status, reason, &denied.to_string())
        }
        CoreError::Denied(denied) => ResponseHead::refusal(403, "Forbidden", &denied.to_string()),
        CoreError::Http(e) => ResponseHead::refusal(400, "Bad Request", &e.to_string()),
        CoreError::Upstream(detail) => ResponseHead::refusal(502, "Bad Gateway", detail),
        other => ResponseHead::refusal(500, "Internal Server Error", &other.to_string()),
    }
}
