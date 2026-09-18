//! Speaking HTTP/1.1 over a minted descriptor.
//!
//! The client-side counterpart to the daemon's parser. The `capcurl` binary
//! uses it, and so can anything else that speaks HTTP: a minted descriptor is
//! an ordinary socket.

use std::os::fd::OwnedFd;

use capcurl_http::{find_head_end, header, HttpError, MAX_HEAD_LEN};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::error::{CoreError, Result};

/// A response read back off a minted descriptor.
#[derive(Debug, Clone)]
pub struct Response {
    /// The status code.
    pub status: u16,
    /// The reason phrase.
    pub reason: String,
    /// The response headers.
    pub headers: Vec<(String, String)>,
    /// The response body.
    pub body: Vec<u8>,
    /// Whether the daemon refused the request rather than relaying an origin's
    /// answer (the `X-Capcurl-Refused` marker).
    pub refused: bool,
}

/// Performs the one request a minted descriptor is good for.
///
/// `method` and `target` must match what the descriptor was minted for; the
/// daemon checks, and refuses rather than quietly fetching something else.
pub async fn request_over_fd(
    fd: OwnedFd,
    method: &str,
    target: &str,
    headers: &[(String, String)],
    body: &[u8],
) -> Result<Response> {
    let mut stream = into_stream(fd)?;

    let mut head = format!("{method} {target} HTTP/1.1\r\n");
    // The daemon supplies the real authority; it is not ours to know. A `Host`
    // is sent only because HTTP/1.1 requires one, and the daemon discards it.
    head.push_str("Host: capability.invalid\r\n");
    for (name, value) in headers {
        head.push_str(&format!("{name}: {value}\r\n"));
    }
    head.push_str(&format!("Content-Length: {}\r\n", body.len()));
    head.push_str("\r\n");

    stream.write_all(head.as_bytes()).await?;
    stream.write_all(body).await?;
    stream.flush().await?;
    // Deliberately no half-close. Both legs are explicitly framed — we always
    // send a `Content-Length`, the daemon always answers with one — so neither
    // side needs to read "the peer shut down its write half" as "the message
    // ended". That matters because a half-close is a property of a socket, and
    // a descriptor minted across a zone boundary is a socket the multiplexing
    // transport fabricated: relying on shutdown to survive the hop would make
    // this work locally and hang in a zone.
    read_response(&mut stream).await
}

/// Reads a complete response, using the daemon's explicit `Content-Length`.
async fn read_response(stream: &mut tokio::net::UnixStream) -> Result<Response> {
    let mut buf = Vec::with_capacity(8192);
    let head_end = loop {
        if let Some(end) = find_head_end(&buf) {
            break end;
        }
        if buf.len() > MAX_HEAD_LEN {
            return Err(CoreError::Http(HttpError::HeadTooLarge));
        }
        let mut chunk = [0u8; 8192];
        let n = stream.read(&mut chunk).await?;
        if n == 0 {
            return Err(CoreError::Handshake(
                "capability closed before a complete response head".into(),
            ));
        }
        buf.extend_from_slice(&chunk[..n]);
    };

    let (status, reason, headers) = parse_status_and_headers(&buf[..head_end])?;

    let length: usize = header(&headers, "content-length")
        .ok_or_else(|| CoreError::Handshake("response had no Content-Length".into()))?
        .trim()
        .parse()
        .map_err(|_| CoreError::Http(HttpError::BadContentLength))?;

    let mut body = buf[head_end..].to_vec();
    while body.len() < length {
        let mut chunk = [0u8; 8192];
        let n = stream.read(&mut chunk).await?;
        if n == 0 {
            return Err(CoreError::Handshake(format!(
                "capability closed after {} of {} body bytes",
                body.len(),
                length
            )));
        }
        body.extend_from_slice(&chunk[..n]);
    }
    body.truncate(length);

    let refused = header(&headers, "x-capcurl-refused").is_some();
    Ok(Response {
        status,
        reason,
        headers,
        body,
        refused,
    })
}

/// A status line and its header fields.
type StatusAndHeaders = (u16, String, Vec<(String, String)>);

/// Parses a response status line and headers.
fn parse_status_and_headers(head: &[u8]) -> Result<StatusAndHeaders> {
    let text = std::str::from_utf8(head).map_err(|_| CoreError::Http(HttpError::BadHeader))?;
    let mut lines = text.split("\r\n");

    let status_line = lines.next().ok_or(CoreError::Http(HttpError::BadHeader))?;
    let mut parts = status_line.splitn(3, ' ');
    let version = parts.next().unwrap_or_default();
    if version != "HTTP/1.1" && version != "HTTP/1.0" {
        return Err(CoreError::Http(HttpError::BadVersion));
    }
    let status: u16 = parts
        .next()
        .ok_or(CoreError::Http(HttpError::BadHeader))?
        .parse()
        .map_err(|_| CoreError::Http(HttpError::BadHeader))?;
    let reason = parts.next().unwrap_or("").to_string();

    let mut headers = Vec::new();
    for line in lines {
        if line.is_empty() {
            break;
        }
        let (name, value) = line
            .split_once(':')
            .ok_or(CoreError::Http(HttpError::BadHeader))?;
        headers.push((name.trim().to_string(), value.trim().to_string()));
    }

    Ok((status, reason, headers))
}

/// Wraps an owned descriptor as a tokio stream.
pub(crate) fn into_stream(fd: OwnedFd) -> Result<tokio::net::UnixStream> {
    let std_stream = std::os::unix::net::UnixStream::from(fd);
    std_stream.set_nonblocking(true)?;
    Ok(tokio::net::UnixStream::from_std(std_stream)?)
}
