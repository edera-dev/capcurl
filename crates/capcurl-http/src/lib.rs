//! HTTP/1.1 on the capability descriptor — parsing in, framing out.
//!
//! This crate does no I/O, in the same spirit as `capsudo-proto`: it turns
//! bytes into a [`RequestHead`] and a [`ResponseHead`] back into bytes, and
//! `capcurl-core` owns the descriptor.
//!
//! Framing the descriptor with `capsudo-proto` messages instead would delete
//! this crate, and the daemon's HTTP-parsing attack surface with it. HTTP is
//! what lets anything that speaks it drive a minted descriptor; this crate is
//! the cost of that.
//!
//! The parser is strict rather than permissive. Bytes on a minted descriptor
//! come from the least trusted party in the system, and the daemon sits between
//! that party and a credential. Anywhere the parser could guess at a malformed
//! message, the client and the origin can be made to disagree about where one
//! request ends and the next begins, which is request smuggling. So anything
//! ambiguous is an error.

mod chunked;
mod request;
mod response;

pub use chunked::{decode_chunked, ChunkedOutcome};
pub use request::{Framing, RequestHead, Version, MAX_HEADERS, MAX_HEAD_LEN};
pub use response::{is_hop_by_hop, ResponseHead};

/// Why a message was rejected.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum HttpError {
    /// The head exceeded [`MAX_HEAD_LEN`].
    #[error("request head exceeds {MAX_HEAD_LEN} bytes")]
    HeadTooLarge,
    /// More than [`MAX_HEADERS`] header fields.
    #[error("more than {MAX_HEADERS} header fields")]
    TooManyHeaders,
    /// The request line was not `METHOD SP target SP HTTP/1.x`.
    #[error("malformed request line")]
    BadRequestLine,
    /// Not HTTP/1.0 or HTTP/1.1.
    #[error("unsupported HTTP version")]
    BadVersion,
    /// A header field was malformed.
    #[error("malformed header field")]
    BadHeader,
    /// A continuation line (obsolete line folding).
    #[error("obsolete line folding is not accepted")]
    ObsFold,
    /// `Content-Length` was absent, repeated with differing values, or not a
    /// plain decimal number.
    #[error("malformed Content-Length")]
    BadContentLength,
    /// `Transfer-Encoding` was something other than a bare `chunked`.
    #[error("unsupported Transfer-Encoding")]
    BadTransferEncoding,
    /// Both `Content-Length` and `Transfer-Encoding` were present. This is the
    /// classic smuggling primitive: two framings, two readers, two answers.
    #[error("Content-Length and Transfer-Encoding must not both be present")]
    ConflictingFraming,
    /// The client asked for a protocol upgrade, which a capability cannot carry.
    #[error("protocol upgrades are not supported")]
    Upgrade,
    /// A chunked body was malformed.
    #[error("malformed chunked body")]
    BadChunk,
    /// The body exceeded the caller's limit.
    #[error("body exceeds the permitted size")]
    BodyTooLarge,
}

/// Locates the end of a message head, returning the offset just past the
/// terminating CRLFCRLF.
///
/// Only CRLFCRLF terminates a head. A bare LFLF is accepted by many parsers,
/// which is the sort of disagreement this crate avoids.
pub fn find_head_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n").map(|i| i + 4)
}

/// Case-insensitive lookup over a header list.
pub fn header<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(n, _)| n.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_str())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_crlf_terminated_head() {
        assert_eq!(find_head_end(b"GET / HTTP/1.1\r\n\r\n"), Some(18));
        assert_eq!(find_head_end(b"GET / HTTP/1.1\n\n"), None);
        assert_eq!(find_head_end(b"GET / HTTP/1.1\r\n"), None);
    }
}
