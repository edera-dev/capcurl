//! Response framing, written back onto the capability descriptor.

/// A response head to serialize for the client.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResponseHead {
    /// The status code.
    pub status: u16,
    /// The reason phrase.
    pub reason: String,
    /// Header fields to pass through, hop-by-hop ones already removed.
    pub headers: Vec<(String, String)>,
}

impl ResponseHead {
    /// Serializes the head for a body of exactly `body_len` bytes.
    ///
    /// The framing is always an explicit `Content-Length` plus
    /// `Connection: close`, whatever the origin said. A minted descriptor
    /// carries one request and is then closed, so there is no next message to
    /// disagree about — and an explicit length means the client never has to
    /// treat "the descriptor closed" as "the body ended", which is how a
    /// truncated response becomes a successful-looking one.
    pub fn encode(&self, body_len: usize) -> Vec<u8> {
        let mut out = Vec::with_capacity(256 + self.headers.len() * 48);
        out.extend_from_slice(
            format!(
                "HTTP/1.1 {} {}\r\n",
                self.status,
                sanitize_reason(&self.reason)
            )
            .as_bytes(),
        );
        for (name, value) in &self.headers {
            out.extend_from_slice(name.as_bytes());
            out.extend_from_slice(b": ");
            out.extend_from_slice(value.as_bytes());
            out.extend_from_slice(b"\r\n");
        }
        out.extend_from_slice(format!("Content-Length: {body_len}\r\n").as_bytes());
        out.extend_from_slice(b"Connection: close\r\n\r\n");
        out
    }

    /// Builds a capcurl-generated error response — a refusal by the daemon, not
    /// anything the origin said.
    ///
    /// The body is `text/plain` and describes policy. Nothing about the
    /// upstream, and never a credential, reaches it.
    pub fn refusal(status: u16, reason: &str, detail: &str) -> (ResponseHead, Vec<u8>) {
        let body = format!("capcurl: {detail}\n").into_bytes();
        let head = ResponseHead {
            status,
            reason: reason.to_string(),
            headers: vec![
                (
                    "Content-Type".to_string(),
                    "text/plain; charset=utf-8".to_string(),
                ),
                ("X-Capcurl-Refused".to_string(), "1".to_string()),
            ],
        };
        (head, body)
    }
}

/// Header names that describe a single connection rather than the message, and
/// so must not be forwarded between the origin leg and the descriptor leg.
///
/// `content-length` and `transfer-encoding` are here because the framing on the
/// descriptor is recomputed from the body we actually hold; passing the origin's
/// through would let the two legs disagree.
const HOP_BY_HOP: &[&str] = &[
    "connection",
    "content-length",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "proxy-connection",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];

/// Whether a header is hop-by-hop and must be dropped when relaying.
///
/// `connection_header` is the origin's `Connection` value, which nominates
/// further headers as hop-by-hop for that connection.
pub fn is_hop_by_hop(name: &str, connection_header: Option<&str>) -> bool {
    let lower = name.to_ascii_lowercase();
    if HOP_BY_HOP.contains(&lower.as_str()) {
        return true;
    }
    match connection_header {
        Some(value) => value
            .split(',')
            .any(|nominated| nominated.trim().eq_ignore_ascii_case(&lower)),
        None => false,
    }
}

/// Keeps a reason phrase from carrying a CRLF into the status line.
fn sanitize_reason(reason: &str) -> String {
    let cleaned: String = reason
        .chars()
        .filter(|c| c.is_ascii_graphic() || *c == ' ')
        .take(64)
        .collect();
    if cleaned.is_empty() {
        "Unknown".to_string()
    } else {
        cleaned
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_explicit_framing() {
        let head = ResponseHead {
            status: 200,
            reason: "OK".into(),
            headers: vec![("Content-Type".into(), "application/json".into())],
        };
        let encoded = String::from_utf8(head.encode(9)).expect("ascii");
        assert_eq!(
            encoded,
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 9\r\nConnection: close\r\n\r\n"
        );
    }

    #[test]
    fn strips_crlf_from_reason() {
        let head = ResponseHead {
            status: 200,
            reason: "OK\r\nX-Injected: 1".into(),
            headers: vec![],
        };
        let encoded = String::from_utf8(head.encode(0)).expect("ascii");
        assert!(encoded.starts_with("HTTP/1.1 200 OKX-Injected: 1\r\n"));
        assert!(!encoded.contains("\r\nX-Injected"));
    }

    #[test]
    fn identifies_hop_by_hop() {
        assert!(is_hop_by_hop("Connection", None));
        assert!(is_hop_by_hop("transfer-encoding", None));
        assert!(is_hop_by_hop("Content-Length", None));
        assert!(!is_hop_by_hop("Content-Type", None));
        // Nominated by the origin's Connection header.
        assert!(is_hop_by_hop("X-Custom", Some("keep-alive, X-Custom")));
        assert!(!is_hop_by_hop("X-Other", Some("keep-alive, X-Custom")));
    }

    #[test]
    fn refusals_are_self_describing() {
        let (head, body) = ResponseHead::refusal(403, "Forbidden", "method PUT is not permitted");
        assert_eq!(head.status, 403);
        assert_eq!(crate::header(&head.headers, "x-capcurl-refused"), Some("1"));
        assert_eq!(body, b"capcurl: method PUT is not permitted\n");
    }
}
