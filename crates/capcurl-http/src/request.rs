//! Request head parsing.

use crate::HttpError;

/// The longest request head accepted, in bytes.
pub const MAX_HEAD_LEN: usize = 64 * 1024;
/// The most header fields accepted.
pub const MAX_HEADERS: usize = 128;

/// The HTTP versions capcurl speaks on a capability descriptor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Version {
    /// `HTTP/1.0`
    Http10,
    /// `HTTP/1.1`
    Http11,
}

/// How the request body is delimited.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Framing {
    /// No body.
    None,
    /// A body of exactly this many bytes.
    Length(u64),
    /// A chunked body.
    Chunked,
}

/// A parsed request head.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestHead {
    /// The method, exactly as sent.
    pub method: String,
    /// The request-target, exactly as sent.
    pub target: String,
    /// The protocol version.
    pub version: Version,
    /// Header fields in order, names as sent.
    pub headers: Vec<(String, String)>,
    /// How to read the body that follows.
    pub framing: Framing,
}

impl RequestHead {
    /// Parses a complete head, including its terminating CRLFCRLF.
    pub fn parse(buf: &[u8]) -> Result<RequestHead, HttpError> {
        if buf.len() > MAX_HEAD_LEN {
            return Err(HttpError::HeadTooLarge);
        }

        let mut lines = split_crlf(buf);

        let request_line = lines.next().ok_or(HttpError::BadRequestLine)?;
        // RFC 9112 permits ignoring a leading empty line. Accepting it means
        // accepting a message whose start we had to guess at.
        if request_line.is_empty() {
            return Err(HttpError::BadRequestLine);
        }
        let (method, target, version) = parse_request_line(request_line)?;

        let mut headers: Vec<(String, String)> = Vec::new();
        for line in lines {
            if line.is_empty() {
                break;
            }
            if headers.len() >= MAX_HEADERS {
                return Err(HttpError::TooManyHeaders);
            }
            // A field line starting with SP or HTAB is a continuation of the
            // previous one. Nothing generates these any more and unfolding them
            // is a well-worn source of parser disagreement.
            if line[0] == b' ' || line[0] == b'\t' {
                return Err(HttpError::ObsFold);
            }
            headers.push(parse_header_line(line)?);
        }

        let framing = framing_of(&headers)?;

        if crate::header(&headers, "upgrade").is_some() {
            return Err(HttpError::Upgrade);
        }

        Ok(RequestHead {
            method,
            target,
            version,
            headers,
            framing,
        })
    }
}

/// Splits on CRLF only, yielding lines without their terminators.
fn split_crlf(buf: &[u8]) -> impl Iterator<Item = &[u8]> {
    let mut rest = buf;
    std::iter::from_fn(move || {
        if rest.is_empty() {
            return None;
        }
        match rest.windows(2).position(|w| w == b"\r\n") {
            Some(i) => {
                let line = &rest[..i];
                rest = &rest[i + 2..];
                Some(line)
            }
            None => {
                let line = rest;
                rest = &[];
                Some(line)
            }
        }
    })
}

/// Parses `METHOD SP request-target SP HTTP/1.x`.
///
/// Exactly one space between each element. Runs of spaces, or a tab in place of
/// a space, are how a target gets read as a method by one parser and a target by
/// another.
fn parse_request_line(line: &[u8]) -> Result<(String, String, Version), HttpError> {
    let mut parts = line.splitn(3, |b| *b == b' ');
    let method = parts.next().ok_or(HttpError::BadRequestLine)?;
    let target = parts.next().ok_or(HttpError::BadRequestLine)?;
    let version = parts.next().ok_or(HttpError::BadRequestLine)?;

    if method.is_empty() || target.is_empty() {
        return Err(HttpError::BadRequestLine);
    }
    if target.contains(&b' ') || version.contains(&b' ') {
        return Err(HttpError::BadRequestLine);
    }
    if !method.iter().all(|b| is_token_byte(*b)) {
        return Err(HttpError::BadRequestLine);
    }
    if !target.iter().all(|b| (0x21..=0x7e).contains(b)) {
        return Err(HttpError::BadRequestLine);
    }

    let version = match version {
        b"HTTP/1.1" => Version::Http11,
        b"HTTP/1.0" => Version::Http10,
        _ => return Err(HttpError::BadVersion),
    };

    // Safe: both were just checked to be printable ASCII.
    let method = String::from_utf8(method.to_vec()).map_err(|_| HttpError::BadRequestLine)?;
    let target = String::from_utf8(target.to_vec()).map_err(|_| HttpError::BadRequestLine)?;
    Ok((method, target, version))
}

/// Parses `name: value`, trimming optional whitespace around the value.
fn parse_header_line(line: &[u8]) -> Result<(String, String), HttpError> {
    let colon = line
        .iter()
        .position(|b| *b == b':')
        .ok_or(HttpError::BadHeader)?;
    let (name, value) = line.split_at(colon);
    let value = &value[1..];

    // No space is permitted between the field name and the colon: `Foo : bar`
    // is rejected by some parsers and read as `Foo ` by others.
    if name.is_empty() || !name.iter().all(|b| is_token_byte(*b)) {
        return Err(HttpError::BadHeader);
    }

    let value = trim_ows(value);
    if !value
        .iter()
        .all(|b| *b == b'\t' || (0x20..=0x7e).contains(b))
    {
        return Err(HttpError::BadHeader);
    }

    Ok((
        String::from_utf8(name.to_vec()).map_err(|_| HttpError::BadHeader)?,
        String::from_utf8(value.to_vec()).map_err(|_| HttpError::BadHeader)?,
    ))
}

fn trim_ows(mut v: &[u8]) -> &[u8] {
    while let [b' ' | b'\t', rest @ ..] = v {
        v = rest;
    }
    while let [rest @ .., b' ' | b'\t'] = v {
        v = rest;
    }
    v
}

/// Determines body framing, rejecting every way of specifying two.
fn framing_of(headers: &[(String, String)]) -> Result<Framing, HttpError> {
    let mut content_length: Option<u64> = None;
    let mut saw_transfer_encoding = false;

    for (name, value) in headers {
        if name.eq_ignore_ascii_case("content-length") {
            // A repeated Content-Length is legal only if every value agrees.
            // Anything else is two framings wearing one name.
            let parsed = parse_content_length(value)?;
            match content_length {
                Some(existing) if existing != parsed => return Err(HttpError::BadContentLength),
                _ => content_length = Some(parsed),
            }
        } else if name.eq_ignore_ascii_case("transfer-encoding") {
            if !value.trim().eq_ignore_ascii_case("chunked") {
                return Err(HttpError::BadTransferEncoding);
            }
            if saw_transfer_encoding {
                return Err(HttpError::BadTransferEncoding);
            }
            saw_transfer_encoding = true;
        }
    }

    match (content_length, saw_transfer_encoding) {
        (Some(_), true) => Err(HttpError::ConflictingFraming),
        (Some(0), false) => Ok(Framing::None),
        (Some(n), false) => Ok(Framing::Length(n)),
        (None, true) => Ok(Framing::Chunked),
        (None, false) => Ok(Framing::None),
    }
}

/// Parses a `Content-Length` value as a plain decimal number.
///
/// No sign, no whitespace, no `0x`, no leading `+`. Every one of those is
/// accepted somewhere and means something different there.
fn parse_content_length(value: &str) -> Result<u64, HttpError> {
    let value = value.trim();
    if value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
        return Err(HttpError::BadContentLength);
    }
    value
        .parse::<u64>()
        .map_err(|_| HttpError::BadContentLength)
}

/// RFC 9110 `tchar`.
fn is_token_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric()
        || matches!(
            b,
            b'!' | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'\''
                | b'*'
                | b'+'
                | b'-'
                | b'.'
                | b'^'
                | b'_'
                | b'`'
                | b'|'
                | b'~'
        )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(s: &str) -> Result<RequestHead, HttpError> {
        RequestHead::parse(s.as_bytes())
    }

    #[test]
    fn parses_plain_request() {
        let head =
            parse("GET /issues HTTP/1.1\r\nAccept: application/json\r\n\r\n").expect("valid");
        assert_eq!(head.method, "GET");
        assert_eq!(head.target, "/issues");
        assert_eq!(head.version, Version::Http11);
        assert_eq!(
            head.headers,
            vec![("Accept".into(), "application/json".into())]
        );
        assert_eq!(head.framing, Framing::None);
    }

    #[test]
    fn reads_length_framing() {
        let head = parse("POST /x HTTP/1.1\r\nContent-Length: 42\r\n\r\n").expect("valid");
        assert_eq!(head.framing, Framing::Length(42));
        let head = parse("POST /x HTTP/1.1\r\nContent-Length: 0\r\n\r\n").expect("valid");
        assert_eq!(head.framing, Framing::None);
    }

    #[test]
    fn reads_chunked_framing() {
        let head = parse("POST /x HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n").expect("valid");
        assert_eq!(head.framing, Framing::Chunked);
    }

    #[test]
    fn rejects_both_framings() {
        assert_eq!(
            parse("POST /x HTTP/1.1\r\nContent-Length: 6\r\nTransfer-Encoding: chunked\r\n\r\n"),
            Err(HttpError::ConflictingFraming)
        );
    }

    #[test]
    fn rejects_conflicting_lengths() {
        assert_eq!(
            parse("POST /x HTTP/1.1\r\nContent-Length: 6\r\nContent-Length: 7\r\n\r\n"),
            Err(HttpError::BadContentLength)
        );
        // Agreeing duplicates are harmless.
        assert!(
            parse("POST /x HTTP/1.1\r\nContent-Length: 6\r\nContent-Length: 6\r\n\r\n").is_ok()
        );
    }

    #[test]
    fn rejects_odd_content_lengths() {
        for value in ["+6", "-6", "0x6", "6 ", " 6", "6.0", "six", ""] {
            let req = format!("POST /x HTTP/1.1\r\nContent-Length: {value}\r\n\r\n");
            // A trailing/leading space is trimmed as OWS, so "6 " and " 6" are
            // legitimately 6; the rest must fail.
            if value.trim() == "6" {
                assert!(parse(&req).is_ok(), "{value:?} should parse as 6");
            } else {
                assert_eq!(
                    parse(&req),
                    Err(HttpError::BadContentLength),
                    "{value:?} should be rejected"
                );
            }
        }
    }

    #[test]
    fn rejects_other_encodings() {
        assert_eq!(
            parse("POST /x HTTP/1.1\r\nTransfer-Encoding: gzip, chunked\r\n\r\n"),
            Err(HttpError::BadTransferEncoding)
        );
        assert_eq!(
            parse("POST /x HTTP/1.1\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: chunked\r\n\r\n"),
            Err(HttpError::BadTransferEncoding)
        );
    }

    #[test]
    fn rejects_obs_fold() {
        assert_eq!(
            parse("GET /x HTTP/1.1\r\nAccept: a\r\n b\r\n\r\n"),
            Err(HttpError::ObsFold)
        );
    }

    #[test]
    fn rejects_space_before_colon() {
        assert_eq!(
            parse("GET /x HTTP/1.1\r\nAccept : a\r\n\r\n"),
            Err(HttpError::BadHeader)
        );
    }

    #[test]
    fn rejects_malformed_request_line() {
        assert_eq!(
            parse("GET  /x HTTP/1.1\r\n\r\n"),
            Err(HttpError::BadRequestLine)
        );
        assert_eq!(
            parse("GET /x  HTTP/1.1\r\n\r\n"),
            Err(HttpError::BadRequestLine)
        );
        assert_eq!(parse("GET /x\r\n\r\n"), Err(HttpError::BadRequestLine));
        assert_eq!(
            parse("\r\nGET /x HTTP/1.1\r\n\r\n"),
            Err(HttpError::BadRequestLine)
        );
        assert_eq!(
            parse("GET\t/x\tHTTP/1.1\r\n\r\n"),
            Err(HttpError::BadRequestLine)
        );
    }

    #[test]
    fn rejects_other_versions() {
        assert_eq!(parse("GET /x HTTP/2.0\r\n\r\n"), Err(HttpError::BadVersion));
        assert_eq!(parse("GET /x HTTP/0.9\r\n\r\n"), Err(HttpError::BadVersion));
    }

    #[test]
    fn rejects_upgrades() {
        assert_eq!(
            parse("GET /x HTTP/1.1\r\nUpgrade: websocket\r\n\r\n"),
            Err(HttpError::Upgrade)
        );
    }

    #[test]
    fn rejects_oversized_heads() {
        let big = format!("GET /x HTTP/1.1\r\nX: {}\r\n\r\n", "a".repeat(MAX_HEAD_LEN));
        assert_eq!(
            RequestHead::parse(big.as_bytes()),
            Err(HttpError::HeadTooLarge)
        );
    }

    #[test]
    fn rejects_too_many_headers() {
        let mut req = String::from("GET /x HTTP/1.1\r\n");
        for i in 0..=MAX_HEADERS {
            req.push_str(&format!("X-{i}: v\r\n"));
        }
        req.push_str("\r\n");
        assert_eq!(parse(&req), Err(HttpError::TooManyHeaders));
    }
}
