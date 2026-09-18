//! Request-target validation.
//!
//! A client names a resource relative to the capability, never absolutely: the
//! scheme and authority come from the grant, and the client supplies only an
//! origin-form target like `/issues/42?state=open`. A client that cannot spell
//! an authority cannot ask for a different one.
//!
//! Everything here rejects; there is no repair and no normalization-then-retry.
//! Every ambiguity between what this crate thinks a path means and what the
//! origin thinks it means is a way out of the grant.

/// Why a request-target was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TargetError {
    /// The target did not begin with `/` — an absolute-form or authority-form
    /// target, which would let the client choose the origin.
    #[error("must be an origin-form target beginning with '/'")]
    NotOriginForm,
    /// The target began with `//`, which many URL parsers read as the start of
    /// an authority.
    #[error("must not begin with '//'")]
    ProtocolRelative,
    /// A byte outside printable US-ASCII.
    #[error("contains a byte that is not printable US-ASCII")]
    NonAscii,
    /// A fragment, which has no business on the wire.
    #[error("must not contain a fragment")]
    Fragment,
    /// A `.` or `..` segment, encoded or otherwise.
    #[error("must not contain '.' or '..' path segments")]
    DotSegment,
    /// An empty interior segment (`//` inside the path).
    #[error("must not contain empty path segments")]
    EmptySegment,
    /// A percent-escape that was malformed.
    #[error("contains a malformed percent-escape")]
    BadEscape,
    /// An encoded `/` or `\`, which some origins decode back into separators
    /// after this crate has approved the target.
    #[error("must not contain an encoded path separator")]
    EncodedSeparator,
    /// A query string where the grant forbids one.
    #[error("this capability does not permit a query string")]
    QueryNotAllowed,
    /// The target was longer than [`MAX_TARGET_LEN`].
    #[error("longer than {MAX_TARGET_LEN} bytes")]
    TooLong,
}

/// The longest request-target accepted, in bytes.
pub const MAX_TARGET_LEN: usize = 4096;

/// A request-target that has been checked and split.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NormalizedTarget {
    /// The path, with its leading `/` removed so it can be concatenated onto a
    /// base path that ends in `/`. Percent-escapes are preserved exactly as the
    /// client sent them.
    pub path: String,
    /// The query string, without the `?`, if one was present.
    pub query: Option<String>,
}

/// Validates and splits a client-supplied request-target.
///
/// `allow_encoded_separators` permits `%2F`/`%5C` inside segments; see
/// [`Grant::with_encoded_separators_allowed`](crate::Grant::with_encoded_separators_allowed).
pub fn normalize_target(
    target: &str,
    allow_encoded_separators: bool,
) -> Result<NormalizedTarget, TargetError> {
    if target.len() > MAX_TARGET_LEN {
        return Err(TargetError::TooLong);
    }
    // Printable US-ASCII only. This forecloses NUL, CR, LF and every control
    // byte in one rule, so nothing below has to reason about request splitting.
    if !target.bytes().all(|b| (0x21..=0x7e).contains(&b)) {
        return Err(TargetError::NonAscii);
    }
    if !target.starts_with('/') {
        return Err(TargetError::NotOriginForm);
    }
    if target.starts_with("//") {
        return Err(TargetError::ProtocolRelative);
    }
    if target.contains('#') {
        return Err(TargetError::Fragment);
    }

    let (path, query) = match target.split_once('?') {
        Some((path, query)) => (path, Some(query.to_string())),
        None => (target, None),
    };

    check_path(path, allow_encoded_separators)?;
    if let Some(query) = &query {
        check_escapes(query)?;
    }

    Ok(NormalizedTarget {
        // Safe: `check_path` ran against a string starting with '/'.
        path: path[1..].to_string(),
        query,
    })
}

/// Walks the path segment by segment.
fn check_path(path: &str, allow_encoded_separators: bool) -> Result<(), TargetError> {
    check_escapes(path)?;

    // `path` starts with '/', so the first split element is always empty and is
    // not a segment. A trailing '/' likewise yields a final empty element, which
    // is a legitimate "directory" target rather than an empty segment.
    let segments: Vec<&str> = path[1..].split('/').collect();
    let last = segments.len().saturating_sub(1);

    for (i, segment) in segments.iter().enumerate() {
        if segment.is_empty() {
            // A trailing slash is fine; `//` in the middle is not.
            if i == last {
                continue;
            }
            return Err(TargetError::EmptySegment);
        }

        let decoded = percent_decode(segment)?;

        // Both the literal and the encoded spellings of a dot segment. An
        // origin that decodes before it normalizes would walk `%2e%2e` up out
        // of the prefix; refusing both spellings means we never have to know
        // which order a given origin uses.
        if decoded == b"." || decoded == b".." {
            return Err(TargetError::DotSegment);
        }

        if !allow_encoded_separators && decoded.iter().any(|b| *b == b'/' || *b == b'\\') {
            return Err(TargetError::EncodedSeparator);
        }
    }

    Ok(())
}

/// Verifies every `%` in `s` introduces a well-formed escape.
fn check_escapes(s: &str) -> Result<(), TargetError> {
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            if i + 2 >= bytes.len() {
                return Err(TargetError::BadEscape);
            }
            if !bytes[i + 1].is_ascii_hexdigit() || !bytes[i + 2].is_ascii_hexdigit() {
                return Err(TargetError::BadEscape);
            }
            i += 3;
        } else {
            i += 1;
        }
    }
    Ok(())
}

/// Decodes percent-escapes in one already-validated segment.
fn percent_decode(segment: &str) -> Result<Vec<u8>, TargetError> {
    let bytes = segment.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            if i + 2 >= bytes.len() {
                return Err(TargetError::BadEscape);
            }
            let hi = (bytes[i + 1] as char)
                .to_digit(16)
                .ok_or(TargetError::BadEscape)?;
            let lo = (bytes[i + 2] as char)
                .to_digit(16)
                .ok_or(TargetError::BadEscape)?;
            out.push(((hi << 4) | lo) as u8);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ok(target: &str) -> NormalizedTarget {
        normalize_target(target, false).expect("should be accepted")
    }

    fn err(target: &str) -> TargetError {
        normalize_target(target, false).expect_err("should be rejected")
    }

    #[test]
    fn accepts_ordinary_targets() {
        assert_eq!(ok("/").path, "");
        assert_eq!(ok("/issues").path, "issues");
        assert_eq!(ok("/issues/42/comments").path, "issues/42/comments");
        assert_eq!(ok("/issues/").path, "issues/");
    }

    #[test]
    fn splits_the_query() {
        let t = ok("/issues?state=open&per_page=10");
        assert_eq!(t.path, "issues");
        assert_eq!(t.query.as_deref(), Some("state=open&per_page=10"));
    }

    #[test]
    fn preserves_escapes() {
        // The origin, not us, decides what %20 means. Round-tripping it through
        // a decode/encode cycle is how targets quietly change meaning.
        assert_eq!(ok("/a%20b").path, "a%20b");
    }

    #[test]
    fn rejects_non_origin_form() {
        assert_eq!(err("https://evil.example/"), TargetError::NotOriginForm);
        assert_eq!(err("evil.example:443"), TargetError::NotOriginForm);
        assert_eq!(err(""), TargetError::NotOriginForm);
    }

    #[test]
    fn rejects_protocol_relative() {
        assert_eq!(err("//evil.example/x"), TargetError::ProtocolRelative);
    }

    #[test]
    fn rejects_dot_segments() {
        assert_eq!(err("/../etc"), TargetError::DotSegment);
        assert_eq!(err("/issues/../../etc"), TargetError::DotSegment);
        assert_eq!(err("/issues/./x"), TargetError::DotSegment);
        assert_eq!(err("/%2e%2e/etc"), TargetError::DotSegment);
        assert_eq!(err("/%2E%2E/etc"), TargetError::DotSegment);
        assert_eq!(err("/.%2e/etc"), TargetError::DotSegment);
        assert_eq!(err("/%2e./etc"), TargetError::DotSegment);
    }

    #[test]
    fn rejects_encoded_separators() {
        assert_eq!(err("/a%2fb"), TargetError::EncodedSeparator);
        assert_eq!(err("/a%2Fb"), TargetError::EncodedSeparator);
        assert_eq!(err("/a%5cb"), TargetError::EncodedSeparator);
        assert_eq!(
            normalize_target("/a%2fb", true)
                .expect("allowed when opted in")
                .path,
            "a%2fb"
        );
    }

    #[test]
    fn rejects_splitting_bytes() {
        assert_eq!(err("/a\r\nHost: evil.example"), TargetError::NonAscii);
        assert_eq!(err("/a\nb"), TargetError::NonAscii);
        assert_eq!(err("/a\0b"), TargetError::NonAscii);
        assert_eq!(err("/a b"), TargetError::NonAscii);
    }

    #[test]
    fn rejects_fragment_and_empty() {
        assert_eq!(err("/issues#frag"), TargetError::Fragment);
        assert_eq!(err("/issues//42"), TargetError::EmptySegment);
    }

    #[test]
    fn rejects_malformed_escapes() {
        assert_eq!(err("/a%"), TargetError::BadEscape);
        assert_eq!(err("/a%2"), TargetError::BadEscape);
        assert_eq!(err("/a%zz"), TargetError::BadEscape);
        assert_eq!(err("/a?b=%g1"), TargetError::BadEscape);
    }

    #[test]
    fn rejects_overlong_target() {
        let long = format!("/{}", "a".repeat(MAX_TARGET_LEN));
        assert_eq!(err(&long), TargetError::TooLong);
    }
}
