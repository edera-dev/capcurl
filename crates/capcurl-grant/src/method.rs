//! The methods a grant permits.

use std::collections::BTreeSet;

/// The methods a capability allows. Read-only by default: widening a grant
/// should be a thing someone typed, not a thing they inherited.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MethodSet(BTreeSet<String>);

impl MethodSet {
    /// `GET` and `HEAD` only.
    pub fn safe_default() -> MethodSet {
        MethodSet(
            ["GET".to_string(), "HEAD".to_string()]
                .into_iter()
                .collect(),
        )
    }

    /// Builds a set from a comma-separated list such as `GET,POST`.
    pub fn parse(spec: &str) -> Result<MethodSet, crate::GrantError> {
        let mut set = BTreeSet::new();
        for raw in spec.split(',') {
            let raw = raw.trim();
            if raw.is_empty() {
                continue;
            }
            let method =
                canonicalize(raw).ok_or_else(|| crate::GrantError::Method(crate::sanitize(raw)))?;
            set.insert(method);
        }
        if set.is_empty() {
            return Err(crate::GrantError::Method("<empty>".to_string()));
        }
        Ok(MethodSet(set))
    }

    /// Whether `method` (already canonicalized) is permitted.
    pub fn contains(&self, method: &str) -> bool {
        self.0.contains(method)
    }

    /// The permitted methods, in sorted order.
    pub fn iter(&self) -> impl Iterator<Item = &str> {
        self.0.iter().map(String::as_str)
    }
}

impl std::fmt::Display for MethodSet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut first = true;
        for method in self.iter() {
            if !first {
                f.write_str(",")?;
            }
            f.write_str(method)?;
            first = false;
        }
        Ok(())
    }
}

/// Uppercases a method and verifies it is an HTTP token.
///
/// HTTP methods are case-sensitive, so uppercasing is a policy choice rather
/// than a normalization: it means a grant for `GET` cannot be slipped past with
/// `get`, at the cost of forbidding hypothetical lowercase methods. No origin
/// defines one.
pub fn canonicalize(method: &str) -> Option<String> {
    if method.is_empty() || method.len() > 32 {
        return None;
    }
    if !method.bytes().all(is_token_byte) {
        return None;
    }
    Some(method.to_ascii_uppercase())
}

/// RFC 9110 `tchar`.
pub(crate) fn is_token_byte(b: u8) -> bool {
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

    #[test]
    fn default_is_read_only() {
        let set = MethodSet::safe_default();
        assert!(set.contains("GET"));
        assert!(set.contains("HEAD"));
        assert!(!set.contains("POST"));
        assert!(!set.contains("DELETE"));
    }

    #[test]
    fn parses_list() {
        let set = MethodSet::parse("GET, POST ,PATCH").expect("valid");
        assert!(set.contains("GET") && set.contains("POST") && set.contains("PATCH"));
        assert_eq!(set.to_string(), "GET,PATCH,POST");
    }

    #[test]
    fn canonicalizes_case() {
        assert_eq!(canonicalize("get").as_deref(), Some("GET"));
        assert!(MethodSet::parse("get").expect("valid").contains("GET"));
    }

    #[test]
    fn rejects_non_tokens() {
        assert!(canonicalize("GET POST").is_none());
        assert!(canonicalize("GET\r\nX:").is_none());
        assert!(canonicalize("").is_none());
        assert!(MethodSet::parse("").is_err());
        assert!(MethodSet::parse("GET,@bad").is_err());
    }
}
