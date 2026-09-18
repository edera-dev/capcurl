//! Which headers a client may set, and which the daemon supplies.

use std::collections::BTreeSet;

use crate::{sanitize, GrantError};

/// Headers a client may never set, whatever the policy.
///
/// Two kinds are listed. Framing headers (`content-length`, `transfer-encoding`,
/// `connection`, `te`, `upgrade`, `trailer`) are the daemon's to compute: a
/// client that can set them can disagree with the daemon about where its own
/// request ends, which is request smuggling. Authority headers (`host`, the
/// `proxy-*` pair, `authorization`, `cookie`) are the ones that would let a
/// client re-aim the request or supply its own credentials alongside the
/// injected one.
pub const DENIED_CLIENT_HEADERS: &[&str] = &[
    "authorization",
    "connection",
    "content-length",
    "cookie",
    "expect",
    "host",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "proxy-connection",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];

/// Which client-supplied headers reach the origin.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum HeaderPolicy {
    /// No client headers at all. The daemon's injections are the entire header
    /// set, plus whatever the HTTP client must compute.
    None,
    /// Everything except [`DENIED_CLIENT_HEADERS`]. The default.
    #[default]
    AllExceptDenied,
    /// Only these header names (lowercase), and still never a denied one.
    Allowed(BTreeSet<String>),
}

impl HeaderPolicy {
    /// Parses `none`, `safe`, or `list:accept,x-trace-id`.
    pub fn parse(spec: &str) -> Result<HeaderPolicy, GrantError> {
        match spec {
            "none" => Ok(HeaderPolicy::None),
            "safe" => Ok(HeaderPolicy::AllExceptDenied),
            other => match other.strip_prefix("list:") {
                Some(list) => {
                    let mut set = BTreeSet::new();
                    for name in list.split(',') {
                        let name = name.trim().to_ascii_lowercase();
                        if name.is_empty() {
                            continue;
                        }
                        if !name.bytes().all(crate::method::is_token_byte) {
                            return Err(GrantError::Injection("header name is not a token"));
                        }
                        set.insert(name);
                    }
                    Ok(HeaderPolicy::Allowed(set))
                }
                None => Err(GrantError::Injection(
                    "header policy must be 'none', 'safe' or 'list:a,b'",
                )),
            },
        }
    }

    /// Whether a client may set `lowercase_name`.
    pub fn permits(&self, lowercase_name: &str) -> bool {
        if DENIED_CLIENT_HEADERS.contains(&lowercase_name) {
            return false;
        }
        match self {
            HeaderPolicy::None => false,
            HeaderPolicy::AllExceptDenied => true,
            HeaderPolicy::Allowed(set) => set.contains(lowercase_name),
        }
    }
}

/// A header the daemon adds to every request — typically the credential the
/// capability exists to hold.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Injection {
    /// Header name, as it should appear on the wire.
    pub name: String,
    /// Header value.
    pub value: String,
}

impl Injection {
    /// Parses a `Name: value` specification.
    ///
    /// Any whitespace-delimited word beginning with `@` is replaced by the
    /// contents of that file, so a token need never appear in the daemon's argv
    /// where `ps` would show it. Both spellings work, and the second is the one
    /// people actually write:
    ///
    /// ```text
    /// -H 'Authorization: @/run/secrets/token'          # file holds "Bearer xyz"
    /// -H 'Authorization: Bearer @/run/secrets/token'   # file holds just "xyz"
    /// ```
    ///
    /// The file's trailing newline is trimmed. Only words *beginning* with `@`
    /// are substituted, so an address or a `key=a@b` value passes through
    /// untouched.
    pub fn parse(spec: &str) -> Result<Injection, GrantError> {
        let (name, value) = spec
            .split_once(':')
            .ok_or(GrantError::Injection("expected 'Name: value'"))?;
        let name = name.trim();
        let value = value.trim();

        if name.is_empty() || !name.bytes().all(crate::method::is_token_byte) {
            return Err(GrantError::Injection("header name is not a token"));
        }

        let value = expand_file_references(value)?;

        if !value.bytes().all(is_field_value_byte) {
            return Err(GrantError::Injection("header value has a forbidden byte"));
        }

        Ok(Injection {
            name: name.to_string(),
            value,
        })
    }

    /// Renders the injection for logging, with the value elided. Injected
    /// values are credentials; they are never logged.
    pub fn redacted(&self) -> String {
        format!("{}: <redacted>", sanitize(&self.name))
    }
}

/// Replaces every `@<path>` word in a header value with that file's contents.
///
/// A failure to read is an error rather than a passthrough. Sending the literal
/// text `@/run/secrets/token` as a credential would fail confusingly at the
/// origin, and would put a filesystem path in a request to a third party.
fn expand_file_references(value: &str) -> Result<String, GrantError> {
    if !value.split_whitespace().any(|word| word.starts_with('@')) {
        return Ok(value.to_string());
    }

    let mut out = String::with_capacity(value.len());
    for (i, word) in value.split_whitespace().enumerate() {
        if i > 0 {
            out.push(' ');
        }
        match word.strip_prefix('@') {
            Some(path) => {
                let contents = std::fs::read_to_string(path)
                    .map_err(|_| GrantError::Injection("cannot read header value file"))?;
                out.push_str(contents.trim_end_matches(['\r', '\n']));
            }
            None => out.push_str(word),
        }
    }
    Ok(out)
}

/// Visible ASCII plus SP and HTAB: RFC 9110 `field-value`, minus obs-text.
fn is_field_value_byte(b: u8) -> bool {
    b == b'\t' || (0x20..=0x7e).contains(&b)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn denied_under_every_policy() {
        for policy in [
            HeaderPolicy::None,
            HeaderPolicy::AllExceptDenied,
            HeaderPolicy::parse("list:host,authorization,content-length,accept").expect("valid"),
        ] {
            assert!(!policy.permits("host"));
            assert!(!policy.permits("authorization"));
            assert!(!policy.permits("content-length"));
            assert!(!policy.permits("transfer-encoding"));
        }
    }

    #[test]
    fn allow_list_admits_listed() {
        let policy = HeaderPolicy::parse("list:accept,x-trace-id").expect("valid");
        assert!(policy.permits("accept"));
        assert!(policy.permits("x-trace-id"));
        assert!(!policy.permits("user-agent"));
    }

    #[test]
    fn safe_policy_admits_ordinary() {
        let policy = HeaderPolicy::AllExceptDenied;
        assert!(policy.permits("accept"));
        assert!(policy.permits("user-agent"));
        assert!(policy.permits("content-type"));
    }

    #[test]
    fn parses_injections() {
        let injection = Injection::parse("Authorization: Bearer hunter2").expect("valid");
        assert_eq!(injection.name, "Authorization");
        assert_eq!(injection.value, "Bearer hunter2");
        assert_eq!(injection.redacted(), "Authorization: <redacted>");
    }

    #[test]
    fn rejects_header_splitting() {
        assert!(Injection::parse("X-Bad: a\r\nHost: evil.example").is_err());
        assert!(Injection::parse("X Bad: value").is_err());
        assert!(Injection::parse("no-colon").is_err());
    }

    #[test]
    fn reads_value_from_file() {
        let dir = std::env::temp_dir().join(format!("capcurl-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("mkdir");

        // The whole value is the file.
        let whole = dir.join("whole");
        std::fs::write(&whole, "Bearer from-file\n").expect("write");
        let injection =
            Injection::parse(&format!("Authorization: @{}", whole.display())).expect("valid");
        assert_eq!(injection.value, "Bearer from-file");

        // The file holds only the token and the scheme is written inline. This
        // is what people actually type, and it silently sent the literal path
        // before it was supported.
        let bare = dir.join("bare");
        std::fs::write(&bare, "tok3n\n").expect("write");
        let injection =
            Injection::parse(&format!("Authorization: Bearer @{}", bare.display())).expect("valid");
        assert_eq!(injection.value, "Bearer tok3n");

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn unreadable_file_ref_errors() {
        let error = Injection::parse("Authorization: Bearer @/nonexistent/token")
            .expect_err("should not send the path as a credential");
        assert_eq!(
            error,
            GrantError::Injection("cannot read header value file")
        );
    }

    #[test]
    fn leaves_bare_at_signs_alone() {
        // Only words *beginning* with @ are file references.
        let injection = Injection::parse("From: kaniini@example.com").expect("valid");
        assert_eq!(injection.value, "kaniini@example.com");
        let injection = Injection::parse("Cookie: session=a@b").expect("valid");
        assert_eq!(injection.value, "session=a@b");
    }
}
