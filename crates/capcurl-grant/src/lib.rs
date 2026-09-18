//! What a capcurl endpoint is allowed to reach.
//!
//! A [`Grant`] is the whole of capcurl's policy: the absolute base URI a
//! capability is bound to, the methods permitted under it, the headers the
//! daemon injects (credentials the client never sees), and the size limits.
//! Reaching the endpoint is permission to make *these* requests and no others
//! — the direct analogue of capsudo's fixed argv.
//!
//! This crate performs no I/O. It answers one question:
//!
//! > given a method and a client-supplied request-target, what absolute URL may
//! > the daemon fetch — if any?
//!
//! The answer is conservative. Every rejection in [`target`] is there because
//! the alternative is a way out of the grant.

mod header;
mod method;
mod target;

use std::collections::BTreeSet;

use url::Url;

pub use header::{HeaderPolicy, Injection, DENIED_CLIENT_HEADERS};

/// How much of the URI space a grant covers.
///
/// Decided by the base URI's trailing slash, which is the distinction people
/// already expect from a path: `…/api/v1/` is a directory and `…/api/v1/statuses`
/// is a thing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scope {
    /// Exactly one resource. The client's only valid request-target is `/`, so
    /// it names nothing at all — the daemon supplies the entire URI.
    Exact,
    /// Everything at or beneath a path prefix. The client names the part
    /// beneath it.
    Prefix,
}

impl std::fmt::Display for Scope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Scope::Exact => "exactly this resource",
            Scope::Prefix => "this prefix and below",
        })
    }
}
pub use method::MethodSet;
pub use target::{normalize_target, NormalizedTarget, TargetError, MAX_TARGET_LEN};

/// Why a request was refused. The daemon reports these to the client verbatim;
/// they describe policy, never the credential or the upstream.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Denied {
    /// The method is not in the grant's method set.
    #[error("method {0} is not permitted by this capability")]
    Method(String),
    /// The request-target was malformed or tried to leave the grant.
    #[error("request-target rejected: {0}")]
    Target(#[from] target::TargetError),
    /// A header the client is not allowed to set.
    #[error("client may not set header {0}")]
    Header(String),
    /// The request or response body exceeded the grant's cap.
    #[error("{what} body exceeds the {limit}-byte limit of this capability")]
    TooLarge {
        /// Which body: `"request"` or `"response"`.
        what: &'static str,
        /// The configured cap, in bytes.
        limit: u64,
    },
    /// The resolved URL did not land under the base URI. Defence in depth: the
    /// checks in [`target`] should make this unreachable.
    #[error("resolved URL escapes the capability's base URI")]
    Escape,
    /// The endpoint pins one exact request and this is not it.
    #[error("this capability is bound to a single fixed request")]
    NotFixedRequest,
    /// The grant names one exact resource, so `/` is the only valid target.
    #[error("this capability names one exact resource; the only valid request-target is '/'")]
    ExactResource,
}

/// One exact request an endpoint may be pinned to, the analogue of capsudo's
/// `-f`. With this set, the client's method and target are ignored entirely and
/// a compromised client can cause only the pre-approved fetch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FixedRequest {
    /// The method to use regardless of what the client asks for.
    pub method: String,
    /// The request-target to use, relative to the grant's base URI.
    pub target: String,
}

/// A URI-bound capability.
#[derive(Debug, Clone)]
pub struct Grant {
    base: Url,
    scope: Scope,
    methods: MethodSet,
    injections: Vec<Injection>,
    headers: HeaderPolicy,
    fixed: Option<FixedRequest>,
    allow_query: bool,
    allow_encoded_separators: bool,
    max_request_body: u64,
    max_response_body: u64,
}

/// Grants default to 8 MiB in either direction; enough for ordinary API work,
/// small enough that a compromised client cannot use a capability as a pump.
pub const DEFAULT_MAX_BODY: u64 = 8 * 1024 * 1024;

impl Grant {
    /// Builds a grant bound to `base`.
    ///
    /// `base` must be an absolute `http`/`https` URL with no query, fragment or
    /// userinfo.
    ///
    /// The trailing slash decides the [`Scope`]. A base of `…/api/v1/` is a
    /// prefix: the client names a resource beneath it. A base of
    /// `…/api/v1/statuses` is that one resource: the client's only valid target
    /// is `/`, and it names nothing at all.
    ///
    /// Either way the grant is anchored at a segment boundary, so a capability
    /// for `…/capcurl` never reaches `…/capcurl-evil`.
    pub fn new(base: &str) -> Result<Grant, GrantError> {
        let base = Url::parse(base).map_err(|_| GrantError::BaseUri("not a valid URL"))?;

        match base.scheme() {
            "http" | "https" => {}
            _ => return Err(GrantError::BaseUri("scheme must be http or https")),
        }
        if base.host().is_none() {
            return Err(GrantError::BaseUri("no host"));
        }
        if !base.username().is_empty() || base.password().is_some() {
            return Err(GrantError::BaseUri(
                "userinfo is not allowed; inject credentials with a header instead",
            ));
        }
        if base.query().is_some() {
            return Err(GrantError::BaseUri("query string is not allowed"));
        }
        if base.fragment().is_some() {
            return Err(GrantError::BaseUri("fragment is not allowed"));
        }

        // The trailing slash is the whole signal, so it is read rather than
        // normalized away. Forcing one would make `…/statuses` silently mean
        // `…/statuses/` — a different resource, and one the origin may not even
        // have.
        let scope = if base.path().ends_with('/') {
            Scope::Prefix
        } else {
            Scope::Exact
        };

        Ok(Grant {
            base,
            scope,
            methods: MethodSet::safe_default(),
            injections: Vec::new(),
            headers: HeaderPolicy::default(),
            fixed: None,
            allow_query: true,
            allow_encoded_separators: false,
            max_request_body: DEFAULT_MAX_BODY,
            max_response_body: DEFAULT_MAX_BODY,
        })
    }

    /// Replaces the permitted method set.
    pub fn with_methods(mut self, methods: MethodSet) -> Grant {
        self.methods = methods;
        self
    }

    /// Adds a header the daemon injects on every request. Injections are
    /// applied *after* client headers and overwrite them, so a client can never
    /// displace an injected `Authorization`.
    pub fn with_injection(mut self, injection: Injection) -> Grant {
        self.injections.push(injection);
        self
    }

    /// Replaces the policy governing which headers a client may set.
    pub fn with_header_policy(mut self, policy: HeaderPolicy) -> Grant {
        self.headers = policy;
        self
    }

    /// Pins the endpoint to one exact request (capsudo's `-f`).
    ///
    /// Pinning also narrows the method set to the pinned method. A pinned
    /// endpoint permits one request, so a wider set would misdescribe it, and
    /// requiring `-X POST` alongside `-f 'POST /x'` only produced a refusal
    /// saying POST was not permitted.
    pub fn with_fixed_request(mut self, fixed: FixedRequest) -> Grant {
        if let Some(method) = method::canonicalize(&fixed.method) {
            if let Ok(only) = MethodSet::parse(&method) {
                self.methods = only;
            }
        }
        self.fixed = Some(fixed);
        self
    }

    /// Sets whether clients may supply a query string.
    pub fn with_query_allowed(mut self, allow: bool) -> Grant {
        self.allow_query = allow;
        self
    }

    /// Permits `%2F`/`%5C` inside path segments. Off by default: some origins
    /// decode them back into separators, which would walk out of the prefix
    /// *after* this crate has approved the target.
    pub fn with_encoded_separators_allowed(mut self, allow: bool) -> Grant {
        self.allow_encoded_separators = allow;
        self
    }

    /// Sets the request and response body caps, in bytes.
    pub fn with_body_limits(mut self, request: u64, response: u64) -> Grant {
        self.max_request_body = request;
        self.max_response_body = response;
        self
    }

    /// The base URI this capability is bound to.
    pub fn base(&self) -> &Url {
        &self.base
    }

    /// Whether this grant names one resource or a prefix.
    pub fn scope(&self) -> Scope {
        self.scope
    }

    /// The fixed request, if this endpoint is pinned to one.
    pub fn fixed_request(&self) -> Option<&FixedRequest> {
        self.fixed.as_ref()
    }

    /// The permitted methods.
    pub fn methods(&self) -> &MethodSet {
        &self.methods
    }

    /// The request body cap, in bytes.
    pub fn max_request_body(&self) -> u64 {
        self.max_request_body
    }

    /// The response body cap, in bytes.
    pub fn max_response_body(&self) -> u64 {
        self.max_response_body
    }

    /// Resolves a client's method and request-target into the absolute URL the
    /// daemon may fetch.
    ///
    /// If the grant pins a fixed request, the client's arguments are discarded
    /// and the pinned ones are resolved instead.
    pub fn resolve(&self, method: &str, target: &str) -> Result<(String, Url), Denied> {
        let (method, target) = match &self.fixed {
            Some(fixed) => (fixed.method.as_str(), fixed.target.as_str()),
            None => (method, target),
        };

        let method =
            method::canonicalize(method).ok_or_else(|| Denied::Method(sanitize(method)))?;
        if !self.methods.contains(&method) {
            return Err(Denied::Method(method));
        }

        let normalized = normalize_target(target, self.allow_encoded_separators)?;
        if normalized.query.is_some() && !self.allow_query {
            return Err(Denied::Target(target::TargetError::QueryNotAllowed));
        }
        // An exact grant supplies the whole URI, so the client has nothing left
        // to name. Anything but `/` is it trying to name something anyway.
        if self.scope == Scope::Exact && !normalized.path.is_empty() {
            return Err(Denied::ExactResource);
        }

        let url = self.join(&normalized)?;
        Ok((method, url))
    }

    /// Joins a normalized target onto the base URI and re-verifies the result.
    ///
    /// The URL is assembled as text and parsed *once*, then checked against the
    /// base. Building it any other way means trusting a URL library's setters
    /// not to re-encode or re-normalize what we just validated; parsing and
    /// re-checking means any surprise it does produce is caught here rather
    /// than shipped upstream.
    fn join(&self, target: &NormalizedTarget) -> Result<Url, Denied> {
        let base_path = self.base.path();
        let mut assembled = String::with_capacity(base_path.len() + target.path.len() + 8);
        assembled.push_str(self.base.scheme());
        assembled.push_str("://");
        assembled.push_str(self.base.authority());
        assembled.push_str(base_path);
        // Under `Prefix`, `base_path` ends in `/` and `target.path` has had its
        // leading `/` stripped, so this is a plain segment-boundary
        // concatenation. Under `Exact`, `resolve` has already established that
        // `target.path` is empty and the base *is* the URI.
        assembled.push_str(&target.path);
        if let Some(query) = &target.query {
            assembled.push('?');
            assembled.push_str(query);
        }

        let url = Url::parse(&assembled).map_err(|_| Denied::Escape)?;

        // Defence in depth. Nothing above should be able to change the origin
        // or walk above the prefix; if parsing disagrees, refuse rather than
        // reason about which of us is right.
        if url.scheme() != self.base.scheme()
            || url.authority() != self.base.authority()
            || !url.path().starts_with(base_path)
        {
            return Err(Denied::Escape);
        }

        Ok(url)
    }

    /// Filters client headers and appends the grant's injections.
    ///
    /// Injections go last so they overwrite anything the client sent under the
    /// same name, and the returned list is what goes upstream verbatim.
    pub fn apply_headers(
        &self,
        client: &[(String, String)],
    ) -> Result<Vec<(String, String)>, Denied> {
        let injected: BTreeSet<String> = self
            .injections
            .iter()
            .map(|i| i.name.to_ascii_lowercase())
            .collect();

        let mut out = Vec::with_capacity(client.len() + self.injections.len());
        for (name, value) in client {
            let lower = name.to_ascii_lowercase();
            // A client may not pre-empt an injected header, whatever the
            // general policy says: that is the credential being displaced.
            if injected.contains(&lower) {
                return Err(Denied::Header(sanitize(name)));
            }
            if !self.headers.permits(&lower) {
                return Err(Denied::Header(sanitize(name)));
            }
            out.push((name.clone(), value.clone()));
        }

        for injection in &self.injections {
            out.push((injection.name.clone(), injection.value.clone()));
        }

        Ok(out)
    }
}

/// Why a grant could not be constructed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum GrantError {
    /// The base URI was unusable.
    #[error("invalid base URI: {0}")]
    BaseUri(&'static str),
    /// A header injection specification was unusable.
    #[error("invalid header injection: {0}")]
    Injection(&'static str),
    /// A method name was not a valid HTTP token.
    #[error("invalid method: {0}")]
    Method(String),
}

/// Renders untrusted text safe to put in an error string that will be logged
/// and sent back over the wire. Keeps printable ASCII, drops everything else.
pub(crate) fn sanitize(s: &str) -> String {
    let cleaned: String = s
        .chars()
        .filter(|c| c.is_ascii_graphic() || *c == ' ')
        .take(64)
        .collect();
    if cleaned.is_empty() {
        "<empty>".to_string()
    } else {
        cleaned
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn exact() -> Grant {
        Grant::new("https://social.example/api/v1/statuses")
            .expect("valid")
            .with_methods(MethodSet::parse("GET,POST").expect("valid"))
    }

    fn prefix() -> Grant {
        Grant::new("https://social.example/api/v1/")
            .expect("valid")
            .with_methods(MethodSet::parse("GET,POST").expect("valid"))
    }

    #[test]
    fn trailing_slash_sets_scope() {
        assert_eq!(exact().scope(), Scope::Exact);
        assert_eq!(prefix().scope(), Scope::Prefix);
    }

    #[test]
    fn exact_needs_no_target() {
        // The daemon supplies the whole URI; the client names nothing.
        let (method, url) = exact().resolve("POST", "/").expect("resolves");
        assert_eq!(method, "POST");
        assert_eq!(url.as_str(), "https://social.example/api/v1/statuses");
    }

    #[test]
    fn exact_refuses_other_targets() {
        for target in ["/statuses", "/12345", "/anything"] {
            assert_eq!(
                exact().resolve("GET", target),
                Err(Denied::ExactResource),
                "{target}"
            );
        }
    }

    #[test]
    fn exact_excludes_neighbours() {
        // `…/statuses` is one resource. Neither `…/statuses/1` (a child) nor
        // `…/statuses-evil` (a sibling sharing a textual prefix) is it.
        let grant = exact();
        assert!(grant.resolve("GET", "/1").is_err());
        assert!(grant.resolve("GET", "-evil").is_err());
    }

    #[test]
    fn prefix_resolves_below() {
        let (_, url) = prefix().resolve("POST", "/statuses").expect("resolves");
        assert_eq!(url.as_str(), "https://social.example/api/v1/statuses");

        let (_, url) = prefix().resolve("GET", "/statuses/42").expect("resolves");
        assert_eq!(url.as_str(), "https://social.example/api/v1/statuses/42");
    }

    #[test]
    fn exact_keeps_query() {
        let (_, url) = exact()
            .resolve("GET", "/?limit=1")
            .expect("query is not a target");
        assert_eq!(
            url.as_str(),
            "https://social.example/api/v1/statuses?limit=1"
        );
    }

    #[test]
    fn pinning_permits_its_method() {
        // Previously the pinned method was still checked against the default
        // GET,HEAD set, so `-f 'POST /statuses'` refused its own pinned request.
        let grant = prefix()
            .with_methods(MethodSet::safe_default())
            .with_fixed_request(FixedRequest {
                method: "POST".to_string(),
                target: "/statuses".to_string(),
            });

        let (method, url) = grant
            .resolve("GET", "/ignored")
            .expect("pinned request resolves");
        assert_eq!(method, "POST");
        assert_eq!(url.as_str(), "https://social.example/api/v1/statuses");
    }

    #[test]
    fn pinning_narrows_methods() {
        let grant = prefix().with_fixed_request(FixedRequest {
            method: "POST".to_string(),
            target: "/statuses".to_string(),
        });
        assert_eq!(grant.methods().to_string(), "POST");
    }
}
