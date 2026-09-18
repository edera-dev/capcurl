//! The origin leg: the request the daemon makes on the client's behalf.

use std::time::Duration;

use capcurl_grant::Grant;
use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use reqwest::Client;
use url::Url;

use crate::error::{CoreError, Result};

/// Builds the HTTP client the daemon uses upstream.
///
/// Redirects are **not** followed. A `3xx` is relayed to the client as data. A
/// capability is bound to a URI, and a redirect is the origin proposing a
/// different one — following it would let the origin widen a grant that the
/// daemon's operator, not the origin, is supposed to define. The client may mint
/// a fresh capability for the new location if its grant already covers it.
pub fn build_http_client(timeout: Duration) -> std::result::Result<Client, reqwest::Error> {
    Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(timeout)
        .user_agent(concat!("capcurl/", env!("CARGO_PKG_VERSION")))
        .build()
}

/// What the origin said.
pub struct UpstreamResponse {
    /// The status code.
    pub status: u16,
    /// The reason phrase, if the origin supplied a recognizable one.
    pub reason: String,
    /// The response headers, hop-by-hop fields still present.
    pub headers: HeaderMap,
    /// The response body, already capped.
    pub body: Vec<u8>,
}

/// Performs the upstream request.
pub async fn fetch(
    client: &Client,
    grant: &Grant,
    method: &str,
    url: &Url,
    headers: &[(String, String)],
    body: Vec<u8>,
) -> Result<UpstreamResponse> {
    let method = reqwest::Method::from_bytes(method.as_bytes())
        .map_err(|_| CoreError::Upstream("unusable method".into()))?;

    let mut map = HeaderMap::new();
    for (name, value) in headers {
        let name = HeaderName::from_bytes(name.as_bytes())
            .map_err(|_| CoreError::Upstream("unusable header name".into()))?;
        let value = HeaderValue::from_str(value)
            .map_err(|_| CoreError::Upstream("unusable header value".into()))?;
        map.append(name, value);
    }

    let response = client
        .request(method, url.clone())
        .headers(map)
        .body(body)
        .send()
        .await
        .map_err(|e| CoreError::Upstream(describe(&e)))?;

    let status = response.status();
    let headers = response.headers().clone();

    // Cap before buffering: the limit exists so a capability cannot be used as
    // an unbounded pump, which means refusing to hold the bytes, not trimming
    // them after the fact. `Content-Length` is a hint, so the read below is
    // still bounded independently.
    let limit = grant.max_response_body();
    if let Some(len) = response.content_length() {
        if len > limit {
            return Err(CoreError::Denied(capcurl_grant::Denied::TooLarge {
                what: "response",
                limit,
            }));
        }
    }

    let body = read_capped(response, limit).await?;

    Ok(UpstreamResponse {
        status: status.as_u16(),
        reason: status.canonical_reason().unwrap_or("Unknown").to_string(),
        headers,
        body,
    })
}

/// Reads a response body, stopping if it exceeds `limit`.
async fn read_capped(mut response: reqwest::Response, limit: u64) -> Result<Vec<u8>> {
    let mut body: Vec<u8> = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|e| CoreError::Upstream(describe(&e)))?
    {
        if body.len() as u64 + chunk.len() as u64 > limit {
            return Err(CoreError::Denied(capcurl_grant::Denied::TooLarge {
                what: "response",
                limit,
            }));
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

/// Describes a upstream failure without leaking the URL, which may carry a
/// query the daemon would rather not repeat into a client-visible string.
fn describe(e: &reqwest::Error) -> String {
    if e.is_timeout() {
        "timed out".to_string()
    } else if e.is_connect() {
        "could not connect to the origin".to_string()
    } else if e.is_body() || e.is_decode() {
        "malformed response from the origin".to_string()
    } else {
        "request to the origin failed".to_string()
    }
}
