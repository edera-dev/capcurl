//! End-to-end sessions: mint a descriptor, drive one request over it.
//!
//! Every test runs twice — once over a local Unix socket with real
//! `SCM_RIGHTS`, once over the multiplexing transport that stands in for a
//! cross-zone IDM channel and *fabricates* the descriptor locally. The claim
//! capcurl inherits from capsudo is that neither side can tell which happened,
//! so the tests assert on the same outcomes for both.

mod origin;

use std::time::Duration;

use capcurl_core::{build_http_client, mint, request_over_fd, serve_connection, DaemonConfig};
use capcurl_grant::{FixedRequest, Grant, HeaderPolicy, Injection, MethodSet};
use capsudo_transport::mux::{MuxTransport, Side};
use capsudo_transport::{Transport, UnixTransport};
use nix::sys::socket::{socketpair, AddressFamily, SockFlag, SockType};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// How the capability channel is realized.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Channel {
    /// A local Unix socket: real descriptor passing.
    Local,
    /// A byte channel with simulated descriptor passing, as across a zone.
    CrossZone,
}

const BOTH: [Channel; 2] = [Channel::Local, Channel::CrossZone];

/// Builds a connected (client, daemon) transport pair.
fn channel_pair(channel: Channel) -> (Box<dyn Transport>, Box<dyn Transport>) {
    match channel {
        Channel::Local => {
            let (client, daemon) = socketpair(
                AddressFamily::Unix,
                SockType::Stream,
                None,
                SockFlag::empty(),
            )
            .expect("socketpair");
            (
                Box::new(UnixTransport::from_fd(client).expect("client transport")),
                Box::new(UnixTransport::from_fd(daemon).expect("daemon transport")),
            )
        }
        Channel::CrossZone => {
            let (client, daemon) = tokio::io::duplex(64 * 1024);
            (
                Box::new(MuxTransport::new(client, Side::Dialer)),
                Box::new(MuxTransport::new(daemon, Side::Listener)),
            )
        }
    }
}

/// The outcome of one client session.
struct Outcome {
    result: Result<capcurl_core::Response, String>,
}

/// Runs a full session: spawn the daemon on one end, drive the client on the
/// other, and return what the client saw.
async fn session(
    channel: Channel,
    grant: Grant,
    method: &str,
    target: &str,
    headers: &[(String, String)],
    body: &[u8],
) -> Outcome {
    let (mut client_transport, mut daemon_transport) = channel_pair(channel);

    let config = DaemonConfig {
        grant,
        timeout: Duration::from_secs(10),
    };
    let http = build_http_client(config.timeout).expect("http client");

    let daemon = tokio::spawn(async move {
        let _ = serve_connection(daemon_transport.as_mut(), &config, &http).await;
        // Hold the transport until the exchange is done; dropping it early
        // would tear down the mux pumps mid-flight.
        daemon_transport
    });

    let result = async {
        let capability = mint(client_transport.as_mut(), method, target)
            .await
            .map_err(|e| e.to_string())?;
        request_over_fd(
            capability.fd,
            &capability.method,
            &capability.target,
            headers,
            body,
        )
        .await
        .map_err(|e| e.to_string())
    }
    .await;

    let _ = daemon.await;
    Outcome { result }
}

/// A grant over `origin` with an injected credential, permitting reads.
fn grant_for(base: &str) -> Grant {
    Grant::new(base)
        .expect("valid base")
        .with_injection(Injection::parse("Authorization: Bearer s3cret").expect("valid injection"))
}

#[tokio::test]
async fn relays_and_injects_credential() {
    for channel in BOTH {
        let origin = origin::start(200, r#"{"ok":true}"#).await;
        let grant = grant_for(&format!("{}/repos/edera/", origin.base));

        let outcome = session(channel, grant, "GET", "/capcurl/issues", &[], b"").await;
        let response = outcome
            .result
            .unwrap_or_else(|e| panic!("{channel:?}: {e}"));

        assert_eq!(response.status, 200, "{channel:?}");
        assert_eq!(response.body, br#"{"ok":true}"#, "{channel:?}");

        let seen = origin.seen.lock().expect("lock");
        assert_eq!(seen.len(), 1, "{channel:?}");
        // The grant's base supplied the authority and the path prefix; the
        // client supplied only the part beneath it.
        assert_eq!(seen[0].method, "GET", "{channel:?}");
        assert_eq!(seen[0].target, "/repos/edera/capcurl/issues", "{channel:?}");
        assert_eq!(
            seen[0].header("authorization"),
            Some("Bearer s3cret"),
            "{channel:?}"
        );
    }
}

#[tokio::test]
async fn client_never_sees_credential() {
    for channel in BOTH {
        let origin = origin::start(200, "body").await;
        let grant = grant_for(&format!("{}/", origin.base));

        let outcome = session(channel, grant, "GET", "/", &[], b"").await;
        let response = outcome.result.expect("session");

        let rendered = format!("{:?}{:?}", response.headers, response.body);
        assert!(
            !rendered.contains("s3cret"),
            "{channel:?}: credential leaked to the client"
        );
    }
}

#[tokio::test]
async fn refuses_method_outside_grant() {
    for channel in BOTH {
        let origin = origin::start(200, "body").await;
        let grant = grant_for(&format!("{}/", origin.base));

        // The default method set is read-only, so a mint for DELETE never
        // yields a descriptor at all.
        let outcome = session(channel, grant, "DELETE", "/", &[], b"").await;
        let error = outcome.result.expect_err("should be refused");
        assert!(error.contains("DELETE"), "{channel:?}: {error}");

        assert!(origin.seen.lock().expect("lock").is_empty(), "{channel:?}");
    }
}

#[tokio::test]
async fn refuses_escaping_target() {
    for channel in BOTH {
        let origin = origin::start(200, "body").await;
        let grant = grant_for(&format!("{}/repos/edera/", origin.base));

        for escape in ["/../../etc/passwd", "/%2e%2e/secrets", "//evil.example/x"] {
            let outcome = session(channel, grant.clone(), "GET", escape, &[], b"").await;
            let error = outcome.result.expect_err("should be refused");
            assert!(
                error.contains("request-target rejected"),
                "{channel:?} {escape}: {error}"
            );
        }

        assert!(origin.seen.lock().expect("lock").is_empty(), "{channel:?}");
    }
}

#[tokio::test]
async fn pinned_ignores_client() {
    for channel in BOTH {
        let origin = origin::start(200, "pinned").await;
        let grant = grant_for(&format!("{}/", origin.base)).with_fixed_request(FixedRequest {
            method: "GET".to_string(),
            target: "/status".to_string(),
        });

        // The client asks for something else entirely and gets the pinned
        // request regardless — capsudo's `-f`, for a URI.
        let outcome = session(channel, grant, "GET", "/admin/keys", &[], b"").await;
        let response = outcome
            .result
            .unwrap_or_else(|e| panic!("{channel:?}: {e}"));
        assert_eq!(response.body, b"pinned", "{channel:?}");

        let seen = origin.seen.lock().expect("lock");
        assert_eq!(seen[0].target, "/status", "{channel:?}");
    }
}

#[tokio::test]
async fn refuses_client_authorization() {
    for channel in BOTH {
        let origin = origin::start(200, "body").await;
        let grant = grant_for(&format!("{}/", origin.base));

        let headers = vec![("Authorization".to_string(), "Bearer forged".to_string())];
        let outcome = session(channel, grant, "GET", "/", &headers, b"").await;
        let response = outcome.result.expect("session");

        assert!(response.refused, "{channel:?}");
        assert_eq!(response.status, 403, "{channel:?}");
        assert!(origin.seen.lock().expect("lock").is_empty(), "{channel:?}");
    }
}

#[tokio::test]
async fn passes_client_headers() {
    for channel in BOTH {
        let origin = origin::start(200, "body").await;
        let grant = grant_for(&format!("{}/", origin.base));

        let headers = vec![("Accept".to_string(), "application/json".to_string())];
        let outcome = session(channel, grant, "GET", "/", &headers, b"").await;
        outcome
            .result
            .unwrap_or_else(|e| panic!("{channel:?}: {e}"));

        let seen = origin.seen.lock().expect("lock");
        assert_eq!(
            seen[0].header("accept"),
            Some("application/json"),
            "{channel:?}"
        );
    }
}

#[tokio::test]
async fn relays_request_body() {
    for channel in BOTH {
        let origin = origin::start(201, "created").await;
        let grant = grant_for(&format!("{}/", origin.base))
            .with_methods(MethodSet::parse("GET,POST").expect("valid"));

        let headers = vec![("Content-Type".to_string(), "application/json".to_string())];
        let outcome = session(
            channel,
            grant,
            "POST",
            "/issues",
            &headers,
            br#"{"title":"x"}"#,
        )
        .await;
        let response = outcome
            .result
            .unwrap_or_else(|e| panic!("{channel:?}: {e}"));
        assert_eq!(response.status, 201, "{channel:?}");

        let seen = origin.seen.lock().expect("lock");
        assert_eq!(seen[0].method, "POST", "{channel:?}");
        assert_eq!(seen[0].body, br#"{"title":"x"}"#, "{channel:?}");
    }
}

#[tokio::test]
async fn passes_redirect_unfollowed() {
    for channel in BOTH {
        let origin = origin::start_with_headers(
            302,
            "",
            vec![("Location".to_string(), "http://evil.example/".to_string())],
        )
        .await;
        let grant = grant_for(&format!("{}/", origin.base));

        let outcome = session(channel, grant, "GET", "/", &[], b"").await;
        let response = outcome
            .result
            .unwrap_or_else(|e| panic!("{channel:?}: {e}"));

        // The redirect is data, not an instruction. A capability is bound to a
        // URI; letting the origin redirect out of it would let the origin widen
        // the grant.
        assert_eq!(response.status, 302, "{channel:?}");
        assert_eq!(
            response
                .headers
                .iter()
                .find(|(n, _)| n.eq_ignore_ascii_case("location"))
                .map(|(_, v)| v.as_str()),
            Some("http://evil.example/"),
            "{channel:?}"
        );
        assert_eq!(origin.seen.lock().expect("lock").len(), 1, "{channel:?}");
    }
}

#[tokio::test]
async fn enforces_response_limit() {
    for channel in BOTH {
        let origin = origin::start(200, "0123456789").await;
        let grant = grant_for(&format!("{}/", origin.base)).with_body_limits(1024, 4);

        let outcome = session(channel, grant, "GET", "/", &[], b"").await;
        let response = outcome.result.expect("session");
        assert!(response.refused, "{channel:?}");
        assert_eq!(response.status, 502, "{channel:?}");
    }
}

#[tokio::test]
async fn descriptor_serves_one_request() {
    for channel in BOTH {
        let origin = origin::start(200, "once").await;
        let grant = grant_for(&format!("{}/", origin.base));
        let (mut client_transport, mut daemon_transport) = channel_pair(channel);

        let config = DaemonConfig {
            grant,
            timeout: Duration::from_secs(10),
        };
        let http = build_http_client(config.timeout).expect("http client");
        let daemon = tokio::spawn(async move {
            let _ = serve_connection(daemon_transport.as_mut(), &config, &http).await;
            daemon_transport
        });

        let capability = mint(client_transport.as_mut(), "GET", "/")
            .await
            .expect("mint");
        let response = request_over_fd(capability.fd, "GET", "/", &[], b"")
            .await
            .expect("first request");
        assert_eq!(response.body, b"once", "{channel:?}");

        // `request_over_fd` consumed the descriptor. Minting is the only way to
        // get another, which is what makes the fd a single-use token rather
        // than a standing grant.
        let _ = daemon.await;
        assert_eq!(origin.seen.lock().expect("lock").len(), 1, "{channel:?}");
    }
}

#[tokio::test]
async fn header_policy_forbids_all() {
    for channel in BOTH {
        let origin = origin::start(200, "body").await;
        let grant = grant_for(&format!("{}/", origin.base))
            .with_header_policy(HeaderPolicy::parse("none").expect("valid"));

        let headers = vec![("Accept".to_string(), "application/json".to_string())];
        let outcome = session(channel, grant, "GET", "/", &headers, b"").await;
        let response = outcome.result.expect("session");

        assert!(response.refused, "{channel:?}");
        assert_eq!(response.status, 403, "{channel:?}");
    }
}

#[tokio::test]
async fn binding_survives_hostile_holder() {
    // The delegation story: a descriptor can be handed to an untrusted child
    // over SCM_RIGHTS. That is only safe if the binding is enforced by the
    // daemon rather than implied by the client's good behaviour — so here the
    // holder writes a request line for something else entirely, by hand, and
    // must still not get it.
    for channel in BOTH {
        let origin = origin::start(200, "body").await;
        let grant = grant_for(&format!("{}/repos/edera/", origin.base));
        let (mut client_transport, mut daemon_transport) = channel_pair(channel);

        let config = DaemonConfig {
            grant,
            timeout: Duration::from_secs(10),
        };
        let http = build_http_client(config.timeout).expect("http client");
        let daemon = tokio::spawn(async move {
            let _ = serve_connection(daemon_transport.as_mut(), &config, &http).await;
            daemon_transport
        });

        let capability = mint(client_transport.as_mut(), "GET", "/capcurl/issues")
            .await
            .expect("mint");

        // Hand-written, and not what was minted.
        let mut stream = {
            let std_stream = std::os::unix::net::UnixStream::from(capability.fd);
            std_stream.set_nonblocking(true).expect("nonblocking");
            tokio::net::UnixStream::from_std(std_stream).expect("stream")
        };
        stream
            .write_all(b"GET /admin/keys HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\n\r\n")
            .await
            .expect("write");
        stream.flush().await.expect("flush");

        let mut response = Vec::new();
        stream.read_to_end(&mut response).await.expect("read");
        let response = String::from_utf8_lossy(&response);

        assert!(
            response.starts_with("HTTP/1.1 403 "),
            "{channel:?}: {response}"
        );
        assert!(
            response.contains("X-Capcurl-Refused"),
            "{channel:?}: {response}"
        );
        assert!(
            origin.seen.lock().expect("lock").is_empty(),
            "{channel:?}: the request reached the origin"
        );

        let _ = daemon.await;
    }
}
