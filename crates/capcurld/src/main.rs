//! `capcurld` — bind a credential and a base URI to a transport endpoint.
//!
//! The daemon is started ahead of time by whoever holds the credential, and
//! binds it to an endpoint. Whoever can reach the endpoint may make the
//! requests the grant describes, and no others. There is nothing in the
//! client's reach to steal: the token lives here.

use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use capcurl_core::{build_http_client, serve_connection, DaemonConfig};
use capcurl_grant::{FixedRequest, Grant, HeaderPolicy, Injection, MethodSet};
use capsudo_transport::ownerspec::{parse_mode, parse_owner_spec};
use capsudo_transport::{Listener, UnixListener, UnixTransport};

const USAGE: &str = "\
usage: capcurld -U <base-uri> [-S <socket>] [options]

  -U <uri>       base URI this capability is bound to (required).
                 A trailing slash means a prefix, and the client names
                 what is beneath it. No trailing slash means exactly that
                 one resource, and the client's target is just '/'.
  -S <path>      listen on this Unix socket
  -1             serve one connection already present on stdin
  -X <methods>   permitted methods, comma separated (default: GET,HEAD)
  -H <hdr>       inject 'Name: value' on every request; any word
                 beginning with @ is replaced by that file's contents,
                 e.g. 'Authorization: Bearer @/run/secrets/tok' (repeatable)
  -c <policy>    client headers: none | safe | list:a,b (default: safe)
  -f <request>   pin one exact request, e.g. -f 'GET /status'
  -o <user:grp>  socket ownership
  -m <mode>      socket permission bits (default: 0600)
  -q             refuse client-supplied query strings
  -e             permit %2F and %5C inside path segments
  -t <seconds>   upstream timeout (default: 30)
  --max-request-body <bytes>
  --max-response-body <bytes>
";

fn main() -> ExitCode {
    let runtime = match tokio::runtime::Runtime::new() {
        Ok(runtime) => runtime,
        Err(e) => {
            eprintln!("capcurld: cannot start runtime: {e}");
            return ExitCode::FAILURE;
        }
    };

    match runtime.block_on(run()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("capcurld: {e}");
            ExitCode::FAILURE
        }
    }
}

/// Everything the command line can say.
struct Options {
    base: Option<String>,
    socket: Option<String>,
    one_shot: bool,
    methods: Option<String>,
    injections: Vec<String>,
    header_policy: Option<String>,
    fixed: Option<String>,
    owner: Option<String>,
    mode: Option<String>,
    allow_query: bool,
    allow_encoded_separators: bool,
    timeout: u64,
    max_request_body: Option<u64>,
    max_response_body: Option<u64>,
}

impl Default for Options {
    fn default() -> Options {
        Options {
            base: None,
            socket: None,
            one_shot: false,
            methods: None,
            injections: Vec::new(),
            header_policy: None,
            fixed: None,
            owner: None,
            mode: None,
            allow_query: true,
            allow_encoded_separators: false,
            timeout: 30,
            max_request_body: None,
            max_response_body: None,
        }
    }
}

async fn run() -> Result<(), String> {
    let options = parse_args()?;
    let grant = build_grant(&options)?;
    let config = Arc::new(DaemonConfig {
        grant,
        timeout: Duration::from_secs(options.timeout),
    });

    let client = build_http_client(config.timeout)
        .map_err(|e| format!("cannot build the upstream HTTP client: {e}"))?;

    describe(&config);

    if options.one_shot {
        let stdin = std::os::fd::OwnedFd::from(unsafe {
            <std::os::unix::net::UnixStream as std::os::fd::FromRawFd>::from_raw_fd(0)
        });
        let mut transport =
            UnixTransport::from_fd(stdin).map_err(|e| format!("stdin is not a socket: {e}"))?;
        if let Err(e) = serve_connection(&mut transport, &config, &client).await {
            eprintln!("capcurld: {e}");
        }
        return Ok(());
    }

    let socket = options
        .socket
        .as_deref()
        .ok_or("either -S <socket> or -1 is required")?;

    let (uid, gid) = match &options.owner {
        Some(spec) => parse_owner_spec(spec).ok_or("cannot parse -o owner specification")?,
        None => (None, None),
    };
    let mode = match &options.mode {
        Some(spec) => parse_mode(spec).ok_or("cannot parse -m mode")?,
        None => 0o600,
    };

    let mut listener = UnixListener::bind(socket, uid, gid, mode)
        .map_err(|e| format!("cannot bind {socket}: {e}"))?;

    loop {
        let mut transport = match listener.accept().await {
            Ok(transport) => transport,
            Err(e) => {
                eprintln!("capcurld: accept failed: {e}");
                continue;
            }
        };
        let config = Arc::clone(&config);
        let client = client.clone();
        tokio::spawn(async move {
            if let Err(e) = serve_connection(transport.as_mut(), &config, &client).await {
                // Refusals are ordinary operation, not daemon failures: an
                // operator wants to see what was attempted against a grant.
                eprintln!("capcurld: {e}");
            }
        });
    }
}

/// Assembles the grant from the parsed options.
fn build_grant(options: &Options) -> Result<Grant, String> {
    let base = options.base.as_deref().ok_or("-U <base-uri> is required")?;
    let mut grant = Grant::new(base).map_err(|e| e.to_string())?;

    if let Some(methods) = &options.methods {
        grant = grant.with_methods(MethodSet::parse(methods).map_err(|e| e.to_string())?);
    }
    for spec in &options.injections {
        grant = grant.with_injection(Injection::parse(spec).map_err(|e| e.to_string())?);
    }
    if let Some(policy) = &options.header_policy {
        grant = grant.with_header_policy(HeaderPolicy::parse(policy).map_err(|e| e.to_string())?);
    }
    if let Some(fixed) = &options.fixed {
        let (method, target) = fixed
            .split_once(' ')
            .ok_or("-f takes a method and a target, e.g. -f 'GET /status'")?;
        grant = grant.with_fixed_request(FixedRequest {
            method: method.trim().to_string(),
            target: target.trim().to_string(),
        });
    }
    grant = grant
        .with_query_allowed(options.allow_query)
        .with_encoded_separators_allowed(options.allow_encoded_separators);

    if options.max_request_body.is_some() || options.max_response_body.is_some() {
        grant = grant.with_body_limits(
            options
                .max_request_body
                .unwrap_or(capcurl_grant::DEFAULT_MAX_BODY),
            options
                .max_response_body
                .unwrap_or(capcurl_grant::DEFAULT_MAX_BODY),
        );
    }

    Ok(grant)
}

/// Prints what the endpoint grants, so an operator can see it in a log.
///
/// Injected values never appear; the names do. Knowing an endpoint carries an
/// `Authorization` is operationally necessary; knowing its value is what the
/// capability prevents.
fn describe(config: &DaemonConfig) {
    let grant = &config.grant;
    eprintln!("capcurld: bound to {} ({})", grant.base(), grant.scope());
    match grant.fixed_request() {
        Some(fixed) => eprintln!("capcurld: pinned to {} {}", fixed.method, fixed.target),
        None => eprintln!("capcurld: methods {}", grant.methods()),
    }
}

fn parse_args() -> Result<Options, String> {
    let mut options = Options::default();
    let mut args = std::env::args().skip(1);

    while let Some(arg) = args.next() {
        let mut want = |flag: &str| -> Result<String, String> {
            args.next()
                .ok_or_else(|| format!("{flag} requires an argument"))
        };
        match arg.as_str() {
            "-U" => options.base = Some(want("-U")?),
            "-S" => options.socket = Some(want("-S")?),
            "-X" => options.methods = Some(want("-X")?),
            "-H" => options.injections.push(want("-H")?),
            "-c" => options.header_policy = Some(want("-c")?),
            "-f" => options.fixed = Some(want("-f")?),
            "-o" => options.owner = Some(want("-o")?),
            "-m" => options.mode = Some(want("-m")?),
            "-t" => {
                options.timeout = want("-t")?
                    .parse()
                    .map_err(|_| "-t takes a number of seconds".to_string())?
            }
            "--max-request-body" => {
                options.max_request_body = Some(
                    want("--max-request-body")?
                        .parse()
                        .map_err(|_| "--max-request-body takes a byte count".to_string())?,
                )
            }
            "--max-response-body" => {
                options.max_response_body = Some(
                    want("--max-response-body")?
                        .parse()
                        .map_err(|_| "--max-response-body takes a byte count".to_string())?,
                )
            }
            "-1" => options.one_shot = true,
            "-q" => options.allow_query = false,
            "-e" => options.allow_encoded_separators = true,
            "-h" | "--help" => {
                print!("{USAGE}");
                std::process::exit(0);
            }
            other => return Err(format!("unknown option {other}\n\n{USAGE}")),
        }
    }

    Ok(options)
}
