//! `capcurl` — make the one request a capability allows.
//!
//! The client holds no credential and cannot name an origin. It reaches an
//! endpoint, mints a descriptor for one method and one target *under* that
//! endpoint's grant, and speaks ordinary HTTP/1.1 over it.
//!
//! Nothing here is privileged, and nothing here is clever: the descriptor is a
//! socket, and this binary is a demonstration that any HTTP speaker can drive
//! one.

use std::io::Write;
use std::process::ExitCode;

use capcurl_core::{mint, request_over_fd};
use capsudo_transport::UnixTransport;

const USAGE: &str = "\
usage: capcurl -S <socket> [options] [target]

  -S <path>      capability endpoint to mint from (required)
  -X <method>    request method (default: GET)
  -H <hdr>       send 'Name: value' (repeatable)
  -d <data>      request body; @<path> reads the body from a file
  -i             print response headers before the body
  -o <path>      write the body to a file instead of stdout
  -F             exit non-zero on a 4xx or 5xx response

  target         request-target relative to the capability (default: /)
";

/// Mirrors curl's exit code for `--fail`, so scripts that already handle curl
/// need no new cases.
const EXIT_HTTP_ERROR: u8 = 22;

fn main() -> ExitCode {
    let runtime = match tokio::runtime::Runtime::new() {
        Ok(runtime) => runtime,
        Err(e) => {
            eprintln!("capcurl: cannot start runtime: {e}");
            return ExitCode::FAILURE;
        }
    };

    match runtime.block_on(run()) {
        Ok(code) => ExitCode::from(code),
        Err(e) => {
            eprintln!("capcurl: {e}");
            ExitCode::FAILURE
        }
    }
}

struct Options {
    socket: Option<String>,
    method: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
    include_headers: bool,
    output: Option<String>,
    fail_on_error: bool,
    target: String,
}

impl Default for Options {
    fn default() -> Options {
        Options {
            socket: None,
            method: "GET".to_string(),
            headers: Vec::new(),
            body: Vec::new(),
            include_headers: false,
            output: None,
            fail_on_error: false,
            target: "/".to_string(),
        }
    }
}

async fn run() -> Result<u8, String> {
    let options = parse_args()?;
    let socket = options.socket.as_deref().ok_or("-S <socket> is required")?;

    let mut transport = UnixTransport::connect(socket)
        .await
        .map_err(|e| format!("cannot reach the capability at {socket}: {e}"))?;

    let capability = mint(&mut transport, &options.method, &options.target)
        .await
        .map_err(|e| e.to_string())?;

    // A pinned endpoint ignores what we asked for. Say so, rather than let the
    // caller believe the target on their command line is what was fetched.
    if capability.method != options.method || capability.target != options.target {
        eprintln!(
            "capcurl: endpoint is pinned; fetching {} {}",
            capability.method, capability.target
        );
    }

    let response = request_over_fd(
        capability.fd,
        &capability.method,
        &capability.target,
        &options.headers,
        &options.body,
    )
    .await
    .map_err(|e| e.to_string())?;

    if options.include_headers {
        let mut out = String::new();
        out.push_str(&format!(
            "HTTP/1.1 {} {}\n",
            response.status, response.reason
        ));
        for (name, value) in &response.headers {
            out.push_str(&format!("{name}: {value}\n"));
        }
        out.push('\n');
        print!("{out}");
    }

    match &options.output {
        Some(path) => {
            std::fs::write(path, &response.body).map_err(|e| format!("cannot write {path}: {e}"))?
        }
        None => {
            let mut stdout = std::io::stdout();
            stdout
                .write_all(&response.body)
                .map_err(|e| format!("cannot write to stdout: {e}"))?;
            stdout.flush().ok();
        }
    }

    // A refusal by the daemon is a policy answer, not an origin's, so it is
    // reported even without -F.
    if response.refused {
        eprintln!("capcurl: refused by the capability ({})", response.status);
        return Ok(EXIT_HTTP_ERROR);
    }
    if options.fail_on_error && response.status >= 400 {
        return Ok(EXIT_HTTP_ERROR);
    }
    Ok(0)
}

fn parse_args() -> Result<Options, String> {
    let mut options = Options::default();
    let mut args = std::env::args().skip(1);
    let mut saw_target = false;

    while let Some(arg) = args.next() {
        let mut want = |flag: &str| -> Result<String, String> {
            args.next()
                .ok_or_else(|| format!("{flag} requires an argument"))
        };
        match arg.as_str() {
            "-S" => options.socket = Some(want("-S")?),
            "-X" => options.method = want("-X")?,
            "-H" => {
                let spec = want("-H")?;
                let (name, value) = spec
                    .split_once(':')
                    .ok_or("-H takes 'Name: value'".to_string())?;
                options
                    .headers
                    .push((name.trim().to_string(), value.trim().to_string()));
            }
            "-d" => {
                let spec = want("-d")?;
                options.body = match spec.strip_prefix('@') {
                    Some(path) => std::fs::read(path)
                        .map_err(|e| format!("cannot read request body from {path}: {e}"))?,
                    None => spec.into_bytes(),
                };
            }
            "-o" => options.output = Some(want("-o")?),
            "-i" => options.include_headers = true,
            "-F" => options.fail_on_error = true,
            "-h" | "--help" => {
                print!("{USAGE}");
                std::process::exit(0);
            }
            other if other.starts_with('-') && other.len() > 1 => {
                return Err(format!("unknown option {other}\n\n{USAGE}"))
            }
            other => {
                if saw_target {
                    return Err("only one target may be given".to_string());
                }
                options.target = other.to_string();
                saw_target = true;
            }
        }
    }

    Ok(options)
}
