//! A throwaway origin server for the session tests.
//!
//! Speaks just enough HTTP/1.1 to record what arrived and answer it. Tests
//! assert on what the origin saw: that the credential arrived, that the path
//! was the one the grant resolved, and that nothing the client sent leaked
//! through.

use std::sync::{Arc, Mutex};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// What the origin saw.
#[derive(Debug, Clone, Default)]
pub struct SeenRequest {
    pub method: String,
    pub target: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl SeenRequest {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

/// A running origin.
pub struct Origin {
    pub base: String,
    pub seen: Arc<Mutex<Vec<SeenRequest>>>,
}

/// Starts an origin that answers every request with `status` and `body`.
pub async fn start(status: u16, body: &'static str) -> Origin {
    start_with_headers(status, body, Vec::new()).await
}

/// Starts an origin that also sends `extra` response headers.
pub async fn start_with_headers(
    status: u16,
    body: &'static str,
    extra: Vec<(String, String)>,
) -> Origin {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind origin");
    let addr = listener.local_addr().expect("origin addr");
    let seen = Arc::new(Mutex::new(Vec::new()));
    let recorded = Arc::clone(&seen);

    tokio::spawn(async move {
        loop {
            let Ok((mut socket, _)) = listener.accept().await else {
                return;
            };
            let recorded = Arc::clone(&recorded);
            let extra = extra.clone();
            tokio::spawn(async move {
                let mut buf = Vec::new();
                let head_end = loop {
                    if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                        break i + 4;
                    }
                    let mut chunk = [0u8; 4096];
                    match socket.read(&mut chunk).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => buf.extend_from_slice(&chunk[..n]),
                    }
                };

                let head = String::from_utf8_lossy(&buf[..head_end]).to_string();
                let mut lines = head.split("\r\n");
                let request_line = lines.next().unwrap_or_default();
                let mut parts = request_line.split(' ');
                let method = parts.next().unwrap_or_default().to_string();
                let target = parts.next().unwrap_or_default().to_string();

                let mut headers = Vec::new();
                let mut content_length = 0usize;
                for line in lines {
                    if line.is_empty() {
                        break;
                    }
                    if let Some((name, value)) = line.split_once(':') {
                        let (name, value) = (name.trim().to_string(), value.trim().to_string());
                        if name.eq_ignore_ascii_case("content-length") {
                            content_length = value.parse().unwrap_or(0);
                        }
                        headers.push((name, value));
                    }
                }

                let mut request_body = buf[head_end..].to_vec();
                while request_body.len() < content_length {
                    let mut chunk = [0u8; 4096];
                    match socket.read(&mut chunk).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => request_body.extend_from_slice(&chunk[..n]),
                    }
                }

                recorded.lock().expect("lock").push(SeenRequest {
                    method,
                    target,
                    headers,
                    body: request_body,
                });

                let mut response = format!("HTTP/1.1 {status} Test\r\n");
                for (name, value) in &extra {
                    response.push_str(&format!("{name}: {value}\r\n"));
                }
                response.push_str(&format!("Content-Length: {}\r\n\r\n", body.len()));
                response.push_str(body);
                let _ = socket.write_all(response.as_bytes()).await;
                let _ = socket.flush().await;
            });
        }
    });

    Origin {
        base: format!("http://127.0.0.1:{}", addr.port()),
        seen,
    }
}
