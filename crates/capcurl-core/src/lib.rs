//! capcurl's client and daemon logic.
//!
//! The shape is capsudo's, with one verb changed. A privileged daemon holds
//! something the caller must not: not the ability to run a program, but a
//! credential and the network path to one origin. It binds that to a transport
//! endpoint, and reaching the endpoint is the permission.
//!
//! What capcurl adds is a second, narrower capability *derived* from the first.
//! A client mints a descriptor for one method and one request-target; the
//! daemon resolves that against its [`Grant`](capcurl_grant::Grant) and hands
//! back a socket good for exactly that request and then closed. The descriptor
//! is an ordinary fd: it can be written by hand, driven by any HTTP speaker, or
//! passed on to a less trusted child over `SCM_RIGHTS`. It conveys no authority
//! beyond the one request it was minted for, whatever its holder writes on it.
//!
//! Everything here is written against `capsudo_transport::Transport`, so the
//! mint works identically over a local Unix socket and across an Edera zone
//! boundary. Cross-zone, the descriptor the client receives is fabricated
//! locally by the multiplexing transport and its bytes are pumped over IDM;
//! neither side can tell.

mod client;
mod daemon;
mod error;
mod exchange;
mod upstream;

pub use client::{mint, MintedCapability};
pub use daemon::{serve_connection, DaemonConfig};
pub use error::{CoreError, Result};
pub use exchange::{request_over_fd, Response};
pub use upstream::build_http_client;
