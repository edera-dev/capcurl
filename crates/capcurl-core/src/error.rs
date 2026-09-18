//! Errors shared by the client and daemon halves.

use capcurl_grant::Denied;
use capcurl_http::HttpError;
use capsudo_proto::ProtoError;
use capsudo_transport::TransportError;

/// A `Result` over [`CoreError`].
pub type Result<T> = std::result::Result<T, CoreError>;

/// What can go wrong in a capcurl session.
#[derive(Debug, thiserror::Error)]
pub enum CoreError {
    /// The capability channel failed.
    #[error("transport error: {0}")]
    Transport(#[from] TransportError),
    /// A malformed protocol message.
    #[error("protocol error: {0}")]
    Proto(#[from] ProtoError),
    /// Local I/O on the minted descriptor failed.
    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),
    /// The peer did not follow the mint handshake.
    #[error("{0}")]
    Handshake(String),
    /// The daemon refused to mint the capability. Carries its message verbatim.
    #[error("{0}")]
    Refused(String),
    /// The request on a minted descriptor was not valid HTTP.
    #[error("{0}")]
    Http(#[from] HttpError),
    /// The request was outside the grant.
    #[error("{0}")]
    Denied(#[from] Denied),
    /// The upstream fetch failed.
    #[error("upstream request failed: {0}")]
    Upstream(String),
}
