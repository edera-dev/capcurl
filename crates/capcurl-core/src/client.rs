//! Minting a capability descriptor.

use std::os::fd::OwnedFd;

use capsudo_proto::{FieldType, Message};
use capsudo_transport::Transport;

use crate::error::{CoreError, Result};

/// A descriptor minted for one request.
///
/// Dropping this closes the descriptor, which is all revocation amounts to: the
/// authority was the descriptor, so there is nothing else to withdraw.
pub struct MintedCapability {
    /// The socket to speak HTTP/1.1 on. Good for exactly one request.
    pub fd: OwnedFd,
    /// The method the daemon bound it to.
    pub method: String,
    /// The request-target the daemon bound it to.
    pub target: String,
}

/// Asks the daemon for a descriptor bound to `method` and `target`.
///
/// The target is relative to the endpoint's grant: a client names a resource
/// *under* the capability and can never name one beside it, because it does not
/// supply the scheme or authority at all.
///
/// If the endpoint pins a fixed request, whatever is passed here is discarded
/// and the daemon reports back what it actually bound.
pub async fn mint(
    transport: &mut dyn Transport,
    method: &str,
    target: &str,
) -> Result<MintedCapability> {
    transport.send(&Message::arg(method), &[]).await?;
    transport.send(&Message::arg(target), &[]).await?;
    transport.send(&Message::end(), &[]).await?;

    let mut bound_method = method.to_string();
    let mut bound_target = target.to_string();
    let mut args_seen = 0usize;

    loop {
        let received = transport
            .recv()
            .await?
            .ok_or_else(|| CoreError::Handshake("daemon closed the channel".into()))?;

        match received.message.field_type() {
            // The daemon reports what it bound before handing the descriptor
            // over, so a client of a pinned endpoint can see what it got.
            FieldType::Arg => {
                let value = received.message.as_str()?.to_string();
                match args_seen {
                    0 => bound_method = value,
                    1 => bound_target = value,
                    _ => return Err(CoreError::Handshake("too many bound-request args".into())),
                }
                args_seen += 1;
            }
            FieldType::Fd => {
                let mut fds = received.fds;
                if fds.len() != 1 {
                    return Err(CoreError::Handshake(format!(
                        "expected exactly one descriptor, got {}",
                        fds.len()
                    )));
                }
                return Ok(MintedCapability {
                    fd: fds.remove(0),
                    method: bound_method,
                    target: bound_target,
                });
            }
            FieldType::Error => {
                return Err(CoreError::Refused(received.message.as_str()?.to_string()));
            }
            FieldType::Unauthorized => {
                return Err(CoreError::Refused(format!(
                    "authentication required: {}",
                    received.message.as_str()?
                )));
            }
            other => {
                return Err(CoreError::Handshake(format!(
                    "unexpected {other:?} message during mint"
                )));
            }
        }
    }
}
