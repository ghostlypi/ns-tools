//! Typed errors.
//!
//! The CLI previously let `anyhow` chains reach the user, which meant transfer failures
//! were reported as prose ("Make sure the receiver is running and the IP address is
//! correct."). A library needs errors a caller can *match on* — and the eventual UniFFI
//! layer cannot expose `anyhow::Error` at all.

use std::path::PathBuf;

pub type Result<T> = std::result::Result<T, TransferError>;

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum TransferError {
    #[error("{0}")]
    Io(#[from] std::io::Error),

    #[error("could not connect to {addr}")]
    Connect {
        addr: String,
        #[source]
        source: std::io::Error,
    },

    #[error("could not listen on port {port}")]
    Bind {
        port: u16,
        #[source]
        source: std::io::Error,
    },

    #[error("could not read {path}")]
    ReadFile {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("could not write into {path}")]
    WriteFile {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    /// Cipher setup or finalisation failed. Carries no plaintext detail on purpose.
    #[error("cryptographic operation failed: {0}")]
    Crypto(String),

    /// The peer sent something that does not parse as a valid stream. Note that with
    /// wire v1 a *wrong password* usually lands here too, because the format has no MAC
    /// and the failure only surfaces once zstd or CBC unpadding chokes on the garbage.
    /// Phase 2's AEAD is what separates these two cases.
    #[error("malformed transfer: {0}")]
    Protocol(String),

    /// The sender supplied a filename that would escape the destination directory.
    #[error("refusing unsafe filename from sender: {0:?}")]
    UnsafeFilename(String),

    #[error("transfer cancelled")]
    Cancelled,
}

impl TransferError {
    pub(crate) fn crypto(e: impl std::fmt::Display) -> Self {
        TransferError::Crypto(e.to_string())
    }

    pub(crate) fn protocol(msg: impl Into<String>) -> Self {
        TransferError::Protocol(msg.into())
    }
}
