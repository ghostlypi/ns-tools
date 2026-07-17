//! The control channel: a small length-prefixed JSON protocol spoken between a
//! sender and a receiver daemon, separate from nsen's bulk data port.
//!
//! Framing: a 4-byte big-endian length, then that many bytes of JSON. Large
//! binary blobs (the ML-KEM public key and ciphertext) ride base64-encoded
//! inside their JSON messages.

use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};
use std::io::{Read, Write};

/// Protocol version, sent in `Offer` and checked by the receiver.
pub const PROTO_VERSION: u32 = 1;

/// Default TCP port the receiver daemon listens on for control connections.
pub const CONTROL_PORT: u16 = 4445;

/// Default nsen data port used for the bulk transfer.
pub const DATA_PORT: u16 = 4444;

/// Control port to use, overridable via `$NETDROP_CONTROL_PORT` (lets multiple
/// instances or custom setups coexist).
pub fn control_port() -> u16 {
    port_env("NETDROP_CONTROL_PORT").unwrap_or(CONTROL_PORT)
}

/// Data port for `nsen`, overridable via `$NETDROP_DATA_PORT`.
pub fn data_port() -> u16 {
    port_env("NETDROP_DATA_PORT").unwrap_or(DATA_PORT)
}

fn port_env(key: &str) -> Option<u16> {
    std::env::var(key).ok().and_then(|v| v.parse().ok())
}

/// Reject oversized frames (the largest legitimate message is the ~1.2 KB
/// public key, comfortably under this cap).
const MAX_MSG: usize = 64 * 1024;

/// Metadata describing an offered transfer, shown in the Accept/Reject prompt.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Offer {
    pub proto: u32,
    pub sender_name: String,
    pub sender_id: String,
    pub transfer_id: String,
    pub filename: String,
    pub size: u64,
    pub is_dir: bool,
}

/// Messages exchanged over the control channel (JSON-tagged by `type`).
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum ControlMsg {
    /// Sender → Receiver: opens the exchange.
    Offer(Offer),
    /// Receiver → Sender: already servicing another transfer.
    Busy,
    /// Receiver → Sender: the user declined.
    Reject,
    /// Receiver → Sender: accepted; carries the ephemeral ML-KEM public key.
    Accept {
        receiver_id: String,
        pubkey_b64: String,
    },
    /// Sender → Receiver: the ML-KEM ciphertext (encapsulated shared secret).
    KemCt { ct_b64: String },
    /// Receiver → Sender: `nsen recv` is listening; start sending.
    Ready { data_port: u16 },
    /// Either direction: final status once the transfer settles.
    Done { ok: bool, message: String },
}

/// Write one framed message.
pub fn write_msg<W: Write>(w: &mut W, msg: &ControlMsg) -> Result<()> {
    let body = serde_json::to_vec(msg)?;
    if body.len() > MAX_MSG {
        bail!("control message too large to send ({} bytes)", body.len());
    }
    w.write_all(&(body.len() as u32).to_be_bytes())?;
    w.write_all(&body)?;
    w.flush()?;
    Ok(())
}

/// Read one framed message.
pub fn read_msg<R: Read>(r: &mut R) -> Result<ControlMsg> {
    let mut len_buf = [0u8; 4];
    r.read_exact(&mut len_buf)?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > MAX_MSG {
        bail!("control message too large ({len} bytes)");
    }
    let mut body = vec![0u8; len];
    r.read_exact(&mut body)?;
    Ok(serde_json::from_slice(&body)?)
}
