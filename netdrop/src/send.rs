//! Sender side of a transfer: run the control handshake, then hand off to nsen.

use crate::protocol::{self, ControlMsg, Offer};
use crate::{config, crypto, nsen};
use anyhow::{bail, Context, Result};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use std::net::TcpStream;
use std::path::Path;
use std::time::Duration;

/// Send one path to a receiver's control endpoint at `ip:control_port`.
pub fn send_to_ip(ip: &str, control_port: u16, path: &Path) -> Result<()> {
    if !path.exists() {
        bail!("no such file or directory: {}", path.display());
    }
    let me = config::identity()?;
    let filename = path
        .file_name()
        .and_then(|s| s.to_str())
        .context("path has no valid filename")?
        .to_string();
    let is_dir = path.is_dir();
    let size = path_size(path);
    let transfer_id = config::random_hex(8);

    let addr = format!("{ip}:{control_port}");
    let mut stream =
        TcpStream::connect(&addr).with_context(|| format!("connecting to {addr}"))?;
    stream.set_read_timeout(Some(Duration::from_secs(300)))?;

    protocol::write_msg(
        &mut stream,
        &ControlMsg::Offer(Offer {
            proto: protocol::PROTO_VERSION,
            sender_name: me.name.clone(),
            sender_id: me.id.clone(),
            transfer_id: transfer_id.clone(),
            filename: filename.clone(),
            size,
            is_dir,
        }),
    )?;

    let (receiver_id, pubkey_b64) = match protocol::read_msg(&mut stream)? {
        ControlMsg::Accept {
            receiver_id,
            pubkey_b64,
        } => (receiver_id, pubkey_b64),
        ControlMsg::Reject => {
            println!("Declined by the receiver.");
            return Ok(());
        }
        ControlMsg::Busy => bail!("receiver is busy with another transfer"),
        other => bail!("unexpected reply to offer: {other:?}"),
    };

    // Encapsulate to the receiver's ephemeral public key and derive the key.
    let ek = crypto::ek_from_bytes(&B64.decode(pubkey_b64).context("bad pubkey base64")?)?;
    let (ct, ss) = crypto::encapsulate(&ek)?;
    let password = crypto::derive_password(&ss, &transfer_id, &me.id, &receiver_id);

    protocol::write_msg(
        &mut stream,
        &ControlMsg::KemCt {
            ct_b64: B64.encode(&ct),
        },
    )?;

    let data_port = match protocol::read_msg(&mut stream)? {
        ControlMsg::Ready { data_port } => data_port,
        ControlMsg::Reject => {
            println!("Declined by the receiver.");
            return Ok(());
        }
        other => bail!("expected READY, got {other:?}"),
    };

    println!("Sending {filename} \u{2192} {receiver_id} ...");
    nsen::run_send(ip, path, data_port, &password)?;

    // Best-effort final status from the receiver (ignored if it times out).
    if let Ok(ControlMsg::Done { ok, message }) = protocol::read_msg(&mut stream) {
        if !ok {
            bail!("receiver reported failure: {message}");
        }
    }
    println!("Sent {filename}.");
    crate::ui::notify("netdrop — file sent", &format!("{filename} \u{2192} {receiver_id}"));
    Ok(())
}

/// Total size of a file, or the recursive size of a directory (best effort).
fn path_size(path: &Path) -> u64 {
    if path.is_file() {
        std::fs::metadata(path).map(|m| m.len()).unwrap_or(0)
    } else if path.is_dir() {
        std::fs::read_dir(path)
            .map(|rd| rd.flatten().map(|e| path_size(&e.path())).sum())
            .unwrap_or(0)
    } else {
        0
    }
}
