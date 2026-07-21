//! Sender side of a transfer: run the control handshake, then hand off to nsen.

use crate::protocol::{self, ControlMsg, Offer};
use crate::{config, crypto, nsen};
use anyhow::{bail, Context, Result};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use std::net::TcpStream;
use std::path::Path;
use std::time::Duration;

/// Send one path to a receiver's control endpoint at `ip:control_port`.
/// `label` is a human-friendly name for the receiver (shown in the dialogs).
pub fn send_to_ip(ip: &str, control_port: u16, path: &Path, label: &str) -> Result<()> {
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

    // Waiting for the receiver to tap Accept/Reject: show an indeterminate
    // "not accepted yet" dialog (and a terminal line) until a reply arrives.
    println!("Waiting for {label} to accept \u{201c}{filename}\u{201d}…");
    let waiting = crate::ui::Progress::start(
        "netdrop — waiting",
        &format!("Waiting for {label} to accept \u{201c}{filename}\u{201d}…"),
        true,
    );

    let reply = protocol::read_msg(&mut stream);
    waiting.finish();
    let (receiver_id, pubkey_b64) = match reply? {
        ControlMsg::Accept {
            receiver_id,
            pubkey_b64,
        } => (receiver_id, pubkey_b64),
        ControlMsg::Reject => {
            println!("Declined by the receiver.");
            crate::ui::notify("netdrop — declined", &format!("{label} declined {filename}"));
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

    println!("Sending {filename} \u{2192} {label} ...");
    let mut progress = crate::ui::Progress::start(
        "netdrop — sending",
        &format!("Sending \u{201c}{filename}\u{201d} to {label}…"),
        false,
    );
    let send_result = nsen::run_send(ip, path, data_port, &password, |done, total| {
        progress.set_progress(done, total);
    });
    progress.finish();
    send_result?;

    // Best-effort final status from the receiver (ignored if it times out).
    if let Ok(ControlMsg::Done { ok, message }) = protocol::read_msg(&mut stream) {
        if !ok {
            bail!("receiver reported failure: {message}");
        }
    }
    println!("Sent {filename}.");
    crate::ui::notify("netdrop — file sent", &format!("{filename} \u{2192} {label}"));
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
