//! Receiver daemon: listens for control connections, prompts (later phases),
//! runs the key exchange, and drives `nsen recv`.

use crate::protocol::{self, ControlMsg};
use crate::{config, crypto, nsen, ui};
use anyhow::{bail, Context, Result};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use std::net::TcpStream;
use std::path::Path;
use std::sync::{Arc, Mutex};

/// Run the receiver daemon until interrupted. Transfers are handled one at a
/// time (nsen's data port is fixed and single-shot).
pub fn run() -> Result<()> {
    let me = config::identity()?;
    let downloads = config::downloads_dir()?;

    let control_port = protocol::control_port();
    let listener = std::net::TcpListener::bind(("0.0.0.0", control_port))
        .with_context(|| format!("binding control port {control_port}"))?;

    // Advertise over mDNS and start the continuous browse cache; keep the
    // handle alive for the daemon's lifetime.
    let (_mdns, cache) = crate::discovery::start(&me).context("mDNS setup")?;
    crate::discovery::serve_cache(cache).context("starting device-cache socket")?;

    println!(
        "netdrop daemon ready as \"{}\" ({})",
        me.name, me.id
    );
    println!("  receiving into : {}", downloads.display());
    println!("  control port   : {control_port}");
    println!("  advertising    : {}", crate::discovery::SERVICE_TYPE);
    println!("  device cache   : {}", crate::discovery::socket_path().display());

    for conn in listener.incoming() {
        match conn {
            Ok(stream) => {
                if let Err(e) = handle(stream, &me, &downloads) {
                    eprintln!("transfer error: {e:#}");
                }
            }
            Err(e) => eprintln!("accept error: {e}"),
        }
    }
    Ok(())
}

fn handle(mut stream: TcpStream, me: &config::Identity, downloads: &Path) -> Result<()> {
    let offer = match protocol::read_msg(&mut stream)? {
        ControlMsg::Offer(o) => o,
        other => bail!("expected OFFER, got {other:?}"),
    };
    if offer.proto != protocol::PROTO_VERSION {
        let _ = protocol::write_msg(&mut stream, &ControlMsg::Reject);
        bail!("unsupported protocol version {}", offer.proto);
    }

    let size_human = human_size(offer.size);
    println!(
        "Incoming: \"{}\" wants to send \"{}\" ({}){}",
        offer.sender_name,
        offer.filename,
        size_human,
        if offer.is_dir { " [directory]" } else { "" },
    );

    // Ask the user (zenity dialog, or $NETDROP_AUTO_ACCEPT).
    if !crate::ui::prompt_accept(&offer.sender_name, &offer.filename, &size_human, offer.is_dir) {
        protocol::write_msg(&mut stream, &ControlMsg::Reject)?;
        println!("Declined.");
        return Ok(());
    }

    // Ephemeral keypair; the sender encapsulates to this public key.
    let (dk, ek) = crypto::generate();
    protocol::write_msg(
        &mut stream,
        &ControlMsg::Accept {
            receiver_id: me.id.clone(),
            pubkey_b64: B64.encode(crypto::ek_to_bytes(&ek)),
        },
    )?;

    let ct = match protocol::read_msg(&mut stream)? {
        ControlMsg::KemCt { ct_b64 } => B64.decode(ct_b64).context("bad ciphertext base64")?,
        other => bail!("expected KEM_CT, got {other:?}"),
    };
    let ss = crypto::decapsulate(&dk, &ct)?;
    let password = crypto::derive_password(&ss, &offer.transfer_id, &offer.sender_id, &me.id);

    // A desktop progress bar, updated from nsen's byte-progress lines. The
    // dialog runs in its own process; we push percentages to it from the
    // background reader thread inside `spawn_recv`.
    let progress = Arc::new(Mutex::new(ui::Progress::start(
        "netdrop — receiving",
        &format!("Receiving \"{}\" from {}…", offer.filename, offer.sender_name),
        false,
    )));
    let progress_cb = progress.clone();

    // Start nsen recv into the downloads dir; wait until it is listening.
    let data_port = protocol::data_port();
    let mut child = nsen::spawn_recv(downloads, data_port, &password, move |done, total| {
        progress_cb.lock().unwrap().set_progress(done, total);
    })?;
    protocol::write_msg(&mut stream, &ControlMsg::Ready { data_port })?;

    let status = child.wait()?;
    progress.lock().unwrap().close();
    let ok = status.success();
    let message = if ok {
        format!("received {}", offer.filename)
    } else {
        format!("nsen recv exited with {status}")
    };
    let _ = protocol::write_msg(&mut stream, &ControlMsg::Done { ok, message });

    if ok {
        println!("Received \"{}\" into {}", offer.filename, downloads.display());
        crate::ui::notify(
            "netdrop — file received",
            &format!("{} from {}", offer.filename, offer.sender_name),
        );
        Ok(())
    } else {
        bail!("nsen recv failed with {status}");
    }
}

/// Render a byte count as a short human-readable string.
fn human_size(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    let mut v = bytes as f64;
    let mut u = 0;
    while v >= 1024.0 && u < UNITS.len() - 1 {
        v /= 1024.0;
        u += 1;
    }
    if u == 0 {
        format!("{bytes} B")
    } else {
        format!("{v:.1} {}", UNITS[u])
    }
}
