//! netdrop — AirDrop-like wrapper around the `nsen` file-transfer engine.
//!
//! Adds LAN discovery (mDNS), a post-quantum key exchange (ML-KEM-768) that
//! removes the need for a shared password, and an Accept/Reject prompt on the
//! receiver. The actual bulk transfer is delegated to the `nsen` binary.

mod config;
mod crypto;
mod daemon;
mod discovery;
mod nsen;
mod protocol;
mod send;
mod ui;

use anyhow::{bail, Result};
use clap::{Parser, Subcommand};
use std::path::PathBuf;
use std::time::Duration;

#[derive(Parser)]
#[command(name = "netdrop", version, about = "AirDrop-like sharing built on nsen")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Run the background receiver daemon: discoverable, prompts Accept/Reject.
    Daemon,
    /// List nsen devices discovered on the local network.
    Discover {
        /// Emit machine-readable JSON.
        #[arg(long)]
        json: bool,
        /// Read from the daemon's cached device list instead of browsing live.
        #[arg(long)]
        cached: bool,
    },
    /// Send file(s) to a device identified by its id or friendly name.
    Send {
        /// Target device id or friendly name (or an IP for testing).
        target: String,
        /// One or more files/directories to send.
        #[arg(required = true)]
        paths: Vec<PathBuf>,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Daemon => daemon::run(),
        Commands::Discover { json, cached } => discover_cmd(json, cached),
        Commands::Send { target, paths } => {
            let (ip, port, label) = resolve_target(&target)?;
            for path in &paths {
                send::send_to_ip(&ip, port, path, &label)?;
            }
            Ok(())
        }
    }
}

/// How long to browse mDNS when discovering or resolving a target.
const BROWSE_TIMEOUT: Duration = Duration::from_millis(1500);

/// Print discovered devices (human-readable or JSON).
fn discover_cmd(json: bool, cached: bool) -> Result<()> {
    // `--cached` reads the running daemon's live cache over its Unix socket
    // (instant — used by the Nautilus menu). Otherwise browse mDNS live.
    let peers = if cached {
        discovery::read_cached()?
    } else {
        let exclude = config::identity().ok();
        discovery::browse(BROWSE_TIMEOUT, exclude.as_ref().map(|m| m.id.as_str()))?
    };
    if json {
        println!("{}", serde_json::to_string(&peers)?);
    } else if peers.is_empty() {
        println!("No nsen devices found.");
    } else {
        for p in &peers {
            println!("{:<24} {}  ({}:{})", p.name, p.id, p.addr, p.port);
        }
    }
    Ok(())
}

/// Resolve a send target to `(ip, control_port, label)`: accept a literal IP,
/// else match a discovered device by id or (case-insensitive) friendly name.
/// `label` is the device's friendly name when known, otherwise the raw target.
fn resolve_target(target: &str) -> Result<(String, u16, String)> {
    if target.parse::<std::net::IpAddr>().is_ok() {
        return Ok((target.to_string(), protocol::control_port(), target.to_string()));
    }
    let exclude = config::identity().ok();
    let peers = discovery::browse(BROWSE_TIMEOUT, exclude.as_ref().map(|m| m.id.as_str()))?;

    if let Some(p) = peers.iter().find(|p| p.id == target) {
        return Ok((p.addr.clone(), p.port, p.name.clone()));
    }
    let named: Vec<&discovery::Peer> = peers
        .iter()
        .filter(|p| p.name.eq_ignore_ascii_case(target))
        .collect();
    match named.as_slice() {
        [] => bail!("no nsen device matching \"{target}\" found on the network"),
        [p] => Ok((p.addr.clone(), p.port, p.name.clone())),
        _ => bail!("multiple devices named \"{target}\"; use the device id instead"),
    }
}
