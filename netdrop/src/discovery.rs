//! mDNS / DNS-SD discovery of nsen devices on the local network.
//!
//! The daemon registers a `_nsen._tcp.local.` service advertising this device's
//! id, friendly name, and protocol version. Senders browse for the same service
//! type to resolve a target by id or name. The ML-KEM public key is NOT
//! advertised here (too large for TXT); it is exchanged over the control channel.

use crate::config::Identity;
use crate::protocol;
use anyhow::{Context, Result};
use mdns_sd::{ServiceDaemon, ServiceEvent, ServiceInfo};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::IpAddr;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// The DNS-SD service type nsen devices advertise and browse for.
pub const SERVICE_TYPE: &str = "_nsen._tcp.local.";

/// A discovered peer device.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Peer {
    pub id: String,
    pub name: String,
    pub addr: String,
    pub port: u16,
}

/// Live cache of discovered peers, keyed by mDNS fullname (so removals map
/// cleanly). Shared between the browse loop and the socket server.
pub type PeerCache = Arc<Mutex<HashMap<String, Peer>>>;

/// Start advertising this device and continuously browsing for others.
/// Returns the mDNS handle (keep alive) and the live peer cache.
pub fn start(me: &Identity) -> Result<(ServiceDaemon, PeerCache)> {
    let mdns = ServiceDaemon::new().context("starting mDNS daemon")?;
    register_on(&mdns, me)?;
    let cache = start_browse_loop(&mdns, me.id.clone())?;
    Ok((mdns, cache))
}

/// Register this device as an `_nsen._tcp` service on an existing daemon.
fn register_on(mdns: &ServiceDaemon, me: &Identity) -> Result<()> {
    // A stable, DNS-safe host label derived from the device id.
    let host = format!("nsen-{}.local.", &me.id[..me.id.len().min(12)]);
    let props: [(&str, &str); 4] = [
        ("v", "1"),
        ("id", &me.id),
        ("name", &me.name),
        ("kem", "mlkem768"),
    ];

    // enable_addr_auto lets mdns-sd fill in this host's interface addresses.
    let info = ServiceInfo::new(
        SERVICE_TYPE,
        &me.name,
        &host,
        "",
        protocol::control_port(),
        &props[..],
    )
    .context("building mDNS service info")?
    .enable_addr_auto();

    mdns.register(info).context("registering mDNS service")?;
    Ok(())
}

/// Spawn a background thread that browses forever, keeping `cache` current.
fn start_browse_loop(mdns: &ServiceDaemon, my_id: String) -> Result<PeerCache> {
    let receiver = mdns.browse(SERVICE_TYPE).context("starting mDNS browse")?;
    let cache: PeerCache = Arc::new(Mutex::new(HashMap::new()));
    let cache_thread = cache.clone();
    std::thread::spawn(move || {
        while let Ok(event) = receiver.recv() {
            match event {
                ServiceEvent::ServiceResolved(info) => {
                    let fullname = info.get_fullname().to_string();
                    if let Some(peer) = to_peer(&info) {
                        if peer.id != my_id {
                            cache_thread.lock().unwrap().insert(fullname, peer);
                        }
                    }
                }
                ServiceEvent::ServiceRemoved(_ty, fullname) => {
                    cache_thread.lock().unwrap().remove(&fullname);
                }
                _ => {}
            }
        }
    });
    Ok(cache)
}

/// Snapshot the cache as a sorted, id-deduplicated peer list.
pub fn snapshot(cache: &PeerCache) -> Vec<Peer> {
    let mut by_id: HashMap<String, Peer> = HashMap::new();
    for peer in cache.lock().unwrap().values() {
        by_id.insert(peer.id.clone(), peer.clone());
    }
    let mut out: Vec<Peer> = by_id.into_values().collect();
    out.sort_by_key(|p| p.name.to_lowercase());
    out
}

/// Path to the daemon's peer-cache Unix socket (override: `$NETDROP_SOCKET`).
pub fn socket_path() -> PathBuf {
    if let Ok(p) = std::env::var("NETDROP_SOCKET") {
        return PathBuf::from(p);
    }
    if let Some(dir) = dirs::runtime_dir() {
        dir.join("netdrop.sock")
    } else {
        let uid = unsafe { libc_getuid() };
        PathBuf::from(format!("/tmp/netdrop-{uid}.sock"))
    }
}

// Avoid a libc dependency just for getuid in the rare no-XDG_RUNTIME_DIR case.
extern "C" {
    #[link_name = "getuid"]
    fn libc_getuid() -> u32;
}

/// Serve the cached peer list on the Unix socket: each connection receives the
/// current snapshot as one JSON line, then the socket closes.
pub fn serve_cache(cache: PeerCache) -> Result<()> {
    let path = socket_path();
    let _ = std::fs::remove_file(&path); // clear any stale socket
    let listener = UnixListener::bind(&path)
        .with_context(|| format!("binding {}", path.display()))?;
    std::thread::spawn(move || {
        for mut stream in listener.incoming().flatten() {
            let json = serde_json::to_string(&snapshot(&cache)).unwrap_or_else(|_| "[]".into());
            let _ = stream.write_all(json.as_bytes());
        }
    });
    Ok(())
}

/// Read the peer list from the daemon's cache socket (fast; used by Nautilus).
pub fn read_cached() -> Result<Vec<Peer>> {
    let path = socket_path();
    let mut stream = UnixStream::connect(&path)
        .with_context(|| format!("netdrop daemon not reachable at {}", path.display()))?;
    let mut buf = String::new();
    stream.read_to_string(&mut buf)?;
    Ok(serde_json::from_str(&buf)?)
}

/// Browse for nsen devices for up to `timeout`, returning discovered peers
/// (excluding `exclude_id`, normally our own id).
pub fn browse(timeout: Duration, exclude_id: Option<&str>) -> Result<Vec<Peer>> {
    let mdns = ServiceDaemon::new().context("starting mDNS daemon")?;
    let receiver = mdns.browse(SERVICE_TYPE).context("starting mDNS browse")?;

    let mut peers: HashMap<String, Peer> = HashMap::new();
    let deadline = Instant::now() + timeout;
    while let Some(remaining) = deadline.checked_duration_since(Instant::now()) {
        match receiver.recv_timeout(remaining) {
            Ok(ServiceEvent::ServiceResolved(info)) => {
                if let Some(peer) = to_peer(&info) {
                    if exclude_id != Some(peer.id.as_str()) {
                        peers.insert(peer.id.clone(), peer);
                    }
                }
            }
            Ok(_) => {}
            Err(_) => break, // timed out
        }
    }
    let _ = mdns.shutdown();

    let mut out: Vec<Peer> = peers.into_values().collect();
    out.sort_by_key(|p| p.name.to_lowercase());
    Ok(out)
}

/// Convert a resolved mDNS service into a `Peer`, preferring an IPv4 address.
fn to_peer(info: &ServiceInfo) -> Option<Peer> {
    let id = info.get_property_val_str("id")?.to_string();
    let name = info
        .get_property_val_str("name")
        .map(|s| s.to_string())
        .unwrap_or_else(|| info.get_fullname().to_string());

    // Prefer a routable IPv4: drop loopback/link-local, then pick the lowest
    // address deterministically (avoids the unordered-set nondeterminism of
    // multi-homed hosts). Fall back to any address if nothing else remains.
    let mut v4: Vec<std::net::Ipv4Addr> = info
        .get_addresses()
        .iter()
        .filter_map(|a| match a {
            IpAddr::V4(v) if !v.is_loopback() && !v.is_link_local() => Some(*v),
            _ => None,
        })
        .collect();
    v4.sort();
    let addr = match v4.first() {
        Some(v) => IpAddr::V4(*v),
        None => *info.get_addresses().iter().next()?,
    };

    Some(Peer {
        id,
        name,
        addr: addr.to_string(),
        port: info.get_port(),
    })
}
