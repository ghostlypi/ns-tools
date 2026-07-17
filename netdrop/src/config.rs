//! Local device identity and paths.

use anyhow::{Context, Result};
use rand::RngCore;
use std::fs;
use std::path::PathBuf;

/// This device's stable id and friendly name, shown to peers.
#[derive(Clone, Debug)]
pub struct Identity {
    pub id: String,
    pub name: String,
}

/// `~/.config/nsen`, created if missing.
pub fn config_dir() -> Result<PathBuf> {
    let dir = dirs::config_dir()
        .context("cannot locate config directory")?
        .join("nsen");
    fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
    Ok(dir)
}

/// Directory incoming files land in (`~/Downloads`, falling back to `~`).
pub fn downloads_dir() -> Result<PathBuf> {
    let dir = dirs::download_dir()
        .or_else(dirs::home_dir)
        .context("cannot locate a downloads/home directory")?;
    fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
    Ok(dir)
}

/// Load (or first-time create) this device's identity.
///
/// The id is a random hex string persisted at `~/.config/nsen/device_id`.
/// The name comes from `$NETDROP_NAME`, then `~/.config/nsen/name`, then the
/// device's friendly name (the "Device Name" set in GNOME Settings).
pub fn identity() -> Result<Identity> {
    let dir = config_dir()?;

    let id_path = dir.join("device_id");
    let id = match fs::read_to_string(&id_path) {
        Ok(s) if !s.trim().is_empty() => s.trim().to_string(),
        _ => {
            let id = random_hex(16);
            fs::write(&id_path, &id).with_context(|| format!("writing {}", id_path.display()))?;
            id
        }
    };

    let name = std::env::var("NETDROP_NAME")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .or_else(|| {
            fs::read_to_string(dir.join("name"))
                .ok()
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
        })
        .unwrap_or_else(device_name);

    Ok(Identity { id, name })
}

/// The device's friendly name — the "Device Name" from GNOME Settings → About
/// (the systemd *pretty* hostname), falling back to the static hostname, then
/// `nsen-device`.
fn device_name() -> String {
    if let Some(pretty) = pretty_hostname() {
        return pretty;
    }
    fs::read_to_string("/proc/sys/kernel/hostname")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "nsen-device".to_string())
}

/// The systemd pretty hostname, if one is set. Read from `/etc/machine-info`
/// (no subprocess), falling back to `hostnamectl --pretty`.
fn pretty_hostname() -> Option<String> {
    if let Ok(content) = fs::read_to_string("/etc/machine-info") {
        for line in content.lines() {
            if let Some(v) = line.strip_prefix("PRETTY_HOSTNAME=") {
                let v = v.trim().trim_matches('"').trim();
                if !v.is_empty() {
                    return Some(v.to_string());
                }
            }
        }
    }
    let out = std::process::Command::new("hostnamectl")
        .arg("--pretty")
        .output()
        .ok()?;
    let name = String::from_utf8_lossy(&out.stdout).trim().to_string();
    (!name.is_empty()).then_some(name)
}

/// A random lowercase-hex string of `n` bytes.
pub fn random_hex(n: usize) -> String {
    let mut bytes = vec![0u8; n];
    rand::thread_rng().fill_bytes(&mut bytes);
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
