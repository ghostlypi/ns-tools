//! Driving the external `nsen` binary for the actual bulk transfer.

use anyhow::{bail, Context, Result};
use std::io::{BufRead, BufReader, Read, Write};
use std::path::Path;
use std::process::{Child, Command, Stdio};

/// Path to the nsen binary: `$NETDROP_NSEN_BIN`, else `nsen` on `PATH`.
fn nsen_bin() -> String {
    std::env::var("NETDROP_NSEN_BIN").unwrap_or_else(|_| "nsen".to_string())
}

/// Spawn `nsen recv` in `cwd`, feed it `password` on stdin, and block until it
/// reports it is listening. Returns the still-running child (mid-receive); the
/// caller waits on it. stderr is inherited (nsen's progress bar); stdout is
/// drained on a background thread so nsen never blocks on a full pipe.
pub fn spawn_recv(cwd: &Path, port: u16, password: &str) -> Result<Child> {
    let mut child = Command::new(nsen_bin())
        .arg("recv")
        .arg("--password-stdin")
        .arg("--port")
        .arg(port.to_string())
        .current_dir(cwd)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .context("failed to spawn `nsen recv` (is nsen installed, or NETDROP_NSEN_BIN set?)")?;

    // nsen reads the password before printing its readiness line, so feed it first.
    {
        let mut stdin = child.stdin.take().context("no stdin handle for nsen recv")?;
        writeln!(stdin, "{password}")?;
    } // dropping stdin closes it (EOF for nsen)

    let stdout = child.stdout.take().context("no stdout handle for nsen recv")?;
    let mut reader = BufReader::new(stdout);
    let mut line = String::new();
    loop {
        line.clear();
        if reader.read_line(&mut line)? == 0 {
            let _ = child.wait();
            bail!("nsen recv exited before it started listening");
        }
        if line.contains("Waiting for connection") {
            break;
        }
    }

    // Drain the rest of stdout in the background until nsen exits.
    std::thread::spawn(move || {
        let mut sink = Vec::new();
        let _ = reader.read_to_end(&mut sink);
    });

    Ok(child)
}

/// Run `nsen send <ip> <path>` to completion, feeding `password` on stdin.
pub fn run_send(ip: &str, path: &Path, port: u16, password: &str) -> Result<()> {
    let mut child = Command::new(nsen_bin())
        .arg("send")
        .arg(ip)
        .arg(path)
        .arg("--password-stdin")
        .arg("--port")
        .arg(port.to_string())
        .stdin(Stdio::piped())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()
        .context("failed to spawn `nsen send`")?;

    {
        let mut stdin = child.stdin.take().context("no stdin handle for nsen send")?;
        writeln!(stdin, "{password}")?;
    }

    let status = child.wait()?;
    if !status.success() {
        bail!("nsen send exited with {status}");
    }
    Ok(())
}
