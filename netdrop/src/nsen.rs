//! Driving the external `nsen` binary for the actual bulk transfer.

use anyhow::{bail, Context, Result};
use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use std::process::{Child, Command, Stdio};

/// Path to the nsen binary: `$NETDROP_NSEN_BIN`, else `nsen` on `PATH`.
fn nsen_bin() -> String {
    std::env::var("NETDROP_NSEN_BIN").unwrap_or_else(|_| "nsen".to_string())
}

/// Parse one `NSEN_PROGRESS <done> <total>` line into `(done, total)` bytes.
fn parse_progress(line: &str) -> Option<(u64, u64)> {
    let rest = line.trim().strip_prefix("NSEN_PROGRESS ")?;
    let mut parts = rest.split_whitespace();
    let done = parts.next()?.parse().ok()?;
    let total = parts.next()?.parse().ok()?;
    Some((done, total))
}

/// Spawn `nsen recv` in `cwd`, feed it `password` on stdin, and block until it
/// reports it is listening. Returns the still-running child (mid-receive); the
/// caller waits on it. stderr is inherited (nsen's progress bar); stdout is
/// parsed on a background thread for `NSEN_PROGRESS` lines, which are handed to
/// `on_progress(done, total)` so the caller can render a GUI bar.
pub fn spawn_recv<F>(cwd: &Path, port: u16, password: &str, mut on_progress: F) -> Result<Child>
where
    F: FnMut(u64, u64) + Send + 'static,
{
    let mut child = Command::new(nsen_bin())
        .arg("recv")
        .arg("--password-stdin")
        .arg("--progress-stdout")
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

    // Parse the rest of stdout in the background, forwarding progress updates,
    // until nsen exits (also keeps the pipe drained so nsen never blocks).
    std::thread::spawn(move || {
        let mut line = String::new();
        while reader.read_line(&mut line).unwrap_or(0) > 0 {
            if let Some((done, total)) = parse_progress(&line) {
                on_progress(done, total);
            }
            line.clear();
        }
    });

    Ok(child)
}

/// Run `nsen send <ip> <path>` to completion, feeding `password` on stdin.
/// `NSEN_PROGRESS` lines on nsen's stdout are forwarded to `on_progress(done,
/// total)`; any other stdout line is echoed through to our own stdout.
pub fn run_send<F>(
    ip: &str,
    path: &Path,
    port: u16,
    password: &str,
    mut on_progress: F,
) -> Result<()>
where
    F: FnMut(u64, u64),
{
    let mut child = Command::new(nsen_bin())
        .arg("send")
        .arg(ip)
        .arg(path)
        .arg("--password-stdin")
        .arg("--progress-stdout")
        .arg("--port")
        .arg(port.to_string())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .context("failed to spawn `nsen send`")?;

    {
        let mut stdin = child.stdin.take().context("no stdin handle for nsen send")?;
        writeln!(stdin, "{password}")?;
    }

    let stdout = child.stdout.take().context("no stdout handle for nsen send")?;
    let mut reader = BufReader::new(stdout);
    let mut line = String::new();
    while reader.read_line(&mut line)? > 0 {
        if let Some((done, total)) = parse_progress(&line) {
            on_progress(done, total);
        } else {
            print!("{line}"); // pass nsen's own chatter through to the terminal
        }
        line.clear();
    }

    let status = child.wait()?;
    if !status.success() {
        bail!("nsen send exited with {status}");
    }
    Ok(())
}
