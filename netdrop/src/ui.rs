//! Desktop interaction: the Accept/Reject prompt and completion toasts.
//!
//! These shell out to `zenity` (a real GTK dialog — reliable on GNOME/Wayland,
//! unlike notification action buttons) and `notify-send`. Both are treated as
//! optional: a missing tool never crashes a transfer, but a prompt that cannot
//! be shown fails safe (reject).

use std::io::Write;
use std::process::{Child, ChildStdin, Command, Stdio};

/// Ask the user whether to accept an incoming transfer.
///
/// Honors `$NETDROP_AUTO_ACCEPT=1` (accept without prompting — for headless or
/// automated use). Otherwise shows a zenity dialog; if zenity cannot run (not
/// installed, or no graphical session), the transfer is **rejected**.
pub fn prompt_accept(sender_name: &str, filename: &str, size_human: &str, is_dir: bool) -> bool {
    if std::env::var("NETDROP_AUTO_ACCEPT").is_ok_and(|v| v == "1") {
        return true;
    }

    let kind = if is_dir { "folder" } else { "file" };
    // --no-markup below renders this literally; the sender-controlled name and
    // filename are therefore safe from Pango-markup tricks.
    let text = format!(
        "\"{sender_name}\" wants to send you a {kind}:\n\n{filename}  ({size_human})\n\nAccept this transfer?"
    );

    match Command::new("zenity")
        .arg("--question")
        .args(["--title", "netdrop"])
        .args(["--text", &text])
        .args(["--ok-label", "Accept"])
        .args(["--cancel-label", "Reject"])
        .arg("--no-markup")
        .status()
    {
        Ok(status) => status.success(),
        Err(e) => {
            eprintln!("could not show Accept/Reject dialog ({e}); rejecting for safety");
            false
        }
    }
}

/// A GTK progress dialog (a `zenity --progress` child) for showing transfer
/// status on the desktop. Everything is best-effort: if zenity can't be
/// launched (headless / not installed), the handle is inert and every method is
/// a no-op, so callers never need to special-case a missing display.
///
/// Two modes: `pulsate` shows an indeterminate "working…" bar (used while a
/// sender waits to be accepted); otherwise the bar reflects `set_progress`.
pub struct Progress {
    child: Option<Child>,
    stdin: Option<ChildStdin>,
    last_percent: i32,
}

impl Progress {
    /// Open a progress dialog titled `title` with initial body `text`.
    /// `pulsate` makes it indeterminate (percentages are then ignored by zenity).
    pub fn start(title: &str, text: &str, pulsate: bool) -> Progress {
        let mut cmd = Command::new("zenity");
        cmd.arg("--progress")
            .args(["--title", title])
            .args(["--text", text])
            .args(["--width", "360"])
            .arg("--auto-close")
            .arg("--no-cancel")
            .arg("--percentage=0")
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        if pulsate {
            cmd.arg("--pulsate");
        }
        match cmd.spawn() {
            Ok(mut child) => {
                let stdin = child.stdin.take();
                Progress {
                    child: Some(child),
                    stdin,
                    last_percent: -1,
                }
            }
            Err(_) => Progress {
                child: None,
                stdin: None,
                last_percent: -1,
            },
        }
    }

    /// Update the bar from a `done`/`total` byte count (clamped to 0..=100).
    /// No-op on a pulsating or inert dialog.
    pub fn set_progress(&mut self, done: u64, total: u64) {
        if total == 0 {
            return;
        }
        let percent = ((done.min(total) as f64 / total as f64) * 100.0).round() as i32;
        if percent == self.last_percent {
            return;
        }
        self.last_percent = percent;
        if let Some(stdin) = self.stdin.as_mut() {
            // zenity reads a bare number as the new percentage.
            if writeln!(stdin, "{percent}").is_err() {
                self.stdin = None; // dialog closed; stop trying
            }
        }
    }

    /// Close the dialog (dropping stdin makes zenity exit) and reap the child.
    pub fn finish(mut self) {
        self.close();
    }

    /// Close the dialog in place (idempotent). Handy when the handle is shared
    /// behind a lock and can't be consumed by `finish`.
    pub fn close(&mut self) {
        // Dropping the stdin handle sends EOF, which closes the zenity window.
        self.stdin = None;
        if let Some(mut child) = self.child.take() {
            let _ = child.wait();
        }
    }
}

impl Drop for Progress {
    fn drop(&mut self) {
        self.close();
    }
}

/// Post a best-effort desktop notification (never fails the caller).
pub fn notify(summary: &str, body: &str) {
    let _ = Command::new("notify-send")
        .args(["--app-name", "netdrop"])
        .arg(summary)
        .arg(body)
        .status();
}
