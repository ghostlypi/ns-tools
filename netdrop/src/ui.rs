//! Desktop interaction: the Accept/Reject prompt and completion toasts.
//!
//! These shell out to `zenity` (a real GTK dialog — reliable on GNOME/Wayland,
//! unlike notification action buttons) and `notify-send`. Both are treated as
//! optional: a missing tool never crashes a transfer, but a prompt that cannot
//! be shown fails safe (reject).

use std::process::Command;

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

/// Post a best-effort desktop notification (never fails the caller).
pub fn notify(summary: &str, body: &str) {
    let _ = Command::new("notify-send")
        .args(["--app-name", "netdrop"])
        .arg(summary)
        .arg(body)
        .status();
}
