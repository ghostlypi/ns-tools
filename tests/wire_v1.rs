//! End-to-end round-trip tests for the wire-v1 transfer format.
//!
//! These drive the real `nsen` binary over loopback, so they pin the *observable*
//! behaviour of the whole pipeline — header framing, PBKDF2, AES-256-CBC, zstd, tar,
//! and the on-disk layout — without depending on any internal API. That matters because
//! the engine is about to be extracted into a library (roadmap Phase 1) and reimplemented
//! on RustCrypto (Phase 2); everything asserted here must survive both.
//!
//! Note that byte-for-byte golden vectors of the full stream are *impossible*: the
//! sender calls `zstd_encoder.multithread(num_cpus::get())`, so the compressed bytes
//! depend on the machine's core count. Layer-boundary known-answer tests live in
//! `src/main.rs`'s `mod tests`; this file covers the layers above them.

use std::io::{BufRead, BufReader, Read, Write};
use std::path::Path;
use std::process::{Child, Command, Stdio};

fn nsen() -> &'static str {
    env!("CARGO_BIN_EXE_nsen")
}

/// Start `nsen recv` in `dir` and block until it is actually listening.
///
/// Readiness is detected the same way netdrop does it today (`netdrop/src/nsen.rs:59`):
/// by waiting for the "Waiting for connection" line on stdout. Connecting before that
/// line appears is a race.
fn start_recv(dir: &Path, port: u16, password: &str) -> Child {
    let mut child = Command::new(nsen())
        .args(["recv", "--password-stdin", "--port", &port.to_string()])
        .current_dir(dir)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn nsen recv");

    {
        let mut stdin = child.stdin.take().expect("recv stdin");
        writeln!(stdin, "{password}").expect("write password");
    } // drop closes stdin, which nsen reads as EOF

    let stdout = child.stdout.as_mut().expect("recv stdout");
    let mut reader = BufReader::new(stdout);
    let mut line = String::new();
    loop {
        line.clear();
        let n = reader.read_line(&mut line).expect("read recv stdout");
        assert!(n > 0, "nsen recv exited before it started listening");
        if line.contains("Waiting for connection") {
            return child;
        }
    }
}

/// Run `nsen send` to completion and return whether it succeeded.
fn run_send(port: u16, path: &Path, password: &str) -> bool {
    let mut child = Command::new(nsen())
        .arg("send")
        .arg("127.0.0.1")
        .arg(path)
        .args(["--password-stdin", "--port", &port.to_string()])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn nsen send");

    {
        let mut stdin = child.stdin.take().expect("send stdin");
        writeln!(stdin, "{password}").expect("write password");
    }

    child.wait().expect("wait for send").success()
}

/// Send `src` to a fresh receiving directory. Returns (receiver dir, both exit statuses).
fn transfer(port: u16, src: &Path, password: &str) -> (tempfile::TempDir, bool, bool) {
    transfer_with_passwords(port, src, password, password)
}

fn transfer_with_passwords(
    port: u16,
    src: &Path,
    send_password: &str,
    recv_password: &str,
) -> (tempfile::TempDir, bool, bool) {
    let dest = tempfile::tempdir().expect("tempdir");
    let mut recv = start_recv(dest.path(), port, recv_password);
    let sent_ok = run_send(port, src, send_password);
    let recv_ok = recv.wait().expect("wait for recv").success();
    (dest, sent_ok, recv_ok)
}

fn write_file(path: &Path, bytes: &[u8]) {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).expect("mkdir -p");
    }
    std::fs::write(path, bytes).expect("write file");
}

/// Deterministic pseudo-random bytes — compressible enough to be quick, varied enough
/// that a truncation or an off-by-one shows up.
fn payload(len: usize) -> Vec<u8> {
    (0..len).map(|i| ((i * 7 + i / 251) % 251) as u8).collect()
}

// ---------------------------------------------------------------------------
// Single-file fast path
// ---------------------------------------------------------------------------

#[test]
fn single_file_roundtrip() {
    let src = tempfile::tempdir().unwrap();
    let file = src.path().join("hello.txt");
    let content = b"the quick brown fox\n";
    write_file(&file, content);

    let (dest, sent, received) = transfer(45001, &file, "correct horse");
    assert!(sent && received, "transfer should succeed");
    assert_eq!(
        std::fs::read(dest.path().join("hello.txt")).unwrap(),
        content
    );
}

#[test]
fn empty_file_roundtrip() {
    let src = tempfile::tempdir().unwrap();
    let file = src.path().join("empty.bin");
    write_file(&file, b"");

    let (dest, sent, received) = transfer(45002, &file, "pw");
    assert!(sent && received);
    assert_eq!(std::fs::read(dest.path().join("empty.bin")).unwrap(), b"");
}

/// Crosses `BUFFER_SIZE` (256 KiB), so the copy loop runs more than one iteration.
#[test]
fn file_larger_than_buffer_roundtrip() {
    let src = tempfile::tempdir().unwrap();
    let file = src.path().join("big.bin");
    let content = payload(300 * 1024);
    write_file(&file, &content);

    let (dest, sent, received) = transfer(45003, &file, "pw");
    assert!(sent && received);
    assert_eq!(std::fs::read(dest.path().join("big.bin")).unwrap(), content);
}

#[test]
fn unicode_and_spaces_in_filename() {
    let src = tempfile::tempdir().unwrap();
    let name = "café ☕ report (final).txt";
    let file = src.path().join(name);
    write_file(&file, b"unicode filename");

    let (dest, sent, received) = transfer(45004, &file, "pw");
    assert!(sent && received);
    assert_eq!(
        std::fs::read(dest.path().join(name)).unwrap(),
        b"unicode filename"
    );
}

// ---------------------------------------------------------------------------
// Directory / tar path
// ---------------------------------------------------------------------------

#[test]
fn directory_roundtrip_preserves_tree() {
    let src = tempfile::tempdir().unwrap();
    let root = src.path().join("bundle");
    write_file(&root.join("a.txt"), b"alpha");
    write_file(&root.join("nested/b.txt"), b"bravo");
    write_file(&root.join("nested/deep/c.bin"), &payload(100_000));

    let (dest, sent, received) = transfer(45005, &root, "pw");
    assert!(sent && received);

    // Sender tars entries as `<dir_name>/<relative>`, so the tree lands under `bundle/`.
    let out = dest.path().join("bundle");
    assert_eq!(std::fs::read(out.join("a.txt")).unwrap(), b"alpha");
    assert_eq!(std::fs::read(out.join("nested/b.txt")).unwrap(), b"bravo");
    assert_eq!(
        std::fs::read(out.join("nested/deep/c.bin")).unwrap(),
        payload(100_000)
    );
}

#[cfg(unix)]
#[test]
fn directory_roundtrip_preserves_modes() {
    use std::os::unix::fs::PermissionsExt;

    let src = tempfile::tempdir().unwrap();
    let root = src.path().join("modes");
    let script = root.join("run.sh");
    write_file(&script, b"#!/bin/sh\necho hi\n");
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
    write_file(&root.join("plain.txt"), b"data");

    let (dest, sent, received) = transfer(45006, &root, "pw");
    assert!(sent && received);

    let mode = std::fs::metadata(dest.path().join("modes/run.sh"))
        .unwrap()
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(mode, 0o755, "executable bit should survive the tar round-trip");
}

/// A file above `MAX_FILE_BUFFER_SIZE` (16 MiB) takes the `FileEntry::Streamed` branch
/// instead of `Buffered`. Only one of those two branches is exercised by a casual test,
/// and they are separate code paths in `file_reader_worker`.
#[test]
fn large_file_takes_streamed_branch() {
    let src = tempfile::tempdir().unwrap();
    let root = src.path().join("heavy");
    let content = payload(17 * 1024 * 1024);
    write_file(&root.join("large.bin"), &content);
    write_file(&root.join("small.txt"), b"buffered sibling");

    let (dest, sent, received) = transfer(45007, &root, "pw");
    assert!(sent && received);

    let got = std::fs::read(dest.path().join("heavy/large.bin")).unwrap();
    assert_eq!(got.len(), content.len(), "streamed file truncated");
    assert_eq!(got, content);
    assert_eq!(
        std::fs::read(dest.path().join("heavy/small.txt")).unwrap(),
        b"buffered sibling"
    );
}

// ---------------------------------------------------------------------------
// Failure modes
// ---------------------------------------------------------------------------

/// A wrong password must fail rather than writing garbage.
///
/// Wire v1 has no MAC, so the failure surfaces deep in zstd or CBC unpadding rather
/// than as "bad password". Phase 2's AEAD is what turns this into a clean, immediate
/// error — this test documents today's behaviour so the improvement is visible.
#[test]
fn wrong_password_does_not_produce_a_valid_file() {
    let src = tempfile::tempdir().unwrap();
    let file = src.path().join("secret.txt");
    write_file(&file, &payload(50_000));

    let (dest, _sent, received) = transfer_with_passwords(45008, &file, "right", "wrong");
    assert!(!received, "receiver must not report success on a bad password");

    // If anything was written at all, it must not be the plaintext.
    if let Ok(got) = std::fs::read(dest.path().join("secret.txt")) {
        assert_ne!(got, payload(50_000), "decrypted with the wrong password!");
    }
}

/// A sender that hangs up mid-stream must not leave a receiver reporting success.
#[test]
fn truncated_stream_is_rejected() {
    use std::net::TcpStream;

    let dest = tempfile::tempdir().unwrap();
    let mut recv = start_recv(dest.path(), 45009, "pw");

    // Valid-looking header, then an abrupt disconnect: 16-byte salt, u64 size,
    // type=0 (single file), u32 name length, name — then nothing.
    {
        let mut sock = TcpStream::connect(("127.0.0.1", 45009)).expect("connect");
        sock.write_all(&[0u8; 16]).unwrap();
        sock.write_all(&1_000_000u64.to_be_bytes()).unwrap();
        sock.write_all(&[0u8]).unwrap();
        let name = b"truncated.bin";
        sock.write_all(&(name.len() as u32).to_be_bytes()).unwrap();
        sock.write_all(name).unwrap();
        sock.write_all(&[0xab; 64]).unwrap(); // a little ciphertext-shaped garbage
    } // drop closes the connection

    let ok = recv.wait().expect("wait for recv").success();
    assert!(!ok, "receiver must fail on a truncated stream");
}

/// Regression guard for the path-traversal fix.
///
/// The wire filename is attacker-controlled and the receiver writes it relative to its
/// working directory — `~/Downloads` under netdrop. A malicious sender that gets an
/// Accept must not be able to reach `../`. The unit tests in `src/main.rs` cover the
/// sanitizer itself; this drives it over a real socket to prove it is actually wired in
/// at the parse site.
#[test]
fn traversal_filename_never_escapes_the_destination() {
    use std::net::TcpStream;

    let jail = tempfile::tempdir().unwrap();
    let dest = jail.path().join("downloads");
    std::fs::create_dir_all(&dest).unwrap();
    let canary = jail.path().join("escaped.txt");

    let mut recv = start_recv(&dest, 45010, "pw");

    {
        let mut sock = TcpStream::connect(("127.0.0.1", 45010)).expect("connect");
        sock.write_all(&[0u8; 16]).unwrap();
        sock.write_all(&64u64.to_be_bytes()).unwrap();
        sock.write_all(&[0u8]).unwrap();
        let name = b"../escaped.txt";
        sock.write_all(&(name.len() as u32).to_be_bytes()).unwrap();
        sock.write_all(name).unwrap();
        sock.write_all(&[0xab; 64]).unwrap();
    }

    let _ = recv.wait();
    assert!(
        !canary.exists(),
        "sender escaped the destination directory: {} was created",
        canary.display()
    );
}

// ---------------------------------------------------------------------------
// External oracle
// ---------------------------------------------------------------------------

fn have(tool: &str) -> bool {
    Command::new(tool)
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Decode a captured stream with three *independent* implementations — the `openssl`,
/// `zstd`, and `tar` CLIs — rather than with our own code.
///
/// This is what proves the format is what we believe it is, instead of merely
/// self-consistent. Skipped if the tools are missing.
#[test]
fn stream_decodes_with_external_tools() {
    if !(have("openssl") && have("zstd") && have("tar")) {
        eprintln!("skipping: openssl/zstd/tar not all available");
        return;
    }

    use std::net::TcpListener;

    let src = tempfile::tempdir().unwrap();
    let root = src.path().join("oracle");
    write_file(&root.join("one.txt"), b"first");
    write_file(&root.join("sub/two.txt"), b"second");

    // Capture the raw stream instead of running a real receiver.
    let listener = TcpListener::bind(("127.0.0.1", 45011)).expect("bind");
    let sender = std::thread::spawn(move || run_send(45011, &root, "oracle-pw"));
    let (mut sock, _) = listener.accept().expect("accept");
    let mut stream = Vec::new();
    sock.read_to_end(&mut stream).expect("read stream");
    assert!(sender.join().unwrap(), "send should succeed");

    // Header: salt[16] || size[8] || type[1]. Directory transfers carry no filename.
    let salt = &stream[..16];
    assert_eq!(stream[24], 1, "expected TRANSFER_TYPE_DIRECTORY");
    let ciphertext = &stream[25..];

    let work = tempfile::tempdir().unwrap();
    let ct_path = work.path().join("payload.bin");
    std::fs::write(&ct_path, ciphertext).unwrap();

    // Derive the same key/IV the way OpenSSL would, then decrypt + decompress + list.
    let salt_hex: String = salt.iter().map(|b| format!("{b:02x}")).collect();
    let kdf = Command::new("openssl")
        .args(["kdf", "-keylen", "48", "-kdfopt", "digest:SHA2-256"])
        .args(["-kdfopt", "pass:oracle-pw"])
        .arg("-kdfopt")
        .arg(format!("hexsalt:{salt_hex}"))
        .args(["-kdfopt", "iter:10000", "PBKDF2"])
        .output()
        .expect("openssl kdf");
    let key_iv = String::from_utf8_lossy(&kdf.stdout)
        .trim()
        .replace(':', "")
        .to_lowercase();
    let (key, iv) = key_iv.split_at(64);

    let listing = Command::new("sh")
        .arg("-c")
        .arg(format!(
            "openssl enc -d -aes-256-cbc -K {key} -iv {iv} -in {} | zstd -d | tar -t",
            ct_path.display()
        ))
        .output()
        .expect("decode pipeline");

    let files = String::from_utf8_lossy(&listing.stdout);
    assert!(
        listing.status.success(),
        "external decode failed: {}",
        String::from_utf8_lossy(&listing.stderr)
    );
    assert!(files.contains("oracle/one.txt"), "got listing: {files}");
    assert!(files.contains("oracle/sub/two.txt"), "got listing: {files}");
}

// ---------------------------------------------------------------------------
// Metadata: mtimes, empty directories, symlinks
// ---------------------------------------------------------------------------

#[cfg(unix)]
fn set_mtime(path: &Path, secs: u64) {
    let t = std::time::UNIX_EPOCH + std::time::Duration::from_secs(secs);
    std::fs::File::open(path).unwrap().set_modified(t).unwrap();
}

#[cfg(unix)]
fn mtime(path: &Path) -> u64 {
    std::fs::symlink_metadata(path)
        .unwrap()
        .modified()
        .unwrap()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// Before this was fixed every received file was stamped 1970-01-01.
#[cfg(unix)]
#[test]
fn directory_roundtrip_preserves_mtimes() {
    let src = tempfile::tempdir().unwrap();
    let root = src.path().join("dated");
    write_file(&root.join("small.txt"), b"tiny");
    write_file(&root.join("sub/big.bin"), &payload(17 * 1024 * 1024)); // streamed branch
    set_mtime(&root.join("small.txt"), 1_600_000_000);
    set_mtime(&root.join("sub/big.bin"), 1_650_000_000);
    // Directory mtimes last: writing children bumps the parent's.
    set_mtime(&root.join("sub"), 1_700_000_000);
    set_mtime(&root, 1_710_000_000);

    let (dest, sent, received) = transfer(45012, &root, "pw");
    assert!(sent && received);

    let out = dest.path().join("dated");
    assert_eq!(mtime(&out.join("small.txt")), 1_600_000_000);
    assert_eq!(mtime(&out.join("sub/big.bin")), 1_650_000_000);
    assert_eq!(mtime(&out.join("sub")), 1_700_000_000);
    assert_eq!(mtime(&out), 1_710_000_000);
}

#[test]
fn empty_directories_survive() {
    let src = tempfile::tempdir().unwrap();
    let root = src.path().join("hollow");
    std::fs::create_dir_all(root.join("empty")).unwrap();
    std::fs::create_dir_all(root.join("a/b/also-empty")).unwrap();
    write_file(&root.join("a/file.txt"), b"x");

    let (dest, sent, received) = transfer(45013, &root, "pw");
    assert!(sent && received);

    let out = dest.path().join("hollow");
    assert!(out.join("empty").is_dir());
    assert!(out.join("a/b/also-empty").is_dir());
    assert_eq!(std::fs::read(out.join("a/file.txt")).unwrap(), b"x");
}

/// A whole sent folder that is itself empty must still arrive.
#[test]
fn empty_root_directory_survives() {
    let src = tempfile::tempdir().unwrap();
    let root = src.path().join("nothing-here");
    std::fs::create_dir_all(&root).unwrap();

    let (dest, sent, received) = transfer(45014, &root, "pw");
    assert!(sent && received);
    assert!(dest.path().join("nothing-here").is_dir());
}

#[cfg(unix)]
#[test]
fn symlinks_are_sent_as_links_not_followed() {
    use std::os::unix::fs::symlink;

    let src = tempfile::tempdir().unwrap();
    let root = src.path().join("linky");
    write_file(&root.join("real/data.txt"), b"payload");
    symlink("real/data.txt", root.join("rel-file")).unwrap();
    symlink("real", root.join("rel-dir")).unwrap();
    symlink("/usr/bin/env", root.join("absolute")).unwrap();
    symlink("does/not/exist", root.join("dangling")).unwrap();
    // Longer than the 100-byte tar name field: needs a GNU long-link record.
    let long_target = format!("real/{}", "n".repeat(150));
    symlink(&long_target, root.join("long")).unwrap();

    let (dest, sent, received) = transfer(45015, &root, "pw");
    assert!(sent && received);

    let out = dest.path().join("linky");
    let link = |name: &str| std::fs::read_link(out.join(name)).unwrap();
    assert_eq!(link("rel-file"), Path::new("real/data.txt"));
    assert_eq!(link("rel-dir"), Path::new("real"));
    assert_eq!(link("absolute"), Path::new("/usr/bin/env"));
    assert_eq!(link("dangling"), Path::new("does/not/exist"));
    assert_eq!(link("long"), Path::new(&long_target));
    assert_eq!(std::fs::read(out.join("rel-file")).unwrap(), b"payload");
    // The directory link must stay a link: its contents are not copied a second time.
    assert!(std::fs::symlink_metadata(out.join("rel-dir")).unwrap().file_type().is_symlink());
}

/// Unreadable entries used to vanish from the transfer without a word.
#[cfg(unix)]
#[test]
fn unreadable_directory_fails_the_send() {
    use std::os::unix::fs::PermissionsExt;

    if unsafe { libc::geteuid() } == 0 {
        eprintln!("skipping: root can read everything");
        return;
    }
    let src = tempfile::tempdir().unwrap();
    let root = src.path().join("locked");
    write_file(&root.join("secret/inside.txt"), b"x");
    write_file(&root.join("ok.txt"), b"y");
    std::fs::set_permissions(root.join("secret"), std::fs::Permissions::from_mode(0o000)).unwrap();

    let dest = tempfile::tempdir().unwrap();
    let mut recv = start_recv(dest.path(), 45016, "pw");
    let sent = run_send(45016, &root, "pw");
    // The sender bails before connecting, so unblock the receiver ourselves.
    let _ = recv.kill();
    let _ = recv.wait();
    std::fs::set_permissions(root.join("secret"), std::fs::Permissions::from_mode(0o755)).unwrap();

    assert!(!sent, "send must fail rather than silently skip an unreadable directory");
}

/// Now that real symlinks travel, prove a hostile sender still cannot use one to
/// write outside the destination: a link `evil -> <outside>` followed by an entry
/// `evil/pwned.txt`. `tar::Archive::unpack` must refuse the second entry.
#[cfg(unix)]
#[test]
fn hostile_symlink_cannot_write_outside_destination() {
    if !(have("openssl") && have("zstd") && have("tar")) {
        eprintln!("skipping: openssl/zstd/tar not all available");
        return;
    }
    use std::net::TcpStream;

    let jail = tempfile::tempdir().unwrap();
    let dest = jail.path().join("downloads");
    let outside = jail.path().join("outside");
    std::fs::create_dir_all(&dest).unwrap();
    std::fs::create_dir_all(&outside).unwrap();

    // Build the hostile tar by hand: the link first, then a file "through" it.
    let work = tempfile::tempdir().unwrap();
    let stage = work.path().join("stage");
    std::fs::create_dir_all(stage.join("pkg")).unwrap();
    std::os::unix::fs::symlink(&outside, stage.join("pkg/evil")).unwrap();
    let tar1 = work.path().join("one.tar");
    let tar2 = work.path().join("two.tar");
    let ok = |c: &mut Command| assert!(c.status().unwrap().success());
    ok(Command::new("tar").current_dir(&stage).args(["-cf"]).arg(&tar1).arg("pkg"));
    let stage2 = work.path().join("stage2");
    write_file(&stage2.join("pkg/evil/pwned.txt"), b"gotcha");
    ok(Command::new("tar").current_dir(&stage2).args(["-cf"]).arg(&tar2).arg("pkg/evil/pwned.txt"));
    ok(Command::new("tar").args(["-Af"]).arg(&tar1).arg(&tar2));

    let salt = [7u8; 16];
    let salt_hex: String = salt.iter().map(|b| format!("{b:02x}")).collect();
    let kdf = Command::new("openssl")
        .args(["kdf", "-keylen", "48", "-kdfopt", "digest:SHA2-256", "-kdfopt", "pass:pw"])
        .arg("-kdfopt")
        .arg(format!("hexsalt:{salt_hex}"))
        .args(["-kdfopt", "iter:10000", "PBKDF2"])
        .output()
        .unwrap();
    let key_iv = String::from_utf8_lossy(&kdf.stdout).trim().replace(':', "").to_lowercase();
    let (key, iv) = key_iv.split_at(64);
    let ct = Command::new("sh")
        .arg("-c")
        .arg(format!(
            "zstd -q -c {} | openssl enc -aes-256-cbc -K {key} -iv {iv}",
            tar1.display()
        ))
        .output()
        .unwrap();
    assert!(ct.status.success());

    let mut recv = start_recv(&dest, 45017, "pw");
    {
        let mut sock = TcpStream::connect(("127.0.0.1", 45017)).expect("connect");
        sock.write_all(&salt).unwrap();
        sock.write_all(&64u64.to_be_bytes()).unwrap();
        sock.write_all(&[1u8]).unwrap(); // directory transfer
        sock.write_all(&ct.stdout).unwrap();
    }
    let _ = recv.wait();

    // The link itself must have arrived, or this test proved nothing.
    assert!(
        std::fs::symlink_metadata(dest.join("pkg/evil")).is_ok(),
        "hostile stream was not decoded; the test is not exercising unpack"
    );
    assert!(
        !outside.join("pwned.txt").exists(),
        "a sender wrote through a symlink to outside the destination"
    );
}

// ---------------------------------------------------------------------------
// Single files: now sent as a one-entry tar so mode and mtime travel
// ---------------------------------------------------------------------------

#[cfg(unix)]
#[test]
fn single_file_preserves_mtime_and_mode() {
    use std::os::unix::fs::PermissionsExt;

    let src = tempfile::tempdir().unwrap();
    for (port, name, len) in [(45018u16, "small.sh", 64usize), (45019, "big.bin", 17 * 1024 * 1024)] {
        let file = src.path().join(name);
        write_file(&file, &payload(len));
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o750)).unwrap();
        set_mtime(&file, 1_234_567_890);

        let (dest, sent, received) = transfer(port, &file, "pw");
        assert!(sent && received, "{name}");
        let out = dest.path().join(name);
        assert_eq!(std::fs::read(&out).unwrap(), payload(len), "{name}");
        assert_eq!(mtime(&out), 1_234_567_890, "{name} mtime");
        let mode = std::fs::metadata(&out).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o750, "{name} mode");
    }
}

/// Naming a symlink sends the file it points to, under the link's name.
#[cfg(unix)]
#[test]
fn single_file_symlink_sends_its_target() {
    let src = tempfile::tempdir().unwrap();
    write_file(&src.path().join("real.txt"), b"behind the link");
    std::os::unix::fs::symlink("real.txt", src.path().join("alias.txt")).unwrap();

    let (dest, sent, received) = transfer(45020, &src.path().join("alias.txt"), "pw");
    assert!(sent && received);
    let out = dest.path().join("alias.txt");
    assert!(std::fs::symlink_metadata(&out).unwrap().file_type().is_file());
    assert_eq!(std::fs::read(&out).unwrap(), b"behind the link");
}

/// Senders built before this change still use the raw single-file stream
/// (transfer type 0 + a filename). Receivers must keep accepting it.
#[test]
fn receiver_still_accepts_legacy_single_file_stream() {
    if !(have("openssl") && have("zstd")) {
        eprintln!("skipping: openssl/zstd not available");
        return;
    }
    use std::net::TcpStream;

    let work = tempfile::tempdir().unwrap();
    let plain = work.path().join("plain.bin");
    std::fs::write(&plain, payload(5000)).unwrap();

    let salt = [9u8; 16];
    let salt_hex: String = salt.iter().map(|b| format!("{b:02x}")).collect();
    let kdf = Command::new("openssl")
        .args(["kdf", "-keylen", "48", "-kdfopt", "digest:SHA2-256", "-kdfopt", "pass:pw"])
        .arg("-kdfopt")
        .arg(format!("hexsalt:{salt_hex}"))
        .args(["-kdfopt", "iter:10000", "PBKDF2"])
        .output()
        .unwrap();
    let key_iv = String::from_utf8_lossy(&kdf.stdout).trim().replace(':', "").to_lowercase();
    let (key, iv) = key_iv.split_at(64);
    let ct = Command::new("sh")
        .arg("-c")
        .arg(format!(
            "zstd -q -c {} | openssl enc -aes-256-cbc -K {key} -iv {iv}",
            plain.display()
        ))
        .output()
        .unwrap();
    assert!(ct.status.success());

    let dest = tempfile::tempdir().unwrap();
    let mut recv = start_recv(dest.path(), 45021, "pw");
    {
        let mut sock = TcpStream::connect(("127.0.0.1", 45021)).expect("connect");
        sock.write_all(&salt).unwrap();
        sock.write_all(&5000u64.to_be_bytes()).unwrap();
        sock.write_all(&[0u8]).unwrap(); // legacy single-file type
        let name = b"legacy.bin";
        sock.write_all(&(name.len() as u32).to_be_bytes()).unwrap();
        sock.write_all(name).unwrap();
        sock.write_all(&ct.stdout).unwrap();
    }
    assert!(recv.wait().unwrap().success(), "receiver rejected a legacy stream");
    assert_eq!(std::fs::read(dest.path().join("legacy.bin")).unwrap(), payload(5000));
}
