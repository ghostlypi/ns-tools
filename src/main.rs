/**
 *  Network Share ENcrypted (nsen) utility is a file sharing utility for high speed network transfers
 *  between 2 devices.
 *  Copyright © 2025 Parth Iyer
 */

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use crossbeam_channel::{bounded, Sender};
use indicatif::{ProgressBar, ProgressStyle};
use local_ip_address::local_ip;
use openssl::hash::MessageDigest;
use openssl::pkcs5::pbkdf2_hmac;
use openssl::rand::rand_bytes;
use openssl::symm::{Cipher, Crypter, Mode};
use rpassword::read_password;
use std::fs::File;
use std::io::{self, BufReader, BufWriter, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::thread;
use std::time::Instant;
use tokio::task;
use walkdir::{DirEntry, WalkDir};
use zstd::stream::read::Decoder as ZstdDecoder;
use zstd::stream::write::Encoder as ZstdEncoder;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {

    #[command(verbatim_doc_comment)]
    Send {
        #[arg(value_name = "IP")]
        ip: String,
        #[arg(value_name = "PATH")]
        input: PathBuf,
        /// Read the password from a single line on stdin instead of prompting.
        #[arg(long)]
        password_stdin: bool,
        /// Port to connect to (defaults to 4444).
        #[arg(long)]
        port: Option<u16>,
        /// Emit machine-readable `NSEN_PROGRESS <done> <total>` lines on stdout
        /// (in addition to the on-screen bar) so a wrapper can track progress.
        #[arg(long)]
        progress_stdout: bool,
    },

    #[command(verbatim_doc_comment)]
    Recv {
        /// Read the password from a single line on stdin instead of prompting.
        #[arg(long)]
        password_stdin: bool,
        /// Port to listen on (defaults to 4444).
        #[arg(long)]
        port: Option<u16>,
        /// Emit machine-readable `NSEN_PROGRESS <done> <total>` lines on stdout
        /// (in addition to the on-screen bar) so a wrapper can track progress.
        #[arg(long)]
        progress_stdout: bool,
    },
}

/// Spawn a background thread that prints `NSEN_PROGRESS <done> <total>` to stdout
/// roughly every 100 ms until the bar finishes. This is a machine-readable
/// side-channel for wrapper tools (like netdrop) that drive nsen and want to
/// render their own progress UI; the human-facing bar (on stderr) is unaffected.
/// Returns a handle to join so the final 100% line is flushed before exit.
fn spawn_progress_reporter(progress: Arc<ProgressBar>) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        let stdout = io::stdout();
        loop {
            let done = progress.position();
            let total = progress.length().unwrap_or(0);
            {
                let mut h = stdout.lock();
                let _ = writeln!(h, "NSEN_PROGRESS {} {}", done, total);
                let _ = h.flush();
            }
            if progress.is_finished() {
                break;
            }
            thread::sleep(std::time::Duration::from_millis(100));
        }
    })
}

/// Obtain the transfer password either from a single line on stdin
/// (non-interactive, for wrapper tools like ndrop) or via the interactive prompt.
fn get_password(from_stdin: bool) -> Result<String> {
    if from_stdin {
        let mut line = String::new();
        io::stdin()
            .read_line(&mut line)
            .context("Failed to read password from stdin")?;
        Ok(line.trim_end_matches(['\n', '\r']).to_string())
    } else {
        print!("Enter password: ");
        io::stdout().flush()?;
        Ok(read_password()?)
    }
}

const PORT: u16 = 4444;
const KEY_ITERATIONS: usize = 10000;
const KEY_LEN: usize = 32;
const IV_LEN: usize = 16;
const SALT_LEN: usize = 16;
const BUFFER_SIZE: usize = 256 * 1024; // 256KB buffers for better throughput
const TCP_BUFFER_SIZE: usize = 4 * 1024 * 1024; // 4MB TCP buffers

// Transfer type flags
const TRANSFER_TYPE_SINGLE_FILE: u8 = 0;
const TRANSFER_TYPE_DIRECTORY: u8 = 1;

// Parallel file reading configuration
const FILE_BUFFER_QUEUE_SIZE: usize = 16; // Number of files to buffer in memory
const MAX_FILE_BUFFER_SIZE: u64 = 16 * 1024 * 1024; // 16MB - only buffer files smaller than this
// Max total buffered memory = FILE_BUFFER_QUEUE_SIZE * MAX_FILE_BUFFER_SIZE = ~256MB

// Structure to hold a file for tar processing
enum FileEntry {
    Buffered {
        relative_path: PathBuf,
        data: Vec<u8>,
        mode: u32,
        mtime: u64,
    },
    Streamed {
        relative_path: PathBuf,
        full_path: PathBuf,
        size: u64,
        mode: u32,
        mtime: u64,
    },
    // Sent as its own entry so empty directories survive and keep their mode/mtime.
    Dir {
        relative_path: PathBuf,
        mode: u32,
        mtime: u64,
    },
    // Sent as a link, never followed; the target is carried verbatim.
    Symlink {
        relative_path: PathBuf,
        target: PathBuf,
        mtime: u64,
    },
}

// Seconds since the Unix epoch, clamped to 0 for pre-1970 or unreadable timestamps.
fn mtime_of(metadata: &std::fs::Metadata) -> u64 {
    metadata
        .modified()
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(unix)]
fn mode_of(metadata: &std::fs::Metadata) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    metadata.permissions().mode()
}

#[cfg(not(unix))]
fn mode_of(metadata: &std::fs::Metadata) -> u32 {
    if metadata.is_dir() { 0o755 } else { 0o644 }
}

// Every directory, regular file and symlink under `path` (including `path` itself),
// sorted. Symlinks are not followed; sockets, FIFOs and devices are skipped. An
// unreadable entry is an error, never silently dropped.
fn collect_entries(path: &Path) -> Result<Vec<DirEntry>> {
    let mut entries = Vec::new();
    for entry in WalkDir::new(path) {
        let entry = entry.context("Failed to read directory tree")?;
        let ft = entry.file_type();
        if ft.is_file() || ft.is_dir() || ft.is_symlink() {
            entries.push(entry);
        }
    }
    entries.sort_by(|a, b| a.path().cmp(b.path()));
    Ok(entries)
}

// A file named on the command line, as a top-level tar entry. Follows a symlink:
// naming a link means "send what it points to".
fn single_file_entry(path: &Path) -> Result<FileEntry> {
    let metadata = std::fs::metadata(path)
        .with_context(|| format!("Failed to read {}", path.display()))?;
    let relative_path = PathBuf::from(path.file_name().context("Path has no file name")?);
    let (mode, mtime, size) = (mode_of(&metadata), mtime_of(&metadata), metadata.len());
    if size <= MAX_FILE_BUFFER_SIZE {
        let mut data = Vec::new();
        File::open(path)
            .with_context(|| format!("Failed to open {}", path.display()))?
            .read_to_end(&mut data)?;
        Ok(FileEntry::Buffered { relative_path, data, mode, mtime })
    } else {
        Ok(FileEntry::Streamed { relative_path, full_path: path.to_path_buf(), size, mode, mtime })
    }
}

// Append one entry under `<dir_name>/<relative_path>` with its type, mode and mtime.
fn append_entry<W: Write>(tar: &mut tar::Builder<W>, dir_name: &Path, entry: FileEntry) -> Result<()> {
    let mut header = tar::Header::new_gnu();
    match entry {
        FileEntry::Buffered { relative_path, data, mode, mtime } => {
            header.set_entry_type(tar::EntryType::Regular);
            header.set_size(data.len() as u64);
            header.set_mode(mode);
            header.set_mtime(mtime);
            tar.append_data(&mut header, dir_name.join(&relative_path), &data[..])?;
        }
        FileEntry::Streamed { relative_path, full_path, size, mode, mtime } => {
            let mut file = File::open(&full_path)
                .with_context(|| format!("Failed to open {}", full_path.display()))?;
            header.set_entry_type(tar::EntryType::Regular);
            header.set_size(size);
            header.set_mode(mode);
            header.set_mtime(mtime);
            tar.append_data(&mut header, dir_name.join(&relative_path), &mut file)?;
        }
        FileEntry::Dir { relative_path, mode, mtime } => {
            header.set_entry_type(tar::EntryType::Directory);
            header.set_size(0);
            header.set_mode(mode);
            header.set_mtime(mtime);
            tar.append_data(&mut header, dir_name.join(&relative_path), io::empty())?;
        }
        FileEntry::Symlink { relative_path, target, mtime } => {
            header.set_entry_type(tar::EntryType::Symlink);
            header.set_size(0);
            header.set_mode(0o777);
            header.set_mtime(mtime);
            // Emits GNU long-name/long-link records for paths over 100 bytes.
            tar.append_link(&mut header, dir_name.join(&relative_path), &target)?;
        }
    }
    Ok(())
}


/// Reduce a filename received over the wire to a bare, safe basename.
///
/// The sender controls this string and the receiver creates it in its working
/// directory (`~/Downloads` under netdrop). Without this a peer whose transfer is
/// accepted could write `../.bashrc`. Mirrors `nsen_core::wire::sanitize_wire_filename`.
fn sanitize_wire_filename(raw: &str) -> Result<String> {
    let name = Path::new(raw)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("");
    // A backslash is a legal filename byte on Unix, so a Windows-style path would
    // otherwise survive as one long literal name.
    if name.is_empty() || name == "." || name == ".." || name.contains('\\') {
        anyhow::bail!("Refusing unsafe filename from sender: {:?}", raw);
    }
    Ok(name.to_string())
}

/// Unpack a tar stream into `dst`, like `tar::Archive::unpack`, but also restore
/// directory mtimes (the tar crate sets a directory's permissions, never its mtime).
///
/// This mirrors `Archive::unpack` step for step: create and canonicalize `dst`,
/// unpack non-directories as they stream past, then directories in reverse path
/// order, every entry through `Entry::unpack_in` and its traversal checks. Only then,
/// once nothing else will write into them, are directory mtimes set — best-effort,
/// and only on paths that are still real directories inside `dst`.
fn unpack_tar<R: Read>(reader: R, dst: &Path) -> std::io::Result<()> {
    use std::path::Component;

    if dst.symlink_metadata().is_err() {
        std::fs::create_dir_all(dst)?;
    }
    let dst = &dst.canonicalize().unwrap_or_else(|_| dst.to_path_buf());

    let mut archive = tar::Archive::new(reader);
    let mut directories = Vec::new();
    for entry in archive.entries()? {
        let mut entry = entry?;
        if entry.header().entry_type() == tar::EntryType::Directory {
            directories.push(entry);
        } else {
            entry.unpack_in(dst)?;
        }
    }

    directories.sort_by(|a, b| b.path_bytes().cmp(&a.path_bytes()));
    let mut dir_times = Vec::with_capacity(directories.len());
    for mut dir in directories {
        let mtime = dir.header().mtime().ok();
        // Same component rules `unpack_in` applies; `..` means it was skipped.
        let mut target = dst.to_path_buf();
        let mut skipped = false;
        for part in dir.path()?.components() {
            match part {
                Component::Normal(p) => target.push(p),
                Component::ParentDir => skipped = true,
                _ => {}
            }
        }
        if dir.unpack_in(dst)? && !skipped {
            if let Some(mtime) = mtime {
                dir_times.push((target, mtime));
            }
        }
    }

    for (path, mtime) in dir_times {
        let is_real_dir = path
            .symlink_metadata()
            .map(|m| m.file_type().is_dir())
            .unwrap_or(false);
        let inside = path.canonicalize().map(|c| c.starts_with(dst)).unwrap_or(false);
        if is_real_dir && inside {
            let t = std::time::UNIX_EPOCH + std::time::Duration::from_secs(mtime);
            if let Ok(f) = File::open(&path) {
                let _ = f.set_modified(t);
            }
        }
    }
    Ok(())
}

fn optimize_tcp_stream(stream: &TcpStream) -> io::Result<()> {
    stream.set_nodelay(true)?;

    #[cfg(unix)]
    {
        use std::os::unix::io::AsRawFd;
        let fd = stream.as_raw_fd();
        unsafe {
            let size = TCP_BUFFER_SIZE as libc::c_int;
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_SNDBUF,
                &size as *const _ as *const libc::c_void,
                std::mem::size_of_val(&size) as libc::socklen_t,
            );
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_RCVBUF,
                &size as *const _ as *const libc::c_void,
                std::mem::size_of_val(&size) as libc::socklen_t,
            );
        }
    }

    Ok(())
}

fn derive_key_iv(password: &str, salt: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    let mut key_iv = vec![0u8; KEY_LEN + IV_LEN];
    pbkdf2_hmac(
        password.as_bytes(),
        salt,
        KEY_ITERATIONS,
        MessageDigest::sha256(),
        &mut key_iv,
    )?;
    let (key, iv) = key_iv.split_at(KEY_LEN);
    Ok((key.to_vec(), iv.to_vec()))
}

struct AesWriter<W: Write> {
    writer: W,
    crypter: Crypter,
    buffer: Vec<u8>,
}

impl<W: Write> AesWriter<W> {
    pub fn new(writer: W, key: &[u8], iv: &[u8]) -> io::Result<Self> {
        let crypter = Crypter::new(Cipher::aes_256_cbc(), Mode::Encrypt, key, Some(iv))
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
        Ok(Self {
            writer,
            crypter,
            buffer: vec![0; BUFFER_SIZE + 16],
        })
    }

    pub fn finish(&mut self) -> io::Result<()> {
        let count = self.crypter.finalize(&mut self.buffer)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
        if count > 0 {
            self.writer.write_all(&self.buffer[..count])?;
        }
        self.writer.flush()?;
        Ok(())
    }
}

impl<W: Write> Write for AesWriter<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if self.buffer.len() < buf.len() + 16 {
            self.buffer.resize(buf.len() + 16, 0);
        }
        let count = self.crypter.update(buf, &mut self.buffer)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
        if count > 0 {
            self.writer.write_all(&self.buffer[..count])?;
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.writer.flush()
    }
}

struct AesReader<R: Read> {
    reader: R,
    crypter: Crypter,
    in_buffer: Vec<u8>,
    out_buffer: Vec<u8>,
    out_pos: usize,
    out_len: usize,
    eof: bool,
}

impl<R: Read> AesReader<R> {
    pub fn new(reader: R, key: &[u8], iv: &[u8]) -> io::Result<Self> {
        let crypter = Crypter::new(Cipher::aes_256_cbc(), Mode::Decrypt, key, Some(iv))
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
        Ok(Self {
            reader,
            crypter,
            in_buffer: vec![0; BUFFER_SIZE],
            out_buffer: vec![0; BUFFER_SIZE + 16],
            out_pos: 0,
            out_len: 0,
            eof: false,
        })
    }
}

impl<R: Read> Read for AesReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.out_pos < self.out_len {
            let len = std::cmp::min(buf.len(), self.out_len - self.out_pos);
            buf[..len].copy_from_slice(&self.out_buffer[self.out_pos..self.out_pos + len]);
            self.out_pos += len;
            return Ok(len);
        }

        if self.eof {
            return Ok(0);
        }

        let n = self.reader.read(&mut self.in_buffer)?;
        if n == 0 {
            self.eof = true;
            let count = self.crypter.finalize(&mut self.out_buffer)
                .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
            self.out_pos = 0;
            self.out_len = count;
            if count > 0 {
                return self.read(buf);
            }
            return Ok(0);
        }

        let count = self.crypter.update(&self.in_buffer[..n], &mut self.out_buffer)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
        self.out_pos = 0;
        self.out_len = count;
        self.read(buf)
    }
}

struct ProgressWriter<W: Write> {
    inner: W,
    progress: Arc<ProgressBar>,
}

impl<W: Write> ProgressWriter<W> {
    fn new(inner: W, progress: Arc<ProgressBar>) -> Self {
        Self { inner, progress }
    }
}

impl<W: Write> Write for ProgressWriter<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let n = self.inner.write(buf)?;
        self.progress.inc(n as u64);
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

struct ProgressReader<R: Read> {
    inner: R,
    progress: Arc<ProgressBar>,
}

impl<R: Read> ProgressReader<R> {
    fn new(inner: R, progress: Arc<ProgressBar>) -> Self {
        Self { inner, progress }
    }
}

impl<R: Read> Read for ProgressReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.progress.inc(n as u64);
        Ok(n)
    }
}

fn calculate_size(path: &Path) -> Result<u64> {
    if path.is_file() {
        Ok(std::fs::metadata(path)?.len())
    } else if path.is_dir() {
        let mut total = 0u64;
        for entry in WalkDir::new(path) {
            let entry = entry?;
            if entry.file_type().is_file() {
                total += entry.metadata()?.len();
            }
        }
        Ok(total)
    } else {
        Ok(0)
    }
}

fn format_duration(duration: std::time::Duration) -> String {
    let total_secs = duration.as_secs();
    let hours = total_secs / 3600;
    let minutes = (total_secs % 3600) / 60;
    let seconds = total_secs % 60;
    format!("{:02}:{:02}:{:02}", hours, minutes, seconds)
}

// Parallel file reader worker
fn file_reader_worker(
    work_rx: crossbeam_channel::Receiver<DirEntry>,
    result_tx: Sender<Result<FileEntry>>,
    base_path: PathBuf,
) {
    while let Ok(entry) = work_rx.recv() {
        let result = (|| -> Result<FileEntry> {
            let path = entry.path();
            // Does not follow symlinks, so a link reports itself.
            let metadata = entry.metadata()?;

            let relative_path = path.strip_prefix(&base_path)
                .unwrap_or(path)
                .to_path_buf();
            let mtime = mtime_of(&metadata);

            if metadata.file_type().is_symlink() {
                let target = std::fs::read_link(path)
                    .with_context(|| format!("Failed to read link {}", path.display()))?;
                return Ok(FileEntry::Symlink { relative_path, target, mtime });
            }

            let mode = mode_of(&metadata);

            if metadata.is_dir() {
                return Ok(FileEntry::Dir { relative_path, mode, mtime });
            }

            if !metadata.is_file() {
                anyhow::bail!("{} is not a regular file, directory or symlink", path.display());
            }

            let size = metadata.len();

            // Only buffer small files to prevent OOM
            if size <= MAX_FILE_BUFFER_SIZE {
                let mut data = Vec::new();
                let mut file = File::open(path)
                    .with_context(|| format!("Failed to open {}", path.display()))?;
                file.read_to_end(&mut data)?;

                Ok(FileEntry::Buffered {
                    relative_path,
                    data,
                    mode,
                    mtime,
                })
            } else {
                // Large files: return path for streaming
                Ok(FileEntry::Streamed {
                    relative_path,
                    full_path: path.to_path_buf(),
                    size,
                    mode,
                    mtime,
                })
            }
        })();

        // Send result (success or error) to main thread
        if result_tx.send(result).is_err() {
            break;
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Recv { password_stdin, port, progress_stdout } => {
            let ip = local_ip().context("Failed to get local IP")?;
            println!("Connect to {}", ip);

            let password = get_password(password_stdin)?;
            let port = port.unwrap_or(PORT);

            task::spawn_blocking(move || -> Result<()> {
                let listener = TcpListener::bind(format!("0.0.0.0:{}", port))?;
                println!("Waiting for connection...");
                let (stream, _) = listener.accept()?;

                optimize_tcp_stream(&stream)?;

                let mut buffered_stream = BufReader::with_capacity(BUFFER_SIZE, stream);

                // Read protocol header
                let mut salt = [0u8; SALT_LEN];
                buffered_stream.read_exact(&mut salt).context("Failed to read salt")?;

                let mut size_bytes = [0u8; 8];
                buffered_stream.read_exact(&mut size_bytes).context("Failed to read size")?;
                let total_size = u64::from_be_bytes(size_bytes);

                // Read transfer type
                let mut transfer_type = [0u8; 1];
                buffered_stream.read_exact(&mut transfer_type).context("Failed to read transfer type")?;

                // For single files, read filename before decryption setup
                let filename = if transfer_type[0] == TRANSFER_TYPE_SINGLE_FILE {
                    let mut filename_len_bytes = [0u8; 4];
                    buffered_stream.read_exact(&mut filename_len_bytes)?;
                    let filename_len = u32::from_be_bytes(filename_len_bytes) as usize;

                    let mut filename_bytes = vec![0u8; filename_len];
                    buffered_stream.read_exact(&mut filename_bytes)?;
                    let raw = String::from_utf8(filename_bytes)
                        .context("Invalid filename encoding")?;
                    Some(sanitize_wire_filename(&raw)?)
                } else {
                    None
                };

                let (key, iv) = derive_key_iv(&password, &salt)?;

                let progress = Arc::new(ProgressBar::new(total_size));
                progress.set_style(
                    ProgressStyle::default_bar()
                        .template("{msg}\n[{bar:40.cyan/blue}] {bytes}/{total_bytes} | {bytes_per_sec} | {eta_precise}")
                        .unwrap()
                        .progress_chars("=>-"),
                );
                progress.set_message("Receiving");

                let reporter = if progress_stdout {
                    Some(spawn_progress_reporter(progress.clone()))
                } else {
                    None
                };

                let start = Instant::now();
                let aes_reader = AesReader::new(buffered_stream, &key, &iv)?;
                let zstd_decoder = ZstdDecoder::new(aes_reader)?;
                let mut progress_reader = ProgressReader::new(zstd_decoder, progress.clone());

                match transfer_type[0] {
                    TRANSFER_TYPE_SINGLE_FILE => {
                        let filename = filename.unwrap();
                        let mut output_file = File::create(&filename)
                            .with_context(|| format!("Failed to create file: {}", filename))?;
                        io::copy(&mut progress_reader, &mut output_file)?;
                        output_file.flush()?;
                    }
                    TRANSFER_TYPE_DIRECTORY => {
                        // Use tar to unpack
                        unpack_tar(progress_reader, Path::new("."))
                            .context("Failed to unpack archive")?;
                    }
                    _ => anyhow::bail!("Unknown transfer type: {}", transfer_type[0]),
                }

                let elapsed = start.elapsed();
                progress.finish_with_message(format!("Complete in {}", format_duration(elapsed)));
                if let Some(reporter) = reporter {
                    let _ = reporter.join();
                }
                Ok(())
            }).await??;
        }
        Commands::Send { ip, input, password_stdin, port, progress_stdout } => {
            println!("Connecting to {}...", ip);

            let password = get_password(password_stdin)?;
            let port = port.unwrap_or(PORT);

            task::spawn_blocking(move || -> Result<()> {
                let path = Path::new(&input);
                let total_size = calculate_size(path)?;
                let is_file = path.is_file();

                let mut salt = [0u8; SALT_LEN];
                rand_bytes(&mut salt).context("Failed to generate salt")?;
                let (key, iv) = derive_key_iv(&password, &salt)?;

                let addr = format!("{}:{}", ip, port);
                let stream = TcpStream::connect(&addr)
                    .with_context(|| format!("Failed to connect to {}. Make sure the receiver is running and the IP address is correct.", addr))?;

                optimize_tcp_stream(&stream)?;

                let mut buffered_stream = BufWriter::with_capacity(BUFFER_SIZE, stream);

                // Send protocol header
                buffered_stream.write_all(&salt).context("Failed to send salt")?;
                buffered_stream.write_all(&total_size.to_be_bytes()).context("Failed to send size")?;

                // Send transfer type. Single files go out as a one-entry tar too, so they
                // keep their mode and mtime; the raw single-file type has nowhere to put
                // them. Receivers still accept that type from older senders.
                buffered_stream.write_all(&[TRANSFER_TYPE_DIRECTORY]).context("Failed to send transfer type")?;

                buffered_stream.flush()?;

                let progress = Arc::new(ProgressBar::new(total_size));
                progress.set_style(
                    ProgressStyle::default_bar()
                        .template("{msg}\n[{bar:40.cyan/blue}] {bytes}/{total_bytes} | {bytes_per_sec} | {eta_precise}")
                        .unwrap()
                        .progress_chars("=>-"),
                );
                progress.set_message("Sending");

                let reporter = if progress_stdout {
                    Some(spawn_progress_reporter(progress.clone()))
                } else {
                    None
                };

                let start = Instant::now();
                let aes_writer = AesWriter::new(buffered_stream, &key, &iv)?;
                let mut zstd_encoder = ZstdEncoder::new(aes_writer, 3)?;
                zstd_encoder.multithread(num_cpus::get() as u32)?;

                if is_file {
                    let entry = single_file_entry(path)?;
                    let progress_writer = ProgressWriter::new(&mut zstd_encoder, progress.clone());
                    let mut tar_builder = tar::Builder::new(progress_writer);
                    append_entry(&mut tar_builder, Path::new(""), entry)?;
                    tar_builder.finish()?;
                } else {
                    // Directory: use parallel file buffering with tar
                    let base_path = path.to_path_buf();
                    let dir_name = path.file_name().unwrap_or(path.as_os_str());

                    // Collect all file entries
                    let entries = collect_entries(path)?;

                    let num_workers = num_cpus::get().min(8); // Cap at 8 workers
                    let (work_tx, work_rx) = bounded::<DirEntry>(FILE_BUFFER_QUEUE_SIZE);
                    let (result_tx, result_rx) = bounded::<Result<FileEntry>>(FILE_BUFFER_QUEUE_SIZE);

                    // Spawn worker threads
                    let mut workers = Vec::new();
                    for _ in 0..num_workers {
                        let work_rx_clone = work_rx.clone();
                        let result_tx_clone = result_tx.clone();
                        let base_path_clone = base_path.clone();

                        let handle = thread::spawn(move || {
                            file_reader_worker(work_rx_clone, result_tx_clone, base_path_clone);
                        });
                        workers.push(handle);
                    }

                    // Drop the original senders so workers can detect when work is done
                    drop(result_tx);

                    // Send work to workers in a separate thread
                    let total_files = entries.len();
                    thread::spawn(move || {
                        for entry in entries {
                            if work_tx.send(entry).is_err() {
                                break;
                            }
                        }
                        drop(work_tx);
                    });

                    // Build tar archive from file entries
                    let progress_writer = ProgressWriter::new(&mut zstd_encoder, progress.clone());
                    let mut tar_builder = tar::Builder::new(progress_writer);

                    let mut files_processed = 0;

                    while let Ok(result) = result_rx.recv() {
                        let entry = result?;

                        append_entry(&mut tar_builder, Path::new(dir_name), entry)?;

                        files_processed += 1;
                        if files_processed >= total_files {
                            break;
                        }
                    }

                    tar_builder.finish()?;

                    // Wait for all workers to complete
                    for worker in workers {
                        let _ = worker.join();
                    }
                }

                let mut aes_writer = zstd_encoder.finish()?;
                aes_writer.finish()?;

                let elapsed = start.elapsed();
                progress.finish_with_message(format!("Complete in {}", format_duration(elapsed)));
                if let Some(reporter) = reporter {
                    let _ = reporter.join();
                }
                Ok(())
            }).await??;
        }
    }

    Ok(())
}
