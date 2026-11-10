//! The nsen encrypted bulk-transfer engine.
//!
//! A sender streams `tar` → `zstd` → AES-256-CBC over a plain TCP connection; the
//! receiver mirrors it. Key and IV come from PBKDF2-HMAC-SHA256 over a shared password
//! and a random per-transfer salt sent in the clear.
//!
//! # Why this is a library
//!
//! It used to be two inline blocks inside the CLI's `main()`, driven by `netdrop` as a
//! subprocess: password on stdin, progress screen-scraped from stdout. Android 10+ bans
//! executing binaries from app-writable storage, so that boundary had to become a
//! function call.
//!
//! # Usage
//!
//! ```no_run
//! use nsen_core::{CancelToken, Listener, NoProgress, RecvOpts, TransferSink};
//!
//! // Bind first, then accept — so a caller can announce readiness before a peer
//! // connects. Port 0 asks the OS for a free port.
//! let listener = Listener::bind(4444)?;
//! println!("listening on {}", listener.local_port()?);
//! let stats = listener.accept_and_recv(
//!     RecvOpts::new("hunter2", TransferSink::Directory("/tmp/incoming".into())),
//!     &NoProgress,
//!     &CancelToken::new(),
//! )?;
//! println!("{} bytes in {:?}", stats.bytes, stats.elapsed);
//! # Ok::<(), nsen_core::TransferError>(())
//! ```

mod cipher;
mod error;
mod pack;
mod progress;
mod wire;

pub use error::{Result, TransferError};
pub use progress::{CancelToken, NoProgress, ProgressSink};

use cipher::{AesReader, AesWriter, BUFFER_SIZE};
use progress::{classify, Meter, ProgressReader, ProgressWriter};
use std::fs::File;
use std::io::{self, BufReader, BufWriter, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, Instant};
use wire::Header;

/// The port nsen uses when none is given.
pub const DEFAULT_PORT: u16 = 4444;

/// How long a connection may produce no bytes before it is abandoned.
///
/// The original had no timeouts at all, so a vanished peer hung the process forever.
/// Note this bounds *stalls*, not total duration — a slow transfer is fine.
pub const DEFAULT_STALL_TIMEOUT: Duration = Duration::from_secs(300);

/// What to send.
///
/// An enum rather than a bare path because Android supplies files through the Storage
/// Access Framework as content URIs, not filesystem paths; that variant lands here in
/// roadmap Phase 5 without breaking this signature.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum TransferSource {
    /// A file (sent directly) or a directory (sent as a tar).
    Path(PathBuf),
}

/// Where received data goes.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum TransferSink {
    /// A directory on the local filesystem. Single files land directly inside it;
    /// directory transfers unpack into a subdirectory named by the sender.
    Directory(PathBuf),
}

#[derive(Debug, Clone)]
pub struct SendOpts {
    /// `host:port`, as accepted by [`std::net::TcpStream::connect`].
    pub addr: String,
    pub source: TransferSource,
    pub password: String,
    /// zstd compression level. 3 is the default and part of no wire contract — the
    /// decoder reads whatever the encoder produced.
    pub zstd_level: i32,
    /// zstd worker threads. Defaults to the core count; set 1 on battery-powered
    /// devices, where the extra threads cost more than they save.
    pub zstd_threads: u32,
    pub stall_timeout: Option<Duration>,
}

impl SendOpts {
    pub fn new(addr: impl Into<String>, source: TransferSource, password: impl Into<String>) -> Self {
        Self {
            addr: addr.into(),
            source,
            password: password.into(),
            zstd_level: 3,
            zstd_threads: num_cpus::get() as u32,
            stall_timeout: Some(DEFAULT_STALL_TIMEOUT),
        }
    }
}

#[derive(Debug, Clone)]
pub struct RecvOpts {
    pub password: String,
    /// Explicit destination. The engine never consults or changes the process working
    /// directory — `set_current_dir` is process-global and racy, which made in-process
    /// use impossible before.
    pub sink: TransferSink,
    pub stall_timeout: Option<Duration>,
}

impl RecvOpts {
    pub fn new(password: impl Into<String>, sink: TransferSink) -> Self {
        Self {
            password: password.into(),
            sink,
            stall_timeout: Some(DEFAULT_STALL_TIMEOUT),
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct Stats {
    /// Plaintext bytes moved.
    pub bytes: u64,
    pub elapsed: Duration,
}

// ---------------------------------------------------------------------------
// Send
// ---------------------------------------------------------------------------

/// Connect to a receiver and send `opts.source`.
pub fn send(opts: SendOpts, progress: &dyn ProgressSink, cancel: &CancelToken) -> Result<Stats> {
    let TransferSource::Path(ref path) = opts.source;
    let path = path.clone();

    if !path.exists() {
        return Err(TransferError::ReadFile {
            path: path.clone(),
            source: io::Error::new(io::ErrorKind::NotFound, "no such file or directory"),
        });
    }

    let total_size = pack::calculate_size(&path)?;
    let is_file = path.is_file();

    let mut salt = [0u8; wire::SALT_LEN];
    cipher::random_bytes(&mut salt)?;
    let (key, iv) = cipher::derive_key_iv(&opts.password, &salt)?;

    let stream = TcpStream::connect(&opts.addr).map_err(|source| TransferError::Connect {
        addr: opts.addr.clone(),
        source,
    })?;
    optimize_tcp_stream(&stream)?;
    stream.set_write_timeout(opts.stall_timeout)?;

    let mut buffered = BufWriter::with_capacity(BUFFER_SIZE, stream);

    // Both single files and directories go out as a tar (header type DIRECTORY), so a
    // single file keeps its mode and mtime. Wire v1's raw single-file type has nowhere
    // to put them; receivers still accept it from older senders.
    Header {
        salt,
        total_size,
        filename: None,
    }
    .write(&mut buffered)?;
    buffered.flush()?;

    let start = Instant::now();
    let mut meter = Meter::new(progress, cancel, total_size);

    (|| -> Result<()> {
        let aes = AesWriter::new(buffered, &key, &iv)?;
        let mut zstd = zstd::stream::write::Encoder::new(aes, opts.zstd_level)?;
        zstd.multithread(opts.zstd_threads)?;

        if is_file {
            send_one_file(&path, &mut zstd, &mut meter)?;
        } else {
            send_directory(&path, &mut zstd, &mut meter)?;
        }

        let mut aes = zstd.finish()?;
        aes.finish()?;
        Ok(())
    })()
    .map_err(|e| classify(e, cancel))?;

    meter.finish();
    Ok(Stats {
        bytes: meter.bytes(),
        elapsed: start.elapsed(),
    })
}

/// Single file: a one-entry tar, so its mode and mtime travel with it.
fn send_one_file<W: Write>(path: &Path, zstd: &mut W, meter: &mut Meter) -> Result<()> {
    let entry = pack::single_file_entry(path)?;
    let mut tar = tar::Builder::new(ProgressWriter::new(zstd, meter));
    pack::append_entry(&mut tar, Path::new(""), entry)?;
    tar.finish()?;
    Ok(())
}

/// Directory: a worker pool reads files while the main thread builds the tar.
fn send_directory<W: Write>(path: &Path, zstd: &mut W, meter: &mut Meter) -> Result<()> {
    let base_path = path.to_path_buf();
    let dir_name = PathBuf::from(path.file_name().unwrap_or(path.as_os_str()));

    let entries = pack::collect_entries(path)?;
    let total_files = entries.len();

    let num_workers = num_cpus::get().min(8);
    let (work_tx, work_rx) = crossbeam_channel::bounded(pack::FILE_BUFFER_QUEUE_SIZE);
    let (result_tx, result_rx) = crossbeam_channel::bounded(pack::FILE_BUFFER_QUEUE_SIZE);

    let mut workers = Vec::with_capacity(num_workers);
    for _ in 0..num_workers {
        let work_rx = work_rx.clone();
        let result_tx = result_tx.clone();
        let base_path = base_path.clone();
        workers.push(thread::spawn(move || {
            pack::file_reader_worker(work_rx, result_tx, base_path)
        }));
    }
    drop(result_tx);
    drop(work_rx);

    let feeder = thread::spawn(move || {
        for entry in entries {
            if work_tx.send(entry).is_err() {
                break;
            }
        }
    });

    let build = (|| -> Result<()> {
        let mut tar = tar::Builder::new(ProgressWriter::new(zstd, meter));
        let mut processed = 0usize;

        while processed < total_files {
            let Ok(result) = result_rx.recv() else { break };
            pack::append_entry(&mut tar, &dir_name, result?)?;
            processed += 1;
        }

        tar.finish()?;
        Ok(())
    })();

    // Drain and join so a failure mid-build doesn't leave workers blocked on a full
    // channel. The feeder exits once the receiver is dropped.
    drop(result_rx);
    let _ = feeder.join();
    for worker in workers {
        let _ = worker.join();
    }

    build
}

// ---------------------------------------------------------------------------
// Receive
// ---------------------------------------------------------------------------

/// A bound-but-not-yet-accepting receiver socket.
///
/// Binding and accepting are separate so a caller can publish the port and signal
/// readiness *before* a peer connects. netdrop needed exactly this and previously got it
/// by watching for a "Waiting for connection" line on the child's stdout.
pub struct Listener {
    inner: TcpListener,
}

impl Listener {
    /// Bind `0.0.0.0:port`. Port 0 asks the OS for a free port — read it back with
    /// [`Listener::local_port`].
    pub fn bind(port: u16) -> Result<Self> {
        let inner = TcpListener::bind(("0.0.0.0", port))
            .map_err(|source| TransferError::Bind { port, source })?;
        Ok(Self { inner })
    }

    pub fn local_port(&self) -> Result<u16> {
        Ok(self.inner.local_addr()?.port())
    }

    /// Accept one connection and receive the transfer it carries.
    pub fn accept_and_recv(
        self,
        opts: RecvOpts,
        progress: &dyn ProgressSink,
        cancel: &CancelToken,
    ) -> Result<Stats> {
        let (stream, _peer) = self.inner.accept()?;
        recv_on(stream, opts, progress, cancel)
    }
}

/// Receive a transfer from an already-connected stream.
pub fn recv_on(
    stream: TcpStream,
    opts: RecvOpts,
    progress: &dyn ProgressSink,
    cancel: &CancelToken,
) -> Result<Stats> {
    optimize_tcp_stream(&stream)?;
    stream.set_read_timeout(opts.stall_timeout)?;

    let mut buffered = BufReader::with_capacity(BUFFER_SIZE, stream);
    let header = Header::read(&mut buffered)?;
    let (key, iv) = cipher::derive_key_iv(&opts.password, &header.salt)?;

    let TransferSink::Directory(ref dest) = opts.sink;
    std::fs::create_dir_all(dest).map_err(|source| TransferError::WriteFile {
        path: dest.clone(),
        source,
    })?;

    let start = Instant::now();
    let mut meter = Meter::new(progress, cancel, header.total_size);

    (|| -> Result<()> {
        let aes = AesReader::new(buffered, &key, &iv)?;
        let zstd = zstd::stream::read::Decoder::new(aes)?;
        let mut reader = ProgressReader::new(zstd, &mut meter);

        match header.filename {
            Some(name) => {
                // `name` was sanitized to a basename by `Header::read`, so this join
                // cannot escape `dest`.
                let out_path = dest.join(&name);
                let mut out =
                    File::create(&out_path).map_err(|source| TransferError::WriteFile {
                        path: out_path.clone(),
                        source,
                    })?;
                io::copy(&mut reader, &mut out)?;
                out.flush()?;
            }
            None => {
                pack::unpack_tar(&mut reader, dest)?;
            }
        }
        Ok(())
    })()
    .map_err(|e| classify(e, cancel))?;

    meter.finish();
    Ok(Stats {
        bytes: meter.bytes(),
        elapsed: start.elapsed(),
    })
}

// ---------------------------------------------------------------------------
// Socket tuning
// ---------------------------------------------------------------------------

/// Disable Nagle and ask for large socket buffers.
///
/// Android is Linux, so the `libc` path applies there unchanged.
fn optimize_tcp_stream(stream: &TcpStream) -> io::Result<()> {
    const TCP_BUFFER_SIZE: usize = 4 * 1024 * 1024;
    stream.set_nodelay(true)?;

    #[cfg(unix)]
    {
        use std::os::unix::io::AsRawFd;
        let fd = stream.as_raw_fd();
        unsafe {
            let size = TCP_BUFFER_SIZE as libc::c_int;
            // Best effort: the kernel may clamp these, and a failure is not fatal.
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
