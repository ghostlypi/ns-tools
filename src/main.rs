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
    },

    #[command(verbatim_doc_comment)]
    Recv,
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
    },
    Streamed {
        relative_path: PathBuf,
        full_path: PathBuf,
        size: u64,
        mode: u32,
    },
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
            let metadata = entry.metadata()?;

            if !metadata.is_file() {
                anyhow::bail!("Not a file");
            }

            let relative_path = path.strip_prefix(&base_path)
                .unwrap_or(path)
                .to_path_buf();

            let size = metadata.len();

            #[cfg(unix)]
            let mode = {
                use std::os::unix::fs::PermissionsExt;
                metadata.permissions().mode()
            };

            #[cfg(not(unix))]
            let mode = 0o644;

            // Only buffer small files to prevent OOM
            if size <= MAX_FILE_BUFFER_SIZE {
                let mut data = Vec::new();
                let mut file = File::open(path)?;
                file.read_to_end(&mut data)?;

                Ok(FileEntry::Buffered {
                    relative_path,
                    data,
                    mode,
                })
            } else {
                // Large files: return path for streaming
                Ok(FileEntry::Streamed {
                    relative_path,
                    full_path: path.to_path_buf(),
                    size,
                    mode,
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
        Commands::Recv => {
            let ip = local_ip().context("Failed to get local IP")?;
            println!("Listening on {}:{}", ip, PORT);

            print!("Enter password: ");
            io::stdout().flush()?;
            let password = read_password()?;

            task::spawn_blocking(move || -> Result<()> {
                let listener = TcpListener::bind(format!("0.0.0.0:{}", PORT))?;
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
                    Some(String::from_utf8(filename_bytes)
                        .context("Invalid filename encoding")?)
                } else {
                    None
                };

                let (key, iv) = derive_key_iv(&password, &salt)?;

                let progress = Arc::new(ProgressBar::new(total_size));
                progress.set_style(
                    ProgressStyle::default_bar()
                        .template("{msg}\n{bar:40.cyan/blue} {bytes}/{total_bytes} | {bytes_per_sec} | {eta_precise}")
                        .unwrap()
                        .progress_chars("=>-"),
                );
                progress.set_message("Receiving");

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
                        let mut archive = tar::Archive::new(progress_reader);
                        archive.unpack(".").context("Failed to unpack archive")?;
                    }
                    _ => anyhow::bail!("Unknown transfer type: {}", transfer_type[0]),
                }

                let elapsed = start.elapsed();
                progress.finish_with_message(format!("Complete in {}", format_duration(elapsed)));
                Ok(())
            }).await??;
        }
        Commands::Send { ip, input } => {
            println!("Connecting to {}:{}...", ip, PORT);

            print!("Enter password: ");
            io::stdout().flush()?;
            let password = read_password()?;

            task::spawn_blocking(move || -> Result<()> {
                let path = Path::new(&input);
                let total_size = calculate_size(path)?;
                let is_file = path.is_file();

                let mut salt = [0u8; SALT_LEN];
                rand_bytes(&mut salt).context("Failed to generate salt")?;
                let (key, iv) = derive_key_iv(&password, &salt)?;

                let addr = format!("{}:{}", ip, PORT);
                let stream = TcpStream::connect(&addr)
                    .with_context(|| format!("Failed to connect to {}. Make sure the receiver is running and the IP address is correct.", addr))?;

                optimize_tcp_stream(&stream)?;

                let mut buffered_stream = BufWriter::with_capacity(BUFFER_SIZE, stream);

                // Send protocol header
                buffered_stream.write_all(&salt).context("Failed to send salt")?;
                buffered_stream.write_all(&total_size.to_be_bytes()).context("Failed to send size")?;

                // Send transfer type
                let transfer_type = if is_file { TRANSFER_TYPE_SINGLE_FILE } else { TRANSFER_TYPE_DIRECTORY };
                buffered_stream.write_all(&[transfer_type]).context("Failed to send transfer type")?;

                // For single files, send filename
                if is_file {
                    let filename = path.file_name()
                        .and_then(|n| n.to_str())
                        .context("Invalid filename")?;
                    let filename_bytes = filename.as_bytes();
                    buffered_stream.write_all(&(filename_bytes.len() as u32).to_be_bytes())?;
                    buffered_stream.write_all(filename_bytes)?;
                }

                buffered_stream.flush()?;

                let progress = Arc::new(ProgressBar::new(total_size));
                progress.set_style(
                    ProgressStyle::default_bar()
                        .template("{msg}\n{bar:40.cyan/blue} {bytes}/{total_bytes} | {bytes_per_sec} | {eta_precise}")
                        .unwrap()
                        .progress_chars("=>-"),
                );
                progress.set_message("Sending");

                let start = Instant::now();
                let aes_writer = AesWriter::new(buffered_stream, &key, &iv)?;
                let mut zstd_encoder = ZstdEncoder::new(aes_writer, 3)?;
                zstd_encoder.multithread(num_cpus::get() as u32)?;

                if is_file {
                    // Fast path: stream file directly without tar overhead
                    let mut file = File::open(path)?;
                    let progress_writer = ProgressWriter::new(&mut zstd_encoder, progress.clone());
                    let mut buf_writer = BufWriter::with_capacity(BUFFER_SIZE, progress_writer);
                    io::copy(&mut file, &mut buf_writer)?;
                    buf_writer.flush()?;
                } else {
                    // Directory: use parallel file buffering with tar
                    let base_path = path.parent().unwrap_or_else(|| Path::new(".")).to_path_buf();
                    let dir_name = path.file_name().unwrap_or(path.as_os_str());

                    // Collect all file entries
                    let mut entries: Vec<DirEntry> = WalkDir::new(path)
                        .into_iter()
                        .filter_map(|e| e.ok())
                        .filter(|e| e.file_type().is_file())
                        .collect();

                    // Sort for deterministic ordering
                    entries.sort_by(|a, b| a.path().cmp(b.path()));

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

                        match entry {
                            FileEntry::Buffered { relative_path, data, mode } => {
                                let tar_path = PathBuf::from(dir_name).join(&relative_path);

                                let mut header = tar::Header::new_gnu();
                                header.set_size(data.len() as u64);
                                header.set_mode(mode);
                                header.set_cksum();

                                tar_builder.append_data(&mut header, tar_path, &data[..])?;
                            }
                            FileEntry::Streamed { relative_path, full_path, size, mode } => {
                                let tar_path = PathBuf::from(dir_name).join(&relative_path);

                                let mut file = File::open(&full_path)
                                    .with_context(|| format!("Failed to open {}", full_path.display()))?;

                                let mut header = tar::Header::new_gnu();
                                header.set_size(size);
                                header.set_mode(mode);
                                header.set_cksum();

                                tar_builder.append_data(&mut header, tar_path, &mut file)?;
                            }
                        }

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
                Ok(())
            }).await??;
        }
    }

    Ok(())
}
