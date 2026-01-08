/**
 *  Network Share ENcrypted (nsen) utility is a file sharing utility for high speed network transfers
 *  between 2 devices.
 *  Copyright © 2025 Parth Iyer
 */

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use indicatif::{ProgressBar, ProgressStyle};
use local_ip_address::local_ip;
use openssl::hash::MessageDigest;
use openssl::pkcs5::pbkdf2_hmac;
use openssl::rand::rand_bytes;
use openssl::symm::{Cipher, Crypter, Mode};
use rpassword::read_password;
use std::io::{self, BufReader, BufWriter, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;
use tokio::task;
use walkdir::WalkDir;
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
    Send {
        ip: String,
        input: PathBuf,
    },
    Recv,
}

const PORT: u16 = 4444;
const KEY_ITERATIONS: usize = 10000;
const KEY_LEN: usize = 32;
const IV_LEN: usize = 16;
const SALT_LEN: usize = 16;
const BUFFER_SIZE: usize = 256 * 1024; // 256KB buffers for better throughput
const TCP_BUFFER_SIZE: usize = 4 * 1024 * 1024; // 4MB TCP buffers

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

                let mut salt = [0u8; SALT_LEN];
                buffered_stream.read_exact(&mut salt).context("Failed to read salt")?;

                let mut size_bytes = [0u8; 8];
                buffered_stream.read_exact(&mut size_bytes).context("Failed to read size")?;
                let total_size = u64::from_be_bytes(size_bytes);

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
                let progress_reader = ProgressReader::new(zstd_decoder, progress.clone());
                let mut archive = tar::Archive::new(progress_reader);

                archive.unpack(".").context("Failed to unpack archive")?;

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

                let mut salt = [0u8; SALT_LEN];
                rand_bytes(&mut salt).context("Failed to generate salt")?;
                let (key, iv) = derive_key_iv(&password, &salt)?;

                let addr = format!("{}:{}", ip, PORT);
                let stream = TcpStream::connect(&addr)
                    .with_context(|| format!("Failed to connect to {}. Make sure the receiver is running and the IP address is correct.", addr))?;

                optimize_tcp_stream(&stream)?;

                let mut buffered_stream = BufWriter::with_capacity(BUFFER_SIZE, stream);

                buffered_stream.write_all(&salt).context("Failed to send salt")?;

                buffered_stream.write_all(&total_size.to_be_bytes()).context("Failed to send size")?;
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
                zstd_encoder.multithread(num_cpus::get() as u32)?; // Use all available cores

                {
                    let progress_writer = ProgressWriter::new(&mut zstd_encoder, progress.clone());
                    let mut tar_builder = tar::Builder::new(progress_writer);
                    let name = path.file_name().unwrap_or(path.as_os_str());

                    if path.is_dir() {
                        tar_builder.append_dir_all(name, path)?;
                    } else {
                        tar_builder.append_path_with_name(path, name)?;
                    }
                    tar_builder.finish()?;
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
