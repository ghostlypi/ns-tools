//! Walking a directory into tar entries, in parallel.
//!
//! Files at or below [`MAX_FILE_BUFFER_SIZE`] are slurped into memory by a worker pool;
//! larger ones are re-opened and streamed by the tar builder so a single huge file can't
//! blow up memory. Peak buffered memory is bounded by
//! `FILE_BUFFER_QUEUE_SIZE * MAX_FILE_BUFFER_SIZE` (~256 MiB).

use crate::error::{Result, TransferError};
use crossbeam_channel::Sender;
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use walkdir::{DirEntry, WalkDir};

/// Number of file buffers in flight between the reader pool and the tar builder.
pub(crate) const FILE_BUFFER_QUEUE_SIZE: usize = 16;
/// Files larger than this are streamed rather than buffered.
pub(crate) const MAX_FILE_BUFFER_SIZE: u64 = 16 * 1024 * 1024;

pub(crate) enum FileEntry {
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

/// Total bytes of file content under `path`.
///
/// Note this counts payload only — for a directory the tar headers and padding are not
/// included, which is why progress reporting clamps rather than trusting the ratio.
pub(crate) fn calculate_size(path: &Path) -> Result<u64> {
    if path.is_file() {
        Ok(std::fs::metadata(path)
            .map_err(|source| TransferError::ReadFile {
                path: path.to_path_buf(),
                source,
            })?
            .len())
    } else if path.is_dir() {
        let mut total = 0u64;
        for entry in WalkDir::new(path) {
            let entry = entry.map_err(|e| {
                TransferError::ReadFile {
                    path: path.to_path_buf(),
                    source: e.into(),
                }
            })?;
            if entry.file_type().is_file() {
                total += entry
                    .metadata()
                    .map_err(|e| TransferError::ReadFile {
                        path: entry.path().to_path_buf(),
                        source: std::io::Error::other(e),
                    })?
                    .len();
            }
        }
        Ok(total)
    } else {
        Ok(0)
    }
}

/// Collect every regular file under `path`, sorted for deterministic ordering.
///
/// Symlinks and empty directories are skipped — matching the original behaviour, and
/// worth knowing: an empty directory does not survive a transfer.
pub(crate) fn collect_entries(path: &Path) -> Vec<DirEntry> {
    let mut entries: Vec<DirEntry> = WalkDir::new(path)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
        .collect();
    entries.sort_by(|a, b| a.path().cmp(b.path()));
    entries
}

pub(crate) fn file_reader_worker(
    work_rx: crossbeam_channel::Receiver<DirEntry>,
    result_tx: Sender<Result<FileEntry>>,
    base_path: PathBuf,
) {
    while let Ok(entry) = work_rx.recv() {
        let result = read_one(&entry, &base_path);
        if result_tx.send(result).is_err() {
            break;
        }
    }
}

fn read_one(entry: &DirEntry, base_path: &Path) -> Result<FileEntry> {
    let path = entry.path();
    let metadata = entry.metadata().map_err(|e| TransferError::ReadFile {
        path: path.to_path_buf(),
        source: std::io::Error::other(e),
    })?;

    if !metadata.is_file() {
        return Err(TransferError::protocol(format!(
            "{} is not a regular file",
            path.display()
        )));
    }

    let relative_path = path.strip_prefix(base_path).unwrap_or(path).to_path_buf();
    let size = metadata.len();

    #[cfg(unix)]
    let mode = {
        use std::os::unix::fs::PermissionsExt;
        metadata.permissions().mode()
    };
    #[cfg(not(unix))]
    let mode = 0o644;

    let open_err = |source| TransferError::ReadFile {
        path: path.to_path_buf(),
        source,
    };

    if size <= MAX_FILE_BUFFER_SIZE {
        let mut data = Vec::with_capacity(size as usize);
        File::open(path)
            .map_err(open_err)?
            .read_to_end(&mut data)
            .map_err(open_err)?;
        Ok(FileEntry::Buffered {
            relative_path,
            data,
            mode,
        })
    } else {
        Ok(FileEntry::Streamed {
            relative_path,
            full_path: path.to_path_buf(),
            size,
            mode,
        })
    }
}
