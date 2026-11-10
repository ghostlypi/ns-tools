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
        mtime: u64,
    },
    Streamed {
        relative_path: PathBuf,
        full_path: PathBuf,
        size: u64,
        mode: u32,
        mtime: u64,
    },
    /// A directory, sent as its own entry so empty directories survive and the
    /// receiver can restore its mode and mtime.
    Dir {
        relative_path: PathBuf,
        mode: u32,
        mtime: u64,
    },
    /// A symlink, sent as a link (never followed). The target is carried verbatim,
    /// relative or absolute, exactly as `readlink` returns it.
    Symlink {
        relative_path: PathBuf,
        target: PathBuf,
        mtime: u64,
    },
}

/// Seconds since the Unix epoch, clamped to 0 for pre-1970 or unreadable timestamps.
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
    if metadata.is_dir() {
        0o755
    } else {
        0o644
    }
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
            let entry = entry.map_err(|e| TransferError::ReadFile {
                path: path.to_path_buf(),
                source: e.into(),
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

/// Collect every directory, regular file and symlink under `path` (including `path`
/// itself), sorted for deterministic ordering.
///
/// Symlinks are never followed. Sockets, FIFOs and device nodes are skipped: they are
/// runtime objects, not data. A directory that cannot be read is an error rather than
/// being silently left out of the transfer.
pub(crate) fn collect_entries(path: &Path) -> Result<Vec<DirEntry>> {
    let mut entries = Vec::new();
    for entry in WalkDir::new(path) {
        let entry = entry.map_err(|e| TransferError::ReadFile {
            path: e.path().unwrap_or(path).to_path_buf(),
            source: e.into(),
        })?;
        let ft = entry.file_type();
        if ft.is_file() || ft.is_dir() || ft.is_symlink() {
            entries.push(entry);
        }
    }
    entries.sort_by(|a, b| a.path().cmp(b.path()));
    Ok(entries)
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
    // `DirEntry::metadata` does not follow symlinks, so a link reports itself.
    let metadata = entry.metadata().map_err(|e| TransferError::ReadFile {
        path: path.to_path_buf(),
        source: std::io::Error::other(e),
    })?;

    let relative_path = path.strip_prefix(base_path).unwrap_or(path).to_path_buf();
    let mtime = mtime_of(&metadata);
    let read_err = |source| TransferError::ReadFile {
        path: path.to_path_buf(),
        source,
    };

    if metadata.file_type().is_symlink() {
        let target = std::fs::read_link(path).map_err(read_err)?;
        return Ok(FileEntry::Symlink {
            relative_path,
            target,
            mtime,
        });
    }

    let mode = mode_of(&metadata);

    if metadata.is_dir() {
        return Ok(FileEntry::Dir {
            relative_path,
            mode,
            mtime,
        });
    }

    if !metadata.is_file() {
        return Err(TransferError::protocol(format!(
            "{} is not a regular file, directory or symlink",
            path.display()
        )));
    }

    let size = metadata.len();
    if size <= MAX_FILE_BUFFER_SIZE {
        let mut data = Vec::with_capacity(size as usize);
        File::open(path)
            .map_err(read_err)?
            .read_to_end(&mut data)
            .map_err(read_err)?;
        Ok(FileEntry::Buffered {
            relative_path,
            data,
            mode,
            mtime,
        })
    } else {
        Ok(FileEntry::Streamed {
            relative_path,
            full_path: path.to_path_buf(),
            size,
            mode,
            mtime,
        })
    }
}

/// Append one entry to the tar under `<dir_name>/<relative_path>`, carrying its
/// type, mode and mtime. The receiver's `tar::Archive::unpack` restores all three.
pub(crate) fn append_entry<W: std::io::Write>(
    tar: &mut tar::Builder<W>,
    dir_name: &Path,
    entry: FileEntry,
) -> Result<()> {
    let mut header = tar::Header::new_gnu();
    match entry {
        FileEntry::Buffered {
            relative_path,
            data,
            mode,
            mtime,
        } => {
            header.set_entry_type(tar::EntryType::Regular);
            header.set_size(data.len() as u64);
            header.set_mode(mode);
            header.set_mtime(mtime);
            tar.append_data(&mut header, dir_name.join(&relative_path), &data[..])?;
        }
        FileEntry::Streamed {
            relative_path,
            full_path,
            size,
            mode,
            mtime,
        } => {
            let mut file = File::open(&full_path).map_err(|source| TransferError::ReadFile {
                path: full_path.clone(),
                source,
            })?;
            header.set_entry_type(tar::EntryType::Regular);
            header.set_size(size);
            header.set_mode(mode);
            header.set_mtime(mtime);
            tar.append_data(&mut header, dir_name.join(&relative_path), &mut file)?;
        }
        FileEntry::Dir {
            relative_path,
            mode,
            mtime,
        } => {
            header.set_entry_type(tar::EntryType::Directory);
            header.set_size(0);
            header.set_mode(mode);
            header.set_mtime(mtime);
            tar.append_data(&mut header, dir_name.join(&relative_path), std::io::empty())?;
        }
        FileEntry::Symlink {
            relative_path,
            target,
            mtime,
        } => {
            header.set_entry_type(tar::EntryType::Symlink);
            header.set_size(0);
            header.set_mode(0o777);
            header.set_mtime(mtime);
            // `append_link` emits GNU long-name/long-link records when either path
            // exceeds the 100-byte header field.
            tar.append_link(&mut header, dir_name.join(&relative_path), &target)?;
        }
    }
    Ok(())
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;
    use std::time::{Duration, UNIX_EPOCH};

    fn set_mtime(path: &Path, secs: u64) {
        File::open(path)
            .unwrap()
            .set_modified(UNIX_EPOCH + Duration::from_secs(secs))
            .unwrap();
    }

    fn mtime(path: &Path) -> u64 {
        std::fs::symlink_metadata(path)
            .unwrap()
            .modified()
            .unwrap()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    /// Pack a tree with the real walker/reader/appender, unpack it with the same
    /// `unpack_tar` the receiver uses, and compare.
    #[test]
    fn tree_roundtrips_links_dirs_and_mtimes() {
        let src = tempfile::tempdir().unwrap();
        let root = src.path().join("tree");
        std::fs::create_dir_all(root.join("empty")).unwrap();
        std::fs::create_dir_all(root.join("sub")).unwrap();
        std::fs::write(root.join("sub/f.txt"), b"hello").unwrap();
        symlink("sub/f.txt", root.join("link")).unwrap();
        symlink("nowhere", root.join("dangling")).unwrap();
        set_mtime(&root.join("sub/f.txt"), 1_500_000_000);
        set_mtime(&root.join("empty"), 1_510_000_000);
        set_mtime(&root.join("sub"), 1_520_000_000);

        let entries = collect_entries(&root).unwrap();
        let mut tar = tar::Builder::new(Vec::new());
        for e in &entries {
            append_entry(&mut tar, Path::new("tree"), read_one(e, &root).unwrap()).unwrap();
        }
        let bytes = tar.into_inner().unwrap();

        let dest = tempfile::tempdir().unwrap();
        unpack_tar(&bytes[..], dest.path()).unwrap();
        let out = dest.path().join("tree");

        assert_eq!(std::fs::read(out.join("sub/f.txt")).unwrap(), b"hello");
        assert_eq!(
            std::fs::read_link(out.join("link")).unwrap(),
            Path::new("sub/f.txt")
        );
        assert_eq!(
            std::fs::read_link(out.join("dangling")).unwrap(),
            Path::new("nowhere")
        );
        assert!(out.join("empty").is_dir());
        assert_eq!(mtime(&out.join("sub/f.txt")), 1_500_000_000);
        assert_eq!(mtime(&out.join("empty")), 1_510_000_000);
        assert_eq!(mtime(&out.join("sub")), 1_520_000_000);
    }

    #[test]
    fn single_file_roundtrips_with_mtime() {
        let src = tempfile::tempdir().unwrap();
        let f = src.path().join("one.txt");
        std::fs::write(&f, b"solo").unwrap();
        set_mtime(&f, 1_400_000_000);

        let mut tar = tar::Builder::new(Vec::new());
        append_entry(&mut tar, Path::new(""), single_file_entry(&f).unwrap()).unwrap();
        let bytes = tar.into_inner().unwrap();

        let dest = tempfile::tempdir().unwrap();
        unpack_tar(&bytes[..], dest.path()).unwrap();
        assert_eq!(std::fs::read(dest.path().join("one.txt")).unwrap(), b"solo");
        assert_eq!(mtime(&dest.path().join("one.txt")), 1_400_000_000);
    }

    #[test]
    fn unreadable_directory_is_an_error() {
        use std::os::unix::fs::PermissionsExt;
        if unsafe { libc::geteuid() } == 0 {
            return;
        }
        let src = tempfile::tempdir().unwrap();
        let locked = src.path().join("locked");
        std::fs::create_dir_all(locked.join("inner")).unwrap();
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o000)).unwrap();
        let result = collect_entries(src.path());
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(result.is_err());
    }
}

/// Unpack a tar stream into `dst`, like `tar::Archive::unpack`, but also restore
/// directory mtimes (the tar crate sets a directory's permissions, never its mtime).
///
/// This mirrors `Archive::unpack` step for step: create and canonicalize `dst`,
/// unpack non-directories as they stream past, then directories in reverse path
/// order, every entry through `Entry::unpack_in` and its traversal checks. Only then,
/// once nothing else will write into them, are directory mtimes set — best-effort,
/// and only on paths that are still real directories inside `dst`.
pub(crate) fn unpack_tar<R: Read>(reader: R, dst: &Path) -> std::io::Result<()> {
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
        let inside = path
            .canonicalize()
            .map(|c| c.starts_with(dst))
            .unwrap_or(false);
        if is_real_dir && inside {
            let t = std::time::UNIX_EPOCH + std::time::Duration::from_secs(mtime);
            if let Ok(f) = File::open(&path) {
                let _ = f.set_modified(t);
            }
        }
    }
    Ok(())
}

/// A single file named on the command line, as a top-level tar entry.
///
/// Unlike the directory walk this follows a symlink: naming a link means "send
/// what it points to", as the old raw single-file path did.
pub(crate) fn single_file_entry(path: &Path) -> Result<FileEntry> {
    let read_err = |source| TransferError::ReadFile {
        path: path.to_path_buf(),
        source,
    };
    let metadata = std::fs::metadata(path).map_err(read_err)?;
    let relative_path = PathBuf::from(
        path.file_name()
            .ok_or_else(|| TransferError::protocol("path has no file name"))?,
    );
    let (mode, mtime, size) = (mode_of(&metadata), mtime_of(&metadata), metadata.len());
    if size <= MAX_FILE_BUFFER_SIZE {
        let mut data = Vec::with_capacity(size as usize);
        File::open(path)
            .map_err(read_err)?
            .read_to_end(&mut data)
            .map_err(read_err)?;
        Ok(FileEntry::Buffered {
            relative_path,
            data,
            mode,
            mtime,
        })
    } else {
        Ok(FileEntry::Streamed {
            relative_path,
            full_path: path.to_path_buf(),
            size,
            mode,
            mtime,
        })
    }
}
