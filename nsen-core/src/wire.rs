//! The wire-v1 stream header.
//!
//! ```text
//! salt[16] || total_size:u64be || transfer_type:u8 || [name_len:u32be || name]
//! ```
//!
//! The name field is present only for single-file transfers; directory transfers carry
//! their names inside the tar. Everything after the header is AES-256-CBC ciphertext of
//! a zstd stream, running to EOF.
//!
//! Known limitations, all inherited and all addressed by the planned v2 format: there is
//! no magic number, no version field, no MAC over the header, and no completion marker —
//! so a truncated transfer is only distinguishable from a short one because zstd or the
//! CBC unpadding happens to fail.

use crate::error::{Result, TransferError};
use std::io::{Read, Write};
use std::path::Path;

pub(crate) const SALT_LEN: usize = 16;
pub(crate) const TRANSFER_TYPE_SINGLE_FILE: u8 = 0;
pub(crate) const TRANSFER_TYPE_DIRECTORY: u8 = 1;

/// Reduce a filename received over the wire to a bare, safe basename.
///
/// The sender controls this string and the receiver joins it onto the destination
/// directory. Without this guard a peer whose transfer is accepted can write
/// `../.bashrc` or `../.config/autostart/evil.desktop`.
///
/// Only the single-file path needs this: directory transfers go through
/// `pack::unpack_tar`, which routes every entry through `tar::Entry::unpack_in` and its checks.
pub(crate) fn sanitize_wire_filename(raw: &str) -> Result<String> {
    let name = Path::new(raw)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("");

    // `file_name()` strips '/', but a backslash is a legal filename byte on Unix, so a
    // Windows-style path would otherwise survive as one long literal name.
    if name.is_empty() || name == "." || name == ".." || name.contains('\\') {
        return Err(TransferError::UnsafeFilename(raw.to_string()));
    }
    Ok(name.to_string())
}

pub(crate) struct Header {
    pub salt: [u8; SALT_LEN],
    /// Total plaintext bytes, used only to drive the progress display.
    pub total_size: u64,
    /// `Some` for a single file, `None` for a directory.
    pub filename: Option<String>,
}

impl Header {
    pub fn write(&self, w: &mut impl Write) -> Result<()> {
        w.write_all(&self.salt)?;
        w.write_all(&self.total_size.to_be_bytes())?;
        match &self.filename {
            Some(name) => {
                w.write_all(&[TRANSFER_TYPE_SINGLE_FILE])?;
                let bytes = name.as_bytes();
                w.write_all(&(bytes.len() as u32).to_be_bytes())?;
                w.write_all(bytes)?;
            }
            None => w.write_all(&[TRANSFER_TYPE_DIRECTORY])?,
        }
        Ok(())
    }

    /// Read and validate a header. The filename is sanitized here, at the parse site,
    /// so no downstream code can accidentally use the raw value.
    pub fn read(r: &mut impl Read) -> Result<Self> {
        let mut salt = [0u8; SALT_LEN];
        r.read_exact(&mut salt)?;

        let mut size_bytes = [0u8; 8];
        r.read_exact(&mut size_bytes)?;
        let total_size = u64::from_be_bytes(size_bytes);

        let mut transfer_type = [0u8; 1];
        r.read_exact(&mut transfer_type)?;

        let filename = match transfer_type[0] {
            TRANSFER_TYPE_SINGLE_FILE => {
                let mut len_bytes = [0u8; 4];
                r.read_exact(&mut len_bytes)?;
                let len = u32::from_be_bytes(len_bytes) as usize;

                let mut name_bytes = vec![0u8; len];
                r.read_exact(&mut name_bytes)?;
                let raw = String::from_utf8(name_bytes)
                    .map_err(|_| TransferError::protocol("filename is not valid UTF-8"))?;
                Some(sanitize_wire_filename(&raw)?)
            }
            TRANSFER_TYPE_DIRECTORY => None,
            other => {
                return Err(TransferError::protocol(format!(
                    "unknown transfer type {other}"
                )))
            }
        };

        Ok(Header {
            salt,
            total_size,
            filename,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_strips_traversal() {
        // The actual attack: under netdrop the destination is ~/Downloads.
        assert_eq!(sanitize_wire_filename("../.bashrc").unwrap(), ".bashrc");
        assert_eq!(
            sanitize_wire_filename("../../.config/autostart/evil.desktop").unwrap(),
            "evil.desktop"
        );
        assert_eq!(sanitize_wire_filename("/etc/passwd").unwrap(), "passwd");
        assert_eq!(sanitize_wire_filename("a/b/c.txt").unwrap(), "c.txt");
    }

    #[test]
    fn sanitize_passes_ordinary_names_through() {
        for name in ["photo.jpg", "a b c.tar.gz", "café ☕.txt", ".hidden"] {
            assert_eq!(sanitize_wire_filename(name).unwrap(), name);
        }
    }

    #[test]
    fn sanitize_rejects_names_with_no_basename() {
        for bad in ["", ".", "..", "../..", "/", "///", "foo\\..\\bar"] {
            assert!(
                sanitize_wire_filename(bad).is_err(),
                "should have rejected {bad:?}"
            );
        }
    }

    #[test]
    fn header_roundtrips_single_file() {
        let h = Header {
            salt: [7u8; SALT_LEN],
            total_size: 123456,
            filename: Some("photo.jpg".into()),
        };
        let mut buf = Vec::new();
        h.write(&mut buf).unwrap();
        // 16 salt + 8 size + 1 type + 4 len + 9 name
        assert_eq!(buf.len(), 38);

        let got = Header::read(&mut &buf[..]).unwrap();
        assert_eq!(got.salt, [7u8; SALT_LEN]);
        assert_eq!(got.total_size, 123456);
        assert_eq!(got.filename.as_deref(), Some("photo.jpg"));
    }

    #[test]
    fn header_roundtrips_directory() {
        let h = Header {
            salt: [0u8; SALT_LEN],
            total_size: 0,
            filename: None,
        };
        let mut buf = Vec::new();
        h.write(&mut buf).unwrap();
        assert_eq!(buf.len(), 25);
        assert!(Header::read(&mut &buf[..]).unwrap().filename.is_none());
    }

    /// A malicious peer cannot get a traversing name past the parser at all.
    #[test]
    fn header_read_rejects_traversal() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&[0u8; SALT_LEN]);
        buf.extend_from_slice(&64u64.to_be_bytes());
        buf.push(TRANSFER_TYPE_SINGLE_FILE);
        let name = b"../escaped.txt";
        buf.extend_from_slice(&(name.len() as u32).to_be_bytes());
        buf.extend_from_slice(name);

        // Sanitized to a basename rather than rejected outright — the transfer still
        // lands, just inside the destination where it belongs.
        assert_eq!(
            Header::read(&mut &buf[..]).unwrap().filename.as_deref(),
            Some("escaped.txt")
        );
    }

    #[test]
    fn header_read_rejects_unknown_transfer_type() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&[0u8; SALT_LEN]);
        buf.extend_from_slice(&0u64.to_be_bytes());
        buf.push(99);
        assert!(matches!(
            Header::read(&mut &buf[..]),
            Err(TransferError::Protocol(_))
        ));
    }
}
