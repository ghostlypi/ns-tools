//! Wire-v1 key derivation and the AES-256-CBC stream adapters.
//!
//! This module is the one Phase 2 replaces with RustCrypto. The known-answer tests at
//! the bottom were generated with the `openssl` command-line tool rather than with this
//! code, so they remain a valid oracle across that swap.

use crate::error::{Result, TransferError};
use openssl::hash::MessageDigest;
use openssl::pkcs5::pbkdf2_hmac;
use openssl::symm::{Cipher, Crypter, Mode};
use std::io::{self, Read, Write};

pub(crate) const KEY_ITERATIONS: usize = 10000;
pub(crate) const KEY_LEN: usize = 32;
pub(crate) const IV_LEN: usize = 16;
pub(crate) const BUFFER_SIZE: usize = 256 * 1024;

/// Fill `buf` with cryptographically secure random bytes.
pub(crate) fn random_bytes(buf: &mut [u8]) -> Result<()> {
    openssl::rand::rand_bytes(buf).map_err(TransferError::crypto)
}

/// PBKDF2-HMAC-SHA256 over `password` and `salt`, split into a 32-byte key and a
/// 16-byte IV. Iteration count and digest are part of the wire format — changing
/// either makes every existing peer undecryptable.
pub(crate) fn derive_key_iv(password: &str, salt: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    let mut key_iv = vec![0u8; KEY_LEN + IV_LEN];
    pbkdf2_hmac(
        password.as_bytes(),
        salt,
        KEY_ITERATIONS,
        MessageDigest::sha256(),
        &mut key_iv,
    )
    .map_err(TransferError::crypto)?;
    let (key, iv) = key_iv.split_at(KEY_LEN);
    Ok((key.to_vec(), iv.to_vec()))
}

pub(crate) struct AesWriter<W: Write> {
    writer: W,
    crypter: Crypter,
    buffer: Vec<u8>,
}

impl<W: Write> AesWriter<W> {
    pub fn new(writer: W, key: &[u8], iv: &[u8]) -> io::Result<Self> {
        let crypter = Crypter::new(Cipher::aes_256_cbc(), Mode::Encrypt, key, Some(iv))
            .map_err(io::Error::other)?;
        Ok(Self {
            writer,
            crypter,
            buffer: vec![0; BUFFER_SIZE + 16],
        })
    }

    /// Emit the final PKCS#7 padding block and flush.
    pub fn finish(&mut self) -> io::Result<()> {
        let count = self
            .crypter
            .finalize(&mut self.buffer)
            .map_err(io::Error::other)?;
        if count > 0 {
            self.writer.write_all(&self.buffer[..count])?;
        }
        self.writer.flush()?;
        Ok(())
    }
}

impl<W: Write> Write for AesWriter<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        // `Crypter::update` needs room for one extra block. Nothing in the normal
        // pipeline hands us more than BUFFER_SIZE at once, but a library caller can.
        if self.buffer.len() < buf.len() + 16 {
            self.buffer.resize(buf.len() + 16, 0);
        }
        let count = self
            .crypter
            .update(buf, &mut self.buffer)
            .map_err(io::Error::other)?;
        if count > 0 {
            self.writer.write_all(&self.buffer[..count])?;
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.writer.flush()
    }
}

pub(crate) struct AesReader<R: Read> {
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
            .map_err(io::Error::other)?;
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
        // Loop rather than recurse: a reader that yields very little at a time (which
        // `io::Read` explicitly permits) would otherwise nest one frame per short read.
        loop {
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
                let count = self
                    .crypter
                    .finalize(&mut self.out_buffer)
                    .map_err(io::Error::other)?;
                self.out_pos = 0;
                self.out_len = count;
                if count == 0 {
                    return Ok(0);
                }
                continue;
            }

            let count = self
                .crypter
                .update(&self.in_buffer[..n], &mut self.out_buffer)
                .map_err(io::Error::other)?;
            self.out_pos = 0;
            self.out_len = count;

            // A short input can decrypt to nothing; go round again rather than
            // returning Ok(0), which callers would read as end-of-stream.
            if buf.is_empty() {
                return Ok(0);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// PBKDF2-HMAC-SHA256, pass="hunter2", salt=00..0f, 10 000 iterations, 48 bytes.
    /// Regenerate with:
    ///   openssl kdf -keylen 48 -kdfopt digest:SHA2-256 -kdfopt pass:hunter2 \
    ///     -kdfopt hexsalt:000102030405060708090a0b0c0d0e0f -kdfopt iter:10000 PBKDF2
    const KAT_SALT: [u8; 16] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f,
    ];
    const KAT_PASSWORD: &str = "hunter2";
    const KAT_KEY_HEX: &str = "cef000bef1c43b047de293e1001f10b2f97e6e5dea7cf4b6719fc559b14912c5";
    const KAT_IV_HEX: &str = "4bb2fcf3f275833314dd1b8ab2b11c14";

    fn to_hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    fn from_hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("valid hex"))
            .collect()
    }

    fn encrypt(plaintext: &[u8], key: &[u8], iv: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        {
            let mut w = AesWriter::new(&mut out, key, iv).expect("cipher init");
            w.write_all(plaintext).expect("encrypt");
            w.finish().expect("finalize");
        }
        out
    }

    fn decrypt(ciphertext: &[u8], key: &[u8], iv: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        AesReader::new(ciphertext, key, iv)
            .expect("cipher init")
            .read_to_end(&mut out)
            .expect("decrypt");
        out
    }

    /// The vector that catches a bad RustCrypto port. If this drifts, every peer running
    /// the released build becomes unable to decrypt anything we send.
    #[test]
    fn pbkdf2_matches_openssl_kat() {
        let (key, iv) = derive_key_iv(KAT_PASSWORD, &KAT_SALT).expect("derive");
        assert_eq!(to_hex(&key), KAT_KEY_HEX, "PBKDF2 key drifted");
        assert_eq!(to_hex(&iv), KAT_IV_HEX, "PBKDF2 IV drifted");
    }

    #[test]
    fn pbkdf2_is_salt_dependent() {
        let (k1, _) = derive_key_iv(KAT_PASSWORD, &KAT_SALT).unwrap();
        let (k2, _) = derive_key_iv(KAT_PASSWORD, &[0xff; 16]).unwrap();
        assert_ne!(k1, k2);
    }

    /// 30-byte input: PKCS#7 pads to a 32-byte ciphertext.
    #[test]
    fn aes_cbc_partial_pad_matches_openssl_kat() {
        let ct = encrypt(
            b"nsen wire v1 known-answer test",
            &from_hex(KAT_KEY_HEX),
            &from_hex(KAT_IV_HEX),
        );
        assert_eq!(
            to_hex(&ct),
            "e24b573cf0370a1ccd1db3c595da909cc385c26854dcf9737b6bf4d4613d0542"
        );
    }

    /// 16-byte input: PKCS#7 must emit a *whole extra block* of padding. Getting this
    /// wrong is the classic reimplementation bug and it is invisible on other inputs.
    #[test]
    fn aes_cbc_full_block_pad_matches_openssl_kat() {
        let ct = encrypt(
            b"0123456789abcdef",
            &from_hex(KAT_KEY_HEX),
            &from_hex(KAT_IV_HEX),
        );
        assert_eq!(
            to_hex(&ct),
            "b9d6ada9951b3cbe5ec5e5579f6d0a2a2ff16fa3c663402609d1f1eed453085b"
        );
    }

    #[test]
    fn aes_roundtrips_empty_input() {
        let (key, iv) = (from_hex(KAT_KEY_HEX), from_hex(KAT_IV_HEX));
        let ct = encrypt(b"", &key, &iv);
        assert_eq!(ct.len(), 16, "empty plaintext still emits one pad block");
        assert_eq!(decrypt(&ct, &key, &iv), b"");
    }

    /// Exercises the buffer-resize branch in `AesWriter::write`, which the normal
    /// pipeline never reaches because zstd writes in smaller chunks.
    #[test]
    fn aes_writer_handles_write_larger_than_buffer() {
        let (key, iv) = (from_hex(KAT_KEY_HEX), from_hex(KAT_IV_HEX));
        let big: Vec<u8> = (0..BUFFER_SIZE + 4096).map(|i| (i % 251) as u8).collect();
        assert_eq!(decrypt(&encrypt(&big, &key, &iv), &key, &iv), big);
    }

    /// `io::Read` may return one byte at a time. In production only a `BufReader` feeds
    /// `AesReader`, so this path is otherwise untested — and an in-process caller on
    /// Android could hit it.
    #[test]
    fn aes_reader_handles_one_byte_at_a_time() {
        struct Trickle<R: Read>(R);
        impl<R: Read> Read for Trickle<R> {
            fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
                if buf.is_empty() {
                    return Ok(0);
                }
                self.0.read(&mut buf[..1])
            }
        }

        let (key, iv) = (from_hex(KAT_KEY_HEX), from_hex(KAT_IV_HEX));
        let plain: Vec<u8> = (0..5000).map(|i| (i % 251) as u8).collect();
        let ct = encrypt(&plain, &key, &iv);

        let mut out = Vec::new();
        AesReader::new(Trickle(&ct[..]), &key, &iv)
            .unwrap()
            .read_to_end(&mut out)
            .expect("decrypt from a trickling reader");
        assert_eq!(out, plain);
    }
}
