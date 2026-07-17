//! Post-quantum key exchange (ML-KEM-768 / FIPS 203) and key derivation.
//!
//! Flow: the receiver generates an ephemeral keypair and sends the public
//! (encapsulation) key to the sender. The sender encapsulates to it, producing a
//! ciphertext and a shared secret; the receiver decapsulates the ciphertext with
//! its secret (decapsulation) key to recover the same shared secret. Both sides
//! then derive an identical nsen password from that secret via HKDF.

use anyhow::{anyhow, Result};
use base64::Engine;
use hkdf::Hkdf;
use ml_kem::kem::{Decapsulate, Encapsulate};
use ml_kem::{Ciphertext, Encoded, EncodedSizeUser, KemCore, MlKem768};
use rand::rngs::OsRng;
use sha2::Sha256;

/// Receiver's secret (decapsulation) key.
pub type Dk = <MlKem768 as KemCore>::DecapsulationKey;
/// Public (encapsulation) key, exchanged over the control channel.
pub type Ek = <MlKem768 as KemCore>::EncapsulationKey;

/// Generate an ephemeral ML-KEM-768 keypair `(secret, public)`.
pub fn generate() -> (Dk, Ek) {
    MlKem768::generate(&mut OsRng)
}

/// Serialize the public (encapsulation) key for the wire (~1184 bytes).
pub fn ek_to_bytes(ek: &Ek) -> Vec<u8> {
    ek.as_bytes().to_vec()
}

/// Parse a public key received over the wire.
pub fn ek_from_bytes(bytes: &[u8]) -> Result<Ek> {
    let encoded = Encoded::<Ek>::try_from(bytes)
        .map_err(|_| anyhow!("invalid ML-KEM public key length"))?;
    Ok(Ek::from_bytes(&encoded))
}

/// Sender side: encapsulate to the peer's public key.
/// Returns `(ciphertext_bytes, shared_secret)`.
pub fn encapsulate(ek: &Ek) -> Result<(Vec<u8>, [u8; 32])> {
    let (ct, ss) = ek
        .encapsulate(&mut OsRng)
        .map_err(|_| anyhow!("ML-KEM encapsulation failed"))?;
    let mut secret = [0u8; 32];
    secret.copy_from_slice(ss.as_slice());
    Ok((ct.to_vec(), secret))
}

/// Receiver side: decapsulate the ciphertext with our secret key.
pub fn decapsulate(dk: &Dk, ct_bytes: &[u8]) -> Result<[u8; 32]> {
    let ct = Ciphertext::<MlKem768>::try_from(ct_bytes)
        .map_err(|_| anyhow!("invalid ML-KEM ciphertext length"))?;
    let ss = dk
        .decapsulate(&ct)
        .map_err(|_| anyhow!("ML-KEM decapsulation failed"))?;
    let mut secret = [0u8; 32];
    secret.copy_from_slice(ss.as_slice());
    Ok(secret)
}

/// Derive the nsen password (base64url, no padding) from the KEM shared secret,
/// binding it to the transfer context so a captured secret can't be replayed
/// into a different transfer. Both sides compute this identically.
pub fn derive_password(
    shared_secret: &[u8; 32],
    transfer_id: &str,
    sender_id: &str,
    receiver_id: &str,
) -> String {
    let hk = Hkdf::<Sha256>::new(None, shared_secret);
    let info = format!("nsen-air v1|{transfer_id}|{sender_id}|{receiver_id}");
    let mut okm = [0u8; 32];
    hk.expand(info.as_bytes(), &mut okm)
        .expect("HKDF expand of 32 bytes never fails");
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(okm)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kem_roundtrip_and_key_agreement() {
        // Receiver keypair; public key crosses the wire and is re-parsed.
        let (dk, ek) = generate();
        let ek_bytes = ek_to_bytes(&ek);
        let ek_wire = ek_from_bytes(&ek_bytes).expect("parse public key");

        // Sender encapsulates; receiver decapsulates.
        let (ct, ss_sender) = encapsulate(&ek_wire).expect("encapsulate");
        let ss_receiver = decapsulate(&dk, &ct).expect("decapsulate");
        assert_eq!(ss_sender, ss_receiver, "shared secrets must agree");

        // Both sides derive the identical password from the same context.
        let pw_s = derive_password(&ss_sender, "t1", "alice", "bob");
        let pw_r = derive_password(&ss_receiver, "t1", "alice", "bob");
        assert_eq!(pw_s, pw_r);
        assert!(!pw_s.is_empty());
    }

    #[test]
    fn different_context_yields_different_password() {
        let secret = [7u8; 32];
        let a = derive_password(&secret, "t1", "alice", "bob");
        let b = derive_password(&secret, "t2", "alice", "bob");
        let c = derive_password(&secret, "t1", "eve", "bob");
        assert_ne!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn bad_lengths_are_rejected() {
        assert!(ek_from_bytes(&[0u8; 10]).is_err());
        let (dk, _ek) = generate();
        assert!(decapsulate(&dk, &[0u8; 10]).is_err());
    }
}
