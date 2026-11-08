//! ChaCha20-Poly1305 AEAD, backed by RustCrypto's `chacha20poly1305` crate
//! (independently audited by NCC Group). The RFC 8439 vector test below
//! pins the wiring. Keys are one-time, encapsulated per bundle in `kem`.

#[allow(unused_imports)]
use crate::alloc_prelude::*;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};

/// Poly1305 authentication tag length, in bytes.
pub const TAG_LEN: usize = 16;

/// Nonce length, in bytes.
pub const NONCE_LEN: usize = 12;

/// AEAD failure. Deliberately carries no detail: distinguishing "bad tag" from
/// "bad length" gives an attacker a decryption oracle.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AeadError;

/// Encrypt `plaintext` under a one-time `key`, authenticating `aad` alongside.
/// Returns `ciphertext || tag`.
pub fn seal(key: &[u8; 32], nonce: &[u8; NONCE_LEN], aad: &[u8], plaintext: &[u8]) -> Vec<u8> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    cipher
        .encrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .expect("in-memory encryption cannot fail")
}

/// Verify and decrypt `ciphertext || tag`. The tag is checked before any
/// plaintext is produced.
pub fn open(
    key: &[u8; 32],
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    sealed: &[u8],
) -> Result<Vec<u8>, AeadError> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    cipher
        .decrypt(Nonce::from_slice(nonce), Payload { msg: sealed, aad })
        .map_err(|_| AeadError)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{:02x}", x)).collect()
    }

    #[test]
    fn rfc8439_aead_vector() {
        // RFC 8439 section 2.8.2.
        let mut key = [0u8; 32];
        for (i, b) in key.iter_mut().enumerate() {
            *b = 0x80 + i as u8;
        }
        let nonce: [u8; 12] = [
            0x07, 0x00, 0x00, 0x00, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
        ];
        let aad: [u8; 12] = [
            0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7,
        ];
        let plaintext = b"Ladies and Gentlemen of the class of '99: If I could offer you \
                          only one tip for the future, sunscreen would be it.";

        let sealed = seal(&key, &nonce, &aad, plaintext);
        let (ct, tag) = sealed.split_at(sealed.len() - TAG_LEN);

        assert_eq!(
            hex(ct),
            "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d6\
             3dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b36\
             92ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc\
             3ff4def08e4b7a9de576d26586cec64b6116"
        );
        assert_eq!(hex(tag), "1ae10b594f09e26a7e902ecbd0600691");

        // And decryption round-trips.
        assert_eq!(open(&key, &nonce, &aad, &sealed).unwrap(), plaintext);
    }

    #[test]
    fn seal_open_roundtrip() {
        let key = [3u8; 32];
        let nonce = [1u8; NONCE_LEN];
        let sealed = seal(&key, &nonce, b"aad", b"telemetry");
        assert_eq!(open(&key, &nonce, b"aad", &sealed).unwrap(), b"telemetry");
    }

    #[test]
    fn tampered_ciphertext_is_rejected() {
        let key = [3u8; 32];
        let nonce = [1u8; NONCE_LEN];
        let mut sealed = seal(&key, &nonce, b"aad", b"telemetry");
        sealed[0] ^= 0xff;
        assert_eq!(open(&key, &nonce, b"aad", &sealed), Err(AeadError));
    }

    #[test]
    fn tampered_aad_is_rejected() {
        let key = [3u8; 32];
        let nonce = [1u8; NONCE_LEN];
        let sealed = seal(&key, &nonce, b"aad", b"telemetry");
        assert_eq!(open(&key, &nonce, b"different", &sealed), Err(AeadError));
    }

    #[test]
    fn wrong_key_is_rejected() {
        let nonce = [1u8; NONCE_LEN];
        let sealed = seal(&[3u8; 32], &nonce, b"aad", b"telemetry");
        assert_eq!(open(&[4u8; 32], &nonce, b"aad", &sealed), Err(AeadError));
    }

    #[test]
    fn empty_plaintext_and_aad() {
        let key = [9u8; 32];
        let nonce = [2u8; NONCE_LEN];
        let sealed = seal(&key, &nonce, b"", b"");
        assert_eq!(sealed.len(), TAG_LEN);
        assert_eq!(open(&key, &nonce, b"", &sealed).unwrap(), b"");
    }

    #[test]
    fn truncated_input_is_rejected() {
        // Shorter than a tag: must fail cleanly, not panic.
        assert_eq!(
            open(&[9u8; 32], &[2u8; NONCE_LEN], b"", &[0u8; 7]),
            Err(AeadError)
        );
    }
}
