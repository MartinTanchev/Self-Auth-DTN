//! CBOR wire encoding (RFC 8949 subset) of the self-auth and
//! confidentiality blocks as BPSec security-context parameters (block
//! layouts below). Versioned and separate from the hashed encoding
//! in `codec`, so the wire form can evolve without moving identifiers.
//!
//! Self-auth block layout:
//!
//! ```text
//! [ version, alg_suite,
//!   [ first_public_key, next_commitment, metadata ],
//!   inception_sig,
//!   [ [ event_index, revealed_public_key, operational_public_key,
//!       next_commitment, prior_event_hash, signature ] ... ] ]
//! ```
//!
//! Version 2 (crate 0.9) added `operational_public_key`; version 1 logs are
//! refused, because their events let the revealed key sign bundles.
//!
//! # Carriage as a payload
//!
//! A bundle agent without BPSec (uD3TN today) cannot carry these as
//! extension blocks. [`encode_bundle`] and [`encode_bulletin`] pack a whole
//! secured bundle, or a bulletin, into one CBOR item that travels as an
//! ordinary bundle payload (an ADU). The cryptography is the same; what is
//! lost is hop-by-hop checking by forwarders, which never parse payloads.
//!
//! ```text
//! bundle   = [ 1, alg_suite, source_id, name_tag, ipn, self_auth, payload_tag,
//!              payload, bib_signature ]
//! bulletin = [ 2, issuer, seq, expires_at, body, signature ]
//! body     = [ 1, node_id, has_ipn, ipn, kem_public_key, kem_epoch ]
//!          | [ 2, peer_name, peer_root_key ]
//!          | [ 3, node_id, reason, effective_at ]
//! ```
//!
//! `self_auth` is the [`encode_self_auth`] bytes and a confidential
//! `payload` the [`encode_bcb`] bytes, each as a byte string. Text fields are
//! UTF-8 byte strings. Readers refuse trailing bytes and unknown tags.

use crate::aead::NONCE_LEN;
#[allow(unused_imports)]
use crate::alloc_prelude::*;
use crate::bulletin::{Bulletin, BulletinBody, RevocationReason};
use crate::identity::InceptionRecord;
use crate::keylog::KeyEvent;
use crate::naming::SourceName;
use crate::verify::{Bcb, Bib, Bundle, Payload, SelfAuthBlock};

/// Wire-format version this module reads and writes.
pub const WIRE_VERSION: u64 = 2;

/// Carriage tag: a whole secured bundle ([`encode_bundle`]).
pub const ADU_BUNDLE: u64 = 1;
/// Carriage tag: a bulletin ([`encode_bulletin`]).
pub const ADU_BULLETIN: u64 = 2;

/// Algorithm suite: insecure mock backends (tests only).
pub const SUITE_MOCK: u64 = 0;
/// Algorithm suite: ML-DSA-65 signatures, SHA-256 hashing, ML-KEM-1024 KEM.
pub const SUITE_ML_DSA_65_SHA256: u64 = 1;

/// Decoding failures. Deliberately coarse: a decoder that explains exactly what
/// it disliked is a parsing oracle.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WireError {
    /// Input ended before the structure did.
    Truncated,
    /// A CBOR item of the wrong major type where another was required.
    UnexpectedType,
    /// The version field is not one this decoder understands.
    UnsupportedVersion,
    /// Structurally invalid (bad lengths, trailing bytes, oversize counts).
    Malformed,
}

// ---------------------------------------------------------------------------
// Encoder
// ---------------------------------------------------------------------------

fn put_head(buf: &mut Vec<u8>, major: u8, value: u64) {
    let m = major << 5;
    if value < 24 {
        buf.push(m | value as u8);
    } else if value <= 0xff {
        buf.push(m | 24);
        buf.push(value as u8);
    } else if value <= 0xffff {
        buf.push(m | 25);
        buf.extend_from_slice(&(value as u16).to_be_bytes());
    } else if value <= 0xffff_ffff {
        buf.push(m | 26);
        buf.extend_from_slice(&(value as u32).to_be_bytes());
    } else {
        buf.push(m | 27);
        buf.extend_from_slice(&value.to_be_bytes());
    }
}

fn put_uint(buf: &mut Vec<u8>, v: u64) {
    put_head(buf, 0, v);
}

fn put_bstr(buf: &mut Vec<u8>, b: &[u8]) {
    put_head(buf, 2, b.len() as u64);
    buf.extend_from_slice(b);
}

fn put_array(buf: &mut Vec<u8>, len: u64) {
    put_head(buf, 4, len);
}

/// Encode a self-auth block as the security-context parameter bytes.
pub fn encode_self_auth(block: &SelfAuthBlock, alg_suite: u64) -> Vec<u8> {
    let mut buf = Vec::new();
    put_array(&mut buf, 5);
    put_uint(&mut buf, WIRE_VERSION);
    put_uint(&mut buf, alg_suite);

    put_array(&mut buf, 3);
    put_bstr(&mut buf, &block.inception.first_public_key);
    put_bstr(&mut buf, &block.inception.next_commitment);
    put_bstr(&mut buf, &block.inception.metadata);

    put_bstr(&mut buf, &block.inception_sig);

    put_array(&mut buf, block.rotations.len() as u64);
    for ev in &block.rotations {
        put_array(&mut buf, 6);
        put_uint(&mut buf, ev.event_index as u64);
        put_bstr(&mut buf, &ev.revealed_public_key);
        put_bstr(&mut buf, &ev.operational_public_key);
        put_bstr(&mut buf, &ev.next_commitment);
        put_bstr(&mut buf, &ev.prior_event_hash);
        put_bstr(&mut buf, &ev.signature);
    }
    buf
}

/// Encode a confidentiality block.
pub fn encode_bcb(bcb: &Bcb) -> Vec<u8> {
    let mut buf = Vec::new();
    put_array(&mut buf, 4);
    put_bstr(&mut buf, &bcb.kem_ciphertext);
    put_uint(&mut buf, bcb.kem_epoch);
    put_bstr(&mut buf, &bcb.nonce);
    put_bstr(&mut buf, &bcb.sealed_payload);
    buf
}

/// Encode a whole secured bundle (source, name, self-auth block, payload or
/// BCB, BIB) for carriage as a bundle payload. See the module docs.
pub fn encode_bundle(bundle: &Bundle, alg_suite: u64) -> Vec<u8> {
    let mut buf = Vec::new();
    put_array(&mut buf, 9);
    put_uint(&mut buf, ADU_BUNDLE);
    put_uint(&mut buf, alg_suite);
    put_bstr(&mut buf, &bundle.source_id);
    match bundle.name {
        SourceName::SelfCertifying => {
            put_uint(&mut buf, 0);
            put_uint(&mut buf, 0);
        }
        SourceName::Ipn(n) => {
            put_uint(&mut buf, 1);
            put_uint(&mut buf, n);
        }
    }
    put_bstr(&mut buf, &encode_self_auth(&bundle.self_auth, alg_suite));
    match &bundle.payload {
        Payload::Plain(p) => {
            put_uint(&mut buf, 0);
            put_bstr(&mut buf, p);
        }
        Payload::Confidential(bcb) => {
            put_uint(&mut buf, 1);
            put_bstr(&mut buf, &encode_bcb(bcb));
        }
    }
    put_bstr(&mut buf, &bundle.bib.signature);
    buf
}

/// Encode a bulletin for carriage as a bundle payload.
pub fn encode_bulletin(b: &Bulletin) -> Vec<u8> {
    let mut buf = Vec::new();
    put_array(&mut buf, 6);
    put_uint(&mut buf, ADU_BULLETIN);
    put_bstr(&mut buf, b.issuer.as_bytes());
    put_uint(&mut buf, b.seq);
    put_uint(&mut buf, b.expires_at);
    match &b.body {
        BulletinBody::Membership {
            node_id,
            ipn,
            kem_public_key,
            kem_epoch,
        } => {
            put_array(&mut buf, 6);
            put_uint(&mut buf, 1);
            put_bstr(&mut buf, node_id);
            put_uint(&mut buf, ipn.is_some() as u64);
            put_uint(&mut buf, ipn.unwrap_or(0));
            put_bstr(&mut buf, kem_public_key);
            put_uint(&mut buf, *kem_epoch);
        }
        BulletinBody::Peering {
            peer_name,
            peer_root_key,
        } => {
            put_array(&mut buf, 3);
            put_uint(&mut buf, 2);
            put_bstr(&mut buf, peer_name.as_bytes());
            put_bstr(&mut buf, peer_root_key);
        }
        BulletinBody::Revocation {
            node_id,
            reason,
            effective_at,
        } => {
            put_array(&mut buf, 4);
            put_uint(&mut buf, 3);
            put_bstr(&mut buf, node_id);
            put_uint(&mut buf, reason.wire_tag());
            put_uint(&mut buf, *effective_at);
        }
    }
    put_bstr(&mut buf, &b.signature);
    buf
}

// ---------------------------------------------------------------------------
// Decoder
// ---------------------------------------------------------------------------

/// A sanity ceiling on element counts and byte-string lengths, so a hostile
/// header cannot request an absurd allocation.
const MAX_LEN: u64 = 1 << 24;

struct Cur<'a> {
    d: &'a [u8],
    p: usize,
}

impl<'a> Cur<'a> {
    fn byte(&mut self) -> Result<u8, WireError> {
        let b = *self.d.get(self.p).ok_or(WireError::Truncated)?;
        self.p += 1;
        Ok(b)
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], WireError> {
        if self.p + n > self.d.len() {
            return Err(WireError::Truncated);
        }
        let s = &self.d[self.p..self.p + n];
        self.p += n;
        Ok(s)
    }

    fn head(&mut self) -> Result<(u8, u64), WireError> {
        let b = self.byte()?;
        let major = b >> 5;
        let ai = b & 0x1f;
        let value = match ai {
            0..=23 => ai as u64,
            24 => self.byte()? as u64,
            25 => {
                let s = self.take(2)?;
                u16::from_be_bytes([s[0], s[1]]) as u64
            }
            26 => {
                let s = self.take(4)?;
                u32::from_be_bytes([s[0], s[1], s[2], s[3]]) as u64
            }
            27 => {
                let s = self.take(8)?;
                u64::from_be_bytes([s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7]])
            }
            _ => return Err(WireError::Malformed), // indefinite lengths not used
        };
        // NOTE: no size ceiling here. A header's value is only a *length* for
        // byte strings and arrays; for a uint it is the integer itself, and
        // arbitrarily large integers are legal. The allocation guard lives in
        // bstr() and array(), the two places a hostile length could bite.
        Ok((major, value))
    }

    fn uint(&mut self) -> Result<u64, WireError> {
        let (major, v) = self.head()?;
        if major != 0 {
            return Err(WireError::UnexpectedType);
        }
        Ok(v)
    }

    fn bstr(&mut self) -> Result<Vec<u8>, WireError> {
        let (major, len) = self.head()?;
        if major != 2 {
            return Err(WireError::UnexpectedType);
        }
        if len > MAX_LEN {
            return Err(WireError::Malformed);
        }
        Ok(self.take(len as usize)?.to_vec())
    }

    fn bstr32(&mut self) -> Result<[u8; 32], WireError> {
        let v = self.bstr()?;
        v.try_into().map_err(|_| WireError::Malformed)
    }

    fn text(&mut self) -> Result<String, WireError> {
        String::from_utf8(self.bstr()?).map_err(|_| WireError::Malformed)
    }

    fn array(&mut self) -> Result<u64, WireError> {
        let (major, len) = self.head()?;
        if major != 4 {
            return Err(WireError::UnexpectedType);
        }
        if len > MAX_LEN {
            return Err(WireError::Malformed);
        }
        Ok(len)
    }

    fn done(&self) -> Result<(), WireError> {
        if self.p == self.d.len() {
            Ok(())
        } else {
            Err(WireError::Malformed)
        }
    }
}

/// Decode a self-auth block. Returns the algorithm suite and the block, with
/// the current public key reconstructed from the log.
pub fn decode_self_auth(bytes: &[u8]) -> Result<(u64, SelfAuthBlock), WireError> {
    let mut c = Cur { d: bytes, p: 0 };

    if c.array()? != 5 {
        return Err(WireError::Malformed);
    }
    if c.uint()? != WIRE_VERSION {
        return Err(WireError::UnsupportedVersion);
    }
    let alg_suite = c.uint()?;

    if c.array()? != 3 {
        return Err(WireError::Malformed);
    }
    let first_public_key = c.bstr()?;
    let next_commitment = c.bstr32()?;
    let metadata = c.bstr()?;

    let inception_sig = c.bstr()?;

    // The declared count comes from the attacker: refuse it before reserving
    // memory for it. Validation refuses longer logs anyway.
    let n_rot = c.array()?;
    if n_rot > crate::keylog::MAX_KEY_EVENTS as u64 {
        return Err(WireError::Malformed);
    }
    let mut rotations = Vec::with_capacity(n_rot as usize);
    for _ in 0..n_rot {
        if c.array()? != 6 {
            return Err(WireError::Malformed);
        }
        let event_index = c.uint()?;
        if event_index > u32::MAX as u64 {
            return Err(WireError::Malformed);
        }
        rotations.push(KeyEvent {
            event_index: event_index as u32,
            revealed_public_key: c.bstr()?,
            operational_public_key: c.bstr()?,
            next_commitment: c.bstr32()?,
            prior_event_hash: c.bstr32()?,
            signature: c.bstr()?,
        });
    }
    c.done()?;

    // The current key is derivable: the last operational key, or the
    // inception key at zero rotations.
    let current_public_key = rotations
        .last()
        .map(|ev| ev.operational_public_key.clone())
        .unwrap_or_else(|| first_public_key.clone());

    Ok((
        alg_suite,
        SelfAuthBlock {
            inception: InceptionRecord {
                first_public_key,
                next_commitment,
                metadata,
            },
            inception_sig,
            rotations,
            current_public_key,
        },
    ))
}

/// Decode a confidentiality block.
pub fn decode_bcb(bytes: &[u8]) -> Result<Bcb, WireError> {
    let mut c = Cur { d: bytes, p: 0 };
    if c.array()? != 4 {
        return Err(WireError::Malformed);
    }
    let kem_ciphertext = c.bstr()?;
    let kem_epoch = c.uint()?;
    let nonce_v = c.bstr()?;
    let sealed_payload = c.bstr()?;
    c.done()?;
    let nonce: [u8; NONCE_LEN] = nonce_v.try_into().map_err(|_| WireError::Malformed)?;
    Ok(Bcb {
        kem_ciphertext,
        kem_epoch,
        nonce,
        sealed_payload,
    })
}

/// Which carriage a payload holds, without decoding it: [`ADU_BUNDLE`],
/// [`ADU_BULLETIN`], or `None` if it is neither.
pub fn adu_kind(bytes: &[u8]) -> Option<u64> {
    let mut c = Cur { d: bytes, p: 0 };
    c.array().ok()?;
    match c.uint().ok()? {
        k @ (ADU_BUNDLE | ADU_BULLETIN) => Some(k),
        _ => None,
    }
}

/// Decode a carried bundle. Returns the algorithm suite and the bundle. The
/// suite inside the self-auth block must agree with the outer one. Nothing
/// is verified here: hand the bundle to [`crate::verify::Receiver`].
pub fn decode_bundle(bytes: &[u8]) -> Result<(u64, Bundle), WireError> {
    let mut c = Cur { d: bytes, p: 0 };
    if c.array()? != 9 || c.uint()? != ADU_BUNDLE {
        return Err(WireError::Malformed);
    }
    let alg_suite = c.uint()?;
    let source_id = c.bstr32()?;
    let name = match (c.uint()?, c.uint()?) {
        (0, 0) => SourceName::SelfCertifying,
        (1, n) => SourceName::Ipn(n),
        _ => return Err(WireError::Malformed),
    };
    let (inner_suite, self_auth) = decode_self_auth(&c.bstr()?)?;
    if inner_suite != alg_suite {
        return Err(WireError::Malformed);
    }
    let payload = match c.uint()? {
        0 => Payload::Plain(c.bstr()?),
        1 => Payload::Confidential(decode_bcb(&c.bstr()?)?),
        _ => return Err(WireError::Malformed),
    };
    let signature = c.bstr()?;
    c.done()?;
    Ok((
        alg_suite,
        Bundle {
            source_id,
            name,
            self_auth,
            payload,
            bib: Bib { signature },
        },
    ))
}

/// Decode a carried bulletin. Nothing is verified here: apply it to a
/// [`crate::trust::TrustStore`], which checks the signature.
pub fn decode_bulletin(bytes: &[u8]) -> Result<Bulletin, WireError> {
    let mut c = Cur { d: bytes, p: 0 };
    if c.array()? != 6 || c.uint()? != ADU_BULLETIN {
        return Err(WireError::Malformed);
    }
    let issuer = c.text()?;
    let seq = c.uint()?;
    let expires_at = c.uint()?;
    let n = c.array()?;
    let body = match (n, c.uint()?) {
        (6, 1) => {
            let node_id = c.bstr32()?;
            let ipn = match (c.uint()?, c.uint()?) {
                (0, 0) => None,
                (1, n) => Some(n),
                _ => return Err(WireError::Malformed),
            };
            BulletinBody::Membership {
                node_id,
                ipn,
                kem_public_key: c.bstr()?,
                kem_epoch: c.uint()?,
            }
        }
        (3, 2) => BulletinBody::Peering {
            peer_name: c.text()?,
            peer_root_key: c.bstr()?,
        },
        (4, 3) => BulletinBody::Revocation {
            node_id: c.bstr32()?,
            reason: RevocationReason::from_tag(c.uint()?).ok_or(WireError::Malformed)?,
            effective_at: c.uint()?,
        },
        _ => return Err(WireError::Malformed),
    };
    let signature = c.bstr()?;
    c.done()?;
    Ok(Bulletin {
        issuer,
        seq,
        expires_at,
        body,
        signature,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cbor_heads_roundtrip_boundaries() {
        // Encode the boundary values and decode them back. Large integers are
        // legal uints; the size ceiling applies to lengths, not values.
        for v in [
            0u64,
            23,
            24,
            255,
            256,
            65535,
            65536,
            u32::MAX as u64,
            u64::MAX,
        ] {
            let mut buf = Vec::new();
            put_uint(&mut buf, v);
            let mut c = Cur { d: &buf, p: 0 };
            assert_eq!(c.uint().unwrap(), v);
            assert!(c.done().is_ok());
        }
    }

    #[test]
    fn oversize_length_header_is_rejected() {
        // A byte-string header claiming more than MAX_LEN bytes must fail
        // structurally, before any allocation is attempted.
        let mut buf = Vec::new();
        put_head(&mut buf, 2, MAX_LEN + 1);
        let mut c = Cur { d: &buf, p: 0 };
        assert_eq!(c.bstr(), Err(WireError::Malformed));

        let mut buf = Vec::new();
        put_head(&mut buf, 4, MAX_LEN + 1);
        let mut c = Cur { d: &buf, p: 0 };
        assert_eq!(c.array(), Err(WireError::Malformed));
    }

    #[test]
    fn bcb_roundtrip() {
        let bcb = Bcb {
            kem_ciphertext: vec![1, 2, 3],
            kem_epoch: 8600,
            nonce: [7u8; NONCE_LEN],
            sealed_payload: vec![9; 40],
        };
        let enc = encode_bcb(&bcb);
        let dec = decode_bcb(&enc).unwrap();
        assert_eq!(dec.kem_ciphertext, bcb.kem_ciphertext);
        assert_eq!(dec.kem_epoch, bcb.kem_epoch);
        assert_eq!(dec.nonce, bcb.nonce);
        assert_eq!(dec.sealed_payload, bcb.sealed_payload);
    }

    #[test]
    fn truncated_bcb_is_rejected() {
        let bcb = Bcb {
            kem_ciphertext: vec![1, 2, 3],
            kem_epoch: 0,
            nonce: [7u8; NONCE_LEN],
            sealed_payload: vec![9; 40],
        };
        let enc = encode_bcb(&bcb);
        assert_eq!(decode_bcb(&enc[..enc.len() - 1]), Err(WireError::Truncated));
    }

    #[test]
    fn trailing_bytes_are_rejected() {
        let bcb = Bcb {
            kem_ciphertext: vec![1],
            kem_epoch: 0,
            nonce: [0u8; NONCE_LEN],
            sealed_payload: vec![2],
        };
        let mut enc = encode_bcb(&bcb);
        enc.push(0);
        assert_eq!(decode_bcb(&enc), Err(WireError::Malformed));
    }
}
