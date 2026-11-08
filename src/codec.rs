//! Canonical length-prefixed encoding for everything that gets hashed or
//! signed. Kept separate from the CBOR wire format (`wire`) so identifiers
//! stay stable if the wire framing changes.

#[allow(unused_imports)]
use crate::alloc_prelude::*;
/// Append a big-endian u32.
pub fn push_u32(buf: &mut Vec<u8>, v: u32) {
    buf.extend_from_slice(&v.to_be_bytes());
}

/// Append a big-endian u64.
pub fn push_u64(buf: &mut Vec<u8>, v: u64) {
    buf.extend_from_slice(&v.to_be_bytes());
}

/// Append a variable-length field, framed as `len(u32-be) || bytes`.
pub fn push_field(buf: &mut Vec<u8>, field: &[u8]) {
    push_u32(buf, field.len() as u32);
    buf.extend_from_slice(field);
}
