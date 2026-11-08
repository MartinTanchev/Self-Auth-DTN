//! Inception record and identifier derivation: `id = H(inception_record)`.
//! The record fixes the first key and pre-commits the successor, so the live
//! key can rotate without the identifier moving.

#[allow(unused_imports)]
use crate::alloc_prelude::*;
use crate::codec;
use crate::sha256::sha256;

/// A 32-byte node identifier: `H(inception_record)`.
pub type NodeId = [u8; 32];

/// The one-time record that fixes a node's first key and pre-commits its
/// successor. Entirely public: it travels with the bundle.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InceptionRecord {
    /// The node's first operational public key.
    pub first_public_key: Vec<u8>,
    /// Commitment to the successor key: `H(second_public_key)`.
    pub next_commitment: [u8; 32],
    /// Opaque administrative metadata (for example a collective hint). It is
    /// covered by the identifier hash but carries no trust by itself.
    pub metadata: Vec<u8>,
}

/// Metadata prefix marking a committed ipn node number: `b"ipn\0"` followed by
/// the number as 8 big-endian bytes, 12 bytes total.
const IPN_META_PREFIX: &[u8; 4] = b"ipn\0";

impl InceptionRecord {
    /// Canonical metadata bytes committing to ipn node number `n`. Pass the
    /// result as `metadata` at inception (or use
    /// [`crate::keylog::Identity::incept_with_ipn`]).
    pub fn metadata_for_ipn(n: u64) -> Vec<u8> {
        let mut m = Vec::with_capacity(12);
        m.extend_from_slice(IPN_META_PREFIX);
        m.extend_from_slice(&n.to_be_bytes());
        m
    }

    /// The ipn node number this record commits to, if its metadata carries the
    /// canonical commitment form. Opaque metadata yields `None`.
    pub fn committed_ipn(&self) -> Option<u64> {
        if self.metadata.len() != 12 || self.metadata[..4] != IPN_META_PREFIX[..] {
            return None;
        }
        let mut b = [0u8; 8];
        b.copy_from_slice(&self.metadata[4..12]);
        Some(u64::from_be_bytes(b))
    }

    /// Canonical bytes for hashing and signing. Event index 0 marks inception.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        codec::push_u32(&mut buf, 0);
        codec::push_field(&mut buf, &self.first_public_key);
        codec::push_field(&mut buf, &self.next_commitment);
        codec::push_field(&mut buf, &self.metadata);
        buf
    }

    /// The node identifier this record commits to.
    pub fn node_id(&self) -> NodeId {
        sha256(&self.canonical_bytes())
    }
}

/// Render a [`NodeId`] as lowercase hex, for logs and display.
pub fn node_id_hex(id: &NodeId) -> String {
    id.iter().map(|b| format!("{:02x}", b)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identifier_is_deterministic() {
        let rec = InceptionRecord {
            first_public_key: vec![1, 2, 3, 4],
            next_commitment: [9u8; 32],
            metadata: b"collective:mars-a".to_vec(),
        };
        assert_eq!(rec.node_id(), rec.node_id());
    }

    #[test]
    fn identifier_changes_with_key() {
        let base = InceptionRecord {
            first_public_key: vec![1, 2, 3, 4],
            next_commitment: [9u8; 32],
            metadata: Vec::new(),
        };
        let mut other = base.clone();
        other.first_public_key = vec![1, 2, 3, 5];
        assert_ne!(base.node_id(), other.node_id());
    }
}
