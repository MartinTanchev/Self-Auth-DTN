//! DTKA bulletins: signed, self-contained, valid however late they arrive.
//! One object class, three bodies: Membership (identifier is ours, carries
//! its KEM key), Peering (a peer collective's root key), Revocation.

#[allow(unused_imports)]
use crate::alloc_prelude::*;
use crate::codec;
use crate::crypto::SignatureScheme;
use crate::identity::NodeId;

/// Why an identifier was revoked. Advisory: the effect is the same.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RevocationReason {
    /// The node's signing key is believed stolen.
    KeyCompromise,
    /// The node has left the collective.
    Superseded,
    /// Unspecified.
    Unspecified,
}

impl RevocationReason {
    fn tag(&self) -> u32 {
        match self {
            RevocationReason::KeyCompromise => 1,
            RevocationReason::Superseded => 2,
            RevocationReason::Unspecified => 3,
        }
    }

    pub(crate) fn from_tag(tag: u64) -> Option<Self> {
        match tag {
            1 => Some(RevocationReason::KeyCompromise),
            2 => Some(RevocationReason::Superseded),
            3 => Some(RevocationReason::Unspecified),
            _ => None,
        }
    }

    pub(crate) fn wire_tag(&self) -> u64 {
        self.tag() as u64
    }
}

/// What a bulletin asserts.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BulletinBody {
    /// `node_id` is a member of the issuing collective.
    Membership {
        node_id: NodeId,
        /// The ipn node number this identifier belongs to, in extension-block
        /// naming. `None` under self-certifying naming, where the identifier
        /// is the node number.
        ipn: Option<u64>,
        /// The node's ML-KEM encapsulation key.
        kem_public_key: Vec<u8>,
        /// The epoch this KEM key serves (seconds, deployment epoch; 0 = a
        /// permanent key). A node announces per-epoch keys in advance and
        /// erases each decapsulation key when its epoch closes: forward
        /// secrecy with no handshake.
        kem_epoch: u64,
    },
    /// The issuing collective recognises `peer_name`, whose root key follows.
    /// An *empty* `peer_root_key` withdraws the peering: the peer's root is
    /// removed and its future bulletins are refused as from an unknown
    /// issuer. Ordering against the grant is per-subject sequence numbers.
    Peering {
        peer_name: String,
        peer_root_key: Vec<u8>,
    },
    /// The issuing collective withdraws trust in `node_id`.
    Revocation {
        node_id: NodeId,
        reason: RevocationReason,
        /// When the compromise is believed to have begun (seconds, deployment
        /// epoch). Receipt-time promotion uses this: accumulated bundles
        /// *received* before this instant remain promotable. Zero means
        /// unknown, which conservatively voids the whole accumulated history.
        effective_at: u64,
    },
}

impl BulletinBody {
    fn canonical(&self, buf: &mut Vec<u8>) {
        match self {
            BulletinBody::Membership {
                node_id,
                ipn,
                kem_public_key,
                kem_epoch,
            } => {
                codec::push_u32(buf, 1);
                codec::push_field(buf, node_id);
                match ipn {
                    Some(n) => {
                        codec::push_u32(buf, 1);
                        codec::push_u64(buf, *n);
                    }
                    None => codec::push_u32(buf, 0),
                }
                codec::push_field(buf, kem_public_key);
                codec::push_u64(buf, *kem_epoch);
            }
            BulletinBody::Peering {
                peer_name,
                peer_root_key,
            } => {
                codec::push_u32(buf, 2);
                codec::push_field(buf, peer_name.as_bytes());
                codec::push_field(buf, peer_root_key);
            }
            BulletinBody::Revocation {
                node_id,
                reason,
                effective_at,
            } => {
                codec::push_u32(buf, 3);
                codec::push_field(buf, node_id);
                codec::push_u32(buf, reason.tag());
                codec::push_u64(buf, *effective_at);
            }
        }
    }
}

/// A signed bulletin.
#[derive(Clone, Debug)]
pub struct Bulletin {
    /// Name of the issuing collective.
    pub issuer: String,
    /// Monotonic sequence number from that issuer.
    pub seq: u64,
    /// Optional expiry, as seconds since an epoch the deployment agrees on.
    /// Zero means no expiry.
    pub expires_at: u64,
    pub body: BulletinBody,
    pub signature: Vec<u8>,
}

impl Bulletin {
    /// The canonical bytes a collective's root key signs.
    pub fn signing_bytes(issuer: &str, seq: u64, expires_at: u64, body: &BulletinBody) -> Vec<u8> {
        let mut buf = Vec::new();
        codec::push_field(&mut buf, issuer.as_bytes());
        codec::push_u64(&mut buf, seq);
        codec::push_u64(&mut buf, expires_at);
        body.canonical(&mut buf);
        buf
    }

    /// Verify this bulletin's signature under a collective root key.
    pub fn verify_signature<S: SignatureScheme>(&self, root_key: &[u8]) -> bool {
        let bytes = Self::signing_bytes(&self.issuer, self.seq, self.expires_at, &self.body);
        S::verify(root_key, &bytes, &self.signature)
    }
}

/// A collective's key authority: the signing side of the trust root.
pub struct Authority<S: SignatureScheme> {
    name: String,
    root_public_key: Vec<u8>,
    root_secret: S::SecretKey,
    seq: u64,
}

impl<S: SignatureScheme> Authority<S> {
    /// Stand up a collective with a root keypair.
    pub fn new(name: &str, root_seed: &[u8; 32]) -> Self {
        let (pk, sk) = S::keygen(root_seed);
        Authority {
            name: name.to_string(),
            root_public_key: pk,
            root_secret: sk,
            seq: 0,
        }
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    /// The root key that peers and members must be configured with (or learn
    /// via a peering bulletin).
    pub fn root_public_key(&self) -> &[u8] {
        &self.root_public_key
    }

    fn issue(&mut self, body: BulletinBody, expires_at: u64) -> Bulletin {
        self.seq += 1;
        let bytes = Bulletin::signing_bytes(&self.name, self.seq, expires_at, &body);
        let signature = S::sign(&self.root_secret, &bytes);
        Bulletin {
            issuer: self.name.clone(),
            seq: self.seq,
            expires_at,
            body,
            signature,
        }
    }

    /// Assert that `node_id` is a member, optionally bound to an ipn number,
    /// and publish its KEM key. No expiry.
    pub fn announce_member(
        &mut self,
        node_id: &NodeId,
        ipn: Option<u64>,
        kem_public_key: &[u8],
    ) -> Bulletin {
        self.issue(
            BulletinBody::Membership {
                node_id: *node_id,
                ipn,
                kem_public_key: kem_public_key.to_vec(),
                kem_epoch: 0,
            },
            0,
        )
    }

    /// As [`Authority::announce_member`], announcing the node's KEM key for
    /// one epoch. Announce future epochs ahead of need; the node erases each
    /// decapsulation key as its epoch closes.
    pub fn announce_member_epoch(
        &mut self,
        node_id: &NodeId,
        ipn: Option<u64>,
        kem_public_key: &[u8],
        kem_epoch: u64,
    ) -> Bulletin {
        self.issue(
            BulletinBody::Membership {
                node_id: *node_id,
                ipn,
                kem_public_key: kem_public_key.to_vec(),
                kem_epoch,
            },
            0,
        )
    }

    /// As [`Authority::announce_member`], with an expiry timestamp after which
    /// clock-aware receivers refuse the bulletin.
    pub fn announce_member_until(
        &mut self,
        node_id: &NodeId,
        ipn: Option<u64>,
        kem_public_key: &[u8],
        expires_at: u64,
    ) -> Bulletin {
        self.issue(
            BulletinBody::Membership {
                node_id: *node_id,
                ipn,
                kem_public_key: kem_public_key.to_vec(),
                kem_epoch: 0,
            },
            expires_at,
        )
    }

    /// Withdraw a previously announced peering. The peer's root key is
    /// removed on application; its future bulletins are refused.
    pub fn withdraw_peer(&mut self, peer_name: &str) -> Bulletin {
        self.issue(
            BulletinBody::Peering {
                peer_name: peer_name.to_string(),
                peer_root_key: Vec::new(),
            },
            0,
        )
    }

    /// Recognise a peer collective by distributing its root key. No expiry.
    pub fn announce_peer(&mut self, peer_name: &str, peer_root_key: &[u8]) -> Bulletin {
        self.issue(
            BulletinBody::Peering {
                peer_name: peer_name.to_string(),
                peer_root_key: peer_root_key.to_vec(),
            },
            0,
        )
    }

    /// Withdraw trust in an identifier. Never expires. The compromise onset is
    /// unknown, so receivers conservatively void the accumulated history.
    pub fn revoke(&mut self, node_id: &NodeId, reason: RevocationReason) -> Bulletin {
        self.revoke_effective(node_id, reason, 0)
    }

    /// As [`Authority::revoke`], asserting that the compromise began at
    /// `effective_at`. Bundles a receiver took in before that instant, by its
    /// own clock, remain promotable.
    pub fn revoke_effective(
        &mut self,
        node_id: &NodeId,
        reason: RevocationReason,
        effective_at: u64,
    ) -> Bulletin {
        self.issue(
            BulletinBody::Revocation {
                node_id: *node_id,
                reason,
                effective_at,
            },
            0,
        )
    }
}
