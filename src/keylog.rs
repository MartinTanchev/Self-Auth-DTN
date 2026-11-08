//! Key-event log: holder side (`Identity`: incept, rotate, sign) and
//! verifier side (`validate_chain`: walk inception to current key from
//! carried material only).
//!
//! Two kinds of key. *Establishment* keys control the identifier: each one is
//! pre-committed by hash, revealed by exactly one rotation event, signs that
//! event and nothing else, and is then destroyed. *Operational* keys sign
//! bundles: each rotation event designates one, and the inception key serves
//! as the first.
//!
//! A rotation is valid if the revealed establishment key matches the previous
//! commitment and signs the event. A thief with the operational key can
//! impersonate only until the next rotation (or a revocation) propagates, and
//! cannot fork the log: every past event was signed by an establishment key
//! that no longer exists. Taking the identity requires the pre-committed
//! successor, which is inherent to pre-rotation. Receivers enforce the
//! propagation bound and detect forks by keeping the key log they first saw
//! (`verify::Receiver`).
//!
//! Before 0.9 the revealed key also signed bundles. A thief holding it after a
//! rotation could re-sign that rotation event with its own successor, extend
//! the fork past the real log, and take the identifier over
//! (`tests/fork_takeover.rs` keeps that attack as a regression test).

#[allow(unused_imports)]
use crate::alloc_prelude::*;
use crate::codec;
use crate::crypto::SignatureScheme;
use crate::identity::{InceptionRecord, NodeId};
use crate::sha256::sha256;

/// Maximum rotation events a key log may carry. Every event costs one
/// signature verification per bundle and up to ~7 kB on the wire, so an
/// unbounded log is a CPU and memory lever for anyone who can mint an
/// identifier. 64 rotations is decades of monthly rotation; past it, the
/// holder re-incepts.
pub const MAX_KEY_EVENTS: usize = 64;

/// A single rotation event.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyEvent {
    /// 1-based position in the chain (event 0 is the inception record).
    pub event_index: u32,
    /// The establishment key revealed by this rotation. Must match the prior
    /// commitment. It signs this event and is then destroyed.
    pub revealed_public_key: Vec<u8>,
    /// The operational key that signs bundles until the next rotation. Must
    /// differ from the revealed key and from the committed successor.
    pub operational_public_key: Vec<u8>,
    /// Commitment to the *next* establishment key: `H(next_public_key)`.
    pub next_commitment: [u8; 32],
    /// Hash of the prior event's canonical body, chaining the log together.
    pub prior_event_hash: [u8; 32],
    /// Signature over this event's body by the revealed key: proves possession
    /// of the pre-committed successor.
    pub signature: Vec<u8>,
}

impl KeyEvent {
    /// Canonical bytes signed and chained over.
    pub fn canonical_body(
        index: u32,
        revealed_pk: &[u8],
        operational_pk: &[u8],
        next_commitment: &[u8; 32],
        prior_hash: &[u8; 32],
    ) -> Vec<u8> {
        let mut buf = Vec::new();
        codec::push_u32(&mut buf, index);
        codec::push_field(&mut buf, revealed_pk);
        codec::push_field(&mut buf, operational_pk);
        codec::push_field(&mut buf, next_commitment);
        codec::push_field(&mut buf, prior_hash);
        buf
    }

    /// This event's canonical body.
    pub fn body(&self) -> Vec<u8> {
        Self::canonical_body(
            self.event_index,
            &self.revealed_public_key,
            &self.operational_public_key,
            &self.next_commitment,
            &self.prior_event_hash,
        )
    }

    /// The hash the next event chains to.
    pub fn hash(&self) -> [u8; 32] {
        sha256(&self.body())
    }
}

/// Everything a verifier needs to establish binding, carried in the bundle.
#[derive(Clone, Debug)]
pub struct SelfAuthMaterial {
    pub inception: InceptionRecord,
    pub inception_sig: Vec<u8>,
    pub rotations: Vec<KeyEvent>,
}

/// Reasons chain validation (or acceptance) can fail.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VerifyError {
    /// `H(inception_record)` did not equal the claimed node identifier.
    NodeIdMismatch,
    /// The inception record's self-signature did not verify.
    InceptionSignature,
    /// A rotation event was out of order.
    EventOrder,
    /// A rotation event did not chain to its predecessor.
    ChainBroken,
    /// A revealed key did not match the prior commitment.
    CommitmentMismatch,
    /// A rotation event's signature did not verify.
    EventSignature,
    /// An operational key equals the establishment key it was issued under,
    /// or the committed successor. Either would let a thief of the operational
    /// key sign rotation events, which is exactly what the split prevents.
    KeyReuse,
    /// The key log carries more than [`MAX_KEY_EVENTS`] rotation events.
    KeyLogTooLong,
    /// The current key derived from the chain did not match the one presented.
    CurrentKeyMismatch,
    /// The BIB signature over the bundle did not verify.
    BibSignature,
    /// The presented key log is a strict prefix of one this receiver has
    /// already witnessed for this identifier: a stale (pre-rotation) log, most
    /// likely a replay by a thief of a superseded operational key.
    StaleKeyLog,
    /// The presented key log conflicts with the one this receiver first saw
    /// for this identifier: two validly signed events at the same position.
    /// Proof that an establishment key was used twice, by a thief or by the
    /// holder. The receiver keeps its first-seen log and records the evidence
    /// (`verify::Receiver::duplicity`).
    Duplicity,
    /// The bundle claims an ipn node number different from the one committed
    /// in its own inception record. The identity is equivocating about its
    /// number, detectable already in the window, before any bulletin.
    IpnCommitmentMismatch,
}

/// Validate a self-auth chain from borrowed parts and return the current
/// operational public key.
pub fn validate_chain<S: SignatureScheme>(
    inception: &InceptionRecord,
    inception_sig: &[u8],
    rotations: &[KeyEvent],
    claimed_node_id: &NodeId,
) -> Result<Vec<u8>, VerifyError> {
    // Bound the work before doing any: each event is a signature check.
    if rotations.len() > MAX_KEY_EVENTS {
        return Err(VerifyError::KeyLogTooLong);
    }
    let inception_body = inception.canonical_bytes();
    let node_id = sha256(&inception_body);
    if &node_id != claimed_node_id {
        return Err(VerifyError::NodeIdMismatch);
    }
    if !S::verify(&inception.first_public_key, &inception_body, inception_sig) {
        return Err(VerifyError::InceptionSignature);
    }
    // The inception key is the first operational key; it must not also be
    // the committed successor.
    if sha256(&inception.first_public_key) == inception.next_commitment {
        return Err(VerifyError::KeyReuse);
    }

    let mut current_commitment = inception.next_commitment;
    let mut prior_hash = node_id;
    let mut current_pk: &[u8] = &inception.first_public_key;

    for (i, ev) in rotations.iter().enumerate() {
        let expected_index = (i as u32) + 1;
        if ev.event_index != expected_index {
            return Err(VerifyError::EventOrder);
        }
        if ev.prior_event_hash != prior_hash {
            return Err(VerifyError::ChainBroken);
        }
        // Each rotation is valid only if it reveals the establishment key the
        // previous event committed to.
        if sha256(&ev.revealed_public_key) != current_commitment {
            return Err(VerifyError::CommitmentMismatch);
        }
        if ev.operational_public_key == ev.revealed_public_key
            || sha256(&ev.operational_public_key) == ev.next_commitment
        {
            return Err(VerifyError::KeyReuse);
        }

        let body = ev.body();
        // Signed by the revealed establishment key: possession of the
        // pre-committed successor.
        if !S::verify(&ev.revealed_public_key, &body, &ev.signature) {
            return Err(VerifyError::EventSignature);
        }

        current_pk = &ev.operational_public_key;
        current_commitment = ev.next_commitment;
        prior_hash = sha256(&body);
    }

    Ok(current_pk.to_vec())
}

/// Validate a [`SelfAuthMaterial`]. Convenience wrapper over
/// [`validate_chain`].
pub fn validate_material<S: SignatureScheme>(
    material: &SelfAuthMaterial,
    claimed_node_id: &NodeId,
) -> Result<Vec<u8>, VerifyError> {
    validate_chain::<S>(
        &material.inception,
        &material.inception_sig,
        &material.rotations,
        claimed_node_id,
    )
}

/// Check third-party evidence of duplicity: two distinct rotation events at
/// the same position of the same log, both signed by the establishment key
/// they reveal. Each is checked on its own; neither needs the rest of the log,
/// because both name the same prior event. Valid evidence proves that key was
/// used twice, so it can justify a revocation by anyone holding it.
pub fn verify_duplicity<S: SignatureScheme>(a: &KeyEvent, b: &KeyEvent) -> bool {
    a != b
        && a.event_index == b.event_index
        && a.prior_event_hash == b.prior_event_hash
        && a.revealed_public_key == b.revealed_public_key
        && S::verify(&a.revealed_public_key, &a.body(), &a.signature)
        && S::verify(&b.revealed_public_key, &b.body(), &b.signature)
}

/// Holder-side identity state: the current operational keypair and the
/// pre-committed next establishment keypair. Spent establishment keys are
/// destroyed as soon as they have signed their event.
pub struct Identity<S: SignatureScheme> {
    node_id: NodeId,
    inception: InceptionRecord,
    inception_sig: Vec<u8>,
    current_public_key: Vec<u8>,
    current_secret: S::SecretKey,
    next_public_key: Vec<u8>,
    next_secret: S::SecretKey,
    rotations: Vec<KeyEvent>,
    prior_event_hash: [u8; 32],
}

impl<S: SignatureScheme> Identity<S> {
    /// Create a fresh identity. `seed0` keys the inception key, which signs the
    /// inception record and is the first operational key; `seed1` keys the
    /// pre-committed next establishment key. `metadata` is opaque admin data.
    ///
    /// The inception key may sign bundles because the record it signed is
    /// fixed by the identifier itself: stealing it gives impersonation until
    /// the first rotation, never a fork.
    ///
    /// # Panics
    /// If both seeds yield the same key.
    pub fn incept(seed0: &[u8; 32], seed1: &[u8; 32], metadata: &[u8]) -> Self {
        let (pk0, sk0) = S::keygen(seed0);
        let (pk1, sk1) = S::keygen(seed1);
        assert_ne!(pk0, pk1, "inception key and successor must differ");
        let next_commitment = sha256(&pk1);

        let inception = InceptionRecord {
            first_public_key: pk0.clone(),
            next_commitment,
            metadata: metadata.to_vec(),
        };
        let body = inception.canonical_bytes();
        let node_id = sha256(&body);
        let inception_sig = S::sign(&sk0, &body);

        Identity {
            node_id,
            inception,
            inception_sig,
            current_public_key: pk0,
            current_secret: sk0,
            next_public_key: pk1,
            next_secret: sk1,
            rotations: Vec::new(),
            prior_event_hash: node_id,
        }
    }

    /// As [`Identity::incept`], additionally committing the node's claimed ipn
    /// number inside the inception record. The identifier then pins the
    /// number: the identity cannot later claim a different one, and two
    /// identities claiming the same number are distinguishable on contact,
    /// before any bulletin. Entitlement to the number remains the
    /// collective's assertion, exactly as without the commitment.
    pub fn incept_with_ipn(seed0: &[u8; 32], seed1: &[u8; 32], ipn: u64) -> Self {
        Self::incept(seed0, seed1, &InceptionRecord::metadata_for_ipn(ipn))
    }

    /// This node's stable identifier.
    pub fn node_id(&self) -> NodeId {
        self.node_id
    }

    /// The current operational public key.
    pub fn current_public_key(&self) -> &[u8] {
        &self.current_public_key
    }

    /// How many rotations have occurred.
    pub fn rotation_count(&self) -> usize {
        self.rotations.len()
    }

    /// The self-auth material to attach to outgoing bundles.
    pub fn material(&self) -> SelfAuthMaterial {
        SelfAuthMaterial {
            inception: self.inception.clone(),
            inception_sig: self.inception_sig.clone(),
            rotations: self.rotations.clone(),
        }
    }

    /// Borrowing views, so a sender can build a block without the throwaway
    /// [`SelfAuthMaterial`] allocation.
    pub fn inception(&self) -> &InceptionRecord {
        &self.inception
    }
    pub fn inception_sig(&self) -> &[u8] {
        &self.inception_sig
    }
    pub fn rotations(&self) -> &[KeyEvent] {
        &self.rotations
    }

    /// Sign the bytes covered by a BIB, with the operational key.
    pub fn sign_protected(&self, protected: &[u8]) -> Vec<u8> {
        S::sign(&self.current_secret, protected)
    }

    /// Rotate: reveal the pre-committed establishment key, use it to sign one
    /// event designating a fresh operational key (from `operational_seed`)
    /// and committing to a fresh successor (from `next_seed`), then destroy
    /// it, along with the old operational key.
    ///
    /// # Panics
    /// If the new operational key equals the revealed key or the new
    /// successor, or if the log already holds [`MAX_KEY_EVENTS`] events
    /// (receivers would refuse it; re-incept instead).
    pub fn rotate(&mut self, operational_seed: &[u8; 32], next_seed: &[u8; 32]) -> KeyEvent {
        assert!(
            self.rotations.len() < MAX_KEY_EVENTS,
            "key log full: re-incept after {} rotations",
            MAX_KEY_EVENTS
        );
        let (op_pk, op_sk) = S::keygen(operational_seed);
        let (new_next_pk, new_next_sk) = S::keygen(next_seed);
        let revealed_pk = self.next_public_key.clone();
        assert!(
            op_pk != revealed_pk && op_pk != new_next_pk,
            "operational key must differ from establishment keys"
        );
        let next_commitment = sha256(&new_next_pk);
        let event_index = (self.rotations.len() as u32) + 1;

        let body = KeyEvent::canonical_body(
            event_index,
            &revealed_pk,
            &op_pk,
            &next_commitment,
            &self.prior_event_hash,
        );
        // Signed by the newly revealed establishment key: only the party
        // holding the pre-committed successor can rotate.
        let signature = S::sign(&self.next_secret, &body);

        let event = KeyEvent {
            event_index,
            revealed_public_key: revealed_pk,
            operational_public_key: op_pk.clone(),
            next_commitment,
            prior_event_hash: self.prior_event_hash,
            signature,
        };

        // The establishment key has signed its one event: destroy it, so no
        // later theft can sign an alternative to it. The old operational key
        // goes too.
        let mut spent = core::mem::replace(&mut self.next_secret, new_next_sk);
        S::destroy(&mut spent);
        let mut old_op = core::mem::replace(&mut self.current_secret, op_sk);
        S::destroy(&mut old_op);

        self.prior_event_hash = sha256(&body);
        self.current_public_key = op_pk;
        self.next_public_key = new_next_pk;
        self.rotations.push(event.clone());

        event
    }
}

impl<S: SignatureScheme> Drop for Identity<S> {
    fn drop(&mut self) {
        // Best-effort: wipe both held secrets. Backends with self-zeroizing
        // keys also cover intermediate copies.
        S::destroy(&mut self.current_secret);
        S::destroy(&mut self.next_secret);
    }
}
