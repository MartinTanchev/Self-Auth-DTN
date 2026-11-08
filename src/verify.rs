//! Sender and receiver endpoints. `Receiver::accept` answers binding
//! (self-auth, immediate, offline) and authorization (DTKA, whenever the
//! bulletin lands) separately; a bundle can be bound but not yet
//! authorized, and history accumulated in that window is authorized
//! retroactively. Also holds the first-seen key log per source (stale-key
//! cutoff and fork detection) and bounded per-source
//! history.

use crate::aead::{self, NONCE_LEN};
#[allow(unused_imports)]
use crate::alloc_prelude::*;
use crate::bulletin::Bulletin;
use crate::crypto::SignatureScheme;
use crate::identity::{InceptionRecord, NodeId};
use crate::kem::KemScheme;
use crate::keylog::{validate_chain, Identity, KeyEvent, VerifyError};
use crate::naming::SourceName;
use crate::sha256::sha256;
use crate::trust::{Applied, MemberRecord, TrustError, TrustStore};
use alloc::collections::{BTreeMap, VecDeque};

/// The self-auth extension block carried in a bundle.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SelfAuthBlock {
    pub inception: InceptionRecord,
    pub inception_sig: Vec<u8>,
    pub rotations: Vec<KeyEvent>,
    /// The current key, presented for convenience. Verification confirms it
    /// equals the key derived from the chain, so it is never trusted blindly.
    pub current_public_key: Vec<u8>,
}

/// A Block Confidentiality Block: the per-bundle key, encapsulated under the
/// destination's KEM key, plus the sealed payload.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Bcb {
    /// ML-KEM ciphertext encapsulating the one-time payload key.
    pub kem_ciphertext: Vec<u8>,
    /// The destination KEM-key epoch this bundle was encapsulated under
    /// (0 = the permanent key). A receiver that has erased this epoch's
    /// decapsulation key can no longer read the payload: forward secrecy,
    /// and the reason the secrecy window is floored by bundle lifetime.
    pub kem_epoch: u64,
    pub nonce: [u8; NONCE_LEN],
    /// `ciphertext || tag`.
    pub sealed_payload: Vec<u8>,
}

/// AEAD associated data for a BCB: a domain label, the source identifier,
/// the KEM epoch and the KEM ciphertext.
///
/// Binding the source identifier stops authorship confusion: without it, an
/// attacker who captures A's confidential bundle to B can re-sign the same
/// BCB under its own identifier, and B would decrypt it as coming from the
/// attacker (sign-and-encrypt's classic gap). With it, the payload opens only
/// under the identifier that sealed it. Binding the ciphertext stops the
/// sealed payload being lifted onto another encapsulation; binding the epoch
/// stops it being presented under a different epoch's key.
pub fn bcb_aad(source_id: &NodeId, kem_epoch: u64, kem_ciphertext: &[u8]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(16 + 32 + 8 + kem_ciphertext.len());
    aad.extend_from_slice(b"self-auth-dtn bcb");
    aad.extend_from_slice(source_id);
    aad.extend_from_slice(&kem_epoch.to_be_bytes());
    aad.extend_from_slice(kem_ciphertext);
    aad
}

/// The payload: either in the clear, or sealed under a per-bundle key.
#[derive(Clone, Debug)]
pub enum Payload {
    Plain(Vec<u8>),
    Confidential(Bcb),
}

/// A Block Integrity Block: a signature over the protected bytes.
#[derive(Clone, Debug)]
pub struct Bib {
    pub signature: Vec<u8>,
}

/// A bundle, reduced to the parts this prototype reasons about.
#[derive(Clone, Debug)]
pub struct Bundle {
    /// The self-certifying identifier of the source.
    pub source_id: NodeId,
    /// How the source was named on the wire. See [`crate::naming`].
    pub name: SourceName,
    pub self_auth: SelfAuthBlock,
    pub payload: Payload,
    pub bib: Bib,
}

impl Bundle {
    /// The bytes the BIB covers: the source identifier, the claimed name, and
    /// a digest of the payload as it appears on the wire.
    pub fn protected_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&self.source_id);
        match &self.name {
            SourceName::SelfCertifying => buf.push(0),
            SourceName::Ipn(n) => {
                buf.push(1);
                buf.extend_from_slice(&n.to_be_bytes());
            }
        }
        match &self.payload {
            Payload::Plain(p) => {
                buf.push(0);
                buf.extend_from_slice(&sha256(p));
            }
            Payload::Confidential(bcb) => {
                buf.push(1);
                buf.extend_from_slice(&sha256(&bcb.kem_ciphertext));
                buf.extend_from_slice(&bcb.kem_epoch.to_be_bytes());
                buf.extend_from_slice(&bcb.nonce);
                buf.extend_from_slice(&sha256(&bcb.sealed_payload));
            }
        }
        sha256(&buf).to_vec()
    }
}

/// Verify a bundle's binding. The whole offline check, needing nothing
/// external.
pub fn verify_binding<S: SignatureScheme>(bundle: &Bundle) -> Result<NodeId, VerifyError> {
    let current_pk = validate_chain::<S>(
        &bundle.self_auth.inception,
        &bundle.self_auth.inception_sig,
        &bundle.self_auth.rotations,
        &bundle.source_id,
    )?;

    if current_pk != bundle.self_auth.current_public_key {
        return Err(VerifyError::CurrentKeyMismatch);
    }
    // If the inception record committed to an ipn number, the bundle may not
    // claim a different one. Entitlement to the number is still the bulletin's
    // call; this only makes the *claim* non-equivocable, so two identities
    // claiming one number are distinguishable already in the window.
    if let SourceName::Ipn(claimed) = &bundle.name {
        if let Some(committed) = bundle.self_auth.inception.committed_ipn() {
            if *claimed != committed {
                return Err(VerifyError::IpnCommitmentMismatch);
            }
        }
    }
    if !S::verify(
        &current_pk,
        &bundle.protected_bytes(),
        &bundle.bib.signature,
    ) {
        return Err(VerifyError::BibSignature);
    }
    Ok(bundle.source_id)
}

// ---------------------------------------------------------------------------
// Sending
// ---------------------------------------------------------------------------

/// Errors when constructing a bundle.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SendError {
    /// We do not hold the destination's KEM key, so we cannot encrypt to it.
    NoDestinationKey,
    /// Encapsulation failed (malformed key).
    Encapsulation,
}

/// A node that can emit bundles.
pub struct Sender<'a, S: SignatureScheme> {
    id: &'a Identity<S>,
    name: SourceName,
}

impl<'a, S: SignatureScheme> Sender<'a, S> {
    pub fn new(id: &'a Identity<S>, name: SourceName) -> Self {
        Sender { id, name }
    }

    fn block(&self) -> SelfAuthBlock {
        SelfAuthBlock {
            inception: self.id.inception().clone(),
            inception_sig: self.id.inception_sig().to_vec(),
            rotations: self.id.rotations().to_vec(),
            current_public_key: self.id.current_public_key().to_vec(),
        }
    }

    fn finish(&self, payload: Payload) -> Bundle {
        let mut bundle = Bundle {
            source_id: self.id.node_id(),
            name: self.name.clone(),
            self_auth: self.block(),
            payload,
            bib: Bib {
                signature: Vec::new(),
            },
        };
        let protected = bundle.protected_bytes();
        bundle.bib.signature = self.id.sign_protected(&protected);
        bundle
    }

    /// An authenticated bundle, in the clear. Needs nothing about the
    /// destination: this always works, even at first contact.
    pub fn send_plain(&self, payload: &[u8]) -> Bundle {
        self.finish(Payload::Plain(payload.to_vec()))
    }

    /// An authenticated *and confidential* bundle. Requires the destination's
    /// KEM key, which must already have arrived by bulletin.
    pub fn send_confidential<K: KemScheme>(
        &self,
        trust: &TrustStore,
        destination: &NodeId,
        payload: &[u8],
        kem_seed: &[u8; 32],
        nonce: [u8; NONCE_LEN],
    ) -> Result<Bundle, SendError> {
        let (kem_epoch, dest_kem) = trust
            .kem_key_for(destination)
            .ok_or(SendError::NoDestinationKey)?;

        // Fresh one-time key for this bundle only.
        let (kem_ciphertext, mut shared) =
            K::encapsulate(dest_kem, kem_seed).ok_or(SendError::Encapsulation)?;

        // Associated data binds the sealed payload to its source identifier,
        // the epoch and the encapsulation (see `bcb_aad`).
        let aad = bcb_aad(&self.id.node_id(), kem_epoch, &kem_ciphertext);
        let sealed_payload = aead::seal(&shared, &nonce, &aad, payload);
        // One-time key: wipe it the moment it has served its purpose.
        crate::mac::wipe(&mut shared);

        Ok(self.finish(Payload::Confidential(Bcb {
            kem_ciphertext,
            kem_epoch,
            nonce,
            sealed_payload,
        })))
    }
}

// ---------------------------------------------------------------------------
// Receiving
// ---------------------------------------------------------------------------

/// What became of a received bundle's payload.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReceivedPayload {
    /// Carried in the clear.
    Plain(Vec<u8>),
    /// Confidential, and this receiver decrypted it.
    Decrypted(Vec<u8>),
    /// Confidential, but this receiver could not decrypt it: not addressed to
    /// us, or the ciphertext failed authentication.
    Undecryptable,
}

/// The two verdicts, reported separately.
#[derive(Clone, Debug)]
pub struct Verdict {
    /// Proven from the bundle alone.
    pub node_id: NodeId,
    /// Always true if the bundle was accepted at all.
    pub binding_verified: bool,
    /// `Ok` once a bulletin has vouched for this identifier; `Err` in the window
    /// before, or if it has been revoked.
    pub authorization: Result<MemberRecord, TrustError>,
    /// How many bundles from this source we have now accumulated.
    pub accumulated: usize,
    /// What became of the payload.
    pub payload: ReceivedPayload,
}

impl Verdict {
    /// Whether the source is currently authorized.
    pub fn is_authorized(&self) -> bool {
        self.authorization.is_ok()
    }
}

/// Receipt stamp for bundles accepted without a clock ([`Receiver::accept`]).
/// It sorts after every real time, so a revocation always excludes such
/// bundles from promotion.
pub const UNKNOWN_RECEIPT_TIME: u64 = u64::MAX;

/// Maximum identifiers tracked (accumulation plus key log) before eviction.
/// Bounds memory against identifier-minting floods; see the note in `accept`.
pub const MAX_SOURCES: usize = 4096;

/// Maximum bundles retained per source; oldest are dropped beyond this.
pub const MAX_HISTORY_PER_SOURCE: usize = 1024;

/// One accumulated bundle: when this receiver took it in (its own clock, the
/// one timestamp a key thief cannot backdate) and the payload, if readable.
#[derive(Clone, Debug)]
struct HistoryEntry {
    received_at: u64,
    payload: Option<Vec<u8>>,
}

/// A node that receives bundles and bulletins, in any order.
pub struct Receiver<K: KemScheme> {
    trust: TrustStore,
    /// Our own decapsulation keys, by epoch start (0 = permanent). Erasing an
    /// epoch's key (see [`Receiver::erase_epochs_before`]) makes recorded
    /// traffic from that epoch permanently unreadable, even to us.
    epoch_keys: BTreeMap<u64, K::DecapKey>,
    /// Per-source history of accepted-but-unauthorized bundles.
    accumulated: BTreeMap<NodeId, VecDeque<HistoryEntry>>,
    /// The key log this receiver first saw per identifier, extended only by
    /// logs that agree with it. Refusing strict prefixes closes the stale-key
    /// replay window once a rotation has reached us; refusing conflicts
    /// detects forks. Stored as its length and newest event: events chain by
    /// hash, so agreeing on the newest event means agreeing on all before it,
    /// and the event itself is what fork evidence needs.
    key_logs: BTreeMap<NodeId, SeenLog>,
    /// First fork seen per identifier, kept as checkable evidence.
    duplicity: BTreeMap<NodeId, DuplicityEvidence>,
}

/// What a receiver keeps of an identifier's key log.
#[derive(Clone, Debug)]
struct SeenLog {
    len: usize,
    newest: Option<KeyEvent>,
}

/// Two validly signed rotation events at the same position of one
/// identifier's log: the one this receiver saw first, and a conflicting one.
/// Check with [`crate::keylog::verify_duplicity`]. Valid evidence proves the
/// revealed establishment key signed twice, which the honest holder never
/// does: the identifier should be revoked.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DuplicityEvidence {
    pub node_id: NodeId,
    pub first_seen: KeyEvent,
    pub conflicting: KeyEvent,
}

impl<K: KemScheme> Receiver<K> {
    pub fn new(trust: TrustStore, decap_key: K::DecapKey) -> Self {
        let mut epoch_keys = BTreeMap::new();
        epoch_keys.insert(0, decap_key);
        Receiver {
            trust,
            epoch_keys,
            accumulated: BTreeMap::new(),
            key_logs: BTreeMap::new(),
            duplicity: BTreeMap::new(),
        }
    }

    /// Hold the decapsulation key for one KEM epoch (announced to peers via a
    /// membership bulletin with the same epoch start).
    ///
    /// Re-keying an epoch destroys the key it replaces: an old decapsulation
    /// key that merely fell out of the map would still sit in memory, which
    /// is what epoch erasure exists to prevent.
    pub fn add_epoch_key(&mut self, epoch: u64, decap_key: K::DecapKey) {
        if let Some(mut old) = self.epoch_keys.insert(epoch, decap_key) {
            K::destroy(&mut old);
        }
    }

    /// Erase every decapsulation key for epochs starting before `cutoff`,
    /// destroying the key material. Bundles sealed to an erased epoch become
    /// permanently unreadable, which is the forward-secrecy guarantee, and
    /// also the bound: erase no earlier than one maximum bundle lifetime
    /// after an epoch closes, or bundles still in flight outlive their key.
    /// Erasure is only real if it also reaches ground-held state.
    pub fn erase_epochs_before(&mut self, cutoff: u64) -> usize {
        let keep = self.epoch_keys.split_off(&cutoff);
        let mut erased = core::mem::replace(&mut self.epoch_keys, keep);
        let n = erased.len();
        for dk in erased.values_mut() {
            K::destroy(dk);
        }
        n
    }

    pub fn trust(&self) -> &TrustStore {
        &self.trust
    }

    /// Apply a bulletin whenever it arrives, without a clock. A re-admission
    /// applied this way marks everything held from the revocation's onset
    /// onward as suspect for good; use [`Receiver::apply_bulletin_at`] to
    /// close that span at the moment of re-admission.
    pub fn apply_bulletin<S: SignatureScheme>(
        &mut self,
        b: &Bulletin,
    ) -> Result<Applied, TrustError> {
        self.trust.apply::<S>(b)
    }

    /// Apply a bulletin at local time `now` (seconds, deployment epoch, on the
    /// same clock as [`Receiver::accept_at`]).
    pub fn apply_bulletin_at<S: SignatureScheme>(
        &mut self,
        b: &Bulletin,
        now: u64,
    ) -> Result<Applied, TrustError> {
        self.trust.apply_at::<S>(b, now)
    }

    /// Accept a bundle with no clock. Entries are stamped
    /// [`UNKNOWN_RECEIPT_TIME`], which fails safe: any revocation of the
    /// source, and any suspect span from a lifted one, excludes them from
    /// promotion, since they cannot be shown to predate the compromise.
    /// Prefer [`Receiver::accept_at`] wherever a clock exists.
    pub fn accept<S: SignatureScheme>(&mut self, bundle: &Bundle) -> Result<Verdict, VerifyError> {
        self.accept_at::<S>(bundle, UNKNOWN_RECEIPT_TIME)
    }

    /// Accept a bundle at local time `now` (seconds, deployment epoch). Fails
    /// only if binding fails; a bound-but-unauthorized bundle is accumulated
    /// for later retroactive authorization, stamped with *this receiver's*
    /// receipt time. Promotion decisions key on that stamp, never on the
    /// sender's creation timestamp, which a stolen key can backdate.
    pub fn accept_at<S: SignatureScheme>(
        &mut self,
        bundle: &Bundle,
        now: u64,
    ) -> Result<Verdict, VerifyError> {
        let node_id = verify_binding::<S>(bundle)?;

        // The presented log must agree with the one first seen here. Both
        // are valid hash chains, so it suffices to compare our newest event
        // with the presented event at the same position. A conflict is a
        // fork: an establishment key signed twice. Keep the first-seen log
        // and the evidence. A shorter log is stale (a thief holding a
        // since-rotated-away operational key carries only the old log), and
        // is refused whether or not it also diverges.
        let presented = &bundle.self_auth.rotations;
        let mut extends = true;
        if let Some(seen) = self.key_logs.get(&node_id) {
            if presented.len() < seen.len {
                return Err(VerifyError::StaleKeyLog);
            }
            if let Some(ours) = &seen.newest {
                let theirs = &presented[seen.len - 1];
                if theirs != ours {
                    let evidence = DuplicityEvidence {
                        node_id,
                        first_seen: ours.clone(),
                        conflicting: theirs.clone(),
                    };
                    self.duplicity.entry(node_id).or_insert(evidence);
                    return Err(VerifyError::Duplicity);
                }
            }
            extends = presented.len() > seen.len;
        }

        // Cap tracked state: identifiers are free to mint, so evict when full.
        // Eviction picks the *unrecognised* source with the least history:
        // identifiers the trust store knows are pinned, so a flood of minted
        // identities cannot evict a chosen victim's watermark and reopen the
        // stale-log window against it. Only if every tracked source is a
        // member (bounded by bulletin count, so effectively never at
        // MAX_SOURCES) does eviction fall back to least-history overall.
        if !self.accumulated.contains_key(&node_id) && self.accumulated.len() >= MAX_SOURCES {
            let victim = self
                .accumulated
                .iter()
                .filter(|(k, _)| !self.trust.is_member(k))
                .min_by_key(|(_, v)| v.len())
                .map(|(k, _)| *k)
                .or_else(|| {
                    self.accumulated
                        .iter()
                        .min_by_key(|(_, v)| v.len())
                        .map(|(k, _)| *k)
                });
            if let Some(victim) = victim {
                self.accumulated.remove(&victim);
                if !self.trust.is_member(&victim) {
                    self.key_logs.remove(&victim);
                    self.duplicity.remove(&victim);
                }
            }
        }
        if extends {
            self.key_logs.insert(
                node_id,
                SeenLog {
                    len: presented.len(),
                    newest: presented.last().cloned(),
                },
            );
        }

        let payload = match &bundle.payload {
            Payload::Plain(p) => ReceivedPayload::Plain(p.clone()),
            Payload::Confidential(bcb) => {
                match self
                    .epoch_keys
                    .get(&bcb.kem_epoch)
                    .and_then(|dk| K::decapsulate(dk, &bcb.kem_ciphertext))
                {
                    Some(mut shared) => {
                        let aad = bcb_aad(&bundle.source_id, bcb.kem_epoch, &bcb.kem_ciphertext);
                        let outcome =
                            match aead::open(&shared, &bcb.nonce, &aad, &bcb.sealed_payload) {
                                Ok(pt) => ReceivedPayload::Decrypted(pt),
                                Err(_) => ReceivedPayload::Undecryptable,
                            };
                        crate::mac::wipe(&mut shared);
                        outcome
                    }
                    None => ReceivedPayload::Undecryptable,
                }
            }
        };

        let history_payload = match &payload {
            ReceivedPayload::Plain(p) | ReceivedPayload::Decrypted(p) => Some(p.clone()),
            ReceivedPayload::Undecryptable => None,
        };

        let entry = self.accumulated.entry(node_id).or_default();
        if entry.len() >= MAX_HISTORY_PER_SOURCE {
            entry.pop_front();
        }
        entry.push_back(HistoryEntry {
            received_at: now,
            payload: history_payload,
        });
        let count = entry.len();

        let authorization = self
            .trust
            .authorize_at(&node_id, &bundle.name, now)
            .cloned();

        Ok(Verdict {
            node_id,
            binding_verified: true,
            authorization,
            accumulated: count,
            payload,
        })
    }

    /// Readable payloads accumulated from a source, oldest first. Bundles whose
    /// payload could not be read are counted in the history but omitted here.
    /// This is the raw record; promotion decisions go through
    /// [`Receiver::promotable_history`].
    pub fn history(&self, node_id: &NodeId) -> Vec<&[u8]> {
        self.accumulated
            .get(node_id)
            .map(|q| q.iter().filter_map(|e| e.payload.as_deref()).collect())
            .unwrap_or_default()
    }

    /// The accumulated payloads that survive the receipt-time rule, oldest
    /// first. For a revoked source, only bundles *received* before the
    /// revocation's effective time remain; a revocation with unknown onset
    /// (`effective_at == 0`) voids the history entirely, the conservative
    /// default. Whether revoked or not, bundles received inside a suspect span
    /// left by an earlier, lifted revocation never return (re-admission ends
    /// the revocation, not the suspicion), and bundles with an unknown receipt
    /// time are excluded by either. The comparison uses this receiver's own
    /// receipt stamps: a thief can backdate a bundle's creation timestamp, not
    /// our clock.
    pub fn promotable_history(&self, node_id: &NodeId) -> Vec<&[u8]> {
        let revoked_since = self.trust.revocation_effective_at(node_id);
        if revoked_since == Some(0) {
            return Vec::new();
        }
        let spans = self.trust.suspect_spans(node_id);
        let suspect = |t: u64| {
            spans
                .iter()
                .any(|&(onset, cleared)| t == UNKNOWN_RECEIPT_TIME || (onset <= t && t < cleared))
        };
        self.accumulated
            .get(node_id)
            .map(|q| {
                q.iter()
                    .filter(|e| match revoked_since {
                        Some(eff) => e.received_at < eff,
                        None => true,
                    })
                    .filter(|e| !suspect(e.received_at))
                    .filter_map(|e| e.payload.as_deref())
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Number of bundles accumulated from a source.
    pub fn accumulated(&self, node_id: &NodeId) -> usize {
        self.accumulated.get(node_id).map(|v| v.len()).unwrap_or(0)
    }

    /// Length of the key log this receiver holds for an identifier, if any.
    pub fn watermark(&self, node_id: &NodeId) -> Option<u32> {
        self.key_logs.get(node_id).map(|l| l.len as u32)
    }

    /// Evidence of a fork in an identifier's key log, if this receiver has
    /// seen one.
    pub fn duplicity(&self, node_id: &NodeId) -> Option<&DuplicityEvidence> {
        self.duplicity.get(node_id)
    }

    /// Current authorization state for a source, without a clock: membership
    /// expiry is not checked (see [`TrustStore::authorize`]).
    pub fn authorization(
        &self,
        node_id: &NodeId,
        name: &SourceName,
    ) -> Result<&MemberRecord, TrustError> {
        self.trust.authorize(node_id, name)
    }

    /// Authorization state for a source at time `now`, membership expiry
    /// included.
    pub fn authorization_at(
        &self,
        node_id: &NodeId,
        name: &SourceName,
        now: u64,
    ) -> Result<&MemberRecord, TrustError> {
        self.trust.authorize_at(node_id, name, now)
    }
}

impl<K: KemScheme> Drop for Receiver<K> {
    fn drop(&mut self) {
        for dk in self.epoch_keys.values_mut() {
            K::destroy(dk);
        }
    }
}
