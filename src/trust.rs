//! Authorization state: a `TrustStore` starts with one configured root key
//! and learns everything else from signed bulletins.
//!
//! Foreign nodes are authorized by walking, offline: bundle sig -> foreign
//! key -> foreign identifier -> foreign membership bulletin -> foreign root
//! -> peering bulletin signed by our own root. Peering is deliberately
//! non-transitive.

#[allow(unused_imports)]
use crate::alloc_prelude::*;
use crate::bulletin::{Bulletin, BulletinBody, RevocationReason};
use crate::crypto::SignatureScheme;
use crate::identity::NodeId;
use crate::naming::SourceName;
use alloc::collections::{BTreeMap, BTreeSet};

/// Why a bulletin was not accepted, or an authorization failed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TrustError {
    /// The issuing collective's root key is not known to this node.
    UnknownIssuer(String),
    /// The bulletin's signature did not verify under the issuer's root key.
    BadSignature,
    /// A peering bulletin arrived from someone other than our own collective.
    /// Trust is pairwise; it does not chain.
    PeeringNotFromOwnCollective(String),
    /// A bulletin older than one already applied from the same issuer *about
    /// the same subject*. Freshness is tracked per (issuer, subject), not per
    /// issuer: bundles reorder in a DTN, and a delayed bulletin about node A
    /// must not be refused because a newer bulletin about node B arrived first.
    StaleSequence { seen: u64, got: u64 },
    /// The bulletin's expiry timestamp has passed.
    Expired,
    /// The membership was applied, but its `expires_at` has since passed.
    /// A fresh membership bulletin renews it.
    MembershipExpired { expired_at: u64 },
    /// The identifier has been revoked.
    Revoked(RevocationReason),
    /// No membership bulletin has been seen for this identifier yet. Binding
    /// still holds; authorization does not.
    NotAMember,
    /// Extension-block naming: the bundle claims an ipn number that the
    /// collective did not bind to this identifier.
    IpnBindingMismatch { claimed: u64, vouched: Option<u64> },
    /// A bulletin tried to assert (membership) or withdraw (revocation) an
    /// identifier that a *different* collective vouches for. A peer speaks
    /// only for its own members; it cannot hijack another collective's
    /// records or substitute their KEM keys.
    MemberOfAnotherCollective { collective: String },
}

/// What a collective has asserted about a node.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MemberRecord {
    /// The collective that vouched for it. Ownership: only this collective's
    /// bulletins may update or revoke the record.
    pub collective: String,
    /// The ipn node number bound to this identifier, under extension-block
    /// naming.
    pub ipn: Option<u64>,
    /// The node's KEM keys by epoch start (0 = a permanent key). Senders
    /// encapsulate under the newest announced epoch; the node erases each
    /// decapsulation key when its epoch closes.
    pub kem_keys: BTreeMap<u64, Vec<u8>>,
    /// When this membership lapses (seconds, deployment epoch; 0 = never):
    /// the `expires_at` of the newest membership bulletin applied for it.
    /// [`TrustStore::authorize_at`] refuses the member after this time.
    pub expires_at: u64,
}

/// What a bulletin is *about*, for per-subject freshness tracking.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum SubjectKey {
    Node(NodeId),
    Peer(String),
}

impl SubjectKey {
    fn of(body: &BulletinBody) -> SubjectKey {
        match body {
            BulletinBody::Membership { node_id, .. } => SubjectKey::Node(*node_id),
            BulletinBody::Revocation { node_id, .. } => SubjectKey::Node(*node_id),
            BulletinBody::Peering { peer_name, .. } => SubjectKey::Peer(peer_name.clone()),
        }
    }
}

/// A standing revocation: why, who said so, and when the compromise is
/// believed to have begun (0 = unknown).
#[derive(Clone, Debug, PartialEq, Eq)]
struct RevokedEntry {
    reason: RevocationReason,
    issuer: String,
    effective_at: u64,
}

/// What changed when a bulletin was applied.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Applied {
    /// A node was recognised as a member.
    Member(NodeId),
    /// A peer collective's root key was learned.
    Peer(String),
    /// A peering was withdrawn: the named collective's root key was removed.
    PeerWithdrawn(String),
    /// A node was revoked.
    Revoked(NodeId),
}

/// A node's view of who is trusted.
pub struct TrustStore {
    own_collective: String,
    /// Collective name -> root public key. Seeded with our own; peers are
    /// learned from peering bulletins issued by our own collective.
    roots: BTreeMap<String, Vec<u8>>,
    members: BTreeMap<NodeId, MemberRecord>,
    revoked: BTreeMap<NodeId, RevokedEntry>,
    /// Per identifier, every span [onset, cleared) between a revocation's
    /// stated onset and the re-admission that lifted it. Bundles received in
    /// a span are never promoted: re-admission ends the revocation, not the
    /// suspicion over what arrived while the key was compromised.
    suspect: BTreeMap<NodeId, Vec<(u64, u64)>>,
    /// Highest sequence number applied per (issuer, subject), to reject stale
    /// replays without refusing legitimately delayed news about other subjects.
    seen_seq: BTreeMap<(String, SubjectKey), u64>,
    /// Collectives we have peered with, for reporting.
    peers: BTreeSet<String>,
}

impl TrustStore {
    /// Create a store configured with its own collective's root key. This is
    /// the single piece of a priori trust the node is fielded with.
    pub fn new(own_collective: &str, own_root_key: &[u8]) -> Self {
        let mut roots = BTreeMap::new();
        roots.insert(own_collective.to_string(), own_root_key.to_vec());
        TrustStore {
            own_collective: own_collective.to_string(),
            roots,
            members: BTreeMap::new(),
            revoked: BTreeMap::new(),
            suspect: BTreeMap::new(),
            seen_seq: BTreeMap::new(),
            peers: BTreeSet::new(),
        }
    }

    /// Apply a bulletin, whenever it happens to arrive, without a clock.
    /// Equivalent to [`TrustStore::apply_at`] with `now = 0`, meaning expiry
    /// is not enforced.
    pub fn apply<S: SignatureScheme>(&mut self, b: &Bulletin) -> Result<Applied, TrustError> {
        self.apply_at::<S>(b, 0)
    }

    /// Apply a bulletin at time `now` (seconds, deployment epoch). A bulletin
    /// with a nonzero `expires_at` in the past is refused.
    pub fn apply_at<S: SignatureScheme>(
        &mut self,
        b: &Bulletin,
        now: u64,
    ) -> Result<Applied, TrustError> {
        // 1 and 2: do we know the issuer's root key, and is the bulletin really
        // from them? Checked against a borrowed root; the borrow ends before
        // any mutation below.
        {
            let root = self
                .roots
                .get(&b.issuer)
                .ok_or_else(|| TrustError::UnknownIssuer(b.issuer.clone()))?;
            if !b.verify_signature::<S>(root) {
                return Err(TrustError::BadSignature);
            }
        }

        // 3. Is it still valid?
        if b.expires_at != 0 && now > b.expires_at {
            return Err(TrustError::Expired);
        }

        // 4. Is it fresh *for its subject*? Rejects replaying a
        // pre-revocation bulletin about the same node, while a delayed
        // bulletin about a different subject still applies: bulletins
        // reorder in a DTN, and "valid however late it arrives" has to
        // survive that.
        let subject = (b.issuer.clone(), SubjectKey::of(&b.body));
        if let Some(&seen) = self.seen_seq.get(&subject) {
            if b.seq <= seen {
                return Err(TrustError::StaleSequence { seen, got: b.seq });
            }
        }

        let applied = match &b.body {
            BulletinBody::Peering {
                peer_name,
                peer_root_key,
            } => {
                // No transitivity: only our own collective can extend our trust.
                if b.issuer != self.own_collective {
                    return Err(TrustError::PeeringNotFromOwnCollective(b.issuer.clone()));
                }
                if peer_root_key.is_empty() {
                    // Withdrawal. Never of our own root.
                    if peer_name == &self.own_collective {
                        return Err(TrustError::PeeringNotFromOwnCollective(b.issuer.clone()));
                    }
                    self.roots.remove(peer_name);
                    self.peers.remove(peer_name);
                    // Withdrawal also ends what the peer vouched for: its
                    // member records go, so they no longer authorize nor
                    // supply KEM keys. Their sequence state stays, so the old
                    // bulletins cannot be replayed back in after a re-grant.
                    self.members.retain(|_, r| r.collective != *peer_name);
                    Applied::PeerWithdrawn(peer_name.clone())
                } else {
                    // Never a grant naming our own collective: our root is
                    // the one a priori trust, and no bulletin replaces it.
                    if peer_name == &self.own_collective {
                        return Err(TrustError::PeeringNotFromOwnCollective(b.issuer.clone()));
                    }
                    // A grant under a different root replaces the peer's
                    // root: records vouched under the old one go with it.
                    let replaced = self
                        .roots
                        .get(peer_name)
                        .map(|old| old != peer_root_key)
                        .unwrap_or(false);
                    if replaced {
                        self.members.retain(|_, r| r.collective != *peer_name);
                    }
                    self.roots.insert(peer_name.clone(), peer_root_key.clone());
                    self.peers.insert(peer_name.clone());
                    Applied::Peer(peer_name.clone())
                }
            }

            BulletinBody::Membership {
                node_id,
                ipn,
                kem_public_key,
                kem_epoch,
            } => {
                // Ownership: a record belongs to the collective that vouched
                // it. A peer cannot overwrite it (or substitute its KEM key).
                if let Some(existing) = self.members.get(node_id) {
                    if existing.collective != b.issuer {
                        return Err(TrustError::MemberOfAnotherCollective {
                            collective: existing.collective.clone(),
                        });
                    }
                }
                let rec = self
                    .members
                    .entry(*node_id)
                    .or_insert_with(|| MemberRecord {
                        collective: b.issuer.clone(),
                        ipn: *ipn,
                        kem_keys: BTreeMap::new(),
                        expires_at: b.expires_at,
                    });
                rec.ipn = *ipn;
                rec.expires_at = b.expires_at;
                rec.kem_keys.insert(*kem_epoch, kem_public_key.clone());
                // Re-admission: the per-subject freshness check above proves
                // this membership was issued *after* any standing revocation
                // from the same issuer, so that revocation is lifted. A
                // revocation from a different issuer stands. What arrived
                // between the stated onset and now stays suspect for good
                // (see `suspect_spans`); with no clock (`now == 0`) the span
                // runs to the end of time, so nothing held from the
                // compromise onward is ever promoted.
                if self
                    .revoked
                    .get(node_id)
                    .map(|e| e.issuer == b.issuer)
                    .unwrap_or(false)
                {
                    if let Some(entry) = self.revoked.remove(node_id) {
                        let cleared = if now == 0 { u64::MAX } else { now };
                        self.suspect
                            .entry(*node_id)
                            .or_default()
                            .push((entry.effective_at, cleared));
                    }
                }
                Applied::Member(*node_id)
            }

            BulletinBody::Revocation {
                node_id,
                reason,
                effective_at,
            } => {
                // Ownership: a collective revokes only its own members. (With
                // no record yet, the revocation stands pre-emptively; if a
                // different collective later vouches the identifier, its
                // record outranks a foreign revocation at authorization.)
                if let Some(rec) = self.members.get(node_id) {
                    if rec.collective != b.issuer {
                        return Err(TrustError::MemberOfAnotherCollective {
                            collective: rec.collective.clone(),
                        });
                    }
                }
                self.revoked.insert(
                    *node_id,
                    RevokedEntry {
                        reason: *reason,
                        issuer: b.issuer.clone(),
                        effective_at: *effective_at,
                    },
                );
                Applied::Revoked(*node_id)
            }
        };

        self.seen_seq.insert(subject, b.seq);
        Ok(applied)
    }

    /// Authorization at time `now`: [`TrustStore::authorize`] plus
    /// membership expiry. A membership whose `expires_at` is nonzero and
    /// earlier than `now` is refused with [`TrustError::MembershipExpired`].
    /// `now == u64::MAX` (no trustworthy clock) refuses every membership that
    /// has an expiry: fail safe.
    pub fn authorize_at(
        &self,
        node_id: &NodeId,
        name: &SourceName,
        now: u64,
    ) -> Result<&MemberRecord, TrustError> {
        let record = self.authorize(node_id, name)?;
        if record.expires_at != 0 && now > record.expires_at {
            return Err(TrustError::MembershipExpired {
                expired_at: record.expires_at,
            });
        }
        Ok(record)
    }

    /// Authorize an identifier that has already had its *binding* verified.
    /// `name` is how the bundle named its source. No clock, matching
    /// [`TrustStore::apply`]: membership expiry is not checked; use
    /// [`TrustStore::authorize_at`] where time is known.
    pub fn authorize(
        &self,
        node_id: &NodeId,
        name: &SourceName,
    ) -> Result<&MemberRecord, TrustError> {
        if let Some(entry) = self.revoked.get(node_id) {
            // A revocation blocks when it comes from the collective that owns
            // the record, or when no record exists at all. A foreign
            // revocation cannot suppress another collective's member.
            let blocks = match self.members.get(node_id) {
                Some(rec) => rec.collective == entry.issuer,
                None => true,
            };
            if blocks {
                return Err(TrustError::Revoked(entry.reason));
            }
        }

        let record = self.members.get(node_id).ok_or(TrustError::NotAMember)?;

        if let Some(claimed) = name.ipn() {
            if record.ipn != Some(claimed) {
                return Err(TrustError::IpnBindingMismatch {
                    claimed,
                    vouched: record.ipn,
                });
            }
        }

        Ok(record)
    }

    /// The newest announced KEM key for a node, with its epoch start, if we
    /// have been told one. Mirrors the revocation scoping of
    /// [`TrustStore::authorize`].
    pub fn kem_key_for(&self, node_id: &NodeId) -> Option<(u64, &[u8])> {
        let record = self.members.get(node_id)?;
        if let Some(entry) = self.revoked.get(node_id) {
            if record.collective == entry.issuer {
                return None;
            }
        }
        record
            .kem_keys
            .iter()
            .next_back()
            .map(|(e, k)| (*e, k.as_slice()))
    }

    /// Whether an identifier is currently revoked.
    pub fn is_revoked(&self, node_id: &NodeId) -> bool {
        self.revoked.contains_key(node_id)
    }

    /// Whether an identifier has a standing membership record.
    pub fn is_member(&self, node_id: &NodeId) -> bool {
        self.members.contains_key(node_id)
    }

    /// If the identifier is revoked *by the collective whose record governs
    /// it* (or with no record at all), when the compromise is believed to
    /// have begun. `Some(0)` means revoked with unknown onset. A foreign
    /// revocation of another collective's member yields `None`, matching
    /// [`TrustStore::authorize`].
    pub fn revocation_effective_at(&self, node_id: &NodeId) -> Option<u64> {
        let entry = self.revoked.get(node_id)?;
        match self.members.get(node_id) {
            Some(rec) if rec.collective != entry.issuer => None,
            _ => Some(entry.effective_at),
        }
    }

    /// Spans of receipt time [onset, cleared) recorded when a revocation of
    /// this identifier was lifted by re-admission. Bundles received in any of
    /// them are excluded from promotion permanently. Onset 0 (unknown) makes
    /// the span start at the beginning of time.
    pub fn suspect_spans(&self, node_id: &NodeId) -> &[(u64, u64)] {
        self.suspect
            .get(node_id)
            .map(|v| v.as_slice())
            .unwrap_or(&[])
    }

    /// Collectives whose root keys we hold (our own, plus peers learned).
    pub fn known_collectives(&self) -> Vec<&str> {
        let mut v: Vec<&str> = self.roots.keys().map(|s| s.as_str()).collect();
        v.sort_unstable();
        v
    }

    /// Peer collectives learned via peering bulletins.
    pub fn peers(&self) -> Vec<&str> {
        let mut v: Vec<&str> = self.peers.iter().map(|s| s.as_str()).collect();
        v.sort_unstable();
        v
    }

    pub fn own_collective(&self) -> &str {
        &self.own_collective
    }
}
