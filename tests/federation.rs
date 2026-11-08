#![cfg(feature = "mock")]

//! Federation, revocation, naming modes, and the confidentiality
//! asymmetry.

mod common;
use common::*;

use self_auth_dtn::prelude::*;

/// The two-rovers case. Rover A belongs to collective `agency-a`, rover B to
/// `agency-b`. They meet on the surface.
#[test]
fn two_rovers_from_different_agencies() {
    let mut agency_a = Authority::<Sig>::new("agency-a", &[10u8; 32]);
    let mut agency_b = Authority::<Sig>::new("agency-b", &[20u8; 32]);

    let rover_b = Node::new(2, SourceName::SelfCertifying);

    // Rover A is fielded knowing only its own collective's root key.
    let mut rover_a = receiver_for("agency-a", agency_a.root_public_key());

    // --- Encounter, before any peering exists ---
    let v1 = rover_a.accept::<Sig>(&rover_b.send(b"survey-1")).unwrap();
    assert!(v1.binding_verified, "binding works with no bulletin at all");
    assert_eq!(v1.authorization, Err(TrustError::NotAMember));

    rover_a.accept::<Sig>(&rover_b.send(b"survey-2")).unwrap();
    assert_eq!(rover_a.accumulated(&rover_b.id()), 2);

    // B's own collective vouches for it. A cannot use this yet: it does not know
    // agency-b's root key, so the bulletin is from an unknown issuer.
    let b_membership = agency_b.announce_member(&rover_b.id(), None, &rover_b.kem_public);
    assert_eq!(
        rover_a.apply_bulletin::<Sig>(&b_membership),
        Err(TrustError::UnknownIssuer("agency-b".to_string()))
    );

    // --- The agencies peer, after deployment ---
    // A's own collective distributes B's root key. This is an ordinary bulletin,
    // not a special certificate object.
    let peering = agency_a.announce_peer("agency-b", agency_b.root_public_key());
    assert_eq!(
        rover_a.apply_bulletin::<Sig>(&peering).unwrap(),
        Applied::Peer("agency-b".to_string())
    );

    // Now B's membership bulletin verifies: its issuer's root is vouched by our
    // own root.
    assert_eq!(
        rover_a.apply_bulletin::<Sig>(&b_membership).unwrap(),
        Applied::Member(rover_b.id())
    );

    // The history accumulated before any of this is now authorized, retroactively.
    let record = rover_a
        .authorization(&rover_b.id(), &rover_b.name)
        .expect("foreign node now authorized");
    assert_eq!(record.collective, "agency-b");
    assert_eq!(rover_a.accumulated(&rover_b.id()), 2);
}

/// Trust is pairwise. If A peers with B, and B peers with C, A does not trust C.
#[test]
fn peering_does_not_chain() {
    let mut agency_a = Authority::<Sig>::new("agency-a", &[10u8; 32]);
    let mut agency_b = Authority::<Sig>::new("agency-b", &[20u8; 32]);
    let agency_c = Authority::<Sig>::new("agency-c", &[30u8; 32]);

    let _node = Node::new(3, SourceName::SelfCertifying);
    let mut rx = receiver_for("agency-a", agency_a.root_public_key());

    // A peers with B.
    rx.apply_bulletin::<Sig>(&agency_a.announce_peer("agency-b", agency_b.root_public_key()))
        .unwrap();

    // B now tries to extend our trust to C. Refused: only our own collective may
    // do that.
    let b_vouches_c = agency_b.announce_peer("agency-c", agency_c.root_public_key());
    assert_eq!(
        rx.apply_bulletin::<Sig>(&b_vouches_c),
        Err(TrustError::PeeringNotFromOwnCollective(
            "agency-b".to_string()
        ))
    );
}

/// Revocation rides in an ordinary bulletin. No expiry, no re-issue schedule,
/// no separate object class.
#[test]
fn revocation_bounds_key_theft_in_time() {
    let mut authority = Authority::<Sig>::new("mars-a", &[9u8; 32]);
    let q = Node::new(1, SourceName::SelfCertifying);
    let mut rx = receiver_for("mars-a", authority.root_public_key());

    rx.apply_bulletin::<Sig>(&authority.announce_member(&q.id(), None, &q.kem_public))
        .unwrap();

    // Authorized while healthy.
    let v = rx.accept::<Sig>(&q.send(b"nominal")).unwrap();
    assert!(v.is_authorized());

    // Q's signing key is stolen. The thief can produce valid-looking bundles: a
    // stolen key still signs. This is the window the design bounds, not one it
    // eliminates.
    let thief_bundle = q.send(b"malicious-command");
    assert!(rx.accept::<Sig>(&thief_bundle).unwrap().is_authorized());

    // The collective revokes the identifier. The bulletin propagates.
    let revocation = authority.revoke(&q.id(), RevocationReason::KeyCompromise);
    assert_eq!(
        rx.apply_bulletin::<Sig>(&revocation).unwrap(),
        Applied::Revoked(q.id())
    );

    // Binding still verifies (the maths is unchanged), but authorization is gone.
    let after = rx.accept::<Sig>(&q.send(b"more-malice")).unwrap();
    assert!(after.binding_verified);
    assert_eq!(
        after.authorization,
        Err(TrustError::Revoked(RevocationReason::KeyCompromise))
    );
}

/// A stale bulletin cannot be replayed over a newer one: a revoked node cannot
/// be "un-revoked" by re-flooding its old membership bulletin.
#[test]
fn stale_bulletin_replay_is_rejected() {
    let mut authority = Authority::<Sig>::new("mars-a", &[9u8; 32]);
    let q = Node::new(1, SourceName::SelfCertifying);
    let mut rx = receiver_for("mars-a", authority.root_public_key());

    let membership = authority.announce_member(&q.id(), None, &q.kem_public);
    rx.apply_bulletin::<Sig>(&membership).unwrap();
    rx.apply_bulletin::<Sig>(&authority.revoke(&q.id(), RevocationReason::KeyCompromise))
        .unwrap();

    // Replay the old membership bulletin.
    assert!(matches!(
        rx.apply_bulletin::<Sig>(&membership),
        Err(TrustError::StaleSequence { .. })
    ));
    assert!(rx.trust().is_revoked(&q.id()));
}

/// Extension-block naming: binding proves the sender holds identifier X, but
/// it says nothing about whether X is entitled to the ipn number it claims.
#[test]
fn extension_block_naming_binds_ipn_only_via_bulletin() {
    let mut authority = Authority::<Sig>::new("mars-a", &[9u8; 32]);

    // The legitimate node is ipn:42.
    let honest = Node::new(1, SourceName::Ipn(42));
    // The attacker mints its own identifier and claims to be ipn:42 as well.
    let attacker = Node::new(2, SourceName::Ipn(42));

    let mut rx = receiver_for("mars-a", authority.root_public_key());
    rx.apply_bulletin::<Sig>(&authority.announce_member(
        &honest.id(),
        Some(42),
        &honest.kem_public,
    ))
    .unwrap();

    // The honest node is authorized under ipn:42.
    let v = rx.accept::<Sig>(&honest.send(b"telemetry")).unwrap();
    assert!(v.is_authorized());

    // The attacker's binding verifies (it really does hold its own key), but the
    // ipn claim is unvouched, so authorization fails.
    let a = rx.accept::<Sig>(&attacker.send(b"spoof")).unwrap();
    assert!(a.binding_verified);
    assert_eq!(a.authorization, Err(TrustError::NotAMember));
}

/// The attacker is a member, but of a different node number.
#[test]
fn ipn_binding_mismatch_is_caught() {
    let mut authority = Authority::<Sig>::new("mars-a", &[9u8; 32]);

    // Node is vouched as ipn:7, but sends claiming ipn:42.
    let mut node = Node::new(1, SourceName::Ipn(7));
    let mut rx = receiver_for("mars-a", authority.root_public_key());
    rx.apply_bulletin::<Sig>(&authority.announce_member(&node.id(), Some(7), &node.kem_public))
        .unwrap();

    node.name = SourceName::Ipn(42);
    let v = rx.accept::<Sig>(&node.send(b"escalate")).unwrap();

    assert!(v.binding_verified);
    assert_eq!(
        v.authorization,
        Err(TrustError::IpnBindingMismatch {
            claimed: 42,
            vouched: Some(7)
        })
    );
}

/// The asymmetry: authentication is self-contained, confidentiality is not.
/// You can *authenticate* a peer you have never heard of.
#[test]
fn confidentiality_requires_the_destination_key() {
    use self_auth_dtn::verify::SendError;

    let mut authority = Authority::<Sig>::new("mars-a", &[9u8; 32]);

    let sender_node = Node::new(1, SourceName::SelfCertifying);
    let dest = Node::new(2, SourceName::SelfCertifying);

    // The sender's own view of the world: knows its collective root, nothing else.
    let mut sender_trust = TrustStore::new("mars-a", authority.root_public_key());

    // Before the destination's bulletin arrives, we cannot encrypt to it.
    let attempt = sender_node.sender().send_confidential::<Kem>(
        &sender_trust,
        &dest.id(),
        b"secret",
        &[7u8; 32],
        [1u8; 12],
    );
    assert_eq!(attempt.unwrap_err(), SendError::NoDestinationKey);

    // Authentication in the clear, however, works right now.
    let plain = sender_node.send(b"hello");
    assert_eq!(verify_binding::<Sig>(&plain).unwrap(), sender_node.id());

    // The destination's membership bulletin arrives, carrying its KEM key.
    sender_trust
        .apply::<Sig>(&authority.announce_member(&dest.id(), None, &dest.kem_public))
        .unwrap();

    // Now confidentiality is possible.
    let sealed = sender_node
        .sender()
        .send_confidential::<Kem>(&sender_trust, &dest.id(), b"secret", &[7u8; 32], [1u8; 12])
        .expect("destination key now known");

    // A bystander holding the wrong decapsulation key sees the binding verify
    // but the payload as Undecryptable: reported, not silently swallowed.
    let (_ek, wrong_dk) = Kem::keygen(&[123u8; 32]);
    let mut bystander = receiver_with_kem("mars-a", authority.root_public_key(), wrong_dk);
    let vb = bystander.accept::<Sig>(&sealed).unwrap();
    assert!(vb.binding_verified);
    assert_eq!(vb.payload, ReceivedPayload::Undecryptable);

    // The destination decrypts it, and its binding verifies as usual.
    let mut dest_rx = receiver_with_kem("mars-a", authority.root_public_key(), dest.kem_secret);
    let v = dest_rx.accept::<Sig>(&sealed).unwrap();
    assert!(v.binding_verified);
    assert_eq!(v.payload, ReceivedPayload::Decrypted(b"secret".to_vec()));
    assert_eq!(dest_rx.history(&sender_node.id())[0], b"secret");
}

/// A confidential bundle's integrity is checkable by any node on the path, not
/// only by the destination that can decrypt it.
#[test]
fn confidential_bundle_integrity_is_publicly_checkable() {
    let mut authority = Authority::<Sig>::new("mars-a", &[9u8; 32]);
    let sender_node = Node::new(1, SourceName::SelfCertifying);
    let dest = Node::new(2, SourceName::SelfCertifying);

    let mut sender_trust = TrustStore::new("mars-a", authority.root_public_key());
    sender_trust
        .apply::<Sig>(&authority.announce_member(&dest.id(), None, &dest.kem_public))
        .unwrap();

    let mut sealed = sender_node
        .sender()
        .send_confidential::<Kem>(&sender_trust, &dest.id(), b"secret", &[7u8; 32], [1u8; 12])
        .unwrap();

    // An intermediate router, holding no keys at all, can still verify binding.
    assert_eq!(verify_binding::<Sig>(&sealed).unwrap(), sender_node.id());

    // And it detects tampering with the sealed payload.
    if let Payload::Confidential(bcb) = &mut sealed.payload {
        bcb.sealed_payload[0] ^= 0xff;
    }
    assert_eq!(
        verify_binding::<Sig>(&sealed).unwrap_err(),
        VerifyError::BibSignature
    );
}

/// A bulletin with an expiry in the past is refused by a clock-aware receiver,
/// and refusal neither advances the sequence number nor mutates trust.
#[test]
fn expired_bulletin_is_rejected() {
    let mut authority = Authority::<Sig>::new("mars-a", &[9u8; 32]);
    let q = Node::new(1, SourceName::SelfCertifying);

    let mut store = TrustStore::new("mars-a", authority.root_public_key());
    let b = authority.announce_member_until(&q.id(), None, &q.kem_public, 100);

    // Past its expiry: refused.
    assert_eq!(store.apply_at::<Sig>(&b, 150), Err(TrustError::Expired));
    assert_eq!(
        store.authorize(&q.id(), &SourceName::SelfCertifying),
        Err(TrustError::NotAMember)
    );

    // Refusal did not burn the sequence number: the same bulletin still
    // applies when presented in time.
    assert_eq!(
        store.apply_at::<Sig>(&b, 50).unwrap(),
        Applied::Member(q.id())
    );

    // A clock-free apply() does not enforce expiry, by documented design.
    let mut lax = TrustStore::new("mars-a", authority.root_public_key());
    assert!(lax.apply::<Sig>(&b).is_ok());
}

/// Regression (per-subject freshness): bulletins reorder in a DTN. A delayed
/// bulletin about node A must not be refused because a newer bulletin about
/// node B was applied first.
#[test]
fn delayed_bulletin_about_another_subject_still_applies() {
    let mut authority = Authority::<Sig>::new("mars-a", &[9u8; 32]);
    let n1 = Node::new(1, SourceName::SelfCertifying);
    let n2 = Node::new(2, SourceName::SelfCertifying);

    let b1 = authority.announce_member(&n1.id(), None, &n1.kem_public); // seq 1
    let b2 = authority.announce_member(&n2.id(), None, &n2.kem_public); // seq 2

    let mut rx = receiver_for("mars-a", authority.root_public_key());
    rx.apply_bulletin::<Sig>(&b2).unwrap();
    rx.apply_bulletin::<Sig>(&b1)
        .expect("delayed news about a different subject must still apply");

    assert!(rx.authorization(&n1.id(), &n1.name).is_ok());
    assert!(rx.authorization(&n2.id(), &n2.name).is_ok());
}

/// Receipt-time promotion: only bundles *received* (by this receiver's clock)
/// before the revocation's effective time survive; a revocation with unknown
/// onset voids the whole history. The raw record is untouched either way.
#[test]
fn promotion_is_gated_by_receipt_time() {
    let mut authority = Authority::<Sig>::new("mars-a", &[9u8; 32]);
    let q = Node::new(1, SourceName::SelfCertifying);
    let mut rx = receiver_for("mars-a", authority.root_public_key());

    rx.accept_at::<Sig>(&q.send(b"early"), 10).unwrap();
    rx.accept_at::<Sig>(&q.send(b"late"), 90).unwrap();

    // The collective learns the key was stolen and asserts the compromise
    // began at t=50.
    rx.apply_bulletin::<Sig>(&authority.revoke_effective(
        &q.id(),
        RevocationReason::KeyCompromise,
        50,
    ))
    .unwrap();

    assert_eq!(rx.promotable_history(&q.id()), vec![b"early".as_slice()]);
    assert_eq!(rx.history(&q.id()).len(), 2, "the raw record is untouched");
}

/// A revocation with unknown onset (`revoke`, effective_at = 0) is the
/// conservative case: nothing promotes.
#[test]
fn unknown_onset_revocation_voids_the_history() {
    let mut authority = Authority::<Sig>::new("mars-a", &[9u8; 32]);
    let q = Node::new(1, SourceName::SelfCertifying);
    let mut rx = receiver_for("mars-a", authority.root_public_key());

    rx.accept_at::<Sig>(&q.send(b"anything"), 10).unwrap();
    rx.apply_bulletin::<Sig>(&authority.revoke(&q.id(), RevocationReason::KeyCompromise))
        .unwrap();

    assert!(rx.promotable_history(&q.id()).is_empty());
    assert_eq!(rx.history(&q.id()).len(), 1);
}

/// Re-admission: a membership bulletin issued *after* a revocation (higher
/// seq, same issuer) lifts it. The stale-replay test above covers the
/// converse: the old membership bulletin cannot lift it.
#[test]
fn newer_membership_readmits_after_revocation() {
    let mut authority = Authority::<Sig>::new("mars-a", &[9u8; 32]);
    let q = Node::new(1, SourceName::SelfCertifying);
    let mut rx = receiver_for("mars-a", authority.root_public_key());

    rx.apply_bulletin::<Sig>(&authority.announce_member(&q.id(), None, &q.kem_public))
        .unwrap();
    rx.apply_bulletin::<Sig>(&authority.revoke(&q.id(), RevocationReason::KeyCompromise))
        .unwrap();
    assert!(rx.trust().is_revoked(&q.id()));

    rx.apply_bulletin::<Sig>(&authority.announce_member(&q.id(), None, &q.kem_public))
        .unwrap();
    assert!(!rx.trust().is_revoked(&q.id()));
    assert!(rx.authorization(&q.id(), &q.name).is_ok());
}

/// Regression (pinned watermarks): a flood of freshly minted identifiers must
/// not evict a member's rotation watermark and reopen the stale-key-log
/// window against it.
#[test]
fn member_watermark_survives_identifier_flood() {
    use self_auth_dtn::verify::MAX_SOURCES;

    let mut authority = Authority::<Sig>::new("mars-a", &[9u8; 32]);
    let mut q = Node::new(1, SourceName::SelfCertifying);
    let mut rx = receiver_for("mars-a", authority.root_public_key());
    rx.apply_bulletin::<Sig>(&authority.announce_member(&q.id(), None, &q.kem_public))
        .unwrap();

    // The thief snapshots the pre-rotation key log; the node then rotates and
    // its post-rotation bundle reaches the receiver, setting the watermark.
    let thief_bundle = q.send(b"stolen-material");
    q.identity.rotate(&[142u8; 32], &[42u8; 32]);
    rx.accept::<Sig>(&q.send(b"post-rotation")).unwrap();
    assert_eq!(rx.watermark(&q.id()), Some(1));

    // Flood: mint enough identifiers to wrap the source table.
    for i in 0..(MAX_SOURCES + 8) {
        let mut s0 = [0u8; 32];
        s0[..8].copy_from_slice(&(i as u64).to_be_bytes());
        s0[8] = 101;
        let mut s1 = s0;
        s1[8] = 102;
        let sybil = Identity::<Sig>::incept(&s0, &s1, b"");
        let noise = Sender::new(&sybil, SourceName::SelfCertifying).send_plain(b"noise");
        rx.accept::<Sig>(&noise).unwrap();
    }

    // The member's watermark was pinned through the flood: the thief's stale
    // log is still refused.
    assert_eq!(
        rx.accept::<Sig>(&thief_bundle).unwrap_err(),
        VerifyError::StaleKeyLog
    );
}

/// Ownership: a peer collective cannot overwrite another collective's member
/// record. Without this rule, a compromised peer could substitute its own KEM
/// key for a foreign node and read every confidential bundle sent to it.
#[test]
fn peer_collective_cannot_hijack_membership() {
    let mut agency_a = Authority::<Sig>::new("agency-a", &[10u8; 32]);
    let mut agency_b = Authority::<Sig>::new("agency-b", &[20u8; 32]);
    let q = Node::new(1, SourceName::SelfCertifying);

    let mut rx = receiver_for("agency-a", agency_a.root_public_key());
    rx.apply_bulletin::<Sig>(&agency_a.announce_peer("agency-b", agency_b.root_public_key()))
        .unwrap();
    rx.apply_bulletin::<Sig>(&agency_a.announce_member(&q.id(), None, &q.kem_public))
        .unwrap();

    // B, though trusted for its own members, tries to re-vouch A's node with
    // a KEM key B controls.
    let (b_key, _) = Kem::keygen(&[66u8; 32]);
    let hijack = agency_b.announce_member(&q.id(), None, &b_key);
    assert_eq!(
        rx.apply_bulletin::<Sig>(&hijack),
        Err(TrustError::MemberOfAnotherCollective {
            collective: "agency-a".to_string()
        })
    );

    // The record, and the KEM key senders will use, are still A's.
    let (_, key) = rx.trust().kem_key_for(&q.id()).expect("still a member");
    assert_eq!(key, q.kem_public.as_slice());
}

/// Ownership: a peer collective cannot revoke another collective's member.
#[test]
fn foreign_revocation_cannot_suppress_a_member() {
    let mut agency_a = Authority::<Sig>::new("agency-a", &[10u8; 32]);
    let mut agency_b = Authority::<Sig>::new("agency-b", &[20u8; 32]);
    let q = Node::new(1, SourceName::SelfCertifying);

    let mut rx = receiver_for("agency-a", agency_a.root_public_key());
    rx.apply_bulletin::<Sig>(&agency_a.announce_peer("agency-b", agency_b.root_public_key()))
        .unwrap();
    rx.apply_bulletin::<Sig>(&agency_a.announce_member(&q.id(), None, &q.kem_public))
        .unwrap();

    let foreign = agency_b.revoke(&q.id(), RevocationReason::Unspecified);
    assert_eq!(
        rx.apply_bulletin::<Sig>(&foreign),
        Err(TrustError::MemberOfAnotherCollective {
            collective: "agency-a".to_string()
        })
    );
    assert!(rx.authorization(&q.id(), &q.name).is_ok());
}

/// A pre-emptive revocation of a not-yet-vouched identifier stands, but a
/// collective actually vouching for that identifier outranks the foreign
/// revocation at authorization time.
#[test]
fn preemptive_foreign_revocation_is_outranked_by_true_membership() {
    let mut agency_a = Authority::<Sig>::new("agency-a", &[10u8; 32]);
    let mut agency_b = Authority::<Sig>::new("agency-b", &[20u8; 32]);
    let q = Node::new(1, SourceName::SelfCertifying);

    let mut rx = receiver_for("agency-a", agency_a.root_public_key());
    rx.apply_bulletin::<Sig>(&agency_a.announce_peer("agency-b", agency_b.root_public_key()))
        .unwrap();

    // B revokes an identifier nobody has vouched for. It blocks, for now.
    rx.apply_bulletin::<Sig>(&agency_b.revoke(&q.id(), RevocationReason::Unspecified))
        .unwrap();
    assert!(matches!(
        rx.authorization(&q.id(), &q.name),
        Err(TrustError::Revoked(_))
    ));

    // A then vouches for it. A's record governs; B's revocation is foreign.
    rx.apply_bulletin::<Sig>(&agency_a.announce_member(&q.id(), None, &q.kem_public))
        .unwrap();
    assert!(rx.authorization(&q.id(), &q.name).is_ok());
}

/// De-peering: a peering bulletin with an empty root key withdraws the
/// peering, and the former peer's bulletins are refused thereafter.
#[test]
fn peering_can_be_withdrawn() {
    let mut agency_a = Authority::<Sig>::new("agency-a", &[10u8; 32]);
    let mut agency_b = Authority::<Sig>::new("agency-b", &[20u8; 32]);
    let n = Node::new(3, SourceName::SelfCertifying);

    let mut rx = receiver_for("agency-a", agency_a.root_public_key());
    rx.apply_bulletin::<Sig>(&agency_a.announce_peer("agency-b", agency_b.root_public_key()))
        .unwrap();
    assert_eq!(rx.trust().peers(), vec!["agency-b"]);

    assert_eq!(
        rx.apply_bulletin::<Sig>(&agency_a.withdraw_peer("agency-b"))
            .unwrap(),
        Applied::PeerWithdrawn("agency-b".to_string())
    );
    assert!(rx.trust().peers().is_empty());

    // B's bulletins are now from an unknown issuer again.
    let b_membership = agency_b.announce_member(&n.id(), None, &n.kem_public);
    assert_eq!(
        rx.apply_bulletin::<Sig>(&b_membership),
        Err(TrustError::UnknownIssuer("agency-b".to_string()))
    );
}

/// Withdrawal ends what the peer vouched for, not only its future bulletins.
/// Up to 0.8 a member vouched by a withdrawn peer stayed authorized. Replaying
/// the old membership after a re-grant changes nothing: B has to vouch again.
#[test]
fn withdrawal_ends_the_peers_memberships() {
    let mut agency_a = Authority::<Sig>::new("agency-a", &[10u8; 32]);
    let mut agency_b = Authority::<Sig>::new("agency-b", &[20u8; 32]);
    let n = Node::new(3, SourceName::SelfCertifying);
    let mut rx = receiver_for("agency-a", agency_a.root_public_key());

    let grant = agency_a.announce_peer("agency-b", agency_b.root_public_key());
    rx.apply_bulletin::<Sig>(&grant).unwrap();
    let old_membership = agency_b.announce_member(&n.id(), None, &n.kem_public);
    rx.apply_bulletin::<Sig>(&old_membership).unwrap();
    assert!(rx
        .accept::<Sig>(&n.send(b"before"))
        .unwrap()
        .is_authorized());

    rx.apply_bulletin::<Sig>(&agency_a.withdraw_peer("agency-b"))
        .unwrap();
    assert_eq!(
        rx.authorization(&n.id(), &n.name).unwrap_err(),
        TrustError::NotAMember
    );
    assert!(!rx.accept::<Sig>(&n.send(b"after")).unwrap().is_authorized());
    assert!(
        rx.trust().kem_key_for(&n.id()).is_none(),
        "no KEM key from a withdrawn peer"
    );

    // Replaying the old grant does nothing (stale for its subject).
    assert!(matches!(
        rx.apply_bulletin::<Sig>(&grant),
        Err(TrustError::StaleSequence { .. })
    ));
    // A fresh grant restores the peering, but not the old membership: its
    // replay is stale. B vouches again, and only then is the node authorized.
    rx.apply_bulletin::<Sig>(&agency_a.announce_peer("agency-b", agency_b.root_public_key()))
        .unwrap();
    assert!(matches!(
        rx.apply_bulletin::<Sig>(&old_membership),
        Err(TrustError::StaleSequence { .. })
    ));
    assert!(rx.authorization(&n.id(), &n.name).is_err());
    rx.apply_bulletin::<Sig>(&agency_b.announce_member(&n.id(), None, &n.kem_public))
        .unwrap();
    assert!(rx.authorization(&n.id(), &n.name).is_ok());
}

/// A grant that replaces a peer's root drops records vouched under the old
/// root; a refresh under the same root keeps them.
#[test]
fn root_replacement_ends_old_memberships() {
    let mut agency_a = Authority::<Sig>::new("agency-a", &[10u8; 32]);
    let mut agency_b = Authority::<Sig>::new("agency-b", &[20u8; 32]);
    let n = Node::new(3, SourceName::SelfCertifying);
    let mut rx = receiver_for("agency-a", agency_a.root_public_key());

    rx.apply_bulletin::<Sig>(&agency_a.announce_peer("agency-b", agency_b.root_public_key()))
        .unwrap();
    rx.apply_bulletin::<Sig>(&agency_b.announce_member(&n.id(), None, &n.kem_public))
        .unwrap();
    rx.apply_bulletin::<Sig>(&agency_a.announce_peer("agency-b", agency_b.root_public_key()))
        .unwrap();
    assert!(
        rx.authorization(&n.id(), &n.name).is_ok(),
        "same-root refresh keeps records"
    );

    let new_b = Authority::<Sig>::new("agency-b", &[21u8; 32]);
    rx.apply_bulletin::<Sig>(&agency_a.announce_peer("agency-b", new_b.root_public_key()))
        .unwrap();
    assert_eq!(
        rx.authorization(&n.id(), &n.name).unwrap_err(),
        TrustError::NotAMember
    );
}

/// Forward secrecy, executable: a bundle sealed to an erased KEM epoch is
/// permanently unreadable, and one sealed to a live epoch still decrypts.
/// This is Finding 3 as a test, and the reason the secrecy window is floored
/// by bundle lifetime: erase too early and bundles in flight outlive their key.
#[test]
fn bundle_outliving_its_epoch_is_undecryptable() {
    let mut authority = Authority::<Sig>::new("mars-a", &[9u8; 32]);
    let sender_node = Node::new(1, SourceName::SelfCertifying);
    let dest = Node::new(2, SourceName::SelfCertifying);

    // The destination's epoch keys: its Node keypair serves epoch 0, a second
    // pair serves epoch 100. Both announced by bulletin, in advance.
    let (ek_b, dk_b) = Kem::keygen(&[77u8; 32]);
    let b0 = authority.announce_member(&dest.id(), None, &dest.kem_public);
    let b100 = authority.announce_member_epoch(&dest.id(), None, &ek_b, 100);

    // A sender holding only the epoch-0 bulletin seals under epoch 0.
    let mut trust_old = TrustStore::new("mars-a", authority.root_public_key());
    trust_old.apply::<Sig>(&b0).unwrap();
    let sealed_e0 = sender_node
        .sender()
        .send_confidential::<Kem>(&trust_old, &dest.id(), b"old-epoch", &[5u8; 32], [1u8; 12])
        .unwrap();

    // A sender holding both bulletins seals under the newest epoch, 100.
    let mut trust_new = TrustStore::new("mars-a", authority.root_public_key());
    trust_new.apply::<Sig>(&b0).unwrap();
    trust_new.apply::<Sig>(&b100).unwrap();
    let sealed_e100 = sender_node
        .sender()
        .send_confidential::<Kem>(&trust_new, &dest.id(), b"new-epoch", &[6u8; 32], [2u8; 12])
        .unwrap();

    // The destination holds both decapsulation keys and reads both bundles.
    let mut rx = receiver_with_kem("mars-a", authority.root_public_key(), dest.kem_secret);
    rx.add_epoch_key(100, dk_b);
    assert_eq!(
        rx.accept::<Sig>(&sealed_e0).unwrap().payload,
        ReceivedPayload::Decrypted(b"old-epoch".to_vec())
    );
    assert_eq!(
        rx.accept::<Sig>(&sealed_e100).unwrap().payload,
        ReceivedPayload::Decrypted(b"new-epoch".to_vec())
    );

    // Epoch 0 closes; its key is erased. The old bundle is now unreadable,
    // even to its own destination; the live epoch still decrypts.
    assert_eq!(rx.erase_epochs_before(100), 1);
    assert_eq!(
        rx.accept::<Sig>(&sealed_e0).unwrap().payload,
        ReceivedPayload::Undecryptable
    );
    assert_eq!(
        rx.accept::<Sig>(&sealed_e100).unwrap().payload,
        ReceivedPayload::Decrypted(b"new-epoch".to_vec())
    );
}

/// A grant naming the receiver's own collective is refused: no bulletin, not
/// even one signed by the own root, replaces that root or purges its members.
#[test]
fn own_root_cannot_be_replaced_by_bulletin() {
    let mut agency_a = Authority::<Sig>::new("agency-a", &[10u8; 32]);
    let other = Authority::<Sig>::new("agency-a", &[11u8; 32]);
    let n = Node::new(3, SourceName::SelfCertifying);
    let mut rx = receiver_for("agency-a", agency_a.root_public_key());
    rx.apply_bulletin::<Sig>(&agency_a.announce_member(&n.id(), None, &n.kem_public))
        .unwrap();

    let takeover = agency_a.announce_peer("agency-a", other.root_public_key());
    assert!(matches!(
        rx.apply_bulletin::<Sig>(&takeover),
        Err(TrustError::PeeringNotFromOwnCollective(_))
    ));
    assert!(rx.authorization(&n.id(), &n.name).is_ok());
}
