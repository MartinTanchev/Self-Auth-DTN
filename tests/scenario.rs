#![cfg(feature = "mock")]

//! Core scenarios: the window before the bulletin, rotation, and the
//! rejection paths.

mod common;
use common::*;

use self_auth_dtn::prelude::*;

#[test]
fn window_before_the_bulletin() {
    // A collective, and a node in it.
    let mut authority = Authority::<Sig>::new("mars-a", &[9u8; 32]);
    let q = Node::new(1, SourceName::SelfCertifying);

    // A receiver fielded knowing only its own collective's root key.
    let mut rx = receiver_for("mars-a", authority.root_public_key());

    // First contact, no bulletin held. Binding verifies from the bundle alone.
    let v1 = rx.accept::<Sig>(&q.send(b"frame-1")).unwrap();
    assert!(v1.binding_verified);
    assert_eq!(v1.node_id, q.id());
    assert_eq!(v1.authorization, Err(TrustError::NotAMember));
    assert!(!v1.is_authorized());

    // More bundles accumulate under the same proven identifier.
    rx.accept::<Sig>(&q.send(b"frame-2")).unwrap();
    let v3 = rx.accept::<Sig>(&q.send(b"frame-3")).unwrap();
    assert_eq!(v3.accumulated, 3);
    assert_eq!(rx.history(&q.id()).len(), 3);

    // The bulletin lands. The whole accumulated history is authorized at once,
    // because the identifier in the bulletin is the same object we were checking.
    let bulletin = authority.announce_member(&q.id(), None, &q.kem_public);
    assert_eq!(
        rx.apply_bulletin::<Sig>(&bulletin).unwrap(),
        Applied::Member(q.id())
    );

    let after = rx.authorization(&q.id(), &q.name).unwrap();
    assert_eq!(after.collective, "mars-a");
    assert_eq!(rx.history(&q.id()).len(), 3); // nothing was discarded
}

#[test]
fn imposter_cannot_claim_another_identifier() {
    let victim = Node::new(1, SourceName::SelfCertifying);
    let attacker = Node::new(2, SourceName::SelfCertifying);

    // Attacker sends its own bundle but stamps the victim's identifier.
    let mut bundle = attacker.send(b"spoof");
    bundle.source_id = victim.id();

    assert_eq!(
        verify_binding::<Sig>(&bundle).unwrap_err(),
        VerifyError::NodeIdMismatch
    );
}

#[test]
fn rotation_preserves_the_identifier() {
    let mut q = Node::new(1, SourceName::SelfCertifying);
    let id_before = q.id();
    let key_before = q.identity.current_public_key().to_vec();

    q.identity.rotate(&[142u8; 32], &[42u8; 32]);

    assert_eq!(q.id(), id_before, "identifier must not move");
    assert_ne!(q.identity.current_public_key().to_vec(), key_before);

    // A bundle signed by the rotated key still verifies offline.
    assert_eq!(verify_binding::<Sig>(&q.send(b"after")).unwrap(), id_before);
}

#[test]
fn multiple_rotations_validate() {
    let mut q = Node::new(1, SourceName::SelfCertifying);
    let id = q.id();
    q.identity.rotate(&[142u8; 32], &[42u8; 32]);
    q.identity.rotate(&[143u8; 32], &[43u8; 32]);

    let bundle = q.send(b"payload");
    assert_eq!(bundle.self_auth.rotations.len(), 2);
    assert_eq!(verify_binding::<Sig>(&bundle).unwrap(), id);
}

// --- rejection paths -------------------------------------------------------

#[test]
fn tampered_payload_is_rejected() {
    let q = Node::new(1, SourceName::SelfCertifying);
    let mut bundle = q.send(b"honest");
    bundle.payload = Payload::Plain(b"tampered".to_vec());

    assert_eq!(
        verify_binding::<Sig>(&bundle).unwrap_err(),
        VerifyError::BibSignature
    );
}

#[test]
fn tampered_name_is_rejected() {
    // The claimed name is inside the signed bytes, so it cannot be swapped.
    let q = Node::new(1, SourceName::Ipn(42));
    let mut bundle = q.send(b"payload");
    bundle.name = SourceName::Ipn(43);

    assert_eq!(
        verify_binding::<Sig>(&bundle).unwrap_err(),
        VerifyError::BibSignature
    );
}

#[test]
fn forged_rotation_is_rejected() {
    let mut q = Node::new(1, SourceName::SelfCertifying);
    q.identity.rotate(&[142u8; 32], &[42u8; 32]);
    let mut bundle = q.send(b"payload");

    // Swap in a key that was never pre-committed.
    let (bogus, _) = <Sig as SignatureScheme>::keygen(&[77u8; 32]);
    bundle.self_auth.rotations[0].revealed_public_key = bogus;

    assert_eq!(
        verify_binding::<Sig>(&bundle).unwrap_err(),
        VerifyError::CommitmentMismatch
    );
}

#[test]
fn rotation_without_successor_possession_is_rejected() {
    // "Rotation requires producing the pre-committed successor key": a valid
    // rotation event must be signed by the revealed key. A forged signature
    // fails even when the revealed key matches the commitment.
    let mut q = Node::new(1, SourceName::SelfCertifying);
    q.identity.rotate(&[142u8; 32], &[42u8; 32]);
    let mut bundle = q.send(b"payload");

    bundle.self_auth.rotations[0].signature = vec![0u8; 32];

    assert_eq!(
        verify_binding::<Sig>(&bundle).unwrap_err(),
        VerifyError::EventSignature
    );
}

#[test]
fn broken_chain_is_rejected() {
    let mut q = Node::new(1, SourceName::SelfCertifying);
    q.identity.rotate(&[142u8; 32], &[42u8; 32]);
    let mut bundle = q.send(b"payload");
    bundle.self_auth.rotations[0].prior_event_hash = [0u8; 32];

    assert_eq!(
        verify_binding::<Sig>(&bundle).unwrap_err(),
        VerifyError::ChainBroken
    );
}

#[test]
fn out_of_order_event_is_rejected() {
    let mut q = Node::new(1, SourceName::SelfCertifying);
    q.identity.rotate(&[142u8; 32], &[42u8; 32]);
    let mut bundle = q.send(b"payload");
    bundle.self_auth.rotations[0].event_index = 9;

    assert_eq!(
        verify_binding::<Sig>(&bundle).unwrap_err(),
        VerifyError::EventOrder
    );
}

#[test]
fn tampered_inception_signature_is_rejected() {
    let q = Node::new(1, SourceName::SelfCertifying);
    let mut bundle = q.send(b"payload");
    bundle.self_auth.inception_sig = vec![0u8; 32];

    assert_eq!(
        verify_binding::<Sig>(&bundle).unwrap_err(),
        VerifyError::InceptionSignature
    );
}

#[test]
fn substituted_current_key_is_rejected() {
    let q = Node::new(1, SourceName::SelfCertifying);
    let mut bundle = q.send(b"payload");
    let (other, _) = <Sig as SignatureScheme>::keygen(&[88u8; 32]);
    bundle.self_auth.current_public_key = other;

    assert_eq!(
        verify_binding::<Sig>(&bundle).unwrap_err(),
        VerifyError::CurrentKeyMismatch
    );
}

#[test]
fn rotation_watermark_cuts_off_a_stolen_key() {
    // The claim: a thief holding the current signing key can impersonate the
    // node "only until the legitimate rotation propagates". Chain validation is
    // stateless, so the propagation bound is enforced by the receiver's
    // rotation watermark: once the longer log has been witnessed, the thief's
    // pre-rotation log is refused.
    let authority = Authority::<Sig>::new("mars-a", &[9u8; 32]);
    let mut q = Node::new(1, SourceName::SelfCertifying);
    let mut rx = receiver_for("mars-a", authority.root_public_key());

    // The thief captures the key and the current (pre-rotation) key log. A
    // bundle built from that material stands in for anything the thief signs.
    let thief_bundle = q.send(b"thief-was-here");

    // Before the rotation reaches this receiver, the thief's bundle verifies:
    // this is the window the design bounds, not one it eliminates.
    assert!(rx.accept::<Sig>(&thief_bundle).unwrap().binding_verified);

    // The legitimate node rotates and its next bundle reaches the receiver.
    q.identity.rotate(&[142u8; 32], &[42u8; 32]);
    let post = q.send(b"legitimate-post-rotation");
    assert!(rx.accept::<Sig>(&post).unwrap().binding_verified);
    assert_eq!(rx.watermark(&q.id()), Some(1));

    // From now on the thief is cut off here: the old log is stale.
    assert_eq!(
        rx.accept::<Sig>(&thief_bundle).unwrap_err(),
        VerifyError::StaleKeyLog
    );

    // And the thief cannot fabricate a longer log: extending it requires the
    // pre-committed successor, which the thief has never seen (covered by
    // forged_rotation_is_rejected and rotation_without_successor_possession).
}

/// An inception record may commit to the node's ipn number. The claim is then
/// non-equivocable already in the window: the same identity cannot present a
/// different number, and two identities claiming one number are
/// distinguishable on contact. Entitlement stays with the bulletin.
#[test]
fn committed_ipn_pins_the_claimed_number() {
    let id = Identity::<Sig>::incept_with_ipn(&[3u8; 32], &[4u8; 32], 7001);

    let good = Sender::new(&id, SourceName::Ipn(7001)).send_plain(b"telemetry");
    assert!(verify_binding::<Sig>(&good).is_ok());

    let bad = Sender::new(&id, SourceName::Ipn(7002)).send_plain(b"escalate");
    assert_eq!(
        verify_binding::<Sig>(&bad).unwrap_err(),
        VerifyError::IpnCommitmentMismatch
    );

    // Opaque metadata commits to nothing: any number may be claimed, and the
    // bulletin remains the only check, as before.
    let free = Identity::<Sig>::incept(&[5u8; 32], &[6u8; 32], b"opaque");
    let b = Sender::new(&free, SourceName::Ipn(9)).send_plain(b"x");
    assert!(verify_binding::<Sig>(&b).is_ok());
}
