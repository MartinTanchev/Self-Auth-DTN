#![cfg(feature = "mock")]

//! Key theft and forks.
//!
//! Before 0.9 the key revealed by a rotation event also signed bundles. A
//! thief holding it after a rotation could sign an alternative version of that
//! event committing to its own successor, extend the fork past the real log,
//! and take the identifier over, since the receiver only compared log lengths.
//!
//! Since 0.9 an establishment key signs exactly one event and is destroyed;
//! bundles are signed by a separate operational key. Receivers keep the key
//! log they first saw and refuse conflicting ones, recording the two events
//! as evidence. These tests pin all of that.

mod common;
use common::*;

use self_auth_dtn::prelude::*;
use self_auth_dtn::sha256::sha256;

/// A bundle from an arbitrary key log, signed by `signer`.
fn bundle_with_log(
    holder: &Identity<Sig>,
    rotations: Vec<KeyEvent>,
    current_pk: Vec<u8>,
    signer: &<Sig as SignatureScheme>::SecretKey,
    payload: &[u8],
) -> Bundle {
    let mut b = Bundle {
        source_id: holder.node_id(),
        name: SourceName::SelfCertifying,
        self_auth: SelfAuthBlock {
            inception: holder.inception().clone(),
            inception_sig: holder.inception_sig().to_vec(),
            rotations,
            current_public_key: current_pk,
        },
        payload: Payload::Plain(payload.to_vec()),
        bib: Bib {
            signature: Vec::new(),
        },
    };
    b.bib.signature = Sig::sign(signer, &b.protected_bytes());
    b
}

/// A rotation event revealing `revealed`, signed by `key`.
fn event(
    index: u32,
    revealed: &[u8],
    key: &<Sig as SignatureScheme>::SecretKey,
    operational: &[u8],
    next_pk: &[u8],
    prior: [u8; 32],
) -> KeyEvent {
    let next_commitment = sha256(next_pk);
    let body = KeyEvent::canonical_body(index, revealed, operational, &next_commitment, &prior);
    KeyEvent {
        event_index: index,
        revealed_public_key: revealed.to_vec(),
        operational_public_key: operational.to_vec(),
        next_commitment,
        prior_event_hash: prior,
        signature: Sig::sign(key, &body),
    }
}

// Node::new(1, ..): inception key k0 = [1; 32], committed successor k1 = [101; 32].
// rotate(&[142..], &[42..]): reveals k1, operational o1 = [142; 32], commits k2 = [42; 32].
// rotate(&[143..], &[43..]): reveals k2, operational o2 = [143; 32], commits k3 = [43; 32].

#[test]
fn stolen_operational_key_cannot_fork() {
    let mut q = Node::new(1, SourceName::SelfCertifying);
    q.identity.rotate(&[142u8; 32], &[42u8; 32]);
    let id = q.id();

    // The thief holds the operational key o1 only. The establishment key k1
    // that signed event 1 has been destroyed by the holder.
    let (o1, o1_sk) = Sig::keygen(&[142u8; 32]);
    assert_eq!(o1, q.identity.current_public_key());
    let (pka, _) = Sig::keygen(&[66u8; 32]);
    let (pkb, _) = Sig::keygen(&[67u8; 32]);

    // Re-signing event 1 with o1 fails: event 1 must be signed by the key it
    // reveals, and that key must be k1.
    let (pk1, _) = Sig::keygen(&[101u8; 32]);
    let fake = event(1, &pk1, &o1_sk, &pka, &pkb, id);
    let b = bundle_with_log(&q.identity, vec![fake], pka.clone(), &o1_sk, b"thief");
    assert_eq!(
        verify_binding::<Sig>(&b).unwrap_err(),
        VerifyError::EventSignature
    );

    // Revealing o1 itself fails the commitment.
    let fake = event(1, &o1, &o1_sk, &pka, &pkb, id);
    let b = bundle_with_log(&q.identity, vec![fake], pka, &o1_sk, b"thief");
    assert_eq!(
        verify_binding::<Sig>(&b).unwrap_err(),
        VerifyError::CommitmentMismatch
    );
}

#[test]
fn stolen_operational_key_is_cut_off_by_the_next_rotation() {
    let authority = Authority::<Sig>::new("mars-a", &[9u8; 32]);
    let mut q = Node::new(1, SourceName::SelfCertifying);
    let mut rx = receiver_for("mars-a", authority.root_public_key());
    q.identity.rotate(&[142u8; 32], &[42u8; 32]);

    // The thief signs with stolen o1 and the current log: valid until the
    // next rotation reaches this receiver. That window is the design's bound.
    let thief = q.send(b"thief-with-o1");
    assert!(rx.accept::<Sig>(&thief).unwrap().binding_verified);

    q.identity.rotate(&[143u8; 32], &[43u8; 32]);
    assert!(rx.accept::<Sig>(&q.send(b"honest")).is_ok());
    assert_eq!(rx.watermark(&q.id()), Some(2));
    assert_eq!(
        rx.accept::<Sig>(&thief).unwrap_err(),
        VerifyError::StaleKeyLog
    );
}

#[test]
fn stolen_next_key_forks_and_first_seen_detects_it() {
    // The inherent case of pre-rotation: the thief steals the committed next
    // establishment key k2 before the holder uses it. The thief can then
    // rotate the identifier. First-seen receivers detect the fork and keep
    // proof; which branch a receiver keeps is whichever reached it first.
    let mut q = Node::new(1, SourceName::SelfCertifying);
    q.identity.rotate(&[142u8; 32], &[42u8; 32]);
    let id = q.id();
    let ev1_hash = q.identity.rotations()[0].hash();

    let (pk2, k2) = Sig::keygen(&[42u8; 32]); // stolen
    let (pka, ka) = Sig::keygen(&[66u8; 32]);
    let (pkb, _) = Sig::keygen(&[67u8; 32]);
    let fork = event(2, &pk2, &k2, &pka, &pkb, ev1_hash);
    let mut fork_log = q.identity.rotations().to_vec();
    fork_log.push(fork.clone());
    let thief = bundle_with_log(&q.identity, fork_log, pka, &ka, b"thief");
    assert_eq!(
        verify_binding::<Sig>(&thief).unwrap(),
        id,
        "the fork is valid on its own"
    );

    // The holder rotates too.
    q.identity.rotate(&[143u8; 32], &[43u8; 32]);
    let honest = q.send(b"honest");
    let honest_ev2 = q.identity.rotations()[1].clone();

    // Receiver A sees the real event first: the fork is refused.
    let mut rx_a = receiver_for("mars-a", &[0u8; 32]);
    rx_a.accept::<Sig>(&honest).unwrap();
    assert_eq!(
        rx_a.accept::<Sig>(&thief).unwrap_err(),
        VerifyError::Duplicity
    );
    let ev = rx_a.duplicity(&id).unwrap();
    assert_eq!((&ev.first_seen, &ev.conflicting), (&honest_ev2, &fork));
    assert!(verify_duplicity::<Sig>(&ev.first_seen, &ev.conflicting));
    assert!(
        rx_a.accept::<Sig>(&q.send(b"honest-again")).is_ok(),
        "first seen stays usable"
    );

    // Receiver B sees the fork first: it keeps the thief's branch, refuses the
    // holder, and holds the same proof. Revocation has to come from here.
    let mut rx_b = receiver_for("mars-a", &[0u8; 32]);
    rx_b.accept::<Sig>(&thief).unwrap();
    assert_eq!(
        rx_b.accept::<Sig>(&honest).unwrap_err(),
        VerifyError::Duplicity
    );
    assert!(verify_duplicity::<Sig>(
        &rx_b.duplicity(&id).unwrap().first_seen,
        &rx_b.duplicity(&id).unwrap().conflicting
    ));
}

#[test]
fn duplicity_evidence_needs_two_valid_signatures() {
    let mut q = Node::new(1, SourceName::SelfCertifying);
    q.identity.rotate(&[142u8; 32], &[42u8; 32]);
    let real = q.identity.rotations()[0].clone();
    assert!(
        !verify_duplicity::<Sig>(&real, &real),
        "an event is not a fork of itself"
    );
    let mut forged = real.clone();
    forged.operational_public_key = vec![7u8; 32];
    assert!(
        !verify_duplicity::<Sig>(&real, &forged),
        "an unsigned alteration is not evidence"
    );
}

#[test]
fn operational_key_must_not_be_an_establishment_key() {
    // A log in which the operational key is the revealed key, or the
    // committed successor, would let a thief of the operational key sign
    // rotation events: the pre-0.9 weakness. Both are refused.
    let q = Node::new(1, SourceName::SelfCertifying);
    let id = q.id();
    let (pk1, k1) = Sig::keygen(&[101u8; 32]); // as the holder
    let (pkn, _) = Sig::keygen(&[42u8; 32]);

    let same_as_revealed = event(1, &pk1, &k1, &pk1, &pkn, id);
    let b = bundle_with_log(&q.identity, vec![same_as_revealed], pk1.clone(), &k1, b"x");
    assert_eq!(
        verify_binding::<Sig>(&b).unwrap_err(),
        VerifyError::KeyReuse
    );

    let same_as_next = event(1, &pk1, &k1, &pkn, &pkn, id);
    let b = bundle_with_log(&q.identity, vec![same_as_next], pkn, &k1, b"x");
    assert_eq!(
        verify_binding::<Sig>(&b).unwrap_err(),
        VerifyError::KeyReuse
    );
}

#[test]
fn stolen_key_before_any_rotation_cannot_fork() {
    // With no rotation yet, the inception key signed only the inception
    // record, whose commitment the identifier fixes. A thief with k0 cannot
    // produce any event 1.
    let q = Node::new(1, SourceName::SelfCertifying);
    let (pk0, k0) = Sig::keygen(&[1u8; 32]);
    assert_eq!(pk0, q.identity.current_public_key());
    let (pka, _) = Sig::keygen(&[66u8; 32]);
    let (pkb, _) = Sig::keygen(&[67u8; 32]);
    let bad = event(1, &pk0, &k0, &pka, &pkb, q.id());
    let b = bundle_with_log(&q.identity, vec![bad], pka, &k0, b"thief");
    assert_eq!(
        verify_binding::<Sig>(&b).unwrap_err(),
        VerifyError::CommitmentMismatch
    );
}
