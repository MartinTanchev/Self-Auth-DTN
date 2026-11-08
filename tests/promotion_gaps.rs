#![cfg(feature = "mock")]

//! Regressions for three gaps found while writing the formal model (0.9):
//!
//! 1. Re-admission lifted a revocation and made the whole held history
//!    promotable again, a thief's bundles from the compromise window
//!    included. Now the window stays suspect for good.
//! 2. `Receiver::accept` (no clock) stamped receipt time 0, so any revocation
//!    with a stated onset let everything through. Now it stamps
//!    `UNKNOWN_RECEIPT_TIME`, which fails safe.
//! 3. Re-keying an epoch dropped the old decapsulation key without destroying
//!    it. Now it is destroyed.

mod common;
use common::*;

use self_auth_dtn::prelude::*;
use self_auth_dtn::verify::UNKNOWN_RECEIPT_TIME;
use std::sync::atomic::{AtomicUsize, Ordering};

#[test]
fn readmission_keeps_the_compromise_window_suspect() {
    let mut authority = Authority::<Sig>::new("mars-a", &[9u8; 32]);
    let q = Node::new(1, SourceName::SelfCertifying);
    let mut rx = receiver_for("mars-a", authority.root_public_key());
    rx.apply_bulletin_at::<Sig>(&authority.announce_member(&q.id(), None, &q.kem_public), 1)
        .unwrap();

    rx.accept_at::<Sig>(&q.send(b"early"), 10).unwrap();
    // Key stolen at 40; this one came from the thief.
    rx.accept_at::<Sig>(&q.send(b"during-compromise"), 50)
        .unwrap();

    let revocation = authority.revoke_effective(&q.id(), RevocationReason::KeyCompromise, 40);
    rx.apply_bulletin_at::<Sig>(&revocation, 60).unwrap();
    assert_eq!(rx.promotable_history(&q.id()), vec![b"early".as_slice()]);

    // The node recovers (rotation, new key) and is re-admitted at 100.
    rx.apply_bulletin_at::<Sig>(
        &authority.announce_member(&q.id(), None, &q.kem_public),
        100,
    )
    .unwrap();
    assert!(rx.authorization(&q.id(), &q.name).is_ok());
    assert_eq!(rx.trust().suspect_spans(&q.id()), &[(40, 100)]);

    rx.accept_at::<Sig>(&q.send(b"after-readmission"), 120)
        .unwrap();
    assert_eq!(
        rx.promotable_history(&q.id()),
        vec![b"early".as_slice(), b"after-readmission".as_slice()],
        "the compromise window never comes back"
    );
}

#[test]
fn readmission_without_a_clock_keeps_everything_since_onset_suspect() {
    let mut authority = Authority::<Sig>::new("mars-a", &[9u8; 32]);
    let q = Node::new(1, SourceName::SelfCertifying);
    let mut rx = receiver_for("mars-a", authority.root_public_key());
    rx.apply_bulletin::<Sig>(&authority.announce_member(&q.id(), None, &q.kem_public))
        .unwrap();
    rx.accept_at::<Sig>(&q.send(b"early"), 10).unwrap();
    rx.accept_at::<Sig>(&q.send(b"during-compromise"), 50)
        .unwrap();
    rx.apply_bulletin::<Sig>(&authority.revoke_effective(
        &q.id(),
        RevocationReason::KeyCompromise,
        40,
    ))
    .unwrap();
    rx.apply_bulletin::<Sig>(&authority.announce_member(&q.id(), None, &q.kem_public))
        .unwrap();

    // With no clock the re-admission time is unknown: the span stays open.
    assert_eq!(rx.trust().suspect_spans(&q.id()), &[(40, u64::MAX)]);
    rx.accept_at::<Sig>(&q.send(b"later"), 500).unwrap();
    assert_eq!(rx.promotable_history(&q.id()), vec![b"early".as_slice()]);
    // Live authorization is unaffected: only retroactive promotion is.
    assert!(rx.accept::<Sig>(&q.send(b"live")).unwrap().is_authorized());
}

#[test]
fn unknown_onset_readmission_voids_the_held_history() {
    let mut authority = Authority::<Sig>::new("mars-a", &[9u8; 32]);
    let q = Node::new(1, SourceName::SelfCertifying);
    let mut rx = receiver_for("mars-a", authority.root_public_key());
    rx.apply_bulletin_at::<Sig>(&authority.announce_member(&q.id(), None, &q.kem_public), 1)
        .unwrap();
    rx.accept_at::<Sig>(&q.send(b"before"), 10).unwrap();
    rx.apply_bulletin_at::<Sig>(
        &authority.revoke(&q.id(), RevocationReason::KeyCompromise),
        20,
    )
    .unwrap();
    rx.apply_bulletin_at::<Sig>(&authority.announce_member(&q.id(), None, &q.kem_public), 30)
        .unwrap();
    rx.accept_at::<Sig>(&q.send(b"after"), 40).unwrap();
    assert_eq!(rx.promotable_history(&q.id()), vec![b"after".as_slice()]);
}

#[test]
fn clockless_accept_fails_safe_under_revocation() {
    let mut authority = Authority::<Sig>::new("mars-a", &[9u8; 32]);
    let q = Node::new(1, SourceName::SelfCertifying);
    let mut rx = receiver_for("mars-a", authority.root_public_key());
    rx.apply_bulletin::<Sig>(&authority.announce_member(&q.id(), None, &q.kem_public))
        .unwrap();

    rx.accept::<Sig>(&q.send(b"unknown-time")).unwrap();
    assert_eq!(
        rx.promotable_history(&q.id()),
        vec![b"unknown-time".as_slice()]
    );

    // Up to 0.9 the stamp was 0, which passed `received_at < 40`.
    rx.apply_bulletin::<Sig>(&authority.revoke_effective(
        &q.id(),
        RevocationReason::KeyCompromise,
        40,
    ))
    .unwrap();
    assert!(rx.promotable_history(&q.id()).is_empty());
    assert_eq!(UNKNOWN_RECEIPT_TIME, u64::MAX);
}

/// A KEM that counts destroyed keys, to observe erasure.
static DESTROYED: AtomicUsize = AtomicUsize::new(0);
struct CountingKem;
impl KemScheme for CountingKem {
    type DecapKey = <Kem as KemScheme>::DecapKey;
    const IS_MOCK: bool = true;
    fn keygen(seed: &[u8; 32]) -> (Vec<u8>, Self::DecapKey) {
        Kem::keygen(seed)
    }
    fn encapsulate(encap_key: &[u8], seed: &[u8; 32]) -> Option<(Vec<u8>, [u8; 32])> {
        Kem::encapsulate(encap_key, seed)
    }
    fn decapsulate(decap_key: &Self::DecapKey, ciphertext: &[u8]) -> Option<[u8; 32]> {
        Kem::decapsulate(decap_key, ciphertext)
    }
    fn destroy(secret: &mut Self::DecapKey) {
        Kem::destroy(secret);
        DESTROYED.fetch_add(1, Ordering::SeqCst);
    }
}

#[test]
fn rekeying_an_epoch_destroys_the_old_key() {
    let (_, primary) = CountingKem::keygen(&[250u8; 32]);
    let mut rx = Receiver::<CountingKem>::new(TrustStore::new("mars-a", &[0u8; 32]), primary);
    let (_, k1) = CountingKem::keygen(&[1u8; 32]);
    let (_, k2) = CountingKem::keygen(&[2u8; 32]);

    let before = DESTROYED.load(Ordering::SeqCst);
    rx.add_epoch_key(5, k1);
    assert_eq!(
        DESTROYED.load(Ordering::SeqCst),
        before,
        "first key for an epoch"
    );
    rx.add_epoch_key(5, k2);
    assert_eq!(
        DESTROYED.load(Ordering::SeqCst),
        before + 1,
        "replaced key destroyed"
    );
    // The primary key is epoch 0 (Receiver::new); erasing before 10 takes it
    // and epoch 5's replacement.
    assert_eq!(rx.erase_epochs_before(10), 2);
    assert_eq!(
        DESTROYED.load(Ordering::SeqCst),
        before + 3,
        "erasure destroys too"
    );
}
