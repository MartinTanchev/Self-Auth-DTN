#![cfg(feature = "mock")]

//! Regressions for two findings from an external review (0.9):
//!
//! 1. Authorship confusion on confidential bundles. The BCB's AEAD bound only
//!    the KEM ciphertext, so an attacker could lift A's sealed payload into a
//!    bundle under its own identifier, re-sign it, and B would decrypt it as
//!    coming from the attacker. The associated data now carries the source
//!    identifier (and epoch).
//! 2. Membership expiry expired nothing. `announce_member_until` was checked
//!    only on arrival; the record kept no expiry. Records now store it and
//!    `authorize_at` refuses a lapsed member.

use self_auth_dtn::prelude::*;
use self_auth_dtn::verify::{bcb_aad, Sender, UNKNOWN_RECEIPT_TIME};

fn setup() -> (
    Authority<MockSig>,
    Identity<MockSig>,
    Identity<MockSig>,
    NodeId,
    Receiver<MockKem>,
    TrustStore,
) {
    let mut auth = Authority::<MockSig>::new("lab", &[1u8; 32]);
    let a = Identity::<MockSig>::incept(&[2u8; 32], &[3u8; 32], b"a");
    let m = Identity::<MockSig>::incept(&[4u8; 32], &[5u8; 32], b"m");
    let b_id = Identity::<MockSig>::incept(&[6u8; 32], &[7u8; 32], b"b").node_id();
    let (b_kem, b_decap) = MockKem::keygen(&[8u8; 32]);
    let b_member = auth.announce_member(&b_id, None, &b_kem);

    let mut sender_view = TrustStore::new("lab", auth.root_public_key());
    sender_view.apply::<MockSig>(&b_member).unwrap();
    let rx = Receiver::<MockKem>::new(TrustStore::new("lab", auth.root_public_key()), b_decap);
    (auth, a, m, b_id, rx, sender_view)
}

#[test]
fn lifted_bcb_does_not_open_under_another_identifier() {
    let (_, a, m, b_id, mut rx, view) = setup();

    let original = Sender::new(&a, SourceName::SelfCertifying)
        .send_confidential::<MockKem>(&view, &b_id, b"from A", &[9u8; 32], [1u8; 12])
        .unwrap();
    let v = rx.accept_at::<MockSig>(&original, 10).unwrap();
    assert_eq!(v.payload, ReceivedPayload::Decrypted(b"from A".to_vec()));

    // M lifts A's BCB into a bundle under M's own identifier and signs it.
    let Payload::Confidential(bcb) = original.payload.clone() else {
        unreachable!()
    };
    let mut forged = Sender::new(&m, SourceName::SelfCertifying).send_plain(b"placeholder");
    forged.payload = Payload::Confidential(bcb);
    forged.bib.signature = m.sign_protected(&forged.protected_bytes());

    // Binding holds (M really signed it) but the payload must not open.
    let v = rx.accept_at::<MockSig>(&forged, 11).unwrap();
    assert_eq!(v.node_id, m.node_id());
    assert_eq!(v.payload, ReceivedPayload::Undecryptable);
}

#[test]
fn bcb_aad_binds_source_epoch_and_ciphertext() {
    let base = bcb_aad(&[1u8; 32], 0, b"ct");
    assert_ne!(base, bcb_aad(&[2u8; 32], 0, b"ct"), "source");
    assert_ne!(base, bcb_aad(&[1u8; 32], 1, b"ct"), "epoch");
    assert_ne!(base, bcb_aad(&[1u8; 32], 0, b"cu"), "ciphertext");
}

#[test]
fn membership_lapses_at_its_expiry() {
    let (mut auth, a, _, _, mut rx, _) = setup();
    let (a_kem, _) = MockKem::keygen(&[10u8; 32]);
    let b = auth.announce_member_until(&a.node_id(), None, &a_kem, 100);
    rx.apply_bulletin_at::<MockSig>(&b, 50).unwrap();

    let bundle = Sender::new(&a, SourceName::SelfCertifying).send_plain(b"hi");
    assert!(rx
        .accept_at::<MockSig>(&bundle, 90)
        .unwrap()
        .is_authorized());
    assert!(rx
        .accept_at::<MockSig>(&bundle, 100)
        .unwrap()
        .is_authorized());
    let late = rx.accept_at::<MockSig>(&bundle, 101).unwrap();
    assert_eq!(
        late.authorization,
        Err(TrustError::MembershipExpired { expired_at: 100 })
    );
    assert_eq!(
        rx.authorization_at(&a.node_id(), &SourceName::SelfCertifying, 101),
        Err(TrustError::MembershipExpired { expired_at: 100 })
    );
    // No clock: fail safe.
    assert!(rx
        .authorization_at(
            &a.node_id(),
            &SourceName::SelfCertifying,
            UNKNOWN_RECEIPT_TIME
        )
        .is_err());

    // Renewal: a fresh membership bulletin moves the expiry.
    let renewed = auth.announce_member_until(&a.node_id(), None, &a_kem, 500);
    rx.apply_bulletin_at::<MockSig>(&renewed, 200).unwrap();
    assert!(rx
        .accept_at::<MockSig>(&bundle, 300)
        .unwrap()
        .is_authorized());

    // A membership without expiry never lapses.
    let forever = auth.announce_member(&a.node_id(), None, &a_kem);
    rx.apply_bulletin_at::<MockSig>(&forever, 400).unwrap();
    assert!(rx
        .accept_at::<MockSig>(&bundle, 10_000)
        .unwrap()
        .is_authorized());
}
