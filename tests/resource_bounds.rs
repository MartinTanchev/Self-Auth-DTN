#![cfg(feature = "mock")]

//! Resource bounds against identifiers minted to exhaust a receiver.
//!
//! 1. The wire decoder used to reserve memory for however many rotation
//!    events a header declared, before reading any: a few bytes could ask for
//!    gigabytes. Counts above `MAX_KEY_EVENTS` are now refused first.
//! 2. Key logs were unbounded: every event costs a signature check per bundle,
//!    and receivers kept whole logs per identifier. Logs are now capped at
//!    `MAX_KEY_EVENTS`, and receivers keep only a log's length and newest
//!    event.

mod common;
use common::*;

use self_auth_dtn::keylog::MAX_KEY_EVENTS;
use self_auth_dtn::prelude::*;
use self_auth_dtn::wire::{decode_self_auth, encode_self_auth, WireError};

#[test]
fn hostile_rotation_count_is_refused_before_allocating() {
    let q = Node::new(1, SourceName::SelfCertifying);
    let mut encoded = encode_self_auth(&q.send(b"x").self_auth, 1);
    // With zero rotations the block ends in the empty rotations array (0x80).
    assert_eq!(encoded.pop(), Some(0x80));
    // Declare 2^24 events: array head with a 4-byte length, and no events.
    encoded.extend_from_slice(&[0x9A, 0x01, 0x00, 0x00, 0x00]);
    assert_eq!(
        decode_self_auth(&encoded).unwrap_err(),
        WireError::Malformed
    );

    // One more than the cap is refused too; the cap itself only by the
    // missing events (truncated), not by the count.
    let base = &encoded[..encoded.len() - 5];
    let mut over = base.to_vec();
    over.extend_from_slice(&[0x98, (MAX_KEY_EVENTS + 1) as u8]);
    assert_eq!(decode_self_auth(&over).unwrap_err(), WireError::Malformed);
    let mut at_cap = base.to_vec();
    at_cap.extend_from_slice(&[0x98, MAX_KEY_EVENTS as u8]);
    assert_eq!(decode_self_auth(&at_cap).unwrap_err(), WireError::Truncated);
}

#[test]
fn key_log_at_the_cap_validates_and_longer_is_refused() {
    let mut q = Node::new(1, SourceName::SelfCertifying);
    for i in 0..MAX_KEY_EVENTS {
        let mut op = [0xA0u8; 32];
        op[0] = i as u8;
        let mut next = [0xB0u8; 32];
        next[0] = i as u8;
        q.identity.rotate(&op, &next);
    }
    let full = q.send(b"at-cap");
    assert_eq!(full.self_auth.rotations.len(), MAX_KEY_EVENTS);
    assert_eq!(verify_binding::<Sig>(&full).unwrap(), q.id());

    // A log one event longer (here: a duplicated last event, which never gets
    // as far as its own checks) is refused on length alone.
    let mut long = full.clone();
    let last = long.self_auth.rotations.last().unwrap().clone();
    long.self_auth.rotations.push(last);
    assert_eq!(
        verify_binding::<Sig>(&long).unwrap_err(),
        VerifyError::KeyLogTooLong
    );
}

#[test]
#[should_panic(expected = "key log full")]
fn rotating_past_the_cap_panics() {
    let mut q = Node::new(1, SourceName::SelfCertifying);
    for i in 0..=MAX_KEY_EVENTS {
        let mut op = [0xA0u8; 32];
        op[0] = i as u8;
        let mut next = [0xB0u8; 32];
        next[0] = i as u8;
        q.identity.rotate(&op, &next);
    }
}

#[test]
fn receiver_keeps_length_and_newest_event_only() {
    let mut q = Node::new(1, SourceName::SelfCertifying);
    let mut rx = receiver_for("mars-a", &[0u8; 32]);
    q.identity.rotate(&[142u8; 32], &[42u8; 32]);
    let one = q.send(b"one"); // genuinely sent at log length 1
    q.identity.rotate(&[143u8; 32], &[43u8; 32]);
    rx.accept::<Sig>(&q.send(b"two")).unwrap();
    assert_eq!(rx.watermark(&q.id()), Some(2));

    // Same log again: accepted. The earlier, shorter log: stale.
    rx.accept::<Sig>(&q.send(b"again")).unwrap();
    assert_eq!(
        rx.accept::<Sig>(&one).unwrap_err(),
        VerifyError::StaleKeyLog
    );
}
