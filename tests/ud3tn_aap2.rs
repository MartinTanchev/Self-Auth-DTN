//! The AAP 2.0 client against an in-process stand-in for uD3TN.
//!
//! The stand-in speaks the framing of the AAP 2.0 specification with this
//! crate's own field table, so these tests check the client's state machine
//! and the payload carriage end to end, not agreement with uD3TN's
//! `aap2.proto`. That is `integrations/ud3tn/gen_fields.py --check` plus
//! `integrations/ud3tn/run-local.sh` against a real uD3TN.

#![cfg(all(feature = "ud3tn", feature = "mock", unix))]

use self_auth_dtn::prelude::*;
use self_auth_dtn::ud3tn::fields::*;
use self_auth_dtn::ud3tn::{
    decode_response, encode_response, read_delimited, write_delimited, Aap2Client, Aap2Error,
    AduMeta, Message, AAP2_MAGIC, MAX_MESSAGE,
};
use self_auth_dtn::verify::Sender;
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::sync::mpsc;
use std::thread;

const NODE: &str = "dtn://b.dtn/";

/// One agent-side connection: greet, take the config, then either accept
/// ADUs (sender) into `tx` or deliver ADUs from `rx` (subscriber).
fn agent_conn(
    mut s: UnixStream,
    tx: mpsc::Sender<(AduMeta, Vec<u8>)>,
    rx: Option<mpsc::Receiver<(AduMeta, Vec<u8>)>>,
) {
    s.write_all(&[AAP2_MAGIC]).unwrap();
    let welcome = Message::Welcome {
        node_id: NODE.into(),
    };
    write_delimited(&mut s, &welcome.encode()).unwrap();

    let cfg = match Message::decode(&read_delimited(&mut s).unwrap()).unwrap() {
        Message::Config(c) => c,
        other => panic!("expected config, got {other:?}"),
    };
    assert!(cfg.endpoint_id.starts_with(NODE));
    write_delimited(&mut s, &encode_response(RESPONSE_STATUS_SUCCESS)).unwrap();

    if cfg.is_subscriber {
        let rx = rx.expect("subscriber needs a queue");
        // One keepalive first: the client must answer it and keep waiting.
        write_delimited(&mut s, &Message::Keepalive.encode()).unwrap();
        assert_eq!(
            decode_response(&read_delimited(&mut s).unwrap()).unwrap(),
            RESPONSE_STATUS_ACK
        );
        for (mut meta, payload) in rx {
            meta.payload_length = payload.len() as u64;
            write_delimited(&mut s, &Message::Adu(meta).encode()).unwrap();
            s.write_all(&payload).unwrap();
            assert_eq!(
                decode_response(&read_delimited(&mut s).unwrap()).unwrap(),
                RESPONSE_STATUS_SUCCESS
            );
        }
    } else {
        while let Ok(raw) = read_delimited(&mut s) {
            let mut meta = match Message::decode(&raw).unwrap() {
                Message::Adu(m) => m,
                other => panic!("expected adu, got {other:?}"),
            };
            let mut payload = vec![0u8; meta.payload_length as usize];
            s.read_exact(&mut payload).unwrap();
            meta.src_eid = "dtn://a.dtn/sad".into();
            write_delimited(&mut s, &encode_response(RESPONSE_STATUS_SUCCESS)).unwrap();
            tx.send((meta, payload)).unwrap();
        }
    }
}

/// A sending and a receiving client wired through one stand-in agent.
fn pair() -> (Aap2Client<UnixStream>, Aap2Client<UnixStream>) {
    let (q_tx, q_rx) = mpsc::channel();
    let (a_send, b_send) = UnixStream::pair().unwrap();
    let (a_recv, b_recv) = UnixStream::pair().unwrap();
    let tx2 = q_tx.clone();
    thread::spawn(move || agent_conn(b_send, q_tx, None));
    thread::spawn(move || agent_conn(b_recv, tx2, Some(q_rx)));

    let mut sender = Aap2Client::handshake(a_send).unwrap();
    let mut receiver = Aap2Client::handshake(a_recv).unwrap();
    assert_eq!(sender.node_id(), NODE);
    let eid = sender.endpoint_for("sad");
    assert_eq!(eid, "dtn://b.dtn/sad");
    sender.configure(&eid, false, "s3cret").unwrap();
    receiver.configure(&eid, true, "s3cret").unwrap();
    (sender, receiver)
}

#[test]
fn payload_bytes_survive_the_round_trip() {
    let (mut tx, mut rx) = pair();
    let payload: Vec<u8> = (0..70_000u32).map(|i| (i * 7) as u8).collect();
    tx.send("dtn://b.dtn/sad", &payload).unwrap();
    let (meta, got) = rx.receive().unwrap();
    assert_eq!(got, payload);
    assert_eq!(meta.dst_eid, "dtn://b.dtn/sad");
    assert_eq!(meta.src_eid, "dtn://a.dtn/sad");
}

#[test]
fn window_promotion_and_confidentiality_through_aap2() {
    let (mut tx, mut rx) = pair();
    let mut authority = Authority::<MockSig>::new("lab", &[1u8; 32]);
    let a = Identity::<MockSig>::incept(&[2u8; 32], &[3u8; 32], b"a");
    let (a_kem, _) = MockKem::keygen(&[4u8; 32]);
    let (b_kem, b_decap) = MockKem::keygen(&[5u8; 32]);
    let b_id = Identity::<MockSig>::incept(&[6u8; 32], &[7u8; 32], b"b").node_id();

    // Sender side: learns b's KEM key from b's membership bulletin.
    let b_member = authority.announce_member(&b_id, None, &b_kem);
    let mut a_trust = TrustStore::new("lab", authority.root_public_key());
    a_trust.apply::<MockSig>(&b_member).unwrap();

    let sender = Sender::new(&a, SourceName::SelfCertifying);
    let plain = sender.send_plain(b"before the bulletin");
    let secret = sender
        .send_confidential::<MockKem>(&a_trust, &b_id, b"for b only", &[8u8; 32], [9u8; 12])
        .unwrap();
    let a_member = authority.announce_member(&a.node_id(), None, &a_kem);

    // Bundles first, bulletin last: the window, then promotion.
    tx.send("dtn://b.dtn/sad", &encode_bundle(&plain, SUITE_MOCK))
        .unwrap();
    tx.send("dtn://b.dtn/sad", &encode_bundle(&secret, SUITE_MOCK))
        .unwrap();
    tx.send("dtn://b.dtn/sad", &encode_bulletin(&a_member))
        .unwrap();

    let mut b =
        Receiver::<MockKem>::new(TrustStore::new("lab", authority.root_public_key()), b_decap);

    let (_, p) = rx.receive().unwrap();
    assert_eq!(adu_kind(&p), Some(ADU_BUNDLE));
    let (suite, bundle) = decode_bundle(&p).unwrap();
    assert_eq!(suite, SUITE_MOCK);
    let v = b.accept_at::<MockSig>(&bundle, 100).unwrap();
    assert_eq!(v.node_id, a.node_id());
    assert!(!v.is_authorized(), "no bulletin yet: held");
    assert_eq!(
        v.payload,
        ReceivedPayload::Plain(b"before the bulletin".to_vec())
    );

    let (_, p) = rx.receive().unwrap();
    let (_, bundle) = decode_bundle(&p).unwrap();
    let v = b.accept_at::<MockSig>(&bundle, 101).unwrap();
    assert_eq!(
        v.payload,
        ReceivedPayload::Decrypted(b"for b only".to_vec())
    );
    assert_eq!(v.accumulated, 2);

    let (_, p) = rx.receive().unwrap();
    assert_eq!(adu_kind(&p), Some(ADU_BULLETIN));
    let bulletin = decode_bulletin(&p).unwrap();
    b.apply_bulletin_at::<MockSig>(&bulletin, 102).unwrap();
    assert_eq!(b.promotable_history(&a.node_id()).len(), 2);
}

#[test]
fn tampered_carriage_is_refused_after_transport() {
    let (mut tx, mut rx) = pair();
    let a = Identity::<MockSig>::incept(&[2u8; 32], &[3u8; 32], b"a");
    let bundle = Sender::new(&a, SourceName::SelfCertifying).send_plain(b"original");
    let mut adu = encode_bundle(&bundle, SUITE_MOCK);
    // Flip a byte of the plaintext payload ("original" is near the end,
    // just before the BIB signature).
    let pos = adu
        .windows(8)
        .position(|w| w == b"original")
        .expect("payload in ADU");
    adu[pos] ^= 1;
    tx.send("dtn://b.dtn/sad", &adu).unwrap();
    let (_, p) = rx.receive().unwrap();
    let (_, bundle) = decode_bundle(&p).unwrap();
    let mut b = Receiver::<MockKem>::new(
        TrustStore::new(
            "lab",
            Authority::<MockSig>::new("lab", &[1u8; 32]).root_public_key(),
        ),
        MockKem::keygen(&[5u8; 32]).1,
    );
    assert!(b.accept_at::<MockSig>(&bundle, 1).is_err());
}

#[test]
fn wrong_magic_is_refused() {
    let (client, mut agent) = UnixStream::pair().unwrap();
    agent.write_all(&[0x00]).unwrap();
    assert!(matches!(
        Aap2Client::handshake(client),
        Err(Aap2Error::Protocol(_))
    ));
}

#[test]
fn oversized_message_is_refused_before_allocation() {
    let (mut client, mut agent) = UnixStream::pair().unwrap();
    // Length prefix far above the cap, and no body at all: the reader must
    // refuse on the prefix, not try to allocate or read it.
    let mut prefix = Vec::new();
    self_auth_dtn::ud3tn::pb::put_varint(&mut prefix, MAX_MESSAGE + 1);
    agent.write_all(&prefix).unwrap();
    assert!(matches!(
        read_delimited(&mut client),
        Err(Aap2Error::Protocol(_))
    ));
}

#[test]
fn ipn_endpoint_ids() {
    let (client, mut agent) = UnixStream::pair().unwrap();
    agent.write_all(&[AAP2_MAGIC]).unwrap();
    write_delimited(
        &mut agent,
        &Message::Welcome {
            node_id: "ipn:7.0".into(),
        }
        .encode(),
    )
    .unwrap();
    let c = Aap2Client::handshake(client).unwrap();
    assert_eq!(c.endpoint_for("42"), "ipn:7.42");
}
