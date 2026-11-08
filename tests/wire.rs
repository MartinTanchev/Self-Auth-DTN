#![cfg(feature = "mock")]

//! Wire round-trips plus randomized decoder tests: arbitrary bytes and
//! mutated valid frames must never panic the CBOR decoder.

mod common;
use common::*;

use self_auth_dtn::prelude::*;

/// Encode a bundle's self-auth block, decode it, and rebuild the bundle around
/// the decoded block.
fn roundtrip(bundle: &Bundle) -> Bundle {
    let encoded = encode_self_auth(&bundle.self_auth, SUITE_MOCK);
    let (suite, decoded) = decode_self_auth(&encoded).expect("decode");
    assert_eq!(suite, SUITE_MOCK);
    Bundle {
        source_id: bundle.source_id,
        name: bundle.name.clone(),
        self_auth: decoded,
        payload: bundle.payload.clone(),
        bib: bundle.bib.clone(),
    }
}

#[test]
fn roundtrip_preserves_binding_zero_rotations() {
    let q = Node::new(1, SourceName::SelfCertifying);
    let bundle = q.send(b"payload");
    let rebuilt = roundtrip(&bundle);
    assert_eq!(verify_binding::<Sig>(&rebuilt).unwrap(), q.id());
}

#[test]
fn roundtrip_preserves_binding_after_rotations() {
    let mut q = Node::new(1, SourceName::SelfCertifying);
    q.identity.rotate(&[142u8; 32], &[42u8; 32]);
    q.identity.rotate(&[143u8; 32], &[43u8; 32]);
    let bundle = q.send(b"payload");

    let rebuilt = roundtrip(&bundle);
    // The wire form omits the current key; the decoder must reconstruct the
    // rotated one correctly for the BIB to verify.
    assert_eq!(
        rebuilt.self_auth.current_public_key,
        bundle.self_auth.current_public_key
    );
    assert_eq!(verify_binding::<Sig>(&rebuilt).unwrap(), q.id());
}

#[test]
fn truncated_input_is_rejected() {
    let q = Node::new(1, SourceName::SelfCertifying);
    let encoded = encode_self_auth(&q.send(b"x").self_auth, SUITE_MOCK);
    for cut in [1usize, encoded.len() / 2, encoded.len() - 1] {
        assert!(decode_self_auth(&encoded[..cut]).is_err());
    }
}

#[test]
fn trailing_garbage_is_rejected() {
    let q = Node::new(1, SourceName::SelfCertifying);
    let mut encoded = encode_self_auth(&q.send(b"x").self_auth, SUITE_MOCK);
    encoded.push(0xff);
    assert_eq!(decode_self_auth(&encoded), Err(WireError::Malformed));
}

#[test]
fn unsupported_version_is_rejected() {
    let q = Node::new(1, SourceName::SelfCertifying);
    let mut encoded = encode_self_auth(&q.send(b"x").self_auth, SUITE_MOCK);
    // The outer array head is one byte; the version uint follows it. Version 2
    // encodes as the single byte 0x02. Both the pre-0.9 version 1 (whose
    // events let the revealed key sign bundles) and an unknown version 3 are
    // refused.
    assert_eq!(encoded[1], 0x02);
    for v in [0x01, 0x03] {
        encoded[1] = v;
        assert_eq!(
            decode_self_auth(&encoded),
            Err(WireError::UnsupportedVersion)
        );
    }
}

#[test]
fn tampered_wire_bytes_do_not_yield_a_verifiable_chain() {
    // Flipping a byte inside the encoded material must never produce a bundle
    // a correct receiver accepts. Three rejection routes exist: the CBOR
    // structure breaks (decode error), the algorithm-suite label no longer
    // matches what the receiver supports (a receiver MUST validate the suite
    // and select its verification algorithm by it, so a relabel fails closed),
    // or the chain fails verification.
    let mut q = Node::new(1, SourceName::SelfCertifying);
    q.identity.rotate(&[142u8; 32], &[42u8; 32]);
    let bundle = q.send(b"payload");
    let encoded = encode_self_auth(&bundle.self_auth, SUITE_MOCK);

    let step = (encoded.len() / 23).max(1);
    let mut pos = 1; // include the version byte; its corruption must also fail
    while pos < encoded.len() {
        let mut evil = encoded.clone();
        evil[pos] ^= 0x01;
        if let Ok((suite, block)) = decode_self_auth(&evil) {
            // The receiver's suite check: this harness supports SUITE_MOCK
            // only. Anything else is a rejection, exactly as a real processor
            // rejects (or fails verification under) an unsupported suite.
            if suite != SUITE_MOCK {
                pos += step;
                continue;
            }
            let rebuilt = Bundle {
                source_id: bundle.source_id,
                name: bundle.name.clone(),
                self_auth: block,
                payload: bundle.payload.clone(),
                bib: bundle.bib.clone(),
            };
            assert!(
                verify_binding::<Sig>(&rebuilt).is_err(),
                "tampered byte at {} produced a verifiable bundle",
                pos
            );
        }
        pos += step;
    }
}

#[test]
fn bcb_roundtrips_and_still_decrypts() {
    let mut authority = Authority::<Sig>::new("mars-a", &[9u8; 32]);
    let sender_node = Node::new(1, SourceName::SelfCertifying);
    let dest = Node::new(2, SourceName::SelfCertifying);

    let mut sender_trust = TrustStore::new("mars-a", authority.root_public_key());
    sender_trust
        .apply::<Sig>(&authority.announce_member(&dest.id(), None, &dest.kem_public))
        .unwrap();

    let sealed = sender_node
        .sender()
        .send_confidential::<Kem>(&sender_trust, &dest.id(), b"secret", &[7u8; 32], [1u8; 12])
        .unwrap();

    // Round-trip the BCB through its wire form and rebuild the bundle.
    let rebuilt = match &sealed.payload {
        Payload::Confidential(bcb) => {
            let dec = decode_bcb(&encode_bcb(bcb)).expect("bcb decode");
            Bundle {
                source_id: sealed.source_id,
                name: sealed.name.clone(),
                self_auth: sealed.self_auth.clone(),
                payload: Payload::Confidential(dec),
                bib: sealed.bib.clone(),
            }
        }
        Payload::Plain(_) => unreachable!(),
    };

    // Integrity still checks, and the destination still decrypts.
    assert_eq!(verify_binding::<Sig>(&rebuilt).unwrap(), sender_node.id());
    let mut dest_rx = receiver_with_kem("mars-a", authority.root_public_key(), dest.kem_secret);
    dest_rx.accept::<Sig>(&rebuilt).unwrap();
    assert_eq!(dest_rx.history(&sender_node.id())[0], b"secret");
}

// A small deterministic PRNG (SplitMix64), so these randomized tests are
// reproducible and need no dependency.
struct Prng(u64);
impl Prng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E3779B97F4A7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D049BB133111EB);
        z ^ (z >> 31)
    }
    fn byte(&mut self) -> u8 {
        self.next() as u8
    }
}

#[test]
fn decoder_never_panics_on_arbitrary_bytes() {
    // The decoder faces hostile input on the wire; it must reject, never panic.
    let mut rng = Prng(0xC0FFEE);
    for _ in 0..20_000 {
        let len = (rng.next() % 64) as usize;
        let buf: Vec<u8> = (0..len).map(|_| rng.byte()).collect();
        // Both entry points, both must return a Result without unwinding.
        let _ = decode_self_auth(&buf);
        let _ = decode_bcb(&buf);
    }
}

#[test]
fn decoder_never_panics_on_mutated_valid_frames() {
    // Start from valid encodings and mutate them, which reaches deeper decode
    // paths than purely random bytes: valid heads with corrupted bodies.
    let mut q = Node::new(1, SourceName::SelfCertifying);
    q.identity.rotate(&[142u8; 32], &[42u8; 32]);
    q.identity.rotate(&[143u8; 32], &[43u8; 32]);
    let valid = encode_self_auth(&q.send(b"payload").self_auth, SUITE_MOCK);

    let mut rng = Prng(0x1234_5678);
    for _ in 0..20_000 {
        let mut buf = valid.clone();
        let n_mut = 1 + (rng.next() % 4) as usize;
        for _ in 0..n_mut {
            if buf.is_empty() {
                break;
            }
            let pos = (rng.next() as usize) % buf.len();
            match rng.next() % 3 {
                0 => buf[pos] ^= rng.byte(),      // flip
                1 => buf.truncate(pos),           // shorten
                _ => buf.insert(pos, rng.byte()), // lengthen
            }
        }
        // Whatever comes back, it is a Result, and if it decodes it must not
        // then verify against the original identity (mutation broke something).
        if let Ok((_, block)) = decode_self_auth(&buf) {
            let rebuilt = Bundle {
                source_id: q.id(),
                name: SourceName::SelfCertifying,
                self_auth: block,
                payload: Payload::Plain(b"payload".to_vec()),
                bib: q.send(b"payload").bib.clone(),
            };
            // Not asserting rejection here (a mutation could, astronomically
            // rarely, produce a self-consistent different identity); the point
            // is that decode + verify complete without panicking.
            let _ = verify_binding::<Sig>(&rebuilt);
        }
    }
}

#[test]
fn random_valid_blocks_roundtrip_exactly() {
    // Differential property: encode then decode is the identity on the fields
    // the wire form carries, for randomly shaped blocks.
    let mut rng = Prng(0xABCD_1234);
    for _ in 0..500 {
        let mut node = Node::new((rng.byte() % 200) + 1, SourceName::SelfCertifying);
        let rots = (rng.next() % 4) as usize;
        for _ in 0..rots {
            // Operational seeds are never all-equal bytes, so they cannot
            // collide with the all-equal establishment seeds.
            let mut op = [rng.byte(); 32];
            op[0] = 0xFE;
            op[1] = 0xEF;
            node.identity.rotate(&op, &[rng.byte(); 32]);
        }
        let block = node.send(b"x").self_auth;
        let (suite, decoded) = decode_self_auth(&encode_self_auth(&block, SUITE_MOCK)).unwrap();
        assert_eq!(suite, SUITE_MOCK);
        assert_eq!(decoded.inception, block.inception);
        assert_eq!(decoded.inception_sig, block.inception_sig);
        assert_eq!(decoded.rotations, block.rotations);
        assert_eq!(decoded.current_public_key, block.current_public_key);
    }
}

// ---------------------------------------------------------------------------
// Payload carriage (bundles and bulletins as ADUs, for agents without BPSec)
// ---------------------------------------------------------------------------

mod carriage {
    use self_auth_dtn::prelude::*;
    use self_auth_dtn::verify::Sender;

    fn signed_bundle(confidential: bool) -> (Bundle, TrustStore) {
        let mut auth = Authority::<MockSig>::new("lab", &[1u8; 32]);
        let mut a = Identity::<MockSig>::incept(&[2u8; 32], &[3u8; 32], b"a");
        a.rotate(&[4u8; 32], &[5u8; 32]);
        let b_id = Identity::<MockSig>::incept(&[6u8; 32], &[7u8; 32], b"b").node_id();
        let (b_kem, _) = MockKem::keygen(&[8u8; 32]);
        let mut trust = TrustStore::new("lab", auth.root_public_key());
        trust
            .apply::<MockSig>(&auth.announce_member(&b_id, None, &b_kem))
            .unwrap();
        let s = Sender::new(&a, SourceName::Ipn(42));
        let bundle = if confidential {
            s.send_confidential::<MockKem>(&trust, &b_id, b"secret", &[9u8; 32], [1u8; 12])
                .unwrap()
        } else {
            s.send_plain(b"hello")
        };
        (bundle, trust)
    }

    #[test]
    fn bundle_roundtrips_and_still_verifies() {
        for confidential in [false, true] {
            let (bundle, _) = signed_bundle(confidential);
            let enc = encode_bundle(&bundle, SUITE_MOCK);
            assert_eq!(adu_kind(&enc), Some(ADU_BUNDLE));
            let (suite, dec) = decode_bundle(&enc).unwrap();
            assert_eq!(suite, SUITE_MOCK);
            assert_eq!(dec.source_id, bundle.source_id);
            assert_eq!(dec.name, bundle.name);
            assert_eq!(dec.self_auth, bundle.self_auth);
            assert_eq!(dec.bib.signature, bundle.bib.signature);
            assert_eq!(dec.protected_bytes(), bundle.protected_bytes());
            assert_eq!(verify_binding::<MockSig>(&dec).unwrap(), bundle.source_id);
            assert_eq!(encode_bundle(&dec, SUITE_MOCK), enc, "canonical");
        }
    }

    #[test]
    fn bulletins_roundtrip_and_still_verify() {
        let mut auth = Authority::<MockSig>::new("lab", &[1u8; 32]);
        let id = [7u8; 32];
        let all = [
            auth.announce_member(&id, Some(42), b"kem"),
            auth.announce_member(&id, None, b"kem"),
            auth.announce_member_epoch(&id, None, b"kem2", 86_400),
            auth.announce_peer("other", b"root"),
            auth.withdraw_peer("other"),
            auth.revoke(&id, RevocationReason::Superseded),
            auth.revoke_effective(&id, RevocationReason::KeyCompromise, 1234),
        ];
        for b in &all {
            let enc = encode_bulletin(b);
            assert_eq!(adu_kind(&enc), Some(ADU_BULLETIN));
            let dec = decode_bulletin(&enc).unwrap();
            assert_eq!(dec.issuer, b.issuer);
            assert_eq!(dec.seq, b.seq);
            assert_eq!(dec.expires_at, b.expires_at);
            assert_eq!(dec.body, b.body);
            assert!(dec.verify_signature::<MockSig>(auth.root_public_key()));
            assert_eq!(encode_bulletin(&dec), enc, "canonical");
        }
    }

    #[test]
    fn truncation_and_trailing_bytes_are_refused() {
        let (bundle, _) = signed_bundle(true);
        let enc = encode_bundle(&bundle, SUITE_MOCK);
        for cut in [1, 10, enc.len() / 2, enc.len() - 1] {
            assert!(decode_bundle(&enc[..cut]).is_err(), "cut at {cut}");
        }
        let mut long = enc.clone();
        long.push(0);
        assert_eq!(decode_bundle(&long).unwrap_err(), WireError::Malformed);

        let mut auth = Authority::<MockSig>::new("lab", &[1u8; 32]);
        let b = encode_bulletin(&auth.announce_member(&[7u8; 32], None, b"kem"));
        assert!(decode_bulletin(&b[..b.len() - 1]).is_err());
        let mut long = b.clone();
        long.push(0);
        assert_eq!(decode_bulletin(&long).unwrap_err(), WireError::Malformed);
    }

    #[test]
    fn kinds_do_not_cross() {
        let (bundle, _) = signed_bundle(false);
        let enc = encode_bundle(&bundle, SUITE_MOCK);
        assert!(decode_bulletin(&enc).is_err());
        let mut auth = Authority::<MockSig>::new("lab", &[1u8; 32]);
        let b = encode_bulletin(&auth.announce_member(&[7u8; 32], None, b"kem"));
        assert!(decode_bundle(&b).is_err());
        assert_eq!(adu_kind(b"not cbor at all"), None);
        assert_eq!(adu_kind(&[]), None);
    }

    #[test]
    fn suite_mismatch_inside_is_refused() {
        // The outer suite is not signed by itself; it must agree with the
        // suite inside the self-auth block.
        let (bundle, _) = signed_bundle(false);
        let enc = encode_bundle(&bundle, SUITE_MOCK);
        // [9-array, 1, suite...]: the suite is the third byte.
        assert_eq!(enc[2], SUITE_MOCK as u8);
        let mut forged = enc.clone();
        forged[2] = SUITE_ML_DSA_65_SHA256 as u8;
        assert_eq!(decode_bundle(&forged).unwrap_err(), WireError::Malformed);
    }
}
