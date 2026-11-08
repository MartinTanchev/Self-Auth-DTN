//! End-to-end walkthrough on the mock backends.
//!
//! Run with:  cargo run --example demo

use self_auth_dtn::prelude::*;
use self_auth_dtn::verify::{SendError, Sender};

type Sig = MockSig;
type Kem = MockKem;

fn short(id: &NodeId) -> String {
    node_id_hex(id).chars().take(12).collect()
}

fn rule(title: &str) {
    println!("\n{}\n{}", title, "-".repeat(title.len()));
}

fn main() {
    println!("self-auth-dtn");
    println!("binding offline; authorization when the bulletin arrives");
    println!("(mock crypto backends: control flow only, not secure)");

    // Two independently run collectives.
    let mut agency_a = Authority::<Sig>::new("agency-a", &[10u8; 32]);
    let mut agency_b = Authority::<Sig>::new("agency-b", &[20u8; 32]);

    // Rover B belongs to agency-b.
    let mut rover_b = Identity::<Sig>::incept(&[2u8; 32], &[102u8; 32], b"rover-b");
    let (b_kem_pub, _b_kem_sec) = Kem::keygen(&[202u8; 32]);
    let b_id = rover_b.node_id();

    // Rover A belongs to agency-a. It is fielded knowing exactly one thing:
    // its own collective's root key.
    let (_a_kem_pub, a_kem_sec) = Kem::keygen(&[201u8; 32]);
    let mut rover_a = Receiver::<Kem>::new(
        TrustStore::new("agency-a", agency_a.root_public_key()),
        a_kem_sec,
    );

    rule("1. Inception");
    println!("Rover B's identifier is the hash of its inception record,");
    println!("not its live key:  {}...", short(&b_id));
    println!("Rover A is fielded trusting only agency-a's root key.");

    rule("2. First contact, with no bulletin in hand");
    let v = rover_a
        .accept::<Sig>(&Sender::new(&rover_b, SourceName::SelfCertifying).send_plain(b"survey-1"))
        .unwrap();
    println!("binding verified : {}", v.binding_verified);
    println!("authorization    : {:?}", v.authorization);
    println!();
    println!("This is the window. Rover A cannot yet say B is legitimate,");
    println!("but it can already prove every bundle came from the same,");
    println!("unforgeable sender, with no lookup and no handshake.");

    rule("3. An imposter tries to claim B's identifier");
    let attacker = Identity::<Sig>::incept(&[99u8; 32], &[199u8; 32], b"attacker");
    let mut spoof = Sender::new(&attacker, SourceName::SelfCertifying).send_plain(b"fake-command");
    spoof.source_id = b_id; // stamp B's name on it
    match rover_a.accept::<Sig>(&spoof) {
        Err(e) => println!("rejected: {:?}   (no bulletin needed to catch this)", e),
        Ok(_) => println!("ERROR: imposter accepted"),
    }

    rule("4. History accumulates under the proven identifier");
    rover_a
        .accept::<Sig>(&Sender::new(&rover_b, SourceName::SelfCertifying).send_plain(b"survey-2"))
        .unwrap();
    rover_a
        .accept::<Sig>(&Sender::new(&rover_b, SourceName::SelfCertifying).send_plain(b"survey-3"))
        .unwrap();
    println!(
        "accumulated from B: {} bundles, all still unauthorized",
        rover_a.accumulated(&b_id)
    );

    // An adversary captures B's current key and key log at this moment. This
    // bundle stands in for anything the thief can sign with that material.
    let stolen_material_bundle =
        Sender::new(&rover_b, SourceName::SelfCertifying).send_plain(b"thief-was-here");

    rule("5. B rotates its key. The identifier does not move.");
    rover_b.rotate(&[142u8; 32], &[42u8; 32]);
    println!(
        "after rotation, identifier: {}...  (unchanged)",
        short(&rover_b.node_id())
    );
    let v = rover_a
        .accept::<Sig>(&Sender::new(&rover_b, SourceName::SelfCertifying).send_plain(b"survey-4"))
        .unwrap();
    println!(
        "bundle signed by the rotated key still verifies: {}",
        v.binding_verified
    );
    println!();
    println!("A thief of B's operational key could not have done this: rotation");
    println!("requires the pre-committed successor, generated offline, and every");
    println!("past rotation was signed by a key B has since destroyed, so the");
    println!("thief cannot fork B's key log either.");
    println!();
    println!("And having witnessed the rotation, this receiver now refuses the");
    println!("thief's stale, pre-rotation key log:");
    match rover_a.accept::<Sig>(&stolen_material_bundle) {
        Err(e) => println!("replay of pre-rotation material: rejected, {:?}", e),
        Ok(_) => println!("ERROR: stale key log accepted"),
    }
    println!("The thief can act only until the legitimate rotation propagates.");

    rule("6. The agencies peer, after deployment");
    let b_membership = agency_b.announce_member(&b_id, None, &b_kem_pub);
    match rover_a.apply_bulletin::<Sig>(&b_membership) {
        Err(e) => println!("B's membership bulletin, before peering: {:?}", e),
        Ok(_) => println!("ERROR: accepted a bulletin from an unknown issuer"),
    }

    let peering = agency_a.announce_peer("agency-b", agency_b.root_public_key());
    println!(
        "applying peering bulletin from our own collective: {:?}",
        rover_a.apply_bulletin::<Sig>(&peering).unwrap()
    );
    println!(
        "applying B's membership bulletin again: {:?}",
        rover_a.apply_bulletin::<Sig>(&b_membership).unwrap()
    );

    rule("7. Retroactive authorization");
    let record = rover_a
        .authorization(&b_id, &SourceName::SelfCertifying)
        .unwrap();
    println!("B is now authorized, vouched by: {}", record.collective);
    println!(
        "bundles authorized retroactively: {}",
        rover_a.accumulated(&b_id)
    );
    println!();
    println!("Nothing was discarded while we waited. The identifier in the");
    println!("bulletin is the same cryptographic object we were checking all");
    println!("along, so the accumulated history becomes usable at once.");

    rule("8. Trust does not chain");
    let agency_c = Authority::<Sig>::new("agency-c", &[30u8; 32]);
    let b_vouches_c = agency_b.announce_peer("agency-c", agency_c.root_public_key());
    match rover_a.apply_bulletin::<Sig>(&b_vouches_c) {
        Err(e) => println!("agency-b tries to extend our trust to agency-c: {:?}", e),
        Ok(_) => println!("ERROR: trust chained transitively"),
    }
    println!("Peering is pairwise and deliberate. Only our own collective");
    println!("can extend our trust.");

    rule("9. Confidentiality is NOT self-contained");
    let dest = Identity::<Sig>::incept(&[7u8; 32], &[107u8; 32], b"dest");
    let (dest_kem_pub, _dest_kem_sec) = Kem::keygen(&[207u8; 32]);
    let dest_id = dest.node_id();

    let mut sender_trust = TrustStore::new("agency-a", agency_a.root_public_key());
    let attempt = Sender::new(&rover_b, SourceName::SelfCertifying).send_confidential::<Kem>(
        &sender_trust,
        &dest_id,
        b"classified",
        &[7u8; 32],
        [1u8; 12],
    );
    match attempt {
        Err(SendError::NoDestinationKey) => {
            println!("cannot encrypt to a node whose KEM key we do not hold.")
        }
        _ => println!("ERROR: encrypted without the destination key"),
    }
    println!();
    println!("This is the honest limit of the design. The source's signing key");
    println!("rides in the bundle, so AUTHENTICATION bootstraps itself.");
    println!("The destination's key cannot ride in the bundle we are encrypting,");
    println!("so CONFIDENTIALITY still waits on DTKA. That asymmetry is real.");

    sender_trust
        .apply::<Sig>(&agency_a.announce_member(&dest_id, None, &dest_kem_pub))
        .unwrap();
    let sealed = Sender::new(&rover_b, SourceName::SelfCertifying)
        .send_confidential::<Kem>(
            &sender_trust,
            &dest_id,
            b"classified",
            &[7u8; 32],
            [1u8; 12],
        )
        .expect("destination key now known");
    println!();
    println!("after the destination's bulletin arrives: sealed bundle emitted.");
    println!("each bundle carries its own one-time key, encapsulated under the");
    println!("destination's public key. no shared session state.");
    println!(
        "an intermediate router, holding no keys, can still verify its integrity: {}",
        verify_binding::<Sig>(&sealed).is_ok()
    );

    rule("10. Revocation, in an ordinary bulletin");
    let revocation = agency_b.revoke(&b_id, RevocationReason::KeyCompromise);
    println!(
        "applying agency-b's revocation of B: {:?}",
        rover_a.apply_bulletin::<Sig>(&revocation).unwrap()
    );

    let v = rover_a
        .accept::<Sig>(&Sender::new(&rover_b, SourceName::SelfCertifying).send_plain(b"post-hack"))
        .unwrap();
    println!("binding still verifies : {}", v.binding_verified);
    println!("authorization          : {:?}", v.authorization);
    println!();
    println!("Key theft is bounded in time, not eliminated. The thief can act");
    println!("only until the revocation propagates, and cannot take the identity");
    println!("with the operational key: rotation needs the pre-committed successor,");
    println!("and receivers keep the key log they saw first.");
    println!("No expiry schedules, no short-lived certificates. Just a bulletin.");

    println!("\ndone. the value showed up in steps 2 to 5, before any bulletin arrived.");
}
