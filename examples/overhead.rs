//! Byte-overhead table from the standardized FIPS-204/203 sizes against an
//! Ed25519 / X25519 baseline. Structural sizes, exact for any backend.
//!
//! Run with:  cargo run --example overhead

use self_auth_dtn::crypto::sizes::*;

struct Row {
    label: &'static str,
    pq: usize,
    classical: usize,
}

fn table(title: &str, rows: &[Row], subtotal: bool) {
    println!("\n  [{}]", title);
    let mut pq_sum = 0;
    let mut cl_sum = 0;
    for r in rows {
        let ratio = if r.classical == 0 {
            0.0
        } else {
            r.pq as f64 / r.classical as f64
        };
        println!(
            "  {:<38} {:>7} {:>10} {:>8.1}x",
            r.label, r.pq, r.classical, ratio
        );
        pq_sum += r.pq;
        cl_sum += r.classical;
    }
    if subtotal {
        println!("  {}", "-".repeat(66));
        println!(
            "  {:<38} {:>7} {:>10} {:>8.1}x",
            "subtotal",
            pq_sum,
            cl_sum,
            pq_sum as f64 / cl_sum as f64
        );
    }
}

fn main() {
    let meta = 16usize; // small opaque admin metadata
    let hash = 32usize;

    println!("self-auth over BPSec: byte overhead (bytes)\n");
    println!(
        "  {:<38} {:>7} {:>10} {:>9}",
        "component", "PQ", "classical", "ratio"
    );

    // Steady state: keys already known. The only recurring charge is the
    // per-bundle BIB signature.
    table(
        "steady state, keys already known",
        &[Row {
            label: "BIB signature (per bundle)",
            pq: ML_DSA_65_SIG,
            classical: ED25519_SIG,
        }],
        false,
    );

    // First contact: the bundle carries the identity material so a receiver can
    // verify binding with nothing in hand.
    let fc = [
        Row {
            label: "inception: first public key",
            pq: ML_DSA_65_PK,
            classical: ED25519_PK,
        },
        Row {
            label: "inception: successor commitment",
            pq: hash,
            classical: hash,
        },
        Row {
            label: "inception: metadata",
            pq: meta,
            classical: meta,
        },
        Row {
            label: "inception: self-signature",
            pq: ML_DSA_65_SIG,
            classical: ED25519_SIG,
        },
        Row {
            label: "BIB signature",
            pq: ML_DSA_65_SIG,
            classical: ED25519_SIG,
        },
    ];
    table("first contact, authenticated, zero rotations", &fc, true);
    let fc_pq: usize = fc.iter().map(|r| r.pq).sum();
    let fc_cl: usize = fc.iter().map(|r| r.classical).sum();

    // Each rotation event in the log adds the revealed establishment key, the
    // operational key it designates, the chaining hashes, and one signature by
    // the revealed key, proving possession of the pre-committed successor.
    let rot = [
        Row {
            label: "revealed establishment key",
            pq: ML_DSA_65_PK,
            classical: ED25519_PK,
        },
        Row {
            label: "operational public key",
            pq: ML_DSA_65_PK,
            classical: ED25519_PK,
        },
        Row {
            label: "next commitment",
            pq: hash,
            classical: hash,
        },
        Row {
            label: "prior event hash",
            pq: hash,
            classical: hash,
        },
        Row {
            label: "rotation signature (by revealed key)",
            pq: ML_DSA_65_SIG,
            classical: ED25519_SIG,
        },
    ];
    table("per rotation event in the carried log", &rot, true);
    let rot_pq: usize = rot.iter().map(|r| r.pq).sum();

    // Confidentiality.
    table(
        "confidentiality, per bundle",
        &[
            Row {
                label: "KEM ciphertext",
                pq: ML_KEM_1024_CT,
                classical: X25519_CT,
            },
            Row {
                label: "AEAD nonce + tag (ChaCha20-Poly1305)",
                pq: 12 + 16,
                classical: 12 + 16,
            },
        ],
        true,
    );

    println!("\nnotes");
    println!(
        "  - Steady-state recurring charge is the BIB signature: {} bytes, about {:.0}x classical.",
        ML_DSA_65_SIG,
        ML_DSA_65_SIG as f64 / ED25519_SIG as f64
    );
    println!(
        "  - First-contact authenticated overhead: {} bytes (~{:.1} KB), about {:.0}x classical.",
        fc_pq,
        fc_pq as f64 / 1024.0,
        fc_pq as f64 / fc_cl as f64
    );
    println!(
        "  - Each rotation carried in the log adds {} bytes (~{:.1} KB).",
        rot_pq,
        rot_pq as f64 / 1024.0
    );
    println!("    Truncating it (not implemented) would need a bulletin that vouches for");
    println!("    the log head, not just the key: receivers detect forks by comparing logs.");
    println!(
        "  - Sizes: FIPS-204 ML-DSA-65 (pk {}, sig {}),",
        ML_DSA_65_PK, ML_DSA_65_SIG
    );
    println!(
        "           FIPS-203 ML-KEM-1024 (pk {}, ct {}).",
        ML_KEM_1024_PK, ML_KEM_1024_CT
    );
    println!("  - The dominant recurring term is the signature, not the identity material:");
    println!("    identity material is a one-time charge per peer, the signature is per bundle.");
}
