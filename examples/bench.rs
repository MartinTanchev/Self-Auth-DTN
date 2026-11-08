//! Timing for the real pq backends. Indicative numbers only.
//!
//! Run with:  cargo run --release --example bench --features pq

#[cfg(feature = "pq")]
fn main() {
    use self_auth_dtn::crypto::{MlDsa65, SignatureScheme};
    use self_auth_dtn::kem::{KemScheme, MlKem1024};
    use std::time::Instant;

    let iters: u32 = 200;
    let seed = [0u8; 32];
    let message = b"self-auth-dtn benchmark message";

    println!("averaged over {} iterations\n", iters);

    // --- ML-DSA-65 (signatures) ---
    let t = Instant::now();
    let mut kp = MlDsa65::keygen(&seed);
    for _ in 1..iters {
        kp = MlDsa65::keygen(&seed);
    }
    let sig_keygen = t.elapsed() / iters;
    let (pk, sk) = kp;

    let t = Instant::now();
    let mut sig = MlDsa65::sign(&sk, message);
    for _ in 1..iters {
        sig = MlDsa65::sign(&sk, message);
    }
    let sign = t.elapsed() / iters;

    let t = Instant::now();
    let mut ok = true;
    for _ in 0..iters {
        ok &= MlDsa65::verify(&pk, message, &sig);
    }
    let verify = t.elapsed() / iters;

    println!("ML-DSA-65 (FIPS 204)");
    println!("  public key : {} bytes", pk.len());
    println!("  signature  : {} bytes", sig.len());
    println!("  keygen     : {:?}", sig_keygen);
    println!("  sign       : {:?}", sign);
    println!("  verify     : {:?}  (all verified: {})", verify, ok);

    // --- ML-KEM-1024 (encapsulation) ---
    let t = Instant::now();
    let mut kem_kp = MlKem1024::keygen(&seed);
    for _ in 1..iters {
        kem_kp = MlKem1024::keygen(&seed);
    }
    let kem_keygen = t.elapsed() / iters;
    let (ek, dk) = kem_kp;

    let t = Instant::now();
    let mut enc = MlKem1024::encapsulate(&ek, &seed).expect("encapsulate");
    for _ in 1..iters {
        enc = MlKem1024::encapsulate(&ek, &seed).expect("encapsulate");
    }
    let encaps = t.elapsed() / iters;
    let (ct, ss_sender) = enc;

    let t = Instant::now();
    let mut agree = true;
    for _ in 0..iters {
        let ss = MlKem1024::decapsulate(&dk, &ct).expect("decapsulate");
        agree &= ss == ss_sender;
    }
    let decaps = t.elapsed() / iters;

    println!("\nML-KEM-1024 (FIPS 203)");
    println!("  encaps key : {} bytes", ek.len());
    println!("  ciphertext : {} bytes", ct.len());
    println!("  keygen     : {:?}", kem_keygen);
    println!("  encapsulate: {:?}", encaps);
    println!("  decapsulate: {:?}  (secrets agree: {})", decaps, agree);

    println!("\nper-bundle recurring cost = 1 sign (source) + 1 verify (each hop that checks)");
    println!("                          + 1 encapsulate (source) + 1 decapsulate (destination)");
}

#[cfg(not(feature = "pq"))]
fn main() {
    println!("This benchmark needs the real backends.");
    println!("Run: cargo run --release --example bench --features pq");
}
