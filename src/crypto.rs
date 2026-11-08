//! `SignatureScheme` trait and backends: `MockSig` (insecure, test-only,
//! default) and `MlDsa65` (FIPS-204, behind `pq`). Swapping in another
//! backend replaces one impl block.

#[allow(unused_imports)]
use crate::alloc_prelude::*;
#[cfg(feature = "mock")]
use crate::sha256::sha256;

/// A post-quantum-ready signature scheme.
pub trait SignatureScheme {
    /// Opaque secret-key handle for this backend.
    type SecretKey;

    /// True for insecure mock backends. Deployment code can assert
    /// `!S::IS_MOCK` at startup so a test backend cannot ship by accident.
    const IS_MOCK: bool = false;

    /// Derive a keypair deterministically from `seed`. Seeds must be unique and
    /// high-entropy; a live node should draw the seed from the OS RNG once.
    fn keygen(seed: &[u8; 32]) -> (Vec<u8>, Self::SecretKey);

    /// Sign `message`, returning the signature bytes.
    fn sign(secret: &Self::SecretKey, message: &[u8]) -> Vec<u8>;

    /// Verify `signature` over `message` under `public_key`.
    fn verify(public_key: &[u8], message: &[u8], signature: &[u8]) -> bool;

    /// Best-effort secret destruction. Backends whose key types already wipe on
    /// drop can leave the default no-op.
    fn destroy(_secret: &mut Self::SecretKey) {}
}

/// Standardised sizes, in bytes, used for overhead accounting. Post-quantum
/// figures are the FIPS-204 (ML-DSA) and FIPS-203 (ML-KEM) final values.
pub mod sizes {
    // FIPS-204 ML-DSA-65 (final).
    pub const ML_DSA_65_PK: usize = 1952;
    pub const ML_DSA_65_SIG: usize = 3309;

    // FIPS-203 ML-KEM-1024 (final), the parameter set CNSA 2.0 approves.
    pub const ML_KEM_1024_PK: usize = 1568;
    pub const ML_KEM_1024_CT: usize = 1568;

    // FIPS-203 ML-KEM-768 (final), kept for comparison tables.
    pub const ML_KEM_768_PK: usize = 1184;
    pub const ML_KEM_768_CT: usize = 1088;

    // Classical baseline.
    pub const ED25519_PK: usize = 32;
    pub const ED25519_SIG: usize = 64;
    pub const X25519_PK: usize = 32;
    pub const X25519_CT: usize = 32;
}

/// INSECURE mock backend. For control-flow and tests only. The "public key"
/// equals the secret seed, and a signature is `SHA-256(public_key ||
/// message)`.
#[cfg(feature = "mock")]
pub struct MockSig;

#[cfg(feature = "mock")]
impl SignatureScheme for MockSig {
    type SecretKey = [u8; 32];

    const IS_MOCK: bool = true;

    fn keygen(seed: &[u8; 32]) -> (Vec<u8>, Self::SecretKey) {
        // INSECURE by construction: public == secret.
        (seed.to_vec(), *seed)
    }

    fn sign(secret: &Self::SecretKey, message: &[u8]) -> Vec<u8> {
        let mut buf = Vec::with_capacity(secret.len() + message.len());
        buf.extend_from_slice(secret);
        buf.extend_from_slice(message);
        sha256(&buf).to_vec()
    }

    fn verify(public_key: &[u8], message: &[u8], signature: &[u8]) -> bool {
        let mut buf = Vec::with_capacity(public_key.len() + message.len());
        buf.extend_from_slice(public_key);
        buf.extend_from_slice(message);
        sha256(&buf).as_slice() == signature
    }

    fn destroy(secret: &mut Self::SecretKey) {
        crate::mac::wipe(secret);
    }
}

// ---------------------------------------------------------------------------
// Real post-quantum backend: FIPS-204 ML-DSA-65 via the `fips204` crate.
//
// Compiled only under `--features pq`. The API below tracks fips204 0.4.x; if
// your installed version differs, adjust the type and constant names. This is
// the one place that needs touching to swap in a different (or audited) ML-DSA
// implementation.
// ---------------------------------------------------------------------------
#[cfg(feature = "pq")]
pub struct MlDsa65;

#[cfg(feature = "pq")]
impl SignatureScheme for MlDsa65 {
    type SecretKey = fips204::ml_dsa_65::PrivateKey;

    fn keygen(seed: &[u8; 32]) -> (Vec<u8>, Self::SecretKey) {
        use fips204::traits::SerDes;
        // Deterministic from the caller's seed via the ChaCha20 DRBG, so the
        // seed parameter is honored rather than silently ignored. Seed hygiene
        // (uniqueness, entropy) is the caller's responsibility.
        let mut rng = crate::rng::SeededRng::from_seed(seed);
        let (pk, sk) =
            fips204::ml_dsa_65::try_keygen_with_rng(&mut rng).expect("ml-dsa keygen failed");
        (pk.into_bytes().to_vec(), sk)
    }

    fn sign(secret: &Self::SecretKey, message: &[u8]) -> Vec<u8> {
        use fips204::traits::Signer;
        // Empty context string, matching the verifier below.
        // With `std`: FIPS 204 hedged mode, rnd drawn from the OS RNG.
        // Without `std` there is no OS RNG to rely on, so sign in the FIPS 204
        // deterministic mode (rnd = 0^32), which the standard permits. Both
        // produce signatures any verifier accepts; hedged mode is preferred
        // where an RNG exists because it blunts fault and side-channel attacks.
        #[cfg(feature = "std")]
        let sig = secret.try_sign(message, &[]);
        #[cfg(not(feature = "std"))]
        let sig = secret.try_sign_with_seed(&[0u8; 32], message, &[]);
        sig.expect("ml-dsa sign failed").to_vec()
    }

    fn verify(public_key: &[u8], message: &[u8], signature: &[u8]) -> bool {
        use fips204::traits::{SerDes, Verifier};

        let pk_bytes: [u8; fips204::ml_dsa_65::PK_LEN] = match public_key.try_into() {
            Ok(a) => a,
            Err(_) => return false,
        };
        let pk = match fips204::ml_dsa_65::PublicKey::try_from_bytes(pk_bytes) {
            Ok(p) => p,
            Err(_) => return false,
        };
        let sig: [u8; fips204::ml_dsa_65::SIG_LEN] = match signature.try_into() {
            Ok(a) => a,
            Err(_) => return false,
        };
        pk.verify(message, &sig, &[])
    }
}

#[cfg(all(test, feature = "mock"))]
mod tests {
    use super::*;

    #[test]
    fn mock_roundtrip() {
        let seed = [7u8; 32];
        let (pk, sk) = MockSig::keygen(&seed);
        let sig = MockSig::sign(&sk, b"hello");
        assert!(MockSig::verify(&pk, b"hello", &sig));
        assert!(!MockSig::verify(&pk, b"hell0", &sig)); // tampered message
        assert!(!MockSig::verify(&pk, b"hello", b"not-a-sig")); // tampered sig
    }
}
