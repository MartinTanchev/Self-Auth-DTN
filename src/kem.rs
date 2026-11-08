//! Key encapsulation for per-bundle payload keying. Each bundle carries its
//! own one-time key encapsulated under the destination's public key, so
//! there is no session state. Note the asymmetry: authentication is
//! self-contained, but encrypting *to* a node requires its KEM key from a
//! bulletin first.

#[allow(unused_imports)]
use crate::alloc_prelude::*;
#[cfg(feature = "mock")]
use crate::sha256::sha256;

/// A key-encapsulation mechanism.
pub trait KemScheme {
    /// Opaque decapsulation (private) key.
    type DecapKey;

    /// True for insecure mock backends. Deployment code can assert
    /// `!K::IS_MOCK` at startup so a test backend cannot ship by accident.
    const IS_MOCK: bool = false;

    /// Generate an (encapsulation key, decapsulation key) pair,
    /// deterministically from `seed`. Seed hygiene is the caller's job.
    fn keygen(seed: &[u8; 32]) -> (Vec<u8>, Self::DecapKey);

    /// Encapsulate a fresh shared secret under `encap_key`, with entropy
    /// drawn deterministically from `seed`. Returns `(ciphertext,
    /// shared_secret)`.
    fn encapsulate(encap_key: &[u8], seed: &[u8; 32]) -> Option<(Vec<u8>, [u8; 32])>;

    /// Recover the shared secret from `ciphertext`.
    fn decapsulate(decap_key: &Self::DecapKey, ciphertext: &[u8]) -> Option<[u8; 32]>;

    /// Best-effort secret destruction. Backends whose key types already wipe on
    /// drop can leave the default no-op.
    fn destroy(_secret: &mut Self::DecapKey) {}
}

/// INSECURE mock KEM. For control flow and tests only.
#[cfg(feature = "mock")]
pub struct MockKem;

#[cfg(feature = "mock")]
impl KemScheme for MockKem {
    type DecapKey = [u8; 32];

    const IS_MOCK: bool = true;

    fn keygen(seed: &[u8; 32]) -> (Vec<u8>, Self::DecapKey) {
        (seed.to_vec(), *seed)
    }

    fn encapsulate(encap_key: &[u8], seed: &[u8; 32]) -> Option<(Vec<u8>, [u8; 32])> {
        // The "ciphertext" is just the ephemeral seed.
        let ct = seed.to_vec();
        let mut buf = Vec::with_capacity(encap_key.len() + ct.len());
        buf.extend_from_slice(encap_key);
        buf.extend_from_slice(&ct);
        Some((ct, sha256(&buf)))
    }

    fn decapsulate(decap_key: &Self::DecapKey, ciphertext: &[u8]) -> Option<[u8; 32]> {
        let mut buf = Vec::with_capacity(decap_key.len() + ciphertext.len());
        buf.extend_from_slice(decap_key);
        buf.extend_from_slice(ciphertext);
        Some(sha256(&buf))
    }

    fn destroy(secret: &mut Self::DecapKey) {
        crate::mac::wipe(secret);
    }
}

// ---------------------------------------------------------------------------
// Real post-quantum backend: FIPS-203 ML-KEM-1024 via the `fips203` crate.
// Parameter set per CNSA 2.0, which approves only ML-KEM-1024.
//
// Compiled only under `--features pq`. If your installed fips203 version uses
// different type or constant names, this is the single place to adjust.
// ---------------------------------------------------------------------------
#[cfg(feature = "pq")]
pub struct MlKem1024;

#[cfg(feature = "pq")]
impl KemScheme for MlKem1024 {
    type DecapKey = fips203::ml_kem_1024::DecapsKey;

    fn keygen(seed: &[u8; 32]) -> (Vec<u8>, Self::DecapKey) {
        use fips203::traits::{KeyGen, SerDes};
        let mut rng = crate::rng::SeededRng::from_seed(seed);
        let (ek, dk) =
            fips203::ml_kem_1024::KG::try_keygen_with_rng(&mut rng).expect("ml-kem keygen failed");
        (ek.into_bytes().to_vec(), dk)
    }

    fn encapsulate(encap_key: &[u8], seed: &[u8; 32]) -> Option<(Vec<u8>, [u8; 32])> {
        use fips203::traits::{Encaps, SerDes};

        let ek_bytes: [u8; fips203::ml_kem_1024::EK_LEN] = encap_key.try_into().ok()?;
        let ek = fips203::ml_kem_1024::EncapsKey::try_from_bytes(ek_bytes).ok()?;
        let mut rng = crate::rng::SeededRng::from_seed(seed);
        let (ssk, ct) = ek.try_encaps_with_rng(&mut rng).ok()?;
        Some((ct.into_bytes().to_vec(), ssk.into_bytes()))
    }

    fn decapsulate(decap_key: &Self::DecapKey, ciphertext: &[u8]) -> Option<[u8; 32]> {
        use fips203::traits::{Decaps, SerDes};

        let ct_bytes: [u8; fips203::ml_kem_1024::CT_LEN] = ciphertext.try_into().ok()?;
        let ct = fips203::ml_kem_1024::CipherText::try_from_bytes(ct_bytes).ok()?;
        let ssk = decap_key.try_decaps(&ct).ok()?;
        Some(ssk.into_bytes())
    }
}

#[cfg(all(test, feature = "mock"))]
mod tests {
    use super::*;

    #[test]
    fn mock_kem_roundtrip() {
        let (ek, dk) = MockKem::keygen(&[1u8; 32]);
        let (ct, ss_sender) = MockKem::encapsulate(&ek, &[2u8; 32]).unwrap();
        let ss_receiver = MockKem::decapsulate(&dk, &ct).unwrap();
        assert_eq!(ss_sender, ss_receiver);
    }
}
