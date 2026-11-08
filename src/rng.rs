//! Deterministic RNG bridging the crate's 32-byte-seed keygen API to the
//! FIPS crates' `CryptoRngCore`, backed by `rand_chacha`'s `ChaCha20Rng`
//! (compiled under `pq` only). Seed hygiene is the caller's job.

use rand_chacha::ChaCha20Rng;
use rand_core::{CryptoRng, Error, RngCore, SeedableRng};

/// Deterministic generator: same seed, same keys, on every backend.
pub struct SeededRng(ChaCha20Rng);

impl SeededRng {
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        SeededRng(ChaCha20Rng::from_seed(*seed))
    }
}

impl RngCore for SeededRng {
    fn next_u32(&mut self) -> u32 {
        self.0.next_u32()
    }

    fn next_u64(&mut self) -> u64 {
        self.0.next_u64()
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.0.fill_bytes(dest)
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Error> {
        self.0.try_fill_bytes(dest)
    }
}

impl CryptoRng for SeededRng {}
