//! Secret wiping.
//!
//! (HMAC-SHA256 and a constant-time comparison used to live here; nothing has
//! used them since the AEAD moved to RustCrypto's ChaCha20-Poly1305, so they
//! were removed in 0.9.)
//!
//! The ML-DSA and ML-KEM key types from the `fips204` / `fips203` crates
//! zeroize themselves on drop, which is what `SignatureScheme::destroy` and
//! `KemScheme::destroy` rely on for those backends. `wipe` covers the byte
//! buffers this crate owns: one-time AEAD keys and mock-backend secrets.

/// Best-effort secret erasure: overwrite with volatile writes so the compiler
/// cannot elide the zeroing as a dead store, then fence.
#[allow(unsafe_code)] // the one audited exception to the crate-wide deny
pub fn wipe(buf: &mut [u8]) {
    for b in buf.iter_mut() {
        // SAFETY: `b` is a valid, exclusive reference into `buf`.
        unsafe { core::ptr::write_volatile(b, 0) };
    }
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wipe_zeroes() {
        let mut secret = [0xAAu8; 32];
        wipe(&mut secret);
        assert_eq!(secret, [0u8; 32]);
    }
}
