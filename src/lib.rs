//! Self-authenticating node identifiers for the DTN Bundle Protocol.
//!
//! A node's identifier is `H(inception_record)`, with KERI-style pre-committed
//! key rotation, so identifier-to-key binding verifies offline from the bundle
//! alone. DTKA bulletins still handle authorization (membership, peering,
//! revocation) whenever they arrive; accumulated traffic from a bound sender
//! is authorized retroactively.
//!
//! Mock signature/KEM backends by default (insecure, test-only). Build with
//! `--features pq` for FIPS-204 ML-DSA-65 and FIPS-203 ML-KEM-1024. The AEAD
//! is RustCrypto's audited `chacha20poly1305` on every build.

// Unsafe is denied crate-wide. The sole exception is the volatile-write in
// `mac::wipe`, allowed locally at its definition.
#![deny(unsafe_code)]
// `no_std` + `alloc` unless the `std` feature is on (it is by default).
#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

/// The `alloc` items every module uses, so the same source builds with and
/// without `std`.
#[allow(unused_imports)]
mod alloc_prelude {
    pub use alloc::borrow::ToOwned;
    pub use alloc::boxed::Box;
    pub use alloc::format;
    pub use alloc::string::{String, ToString};
    pub use alloc::vec;
    pub use alloc::vec::Vec;
}

pub mod aead;
pub mod bulletin;
pub mod codec;
pub mod crypto;
pub mod identity;
pub mod kem;
pub mod keylog;
pub mod mac;
pub mod naming;
#[cfg(feature = "pq")]
pub mod rng;
pub mod sha256;
pub mod trust;
#[cfg(feature = "ud3tn")]
pub mod ud3tn;
pub mod verify;
pub mod wire;

/// Common imports.
pub mod prelude {
    pub use crate::bulletin::{Authority, Bulletin, BulletinBody, RevocationReason};
    #[cfg(feature = "mock")]
    pub use crate::crypto::MockSig;
    pub use crate::crypto::SignatureScheme;
    pub use crate::identity::{node_id_hex, InceptionRecord, NodeId};
    pub use crate::kem::KemScheme;
    #[cfg(feature = "mock")]
    pub use crate::kem::MockKem;
    pub use crate::keylog::{
        validate_material, verify_duplicity, Identity, KeyEvent, SelfAuthMaterial, VerifyError,
    };
    pub use crate::naming::SourceName;
    pub use crate::trust::{Applied, MemberRecord, TrustError, TrustStore};
    pub use crate::verify::{
        verify_binding, Bcb, Bib, Bundle, DuplicityEvidence, Payload, ReceivedPayload, Receiver,
        SelfAuthBlock, SendError, Sender, Verdict,
    };
    pub use crate::wire::{
        adu_kind, decode_bcb, decode_bulletin, decode_bundle, decode_self_auth, encode_bcb,
        encode_bulletin, encode_bundle, encode_self_auth, WireError, ADU_BULLETIN, ADU_BUNDLE,
        SUITE_ML_DSA_65_SHA256, SUITE_MOCK, WIRE_VERSION,
    };

    #[cfg(feature = "pq")]
    pub use crate::crypto::MlDsa65;
    #[cfg(feature = "pq")]
    pub use crate::kem::MlKem1024;
}
