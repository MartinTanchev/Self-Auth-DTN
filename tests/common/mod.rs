//! Shared test helpers, all on the mock backends.

#![allow(dead_code)]

use self_auth_dtn::prelude::*;
use self_auth_dtn::verify::Sender;

pub type Sig = MockSig;
pub type Kem = MockKem;

/// A node: its self-auth identity plus its KEM keypair.
pub struct Node {
    pub identity: Identity<Sig>,
    pub kem_public: Vec<u8>,
    pub kem_secret: <Kem as KemScheme>::DecapKey,
    pub name: SourceName,
}

impl Node {
    pub fn new(seed: u8, name: SourceName) -> Self {
        let identity = Identity::<Sig>::incept(&[seed; 32], &[seed.wrapping_add(100); 32], b"");
        let (kem_public, kem_secret) = Kem::keygen(&[seed.wrapping_add(200); 32]);
        Node {
            identity,
            kem_public,
            kem_secret,
            name,
        }
    }

    pub fn id(&self) -> NodeId {
        self.identity.node_id()
    }

    pub fn sender(&self) -> Sender<'_, Sig> {
        Sender::new(&self.identity, self.name.clone())
    }

    pub fn send(&self, payload: &[u8]) -> Bundle {
        self.sender().send_plain(payload)
    }
}

/// Build a receiver whose only a priori trust is its own collective's root key.
pub fn receiver_for(collective: &str, root_key: &[u8]) -> Receiver<Kem> {
    let trust = TrustStore::new(collective, root_key);
    // The receiver's own decapsulation key.
    let (_ek, dk) = Kem::keygen(&[250u8; 32]);
    Receiver::new(trust, dk)
}

/// A receiver that owns a specific KEM keypair (so bundles can be encrypted to
/// it).
pub fn receiver_with_kem(
    collective: &str,
    root_key: &[u8],
    decap_key: <Kem as KemScheme>::DecapKey,
) -> Receiver<Kem> {
    Receiver::new(TrustStore::new(collective, root_key), decap_key)
}
