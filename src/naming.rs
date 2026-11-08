//! Source naming: mode 1 uses the identifier itself as the node number,
//! mode 2 keeps an ordinary ipn number and carries the identifier in an
//! extension block. Mode 2's ipn-to-identifier link is an authorization
//! claim, checked against membership bulletins in `trust`.

#[allow(unused_imports)]
use crate::alloc_prelude::*;
use crate::identity::NodeId;

/// How a bundle's source is named on the wire.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SourceName {
    /// Mode 1: the node number is the self-certifying identifier itself.
    SelfCertifying,
    /// Mode 2: an ordinary ipn node number, with the identifier carried
    /// alongside in an extension block.
    Ipn(u64),
}

impl SourceName {
    /// The ipn number, if this is mode 2.
    pub fn ipn(&self) -> Option<u64> {
        match self {
            SourceName::SelfCertifying => None,
            SourceName::Ipn(n) => Some(*n),
        }
    }

    /// Whether the name is cryptographically self-certifying on its own.
    pub fn is_self_certifying(&self) -> bool {
        matches!(self, SourceName::SelfCertifying)
    }

    /// Human-readable form, for logs.
    pub fn display(&self, id: &NodeId) -> String {
        match self {
            SourceName::SelfCertifying => {
                let hex: String = id.iter().take(8).map(|b| format!("{:02x}", b)).collect();
                format!("ipn:{}...(self-certifying)", hex)
            }
            SourceName::Ipn(n) => format!("ipn:{}", n),
        }
    }
}
