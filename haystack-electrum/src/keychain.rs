//! Keychains, and how a request's keychain type maps onto them.
//!
//! The decoy HMAC needs a stable byte label per keychain, and a request's own keychain type (for a
//! `bdk_wallet` app, `KeychainKind`) doesn't have one. `DecoyKeychain` maps it onto `Keychain`, whose
//! labels are fixed and explicit rather than inferred from listing order.
//!
//! Only the two keychains of a standard receive/change descriptor pair are modelled.

/// One derivation branch of a descriptor wallet.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Keychain {
    External,
    Internal,
}

impl Keychain {
    /// Stable byte encoding used as part of the decoy HMAC's input (keychain ‖ index ‖ j).
    /// `"external"` and `"internal"` are fixed, prefix-free labels, so no separator is needed.
    pub fn as_bytes(self) -> &'static [u8] {
        match self {
            Keychain::External => b"external",
            Keychain::Internal => b"internal",
        }
    }
}

/// A request keychain type that Haystack can pad.
pub trait DecoyKeychain: Ord + Clone {
    fn keychain(&self) -> Keychain;
}

impl DecoyKeychain for Keychain {
    fn keychain(&self) -> Keychain {
        *self
    }
}

#[cfg(feature = "bdk_wallet")]
impl DecoyKeychain for bdk_wallet::KeychainKind {
    fn keychain(&self) -> Keychain {
        match self {
            bdk_wallet::KeychainKind::External => Keychain::External,
            bdk_wallet::KeychainKind::Internal => Keychain::Internal,
        }
    }
}
