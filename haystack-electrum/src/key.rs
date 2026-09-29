//! The decoy key: the input that makes a wallet's decoys reproducible.
//!
//! Its job is determinism, not secrecy. It is derived from the wallet's own account xpubs rather
//! than chosen by anyone, so every device that watches the wallet, and every reinstall, arrives at
//! the same key without being told it.
//!
//! The input is each xpub's 78-byte BIP32 encoding, not a descriptor string, since a string can be
//! printed more than one way for the same wallet (hardened steps as `84'` or `84h`) and a different
//! key changes every decoy at once.

use bdk_core::bitcoin::bip32::Xpub;
use bdk_core::bitcoin::hashes::{sha256, Hash, HashEngine};

const KEY_TAG: &[u8] = b"haystack/decoy-key/v1";

#[derive(Clone, PartialEq, Eq)]
pub struct DecoyKey([u8; 32]);

impl DecoyKey {
    /// Tagged SHA-256 over the wallet's xpubs, sorted and deduplicated so that neither the order
    /// they are listed in nor a keychain pair sharing one account xpub changes the key. `None` for
    /// an empty list: a key derived from nothing would be shared by every such wallet.
    pub fn from_xpubs(xpubs: impl IntoIterator<Item = Xpub>) -> Option<Self> {
        let mut encoded: Vec<[u8; 78]> = xpubs.into_iter().map(|x| x.encode()).collect();
        if encoded.is_empty() {
            return None;
        }
        encoded.sort_unstable();
        encoded.dedup();
        Some(Self(tagged_hash(KEY_TAG, &encoded)))
    }

    /// Short identifier stored in the ledger, so a changed key is refused instead of silently
    /// replacing every decoy.
    pub fn fingerprint(&self) -> [u8; 8] {
        let digest = sha256::Hash::hash(&self.0).to_byte_array();
        digest[..8].try_into().expect("8 of 32 bytes")
    }

    pub(crate) fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    #[cfg(test)]
    pub(crate) fn for_tests(seed: &[u8]) -> Self {
        Self(sha256::Hash::hash(seed).to_byte_array())
    }
}

impl std::fmt::Debug for DecoyKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "DecoyKey({:02x?})", self.fingerprint())
    }
}

/// BIP340-style tagged hash: `sha256(sha256(tag) ‖ sha256(tag) ‖ message)`.
fn tagged_hash(tag: &[u8], parts: &[[u8; 78]]) -> [u8; 32] {
    let tag = sha256::Hash::hash(tag);
    let mut engine = sha256::Hash::engine();
    engine.input(tag.as_ref());
    engine.input(tag.as_ref());
    for part in parts {
        engine.input(part);
    }
    sha256::Hash::from_engine(engine).to_byte_array()
}

#[cfg(test)]
mod tests {
    use super::*;
    use bdk_core::bitcoin::bip32::{DerivationPath, Xpriv};
    use bdk_core::bitcoin::secp256k1::Secp256k1;
    use bdk_core::bitcoin::Network;
    use std::str::FromStr;

    fn account_xpub(seed: &[u8]) -> Xpub {
        let secp = Secp256k1::new();
        let master = Xpriv::new_master(Network::Bitcoin, seed).unwrap();
        let path = DerivationPath::from_str("m/84'/0'/0'").unwrap();
        Xpub::from_priv(&secp, &master.derive_priv(&secp, &path).unwrap())
    }

    #[test]
    fn same_xpubs_give_the_same_key() {
        let a = DecoyKey::from_xpubs([account_xpub(b"seed-one-0000000")]).unwrap();
        let b = DecoyKey::from_xpubs([account_xpub(b"seed-one-0000000")]).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn order_and_duplicates_do_not_matter() {
        let (x, y) = (
            account_xpub(b"seed-one-0000000"),
            account_xpub(b"seed-two-0000000"),
        );
        let a = DecoyKey::from_xpubs([x, y]).unwrap();
        let b = DecoyKey::from_xpubs([y, x, y]).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn different_wallets_get_different_keys() {
        let a = DecoyKey::from_xpubs([account_xpub(b"seed-one-0000000")]).unwrap();
        let b = DecoyKey::from_xpubs([account_xpub(b"seed-two-0000000")]).unwrap();
        assert_ne!(a, b);
        assert_ne!(a.fingerprint(), b.fingerprint());
    }

    #[test]
    fn no_xpubs_no_key() {
        assert!(DecoyKey::from_xpubs([]).is_none());
    }
}
