//! Decoy scripts.
//!
//! Decoy `j` of a position is a script of the same type as the real script at that position, with
//! its hash or key filled from `HMAC-SHA256(key, keychain ‖ index ‖ j)`. The server only ever sees
//! `sha256(script)`, so on the wire a decoy is a 32-byte scripthash like any other, and giving it a
//! real script keeps reals and decoys on one code path with the wallet's own script type.
//!
//! A decoy covers only a position that has never been paid: a script nobody holds a key for can
//! never acquire history.

use bdk_core::bitcoin::hashes::{sha256, Hash, HashEngine, Hmac, HmacEngine};
use bdk_core::bitcoin::key::TweakedPublicKey;
use bdk_core::bitcoin::secp256k1::XOnlyPublicKey;
use bdk_core::bitcoin::{PubkeyHash, Script, ScriptBuf, ScriptHash, WPubkeyHash, WScriptHash};

use crate::key::DecoyKey;
use crate::keychain::Keychain;

/// Decoy `j` for the position `(keychain, index)` whose real script is `real`. `None` if `real`
/// isn't one of the five standard output types, since there is no shape to match.
pub fn decoy_script(
    key: &DecoyKey,
    real: &Script,
    keychain: Keychain,
    index: u32,
    j: u32,
) -> Option<ScriptBuf> {
    let h = payload(key, keychain, index, j);
    let h20: [u8; 20] = h[..20].try_into().expect("20 of 32 bytes");
    if real.is_p2wpkh() {
        Some(ScriptBuf::new_p2wpkh(&WPubkeyHash::from_byte_array(h20)))
    } else if real.is_p2wsh() {
        Some(ScriptBuf::new_p2wsh(&WScriptHash::from_byte_array(h)))
    } else if real.is_p2tr() {
        Some(ScriptBuf::new_p2tr_tweaked(
            TweakedPublicKey::dangerous_assume_tweaked(x_only_key(h)),
        ))
    } else if real.is_p2pkh() {
        Some(ScriptBuf::new_p2pkh(&PubkeyHash::from_byte_array(h20)))
    } else if real.is_p2sh() {
        Some(ScriptBuf::new_p2sh(&ScriptHash::from_byte_array(h20)))
    } else {
        None
    }
}

/// All `count` decoys for one position, in `j` order.
pub fn decoys_for(
    key: &DecoyKey,
    real: &Script,
    keychain: Keychain,
    index: u32,
    count: u32,
) -> Option<Vec<ScriptBuf>> {
    (0..count)
        .map(|j| decoy_script(key, real, keychain, index, j))
        .collect()
}

fn payload(key: &DecoyKey, keychain: Keychain, index: u32, j: u32) -> [u8; 32] {
    let mut engine = HmacEngine::<sha256::Hash>::new(key.as_bytes());
    engine.input(keychain.as_bytes());
    engine.input(&index.to_be_bytes());
    engine.input(&j.to_be_bytes());
    Hmac::<sha256::Hash>::from_engine(engine).to_byte_array()
}

/// About half of all 32-byte strings are valid x-only keys. Rehash until one is, so a taproot
/// decoy is a well-formed output key, and stays deterministic.
fn x_only_key(mut h: [u8; 32]) -> XOnlyPublicKey {
    loop {
        if let Ok(k) = XOnlyPublicKey::from_slice(&h) {
            return k;
        }
        h = sha256::Hash::hash(&h).to_byte_array();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> DecoyKey {
        DecoyKey::for_tests(b"test-wallet")
    }

    fn real_p2wpkh() -> ScriptBuf {
        ScriptBuf::new_p2wpkh(&WPubkeyHash::from_byte_array([7; 20]))
    }

    fn templates() -> Vec<ScriptBuf> {
        vec![
            real_p2wpkh(),
            ScriptBuf::new_p2wsh(&WScriptHash::from_byte_array([7; 32])),
            ScriptBuf::new_p2tr_tweaked(TweakedPublicKey::dangerous_assume_tweaked(x_only_key(
                [7; 32],
            ))),
            ScriptBuf::new_p2pkh(&PubkeyHash::from_byte_array([7; 20])),
            ScriptBuf::new_p2sh(&ScriptHash::from_byte_array([7; 20])),
        ]
    }

    fn same_type(a: &Script, b: &Script) -> bool {
        (a.is_p2wpkh() && b.is_p2wpkh())
            || (a.is_p2wsh() && b.is_p2wsh())
            || (a.is_p2tr() && b.is_p2tr())
            || (a.is_p2pkh() && b.is_p2pkh())
            || (a.is_p2sh() && b.is_p2sh())
    }

    #[test]
    fn deterministic() {
        let r = real_p2wpkh();
        assert_eq!(
            decoy_script(&key(), &r, Keychain::External, 3, 0),
            decoy_script(&key(), &r, Keychain::External, 3, 0)
        );
    }

    #[test]
    fn matches_the_real_script_type() {
        for real in templates() {
            let d = decoy_script(&key(), &real, Keychain::External, 3, 0).unwrap();
            assert!(same_type(&real, &d), "{real:?} -> {d:?}");
            assert_ne!(real, d);
        }
    }

    #[test]
    fn distinct_across_every_input() {
        let r = real_p2wpkh();
        let base = decoy_script(&key(), &r, Keychain::External, 3, 0);
        for other in [
            decoy_script(&key(), &r, Keychain::External, 4, 0),
            decoy_script(&key(), &r, Keychain::External, 3, 1),
            decoy_script(&key(), &r, Keychain::Internal, 3, 0),
            decoy_script(&DecoyKey::for_tests(b"other"), &r, Keychain::External, 3, 0),
        ] {
            assert_ne!(base, other);
        }
    }

    #[test]
    fn does_not_depend_on_the_real_scripts_payload() {
        // Only the type of the real script is read, never its hash: a decoy must not leak
        // anything about the address it covers.
        let a = ScriptBuf::new_p2wpkh(&WPubkeyHash::from_byte_array([1; 20]));
        let b = ScriptBuf::new_p2wpkh(&WPubkeyHash::from_byte_array([2; 20]));
        assert_eq!(
            decoy_script(&key(), &a, Keychain::External, 3, 0),
            decoy_script(&key(), &b, Keychain::External, 3, 0)
        );
    }

    #[test]
    fn unknown_script_type_has_no_decoy() {
        let op_return = ScriptBuf::new_op_return([1, 2, 3]);
        assert!(decoy_script(&key(), &op_return, Keychain::External, 0, 0).is_none());
        assert!(decoys_for(&key(), &op_return, Keychain::External, 0, 9).is_none());
    }

    #[test]
    fn decoys_for_matches_individual_calls() {
        let r = real_p2wpkh();
        let all = decoys_for(&key(), &r, Keychain::External, 7, 9).unwrap();
        assert_eq!(all.len(), 9);
        for (j, d) in all.iter().enumerate() {
            assert_eq!(
                Some(d.clone()),
                decoy_script(&key(), &r, Keychain::External, 7, j as u32)
            );
        }
    }
}
