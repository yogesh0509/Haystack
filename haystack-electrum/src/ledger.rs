//! The decoy ledger: how many decoys were frozen for each position, the first time it was ever
//! queried, and never changed afterward. It also doubles as the confirmed pool for round planning:
//! whatever this ledger already knows needs no further network round trip to include in the next
//! round.
//!
//! It also holds every chain-sourced decoy's script. An HMAC-direct decoy is rebuilt from the key,
//! but a chain decoy was picked from the chain at one moment and can't be: asking again could pick
//! a different address, which the server would read as a withdrawal.
//!
//! This module is pure in-memory logic; wiring it to durable storage is a separate step.

use std::collections::BTreeMap;

use bdk_core::bitcoin::ScriptBuf;

use crate::key::DecoyKey;
use crate::keychain::Keychain;

pub type Position = (Keychain, u32);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LedgerEntry {
    pub decoy_count: u32,
    /// Decoy number `j` to its chain-sourced script; every other `j` is HMAC-direct.
    pub chain: BTreeMap<u32, ScriptBuf>,
}

/// The frozen decoy counts only mean anything together with the key that generated the decoys,
/// so the ledger records which key that was.
#[derive(Debug)]
pub struct Ledger {
    key_fingerprint: [u8; 8],
    entries: BTreeMap<Position, LedgerEntry>,
}

/// The ledger was built with a different decoy key. Using it would replace every frozen decoy at
/// once, which the intersection attack reads as all of them being withdrawn.
#[derive(Debug, PartialEq, Eq)]
pub struct KeyMismatch {
    pub ledger: [u8; 8],
    pub offered: [u8; 8],
}

/// An already-frozen position was asked for a different decoy count than it originally got — a
/// withdrawal, which the append-only design treats as a bug. `freeze` itself can't produce this
/// (it silently keeps the original count); this is for a caller that wants to notice the mismatch.
#[derive(Debug, PartialEq, Eq)]
pub struct WithdrawalRejected {
    pub position: Position,
    pub existing_count: u32,
    pub attempted_count: u32,
}

#[derive(Debug, PartialEq, Eq)]
pub struct NonContiguous {
    pub keychain: Keychain,
    pub missing: u32,
}

impl Ledger {
    pub fn new(key: &DecoyKey) -> Self {
        Self {
            key_fingerprint: key.fingerprint(),
            entries: BTreeMap::new(),
        }
    }

    pub fn key_fingerprint(&self) -> [u8; 8] {
        self.key_fingerprint
    }

    #[cfg(test)]
    pub(crate) fn for_tests() -> Self {
        Self::new(&DecoyKey::for_tests(b"test-wallet"))
    }

    pub fn check_key(&self, key: &DecoyKey) -> Result<(), KeyMismatch> {
        let offered = key.fingerprint();
        if offered == self.key_fingerprint {
            Ok(())
        } else {
            Err(KeyMismatch {
                ledger: self.key_fingerprint,
                offered,
            })
        }
    }

    /// Freeze `decoy_count` decoys for `position` if it has never been queried before, and return
    /// the frozen count either way. A position already in the ledger keeps whatever it was first
    /// assigned, even if `decoy_count` (the wallet's *current* padding dial) now asks for something
    /// else — moving the dial only ever affects positions frozen after the change.
    pub fn freeze(&mut self, position: Position, decoy_count: u32) -> u32 {
        self.entries
            .entry(position)
            .or_insert(LedgerEntry {
                decoy_count,
                chain: BTreeMap::new(),
            })
            .decoy_count
    }

    /// Record that decoy `j` of a frozen position is the chain-sourced `script`. Only for a decoy
    /// that hasn't been sent yet: `false`, and no change, if the position isn't frozen, `j` is out of
    /// range, or `j` already has a script.
    pub fn set_chain_decoy(&mut self, position: Position, j: u32, script: ScriptBuf) -> bool {
        match self.entries.get_mut(&position) {
            Some(e) if j < e.decoy_count && !e.chain.contains_key(&j) => {
                e.chain.insert(j, script);
                true
            }
            _ => false,
        }
    }

    /// The chain-sourced decoys of a position, by `j`. Empty for an unfrozen position.
    pub fn chain_decoys(&self, position: Position) -> BTreeMap<u32, ScriptBuf> {
        self.entries
            .get(&position)
            .map(|e| e.chain.clone())
            .unwrap_or_default()
    }

    /// Every chain-sourced decoy script in the ledger, across all positions.
    pub fn all_chain_decoys(&self) -> impl Iterator<Item = (Position, u32, &ScriptBuf)> + '_ {
        self.entries
            .iter()
            .flat_map(|(&pos, e)| e.chain.iter().map(move |(&j, s)| (pos, j, s)))
    }

    /// The confirmed pool: every position this ledger already knows about, with its frozen decoy
    /// count.
    pub fn confirmed(&self) -> impl Iterator<Item = (Position, u32)> + '_ {
        self.entries.iter().map(|(&pos, e)| (pos, e.decoy_count))
    }

    pub fn get(&self, position: Position) -> Option<u32> {
        self.entries.get(&position).map(|e| e.decoy_count)
    }

    /// How many positions of `keychain` are frozen. They must be exactly `0..n`: positions are
    /// only ever frozen in ascending order, so a gap means the ledger was corrupted or edited.
    pub fn confirmed_len(&self, keychain: Keychain) -> Result<u32, NonContiguous> {
        let mut n = 0u32;
        for &(k, index) in self.entries.keys() {
            if k != keychain {
                continue;
            }
            if index != n {
                return Err(NonContiguous {
                    keychain,
                    missing: n,
                });
            }
            n += 1;
        }
        Ok(n)
    }

    pub fn check_no_withdrawal(
        &self,
        position: Position,
        proposed_count: u32,
    ) -> Result<(), WithdrawalRejected> {
        if let Some(existing) = self.entries.get(&position) {
            if existing.decoy_count != proposed_count {
                return Err(WithdrawalRejected {
                    position,
                    existing_count: existing.decoy_count,
                    attempted_count: proposed_count,
                });
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn freeze_is_idempotent() {
        let mut ledger = Ledger::for_tests();
        let pos = (Keychain::External, 0);
        assert_eq!(ledger.freeze(pos, 9), 9);
        // A later call with a different count (e.g. the dial moved) must not change it.
        assert_eq!(ledger.freeze(pos, 20), 9);
        assert_eq!(ledger.get(pos), Some(9));
    }

    #[test]
    fn distinct_positions_are_independent() {
        let mut ledger = Ledger::for_tests();
        ledger.freeze((Keychain::External, 0), 9);
        ledger.freeze((Keychain::Internal, 0), 4);
        assert_eq!(ledger.get((Keychain::External, 0)), Some(9));
        assert_eq!(ledger.get((Keychain::Internal, 0)), Some(4));
    }

    #[test]
    fn unknown_position_is_not_confirmed() {
        let ledger = Ledger::for_tests();
        assert_eq!(ledger.get((Keychain::External, 0)), None);
        assert_eq!(ledger.confirmed().count(), 0);
    }

    #[test]
    fn confirmed_lists_every_frozen_position() {
        let mut ledger = Ledger::for_tests();
        ledger.freeze((Keychain::External, 0), 9);
        ledger.freeze((Keychain::External, 1), 9);
        ledger.freeze((Keychain::Internal, 0), 9);
        let mut confirmed: Vec<_> = ledger.confirmed().collect();
        confirmed.sort();
        assert_eq!(
            confirmed,
            vec![
                ((Keychain::External, 0), 9),
                ((Keychain::External, 1), 9),
                ((Keychain::Internal, 0), 9),
            ]
        );
    }

    #[test]
    fn withdrawal_is_rejected_when_checked() {
        let mut ledger = Ledger::for_tests();
        let pos = (Keychain::External, 0);
        ledger.freeze(pos, 9);
        let err = ledger.check_no_withdrawal(pos, 5).unwrap_err();
        assert_eq!(
            err,
            WithdrawalRejected {
                position: pos,
                existing_count: 9,
                attempted_count: 5,
            }
        );
    }

    #[test]
    fn matching_count_passes_the_check() {
        let mut ledger = Ledger::for_tests();
        let pos = (Keychain::External, 0);
        ledger.freeze(pos, 9);
        assert!(ledger.check_no_withdrawal(pos, 9).is_ok());
    }

    #[test]
    fn confirmed_len_counts_a_contiguous_prefix() {
        let mut ledger = Ledger::for_tests();
        for i in 0..5 {
            ledger.freeze((Keychain::External, i), 9);
        }
        ledger.freeze((Keychain::Internal, 0), 9);
        assert_eq!(ledger.confirmed_len(Keychain::External), Ok(5));
        assert_eq!(ledger.confirmed_len(Keychain::Internal), Ok(1));
    }

    #[test]
    fn confirmed_len_rejects_a_gap() {
        let mut ledger = Ledger::for_tests();
        ledger.freeze((Keychain::External, 0), 9);
        ledger.freeze((Keychain::External, 2), 9);
        assert_eq!(
            ledger.confirmed_len(Keychain::External),
            Err(NonContiguous {
                keychain: Keychain::External,
                missing: 1,
            })
        );
    }

    #[test]
    fn accepts_the_key_it_was_built_with() {
        let key = DecoyKey::for_tests(b"wallet");
        assert!(Ledger::new(&key).check_key(&key).is_ok());
    }

    #[test]
    fn refuses_a_different_key() {
        let ledger = Ledger::new(&DecoyKey::for_tests(b"wallet"));
        let other = DecoyKey::for_tests(b"reinstalled with a typo");
        assert_eq!(
            ledger.check_key(&other),
            Err(KeyMismatch {
                ledger: DecoyKey::for_tests(b"wallet").fingerprint(),
                offered: other.fingerprint(),
            })
        );
    }

    #[test]
    fn a_chain_decoy_is_kept_once_and_only_inside_the_frozen_count() {
        let mut ledger = Ledger::for_tests();
        let pos = (Keychain::External, 0);
        let a = ScriptBuf::from_bytes(vec![0x00, 0x14, 1]);
        assert!(!ledger.set_chain_decoy(pos, 0, a.clone()), "not frozen yet");
        ledger.freeze(pos, 2);
        assert!(ledger.set_chain_decoy(pos, 1, a.clone()));
        assert!(!ledger.set_chain_decoy(pos, 1, ScriptBuf::new()), "already set");
        assert!(!ledger.set_chain_decoy(pos, 2, a.clone()), "past the count");
        assert_eq!(ledger.chain_decoys(pos), BTreeMap::from([(1, a)]));
        assert_eq!(ledger.all_chain_decoys().count(), 1);
    }

    #[test]
    fn a_new_position_always_passes_the_check() {
        let ledger = Ledger::for_tests();
        assert!(ledger
            .check_no_withdrawal((Keychain::External, 0), 9)
            .is_ok());
    }
}
