//! Round planning: which real positions to query, in how many sequential stages.
//!
//! Every sync is a full scan, so each keychain must end the round with `stop_gap` unused positions
//! in a row, as upstream's `populate_with_spks` requires. The positions queried are the ones
//! upstream's walk would reach, plus any the ledger already froze, since append-only means a frozen
//! position is queried every round even where the walk would stop before it.
//!
//! A keychain's shortfall is known before any answer arrives, and answers can only raise it: a used
//! position resets the unused run, an unused one never shortens what's needed. So the whole
//! shortfall goes out as one stage, and another stage is needed only when an answer reveals a used
//! position near the end. A never-paid wallet finishes in one stage.

use std::collections::BTreeMap;

use crate::key::DecoyKey;
use crate::keychain::Keychain;
use crate::ledger::{KeyMismatch, Ledger, NonContiguous, Position};

/// Why a round can't be planned from this ledger.
#[derive(Debug, PartialEq, Eq)]
pub enum PlanError {
    KeyMismatch(KeyMismatch),
    NonContiguous(NonContiguous),
}

#[derive(Debug)]
struct KeychainState {
    confirmed: u32,
    planned: u32,
    answers: Vec<Option<bool>>,
    exhausted: bool,
}

#[derive(Debug)]
pub struct RoundPlanner {
    stop_gap: u32,
    started: bool,
    keychains: BTreeMap<Keychain, KeychainState>,
}

impl RoundPlanner {
    /// `stop_gap` has upstream's meaning; 0 behaves as 1, as it does in `populate_with_spks`.
    /// Refuses a ledger built with a different key: every decoy it froze would change at once.
    pub fn new(
        stop_gap: usize,
        keychains: impl IntoIterator<Item = Keychain>,
        ledger: &Ledger,
        key: &DecoyKey,
    ) -> Result<Self, PlanError> {
        ledger.check_key(key).map_err(PlanError::KeyMismatch)?;
        let mut states = BTreeMap::new();
        for k in keychains {
            states.insert(
                k,
                KeychainState {
                    confirmed: ledger.confirmed_len(k).map_err(PlanError::NonContiguous)?,
                    planned: 0,
                    answers: Vec::new(),
                    exhausted: false,
                },
            );
        }
        Ok(Self {
            stop_gap: u32::try_from(stop_gap.max(1)).unwrap_or(u32::MAX),
            started: false,
            keychains: states,
        })
    }

    /// The positions for the next stage, in ascending index order per keychain. Empty once the
    /// round is complete. Every position of the previous stage must be recorded first.
    pub fn next_stage(&mut self) -> Vec<Position> {
        let mut stage = Vec::new();
        for (&keychain, st) in &mut self.keychains {
            if st.exhausted {
                continue;
            }
            let target = if !self.started {
                // The ledger's positions, extended as if none of them has new history.
                st.confirmed.max(self.stop_gap)
            } else {
                assert!(
                    st.answers.iter().all(Option::is_some),
                    "next_stage called before every position of the last stage was recorded"
                );
                let run = trailing_unused(&st.answers);
                if run >= self.stop_gap {
                    continue;
                }
                st.planned + (self.stop_gap - run)
            };
            stage.extend((st.planned..target).map(|i| (keychain, i)));
            st.answers.resize(target as usize, None);
            st.planned = target;
        }
        self.started = true;
        stage
    }

    pub fn record(&mut self, (keychain, index): Position, used: bool) {
        let st = self
            .keychains
            .get_mut(&keychain)
            .expect("recorded a keychain the planner doesn't know");
        let slot = st
            .answers
            .get_mut(index as usize)
            .expect("recorded a position that was never planned");
        *slot = Some(used);
    }

    /// The wallet's descriptor yields no position at `first_missing` or beyond: a non-wildcard
    /// descriptor stops after index 0, and a wildcard one at the BIP32 limit. Call this before
    /// recording that stage's answers, and don't send the positions past it.
    pub fn exhausted(&mut self, keychain: Keychain, first_missing: u32) {
        let st = self
            .keychains
            .get_mut(&keychain)
            .expect("exhausted a keychain the planner doesn't know");
        st.planned = st.planned.min(first_missing);
        st.answers.truncate(st.planned as usize);
        st.exhausted = true;
    }

    /// The highest used index per keychain, omitting keychains with none — the same shape as
    /// upstream's `FullScanResponse::last_active_indices`.
    pub fn last_active_indices(&self) -> BTreeMap<Keychain, u32> {
        self.keychains
            .iter()
            .filter_map(|(&k, st)| {
                st.answers
                    .iter()
                    .rposition(|a| *a == Some(true))
                    .map(|i| (k, i as u32))
            })
            .collect()
    }
}

fn trailing_unused(answers: &[Option<bool>]) -> u32 {
    answers
        .iter()
        .rev()
        .take_while(|a| **a == Some(false))
        .count() as u32
}

#[cfg(test)]
mod tests {
    use super::*;

    const BOTH: [Keychain; 2] = [Keychain::External, Keychain::Internal];

    /// Run a planner to completion against `used`, returning (positions queried per keychain,
    /// number of stages).
    fn drive(
        planner: &mut RoundPlanner,
        used: impl Fn(Position) -> bool,
    ) -> (BTreeMap<Keychain, u32>, usize) {
        let mut queried = BTreeMap::new();
        let mut stages = 0;
        loop {
            let stage = planner.next_stage();
            if stage.is_empty() {
                return (queried, stages);
            }
            stages += 1;
            for pos in stage {
                *queried.entry(pos.0).or_insert(0) += 1;
                planner.record(pos, used(pos));
            }
        }
    }

    /// The key `Ledger::for_tests` was built with.
    fn test_key() -> DecoyKey {
        DecoyKey::for_tests(b"test-wallet")
    }

    fn ledger_with(n: u32) -> Ledger {
        let mut ledger = Ledger::for_tests();
        for k in BOTH {
            for i in 0..n {
                ledger.freeze((k, i), 9);
            }
        }
        ledger
    }

    #[test]
    fn refuses_to_plan_with_a_different_key() {
        let other = DecoyKey::for_tests(b"reinstalled with a typo");
        let err = RoundPlanner::new(50, BOTH, &ledger_with(50), &other).unwrap_err();
        assert!(matches!(err, PlanError::KeyMismatch(_)));
    }

    #[test]
    fn fresh_never_paid_wallet_is_one_stage() {
        let mut p = RoundPlanner::new(50, BOTH, &Ledger::for_tests(), &test_key()).unwrap();
        let (queried, stages) = drive(&mut p, |_| false);
        assert_eq!(stages, 1);
        assert_eq!(queried[&Keychain::External], 50);
        assert_eq!(queried[&Keychain::Internal], 50);
        assert!(p.last_active_indices().is_empty());
    }

    #[test]
    fn second_sync_requeries_the_ledger_in_one_stage() {
        let mut p = RoundPlanner::new(50, BOTH, &ledger_with(50), &test_key()).unwrap();
        let (queried, stages) = drive(&mut p, |_| false);
        assert_eq!(stages, 1);
        assert_eq!(queried[&Keychain::External], 50);
    }

    #[test]
    fn payment_to_index_3_extends_to_53() {
        // docs/02-design.md, diagram 2's third sync.
        let mut p = RoundPlanner::new(50, BOTH, &ledger_with(50), &test_key()).unwrap();
        assert_eq!(p.next_stage().len(), 100);
        for k in BOTH {
            for i in 0..50 {
                p.record((k, i), k == Keychain::External && i == 3);
            }
        }
        let second: Vec<Position> = p.next_stage();
        assert_eq!(
            second,
            (50..54)
                .map(|i| (Keychain::External, i))
                .collect::<Vec<_>>()
        );
        for pos in second {
            p.record(pos, false);
        }
        assert!(p.next_stage().is_empty());
        assert_eq!(p.last_active_indices()[&Keychain::External], 3);
    }

    #[test]
    fn used_position_at_the_edge_asks_for_a_full_gap_more() {
        let mut p =
            RoundPlanner::new(50, [Keychain::External], &Ledger::for_tests(), &test_key()).unwrap();
        let (queried, stages) = drive(&mut p, |(_, i)| i == 49);
        assert_eq!(stages, 2);
        assert_eq!(queried[&Keychain::External], 100);
    }

    #[test]
    fn frozen_positions_past_the_gap_are_still_queried() {
        // Append-only: 80 frozen positions stay in the query even though the gap ends at 50.
        let mut p =
            RoundPlanner::new(50, [Keychain::External], &ledger_with(80), &test_key()).unwrap();
        let (queried, stages) = drive(&mut p, |_| false);
        assert_eq!(stages, 1);
        assert_eq!(queried[&Keychain::External], 80);
    }

    #[test]
    fn stop_gap_zero_behaves_as_one() {
        let mut p =
            RoundPlanner::new(0, [Keychain::External], &Ledger::for_tests(), &test_key()).unwrap();
        let (queried, _) = drive(&mut p, |_| false);
        assert_eq!(queried[&Keychain::External], 1);
    }

    #[test]
    fn non_wildcard_descriptor_stops_after_index_zero() {
        let mut p =
            RoundPlanner::new(50, [Keychain::External], &Ledger::for_tests(), &test_key()).unwrap();
        let stage = p.next_stage();
        assert_eq!(stage.len(), 50);
        p.exhausted(Keychain::External, 1);
        p.record((Keychain::External, 0), true);
        assert!(p.next_stage().is_empty());
        assert_eq!(p.last_active_indices()[&Keychain::External], 0);
    }

    #[test]
    fn rejects_a_ledger_with_a_gap() {
        let mut ledger = Ledger::for_tests();
        ledger.freeze((Keychain::External, 0), 9);
        ledger.freeze((Keychain::External, 2), 9);
        assert!(RoundPlanner::new(50, [Keychain::External], &ledger, &test_key()).is_err());
    }

    /// The first `n >= confirmed` at which positions `0..n` end in `stop_gap` unused ones — for
    /// `confirmed = 0`, exactly where upstream's sequential walk stops.
    fn reference_stop(used: &[bool], stop_gap: u32, confirmed: u32) -> u32 {
        let stop_gap = stop_gap.max(1);
        let mut run = 0;
        for n in 1.. {
            let i = (n - 1) as usize;
            if used.get(i).copied().unwrap_or(false) {
                run = 0;
            } else {
                run += 1;
            }
            if n >= confirmed && run >= stop_gap {
                return n;
            }
        }
        unreachable!()
    }

    #[test]
    fn matches_upstream_walk_on_random_histories() {
        let mut seed: u64 = 0x5eed;
        let mut next = move || {
            seed = seed
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            (seed >> 33) as u32
        };
        for _ in 0..2000 {
            let stop_gap = next() % 12;
            let len = (next() % 120) as usize;
            let density = next() % 5;
            let used: Vec<bool> = (0..len).map(|_| next() % 10 < density).collect();
            let confirmed = if next() % 3 == 0 { next() % 60 } else { 0 };

            let mut ledger = Ledger::for_tests();
            for i in 0..confirmed {
                ledger.freeze((Keychain::External, i), 9);
            }
            let mut p = RoundPlanner::new(
                stop_gap as usize,
                [Keychain::External],
                &ledger,
                &test_key(),
            )
            .unwrap();
            let (queried, stages) = drive(&mut p, |(_, i)| {
                used.get(i as usize).copied().unwrap_or(false)
            });

            let expected = reference_stop(&used, stop_gap, confirmed);
            assert_eq!(
                queried[&Keychain::External],
                expected,
                "gap {stop_gap}, used {used:?}"
            );
            let used_count = used.iter().take(expected as usize).filter(|u| **u).count();
            assert!(
                stages <= 1 + used_count,
                "{stages} stages for {used_count} used positions"
            );
        }
    }
}
