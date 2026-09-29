//! Sibling crate to `bdk_electrum`: the same `full_scan` surface, with decoy padding injected at
//! the batch level. See `docs/02-design.md`, "Sync integration," for why this can't be a wrapper
//! around `bdk_electrum` itself.

pub mod client;
pub mod decoy;
pub mod key;
pub mod keychain;
pub mod ledger;
pub mod ledger_file;
pub mod planner;
pub mod schedule;
pub mod session;
