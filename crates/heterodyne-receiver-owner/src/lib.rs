//! Finite protected receiver initialization and installation owner.
//!
//! Mechanics remain private until the concrete bootstrap admission and fixed
//! descriptor entry are composed. Linking this crate grants no authority.

mod generation;
mod initializer;
mod preparation;
mod publication_journal;

#[cfg(test)]
mod sdk_partial_tests;

mod owned_child;

mod initializer_handoff;

mod initializer_entry;

/// Fixed no-argument initializer binary boundary; no JSON authority constructor.
pub fn protected_initializer_entry() -> bool {
    initializer_entry::entry().is_ok()
}

mod owner_entry;
/// Fixed root supervisor entry. No configurable executable or arbitrary plan.
pub fn protected_owner_init_entry() -> bool {
    owner_entry::entry().is_ok()
}

mod bootstrap;
mod bootstrap_peer;
/// Finite root-owned descriptor lifecycle; no parsed consent constructor.
pub fn protected_bootstrap_entry() -> bool {
    bootstrap::entry().is_ok()
}

mod assembly;
/// Root read-only source-qualified index/profile assembly; grants no consent.
pub fn protected_assembly_entry() -> bool {
    assembly::entry().is_ok()
}

mod native_frame;

mod supervision;
