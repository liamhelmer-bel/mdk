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
