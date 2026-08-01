//! Re-exported random choice primitives.
//!
//! The implementation lives in `stealth-choice` so lower-level Santh crates can
//! share the same sampling and alphabet contracts without depending on the full
//! stealth stack.

pub use guise_choice::{
    chance, chance_with_rng, random_ascii_string, random_ascii_string_with_rng, random_index,
    random_index_with_rng, random_item, random_item_with_rng, random_lower_alphanumeric,
    random_lower_alphanumeric_with_rng, weighted_index, weighted_index_by_with_rng,
    weighted_index_with_rng, LOWER_ALPHANUMERIC,
};
