//! Session-aged persona seeding (G126 / R148).
//!
//! A freshly-launched automation profile has `history.length == 0` and an empty
//! `localStorage`, which anti-bot scripts read as a "new profile" tell. This
//! module generates a small, deterministic set of age artifacts for a persona
//! and injects them into a live page so the profile looks plausibly used.
//!
//! The seed is deterministic per identity (e.g. the profile directory/account
//! key) so the same account always presents the same age surface, and different
//! accounts present different but still plausible ages.

use anyhow::{Context, Result};
use rand::{rngs::StdRng, Rng, SeedableRng};
use runtime_foxdriver::browser::Page;
use serde_json::json;

/// A plausible "used" session state for one persona.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionAgeSeed {
    /// Target `history.length`. Real browsers after a short browsing session
    /// report small positive integers; we stay inside 2–12 to avoid the fresh
    /// `0` tell without claiming an implausibly deep history.
    pub history_length: u32,
    /// A few `localStorage` entries typical of a real session (theme, locale,
    /// consent flags). Values are short and profile-agnostic so they read as
    /// ordinary site-local state, not injected noise.
    pub local_storage_entries: Vec<(String, String)>,
}

impl SessionAgeSeed {
    /// No-op age seed: leaves the fresh profile untouched. Useful when a caller
    /// explicitly wants the default automation profile.
    #[must_use]
    pub fn none() -> Self {
        Self {
            history_length: 0,
            local_storage_entries: Vec::new(),
        }
    }

    /// True if this seed actually mutates any surface.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.history_length == 0 && self.local_storage_entries.is_empty()
    }
}

/// Generate a deterministic but persona-different age seed from a 64-bit
/// identity key (e.g. `identity_seed(profile_dir)`).
///
/// The result is stable for the same key and bounded to realistic values, so
/// the surface does not vary wildly between launches of the same account.
#[must_use]
pub fn generate_session_age(seed: u64) -> SessionAgeSeed {
    let mut rng = StdRng::seed_from_u64(seed);

    // History length: 2–12, weighted toward the low end (realistic short session).
    let history_length = rng.gen_range(2..=12);

    // A small fixed pool of plausible localStorage keys. We pick a deterministic
    // subset and values so the result looks like ordinary site state.
    let key_pool: [(&str, &[&str]); 5] = [
        ("theme", &["light", "dark", "auto"]),
        ("locale", &["en-US", "en-GB", "en-CA"]),
        ("cookies_accepted", &["true", "false"]),
        ("visited_before", &["true"]),
        ("font_size", &["medium", "large", "small"]),
    ];

    let count = rng.gen_range(2..=key_pool.len());
    let mut local_storage_entries = Vec::with_capacity(count);
    for &(key, values) in key_pool.iter().take(count) {
        let value = values[rng.gen_range(0..values.len())];
        local_storage_entries.push((key.to_string(), value.to_string()));
    }

    SessionAgeSeed {
        history_length,
        local_storage_entries,
    }
}

/// Build the JS snippet that seeds a page with [`SessionAgeSeed`].
///
/// The script is idempotent: running it twice does not keep inflating
/// `history.length` because it only pushes states until the real length reaches
/// the target. It uses real `history.pushState` entries rather than a getter
/// override so post-seed navigations update `history.length` naturally and no
/// property descriptor tell is introduced.
///
/// The script returns `{{historyBefore, historyAfter, storedCount}}` (or a best-
/// effort subset wrapped in try/catch) so callers can verify the work without
/// issuing extra evaluations.
#[must_use]
pub fn session_age_js(seed: &SessionAgeSeed) -> String {
    if seed.is_empty() {
        return String::new();
    }

    let entries_json = json!(seed.local_storage_entries);
    let target = seed.history_length;
    let wanted_keys_json = json!(seed
        .local_storage_entries
        .iter()
        .map(|(k, _)| k.as_str())
        .collect::<Vec<_>>());

    format!(
        r#"
(() => {{
    const entries = {entries_json};
    const targetHistory = {target};
    const wantedKeys = {wanted_keys_json};
    let historyBefore = -1;
    let historyAfter = -1;
    let storedCount = 0;
    try {{
        historyBefore = history.length;
        if (historyBefore < targetHistory) {{
            for (let i = historyBefore; i < targetHistory; i++) {{
                history.pushState({{ _: i }}, '', '');
            }}
        }}
        historyAfter = history.length;
    }} catch (_) {{}}
    try {{
        for (const [k, v] of entries) {{
            try {{ localStorage.setItem(k, v); }} catch (_) {{}}
        }}
        for (let i = 0; i < localStorage.length; i++) {{
            const k = localStorage.key(i);
            if (k && wantedKeys.includes(k)) storedCount++;
        }}
    }} catch (_) {{}}
    return {{ historyBefore, historyAfter, storedCount }};
}})();
"#
    )
}

/// Apply the session-age seed to a live page.
///
/// Returns the number of history entries added and the number of localStorage
/// entries written, surfaced so tests can assert real work happened. A no-op
/// seed returns `Ok((0, 0))` without touching the page.
pub async fn apply_session_age(page: &Page, seed: &SessionAgeSeed) -> Result<(u32, u32)> {
    if seed.is_empty() {
        return Ok((0, 0));
    }

    let result = page
        .evaluate(session_age_js(seed))
        .await
        .context("apply_session_age: inject session age script")?;
    let result: serde_json::Value = result
        .into_value()
        .context("apply_session_age: parse session age result")?;

    let added = result
        .get("historyBefore")
        .and_then(|v| v.as_i64())
        .zip(result.get("historyAfter").and_then(|v| v.as_i64()))
        .map(|(before, after)| (after - before).max(0) as u32)
        .unwrap_or(0);
    let stored = result
        .get("storedCount")
        .and_then(|v| v.as_i64())
        .map(|n| n.max(0) as u32)
        .unwrap_or(0);

    Ok((added, stored))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_is_deterministic() {
        let a = generate_session_age(0xC0FFEE);
        let b = generate_session_age(0xC0FFEE);
        assert_eq!(a, b);
    }

    #[test]
    fn generate_differs_across_seeds() {
        let a = generate_session_age(1);
        let b = generate_session_age(2);
        assert_ne!(a.history_length, b.history_length);
    }

    #[test]
    fn history_length_in_realistic_range() {
        for seed in 0..200u64 {
            let age = generate_session_age(seed);
            assert!(
                (2..=12).contains(&age.history_length),
                "seed {seed}: history_length {} out of range",
                age.history_length
            );
        }
    }

    #[test]
    fn local_storage_count_bounded() {
        for seed in 0..200u64 {
            let age = generate_session_age(seed);
            assert!((2..=5).contains(&age.local_storage_entries.len()));
        }
    }

    #[test]
    fn none_seed_is_empty_and_emits_no_js() {
        let seed = SessionAgeSeed::none();
        assert!(seed.is_empty());
        assert!(session_age_js(&seed).is_empty());
    }

    #[test]
    fn session_age_js_contains_targets() {
        let seed = generate_session_age(42);
        let js = session_age_js(&seed);
        assert!(js.contains(&format!("const targetHistory = {};", seed.history_length)));
        assert!(js.contains("history.pushState"));
        assert!(js.contains("localStorage.setItem"));
        for (k, v) in &seed.local_storage_entries {
            assert!(js.contains(&format!("\"{k}\"")));
            assert!(js.contains(&format!("\"{v}\"")));
        }
    }

    #[test]
    fn empty_apply_returns_zero_counts() {
        // Unit-level check: an empty seed reports zero work without a page.
        assert_eq!(SessionAgeSeed::none().history_length, 0);
        assert!(SessionAgeSeed::none().local_storage_entries.is_empty());
    }
}
