//! Compatibility browser application for [`super::StealthProfile`] (requires `browser` feature).

use anyhow::Result;
use runtime_foxdriver::browser::Page;

use super::profiles::StealthProfile;

/// Apply the canonical profiled BiDi stealth stack for `profile`.
pub async fn apply_stealth_profile(page: &Page, profile: &StealthProfile) -> Result<()> {
    crate::browser::apply_stealth_profile(page, profile).await
}

/// Apply the canonical profiled BiDi stealth stack for the default profile.
pub async fn apply_default_stealth_profile(page: &Page) -> Result<()> {
    crate::browser::apply_default_stealth_profile(page).await
}
