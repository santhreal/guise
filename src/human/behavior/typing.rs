//! Browser typing compatibility wrappers backed by the canonical human-typing
//! model in [`crate::human::typing`].
//!
//! Both entry points route through [`HumanTyper::type_text`] so there is a single
//! typing model in the codebase (G135).

use runtime_foxdriver::Page;

use crate::human::{HumanTyper, TypingConfig};

/// Type text with human-like cadence via the canonical [`HumanTyper`].
///
/// # Example
///
/// ```rust,no_run
/// use guise::human::behavior::type_realistic;
/// # async fn example(page: &runtime_foxdriver::Page) -> anyhow::Result<()> {
/// type_realistic(page, "hello world").await?;
/// # Ok(()) }
/// ```
pub async fn type_realistic(page: &Page, text: &str) -> anyhow::Result<()> {
    HumanTyper::default().type_text(page, text).await
}

/// Type text with bigram-aware human keystroke timing.
///
/// This is now the same path as [`type_realistic`], both use the canonical
/// [`HumanTyper`] backed by [`crate::human::plan_keystrokes`].  The separate
/// name is retained for source compatibility with callers that explicitly
/// requested bigram-aware typing.
///
/// # Example
///
/// ```rust,no_run
/// use guise::human::behavior::type_human;
/// # async fn example(page: &runtime_foxdriver::Page) -> anyhow::Result<()> {
/// type_human(page, "the quick brown fox").await?;
/// # Ok(()) }
/// ```
pub async fn type_human(page: &Page, text: &str) -> anyhow::Result<()> {
    HumanTyper::default().type_text(page, text).await
}

/// Type text with an explicit WPM target.
///
/// Convenience wrapper that builds a [`TypingConfig`] and dispatches through
/// the canonical [`HumanTyper`].
///
/// # Example
///
/// ```rust,no_run
/// use guise::human::behavior::type_at_wpm;
/// # async fn example(page: &runtime_foxdriver::Page) -> anyhow::Result<()> {
/// type_at_wpm(page, "the quick brown fox", 45.0).await?;
/// # Ok(()) }
/// ```
pub async fn type_at_wpm(page: &Page, text: &str, wpm: f64) -> anyhow::Result<()> {
    HumanTyper::new(TypingConfig::with_wpm(wpm))
        .type_text(page, text)
        .await
}
