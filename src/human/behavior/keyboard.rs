//! Realistic keyboard-combo dispatch (copy/paste/select-all, etc.).
//!
//! Anti-bot detectors watch for synthetic `ClipboardEvent`s and uniform
//! modifier timing. These helpers emit trusted `keydown`/`keyup` sequences
//! through BiDi with sampled hold times, so the browser treats them as real
//! keyboard input (G164).

use anyhow::Result;
use rand::Rng;
use runtime_foxdriver::Page;
use std::time::Duration;

/// Dispatch a chord of keys in order, hold them all for a sampled duration,
/// then release them in reverse order.
///
/// # Example
///
/// ```rust,no_run
/// use guise::human::behavior::key_combo;
/// # async fn example(page: &runtime_foxdriver::Page) -> anyhow::Result<()> {
/// key_combo(page, &["Control", "a"]).await?; // select all
/// # Ok(()) }
/// ```
pub async fn key_combo(page: &Page, keys: &[&str]) -> Result<()> {
    if keys.is_empty() {
        return Ok(());
    }
    let mut rng = rand::thread_rng();
    // Hold the full chord for 60–140 ms; individual keys are pressed with a
    // small stagger to avoid a machine-perfect simultaneous-down tell.
    let hold_ms = rng.gen_range(60..=140);
    let stagger_ms = rng.gen_range(15..=45);

    for (i, key) in keys.iter().enumerate() {
        page.key_down(key).await?;
        if i + 1 < keys.len() {
            tokio::time::sleep(Duration::from_millis(stagger_ms)).await;
        }
    }

    tokio::time::sleep(Duration::from_millis(hold_ms)).await;

    for key in keys.iter().rev() {
        page.key_up(key).await?;
    }

    Ok(())
}

/// Select all content in the focused element (`Ctrl+A` / `Cmd+A`).
///
/// Currently uses the Control modifier; macOS personas should override the
/// modifier to `"Meta"`.
pub async fn select_all(page: &Page) -> Result<()> {
    key_combo(page, &["Control", "a"]).await
}

/// Copy the current selection (`Ctrl+C`).
pub async fn copy(page: &Page) -> Result<()> {
    key_combo(page, &["Control", "c"]).await
}

/// Paste the clipboard into the focused element (`Ctrl+V`).
pub async fn paste(page: &Page) -> Result<()> {
    key_combo(page, &["Control", "v"]).await
}

/// Cut the current selection (`Ctrl+X`).
pub async fn cut(page: &Page) -> Result<()> {
    key_combo(page, &["Control", "x"]).await
}
