//! Human behavior simulation - realistic mouse, keyboard, and scroll patterns.
//!
//! Anti-bot detectors analyze:
//!   - Mouse trajectory (bots move in straight lines)
//!   - Typing cadence (bots type at constant speed)
//!   - Scroll patterns (bots scroll uniformly)
//!   - Idle time (bots never pause)
//!
//! This module generates Bézier-curve mouse paths, variable typing delays,
//! and natural scroll increments. Each async fn seeds its own `StdRng` from
//! entropy at the call site, so no RNG is held across an `.await` and the
//! futures stay `Send` for multi-threaded Tokio runtimes. Per-step *timing* is
//! jittered through [`crate::human::timing::jittered_step`] so a loop's cadence
//! is never a constant tick (the behavioral tell this module defends against).

use rand::{Rng, SeedableRng};
use runtime_foxdriver::Page;
pub use runtime_foxdriver::ScrollDirection;
use std::time::Duration;

use crate::human::timing::{jittered_step, ActionDelay};

mod keyboard;
mod typing;
pub use keyboard::{copy, cut, key_combo, paste, select_all};
pub use typing::{type_at_wpm, type_human, type_realistic};

/// Move mouse along a Bézier curve from (x0,y0) to (x1,y1).
/// Generates 8-20 intermediate points with realistic timing.
///
/// # Example
///
/// ```rust,no_run
/// use guise::human::behavior::mouse_move_bezier;
/// # async fn example(page: &runtime_foxdriver::Page) -> anyhow::Result<()> {
/// mouse_move_bezier(page, 0.0, 0.0, 400.0, 300.0).await?;
/// # Ok(()) }
/// ```
pub async fn mouse_move_bezier(
    page: &Page,
    x0: f64,
    y0: f64,
    x1: f64,
    y1: f64,
) -> anyhow::Result<()> {
    let mut rng = rand::rngs::StdRng::from_entropy();
    let steps = rng.gen_range(8..=20);

    // Two random control points for the cubic Bézier
    let cx1 = x0 + (x1 - x0) * rng.gen_range(0.2..0.5) + rng.gen_range(-30.0..30.0);
    let cy1 = y0 + (y1 - y0) * rng.gen_range(0.1..0.4) + rng.gen_range(-20.0..20.0);
    let cx2 = x0 + (x1 - x0) * rng.gen_range(0.6..0.9) + rng.gen_range(-20.0..20.0);
    let cy2 = y0 + (y1 - y0) * rng.gen_range(0.5..0.8) + rng.gen_range(-15.0..15.0);

    for i in 0..=steps {
        let t = i as f64 / steps as f64;
        let u = 1.0 - t;

        // Cubic Bézier: B(t) = (1-t)³P0 + 3(1-t)²tP1 + 3(1-t)t²P2 + t³P3
        let x = u * u * u * x0 + 3.0 * u * u * t * cx1 + 3.0 * u * t * t * cx2 + t * t * t * x1;
        let y = u * u * u * y0 + 3.0 * u * u * t * cy1 + 3.0 * u * t * t * cy2 + t * t * t * y1;

        // Dispatch each sampled point as a TRUSTED BiDi pointer move. A
        // synthetic JS `MouseEvent` would carry `isTrusted === false` and hand
        // the anti-bot scorer a free detection, defeating the curve we just
        // shaped. `move_mouse_to` keeps the distinct Bézier trajectory but
        // makes every event real.
        page.move_mouse_to(x, y).await?;

        // Variable delay: faster in middle, slower at start/end (ease-in-out)
        let ease = (std::f64::consts::PI * t).sin(); // 0 at endpoints, 1 at midpoint
        let base_ms = rng.gen_range(8..25);
        let delay_ms = base_ms + ((1.0 - ease) * 15.0) as u64;
        tokio::time::sleep(Duration::from_millis(delay_ms)).await;
    }

    Ok(())
}

/// Move along a human-like trajectory from `(x0, y0)` to `(x1, y1)`.
///
/// Delegates to the runtime's built-in human-mouse path generator.
///
/// # Example
///
/// ```rust,no_run
/// use guise::human::behavior::mouse_move_human;
/// # async fn example(page: &runtime_foxdriver::Page) -> anyhow::Result<()> {
/// mouse_move_human(page, 0.0, 0.0, 400.0, 300.0).await?;
/// # Ok(()) }
/// ```
pub async fn mouse_move_human(
    page: &Page,
    x0: f64,
    y0: f64,
    x1: f64,
    y1: f64,
) -> anyhow::Result<()> {
    page.mouse_move_human(x0, y0, x1, y1).await
}

/// Click at position with realistic mouse-down delay.
///
/// # Example
///
/// ```rust,no_run
/// use guise::human::behavior::click_realistic;
/// # async fn example(page: &runtime_foxdriver::Page) -> anyhow::Result<()> {
/// click_realistic(page, 200.0, 150.0).await?;
/// # Ok(()) }
/// ```
pub async fn click_realistic(page: &Page, x: f64, y: f64) -> anyhow::Result<()> {
    page.click_at(x, y).await
}

/// Scroll with human-like pattern: variable speed, direction micro-corrections.
///
/// Thin convenience wrapper over the runtime's built-in smooth scroll.
///
/// # Example
///
/// ```rust,no_run
/// use guise::human::behavior::{scroll_realistic, ScrollDirection};
/// # async fn example(page: &runtime_foxdriver::Page) -> anyhow::Result<()> {
/// scroll_realistic(page, ScrollDirection::Down, 500).await?;
/// # Ok(()) }
/// ```
pub async fn scroll_realistic(
    page: &Page,
    direction: ScrollDirection,
    amount: u32,
) -> anyhow::Result<()> {
    page.scroll_realistic(direction, amount).await
}

/// Random idle pause - simulates reading/thinking time.
///
/// Delegates to [`ActionDelay::wait_idle`] so all pacing lives in the
/// canonical timing module (G141).
///
/// # Example
///
/// ```rust,no_run
/// use guise::human::behavior::idle_pause;
///
/// # async fn example() {
/// idle_pause().await;
/// # }
/// ```
pub async fn idle_pause() {
    ActionDelay::wait_idle().await;
}

/// Short micro-pause between actions (100-400ms).
///
/// Delegates to [`ActionDelay::wait_between_actions`] so all pacing lives in
/// the canonical timing module (G141).
///
/// # Example
///
/// ```rust,no_run
/// use guise::human::behavior::micro_pause;
///
/// # async fn example() {
/// micro_pause().await;
/// # }
/// ```
pub async fn micro_pause() {
    ActionDelay::wait_between_actions().await;
}

/// Pause for a uniformly-random duration in `[min_ms, max_ms]`.
///
/// General-purpose human-pacing primitive that complements
/// [`idle_pause`] and [`micro_pause`].  Delegates to
/// [`ActionDelay::wait_uniform`] so all pacing lives in the canonical timing
/// module (G141).  Panics if `min_ms > max_ms`.
///
/// # Example
///
/// ```rust,no_run
/// use guise::human::behavior::random_pause;
/// # async fn run() {
/// random_pause(150, 600).await;
/// # }
/// ```
pub async fn random_pause(min_ms: u64, max_ms: u64) {
    ActionDelay::wait_uniform(min_ms, max_ms).await;
}

/// Triple-click at `(x, y)` to select all text in an input/textarea.
///
/// Shortcut for "select-all-then-type" patterns common when filling
/// captcha answer fields that pre-populate with placeholder text.
///
/// # Example
///
/// ```rust,no_run
/// use guise::human::behavior::triple_click;
/// # async fn run(page: &runtime_foxdriver::Page) -> anyhow::Result<()> {
/// triple_click(page, 320.0, 200.0).await?;
/// # Ok(()) }
/// ```
pub async fn triple_click(page: &Page, x: f64, y: f64) -> anyhow::Result<()> {
    let mut rng = rand::rngs::StdRng::from_entropy();
    for _ in 0..3 {
        page.click_at(x, y).await?;
        // Jitter the inter-click gap: a real triple-click's gaps vary, a fixed
        // 60 ms × 3 is a robotic cadence (G143).
        tokio::time::sleep(jittered_step(Duration::from_millis(60), 0.35, &mut rng)).await;
    }
    Ok(())
}

/// Hover the mouse over a viewport coordinate WITHOUT clicking, then
/// dwell for 200-700ms - triggers `mouseenter` / `mouseover` listeners
/// that anti-bot widgets watch for to confirm the visitor's pointer
/// is actually traversing the page (real users rest the cursor on
/// elements; bots warp to coordinates and click).
///
/// # Example
///
/// ```rust,no_run
/// use guise::human::behavior::hover_dwell;
/// # async fn run(page: &runtime_foxdriver::Page) -> anyhow::Result<()> {
/// hover_dwell(page, 320.0, 240.0).await?;
/// # Ok(()) }
/// ```
pub async fn hover_dwell(page: &Page, x: f64, y: f64) -> anyhow::Result<()> {
    page.mouse_move_human(0.0, 0.0, x, y).await?;
    let ms = rand::rngs::StdRng::from_entropy().gen_range(200..700);
    tokio::time::sleep(Duration::from_millis(ms)).await;
    Ok(())
}

/// Touch-style swipe gesture between two viewport coordinates.
///
/// Unlike a desktop drag, mobile swipes have higher initial velocity
/// and a brief decelerating tail. Useful for slider widgets in mobile
/// stealth profiles.
///
/// `duration_ms` controls the total swipe time (typical 250-500ms for
/// a fast gesture, 700-1200ms for a deliberate one). 25 sub-steps
/// gives a smooth-enough trajectory without spamming events.
///
/// # Example
///
/// ```rust,no_run
/// use guise::human::behavior::touch_swipe;
/// # async fn run(page: &runtime_foxdriver::Page) -> anyhow::Result<()> {
/// // Swipe a slider knob 280px to the right.
/// touch_swipe(page, 40.0, 200.0, 320.0, 200.0, 350).await?;
/// # Ok(()) }
/// ```
pub async fn touch_swipe(
    page: &Page,
    x0: f64,
    y0: f64,
    x1: f64,
    y1: f64,
    duration_ms: u64,
) -> anyhow::Result<()> {
    let steps = 25;
    let step_ms = (duration_ms / steps as u64).max(8);
    let mut rng = rand::rngs::StdRng::from_entropy();

    page.mouse_down(x0, y0).await?;

    // CONTINUE each segment from the PREVIOUS point. `mouse_move_human(from, to)`
    // forcibly resets the cursor to `from` before moving, so passing the original
    // `(x0, y0)` every iteration (the old bug) teleported the cursor back to the
    // swipe origin on every sub-step: 25 trajectories fanning out from the start
    // instead of one continuous drag. Threading the previous point keeps the drag
    // continuous and on the same (button-held) pointer source as `mouse_down`.
    let (mut px, mut py) = (x0, y0);
    for (x, y) in swipe_points(x0, y0, x1, y1, steps) {
        page.mouse_move_human(px, py, x, y).await?;
        px = x;
        py = y;
        // Jitter the per-event cadence so the swipe's *timing* isn't a uniform
        // tick even though its *path* is eased (G143).
        tokio::time::sleep(jittered_step(
            Duration::from_millis(step_ms),
            0.30,
            &mut rng,
        ))
        .await;
    }

    page.mouse_up(x1, y1).await?;
    Ok(())
}

/// Ease-out sample points of a touch swipe from `(x0, y0)` to `(x1, y1)`.
///
/// Ease-out (`1 − (1−t)²`) models a real finger flick: high initial velocity
/// decelerating onto the target. The final point lands EXACTLY on `(x1, y1)`.
/// Pure so the trajectory geometry is unit-testable independently of the async
/// trusted-dispatch loop.
fn swipe_points(x0: f64, y0: f64, x1: f64, y1: f64, steps: u32) -> Vec<(f64, f64)> {
    let steps = steps.max(1);
    (1..=steps)
        .map(|s| {
            let t = f64::from(s) / f64::from(steps);
            let eased = 1.0 - (1.0 - t).powi(2);
            (x0 + (x1 - x0) * eased, y0 + (y1 - y0) * eased)
        })
        .collect()
}

/// Apply small Lissajous-curve pointer jitter around `(cx, cy)` for `cycles`
/// cycles of `cycle_ms` each.
///
/// # Example
///
/// ```rust,no_run
/// use guise::human::behavior::pointer_jitter;
/// # async fn run(page: &runtime_foxdriver::Page) -> anyhow::Result<()> {
/// pointer_jitter(page, 400.0, 300.0, 5, 80).await?;
/// # Ok(()) }
/// ```
pub async fn pointer_jitter(
    page: &Page,
    cx: f64,
    cy: f64,
    cycles: u32,
    cycle_ms: u64,
) -> anyhow::Result<()> {
    let mut rng = rand::rngs::StdRng::from_entropy();
    for c in 0..cycles {
        let amp_x: f64 = rng.gen_range(2.0..4.5);
        let amp_y: f64 = rng.gen_range(2.0..4.5);
        let phase: f64 = rng.gen_range(0.0..std::f64::consts::TAU);
        let steps = 8u64;
        for s in 0..steps {
            let theta = phase + (c as f64 + s as f64 / steps as f64) * std::f64::consts::TAU;
            let x = cx + amp_x * theta.sin();
            let y = cy + amp_y * (theta * 1.7).cos();
            // One TRUSTED move to each absolute Lissajous point. The old
            // `mouse_move_human(cx, cy, …)` reset the cursor to the centre before
            // every point (see `mouse_move_human`'s `set_last_position`), so the
            // tremor became a star burst through the centre instead of a smooth
            // continuous wander. `move_mouse_to` is a single absolute pointer move
            //: the points are already a continuous curve, so no re-curving is
            // needed and there is no held button to keep on one source.
            page.move_mouse_to(x, y).await?;
            // Jitter the dwell between jitter-points so the idle "tremor" itself
            // has a human, non-uniform cadence (G143).
            tokio::time::sleep(jittered_step(
                Duration::from_millis(cycle_ms / steps),
                0.30,
                &mut rng,
            ))
            .await;
        }
    }
    Ok(())
}

#[cfg(test)]
mod random_pause_tests;

#[cfg(test)]
mod tests;
