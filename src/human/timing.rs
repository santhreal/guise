//! Human-like timing utilities (lifted from archived golemn-browser).
//!
//! Three independent subsystems, all pure (no browser, no async) so they can be
//! sampled and unit-tested offline; the `browser` feature adds thin `async`
//! sleep wrappers on top:
//!
//! 1. [`ReadingTimeEstimator`], a realistic pause duration based on the number
//!    of visible words and a 200–250 WPM reading speed with variance.
//! 2. [`ActionDelay`], pre-action think-time delays (`before_click`,
//!    `form_field_transition`, `after_page_load`, `micro`).
//! 3. [`SessionPacing`], session-level fatigue and burst/pause rhythm: tracks
//!    elapsed actions and injects burst-end and long idle pauses, with a fatigue
//!    factor that grows over time and gradually slows every delay.
//!
//! The pacing decision is split from the sleep: [`SessionPacing::advance`]
//! mutates the state and *returns* the [`Duration`] to wait (deterministic under
//! a seeded RNG, so it is unit-testable), while the `browser`-only
//! [`SessionPacing::tick`] performs the actual `tokio` sleep.

use rand::Rng;
use std::time::Duration;

use crate::pacing::BoundedNormalDelay;
use crate::sampling::standard_normal;

// ── ReadingTimeEstimator ─────────────────────────────────────────────────

/// Estimates a realistic reading pause for a block of text.
///
/// Reading speed is drawn from a normal distribution centred at 225 WPM
/// (midpoint of the 200–250 WPM range), σ = 20 WPM.
pub struct ReadingTimeEstimator {
    /// Mean reading speed in words-per-minute.
    wpm_mean: f64,
    /// Standard deviation of reading speed.
    wpm_std: f64,
}

impl Default for ReadingTimeEstimator {
    fn default() -> Self {
        Self {
            wpm_mean: 225.0,
            wpm_std: 20.0,
        }
    }
}

impl ReadingTimeEstimator {
    /// Build an estimator with an explicit mean / standard-deviation WPM.
    #[must_use]
    pub fn new(wpm_mean: f64, wpm_std: f64) -> Self {
        Self { wpm_mean, wpm_std }
    }

    /// Estimate the time a human would spend reading `text`.
    ///
    /// Returns a `Duration` sampled from the configured reading-speed
    /// distribution, clamped to 500 ms – 120 s.
    #[must_use]
    pub fn estimate(&self, text: &str) -> Duration {
        let mut rng = rand::thread_rng();
        let word_count = count_words(text).max(1) as f64;

        // Sample WPM with normal noise.
        let z = standard_normal(&mut rng);
        let wpm = (self.wpm_mean + z * self.wpm_std).max(100.0);

        let minutes = word_count / wpm;
        let ms = (minutes * 60_000.0) as u64;

        // Clamp to a sensible range: 500 ms – 120 s.
        Duration::from_millis(ms.clamp(500, 120_000))
    }

    /// Estimate reading time given a raw word count.
    #[must_use]
    pub fn estimate_words(&self, word_count: usize) -> Duration {
        // Build a string with actual words so count_words() returns the right count.
        let words = "word ".repeat(word_count);
        self.estimate(&words)
    }
}

// ── ActionDelay ──────────────────────────────────────────────────────────

/// Pre-action "think time" delays that mimic human hesitation.
///
/// All distributions are sampled from [`crate::pacing::BoundedNormalDelay`], the
/// same primitive used by `guise_pacing::RequestPacer`. This keeps behavioral
/// timing and request pacing as one model rather than two independent delay
/// sources (G228).
pub struct ActionDelay;

impl ActionDelay {
    /// Pause before a click: 200–800 ms.
    #[must_use]
    pub fn before_click() -> Duration {
        BoundedNormalDelay::from_unordered_bounds(200, 800).sample_thread()
    }

    /// Pause when moving between form fields: 300–1 200 ms.
    #[must_use]
    pub fn form_field_transition() -> Duration {
        BoundedNormalDelay::from_unordered_bounds(300, 1_200).sample_thread()
    }

    /// Initial pause after a page loads (user "takes in" the page: 800–3 000 ms).
    #[must_use]
    pub fn after_page_load() -> Duration {
        BoundedNormalDelay::from_unordered_bounds(800, 3_000).sample_thread()
    }

    /// Short micro-pause between UI events: 50–200 ms.
    #[must_use]
    pub fn micro() -> Duration {
        BoundedNormalDelay::from_unordered_bounds(50, 200).sample_thread()
    }

    /// Sleep for a [`before_click`](Self::before_click) duration.
    #[cfg(feature = "browser")]
    pub async fn wait_before_click() {
        tokio::time::sleep(Self::before_click()).await;
    }

    /// Sleep for a [`form_field_transition`](Self::form_field_transition) duration.
    #[cfg(feature = "browser")]
    pub async fn wait_form_transition() {
        tokio::time::sleep(Self::form_field_transition()).await;
    }

    /// Sleep for an [`after_page_load`](Self::after_page_load) duration.
    #[cfg(feature = "browser")]
    pub async fn wait_after_load() {
        tokio::time::sleep(Self::after_page_load()).await;
    }

    /// Hover dwell before a click: 200–700 ms.
    #[must_use]
    pub fn hover_dwell() -> Duration {
        BoundedNormalDelay::from_unordered_bounds(200, 700).sample_thread()
    }

    /// Idle reading/thinking pause: 500–2 000 ms.
    #[must_use]
    pub fn idle() -> Duration {
        BoundedNormalDelay::from_unordered_bounds(500, 2_000).sample_thread()
    }

    /// Short pause between actions (100–400 ms).
    #[must_use]
    pub fn between_actions() -> Duration {
        BoundedNormalDelay::from_unordered_bounds(100, 400).sample_thread()
    }

    /// Uniformly-random duration in `[min_ms, max_ms]`.
    ///
    /// Panics if `min_ms > max_ms`.
    #[must_use]
    pub fn uniform(min_ms: u64, max_ms: u64) -> Duration {
        assert!(
            min_ms <= max_ms,
            "ActionDelay::uniform: min_ms ({min_ms}) > max_ms ({max_ms})"
        );
        let ms = if min_ms == max_ms {
            min_ms
        } else {
            rand::thread_rng().gen_range(min_ms..=max_ms)
        };
        Duration::from_millis(ms)
    }

    /// Sleep for a [`hover_dwell`](Self::hover_dwell) duration.
    #[cfg(feature = "browser")]
    pub async fn wait_hover_dwell() {
        tokio::time::sleep(Self::hover_dwell()).await;
    }

    /// Sleep for an [`idle`](Self::idle) duration.
    #[cfg(feature = "browser")]
    pub async fn wait_idle() {
        tokio::time::sleep(Self::idle()).await;
    }

    /// Sleep for a [`between_actions`](Self::between_actions) duration.
    #[cfg(feature = "browser")]
    pub async fn wait_between_actions() {
        tokio::time::sleep(Self::between_actions()).await;
    }

    /// Sleep for a [`uniform`](Self::uniform) duration.
    #[cfg(feature = "browser")]
    pub async fn wait_uniform(min_ms: u64, max_ms: u64) {
        tokio::time::sleep(Self::uniform(min_ms, max_ms)).await;
    }
}

// ── Per-step cadence jitter ───────────────────────────────────────────────

/// Jitter a nominal per-step delay so a repeated action's *temporal* cadence is
/// non-uniform.
///
/// A human never ticks at a perfectly constant interval, so a fixed
/// `sleep(step)` inside a move/click/swipe loop is itself a behavioral tell
/// (G143): the spatial path can be perfectly eased, but a uniform time-between
/// events betrays automation just as plainly as a warped pointer. This samples
/// uniformly in `[nominal·(1−spread), nominal·(1+spread)]`, clamped to a 1 ms
/// floor so a step never collapses into a zero-delay burst.
///
/// `spread` is clamped to `[0.0, 0.95]`; `0.0` returns the nominal unchanged.
/// Taking the RNG by reference keeps this pure and seed-deterministic for tests
/// while letting callers thread one RNG through a whole gesture.
#[must_use]
pub fn jittered_step<R: Rng + ?Sized>(nominal: Duration, spread: f64, rng: &mut R) -> Duration {
    let nominal_ms = nominal.as_millis() as f64;
    if nominal_ms <= 0.0 {
        return Duration::from_millis(1);
    }
    let spread = spread.clamp(0.0, 0.95);
    if spread == 0.0 {
        return Duration::from_millis((nominal_ms.round() as u64).max(1));
    }
    let low = nominal_ms * (1.0 - spread);
    let high = nominal_ms * (1.0 + spread);
    let sampled = rng.gen_range(low..=high);
    Duration::from_millis((sampled.round() as u64).max(1))
}

// ── SessionPacing ─────────────────────────────────────────────────────────

/// Tracks session-level pacing: fatigue, burst sequences, and idle breaks.
///
/// Usage pattern (with the `browser` feature):
/// ```no_run
/// # #[cfg(feature = "browser")]
/// # async fn run() {
/// use guise::human::timing::SessionPacing;
/// let mut pacing = SessionPacing::new();
/// loop {
///     pacing.tick().await; // potentially inserts a burst-end / idle pause
///     // … do browser action …
/// #   break;
/// }
/// # }
/// ```
/// Without a browser, call [`SessionPacing::advance`] and sleep on the returned
/// [`Duration`] yourself.
#[derive(Debug, Clone)]
pub struct SessionPacing {
    /// Number of actions taken so far in the session.
    actions_taken: u32,
    /// Actions until next forced idle break.
    next_idle_at: u32,
    /// Cumulative fatigue factor (starts at 1.0, grows toward ~1.5).
    fatigue: f64,
    /// How many consecutive "burst" actions remain before a pause.
    burst_remaining: u32,
    /// When true, the session is under suspected challenge and delays are
    /// multiplied to look more deliberate and human (G167).
    challenge_mode: bool,
}

impl Default for SessionPacing {
    fn default() -> Self {
        Self::new()
    }
}

impl SessionPacing {
    /// Start a fresh session with a randomised first idle break and burst length.
    #[must_use]
    pub fn new() -> Self {
        let mut rng = rand::thread_rng();
        Self {
            actions_taken: 0,
            next_idle_at: rng.gen_range(8..20),
            fatigue: 1.0,
            burst_remaining: rng.gen_range(3..8),
            challenge_mode: false,
        }
    }

    /// Advance one action tick and return how long the caller should pause
    /// before the *next* action, or `None` for no pause.
    ///
    /// This is the pure heart of the pacer: it mutates fatigue / burst / idle
    /// state and computes the (fatigue-scaled) burst-end and idle pauses, but
    /// performs no sleeping itself (so it is deterministic under a seeded RNG).
    pub fn advance<R: Rng + ?Sized>(&mut self, rng: &mut R) -> Option<Duration> {
        self.actions_taken += 1;
        // Fatigue grows slowly, asymptotically approaching 1.5.
        self.fatigue = 1.0 + 0.5 * (1.0 - (-(self.actions_taken as f64) / 60.0).exp());

        let mut total_ms: u64 = 0;

        // Burst tracking.
        if self.burst_remaining == 0 {
            // End-of-burst pause: 800–3 000 ms scaled by fatigue.
            let base_ms = rng.gen_range(800_u64..3_000);
            total_ms += (base_ms as f64 * self.fatigue) as u64;
            // Start a new burst.
            self.burst_remaining = rng.gen_range(3..8);
        } else {
            self.burst_remaining -= 1;
        }

        // Long idle break.
        if self.actions_taken >= self.next_idle_at {
            let idle_ms = rng.gen_range(5_000_u64..15_000);
            total_ms += (idle_ms as f64 * self.fatigue) as u64;
            self.actions_taken = 0;
            self.next_idle_at = rng.gen_range(8..20);
            // Reset burst after a long idle.
            self.burst_remaining = rng.gen_range(3..8);
        }

        if self.challenge_mode {
            total_ms = total_ms.saturating_mul(2);
        }

        (total_ms > 0).then(|| Duration::from_millis(total_ms))
    }

    /// Advance one action tick and sleep for any burst-end / idle pause.
    #[cfg(feature = "browser")]
    pub async fn tick(&mut self) {
        use rand::SeedableRng;
        // Send-safe RNG so the future stays `Send` across the await point.
        let mut rng = rand::rngs::StdRng::from_entropy();
        if let Some(delay) = self.advance(&mut rng) {
            tokio::time::sleep(delay).await;
        }
    }

    /// Current fatigue multiplier (1.0 = fresh, up to ~1.5 = tired).
    #[must_use]
    pub fn fatigue(&self) -> f64 {
        self.fatigue
    }

    /// Total number of actions taken in this session (since the last idle reset).
    #[must_use]
    pub fn actions_taken(&self) -> u32 {
        self.actions_taken
    }

    /// Scale a base delay by the current fatigue factor.
    #[must_use]
    pub fn scale_duration(&self, base: Duration) -> Duration {
        Duration::from_millis((base.as_millis() as f64 * self.fatigue) as u64)
    }

    /// Enter challenge mode: subsequent pauses are lengthened to look more
    /// deliberate when a challenge or suspicious page is detected (G167).
    pub fn enter_challenge_mode(&mut self) {
        self.challenge_mode = true;
    }

    /// Exit challenge mode and return to normal pacing.
    pub fn exit_challenge_mode(&mut self) {
        self.challenge_mode = false;
    }

    /// True when the session is currently in challenge-slowdown mode.
    #[must_use]
    pub fn is_challenge_mode(&self) -> bool {
        self.challenge_mode
    }
}

// ── helpers ───────────────────────────────────────────────────────────────

fn count_words(text: &str) -> usize {
    text.split_whitespace().count()
}

#[cfg(test)]
#[path = "timing/tests.rs"]
mod tests;

#[cfg(test)]
#[path = "timing/plausibility.rs"]
mod human_plausibility_bounds;
