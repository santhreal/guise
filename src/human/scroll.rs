//! Human-like scroll simulation with momentum physics (lifted from archived
//! golemn-browser).
//!
//! Models:
//! - Flick scrolling: initial velocity decays via a friction coefficient.
//! - Variable scroll amounts (not uniform steps) via a Dirichlet-like split.
//! - Occasional overshoot + correction.
//! - Behaviour modes: Reading, Scanning, Searching, Idle, each with a distinct
//!   velocity / friction / overshoot / cadence profile.
//!
//! [`HumanScroller`] is guise's rich scroll engine, momentum physics, per-intent
//! behaviour modes, overshoot+correction, wheel-device coherence, and telemetry
//! offered to callers that drive a [`runtime_foxdriver::Page`] directly. (Note:
//! [`super::behavior::scroll_realistic`] is a SEPARATE thin convenience helper that
//! delegates to `Page::scroll_realistic` in foxdriver; it does NOT route through
//! `HumanScroller`. Use `HumanScroller` when you want the behaviour-mode /
//! overshoot / telemetry model.) Requires the `browser` feature.

use anyhow::Result;
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use runtime_foxdriver::Page;
use std::time::Duration;

use crate::choice::chance_with_rng;
use crate::human::telemetry::{BehavioralEvent, TelemetryCollector};
use crate::human::wheel::WheelDevice;

// ── ScrollBehavior ────────────────────────────────────────────────────────

/// Describes the user's intent while scrolling, each mode produces
/// a distinct velocity/cadence profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScrollBehavior {
    /// Slow, steady downward scroll while reading line by line.
    Reading,
    /// Moderate speed, skimming sections.
    Scanning,
    /// Fast scroll looking for a specific piece of content.
    Searching,
    /// Occasional small movements, mostly paused.
    Idle,
}

impl ScrollBehavior {
    /// Initial flick velocity in px (mean).
    fn base_velocity(self) -> f64 {
        match self {
            ScrollBehavior::Reading => 80.0,
            ScrollBehavior::Scanning => 200.0,
            ScrollBehavior::Searching => 420.0,
            ScrollBehavior::Idle => 30.0,
        }
    }

    /// Friction coefficient per tick (0–1; higher = stops faster).
    fn friction(self) -> f64 {
        match self {
            ScrollBehavior::Reading => 0.72,
            ScrollBehavior::Scanning => 0.65,
            ScrollBehavior::Searching => 0.55,
            ScrollBehavior::Idle => 0.80,
        }
    }

    /// Probability of overshoot on a given flick (0–1).
    fn overshoot_probability(self) -> f64 {
        match self {
            ScrollBehavior::Reading => 0.05,
            ScrollBehavior::Scanning => 0.12,
            ScrollBehavior::Searching => 0.20,
            ScrollBehavior::Idle => 0.02,
        }
    }

    /// Inter-flick pause range (ms).
    fn pause_range_ms(self) -> (u64, u64) {
        match self {
            ScrollBehavior::Reading => (600, 2000),
            ScrollBehavior::Scanning => (200, 700),
            ScrollBehavior::Searching => (50, 200),
            ScrollBehavior::Idle => (2000, 8000),
        }
    }
}

// ── HumanScroller ────────────────────────────────────────────────────────

/// Configures the scroller.
#[derive(Debug, Clone)]
pub struct HumanScrollConfig {
    /// Total pixel distance to scroll over the session.
    pub total_px: i32,
    /// How the user intends to scroll.
    pub behavior: ScrollBehavior,
    /// Number of flick gestures to spread the total distance across.
    pub flick_count: usize,
    /// Whether scrolling is predominantly downward (`true`) or upward.
    pub scroll_down: bool,
    /// Physical wheel-device class (mouse wheel vs trackpad vs touch).
    /// Determines `WheelEvent.deltaMode` and delta granularity (G173 / G174).
    pub wheel_device: WheelDevice,
}

impl Default for HumanScrollConfig {
    fn default() -> Self {
        Self {
            total_px: 800,
            behavior: ScrollBehavior::Reading,
            flick_count: 5,
            scroll_down: true,
            wheel_device: WheelDevice::MouseWheel,
        }
    }
}

/// Human-like scroller driving a [`runtime_foxdriver::Page`] with momentum physics.
pub struct HumanScroller {
    config: HumanScrollConfig,
    /// Optional behavioral-telemetry sink for downstream scorers (G170).
    telemetry: Option<TelemetryCollector>,
}

impl HumanScroller {
    /// Build a scroller from a [`HumanScrollConfig`].
    #[must_use]
    pub fn new(config: HumanScrollConfig) -> Self {
        Self {
            config,
            telemetry: None,
        }
    }

    /// Set the wheel-device class used for scroll deltas (default: mouse wheel).
    pub fn with_wheel_device(mut self, device: WheelDevice) -> Self {
        self.config.wheel_device = device;
        self
    }

    /// Current wheel-device class.
    pub fn wheel_device(&self) -> WheelDevice {
        self.config.wheel_device
    }

    /// Attach a telemetry collector to record scroll events (G170).
    pub fn with_telemetry(mut self, telemetry: TelemetryCollector) -> Self {
        self.telemetry = Some(telemetry);
        self
    }

    /// Take the telemetry collector back, if one was attached.
    pub fn take_telemetry(&mut self) -> Option<TelemetryCollector> {
        self.telemetry.take()
    }

    fn record(&mut self, event: BehavioralEvent) {
        if let Some(ref mut t) = self.telemetry {
            t.record(event);
        }
    }

    /// Perform a full scroll session on `page` matching the configured behaviour.
    ///
    /// # Errors
    ///
    /// Returns any error raised while issuing the trusted BiDi wheel scrolls on
    /// the page.
    pub async fn scroll(&mut self, page: &Page) -> Result<()> {
        // Send-safe RNG so the future stays `Send` across the await points.
        let mut rng = StdRng::from_entropy();
        let direction: f64 = if self.config.scroll_down { 1.0 } else { -1.0 };

        // Distribute the total distance unevenly across flicks.
        let flick_amounts = self.distribute_flicks(&mut rng);

        for flick_px in flick_amounts {
            self.execute_flick(page, flick_px * direction, &mut rng)
                .await?;

            // Possible overshoot + correction.
            if chance_with_rng(self.config.behavior.overshoot_probability(), &mut rng) {
                let overshoot = rng.gen_range(30..120) as f64 * direction;
                self.scroll_by(page, overshoot).await?;
                tokio::time::sleep(Duration::from_millis(rng.gen_range(100..300))).await;
                // Scroll back ~60-90 % of the overshoot.
                let correction = overshoot * rng.gen_range(0.6_f64..0.9);
                self.scroll_by(page, -correction).await?;
                tokio::time::sleep(Duration::from_millis(rng.gen_range(80..200))).await;
            }

            // Pause between flicks.
            let (lo, hi) = self.config.behavior.pause_range_ms();
            let pause = rng.gen_range(lo..hi);
            tokio::time::sleep(Duration::from_millis(pause)).await;
        }

        Ok(())
    }

    /// Execute a single flick.
    ///
    /// The delta *shape* and the inter-step cadence both depend on the persona's
    /// wheel device, so the emitted stream is coherent with the recorded
    /// `deltaMode` (G173 / G174):
    ///
    /// * **Line-mode** devices (a classic mouse wheel) emit discrete, roughly
    ///   equal notches at detent cadence. NOT a smooth decay.
    /// * **Pixel-mode** devices (a trackpad) emit a smooth momentum-decay stream
    ///   at ~frame rate.
    async fn execute_flick<R: Rng + ?Sized>(
        &mut self,
        page: &Page,
        target_px: f64,
        rng: &mut R,
    ) -> Result<()> {
        let line_mode = self.config.wheel_device.properties().delta_mode == 1;
        let steps = self.plan_flick_steps(target_px, rng);
        for step in steps {
            self.scroll_by(page, step).await?;
            // Discrete wheel notches arrive far slower than a trackpad's ~60 fps
            // pixel stream; emitting notches at frame rate would itself be a tell.
            let gap = if line_mode {
                rng.gen_range(45..120)
            } else {
                rng.gen_range(16..32)
            };
            tokio::time::sleep(Duration::from_millis(gap)).await;
        }
        Ok(())
    }

    /// Choose the per-flick step sequence for the configured wheel device.
    ///
    /// Pure (no I/O) so the device→shape mapping is unit-testable: a line-mode
    /// device yields quantized notches ([`Self::wheel_notch_steps`]); a
    /// pixel-mode device yields the smooth momentum model ([`Self::flick_steps`]).
    fn plan_flick_steps<R: Rng + ?Sized>(&self, target_px: f64, rng: &mut R) -> Vec<f64> {
        if self.config.wheel_device.properties().delta_mode == 1 {
            Self::wheel_notch_steps(target_px, self.config.wheel_device, rng)
        } else {
            Self::flick_steps(target_px, self.config.behavior, rng)
        }
    }

    /// Discrete line-mode wheel notches whose pixel magnitudes sum to ~`target_px`.
    ///
    /// A classic mouse wheel emits one detent ("notch") at a time, each roughly
    /// `step_px` pixels (jittered via [`WheelDevice::delta_y`]), never a smooth
    /// momentum decay, which is a trackpad signature. The notch count is
    /// `target_px / step_px`; distance is honored only to whole-notch granularity
    /// because a real wheel user lands on a detent boundary, not an exact pixel.
    /// This is the production consumer of [`WheelDevice::delta_y`], so the
    /// declared per-device granularity actually reaches the wire.
    fn wheel_notch_steps<R: Rng + ?Sized>(
        target_px: f64,
        device: WheelDevice,
        rng: &mut R,
    ) -> Vec<f64> {
        let step = device.properties().step_px.max(1.0);
        let sign = if target_px < 0.0 { -1.0 } else { 1.0 };
        let notches = ((target_px.abs() / step).round() as usize).max(1);
        (0..notches)
            .map(|_| device.delta_y(1, rng) * sign)
            .collect()
    }

    /// Pure-physics step generator for a single flick. Separated from the async
    /// page driver so the momentum model is unit-testable.
    fn flick_steps<R: Rng + ?Sized>(
        target_px: f64,
        behavior: ScrollBehavior,
        rng: &mut R,
    ) -> Vec<f64> {
        let friction = behavior.friction();
        let base_v = behavior.base_velocity();
        // Jitter the initial velocity ±20 %.
        let mut velocity = base_v * (1.0 + rng.gen_range(-0.20_f64..0.20)) * target_px.signum();

        let mut remaining = target_px.abs();
        let mut steps = Vec::new();

        while remaining > 1.0 && velocity.abs() > 1.0 {
            let step = velocity.abs().min(remaining);
            steps.push(step * target_px.signum());
            remaining -= step;
            velocity *= friction;
            // Add tiny noise per tick so velocity decay isn't perfectly smooth.
            velocity += rng.gen_range(-2.0_f64..2.0);
        }

        // Mop up the <1 px residual so the requested distance is honored.
        if remaining > 0.0 {
            steps.push(remaining * target_px.signum());
        }

        steps
    }

    /// Distribute `total_px` among `flick_count` flicks using a Dirichlet-like
    /// random split: produces unequal amounts summing to `total_px`.
    fn distribute_flicks<R: Rng + ?Sized>(&self, rng: &mut R) -> Vec<f64> {
        let n = self.config.flick_count.max(1);
        // Draw exponential-ish weights.
        let weights: Vec<f64> = (0..n)
            .map(|_| {
                let u: f64 = rng.gen::<f64>().max(1e-12);
                -u.ln() // exponential distribution
            })
            .collect();
        let total_w: f64 = weights.iter().sum();
        weights
            .iter()
            .map(|w| (w / total_w) * f64::from(self.config.total_px))
            .collect()
    }

    /// Scroll by `dy` pixels via a TRUSTED BiDi wheel input and record the event.
    ///
    /// Routes through [`runtime_foxdriver::Page::scroll`] (a real `mouse().wheel`
    /// action), NOT `window.scrollBy`. A programmatic `window.scrollBy` moves the
    /// page while firing NO `wheel` event at all, a script listening for `wheel`
    /// sees the page scroll with zero wheel input, the cheapest possible bot tell,
    /// exactly the `isTrusted`-class signal the mouse path routes around. The real
    /// wheel input emits a trusted `wheel` event indistinguishable from hardware.
    ///
    /// The telemetry `deltaMode` is taken from the configured [`WheelDevice`] so
    /// the recorded stream matches the persona's input hardware (G173 / G174).
    async fn scroll_by(&mut self, page: &Page, dy: f64) -> Result<()> {
        // BiDi wheel deltas are integer pixels; round, and skip a no-op 0-delta
        // (which would emit a spurious zero-distance wheel event).
        let dy_int = dy.round() as i64;
        if dy_int != 0 {
            page.scroll(0, dy_int).await?;
        }
        let props = self.config.wheel_device.properties();
        self.record(BehavioralEvent::Scroll {
            ts: BehavioralEvent::now_ms(),
            delta_x: 0.0,
            delta_y: dy,
            delta_mode: props.delta_mode,
        });
        Ok(())
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    // ── ScrollBehavior parameter contracts ──────────────────────────────

    #[test]
    fn searching_faster_than_reading() {
        assert!(
            ScrollBehavior::Searching.base_velocity() > ScrollBehavior::Reading.base_velocity()
        );
    }

    #[test]
    fn idle_slowest_velocity() {
        assert!(ScrollBehavior::Idle.base_velocity() < ScrollBehavior::Reading.base_velocity());
    }

    #[test]
    fn friction_between_zero_and_one() {
        for b in [
            ScrollBehavior::Reading,
            ScrollBehavior::Scanning,
            ScrollBehavior::Searching,
            ScrollBehavior::Idle,
        ] {
            let f = b.friction();
            assert!(
                (0.0..=1.0).contains(&f),
                "friction {f} out of range for {b:?}"
            );
        }
    }

    #[test]
    fn searching_lowest_friction() {
        assert!(ScrollBehavior::Searching.friction() < ScrollBehavior::Reading.friction());
    }

    #[test]
    fn overshoot_probability_valid() {
        for b in [
            ScrollBehavior::Reading,
            ScrollBehavior::Scanning,
            ScrollBehavior::Searching,
            ScrollBehavior::Idle,
        ] {
            let p = b.overshoot_probability();
            assert!(
                (0.0..=1.0).contains(&p),
                "overshoot prob {p} out of range for {b:?}"
            );
        }
    }

    #[test]
    fn searching_highest_overshoot_prob() {
        assert!(
            ScrollBehavior::Searching.overshoot_probability()
                > ScrollBehavior::Reading.overshoot_probability()
        );
    }

    #[test]
    fn pause_range_lo_lt_hi() {
        for b in [
            ScrollBehavior::Reading,
            ScrollBehavior::Scanning,
            ScrollBehavior::Searching,
            ScrollBehavior::Idle,
        ] {
            let (lo, hi) = b.pause_range_ms();
            assert!(lo < hi, "pause range lo {lo} >= hi {hi} for {b:?}");
        }
    }

    #[test]
    fn idle_has_longest_pauses() {
        let (_, idle_hi) = ScrollBehavior::Idle.pause_range_ms();
        let (_, scanning_hi) = ScrollBehavior::Scanning.pause_range_ms();
        assert!(idle_hi > scanning_hi);
    }

    // ── distribute_flicks ────────────────────────────────────────────────

    #[test]
    fn distribute_flicks_correct_count() {
        let scroller = HumanScroller::new(HumanScrollConfig {
            flick_count: 7,
            ..Default::default()
        });
        let mut rng = StdRng::seed_from_u64(1);
        let flicks = scroller.distribute_flicks(&mut rng);
        assert_eq!(flicks.len(), 7);
    }

    #[test]
    fn distribute_flicks_sum_matches_total() {
        let total = 1200;
        let scroller = HumanScroller::new(HumanScrollConfig {
            total_px: total,
            flick_count: 6,
            ..Default::default()
        });
        let mut rng = StdRng::seed_from_u64(2);
        let flicks = scroller.distribute_flicks(&mut rng);
        let sum: f64 = flicks.iter().sum();
        assert!(
            (sum - f64::from(total)).abs() < 1.0,
            "sum {sum:.1} != {total}"
        );
    }

    #[test]
    fn distribute_flicks_all_positive() {
        let scroller = HumanScroller::new(HumanScrollConfig::default());
        let mut rng = StdRng::seed_from_u64(3);
        for _ in 0..20 {
            let flicks = scroller.distribute_flicks(&mut rng);
            for f in flicks {
                assert!(f > 0.0);
            }
        }
    }

    #[test]
    fn distribute_flicks_unequal() {
        // With random exponential weights, it is astronomically unlikely
        // that all flick amounts are identical.
        let scroller = HumanScroller::new(HumanScrollConfig {
            flick_count: 5,
            total_px: 1000,
            ..Default::default()
        });
        let mut rng = StdRng::seed_from_u64(4);
        let flicks = scroller.distribute_flicks(&mut rng);
        let first = flicks[0];
        let all_same = flicks.iter().all(|&f| (f - first).abs() < 0.01);
        assert!(!all_same, "expected unequal flick distribution");
    }

    // ── Flick physics (G139 / G140) ───────────────────────────────────────

    #[test]
    fn flick_steps_sum_to_target() {
        let mut rng = StdRng::seed_from_u64(11);
        // Use targets each behavior can realistically cover in one flick.
        let cases = [
            (ScrollBehavior::Reading, 100.0),
            (ScrollBehavior::Idle, 30.0),
            (ScrollBehavior::Scanning, 300.0),
            (ScrollBehavior::Searching, 800.0),
        ];
        for (behavior, target) in cases {
            let steps = HumanScroller::flick_steps(target, behavior, &mut rng);
            let sum: f64 = steps.iter().sum();
            assert!(
                (sum - target).abs() < 1.0,
                "{behavior:?}: flick steps sum {sum:.1} != {target}"
            );
        }
    }

    #[test]
    fn flick_steps_velocity_decays_to_zero() {
        let mut rng = StdRng::seed_from_u64(22);
        let steps = HumanScroller::flick_steps(500.0, ScrollBehavior::Searching, &mut rng);
        assert!(
            !steps.is_empty(),
            "a non-zero flick must produce at least one step"
        );
        // Step magnitudes should generally decrease as friction drains velocity.
        let first = steps[0].abs();
        let last = steps.last().unwrap().abs();
        assert!(
            last < first,
            "final step {last:.1} should be smaller than initial {first:.1} due to friction"
        );
    }

    #[test]
    fn searching_behavior_uses_fewer_stronger_steps_than_reading() {
        // G139/G140: scanning/searching intent produces larger initial-step
        // magnitudes than reading because of higher base velocity.
        let mut rng = StdRng::seed_from_u64(33);
        let reading = HumanScroller::flick_steps(100.0, ScrollBehavior::Reading, &mut rng);
        let searching = HumanScroller::flick_steps(100.0, ScrollBehavior::Searching, &mut rng);
        let reading_first = reading.first().map(|s| s.abs()).unwrap_or(0.0);
        let searching_first = searching.first().map(|s| s.abs()).unwrap_or(0.0);
        assert!(
            searching_first > reading_first,
            "searching initial step {searching_first:.1} should exceed reading {reading_first:.1}"
        );
    }

    #[test]
    fn flick_steps_finite_for_all_behaviors() {
        let mut rng = StdRng::seed_from_u64(44);
        for behavior in [
            ScrollBehavior::Reading,
            ScrollBehavior::Scanning,
            ScrollBehavior::Searching,
            ScrollBehavior::Idle,
        ] {
            let steps = HumanScroller::flick_steps(2_000.0, behavior, &mut rng);
            assert!(
                steps.len() < 200,
                "{behavior:?}: flick did not terminate ({} steps)",
                steps.len()
            );
        }
    }

    // ── HumanScrollConfig defaults ────────────────────────────────────────

    #[test]
    fn default_config_sane() {
        let cfg = HumanScrollConfig::default();
        assert!(cfg.total_px > 0);
        assert!(cfg.flick_count > 0);
        assert!(cfg.scroll_down);
        assert_eq!(cfg.behavior, ScrollBehavior::Reading);
    }

    // ── Wheel-device coherence (G173 / G174) ───────────────────────────────

    #[test]
    fn default_scroller_uses_mouse_wheel() {
        let scroller = HumanScroller::new(HumanScrollConfig::default());
        assert_eq!(scroller.wheel_device(), WheelDevice::MouseWheel);
    }

    #[test]
    fn scroller_can_switch_to_trackpad() {
        let scroller = HumanScroller::new(HumanScrollConfig::default())
            .with_wheel_device(WheelDevice::Trackpad);
        assert_eq!(scroller.wheel_device(), WheelDevice::Trackpad);
    }

    #[test]
    fn trackpad_config_uses_pixel_mode() {
        let cfg = HumanScrollConfig {
            wheel_device: WheelDevice::Trackpad,
            ..Default::default()
        };
        assert_eq!(cfg.wheel_device.properties().delta_mode, 0);
    }

    #[test]
    fn touch_config_does_not_emit_wheel() {
        let cfg = HumanScrollConfig {
            wheel_device: WheelDevice::Touch,
            ..Default::default()
        };
        assert!(!cfg.wheel_device.properties().emits_wheel_events);
    }

    // ── Wheel-device delta SHAPE coherence (the live-path fix) ──────────────
    //
    // Before: every device used the smooth momentum decay (a trackpad signature)
    // while the default MouseWheel persona recorded deltaMode=1 (line mode), an
    // incoherent stream, and `WheelDevice::delta_y` was dead test-only code.

    #[test]
    fn mouse_wheel_emits_uniform_coarse_notches() {
        // The default (mouse-wheel) persona must emit discrete ~step_px notches,
        // not a decaying flick. delta_y(1) for a mouse wheel is 100 ± 8 px.
        let scroller = HumanScroller::new(HumanScrollConfig::default());
        assert_eq!(scroller.wheel_device(), WheelDevice::MouseWheel);
        let mut rng = StdRng::seed_from_u64(7);
        let steps = scroller.plan_flick_steps(500.0, &mut rng);
        // ~5 notches for 500 px at 100 px/notch.
        assert!(
            (4..=6).contains(&steps.len()),
            "expected ~5 notches for 500px, got {}",
            steps.len()
        );
        for s in &steps {
            assert!(
                (90.0..=110.0).contains(&s.abs()),
                "notch {s:.1} is not a ~100px line-mode notch (delta_y jitter is ±8)"
            );
        }
        // Notches are uniform, NOT a friction decay: first ≈ last.
        let first = steps.first().unwrap().abs();
        let last = steps.last().unwrap().abs();
        assert!(
            (first - last).abs() < 20.0,
            "wheel notches must be uniform, not decaying: first {first:.1} last {last:.1}"
        );
    }

    #[test]
    fn trackpad_emits_smooth_non_notch_stream() {
        // A pixel-mode device keeps the smooth momentum model, so its steps are
        // NOT all clustered in the narrow mouse-wheel notch band.
        let scroller = HumanScroller::new(HumanScrollConfig {
            behavior: ScrollBehavior::Searching,
            ..Default::default()
        })
        .with_wheel_device(WheelDevice::Trackpad);
        let mut rng = StdRng::seed_from_u64(7);
        let steps = scroller.plan_flick_steps(500.0, &mut rng);
        assert!(
            !steps.iter().all(|s| (90.0..=110.0).contains(&s.abs())),
            "trackpad must not emit uniform mouse-wheel notches: {steps:?}"
        );
    }

    #[test]
    fn mouse_wheel_notch_count_scales_with_distance() {
        let mut rng = StdRng::seed_from_u64(99);
        let ten = HumanScroller::wheel_notch_steps(1000.0, WheelDevice::MouseWheel, &mut rng);
        let two = HumanScroller::wheel_notch_steps(200.0, WheelDevice::MouseWheel, &mut rng);
        assert!(
            (9..=11).contains(&ten.len()),
            "1000px should be ~10 notches, got {}",
            ten.len()
        );
        assert!(
            (1..=3).contains(&two.len()),
            "200px should be ~2 notches, got {}",
            two.len()
        );
    }

    #[test]
    fn mouse_wheel_notches_follow_scroll_direction() {
        let mut rng = StdRng::seed_from_u64(5);
        let up = HumanScroller::wheel_notch_steps(-400.0, WheelDevice::MouseWheel, &mut rng);
        assert!(!up.is_empty());
        for s in &up {
            assert!(*s < 0.0, "upward scroll notch {s:.1} must be negative");
        }
    }

    #[test]
    fn sub_notch_distance_still_emits_one_notch() {
        // A target smaller than a single detent is still at least one notch, a
        // wheel cannot move less than one detent.
        let mut rng = StdRng::seed_from_u64(3);
        let steps = HumanScroller::wheel_notch_steps(10.0, WheelDevice::MouseWheel, &mut rng);
        assert_eq!(
            steps.len(),
            1,
            "sub-notch distance must round up to one notch"
        );
        assert!((90.0..=110.0).contains(&steps[0].abs()));
    }
}
