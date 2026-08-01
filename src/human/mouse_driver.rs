/// Enhanced human-like mouse simulation (BiDi/Firefox).
///
/// Extends basic movement with Fitts' Law, overshoots, and persona styles.
use anyhow::Result;
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use runtime_foxdriver::browser::Page;
use std::time::Duration;

use crate::choice::chance_with_rng;
use crate::human::behavioral_grammar::{Motion, Trajectory};
use crate::human::mouse::MouseSampler;
use crate::human::pointer::PointerDevice;
use crate::human::telemetry::{BehavioralEvent, TelemetryCollector};
use crate::human::timing::jittered_step;

// ── MousePersona ──────────────────────────────────────────────────────────

/// Describes the overall mouse behaviour style of a simulated user.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MousePersona {
    /// Moves slowly, hovers before clicking, rarely overshoots.
    Careful,
    /// Balanced speed and accuracy (the default).
    Normal,
    /// Fast movement, sometimes imprecise, clicks quickly.
    Rushed,
    /// Very fast, direct paths, almost no hesitation.
    PowerUser,
}

impl MousePersona {
    fn speed_px_per_sec(&self) -> f64 {
        match self {
            MousePersona::Careful => 300.0,
            MousePersona::Normal => 600.0,
            MousePersona::Rushed => 1_000.0,
            MousePersona::PowerUser => 1_500.0,
        }
    }

    fn overshoot_prob(&self) -> f64 {
        match self {
            MousePersona::Careful => 0.05,
            MousePersona::Normal => 0.12,
            MousePersona::Rushed => 0.25,
            MousePersona::PowerUser => 0.08,
        }
    }

    fn curve_noise_px(&self) -> f64 {
        match self {
            MousePersona::Careful => 10.0,
            MousePersona::Normal => 25.0,
            MousePersona::Rushed => 40.0,
            MousePersona::PowerUser => 15.0,
        }
    }

    pub(crate) fn click_hold_range_ms(&self) -> (u64, u64) {
        match self {
            MousePersona::Careful => (80, 200),
            MousePersona::Normal => (50, 150),
            MousePersona::Rushed => (30, 80),
            MousePersona::PowerUser => (20, 60),
        }
    }

    fn drift_amplitude_px(&self) -> f64 {
        match self {
            MousePersona::Careful => 3.0,
            MousePersona::Normal => 5.0,
            MousePersona::Rushed => 2.0,
            MousePersona::PowerUser => 1.0,
        }
    }
}

// ── HumanMouse ───────────────────────────────────────────────────────────

/// Enhanced mouse that respects Fitts' Law, overshoots, and persona styles.
pub struct HumanMouse {
    pub(crate) persona: MousePersona,
    /// Current horizontal cursor position, tracked locally.
    pub cursor_x: f64,
    /// Current vertical cursor position, tracked locally.
    pub cursor_y: f64,
    /// Physical pointer-device class (mouse/touch/stylus) controlling event
    /// properties such as pressure and tilt (G171 / G172).
    pub(crate) pointer_device: PointerDevice,
    /// Optional behavioral-telemetry sink for downstream scorers (G170).
    telemetry: Option<TelemetryCollector>,
    /// Real-human mouse-trace corpus driving move geometry. Replaces the single
    /// cubic-Bézier path whose constant curvature signature ML behavioural
    /// classifiers flag (see [`crate::human::mouse`]).
    sampler: MouseSampler,
}

impl HumanMouse {
    /// Create a mouse simulator at the viewport origin.
    pub fn new(persona: MousePersona) -> Self {
        Self {
            persona,
            cursor_x: 0.0,
            cursor_y: 0.0,
            pointer_device: PointerDevice::Mouse,
            telemetry: None,
            sampler: MouseSampler::new(),
        }
    }

    /// Create a mouse simulator with an existing cursor position.
    pub fn with_position(persona: MousePersona, x: f64, y: f64) -> Self {
        Self {
            persona,
            cursor_x: x,
            cursor_y: y,
            pointer_device: PointerDevice::Mouse,
            telemetry: None,
            sampler: MouseSampler::new(),
        }
    }

    /// Set the physical pointer-device class (default: mouse).
    pub fn with_pointer_device(mut self, device: PointerDevice) -> Self {
        self.pointer_device = device;
        self
    }

    /// Current pointer-device class.
    pub fn pointer_device(&self) -> PointerDevice {
        self.pointer_device
    }

    /// Expected `PointerEvent` properties for the current device.
    pub fn pointer_properties(&self) -> crate::human::pointer::PointerProperties {
        self.pointer_device.properties()
    }

    /// Attach a telemetry collector to record pointer events (G170).
    pub fn with_telemetry(mut self, telemetry: TelemetryCollector) -> Self {
        self.telemetry = Some(telemetry);
        self
    }

    /// Take the telemetry collector back, if one was attached.
    pub fn take_telemetry(&mut self) -> Option<TelemetryCollector> {
        self.telemetry.take()
    }

    pub(crate) fn record(&mut self, event: BehavioralEvent) {
        if let Some(ref mut t) = self.telemetry {
            t.record(event);
        }
    }

    /// Move the cursor to `(tx, ty)` with persona-specific curves.
    pub async fn move_to(
        &mut self,
        page: &Page,
        tx: f64,
        ty: f64,
        target_size_px: f64,
    ) -> Result<()> {
        let mut rng = rand::thread_rng();
        let x0 = self.cursor_x;
        let y0 = self.cursor_y;

        let dist = distance(x0, y0, tx, ty).max(1.0);
        let base_steps = fitts_steps(dist, target_size_px, self.persona.speed_px_per_sec());
        let steps = base_steps.clamp(6, 40);

        // Geometry comes from the real-human trace corpus, NOT a single cubic
        // Bézier, the corpus carries sub-movements, tremor, and overshoot-
        // correction that a smooth Bézier lacks (and that ML behavioural classifiers
        // train on). The path lands EXACTLY on (tx, ty) so the click hits its target;
        // the persona's curve-noise scales the interior sub-pixel wander. Timing,
        // easing, overshoot, and trusted dispatch below are unchanged.
        let path = self.sampler.resampled_path(
            x0,
            y0,
            tx,
            ty,
            steps + 1,
            self.persona.curve_noise_px() * 0.12,
            &mut rng,
        );

        for (i, &(x, y)) in path.iter().enumerate().take(steps + 1) {
            let t = i as f64 / steps as f64;

            dispatch_mouse_moved(page, x, y).await?;
            let props = self.pointer_device.properties();
            self.record(BehavioralEvent::PointerMove {
                ts: BehavioralEvent::now_ms(),
                x,
                y,
                pressure: props.hover_pressure,
                twist: self.pointer_device.sample_twist(&mut rand::thread_rng()),
            });

            let ease = (std::f64::consts::PI * t).sin();
            let step_ms =
                step_delay_ms(dist, steps, self.persona.speed_px_per_sec(), ease, &mut rng);
            tokio::time::sleep(Duration::from_millis(step_ms)).await;
        }

        // Overshoot on small targets.
        if target_size_px < 20.0 && chance_with_rng(self.persona.overshoot_prob(), &mut rng) {
            let overshoot_px = rng.gen_range(3.0_f64..12.0);
            let angle = (ty - y0).atan2(tx - x0);
            let ox = tx + overshoot_px * angle.cos();
            let oy = ty + overshoot_px * angle.sin();
            dispatch_mouse_moved(page, ox, oy).await?;
            self.record(BehavioralEvent::PointerMove {
                ts: BehavioralEvent::now_ms(),
                x: ox,
                y: oy,
                pressure: self.pointer_device.properties().hover_pressure,
                twist: self.pointer_device.sample_twist(&mut rand::thread_rng()),
            });
            tokio::time::sleep(Duration::from_millis(rng.gen_range(40..100))).await;
            dispatch_mouse_moved(page, tx, ty).await?;
            self.record(BehavioralEvent::PointerMove {
                ts: BehavioralEvent::now_ms(),
                x: tx,
                y: ty,
                pressure: self.pointer_device.properties().hover_pressure,
                twist: self.pointer_device.sample_twist(&mut rand::thread_rng()),
            });
            tokio::time::sleep(Duration::from_millis(rng.gen_range(30..80))).await;
        }

        self.cursor_x = tx;
        self.cursor_y = ty;
        Ok(())
    }

    /// Click at `(x, y)` with persona-specific hold time.
    pub async fn click(&mut self, page: &Page, x: f64, y: f64, target_size_px: f64) -> Result<()> {
        let mut rng = rand::thread_rng();
        self.move_to(page, x, y, target_size_px).await?;
        let (lo, hi) = self.persona.click_hold_range_ms();
        let hold_ms = rng.gen_range(lo..hi);
        let ts = BehavioralEvent::now_ms();
        self.record(BehavioralEvent::PointerDown {
            ts,
            x,
            y,
            button: 0,
            pressure: self
                .pointer_device
                .sample_active_pressure(&mut rand::thread_rng()),
        });
        page.click_at(x, y).await?;
        self.record(BehavioralEvent::PointerUp {
            ts: BehavioralEvent::now_ms(),
            x,
            y,
            button: 0,
            pressure: self.pointer_device.properties().hover_pressure,
        });
        tokio::time::sleep(Duration::from_millis(hold_ms)).await;
        Ok(())
    }

    /// Simulate cursor idle drift.
    pub async fn idle_drift(
        &mut self,
        page: &Page,
        duration: Duration,
        interval_ms: u64,
    ) -> Result<()> {
        let mut rng = rand::thread_rng();
        let ticks = (duration.as_millis() / interval_ms.max(1) as u128) as u32;
        let amp = self.persona.drift_amplitude_px();

        for _ in 0..ticks {
            let dx = rng.gen_range(-amp..amp);
            let dy = rng.gen_range(-amp..amp);
            let nx = (self.cursor_x + dx).max(0.0);
            let ny = (self.cursor_y + dy).max(0.0);
            dispatch_mouse_moved(page, nx, ny).await?;
            self.cursor_x = nx;
            self.cursor_y = ny;
            self.record(BehavioralEvent::PointerMove {
                ts: BehavioralEvent::now_ms(),
                x: nx,
                y: ny,
                pressure: self.pointer_device.properties().hover_pressure,
                twist: self.pointer_device.sample_twist(&mut rand::thread_rng()),
            });
            // Jitter the drift cadence: a real idle hand tremors at an uneven
            // rhythm, a fixed `interval_ms` tick is a robotic signature (G143).
            tokio::time::sleep(jittered_step(
                Duration::from_millis(interval_ms),
                0.30,
                &mut rng,
            ))
            .await;
        }
        Ok(())
    }

    /// Play a [`Trajectory`] (from the behavioural-grammar PCFG) through the
    /// **trusted** BiDi pointer path (the stealth delivery for the grammar model).
    ///
    /// This is the counterpart to
    /// [`crate::human::behavioral_grammar::render_to_js`], which dispatches the
    /// same shape via DOM `dispatchEvent` and therefore arrives
    /// `isTrusted === false` (the single cheapest bot tell). Here every motion
    /// sample is routed through `Page::move_mouse_to` (a hardware-
    /// indistinguishable pointer move) and the terminal `Click` through
    /// `Page::click_at`, so the sophisticated multi-inflection trajectory the
    /// PCFG produces is actually undetectable instead of being negated by an
    /// untrusted dispatch. Per-sample `dt_ms` pacing is honored.
    ///
    /// The cursor position is updated as the trajectory plays, so a subsequent
    /// [`Self::move_to`] continues from where this left off.
    pub async fn follow_trajectory(&mut self, page: &Page, trajectory: &Trajectory) -> Result<()> {
        // StdRng (not ThreadRng) keeps the future `Send` across the awaits, and
        // satisfies `Motion::render`'s `&mut StdRng` contract.
        let mut rng = StdRng::from_entropy();
        for motion in &trajectory.motions {
            // The terminal click carries real button state, press/release via the
            // trusted path, not a position sample.
            if let Motion::Click { at, hold_ms } = motion {
                let ts = BehavioralEvent::now_ms();
                self.record(BehavioralEvent::PointerDown {
                    ts,
                    x: at.0,
                    y: at.1,
                    button: 0,
                    pressure: self.pointer_device.sample_active_pressure(&mut rng),
                });
                page.click_at(at.0, at.1).await?;
                self.record(BehavioralEvent::PointerUp {
                    ts: BehavioralEvent::now_ms(),
                    x: at.0,
                    y: at.1,
                    button: 0,
                    pressure: self.pointer_device.properties().hover_pressure,
                });
                self.cursor_x = at.0;
                self.cursor_y = at.1;
                tokio::time::sleep(Duration::from_millis(*hold_ms)).await;
                continue;
            }
            for s in motion.render(&mut rng) {
                dispatch_mouse_moved(page, s.x, s.y).await?;
                self.record(BehavioralEvent::PointerMove {
                    ts: BehavioralEvent::now_ms(),
                    x: s.x,
                    y: s.y,
                    pressure: self.pointer_device.properties().hover_pressure,
                    twist: self.pointer_device.sample_twist(&mut rng),
                });
                self.cursor_x = s.x;
                self.cursor_y = s.y;
                tokio::time::sleep(Duration::from_millis(s.dt_ms)).await;
            }
        }
        Ok(())
    }
}

// ── helpers ───────────────────────────────────────────────────────────────

fn distance(x0: f64, y0: f64, x1: f64, y1: f64) -> f64 {
    ((x1 - x0).powi(2) + (y1 - y0).powi(2)).sqrt()
}

fn fitts_steps(dist_px: f64, target_size_px: f64, speed_px_s: f64) -> usize {
    // Fitts' Law: MT = a + b * ID, where ID = log2(2D / W).
    // Constants are tuned so ordinary viewport distances produce a plausible
    // number of ~16 ms motion events (roughly 6–40 steps, matching the clamp
    // applied by move_to).
    let w = target_size_px.max(1.0);
    let id = (2.0 * dist_px / w).log2().max(0.5);
    let mt_ms = (80.0 + 70.0 * id) * (600.0 / speed_px_s);
    (mt_ms / 16.0).round() as usize
}

fn step_delay_ms<R: Rng>(dist: f64, steps: usize, speed_px_s: f64, ease: f64, rng: &mut R) -> u64 {
    let total_ms = dist / speed_px_s * 1000.0;
    let avg_ms = (total_ms / steps as f64).max(4.0);
    let adjusted = avg_ms * (1.5 - ease * 0.5);
    let jitter: f64 = rng.gen_range(-3.0..3.0);
    (adjusted + jitter).clamp(4.0, 60.0) as u64
}

async fn dispatch_mouse_moved(page: &Page, x: f64, y: f64) -> Result<()> {
    // TRUSTED dispatch. A synthetic `document.dispatchEvent(new
    // MouseEvent('mousemove', …))` arrives with `isTrusted === false`: the
    // single cheapest tell an anti-bot scorer has, which would nullify this
    // whole Fitts-law / persona trajectory. Route the point through the real
    // BiDi pointer-move path so every sampled move is indistinguishable from a
    // hardware mouse and reaches cross-origin frames.
    page.move_mouse_to(x, y).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn power_user_faster_than_careful() {
        assert!(
            MousePersona::PowerUser.speed_px_per_sec() > MousePersona::Careful.speed_px_per_sec()
        );
    }

    #[test]
    fn rushed_has_highest_overshoot() {
        assert!(MousePersona::Rushed.overshoot_prob() > MousePersona::Careful.overshoot_prob());
    }

    #[test]
    fn careful_has_smallest_noise() {
        assert!(MousePersona::Careful.curve_noise_px() < MousePersona::Rushed.curve_noise_px());
    }

    #[test]
    fn click_hold_lo_lt_hi() {
        for persona in [
            MousePersona::Careful,
            MousePersona::Normal,
            MousePersona::Rushed,
            MousePersona::PowerUser,
        ] {
            let (lo, hi) = persona.click_hold_range_ms();
            assert!(lo < hi, "{persona:?}: hold range lo {lo} >= hi {hi}");
        }
    }

    #[test]
    fn all_personas_have_positive_drift() {
        for persona in [
            MousePersona::Careful,
            MousePersona::Normal,
            MousePersona::Rushed,
            MousePersona::PowerUser,
        ] {
            assert!(persona.drift_amplitude_px() > 0.0);
        }
    }

    #[test]
    fn fitts_steps_increases_with_distance() {
        // Same target size, farther distance → higher Fitts ID → more steps.
        let steps_near = fitts_steps(50.0, 20.0, 600.0);
        let steps_far = fitts_steps(500.0, 20.0, 600.0);
        assert!(
            steps_far > steps_near,
            "far steps {steps_far} should exceed near steps {steps_near}"
        );
    }

    #[test]
    fn fitts_steps_increases_with_target_difficulty() {
        // G132: smaller targets (higher Fitts ID) require more steps at the
        // same distance and speed.
        let easy = fitts_steps(300.0, 200.0, 600.0);
        let hard = fitts_steps(300.0, 10.0, 600.0);
        assert!(
            hard > easy,
            "hard target steps {hard} should exceed easy target steps {easy}"
        );
    }

    #[test]
    fn fitts_steps_is_bounded_and_non_zero() {
        // Realistic viewport distances and target sizes. The move_to() caller
        // clamps the result to [6, 40], but fitts_steps itself must never
        // return zero and should stay reasonable for ordinary inputs.
        for (dist, w) in [
            (10.0_f64, 5.0_f64),
            (800.0_f64, 20.0_f64),
            (100.0_f64, 200.0_f64),
        ] {
            let steps = fitts_steps(dist, w, 600.0);
            assert!(steps > 0, "dist={dist} w={w} produced zero steps");
            assert!(
                steps <= 80,
                "dist={dist} w={w} produced unrealistic {steps} steps"
            );
        }
    }

    #[test]
    fn distance_3_4_5_triangle() {
        let d = distance(0.0, 0.0, 3.0, 4.0);
        assert!((d - 5.0).abs() < 1e-6);
    }

    #[test]
    fn new_mouse_starts_at_origin() {
        let m = HumanMouse::new(MousePersona::Normal);
        assert_eq!(m.cursor_x, 0.0);
        assert_eq!(m.cursor_y, 0.0);
    }
}
