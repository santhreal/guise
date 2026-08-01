/// Human-like typing simulation.
///
/// This is the single browser-backed typing executor for guise.  It delegates
/// all timing decisions to the canonical [`crate::human::keystroke`] planner
/// (per-bigram gaps, hold-time envelopes, typo injection, thinking pauses) and
/// only adds the thin async dispatch over a `runtime_foxdriver::Page`.
///
/// There is intentionally NO second WPM/category timing model here: the WPM
/// target is translated into a speed multiplier on the bigram model
/// ([`crate::human::TypingPlan::with_wpm`]), so every keystroke passes through
/// one coherent planner (G135).
use anyhow::Result;
use rand::{Rng, SeedableRng};
use runtime_foxdriver::Page;
use std::time::Duration;

use crate::human::keyboard_event::{
    key_to_bidi_dispatch_key, key_to_code, key_to_key_value, needs_shift,
};
use crate::human::keystroke::{plan_keystrokes, TypingPlan};
use crate::human::telemetry::{BehavioralEvent, TelemetryCollector};

/// Configuration for the human typer.
#[derive(Debug, Clone)]
pub struct TypingConfig {
    /// Target words-per-minute (40–80 is realistic for most people).
    pub wpm: f64,
    /// Probability of producing a typo on any given character (0.0–1.0).
    pub typo_rate: f64,
    /// Extra delay before uppercase characters to simulate shift-key press (ms).
    pub shift_delay_ms: u64,
}

impl Default for TypingConfig {
    fn default() -> Self {
        Self {
            wpm: 60.0,
            typo_rate: 0.03,
            shift_delay_ms: 80,
        }
    }
}

impl TypingConfig {
    /// Build a config targeting the given WPM (clamped to 40–80).
    pub fn with_wpm(wpm: f64) -> Self {
        Self {
            wpm: wpm.clamp(40.0, 80.0),
            ..Default::default()
        }
    }

    /// Convert this config into the canonical planner configuration.
    fn to_plan(&self) -> TypingPlan {
        TypingPlan {
            typo_probability: self.typo_rate.clamp(0.0, 1.0) as f32,
            ..TypingPlan::with_wpm(self.wpm)
        }
    }
}

/// Human-like typer. Construct once and reuse across multiple calls.
pub struct HumanTyper {
    config: TypingConfig,
    /// Optional behavioral-telemetry sink for downstream scorers (G170).
    telemetry: Option<TelemetryCollector>,
}

impl HumanTyper {
    /// Create a typer with the supplied cadence and typo configuration.
    pub fn new(config: TypingConfig) -> Self {
        Self {
            config,
            telemetry: None,
        }
    }

    /// Attach a telemetry collector to record keystroke events (G170).
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

    /// Type `text` into the currently focused element on `page`.
    ///
    /// The actual timing is produced by [`plan_keystrokes`]; this method only
    /// sleeps and dispatches `keydown`/`keyup` events so every event is trusted.
    pub async fn type_text(&mut self, page: &Page, text: &str) -> Result<()> {
        let mut rng = rand::rngs::StdRng::from_entropy();
        let plan = self.config.to_plan();
        let keystrokes = plan_keystrokes(text, plan, &mut rng);

        for k in keystrokes {
            if k.gap_ms_before > 0 {
                tokio::time::sleep(Duration::from_millis(k.gap_ms_before as u64)).await;
            }

            // The planner carries Backspace/Enter/Tab as control characters
            // ('\u{0008}', '\n'/'\r', '\t'). Two distinct strings are derived:
            //
            //  * `key_name`: the DOM `KeyboardEvent.key` ("Backspace"/"Enter"/
            //    "Tab" or the printable char) recorded in telemetry so the G170
            //    stream matches what the page actually sees (the old code logged
            //    the raw "\n", disagreeing with the real event's "Enter").
            //  * `dispatch`: the WebDriver-BiDi value to send. For a newline this
            //    is U+E006 (main Enter, code "Enter"), NOT the driver's named
            //    "Enter" which resolves to U+E007 (NumpadEnter), a key a real
            //    typist never uses for text. Printable chars / Backspace / Tab are
            //    identical to `key_name`.
            let key_name = key_to_key_value(k.ch);
            let dispatch = key_to_bidi_dispatch_key(k.ch);

            // A character that requires Shift on a real keyboard (uppercase
            // letters, shifted symbols) MUST be wrapped in a genuine Shift
            // keydown/keyup. Gecko does not synthesise Shift for a bare "H"/"!"
            // sent over BiDi, the resulting keydown carries shiftKey===false with
            // no ShiftLeft, which is impossible for real typed input and a
            // keystroke-dynamics tell (proven live, tests/shift_key_live.rs).
            // No control character (Backspace/Enter/Tab) requires Shift.
            let shifted = needs_shift(k.ch);
            if shifted {
                self.record(BehavioralEvent::KeyDown {
                    ts: BehavioralEvent::now_ms(),
                    key: "Shift".to_string(),
                    code: "ShiftLeft".to_string(),
                });
                page.key_down("Shift").await?;
                // Shift-to-key latency: a real typist depresses Shift slightly
                // before the letter, not simultaneously with it.
                if self.config.shift_delay_ms > 0 {
                    tokio::time::sleep(Duration::from_millis(
                        self.config.shift_delay_ms + rng.gen_range(0..40),
                    ))
                    .await;
                }
            }

            let code = key_to_code(k.ch);
            let ts = BehavioralEvent::now_ms();
            self.record(BehavioralEvent::KeyDown {
                ts,
                key: key_name.clone(),
                code: code.clone(),
            });
            page.key_down(&dispatch).await?;
            tokio::time::sleep(Duration::from_millis(k.hold_ms as u64)).await;
            page.key_up(&dispatch).await?;
            self.record(BehavioralEvent::KeyUp {
                ts: BehavioralEvent::now_ms(),
                key: key_name,
                code,
            });

            // Release Shift after the character, completing the human-coherent
            // Shift↓ · char↓ · char↑ · Shift↑ envelope.
            if shifted {
                page.key_up("Shift").await?;
                self.record(BehavioralEvent::KeyUp {
                    ts: BehavioralEvent::now_ms(),
                    key: "Shift".to_string(),
                    code: "ShiftLeft".to_string(),
                });
            }
        }

        Ok(())
    }
}

impl Default for HumanTyper {
    fn default() -> Self {
        Self::new(TypingConfig::default())
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_wpm_in_range() {
        let cfg = TypingConfig::default();
        assert!(cfg.wpm >= 40.0 && cfg.wpm <= 80.0);
    }

    #[test]
    fn default_typer_uses_default_config() {
        let typer = HumanTyper::default();
        assert_eq!(typer.config.wpm, TypingConfig::default().wpm);
        assert_eq!(typer.config.typo_rate, TypingConfig::default().typo_rate);
    }

    #[test]
    fn with_wpm_clamps_low() {
        let cfg = TypingConfig::with_wpm(10.0);
        assert_eq!(cfg.wpm, 40.0);
    }

    #[test]
    fn with_wpm_clamps_high() {
        let cfg = TypingConfig::with_wpm(200.0);
        assert_eq!(cfg.wpm, 80.0);
    }

    #[test]
    fn with_wpm_exact() {
        let cfg = TypingConfig::with_wpm(55.0);
        assert!((cfg.wpm - 55.0).abs() < f64::EPSILON);
    }

    #[test]
    fn config_to_plan_preserves_wpm() {
        let cfg = TypingConfig::with_wpm(50.0);
        let plan = cfg.to_plan();
        assert!((plan.speed_factor - 60.0 / 50.0).abs() < 0.001);
        assert_eq!(plan.typo_probability, cfg.typo_rate as f32);
    }

    #[test]
    fn config_to_plan_clamps_typo_rate() {
        let cfg = TypingConfig {
            typo_rate: 2.0,
            ..Default::default()
        };
        let plan = cfg.to_plan();
        assert_eq!(plan.typo_probability, 1.0);
    }

    #[test]
    fn config_shift_delay_positive() {
        let cfg = TypingConfig::default();
        assert!(cfg.shift_delay_ms > 0);
    }
}
