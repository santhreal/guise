//! Human-behavior emulation: timing and motion drawn from real human data so an
//! automated session is indistinguishable from a person at the input layer.
//!
//! ## Detector-class contract (G179)
//!
//! The behavioral layer defends against **input-timing and motion classifiers**:
//! non-uniform keystroke cadence, Fitts-curve mouse paths, human-distributed click
//! offsets, momentum scroll physics, and plausible read/think pauses. It does NOT
//! defend against fingerprint-class detectors (JS engine/UA/TLS/network tells) or
//! CAPTCHA image challenges; those are owned by [`crate::fingerprint`],
//! [`crate::probe`], and captchaforge respectively.
//!
//! The module is the stable, reusable crate surface for captchaforge and Meridian
//! to drive human-like input (G180).
//!
//! - [`keystroke`], per-bigram gap + hold-time envelopes, typo injection, and a
//!   [`TypingPlan`] (always available; no browser feature required).
//! - [`typing`], single browser-backed `HumanTyper` executor; all timing is
//!   delegated to [`keystroke`], so there is one typing model in the crate.
//! - [`attention`]. F/Z-pattern gaze planning: where a human looks and for how
//!   long (pure; planner only, no browser).
//! - [`timing`], reading-time, think-time, session fatigue/burst pacing, and
//!   challenge-mode adaptive slowdown (pure sampling; the `browser` feature adds
//!   `async` sleep wrappers).
//! - [`behavior`] / [`behavioral_grammar`], high-level orchestration, key
//!   combos, and a PCFG over motion terminals (`browser` feature).
//! - [`detector_fixture`], minimal timing-classifier fixture for A/B scoring
//!   the human layer vs. a uniform bot cadence (G178).
//! - [`mouse`] (synthetic mouse-motion sampling (`browser` feature)).
//! - [`pointer`], pointer-device persona model: pressure, tilt, twist coherence
//!   (`browser` feature; G171 / G172).
//! - [`element_interaction`]. DOM-aware move/click/hover with human-distributed
//!   offsets and visibility/disabled guards (`browser` feature).
//! - [`scroll`], momentum-physics scroll engine with overshoot/correction and
//!   per-intent cadence profiles (`browser` feature).
//! - [`telemetry`], normalized behavioral event stream consumed by downstream
//!   scorers such as captchaforge (G170).
//! - [`wheel`], wheel-event persona model: `deltaMode` and granularity per
//!   device class (G173 / G174).
//! - [`keyboard_event`]. `KeyboardEvent` sequence planner (`code` vs `key` vs
//!   layout) (G175 / G176).
//!
//! All timing is deterministic given a seeded `Rng`, so a session can be
//! reproduced exactly for testing.

pub mod attention;
#[cfg(feature = "browser")]
pub mod behavior;
#[cfg(feature = "browser")]
pub mod behavioral_grammar;
pub mod detector_fixture;
#[cfg(feature = "browser")]
pub mod element_interaction;
pub mod ime;
pub mod keyboard_event;
pub mod keystroke;
#[cfg(feature = "browser")]
pub mod mouse;
#[cfg(feature = "browser")]
mod mouse_driver;
#[cfg(feature = "browser")]
pub mod pointer;

#[cfg(feature = "browser")]
pub mod scroll;
pub mod telemetry;
pub mod timing;
/// Browser-backed configurable typing executor.
#[cfg(feature = "browser")]
pub mod typing;
#[cfg(feature = "browser")]
pub mod wheel;

pub use attention::{AttentionConfig, AttentionSimulator, FocusPoint, GazePattern};
pub use detector_fixture::{bot_typing_stream, human_typing_stream, lift_ratio, timing_cv};
#[cfg(feature = "browser")]
pub use element_interaction::{assert_interactable, human_click_offset, ElementBox};
pub use ime::{plan_ime_sequence, CompositionEvent};
pub use keyboard_event::{
    key_to_bidi_dispatch_key, key_to_code, key_to_key_value, needs_shift, plan_key_events,
    plan_typed_text, KeyboardEvent,
};
pub use keystroke::{
    bigram_gap, hold_envelope, plan_keystrokes, qwerty_neighbour, Keystroke, TypingPlan,
};
pub use telemetry::{BehavioralEvent, TelemetryCollector};
pub use timing::{ActionDelay, ReadingTimeEstimator, SessionPacing};

#[cfg(feature = "browser")]
pub use behavior::*;
#[cfg(feature = "browser")]
pub use mouse_driver::{HumanMouse, MousePersona};
#[cfg(feature = "browser")]
pub use pointer::{PointerDevice, PointerProperties};
#[cfg(feature = "browser")]
pub use scroll::{HumanScrollConfig, HumanScroller, ScrollBehavior};
#[cfg(feature = "browser")]
pub use typing::{HumanTyper, TypingConfig};
#[cfg(feature = "browser")]
pub use wheel::{WheelDevice, WheelProperties};

#[cfg(test)]
mod no_fixed_sleep_audit {
    //! G143 / Law 7, no fixed sleeps in the action path. Every inter-action delay
    //! must be drawn from a sampled distribution (`rng.gen_range(…)`,
    //! `jittered_step(nominal, …)`, or a value computed from a sampled plan), never
    //! a constant `sleep(Duration::from_millis(<N>))`. A fixed tick is a behavioral
    //! tell: a detector that times keystrokes/clicks sees a machine-perfect cadence.
    //!
    //! This walks the action-path source (`src/human`, plus the HTTP background-noise
    //! pacer) and fails if any `sleep()` is called directly on a literal `Duration`.
    //! It deliberately ALLOWS `sleep(jittered_step(Duration::from_millis(<N>), …))`
    //! and `sleep(rng.gen_range(…))`: there the literal is a distribution *nominal*,
    //! not the delay itself. The banned stems are assembled with `concat!` so the
    //! joined literal never appears here, and the panic text uses `<N>` (not a digit)
    //! so the audit is immune to its own message; pure-comment lines are skipped.
    use std::fs;
    use std::path::{Path, PathBuf};

    fn rs_files(dir: &Path, out: &mut Vec<PathBuf>) {
        let Ok(entries) = fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let p = entry.path();
            if p.is_dir() {
                rs_files(&p, out);
            } else if p.extension().and_then(|e| e.to_str()) == Some("rs") {
                out.push(p);
            }
        }
    }

    #[test]
    fn action_path_delays_are_sampled_never_fixed() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"));
        let mut files = Vec::new();
        rs_files(&root.join("src/human"), &mut files);
        files.push(root.join("src/http/behavioral_noise.rs"));

        // A direct `sleep()` on a literal `Duration` is the banned shape. Stems are
        // split across `concat!` so this file contains no contiguous joined literal.
        let banned_stems = [
            concat!("sleep(Duration::from_", "millis("),
            concat!("sleep(Duration::from_", "secs("),
            concat!("sleep(tokio::time::Duration::from_", "millis("),
            concat!("sleep(tokio::time::Duration::from_", "secs("),
        ];

        let mut sleep_sites = 0usize;
        for f in &files {
            let Ok(src) = fs::read_to_string(f) else {
                continue;
            };
            for (idx, line) in src.lines().enumerate() {
                if line.trim_start().starts_with("//") {
                    continue;
                }
                let compact: String = line.chars().filter(|c| !c.is_whitespace()).collect();
                if compact.contains("sleep(") {
                    sleep_sites += 1;
                }
                for stem in banned_stems {
                    for (pos, _) in compact.match_indices(stem) {
                        let next = compact[pos + stem.len()..].chars().next();
                        if next.is_some_and(|c| c.is_ascii_digit()) {
                            panic!(
                                "{}:{}: a fixed-literal delay. `sleep` directly on \
                                 Duration::from_millis(<N>)/from_secs(<N>), is in the action path \
                                 (Law 7 / G143). A constant tick is a behavioral tell. Draw the delay \
                                 from a sampled distribution (`rng.gen_range(…)`, `jittered_step(…)`, \
                                 or a value off a sampled plan). Line: {}",
                                f.display(),
                                idx + 1,
                                line.trim()
                            );
                        }
                    }
                }
            }
        }
        // Guard against going inert: the action-path modules carry many `sleep()`
        // calls; a near-zero count means the walk is mis-rooted or the code moved.
        assert!(
            sleep_sites >= 15,
            "no-fixed-sleep audit saw only {sleep_sites} sleep call sites, the action path moved \
             out from under the walk and the guard is now inert"
        );
    }
}
