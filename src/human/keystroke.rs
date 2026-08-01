//! Bigram-aware keystroke timing.
//!
//! The old `type_realistic` dispatcher used a uniform 80–250ms inter-key delay
//! plus an occasional "thinking pause." That distribution is bot-shaped: real
//! typists have bigram-dependent timing - `th`, `he`, `in`, `er` are typed
//! 60–110ms apart because the motor program is over-trained, while
//! cold bigrams like `qz`, `xv`, `wq` take 250–400ms. A uniform
//! distribution across all bigrams is one of the cheapest signals
//! a behavioural classifier can train on.
//!
//! This module ships:
//!
//! - A frequency-weighted timing table for the 30 hottest English
//!   bigrams (drawn from Norvig's count_2l corpus, scaled to
//!   typing-latency studies).
//! - Per-character key-hold-time variance tied to character type
//!   (digits and modifier-requiring characters held slightly longer
//!   than letters).
//! - Optional typo injection - at low probability the typist enters
//!   the wrong character, hits backspace, and corrects.
//! - A pure planner ([`plan_keystrokes`]) that turns an input string
//!   into a sequence of [`Keystroke`] events with realistic timing.
//!   The planner is doctested; the dispatcher in
//!   [`crate::human::behavior::type_human`] is the live wrapper around CDP.
//!
//! The numbers were tuned to land inside the 5th–95th percentile
//! envelope from the typing-latency corpora cited in Dhakal et al.
//! (CHI 2018). Real production tuning should ideally come from
//! per-deployment measurement, but the bundled defaults are
//! defensible for cold-start.

use rand::{rngs::StdRng, Rng};

/// One scheduled keystroke. The dispatcher sleeps `gap_ms_before`,
/// emits a `keydown`, sleeps `hold_ms`, then emits a `keyup` and
/// moves to the next keystroke. The first keystroke in a plan has
/// `gap_ms_before = 0`.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Keystroke {
    /// Character to send.
    pub ch: char,
    /// Hold time between keydown and keyup, in milliseconds.
    pub hold_ms: u16,
    /// Inter-keystroke gap that elapses BEFORE the keydown for this
    /// keystroke. The first keystroke has `0`.
    pub gap_ms_before: u16,
    /// True when this keystroke is part of a typo-correction
    /// sequence (an injected wrong character or a backspace).
    /// Useful for tests and observability.
    pub is_correction: bool,
}

/// Per-bigram inter-key gap envelope `(min_ms, max_ms)`.
/// Hot English bigrams (over-trained motor programs) are fast;
/// rare letter combinations are slow. Lookup is case-insensitive.
const HOT_BIGRAMS: &[(&str, u16, u16)] = &[
    // Top 30 English bigrams (Norvig corpus), tuned to ~60–120ms.
    ("th", 60, 100),
    ("he", 65, 105),
    ("in", 70, 110),
    ("er", 70, 115),
    ("an", 70, 115),
    ("re", 75, 120),
    ("on", 80, 125),
    ("at", 80, 125),
    ("en", 80, 130),
    ("nd", 80, 130),
    ("ti", 85, 130),
    ("es", 85, 135),
    ("or", 85, 135),
    ("te", 85, 135),
    ("of", 90, 140),
    ("ed", 90, 140),
    ("is", 90, 140),
    ("it", 90, 145),
    ("al", 95, 145),
    ("ar", 95, 145),
    ("st", 95, 150),
    ("to", 95, 150),
    ("nt", 100, 150),
    ("ng", 100, 155),
    ("se", 100, 155),
    ("ha", 100, 155),
    ("as", 105, 160),
    ("ou", 105, 160),
    ("io", 105, 160),
    ("le", 105, 165),
    // Lukewarm - common but not over-trained.
    ("ve", 110, 170),
    ("co", 115, 175),
    ("me", 115, 175),
    ("de", 115, 180),
    ("hi", 120, 180),
    ("ri", 120, 180),
    ("ro", 125, 185),
    ("ic", 125, 190),
    ("ne", 130, 195),
    ("ea", 130, 200),
];

/// Default cold-bigram envelope used when the bigram doesn't appear
/// in the (private) `HOT_BIGRAMS` table. Anything from `qz` to `wq`
/// to `xj` falls here.
pub const COLD_BIGRAM_GAP_MIN_MS: u16 = 180;
/// Upper bound of the cold-bigram inter-key gap envelope.
pub const COLD_BIGRAM_GAP_MAX_MS: u16 = 320;

/// Whitespace transition envelope. Space-after-word is consistently
/// faster than cold bigrams in real typists because the thumb is
/// already over the spacebar.
pub const SPACE_GAP_MIN_MS: u16 = 90;
/// Upper bound of the whitespace-transition gap envelope.
pub const SPACE_GAP_MAX_MS: u16 = 170;

/// Digit-bigram envelope (digit-after-digit). Digits are typed
/// noticeably slower than letters because most typists don't
/// over-train the number row.
pub const DIGIT_GAP_MIN_MS: u16 = 200;
/// Upper bound of the digit-bigram gap envelope.
pub const DIGIT_GAP_MAX_MS: u16 = 360;

/// Look up the inter-key gap envelope for a `prev → next`
/// transition. Returns `(min_ms, max_ms)`.
///
/// # Examples
///
/// ```
/// use guise::human::keystroke::bigram_gap;
/// // Hot bigram lands in the fast range.
/// let (lo, hi) = bigram_gap('t', 'h');
/// assert!(lo < 110 && hi <= 110);
/// // Space-after-word stays fast.
/// let (lo, hi) = bigram_gap('o', ' ');
/// assert_eq!(lo, 90);
/// assert_eq!(hi, 170);
/// // Cold bigram lands in the slow range.
/// let (lo, hi) = bigram_gap('q', 'z');
/// assert_eq!(lo, 180);
/// assert_eq!(hi, 320);
/// // Digit-bigram envelope.
/// let (lo, hi) = bigram_gap('5', '7');
/// assert_eq!(lo, 200);
/// assert_eq!(hi, 360);
/// ```
pub fn bigram_gap(prev: char, next: char) -> (u16, u16) {
    if next == ' ' || next == '\t' {
        return (SPACE_GAP_MIN_MS, SPACE_GAP_MAX_MS);
    }
    if prev.is_ascii_digit() && next.is_ascii_digit() {
        return (DIGIT_GAP_MIN_MS, DIGIT_GAP_MAX_MS);
    }
    let key = format!("{}{}", prev.to_ascii_lowercase(), next.to_ascii_lowercase());
    if let Some(&(_, lo, hi)) = HOT_BIGRAMS.iter().find(|(k, _, _)| *k == key) {
        return (lo, hi);
    }
    (COLD_BIGRAM_GAP_MIN_MS, COLD_BIGRAM_GAP_MAX_MS)
}

/// Per-character key-hold time envelope `(min_ms, max_ms)`.
/// Letters are held shortest; digits and uppercase characters need
/// the shift modifier and are held slightly longer.
///
/// # Examples
///
/// ```
/// use guise::human::keystroke::hold_envelope;
/// let (lo, hi) = hold_envelope('a');
/// assert!(lo >= 30 && hi <= 80);
/// let (lo_u, hi_u) = hold_envelope('A');
/// assert!(lo_u > lo, "uppercase held longer");
/// let (lo_d, hi_d) = hold_envelope('5');
/// assert!(lo_d >= 40, "digits held >= 40ms");
/// ```
pub fn hold_envelope(ch: char) -> (u16, u16) {
    if ch.is_ascii_uppercase() {
        return (50, 100);
    }
    if ch.is_ascii_digit() {
        return (45, 90);
    }
    if ch == ' ' {
        return (35, 80);
    }
    (30, 75)
}

/// Generate a plausible typo for a target character.
///
/// Picks a neighbouring key on a QWERTY keyboard. Used by
/// [`plan_keystrokes`] when typo injection fires.
///
/// Returns `None` for characters with no defined neighbour set
/// (digits, punctuation, uppercase). Production typo modelling for
/// those classes is a follow-up.
///
/// # Examples
///
/// ```
/// use guise::human::keystroke::qwerty_neighbour;
/// // 'h' neighbours include g/j/y/n/b - never the same key.
/// let n = qwerty_neighbour('h', 0).unwrap();
/// assert_ne!(n, 'h');
/// assert!("gjyn b".contains(n));
/// ```
pub fn qwerty_neighbour(ch: char, rng_seed: u8) -> Option<char> {
    let neighbours: &[char] = match ch.to_ascii_lowercase() {
        'q' => &['w', 'a'],
        'w' => &['q', 'e', 's'],
        'e' => &['w', 'r', 'd'],
        'r' => &['e', 't', 'f'],
        't' => &['r', 'y', 'g'],
        'y' => &['t', 'u', 'h'],
        'u' => &['y', 'i', 'j'],
        'i' => &['u', 'o', 'k'],
        'o' => &['i', 'p', 'l'],
        'p' => &['o', 'l'],
        'a' => &['q', 's', 'z'],
        's' => &['a', 'd', 'w', 'x'],
        'd' => &['s', 'f', 'e', 'c'],
        'f' => &['d', 'g', 'r', 'v'],
        'g' => &['f', 'h', 't', 'b'],
        'h' => &['g', 'j', 'y', 'n', 'b', ' '],
        'j' => &['h', 'k', 'u', 'm'],
        'k' => &['j', 'l', 'i'],
        'l' => &['k', 'o', 'p'],
        'z' => &['a', 'x'],
        'x' => &['z', 'c', 's'],
        'c' => &['x', 'v', 'd'],
        'v' => &['c', 'b', 'f'],
        'b' => &['v', 'n', 'g', 'h'],
        'n' => &['b', 'm', 'h', 'j'],
        'm' => &['n', 'j', 'k'],
        _ => return None,
    };
    Some(neighbours[(rng_seed as usize) % neighbours.len()])
}

/// Configuration for [`plan_keystrokes`].
#[derive(Debug, Clone, Copy)]
pub struct TypingPlan {
    /// Probability in `[0.0, 1.0]` of a single-character typo per
    /// character. Set to `0.0` to disable. Real typists make
    /// 1–4% character-level errors; the default is 0.015 (1.5%).
    pub typo_probability: f32,
    /// Mean inter-keystroke "thinking pause" probability. Real
    /// typists pause every 4–10 characters for 200–600ms. Set to
    /// `0.0` to disable.
    pub thinking_pause_probability: f32,
    /// Global speed multiplier for inter-key gaps. 1.0 leaves the
    /// bundled bigram envelopes unchanged; values below 1.0 speed up
    /// typing and above 1.0 slow it down. Clamped to `[0.5, 2.0]`.
    pub speed_factor: f64,
}

impl Default for TypingPlan {
    fn default() -> Self {
        Self {
            typo_probability: 0.015,
            thinking_pause_probability: 0.10,
            speed_factor: 1.0,
        }
    }
}

impl TypingPlan {
    /// Build a plan with the given WPM target. The default envelopes
    /// approximate a 60 WPM typist; this scales them to hit the
    /// requested speed (clamped to 40–80 WPM).
    #[must_use]
    pub fn with_wpm(wpm: f64) -> Self {
        let wpm = wpm.clamp(40.0, 80.0);
        Self {
            speed_factor: (60.0 / wpm).clamp(0.5, 2.0),
            ..Default::default()
        }
    }
}

/// Sample a center-weighted (triangular) value in `[lo, hi]`: the rounded mean
/// of two independent uniform draws.
///
/// The per-bigram and per-character envelopes are the **5th–95th percentile**
/// bands from the typing-latency corpora, NOT uniform ranges. Drawing each
/// flight/dwell time flat (`gen_range(lo..=hi)`) reproduces neither: it puts
/// equal density on the rare extremes and leaves a hard density cliff exactly at
/// `lo` and `hi`, which a real typist never produces. The realised
/// inter-key-interval histogram is then a flat box with sharp edges, a
/// distribution-shape tell a keystroke-dynamics classifier (the dominant
/// behavioural biometric) trains on directly. A triangular draw peaks at the
/// envelope centre and tapers to ~zero density at both bounds, matching the
/// corpus shape far better while staying strictly within `[lo, hi]` so every
/// envelope contract (and the per-bigram bounds tests) still holds. `lo >= hi`
/// returns `lo`. (Symmetric triangular is a deliberate, well-understood
/// approximation of the right-skewed log-normal latency, a categorical
/// improvement over uniform without overclaiming a fitted corpus distribution.)
fn center_weighted(rng: &mut StdRng, lo: u16, hi: u16) -> u16 {
    if lo >= hi {
        return lo;
    }
    let a = u32::from(rng.gen_range(lo..=hi));
    let b = u32::from(rng.gen_range(lo..=hi));
    // Rounded mean of two draws in [lo, hi] stays in [lo, hi].
    (a + b).div_ceil(2) as u16
}

/// Plan a realistic keystroke sequence for `text`. Pure function
/// (no IO); the dispatcher in [`crate::human::HumanTyper::type_text`] is
/// the live wrapper.
///
/// Returns a `Vec<Keystroke>` whose dispatch produces the timing
/// pattern of a human typist:
///
/// - Inter-key gaps drawn from [`bigram_gap`] for each adjacent pair.
/// - Hold times drawn from [`hold_envelope`] per character.
/// - Optional typo injection - wrong char + backspace + correct
///   char - with the configured probability per character.
/// - Optional thinking pauses (200–600ms extra gap) at the
///   configured rate.
/// - Optional global speed scaling via [`TypingPlan::speed_factor`].
///
/// # Examples
///
/// ```
/// use guise::human::keystroke::{plan_keystrokes, TypingPlan};
/// use rand::{rngs::StdRng, SeedableRng};
/// let mut rng = StdRng::seed_from_u64(0);
/// // With typos and pauses disabled, output length matches input.
/// let plan = TypingPlan { typo_probability: 0.0, thinking_pause_probability: 0.0, speed_factor: 1.0 };
/// let keys = plan_keystrokes("hello", plan, &mut rng);
/// assert_eq!(keys.len(), 5);
/// assert_eq!(keys[0].ch, 'h');
/// assert_eq!(keys[4].ch, 'o');
/// // First keystroke has no preceding context.
/// assert_eq!(keys[0].gap_ms_before, 0);
/// // Subsequent keystrokes carry the (prev → curr) bigram gap; he
/// // is hot, so it lands in the fast envelope.
/// assert!(keys[1].gap_ms_before >= 65 && keys[1].gap_ms_before <= 105);
/// ```
pub fn plan_keystrokes(text: &str, plan: TypingPlan, rng: &mut StdRng) -> Vec<Keystroke> {
    let speed = plan.speed_factor.clamp(0.5, 2.0);
    let scale_ms = |ms: u16| -> u16 { ((ms as f64 * speed).round() as u16).max(1) };
    let scale_range = |(lo, hi): (u16, u16)| -> (u16, u16) { (scale_ms(lo), scale_ms(hi)) };

    let chars: Vec<char> = text.chars().collect();
    let mut out: Vec<Keystroke> = Vec::with_capacity(chars.len() + 8);
    for (i, &ch) in chars.iter().enumerate() {
        // Optional typo: insert a neighbour char then a backspace,
        // then the correct char. We bundle the wrong char and the
        // backspace as `is_correction = true` so observers can tell
        // them apart from the genuine keystrokes.
        let inject_typo = plan.typo_probability > 0.0
            && rng.gen::<f32>() < plan.typo_probability
            && ch.is_ascii_alphabetic();
        if inject_typo {
            if let Some(neighbour) = qwerty_neighbour(ch, rng.gen()) {
                let (h_lo, h_hi) = hold_envelope(neighbour);
                let prev = if i == 0 { ' ' } else { chars[i - 1] };
                let (g_lo, g_hi) = scale_range(bigram_gap(prev, neighbour));
                let typo_gap = if i == 0 {
                    0
                } else {
                    center_weighted(rng, g_lo, g_hi)
                };
                out.push(Keystroke {
                    ch: neighbour,
                    hold_ms: center_weighted(rng, h_lo, h_hi),
                    gap_ms_before: typo_gap,
                    is_correction: true,
                });
                out.push(Keystroke {
                    ch: '\u{0008}', // BS character; dispatcher maps to Backspace
                    hold_ms: center_weighted(rng, 35, 70),
                    // Realisation gap before the typist notices the
                    // wrong char and backspaces - typically 80–250ms.
                    gap_ms_before: scale_ms(center_weighted(rng, 80, 250)),
                    is_correction: true,
                });
                // Now the correct `ch` follows below - its preceding
                // gap is the time after the backspace to recover and
                // resume typing.
            }
        }

        let (h_lo, h_hi) = hold_envelope(ch);
        // For the very first keystroke (no preceding char and no
        // preceding correction event), gap is 0 - the dispatcher
        // starts typing immediately.
        let gap = if out.is_empty() {
            0
        } else if let Some(last) = out.last() {
            // If the previous emitted keystroke was a correction
            // (backspace), use the post-backspace recovery gap rather
            // than a bigram lookup - a typist who just corrected an
            // error usually pauses 60–180ms before continuing.
            if last.is_correction && last.ch == '\u{0008}' {
                scale_ms(center_weighted(rng, 60, 180))
            } else {
                let prev = chars[i - 1];
                let (g_lo, g_hi) = scale_range(bigram_gap(prev, ch));
                let mut g = center_weighted(rng, g_lo, g_hi);
                if plan.thinking_pause_probability > 0.0
                    && rng.gen::<f32>() < plan.thinking_pause_probability
                {
                    // The thinking pause is a deliberate OUTLIER, not a per-key
                    // biometric, so it stays a wide uniform draw, narrowing it
                    // would erase the very dispersion that lifts the rhythm clear
                    // of the uniform-cadence (automation) floor.
                    g = g.saturating_add(scale_ms(rng.gen_range(200..=600)));
                }
                g
            }
        } else {
            0
        };
        out.push(Keystroke {
            ch,
            hold_ms: center_weighted(rng, h_lo, h_hi),
            gap_ms_before: gap,
            is_correction: false,
        });
    }
    out
}

#[cfg(test)]
mod tests;
