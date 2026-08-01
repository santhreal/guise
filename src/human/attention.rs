//! Attention and gaze-pattern simulation (lifted from archived golemn-browser).
//!
//! Models how a human's eyes move across a webpage:
//! - **F-pattern**: full first line, partial second, then a vertical scan.
//! - **Z-pattern**: diagonal sweep, common on image-heavy or marketing pages.
//! - **Focus rules**: headings, images, and CTAs always attract a gaze fixation.
//!
//! The main entry-point is [`AttentionSimulator::viewport_focus_pattern`], which
//! returns a sequence of [`FocusPoint`]s (CSS selector + dwell [`Duration`])
//! representing the sections a user would look at and for how long. The output
//! is a *plan*: a browser driver (the `browser` feature) consumes it to dwell
//! and scroll; the planner itself is pure and needs no browser.

use rand::Rng;
use std::time::Duration;

// ── GazePattern ───────────────────────────────────────────────────────────

/// The broad visual scanning pattern used for the page.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GazePattern {
    /// Horizontal attention across top, then left-edge vertical scan.
    /// Typical for text-heavy content pages.
    FPattern,
    /// Diagonal eye movement across the page (top-left → top-right → bottom-left).
    /// Common on landing/marketing pages.
    ZPattern,
}

impl GazePattern {
    /// Heuristic: choose the pattern based on keyword presence in the page title.
    ///
    /// In practice callers may pass any `context` string (title, URL, meta
    /// description). Landing-page / commerce signals select [`GazePattern::ZPattern`];
    /// everything else defaults to [`GazePattern::FPattern`].
    #[must_use]
    pub fn detect(context: &str) -> Self {
        let lower = context.to_lowercase();
        // Landing-page / marketing signals → Z-pattern.
        let z_signals = ["buy", "shop", "product", "sale", "offer", "price", "deal"];
        if z_signals.iter().any(|s| lower.contains(s)) {
            GazePattern::ZPattern
        } else {
            GazePattern::FPattern
        }
    }
}

// ── FocusPoint ────────────────────────────────────────────────────────────

/// A single gaze fixation: which element to look at and for how long.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FocusPoint {
    /// CSS selector for the element receiving attention.
    pub selector: String,
    /// Estimated gaze dwell duration.
    pub duration: Duration,
}

impl FocusPoint {
    fn new(selector: impl Into<String>, duration: Duration) -> Self {
        Self {
            selector: selector.into(),
            duration,
        }
    }
}

// ── AttentionConfig ───────────────────────────────────────────────────────

/// Configures what the simulator considers "attention-worthy" on the page.
#[derive(Debug, Clone)]
pub struct AttentionConfig {
    /// CSS selectors that should always receive a gaze fixation.
    pub high_priority_selectors: Vec<String>,
    /// Gaze pattern to apply.
    pub pattern: GazePattern,
    /// Base reading speed used to estimate reading-pause durations (WPM).
    pub reading_wpm: f64,
}

impl Default for AttentionConfig {
    fn default() -> Self {
        Self {
            high_priority_selectors: vec![
                "h1".into(),
                "h2".into(),
                "h3".into(),
                "img[src]".into(),
                "button".into(),
                "a.cta".into(),
                "[data-cta]".into(),
                ".cta".into(),
                "form".into(),
                "nav".into(),
            ],
            pattern: GazePattern::FPattern,
            reading_wpm: 225.0,
        }
    }
}

// ── AttentionSimulator ────────────────────────────────────────────────────

/// Generates viewport gaze-focus sequences for human-like page interaction.
pub struct AttentionSimulator {
    config: AttentionConfig,
}

impl AttentionSimulator {
    /// Build a simulator from an [`AttentionConfig`].
    #[must_use]
    pub fn new(config: AttentionConfig) -> Self {
        Self { config }
    }

    /// Build a sequence of [`FocusPoint`]s representing where a user would look
    /// on the current viewport.
    ///
    /// The sequence follows the configured [`GazePattern`] and always includes
    /// every `high_priority_selectors` entry as an explicit fixation point,
    /// inserted in natural reading order rather than appended.
    #[must_use]
    pub fn viewport_focus_pattern(&self) -> Vec<FocusPoint> {
        let mut rng = rand::thread_rng();

        let structural = match self.config.pattern {
            GazePattern::FPattern => self.f_pattern_selectors(),
            GazePattern::ZPattern => self.z_pattern_selectors(),
        };

        let mut points: Vec<FocusPoint> = Vec::new();

        for selector in &structural {
            let dur = self.gaze_duration_for(selector, &mut rng);
            points.push(FocusPoint::new(selector, dur));
        }

        // High-priority elements always appear as explicit fixations.
        // Insert them in a natural reading-order position (after first structural
        // point) rather than appending blindly.
        let insert_pos = if points.len() > 1 { 1 } else { points.len() };
        let mut priority_points: Vec<FocusPoint> = self
            .config
            .high_priority_selectors
            .iter()
            .map(|sel| {
                let dur = self.gaze_duration_for(sel, &mut rng);
                FocusPoint::new(sel, dur)
            })
            .collect();

        // Shuffle priority points slightly so they feel discovered, not scripted.
        for i in (1..priority_points.len()).rev() {
            let j = rng.gen_range(0..=i);
            priority_points.swap(i, j);
        }

        for (offset, pp) in priority_points.into_iter().enumerate() {
            let pos = (insert_pos + offset).min(points.len());
            points.insert(pos, pp);
        }

        points
    }

    /// Return the gaze-focus sequence as raw `(selector, Duration)` tuples.
    #[must_use]
    pub fn viewport_focus_tuples(&self) -> Vec<(String, Duration)> {
        self.viewport_focus_pattern()
            .into_iter()
            .map(|fp| (fp.selector, fp.duration))
            .collect()
    }

    // ── pattern generators ────────────────────────────────────────────────

    /// F-pattern: first two horizontal "bars" + left-edge vertical strip.
    fn f_pattern_selectors(&self) -> Vec<String> {
        vec![
            // Top horizontal bar (title/hero).
            "header".into(),
            "h1, [role='banner']".into(),
            // Second horizontal bar (sub-heading / intro paragraph).
            "h2".into(),
            "p:first-of-type".into(),
            // Left-edge vertical scan.
            "aside, nav, ul:first-of-type".into(),
            "article > p".into(),
            // Footer glimpse (very short).
            "footer".into(),
        ]
    }

    /// Z-pattern: top edge, diagonal, bottom edge.
    fn z_pattern_selectors(&self) -> Vec<String> {
        vec![
            // Top-left (logo / brand).
            "header .logo, header img, h1".into(),
            // Top-right (nav / CTA).
            "nav, header .cta, header button".into(),
            // Middle diagonal (hero image / headline value prop).
            ".hero, .banner, [class*='hero'], [class*='banner']".into(),
            // Bottom-left (social proof, features).
            ".features, .testimonials, [class*='feature']".into(),
            // Bottom-right (final CTA).
            ".cta, button[type='submit'], a[href*='signup'], a[href*='buy']".into(),
            // Footer.
            "footer".into(),
        ]
    }

    // ── duration estimation ───────────────────────────────────────────────

    /// Estimate gaze fixation duration for a selector based on its semantic type.
    fn gaze_duration_for<R: Rng>(&self, selector: &str, rng: &mut R) -> Duration {
        let (base_ms, variance_ms): (u64, u64) = if is_heading(selector) {
            (400, 200) // headings: quick scan
        } else if is_image(selector) {
            (800, 400) // images: longer
        } else if is_cta(selector) {
            (600, 300) // CTAs: evaluate intent
        } else if is_nav(selector) {
            (300, 150) // nav: quick orientation
        } else if is_body_text(selector) {
            // Body text: proportional to reading speed.
            let words_visible: u64 = rng.gen_range(15..50);
            let read_ms = words_visible * 60_000 / self.config.reading_wpm as u64;
            (read_ms, read_ms / 3)
        } else {
            (300, 200) // generic element
        };

        let noise_ms = rng.gen_range(0..variance_ms.max(1));
        let total = base_ms + noise_ms;
        Duration::from_millis(total.max(100))
    }
}

// ── selector heuristics ───────────────────────────────────────────────────

fn is_heading(sel: &str) -> bool {
    ["h1", "h2", "h3", "h4", "h5", "h6"]
        .iter()
        .any(|h| sel.contains(h))
}

fn is_image(sel: &str) -> bool {
    sel.contains("img") || sel.contains("picture") || sel.contains("figure")
}

fn is_cta(sel: &str) -> bool {
    sel.contains("button")
        || sel.contains("cta")
        || sel.contains("submit")
        || sel.contains("signup")
        || sel.contains("buy")
}

fn is_nav(sel: &str) -> bool {
    sel.contains("nav") || sel.contains("menu") || sel.contains("header")
}

fn is_body_text(sel: &str) -> bool {
    sel.contains(" p") || sel.starts_with('p') || sel.contains("article") || sel.contains("aside")
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── GazePattern::detect ───────────────────────────────────────────────

    #[test]
    fn detect_z_for_shop_context() {
        assert_eq!(
            GazePattern::detect("Best deals and shop now!"),
            GazePattern::ZPattern
        );
    }

    #[test]
    fn detect_z_for_buy_context() {
        assert_eq!(
            GazePattern::detect("Buy a new laptop today"),
            GazePattern::ZPattern
        );
    }

    #[test]
    fn detect_f_for_article_context() {
        assert_eq!(
            GazePattern::detect("How Rust memory safety works"),
            GazePattern::FPattern
        );
    }

    #[test]
    fn detect_f_by_default() {
        assert_eq!(GazePattern::detect(""), GazePattern::FPattern);
    }

    // ── viewport_focus_pattern ────────────────────────────────────────────

    #[test]
    fn f_pattern_has_expected_count() {
        let sim = AttentionSimulator::new(AttentionConfig {
            pattern: GazePattern::FPattern,
            high_priority_selectors: vec![],
            ..Default::default()
        });
        let pts = sim.viewport_focus_pattern();
        assert!(
            pts.len() >= 5,
            "F-pattern should produce at least 5 points, got {}",
            pts.len()
        );
    }

    #[test]
    fn z_pattern_has_expected_count() {
        let sim = AttentionSimulator::new(AttentionConfig {
            pattern: GazePattern::ZPattern,
            high_priority_selectors: vec![],
            ..Default::default()
        });
        let pts = sim.viewport_focus_pattern();
        assert!(
            pts.len() >= 5,
            "Z-pattern should produce at least 5 points, got {}",
            pts.len()
        );
    }

    #[test]
    fn all_high_priority_selectors_included() {
        let priorities = vec!["h1".to_string(), "button".to_string(), "img".to_string()];
        let sim = AttentionSimulator::new(AttentionConfig {
            high_priority_selectors: priorities.clone(),
            ..Default::default()
        });
        let pts = sim.viewport_focus_pattern();
        for p in &priorities {
            assert!(
                pts.iter().any(|fp| &fp.selector == p),
                "selector '{p}' missing from focus pattern"
            );
        }
    }

    #[test]
    fn all_durations_at_least_100ms() {
        let sim = AttentionSimulator::new(AttentionConfig::default());
        for fp in sim.viewport_focus_pattern() {
            assert!(
                fp.duration >= Duration::from_millis(100),
                "focus point '{}' has duration {:?} < 100 ms",
                fp.selector,
                fp.duration
            );
        }
    }

    #[test]
    fn viewport_focus_tuples_matches_pattern() {
        let sim = AttentionSimulator::new(AttentionConfig::default());
        let tuples = sim.viewport_focus_tuples();
        // Should have at least structural + priority selectors.
        assert!(
            tuples.len() >= 5,
            "expected ≥5 tuples, got {}",
            tuples.len()
        );
        // Every tuple should have a non-empty selector and duration ≥ 100ms.
        for (sel, dur) in &tuples {
            assert!(!sel.is_empty(), "selector should be non-empty");
            assert!(
                *dur >= Duration::from_millis(100),
                "duration {:?} < 100ms for '{}'",
                dur,
                sel
            );
        }
    }

    // ── semantic heuristics ───────────────────────────────────────────────

    #[test]
    fn is_heading_detects_h1_h2() {
        assert!(is_heading("h1"));
        assert!(is_heading("h2"));
        assert!(is_heading("h3.title"));
        assert!(!is_heading("div"));
    }

    #[test]
    fn is_image_detects_img() {
        assert!(is_image("img[src]"));
        assert!(is_image("picture"));
        assert!(is_image("figure.hero"));
        assert!(!is_image("span"));
    }

    #[test]
    fn is_cta_detects_button_and_signup() {
        assert!(is_cta("button"));
        assert!(is_cta("a[href*='signup']"));
        assert!(is_cta(".cta"));
        assert!(!is_cta("p"));
    }

    #[test]
    fn is_nav_detects_nav_and_header() {
        assert!(is_nav("nav"));
        assert!(is_nav("header"));
        assert!(!is_nav("footer"));
    }

    #[test]
    fn is_body_text_detects_p_and_article() {
        assert!(is_body_text("article > p"));
        assert!(is_body_text("p:first-of-type"));
        assert!(!is_body_text("h1"));
    }

    // ── gaze_duration_for ─────────────────────────────────────────────────

    #[test]
    fn image_duration_longer_than_heading() {
        let sim = AttentionSimulator::new(AttentionConfig::default());
        let mut rng = rand::thread_rng();
        let sum_img: u128 = (0..200)
            .map(|_| sim.gaze_duration_for("img", &mut rng).as_millis())
            .sum();
        let sum_h1: u128 = (0..200)
            .map(|_| sim.gaze_duration_for("h1", &mut rng).as_millis())
            .sum();
        assert!(
            sum_img > sum_h1,
            "image avg ({:.0}) should exceed heading avg ({:.0})",
            sum_img as f64 / 200.0,
            sum_h1 as f64 / 200.0
        );
    }

    // ── FocusPoint ────────────────────────────────────────────────────────

    #[test]
    fn focus_point_stores_selector_and_duration() {
        let fp = FocusPoint::new("h1", Duration::from_millis(500));
        assert_eq!(fp.selector, "h1");
        assert_eq!(fp.duration, Duration::from_millis(500));
    }
}
