//! DOM-aware human interaction helpers.
//!
//! Closes the gap between synthetic viewport coordinates and real page geometry:
//! the driver queries the element's bounding box, rejects hidden/disabled/zero-size
//! targets, and clicks a human-distributed point inside the box rather than the
//! pixel-perfect center (G161–G166).

use anyhow::{anyhow, Result};
use rand::Rng;
use runtime_foxdriver::Page;
use serde::Deserialize;
use std::time::Duration;

use crate::human::timing::ActionDelay;
use crate::human::HumanMouse;

/// Viewport geometry of an element as returned by `getBoundingClientRect`.
#[derive(Debug, Clone, Copy, Deserialize, PartialEq)]
pub struct ElementBox {
    /// Viewport-left of the element's border box.
    pub x: f64,
    /// Viewport-top of the element's border box.
    pub y: f64,
    /// Width of the element's border box.
    pub width: f64,
    /// Height of the element's border box.
    pub height: f64,
}

impl ElementBox {
    /// Center of the box.
    #[must_use]
    pub fn center(&self) -> (f64, f64) {
        (self.x + self.width / 2.0, self.y + self.height / 2.0)
    }

    /// True when the element has a non-empty clickable area.
    #[must_use]
    pub fn has_size(&self) -> bool {
        self.width > 0.0 && self.height > 0.0
    }
}

#[derive(Debug, Clone, Copy, Deserialize)]
struct ElementState {
    rect: ElementBox,
    visible: bool,
    disabled: bool,
    zero_size: bool,
}

const QUERY_ELEMENT_JS: &str = r#"
(function(sel) {
    const el = document.querySelector(sel);
    if (!el) return null;
    const r = el.getBoundingClientRect();
    const s = window.getComputedStyle(el);
    const zero = r.width === 0 || r.height === 0;
    const visible = !zero &&
        s.display !== 'none' &&
        s.visibility !== 'hidden' &&
        s.visibility !== 'collapse' &&
        s.opacity !== '0' &&
        r.width > 0 && r.height > 0;
    return {
        rect: { x: r.x, y: r.y, width: r.width, height: r.height },
        visible: visible,
        disabled: el.disabled === true,
        zero_size: zero
    };
})"#;

/// Sample a human-like click point inside `rect`.
///
/// Real users rarely hit the exact geometric center. The offset is drawn from a
/// normal distribution centered on the center, with σ proportional to the
/// smaller dimension, then clamped to a small margin from the edges so the
/// pointer lands well inside the element.
#[must_use]
pub fn human_click_offset<R: Rng + ?Sized>(rect: &ElementBox, rng: &mut R) -> (f64, f64) {
    let (cx, cy) = rect.center();
    if rect.width < 6.0 || rect.height < 6.0 {
        return (cx, cy);
    }
    let sigma = (rect.width.min(rect.height) / 8.0).max(2.0);
    let z = crate::sampling::standard_normal(rng);
    let x = cx + z * sigma;
    let y = cy + crate::sampling::standard_normal(rng) * sigma;
    let margin_x = (rect.width / 8.0).max(2.0);
    let margin_y = (rect.height / 8.0).max(2.0);
    let x = x.clamp(rect.x + margin_x, rect.x + rect.width - margin_x);
    let y = y.clamp(rect.y + margin_y, rect.y + rect.height - margin_y);
    (x, y)
}

async fn query_element(page: &Page, selector: &str) -> Result<ElementState> {
    let expr = format!("{}({:?})", QUERY_ELEMENT_JS, selector);
    let res = page
        .evaluate(expr)
        .await
        .map_err(|e| anyhow!("failed to query element {selector}: {e:?}"))?;
    res.into_value::<Option<ElementState>>()
        .map_err(|e| anyhow!("invalid element state for {selector}: {e}"))?
        .ok_or_else(|| anyhow!("element not found: {selector}"))
}

/// Verify that `selector` points to a visible, enabled, non-zero-size element.
///
/// Returns the element's bounding box on success, or a descriptive error if the
/// element is missing, hidden, disabled, or has no layout (G165 / G166).
pub async fn assert_interactable(page: &Page, selector: &str) -> Result<ElementBox> {
    let state = query_element(page, selector).await?;
    if state.zero_size || !state.rect.has_size() {
        return Err(anyhow!(
            "element {selector} has zero size and cannot be interacted with"
        ));
    }
    if !state.visible {
        return Err(anyhow!("element {selector} is not visible"));
    }
    if state.disabled {
        return Err(anyhow!("element {selector} is disabled"));
    }
    Ok(state.rect)
}

impl HumanMouse {
    /// Move to a human-distributed point inside the element matched by `selector`.
    pub async fn move_to_element(&mut self, page: &Page, selector: &str) -> Result<()> {
        let rect = assert_interactable(page, selector).await?;
        let mut rng = rand::thread_rng();
        let (tx, ty) = human_click_offset(&rect, &mut rng);
        let target_size = rect.width.min(rect.height);
        self.move_to(page, tx, ty, target_size).await
    }

    /// Hover over the element (without clicking) and dwell briefly.
    ///
    /// The dwell is drawn from the canonical `ActionDelay::hover_dwell()`
    /// distribution (G163).
    pub async fn hover_dwell_element(&mut self, page: &Page, selector: &str) -> Result<()> {
        self.move_to_element(page, selector).await?;
        tokio::time::sleep(ActionDelay::hover_dwell()).await;
        Ok(())
    }

    /// Click a human-distributed point inside the element.
    ///
    /// The path curves to the element using the persona's mouse model, lands on
    /// a non-center offset, and emits trusted pointer events. The press/release
    /// pair is recorded to the behavioral telemetry (G170) just like
    /// [`HumanMouse::click`], so a scorer attached via
    /// [`HumanMouse::with_telemetry`] sees the click button events, not only the
    /// approach moves.
    pub async fn click_element(&mut self, page: &Page, selector: &str) -> Result<()> {
        let rect = assert_interactable(page, selector).await?;
        let mut rng = rand::thread_rng();
        let (tx, ty) = human_click_offset(&rect, &mut rng);
        let target_size = rect.width.min(rect.height);
        self.move_to(page, tx, ty, target_size).await?;

        let (lo, hi) = self.persona.click_hold_range_ms();
        let hold_ms = rng.gen_range(lo..hi);
        let ts = crate::human::BehavioralEvent::now_ms();
        self.record(crate::human::BehavioralEvent::PointerDown {
            ts,
            x: tx,
            y: ty,
            button: 0,
            pressure: self
                .pointer_device
                .sample_active_pressure(&mut rand::thread_rng()),
        });
        page.mouse_down(tx, ty).await?;
        tokio::time::sleep(Duration::from_millis(hold_ms)).await;
        page.mouse_up(tx, ty).await?;
        self.record(crate::human::BehavioralEvent::PointerUp {
            ts: crate::human::BehavioralEvent::now_ms(),
            x: tx,
            y: ty,
            button: 0,
            pressure: self.pointer_device.properties().hover_pressure,
        });
        Ok(())
    }

    /// Hover, dwell, then click the element (G163).
    pub async fn hover_then_click_element(&mut self, page: &Page, selector: &str) -> Result<()> {
        self.hover_dwell_element(page, selector).await?;
        self.click_element(page, selector).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    #[test]
    fn human_click_offset_lies_inside_element() {
        let rect = ElementBox {
            x: 100.0,
            y: 100.0,
            width: 200.0,
            height: 80.0,
        };
        let mut rng = StdRng::seed_from_u64(1);
        for _ in 0..200 {
            let (x, y) = human_click_offset(&rect, &mut rng);
            assert!(x > rect.x && x < rect.x + rect.width);
            assert!(y > rect.y && y < rect.y + rect.height);
        }
    }

    #[test]
    fn human_click_offset_is_not_exact_center() {
        let rect = ElementBox {
            x: 0.0,
            y: 0.0,
            width: 200.0,
            height: 200.0,
        };
        let mut rng = StdRng::seed_from_u64(2);
        let mut all_center = true;
        for _ in 0..50 {
            let (x, y) = human_click_offset(&rect, &mut rng);
            if (x - 100.0).abs() > 1.0 || (y - 100.0).abs() > 1.0 {
                all_center = false;
            }
        }
        assert!(
            !all_center,
            "click offsets should vary, not all hit the center"
        );
    }

    #[test]
    fn human_click_offset_mean_near_center() {
        let rect = ElementBox {
            x: 0.0,
            y: 0.0,
            width: 200.0,
            height: 100.0,
        };
        let mut rng = StdRng::seed_from_u64(3);
        let (sum_x, sum_y) = (0..500)
            .map(|_| human_click_offset(&rect, &mut rng))
            .fold((0.0, 0.0), |(sx, sy), (x, y)| (sx + x, sy + y));
        let mean_x = sum_x / 500.0;
        let mean_y = sum_y / 500.0;
        assert!((mean_x - 100.0).abs() < 10.0);
        assert!((mean_y - 50.0).abs() < 10.0);
    }

    #[test]
    fn human_click_offset_keeps_margin_from_edges() {
        let rect = ElementBox {
            x: 0.0,
            y: 0.0,
            width: 40.0,
            height: 40.0,
        };
        let mut rng = StdRng::seed_from_u64(4);
        for _ in 0..200 {
            let (x, y) = human_click_offset(&rect, &mut rng);
            // margin = width/8 = 5
            assert!((5.0..=35.0).contains(&x));
            assert!((5.0..=35.0).contains(&y));
        }
    }

    #[test]
    fn tiny_element_clicks_its_center() {
        let rect = ElementBox {
            x: 10.0,
            y: 20.0,
            width: 4.0,
            height: 4.0,
        };
        let mut rng = StdRng::seed_from_u64(5);
        let (x, y) = human_click_offset(&rect, &mut rng);
        assert_eq!(x, 12.0);
        assert_eq!(y, 22.0);
    }
}
