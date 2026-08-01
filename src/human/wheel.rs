//! Wheel-event persona model (G173 / G174).
//!
//! Different input devices produce different `WheelEvent` signatures:
//! - A classic mouse wheel fires `deltaMode == 1` (lines) with a fixed line
//!   granularity (typically 3 lines ≈ 100 px).
//! - A trackpad fires `deltaMode == 0` (pixels) with small, smooth increments.
//! - A touch-based "wheel" is really a scroll gesture and should not produce
//!   discrete wheel events at all.
//!
//! This module defines the expected `deltaMode` and delta magnitudes per device
//! class. The scroll dispatch layer ([`crate::human::scroll::HumanScroller`])
//! consumes `delta_mode`, `step_px`, and [`WheelDevice::delta_y`] when emitting
//! BiDi wheel actions, so a line-mode persona emits quantized notches and a
//! pixel-mode persona emits a smooth stream, each coherent with its recorded
//! `deltaMode`.

use rand::Rng;

/// Input-device class for wheel/scroll events.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum WheelDevice {
    /// Classic mouse wheel: line-mode steps.
    #[default]
    MouseWheel,
    /// Trackpad: pixel-mode smooth steps.
    Trackpad,
    /// Touch screen: wheel events should be avoided; use scroll gestures.
    Touch,
}

/// Expected wheel-event parameters for a device class.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct WheelProperties {
    /// DOM `WheelEvent.deltaMode`: 0 = pixels, 1 = lines, 2 = pages.
    pub delta_mode: u8,
    /// Typical magnitude of one scroll tick on the Y axis.
    pub step_px: f64,
    /// Whether this device emits discrete wheel events at all.
    pub emits_wheel_events: bool,
}

impl WheelDevice {
    /// Static properties for this wheel-device class.
    #[must_use]
    pub fn properties(&self) -> WheelProperties {
        match self {
            WheelDevice::MouseWheel => WheelProperties {
                delta_mode: 1,
                step_px: 100.0,
                emits_wheel_events: true,
            },
            WheelDevice::Trackpad => WheelProperties {
                delta_mode: 0,
                step_px: 16.0,
                emits_wheel_events: true,
            },
            WheelDevice::Touch => WheelProperties {
                delta_mode: 0,
                step_px: 0.0,
                emits_wheel_events: false,
            },
        }
    }

    /// Compute a Y-axis delta for `n` logical ticks, with a small jitter so the
    /// stream is not a fixed multiple (a bot tell).
    #[must_use]
    pub fn delta_y<R: Rng + ?Sized>(&self, ticks: i32, rng: &mut R) -> f64 {
        let props = self.properties();
        if !props.emits_wheel_events {
            return 0.0;
        }
        let base = f64::from(ticks) * props.step_px;
        let jitter = if props.delta_mode == 1 {
            // Line-mode wheels are coarse; jitter a small fraction of a line.
            rng.gen_range(-8.0_f64..8.0)
        } else {
            // Trackpads are smooth; jitter a few pixels.
            rng.gen_range(-3.0_f64..3.0)
        };
        (base + jitter).max(1.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    #[test]
    fn mouse_wheel_uses_line_mode() {
        let p = WheelDevice::MouseWheel.properties();
        assert_eq!(p.delta_mode, 1);
        assert!(p.emits_wheel_events);
    }

    #[test]
    fn trackpad_uses_pixel_mode() {
        let p = WheelDevice::Trackpad.properties();
        assert_eq!(p.delta_mode, 0);
        assert!(p.emits_wheel_events);
    }

    #[test]
    fn touch_does_not_emit_wheel() {
        let p = WheelDevice::Touch.properties();
        assert!(!p.emits_wheel_events);
    }

    #[test]
    fn mouse_wheel_delta_is_coarse() {
        let mut rng = StdRng::seed_from_u64(7);
        let dy = WheelDevice::MouseWheel.delta_y(3, &mut rng);
        assert!(
            (250.0..=320.0).contains(&dy),
            "mouse wheel delta {dy} outside line-mode range"
        );
    }

    #[test]
    fn trackpad_delta_is_smooth() {
        let mut rng = StdRng::seed_from_u64(7);
        let dy = WheelDevice::Trackpad.delta_y(3, &mut rng);
        assert!(
            (40.0..=55.0).contains(&dy),
            "trackpad delta {dy} outside smooth range"
        );
    }

    #[test]
    fn touch_delta_is_zero() {
        let mut rng = StdRng::seed_from_u64(7);
        assert_eq!(WheelDevice::Touch.delta_y(3, &mut rng), 0.0);
    }
}
