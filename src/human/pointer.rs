//! Pointer-device persona model (G171 / G172).
//!
//! Anti-bot scripts read `PointerEvent` properties such as `pressure`, `tiltX`,
//! `tiltY`, and `twist`. A mouse should report pressure `0` while moving and a
//! small positive value while the button is down, with no tilt/twist. A stylus
//! should report variable pressure and non-zero tilt/twist. A touch contact
//! reports pressure but no tilt.
//!
//! This module defines the expected properties per device class so the dispatch
//! layer can set them coherently. The current BiDi dispatch path sets pressure
//! and twist on the trusted pointer actions where the driver API exposes them;
//! the model is the source of truth for those values.

use rand::Rng;

/// Input device class that determines pointer-event properties.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PointerDevice {
    /// Standard mouse: pressure 0 while hovering, small positive while down;
    /// no tilt/twist.
    #[default]
    Mouse,
    /// Finger touch: pressure varies with contact area; no tilt.
    Touch,
    /// Active stylus: pressure, tilt, and twist all vary.
    Stylus,
}

/// Expected pointer-event properties for a device class.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct PointerProperties {
    /// `PointerEvent.pointerType` value.
    pub pointer_type: &'static str,
    /// Pressure while hovering (no button down).
    pub hover_pressure: f64,
    /// Pressure range while the button is held: `(min, max)`.
    pub active_pressure_range: (f64, f64),
    /// True if the device reports `tiltX`/`tiltY`.
    pub has_tilt: bool,
    /// True if the device reports `twist`.
    pub has_twist: bool,
    /// Typical twist range in degrees when supported.
    pub twist_range_deg: (u32, u32),
}

impl PointerDevice {
    /// Static properties for this device class.
    #[must_use]
    pub fn properties(&self) -> PointerProperties {
        match self {
            PointerDevice::Mouse => PointerProperties {
                pointer_type: "mouse",
                hover_pressure: 0.0,
                active_pressure_range: (0.5, 0.5),
                has_tilt: false,
                has_twist: false,
                twist_range_deg: (0, 0),
            },
            PointerDevice::Touch => PointerProperties {
                pointer_type: "touch",
                hover_pressure: 0.0,
                active_pressure_range: (0.2, 1.0),
                has_tilt: false,
                has_twist: false,
                twist_range_deg: (0, 0),
            },
            PointerDevice::Stylus => PointerProperties {
                pointer_type: "pen",
                hover_pressure: 0.0,
                active_pressure_range: (0.1, 1.0),
                has_tilt: true,
                has_twist: true,
                twist_range_deg: (0, 359),
            },
        }
    }

    /// Sample a plausible pressure value for an active (button-down) pointer.
    #[must_use]
    pub fn sample_active_pressure<R: Rng + ?Sized>(&self, rng: &mut R) -> f64 {
        let (lo, hi) = self.properties().active_pressure_range;
        rng.gen_range(lo..=hi)
    }

    /// Sample a plausible tilt pair for a stylus, or `(0, 0)` for mouse/touch.
    #[must_use]
    pub fn sample_tilt<R: Rng + ?Sized>(&self, rng: &mut R) -> (i32, i32) {
        if self == &PointerDevice::Stylus {
            (rng.gen_range(-60..=60), rng.gen_range(-60..=60))
        } else {
            (0, 0)
        }
    }

    /// Sample a plausible twist for a stylus, or `0` for mouse/touch.
    #[must_use]
    pub fn sample_twist<R: Rng + ?Sized>(&self, rng: &mut R) -> u32 {
        if self == &PointerDevice::Stylus {
            rng.gen_range(0..=359)
        } else {
            0
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    #[test]
    fn mouse_has_no_tilt_or_twist() {
        let p = PointerDevice::Mouse.properties();
        assert!(!p.has_tilt);
        assert!(!p.has_twist);
        assert_eq!(p.pointer_type, "mouse");
    }

    #[test]
    fn mouse_hover_pressure_is_zero() {
        assert_eq!(PointerDevice::Mouse.properties().hover_pressure, 0.0);
    }

    #[test]
    fn touch_has_pressure_but_no_tilt() {
        let p = PointerDevice::Touch.properties();
        assert!(p.active_pressure_range.0 > 0.0);
        assert!(!p.has_tilt);
        assert!(!p.has_twist);
    }

    #[test]
    fn stylus_has_tilt_and_twist() {
        let p = PointerDevice::Stylus.properties();
        assert!(p.has_tilt);
        assert!(p.has_twist);
        assert_eq!(p.pointer_type, "pen");
    }

    #[test]
    fn stylus_samples_non_zero_tilt() {
        let mut rng = StdRng::seed_from_u64(1);
        let (tx, ty) = PointerDevice::Stylus.sample_tilt(&mut rng);
        assert!(tx != 0 || ty != 0);
    }

    #[test]
    fn mouse_samples_zero_tilt_and_twist() {
        let mut rng = StdRng::seed_from_u64(1);
        assert_eq!(PointerDevice::Mouse.sample_tilt(&mut rng), (0, 0));
        assert_eq!(PointerDevice::Mouse.sample_twist(&mut rng), 0);
    }
}
