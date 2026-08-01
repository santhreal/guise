//! Behavioral telemetry stream used by downstream scorers (e.g. captchaforge).
//!
//! `BehavioralEvent` is a normalized, timestamped record of every human-layer
//! action: pointer motion, clicks, scrolls, keystrokes, and injected typos.  The
//! schema is intentionally flat and JSON-serializable so a behavioral detector
//! can replay or score the session without parsing DOM logs.
//!
//! G170: this is the shared contract surface between guise's human layer and
//! captchaforge's behavioral scorer.

use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

/// Normalized behavioral event produced by the human layer.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum BehavioralEvent {
    /// Pointer moved to a new viewport coordinate.
    PointerMove {
        /// Event timestamp (ms since UNIX epoch).
        ts: u64,
        /// Viewport x coordinate.
        x: f64,
        /// Viewport y coordinate.
        y: f64,
        /// Pointer pressure in [0, 1].
        pressure: f64,
        /// Twist in [0, 359]; meaningful for stylus/touch.
        twist: u32,
    },
    /// Pointer button pressed.
    PointerDown {
        /// Event timestamp (ms since UNIX epoch).
        ts: u64,
        /// Viewport x coordinate.
        x: f64,
        /// Viewport y coordinate.
        y: f64,
        /// DOM button index.
        button: u8,
        /// Pointer pressure in [0, 1].
        pressure: f64,
    },
    /// Pointer button released.
    PointerUp {
        /// Event timestamp (ms since UNIX epoch).
        ts: u64,
        /// Viewport x coordinate.
        x: f64,
        /// Viewport y coordinate.
        y: f64,
        /// DOM button index.
        button: u8,
        /// Pointer pressure in [0, 1].
        pressure: f64,
    },
    /// Key pressed.
    KeyDown {
        /// Event timestamp (ms since UNIX epoch).
        ts: u64,
        /// Logical key value (`"a"`, `"Enter"`, ...).
        key: String,
        /// Physical code value (`"KeyA"`, ...).
        code: String,
    },
    /// Key released.
    KeyUp {
        /// Event timestamp (ms since UNIX epoch).
        ts: u64,
        /// Logical key value.
        key: String,
        /// Physical code value.
        code: String,
    },
    /// Wheel scroll step.
    Scroll {
        /// Event timestamp (ms since UNIX epoch).
        ts: u64,
        /// Horizontal scroll delta.
        delta_x: f64,
        /// Vertical scroll delta.
        delta_y: f64,
        /// DOM `deltaMode`: 0 = pixels, 1 = lines, 2 = pages.
        delta_mode: u8,
    },
    /// Typo + backspace correction injected by the typing model.
    TypoCorrection {
        /// Event timestamp (ms since UNIX epoch).
        ts: u64,
        /// The wrong character that was typed.
        wrong: char,
        /// The intended character.
        intended: char,
    },
}

impl BehavioralEvent {
    /// Timestamp helper: current monotonic wall-clock ms.
    pub fn now_ms() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64
    }

    /// The millisecond timestamp carried by this event.
    pub fn timestamp(&self) -> u64 {
        match self {
            BehavioralEvent::PointerMove { ts, .. }
            | BehavioralEvent::PointerDown { ts, .. }
            | BehavioralEvent::PointerUp { ts, .. }
            | BehavioralEvent::KeyDown { ts, .. }
            | BehavioralEvent::KeyUp { ts, .. }
            | BehavioralEvent::Scroll { ts, .. }
            | BehavioralEvent::TypoCorrection { ts, .. } => *ts,
        }
    }
}

/// In-memory collector for a session's behavioral events.
///
/// A bounded ring buffer prevents unbounded memory growth during long sessions;
/// when the cap is reached the oldest events are dropped.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TelemetryCollector {
    events: Vec<BehavioralEvent>,
    cap: Option<usize>,
}

impl TelemetryCollector {
    /// Create an unbounded collector.
    pub fn new() -> Self {
        Self {
            events: Vec::new(),
            cap: None,
        }
    }

    /// Create a collector with a maximum event count.
    pub fn with_cap(cap: usize) -> Self {
        Self {
            events: Vec::with_capacity(cap.min(1024)),
            cap: Some(cap),
        }
    }

    /// Record one event.
    pub fn record(&mut self, event: BehavioralEvent) {
        if let Some(cap) = self.cap {
            if self.events.len() >= cap {
                self.events.remove(0);
            }
        }
        self.events.push(event);
    }

    /// Current event count.
    pub fn len(&self) -> usize {
        self.events.len()
    }

    /// Whether no events have been recorded.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.events.is_empty()
    }

    /// Immutable view of recorded events.
    pub fn events(&self) -> &[BehavioralEvent] {
        &self.events
    }

    /// Serialize the stream to JSON.
    pub fn to_json(&self) -> serde_json::Result<String> {
        serde_json::to_string(&self.events)
    }

    /// Clear all events.
    pub fn clear(&mut self) {
        self.events.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn collector_records_events() {
        let mut c = TelemetryCollector::new();
        c.record(BehavioralEvent::PointerMove {
            ts: 1,
            x: 10.0,
            y: 20.0,
            pressure: 0.0,
            twist: 0,
        });
        assert_eq!(c.len(), 1);
    }

    #[test]
    fn cap_drops_oldest() {
        let mut c = TelemetryCollector::with_cap(3);
        for i in 0..5 {
            c.record(BehavioralEvent::PointerMove {
                ts: i,
                x: i as f64,
                y: 0.0,
                pressure: 0.0,
                twist: 0,
            });
        }
        assert_eq!(c.len(), 3);
        let first = c.events().first().unwrap();
        assert!(
            matches!(first, BehavioralEvent::PointerMove { ts: 2, .. }),
            "oldest event should be ts=2"
        );
    }

    #[test]
    fn json_roundtrip_preserves_tagged_variant() {
        let mut c = TelemetryCollector::new();
        c.record(BehavioralEvent::KeyDown {
            ts: 42,
            key: "a".into(),
            code: "KeyA".into(),
        });
        let json = c.to_json().unwrap();
        assert!(json.contains("\"type\":\"key_down\""));
        let parsed: Vec<BehavioralEvent> = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, c.events().to_vec());
    }

    #[test]
    fn timestamp_extractor_round_trips_ts() {
        let e = BehavioralEvent::Scroll {
            ts: 1234,
            delta_x: 0.0,
            delta_y: 100.0,
            delta_mode: 0,
        };
        assert_eq!(e.timestamp(), 1234);
    }
}
