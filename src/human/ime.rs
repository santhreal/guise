//! IME / composition-event model (G177).
//!
//! Non-Latin input (CJK, Arabic, etc.) is typically composed in an IME window
//! before being committed to the DOM. Real browsers emit a specific sequence:
//!
//!   `compositionstart` → `compositionupdate` → `input` → `compositionend`
//!
//! for each composed segment. Missing or out-of-order composition events are a
//! strong automation tell on internationalized pages.

/// One IME-related event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CompositionEvent {
    /// IME composition has started.
    CompositionStart,
    /// The intermediate composition string changed.
    CompositionUpdate {
        /// Current intermediate composition text.
        data: String,
    },
    /// The intermediate string was inserted into the editable element.
    Input {
        /// Inserted text.
        data: String,
        /// Whether the insertion is part of an active composition.
        is_composing: bool,
    },
    /// IME composition finished and the final string was committed.
    CompositionEnd {
        /// Committed final text.
        data: String,
    },
}

impl CompositionEvent {
    /// The DOM event type string.
    pub fn event_type(&self) -> &'static str {
        match self {
            CompositionEvent::CompositionStart => "compositionstart",
            CompositionEvent::CompositionUpdate { .. } => "compositionupdate",
            CompositionEvent::Input { .. } => "input",
            CompositionEvent::CompositionEnd { .. } => "compositionend",
        }
    }
}

/// Plan the canonical composition-event sequence for a composed string.
///
/// `segments` are the intermediate strings shown by the IME before the final
/// commit. For example, typing Japanese かんじ might produce segments
/// `["か", "かん", "かんじ"]` before committing "漢字".
#[must_use]
pub fn plan_ime_sequence(segments: &[String], committed: &str) -> Vec<CompositionEvent> {
    let mut out = Vec::with_capacity(segments.len() * 2 + 3);
    out.push(CompositionEvent::CompositionStart);
    for seg in segments {
        out.push(CompositionEvent::CompositionUpdate { data: seg.clone() });
        out.push(CompositionEvent::Input {
            data: seg.clone(),
            is_composing: true,
        });
    }
    out.push(CompositionEvent::CompositionEnd {
        data: committed.to_string(),
    });
    // Final committed input is no longer composing.
    out.push(CompositionEvent::Input {
        data: committed.to_string(),
        is_composing: false,
    });
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ime_sequence_starts_with_compositionstart() {
        let seq = plan_ime_sequence(&["ka".to_string()], "か");
        assert_eq!(seq.first().unwrap().event_type(), "compositionstart");
    }

    #[test]
    fn ime_sequence_ends_with_committed_input() {
        let seq = plan_ime_sequence(&["ka".to_string(), "kan".to_string()], "漢字");
        let last = seq.last().unwrap();
        assert_eq!(last.event_type(), "input");
        assert!(
            matches!(
                last,
                CompositionEvent::Input {
                    is_composing: false,
                    ..
                }
            ),
            "final input must not be composing"
        );
    }

    #[test]
    fn ime_sequence_has_intermediate_updates() {
        let seq = plan_ime_sequence(&["a".to_string(), "ab".to_string()], "AB");
        let updates: Vec<_> = seq
            .iter()
            .filter(|e| matches!(e, CompositionEvent::CompositionUpdate { .. }))
            .collect();
        assert_eq!(updates.len(), 2);
    }
}
