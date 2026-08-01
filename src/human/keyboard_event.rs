//! Keyboard-event sequence model (G175 / G176).
//!
//! Anti-bot detectors compare the `code` (physical key), `key` (logical value),
//! and event order emitted by real input. A synthetic `keypress` arriving before
//! `keydown`, or a `code` that does not match the declared layout, is an easy
//! tell. This module plans the canonical browser sequence for a single key:
//!
//!   `keydown` → (`keypress` for printable keys) → `input` → `keyup`
//!
//! and maps logical characters to QWERTY `code` values so `code` vs `key` stays
//! coherent.

/// A single keyboard event in the canonical sequence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyboardEvent {
    /// `keydown`
    KeyDown {
        /// DOM `key` value.
        key: String,
        /// DOM `code` value.
        code: String,
    },
    /// `keypress`: only for printable characters.
    KeyPress {
        /// DOM `key` value.
        key: String,
        /// DOM `code` value.
        code: String,
    },
    /// `input`: the value-change event between down and up.
    Input {
        /// DOM `key` value.
        key: String,
    },
    /// `keyup`
    KeyUp {
        /// DOM `key` value.
        key: String,
        /// DOM `code` value.
        code: String,
    },
}

impl KeyboardEvent {
    /// The event type string used by the DOM.
    pub fn event_type(&self) -> &'static str {
        match self {
            KeyboardEvent::KeyDown { .. } => "keydown",
            KeyboardEvent::KeyPress { .. } => "keypress",
            KeyboardEvent::Input { .. } => "input",
            KeyboardEvent::KeyUp { .. } => "keyup",
        }
    }
}

/// Map a logical key character to its US-QWERTY [`KeyboardEvent.code`] value
/// the *physical* key (keeping `code` coherent with the logical `key`).
///
/// Every key on a US-QWERTY keyboard has a non-empty `code`. Shifted symbols
/// report the code of the *unshifted* physical key they share (`!` → `Digit1`,
/// `?` → `Slash`, `_` → `Minus`), because `code` is layout-physical and
/// shift-independent. Characters with no US-QWERTY physical key (non-ASCII
/// letters that need a different layout or an IME) return `""`: the same empty
/// `code` real browsers report for IME-composed input. This function never
/// fabricates a code for a key that does not physically exist (an empty `code`
/// for an *ASCII* punctuation key, or a multi-byte glyph used as a `code`, is a
/// synthetic-input tell), so the only empty result is the genuinely
/// off-layout case.
#[must_use]
pub fn key_to_code(ch: char) -> String {
    match ch {
        // Named non-printable keys.
        '\u{0008}' => "Backspace",
        '\n' | '\r' => "Enter",
        '\t' => "Tab",
        ' ' => "Space",
        // Letters and digits sit on their own physical key.
        c if c.is_ascii_alphabetic() => return format!("Key{}", c.to_ascii_uppercase()),
        c if c.is_ascii_digit() => return format!("Digit{c}"),
        // Number-row shifted symbols share the unshifted digit's physical key.
        '!' => "Digit1",
        '@' => "Digit2",
        '#' => "Digit3",
        '$' => "Digit4",
        '%' => "Digit5",
        '^' => "Digit6",
        '&' => "Digit7",
        '*' => "Digit8",
        '(' => "Digit9",
        ')' => "Digit0",
        // Symbol keys: each unshifted/shifted pair shares one physical key.
        '`' | '~' => "Backquote",
        '-' | '_' => "Minus",
        '=' | '+' => "Equal",
        '[' | '{' => "BracketLeft",
        ']' | '}' => "BracketRight",
        '\\' | '|' => "Backslash",
        ';' | ':' => "Semicolon",
        '\'' | '"' => "Quote",
        ',' | '<' => "Comma",
        '.' | '>' => "Period",
        '/' | '?' => "Slash",
        // No US-QWERTY physical key (needs another layout or an IME): browsers
        // report an empty `code` for such composed input. Never fabricate one.
        _ => "",
    }
    .to_string()
}

/// Map a character to its logical [`KeyboardEvent.key`] value.
///
/// For printable characters this is the character itself; the non-printable
/// keys we synthesize get their canonical DOM key name (`Backspace`, `Enter`,
/// `Tab`) so `key` stays coherent with [`key_to_code`] rather than leaking a
/// raw control byte like `"\n"` (which no real `keydown` reports).
#[must_use]
pub fn key_to_key_value(ch: char) -> String {
    match ch {
        '\u{0008}' => "Backspace".to_string(),
        '\n' | '\r' => "Enter".to_string(),
        '\t' => "Tab".to_string(),
        _ => ch.to_string(),
    }
}

/// Map a character to the WebDriver-BiDi key VALUE that must be sent to produce a
/// faithful physical-key press, which is NOT always the same string as the DOM
/// [`key_to_key_value`] name used for telemetry.
///
/// The only divergence is the line break. The WebDriver normalized-key table has
/// two distinct Enter code points: `U+E006` (RETURN) renders as the MAIN keyboard
/// Enter (`code === "Enter"`), while `U+E007` (ENTER) renders as the numeric-
/// keypad Enter (`code === "NumpadEnter"`). The driver's named `"Enter"` (and its
/// normalization of `"\n"`/`"\r"`) both resolve to `U+E007`, so dispatching by
/// name makes every newline a *NumpadEnter*, a key a real typist almost never
/// uses to enter text, and therefore a behavioural tell. We instead send the raw
/// `U+E006` code point, which the BiDi layer passes through verbatim (its single-
/// character fast path) and Gecko renders as the main Enter (proven live in
/// `tests/shift_key_live.rs`). Backspace and Tab map by name (their named code
/// points already produce `code "Backspace"`/`"Tab"`); every printable character
/// is itself.
#[must_use]
pub fn key_to_bidi_dispatch_key(ch: char) -> String {
    match ch {
        // U+E006 RETURN → main Enter (code "Enter"), not U+E007 NumpadEnter.
        '\n' | '\r' => '\u{E006}'.to_string(),
        _ => key_to_key_value(ch),
    }
}

/// Whether producing `ch` on a US-QWERTY layout requires holding Shift: the
/// uppercase letters and the shifted punctuation row.
///
/// A real keyboard emits a `Shift` keydown around these characters, so the
/// resulting `keydown` carries `shiftKey === true`. A driver that sends the bare
/// character (`"H"`, `"!"`) instead produces an event with `shiftKey === false`
/// and no `ShiftLeft` keydown, which Gecko does NOT auto-correct (proven live in
/// `tests/shift_key_live.rs`) and which is impossible for genuine typed input, so
/// the dispatcher uses this to wrap shift-requiring characters in a real Shift
/// press. The unshifted symbols (`` ` - = [ ] \ ; ' , . / ``), digits, lowercase
/// letters, and space return `false`.
#[must_use]
pub fn needs_shift(ch: char) -> bool {
    ch.is_ascii_uppercase()
        || matches!(
            ch,
            '!' | '@'
                | '#'
                | '$'
                | '%'
                | '^'
                | '&'
                | '*'
                | '('
                | ')'
                | '_'
                | '+'
                | '{'
                | '}'
                | '|'
                | ':'
                | '"'
                | '<'
                | '>'
                | '?'
                | '~'
        )
}

/// Plan the canonical browser event sequence for typing `ch`.
///
/// Printable characters produce `[keydown, keypress, input, keyup]`;
/// non-printable characters (e.g. Backspace) produce `[keydown, keyup]`.
#[must_use]
pub fn plan_key_events(ch: char) -> Vec<KeyboardEvent> {
    let key = key_to_key_value(ch);
    let code = key_to_code(ch);
    let mut out = vec![KeyboardEvent::KeyDown {
        key: key.clone(),
        code: code.clone(),
    }];
    if is_printable(ch) {
        out.push(KeyboardEvent::KeyPress {
            key: key.clone(),
            code: code.clone(),
        });
        out.push(KeyboardEvent::Input { key: key.clone() });
    }
    out.push(KeyboardEvent::KeyUp { key, code });
    out
}

fn is_printable(ch: char) -> bool {
    !ch.is_control() && !ch.is_ascii_control()
}

/// Plan the sequence for a full string.
#[must_use]
pub fn plan_typed_text(text: &str) -> Vec<KeyboardEvent> {
    text.chars().flat_map(plan_key_events).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn printable_char_has_full_sequence() {
        let seq = plan_key_events('a');
        assert_eq!(seq.len(), 4);
        assert_eq!(seq[0].event_type(), "keydown");
        assert_eq!(seq[1].event_type(), "keypress");
        assert_eq!(seq[2].event_type(), "input");
        assert_eq!(seq[3].event_type(), "keyup");
    }

    #[test]
    fn backspace_has_no_input_event() {
        let seq = plan_key_events('\u{0008}');
        assert_eq!(seq.len(), 2);
        assert_eq!(seq[0].event_type(), "keydown");
        assert_eq!(seq[1].event_type(), "keyup");
    }

    #[test]
    fn needs_shift_covers_uppercase_and_shifted_symbols() {
        // Every uppercase ASCII letter needs Shift.
        for c in 'A'..='Z' {
            assert!(needs_shift(c), "{c} (uppercase) must need Shift");
        }
        // The full US-QWERTY shifted punctuation row.
        for c in "!@#$%^&*()_+{}|:\"<>?~".chars() {
            assert!(needs_shift(c), "{c:?} (shifted symbol) must need Shift");
        }
        // Lowercase letters, digits, space, and UNSHIFTED symbols do NOT.
        for c in 'a'..='z' {
            assert!(!needs_shift(c), "{c} (lowercase) must not need Shift");
        }
        for c in "0123456789 `-=[]\\;',./".chars() {
            assert!(!needs_shift(c), "{c:?} (unshifted) must not need Shift");
        }
        // Backspace control char never needs Shift.
        assert!(!needs_shift('\u{0008}'));
    }

    #[test]
    fn bidi_dispatch_sends_main_return_codepoint_for_newline() {
        // A newline must dispatch as U+E006 (RETURN → main Enter, code "Enter"),
        // NOT as the name "Enter" (which the driver resolves to U+E007 NumpadEnter,
        // a key real typists do not use for text). Carriage return maps the same.
        assert_eq!(key_to_bidi_dispatch_key('\n'), "\u{E006}");
        assert_eq!(key_to_bidi_dispatch_key('\r'), "\u{E006}");
        // It must NOT be the named-Enter string that resolves to the numpad key.
        assert_ne!(key_to_bidi_dispatch_key('\n'), "Enter");
        // The dispatch value is a single code point (the driver's verbatim fast
        // path), so it cannot be mistaken for a multi-char named key.
        assert_eq!(key_to_bidi_dispatch_key('\n').chars().count(), 1);

        // Backspace and Tab dispatch by name (their named code points already
        // yield the correct physical codes), identical to the telemetry key name.
        assert_eq!(key_to_bidi_dispatch_key('\u{0008}'), "Backspace");
        assert_eq!(key_to_bidi_dispatch_key('\t'), "Tab");

        // Every printable character dispatches as itself (matches key_to_key_value).
        for c in "aZ9!@ _-".chars() {
            assert_eq!(key_to_bidi_dispatch_key(c), c.to_string());
            assert_eq!(key_to_bidi_dispatch_key(c), key_to_key_value(c));
        }
    }

    #[test]
    fn code_matches_key_for_letters() {
        let seq = plan_key_events('A');
        assert!(matches!(
            &seq[0],
            KeyboardEvent::KeyDown { key, code } if key == "A" && code == "KeyA"
        ));
    }

    #[test]
    fn code_matches_key_for_digits() {
        let seq = plan_key_events('7');
        assert!(matches!(
            &seq[0],
            KeyboardEvent::KeyDown { key, code } if key == "7" && code == "Digit7"
        ));
    }

    #[test]
    fn typed_text_concatenates_sequences() {
        let seq = plan_typed_text("ab");
        assert_eq!(seq.len(), 8);
    }

    #[test]
    fn symbol_keys_map_to_physical_code() {
        // Regression: these all returned "" before, an empty `code` on a
        // keyboard event is impossible for a real physical key and is itself a
        // synthetic-input tell. Each must report the physical key it sits on.
        for (ch, want) in [
            ('-', "Minus"),
            ('_', "Minus"),
            ('=', "Equal"),
            ('+', "Equal"),
            ('[', "BracketLeft"),
            ('{', "BracketLeft"),
            (']', "BracketRight"),
            ('}', "BracketRight"),
            ('\\', "Backslash"),
            ('|', "Backslash"),
            (';', "Semicolon"),
            (':', "Semicolon"),
            ('\'', "Quote"),
            ('"', "Quote"),
            (',', "Comma"),
            ('<', "Comma"),
            ('.', "Period"),
            ('>', "Period"),
            ('/', "Slash"),
            ('?', "Slash"),
            ('`', "Backquote"),
            ('~', "Backquote"),
        ] {
            assert_eq!(key_to_code(ch), want, "code for {ch:?}");
        }
    }

    #[test]
    fn shifted_number_row_shares_digit_physical_key() {
        for (ch, want) in [
            ('!', "Digit1"),
            ('@', "Digit2"),
            ('#', "Digit3"),
            ('$', "Digit4"),
            ('%', "Digit5"),
            ('^', "Digit6"),
            ('&', "Digit7"),
            ('*', "Digit8"),
            ('(', "Digit9"),
            (')', "Digit0"),
        ] {
            assert_eq!(key_to_code(ch), want, "code for {ch:?}");
        }
    }

    #[test]
    fn every_printable_ascii_has_nonempty_code() {
        // The core contract: no printable ASCII key may report an empty `code`.
        // This is the property the old punctuation hole violated.
        for byte in 0x20u8..=0x7E {
            let ch = byte as char;
            let code = key_to_code(ch);
            assert!(
                !code.is_empty(),
                "printable ASCII {ch:?} (0x{byte:02X}) produced an empty code"
            );
            assert!(
                code.is_ascii(),
                "code {code:?} for {ch:?} must be an ASCII identifier"
            );
        }
    }

    #[test]
    fn named_keys_map_to_canonical_codes() {
        assert_eq!(key_to_code(' '), "Space");
        assert_eq!(key_to_code('\u{0008}'), "Backspace");
        assert_eq!(key_to_code('\n'), "Enter");
        assert_eq!(key_to_code('\r'), "Enter");
        assert_eq!(key_to_code('\t'), "Tab");
    }

    #[test]
    fn off_layout_char_has_empty_code_not_a_fabricated_one() {
        // A character with no US-QWERTY physical key reports "" (the IME-
        // composed case), never the raw multi-byte glyph as a bogus code.
        assert_eq!(key_to_code('é'), "");
        assert_eq!(key_to_code('好'), "");
        assert_ne!(key_to_code('é'), "é");
    }

    #[test]
    fn logical_key_value_is_coherent_with_code_for_named_keys() {
        // `key` for a synthesized Enter/Tab/Backspace must be the DOM key name,
        // not the raw control byte, so key↔code stay coherent on the wire.
        assert_eq!(key_to_key_value('\n'), "Enter");
        assert_eq!(key_to_key_value('\r'), "Enter");
        assert_eq!(key_to_key_value('\t'), "Tab");
        assert_eq!(key_to_key_value('\u{0008}'), "Backspace");
        assert_eq!(key_to_key_value('a'), "a");
        assert_eq!(key_to_key_value('!'), "!");
    }

    #[test]
    fn plan_key_events_uses_canonical_key_name_for_enter() {
        let seq = plan_key_events('\n');
        match &seq[0] {
            KeyboardEvent::KeyDown { key, code } => {
                assert_eq!(key, "Enter");
                assert_eq!(code, "Enter");
            }
            other => panic!("expected KeyDown, got {other:?}"),
        }
    }
}
