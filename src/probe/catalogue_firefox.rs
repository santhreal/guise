//! Firefox-family fingerprint truths, the inverse of the Chromium-only surfaces
//! [`super::catalogue::probes_for`] drops for a Firefox target. Each asserts what
//! a *real* Firefox reports, so the gate confirms the disguise is coherent with
//! Gecko rather than penalising it for not being Chrome.

use super::catalogue::probe;
use super::classify::*;
use super::{Probe, Severity};

/// The Firefox-family probe set. Folded into [`super::catalogue::probes_for`]
/// when the target browser is Firefox (after the Chromium-only surfaces are
/// dropped).
pub(super) fn firefox_probes() -> Vec<Probe> {
    vec![
        // ─── Identity values that differ from Chromium ───────────────
        probe("navigator.vendor is empty (Firefox)",
            "navigator.vendor",
            Severity::Medium,
            classify_must_be_empty_string),
        probe("navigator.userAgent is Gecko/Firefox",
            "navigator.userAgent",
            Severity::High,
            classify_must_be_firefox_ua),
        // Firefox FREEZES navigator.appVersion to the OS-family form ("5.0 (X11)" /
        // "5.0 (Windows)" / "5.0 (Macintosh)"), NOT userAgent-minus-"Mozilla/".
        // Emitting the full UA string is a value no real Firefox reports (it leaks
        // "Firefox/<v>" and "rv:" into appVersion), the shared "appVersion
        // non-empty" probe could not catch it. Exact-match the frozen form.
        probe("navigator.appVersion is the frozen OS form (Firefox)",
            "(() => /^5\\.0 \\((X11|Windows|Macintosh)\\)$/.test(navigator.appVersion))()",
            Severity::High,
            classify_must_be_true),
        probe("navigator.productSub equals '20100101' (Firefox)",
            "navigator.productSub === '20100101'",
            Severity::Low,
            classify_must_be_true),
        probe("navigator.oscpu is a string (Firefox-only surface)",
            "typeof navigator.oscpu === 'string' && navigator.oscpu.length > 0",
            Severity::Medium,
            classify_must_be_true),
        // ─── Chromium-only surfaces that must be ABSENT on Firefox ───
        // Real Firefox has NO `chrome` key on window: BOTH `typeof window.chrome
        // === 'undefined'` AND `'chrome' in window === false` hold. Checking only
        // `typeof` misses a fabricated own accessor whose getter returns undefined
        // (`'chrome' in window` becomes true), exactly the self-inflicted tell the
        // old stealth JS created. Assert the key is genuinely absent, not just
        // undefined-valued.
        probe("window.chrome absent (Firefox)",
            "(typeof window.chrome === 'undefined' && !('chrome' in window)) ? null : 'present'",
            Severity::High,
            classify_must_be_undefined),
        probe("navigator.getBattery absent (Firefox)",
            "(typeof Navigator.prototype.getBattery === 'undefined' && typeof navigator.getBattery === 'undefined') ? null : 'present'",
            Severity::Medium,
            classify_must_be_undefined),
        probe("navigator.usb absent (Firefox)",
            "(typeof navigator.usb === 'undefined') ? null : 'present'",
            Severity::Medium,
            classify_must_be_undefined),
        probe("navigator.hid absent (Firefox)",
            "(typeof navigator.hid === 'undefined') ? null : 'present'",
            Severity::Low,
            classify_must_be_undefined),
        // navigator.serial is NOT asserted absent: a vanilla, non-automated
        // Firefox 151 on a secure origin exposes `navigator.serial` as a live
        // object (Firefox ships Web Serial in secure contexts). Asserting it
        // absent false-flagged a genuine current Firefox, serial is no longer a
        // Firefox-vs-Chromium discriminator (both expose it), so it carries no
        // probe. usb/hid/bluetooth below remain Gecko-absent (measured undefined).
        probe("navigator.bluetooth absent (Firefox desktop)",
            "(typeof navigator.bluetooth === 'undefined') ? null : 'present'",
            Severity::Low,
            classify_must_be_undefined),
        probe("window.PaymentRequest absent (Firefox)",
            "(typeof window.PaymentRequest === 'undefined') ? null : 'present'",
            Severity::Low,
            classify_must_be_undefined),
        probe("navigator.connection absent (Firefox)",
            "(typeof navigator.connection === 'undefined') ? null : 'present'",
            Severity::Low,
            classify_must_be_undefined),
        // G211: formerly a documented gap in tests/gap.rs. Firefox must not
        // expose Client Hints (`navigator.userAgentData`). A real Gecko browser
        // either lacks the property or exposes an empty brands list.
        probe("navigator.userAgentData absent or brands empty (Firefox)",
            "(() => { try { const uad = navigator.userAgentData; if (!uad) return null; const b = uad.brands || uad.fullVersionList; return Array.isArray(b) ? b : []; } catch (_) { return null; } })()",
            Severity::High,
            classify_user_agent_data_empty_or_absent),
        // ─── Extended-catalogue Chromium-only surfaces that must be ABSENT ───
        // The inverse of the EXTENDED Chromium-only surfaces dropped from the
        // Firefox catalogue: a real Gecko build exposes none of these, so their
        // PRESENCE on a Firefox persona is a Chromium-engine coherence tell (the
        // JS spoof faked the UA but is running on Blink). `performance.memory` is
        // the strongest (a non-standard Chrome-only API Firefox has never shipped).
        probe("performance.memory absent (Firefox)",
            "(typeof performance.memory === 'undefined') ? null : 'present'",
            Severity::Medium,
            classify_must_be_undefined),
        probe("navigator.keyboard absent (Firefox)",
            "(typeof navigator.keyboard === 'undefined') ? null : 'present'",
            Severity::Low,
            classify_must_be_undefined),
        probe("navigator.presentation absent (Firefox)",
            "(typeof navigator.presentation === 'undefined') ? null : 'present'",
            Severity::Low,
            classify_must_be_undefined),
        probe("navigator.scheduling absent (Firefox)",
            "(typeof navigator.scheduling === 'undefined') ? null : 'present'",
            Severity::Low,
            classify_must_be_undefined),
        probe("navigator.setAppBadge absent (Firefox)",
            "(typeof navigator.setAppBadge === 'undefined') ? null : 'present'",
            Severity::Low,
            classify_must_be_undefined),
        // NOTE: there is intentionally NO "DocumentPictureInPicture absent" probe.
        // Firefox 151 ships the Document Picture-in-Picture API in a secure context
        // (verified live, tests/surface_truth_live.rs: documentPictureInPicture ===
        // "object", DocumentPictureInPicture === "function"), so asserting its
        // absence was a false-Critical on guise's own browser. It is dropped for the
        // Firefox gate (CHROMIUM_ONLY_PROBES, category 2) without an inverse.
        probe("window.EyeDropper absent (Firefox)",
            "(typeof EyeDropper === 'undefined') ? null : 'present'",
            Severity::Low,
            classify_must_be_undefined),
        probe("AbsoluteOrientationSensor absent (Firefox)",
            "(typeof AbsoluteOrientationSensor === 'undefined') ? null : 'present'",
            Severity::Low,
            classify_must_be_undefined),
    ]
}
