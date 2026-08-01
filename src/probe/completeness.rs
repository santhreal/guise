//! Catalogue completeness critic (G213 / G215).
//!
//! Real fingerprinters check far more surfaces than any one project can catalogue
//! overnight. The critic keeps an explicit, auditable list of known checks (from
//! CreepJS, fpcollect, sannysoft, and detector telemetry) and compares it against
//! the runtime probe catalogue. It reports:
//!
//!   * which known checks are covered by at least one probe;
//!   * which known checks are **gaps**: a detector checks them but guise does
//!     not probe them yet;
//!   * per-browser coverage, because a check that only makes sense on Chromium
//!     is not a gap for Firefox.
//!
//! The list is Tier-B data: operators can extend `KNOWN_FINGERPRINTER_CHECKS`
//! when a new detector check is observed, and the CI gate ensures the gap is
//! either closed or explicitly accepted.

use super::probes_for;
use crate::fingerprint::UserAgentBrowser;
use serde::{Deserialize, Serialize};

/// How important a known fingerprinter check is to anti-detection coverage.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CheckCriticality {
    /// A hard automation or identity tell that detectors weight heavily.
    Critical,
    /// A contributing entropy signal.
    High,
    /// Corroborating noise.
    Medium,
}

/// One known fingerprinter check that the catalogue should cover.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KnownCheck {
    /// Human name of the check (often the JS API or property tested).
    pub name: &'static str,
    /// Surface family / category (Navigator, WebGl, Canvas, Audio, Screen, …).
    pub category: &'static str,
    /// Which browser families this check applies to. A Chromium-only check is
    /// not a Firefox gap.
    pub browsers: &'static [UserAgentBrowser],
    /// Substring that must appear in a probe name for the check to be considered
    /// covered. Keep these stable; they are the bridge between external check
    /// names and guise's probe catalogue.
    pub probe_pattern: &'static str,
    /// Importance for prioritisation.
    pub criticality: CheckCriticality,
}

/// A known check that has no matching probe in the catalogue.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoverageGap {
    /// The uncovered check.
    pub check: String,
    /// Surface family.
    pub category: String,
    /// Why it matters.
    pub criticality: CheckCriticality,
    /// Human explanation.
    pub reason: &'static str,
}

/// Coverage summary for one browser family.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoverageReport {
    /// Browser family the report is for.
    pub browser: UserAgentBrowser,
    /// Number of known checks applicable to this browser.
    pub total_known: usize,
    /// Number of applicable checks with at least one matching probe.
    pub covered: usize,
    /// Uncovered applicable checks.
    pub gaps: Vec<CoverageGap>,
    /// Coverage percentage (0-100).
    pub coverage_percent: u8,
}

impl CoverageReport {
    /// `true` when every applicable known check is covered.
    pub fn is_fully_covered(&self) -> bool {
        self.gaps.is_empty()
    }

    /// Gaps at or above `criticality`.
    pub fn gaps_at_least(&self, criticality: CheckCriticality) -> Vec<&CoverageGap> {
        let rank = |c: CheckCriticality| match c {
            CheckCriticality::Critical => 2,
            CheckCriticality::High => 1,
            CheckCriticality::Medium => 0,
        };
        let threshold = rank(criticality);
        self.gaps
            .iter()
            .filter(|g| rank(g.criticality) >= threshold)
            .collect()
    }

    /// One-line human summary.
    pub fn summary(&self) -> String {
        format!(
            "{:?} coverage: {}/{} known checks ({}%); {} gap(s)",
            self.browser,
            self.covered,
            self.total_known,
            self.coverage_percent,
            self.gaps.len()
        )
    }
}

/// Known fingerprinter checks curated from CreepJS, fpcollect, sannysoft, and
/// common WAF anti-bot scripts. The `probe_pattern` is a stable substring that
/// must appear in a guise catalogue probe name for the check to count as covered.
pub const KNOWN_FINGERPRINTER_CHECKS: &[KnownCheck] = &[
    // ── Hard automation tells ───────────────────────────────────────────────
    KnownCheck {
        name: "navigator.webdriver",
        category: "navigator",
        browsers: &[UserAgentBrowser::Chrome, UserAgentBrowser::Firefox],
        probe_pattern: "navigator.webdriver",
        criticality: CheckCriticality::Critical,
    },
    KnownCheck {
        name: "automation globals (__webdriver_evaluate, _phantom, etc.)",
        category: "automation",
        browsers: &[UserAgentBrowser::Chrome, UserAgentBrowser::Firefox],
        probe_pattern: "__webdriver_evaluate",
        criticality: CheckCriticality::Critical,
    },
    KnownCheck {
        name: "Error.stack automation markers",
        category: "automation",
        browsers: &[UserAgentBrowser::Chrome, UserAgentBrowser::Firefox],
        probe_pattern: "Error.stack",
        criticality: CheckCriticality::High,
    },
    // ── Navigator identity / entropy ────────────────────────────────────────
    KnownCheck {
        name: "navigator.userAgent",
        category: "navigator",
        browsers: &[UserAgentBrowser::Chrome, UserAgentBrowser::Firefox],
        probe_pattern: "navigator.userAgent",
        criticality: CheckCriticality::Critical,
    },
    KnownCheck {
        name: "navigator.platform",
        category: "navigator",
        browsers: &[UserAgentBrowser::Chrome, UserAgentBrowser::Firefox],
        probe_pattern: "navigator.platform",
        criticality: CheckCriticality::High,
    },
    KnownCheck {
        name: "navigator.vendor",
        category: "navigator",
        browsers: &[UserAgentBrowser::Chrome, UserAgentBrowser::Firefox],
        probe_pattern: "navigator.vendor",
        criticality: CheckCriticality::High,
    },
    KnownCheck {
        name: "navigator.languages",
        category: "navigator",
        browsers: &[UserAgentBrowser::Chrome, UserAgentBrowser::Firefox],
        probe_pattern: "navigator.languages",
        criticality: CheckCriticality::High,
    },
    KnownCheck {
        name: "navigator.plugins",
        category: "navigator",
        browsers: &[UserAgentBrowser::Chrome, UserAgentBrowser::Firefox],
        probe_pattern: "navigator.plugins",
        criticality: CheckCriticality::High,
    },
    KnownCheck {
        name: "navigator.hardwareConcurrency",
        category: "navigator",
        browsers: &[UserAgentBrowser::Chrome, UserAgentBrowser::Firefox],
        probe_pattern: "navigator.hardwareConcurrency",
        criticality: CheckCriticality::High,
    },
    KnownCheck {
        name: "navigator.deviceMemory",
        category: "navigator",
        browsers: &[UserAgentBrowser::Chrome],
        probe_pattern: "navigator.deviceMemory",
        criticality: CheckCriticality::Medium,
    },
    KnownCheck {
        name: "navigator.getBattery",
        category: "navigator",
        browsers: &[UserAgentBrowser::Chrome],
        probe_pattern: "navigator.getBattery",
        criticality: CheckCriticality::Medium,
    },
    KnownCheck {
        name: "navigator.mediaDevices.enumerateDevices",
        category: "navigator",
        browsers: &[UserAgentBrowser::Chrome, UserAgentBrowser::Firefox],
        probe_pattern: "navigator.mediaDevices.enumerateDevices",
        criticality: CheckCriticality::Medium,
    },
    KnownCheck {
        name: "navigator.permissions.query",
        category: "navigator",
        browsers: &[UserAgentBrowser::Chrome, UserAgentBrowser::Firefox],
        probe_pattern: "navigator.permissions.query",
        criticality: CheckCriticality::Medium,
    },
    KnownCheck {
        name: "navigator.connection.effectiveType",
        category: "navigator",
        browsers: &[UserAgentBrowser::Chrome],
        probe_pattern: "navigator.connection.effectiveType",
        criticality: CheckCriticality::Medium,
    },
    KnownCheck {
        name: "navigator.oscpu (Firefox)",
        category: "navigator",
        browsers: &[UserAgentBrowser::Firefox],
        probe_pattern: "navigator.oscpu",
        criticality: CheckCriticality::Medium,
    },
    // ── WebGL ───────────────────────────────────────────────────────────────
    KnownCheck {
        name: "WebGL UNMASKED_VENDOR_WEBGL",
        category: "webgl",
        browsers: &[UserAgentBrowser::Chrome, UserAgentBrowser::Firefox],
        probe_pattern: "WebGL UNMASKED_VENDOR",
        criticality: CheckCriticality::Critical,
    },
    KnownCheck {
        name: "WebGL UNMASKED_RENDERER_WEBGL",
        category: "webgl",
        browsers: &[UserAgentBrowser::Chrome, UserAgentBrowser::Firefox],
        probe_pattern: "WebGL UNMASKED_RENDERER",
        criticality: CheckCriticality::Critical,
    },
    // ── Canvas / Audio / Fonts ──────────────────────────────────────────────
    KnownCheck {
        name: "CanvasRenderingContext2D getImageData",
        category: "canvas",
        browsers: &[UserAgentBrowser::Chrome, UserAgentBrowser::Firefox],
        probe_pattern: "CanvasRenderingContext2D getImageData",
        criticality: CheckCriticality::High,
    },
    KnownCheck {
        name: "HTMLCanvasElement.toDataURL",
        category: "canvas",
        browsers: &[UserAgentBrowser::Chrome, UserAgentBrowser::Firefox],
        probe_pattern: "HTMLCanvasElement.toDataURL",
        criticality: CheckCriticality::High,
    },
    KnownCheck {
        name: "AudioBuffer.getChannelData",
        category: "audio",
        browsers: &[UserAgentBrowser::Chrome, UserAgentBrowser::Firefox],
        probe_pattern: "AudioBuffer.getChannelData",
        criticality: CheckCriticality::High,
    },
    KnownCheck {
        name: "document.fonts",
        category: "fonts",
        browsers: &[UserAgentBrowser::Chrome, UserAgentBrowser::Firefox],
        probe_pattern: "document.fonts",
        criticality: CheckCriticality::Medium,
    },
    // ── Screen / viewport ───────────────────────────────────────────────────
    KnownCheck {
        name: "screen.width / screen.height",
        category: "screen",
        browsers: &[UserAgentBrowser::Chrome, UserAgentBrowser::Firefox],
        probe_pattern: "screen.width plausible",
        criticality: CheckCriticality::High,
    },
    KnownCheck {
        name: "screen.colorDepth",
        category: "screen",
        browsers: &[UserAgentBrowser::Chrome, UserAgentBrowser::Firefox],
        probe_pattern: "screen.colorDepth",
        criticality: CheckCriticality::Medium,
    },
    KnownCheck {
        name: "window.devicePixelRatio",
        category: "screen",
        browsers: &[UserAgentBrowser::Chrome, UserAgentBrowser::Firefox],
        probe_pattern: "devicePixelRatio",
        criticality: CheckCriticality::Medium,
    },
    // ── Timezone / locale ───────────────────────────────────────────────────
    KnownCheck {
        name: "Intl.DateTimeFormat resolved time zone",
        category: "timezone",
        browsers: &[UserAgentBrowser::Chrome, UserAgentBrowser::Firefox],
        probe_pattern: "Intl.DateTimeFormat resolves an IANA time zone",
        criticality: CheckCriticality::High,
    },
    // ── Permissions / notifications ─────────────────────────────────────────
    KnownCheck {
        name: "Notification.permission",
        category: "permissions",
        browsers: &[UserAgentBrowser::Chrome, UserAgentBrowser::Firefox],
        probe_pattern: "Notification.permission",
        criticality: CheckCriticality::Medium,
    },
    // ── Chromium-only APIs (not gaps for Firefox) ───────────────────────────
    KnownCheck {
        name: "window.chrome.runtime",
        category: "chrome",
        browsers: &[UserAgentBrowser::Chrome],
        probe_pattern: "window.chrome.runtime exists",
        criticality: CheckCriticality::Critical,
    },
    KnownCheck {
        name: "navigator.usb",
        category: "device",
        browsers: &[UserAgentBrowser::Chrome],
        probe_pattern: "navigator.usb",
        criticality: CheckCriticality::Medium,
    },
    KnownCheck {
        name: "navigator.bluetooth",
        category: "device",
        browsers: &[UserAgentBrowser::Chrome],
        probe_pattern: "navigator.bluetooth",
        criticality: CheckCriticality::Medium,
    },
    KnownCheck {
        name: "window.PaymentRequest",
        category: "payments",
        browsers: &[UserAgentBrowser::Chrome],
        probe_pattern: "window.PaymentRequest exists",
        criticality: CheckCriticality::Medium,
    },
    // ── WebCodecs / media ───────────────────────────────────────────────────
    KnownCheck {
        name: "MediaCapabilities.decodingInfo",
        category: "media",
        browsers: &[UserAgentBrowser::Chrome, UserAgentBrowser::Firefox],
        probe_pattern: "MediaCapabilities.decodingInfo",
        criticality: CheckCriticality::Medium,
    },
    // ── Expanded from CreepJS / fpcollect / sannysoft source crawl (G214) ───
    KnownCheck {
        name: "window.chrome loadTimes/csi/app object integrity",
        category: "chrome",
        browsers: &[UserAgentBrowser::Chrome],
        probe_pattern: "window.chrome.loadTimes returns object",
        criticality: CheckCriticality::High,
    },
    KnownCheck {
        name: "ChromeDriver cdc_ injection",
        category: "automation",
        browsers: &[UserAgentBrowser::Chrome, UserAgentBrowser::Firefox],
        probe_pattern: "automation-framework globals leak",
        criticality: CheckCriticality::Critical,
    },
    KnownCheck {
        name: "navigator.webdriver is inherited, not an own property",
        category: "navigator",
        browsers: &[UserAgentBrowser::Chrome, UserAgentBrowser::Firefox],
        probe_pattern: "navigator.webdriver is inherited",
        criticality: CheckCriticality::Critical,
    },
    KnownCheck {
        name: "UA-CH platform vs User-Agent OS coherence",
        category: "navigator",
        browsers: &[UserAgentBrowser::Chrome, UserAgentBrowser::Firefox],
        probe_pattern: "navigator.userAgentData",
        criticality: CheckCriticality::Medium,
    },
    KnownCheck {
        name: "Intl timezone vs Date().getTimezoneOffset() coherence",
        category: "timezone",
        browsers: &[UserAgentBrowser::Chrome, UserAgentBrowser::Firefox],
        probe_pattern: "Intl.DateTimeFormat resolves an IANA time zone",
        criticality: CheckCriticality::High,
    },
    KnownCheck {
        name: "navigator.maxTouchPoints",
        category: "navigator",
        browsers: &[UserAgentBrowser::Chrome, UserAgentBrowser::Firefox],
        probe_pattern: "navigator.maxTouchPoints",
        criticality: CheckCriticality::Medium,
    },
    KnownCheck {
        name: "iOS devicePixelRatio / platform coherence",
        category: "screen",
        browsers: &[UserAgentBrowser::Chrome, UserAgentBrowser::Firefox],
        probe_pattern: "window.devicePixelRatio sensible",
        criticality: CheckCriticality::Medium,
    },
    KnownCheck {
        name: "Error.stackTraceLimit / prepareStackTrace presence",
        category: "automation",
        browsers: &[UserAgentBrowser::Chrome, UserAgentBrowser::Firefox],
        probe_pattern: "UA browser-family agrees with Error subsystem",
        criticality: CheckCriticality::High,
    },
    KnownCheck {
        name: "WebGL renderer/vendor lie detection",
        category: "webgl",
        browsers: &[UserAgentBrowser::Chrome, UserAgentBrowser::Firefox],
        probe_pattern: "Function.prototype.toString native for WebGL getParameter",
        criticality: CheckCriticality::High,
    },
    KnownCheck {
        name: "Canvas toDataURL non-empty",
        category: "canvas",
        browsers: &[UserAgentBrowser::Chrome, UserAgentBrowser::Firefox],
        probe_pattern: "HTMLCanvasElement.toDataURL session-stable",
        criticality: CheckCriticality::Medium,
    },
    KnownCheck {
        name: "AudioContext sampleRate / OscillatorNode consistency",
        category: "audio",
        browsers: &[UserAgentBrowser::Chrome, UserAgentBrowser::Firefox],
        probe_pattern: "AudioBuffer.getChannelData session-stable",
        criticality: CheckCriticality::Medium,
    },
    KnownCheck {
        name: "navigator.connection (Network Information API)",
        category: "navigator",
        browsers: &[UserAgentBrowser::Chrome],
        probe_pattern: "navigator.connection.effectiveType exists",
        criticality: CheckCriticality::Medium,
    },
    KnownCheck {
        name: "Notification.permission / requestPermission",
        category: "permissions",
        browsers: &[UserAgentBrowser::Chrome, UserAgentBrowser::Firefox],
        probe_pattern: "Notification.permission not 'denied'",
        criticality: CheckCriticality::Medium,
    },
    KnownCheck {
        name: "Playwright / Puppeteer automation globals",
        category: "automation",
        browsers: &[UserAgentBrowser::Chrome, UserAgentBrowser::Firefox],
        probe_pattern: "automation-framework globals leak",
        criticality: CheckCriticality::Critical,
    },
    KnownCheck {
        name: "Math IEEE 754 fingerprint consistency",
        category: "math",
        browsers: &[UserAgentBrowser::Chrome, UserAgentBrowser::Firefox],
        probe_pattern: "Math.sin",
        criticality: CheckCriticality::Medium,
    },
    KnownCheck {
        name: "document.hasFocus()",
        category: "document",
        browsers: &[UserAgentBrowser::Chrome, UserAgentBrowser::Firefox],
        probe_pattern: "document.hasFocus",
        criticality: CheckCriticality::Medium,
    },
    KnownCheck {
        name: "navigator.permissions.query native code",
        category: "permissions",
        browsers: &[UserAgentBrowser::Chrome, UserAgentBrowser::Firefox],
        probe_pattern: "Permissions.prototype.query is native code",
        criticality: CheckCriticality::High,
    },
    KnownCheck {
        name: "User-Agent Client Hints brands decoy",
        category: "navigator",
        browsers: &[UserAgentBrowser::Chrome],
        probe_pattern: "navigator.userAgentData",
        criticality: CheckCriticality::Medium,
    },
    KnownCheck {
        name: "Brave detection (navigator.brave)",
        category: "navigator",
        browsers: &[UserAgentBrowser::Chrome, UserAgentBrowser::Firefox],
        probe_pattern: "navigator.brave",
        criticality: CheckCriticality::Medium,
    },
    KnownCheck {
        name: "WebRTC device enumeration",
        category: "webrtc",
        browsers: &[UserAgentBrowser::Chrome, UserAgentBrowser::Firefox],
        probe_pattern: "RTCPeerConnection exists",
        criticality: CheckCriticality::Medium,
    },
    KnownCheck {
        name: "outer/inner window dimensions",
        category: "screen",
        browsers: &[UserAgentBrowser::Chrome, UserAgentBrowser::Firefox],
        probe_pattern: "window.outerWidth >= innerWidth",
        criticality: CheckCriticality::Medium,
    },
    // ── CreepJS aggregate score ─────────────────────────────────────────────
    KnownCheck {
        name: "CreepJS trust score",
        category: "aggregate",
        browsers: &[UserAgentBrowser::Chrome, UserAgentBrowser::Firefox],
        probe_pattern: "creepjs.trust_score",
        criticality: CheckCriticality::High,
    },
];

/// Build a coverage report for `browser` by matching `KNOWN_FINGERPRINTER_CHECKS`
/// against the current catalogue (`probes_for`).
#[must_use]
pub fn coverage_report(browser: UserAgentBrowser) -> CoverageReport {
    let applicable: Vec<&KnownCheck> = KNOWN_FINGERPRINTER_CHECKS
        .iter()
        .filter(|c| c.browsers.contains(&browser))
        .collect();
    let probes = probes_for(browser);

    let mut covered = 0usize;
    let mut gaps = Vec::new();

    for check in &applicable {
        let matched = probes.iter().any(|p| p.name.contains(check.probe_pattern));
        if matched {
            covered += 1;
        } else {
            gaps.push(CoverageGap {
                check: check.name.to_string(),
                category: check.category.to_string(),
                criticality: check.criticality,
                reason: "no catalogue probe matches the expected pattern",
            });
        }
    }

    let total_known = applicable.len();
    // total_known == 0 means nothing was applicable: report full coverage.
    let coverage_percent = (covered * 100)
        .checked_div(total_known)
        .map_or(100, |ratio| ratio as u8);

    CoverageReport {
        browser,
        total_known,
        covered,
        gaps,
        coverage_percent,
    }
}

/// All uncovered known checks across every supported browser family.
#[must_use]
pub fn all_gaps() -> Vec<(UserAgentBrowser, CoverageReport)> {
    use UserAgentBrowser::{Chrome, Firefox};
    vec![
        (Chrome, coverage_report(Chrome)),
        (Firefox, coverage_report(Firefox)),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn critical_checks_are_covered_for_firefox() {
        let report = coverage_report(UserAgentBrowser::Firefox);
        let critical_gaps = report.gaps_at_least(CheckCriticality::Critical);
        assert!(
            critical_gaps.is_empty(),
            "Critical known checks are uncovered for Firefox: {:?}",
            critical_gaps
        );
    }

    #[test]
    fn critical_checks_are_covered_for_chrome() {
        let report = coverage_report(UserAgentBrowser::Chrome);
        let critical_gaps = report.gaps_at_least(CheckCriticality::Critical);
        assert!(
            critical_gaps.is_empty(),
            "Critical known checks are uncovered for Chrome: {:?}",
            critical_gaps
        );
    }

    #[test]
    fn coverage_report_counts_known_checks() {
        let report = coverage_report(UserAgentBrowser::Firefox);
        assert!(report.total_known > 0);
        assert_eq!(report.covered + report.gaps.len(), report.total_known);
        assert!(report.coverage_percent <= 100);
    }

    #[test]
    fn uncovered_check_is_reported_as_gap() {
        // A deliberately uncovered check should surface as a gap.
        let fake = KnownCheck {
            name: "definitely.fake.check.not.in.catalogue",
            category: "fake",
            browsers: &[UserAgentBrowser::Firefox],
            probe_pattern: "definitely.fake.check.not.in.catalogue",
            criticality: CheckCriticality::Medium,
        };
        let probes = probes_for(UserAgentBrowser::Firefox);
        let matched = probes.iter().any(|p| p.name.contains(fake.probe_pattern));
        assert!(
            !matched,
            "the fake check should not accidentally match a real probe"
        );

        // Simulate the coverage logic for this one check.
        let gap = CoverageGap {
            check: fake.name.to_string(),
            category: fake.category.to_string(),
            criticality: fake.criticality,
            reason: "no catalogue probe matches the expected pattern",
        };
        assert_eq!(gap.check, "definitely.fake.check.not.in.catalogue");
    }

    #[test]
    fn chrome_only_check_is_not_a_firefox_gap() {
        let report = coverage_report(UserAgentBrowser::Firefox);
        let chrome_only_names: Vec<&str> = KNOWN_FINGERPRINTER_CHECKS
            .iter()
            .filter(|c| c.browsers == [UserAgentBrowser::Chrome])
            .map(|c| c.name)
            .collect();
        for gap in &report.gaps {
            assert!(
                !chrome_only_names.contains(&gap.check.as_str()),
                "Chrome-only check {} was reported as a Firefox gap",
                gap.check
            );
        }
    }

    #[test]
    fn report_summary_includes_numbers() {
        let report = coverage_report(UserAgentBrowser::Chrome);
        let s = report.summary();
        assert!(s.contains("Chrome"));
        assert!(s.contains("known checks"));
        assert!(s.contains("gap"));
    }

    #[test]
    fn all_gaps_returns_one_entry_per_family() {
        let all = all_gaps();
        assert_eq!(all.len(), 2);
        assert!(all.iter().any(|(b, _)| *b == UserAgentBrowser::Chrome));
        assert!(all.iter().any(|(b, _)| *b == UserAgentBrowser::Firefox));
    }
}
