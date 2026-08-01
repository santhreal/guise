//! Network-layer fingerprint surfaces for the full-stack oracle (G202–G203).
//!
//! The differential oracle started as a JavaScript-surface diff (`navigator`,
//! WebGL, canvas, …). Real fingerprinters and WAFs classify the transport layer
//! *before* JS runs: JA3/JA4, HTTP/2 SETTINGS, TCP SYN options, so a
//! "full-stack" persona must be coherent there too. This module computes the
//! transport-layer surfaces a given [`ProfileBundle`] should present and exposes
//! them as [`CapturedSurface`] values that can be appended to a [`Capture`] and
//! diffed by the same oracle machinery.
//!
//! The transport surfaces are derived from the same persona bundle as the JS
//! layer, so a single identity feeds both stacks (G205).

use crate::fingerprint::{
    profile_os_network_stack, tls_profiles, tls_targets, ProfileBundle, StealthProfile,
    UserAgentPlatform,
};
use crate::probe::{Capture, CapturedSurface, Severity};

/// Transport-layer fingerprint values for one persona.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransportFingerprint {
    /// JA3 string for the TLS ClientHello.
    pub ja3: String,
    /// JA4 string for the TLS ClientHello.
    pub ja4: String,
    /// ALPN protocols advertised in the ClientHello, comma-joined.
    pub alpn: String,
    /// FoxIO JA4T TCP SYN fingerprint.
    pub ja4t: String,
    /// p0f-style SYN signature.
    pub p0f_signature: String,
    /// Akamai H2 fingerprint string, when a target is available.
    pub h2_akamai: Option<String>,
    /// Peet H2 fingerprint hash, when a target is available.
    pub h2_peet: Option<String>,
}

/// Compute the transport fingerprint the persona `bundle` should emit.
///
/// # Panics
///
/// Panics if `bundle.browser` resolves to a platform with no modeled TCP/IP
/// stack (this is a persona-construction bug, not a runtime probe failure).
#[must_use]
#[allow(clippy::expect_used)] // every persona ships a TLS profile; absence is a build-time bug
pub fn compute_transport_fingerprint(bundle: &ProfileBundle) -> TransportFingerprint {
    let tls_profile = tls_profiles::profile_for_stealth_profile(bundle.browser)
        .expect("persona must have a TLS ClientHello profile");
    let ja3 = tls_profiles::compute_ja3_string(tls_profile);
    let ja4 = tls_profiles::compute_ja4_string(tls_profile);
    let alpn = tls_profile.alpn_protocols.join(",");

    let os_stack = profile_os_network_stack(bundle.browser);
    let ja4t = os_stack
        .ja4t()
        .unwrap_or_else(|e| format!("ja4t-error:{e}"));
    let p0f_signature = os_stack.p0f_signature();

    let (h2_akamai, h2_peet) = match target_for_profile(bundle.browser) {
        Some(label) => tls_targets::lookup(label)
            .map(|t| (Some(t.akamai_h2.to_string()), Some(t.peet_h2.to_string())))
            .unwrap_or((None, None)),
        None => (None, None),
    };

    TransportFingerprint {
        ja3,
        ja4,
        alpn,
        ja4t,
        p0f_signature,
        h2_akamai,
        h2_peet,
    }
}

/// Map a stealth profile to the bundled TLS/H2 target label. Only profiles
/// with a measured target in [`tls_targets::FINGERPRINT_TARGETS`] get an H2
/// surface; others return `None` rather than fabricating a value.
fn target_for_profile(profile: StealthProfile) -> Option<&'static str> {
    match profile {
        StealthProfile::FirefoxLinux
        | StealthProfile::FirefoxWindows
        | StealthProfile::FirefoxMacStable => Some("firefox-150-linux"),
        StealthProfile::ChromeLinux
        | StealthProfile::ChromeWindowsStable
        | StealthProfile::ChromeMacStable
        | StealthProfile::ChromeAndroid
        | StealthProfile::BraveWindows
        | StealthProfile::OperaWindows
        | StealthProfile::SamsungInternetAndroid
        | StealthProfile::EdgeWindowsStable => Some("chrome-146-linux"),
        _ => None,
    }
}

/// Append transport-layer surfaces to `capture` so the oracle diffs them
/// alongside the JS surfaces.
pub fn enrich_capture(capture: &mut Capture, bundle: &ProfileBundle) {
    let fp = compute_transport_fingerprint(bundle);
    capture.surfaces.push(CapturedSurface {
        name: "transport.ja3".to_string(),
        severity: Severity::High,
        value: Ok(fp.ja3),
    });
    capture.surfaces.push(CapturedSurface {
        name: "transport.ja4".to_string(),
        severity: Severity::High,
        value: Ok(fp.ja4),
    });
    capture.surfaces.push(CapturedSurface {
        name: "transport.alpn".to_string(),
        severity: Severity::Medium,
        value: Ok(fp.alpn),
    });
    capture.surfaces.push(CapturedSurface {
        name: "transport.ja4t".to_string(),
        severity: Severity::High,
        value: Ok(fp.ja4t),
    });
    capture.surfaces.push(CapturedSurface {
        name: "transport.p0f_signature".to_string(),
        severity: Severity::Medium,
        value: Ok(fp.p0f_signature),
    });
    if let Some(h2) = fp.h2_akamai {
        capture.surfaces.push(CapturedSurface {
            name: "transport.h2_akamai".to_string(),
            severity: Severity::High,
            value: Ok(h2),
        });
    }
    if let Some(peet) = fp.h2_peet {
        capture.surfaces.push(CapturedSurface {
            name: "transport.h2_peet".to_string(),
            severity: Severity::High,
            value: Ok(peet),
        });
    }
}

/// Build a capture that contains *only* transport-layer surfaces for `bundle`.
/// Useful for transport-only oracle tests.
#[must_use]
pub fn transport_capture(bundle: &ProfileBundle, label: &str) -> Capture {
    let mut capture = Capture {
        label: label.to_string(),
        surfaces: Vec::new(),
    };
    enrich_capture(&mut capture, bundle);
    capture
}

/// True when the transport surfaces encode a Linux persona, which is the
/// default honest host for guise's Linux development environment.
#[must_use]
pub fn transport_suggests_linux_persona(bundle: &ProfileBundle) -> bool {
    let stack = profile_os_network_stack(bundle.browser);
    matches!(stack.os, UserAgentPlatform::Linux)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn firefox_transport_matches_expected_firefox_150_target() {
        let bundle = ProfileBundle::for_browser(StealthProfile::FirefoxLinux);
        let fp = compute_transport_fingerprint(&bundle);

        // The Firefox-150 TLS profile is the shipping desktop persona.
        assert!(
            fp.ja3.starts_with("771,"),
            "JA3 must start with TLS 1.3 legacy version: {}",
            fp.ja3
        );
        assert!(
            fp.ja4.starts_with("t13d1717h2"),
            "JA4 must reflect 17 ciphers / 17 extensions: {}",
            fp.ja4
        );
        assert_eq!(fp.alpn, "h2,http/1.1");
        assert!(!fp.ja4t.is_empty());
        assert!(!fp.p0f_signature.is_empty());

        // H2 target is populated for Firefox.
        let akamai = fp
            .h2_akamai
            .as_ref()
            .expect("Firefox must have an H2 target");
        assert!(
            akamai.contains("m,p,a,s"),
            "Firefox pseudo-header order is m,p,a,s: {akamai}"
        );
        assert!(fp.h2_peet.as_ref().unwrap().len() == 32);
    }

    #[test]
    fn chrome_transport_matches_expected_chrome_146_target() {
        let bundle = ProfileBundle::for_browser(StealthProfile::ChromeWindowsStable);
        let fp = compute_transport_fingerprint(&bundle);

        assert!(fp.ja3.starts_with("771,"));
        assert!(
            fp.ja4.starts_with("t13d1517h2"),
            "JA4 must reflect 15 ciphers / 17 extensions: {}",
            fp.ja4
        );
        assert_eq!(fp.alpn, "h2,http/1.1");

        let akamai = fp
            .h2_akamai
            .as_ref()
            .expect("Chrome must have an H2 target");
        assert!(
            akamai.contains("m,a,s,p"),
            "Chrome pseudo-header order is m,a,s,p: {akamai}"
        );
    }

    #[test]
    fn transport_capture_diff_reports_divergences() {
        use crate::probe::diff_captures;

        let firefox = ProfileBundle::for_browser(StealthProfile::FirefoxLinux);
        let chrome = ProfileBundle::for_browser(StealthProfile::ChromeLinux);
        let ff_cap = transport_capture(&firefox, "firefox");
        let ch_cap = transport_capture(&chrome, "chrome");

        let report = diff_captures(&ff_cap, &ch_cap);
        assert!(
            !report.is_identical(),
            "Firefox and Chrome transport must diverge"
        );

        let names: std::collections::HashSet<&str> = report
            .divergences
            .iter()
            .map(|d| d.surface.as_str())
            .collect();
        assert!(names.contains("transport.ja3"), "JA3 must diverge");
        assert!(names.contains("transport.ja4"), "JA4 must diverge");
        assert!(
            names.contains("transport.h2_akamai"),
            "H2 Akamai must diverge"
        );
    }

    #[test]
    fn linux_persona_is_detected_as_linux_transport() {
        let bundle = ProfileBundle::for_browser(StealthProfile::FirefoxLinux);
        assert!(transport_suggests_linux_persona(&bundle));
    }

    #[test]
    fn windows_persona_is_not_linux_transport() {
        let bundle = ProfileBundle::for_browser(StealthProfile::ChromeWindowsStable);
        assert!(!transport_suggests_linux_persona(&bundle));
    }
}
