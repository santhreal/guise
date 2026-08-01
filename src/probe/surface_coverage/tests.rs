use super::*;
use crate::fingerprint::surface::SURFACES;
use crate::fingerprint::UserAgentBrowser;
use std::collections::BTreeSet;

/// The referential-integrity universe: every probe name across the family
/// catalogues (Chromium core + misc + codec/redteam, and the Firefox truths).
/// A linked probe must appear here.
fn all_catalogue_probe_names() -> BTreeSet<&'static str> {
    let mut names = BTreeSet::new();
    for browser in [UserAgentBrowser::Chrome, UserAgentBrowser::Firefox] {
        for p in crate::probe::probes_for(browser) {
            names.insert(p.name);
        }
    }
    names
}

fn inventory_ids() -> BTreeSet<&'static str> {
    SURFACES.iter().map(|s| s.surface).collect()
}

#[test]
fn every_linked_surface_id_exists_in_the_inventory() {
    // Direction 1: the inventory is the mechanical source. A `covers` id that is
    // not a real SURFACES entry is a typo or a removed surface, fail loud with
    // the offending pair, never silently track a phantom surface.
    let ids = inventory_ids();
    for l in PROBE_SURFACE_LINKS {
        assert!(
            !l.covers.is_empty(),
            "link for probe `{}` covers no surface, an empty link is dead weight",
            l.probe
        );
        for id in l.covers {
            assert!(
                ids.contains(id),
                "probe `{}` links surface-id `{id}`, which is not in SURFACES, the \
                 inventory is the source of truth; add the surface or fix the id",
                l.probe
            );
        }
    }
}

#[test]
fn every_linked_probe_exists_in_the_catalogue() {
    // Direction 2: every link names a REAL catalogue probe. A renamed or dropped
    // probe leaves a dangling link (caught here, not discovered in production).
    let names = all_catalogue_probe_names();
    for l in PROBE_SURFACE_LINKS {
        assert!(
            names.contains(l.probe),
            "linked probe `{}` is not in the catalogue (Chromium or Firefox family). \
             a probe was renamed/removed without updating its surface link",
            l.probe
        );
    }
}

#[test]
fn no_duplicate_probe_surface_pairs() {
    // A probe may legitimately cover several surfaces, and several probes may
    // cover one surface, but the SAME (probe, surface) pair twice is a copy-paste
    // slip that inflates the link table without adding coverage.
    let mut seen = BTreeSet::new();
    for l in PROBE_SURFACE_LINKS {
        for id in l.covers {
            assert!(
                seen.insert((l.probe, *id)),
                "duplicate link: probe `{}` → surface `{id}` appears twice",
                l.probe
            );
        }
    }
}

#[test]
fn coverage_contract_pins_the_must_cover_gap() {
    // The HONEST coverage contract. `must_cover` is the Critical/High set a
    // disguise must get right; this pins EXACTLY which of those a runtime probe
    // reaches and which still lack one. The uncovered list is named on purpose
    // a real capability gap surfaced as data, never papered over as "all covered."
    //
    // Adding a probe for one of these (e.g. an Intl.DateTimeFormat timezone probe)
    // must move it out of this list, forcing the contract to track the win.
    let cov = surface_coverage();

    let expected_uncovered = [
        // WebGPU adapter: a High surface modern detectors read, but its presence
        // is FF-version/OS conditional so no sound hard probe yet, an HONEST
        // named gap (the whole point of the coverage report), not padded.
        // (RTCPeerConnection.createOffer, audio.getFloatFrequencyData, and
        // navigator.mediaDevices.getUserMedia each gained a runtime probe.)
        "navigator.gpu.requestAdapter",
    ];
    assert_eq!(
        cov.uncovered_must_cover, expected_uncovered,
        "the must-cover coverage gap drifted; if a probe was added/removed update \
         this pin so the honest gap list stays exact"
    );

    // The load-bearing surfaces MUST have a runtime probe, these are the ones a
    // detector weights most and a regression here is a real recall hole.
    for id in [
        "navigator.webdriver",
        "navigator.userAgent",
        "navigator.platform",
        "navigator.plugins",
        "navigator.plugins.length",
        "navigator.languages",
        "navigator.hardwareConcurrency",
        "webgl.getParameter",
        "canvas.getImageData",
        "canvas.toDataURL",
        "audio.getChannelData",
        "RTCPeerConnection",
        "screen.width",
        "screen.height",
        "navigator.bluetooth.requestDevice",
        "navigator.usb.requestDevice",
        "Intl.DateTimeFormat",
        "Intl.DateTimeFormat.resolvedOptions",
    ] {
        assert!(
            cov.covered.contains(&id),
            "load-bearing surface `{id}` lost its runtime probe link"
        );
    }
}

#[test]
fn covered_set_is_substantial_and_sorted() {
    let cov = surface_coverage();
    // The bridge must reach a meaningful slice of the inventory, not a token few.
    assert!(
        cov.covered.len() >= 30,
        "probe coverage collapsed to {} surfaces",
        cov.covered.len()
    );
    // covered + uncovered_must_cover are both sorted (BTreeSet-derived) so the
    // operator-facing report is stable run-to-run.
    let mut sorted = cov.covered.clone();
    sorted.sort_unstable();
    assert_eq!(cov.covered, sorted, "covered list must be sorted");
}

#[test]
fn category_for_probe_resolves_via_the_bridge() {
    use crate::fingerprint::SurfaceCategory;
    assert_eq!(
        category_for_probe("navigator.webdriver"),
        Some(SurfaceCategory::Navigator)
    );
    assert_eq!(
        category_for_probe("WebGL UNMASKED_VENDOR not SwiftShader"),
        Some(SurfaceCategory::WebGl)
    );
    assert_eq!(
        category_for_probe("Intl.DateTimeFormat resolves an IANA time zone"),
        Some(SurfaceCategory::Timezone)
    );
    // An automation-tell probe is not a fingerprint-identity surface → unbridged.
    assert_eq!(category_for_probe("window.chrome.runtime exists"), None);
    assert_eq!(category_for_probe("not a real probe name"), None);
}

#[test]
fn divergence_kind_distinguishes_persona_override_from_engine() {
    // Surfaces the persona deliberately overrides → PersonaIntended.
    assert_eq!(
        divergence_kind_for_probe("navigator.hardwareConcurrency in [2, 16]"),
        DivergenceKind::PersonaIntended
    );
    assert_eq!(
        divergence_kind_for_probe("screen.width plausible"),
        DivergenceKind::PersonaIntended
    );
    // Timezone is persona-applied (TZ env → Intl.DateTimeFormat.resolvedOptions), so a
    // persona-vs-host TZ divergence is PersonaIntended, not an engine tell. Regression
    // fence for the missing `ProfileOverrides::timezone` spoof-link (the reynard gate
    // misclassified the correct persona TZ as EngineDivergence before it was added).
    assert_eq!(
        divergence_kind_for_probe("Intl.DateTimeFormat resolves an IANA time zone"),
        DivergenceKind::PersonaIntended
    );
    // navigator.webdriver is NOT persona-overridden → EngineDivergence (a real
    // engine difference (here a reynard win, but the operator still looks)).
    assert_eq!(
        divergence_kind_for_probe("navigator.webdriver"),
        DivergenceKind::EngineDivergence
    );
    // Unbridged automation-tell probe → EngineDivergence by default (we never
    // fabricate a persona-override explanation).
    assert_eq!(
        divergence_kind_for_probe("window.chrome.runtime exists"),
        DivergenceKind::EngineDivergence
    );
}

#[test]
fn webcodecs_surfaces_are_probed() {
    // G120/G121 atomicity: each new surface lands with a runtime probe on the
    // shared taxonomy. These are Medium-criticality media capabilities; a
    // persona claiming a modern browser should expose them.
    let probed: BTreeSet<&'static str> = surface_coverage().covered.into_iter().collect();
    for id in [
        "VideoDecoder.isConfigSupported",
        "VideoEncoder.isConfigSupported",
        "VideoFrame",
        "MediaCapabilities.decodingInfo",
    ] {
        assert!(
            probed.contains(id),
            "WebCodecs/MediaCapabilities surface `{id}` lacks a runtime probe"
        );
    }
}

#[test]
fn covered_surfaces_are_all_real_inventory_entries() {
    // Belt-and-braces: the report never names a surface outside the inventory.
    let ids = inventory_ids();
    for id in surface_coverage().covered {
        assert!(
            ids.contains(id),
            "coverage names non-inventory surface `{id}`"
        );
    }
}

// ─── Spoof arm (evasion side of G119) ────────────────────────────────────

#[test]
fn every_spoofed_surface_id_exists_in_the_inventory() {
    // The spoof arm is keyed to the same inventory: a field claiming to control
    // a non-existent surface is a typo or a removed surface (fail loud).
    let ids = inventory_ids();
    for l in SPOOF_SURFACE_LINKS {
        assert!(
            ids.contains(l.surface),
            "spoof field `{}` controls surface-id `{}`, not in SURFACES",
            l.field,
            l.surface
        );
    }
    // The public diagnostic agrees and is a real subset of the inventory.
    let spoofed = spoofed_surface_ids();
    assert!(!spoofed.is_empty(), "the spoof arm covers no surface");
    assert!(spoofed.iter().all(|id| ids.contains(id)));
}

#[test]
fn every_load_bearing_spoof_is_probe_verified() {
    // THE cross-check that ties the two arms together: every Critical/High
    // surface guise actively SPOOFS must also be reached by a runtime probe.
    // A spoofed-but-unprobed load-bearing surface is an UNVERIFIED defense, the
    // override could silently fail to take and the self-test would never notice
    // (Law 10, applied to coherence). Today every load-bearing identity override
    // is probe-verified; this guard keeps it that way.
    let must_cover: BTreeSet<&'static str> = crate::fingerprint::surface::must_cover()
        .iter()
        .map(|s| s.surface)
        .collect();
    let probed: BTreeSet<&'static str> = surface_coverage().covered.into_iter().collect();
    for l in SPOOF_SURFACE_LINKS {
        if must_cover.contains(l.surface) {
            assert!(
                probed.contains(l.surface),
                "guise spoofs load-bearing surface `{}` (via {}) but no runtime probe \
                 verifies it, add a probe or the spoof ships unverified",
                l.surface,
                l.field
            );
        }
    }
}

#[test]
fn every_persona_materializes_the_spoofed_identity_values() {
    // Proof the spoof arm is REAL, not a claim: a materialized persona actually
    // carries a value for every UNCONDITIONAL identity surface across ALL_PROFILES.
    //
    // Two fields are present-by-design but not always non-empty, and the loop
    // must respect that or it asserts a falsehood:
    //   - `navigator_vendor`: empty IS the Gecko fingerprint (empty-iff-Firefox,
    //     proven by the bundle coherence gate).
    //   - `webgl_vendor`/`webgl_renderer`: a *native-passthrough* persona
    //     (FirefoxLinux, real Firefox on real Linux) deliberately leaves these
    //     empty so the host's real, Gecko-sanitized adapter shows through, which
    //     is strictly more coherent than a pinned constant. `profile_js` pins
    //     WebGL only when these are set. So WebGL is a CONDITIONAL spoof, proven
    //     real below on a cross-host persona that does pin it.
    use crate::fingerprint::{profile_to_overrides, StealthProfile, ALL_PROFILES};
    for p in ALL_PROFILES {
        let o = profile_to_overrides(p);
        assert!(!o.user_agent.is_empty(), "{p:?}: empty user_agent");
        assert!(!o.platform.is_empty(), "{p:?}: empty platform");
        assert!(!o.languages.is_empty(), "{p:?}: empty languages");
        assert!(
            o.hardware_concurrency > 0,
            "{p:?}: zero hardware_concurrency"
        );
        assert!(o.device_memory > 0, "{p:?}: zero device_memory");
        assert!(
            o.screen_width > 0 && o.screen_height > 0,
            "{p:?}: zero screen dims"
        );
        assert!(o.color_depth > 0, "{p:?}: zero color_depth");
    }

    // The WebGL spoof IS real for a persona that needs it: a Windows Chrome
    // persona is not running on a matched host, so it MUST pin a coherent
    // (vendor, renderer) pair rather than leak the real adapter.
    let win = profile_to_overrides(&StealthProfile::ChromeWindowsStable);
    assert!(
        !win.webgl_vendor.is_empty() && !win.webgl_renderer.is_empty(),
        "ChromeWindowsStable must pin WebGL (cross-host persona), got \
         vendor={:?} renderer={:?}",
        win.webgl_vendor,
        win.webgl_renderer
    );
}

// ─── Noise arm (FingerprintConfig side of G119) ──────────────────────────

#[test]
fn every_noise_surface_id_exists_in_the_inventory() {
    let ids = inventory_ids();
    for l in NOISE_SPOOF_LINKS {
        assert!(
            ids.contains(l.surface),
            "noise axis `{}` patches surface-id `{}`, not in SURFACES",
            l.axis,
            l.surface
        );
    }
}

#[test]
fn every_noise_link_is_grounded_in_the_emitted_js() {
    // THE proof the noise map is not a guess: turn on every axis, generate the
    // real evasion JS, and assert each link's js_token actually appears, so a
    // link can never claim a surface the IIFE does not patch (no fabrication).
    use crate::fingerprint::{evasion_js_source, FingerprintConfig};
    let cfg = FingerprintConfig {
        canvas_noise: 0.05,
        webgl_override: true,
        audio_noise: true,
        font_noise: true,
        performance_noise: true,
        hardware_concurrency: Some(8),
        device_memory: Some(8),
        seed: Some(0x5eed_1234),
    };
    let js = evasion_js_source(&cfg);
    assert!(!js.is_empty(), "all-axes config produced no JS");
    for l in NOISE_SPOOF_LINKS {
        assert!(
            js.contains(l.js_token),
            "noise axis `{}` claims to patch `{}` via token {:?}, but the emitted JS \
             does not contain it, the map drifted from fingerprint::evasion::js",
            l.axis,
            l.surface,
            l.js_token
        );
    }
}

#[test]
fn audio_farble_surfaces_are_both_noised_and_probe_present() {
    // Coherence contract for the audio noise arm: the two canonical audio
    // fingerprint surfaces guise farbles: `audio.getChannelData` (the
    // OfflineAudioContext path) and `audio.getFloatFrequencyData` (the realtime
    // AnalyserNode path), are BOTH in the noise map AND reached by a runtime
    // probe. Whether the noise actually DEVIATES from the host fingerprint is a
    // cross-session property verified in aggregate by the live CreepJS/oracle gate
    // (a single-session probe cannot see it); what the per-surface probe verifies
    // is presence/native-shape and session-stability (the tell-free invariants).
    let noise_surfaces: BTreeSet<&'static str> =
        NOISE_SPOOF_LINKS.iter().map(|l| l.surface).collect();
    let probed: BTreeSet<&'static str> = surface_coverage().covered.into_iter().collect();
    for surface in ["audio.getChannelData", "audio.getFloatFrequencyData"] {
        assert!(
            noise_surfaces.contains(surface),
            "{surface} must be in the noise map (the audio farble patches it)"
        );
        assert!(
            probed.contains(surface),
            "{surface} must be reached by a runtime probe (it is a must-cover audio surface)"
        );
    }
}
