//! G119, the shared surface-ID bridge between the fingerprint-surface
//! *inventory* ([`crate::fingerprint::surface::SURFACES`], keyed at method
//! granularity) and the runtime *probe catalogue* ([`super::catalogue`], keyed at
//! object granularity with descriptive names).
//!
//! The two taxonomies cannot be reconciled by string matching: a probe named
//! `"navigator.bluetooth exists"` exercises the inventory surface
//! `navigator.bluetooth.requestDevice`, and `"screen.colorDepth == 24"` exercises
//! `screen.colorDepth`: a `name.contains(surface)` check would miss both
//! (false negatives) and mis-link others (false positives). So the bridge is an
//! **explicit, curated** map: each [`ProbeSurfaceLink`] names a probe and the
//! inventory surface-id(s) it reads.
//!
//! This makes the inventory the *mechanical source* the probe catalogue is keyed
//! to, enforced bidirectionally (see the tests):
//!   1. every `covers` id is a real [`crate::fingerprint::surface::SURFACES`]
//!      surface, a typo or a removed surface fails the build;
//!   2. every linked probe name is a real catalogue probe (in the Chromium or
//!      Firefox family set), a renamed/dropped probe fails the build;
//!   3. a *pinned* coverage contract asserts exactly which `must_cover`
//!      (Critical/High) surfaces a runtime probe reaches, and names the ones that
//!      still lack one (an honest gap list, never a false "all covered)."
//!
//! The probe bridge covers the *intersection*: a probe is linked only when it
//! exercises an inventory surface. Automation-tell probes
//! (`window.chrome.runtime exists`, `Error.stack` markers, automation-global
//! scrubs) and pure web-platform presence probes are a different taxonomy and are
//! deliberately unlinked, they are not fingerprint-identity surfaces the
//! inventory tracks.
//!
//! **Spoof arm.** [`SPOOF_SURFACE_LINKS`] keys the *other* side, which inventory
//! surfaces guise's persona identity-override path
//! ([`crate::fingerprint::profile_to_overrides`] → `profile_js`) actively sets
//! to the same inventory, with the same referential integrity. That closes the
//! three-way taxonomy (inventory ↔ probe ↔ spoof) for the load-bearing identity
//! surfaces and enables the key coherence guard
//! `every_load_bearing_spoof_is_probe_verified`: every Critical/High surface
//! guise spoofs must also be reached by a runtime probe, so a spoof can never
//! ship an *unverified* defense.
//!
//! **Noise arm.** [`NOISE_SPOOF_LINKS`] keys the third injection path, the
//! `FingerprintConfig` noise IIFEs (canvas/audio/webgl-shape/font/performance
//! jitter + the hardware overrides), to the same inventory, grounded in the
//! ACTUAL emitted JS: each link carries a `js_token` the test asserts present in
//! `evasion_js_source` output, so the map can never drift from
//! `fingerprint::evasion::js`. Noise defenses perturb a surface statistically
//! rather than pin a value, so they are verified in AGGREGATE by the live
//! fingerprint oracle (CreepJS / the differential gate), not by a per-surface
//! probe, the one honest asymmetry vs. the identity arm, pinned by
//! `audio_analyser_noise_is_spoofed_but_not_per_surface_probed`. With this, all
//! three guise surfaces (inventory ↔ probe ↔ identity-spoof ↔ noise-spoof) are
//! one taxonomy keyed by a shared surface-ID. G119 fully closed.

use super::DivergenceKind;
use crate::fingerprint::surface;
use crate::fingerprint::SurfaceCategory;
use std::collections::BTreeSet;

/// One probe ↔ inventory-surface link: the shared surface-ID key (G119).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProbeSurfaceLink {
    /// The exact [`super::Probe::name`] of a probe in the catalogue.
    pub probe: &'static str,
    /// The inventory surface-id(s) from
    /// [`crate::fingerprint::surface::SURFACES`] this probe exercises.
    pub covers: &'static [&'static str],
}

const fn link(probe: &'static str, covers: &'static [&'static str]) -> ProbeSurfaceLink {
    ProbeSurfaceLink { probe, covers }
}

/// The curated probe→surface bridge. Each entry maps a catalogue probe to the
/// inventory surface-id(s) it reads. Probe names match [`super::catalogue`]
/// (Chromium core + misc) and the Firefox-family set exactly; surface-ids match
/// [`crate::fingerprint::surface::SURFACES`] exactly. Both directions are
/// build-enforced (see the tests).
pub const PROBE_SURFACE_LINKS: &[ProbeSurfaceLink] = &[
    // ── Native-shape (Function.prototype.toString) ───────────────────────
    link(
        "Function.prototype.toString returns native code for Navigator.prototype.webdriver getter",
        &["navigator.webdriver"],
    ),
    link(
        "Function.prototype.toString native for WebGL getParameter",
        &["webgl.getParameter"],
    ),
    link(
        "Function.prototype.toString native for toDataURL",
        &["canvas.toDataURL"],
    ),
    // ── Navigator identity ───────────────────────────────────────────────
    link("navigator.webdriver", &["navigator.webdriver"]),
    link(
        "navigator.webdriver is inherited, not an own property",
        &["navigator.webdriver"],
    ),
    link(
        "navigator.plugins.length > 0",
        &["navigator.plugins.length"],
    ),
    link(
        "navigator.plugins is a real PluginArray",
        &["navigator.plugins"],
    ),
    link("navigator.languages.length > 0", &["navigator.languages"]),
    link("navigator.language", &["navigator.language"]),
    link("navigator.vendor non-empty", &["navigator.vendor"]),
    link("navigator.userAgent", &["navigator.userAgent"]),
    link("navigator.platform non-empty", &["navigator.platform"]),
    link("navigator.cookieEnabled true", &["navigator.cookieEnabled"]),
    link(
        "navigator.hardwareConcurrency in [2, 16]",
        &["navigator.hardwareConcurrency"],
    ),
    link(
        "navigator.deviceMemory in [1, 64]",
        &["navigator.deviceMemory"],
    ),
    link(
        "navigator.connection.effectiveType exists",
        &["navigator.connection.effectiveType"],
    ),
    // ── WebGL ────────────────────────────────────────────────────────────
    link(
        "WebGL UNMASKED_VENDOR not SwiftShader",
        &["webgl.getParameter"],
    ),
    link(
        "WebGL UNMASKED_RENDERER not SwiftShader",
        &["webgl.getParameter"],
    ),
    // ── Canvas ───────────────────────────────────────────────────────────
    link(
        "CanvasRenderingContext2D getImageData session-stable (no per-read tell)",
        &["canvas.getImageData", "canvas.getContext"],
    ),
    link(
        "HTMLCanvasElement.toDataURL session-stable (no per-read tell)",
        &["canvas.toDataURL", "canvas.getContext"],
    ),
    link(
        "CanvasRenderingContext2D.measureText session-stable (no per-read tell)",
        &["canvas.measureText"],
    ),
    // ── Web Audio ────────────────────────────────────────────────────────
    link(
        "AudioBuffer.getChannelData session-stable (no per-read tell)",
        &["audio.getChannelData"],
    ),
    link(
        "AnalyserNode.getFloatFrequencyData is a function",
        &["audio.getFloatFrequencyData"],
    ),
    // ── WebRTC ───────────────────────────────────────────────────────────
    link("RTCPeerConnection exists", &["RTCPeerConnection"]),
    link(
        "RTCPeerConnection.createOffer is a function",
        &["RTCPeerConnection.createOffer"],
    ),
    // ── Device-prompt + peripheral APIs (Chromium present) ───────────────
    link("navigator.getBattery() exists", &["navigator.getBattery"]),
    link(
        "navigator.permissions.query exists",
        &["navigator.permissions.query"],
    ),
    link(
        "navigator.mediaDevices.enumerateDevices returns >=2",
        &["navigator.mediaDevices.enumerateDevices"],
    ),
    link(
        "navigator.mediaDevices.getUserMedia is a function",
        &["navigator.mediaDevices.getUserMedia"],
    ),
    link(
        "navigator.bluetooth exists",
        &["navigator.bluetooth.requestDevice"],
    ),
    link("navigator.usb exists", &["navigator.usb.requestDevice"]),
    link("navigator.hid exists", &["navigator.hid.requestDevice"]),
    link("navigator.serial exists", &["navigator.serial.requestPort"]),
    link(
        "navigator.getInstalledRelatedApps exists",
        &["navigator.getInstalledRelatedApps"],
    ),
    link("navigator.wakeLock exists", &["navigator.wakeLock.request"]),
    link("window.PaymentRequest exists", &["PaymentRequest"]),
    link("navigator.share exists", &["navigator.share"]),
    link("navigator.canShare exists", &["navigator.canShare"]),
    link(
        "navigator.serviceWorker exists",
        &["navigator.serviceWorker.register"],
    ),
    link(
        "speechSynthesis.getVoices returns >=16 voices",
        &["speechSynthesis.getVoices"],
    ),
    // ── Media / WebCodecs ────────────────────────────────────────────────
    link("VideoDecoder exists", &["VideoDecoder.isConfigSupported"]),
    link("VideoEncoder exists", &["VideoEncoder.isConfigSupported"]),
    link("VideoFrame exists", &["VideoFrame"]),
    link(
        "MediaCapabilities.decodingInfo exists",
        &["MediaCapabilities.decodingInfo"],
    ),
    // ── Screen ───────────────────────────────────────────────────────────
    link("screen.colorDepth == 24", &["screen.colorDepth"]),
    link("screen.pixelDepth == 24", &["screen.colorDepth"]),
    link(
        "screen.orientation.type exists",
        &["screen.orientation.type"],
    ),
    link("screen.width plausible", &["screen.width"]),
    link("screen.height plausible", &["screen.height"]),
    // ── Timezone / locale ────────────────────────────────────────────────
    link(
        "Intl.DateTimeFormat resolves an IANA time zone",
        &["Intl.DateTimeFormat", "Intl.DateTimeFormat.resolvedOptions"],
    ),
    // ── Notifications + permissions ──────────────────────────────────────
    link(
        "Notification.permission not 'denied'",
        &["Notification.requestPermission"],
    ),
    // ── Misc presence probes that map onto an inventory method ───────────
    link("matchMedia exists", &["matchMedia"]),
    link("ResizeObserver exists", &["ResizeObserver.observe"]),
    link(
        "IntersectionObserver exists",
        &["IntersectionObserver.observe"],
    ),
    link("MutationObserver exists", &["MutationObserver.observe"]),
    link("Notification exists", &["Notification.requestPermission"]),
    link("StorageManager exists", &["navigator.storage.estimate"]),
    link(
        "Element.requestFullscreen exists",
        &["element.requestFullscreen"],
    ),
    link("document.fonts exists", &["document.fonts.forEach"]),
    link("performance.now precision floored", &["performance.now"]),
    link(
        "navigator.userActivation exists",
        &["navigator.userActivation"],
    ),
    link("scheduler.postTask exists", &["scheduler.postTask"]),
    // ── Firefox-family truths (the inverse of the Chromium-only surfaces) ─
    link(
        "navigator.userAgent is Gecko/Firefox",
        &["navigator.userAgent"],
    ),
    link("navigator.vendor is empty (Firefox)", &["navigator.vendor"]),
    link(
        "navigator.getBattery absent (Firefox)",
        &["navigator.getBattery"],
    ),
    link(
        "navigator.usb absent (Firefox)",
        &["navigator.usb.requestDevice"],
    ),
    link(
        "navigator.hid absent (Firefox)",
        &["navigator.hid.requestDevice"],
    ),
    // navigator.serial is intentionally unlinked: FF-151 ships Web Serial in
    // secure contexts, so it is no longer asserted absent (see catalogue_firefox).
    link(
        "navigator.bluetooth absent (Firefox desktop)",
        &["navigator.bluetooth.requestDevice"],
    ),
    link(
        "window.PaymentRequest absent (Firefox)",
        &["PaymentRequest"],
    ),
    link(
        "navigator.connection absent (Firefox)",
        &["navigator.connection.effectiveType"],
    ),
];

/// One identity-spoof link (the evasion arm of G119): a [`ProfileOverrides`]
/// field guise sets and the inventory surface-id it controls. The mapping is the
/// field's own documented target (e.g. `user_agent` → `navigator.userAgent`), not
/// a guess, and the proof that a materialized persona actually carries a value
/// for it lives in the test, so the link is never a fabricated claim.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SpoofSurfaceLink {
    /// The override field, named for the reader (e.g. `ProfileOverrides::platform`).
    pub field: &'static str,
    /// The inventory surface-id this field controls.
    pub surface: &'static str,
}

const fn spoof(field: &'static str, surface: &'static str) -> SpoofSurfaceLink {
    SpoofSurfaceLink { field, surface }
}

/// The persona identity-override arm: which inventory surfaces
/// [`crate::fingerprint::profile_to_overrides`] (→ `profile_js`) actively sets.
/// This is the load-bearing spoof layer (UA/platform/identity/WebGL/screen). The
/// `FingerprintConfig` *noise* arm (canvas/audio/webgl-range/font/performance
/// jitter) is a separate injection path keyed by intensity, not by discrete
/// surface (it stays documented-residual rather than mapped on a guess).
pub const SPOOF_SURFACE_LINKS: &[SpoofSurfaceLink] = &[
    spoof("ProfileOverrides::user_agent", "navigator.userAgent"),
    spoof("ProfileOverrides::platform", "navigator.platform"),
    spoof("ProfileOverrides::navigator_vendor", "navigator.vendor"),
    spoof("ProfileOverrides::languages", "navigator.languages"),
    spoof(
        "ProfileOverrides::hardware_concurrency",
        "navigator.hardwareConcurrency",
    ),
    spoof("ProfileOverrides::device_memory", "navigator.deviceMemory"),
    spoof("ProfileOverrides::screen_width", "screen.width"),
    spoof("ProfileOverrides::screen_height", "screen.height"),
    spoof("ProfileOverrides::color_depth", "screen.colorDepth"),
    // The persona's `timezone` is applied via the engine `TZ` env (reaching ICU in
    // every realm), so `Intl.DateTimeFormat().resolvedOptions().timeZone` reports the
    // persona zone, NOT the host's. This makes a TZ divergence between a persona and
    // the raw host PersonaIntended (deliberate, locale-coherent, see
    // `default_timezone_for_locale`), not an engine tell. Without this link the
    // differential gate misclassified the (correct) persona TZ as an EngineDivergence.
    spoof(
        "ProfileOverrides::timezone",
        "Intl.DateTimeFormat.resolvedOptions",
    ),
    // WebGL is a CONDITIONAL spoof: a matched-host persona (FirefoxLinux) leaves
    // these empty for native passthrough (real adapter > pinned constant), so
    // `profile_js` pins WebGL only when set. The surface is still guise-controlled
    // (and probe-verified), which is what the link records.
    spoof("ProfileOverrides::webgl_vendor", "webgl.getParameter"),
    spoof("ProfileOverrides::webgl_renderer", "webgl.getParameter"),
];

/// The inventory surface-ids guise's identity-override arm actively spoofs.
#[must_use]
pub fn spoofed_surface_ids() -> BTreeSet<&'static str> {
    SPOOF_SURFACE_LINKS.iter().map(|l| l.surface).collect()
}

/// Every inventory surface guise's persona deliberately overrides, the union of
/// the identity-spoof and noise-injection arms. A divergence on one of these is
/// the persona differing from the raw host, by design.
#[must_use]
pub fn persona_overridden_surface_ids() -> BTreeSet<&'static str> {
    SPOOF_SURFACE_LINKS
        .iter()
        .map(|l| l.surface)
        .chain(NOISE_SPOOF_LINKS.iter().map(|l| l.surface))
        .collect()
}

/// Classify a diverging catalogue probe (by name): `PersonaIntended` if any
/// inventory surface it exercises is persona-overridden, else `EngineDivergence`.
#[must_use]
pub fn divergence_kind_for_probe(probe_name: &str) -> DivergenceKind {
    let overridden = persona_overridden_surface_ids();
    let intended = PROBE_SURFACE_LINKS
        .iter()
        .filter(|l| l.probe == probe_name)
        .flat_map(|l| l.covers.iter().copied())
        .any(|id| overridden.contains(id));
    if intended {
        DivergenceKind::PersonaIntended
    } else {
        DivergenceKind::EngineDivergence
    }
}

/// Resolve a catalogue probe name to the inventory [`SurfaceCategory`] it
/// exercises, via the bridge (probe → surface-id → category). `None` for a probe
/// with no inventory link (automation-tell / pure-presence probes that aren't
/// fingerprint-identity surfaces). Lets the differential oracle group a
/// divergence by surface family on the shared taxonomy (X021/X023) instead of a
/// bare probe name.
#[must_use]
pub fn category_for_probe(probe_name: &str) -> Option<SurfaceCategory> {
    surface_for_probe(probe_name).map(|s| s.category)
}

/// Resolve a catalogue probe name to the inventory [`FingerprintSurface`] it
/// exercises. `None` for unbridged probes. This is the primary bridge used by
/// the scorecard to anchor every divergence to the shared surface taxonomy
/// (G181/G217).
#[must_use]
pub fn surface_for_probe(probe_name: &str) -> Option<&'static surface::FingerprintSurface> {
    let link = PROBE_SURFACE_LINKS.iter().find(|l| l.probe == probe_name)?;
    let first = link.covers.first()?;
    surface::SURFACES.iter().find(|s| s.surface == *first)
}

/// Resolve a catalogue probe name to the inventory surface-id it exercises.
/// Convenience wrapper for [`surface_for_probe`].
#[must_use]
pub fn surface_id_for_probe(probe_name: &str) -> Option<&'static str> {
    surface_for_probe(probe_name).map(|s| s.surface)
}

/// One noise-injection link (the `FingerprintConfig` arm of G119): a noise axis,
/// the inventory surface its generated IIFE patches, and a `js_token` substring
/// that PROVES the emitted JS actually patches it, so the mapping is grounded in
/// `evasion_js_source` output, not a guess (the test asserts the token appears).
///
/// Noise defenses differ from identity overrides: they perturb a surface
/// statistically rather than pin an exact value, so they are verified in
/// AGGREGATE by the live fingerprint oracle (CreepJS / the differential gate),
/// not by a per-surface value probe, which is why they are NOT subject to
/// `every_load_bearing_spoof_is_probe_verified`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NoiseSpoofLink {
    /// The `FingerprintConfig` axis, named for the reader.
    pub axis: &'static str,
    /// The inventory surface-id the axis's IIFE patches.
    pub surface: &'static str,
    /// A substring of the emitted IIFE that proves the patch (asserted by test).
    pub js_token: &'static str,
}

const fn noise(
    axis: &'static str,
    surface: &'static str,
    js_token: &'static str,
) -> NoiseSpoofLink {
    NoiseSpoofLink {
        axis,
        surface,
        js_token,
    }
}

/// The `FingerprintConfig` noise-injection arm, grounded in the actual JS each
/// axis emits (see `fingerprint::evasion::js`). Every `surface` is a real
/// [`crate::fingerprint::surface::SURFACES`] entry; every `js_token` is asserted
/// present in `evasion_js_source` output so the map can never drift from the JS.
pub const NOISE_SPOOF_LINKS: &[NoiseSpoofLink] = &[
    noise(
        "FingerprintConfig::canvas_noise",
        "canvas.toDataURL",
        "toDataURL",
    ),
    // getImageData is the PRIMARY canvas-fingerprint extraction path; the canvas
    // IIFE farbles it at the source (not only the toDataURL/toBlob serialization).
    noise(
        "FingerprintConfig::canvas_noise",
        "canvas.getImageData",
        "getImageData",
    ),
    // getChannelData is the canonical OfflineAudioContext fingerprint path; the
    // audio IIFE farbles AudioBuffer.prototype.getChannelData idempotently.
    noise(
        "FingerprintConfig::audio_noise",
        "audio.getChannelData",
        "getChannelData",
    ),
    noise(
        "FingerprintConfig::audio_noise",
        "audio.getFloatFrequencyData",
        "getFloatFrequencyData",
    ),
    // The dominant font fingerprint is canvas measure-and-compare; font_noise now
    // scales TextMetrics uniformly (see `font_noise_js`) instead of perturbing
    // FontFaceSet enumeration (which leaked a size-vs-count tell and only touched
    // page-loaded faces, not installed system fonts).
    noise(
        "FingerprintConfig::font_noise",
        "canvas.measureText",
        "measureText",
    ),
    noise(
        "FingerprintConfig::performance_noise",
        "performance.now",
        "target.now = __seal",
    ),
    noise(
        "FingerprintConfig::webgl_override",
        "webgl.getSupportedExtensions",
        "getSupportedExtensions",
    ),
    noise(
        "FingerprintConfig::hardware_concurrency",
        "navigator.hardwareConcurrency",
        "hardwareConcurrency",
    ),
    noise(
        "FingerprintConfig::device_memory",
        "navigator.deviceMemory",
        "deviceMemory",
    ),
];

/// A coverage report over the inventory: which surfaces a runtime probe reaches.
#[derive(Debug, Clone)]
pub struct SurfaceCoverage {
    /// Inventory surface-ids exercised by at least one linked probe (sorted).
    pub covered: Vec<&'static str>,
    /// `Critical`/`High` (`must_cover`) surfaces with NO runtime probe, the
    /// honest gap. Sorted; empty would mean full critical coverage.
    pub uncovered_must_cover: Vec<&'static str>,
}

/// The set of inventory surface-ids covered by at least one link.
fn covered_ids() -> BTreeSet<&'static str> {
    PROBE_SURFACE_LINKS
        .iter()
        .flat_map(|l| l.covers.iter().copied())
        .collect()
}

/// Compute the probe-coverage report over [`SURFACES`].
///
/// `covered` is every inventory surface a linked probe exercises; the inventory
/// remains the mechanical source, so this is a faithful "what does the runtime
/// probe suite actually reach" view. `uncovered_must_cover` is the Critical/High
/// surfaces with no probe (surfaced as data, never papered over).
#[must_use]
pub fn surface_coverage() -> SurfaceCoverage {
    let covered_set = covered_ids();
    let covered: Vec<&'static str> = covered_set.iter().copied().collect();
    let uncovered_must_cover: Vec<&'static str> = surface::must_cover()
        .iter()
        .map(|s| s.surface)
        .filter(|id| !covered_set.contains(id))
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    SurfaceCoverage {
        covered,
        uncovered_must_cover,
    }
}

#[cfg(test)]
#[path = "surface_coverage/tests.rs"]
mod tests;
