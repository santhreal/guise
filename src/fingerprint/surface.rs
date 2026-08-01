//! Canonical fingerprint-surface inventory, the browser surfaces an anti-bot
//! or sandbox-detection engine reads to tell automation from a human.
//!
//! Mined from the Santh `sear` detonation engine's sandbox instrumentation
//! (`detonation/sear/src/sandbox/bootstrap.js`), which taps every fingerprint
//! API a script touches via `__sear_record_fingerprint(...)`. **Inverted**: each
//! surface sear instruments to *detect* a script is a surface `stealth` must
//! present convincingly.
//!
//! Scope (be precise): this module is the canonical **reference inventory** of
//! *what a detector reads*, keyed at method granularity
//! (`navigator.bluetooth.requestDevice`). The runtime [`crate::probe`] catalogue
//! keys at object granularity (`navigator.bluetooth exists`) with descriptive
//! names, a real granularity gap that makes a naive `probe.name.contains(surface)`
//! parity check unsound (false negatives).
//!
//! **G119 (the probe arm, landed):** that gap is now reconciled by an *explicit,
//! curated* bridge, [`crate::probe::surface_coverage::PROBE_SURFACE_LINKS`], that
//! maps each probe to the inventory surface-id(s) it exercises by a shared
//! surface-ID key. It is enforced bidirectionally, every link references a real
//! [`SURFACES`] surface AND a real catalogue probe (a typo or a renamed/removed
//! probe fails the build), and a *pinned* coverage contract asserts exactly which
//! `must_cover` surfaces a runtime probe reaches and names the ones that still
//! lack one (an honest gap, never a false "all covered"). So this inventory is
//! the mechanical source the probe catalogue is checked against, not an
//! independent list. Both spoof paths are keyed to this inventory too: the
//! persona **identity-override** arm (`profile_to_overrides` → `profile_js`) via
//! [`crate::probe::surface_coverage::SPOOF_SURFACE_LINKS`] (with a guard that
//! every load-bearing surface guise spoofs is also probe-verified), and the
//! `FingerprintConfig` **noise-injection** arm via
//! [`crate::probe::surface_coverage::NOISE_SPOOF_LINKS`] (grounded in the actual
//! emitted JS by a per-link token, verified in aggregate by the live oracle). All
//! three guise surfaces are now one taxonomy on a shared surface-ID key. G119
//! closed.

use serde::{Deserialize, Serialize};

/// The family a fingerprint surface belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SurfaceCategory {
    /// `navigator.*` identity (UA, platform, languages, plugins, webdriver, …).
    Navigator,
    /// Hardware-access prompts (Bluetooth, USB, HID, Serial, XR, media devices).
    DevicePrompt,
    /// WebGL renderer/vendor/extension surface.
    WebGl,
    /// 2D canvas fingerprint surface.
    Canvas,
    /// Web Audio fingerprint surface.
    Audio,
    /// WebRTC / RTCPeerConnection (also an IP-leak vector).
    WebRtc,
    /// Screen, viewport, orientation, and media-query surface.
    Screen,
    /// Timezone / locale.
    Timezone,
    /// Document/window lifecycle and visibility (a headless tab betrays these).
    Lifecycle,
    /// Storage, cache, clipboard, and file-picker surfaces.
    Storage,
    /// Crypto-wallet, WebAuthn, and payment surfaces.
    CryptoAuth,
    /// Sensors and observers (geolocation, motion, intersection, mutation).
    Sensor,
    /// Notifications, push, background sync, service worker.
    Notification,
    /// Speech synthesis.
    Speech,
    /// Font enumeration (`document.fonts` / FontFaceSet iteration), a classic
    /// high-entropy fingerprint surface.
    Font,
    /// High-resolution timing (`performance.now`), the timer-precision surface
    /// anti-bot scripts probe and guise can jitter.
    Timing,
    /// Media-capability surfaces (WebCodecs `VideoDecoder`/`VideoEncoder`,
    /// MediaCapabilities) (what a client claims it can decode/encode).
    Media,
}

/// How strongly mishandling a surface betrays automation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Criticality {
    /// A direct, unambiguous automation tell (e.g. `navigator.webdriver`).
    Critical,
    /// A strong fingerprint signal weighted heavily by detectors.
    High,
    /// A contributing signal.
    Medium,
    /// A weak / corroborating signal.
    Low,
}

/// One browser fingerprint surface a detector reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FingerprintSurface {
    /// The JS access path the detector reads (e.g. `navigator.webdriver`).
    pub surface: &'static str,
    /// The family this surface belongs to.
    pub category: SurfaceCategory,
    /// How strongly mishandling it betrays automation.
    pub criticality: Criticality,
}

const fn s(
    surface: &'static str,
    category: SurfaceCategory,
    criticality: Criticality,
) -> FingerprintSurface {
    FingerprintSurface {
        surface,
        category,
        criticality,
    }
}

use Criticality::{Critical, High, Low, Medium};
use SurfaceCategory::{
    Audio, Canvas, CryptoAuth, DevicePrompt, Font, Lifecycle, Media, Navigator, Notification,
    Screen, Sensor, Speech, Storage, Timezone, Timing, WebGl, WebRtc,
};

/// The sear-mined fingerprint-surface inventory. Each entry is a surface a
/// real-world detector / sandbox reads. This is the reference catalogue of
/// *what to cover*. The runtime [`crate::probe`] suite is mechanically keyed to
/// it via [`crate::probe::surface_coverage`] (G119): adding a surface here that a
/// probe exercises also gets it linked there, and the coverage contract names any
/// `must_cover` surface still lacking a probe. The CDP/evasion injection covers
/// an overlapping set independently (not yet keyed, the residual G119 half), so
/// adding a surface here records the target but does not by itself generate a
/// spoof.
pub const SURFACES: &[FingerprintSurface] = &[
    // ── Navigator identity ────────────────────────────────────────────────
    s("navigator.webdriver", Navigator, Critical),
    s("navigator.userAgent", Navigator, High),
    s("navigator.platform", Navigator, High),
    s("navigator.language", Navigator, Medium),
    s("navigator.languages", Navigator, High),
    s("navigator.vendor", Navigator, Medium),
    s("navigator.hardwareConcurrency", Navigator, High),
    s("navigator.deviceMemory", Navigator, Medium),
    s("navigator.connection.effectiveType", Navigator, Low),
    s("navigator.plugins", Navigator, High),
    s("navigator.plugins.length", Navigator, High),
    s("navigator.cookieEnabled", Navigator, Low),
    s("navigator.getBattery", Navigator, Medium),
    s("navigator.vibrate", Navigator, Low),
    s("navigator.wakeLock.request", Navigator, Medium),
    s("navigator.permissions.query", Navigator, High),
    s("navigator.share", Navigator, Medium),
    s("navigator.canShare", Navigator, Medium),
    s("navigator.storage.estimate", Navigator, Medium),
    s("navigator.registerProtocolHandler", Navigator, Low),
    s("navigator.setAppBadge", Navigator, Low),
    s("navigator.clearAppBadge", Navigator, Low),
    s("navigator.contacts.select", Navigator, Low),
    s("navigator.getInstalledRelatedApps", Navigator, Low),
    // ── Hardware-access prompts (often absent in headless) ────────────────
    s("navigator.bluetooth.requestDevice", DevicePrompt, High),
    s("navigator.usb.requestDevice", DevicePrompt, High),
    s("navigator.serial.requestPort", DevicePrompt, High),
    s("navigator.hid.requestDevice", DevicePrompt, High),
    s("navigator.xr.isSessionSupported", DevicePrompt, Medium),
    s("navigator.mediaDevices.getUserMedia", DevicePrompt, High),
    s(
        "navigator.mediaDevices.enumerateDevices",
        DevicePrompt,
        High,
    ),
    s(
        "navigator.mediaDevices.getDisplayMedia",
        DevicePrompt,
        Medium,
    ),
    // ── WebGL ─────────────────────────────────────────────────────────────
    s("webgl.getParameter", WebGl, High),
    s("webgl.getSupportedExtensions", WebGl, Medium),
    s("webgl.readPixels", WebGl, Medium),
    // WebGPU adapter info (`navigator.gpu.requestAdapter().info`), a modern,
    // heavily-weighted GPU fingerprint surface. Presence is FF-version/OS
    // conditional, so it has no hard presence probe yet (an honest coverage gap).
    s("navigator.gpu.requestAdapter", WebGl, High),
    // ── Canvas ────────────────────────────────────────────────────────────
    s("canvas.getContext", Canvas, Medium),
    s("canvas.getImageData", Canvas, High),
    s("canvas.measureText", Canvas, Medium),
    s("canvas.toDataURL", Canvas, High),
    // ── Web Audio ─────────────────────────────────────────────────────────
    s("audio.createAnalyser", Audio, Medium),
    s("audio.createOscillator", Audio, Medium),
    s("audio.getFloatFrequencyData", Audio, High),
    s("audio.getChannelData", Audio, High),
    s("audio.oscillator.start", Audio, Low),
    s("audio.resume", Audio, Low),
    s("audio.startRendering", Audio, Medium),
    // ── WebRTC ────────────────────────────────────────────────────────────
    s("RTCPeerConnection", WebRtc, High),
    s("RTCPeerConnection.createOffer", WebRtc, High),
    s("RTCPeerConnection.createAnswer", WebRtc, Medium),
    s("RTCPeerConnection.createDataChannel", WebRtc, Medium),
    // ── Screen / viewport ─────────────────────────────────────────────────
    s("screen.width", Screen, High),
    s("screen.height", Screen, High),
    s("screen.colorDepth", Screen, Low),
    s("screen.orientation.angle", Screen, Low),
    s("screen.orientation.type", Screen, Low),
    s("window.orientation", Screen, Low),
    s("matchMedia", Screen, Medium),
    // ── Timezone / locale ─────────────────────────────────────────────────
    s("Intl.DateTimeFormat", Timezone, High),
    s("Intl.DateTimeFormat.resolvedOptions", Timezone, High),
    // ── Lifecycle / visibility ────────────────────────────────────────────
    s("document.hidden", Lifecycle, Medium),
    s("document.visibilityState", Lifecycle, Medium),
    s("document.visibilitychange", Lifecycle, Medium),
    s("window.beforeunload", Lifecycle, Low),
    s("window.pagehide", Lifecycle, Low),
    s("window.name.read", Lifecycle, Low),
    s("element.requestFullscreen", Lifecycle, Low),
    s("element.requestPointerLock", Lifecycle, Low),
    s("navigator.userActivation", Lifecycle, Low),
    // ── Storage / cache / clipboard / files ───────────────────────────────
    s("caches.open", Storage, Medium),
    s("cache.add", Storage, Low),
    s("cache.addAll", Storage, Low),
    s("cache.match", Storage, Low),
    s("cache.put", Storage, Low),
    s("clipboard.readText", Storage, Medium),
    s("clipboard.writeText", Storage, Medium),
    s("showDirectoryPicker", Storage, Medium),
    s("showOpenFilePicker", Storage, Medium),
    s("showSaveFilePicker", Storage, Medium),
    s("URL.createObjectURL", Storage, Low),
    // ── Crypto wallet / WebAuthn / payments ───────────────────────────────
    s("ethereum.on", CryptoAuth, Low),
    s("solana.on", CryptoAuth, Low),
    s("PublicKeyCredential.create", CryptoAuth, Medium),
    s("PublicKeyCredential.get", CryptoAuth, Medium),
    s(
        "PublicKeyCredential.isConditionalMediationAvailable",
        CryptoAuth,
        Low,
    ),
    s(
        "PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable",
        CryptoAuth,
        Low,
    ),
    s("PaymentRequest", CryptoAuth, Medium),
    s("PaymentRequest.show", CryptoAuth, Low),
    // ── Sensors / observers ───────────────────────────────────────────────
    s("geolocation.getCurrentPosition", Sensor, Medium),
    s("geolocation.watchPosition", Sensor, Medium),
    s("DeviceMotionEvent.requestPermission", Sensor, Medium),
    s("DeviceOrientationEvent.requestPermission", Sensor, Medium),
    s("IntersectionObserver.observe", Sensor, Low),
    s("MutationObserver.observe", Sensor, Low),
    s("ResizeObserver.observe", Sensor, Low),
    // ── Notifications / push / sync / SW ──────────────────────────────────
    s("Notification.requestPermission", Notification, Medium),
    s("navigator.serviceWorker.register", Notification, Medium),
    s("pushManager.subscribe", Notification, Low),
    s("periodicSync.register", Notification, Low),
    s("sync.register", Notification, Low),
    s("launchQueue.setConsumer", Notification, Low),
    // ── Speech ────────────────────────────────────────────────────────────
    s("speechSynthesis.speak", Speech, Medium),
    s("speechSynthesis.cancel", Speech, Low),
    s("speechSynthesis.getVoices", Speech, Medium),
    // ── Font enumeration ──────────────────────────────────────────────────
    s("document.fonts.forEach", Font, Medium),
    // ── High-resolution timing ────────────────────────────────────────────
    s("performance.now", Timing, Medium),
    s("scheduler.postTask", Timing, Low),
    // ── Media capability (WebCodecs / MediaCapabilities) ──────────────────
    // Modern consumer browsers (Chrome 94+, Firefox 120+, Safari 16.4+) ship
    // WebCodecs and MediaCapabilities; absence on a persona claiming one of those
    // versions is a headless/stripped-media-stack tell. Probed in core_probes.
    s("VideoDecoder.isConfigSupported", Media, Medium),
    s("VideoEncoder.isConfigSupported", Media, Medium),
    s("VideoFrame", Media, Medium),
    s("MediaCapabilities.decodingInfo", Media, Medium),
];

/// Every surface in the inventory.
#[must_use]
pub const fn surfaces() -> &'static [FingerprintSurface] {
    SURFACES
}

/// Surfaces in a given category.
#[must_use]
pub fn by_category(category: SurfaceCategory) -> Vec<FingerprintSurface> {
    SURFACES
        .iter()
        .copied()
        .filter(|s| s.category == category)
        .collect()
}

/// The `Critical`/`High`-criticality surfaces, the ones a disguise MUST get
/// right; everything else only corroborates.
#[must_use]
pub fn must_cover() -> Vec<FingerprintSurface> {
    SURFACES
        .iter()
        .copied()
        .filter(|s| matches!(s.criticality, Criticality::Critical | Criticality::High))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn inventory_is_substantial_and_unique() {
        // The sear instrumentation taps ~100 surfaces; the inventory must reflect
        // that breadth and never silently shrink.
        assert!(SURFACES.len() >= 90, "inventory shrank: {}", SURFACES.len());
        let mut seen = HashSet::new();
        for s in SURFACES {
            assert!(seen.insert(s.surface), "duplicate surface: {}", s.surface);
        }
    }

    #[test]
    fn every_category_is_represented() {
        use SurfaceCategory::*;
        for cat in [
            Navigator,
            DevicePrompt,
            WebGl,
            Canvas,
            Audio,
            WebRtc,
            Screen,
            Timezone,
            Lifecycle,
            Storage,
            CryptoAuth,
            Sensor,
            Notification,
            Speech,
            Font,
            Timing,
            Media,
        ] {
            assert!(!by_category(cat).is_empty(), "no surfaces for {cat:?}");
        }
    }

    #[test]
    fn webdriver_is_the_one_critical_tell() {
        // navigator.webdriver is the single Critical-rated surface, the rest are
        // High/Medium/Low fingerprint signals. This pins the rating contract.
        let critical: Vec<_> = SURFACES
            .iter()
            .filter(|s| s.criticality == Criticality::Critical)
            .map(|s| s.surface)
            .collect();
        assert_eq!(critical, vec!["navigator.webdriver"]);
    }

    #[test]
    fn must_cover_is_a_meaningful_subset() {
        let n = must_cover().len();
        assert!(n >= 20 && n < SURFACES.len(), "must_cover sized wrong: {n}");
    }
}
