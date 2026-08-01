//! LIVE end-to-end gate: drive the real BoringSSL-backed `StealthClient` against
//! the `tls.peet.ws` reflector and assert the fingerprint it ACTUALLY emits on
//! the wire is engine-coherent with what guise models. This is the full-stack
//! proof the local codec round-trip cannot give: a real TLS ClientHello + real
//! HTTP/2 frames, observed by an independent third party past the kernel.
//!
//! Result (measured 2026-06-12): the real-wire Chrome and Firefox HTTP/2 Akamai
//! fingerprints match guise's `CHROME_H2` / `FIREFOX_H2` models BYTE-FOR-BYTE
//! the production impersonation emits exactly what the catalogue models. Safari
//! is recorded but NOT asserted against the model: wreq's Safari emulation emits
//! the same pseudo-header order (`m,s,a,p`) that a plain `curl` (nghttp2 default)
//! emits, so it is not trustworthy ground truth for real Apple Safari (which
//! still needs an Apple-WebKit capture), unlike Chrome/Firefox, where wreq
//! overrides the order browser-specifically.
//!
//! Opt-in: requires `--features tls-impersonate` (compiles BoringSSL) AND
//! `GUISE_LIVE_PEET=1` plus outbound network. Skips cleanly otherwise, so it
//! never flakes a normal/CI run.
#![cfg(feature = "tls-impersonate")]

use guise::http::{ImpersonateProfile, StealthClient};

// guise's modeled H2 Akamai fingerprints, the values
// `session_coherence::{CHROME_H2, FIREFOX_H2}.akamai_fingerprint()` render and the
// `wire_emit` round-trip tests lock. Hard-coded here so the live gate is a true
// cross-check (real wire vs model) without coupling to internal feature flags.
const GUISE_CHROME_H2: &str = "1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p";
const GUISE_FIREFOX_H2: &str = "1:65536;2:0;4:131072;5:16384|12517377|0|m,p,a,s";

// guise's modeled JA4 cipher-hash (the `_b` segment) per family, the
// version-STABLE part of the TLS fingerprint (same cipher SET across the minor
// versions wreq vs guise model). From guise's chrome-146 / firefox-150 targets.
const GUISE_CHROME_JA4_CIPHERS: &str = "8daaf6152771";
const GUISE_FIREFOX_JA4_CIPHERS: &str = "5b57614c22b0";
// guise's measured `SAFARI_18` TLS profile cipher-hash (the `_b` of
// `t13d2014h2_a09f3c656075_…`, verified by `safari_18_profile_reproduces_the_
// measured_wire_fingerprint`).
const GUISE_SAFARI_JA4_CIPHERS: &str = "a09f3c656075";

struct WireFp {
    akamai: String,
    ja3: String,
    ja3_hash: String,
    ja4: String,
    ja4_r: String,
    ua: String,
    /// The raw IP TTL peet observed on our egress packet (`tcpip.ip.ttl`), before
    /// de-hopping. Set by the HOST KERNEL, not the userland TLS impersonation
    /// the same across every profile from a given host. `None` if peet omits it.
    observed_ttl: Option<u8>,
}

impl WireFp {
    /// The JA4 `_b` cipher-hash segment (`t13d…h2_<THIS>_<ext-hash>`).
    fn ja4_cipher_hash(&self) -> &str {
        self.ja4.split('_').nth(1).unwrap_or("")
    }
}

async fn observe(profile: ImpersonateProfile) -> WireFp {
    let client = StealthClient::new(profile).expect("build impersonating client");
    let resp = client
        .send("GET", "https://tls.peet.ws/api/all", &[], None, 1 << 20)
        .await
        .unwrap_or_else(|e| panic!("{profile:?}: live request failed: {e}"));
    assert_eq!(
        resp.status, 200,
        "{profile:?}: peet returned {}",
        resp.status
    );
    let v: serde_json::Value = serde_json::from_slice(&resp.body).expect("peet returns JSON");
    let get = |a: &str, b: &str| v[a][b].as_str().unwrap_or("?").to_string();
    WireFp {
        akamai: v["http2"]["akamai_fingerprint"]
            .as_str()
            .unwrap_or_else(|| panic!("{profile:?}: no http2.akamai_fingerprint"))
            .to_string(),
        ja3: get("tls", "ja3"),
        ja3_hash: get("tls", "ja3_hash"),
        ja4: get("tls", "ja4"),
        ja4_r: get("tls", "ja4_r"),
        ua: v["user_agent"].as_str().unwrap_or("?").to_string(),
        observed_ttl: v["tcpip"]["ip"]["ttl"]
            .as_u64()
            .and_then(|t| u8::try_from(t).ok()),
    }
}

fn pseudo_order(akamai: &str) -> &str {
    akamai.split('|').nth(3).unwrap_or("")
}

// guise's measured `SAFARI_IOS_18` TLS profile cipher-hash (the `_b` of its JA4),
// verified by `safari_ios_18_profile_reproduces_the_measured_wire_fingerprint`.
// iPadOS/iOS Safari shares Apple's coretls stack with desktop Safari, so the
// cipher SET (hence `_b`) coincides with desktop `a09f3c656075`; the EXTENSION
// ordering (`_c`) is what differs and is locked by the unit test, not here.
const GUISE_SAFARI_IOS_JA4_CIPHERS: &str = "a09f3c656075";

#[tokio::test]
async fn real_wire_ipad_safari_clienthello_matches_guise_ios_model() {
    if std::env::var("GUISE_LIVE_PEET").is_err() {
        eprintln!(
            "skip: set GUISE_LIVE_PEET=1 (+ outbound network) to run the live tls.peet.ws gate"
        );
        return;
    }

    // wreq's iPad-Safari emulation: its TLS ClientHello is browser-specific (same
    // basis on which the desktop `SAFARI_18` and Chrome/Firefox profiles were
    // validated), so this is a credible real iPadOS-Safari TLS wire shape, the
    // capture guise's measured `SAFARI_IOS_18` profile is built and verified
    // against, replacing the prior Chrome-borrowed `SAFARI_IOS_17` placeholder.
    let ipad = observe(ImpersonateProfile::SafariIpad18).await;
    eprintln!(
        "SafariIpad18 real wire:\n  akamai = {}\n  ja3 = {}\n  ja3_hash = {}\n  ja4 = {}\n  ja4_r = {}\n  ua = {}",
        ipad.akamai, ipad.ja3, ipad.ja3_hash, ipad.ja4, ipad.ja4_r, ipad.ua
    );
    // Sanity bounds: a real Safari-over-h2 ClientHello, no GREASE (Apple coretls
    // does not GREASE), and a non-empty md5-shaped JA3 hash.
    assert!(
        ipad.ja4.starts_with("t13d") && ipad.ja4.contains("h2_"),
        "iPad Safari must be a TLS1.3 / h2 ClientHello (ja4 {})",
        ipad.ja4
    );
    assert_eq!(
        ipad.ja3_hash.len(),
        32,
        "ja3_hash must be md5 hex (ja3_hash {})",
        ipad.ja3_hash
    );
    // TLS layer: guise's `SAFARI_IOS_18` profile is built from this exact capture;
    // the real-wire iPad-Safari cipher set MUST equal guise's measured iOS model.
    assert_eq!(
        ipad.ja4_cipher_hash(),
        GUISE_SAFARI_IOS_JA4_CIPHERS,
        "real iPad-Safari JA4 cipher-hash must equal guise's measured SAFARI_IOS_18 cipher set (ja4 {})",
        ipad.ja4
    );
}

#[tokio::test]
async fn real_wire_chrome_and_firefox_h2_exactly_match_guise_models_safari_recorded() {
    if std::env::var("GUISE_LIVE_PEET").is_err() {
        eprintln!(
            "skip: set GUISE_LIVE_PEET=1 (+ outbound network) to run the live tls.peet.ws gate"
        );
        return;
    }

    let chrome = observe(ImpersonateProfile::Chrome131).await;
    eprintln!(
        "Chrome131 real wire:\n  akamai = {}\n  ja3_hash = {}\n  ja4 = {}\n  ja4_r = {}\n  ua = {}",
        chrome.akamai, chrome.ja3_hash, chrome.ja4, chrome.ja4_r, chrome.ua
    );
    assert_eq!(
        chrome.akamai, GUISE_CHROME_H2,
        "real Chrome HTTP/2 wire must equal guise's CHROME_H2 model byte-for-byte",
    );
    // TLS layer: the JA4 cipher-hash is version-stable (same cipher SET); it must
    // equal guise's modeled Chrome cipher-hash, so guise's TLS cipher list is
    // confirmed real-wire-correct even though minor versions differ.
    assert_eq!(
        chrome.ja4_cipher_hash(),
        GUISE_CHROME_JA4_CIPHERS,
        "real Chrome JA4 cipher-hash must equal guise's modeled Chrome cipher set (ja4 {})",
        chrome.ja4
    );

    let firefox = observe(ImpersonateProfile::Firefox133).await;
    eprintln!(
        "Firefox133 real wire:\n  akamai = {}\n  ja3_hash = {}\n  ja4 = {}\n  ja4_r = {}\n  ua = {}",
        firefox.akamai, firefox.ja3_hash, firefox.ja4, firefox.ja4_r, firefox.ua
    );
    assert_eq!(
        firefox.akamai, GUISE_FIREFOX_H2,
        "real Firefox HTTP/2 wire must equal guise's FIREFOX_H2 model byte-for-byte",
    );
    assert_eq!(
        firefox.ja4_cipher_hash(),
        GUISE_FIREFOX_JA4_CIPHERS,
        "real Firefox JA4 cipher-hash must equal guise's modeled Firefox cipher set (ja4 {})",
        firefox.ja4
    );

    // Safari: RECORDED, not asserted against the model. wreq's Safari emulation
    // emits pseudo-header order `m,s,a,p`: the SAME order a plain curl (nghttp2
    // default) emits, so it does not independently confirm real Apple Safari's
    // order, and we do NOT use it to "correct" guise's modeled `m,s,p,a`. We only
    // assert it is a distinct, non-Chrome / non-Firefox shape (a sanity bound),
    // and surface the open question loudly rather than silently passing.
    let safari = observe(ImpersonateProfile::Safari18).await;
    let order = pseudo_order(&safari.akamai);
    // The TLS ClientHello IS browser-specific in wreq (proven: Chrome/Firefox
    // cipher-hashes above match guise exactly), so Safari's ja3/ja4_r here are a
    // credible real-Safari TLS shape, this capture is what guise's `SAFARI_18`
    // measured profile was built and verified against (replacing the old
    // Chrome-borrowed placeholder). The H2 pseudo-order, by contrast, coincides
    // with curl's nghttp2 default and is NOT authoritative.
    eprintln!(
        "Safari18 real wire:\n  akamai = {}\n  ja3 = {}\n  ja3_hash = {}\n  ja4 = {}\n  ja4_r = {}\n  ua = {}\n  \
         NOTE H2 pseudo-order {order} coincides with curl default (not authoritative); \
         TLS ja3/ja4_r ARE browser-specific and usable.",
        safari.akamai, safari.ja3, safari.ja3_hash, safari.ja4, safari.ja4_r, safari.ua
    );
    assert_ne!(order, "m,a,s,p", "Safari wire must not be Chrome's order");
    assert_ne!(order, "m,p,a,s", "Safari wire must not be Firefox's order");
    // TLS layer: guise's `SAFARI_18` profile was built from this exact capture, so
    // the real-wire Safari cipher set MUST equal guise's measured Safari model, the
    // Safari TLS placeholder is now closed and validated against the live wire.
    assert_eq!(
        safari.ja4_cipher_hash(),
        GUISE_SAFARI_JA4_CIPHERS,
        "real Safari JA4 cipher-hash must equal guise's measured SAFARI_18 cipher set (ja4 {})",
        safari.ja4
    );
}

/// The TCP/IP layer of the JA4/HTTP2/TCP frontier, validated against the real
/// wire. peet's `tcpip.ip.ttl` is the egress TTL an independent third party
/// observed about OUR packet past NAT, a REAL producer for the X049 self-probe's
/// `observed_ttl`, the TCP-layer analogue of the H2 `wire_emit` producer (which
/// closed the Akamai half of the same self-probe loop).
///
/// SCOPE / boundary (stated, never silently skipped):
/// - The egress TTL is set by the HOST KERNEL, not by guise's userland TLS/H2
///   impersonation. guise can emit a chosen TLS ClientHello and HTTP/2 opening
///   from userland, but it CANNOT emit another OS's TCP/IP SYN from userland
///   that needs raw sockets / eBPF. So this gate validates guise's TCP/IP TTL
///   model for the HOST's OS only; other OSes' stacks are unreachable from here
///   (the same shape of boundary as wreq's non-authoritative Safari H2 order).
/// - peet `/api/all` reports `tcpip.ip.ttl` but captured a MID-FLOW packet
///   (`cap_length` ~ the ClientHello, not a 60-byte SYN), so it does NOT expose
///   the SYN's MSS / window-scale / option-kinds. The JA4T layer therefore CANNOT
///   be computed from THIS endpoint and is not validated by this network gate.
///   It WAS measured out-of-band: the real egress SYN captured from this host via
///   `tcpdump` (`win 64240, [mss,sackOK,TS,nop,wscale 10]` → JA4T
///   `64240_2-4-8-1-3_1460_10`) is locked as a root-free regression in
///   `wire_probe::wire_self_probe_coherent_on_the_real_captured_tuned_linux_syn`
///   and `os_network::ja4t_matches_observed_treats_window_scale_as_host_variable_advisory`
///: that capture is what surfaced (and fixed) the wscale false-positive in the
///   JA4T coherence matcher. So: TTL validated here; JA4T validated by captured
///   regression; full SYN capture in the live network gate would need root.
#[tokio::test]
async fn real_wire_egress_ttl_coheres_with_host_os_tcp_stack() {
    if std::env::var("GUISE_LIVE_PEET").is_err() {
        eprintln!(
            "skip: set GUISE_LIVE_PEET=1 (+ outbound network) to run the live tls.peet.ws gate"
        );
        return;
    }
    use guise::fingerprint::{infer_initial_ttl, StealthProfile};
    use guise::http::session_coherence::{persona_wire_self_probe, WireCapture, WireSelfProbe};

    // Any profile works (the TTL is host-kernel, profile-independent).
    let obs = observe(ImpersonateProfile::Chrome131).await;
    let ttl = obs
        .observed_ttl
        .expect("peet /api/all must report tcpip.ip.ttl for the egress-TTL gate");
    let inferred = infer_initial_ttl(ttl);

    // The host OS family + its canonical initial TTL. Linux and macOS both start
    // at 64; Windows at 128. guise's de-hop must recover exactly that from the
    // post-hop observed value.
    #[cfg(target_os = "windows")]
    let (persona, host_initial, host_name, wrong_persona) = (
        StealthProfile::ChromeWindowsStable,
        128u8,
        "windows",
        StealthProfile::ChromeLinux,
    );
    #[cfg(target_os = "macos")]
    let (persona, host_initial, host_name, wrong_persona) = (
        StealthProfile::ChromeMacStable,
        64u8,
        "macos",
        StealthProfile::ChromeWindowsStable,
    );
    #[cfg(not(any(target_os = "windows", target_os = "macos")))]
    let (persona, host_initial, host_name, wrong_persona) = (
        StealthProfile::ChromeLinux,
        64u8,
        "linux/unix",
        StealthProfile::ChromeWindowsStable,
    );

    eprintln!(
        "egress TCP/IP TTL: observed={ttl} de-hopped initial={inferred} (host {host_name}, expected initial {host_initial})\n  \
         NOTE peet captured a mid-flow packet. TTL is validated, JA4T is NOT (no SYN MSS/wscale/options exposed here)."
    );

    // guise's de-hop must recover the host OS's canonical initial TTL from the
    // real post-hop wire value (a direct measured check of `infer_initial_ttl`).
    assert_eq!(
        inferred, host_initial,
        "guise infer_initial_ttl({ttl}) must recover the {host_name} initial TTL {host_initial}"
    );

    // Feed the REAL observed egress TTL into the X049 self-probe for a host-OS
    // persona: the TTL layer must read Coherent, guise's modeled TCP/IP stack TTL
    // equals the wire. This closes the TTL half of the X049 producer gap with a
    // real producer (peet's observed TTL).
    let cap = WireCapture {
        observed_ttl: Some(ttl),
        ..WireCapture::default()
    };
    let verdict = persona_wire_self_probe(persona, &cap);
    assert_eq!(
        verdict,
        WireSelfProbe::Coherent,
        "host-OS persona TTL must cohere with the real egress TTL (observed {ttl} -> initial {inferred}): {verdict:?}"
    );

    // NEGATIVE twin: a persona from a different-TTL OS family must be caught
    // Incoherent against this SAME real wire, proving the probe discriminates and
    // the positive pass above is not vacuous. (Linux/mac host TTL 64 vs a Windows
    // persona's 128, or vice-versa.)
    let wrong_verdict = persona_wire_self_probe(wrong_persona, &cap);
    assert!(
        matches!(wrong_verdict, WireSelfProbe::Incoherent(_)),
        "a wrong-OS-family persona ({wrong_persona:?}) must be caught incoherent against the real egress TTL \
         (observed {ttl} -> initial {inferred}): {wrong_verdict:?}"
    );
}
