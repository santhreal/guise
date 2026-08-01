//! Live contract: `navigator.oscpu` must cohere with the persona, not leak the
//! host OS.
//!
//! `navigator.oscpu` is a Firefox-specific, OS-stamped string that fingerprinters
//! cross-check against the UA platform token. Two failure modes:
//!   * a CROSS-OS Firefox persona (e.g. FirefoxWindows on a Linux host) that
//!     leaves the host oscpu, a Windows UA reporting `oscpu="Linux x86_64"` is a
//!     trivial unmask;
//!   * a Chromium persona, where the Firefox ENGINE exposes `oscpu` natively but a
//!     real Chrome has no such property (`'oscpu' in navigator` is false).
//!
//! CONFIRMED live (dump_cross_os_persona_truth in surface_truth_live.rs): before
//! the fix the FirefoxWindows persona reported `oscpu="Linux x86_64"` while its UA
//! said `Windows NT 10.0; Win64; x64`. The fix derives oscpu from the persona UA's
//! OS token. This locks the live Firefox-family cross-OS personas (Windows + Mac on
//! a Linux host) to the UA-coherent oscpu. The Chromium-persona deletion (`'oscpu'
//! in navigator` must be false) is verified at the emission layer instead, the
//! guise launch path is Firefox-only (G092), so a Chrome persona cannot be driven
//! on the engine to assert it live (see profile_js_deletes_oscpu_for_chromium_persona).
//!
//! Opt-in: `STEALTH_LIVE_BROWSER=1 [STEALTH_FIREFOX=/path]` (spawns real Firefox).
#![cfg(feature = "browser")]

use guise::fingerprint::StealthProfile;
use runtime_foxdriver::FoxBrowserConfig;
use serde_json::Value;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

fn skip() -> bool {
    if std::env::var("STEALTH_LIVE_BROWSER").is_err() {
        eprintln!("skip cross_os_oscpu_live: set STEALTH_LIVE_BROWSER=1 (spawns real Firefox)");
        return true;
    }
    false
}

async fn serve_secure_origin() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut sock, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buf = [0u8; 2048];
                let _ = sock.read(&mut buf).await;
                let body =
                    b"<!doctype html><html><head><title>o</title></head><body>x</body></html>";
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                let _ = sock.write_all(resp.as_bytes()).await;
                let _ = sock.write_all(body).await;
                let _ = sock.shutdown().await;
            });
        }
    });
    format!("http://{addr}/")
}

const PROBE: &str = r#"JSON.stringify({
  oscpu: (typeof navigator.oscpu === 'undefined') ? '<undef>' : String(navigator.oscpu),
  has_oscpu: ('oscpu' in navigator),
  ua: String(navigator.userAgent)
})"#;

async fn probe_oscpu(profile: &StealthProfile, url: &str) -> Value {
    let mut cfg = FoxBrowserConfig {
        headless: true,
        ..Default::default()
    };
    if let Ok(p) = std::env::var("STEALTH_FIREFOX") {
        cfg.executable_path = Some(p);
    }
    let page = guise::browser::launch_profiled_firefox(cfg, profile)
        .await
        .expect("launch profiled");
    page.goto(url).await.expect("nav");
    let s = page
        .evaluate(PROBE)
        .await
        .expect("eval PROBE")
        .into_value::<String>()
        .expect("json string");
    let _ = page.close().await;
    serde_json::from_str(&s).unwrap_or_else(|e| panic!("parse {s}: {e}"))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn oscpu_coheres_with_persona_not_host() {
    if skip() {
        return;
    }
    let url = serve_secure_origin().await;

    // Cross-OS Firefox persona: a Windows UA on this (Linux) host MUST report the
    // Windows oscpu, never the host's "Linux x86_64".
    let win = probe_oscpu(&StealthProfile::FirefoxWindows, &url).await;
    let win_oscpu = win["oscpu"].as_str().unwrap_or_default();
    let win_ua = win["ua"].as_str().unwrap_or_default();
    assert!(
        win_ua.contains("Windows"),
        "FirefoxWindows UA is not Windows: {win}"
    );
    assert_eq!(
        win_oscpu, "Windows NT 10.0; Win64; x64",
        "FirefoxWindows oscpu must match the UA OS token, not the host: {win}"
    );
    assert!(
        !win_oscpu.contains("Linux"),
        "FirefoxWindows oscpu leaked the Linux host: {win}"
    );
    assert_eq!(
        win["has_oscpu"].as_bool(),
        Some(true),
        "Firefox persona must expose oscpu: {win}"
    );

    // Second cross-OS Firefox persona: a Mac UA on this Linux host must report the
    // Mac oscpu, never the host's Linux token.
    let mac = probe_oscpu(&StealthProfile::FirefoxMacStable, &url).await;
    let mac_oscpu = mac["oscpu"].as_str().unwrap_or_default();
    assert!(
        mac["ua"].as_str().unwrap_or_default().contains("Mac OS X"),
        "FirefoxMac UA not Mac: {mac}"
    );
    assert_eq!(
        mac_oscpu, "Intel Mac OS X 10.15",
        "FirefoxMac oscpu must match the UA OS token: {mac}"
    );
    assert!(
        !mac_oscpu.contains("Linux"),
        "FirefoxMac oscpu leaked the Linux host: {mac}"
    );

    // Matched Firefox persona: oscpu is the (coherent) host OS token.
    let lin = probe_oscpu(&StealthProfile::FirefoxLinux, &url).await;
    let lin_oscpu = lin["oscpu"].as_str().unwrap_or_default();
    assert_eq!(
        lin_oscpu, "Linux x86_64",
        "FirefoxLinux oscpu must be the Linux token: {lin}"
    );
    assert!(
        lin["ua"].as_str().unwrap_or_default().contains("Linux"),
        "FirefoxLinux UA not Linux: {lin}"
    );
}
