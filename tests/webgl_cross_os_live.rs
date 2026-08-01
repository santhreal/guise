//! Live contract: WebGL adapter strings must cohere with the persona OS, not leak
//! the host GPU.
//!
//! WebGL renderer strings are OS-correlated: Windows Firefox always reports an
//! ANGLE/Direct3D adapter, Linux reports the native/Mesa GPU. FF 151 returns the
//! real (RFP-sanitized) GPU in the MASKED `gl.getParameter(gl.RENDERER)` (0x1F01),
//! not just the deprecated UNMASKED_RENDERER_WEBGL extension, so a cross-OS
//! persona that only spoofs the unmasked param leaks the host GPU in the masked
//! one.
//!
//! CONFIRMED live (dump_cross_os_persona_truth in surface_truth_live.rs): before
//! the fix the FirefoxWindows persona reported masked `gl.RENDERER` =
//! "NVIDIA GeForce GTX 980, or similar" (the Linux host GPU, no ANGLE signature)
//! while the unmasked renderer was the spoofed "ANGLE (Intel … Direct3D11 …)". The
//! fix pins masked RENDERER to the persona renderer for cross-OS personas. This
//! locks: masked == unmasked, the Windows persona carries the ANGLE/Direct3D
//! adapter, and neither leaks the host "NVIDIA" GPU; the matched Linux persona is
//! unchanged (masked == unmasked == host), and GL_VENDOR stays "Mozilla".
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
        eprintln!("skip webgl_cross_os_live: set STEALTH_LIVE_BROWSER=1 (spawns real Firefox)");
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
                    b"<!doctype html><html><head><title>w</title></head><body>x</body></html>";
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

const WEBGL_PROBE: &str = r#"JSON.stringify((function(){
  try {
    var c = document.createElement('canvas');
    var g = c.getContext('webgl') || c.getContext('experimental-webgl');
    if (!g) return { gl: 'NO_WEBGL' };
    var ext = g.getExtension('WEBGL_debug_renderer_info');
    return {
      unmasked_renderer: ext ? String(g.getParameter(ext.UNMASKED_RENDERER_WEBGL)) : 'NO_EXT',
      masked_vendor: String(g.getParameter(g.VENDOR)),
      masked_renderer: String(g.getParameter(g.RENDERER))
    };
  } catch(e){ return { err: String(e) }; }
})())"#;

async fn webgl(profile: &StealthProfile, url: &str) -> Value {
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
        .evaluate(WEBGL_PROBE)
        .await
        .expect("eval WEBGL_PROBE")
        .into_value::<String>()
        .expect("json string");
    let _ = page.close().await;
    serde_json::from_str(&s).unwrap_or_else(|e| panic!("parse {s}: {e}"))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn masked_gl_renderer_coheres_with_persona_not_host() {
    if skip() {
        return;
    }
    let url = serve_secure_origin().await;

    // Cross-OS Windows persona: masked gl.RENDERER must be the ANGLE/Direct3D
    // adapter (matching the unmasked spoof), never the Linux host "NVIDIA" GPU.
    let win = webgl(&StealthProfile::FirefoxWindows, &url).await;
    let win_masked = win["masked_renderer"].as_str().unwrap_or_default();
    let win_unmasked = win["unmasked_renderer"].as_str().unwrap_or_default();
    assert!(
        win_masked.contains("ANGLE"),
        "Windows masked renderer lacks ANGLE: {win}"
    );
    assert!(
        win_masked.contains("Direct3D"),
        "Windows masked renderer lacks Direct3D: {win}"
    );
    assert!(
        !win_masked.contains("NVIDIA"),
        "Windows masked renderer leaked the host NVIDIA GPU: {win}"
    );
    assert_eq!(
        win_masked, win_unmasked,
        "Windows masked != unmasked renderer (incoherent): {win}"
    );
    assert_eq!(
        win["masked_vendor"].as_str(),
        Some("Mozilla"),
        "GL_VENDOR must stay 'Mozilla': {win}"
    );

    // Matched Linux persona: untouched, masked == unmasked == the host adapter,
    // and it is NOT an ANGLE string (Linux Firefox does not use ANGLE).
    let lin = webgl(&StealthProfile::FirefoxLinux, &url).await;
    let lin_masked = lin["masked_renderer"].as_str().unwrap_or_default();
    let lin_unmasked = lin["unmasked_renderer"].as_str().unwrap_or_default();
    assert_eq!(
        lin_masked, lin_unmasked,
        "Linux masked != unmasked renderer: {lin}"
    );
    assert!(
        !lin_masked.contains("ANGLE"),
        "Linux renderer must not be an ANGLE string: {lin}"
    );
    assert_eq!(
        lin["masked_vendor"].as_str(),
        Some("Mozilla"),
        "GL_VENDOR must stay 'Mozilla': {lin}"
    );
}
