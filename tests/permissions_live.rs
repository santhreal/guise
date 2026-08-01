//! Live contract: the Permissions API surface of the stealthed page must be
//! coherent with a real (bare) Firefox, not a self-inflicted tell.
//!
//! CONFIRMED live (dump_permissions_truth in surface_truth_live.rs): the previous
//! disguise (a) ADDED `navigator.permissions.request`, which real Firefox does not
//! expose: `'request' in navigator.permissions` was true on the disguise, false
//! on bare FF, and (b) carried a dead `permissions.query` override whose name
//! list included Chromium-only names that real FF rejects with TypeError, so had
//! it worked it would have invented `{state:'prompt'}` where real FF throws.
//!
//! This asserts the SHIPPED disguise now matches bare Firefox exactly:
//!   * `'request' in navigator.permissions` is false (no fabricated method);
//!   * supported names (notifications/geolocation/camera/microphone) return real
//!     states ('prompt' headless), not a forced constant;
//!   * a Chromium-only name (clipboard-read) still REJECTS as it does on real FF;
//!   * `Notification.permission` reads 'default' (coherent normalization).
//!
//! Opt-in: `STEALTH_LIVE_BROWSER=1 [STEALTH_FIREFOX=/path]` (spawns real Firefox).
#![cfg(feature = "browser")]

use guise::fingerprint::StealthProfile;
use runtime_foxdriver::FoxBrowserConfig;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

fn skip() -> bool {
    if std::env::var("STEALTH_LIVE_BROWSER").is_err() {
        eprintln!("skip permissions_live: set STEALTH_LIVE_BROWSER=1 (spawns real Firefox)");
        return true;
    }
    false
}

/// Serve a one-shot secure origin (http://127.0.0.1), the Permissions API and
/// Notification require a secure context, which about:blank/data: are not.
async fn serve_secure_origin() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut sock, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buf = [0u8; 2048];
                let _ = sock.read(&mut buf).await;
                let body =
                    b"<!doctype html><html><head><title>p</title></head><body>x</body></html>";
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

/// One async probe returning a compact JSON string of every permissions fact we
/// assert on. Runs in the page realm; awaited via `evaluate_await`.
const PROBE: &str = r#"(function(){
  function q(name){
    return navigator.permissions.query({name:name}).then(
      function(s){ return s.state; },
      function(e){ return 'ERR:'+((e&&e.name)||e); }
    );
  }
  return Promise.all([
    q('notifications'), q('geolocation'), q('camera'), q('microphone'), q('clipboard-read')
  ]).then(function(states){
    return JSON.stringify({
      has_request: ('request' in navigator.permissions),
      query_native: /\[native code\]/.test(navigator.permissions.query.toString()),
      notif_perm: (function(){ try { return Notification.permission; } catch(e){ return 'ERR:'+e; } })(),
      notifications: states[0],
      geolocation: states[1],
      camera: states[2],
      microphone: states[3],
      clipboard_read: states[4]
    });
  });
})()"#;

#[derive(serde::Deserialize, Debug)]
struct Perms {
    has_request: bool,
    query_native: bool,
    notif_perm: String,
    notifications: String,
    geolocation: String,
    camera: String,
    microphone: String,
    clipboard_read: String,
}

#[tokio::test]
async fn stealthed_permissions_match_bare_firefox_no_self_tell() {
    if skip() {
        return;
    }
    let mut cfg = FoxBrowserConfig {
        headless: true,
        ..Default::default()
    };
    if let Ok(p) = std::env::var("STEALTH_FIREFOX") {
        cfg.executable_path = Some(p);
    }
    let url = serve_secure_origin().await;

    let page = guise::browser::launch_profiled_firefox(cfg, &StealthProfile::FirefoxLinux)
        .await
        .expect("launch profiled firefox");
    page.goto(&url).await.expect("navigate to secure origin");
    let raw = page
        .evaluate_await(PROBE)
        .await
        .expect("evaluate permissions probe")
        .into_value::<String>()
        .expect("probe returns json string");
    let _ = page.close().await;

    let p: Perms = serde_json::from_str(&raw).unwrap_or_else(|e| panic!("parse {raw}: {e}"));

    // The two confirmed self-tells must be gone.
    assert!(
        !p.has_request,
        "disguise must NOT add navigator.permissions.request (real FF lacks it); got 'request' in permissions = true: {raw}"
    );
    // query must remain the real native method (we did not wrap it).
    assert!(
        p.query_native,
        "navigator.permissions.query must remain native [native code]: {raw}"
    );

    // Supported names return real headless states, identical to bare FF.
    assert_eq!(p.notifications, "prompt", "notifications state: {raw}");
    assert_eq!(p.geolocation, "prompt", "geolocation state: {raw}");
    assert_eq!(p.camera, "prompt", "camera state: {raw}");
    assert_eq!(p.microphone, "prompt", "microphone state: {raw}");

    // A Chromium-only name still rejects, exactly as real Firefox does, proof we
    // did not fabricate a 'prompt' state for names FF does not support.
    assert!(
        p.clipboard_read.starts_with("ERR:"),
        "clipboard-read must REJECT as on real FF, not return a fabricated state; got {}: {raw}",
        p.clipboard_read
    );

    // Notification.permission normalized to 'default' (coherent with headed FF and
    // with the 'prompt' query state).
    assert_eq!(
        p.notif_perm, "default",
        "Notification.permission must read 'default': {raw}"
    );
}
