//! Mid-session persona-drift regression (G124 / G125).
//!
//! Once guise assembles a persona and injects it into a page, the same
//! fingerprint surfaces must read identically at t0 and after a small amount
//! of real browsing activity. A mid-session drift is a strong automation tell
//! (e.g. a lazy override that only applies to the first context, or a clock/
//! randomness source that leaks).
//!
//! Opt-in (spawns a real Firefox): `STEALTH_LIVE_BROWSER=1`.
#![cfg(feature = "browser")]

use guise::fingerprint::StealthProfile;
use runtime_foxdriver::{launch_firefox, FoxBrowserConfig, Page};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

const READ_PERSONA_SNAPSHOT_JS: &str = r#"
(() => {
  let webglVendor = 'n/a', webglRenderer = 'n/a';
  try {
    const c = document.createElement('canvas');
    const gl = c.getContext('webgl');
    if (gl) {
      const ext = gl.getExtension('WEBGL_debug_renderer_info');
      if (ext) {
        webglVendor = String(gl.getParameter(ext.UNMASKED_VENDOR_WEBGL));
        webglRenderer = String(gl.getParameter(ext.UNMASKED_RENDERER_WEBGL));
      }
    }
  } catch (_) {}
  return {
    userAgent: navigator.userAgent,
    platform: navigator.platform,
    languages: JSON.stringify(navigator.languages),
    hardwareConcurrency: navigator.hardwareConcurrency,
    webdriver: navigator.webdriver,
    screenWidth: screen.width,
    screenHeight: screen.height,
    colorDepth: screen.colorDepth,
    outerWidth: window.outerWidth,
    outerHeight: window.outerHeight,
    webglVendor,
    webglRenderer,
  };
})()
"#;

async fn serve() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut s, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut b = [0u8; 1024];
                let _ = s.read(&mut b).await;
                let body = b"<!doctype html><html><body>x</body></html>";
                let _ = s
                    .write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len()).as_bytes())
                    .await;
                let _ = s.write_all(body).await;
                let _ = s.shutdown().await;
            });
        }
    });
    format!("http://{addr}/")
}

async fn snapshot(page: &Page) -> serde_json::Value {
    page.evaluate(READ_PERSONA_SNAPSHOT_JS)
        .await
        .expect("read persona snapshot")
        .into_value()
        .expect("deserialize persona snapshot")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn persona_surfaces_are_identical_at_t0_and_after_activity() {
    if std::env::var("STEALTH_LIVE_BROWSER").is_err() {
        eprintln!("SKIP session_drift: set STEALTH_LIVE_BROWSER=1 to run (spawns Firefox)");
        return;
    }
    let url = serve().await;

    let page = launch_firefox(FoxBrowserConfig {
        headless: true,
        ..Default::default()
    })
    .await
    .expect("launch for session drift");

    guise::browser::apply_stealth_profile(&page, &StealthProfile::FirefoxLinux)
        .await
        .expect("apply stealth profile");

    let before = snapshot(&page).await;

    // Perturb the session: navigate to a real origin and touch canvas/audio.
    page.goto(&url).await.expect("navigate to local page");
    page.evaluate(
        "(() => { \
            const c = document.createElement('canvas'); \
            const ctx = c.getContext('2d'); \
            ctx.fillStyle = 'red'; \
            ctx.fillRect(0,0,10,10); \
            const a = new (window.AudioContext || window.webkitAudioContext)({ sampleRate: 44100 }); \
            const o = a.createOscillator(); \
            o.start(); \
            o.stop(); \
            return 'ok'; \
         })()",
    )
    .await
    .expect("perturb session with canvas + audio");

    // Small delay so any timing- or lazy-state-dependent drift has a chance to
    // appear between the two snapshots.
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    let after = snapshot(&page).await;

    let keys = [
        "userAgent",
        "platform",
        "languages",
        "hardwareConcurrency",
        "webdriver",
        "screenWidth",
        "screenHeight",
        "colorDepth",
        "outerWidth",
        "outerHeight",
        "webglVendor",
        "webglRenderer",
    ];
    for key in keys {
        assert_eq!(
            before.get(key),
            after.get(key),
            "mid-session drift on `{key}`: before={before:?}, after={after:?}",
            before = before.get(key),
            after = after.get(key)
        );
    }

    let _ = page.close().await;
}
