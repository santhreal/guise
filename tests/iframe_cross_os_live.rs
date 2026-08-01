//! Live PoC: does a CROSS-ORIGIN iframe stay OS-coherent on a cross-OS persona, or
//! does a child realm leak the host OS?
//!
//! Ad frames, embedded widgets, and captcha iframes fingerprint INDEPENDENTLY of the
//! top document, frequently cross-origin. guise's persona overrides come in two
//! flavours: ENGINE prefs (UA/platform/appVersion/WebGL, reach every realm) and a
//! BiDi `add_preload_script` (oscpu getter, canvas/audio farble, must be injected
//! per realm). This verifies a cross-origin child realm (separate origin/process)
//! reports the persona OS on BOTH flavours, not the Linux host.
//!
//! Opt-in: `STEALTH_LIVE_BROWSER=1 [STEALTH_FIREFOX=/path]`.
#![cfg(feature = "browser")]

use guise::fingerprint::StealthProfile;
use runtime_foxdriver::FoxBrowserConfig;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

fn skip() -> bool {
    if std::env::var("STEALTH_LIVE_BROWSER").is_err() {
        eprintln!("skip iframe_cross_os_live: set STEALTH_LIVE_BROWSER=1");
        return true;
    }
    false
}

async fn serve_html(listener: TcpListener, body: String) {
    while let Ok((mut s, _)) = listener.accept().await {
        let body = body.clone();
        tokio::spawn(async move {
            let mut b = [0u8; 2048];
            let _ = s.read(&mut b).await;
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            let _ = s.write_all(resp.as_bytes()).await;
            let _ = s.write_all(body.as_bytes()).await;
            let _ = s.shutdown().await;
        });
    }
}

const PROBE: &str = r#"JSON.stringify({
  oscpu: String(navigator.oscpu),
  appVersion: String(navigator.appVersion),
  platform: String(navigator.platform),
  ua: String(navigator.userAgent),
  webgl: (function(){try{var g=document.createElement('canvas').getContext('webgl')||document.createElement('canvas').getContext('experimental-webgl');var e=g.getExtension('WEBGL_debug_renderer_info');return String(g.getParameter(e.UNMASKED_RENDERER_WEBGL));}catch(e){return 'ERR:'+e;}})()
})"#;

fn cfg() -> FoxBrowserConfig {
    let mut c = FoxBrowserConfig {
        headless: true,
        ..Default::default()
    };
    if let Ok(p) = std::env::var("STEALTH_FIREFOX") {
        c.executable_path = Some(p);
    }
    c
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cross_origin_iframe_stays_os_coherent() {
    if skip() {
        return;
    }
    // Two distinct origins (different ports on 127.0.0.1 are cross-origin).
    let main_l = TcpListener::bind("127.0.0.1:0").await.expect("bind main");
    let frame_l = TcpListener::bind("127.0.0.1:0").await.expect("bind frame");
    let main_addr = main_l.local_addr().unwrap();
    let frame_addr = frame_l.local_addr().unwrap();
    let main_url = format!("http://{main_addr}/");
    let frame_origin = format!("http://{frame_addr}/");

    let main_body = format!(
        "<!doctype html><html><body><iframe src=\"{frame_origin}\" width=300 height=200></iframe></body></html>"
    );
    tokio::spawn(serve_html(main_l, main_body));
    tokio::spawn(serve_html(
        frame_l,
        "<!doctype html><html><body>child</body></html>".to_string(),
    ));

    let page = guise::browser::launch_profiled_firefox(cfg(), &StealthProfile::FirefoxWindows)
        .await
        .expect("launch");
    page.goto(&main_url).await.expect("nav main");

    // Find the cross-origin child frame: the browsing context that is not the main one.
    // Poll briefly (the iframe context attaches a beat after the top load commits).
    let main_frame = page.mainframe().await.expect("mainframe");
    let mut child = None;
    for _ in 0..40 {
        let frames = page.frames().await.expect("frames");
        if let Some(f) = frames.into_iter().find(|f| Some(f) != main_frame.as_ref()) {
            child = Some(f);
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    let child = child.expect("cross-origin iframe context never appeared");

    // Read the OS-correlated surfaces from INSIDE the cross-origin iframe.
    let raw = page
        .evaluate_in_context(PROBE, &child)
        .await
        .expect("eval in iframe")
        .into_value::<String>()
        .expect("json");
    let _ = page.close().await;

    let report = format!("FirefoxWindows cross-origin iframe surfaces:\n{raw}\n");
    let _ = std::fs::write("/tmp/guise_iframe_cross_os.txt", &report);
    eprint!("{report}");

    // The child realm must claim Windows on EVERY surface, engine-pref (UA/platform/
    // appVersion/WebGL) AND preload-script (oscpu) (never the Linux host).
    assert!(
        raw.contains("Windows NT"),
        "iframe UA does not claim Windows: {raw}"
    );
    assert!(
        !raw.contains("Linux") && !raw.contains("X11"),
        "cross-origin iframe leaks a Linux token on a Windows persona: {raw}"
    );
    assert!(
        !raw.contains("NVIDIA"),
        "cross-origin iframe WebGL leaks the host GPU on a Windows persona: {raw}"
    );
}
