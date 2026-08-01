//! Live PoC: do WORKER-realm navigator surfaces stay OS-coherent on a cross-OS
//! persona, or does the worker leak the host OS?
//!
//! guise's JS persona overrides ride a BiDi `add_preload_script` that runs in the
//! WINDOW realm. A dedicated Web Worker has its own `WorkerNavigator` that the
//! window preload does NOT reach. UA + platform are pref-based
//! (`general.useragent.override` / `general.platform.override`), which are
//! engine-wide and DO reach workers; but appVersion is handled only by a window
//! getter (`firefox_app_version`) with no pref. On a FirefoxWindows persona on this
//! Linux host, a worker reporting `appVersion` "5.0 (X11)" (or any Linux token)
//! under a Windows UA would be a cross-OS, cross-realm tell.
//!
//! Opt-in: `STEALTH_LIVE_BROWSER=1 [STEALTH_FIREFOX=/path]`.
#![cfg(feature = "browser")]

use guise::fingerprint::StealthProfile;
use runtime_foxdriver::FoxBrowserConfig;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

fn skip() -> bool {
    if std::env::var("STEALTH_LIVE_BROWSER").is_err() {
        eprintln!("skip worker_cross_os_live: set STEALTH_LIVE_BROWSER=1");
        return true;
    }
    false
}

async fn serve() -> (String, TcpListener) {
    let l = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let a = l.local_addr().unwrap();
    (format!("http://{a}/"), l)
}

async fn pump(l: TcpListener) {
    while let Ok((mut s, _)) = l.accept().await {
        tokio::spawn(async move {
            let mut b = [0u8; 2048];
            let _ = s.read(&mut b).await;
            let body = b"<!doctype html><html><body>w</body></html>";
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            let _ = s.write_all(resp.as_bytes()).await;
            let _ = s.write_all(body).await;
            let _ = s.shutdown().await;
        });
    }
}

// Read WorkerNavigator surfaces from inside a dedicated Web Worker, plus the same
// surfaces from the window, so we can compare realms.
const WORKER_PROBE: &str = r#"(function(){
  return new Promise((resolve) => {
    try {
      var win = {
        ua: navigator.userAgent, platform: navigator.platform,
        appVersion: navigator.appVersion, hwc: navigator.hardwareConcurrency,
        tz: Intl.DateTimeFormat().resolvedOptions().timeZone
      };
      var code = "self.onmessage=function(){postMessage(JSON.stringify({"
        + "ua:navigator.userAgent,platform:navigator.platform,"
        + "appVersion:navigator.appVersion,hwc:navigator.hardwareConcurrency,"
        + "deviceMemory:navigator.deviceMemory,language:navigator.language,"
        + "languages:JSON.stringify(navigator.languages),"
        + "tz:Intl.DateTimeFormat().resolvedOptions().timeZone,"
        + "hasOscpu:('oscpu' in navigator)}));};";
      var blob = new Blob([code], {type:'application/javascript'});
      var w = new Worker(URL.createObjectURL(blob));
      w.onmessage = function(e){ resolve(JSON.stringify({win:win, worker:JSON.parse(e.data)})); };
      w.onerror = function(e){ resolve('ERR:worker:'+(e.message||e.filename||'unknown')); };
      w.postMessage('go');
      setTimeout(function(){ resolve('ERR:timeout'); }, 6000);
    } catch(e){ resolve('ERR:'+e); }
  });
})()"#;

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

async fn worker_probe(p: &StealthProfile, url: &str) -> String {
    let page = guise::browser::launch_profiled_firefox(cfg(), p)
        .await
        .expect("persona");
    page.goto(url).await.expect("nav");
    let r = page
        .evaluate_await(WORKER_PROBE)
        .await
        .expect("worker probe")
        .into_value::<String>()
        .expect("s");
    let _ = page.close().await;
    r
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn worker_realm_stays_os_coherent_on_cross_os_persona() {
    if skip() {
        return;
    }
    let (url, listener) = serve().await;
    tokio::spawn(pump(listener));

    let win = worker_probe(&StealthProfile::FirefoxWindows, &url).await;
    let report = format!("FirefoxWindows window+worker:\n{win}\n");
    let _ = std::fs::write("/tmp/guise_worker_cross_os.txt", &report);
    eprint!("{report}");

    assert!(!win.starts_with("ERR"), "worker probe failed: {win}");

    // The WORKER realm must claim Windows, not leak the Linux host, on every surface
    // it exposes. UA + platform are pref-based (should already reach the worker);
    // appVersion is the at-risk one (window-getter only, no pref).
    assert!(
        win.contains("Windows NT"),
        "worker UA/window does not claim Windows: {win}"
    );
    // No Linux token anywhere in the worker's reported surfaces.
    assert!(
        !win.contains("Linux") && !win.contains("X11"),
        "worker realm leaks a Linux token on a Windows persona: {win}"
    );
}
