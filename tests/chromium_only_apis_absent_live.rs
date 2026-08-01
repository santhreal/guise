//! Live contract: a FIREFOX persona must NOT expose Chromium-only APIs.
//!
//! A whole class of fingerprint tells is "presence of an API real Firefox does not
//! implement". `navigator.deviceMemory`, `navigator.userAgentData`, `window.chrome`,
//! and `performance.memory` are Chromium-only, a real Firefox Navigator/Window does
//! not have them. If guise's persona layer ever defines one on a Firefox persona
//! (e.g. `evasion::device_memory_js` is Chromium-shaped, and `FingerprintConfig::
//! maximum()` sets `device_memory: Some(8)`: a footgun if that config is ever used
//! for a FF persona), the persona would carry a property real Firefox lacks: an
//! instant spoof flag. The shipped FF path (`launch_profiled_firefox` →
//! `FingerprintConfig::default()` with `device_memory: None`, and `profile_js` which
//! gates the deviceMemory override on `client_hints.is_some()`, i.e. Chrome only)
//! must therefore leave ALL of these absent (exactly as bare Firefox does).
//!
//! This pins the invariant in BOTH realms: the window AND a dedicated Worker
//! (WorkerNavigator must not gain deviceMemory either). Compared against bare so a
//! future Firefox that natively ships one of these does not make the test lie.
//!
//! Opt-in: `STEALTH_LIVE_BROWSER=1 [STEALTH_FIREFOX=/path]`.
#![cfg(feature = "browser")]

use guise::fingerprint::StealthProfile;
use runtime_foxdriver::browser::launch_firefox_self_managed;
use runtime_foxdriver::FoxBrowserConfig;
use serde_json::Value;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

fn skip() -> bool {
    if std::env::var("STEALTH_LIVE_BROWSER").is_err() {
        eprintln!("skip chromium_only_apis_absent_live: set STEALTH_LIVE_BROWSER=1");
        return true;
    }
    false
}

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

async fn serve_origin() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut sock, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buf = [0u8; 2048];
                let _ = sock.read(&mut buf).await;
                let body = b"<!doctype html><html><body>c</body></html>";
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

const WINDOW_PROBE: &str = r#"JSON.stringify((function(){
  var n = navigator;
  function has(o,k){ try { return (k in o); } catch(e){ return false; } }
  return {
    deviceMemory: typeof n.deviceMemory,
    userAgentData: typeof n.userAgentData,
    chrome: typeof window.chrome,
    perfMemory: typeof (window.performance && window.performance.memory),
    usb: has(n,'usb'),
    hid: has(n,'hid'),
    serial: has(n,'serial'),
    bluetooth: has(n,'bluetooth'),
    getBattery: has(n,'getBattery')
  };
})())"#;

// A dedicated Worker: WorkerNavigator must not gain deviceMemory/userAgentData on a
// FF persona (engine prefs reach Workers, but these Chromium APIs are not set by
// any pref (they must simply be absent, like real FF)).
const WORKER_PROBE: &str = r#"(function(){
  return new Promise(function(resolve){
    try {
      var src = "self.onmessage=function(){ postMessage(JSON.stringify({" +
        "deviceMemory: typeof self.navigator.deviceMemory," +
        "userAgentData: typeof self.navigator.userAgentData," +
        "hwc: (self.navigator.hardwareConcurrency||0) })); }";
      var b = new Blob([src], {type:'application/javascript'});
      var w = new Worker(URL.createObjectURL(b));
      w.onmessage = function(e){ resolve(e.data); };
      w.postMessage(0);
      setTimeout(function(){ resolve(JSON.stringify({err:'timeout'})); }, 3000);
    } catch(e){ resolve(JSON.stringify({err:String(e)})); }
  });
})()"#;

async fn window_apis(
    launch: impl std::future::Future<Output = runtime_foxdriver::browser::Page>,
    url: &str,
) -> Value {
    let page = launch.await;
    page.goto(url).await.expect("nav");
    let raw = page
        .evaluate(WINDOW_PROBE)
        .await
        .expect("eval window")
        .into_value::<String>()
        .expect("json");
    let worker_raw = page
        .evaluate_await(WORKER_PROBE)
        .await
        .expect("eval worker")
        .into_value::<String>()
        .expect("worker json");
    let _ = page.close().await;
    let mut v: Value = serde_json::from_str(&raw).expect("parse window");
    let w: Value = serde_json::from_str(&worker_raw).expect("parse worker");
    v["__worker"] = w;
    v
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn firefox_persona_does_not_expose_chromium_only_apis() {
    if skip() {
        return;
    }
    let url = serve_origin().await;

    let bare = window_apis(
        async { launch_firefox_self_managed(cfg()).await.expect("bare") },
        &url,
    )
    .await;
    let win = window_apis(
        async {
            guise::browser::launch_profiled_firefox(cfg(), &StealthProfile::FirefoxWindows)
                .await
                .expect("persona")
        },
        &url,
    )
    .await;

    let report = format!("BARE:\n{bare}\nFirefoxWindows:\n{win}\n");
    let _ = std::fs::write("/tmp/guise_chromium_only_apis.txt", &report);
    eprint!("{report}");

    // The Chromium-only surfaces must be ABSENT on the persona, exactly as on bare
    // Firefox. A defined value here is an instant "this is not really Firefox" flag.
    for key in ["deviceMemory", "userAgentData", "chrome", "perfMemory"] {
        assert_eq!(
            win[key], serde_json::json!("undefined"),
            "FirefoxWindows persona EXPOSES Chromium-only `{key}` (must be undefined on real FF): {win}"
        );
        // Defense-in-depth: bare FF must also lack it, else a future FF shipped it
        // natively and this contract needs revisiting (not a guise bug).
        assert_eq!(
            bare[key],
            serde_json::json!("undefined"),
            "bare Firefox unexpectedly exposes `{key}`: contract assumption changed: {bare}"
        );
    }
    for key in ["usb", "hid", "serial", "bluetooth", "getBattery"] {
        assert_eq!(
            win[key], bare[key],
            "FirefoxWindows persona diverges from bare on `{key}` presence: persona={win} bare={bare}"
        );
    }

    // Worker realm: WorkerNavigator must not gain the Chromium APIs either, and the
    // persona's spoofed hardwareConcurrency (engine pref) must reach the Worker.
    let bw = &bare["__worker"];
    let ww = &win["__worker"];
    assert_eq!(
        ww["deviceMemory"],
        serde_json::json!("undefined"),
        "Worker WorkerNavigator exposes deviceMemory on a FF persona: {ww}"
    );
    assert_eq!(
        ww["userAgentData"],
        serde_json::json!("undefined"),
        "Worker WorkerNavigator exposes userAgentData on a FF persona: {ww}"
    );
    assert!(
        ww["hwc"].as_u64().unwrap_or(0) > 0,
        "Worker hardwareConcurrency not present/spoofed on the persona: {ww}"
    );
    let _ = bw;
}
