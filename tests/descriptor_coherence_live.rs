//! Live contract: the property DESCRIPTORS of spoofed Navigator getters must match
//! bare Firefox (a CreepJS-class "lie detector" inspects them, not just the values).
//!
//! guise overrides `navigator.userAgent/platform/oscpu/...` via
//! `Object.defineProperty(Navigator.prototype, name, {get: __seal(...), configurable:
//! true})`. Three descriptor-level tells can leak from that:
//!   1. **enumerable**: WebIDL attributes are `enumerable:true`. Redefining an
//!      EXISTING accessor while OMITTING `enumerable` preserves the native value, but
//!      that is subtle; a regression to `enumerable:false` is a constructor-grade tell
//!      (`getOwnPropertyDescriptor(Navigator.prototype,'userAgent').enumerable`).
//!   2. **getter toString**: `Function.prototype.toString.call(descriptor.get)` must
//!      report `[native code]`; if it leaks the override's JS source the spoof is
//!      obvious. This exercises the real `__seal` masking on the shipped getters.
//!   3. **own-vs-prototype + setter shape**: the property must stay on
//!      `Navigator.prototype` (not become an own property of the instance), keep a
//!      getter, and have NO setter (these attributes are readonly).
//!
//! Asserts the persona descriptor SHAPE equals bare for every property present on
//! bare (values differ for a cross-OS persona; the descriptor shape must not).
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
        eprintln!("skip descriptor_coherence_live: set STEALTH_LIVE_BROWSER=1");
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
                let body = b"<!doctype html><html><body>d</body></html>";
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

const PROBE: &str = r#"JSON.stringify((function(){
  var props = ['userAgent','platform','appVersion','vendor','language','languages','hardwareConcurrency','maxTouchPoints','oscpu'];
  var out = {};
  props.forEach(function(p){
    var d = Object.getOwnPropertyDescriptor(Navigator.prototype, p);
    if (!d) { out[p] = {present:false}; return; }
    var getNative = null;
    try { getNative = d.get ? /\[native code\]/.test(Function.prototype.toString.call(d.get)) : null; } catch(e){ getNative = 'ERR'; }
    out[p] = {
      present: true,
      enumerable: d.enumerable,
      configurable: d.configurable,
      hasGet: typeof d.get === 'function',
      hasSet: typeof d.set === 'function',
      getNative: getNative,
      ownOnInstance: Object.prototype.hasOwnProperty.call(navigator, p)
    };
  });
  return out;
})())"#;

async fn descriptors(page: runtime_foxdriver::browser::Page, url: &str) -> Value {
    page.goto(url).await.expect("nav");
    let raw = page
        .evaluate(PROBE)
        .await
        .expect("eval")
        .into_value::<String>()
        .expect("json");
    let _ = page.close().await;
    serde_json::from_str(&raw).expect("parse")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn spoofed_navigator_descriptors_match_bare_firefox() {
    if skip() {
        return;
    }
    let url = serve_origin().await;

    let bare = descriptors(
        launch_firefox_self_managed(cfg()).await.expect("bare"),
        &url,
    )
    .await;
    let win = descriptors(
        guise::browser::launch_profiled_firefox(cfg(), &StealthProfile::FirefoxWindows)
            .await
            .expect("persona"),
        &url,
    )
    .await;

    let report = format!("BARE:\n{bare:#}\nFirefoxWindows:\n{win:#}\n");
    let _ = std::fs::write("/tmp/guise_descriptor_coherence.txt", &report);
    eprint!("{report}");

    let props = [
        "userAgent",
        "platform",
        "appVersion",
        "vendor",
        "language",
        "languages",
        "hardwareConcurrency",
        "maxTouchPoints",
        "oscpu",
    ];
    for p in props {
        let b = &bare[p];
        let w = &win[p];
        // Presence must match bare (don't add/remove a Navigator attribute).
        assert_eq!(
            b["present"], w["present"],
            "{p}: presence on Navigator.prototype diverged from bare: bare={b} win={w}"
        );
        if b["present"] != Value::Bool(true) {
            continue;
        }
        // Descriptor SHAPE must match bare exactly (values may differ cross-OS).
        for field in [
            "enumerable",
            "configurable",
            "hasGet",
            "hasSet",
            "ownOnInstance",
        ] {
            assert_eq!(
                w[field], b[field],
                "{p}.{field} descriptor diverged from bare, a descriptor tell: bare={b} win={w}"
            );
        }
        // Native-attribute invariants real FF always satisfies (guards against a
        // future regression that flips one on the persona AND on a changed bare).
        assert_eq!(
            w["enumerable"],
            Value::Bool(true),
            "{p}: spoofed getter must be enumerable:true: {w}"
        );
        assert_eq!(
            w["hasSet"],
            Value::Bool(false),
            "{p}: a readonly attribute must have NO setter: {w}"
        );
        assert_eq!(
            w["ownOnInstance"],
            Value::Bool(false),
            "{p}: must live on Navigator.prototype, not the instance: {w}"
        );
        // The __seal masking must make the spoofed getter report native source.
        assert_eq!(
            w["getNative"], Value::Bool(true),
            "{p}: spoofed getter toString does not report [native code]. __seal leaked JS source: {w}"
        );
    }
}
