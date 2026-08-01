//! Live contract: the disguise must reach every CHILD realm, not just the top
//! window.
//!
//! A standard bot check creates a hidden iframe and reads
//! `iframe.contentWindow.navigator.webdriver|userAgent|hardwareConcurrency`. The
//! window-realm BiDi preload has to propagate into same-origin `srcdoc` and
//! `about:blank` child realms, or the child leaks the host identity (or
//! webdriver=true) while the top window is spoofed, a trivially-detected
//! divergence.
//!
//! CONFIRMED live (dump_realm_and_order_truth in surface_truth_live.rs): on bare
//! Firefox top/srcdoc/about:blank all agree natively (webdriver=true, real cores);
//! on the stealthed page all three agree on the SPOOFED values (webdriver=false,
//! persona cores). This locks that cross-realm agreement so a regression that
//! stops the preload reaching child frames fails loudly.
//!
//! Opt-in: `STEALTH_LIVE_BROWSER=1 [STEALTH_FIREFOX=/path]` (spawns real Firefox).
#![cfg(feature = "browser")]

use guise::fingerprint::{profile_to_overrides, StealthProfile};
use runtime_foxdriver::FoxBrowserConfig;
use serde_json::Value;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

fn skip() -> bool {
    if std::env::var("STEALTH_LIVE_BROWSER").is_err() {
        eprintln!("skip iframe_realm_live: set STEALTH_LIVE_BROWSER=1 (spawns real Firefox)");
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
                    b"<!doctype html><html><head><title>i</title></head><body>x</body></html>";
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

const IFRAME_PROBE: &str = r#"(function(){
  function snap(nav){ try { return { wd:String(nav.webdriver), ua:nav.userAgent, hc:String(nav.hardwareConcurrency), lang:nav.language, plat:nav.platform, mtp:String(nav.maxTouchPoints) }; } catch(e){ return {err:String(e)}; } }
  return new Promise(function(resolve){
    var out = { top: snap(navigator), srcdoc:null, blank:null };
    var done=false; function fin(){ if(done)return; done=true; resolve(JSON.stringify(out)); }
    var f1 = document.createElement('iframe');
    f1.srcdoc = '<!doctype html><html><body>x</body></html>';
    f1.onload = function(){
      out.srcdoc = snap(f1.contentWindow.navigator);
      var f2 = document.createElement('iframe');
      f2.onload = function(){ out.blank = snap(f2.contentWindow.navigator); fin(); };
      document.body.appendChild(f2);
      try { if (f2.contentWindow && f2.contentWindow.document.readyState==='complete'){ out.blank = snap(f2.contentWindow.navigator); fin(); } } catch(e){}
    };
    document.body.appendChild(f1);
    setTimeout(fin, 3500);
  });
})()"#;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn child_realms_inherit_the_disguise() {
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
    let persona = StealthProfile::FirefoxLinux;
    let want_hc = profile_to_overrides(&persona)
        .hardware_concurrency
        .to_string();

    let page = guise::browser::launch_profiled_firefox(cfg, &persona)
        .await
        .expect("launch profiled");
    page.goto(&url).await.expect("nav");
    let raw = page
        .evaluate_await(IFRAME_PROBE)
        .await
        .expect("eval iframe probe")
        .into_value::<String>()
        .expect("json string");
    let _ = page.close().await;

    let v: Value = serde_json::from_str(&raw).unwrap_or_else(|e| panic!("parse {raw}: {e}"));
    let top = &v["top"];
    let srcdoc = &v["srcdoc"];
    let blank = &v["blank"];

    // Children must have actually loaded (not the timeout fallback leaving nulls).
    assert!(srcdoc.is_object(), "srcdoc child realm never loaded: {raw}");
    assert!(
        blank.is_object(),
        "about:blank child realm never loaded: {raw}"
    );

    let s = |x: &Value, k: &str| x[k].as_str().unwrap_or("<MISSING>").to_string();

    // The spoof is actually in effect at the top (otherwise the cross-realm
    // equality below would be vacuously true on an un-stealthed page).
    assert_eq!(s(top, "wd"), "false", "top webdriver not spoofed: {raw}");
    assert_eq!(
        s(top, "hc"),
        want_hc,
        "top hardwareConcurrency != persona: {raw}"
    );

    // Each child realm must report the SAME spoofed identity as the top window.
    for (label, child) in [("srcdoc", srcdoc), ("about:blank", blank)] {
        assert_eq!(
            s(child, "wd"),
            "false",
            "{label}: webdriver leaked TRUE in child realm: {raw}"
        );
        assert_eq!(
            s(child, "wd"),
            s(top, "wd"),
            "{label}: webdriver != top: {raw}"
        );
        assert_eq!(
            s(child, "ua"),
            s(top, "ua"),
            "{label}: userAgent != top: {raw}"
        );
        assert_eq!(
            s(child, "hc"),
            s(top, "hc"),
            "{label}: hardwareConcurrency != top: {raw}"
        );
        assert_eq!(
            s(child, "lang"),
            s(top, "lang"),
            "{label}: language != top: {raw}"
        );
        assert_eq!(
            s(child, "plat"),
            s(top, "plat"),
            "{label}: platform != top: {raw}"
        );
        assert_eq!(
            s(child, "mtp"),
            s(top, "mtp"),
            "{label}: maxTouchPoints != top: {raw}"
        );
    }
}
