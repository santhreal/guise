//! Live contract: the persona's navigator identity must be coherent (a) with what
//! a real Firefox actually reports and (b) ACROSS realms, the window AND a
//! dedicated Worker.
//!
//! CONFIRMED live (dump_worker_navigator_sweep in surface_truth_live.rs): the
//! disguise overrode `navigator.appVersion` to `userAgent.replace('Mozilla/','')`
//!, the full UA string, but real Firefox 151 FREEZES appVersion to the OS-family
//! form `"5.0 (X11)"`. So the stealthed window reported a value no real Firefox
//! reports, and it disagreed with the worker realm (which returns the frozen native
//! form). The fix derives the frozen form from the persona OS. This asserts:
//!   * window appVersion is the frozen `5.0 (X11|Windows|Macintosh)` form, never a
//!     UA leak (no "Firefox/", "Gecko/", "rv:");
//!   * window and worker AGREE on appVersion, userAgent, languages, and
//!     hardwareConcurrency (no window-realm-only spoof leaking the host in workers).
//!
//! Opt-in: `STEALTH_LIVE_BROWSER=1 [STEALTH_FIREFOX=/path]` (spawns real Firefox).
#![cfg(feature = "browser")]

use guise::fingerprint::StealthProfile;
use runtime_foxdriver::FoxBrowserConfig;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

fn skip() -> bool {
    if std::env::var("STEALTH_LIVE_BROWSER").is_err() {
        eprintln!("skip navigator_realm_live: set STEALTH_LIVE_BROWSER=1 (spawns real Firefox)");
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
                    b"<!doctype html><html><head><title>n</title></head><body>x</body></html>";
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

/// Reads the spoofed navigator props in the window realm and inside a Worker.
const PROBE: &str = r#"(function(){
  function inWorker(){
    return new Promise(function(resolve){
      var code = "self.onmessage=function(){postMessage({ua:navigator.userAgent,av:navigator.appVersion,langs:(navigator.languages||[]).join(','),hc:navigator.hardwareConcurrency})}";
      var w;
      try { w = new Worker(URL.createObjectURL(new Blob([code], {type:'application/javascript'}))); }
      catch(e){ resolve({ua:'NOWORKER:'+e}); return; }
      var done=false;
      w.onmessage=function(ev){ if(done)return; done=true; try{w.terminate()}catch(_){} resolve(ev.data); };
      w.onerror=function(e){ if(done)return; done=true; resolve({ua:'WERR:'+(e.message||e)}); };
      w.postMessage(0);
      setTimeout(function(){ if(done)return; done=true; resolve({ua:'TIMEOUT'}); }, 5000);
    });
  }
  return inWorker().then(function(wk){
    return JSON.stringify({
      win_ua: navigator.userAgent, win_av: navigator.appVersion,
      win_langs: (navigator.languages||[]).join(','), win_hc: navigator.hardwareConcurrency,
      wk_ua: wk.ua, wk_av: wk.av, wk_langs: wk.langs, wk_hc: wk.hc
    });
  });
})()"#;

#[derive(serde::Deserialize, Debug)]
struct Nav {
    win_ua: String,
    win_av: String,
    win_langs: String,
    win_hc: i64,
    wk_ua: String,
    wk_av: String,
    wk_langs: String,
    wk_hc: i64,
}

fn is_frozen_appversion(av: &str) -> bool {
    matches!(av, "5.0 (X11)" | "5.0 (Windows)" | "5.0 (Macintosh)")
}

#[tokio::test]
async fn navigator_identity_is_realm_coherent_and_real_firefox_shaped() {
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
    page.goto(&url).await.expect("navigate");
    let raw = page
        .evaluate_await(PROBE)
        .await
        .expect("evaluate navigator probe")
        .into_value::<String>()
        .expect("probe returns json");
    let _ = page.close().await;

    let n: Nav = serde_json::from_str(&raw).unwrap_or_else(|e| panic!("parse {raw}: {e}"));

    // appVersion must be the frozen OS-family form a real Firefox reports, never a
    // UA leak.
    assert!(
        is_frozen_appversion(&n.win_av),
        "window appVersion must be the frozen OS form (got {:?}): {raw}",
        n.win_av
    );
    for leak in ["Firefox/", "Gecko/", "rv:"] {
        assert!(
            !n.win_av.contains(leak),
            "window appVersion leaked UA token {leak:?} (got {:?}): {raw}",
            n.win_av
        );
    }

    // Cross-realm coherence: a window-realm spoof that the worker realm does not
    // share is a trivially-detected leak.
    assert_eq!(n.wk_av, n.win_av, "worker appVersion != window: {raw}");
    assert_eq!(n.wk_ua, n.win_ua, "worker userAgent != window: {raw}");
    assert_eq!(n.wk_langs, n.win_langs, "worker languages != window: {raw}");
    assert_eq!(
        n.wk_hc, n.win_hc,
        "worker hardwareConcurrency ({}) != window ({}), persona clamp leaked the real core count in the worker realm: {raw}",
        n.wk_hc, n.win_hc
    );
}
