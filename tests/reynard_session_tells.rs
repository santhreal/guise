//! Contract: the reynard engine must be coherent on the surfaces fixed in the
//! stock-Firefox JS layer this session, appVersion frozen form, permissions
//! request/query, Notification.permission, AND window-vs-worker timezone.
//!
//! CONFIRMED live: reynard was coherent on appVersion/permissions/worker-UA/hwc but
//! LEAKED the host timezone, a FirefoxLinux persona reported `America/Phoenix`
//! (the host) in BOTH window and worker realms instead of the persona's
//! `America/New_York`, because the reynard launch sent no timezone. Fixed by
//! setting `TZ` from `overrides.timezone` on the engine process (reynard.rs),
//! mirroring the stock-Firefox path. This asserts every realm reports the persona
//! zone and the rest of the identity stays coherent.
//!
//! Opt-in (built reynard binary + display):
//! ```text
//! REYNARD_BIN=$HOME/.local/share/reynard/reynard DISPLAY=:1 \
//!   MOZ_DISABLE_CONTENT_SANDBOX=1 cargo test -p guise --no-default-features \
//!   --features browser --test reynard_session_tells -- --nocapture
//! ```
#![cfg(feature = "browser")]

use guise::browser::launch_reynard;
use guise::fingerprint::{profile_to_overrides, StealthProfile};
use serde_json::Value;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

async fn serve_secure_origin() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut sock, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buf = [0u8; 2048];
                let _ = sock.read(&mut buf).await;
                let body =
                    b"<!doctype html><html><head><title>r</title></head><body>x</body></html>";
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

const PROBE: &str = r#"(function(){
  function inWorker(){
    return new Promise(function(resolve){
      var code = "self.onmessage=function(){var o={};try{o.av=navigator.appVersion}catch(e){o.av='E'}try{o.ua=navigator.userAgent}catch(e){o.ua='E'}try{o.hc=navigator.hardwareConcurrency}catch(e){o.hc='E'}try{o.tz=Intl.DateTimeFormat().resolvedOptions().timeZone}catch(e){o.tz='E'}try{o.langs=(navigator.languages||[]).join(',')}catch(e){o.langs='E'}postMessage(o)}";
      var w;
      try { w = new Worker(URL.createObjectURL(new Blob([code], {type:'application/javascript'}))); }
      catch(e){ resolve({av:'NOWORKER:'+e}); return; }
      var done=false;
      w.onmessage=function(ev){ if(done)return; done=true; try{w.terminate()}catch(_){} resolve(ev.data); };
      w.onerror=function(e){ if(done)return; done=true; resolve({av:'WERR:'+(e.message||e)}); };
      w.postMessage(0);
      setTimeout(function(){ if(done)return; done=true; resolve({av:'TIMEOUT'}); }, 5000);
    });
  }
  var win = {};
  try { win.av = navigator.appVersion; } catch(e){ win.av='E'; }
  try { win.ua = navigator.userAgent; } catch(e){ win.ua='E'; }
  try { win.hc = navigator.hardwareConcurrency; } catch(e){ win.hc='E'; }
  try { win.tz = Intl.DateTimeFormat().resolvedOptions().timeZone; } catch(e){ win.tz='E'; }
  try { win.langs = (navigator.languages||[]).join(','); } catch(e){ win.langs='E'; }
  try { win.has_request = ('request' in navigator.permissions); } catch(e){ win.has_request='E'; }
  try { win.notif_perm = Notification.permission; } catch(e){ win.notif_perm='E'; }
  return inWorker().then(function(wk){ return JSON.stringify({ window: win, worker: wk }); });
})()"#;

const PERMS_STATE: &str = r#"navigator.permissions.query({name:'notifications'}).then(function(s){return s.state;}).catch(function(e){return 'ERR:'+e;})"#;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reynard_timezone_and_identity_are_realm_coherent() {
    let Ok(reynard_bin) = std::env::var("REYNARD_BIN") else {
        eprintln!("SKIP reynard_session_tells: set REYNARD_BIN=/path/to/reynard binary");
        return;
    };
    if std::env::var("DISPLAY").is_err() {
        eprintln!("SKIP reynard_session_tells: no DISPLAY (headful needs an X server)");
        return;
    }
    let profile = StealthProfile::FirefoxLinux;
    let persona_tz = profile_to_overrides(&profile).timezone;

    let url = serve_secure_origin().await;
    let reynard = launch_reynard(&reynard_bin, &profile, false)
        .await
        .expect("launch reynard");
    let _ = reynard.goto(&url).await;
    tokio::time::sleep(std::time::Duration::from_millis(1200)).await;

    let dump = reynard
        .evaluate_await(PROBE)
        .await
        .expect("eval probe")
        .into_value::<String>()
        .expect("json");
    let state = reynard
        .evaluate_await(PERMS_STATE)
        .await
        .map(|v| v.into_value::<String>().unwrap_or_default())
        .unwrap_or_else(|e| format!("ERR:{e:?}"));
    let _ = reynard.close().await;

    eprintln!("REYNARD TELLS -> {dump}");
    eprintln!("REYNARD notifications query.state -> {state}");

    let v: Value = serde_json::from_str(&dump).unwrap_or_else(|e| panic!("parse {dump}: {e}"));
    let win = &v["window"];
    let wk = &v["worker"];
    let s = |x: &Value| x.as_str().unwrap_or("").to_string();

    // Timezone must be the persona zone in BOTH realms (the fix; was the host zone).
    assert_eq!(
        s(&win["tz"]),
        persona_tz,
        "window timezone != persona: {dump}"
    );
    assert_eq!(
        s(&wk["tz"]),
        persona_tz,
        "worker timezone leaked the host zone instead of the persona: {dump}"
    );
    // appVersion is the frozen OS form in both realms.
    assert_eq!(s(&win["av"]), "5.0 (X11)", "window appVersion: {dump}");
    assert_eq!(s(&wk["av"]), "5.0 (X11)", "worker appVersion: {dump}");
    // userAgent + hardwareConcurrency coherent across realms.
    assert_eq!(s(&win["ua"]), s(&wk["ua"]), "worker UA != window: {dump}");
    assert_eq!(
        win["hc"], wk["hc"],
        "worker hardwareConcurrency != window: {dump}"
    );
    // No fabricated permissions.request; Notification.permission/query coherent.
    assert_eq!(
        win["has_request"],
        Value::Bool(false),
        "permissions.request fabricated: {dump}"
    );
    assert_eq!(
        s(&win["notif_perm"]),
        "default",
        "Notification.permission: {dump}"
    );
    assert_eq!(state, "prompt", "notifications query.state: {state}");
}
