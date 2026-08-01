//! Live contract: the persona timezone must be coherent across EVERY JS realm
//! window AND dedicated Workers (not just the window realm the JS preload reaches).
//!
//! CONFIRMED live (dump_worker_timezone_truth in surface_truth_live.rs): the JS
//! `Intl`/`Date` spoof is a window-realm BiDi preload, so a dedicated Worker (its
//! own realm) fell back to the HOST timezone. On a host in America/Phoenix with a
//! New_York persona the stealthed page reported `window=America/New_York(off 240)`
//! but `worker=America/Phoenix(off 420)`: a 180-minute window-vs-worker mismatch
//! any detector spawning a Worker catches. The fix sets `TZ=<persona zone>` as a
//! per-process env var on the Firefox process (`launch_firefox_self_managed`), so
//! ICU reports the persona zone in every realm, DST-correct.
//!
//! This asserts window and worker AGREE on the persona zone and offset.
//!
//! Opt-in: `STEALTH_LIVE_BROWSER=1 [STEALTH_FIREFOX=/path]` (spawns real Firefox).
#![cfg(feature = "browser")]

use guise::fingerprint::{profile_to_overrides, StealthProfile};
use runtime_foxdriver::FoxBrowserConfig;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

fn skip() -> bool {
    if std::env::var("STEALTH_LIVE_BROWSER").is_err() {
        eprintln!("skip timezone_live: set STEALTH_LIVE_BROWSER=1 (spawns real Firefox)");
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
                    b"<!doctype html><html><head><title>t</title></head><body>x</body></html>";
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

/// Reads window-realm and worker-realm timezone, returns compact JSON. Async
/// (spawns a Worker) → run via `evaluate_await`.
const PROBE: &str = r#"(function(){
  function inWorker(){
    return new Promise(function(resolve){
      var code = "self.onmessage=function(){var tz='';var off=null;try{tz=Intl.DateTimeFormat().resolvedOptions().timeZone}catch(e){tz='ERR:'+e}try{off=(new Date()).getTimezoneOffset()}catch(e){off='ERR:'+e}postMessage({tz:tz,off:off})}";
      var w;
      try { w = new Worker(URL.createObjectURL(new Blob([code], {type:'application/javascript'}))); }
      catch(e){ resolve({tz:'NOWORKER:'+e, off:null}); return; }
      var done=false;
      w.onmessage=function(ev){ if(done)return; done=true; try{w.terminate()}catch(_){} resolve(ev.data); };
      w.onerror=function(e){ if(done)return; done=true; resolve({tz:'WERR:'+(e.message||e), off:null}); };
      w.postMessage(0);
      setTimeout(function(){ if(done)return; done=true; resolve({tz:'TIMEOUT', off:null}); }, 5000);
    });
  }
  var winTz=''; try { winTz=Intl.DateTimeFormat().resolvedOptions().timeZone; } catch(e){ winTz='ERR:'+e; }
  var winOff=null; try { winOff=(new Date()).getTimezoneOffset(); } catch(e){ winOff='ERR:'+e; }
  return inWorker().then(function(wk){
    return JSON.stringify({ window_tz: winTz, window_off: winOff, worker_tz: wk.tz, worker_off: wk.off });
  });
})()"#;

#[derive(serde::Deserialize, Debug)]
struct Tz {
    window_tz: String,
    window_off: i64,
    worker_tz: String,
    worker_off: i64,
}

#[tokio::test]
async fn persona_timezone_is_coherent_in_window_and_worker_realms() {
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

    let profile = StealthProfile::FirefoxLinux;
    let persona_tz = profile_to_overrides(&profile).timezone;

    let page = guise::browser::launch_profiled_firefox(cfg, &profile)
        .await
        .expect("launch profiled firefox");
    page.goto(&url).await.expect("navigate");
    let raw = page
        .evaluate_await(PROBE)
        .await
        .expect("evaluate timezone probe")
        .into_value::<String>()
        .expect("probe returns json");
    let _ = page.close().await;

    let t: Tz = serde_json::from_str(&raw).unwrap_or_else(|e| panic!("parse {raw}: {e}"));

    // The window realm must report the persona zone (the JS Intl/Date spoof).
    assert_eq!(
        t.window_tz, persona_tz,
        "window timezone must be the persona zone: {raw}"
    );
    // The worker realm, unreachable by the JS preload, must ALSO report the
    // persona zone, via the TZ env var ICU honors process-wide. This is the leak
    // the fix closes (was the host zone before).
    assert_eq!(
        t.worker_tz, persona_tz,
        "worker timezone leaked a different zone than the window persona. TZ env not applied to the Firefox process: {raw}"
    );
    // Offsets must agree too (catches a same-name/different-offset edge and proves
    // getTimezoneOffset is coherent across realms).
    assert_eq!(
        t.window_off, t.worker_off,
        "window vs worker getTimezoneOffset mismatch: {raw}"
    );
}
