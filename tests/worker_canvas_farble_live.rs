//! Live PoC: is the canvas farble MISSING in a Worker realm?
//!
//! guise's canvas farble patches `OffscreenCanvasRenderingContext2D.prototype
//! .getImageData` (and the 2D/HTMLCanvas paths) in the WINDOW realm via the BiDi
//! preload. A dedicated Worker is a SEPARATE realm the window preload does not reach
//! (workers are not browsing contexts, unlike same/cross-origin iframes which DO
//! inherit the preload). So a worker's OffscreenCanvas fingerprint is UNFARBLED
//! a known anti-bot bypass (compute the canvas FP inside a Worker to dodge
//! main-thread canvas spoofing) that ALSO makes the window canvas FP (farbled)
//! disagree with the worker canvas FP (real host), and leaks the stable host canvas
//! across personas.
//!
//! This is NOT soundly fixable in stock-FF JS: a `Worker`-constructor hook that
//! prepends the farble cannot cover `new Worker('external.js')` (no source to
//! rewrite without breaking SRI/CSP), module/nested/Shared/Service workers, and the
//! hook itself is detectable. Engine-level farbling (reynard) reaches every realm.
//! This test PINS the residual on about:blank (deterministic software readback, no
//! real-origin drift): the worker hash equals BARE's and differs from the persona's
//! farbled WINDOW hash. When reynard's engine farble lands, worker==window and these
//! flip (intentional, update the disposition then).
//!
//! Opt-in: `STEALTH_LIVE_BROWSER=1 [STEALTH_FIREFOX=/path]`.
#![cfg(feature = "browser")]

use guise::fingerprint::StealthProfile;
use runtime_foxdriver::browser::{launch_firefox_self_managed, Page};
use runtime_foxdriver::FoxBrowserConfig;

fn skip() -> bool {
    if std::env::var("STEALTH_LIVE_BROWSER").is_err() {
        eprintln!("skip worker_canvas_farble_live: set STEALTH_LIVE_BROWSER=1");
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

// Identical drawing + FNV-1a hash of the pixel buffer, run in the window realm.
const WINDOW_HASH: &str = r#"(function(){
  try {
    var oc = new OffscreenCanvas(220,60);
    var ctx = oc.getContext('2d');
    ctx.textBaseline='top'; ctx.font='16px serif';
    ctx.fillStyle='#069'; ctx.fillRect(0,0,220,60);
    ctx.fillStyle='#f60'; ctx.fillText('Cwm fjord bank glyphs 😃',2,2);
    var d = ctx.getImageData(0,0,220,60).data;
    var h=2166136261>>>0; for(var i=0;i<d.length;i++){ h=((h^d[i])*16777619)>>>0; }
    return String(h>>>0);
  } catch(e){ return 'ERR:'+e; }
})()"#;

// The SAME drawing + hash, run INSIDE a dedicated Worker (separate realm).
const WORKER_HASH: &str = r#"(function(){
  return new Promise(function(resolve){
    try {
      var src = "self.onmessage=function(){try{"
        + "var oc=new OffscreenCanvas(220,60);var ctx=oc.getContext('2d');"
        + "ctx.textBaseline='top';ctx.font='16px serif';"
        + "ctx.fillStyle='#069';ctx.fillRect(0,0,220,60);"
        + "ctx.fillStyle='#f60';ctx.fillText('Cwm fjord bank glyphs 😃',2,2);"
        + "var d=ctx.getImageData(0,0,220,60).data;"
        + "var h=2166136261>>>0;for(var i=0;i<d.length;i++){h=((h^d[i])*16777619)>>>0;}"
        + "postMessage(String(h>>>0));}catch(e){postMessage('ERR:'+e);}};";
      var b = new Blob([src],{type:'application/javascript'});
      var w = new Worker(URL.createObjectURL(b));
      w.onmessage=function(e){ resolve(e.data); };
      w.postMessage(0);
      setTimeout(function(){ resolve('TIMEOUT'); }, 4000);
    } catch(e){ resolve('ERR:'+e); }
  });
})()"#;

async fn hashes(page: Page) -> (String, String) {
    page.goto("about:blank").await.expect("nav about:blank");
    let win = page
        .evaluate(WINDOW_HASH)
        .await
        .expect("win eval")
        .into_value::<String>()
        .expect("win str");
    let worker = page
        .evaluate_await(WORKER_HASH)
        .await
        .expect("worker eval")
        .into_value::<String>()
        .expect("worker str");
    let _ = page.close().await;
    (win, worker)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn worker_canvas_is_unfarbled_window_is_farbled() {
    if skip() {
        return;
    }
    let (bare_win, bare_worker) =
        hashes(launch_firefox_self_managed(cfg()).await.expect("bare")).await;
    let (p_win, p_worker) = hashes(
        guise::browser::launch_profiled_firefox(cfg(), &StealthProfile::FirefoxWindows)
            .await
            .expect("persona"),
    )
    .await;

    let report = format!(
        "bare:    window={bare_win} worker={bare_worker}\npersona: window={p_win} worker={p_worker}\n"
    );
    let _ = std::fs::write("/tmp/guise_worker_canvas_farble.txt", &report);
    eprint!("{report}");

    for (label, h) in [
        ("bare_win", &bare_win),
        ("bare_worker", &bare_worker),
        ("p_win", &p_win),
        ("p_worker", &p_worker),
    ] {
        assert!(
            !h.starts_with("ERR") && h != "TIMEOUT",
            "{label} probe failed: {h}"
        );
    }

    // The window canvas IS farbled: the persona's window hash differs from bare's.
    assert_ne!(
        p_win, bare_win,
        "persona WINDOW canvas not farbled (== bare), the window farble regressed: {report}"
    );
    // CURRENT DISPOSITION (worker realm hole): the persona's WORKER canvas is NOT
    // farbled, so it equals BARE's worker hash and DIFFERS from the persona's own
    // farbled window hash. Pin both facts.
    assert_eq!(
        p_worker, bare_worker,
        "persona WORKER canvas hash != bare worker, the worker farble now reaches the \
         Worker realm? Engine-level farble present; update the worker-realm disposition. {report}"
    );
    assert_ne!(
        p_win, p_worker,
        "persona window and worker canvas hashes AGREE, either both farbled (worker hole \
         closed) or both unfarbled (window farble broke); investigate. {report}"
    );
}
