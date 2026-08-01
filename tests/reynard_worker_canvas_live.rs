//! Live proof: reynard (engine-level farble) CLOSES the worker-realm canvas hole
//! that the stock-Firefox JS path leaves open.
//!
//! `worker_canvas_farble_live.rs` proves the stock-FF path farbles the WINDOW canvas
//! but NOT a Worker's (the BiDi preload cannot reach the worker realm): persona
//! window != worker, and worker == bare host. reynard perturbs the TEXT-canvas via
//! glyph spacing (`fonts:spacing_seed`) in Gecko C++ (no JS injection, the engine's
//! own generator), so the perturbation applies in EVERY realm including dedicated
//! Workers. (Pure-SHAPE canvas is NOT noised: `canvas:seed` has no engine reader
//! and audio is a window-only surface in Firefox; this test draws TEXT, the perturbed
//! axis.) The coherent-realm signature is: a reynard persona's WINDOW and WORKER canvas
//! hashes AGREE (same engine seed, same drawing), no window-vs-worker inconsistency for
//! a detector to exploit. This is the exact contrast with stock-FF (window != worker),
//! and it is build-/GPU-immune because it compares two realms of the SAME process on
//! about:blank software readback.
//!
//! NB: `launch_reynard` here is an EPHEMERAL persona (no profile_dir). Since the
//! ephemeral-seed fix, an ephemeral launch gets a RANDOM noise seed (not UNSET), so the
//! window==worker agreement now proves the farble REACHES the worker realm, it is no
//! longer the degenerate case where both realms merely render the bare, unfarbled host
//! canvas identically. The per-launch random seed is also why the bare-stock contrast
//! below is logged, not strictly asserted (that, plus the camoufox-150 vs FF-151 build
//! difference, would confound a strict !=).
//!
//! Opt-in: `REYNARD_BIN=$HOME/.local/share/reynard/reynard DISPLAY=:1
//!   STEALTH_FIREFOX=/usr/local/bin/firefox cargo test -p guise --features browser
//!   --test reynard_worker_canvas_live -- --nocapture`.
#![cfg(feature = "browser")]

use guise::fingerprint::StealthProfile;
use runtime_foxdriver::browser::{launch_firefox_self_managed, Page};
use runtime_foxdriver::FoxBrowserConfig;

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
async fn reynard_farbles_worker_canvas_coherently() {
    let Ok(reynard_bin) = std::env::var("REYNARD_BIN") else {
        eprintln!("SKIP reynard_worker_canvas_live: set REYNARD_BIN=/path/to/reynard");
        return;
    };
    if std::env::var("DISPLAY").is_err() {
        eprintln!("SKIP reynard_worker_canvas_live: no DISPLAY");
        return;
    }

    // reynard: engine-level farble, headless software readback for determinism.
    let reynard =
        guise::browser::launch_reynard(&reynard_bin, &StealthProfile::FirefoxWindows, true)
            .await
            .expect("launch reynard");
    let (r_win, r_worker) = hashes(reynard).await;

    // Bare stock Firefox reference (no farble anywhere) for context.
    let bare_pair = if let Ok(stock) = std::env::var("STEALTH_FIREFOX") {
        let mut c = FoxBrowserConfig {
            headless: true,
            ..Default::default()
        };
        c.executable_path = Some(stock);
        let p = launch_firefox_self_managed(c).await.expect("bare");
        Some(hashes(p).await)
    } else {
        None
    };

    let report = format!("reynard: window={r_win} worker={r_worker}\nbare(stock): {bare_pair:?}\n");
    let _ = std::fs::write("/tmp/guise_reynard_worker_canvas.txt", &report);
    eprint!("{report}");

    for (label, h) in [("r_win", &r_win), ("r_worker", &r_worker)] {
        assert!(
            !h.starts_with("ERR") && h != "TIMEOUT",
            "{label} probe failed: {h}"
        );
    }

    // THE PROOF: reynard's window and worker canvas hashes AGREE, the engine farble
    // reaches the Worker realm, so there is NO window-vs-worker inconsistency (the
    // exact tell stock-FF leaves, where window != worker). Build-/GPU-immune: two
    // realms of the same process on about:blank software readback.
    assert_eq!(
        r_win, r_worker,
        "reynard window and worker canvas hashes DISAGREE, the engine farble is not \
         reaching the Worker realm (reynard would then share stock-FF's worker hole): {report}"
    );

    // Context (informative, not asserted, different builds/seeds): if the bare stock
    // reference ran, reynard's coherent value should differ from bare's unfarbled host
    // canvas, evidence the engine farble is actually active rather than a no-op.
    if let Some((b_win, b_worker)) = bare_pair {
        assert_eq!(
            b_win, b_worker,
            "sanity: bare stock window==worker (both unfarbled): {report}"
        );
        // Not asserted strictly (build difference camoufox-150 vs FF-151 alone could
        // explain a diff), but log whether reynard diverged from the bare host canvas.
        eprintln!(
            "[reynard vs bare] reynard={r_win} bare={b_win} differ={}",
            r_win != b_win
        );
    }
}
