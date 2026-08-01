//! Live characterization of reynard's ENGINE-level device farble and its
//! per-identity SEEDING contract.
//!
//! `launch_reynard_with_config` ALWAYS sets the engine noise seeds
//! (`audio:seed`, `fonts:spacing_seed`, `canvas:seed`); the SEED VALUE is what
//! varies, keyed on `config.profile_dir`:
//!   * a `profile_dir` persona → a STABLE seed derived from the dir, so the same
//!     identity reads as the SAME device across its own sessions but a DIFFERENT
//!     device from other identities (defeats serial-signup correlation);
//!   * an ephemeral persona (no `profile_dir`) → a RANDOM per-launch seed, so two
//!     ephemeral launches from one host are NOT linkable by canvas/audio FP.
//!
//! What each engine seed does (verified by the divergence assertions below, if a
//! seed were inert, two different seeds would produce IDENTICAL output and the
//! `assert_ne!`s would fail):
//!   * `fonts:spacing_seed` → `FontSpacingSeedManager` perturbs glyph spacing, so
//!     any TEXT-based canvas fingerprint shifts, and it reaches EVERY realm
//!     (engine-level), including a Worker's OffscreenCanvas (the JS preload path
//!     cannot reach a Worker realm; this is engine-only coverage).
//!   * `audio:seed`  → `AudioFingerprintManager` farbles the audio fingerprint.
//!   * `canvas:seed` → DEAD: no `.cpp` reader consumes it (the engine reads readable
//!     string keys: `MaskConfig::GetUint32("audio:seed")` /
//!     `("fonts:spacing_seed")`: and `canvas:seed` appears only in the properties
//!     manifest), so pure-SHAPE (non-text) 2D-canvas pixels are NOT noised. Contract 5
//!     below is the live ORACLE for this (not just a source grep): a no-text canvas is
//!     byte-identical across all identities. Set for forward-compat only; do not rely
//!     on it.
//!
//! NB: Firefox does not expose `OfflineAudioContext` in Workers, so the audio FP
//! is a WINDOW-only surface (no audio worker realm to cover); only canvas is
//! probed in the worker.
//!
//! Contracts pinned (all are reynard-vs-reynard, so they hold regardless of which
//! reynard build is under test, no "bare host" reference is needed, and no
//! ground-truth Windows/Mac dump is required):
//!   1. STABILITY     same profile_dir, two launches → identical canvas AND audio
//!   2. UNIQUENESS    two different profile_dirs      → different (canvas,audio) vector
//!   3. UNLINKABILITY two ephemeral launches          → different (canvas,audio) vector
//!   4. WORKER REACH  within a launch: canvas_win == canvas_worker
//!   5. canvas:seed DEAD: pure-SHAPE (no-text) canvas is IDENTICAL across all identities
//!
//! UNIQUENESS/UNLINKABILITY compare the FULL (canvas,audio) VECTOR, not each axis: the
//! `fonts:spacing_seed` text-canvas space is COARSE, so two distinct seeds can collide on
//! the canvas axis alone (seen live), linkability is only defeated when the COMBINED
//! vector differs, which is the sound contract (and a full-vector collision still fails).
//!
//! Opt-in: `REYNARD_BIN=$HOME/.local/share/reynard/reynard DISPLAY=:1
//!   [STEALTH_FIREFOX=…] cargo test -p guise --features browser
//!   --test reynard_canvas_audio_farble_live -- --nocapture`.
#![cfg(feature = "browser")]

use guise::fingerprint::StealthProfile;
use runtime_foxdriver::browser::Page;
use runtime_foxdriver::FoxBrowserConfig;

const CANVAS_WIN: &str = r#"(function(){
  try {
    var oc = new OffscreenCanvas(220,60); var c = oc.getContext('2d');
    c.textBaseline='top'; c.font='16px serif';
    c.fillStyle='#069'; c.fillRect(0,0,220,60);
    c.fillStyle='#f60'; c.fillText('Cwm fjord bank glyphs 😃',2,2);
    var d = c.getImageData(0,0,220,60).data;
    var h=2166136261>>>0; for(var i=0;i<d.length;i++){ h=((h^d[i])*16777619)>>>0; }
    return String(h>>>0);
  } catch(e){ return 'ERR:'+e; }
})()"#;

// PURE-SHAPE 2D canvas: geometry + gradients only, NO text/font. Isolates whether the
// device seeds touch raw 2D pixels (the `canvas:seed` key) vs only text via glyph spacing
// (`fonts:spacing_seed`). If `canvas:seed` were a live reader, this would vary per
// identity; the assertion that it is CONSTANT across identities is the oracle proving the
// "canvas:seed is a dead key / pure-shape canvas unnoised" claim, rather than inferring it
// from source greps.
const CANVAS_SHAPE: &str = r#"(function(){
  try {
    var oc = new OffscreenCanvas(200,80); var c = oc.getContext('2d');
    c.fillStyle='#069'; c.fillRect(0,0,200,80);
    var g = c.createLinearGradient(0,0,200,80); g.addColorStop(0,'#f60'); g.addColorStop(1,'#0a3');
    c.fillStyle=g; c.beginPath(); c.arc(100,40,30,0,Math.PI*2); c.fill();
    c.strokeStyle='#fff'; c.lineWidth=3; c.beginPath(); c.moveTo(10,10); c.lineTo(190,70); c.stroke();
    var d = c.getImageData(0,0,200,80).data;
    var h=2166136261>>>0; for(var i=0;i<d.length;i++){ h=((h^d[i])*16777619)>>>0; }
    return String(h>>>0);
  } catch(e){ return 'ERR:'+e; }
})()"#;

const AUDIO_WIN: &str = r#"(function(){
  return new Promise(function(resolve){
    try {
      var OAC = self.OfflineAudioContext || self.webkitOfflineAudioContext;
      var ctx = new OAC(1, 44100, 44100);
      var osc = ctx.createOscillator(); osc.type='triangle'; osc.frequency.value=10000;
      var cm = ctx.createDynamicsCompressor();
      osc.connect(cm); cm.connect(ctx.destination); osc.start(0);
      ctx.startRendering().then(function(buf){
        var a = buf.getChannelData(0);
        var h=2166136261>>>0; for(var j=4000;j<5000;j++){ var v=Math.round(Math.abs(a[j])*1e7); h=((h^(v&0xff))*16777619)>>>0; }
        resolve(String(h>>>0));
      }).catch(function(e){ resolve('ERR:'+e); });
    } catch(e){ resolve('ERR:'+e); }
  });
})()"#;

// Worker: canvas only (FF has no OfflineAudioContext in workers).
const WORKER_CANVAS: &str = r#"(function(){
  return new Promise(function(resolve){
    var src = "self.onmessage=function(){try{"
      + "var oc=new OffscreenCanvas(220,60);var c=oc.getContext('2d');c.textBaseline='top';c.font='16px serif';"
      + "c.fillStyle='#069';c.fillRect(0,0,220,60);c.fillStyle='#f60';c.fillText('Cwm fjord bank glyphs 😃',2,2);"
      + "var d=c.getImageData(0,0,220,60).data;var h=2166136261>>>0;for(var i=0;i<d.length;i++){h=((h^d[i])*16777619)>>>0;}"
      + "postMessage(String(h>>>0));}catch(e){postMessage('ERR:'+e);}};";
    var b=new Blob([src],{type:'application/javascript'});
    var w=new Worker(URL.createObjectURL(b));
    w.onmessage=function(e){ resolve(e.data); };
    w.postMessage(0);
    setTimeout(function(){ resolve('TIMEOUT'); }, 6000);
  });
})()"#;

struct M {
    canvas_win: String,
    canvas_worker: String,
    canvas_shape: String,
    audio_win: String,
}

impl M {
    fn ok(&self, label: &str) {
        for (k, v) in [
            ("canvas_win", &self.canvas_win),
            ("canvas_worker", &self.canvas_worker),
            ("canvas_shape", &self.canvas_shape),
            ("audio_win", &self.audio_win),
        ] {
            assert!(
                !v.starts_with("ERR") && v != "TIMEOUT",
                "{label}.{k} probe failed: {v}"
            );
        }
    }
}

async fn measure(page: Page) -> M {
    page.goto("about:blank").await.expect("nav");
    let canvas_win = page
        .evaluate(CANVAS_WIN)
        .await
        .expect("cw")
        .into_value::<String>()
        .expect("cw");
    let canvas_shape = page
        .evaluate(CANVAS_SHAPE)
        .await
        .expect("cs")
        .into_value::<String>()
        .expect("cs");
    let audio_win = page
        .evaluate_await(AUDIO_WIN)
        .await
        .expect("aw")
        .into_value::<String>()
        .expect("aw");
    let canvas_worker = page
        .evaluate_await(WORKER_CANVAS)
        .await
        .expect("wk")
        .into_value::<String>()
        .expect("wk");
    // close() (graceful SIGTERM + lock release) then drop fully tears the child
    // down before this fn returns, so the next launch, even one reusing the same
    // profile_dir (does not race the dying process for the profile lock).
    let _ = page.close().await;
    M {
        canvas_win,
        canvas_worker,
        canvas_shape,
        audio_win,
    }
}

fn cfg(profile_dir: Option<&str>) -> FoxBrowserConfig {
    let mut c = FoxBrowserConfig {
        headless: true,
        profile_dir: profile_dir.map(|s| s.to_string()),
        ..Default::default()
    };
    if let Ok(p) = std::env::var("STEALTH_FIREFOX") {
        c.executable_path = Some(p);
    }
    c
}

async fn launch(reynard_bin: &str, profile_dir: Option<&str>) -> M {
    measure(
        guise::browser::launch_reynard_with_config(
            reynard_bin,
            &StealthProfile::FirefoxWindows,
            cfg(profile_dir),
        )
        .await
        .expect("launch reynard"),
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reynard_seed_is_stable_per_identity_random_when_ephemeral() {
    let Ok(reynard_bin) = std::env::var("REYNARD_BIN") else {
        eprintln!("SKIP reynard_canvas_audio_farble_live: set REYNARD_BIN");
        return;
    };
    if std::env::var("DISPLAY").is_err() {
        eprintln!("SKIP reynard_canvas_audio_farble_live: no DISPLAY");
        return;
    }
    let pid = std::process::id();
    let dir_a = format!("{}/reynard-persona-A-{pid}", std::env::temp_dir().display());
    let dir_b = format!("{}/reynard-persona-B-{pid}", std::env::temp_dir().display());

    // SEQUENTIAL so each browser is fully torn down before the next launch.
    let a1 = launch(&reynard_bin, Some(&dir_a)).await; // identity A, session 1
    let a2 = launch(&reynard_bin, Some(&dir_a)).await; // identity A, session 2 (same dir)
    let b = launch(&reynard_bin, Some(&dir_b)).await; // identity B
    let e1 = launch(&reynard_bin, None).await; // ephemeral 1
    let e2 = launch(&reynard_bin, None).await; // ephemeral 2

    let report = format!(
        "                canvas_win   canvas_worker  canvas_shape  audio_win\n\
         A.session1:    {:>10}  {:>10}  {:>10}  {:>10}\n\
         A.session2:    {:>10}  {:>10}  {:>10}  {:>10}\n\
         B:             {:>10}  {:>10}  {:>10}  {:>10}\n\
         ephemeral1:    {:>10}  {:>10}  {:>10}  {:>10}\n\
         ephemeral2:    {:>10}  {:>10}  {:>10}  {:>10}\n",
        a1.canvas_win,
        a1.canvas_worker,
        a1.canvas_shape,
        a1.audio_win,
        a2.canvas_win,
        a2.canvas_worker,
        a2.canvas_shape,
        a2.audio_win,
        b.canvas_win,
        b.canvas_worker,
        b.canvas_shape,
        b.audio_win,
        e1.canvas_win,
        e1.canvas_worker,
        e1.canvas_shape,
        e1.audio_win,
        e2.canvas_win,
        e2.canvas_worker,
        e2.canvas_shape,
        e2.audio_win,
    );
    let _ = std::fs::write("/tmp/guise_reynard_canvas_audio.txt", &report);
    eprint!("{report}");

    for (l, m) in [
        ("A.session1", &a1),
        ("A.session2", &a2),
        ("B", &b),
        ("ephemeral1", &e1),
        ("ephemeral2", &e2),
    ] {
        m.ok(l);
    }

    // NB on comparison shape: STABILITY asserts each axis EXACTLY equal (same seed is
    // deterministic, so this is safe and maximally strict). UNIQUENESS/UNLINKABILITY
    // compare the FULL (canvas, audio) device VECTOR, not each axis independently: the
    // `fonts:spacing_seed` text-canvas hash space is COARSE, distinct seeds can collide
    // on the canvas axis alone (observed live: B.canvas == ephemeral2.canvas for
    // different seeds). Linkability is defeated when the COMBINED vector differs, so a
    // single-axis collision is NOT a leak; a per-axis `assert_ne!` would flake on it. A
    // FULL-vector collision (both axes equal for two different seeds) WOULD be a real
    // linkability bug (so the vector `assert_ne!` still has teeth).
    let dev = |m: &M| (m.canvas_win.clone(), m.audio_win.clone());

    // 1. STABILITY (same profile_dir across sessions reproduces the SAME device).
    assert_eq!(
        a1.canvas_win, a2.canvas_win,
        "same identity gave different text-canvas across sessions (seed not stable): {report}"
    );
    assert_eq!(
        a1.audio_win, a2.audio_win,
        "same identity gave different audio across sessions (seed not stable): {report}"
    );

    // 2. UNIQUENESS, different identities are a DIFFERENT device (proves the seed is
    //    load-bearing, not inert: distinct seeds → distinct device vector).
    assert_ne!(dev(&a1), dev(&b),
        "two identities produced the SAME (canvas,audio) device vector, seed not keyed on profile_dir? {report}");

    // 3. UNLINKABILITY, two ephemeral launches are UNLINKABLE (the fix: ephemeral now
    //    gets a RANDOM per-launch seed instead of leaking the stable real-host FP).
    assert_ne!(dev(&e1), dev(&e2),
        "two ephemeral launches produced the SAME (canvas,audio) device vector, ephemeral seed not randomized (host FP leak): {report}");

    // 4. WORKER REACH, the engine font-spacing perturbation reaches the Worker
    //    realm (window == worker), which the JS preload path cannot do.
    assert_eq!(
        a1.canvas_win, a1.canvas_worker,
        "identity A text-canvas perturbation does not reach the Worker realm: {report}"
    );
    assert_eq!(
        e1.canvas_win, e1.canvas_worker,
        "ephemeral text-canvas perturbation does not reach the Worker realm: {report}"
    );

    // 5. canvas:seed IS A DEAD KEY (pure-SHAPE 2D canvas is NOT noised). The device
    //    seeds drive the TEXT canvas (via fonts:spacing_seed) and audio, but a 2D canvas
    //    with NO text is byte-identical across every identity AND the ephemeral launches,
    //    because no engine reader consumes `canvas:seed`. This is the ORACLE behind the
    //    "canvas:seed dead / pure-shape unnoised" claim in the reynard docs: if any path
    //    noised raw 2D pixels per seed, these five would diverge and this assertion would
    //    fail (a real finding, a non-text canvas FP would then be per-identity, and the
    //    docs would be wrong). It establishes the residual: a pure-shape canvas FP is the
    //    stable host value and is NOT protected by the per-identity seed.
    let shapes = [
        &a1.canvas_shape,
        &a2.canvas_shape,
        &b.canvas_shape,
        &e1.canvas_shape,
        &e2.canvas_shape,
    ];
    for s in &shapes {
        assert_eq!(
            **s, a1.canvas_shape,
            "pure-SHAPE 2D canvas DIFFERS across identities: `canvas:seed` (or another \
             path) IS noising raw 2D pixels; the 'dead key / pure-shape unnoised' doc claim \
             is WRONG and must be corrected: {report}"
        );
    }
}
