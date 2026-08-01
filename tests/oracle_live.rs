//! Unified live oracle suite (G209 / G210).
//!
//! This replaces the previously separate `differential_oracle`, `headful_truth`,
//! `headless_tells`, and `stealth_core_tells` test files with a single
//! oracle-driven run. The shared catalogue is the source of truth, so overlapping
//! assertions (automation tells, WebGL, navigator.webdriver, etc.) are checked
//! once through the probe taxonomy rather than duplicated in bespoke JS snippets.
//!
//! Opt-in (spawns real Firefoxes):
//! ```text
//! STEALTH_LIVE_BROWSER=1 [DISPLAY=:1] \
//!   cargo test -p guise --features browser --test oracle_live -- --nocapture
//! ```
//! `STEALTH_FIREFOX=/path/to/firefox` overrides binary discovery.
//! `HEADFUL_GPU=1` with `DISPLAY` enables the headful GPU truth diagnostic.

#![cfg(feature = "browser")]

use guise::fingerprint::{FingerprintConfig, StealthProfile};
use guise::probe::{diff_pages, render_differential, run_for, Severity, UserAgentBrowser};
use runtime_foxdriver::{launch_firefox, launch_firefox_self_managed, FoxBrowserConfig, Page};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

const FAMILY: UserAgentBrowser = UserAgentBrowser::Firefox;

fn ff_path() -> Option<String> {
    std::env::var("STEALTH_FIREFOX").ok()
}

fn skip_reason() -> Option<&'static str> {
    if std::env::var("STEALTH_LIVE_BROWSER").is_err() {
        return Some("set STEALTH_LIVE_BROWSER=1 to run (spawns real Firefoxes)");
    }
    None
}

async fn stock_page(label: &str) -> Page {
    let mut cfg = FoxBrowserConfig {
        headless: true,
        viewport_width: 1280,
        viewport_height: 720,
        ..Default::default()
    };
    if let Some(p) = ff_path() {
        cfg.executable_path = Some(p);
    }
    let page = launch_firefox(cfg)
        .await
        .unwrap_or_else(|e| panic!("launch stock firefox ({label}): {e}"));
    page.goto("about:blank").await.expect("nav stock");
    page
}

async fn disguised_page() -> Page {
    let profile_dir = std::env::temp_dir()
        .join(format!("guise-oracle-live-{}", std::process::id()))
        .to_string_lossy()
        .to_string();
    let mut cfg = FoxBrowserConfig {
        headless: true,
        viewport_width: 1280,
        viewport_height: 720,
        profile_dir: Some(profile_dir),
        ..Default::default()
    };
    if let Some(p) = ff_path() {
        cfg.executable_path = Some(p);
    }
    let page = guise::browser::launch_profiled_firefox(cfg, &StealthProfile::FirefoxLinux)
        .await
        .expect("launch disguised firefox");
    page.goto("about:blank").await.expect("nav disguised");
    page
}

async fn eval_str(page: &Page, js: &str) -> String {
    page.evaluate(js)
        .await
        .ok()
        .and_then(|e| e.into_value::<String>().ok())
        .unwrap_or_default()
}

async fn serve() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut s, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut b = [0u8; 1024];
                let _ = s.read(&mut b).await;
                // A realistic <head> (with a <title>) so document.head has children
                //: a bare <html><body> leaves document.head auto-created but EMPTY,
                // which the "document.head.children.length >= 1" probe would flag as a
                // false Critical (no real navigated page has an empty head).
                let body =
                    b"<!doctype html><html><head><title>x</title></head><body>x</body></html>";
                let _ = s
                    .write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len()).as_bytes())
                    .await;
                let _ = s.write_all(body).await;
                let _ = s.shutdown().await;
            });
        }
    });
    format!("http://{addr}/")
}

// ── 1. Differential oracle: soundness + residual tells ───────────────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn oracle_soundness_and_disguise_residuals() {
    if let Some(reason) = skip_reason() {
        eprintln!("SKIP oracle_soundness_and_disguise_residuals: {reason}");
        return;
    }

    // Soundness: two identical stock Firefoxes must agree on every High-severity
    // deterministic surface. A divergence here is an oracle/probe bug.
    let a = stock_page("A").await;
    let b = stock_page("B").await;
    let baseline = diff_pages(&a, &b, FAMILY, "stock-A", "stock-B")
        .await
        .expect("diff stock vs stock");
    eprintln!("\n{}", render_differential(&baseline));
    let _ = a.close().await;
    let _ = b.close().await;

    let high_baseline: Vec<&str> = baseline
        .divergences
        .iter()
        .filter(|d| d.severity == Severity::High)
        .map(|d| d.surface.as_str())
        .collect();
    assert!(
        high_baseline.is_empty(),
        "oracle unsound: two identical stock Firefoxes diverged on High-severity surfaces {high_baseline:?}"
    );

    // Visibility: diff the JS disguise against stock and print residual tells.
    let stock_ref = stock_page("ref").await;
    let dis = disguised_page().await;
    let tells = diff_pages(&stock_ref, &dis, FAMILY, "stock-firefox", "js-disguise")
        .await
        .expect("diff stock vs disguise");
    eprintln!(
        "\n── JS-DISGUISE RESIDUAL TELLS (vs stock Firefox) ──\n{}",
        render_differential(&tells)
    );
    let _ = stock_ref.close().await;
    let _ = dis.close().await;

    // WebGL native-passthrough must hold: the disguise must not diverge from stock
    // on any WebGL surface.
    let webgl_tells: Vec<&str> = tells
        .divergences
        .iter()
        .filter(|d| d.surface.to_lowercase().contains("webgl"))
        .map(|d| d.surface.as_str())
        .collect();
    assert!(
        webgl_tells.is_empty(),
        "WebGL native-passthrough regressed, disguise diverges from stock on {webgl_tells:?}"
    );

    // Catalogue-level check: the disguise page must not produce any Critical probe
    // outcome (e.g. navigator.webdriver === true).
    //
    // run_for is an ABSOLUTE catalogue check, so it MUST run on a secure context
    // (http://127.0.0.1), NOT about:blank: a `data:`/opaque origin legitimately
    // lacks crypto.subtle / StorageManager / serviceWorker / clipboard / caches /
    // storage.getDirectory / PushManager, which the catalogue would then flag as
    // false "missing surface" Criticals (the same reason probe_live serves a secure
    // origin). The differential diffs above are RELATIVE (both sides on about:blank)
    // so they are unaffected.
    let secure = serve().await;
    let dis2 = disguised_page().await;
    dis2.goto(&secure)
        .await
        .expect("nav disguise to secure origin");
    let drift = run_for(&dis2, FAMILY)
        .await
        .expect("run probe catalogue on disguise");
    let _ = dis2.close().await;
    assert_eq!(
        drift.critical,
        0,
        "disguise produced Critical probe outcomes: {:?}",
        drift
            .per_probe
            .iter()
            .filter(|p| p.outcome.is_critical())
            .map(|p| &p.name)
            .collect::<Vec<_>>()
    );
}

// ── 2. Core automation-tell regression: native-code sealing ───────────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stealth_overrides_report_native_code_via_tostring() {
    if let Some(reason) = skip_reason() {
        eprintln!("SKIP stealth_overrides_report_native_code_via_tostring: {reason}");
        return;
    }
    let url = serve().await;

    const WEBDRIVER_GETTER_TS: &str = "(function(){try{var d=Object.getOwnPropertyDescriptor(Navigator.prototype,'webdriver');return d&&d.get?String(d.get.toString()):'<<no-getter>>';}catch(e){return '<<err>>';}})()";

    // NEGATIVE twin: a naive un-sealed override leaks non-native source.
    let bare = launch_firefox(FoxBrowserConfig {
        headless: true,
        ..Default::default()
    })
    .await
    .expect("launch bare");
    bare.goto(&url).await.unwrap();
    let _ = bare
        .evaluate("Object.defineProperty(Navigator.prototype, 'webdriver', { get: () => undefined, configurable: true });")
        .await;
    let naive = eval_str(&bare, WEBDRIVER_GETTER_TS).await;
    let _ = bare.close().await;
    assert!(
        !naive.contains("[native code]"),
        "control: naive override must leak non-native source, got {naive:?}"
    );

    // POSITIVE: real disguise seals every override.
    let page = launch_firefox(FoxBrowserConfig {
        headless: true,
        ..Default::default()
    })
    .await
    .expect("launch stealthed");
    guise::browser::apply_stealth_profile(&page, &StealthProfile::FirefoxLinux)
        .await
        .expect("apply stealth");
    let fp_config = FingerprintConfig::default();
    guise::fingerprint::apply_fingerprint(&page, &fp_config)
        .await
        .expect("apply fingerprint evasion");
    page.goto(&url).await.unwrap();

    assert!(
        eval_str(&page, WEBDRIVER_GETTER_TS)
            .await
            .contains("[native code]"),
        "sealed webdriver getter toString must report native"
    );
    assert!(
        eval_str(
            &page,
            "WebGLRenderingContext.prototype.getParameter.toString()"
        )
        .await
        .contains("[native code]"),
        "sealed WebGL getParameter toString must report native"
    );
    assert!(
        eval_str(&page, "HTMLCanvasElement.prototype.toDataURL.toString()")
            .await
            .contains("[native code]"),
        "sealed canvas toDataURL toString must report native"
    );
    assert!(
        // OfflineAudioContext takes (channels, length, sampleRate); AudioContext
        // takes an options object, so `new AudioContext(1,100,44100)` throws a
        // WebIDL TypeError (a non-object where a dictionary is expected) and the
        // probe never reaches getFloatFrequencyData. Use the offline context, its
        // analyser shares AnalyserNode.prototype, so the seal under test is identical.
        eval_str(&page, "(function(){ try { const ctx = new (window.OfflineAudioContext || window.webkitOfflineAudioContext)(1, 100, 44100); const a = ctx.createAnalyser(); return a.getFloatFrequencyData.toString(); } catch (e) { return 'ERR:' + e; } })()").await.contains("[native code]"),
        "sealed audio getFloatFrequencyData toString must report native"
    );
    assert!(
        eval_str(&page, "document.fonts && document.fonts.constructor && document.fonts.constructor.prototype.forEach ? document.fonts.constructor.prototype.forEach.toString() : 'n/a'").await.contains("[native code]"),
        "sealed FontFaceSet.forEach toString must report native"
    );
    assert!(
        eval_str(&page, "Function.prototype.toString.toString()")
            .await
            .contains("[native code]"),
        "Function.prototype.toString must report native"
    );
    // Guard against over-broad spoofing.
    assert!(
        eval_str(&page, "Array.prototype.push.toString()")
            .await
            .contains("[native code]"),
        "genuine native must still report native"
    );

    let _ = page.close().await;
}

// ── 3. Session-age seeding ───────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn session_age_seeds_history_and_local_storage() {
    if let Some(reason) = skip_reason() {
        eprintln!("SKIP session_age_seeds_history_and_local_storage: {reason}");
        return;
    }
    let url = serve().await;

    let page = launch_firefox(FoxBrowserConfig {
        headless: true,
        ..Default::default()
    })
    .await
    .expect("launch for session age");

    // localStorage is only available on a real (secure) origin, on the initial
    // about:blank/opaque origin it is inaccessible and seeding silently stores 0.
    // Navigate to the served http://127.0.0.1 origin BEFORE seeding so the seeded
    // entries land in a usable store (and are readable back below).
    page.goto(&url).await.unwrap();

    let seed = guise::browser::generate_session_age(12345);
    let (added, stored) = guise::browser::apply_session_age(&page, &seed)
        .await
        .expect("apply session age");
    assert!(added > 0, "history.length should increase");
    assert!(stored > 0, "localStorage should receive seeded entries");
    let history_len: i64 = page
        .evaluate("history.length")
        .await
        .unwrap()
        .into_value()
        .unwrap();
    assert!(
        history_len >= i64::from(seed.history_length),
        "history.length {history_len} should be at least {}",
        seed.history_length
    );

    for (k, v) in &seed.local_storage_entries {
        let got: String = page
            .evaluate(format!("localStorage.getItem({})", serde_json::json!(k)))
            .await
            .unwrap()
            .into_value()
            .unwrap();
        assert_eq!(got, *v, "localStorage key {k:?} mismatch");
    }

    let _ = page.close().await;
}

// ── 4. Diagnostic dumps (headful GPU and headless-sensitive surfaces) ────────

const READ_TRUTH_JS: &str = r#"
(() => {
  let gl = null, unmaskedVendor = '?', unmaskedRenderer = '?',
      rawVendor = 'n/a', rawRenderer = 'n/a';
  try {
    const c = document.createElement('canvas');
    gl = c.getContext('webgl') || c.getContext('experimental-webgl');
    if (gl) {
      rawVendor = String(gl.getParameter(gl.VENDOR));
      rawRenderer = String(gl.getParameter(gl.RENDERER));
      const ext = gl.getExtension('WEBGL_debug_renderer_info');
      if (ext) {
        unmaskedVendor = String(gl.getParameter(ext.UNMASKED_VENDOR_WEBGL));
        unmaskedRenderer = String(gl.getParameter(ext.UNMASKED_RENDERER_WEBGL));
      } else {
        unmaskedVendor = '(no debug_renderer_info ext)';
        unmaskedRenderer = '(no debug_renderer_info ext)';
      }
    } else {
      unmaskedRenderer = '(no webgl context)';
    }
  } catch (e) {
    unmaskedRenderer = 'ERR:' + e;
  }
  return {
    webdriver: navigator.webdriver,
    platform: navigator.platform,
    ua: navigator.userAgent,
    unmaskedVendor, unmaskedRenderer, rawVendor, rawRenderer,
    screenW: screen.width, screenH: screen.height, colorDepth: screen.colorDepth,
    innerW: window.innerWidth, innerH: window.innerHeight,
    outerW: window.outerWidth, outerH: window.outerHeight,
    dpr: window.devicePixelRatio,
    hwConcurrency: navigator.hardwareConcurrency,
    pluginsLen: navigator.plugins ? navigator.plugins.length : -1,
    isPluginArray: navigator.plugins ? (navigator.plugins instanceof PluginArray) : false
  };
})()
"#;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn headful_gpu_truth_diagnostic() {
    if let Some(reason) = skip_reason() {
        eprintln!("SKIP headful_gpu_truth_diagnostic: {reason}");
        return;
    }
    if std::env::var("HEADFUL_GPU").is_err() {
        eprintln!("SKIP headful_gpu_truth_diagnostic: set HEADFUL_GPU=1 with DISPLAY to capture headful GPU truth");
        return;
    }
    if std::env::var("DISPLAY").is_err() {
        eprintln!("SKIP headful_gpu_truth_diagnostic: no DISPLAY set");
        return;
    }

    let mut cfg = FoxBrowserConfig {
        headless: false,
        viewport_width: 1280,
        viewport_height: 720,
        ..Default::default()
    };
    if let Some(p) = ff_path() {
        cfg.executable_path = Some(p);
    }
    let bare = launch_firefox(cfg.clone())
        .await
        .expect("launch bare headful firefox");
    bare.goto("about:blank").await.expect("nav bare");
    let truth = bare.evaluate(READ_TRUTH_JS).await.expect("eval truth");
    eprintln!("\n──────── BARE HEADFUL (real GPU truth) ────────");
    eprintln!(
        "{}",
        serde_json::to_string_pretty(&truth.into_value::<serde_json::Value>().unwrap())
            .unwrap_or_default()
    );
    let _ = bare.close().await;

    let profile_dir = std::env::temp_dir()
        .join(format!("guise-oracle-live-headful-{}", std::process::id()))
        .to_string_lossy()
        .to_string();
    cfg.profile_dir = Some(profile_dir);
    let disguised = guise::browser::launch_profiled_firefox(cfg, &StealthProfile::FirefoxLinux)
        .await
        .expect("launch disguised headful firefox");
    disguised.goto("about:blank").await.expect("nav disguised");
    let truth = disguised.evaluate(READ_TRUTH_JS).await.expect("eval truth");
    eprintln!("\n──────── FULL DISGUISE HEADFUL (what sites see) ────────");
    eprintln!(
        "{}",
        serde_json::to_string_pretty(&truth.into_value::<serde_json::Value>().unwrap())
            .unwrap_or_default()
    );
    let _ = disguised.close().await;
}

const TELLS_JS: &str = r#"(function(){
  function cpt(tag, type){ try { return document.createElement(tag).canPlayType(type); } catch(e){ return 'ERR'; } }
  function mse(type){ try { return !!(window.MediaSource && MediaSource.isTypeSupported(type)); } catch(e){ return 'ERR'; } }
  var rend='(none)', vend='(none)', glok=false;
  try {
    var c=document.createElement('canvas');
    var gl=c.getContext('webgl')||c.getContext('experimental-webgl');
    if(gl){ glok=true;
      var dbg=gl.getExtension('WEBGL_debug_renderer_info');
      if(dbg){ rend=gl.getParameter(dbg.UNMASKED_RENDERER_WEBGL); vend=gl.getParameter(dbg.UNMASKED_VENDOR_WEBGL); }
      else { rend='(no-debug-ext)'; vend='(no-debug-ext)'; }
    }
  } catch(e){ rend='ERR'; }
  var ac={};
  try {
    var AC = window.AudioContext||window.webkitAudioContext;
    var ctx = new AC();
    ac.sampleRate = ctx.sampleRate;
    ac.state = ctx.state;
    ac.maxChannelCount = ctx.destination ? ctx.destination.maxChannelCount : -1;
    if (ctx.close) ctx.close();
  } catch(e){ ac.err = String(e); }
  return {
    ua: navigator.userAgent,
    platform: navigator.platform,
    oscpu: navigator.oscpu,
    h264_mp4: cpt('video','video/mp4; codecs="avc1.42E01E"'),
    aac_mp4:  cpt('audio','audio/mp4; codecs="mp4a.40.2"'),
    mp4_bare: cpt('video','video/mp4'),
    vp9_webm: cpt('video','video/webm; codecs="vp9"'),
    av1_mp4:  cpt('video','video/mp4; codecs="av01.0.05M.08"'),
    opus_ogg: cpt('audio','audio/ogg; codecs="opus"'),
    flac:     cpt('audio','audio/flac'),
    mp3:      cpt('audio','audio/mpeg'),
    mse_h264: mse('video/mp4; codecs="avc1.42E01E"'),
    mse_aac:  mse('audio/mp4; codecs="mp4a.40.2"'),
    webgl_ok: glok,
    webgl_vendor: vend,
    webgl_renderer: rend,
    eme: typeof navigator.requestMediaKeySystemAccess,
    audio: ac,
    dpr: window.devicePixelRatio,
    screen: [screen.width, screen.height, screen.availWidth, screen.availHeight, screen.colorDepth, screen.pixelDepth],
    outer: [window.outerWidth, window.outerHeight, window.innerWidth, window.innerHeight]
  };
})()"#;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn headless_sensitive_surface_diagnostic() {
    let Ok(stock_bin) = std::env::var("STEALTH_FIREFOX") else {
        eprintln!(
            "SKIP headless_sensitive_surface_diagnostic: set STEALTH_FIREFOX=/path/to/firefox"
        );
        return;
    };
    let headful = std::env::var("HEADLESS_TELLS_HEADFUL").is_ok();
    let cfg = FoxBrowserConfig {
        headless: !headful,
        viewport_width: 1280,
        viewport_height: 720,
        executable_path: Some(stock_bin),
        ..Default::default()
    };
    let page = launch_firefox_self_managed(cfg)
        .await
        .expect("launch stock firefox");
    page.goto("about:blank").await.expect("nav about:blank");

    let val = page
        .evaluate(TELLS_JS)
        .await
        .expect("eval tells")
        .into_value::<serde_json::Value>()
        .expect("tells json");
    let _ = page.close().await;

    eprintln!(
        "\n=== headless-Firefox tells ({}) ===\n{}\n",
        if headful { "HEADFUL" } else { "HEADLESS" },
        serde_json::to_string_pretty(&val).unwrap_or_default()
    );

    assert!(val.get("ua").is_some(), "UA surface unreachable");
    assert!(
        val.get("webgl_renderer").is_some(),
        "WebGL surface unreachable"
    );
}
