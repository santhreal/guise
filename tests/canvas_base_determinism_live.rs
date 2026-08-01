//! Live DIAGNOSTIC: where does canvas-hash drift across restarts come from, the
//! engine's base render, a non-deterministic glyph (color emoji), or the guise
//! farble seed?
//!
//! guise's canvas farble is a pure function of `(seed, x, y, channel)` applied ON
//! TOP of the engine's real pixels, so a stable seed yields a stable hash ONLY IF
//! the base render is itself stable. Three probes isolate the cause:
//!   A) bare engine, ASCII text, base determinism, no farble
//!   B) bare engine, COLOR EMOJI (does the emoji glyph rasterize deterministically)?
//!   C) full stealth, ASCII text (does the per-profile seed make the farble stable)?
//!
//! Opt-in: `STEALTH_LIVE_BROWSER=1 [STEALTH_FIREFOX=/path]`.
#![cfg(feature = "browser")]

use guise::fingerprint::StealthProfile;
use runtime_foxdriver::browser::launch_firefox_self_managed;
use runtime_foxdriver::FoxBrowserConfig;

fn skip() -> bool {
    if std::env::var("STEALTH_LIVE_BROWSER").is_err() {
        eprintln!("skip canvas_base_determinism_live: set STEALTH_LIVE_BROWSER=1");
        return true;
    }
    false
}

fn hash_js(text: &str) -> String {
    format!(
        r#"(function(){{
  try {{
    var c = document.createElement('canvas'); c.width=200; c.height=50;
    var x = c.getContext('2d');
    x.textBaseline='top'; x.font='14px Arial'; x.fillStyle='#069'; x.fillText({text:?}, 2, 2);
    var d = c.toDataURL();
    var h = 0; for (var i=0;i<d.length;i++){{ h=((h<<5)-h+d.charCodeAt(i))|0; }}
    return d.length + ':' + String(h);
  }} catch(e){{ return 'ERR:'+e; }}
}})()"#
    )
}

fn base_cfg(profile_dir: &str) -> FoxBrowserConfig {
    let mut c = FoxBrowserConfig {
        headless: true,
        profile_dir: Some(profile_dir.to_string()),
        ..Default::default()
    };
    if let Ok(p) = std::env::var("STEALTH_FIREFOX") {
        c.executable_path = Some(p);
    }
    c
}

async fn bare_canvas(profile_dir: &str, text: &str) -> String {
    let page = launch_firefox_self_managed(base_cfg(profile_dir))
        .await
        .expect("bare launch");
    page.goto("about:blank").await.expect("nav");
    let h = page
        .evaluate(&hash_js(text))
        .await
        .expect("eval")
        .into_value::<String>()
        .expect("str");
    let _ = page.close().await;
    h
}

async fn stealth_canvas(profile_dir: &str, text: &str) -> String {
    let page = guise::browser::launch_profiled_firefox(
        base_cfg(profile_dir),
        &StealthProfile::FirefoxLinux,
    )
    .await
    .expect("stealth launch");
    page.goto("about:blank").await.expect("nav");
    let h = page
        .evaluate(&hash_js(text))
        .await
        .expect("eval")
        .into_value::<String>()
        .expect("str");
    let _ = page.close().await;
    h
}

fn fresh_dir(tag: &str) -> String {
    let d = std::env::temp_dir()
        .join(format!("guise-canvasdiag-{tag}-{}", std::process::id()))
        .display()
        .to_string();
    let _ = std::fs::remove_dir_all(&d);
    d
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn canvas_determinism_probes() {
    if skip() {
        return;
    }
    // A) bare engine, ASCII.
    let da = fresh_dir("a");
    let a1 = bare_canvas(&da, "guise-persist-x").await;
    let a2 = bare_canvas(&da, "guise-persist-x").await;
    let _ = std::fs::remove_dir_all(&da);
    eprintln!(
        "A bare ASCII : {a1} | {a2} | {}",
        if a1 == a2 { "STABLE" } else { "DRIFT" }
    );

    // B) bare engine, color emoji.
    let db = fresh_dir("b");
    let b1 = bare_canvas(&db, "guise-persist-\u{2764}").await;
    let b2 = bare_canvas(&db, "guise-persist-\u{2764}").await;
    let _ = std::fs::remove_dir_all(&db);
    eprintln!(
        "B bare EMOJI : {b1} | {b2} | {}",
        if b1 == b2 { "STABLE" } else { "DRIFT" }
    );

    // C) full stealth, ASCII (per-profile seed must make the farble stable).
    let dc = fresh_dir("c");
    let c1 = stealth_canvas(&dc, "guise-persist-x").await;
    let c2 = stealth_canvas(&dc, "guise-persist-x").await;
    let _ = std::fs::remove_dir_all(&dc);
    eprintln!(
        "C stealth ASCII: {c1} | {c2} | {}",
        if c1 == c2 { "STABLE" } else { "DRIFT" }
    );

    // D) full stealth, color emoji, the exact combination the persistence test
    // drifted on (farble applied ON TOP of a color-emoji glyph).
    let dd = fresh_dir("d");
    let d1 = stealth_canvas(&dd, "guise-persist-\u{2764}").await;
    let d2 = stealth_canvas(&dd, "guise-persist-\u{2764}").await;
    let _ = std::fs::remove_dir_all(&dd);

    // Reliable capture (browser stderr races the test harness's stderr): write the
    // verdict to a file the runner can read regardless of fd interleaving.
    let report = format!(
        "A bare ASCII   : {a1} | {a2} | {}\nB bare EMOJI   : {b1} | {b2} | {}\nC stealth ASCII: {c1} | {c2} | {}\nD stealth EMOJI: {d1} | {d2} | {}\n",
        if a1 == a2 { "STABLE" } else { "DRIFT" },
        if b1 == b2 { "STABLE" } else { "DRIFT" },
        if c1 == c2 { "STABLE" } else { "DRIFT" },
        if d1 == d2 { "STABLE" } else { "DRIFT" },
    );
    let _ = std::fs::write("/tmp/guise_canvas_diag.txt", &report);
    eprint!("{report}");

    // CONTRACT: the per-profile device-FP seed (launch_profiled_firefox: persona_seed,
    // FNV-1a of profile_dir) makes the canvas farble deterministic across restarts.
    // On about:blank the engine's base render IS deterministic (probes A/B), so any
    // cross-restart drift here would be a seed regression. Both ASCII and the color
    // emoji must be stable. (Bare probes A/B are engine diagnostics; real-origin base
    // nondeterminism is a separate, engine-level concern, see canvas_real_origin_live.)
    assert!(!c1.starts_with("ERR"), "stealth ASCII canvas errored: {c1}");
    assert_eq!(
        c1, c2,
        "stealth canvas (ASCII) not stable across restart, per-profile seed not applied"
    );
    assert_eq!(
        d1, d2,
        "stealth canvas (emoji) not stable across restart, per-profile seed not applied"
    );
}
