//! Window/screen geometry coherence for the reynard engine, the regression that
//! pins the incolumitas `PHANTOM_WINDOW_HEIGHT` tell.
//!
//! `reynard_live_detectors` found that reynard is flagged by incolumitas on
//! `PHANTOM_WINDOW_HEIGHT` while real stock Firefox on the SAME display is not (a
//! differential proving it is a reynard geometry tell, not an Xvfb artifact). A
//! "phantom window" is one whose advertised window box is inconsistent with the
//! advertised screen, most often `outerHeight > screen.height` (a window taller
//! than the monitor it claims to live on), which happens when the spoofed
//! `screen.*` is small but the real headful window opened at the host display's
//! full height. This test reads reynard's real geometry and asserts the
//! invariants a genuine browser window always satisfies.
//!
//! Opt-in (needs a built reynard binary, a display, network egress):
//! ```text
//! REYNARD_BIN=/…/dist/bin/camoufox DISPLAY=:1 MOZ_DISABLE_CONTENT_SANDBOX=1 \
//!   cargo test -p guise --no-default-features --features browser \
//!   --test reynard_window_geometry -- --nocapture
//! ```
#![cfg(feature = "browser")]

use guise::browser::launch_reynard;
use guise::fingerprint::StealthProfile;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct Geometry {
    outer_w: i64,
    outer_h: i64,
    inner_w: i64,
    inner_h: i64,
    scr_w: i64,
    scr_h: i64,
    avail_w: i64,
    avail_h: i64,
    screen_x: i64,
    screen_y: i64,
    dpr: f64,
    client_w: i64,
    client_h: i64,
    visual_w: i64,
    visual_h: i64,
}

const PROBE: &str = r#"(() => ({
  outer_w: window.outerWidth, outer_h: window.outerHeight,
  inner_w: window.innerWidth, inner_h: window.innerHeight,
  scr_w: screen.width, scr_h: screen.height,
  avail_w: screen.availWidth, avail_h: screen.availHeight,
  screen_x: window.screenX, screen_y: window.screenY,
  dpr: window.devicePixelRatio,
  client_w: document.documentElement.clientWidth,
  client_h: document.documentElement.clientHeight,
  visual_w: Math.round((window.visualViewport && window.visualViewport.width) || 0),
  visual_h: Math.round((window.visualViewport && window.visualViewport.height) || 0)
}))()"#;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reynard_window_is_geometrically_coherent_with_its_screen() {
    let Ok(reynard_bin) = std::env::var("REYNARD_BIN") else {
        eprintln!("SKIP reynard_window_geometry: set REYNARD_BIN=/path/to/reynard/camoufox to run");
        return;
    };
    if std::env::var("DISPLAY").is_err() {
        eprintln!("SKIP reynard_window_geometry: no DISPLAY (headful needs an X server)");
        return;
    }

    let reynard = launch_reynard(&reynard_bin, &StealthProfile::FirefoxLinux, false)
        .await
        .expect("launch reynard binary");
    // A real page (about:blank can report a zero-sized content area); tls.peet.ws
    // is light and already used by the sibling harness.
    let _ = reynard.goto("https://tls.peet.ws/").await;
    tokio::time::sleep(std::time::Duration::from_millis(1500)).await;

    let g: Geometry = reynard
        .evaluate(PROBE)
        .await
        .expect("evaluate geometry probe")
        .into_value()
        .expect("geometry deserializes");
    let _ = reynard.close().await;

    eprintln!(
        "[reynard geometry] outer={}x{} inner={}x{} client={}x{} visual={}x{} screen={}x{} avail={}x{} pos=({},{}) dpr={}",
        g.outer_w, g.outer_h, g.inner_w, g.inner_h, g.client_w, g.client_h, g.visual_w, g.visual_h,
        g.scr_w, g.scr_h, g.avail_w, g.avail_h, g.screen_x, g.screen_y, g.dpr
    );

    let chrome_h = g.outer_h - g.inner_h;
    let mut tells: Vec<String> = Vec::new();
    // 1. Non-zero, plausible dimensions (headless often reports 0).
    if g.outer_w <= 0 || g.outer_h <= 0 || g.inner_w <= 0 || g.inner_h <= 0 {
        tells.push(format!(
            "non-positive dimension (outer={}x{}, inner={}x{})",
            g.outer_w, g.outer_h, g.inner_w, g.inner_h
        ));
    }
    // 2. The window cannot be larger than the screen it claims to be on.
    if g.outer_h > g.scr_h {
        tells.push(format!(
            "outerHeight {} > screen.height {} (phantom: window taller than its screen)",
            g.outer_h, g.scr_h
        ));
    }
    if g.outer_w > g.scr_w {
        tells.push(format!(
            "outerWidth {} > screen.width {} (phantom: window wider than its screen)",
            g.outer_w, g.scr_w
        ));
    }
    // 3. The window cannot extend past the bottom/right edge of its screen.
    if g.screen_y + g.outer_h > g.scr_h {
        tells.push(format!(
            "screenY {} + outerHeight {} = {} > screen.height {} (window off-screen)",
            g.screen_y,
            g.outer_h,
            g.screen_y + g.outer_h,
            g.scr_h
        ));
    }
    // 4. Content cannot exceed the window; chrome height must be a plausible
    //    toolbar/tab band (a real Firefox shows ~70-200px; 0 = "phantom"/headless).
    if chrome_h < 0 {
        tells.push(format!(
            "innerHeight {} > outerHeight {} (content taller than window)",
            g.inner_h, g.outer_h
        ));
    }
    if chrome_h == 0 {
        tells.push("outerHeight == innerHeight (zero browser chrome, phantom window)".to_string());
    }
    // 5. The spoofed innerHeight must agree with the ACTUAL layout viewport
    //    (visualViewport / documentElement.clientHeight), otherwise the engine
    //    spoofed window.innerHeight but renders at a different size, a fresh
    //    inner-vs-layout tell. Allow a scrollbar/rounding margin.
    if g.visual_h > 0 && (g.inner_h - g.visual_h).abs() > 24 {
        tells.push(format!(
            "innerHeight {} disagrees with visualViewport height {} (spoof not applied to layout)",
            g.inner_h, g.visual_h
        ));
    }
    if g.client_h > 0 && (g.inner_h - g.client_h).abs() > 24 {
        tells.push(format!(
            "innerHeight {} disagrees with documentElement.clientHeight {} (layout mismatch)",
            g.inner_h, g.client_h
        ));
    }

    assert!(
        tells.is_empty(),
        "reynard window geometry is incoherent with its advertised screen. \
         the PHANTOM_WINDOW class of tell: {tells:?}"
    );
}
