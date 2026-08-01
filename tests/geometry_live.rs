//! Live contract: the stealthed page's window/screen geometry must satisfy the
//! physical invariants a real browser always satisfies, and must NOT contradict
//! the un-fakeable layout surfaces (documentElement.clientWidth, matchMedia).
//!
//! CONFIRMED live (dump_geometry_truth in surface_truth_live.rs): the previous
//! per-profile disguise pinned window.innerWidth/outerWidth to the persona's
//! screen_width (1920) while the real window stayed the screen-fit size (1366 on a
//! 1366-wide monitor). That produced a TRIPLE contradiction
//!   * innerWidth (1920) > screen.width (1366), window wider than its screen
//!   * `innerWidth` (1920) != `clientWidth` (1366), getter lies over real layout
//!   * `matchMedia('(min-width:1920px)')` == false. CSS engine sees the real 1366
//!     each trivially detected. The fix leaves geometry native (identical to a bare
//!     Firefox). This asserts the shipped disguise is now coherent.
//!
//! Opt-in: `STEALTH_LIVE_BROWSER=1 [STEALTH_FIREFOX=/path]` (spawns real Firefox).
#![cfg(feature = "browser")]

use guise::fingerprint::StealthProfile;
use runtime_foxdriver::FoxBrowserConfig;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

fn skip() -> bool {
    if std::env::var("STEALTH_LIVE_BROWSER").is_err() {
        eprintln!("skip geometry_live: set STEALTH_LIVE_BROWSER=1 (spawns real Firefox)");
        return true;
    }
    false
}

/// Secure origin on http://127.0.0.1 (matchMedia/layout behave like a real page).
async fn serve_secure_origin() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut sock, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buf = [0u8; 2048];
                let _ = sock.read(&mut buf).await;
                let body =
                    b"<!doctype html><html><head><title>g</title></head><body>x</body></html>";
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

const GEOM: &str = r#"JSON.stringify({
  innerW: window.innerWidth, innerH: window.innerHeight,
  outerW: window.outerWidth, outerH: window.outerHeight,
  screenW: screen.width, screenH: screen.height,
  clientW: document.documentElement.clientWidth,
  clientH: document.documentElement.clientHeight,
  /* min-width:innerWidth matches only if the REAL viewport is >= innerWidth, i.e.
     innerWidth is not inflated above the real layout. A lie (1920 over a real
     1366) makes this FALSE. */
  mmAtInner: matchMedia('(min-width: ' + window.innerWidth + 'px)').matches
})"#;

#[derive(serde::Deserialize, Debug)]
struct Geom {
    #[serde(rename = "innerW")]
    inner_w: i64,
    #[serde(rename = "innerH")]
    inner_h: i64,
    #[serde(rename = "outerW")]
    outer_w: i64,
    #[serde(rename = "outerH")]
    outer_h: i64,
    #[serde(rename = "screenW")]
    screen_w: i64,
    #[serde(rename = "screenH")]
    screen_h: i64,
    #[serde(rename = "clientW")]
    client_w: i64,
    #[serde(rename = "mmAtInner")]
    mm_at_inner: bool,
}

#[tokio::test]
async fn stealthed_geometry_is_physically_coherent() {
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
        .evaluate(GEOM)
        .await
        .expect("evaluate geometry")
        .into_value::<String>()
        .expect("geometry json");
    let _ = page.close().await;

    let g: Geom = serde_json::from_str(&raw).unwrap_or_else(|e| panic!("parse {raw}: {e}"));

    // Physical containment: the window cannot exceed the screen it lives on.
    assert!(
        g.outer_w <= g.screen_w,
        "outerWidth ({}) > screen.width ({}), window wider than its screen: {raw}",
        g.outer_w,
        g.screen_w
    );
    assert!(
        g.outer_h <= g.screen_h,
        "outerHeight ({}) > screen.height ({}), window taller than its screen: {raw}",
        g.outer_h,
        g.screen_h
    );
    assert!(
        g.inner_w <= g.screen_w,
        "innerWidth ({}) > screen.width ({}), viewport wider than screen: {raw}",
        g.inner_w,
        g.screen_w
    );
    assert!(
        g.inner_h <= g.screen_h,
        "innerHeight ({}) > screen.height ({}), viewport taller than screen: {raw}",
        g.inner_h,
        g.screen_h
    );

    // Window-chrome ordering: inner viewport never exceeds the outer window.
    assert!(
        g.inner_w <= g.outer_w && g.inner_h <= g.outer_h,
        "inner ({},{}) exceeds outer ({},{}): {raw}",
        g.inner_w,
        g.inner_h,
        g.outer_w,
        g.outer_h
    );

    // Layout coherence: innerWidth (spoofable getter) agrees with clientWidth (the
    // real layout viewport) within one scrollbar width. The old lie had a 554px gap.
    assert!(
        (g.inner_w - g.client_w).abs() <= 25,
        "innerWidth ({}) disagrees with documentElement.clientWidth ({}) by >25px, getter lies over real layout: {raw}",
        g.inner_w,
        g.client_w
    );

    // matchMedia coherence: the CSS engine must agree the viewport is at least
    // innerWidth wide. A getter inflated above the real viewport makes this false.
    assert!(
        g.mm_at_inner,
        "matchMedia('(min-width: innerWidth)') is false, innerWidth is inflated above the real CSS viewport: {raw}"
    );
}
