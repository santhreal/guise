//! Live stealth-probe gate (the plan's non-negotiable "Done when" test).
//!
//! Launches a REAL headless Firefox, applies the stealth disguise, and measures
//! it with the runtime probe suite against an un-stealthed control. Everything
//! else in this crate is verified offline; this is the one test that proves the
//! disguise works against a real browser end-to-end.
//!
//! The probe runs against a local `http://127.0.0.1` page, NOT a `data:` URL: a
//! `data:` URL is an opaque, *insecure* origin where secure-context-only APIs
//! (crypto.subtle, StorageManager, serviceWorker, …) are legitimately absent and
//! would produce false "missing surface" criticals. `http://127.0.0.1` is a
//! secure context, matching how a real session browses.
//!
//! Opt-in: it spawns a browser process and needs a Firefox binary, so it SKIPS
//! cleanly unless `STEALTH_LIVE_BROWSER=1`. Run it on a host with Firefox:
//!
//! ```text
//! STEALTH_LIVE_BROWSER=1 cargo test --features browser --test probe_live -- --nocapture
//! ```
//!
//! `STEALTH_FIREFOX=/path/to/firefox` overrides binary discovery.
#![cfg(feature = "browser")]

use guise::fingerprint::StealthProfile;
use guise::probe::{ProbeOutcome, UserAgentBrowser};
use runtime_foxdriver::{launch_firefox, FoxBrowserConfig, Page};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// guise's live browser is Firefox (driven by foxdriver over BiDi), so the
/// probe suite must measure the disguise against Firefox truth (not Chrome).
const TARGET_FAMILY: UserAgentBrowser = UserAgentBrowser::Firefox;

/// Serve a minimal HTML page on `http://127.0.0.1:<port>/`: a secure
/// context (unlike a `data:` URL), so secure-context APIs are present and the
/// probe measures genuine stealth gaps, not origin artifacts. Returns the URL.
async fn serve_secure_origin() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind origin");
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut sock, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buf = [0u8; 2048];
                let _ = sock.read(&mut buf).await;
                let body =
                    b"<!doctype html><html><head><title>p</title></head><body>probe</body></html>";
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

fn critical_names(report: &guise::probe::DriftReport) -> Vec<&str> {
    report
        .per_probe
        .iter()
        .filter(|p| matches!(p.outcome, ProbeOutcome::Critical(_)))
        .map(|p| p.name.as_str())
        .collect()
}

async fn launch_bare_page(url: &str) -> Page {
    let mut config = FoxBrowserConfig {
        headless: true,
        ..Default::default()
    };
    if let Ok(path) = std::env::var("STEALTH_FIREFOX") {
        config.executable_path = Some(path);
    }
    let page = launch_firefox(config).await.expect("launch firefox (bare)");
    page.goto(url).await.expect("navigate bare page");
    page
}

async fn launch_stealthed_page(url: &str) -> Page {
    let mut config = FoxBrowserConfig {
        headless: true,
        ..Default::default()
    };
    if let Ok(path) = std::env::var("STEALTH_FIREFOX") {
        config.executable_path = Some(path);
    }
    // The FULL disguise a real captchaforge session uses: profile prefs
    // (user.js UA/platform), the generic + profile stealth scripts, AND the
    // fingerprint evasion pass (canvas/audio/WebGL noise). Every override is
    // injected as a preload BEFORE navigation, so the probed page is what a
    // live session actually presents (not a stealth-only subset).
    let page = guise::browser::launch_profiled_firefox(config, &StealthProfile::FirefoxLinux)
        .await
        .expect("launch profiled firefox (full disguise)");
    page.goto(url).await.expect("navigate stealthed page");
    page
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stealthed_page_beats_bare_and_tracks_completion_worklist() {
    if std::env::var("STEALTH_LIVE_BROWSER").is_err() {
        eprintln!("SKIP probe_live: set STEALTH_LIVE_BROWSER=1 (spawns a real Firefox) to run");
        return;
    }

    let url = serve_secure_origin().await;

    // ── Negative twin: an un-stealthed page. Probed against the SAME
    //    (Firefox) family expectations, so the comparison isolates the
    //    disguise's effect, not a browser-family mismatch. ──
    let bare = launch_bare_page(&url).await;
    let bare_report = guise::probe::run_for(&bare, TARGET_FAMILY)
        .await
        .expect("probe bare page");
    eprintln!(
        "── BARE (un-stealthed) ──\n{}",
        guise::probe::render_report(&bare_report)
    );
    let _ = bare.close().await;

    // ── Stealthed page. ──
    let page = launch_stealthed_page(&url).await;
    let report = guise::probe::run_for(&page, TARGET_FAMILY)
        .await
        .expect("probe stealthed page");
    eprintln!("── STEALTHED ──\n{}", guise::probe::render_report(&report));
    let _ = page.close().await;

    let remaining = critical_names(&report);
    eprintln!(
        "\n[stealth gate] bare={} critical, stealthed={} critical, {}/{} pass.\n\
         FULL-GREEN COMPLETION WORKLIST ({} surfaces. SLICE 2/3 / sear inventory):\n  - {}",
        bare_report.critical,
        report.critical,
        report.passed,
        report.probed,
        remaining.len(),
        remaining.join("\n  - ")
    );

    // ── Guarantees the disguise must hold TODAY (non-flaky regression gate): ──
    assert!(
        report.critical < bare_report.critical,
        "stealth must remove criticals a bare page leaks (bare={}, stealthed={})",
        bare_report.critical,
        report.critical
    );
    let leaks: Vec<&str> = remaining
        .iter()
        .copied()
        .filter(|n| n.contains("automation") || n.contains("webdriver === true"))
        .collect();
    assert!(
        leaks.is_empty(),
        "core automation tells must be hidden, still leaking: {leaks:?}"
    );
    assert_eq!(
        report.critical, 0,
        "disguise must leak no criticals; still critical: {remaining:?}"
    );
    assert!(
        report.is_green(),
        "stealth probe gate not green: {}",
        report.summary()
    );
}
