//! Live evaluation regression for `profile_js` (G074).
//!
//! The syntactic bracket-balance guard (G073) catches comment/string accidents
//! that unbalance braces, but a real browser can still throw on valid-looking
//! syntax (e.g. a trailing comma, a reserved word, a `with` statement). This
//! test evaluates the emitted `profile_js` for every shipped profile on a live
//! page and asserts no evaluation error.
//!
//! Opt-in (spawns a real Firefox): `STEALTH_LIVE_BROWSER=1`.
#![cfg(feature = "browser")]

use guise::fingerprint::{profile_js, profile_to_overrides, ALL_PROFILES};
use runtime_foxdriver::{launch_firefox, FoxBrowserConfig};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn profile_js_evaluates_without_error_for_every_profile() {
    if std::env::var("STEALTH_LIVE_BROWSER").is_err() {
        eprintln!("SKIP profile_js_live_eval: set STEALTH_LIVE_BROWSER=1 to run (spawns Firefox)");
        return;
    }

    let page = launch_firefox(FoxBrowserConfig {
        headless: true,
        ..Default::default()
    })
    .await
    .expect("launch for profile_js live eval");

    for profile in ALL_PROFILES {
        let overrides = profile_to_overrides(profile);
        let js = profile_js(&overrides);
        page.evaluate(js)
            .await
            .unwrap_or_else(|e| panic!("profile_js for {profile:?} threw on evaluation: {e:?}"));
    }

    let _ = page.close().await;
}
