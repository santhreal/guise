//! Live validation: can the reynard engine actually get THROUGH real Cloudflare
//! protection (not just pass passive fingerprint detectors)?
//!
//! Passive scorers (sannysoft/areyouheadless) only prove "not flagged at rest".
//! The real bar is surviving a live challenge while interacting with a protected
//! site. This drives reynard at real CF-fronted endpoints and reports, per site,
//! whether it reached real content or got stuck on the challenge / blocked.
//!
//! IP-CONFOUNDED: Cloudflare weighs IP reputation alongside the fingerprint, so a
//! `block` here may be the datacenter IP, not the engine, this test REPORTS the
//! verdict (it does not hard-fail on a block, which would just be measuring the
//! sandbox's IP). A `pass` is the meaningful signal: the engine cleared a real CF
//! challenge from this IP. Opt-in (needs reynard, a display, network):
//! ```text
//! REYNARD_BIN=/…/dist/bin/camoufox DISPLAY=:1 MOZ_DISABLE_CONTENT_SANDBOX=1 \
//!   cargo test -p guise --no-default-features --features browser \
//!   --test reynard_live_cloudflare -- --nocapture
//! ```
#![cfg(feature = "browser")]

use guise::browser::launch_reynard;
use guise::fingerprint::StealthProfile;
use std::time::Duration;

struct Target {
    id: &'static str,
    url: &'static str,
}

const TARGETS: &[Target] = &[
    // The canonical CF-IUAM test page: shows "you passed" only once the JS
    // challenge clears; "Just a moment" while challenged.
    Target {
        id: "nowsecure.nl",
        url: "https://nowsecure.nl/",
    },
    // CF's own marketing site (managed challenge on some edges).
    Target {
        id: "cloudflare.com",
        url: "https://www.cloudflare.com/",
    },
    // The real acceptance target (curl gets 403 here (CF blocks non-browsers)).
    Target {
        id: "dash-login",
        url: "https://dash.cloudflare.com/login",
    },
];

/// Reads the post-challenge state of the current page.
const STATE_JS: &str = r#"(() => {
    const title = (document.title || '');
    const body = document.body ? (document.body.innerText || '') : '';
    const html = document.documentElement ? document.documentElement.outerHTML : '';
    let chlOpt = false; try { chlOpt = typeof window._cf_chl_opt !== 'undefined'; } catch(e){}
    const challenge = /just a moment|checking your browser|cf-challenge|challenge-running/i.test(title + ' ' + body)
        || chlOpt
        || !!document.querySelector('#challenge-running, #cf-challenge-running, #challenge-stage');
    const blocked = /you have been blocked|error 1020|sorry, you have been blocked|access denied/i.test(title + ' ' + body);
    // cf_clearance is httpOnly → invisible to document.cookie; presence here is
    // best-effort only, never a "not cleared" signal.
    const hasClearance = (document.cookie || '').split(';').some(c => c.trim().indexOf('cf_clearance=') === 0);
    // Inline Turnstile on the page (the form's "human" check) + whether it has
    // already produced a token (auto-passed for a real browser).
    const turnstile = !!document.querySelector('iframe[src*="challenges.cloudflare.com"], .cf-turnstile, [data-sitekey]');
    let tsToken = '';
    try { const el = document.querySelector('input[name="cf-turnstile-response"], input[name="cf_challenge_response"]'); if (el) tsToken = el.value || ''; } catch(e){}
    const hasForm = !!document.querySelector('input[type="password"], input[type="email"], form[action*="login"]');
    return { title: title.slice(0,80), url: location.href, bodyLen: body.length,
             snippet: body.replace(/\s+/g,' ').slice(0,160),
             challenge, blocked, hasClearance, hasForm,
             turnstile, tsTokenLen: tsToken.length };
})()"#;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reynard_through_live_cloudflare() {
    let Ok(reynard_bin) = std::env::var("REYNARD_BIN") else {
        eprintln!("SKIP reynard_live_cloudflare: set REYNARD_BIN to run");
        return;
    };
    if std::env::var("DISPLAY").is_err() {
        eprintln!("SKIP reynard_live_cloudflare: no DISPLAY");
        return;
    }

    let reynard = launch_reynard(&reynard_bin, &StealthProfile::FirefoxLinux, false)
        .await
        .expect("launch reynard");

    for t in TARGETS {
        // CF's JS challenge auto-runs and redirects within ~5s; let it settle.
        let nav = reynard.goto(t.url).await;
        if let Err(e) = nav {
            eprintln!("[cf live] {:<16} NAV-ERR {e:?}", t.id);
            continue;
        }
        tokio::time::sleep(Duration::from_millis(12_000)).await;
        let st = reynard
            .evaluate(STATE_JS)
            .await
            .ok()
            .and_then(|e| e.into_value::<serde_json::Value>().ok())
            .unwrap_or(serde_json::Value::Null);

        let challenge = st
            .get("challenge")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let blocked = st.get("blocked").and_then(|v| v.as_bool()).unwrap_or(false);
        let body_len = st.get("bodyLen").and_then(|v| v.as_u64()).unwrap_or(0);
        let has_title = st
            .get("title")
            .and_then(|v| v.as_str())
            .map(|s| !s.is_empty())
            .unwrap_or(false);
        let turnstile = st
            .get("turnstile")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let ts_token = st.get("tsTokenLen").and_then(|v| v.as_u64()).unwrap_or(0);
        let verdict = if blocked {
            "BLOCKED"
        } else if challenge {
            "CHALLENGE (stuck)"
        } else if body_len > 20 || has_title {
            "PASS (reached page)"
        } else {
            "UNKNOWN"
        };
        let ts = if turnstile {
            format!(" | turnstile=present token_len={ts_token}")
        } else {
            String::new()
        };
        eprintln!(
            "[cf live] {:<16} => {:<20}{} | {} | {}",
            t.id,
            verdict,
            ts,
            st.get("title").and_then(|v| v.as_str()).unwrap_or(""),
            st.get("snippet").and_then(|v| v.as_str()).unwrap_or("")
        );
    }

    let _ = reynard.close().await;
    // Diagnostic: reports verdicts above. Does not hard-fail on a CF block (that
    // would measure the sandbox IP, not the engine). The eprintln output is the
    // result to read.
}

/// The decisive interaction test: does reynard's real-Firefox engine SILENTLY
/// clear a real **managed Turnstile** (the kind embedded on the cloudflare.com
/// login form), issuing a `cf-turnstile-response` token without a click? This is
/// CF's own Turnstile demo (a real managed widget, no auth/credentials), so it
/// is the clean surface to characterise the actual remaining gate. token_len>20
/// = the engine auto-passed (can submit CF forms); token_len=0 with a widget
/// present = the interactive solver (captchaforge TurnstileInteractiveSolver) is
/// needed. Reports either way, managed-Turnstile auto-pass is IP+behavior
/// confounded, so a non-pass here is information, not a hard failure.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reynard_managed_turnstile_demo() {
    let Ok(reynard_bin) = std::env::var("REYNARD_BIN") else {
        eprintln!("SKIP reynard_managed_turnstile_demo: set REYNARD_BIN to run");
        return;
    };
    if std::env::var("DISPLAY").is_err() {
        eprintln!("SKIP reynard_managed_turnstile_demo: no DISPLAY");
        return;
    }
    let reynard = launch_reynard(&reynard_bin, &StealthProfile::FirefoxLinux, false)
        .await
        .expect("launch reynard");
    if let Err(e) = reynard.goto("https://demo.turnstile.workers.dev/").await {
        eprintln!("[turnstile] NAV-ERR {e:?}");
        let _ = reynard.close().await;
        return;
    }
    // Managed Turnstile auto-evaluates over a few seconds; give it room.
    tokio::time::sleep(Duration::from_millis(12_000)).await;
    let probe = r#"(() => {
        let token='';
        try { const el=document.querySelector('input[name="cf-turnstile-response"]'); if(el) token=el.value||''; } catch(e){}
        const widget=!!document.querySelector('.cf-turnstile, iframe[src*="challenges.cloudflare.com"]');
        const body=document.body?(document.body.innerText||''):'';
        return { tokenLen: token.length, widget, snippet: body.replace(/\s+/g,' ').slice(0,140) };
    })()"#;
    let st = reynard
        .evaluate(probe)
        .await
        .ok()
        .and_then(|e| e.into_value::<serde_json::Value>().ok())
        .unwrap_or(serde_json::Value::Null);
    let token_len = st.get("tokenLen").and_then(|v| v.as_u64()).unwrap_or(0);
    let widget = st.get("widget").and_then(|v| v.as_bool()).unwrap_or(false);
    let verdict = if token_len > 20 {
        "AUTO-PASSED (token issued, no click)"
    } else if widget {
        "WIDGET present, NO token (needs interactive solve)"
    } else {
        "no widget / unknown"
    };
    eprintln!(
        "[turnstile] managed demo => {verdict} | token_len={token_len} widget={widget} | {}",
        st.get("snippet").and_then(|v| v.as_str()).unwrap_or("")
    );
    let _ = reynard.close().await;
}
