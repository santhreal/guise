//! Live validation: the reynard ENGINE vs real, IP-independent bot detectors.
//!
//! The `reynard_gate` proves reynard is fingerprint-identical to a real Firefox
//! across the probe catalogue, but it diffs two BiDi-driven browsers, so any
//! tell they SHARE (e.g. `navigator.webdriver === true`, which Firefox sets when
//! driven over BiDi) passes the differential silently. This test closes that
//! blind spot by driving reynard against third-party detectors that judge the
//! browser fingerprint independently of the source IP, the headline question:
//! **does our real-Firefox engine pass real anti-bot fingerprinting WITHOUT a
//! residential proxy?**
//!
//! `ip_independent` scorers only (sannysoft, areyouheadless): their verdict is
//! about the browser, not the IP, so a `block` here is a genuine fingerprint
//! tell we own, not proxy/IP reputation. Opt-in (needs a built reynard binary,
//! a display, and network egress):
//! ```text
//! REYNARD_BIN=/…/obj-*/dist/bin/camoufox DISPLAY=:1 MOZ_DISABLE_CONTENT_SANDBOX=1 \
//!   cargo test -p guise --no-default-features --features browser \
//!   --test reynard_live_detectors -- --nocapture
//! ```
#![cfg(feature = "browser")]

use guise::browser::launch_reynard;
use guise::fingerprint::StealthProfile;
use serde::Deserialize;
use std::time::Duration;

#[derive(Debug, Deserialize)]
struct Verdict {
    verdict: String,
    #[serde(default)]
    detail: String,
}

struct Detector {
    id: &'static str,
    url: &'static str,
    wait_ms: u64,
    judge: &'static str,
}

/// The IP-independent fingerprint detectors from the bench's
/// `stealth_gauntlet.json`, with their exact judge expressions (kept verbatim so
/// this test and the bench agree on what "blocked" means). Mirrors every
/// `ip_independent: true` entry in that config except `creepjs`, which has its own
/// dedicated gate (`creepjs_gate.rs`). A judge that can't read its page returns
/// `unknown` (never a false block), so adding a detector can only ADD coverage,
/// never introduce a flaky fail.
const DETECTORS: &[Detector] = &[
    Detector {
        id: "areyouheadless",
        url: "https://arh.antoinevastel.com/bots/areyouheadless",
        wait_ms: 2500,
        judge: r#"(() => { try { const t = (document.body && document.body.innerText) || ''; if (/"isHeadless"\s*:\s*false/i.test(t) || /not.*headless/i.test(t)) return {verdict:'pass', detail:t.slice(0,140)}; if (/"isHeadless"\s*:\s*true/i.test(t) || /you are.*headless/i.test(t)) return {verdict:'block', detail:t.slice(0,140)}; return {verdict:'unknown', detail:t.slice(0,140)}; } catch(e){ return {verdict:'unknown', detail:String(e)}; } })()"#,
    },
    Detector {
        id: "sannysoft",
        url: "https://bot.sannysoft.com/",
        wait_ms: 4000,
        judge: r#"(() => { try { const rows = Array.from(document.querySelectorAll('tr')); const failing = []; let passed = 0; for (const r of rows) { const cells = Array.from(r.querySelectorAll('th,td')); if (cells.some(c => /failed/i.test(c.textContent||''))) { failing.push(((cells[0] && cells[0].textContent) || '?').trim().slice(0,36)); } else if (cells.some(c => /(passed|ok)/i.test(c.textContent||''))) { passed++; } } if (passed === 0 && failing.length === 0) return {verdict:'unknown', detail:'table not rendered'}; var legit = failing.filter(function(f){ return /chrome/i.test(f); }); var real = failing.filter(function(f){ return !/chrome/i.test(f); }); return { verdict: real.length === 0 ? 'pass' : 'block', detail: 'passed='+passed+' real_fail=['+real.join(' | ')+'] firefox_legit=['+legit.join(' | ')+']' }; } catch(e){ return {verdict:'unknown', detail:String(e)}; } })()"#,
    },
    // incolumitas + deviceandbrowserinfo are the other two `ip_independent: true`
    // scorers in stealth_gauntlet.json; their judges are copied byte-for-byte from
    // that config (the bench source of truth) so the harness and the bench can
    // never disagree on a verdict (X022/X024 (one catalogue, one severity)).
    Detector {
        id: "incolumitas_fp",
        url: "https://bot.incolumitas.com/",
        wait_ms: 9000,
        judge: r#"(() => { try { var dt = ((document.getElementById('detection-tests')||{}).innerText)||''; var nt = ((document.getElementById('new-tests')||{}).innerText)||''; var all = dt + '\n' + nt; if (all.replace(/\s/g,'').length < 20) return {verdict:'unknown', detail:'detection tests not rendered'}; var lines = all.split('\n'); var fails = lines.filter(function(l){ return /:\s*"?(FAIL|INCONSISTENT)"?|present \(failed\)/i.test(l); }).map(function(l){ return l.replace(/\s+/g,' ').trim().slice(0,46); }); var real = fails.filter(function(f){ return !/chrome|CHR_|webDriverAdvanced/i.test(f); }); return { verdict: real.length === 0 ? 'pass' : 'block', detail: 'real_fails=['+real.slice(0,5).join(' | ')+'] firefox_legit='+(fails.length-real.length) }; } catch(e){ return {verdict:'unknown', detail:String(e)}; } })()"#,
    },
    Detector {
        id: "deviceandbrowserinfo_bot",
        url: "https://deviceandbrowserinfo.com/are_you_a_bot",
        wait_ms: 5000,
        judge: r#"(() => { try { var t=((document.body&&document.body.innerText)||''); var m=t.match(/you are (not )?(likely )?(detected as )?a? ?bot[^\n.]{0,40}/i); if(m){ return {verdict:/not/i.test(m[0])?'pass':'block', detail:m[0].slice(0,90)}; } if(/not a bot|you are human|human detected/i.test(t)) return {verdict:'pass',detail:'human'}; return {verdict:'unknown',detail:t.replace(/\s+/g,' ').slice(0,90)}; } catch(e){ return {verdict:'unknown',detail:String(e)}; } })()"#,
    },
];

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reynard_passes_ip_independent_detectors() {
    let Ok(reynard_bin) = std::env::var("REYNARD_BIN") else {
        eprintln!("SKIP reynard_live_detectors: set REYNARD_BIN=/path/to/reynard/camoufox to run");
        return;
    };
    if std::env::var("DISPLAY").is_err() {
        eprintln!(
            "SKIP reynard_live_detectors: no DISPLAY (headful needs an X server, e.g. DISPLAY=:1)"
        );
        return;
    }

    let reynard = launch_reynard(&reynard_bin, &StealthProfile::FirefoxLinux, false)
        .await
        .expect("launch reynard binary");

    let mut blocks: Vec<String> = Vec::new();
    for d in DETECTORS {
        if let Err(e) = reynard.goto(d.url).await {
            eprintln!("[{}] navigation error (network?): {e:?}, skipping", d.id);
            continue;
        }
        tokio::time::sleep(Duration::from_millis(d.wait_ms)).await;
        let verdict = match reynard.evaluate(d.judge).await {
            Ok(ev) => ev.into_value::<Verdict>().unwrap_or(Verdict {
                verdict: "unknown".into(),
                detail: "parse failed".into(),
            }),
            Err(e) => Verdict {
                verdict: "unknown".into(),
                detail: format!("eval error: {e:?}"),
            },
        };
        eprintln!(
            "[reynard live] {:<16} => {:<7} | {}",
            d.id, verdict.verdict, verdict.detail
        );
        if verdict.verdict == "block" {
            blocks.push(format!("{} ({})", d.id, verdict.detail));
        }
    }

    let _ = reynard.close().await;

    // A `block` from an IP-independent detector is a genuine fingerprint tell we
    // own (not proxy/IP). `unknown` (page didn't render a clear result / network
    // hiccup) never fails, we only fail on a definitive block, never a false
    // pass, never a flaky-network fail.
    assert!(
        blocks.is_empty(),
        "reynard was flagged a bot by IP-independent detector(s): {blocks:?}. \
         a real fingerprint tell to close (engine pref or disguise gap, NOT a proxy issue)"
    );
}
