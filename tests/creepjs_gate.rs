//! Live validation: the reynard ENGINE against CreepJS, the canonical fingerprint
//! trust-score + "lie detector" benchmark.
//!
//! `reynard_live_detectors` proves reynard passes the binary pass/block detectors
//! (sannysoft, areyouheadless). CreepJS is stronger: it computes a *trust score*
//! and enumerates **lies**: surfaces whose value contradicts another surface or a
//! known-real-browser invariant (a spoof seam). A JS-patched browser leaks lies
//! (overridden getter `toString`, descriptor mismatch, UA-vs-feature disagreement);
//! a correctly engine-patched reynard should leak **zero**, because the spoof lives
//! in Gecko C++, not in JS a page can catch lying.
//!
//! IP-independent: CreepJS judges the browser, not the network, so a lie here is a
//! genuine reynard tell we own. The harness records the parsed score/grade/lie set
//! to `${STACK_BENCH_DIR:-/tmp/stack-bench}/creepjs.json` for the stack scorecard,
//! and prints a generous text sample so the parser stays pinned to CreepJS's real
//! rendered output (refined against live runs, never guessed).
//!
//! Opt-in (needs a built reynard binary, a display, and network egress):
//! ```text
//! REYNARD_BIN=/…/obj-*/dist/bin/camoufox DISPLAY=:1 MOZ_DISABLE_CONTENT_SANDBOX=1 \
//!   cargo test -p guise --no-default-features --features browser \
//!   --test creepjs_gate -- --nocapture
//! ```
#![cfg(feature = "browser")]

use guise::browser::launch_reynard;
use guise::fingerprint::StealthProfile;
use serde::Deserialize;
use std::time::Duration;

const CREEPJS_URL: &str = "https://abrahamjuliot.github.io/creepjs/";

/// Parsed CreepJS result. All fields optional. CreepJS renders asynchronously
/// (workers + offscreen canvas), so a probe may land before a surface resolves;
/// the harness polls and records what it has, never fabricating a value.
#[derive(Debug, Deserialize, Default)]
struct CreepResult {
    #[serde(default)]
    trust_score: Option<f64>,
    #[serde(default)]
    grade: Option<String>,
    #[serde(default)]
    trust_band: Option<String>,
    #[serde(default)]
    lies: Option<i64>,
    #[serde(default)]
    headless: Option<String>,
    #[serde(default)]
    ready: bool,
    /// Candidate score/trust/lie elements (class/id + text) so the parser stays
    /// pinned to CreepJS's real DOM rather than a guessed innerText regex.
    #[serde(default)]
    diag: Vec<String>,
    #[serde(default)]
    sample: String,
}

/// Judge JS kept verbatim and self-contained so the test and any future bench
/// agree on what is read. CreepJS labels its summary in visible text; we extract
/// the trust score %, the letter grade, and the lie count, and flag bot/headless
/// hints. `ready` gates on the score having rendered so the poller knows to wait.
const JUDGE: &str = r#"(() => {
  try {
    const pct = /^\s*([0-9]{1,3}(?:\.[0-9]+)?)\s*%\s*$/;
    // CreepJS renders the visitor trust rating as an element carrying a `grade-X`
    // class (X ∈ A..F[+/-]) whose text is the qualitative band ("high"/"moderate"/…).
    // That class is the reliable score signal (pinned from the live DOM, not guessed).
    let grade = null, trust_band = null;
    const gnode = document.querySelector('[class*="grade-"]');
    if (gnode) {
      const gm = (gnode.className + '').match(/grade-([A-Fa-f][+\-]?)/);
      if (gm) grade = gm[1].toUpperCase();
      trust_band = (gnode.textContent || '').trim().slice(0, 24) || null;
    }
    // Trust score percentage: CreepJS shows it near the grade. Collect every bare-%
    // leaf and keep the one in the grade element's container (else the first plausible).
    let trust_score = null;
    const pctNodes = [];
    for (const n of Array.from(document.querySelectorAll('*'))) {
      if (n.children.length) continue;
      const m = ((n.textContent || '').trim()).match(pct);
      if (m) pctNodes.push({ v: parseFloat(m[1]), n });
    }
    if (gnode) {
      const inGrade = pctNodes.find(p => gnode.contains(p.n) || (gnode.parentElement && gnode.parentElement.contains(p.n)));
      if (inGrade) trust_score = inGrade.v;
    }
    if (trust_score === null && pctNodes.length) trust_score = pctNodes[0].v;
    // Lies: CreepJS labels the lie panel; capture its count from a `[class*="lie"]`
    // element or the "lies (N)" text. 0/absent → no lies (the target).
    let lies = null;
    const lnode = document.querySelector('[class*="lies"],[id*="lies"]');
    if (lnode) {
      const lm = (lnode.textContent || '').match(/(\d+)/);
      if (lm) lies = parseInt(lm[1], 10);
    }
    const body = (document.body && document.body.innerText) || '';
    if (lies === null) {
      const lm = body.match(/lies\s*\(\s*([0-9]+)\s*\)/i) || body.match(/\b([0-9]+)\s+lies\b/i);
      if (lm) lies = parseInt(lm[1], 10);
    }
    let headless = null;
    const hm = body.match(/headless[^0-9]{0,40}([0-9]{1,3})\s*%/i);
    if (hm) headless = hm[1] + '%';
    // Diagnostic snapshot of score/lie-bearing nodes, pinned to CreepJS's class names so
    // a parser regression (or a CreepJS DOM change) is visible in the run log, not guessed.
    const diag = [];
    for (const n of Array.from(document.querySelectorAll('[class*="grade-"],[class*="lies"],[class*="lie"],[class*="trust-"],[class*="score"]'))) {
      const t = (n.textContent || '').trim().replace(/\s+/g, ' ');
      diag.push('SEL ' + ((n.className || n.id || '?') + '').slice(0, 44) + ' :: ' + t.slice(0, 60));
    }
    // Text discovery for a future CreepJS build that re-exposes a "lies (N)" panel or a
    // bare-% score (current builds render neither, verified live 2026-06-12, the grade
    // class is the only surfaced verdict). Scoped to lie/% text so it stays signal, not the
    // `/trust/i` noise that matches TrustedTypes API names in the feature table.
    for (const n of Array.from(document.querySelectorAll('*'))) {
      if (n.children.length > 2) continue;
      const t = (n.textContent || '').trim().replace(/\s+/g, ' ');
      if (t.length > 70 || !t) continue;
      if (/\blie(s)?\b/i.test(t) || /\b\d{1,3}(\.\d+)?\s*%/.test(t)) {
        diag.push('TXT ' + ((n.className || n.id || n.tagName || '?') + '').slice(0, 30) + ' :: ' + t.slice(0, 60));
      }
    }
    const ready = grade !== null || trust_score !== null;
    return { trust_score, grade, trust_band, lies, headless, ready, diag: diag.slice(0, 60),
             sample: body.replace(/\s+/g, ' ').slice(0, 200) };
  } catch (e) {
    return { ready: false, diag: [], sample: 'judge error: ' + String(e) };
  }
})()"#;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reynard_creepjs_trust_and_lies() {
    let Ok(reynard_bin) = std::env::var("REYNARD_BIN") else {
        eprintln!("SKIP creepjs_gate: set REYNARD_BIN=/path/to/reynard/camoufox to run");
        return;
    };
    if std::env::var("DISPLAY").is_err() {
        eprintln!("SKIP creepjs_gate: no DISPLAY (headful needs an X server, e.g. DISPLAY=:1)");
        return;
    }

    let reynard = launch_reynard(&reynard_bin, &StealthProfile::FirefoxLinux, false)
        .await
        .expect("launch reynard binary");

    if let Err(e) = reynard.goto(CREEPJS_URL).await {
        eprintln!("[creepjs] navigation error (network?): {e:?}, skipping (never a false fail)");
        let _ = reynard.close().await;
        return;
    }

    // CreepJS resolves asynchronously (workers + WebRTC + offscreen canvas); poll up to
    // ~75s for the trust score to render rather than guessing one fixed sleep (Law 7).
    let mut result = CreepResult::default();
    for attempt in 0..30 {
        tokio::time::sleep(Duration::from_millis(2500)).await;
        match reynard.evaluate(JUDGE).await {
            Ok(ev) => {
                // Surface a deserialize miss loudly (Law 10), never silently default
                // but keep polling: CreepJS renders incrementally, so an early poll can
                // legitimately land mid-render. A persistent miss shows up every poll.
                result = match ev.into_value::<CreepResult>() {
                    Ok(v) => v,
                    Err(e) => {
                        eprintln!("[creepjs] poll {attempt}: judge result did not deserialize ({e}), retrying");
                        continue;
                    }
                };
                // The grade (CreepJS's headline trust band, e.g. `grade-A`/"high") is the
                // authoritative signal and resolves LATE (workers + offscreen-canvas settle
                // ~40s in). Pinned against live runs (2026-06-12): current CreepJS does NOT
                // render a scrapeable "lies (N)" panel or a bare-`%` score, the grade class
                // is the only surfaced verdict, and CreepJS computes it DOWNSTREAM of the lie
                // set, so gating on the grade band transitively gates on lies. Break once the
                // grade resolves; `lies`/`trust_score` stay best-effort (recorded if a future
                // CreepJS build re-exposes them, never waited on).
                if result.ready && result.grade.is_some() {
                    break;
                }
                eprintln!(
                    "[creepjs] poll {attempt}: ready={} grade={:?} score={:?} lies={:?} diag={}",
                    result.ready,
                    result.grade,
                    result.trust_score,
                    result.lies,
                    result.diag.len()
                );
            }
            Err(e) => eprintln!("[creepjs] eval error on poll {attempt}: {e:?}"),
        }
    }

    eprintln!(
        "\n[creepjs] grade={:?} band={:?} trust_score={:?} lies={:?} headless={:?}",
        result.grade, result.trust_band, result.trust_score, result.lies, result.headless
    );
    eprintln!(
        "[creepjs] score/lie DOM candidates ({}):",
        result.diag.len()
    );
    for d in &result.diag {
        eprintln!("    {d}");
    }
    eprintln!("[creepjs] sample: {}", result.sample);

    // Persist for the stack scorecard (X025/R020). Best-effort, surfaced loudly on error.
    let dir = std::env::var("STACK_BENCH_DIR").unwrap_or_else(|_| "/tmp/stack-bench".into());
    if let Err(e) = std::fs::create_dir_all(&dir) {
        eprintln!("[creepjs] WARN could not create {dir}: {e}");
    } else {
        let path = format!("{dir}/creepjs.json");
        let json = serde_json::json!({
            "benchmark": "creepjs",
            "url": CREEPJS_URL,
            "grade": result.grade,
            "trust_band": result.trust_band,
            "trust_score": result.trust_score,
            "lies": result.lies,
            "headless": result.headless,
            "ready": result.ready,
        });
        match std::fs::write(&path, serde_json::to_vec_pretty(&json).unwrap()) {
            Ok(()) => eprintln!("[creepjs] wrote {path}"),
            Err(e) => eprintln!("[creepjs] WARN could not write {path}: {e}"),
        }
    }

    let _ = reynard.close().await;

    // Never a false fail: if CreepJS did not render a grade (network/slow workers),
    // skip loudly rather than fail.
    if !result.ready {
        eprintln!(
            "SKIP creepjs_gate: CreepJS did not render a grade in ~75s (network/slow workers?), not a fingerprint fail"
        );
        return;
    }
    // The grade is CreepJS's whole verdict (computed downstream of the lie set), so the
    // gate asserts on the TRUSTED band, not merely "not F". reynard earns `A`/"high"
    // live (2026-06-12, two runs, stable). The trusted bands are A and B; a C or worse is
    // CreepJS flagging accumulated lies/tells (a real regression this gate must catch).
    // A coarse "!= F" check would silently pass an A→D slide (several new tells); asserting
    // the leading letter ∈ {A,B} catches that while tolerating benign A↔B worker/canvas
    // wobble. The exact letter + band are recorded to creepjs.json for the scorecard.
    if let Some(g) = result.grade.as_deref() {
        let letter = g.chars().next().unwrap_or('?').to_ascii_uppercase();
        assert!(
            letter == 'A' || letter == 'B',
            "CreepJS graded reynard {g:?} (trust band {:?}), below the trusted A/B band, \
             i.e. accumulated fingerprint lies/tells to close (an F is its outright bot verdict)",
            result.trust_band
        );
    }
}
