//! Live discovery + contract probe for the Shift-modifier tell.
//!
//! CONFIRMED (live Firefox): `HumanTyper::type_text` sends uppercase letters and
//! shifted symbols as the bare character (`"H"`, `"!"`) with only a timing
//! `shift_delay`, never a Shift key action. rustenium passes a single-char value
//! straight through, and Gecko does NOT synthesize Shift, so the keydown carries
//! `shiftKey === false` with no preceding `ShiftLeft`, which is impossible for a
//! real typed uppercase/symbol and a keystroke-dynamics tell.
//!
//! This file (a) re-demonstrates the raw-char failure, (b) discovers which
//! explicit-Shift sequence Gecko renders human-coherently, and (c) asserts the
//! shipped `HumanTyper` now produces a real Shift around uppercase/shifted input.
//! Opt-in: `STEALTH_LIVE_BROWSER=1 [STEALTH_FIREFOX=/path]`.
#![cfg(feature = "browser")]

use runtime_foxdriver::{launch_firefox, FoxBrowserConfig, Page};

fn skip() -> bool {
    if std::env::var("STEALTH_LIVE_BROWSER").is_err() {
        eprintln!("skip shift_key_live: set STEALTH_LIVE_BROWSER=1 (spawns real Firefox)");
        return true;
    }
    false
}

async fn page() -> Page {
    let mut cfg = FoxBrowserConfig {
        headless: true,
        viewport_width: 1024,
        viewport_height: 768,
        ..Default::default()
    };
    if let Ok(p) = std::env::var("STEALTH_FIREFOX") {
        cfg.executable_path = Some(p);
    }
    let page = launch_firefox(cfg).await.expect("launch firefox");
    page.goto("about:blank").await.expect("nav about:blank");
    page
}

/// Install a focused <input> plus a keydown/keyup recorder; returns nothing.
const SETUP: &str = r#"(() => {
  document.body.innerHTML = '<input id="t" />';
  const inp = document.getElementById('t');
  inp.focus();
  window.__ev = [];
  const rec = (t) => (e) => window.__ev.push({
    t, key: e.key, code: e.code, shift: e.shiftKey, mod: e.getModifierState('Shift')
  });
  document.addEventListener('keydown', rec('down'), true);
  document.addEventListener('keyup', rec('up'), true);
  return true;
})()"#;

const READBACK: &str =
    r#"JSON.stringify({ ev: window.__ev, value: document.getElementById('t').value })"#;

#[derive(serde::Deserialize, Debug)]
struct Ev {
    t: String,
    key: String,
    code: String,
    shift: bool,
    #[serde(rename = "mod")]
    modifier: bool,
}
#[derive(serde::Deserialize, Debug)]
struct Readback {
    ev: Vec<Ev>,
    value: String,
}

async fn capture(page: &Page) -> Readback {
    let raw = page
        .evaluate(READBACK)
        .await
        .expect("readback")
        .into_value::<String>()
        .expect("readback json");
    serde_json::from_str(&raw).expect("parse readback")
}

async fn reset(page: &Page) {
    page.evaluate(SETUP).await.expect("setup");
}

/// Discovery: print what each candidate Shift sequence produces, so the fix is
/// chosen from observed Gecko behaviour, not a guess.
#[tokio::test]
async fn discover_shift_sequences() {
    if skip() {
        return;
    }
    let page = page().await;

    // (1) Raw shifted char (current shipped behaviour) (the bug).
    reset(&page).await;
    page.key_down("H").await.unwrap();
    page.key_up("H").await.unwrap();
    eprintln!("RAW 'H'        -> {:?}", capture(&page).await);

    // (2) Explicit Shift wrapping the SHIFTED char.
    reset(&page).await;
    page.key_down("Shift").await.unwrap();
    page.key_down("H").await.unwrap();
    page.key_up("H").await.unwrap();
    page.key_up("Shift").await.unwrap();
    eprintln!("SHIFT+'H'      -> {:?}", capture(&page).await);

    // (3) Explicit Shift wrapping the BASE key (letter).
    reset(&page).await;
    page.key_down("Shift").await.unwrap();
    page.key_down("h").await.unwrap();
    page.key_up("h").await.unwrap();
    page.key_up("Shift").await.unwrap();
    eprintln!("SHIFT+'h'      -> {:?}", capture(&page).await);

    // (4) Explicit Shift wrapping the SHIFTED symbol.
    reset(&page).await;
    page.key_down("Shift").await.unwrap();
    page.key_down("!").await.unwrap();
    page.key_up("!").await.unwrap();
    page.key_up("Shift").await.unwrap();
    eprintln!("SHIFT+'!'      -> {:?}", capture(&page).await);

    // (5) Explicit Shift wrapping the BASE digit for the symbol.
    reset(&page).await;
    page.key_down("Shift").await.unwrap();
    page.key_down("1").await.unwrap();
    page.key_up("1").await.unwrap();
    page.key_up("Shift").await.unwrap();
    eprintln!("SHIFT+'1'      -> {:?}", capture(&page).await);
}

/// Contract: the shipped HumanTyper must emit a real Shift around uppercase and
/// shifted-symbol characters, producing the correct text AND coherent events.
#[tokio::test]
async fn human_typer_emits_real_shift_for_uppercase_and_symbols() {
    if skip() {
        return;
    }
    use guise::human::HumanTyper;
    let page = page().await;
    reset(&page).await;

    let mut typer = HumanTyper::default();
    typer.type_text(&page, "Hi!").await.expect("type Hi!");

    let cap = capture(&page).await;
    eprintln!("HumanTyper 'Hi!' -> {cap:?}");

    // The text actually entered must be exactly "Hi!".
    assert_eq!(
        cap.value, "Hi!",
        "typed value must be 'Hi!', got {:?}",
        cap.value
    );

    let down = |k: &str| cap.ev.iter().find(|e| e.t == "down" && e.key == k);

    // 'H' and '!' must carry the Shift modifier and code of the real physical key.
    let h = down("H").expect("H keydown");
    assert!(
        h.shift && h.modifier,
        "uppercase 'H' must have shiftKey/getModifierState true: {h:?}"
    );
    assert_eq!(h.code, "KeyH", "H must map to physical KeyH: {h:?}");

    let bang = down("!").expect("! keydown");
    assert!(
        bang.shift && bang.modifier,
        "symbol '!' must have shiftKey true: {bang:?}"
    );
    assert_eq!(
        bang.code, "Digit1",
        "! must map to physical Digit1: {bang:?}"
    );

    // lowercase 'i' must NOT be shifted.
    let i = down("i").expect("i keydown");
    assert!(!i.shift, "lowercase 'i' must not be shifted: {i:?}");

    // A real Shift keydown (ShiftLeft) must precede the shifted characters.
    assert!(
        cap.ev
            .iter()
            .any(|e| e.t == "down" && e.code == "ShiftLeft"),
        "a ShiftLeft keydown must be present for the uppercase/symbol input: {:?}",
        cap.ev
    );
}

/// Contract: control characters in typed text (newline, tab) must dispatch as the
/// DOM key NAMES a real physical key reports ("Enter"/"Tab"), never the raw
/// control char ("\n"/"\t"). A bare control char is an impossible
/// `KeyboardEvent.key` and disagrees with the `code` (which already resolves to
/// "Enter"/"Tab"), a synthetic-input tell. The document-level recorder logs the
/// keydowns even though Tab moves focus off the input.
#[tokio::test]
async fn human_typer_emits_dom_key_names_for_control_chars() {
    if skip() {
        return;
    }
    use guise::human::{HumanTyper, TypingConfig};
    let page = page().await;
    reset(&page).await;

    // typo_rate 0 keeps the event set deterministic (no neighbour/backspace noise).
    let mut typer = HumanTyper::new(TypingConfig {
        typo_rate: 0.0,
        ..Default::default()
    });
    typer
        .type_text(&page, "a\tb\nc")
        .await
        .expect("type control text");

    let cap = capture(&page).await;
    eprintln!("HumanTyper 'a\\tb\\nc' -> {cap:?}");

    let down = |k: &str| cap.ev.iter().find(|e| e.t == "down" && e.key == k);

    // Enter must carry key AND code "Enter" (not the raw '\n').
    let enter =
        down("Enter").unwrap_or_else(|| panic!("Enter keydown missing; events: {:?}", cap.ev));
    assert_eq!(
        enter.code, "Enter",
        "newline must map to physical code Enter: {enter:?}"
    );

    // Tab must carry key AND code "Tab".
    let tab = down("Tab").unwrap_or_else(|| panic!("Tab keydown missing; events: {:?}", cap.ev));
    assert_eq!(
        tab.code, "Tab",
        "tab must map to physical code Tab: {tab:?}"
    );

    // No event may leak a raw control character as its KeyboardEvent.key, that is
    // the exact bug (sending key_down("\n")/key_down("\t")).
    assert!(
        !cap.ev
            .iter()
            .any(|e| e.key == "\n" || e.key == "\r" || e.key == "\t"),
        "a raw control char leaked as KeyboardEvent.key (the bug): {:?}",
        cap.ev
    );

    // The surrounding printable letters still arrive as themselves.
    for ch in ["a", "b", "c"] {
        assert!(
            down(ch).is_some(),
            "printable '{ch}' keydown missing: {:?}",
            cap.ev
        );
    }
}
