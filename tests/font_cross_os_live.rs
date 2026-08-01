//! Live PoC: does the stock-FF stealth path leak the HOST OS via font enumeration
//! on a cross-OS persona?
//!
//! Font-presence detection (measureText/offsetWidth width-compare vs a fallback) is
//! the dominant font fingerprint. guise's measureText defense scales widths UNIFORMLY
//! and so, by design, preserves font-PRESENCE detection (it only perturbs the
//! cross-session width vector). The Tier-B font library ships a Linux-only set mapped
//! to reynard's engine whitelist; the stock-FF path has no per-OS font masking. So a
//! FirefoxWindows persona on THIS Linux host should still report Linux fonts present
//! (DejaVu / Liberation) and Windows fonts absent (Segoe UI / Calibri), i.e. the
//! font profile betrays the real OS, contradicting the Windows UA.
//!
//! Methodology: compare each persona against the BARE engine on the same host. A
//! signal present on BARE is the host truth; a cross-OS persona that still shows the
//! host's font profile (instead of its claimed OS's) is leaking.
//!
//! Opt-in: `STEALTH_LIVE_BROWSER=1 [STEALTH_FIREFOX=/path]`.
#![cfg(feature = "browser")]

use guise::fingerprint::StealthProfile;
use runtime_foxdriver::browser::launch_firefox_self_managed;
use runtime_foxdriver::FoxBrowserConfig;

fn skip() -> bool {
    if std::env::var("STEALTH_LIVE_BROWSER").is_err() {
        eprintln!("skip font_cross_os_live: set STEALTH_LIVE_BROWSER=1");
        return true;
    }
    false
}

// Probe a fixed set of OS-signature fonts; return a CSV of those detected present.
// Detection: width of a test string with the candidate font (over 3 generic bases)
// differs from the base alone => the candidate is actually installed.
const PROBE: &str = r#"(function(){
  function installed(font){
    var bases=['monospace','sans-serif','serif'];
    var t='mmmmmmmmmmlli WWWiii @#%';
    var c=document.createElement('canvas').getContext('2d');
    for(var i=0;i<bases.length;i++){
      c.font='72px '+bases[i];
      var base=c.measureText(t).width;
      c.font='72px "'+font+'",'+bases[i];
      if(Math.abs(c.measureText(t).width-base)>0.01) return true;
    }
    return false;
  }
  var win=['Segoe UI','Calibri','Cambria','Consolas','Tahoma'];
  var mac=['Helvetica Neue','Lucida Grande','Menlo','Geneva','Apple Color Emoji'];
  var lin=['DejaVu Sans','Liberation Sans','Ubuntu','Noto Sans'];
  function hits(arr){ return arr.filter(installed); }
  return JSON.stringify({win:hits(win),mac:hits(mac),lin:hits(lin)});
})()"#;

fn cfg() -> FoxBrowserConfig {
    let mut c = FoxBrowserConfig {
        headless: true,
        ..Default::default()
    };
    if let Ok(p) = std::env::var("STEALTH_FIREFOX") {
        c.executable_path = Some(p);
    }
    c
}

async fn bare_fonts() -> String {
    let page = launch_firefox_self_managed(cfg()).await.expect("bare");
    page.goto("about:blank").await.expect("nav");
    let r = page
        .evaluate(PROBE)
        .await
        .expect("probe")
        .into_value::<String>()
        .expect("s");
    let _ = page.close().await;
    r
}

async fn persona_fonts(p: &StealthProfile) -> String {
    let page = guise::browser::launch_profiled_firefox(cfg(), p)
        .await
        .expect("persona");
    page.goto("about:blank").await.expect("nav");
    let r = page
        .evaluate(PROBE)
        .await
        .expect("probe")
        .into_value::<String>()
        .expect("s");
    let _ = page.close().await;
    r
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn font_enumeration_leaks_host_os_on_cross_os_persona() {
    if skip() {
        return;
    }
    let bare = bare_fonts().await;
    let linux = persona_fonts(&StealthProfile::FirefoxLinux).await;
    let windows = persona_fonts(&StealthProfile::FirefoxWindows).await;
    let mac = persona_fonts(&StealthProfile::FirefoxMacStable).await;

    let report = format!(
        "BARE            : {bare}\nFirefoxLinux    : {linux}\nFirefoxWindows  : {windows}\nFirefoxMacStable: {mac}\n"
    );
    let _ = std::fs::write("/tmp/guise_font_cross_os.txt", &report);
    eprint!("{report}");

    // Sanity: the bare engine must report SOME installed fonts (else the probe is
    // broken, not the personas).
    assert!(
        bare.contains("DejaVu")
            || bare.contains("Liberation")
            || bare.contains("Noto")
            || bare.contains("Ubuntu")
            || !(bare.contains("\"win\":[]")
                && bare.contains("\"mac\":[]")
                && bare.contains("\"lin\":[]")),
        "bare engine reported NO fonts, probe sanity failed: {bare}"
    );

    // TEETH (documents the known residual): the stock-FF path applies NO per-OS font
    // masking, so EVERY persona's font enumeration is IDENTICAL to the bare engine's
    //: including cross-OS personas, which therefore expose the host's font set and
    // leak the real OS. Coherent cross-OS fonts are engine-level (reynard's
    // font.system.whitelist), and launch_profiled_firefox now WARNS on this mismatch
    // (surface_cross_os_font_tell). If a future fix masks fonts on the stock path,
    // a cross-OS persona will differ from `bare` and these asserts flip (intentional).
    let host = std::env::consts::OS;
    if host == "linux" {
        assert_eq!(
            linux, bare,
            "Linux persona on Linux host should match bare host fonts"
        );
        assert_eq!(windows, bare, "stock-FF Windows persona font set differs from bare, per-OS masking now present? update the cross-OS font disposition + warn");
        assert_eq!(mac, bare, "stock-FF Mac persona font set differs from bare, per-OS masking now present? update the cross-OS font disposition + warn");
    } else {
        eprintln!(
            "host={host}: the Linux-host residual assertion is host-specific; report-only here"
        );
    }
}
