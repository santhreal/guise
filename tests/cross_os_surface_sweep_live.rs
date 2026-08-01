//! Live DOGFOOD sweep: dump a battery of content-readable, OS-correlated surfaces
//! on a CROSS-OS persona (FirefoxWindows on this Linux host) and compare each to the
//! persona's CLAIMED OS, to surface any remaining sound-fixable cross-OS tell.
//!
//! Methodology: each surface is read on the FirefoxWindows persona. A value that
//! reveals Linux (the host) under a Windows UA is a tell. The report is written to
//! /tmp so it survives fd interleaving; the test asserts only the surfaces guise
//! already contracts (UA/platform/oscpu OS-token), leaving the rest as a dump to
//! eyeball for new leaks.
//!
//! Opt-in: `STEALTH_LIVE_BROWSER=1 [STEALTH_FIREFOX=/path]`.
#![cfg(feature = "browser")]

use guise::fingerprint::StealthProfile;
use runtime_foxdriver::FoxBrowserConfig;

fn skip() -> bool {
    if std::env::var("STEALTH_LIVE_BROWSER").is_err() {
        eprintln!("skip cross_os_surface_sweep_live: set STEALTH_LIVE_BROWSER=1");
        return true;
    }
    false
}

// One JSON blob of OS-correlated, CONTENT-readable surfaces.
const SWEEP: &str = r#"(function(){
  function safe(f){ try { return f(); } catch(e){ return 'ERR:'+e; } }
  var d = {};
  d.userAgent = safe(()=>navigator.userAgent);
  d.platform = safe(()=>navigator.platform);
  d.oscpu = safe(()=>navigator.oscpu);
  d.appVersion = safe(()=>navigator.appVersion);
  d.maxTouchPoints = safe(()=>navigator.maxTouchPoints);
  d.hardwareConcurrency = safe(()=>navigator.hardwareConcurrency);
  d.deviceMemory = safe(()=>navigator.deviceMemory);
  d.languages = safe(()=>JSON.stringify(navigator.languages));
  d.tz = safe(()=>Intl.DateTimeFormat().resolvedOptions().timeZone);
  d.locale = safe(()=>Intl.DateTimeFormat().resolvedOptions().locale);
  d.numbering = safe(()=>Intl.DateTimeFormat().resolvedOptions().numberingSystem);
  d.tzOffset = safe(()=>new Date(2025,0,1).getTimezoneOffset());
  d.dateStr = safe(()=>new Date(0).toString());
  // Scrollbar width: Windows classic ~17px, Mac/overlay 0, GTK varies. OS-ish.
  d.scrollbar = safe(()=>{
    var o=document.createElement('div');
    o.style.cssText='width:100px;height:100px;overflow:scroll;position:absolute;top:-9999px';
    document.body.appendChild(o); var w=o.offsetWidth-o.clientWidth; o.remove(); return w;
  });
  // System colors (RFP is off in guise). OS/theme palette.
  d.sysColor = safe(()=>{
    var s=document.createElement('span'); s.style.color='ButtonFace'; document.body.appendChild(s);
    var c=getComputedStyle(s).color; s.remove(); return c;
  });
  // Default monospace metrics (font-stack dependent).
  d.monoWidth = safe(()=>{var c=document.createElement('canvas').getContext('2d');c.font='16px monospace';return c.measureText('MMMMMMMMMM').width;});
  d.colorDepth = safe(()=>screen.colorDepth);
  d.screen = safe(()=>screen.width+'x'+screen.height+' avail '+screen.availWidth+'x'+screen.availHeight);
  d.pdfViewer = safe(()=>navigator.pdfViewerEnabled);
  d.webglVendor = safe(()=>{var gl=document.createElement('canvas').getContext('webgl');var e=gl.getExtension('WEBGL_debug_renderer_info');return gl.getParameter(e.UNMASKED_VENDOR_WEBGL);});
  d.webglRenderer = safe(()=>{var gl=document.createElement('canvas').getContext('webgl');var e=gl.getExtension('WEBGL_debug_renderer_info');return gl.getParameter(e.UNMASKED_RENDERER_WEBGL);});
  return JSON.stringify(d);
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

async fn sweep_persona(p: &StealthProfile) -> String {
    let page = guise::browser::launch_profiled_firefox(cfg(), p)
        .await
        .expect("persona");
    // A real http origin would be ideal, but these surfaces are origin-independent;
    // a real document is needed for scrollbar/system-color DOM probes, so navigate
    // to a data: document with a body.
    page.goto("data:text/html,<body>x</body>")
        .await
        .expect("nav");
    let r = page
        .evaluate(SWEEP)
        .await
        .expect("sweep")
        .into_value::<String>()
        .expect("s");
    let _ = page.close().await;
    r
}

async fn sweep_bare() -> String {
    use runtime_foxdriver::browser::launch_firefox_self_managed;
    let page = launch_firefox_self_managed(cfg()).await.expect("bare");
    page.goto("data:text/html,<body>x</body>")
        .await
        .expect("nav");
    let r = page
        .evaluate(SWEEP)
        .await
        .expect("sweep")
        .into_value::<String>()
        .expect("s");
    let _ = page.close().await;
    r
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cross_os_surface_sweep() {
    if skip() {
        return;
    }
    let bare = sweep_bare().await;
    let windows = sweep_persona(&StealthProfile::FirefoxWindows).await;
    let report = format!(
        "HOST OS: {}\n\nBARE:\n{bare}\n\nFirefoxWindows:\n{windows}\n",
        std::env::consts::OS
    );
    let _ = std::fs::write("/tmp/guise_cross_os_sweep.txt", &report);
    eprint!("{report}");

    // Contracted JS-readable surfaces: the Windows persona's UA/platform/oscpu must
    // claim Windows, not leak the host.
    assert!(
        windows.contains("Windows NT"),
        "Windows persona UA does not claim Windows: {windows}"
    );
    assert!(
        windows.contains("Win32") || windows.contains("Win64"),
        "Windows persona navigator.platform leaks: {windows}"
    );
    assert!(
        !windows.contains(r#""oscpu":"Linux"#),
        "Windows persona oscpu leaks Linux: {windows}"
    );
    // WebGL renderer carries a Windows signature (ANGLE/Direct3D), not the host GPU.
    assert!(
        windows.contains("ANGLE") && windows.contains("D3D11"),
        "Windows persona WebGL renderer not Windows-shaped: {windows}"
    );

    // DOCUMENTED RESIDUAL (engine-rendered, reynard-domain): the scrollbar width is
    // the host toolkit's on BOTH bare and the Windows persona, the stock-FF path
    // does not (and soundly cannot) mask it. launch_profiled_firefox now WARNS on
    // this (surface_cross_os_rendering_tell). If a future engine fix masks it, the
    // persona value will diverge from bare and this flips (intentional).
    let scrollbar = |j: &str| -> Option<i64> {
        let k = "\"scrollbar\":";
        let i = j.find(k)? + k.len();
        let rest = &j[i..];
        let end = rest
            .find(|c: char| !c.is_ascii_digit() && c != '-')
            .unwrap_or(rest.len());
        rest[..end].parse().ok()
    };
    if std::env::consts::OS == "linux" {
        let (sb, sw) = (scrollbar(&bare), scrollbar(&windows));
        assert!(sb.is_some() && sb == sw,
            "scrollbar residual changed (bare={sb:?} windows={sw:?}), engine masking now present? update the cross-OS rendering disposition");
    }
}
