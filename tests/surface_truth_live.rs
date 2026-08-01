//! Live ground-truth diagnostic for the surfaces the probe gate flagged against
//! guise's own Firefox (WebGPU family + Document Picture-in-Picture). This is an
//! ORACLE, not a contract: it prints what the real engine reports so the probe
//! classifications can be corrected from observed truth rather than assumption.
//!
//! Opt-in: `STEALTH_LIVE_BROWSER=1 [STEALTH_FIREFOX=/path]`.
#![cfg(feature = "browser")]

use guise::fingerprint::StealthProfile;
use runtime_foxdriver::{launch_firefox, FoxBrowserConfig};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// Serve a one-shot secure origin on http://127.0.0.1 (a secure context, unlike
/// about:blank) so secure-context-gated APIs (WebGPU, Document PiP) are exposed.
async fn serve_secure_origin() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut sock, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buf = [0u8; 2048];
                let _ = sock.read(&mut buf).await;
                let body =
                    b"<!doctype html><html><head><title>p</title></head><body>x</body></html>";
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

const DIAG: &str = r#"JSON.stringify({
  nav_gpu: typeof navigator.gpu,
  gpu_requestAdapter: !!(navigator.gpu && typeof navigator.gpu.requestAdapter === 'function'),
  gpu_getPreferredCanvasFormat: !!(navigator.gpu && typeof navigator.gpu.getPreferredCanvasFormat === 'function'),
  GPUAdapter: typeof GPUAdapter,
  GPUBufferUsage: typeof GPUBufferUsage,
  dpip_lower: typeof documentPictureInPicture,
  dpip_upper: typeof DocumentPictureInPicture,
  win_dpip_lower: typeof window.documentPictureInPicture,
  win_dpip_upper: typeof window.DocumentPictureInPicture,
  chrome_typeof: typeof window.chrome,
  chrome_in_window: ('chrome' in window),
  chrome_own_prop: Object.prototype.hasOwnProperty.call(window, 'chrome'),
  chrome_desc: (function(){ var d = Object.getOwnPropertyDescriptor(window, 'chrome'); return d ? JSON.stringify({hasGet: typeof d.get, value: typeof d.value, enumerable: d.enumerable, configurable: d.configurable}) : 'NO_OWN_DESCRIPTOR'; })()
})"#;

/// Timer-resolution truth: the current probe does a tight loop of bare
/// `performance.now()` calls (returns 0 if it never advances). Firefox's
/// `reduceTimerPrecision` clamps the timer, so a tight loop finishing under the
/// clamp window reports 0. This dumps (a) the tight-loop value (the probe's), and
/// (b) the first positive delta once real WORK is done between samples, if (a) is
/// 0 but (b) is positive, the timer is present and working (just coarse), so the
/// probe's "never advanced" Drift is a false positive on a clamped timer.
const TIMER_DIAG: &str = r#"JSON.stringify((function(){
  function tight(){ var last=performance.now(); var ds=[]; for(var i=0;i<50;i++){var n=performance.now(); if(n>last)ds.push(n-last); last=n;} return ds.length?Math.min.apply(null,ds):0; }
  function withWork(){ var last=performance.now(); var ds=[]; for(var i=0;i<50;i++){ var x=0; for(var j=0;j<200000;j++){x+=j;} var n=performance.now(); if(n>last)ds.push(n-last); last=n; } return ds.length?Math.min.apply(null,ds):0; }
  function spin(){ var start=performance.now(); var now=start, iters=0; while(now===start && iters<2000000){ var x=0; for(var j=0;j<50;j++){x+=j;} now=performance.now(); iters++; } return {delta: now-start, iters: iters}; }
  return { tight: tight(), withWork: withWork(), spin: spin() };
})())"#;

/// Permissions-API coherence truth. Real Firefox: `navigator.permissions.query`
/// is native, `'request' in navigator.permissions` is FALSE (no such method), and
/// `query({name:'notifications'}).state` must agree with `Notification.permission`
/// (default<->prompt, granted<->granted, denied<->denied). A headless tell is
/// `Notification.permission` reading 'denied' while a naive disguise forces it to
/// 'default' without fixing the query state (mismatch). This dumps both engines so
/// the disguise's permissions overrides can be checked against real Firefox.
const PERMS_DIAG: &str = r#"JSON.stringify((function(){
  function r(p){ return p && p.then ? 'PROMISE' : String(p); }
  var out = { notif_perm: 'n/a', query_state: 'n/a', has_request: 'n/a', query_native: 'n/a', query_own_on_instance: 'n/a' };
  try { out.notif_perm = Notification.permission; } catch(e){ out.notif_perm = 'ERR:'+e; }
  try { out.has_request = ('request' in navigator.permissions); } catch(e){ out.has_request = 'ERR:'+e; }
  try { out.query_native = /\[native code\]/.test(navigator.permissions.query.toString()); } catch(e){ out.query_native = 'ERR:'+e; }
  try { out.query_own_on_instance = Object.prototype.hasOwnProperty.call(navigator.permissions, 'query'); } catch(e){ out.query_own_on_instance = 'ERR:'+e; }
  try { var d = Object.getOwnPropertyDescriptor(Notification, 'permission'); out.notif_desc = d ? ('get:'+typeof d.get+',set:'+typeof d.set+',enum:'+d.enumerable+',conf:'+d.configurable+',native:'+(d.get?/\[native code\]/.test(d.get.toString()):'n/a')) : 'NO_DESC'; } catch(e){ out.notif_desc = 'ERR:'+e; }
  return out;
})())"#;

const PERMS_STATE_JS: &str = r#"navigator.permissions.query({name:'notifications'}).then(function(s){return s.state;}).catch(function(e){return 'ERR:'+e;})"#;

/// Query every permission name the disguise's (dead) override targets, on the bare
/// engine, so we learn which names FF actually supports vs rejects, and what state
/// each returns headless. Names FF rejects (e.g. Chromium-only 'payment-handler')
/// surface as 'ERR:...', proving the override (had it worked) would have been a
/// tell by inventing 'prompt' where real FF throws.
const PERMS_ALL_NAMES_JS: &str = r#"(function(){
  var names = ['notifications','clipboard-read','clipboard-write','accelerometer','gyroscope','magnetometer','ambient-light-sensor','payment-handler','geolocation','camera','microphone','persistent-storage','push'];
  return Promise.all(names.map(function(n){
    return navigator.permissions.query({name:n}).then(function(s){return n+'='+s.state;}, function(e){return n+'=ERR:'+(e&&e.name||e);});
  })).then(function(a){return a.join('  ');});
})()"#;

#[tokio::test]
async fn dump_permissions_truth() {
    if std::env::var("STEALTH_LIVE_BROWSER").is_err() {
        eprintln!("SKIP surface_truth_live: set STEALTH_LIVE_BROWSER=1");
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

    let bare = launch_firefox(cfg.clone()).await.expect("launch bare");
    bare.goto(&url).await.expect("nav");
    let bv = bare
        .evaluate(PERMS_DIAG)
        .await
        .expect("eval")
        .into_value::<String>()
        .expect("json");
    let bstate = bare
        .evaluate_await(PERMS_STATE_JS)
        .await
        .expect("eval state")
        .into_value::<String>()
        .unwrap_or_default();
    let ball = bare
        .evaluate_await(PERMS_ALL_NAMES_JS)
        .await
        .expect("eval all")
        .into_value::<String>()
        .unwrap_or_default();
    eprintln!("PERMS BARE    -> {bv}  notif_query_state={bstate}");
    eprintln!("PERMS BARE  ALL -> {ball}");
    let _ = bare.close().await;

    let page = guise::browser::launch_profiled_firefox(cfg, &StealthProfile::FirefoxLinux)
        .await
        .expect("launch profiled");
    page.goto(&url).await.expect("nav2");
    let sv = page
        .evaluate(PERMS_DIAG)
        .await
        .expect("eval")
        .into_value::<String>()
        .expect("json");
    let sstate = page
        .evaluate_await(PERMS_STATE_JS)
        .await
        .expect("eval state")
        .into_value::<String>()
        .unwrap_or_default();
    let sall = page
        .evaluate_await(PERMS_ALL_NAMES_JS)
        .await
        .expect("eval all")
        .into_value::<String>()
        .unwrap_or_default();
    eprintln!("PERMS STEALTH -> {sv}  notif_query_state={sstate}");
    eprintln!("PERMS STEALTH ALL -> {sall}");
    let _ = page.close().await;
}

/// Window/screen geometry coherence. Detectors assert hard physical invariants:
/// outerWidth>=innerWidth, outerHeight>=innerHeight, screen.width>=outer*,
/// availWidth<=width, availHeight<=height, screenX/screenY plausible, and DPR
/// consistent. The disguise forces outer=inner+16/inner+88 and DPR=1, this dumps
/// bare vs stealth so the offsets can be checked against the real engine instead of
/// assumed. A bare headless FF where outer==inner is itself a headless tell the
/// disguise is meant to repair; the repair must not break an invariant.
const GEOM_DIAG: &str = r#"JSON.stringify({
  innerW: window.innerWidth, innerH: window.innerHeight,
  outerW: window.outerWidth, outerH: window.outerHeight,
  screenW: screen.width, screenH: screen.height,
  availW: screen.availWidth, availH: screen.availHeight,
  screenX: window.screenX, screenY: window.screenY,
  dpr: window.devicePixelRatio,
  colorDepth: screen.colorDepth,
  /* clientWidth/Height reflect the REAL layout viewport; the window.innerWidth
     getter override cannot change them. A divergence innerW != clientW proves the
     getter is lying over a differently-sized real window (a matchMedia tell). */
  clientW: document.documentElement.clientWidth,
  clientH: document.documentElement.clientHeight,
  /* matchMedia reads the REAL device/viewport and is also un-fakeable by the
     getters; if these disagree with screenW/innerW the disguise is incoherent. */
  mm_dev_1366: matchMedia('(max-device-width: 1400px)').matches,
  mm_dev_1920: matchMedia('(min-device-width: 1900px)').matches,
  mm_vw_1366: matchMedia('(max-width: 1400px)').matches,
  mm_vw_1920: matchMedia('(min-width: 1900px)').matches
})"#;

/// Worker-realm timezone coherence. The JS Intl/Date spoof is a window-realm
/// preload; a dedicated Worker has its OWN realm the BiDi preload never reaches, so
/// `Intl.DateTimeFormat().resolvedOptions().timeZone` and `getTimezoneOffset()`
/// inside a worker fall back to the host zone. If the persona zone (America/
/// New_York) differs from the host (America/Phoenix here), window!=worker is a
/// trivially-detected leak. This dumps window-vs-worker for bare and stealthed.
const WORKER_TZ_JS: &str = r#"(function(){
  function inWorker(){
    return new Promise(function(resolve){
      var code = "self.onmessage=function(){var tz='';var off=null;try{tz=Intl.DateTimeFormat().resolvedOptions().timeZone}catch(e){tz='ERR:'+e}try{off=(new Date()).getTimezoneOffset()}catch(e){off='ERR:'+e}postMessage({tz:tz,off:off})}";
      var w;
      try { w = new Worker(URL.createObjectURL(new Blob([code], {type:'application/javascript'}))); }
      catch(e){ resolve({tz:'NOWORKER:'+e, off:null}); return; }
      var done=false;
      w.onmessage=function(ev){ if(done)return; done=true; try{w.terminate()}catch(_){} resolve(ev.data); };
      w.onerror=function(e){ if(done)return; done=true; resolve({tz:'WERR:'+(e.message||e), off:null}); };
      w.postMessage(0);
      setTimeout(function(){ if(done)return; done=true; resolve({tz:'TIMEOUT', off:null}); }, 4000);
    });
  }
  var winTz=''; try { winTz=Intl.DateTimeFormat().resolvedOptions().timeZone; } catch(e){ winTz='ERR:'+e; }
  var winOff=null; try { winOff=(new Date()).getTimezoneOffset(); } catch(e){ winOff='ERR:'+e; }
  return inWorker().then(function(wk){
    return JSON.stringify({ window_tz: winTz, window_off: winOff, worker_tz: wk.tz, worker_off: wk.off });
  });
})()"#;

#[tokio::test]
async fn dump_worker_timezone_truth() {
    if std::env::var("STEALTH_LIVE_BROWSER").is_err() {
        eprintln!("SKIP surface_truth_live: set STEALTH_LIVE_BROWSER=1");
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

    let bare = launch_firefox(cfg.clone()).await.expect("launch bare");
    bare.goto(&url).await.expect("nav");
    let bv = bare
        .evaluate_await(WORKER_TZ_JS)
        .await
        .expect("eval")
        .into_value::<String>()
        .expect("json");
    eprintln!("WORKER-TZ BARE    -> {bv}");
    let _ = bare.close().await;

    let page = guise::browser::launch_profiled_firefox(cfg, &StealthProfile::FirefoxLinux)
        .await
        .expect("launch profiled");
    page.goto(&url).await.expect("nav2");
    let sv = page
        .evaluate_await(WORKER_TZ_JS)
        .await
        .expect("eval")
        .into_value::<String>()
        .expect("json");
    eprintln!("WORKER-TZ STEALTH -> {sv}");
    let _ = page.close().await;
}

/// Worker-realm LOCALE coherence (the i18n sibling of the timezone leak).
/// navigator.languages is driven by the `intl.accept_languages` pref (reaches all
/// realms) so it should already be coherent; but `Intl.*.resolvedOptions().locale`
/// in a Worker may fall back to the app/OS locale the window-realm JS wrap cannot
/// reach. Dumps window-vs-worker for bare and stealthed so any locale leak shows.
const WORKER_LOCALE_JS: &str = r#"(function(){
  function inWorker(){
    return new Promise(function(resolve){
      var code = "self.onmessage=function(){var o={};try{o.langs=(navigator.languages||[]).join(',')}catch(e){o.langs='ERR:'+e}try{o.lang=navigator.language}catch(e){o.lang='ERR:'+e}try{o.dtf=Intl.DateTimeFormat().resolvedOptions().locale}catch(e){o.dtf='ERR:'+e}try{o.nf=Intl.NumberFormat().resolvedOptions().locale}catch(e){o.nf='ERR:'+e}postMessage(o)}";
      var w;
      try { w = new Worker(URL.createObjectURL(new Blob([code], {type:'application/javascript'}))); }
      catch(e){ resolve({langs:'NOWORKER:'+e}); return; }
      var done=false;
      w.onmessage=function(ev){ if(done)return; done=true; try{w.terminate()}catch(_){} resolve(ev.data); };
      w.onerror=function(e){ if(done)return; done=true; resolve({langs:'WERR:'+(e.message||e)}); };
      w.postMessage(0);
      setTimeout(function(){ if(done)return; done=true; resolve({langs:'TIMEOUT'}); }, 4000);
    });
  }
  var win = {};
  try { win.langs=(navigator.languages||[]).join(','); } catch(e){ win.langs='ERR:'+e; }
  try { win.lang=navigator.language; } catch(e){ win.lang='ERR:'+e; }
  try { win.dtf=Intl.DateTimeFormat().resolvedOptions().locale; } catch(e){ win.dtf='ERR:'+e; }
  try { win.nf=Intl.NumberFormat().resolvedOptions().locale; } catch(e){ win.nf='ERR:'+e; }
  return inWorker().then(function(wk){ return JSON.stringify({ window: win, worker: wk }); });
})()"#;

/// Systematic worker-realm navigator sweep: dump EVERY commonly-fingerprinted
/// navigator property from inside a dedicated Worker, bare vs stealthed. Any
/// property where stealth's WINDOW value (spoofed) differs from stealth's WORKER
/// value, while bare's window==worker, is a worker-realm leak (the window-realm
/// JS preload not reaching the worker). This is the multi-modal version of the
/// tz/locale/hardwareConcurrency probes: it surfaces leaks we did not think to
/// name individually.
const WORKER_NAV_SWEEP_JS: &str = r#"(function(){
  var props = "userAgent,appVersion,platform,vendor,language,languages,hardwareConcurrency,deviceMemory,maxTouchPoints,webdriver,productSub,oscpu,product,doNotTrack";
  function dump(nav){
    var o = {};
    props.split(',').forEach(function(p){
      try { var v = nav[p]; o[p] = (p==='languages' && v) ? Array.prototype.join.call(v,',') : (v===undefined?'<undef>':String(v)); }
      catch(e){ o[p] = 'ERR:'+e; }
    });
    return o;
  }
  function inWorker(){
    return new Promise(function(resolve){
      var code = "self.onmessage=function(){var props='"+props+"';var o={};props.split(',').forEach(function(p){try{var v=navigator[p];o[p]=(p==='languages'&&v)?Array.prototype.join.call(v,','):(v===undefined?'<undef>':String(v))}catch(e){o[p]='ERR:'+e}});postMessage(o)}";
      var w;
      try { w = new Worker(URL.createObjectURL(new Blob([code], {type:'application/javascript'}))); }
      catch(e){ resolve({_err:'NOWORKER:'+e}); return; }
      var done=false;
      w.onmessage=function(ev){ if(done)return; done=true; try{w.terminate()}catch(_){} resolve(ev.data); };
      w.onerror=function(e){ if(done)return; done=true; resolve({_err:'WERR:'+(e.message||e)}); };
      w.postMessage(0);
      setTimeout(function(){ if(done)return; done=true; resolve({_err:'TIMEOUT'}); }, 4000);
    });
  }
  return inWorker().then(function(wk){ return JSON.stringify({ window: dump(navigator), worker: wk }); });
})()"#;

#[tokio::test]
async fn dump_worker_navigator_sweep() {
    if std::env::var("STEALTH_LIVE_BROWSER").is_err() {
        eprintln!("SKIP surface_truth_live: set STEALTH_LIVE_BROWSER=1");
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

    let bare = launch_firefox(cfg.clone()).await.expect("launch bare");
    bare.goto(&url).await.expect("nav");
    let bv = bare
        .evaluate_await(WORKER_NAV_SWEEP_JS)
        .await
        .expect("eval")
        .into_value::<String>()
        .expect("json");
    eprintln!("WORKER-NAV BARE    -> {bv}");
    let _ = bare.close().await;

    let page = guise::browser::launch_profiled_firefox(cfg, &StealthProfile::FirefoxLinux)
        .await
        .expect("launch profiled");
    page.goto(&url).await.expect("nav2");
    let sv = page
        .evaluate_await(WORKER_NAV_SWEEP_JS)
        .await
        .expect("eval")
        .into_value::<String>()
        .expect("json");
    eprintln!("WORKER-NAV STEALTH -> {sv}");
    let _ = page.close().await;
}

#[tokio::test]
async fn dump_worker_locale_truth() {
    if std::env::var("STEALTH_LIVE_BROWSER").is_err() {
        eprintln!("SKIP surface_truth_live: set STEALTH_LIVE_BROWSER=1");
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

    let bare = launch_firefox(cfg.clone()).await.expect("launch bare");
    bare.goto(&url).await.expect("nav");
    let bv = bare
        .evaluate_await(WORKER_LOCALE_JS)
        .await
        .expect("eval")
        .into_value::<String>()
        .expect("json");
    eprintln!("WORKER-LOCALE BARE    -> {bv}");
    let _ = bare.close().await;

    let page = guise::browser::launch_profiled_firefox(cfg, &StealthProfile::FirefoxLinux)
        .await
        .expect("launch profiled");
    page.goto(&url).await.expect("nav2");
    let sv = page
        .evaluate_await(WORKER_LOCALE_JS)
        .await
        .expect("eval")
        .into_value::<String>()
        .expect("json");
    eprintln!("WORKER-LOCALE STEALTH -> {sv}");
    let _ = page.close().await;
}

#[tokio::test]
async fn dump_geometry_truth() {
    if std::env::var("STEALTH_LIVE_BROWSER").is_err() {
        eprintln!("SKIP surface_truth_live: set STEALTH_LIVE_BROWSER=1");
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

    let bare = launch_firefox(cfg.clone()).await.expect("launch bare");
    bare.goto(&url).await.expect("nav");
    let bv = bare
        .evaluate(GEOM_DIAG)
        .await
        .expect("eval")
        .into_value::<String>()
        .expect("json");
    eprintln!("GEOM BARE    -> {bv}");
    let _ = bare.close().await;

    let page = guise::browser::launch_profiled_firefox(cfg, &StealthProfile::FirefoxLinux)
        .await
        .expect("launch profiled");
    page.goto(&url).await.expect("nav2");
    let sv = page
        .evaluate(GEOM_DIAG)
        .await
        .expect("eval")
        .into_value::<String>()
        .expect("json");
    eprintln!("GEOM STEALTH -> {sv}");
    let _ = page.close().await;
}

#[tokio::test]
async fn dump_timer_resolution_truth() {
    if std::env::var("STEALTH_LIVE_BROWSER").is_err() {
        eprintln!("SKIP surface_truth_live: set STEALTH_LIVE_BROWSER=1");
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
    let bare = launch_firefox(cfg.clone()).await.expect("launch bare");
    bare.goto(&url).await.expect("nav");
    let bare_v = bare
        .evaluate_await(TIMER_DIAG)
        .await
        .expect("eval bare")
        .into_value::<String>()
        .expect("bare json");
    eprintln!("TIMER BARE    -> {bare_v}");
    let _ = bare.close().await;
}

#[tokio::test]
async fn dump_webgpu_and_dpip_truth() {
    if std::env::var("STEALTH_LIVE_BROWSER").is_err() {
        eprintln!("SKIP surface_truth_live: set STEALTH_LIVE_BROWSER=1");
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

    // Bare engine truth (secure origin).
    let bare = launch_firefox(cfg.clone()).await.expect("launch bare");
    bare.goto(&url).await.expect("nav");
    let bare_v = bare
        .evaluate(DIAG)
        .await
        .expect("eval bare")
        .into_value::<String>()
        .expect("bare json");
    eprintln!("BARE     -> {bare_v}");
    let _ = bare.close().await;

    // Stealthed (full disguise) truth (what the probe gate actually measures).
    let page = guise::browser::launch_profiled_firefox(cfg, &StealthProfile::FirefoxLinux)
        .await
        .expect("launch profiled");
    page.goto(&url).await.expect("nav2");
    let st_v = page
        .evaluate(DIAG)
        .await
        .expect("eval stealth")
        .into_value::<String>()
        .expect("stealth json");
    eprintln!("STEALTH  -> {st_v}");
    let _ = page.close().await;
}

/// `Function.prototype.toString` masking truth. Every getter guise installs via
/// `Object.defineProperty` is a JS function whose raw `.toString()` would reveal
/// non-native source, a strong tamper tell. The `NATIVE_SEAL_PRELUDE` proxy is
/// meant to make each sealed getter report the EXACT native accessor form. The
/// open question only the bare engine can answer: does Firefox's native accessor
/// getter `.toString()` keep a `get ` prefix (`function get userAgent() {…}`) or
/// drop it (`function userAgent() {…}`)? The seal strips the prefix; if bare FF
/// keeps it, every sealed getter is a mismatch. This dumps the exact byte form of
/// a NATIVE control getter (cookieEnabled, never overridden) and the OVERRIDDEN
/// getters on both engines, plus Proxy-detection vectors (throw-on-non-function,
/// name/length/prototype/descriptor shape), so the masking can be proven sound
/// against observed truth rather than assumed.
const TS_PROBE: &str = r#"JSON.stringify((function(){
  function gd(obj,p){ try{ var d=Object.getOwnPropertyDescriptor(obj,p); if(!d)return 'NO_DESC'; if(d.get) return d.get.toString(); if(typeof d.value==='function') return d.value.toString(); return 'NOT_FN'; }catch(e){return 'ERR:'+e;} }
  var navGetters = ['userAgent','appVersion','platform','vendor','languages','language','hardwareConcurrency','maxTouchPoints','webdriver','cookieEnabled','onLine','product','productSub','oscpu'];
  var out = {};
  navGetters.forEach(function(p){ out['nav.'+p] = gd(Navigator.prototype, p); });
  out['Notification.permission'] = gd(Notification, 'permission');
  try{ out['fpts_self'] = Function.prototype.toString.toString(); }catch(e){ out['fpts_self']='ERR:'+e; }
  try{ out['fpts_call_self'] = Function.prototype.toString.call(Function.prototype.toString); }catch(e){ out['fpts_call_self']='ERR:'+e; }
  try{ Function.prototype.toString.call(undefined); out['fpts_undef']='NO_THROW'; }catch(e){ out['fpts_undef']='THREW:'+e.name; }
  try{ Function.prototype.toString.call({}); out['fpts_obj']='NO_THROW'; }catch(e){ out['fpts_obj']='THREW:'+e.name; }
  try{ Function.prototype.toString.apply(Math.max, []); out['fpts_native_relay']=String(Math.max.toString()); }catch(e){ out['fpts_native_relay']='ERR:'+e; }
  out['fpts_name'] = Function.prototype.toString.name;
  out['fpts_length'] = Function.prototype.toString.length;
  out['fpts_has_prototype'] = ('prototype' in Function.prototype.toString);
  try{ var d=Object.getOwnPropertyDescriptor(Function.prototype,'toString'); out['fpts_desc']='w:'+d.writable+',e:'+d.enumerable+',c:'+d.configurable; }catch(e){out['fpts_desc']='ERR:'+e;}
  return out;
})())"#;

/// Child-realm coherence. A dedicated detector creates a hidden iframe and reads
/// `iframe.contentWindow.navigator.webdriver|userAgent|hardwareConcurrency`: the
/// window-realm BiDi preload must reach every child realm (same-origin srcdoc and
/// about:blank iframes) or the child leaks the host identity / webdriver=true
/// while top is spoofed, a trivially-detected divergence. Dumps top vs each
/// child for both engines (bare: all realms agree natively; stealth: children
/// must equal top).
const IFRAME_PROBE: &str = r#"(function(){
  function snap(nav){ try { return { wd:String(nav.webdriver), ua:nav.userAgent, hc:String(nav.hardwareConcurrency), lang:nav.language, plat:nav.platform, mtp:String(nav.maxTouchPoints) }; } catch(e){ return {err:String(e)}; } }
  return new Promise(function(resolve){
    var out = { top: snap(navigator), srcdoc:null, blank:null };
    var done=false; function fin(){ if(done)return; done=true; resolve(JSON.stringify(out)); }
    var f1 = document.createElement('iframe');
    f1.srcdoc = '<!doctype html><html><body>x</body></html>';
    f1.onload = function(){
      out.srcdoc = snap(f1.contentWindow.navigator);
      var f2 = document.createElement('iframe');
      f2.onload = function(){ out.blank = snap(f2.contentWindow.navigator); fin(); };
      document.body.appendChild(f2);
      try { if (f2.contentWindow && f2.contentWindow.document.readyState==='complete'){ out.blank = snap(f2.contentWindow.navigator); fin(); } } catch(e){}
    };
    document.body.appendChild(f1);
    setTimeout(fin, 3500);
  });
})()"#;

/// Property-enumeration-order coherence. Redefining an EXISTING accessor via
/// `Object.defineProperty` (configurable:true) preserves its slot, but CREATING a
/// property appends it, so a spoof that adds a navigator property the engine
/// lacks reorders `getOwnPropertyNames`, a structural tell independent of values.
/// Dumps the prototype + instance own-name order for both engines; they must be
/// identical.
const ORDER_PROBE: &str = r#"JSON.stringify({ proto: Object.getOwnPropertyNames(Navigator.prototype), nav_own: Object.getOwnPropertyNames(navigator) })"#;

#[tokio::test]
async fn dump_realm_and_order_truth() {
    if std::env::var("STEALTH_LIVE_BROWSER").is_err() {
        eprintln!("SKIP surface_truth_live: set STEALTH_LIVE_BROWSER=1");
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

    let bare = launch_firefox(cfg.clone()).await.expect("launch bare");
    bare.goto(&url).await.expect("nav");
    let bi = bare
        .evaluate_await(IFRAME_PROBE)
        .await
        .expect("eval iframe")
        .into_value::<String>()
        .expect("json");
    let bo = bare
        .evaluate(ORDER_PROBE)
        .await
        .expect("eval order")
        .into_value::<String>()
        .expect("json");
    eprintln!("IFRAME BARE    -> {bi}");
    eprintln!("ORDER  BARE    -> {bo}");
    let _ = bare.close().await;

    let page = guise::browser::launch_profiled_firefox(cfg, &StealthProfile::FirefoxLinux)
        .await
        .expect("launch profiled");
    page.goto(&url).await.expect("nav2");
    let si = page
        .evaluate_await(IFRAME_PROBE)
        .await
        .expect("eval iframe")
        .into_value::<String>()
        .expect("json");
    let so = page
        .evaluate(ORDER_PROBE)
        .await
        .expect("eval order")
        .into_value::<String>()
        .expect("json");
    eprintln!("IFRAME STEALTH -> {si}");
    eprintln!("ORDER  STEALTH -> {so}");
    let _ = page.close().await;
}

/// Cross-OS persona coherence. A FirefoxWindows persona run on this Linux host
/// must present a Windows identity on EVERY OS-correlated surface, not just the
/// UA. `navigator.oscpu` is a Firefox-specific, OS-stamped string that detectors
/// cross-check against the UA platform token, if the UA claims Windows but oscpu
/// (or buildID, platform) leaks the Linux host, the persona is trivially unmasked.
/// Dumps the cross-OS surfaces for the Windows persona (and the matched Linux
/// persona as a control) so the leak set can be read directly.
const CROSS_OS_PROBE: &str = r#"JSON.stringify((function(){
  var o = {};
  ['userAgent','appVersion','platform','oscpu','vendor','buildID','product','productSub'].forEach(function(p){
    try { var v = navigator[p]; o[p] = (v===undefined?'<undef>':String(v)); } catch(e){ o[p]='ERR:'+e; }
  });
  o.ua_says_windows = /Windows|Win64|Win32/.test(String(navigator.userAgent));
  o.oscpu_says_linux = /Linux/.test(String(navigator.oscpu||''));
  o.platform_says_linux = /Linux/.test(String(navigator.platform||''));
  return o;
})())"#;

#[tokio::test]
async fn dump_cross_os_persona_truth() {
    if std::env::var("STEALTH_LIVE_BROWSER").is_err() {
        eprintln!("SKIP surface_truth_live: set STEALTH_LIVE_BROWSER=1");
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

    for profile in [StealthProfile::FirefoxWindows, StealthProfile::FirefoxLinux] {
        let page = guise::browser::launch_profiled_firefox(cfg.clone(), &profile)
            .await
            .expect("launch profiled");
        page.goto(&url).await.expect("nav");
        let v = page
            .evaluate(CROSS_OS_PROBE)
            .await
            .expect("eval")
            .into_value::<String>()
            .expect("json");
        eprintln!("CROSS-OS {profile:?} -> {v}");
        let g = page
            .evaluate(WEBGL_CROSS_OS_PROBE)
            .await
            .expect("eval gl")
            .into_value::<String>()
            .expect("json");
        eprintln!("WEBGL    {profile:?} -> {g}");
        let _ = page.close().await;
    }
}

/// speechSynthesis voices + Date zone-name are OS-correlated, JS-readable surfaces.
/// Windows ships SAPI voices ("Microsoft David"), macOS its own set, Linux usually
/// none; `Date.prototype.toString()` renders the zone NAME ("Eastern Standard Time"
/// on Windows vs "EST"/"GMT-0500" elsewhere). A cross-OS persona that leaves the
/// host voice list / zone-name spelling is a tell. Dumps bare vs a Windows persona
/// so a real leak (vs a headless artifact present on bare too) can be told apart.
const SPEECH_TZNAME_PROBE: &str = r#"(function(){
  return new Promise(function(resolve){
    function snap(){
      var voices = [];
      try { voices = (speechSynthesis.getVoices()||[]).map(function(v){return v.name+'|'+v.lang;}); } catch(e){ voices=['ERR:'+e]; }
      var d = new Date(1700000000000);
      resolve(JSON.stringify({
        voice_count: voices.length,
        voices: voices.slice(0,4),
        date_str: String(d),
        date_tz_name: (function(){ var m=String(d).match(/\(([^)]+)\)/); return m?m[1]:''; })()
      }));
    }
    try {
      if (speechSynthesis.getVoices().length) { snap(); return; }
      speechSynthesis.onvoiceschanged = snap;
      setTimeout(snap, 1500);
    } catch(e){ snap(); }
  });
})()"#;

#[tokio::test]
async fn dump_speech_and_datezone_truth() {
    if std::env::var("STEALTH_LIVE_BROWSER").is_err() {
        eprintln!("SKIP surface_truth_live: set STEALTH_LIVE_BROWSER=1");
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

    let bare = launch_firefox(cfg.clone()).await.expect("launch bare");
    bare.goto(&url).await.expect("nav");
    let bv = bare
        .evaluate_await(SPEECH_TZNAME_PROBE)
        .await
        .expect("eval")
        .into_value::<String>()
        .expect("json");
    eprintln!("SPEECH/TZ BARE              -> {bv}");
    let _ = bare.close().await;

    let page = guise::browser::launch_profiled_firefox(cfg, &StealthProfile::FirefoxWindows)
        .await
        .expect("launch profiled");
    page.goto(&url).await.expect("nav2");
    let sv = page
        .evaluate_await(SPEECH_TZNAME_PROBE)
        .await
        .expect("eval")
        .into_value::<String>()
        .expect("json");
    eprintln!("SPEECH/TZ STEALTH(Windows)  -> {sv}");
    let _ = page.close().await;
}

/// WebGL adapter strings are OS-correlated (ANGLE/Direct3D on Windows, Mesa/llvmpipe
/// on Linux, Apple GPU on macOS). A cross-OS persona whose UNMASKED_RENDERER leaks
/// the host adapter (a Windows UA over a Linux "Mesa"/"llvmpipe" renderer) is a
/// cross-OS tell the "not SwiftShader" gate does not catch. Dumps both the masked
/// (GL_VENDOR/RENDERER, "Mozilla" on Firefox) and unmasked adapter strings.
const WEBGL_CROSS_OS_PROBE: &str = r#"JSON.stringify((function(){
  try {
    var c = document.createElement('canvas');
    var g = c.getContext('webgl') || c.getContext('experimental-webgl');
    if (!g) return { gl: 'NO_WEBGL' };
    var ext = g.getExtension('WEBGL_debug_renderer_info');
    return {
      unmasked_vendor: ext ? String(g.getParameter(ext.UNMASKED_VENDOR_WEBGL)) : 'NO_EXT',
      unmasked_renderer: ext ? String(g.getParameter(ext.UNMASKED_RENDERER_WEBGL)) : 'NO_EXT',
      masked_vendor: String(g.getParameter(g.VENDOR)),
      masked_renderer: String(g.getParameter(g.RENDERER))
    };
  } catch(e){ return { err: String(e) }; }
})())"#;

#[tokio::test]
async fn dump_tostring_truth() {
    if std::env::var("STEALTH_LIVE_BROWSER").is_err() {
        eprintln!("SKIP surface_truth_live: set STEALTH_LIVE_BROWSER=1");
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

    let bare = launch_firefox(cfg.clone()).await.expect("launch bare");
    bare.goto(&url).await.expect("nav");
    let bv = bare
        .evaluate(TS_PROBE)
        .await
        .expect("eval")
        .into_value::<String>()
        .expect("json");
    eprintln!("TOSTRING BARE    -> {bv}");
    let _ = bare.close().await;

    let page = guise::browser::launch_profiled_firefox(cfg, &StealthProfile::FirefoxLinux)
        .await
        .expect("launch profiled");
    page.goto(&url).await.expect("nav2");
    let sv = page
        .evaluate(TS_PROBE)
        .await
        .expect("eval")
        .into_value::<String>()
        .expect("json");
    eprintln!("TOSTRING STEALTH -> {sv}");
    let _ = page.close().await;
}
