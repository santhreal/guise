//! Live contract: `Function.prototype.toString` masking must be BYTE-COHERENT
//! with the bare engine.
//!
//! Every navigator getter guise installs via `Object.defineProperty` is an
//! ordinary JS function whose raw `.toString()` would reveal non-native source
//! (`() => "..."`), the single strongest tamper tell, weighted heavily by
//! CreepJS/FingerprintJS. The `NATIVE_SEAL_PRELUDE` proxy is meant to make each
//! sealed getter report the EXACT form Firefox uses for a native accessor.
//!
//! CONFIRMED live (dump_tostring_truth in surface_truth_live.rs): bare Firefox 151
//! reports an accessor getter as `function <prop>() {\n    [native code]\n}`
//! WITHOUT a `get ` prefix, and the seal's prefix-strip reproduces that byte form
//! exactly; the proxy also throws `TypeError` on a non-function receiver and
//! preserves `name`/`length`/`prototype`/descriptor shape, matching native. This
//! locks all of that so a future override that forgets `__seal`, or a proxy edit
//! that breaks the native-throw / shape parity, fails loudly.
//!
//! Opt-in: `STEALTH_LIVE_BROWSER=1 [STEALTH_FIREFOX=/path]` (spawns real Firefox).
#![cfg(feature = "browser")]

use guise::fingerprint::StealthProfile;
use runtime_foxdriver::{launch_firefox, FoxBrowserConfig};
use serde_json::Value;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

fn skip() -> bool {
    if std::env::var("STEALTH_LIVE_BROWSER").is_err() {
        eprintln!("skip tostring_coherence_live: set STEALTH_LIVE_BROWSER=1 (spawns real Firefox)");
        return true;
    }
    false
}

async fn serve_secure_origin() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut sock, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buf = [0u8; 2048];
                let _ = sock.read(&mut buf).await;
                let body =
                    b"<!doctype html><html><head><title>t</title></head><body>x</body></html>";
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
  out['fpts_name'] = Function.prototype.toString.name;
  out['fpts_length'] = Function.prototype.toString.length;
  out['fpts_has_prototype'] = ('prototype' in Function.prototype.toString);
  try{ var d=Object.getOwnPropertyDescriptor(Function.prototype,'toString'); out['fpts_desc']='w:'+d.writable+',e:'+d.enumerable+',c:'+d.configurable; }catch(e){out['fpts_desc']='ERR:'+e;}
  return out;
})())"#;

async fn probe(page: &runtime_foxdriver::browser::Page, url: &str) -> Value {
    page.goto(url).await.expect("nav");
    let s = page
        .evaluate(TS_PROBE)
        .await
        .expect("eval TS_PROBE")
        .into_value::<String>()
        .expect("json string");
    serde_json::from_str(&s).unwrap_or_else(|e| panic!("parse {s}: {e}"))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tostring_masking_is_byte_coherent_with_bare_firefox() {
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

    let bare = launch_firefox(cfg.clone()).await.expect("launch bare");
    let b = probe(&bare, &url).await;
    let _ = bare.close().await;

    let page = guise::browser::launch_profiled_firefox(cfg, &StealthProfile::FirefoxLinux)
        .await
        .expect("launch profiled");
    let s = probe(&page, &url).await;
    let _ = page.close().await;

    let sv = |v: &Value, k: &str| v[k].as_str().unwrap_or("<MISSING>").to_string();

    // The getters guise OVERRIDES via Object.defineProperty: each MUST report the
    // exact native accessor form, identical to what the bare engine reports for the
    // same (or a sibling native) accessor, i.e. no `get ` prefix, real `[native
    // code]` body. cookieEnabled/onLine/product/productSub/oscpu are NOT overridden
    // and serve as native controls (bare==stealth proves we didn't disturb them).
    let overridden = [
        "nav.userAgent",
        "nav.appVersion",
        "nav.platform",
        "nav.vendor",
        "nav.languages",
        "nav.language",
        "nav.hardwareConcurrency",
        "nav.maxTouchPoints",
        "nav.webdriver",
        "nav.oscpu",
        "Notification.permission",
    ];
    for key in overridden {
        let prop = key.rsplit('.').next().unwrap();
        let expected = format!("function {prop}() {{\n    [native code]\n}}");
        assert_eq!(
            sv(&s, key),
            expected,
            "{key}: stealth toString is not the native accessor form (unsealed override?)"
        );
        // And it must match what the bare engine reports for that same accessor
        // (every one of these exists natively on bare Firefox 151).
        assert_eq!(
            sv(&s, key),
            sv(&b, key),
            "{key}: stealth toString diverges from bare native form"
        );
    }

    // Native controls: untouched accessors are byte-identical across engines.
    for key in [
        "nav.cookieEnabled",
        "nav.onLine",
        "nav.product",
        "nav.productSub",
    ] {
        assert_eq!(
            sv(&s, key),
            sv(&b, key),
            "{key}: control accessor disturbed by stealth"
        );
        assert!(
            sv(&s, key).contains("[native code]"),
            "{key}: control accessor not native: {}",
            sv(&s, key)
        );
    }

    // The toString proxy must be indistinguishable from the native function:
    // reports native source for itself, throws TypeError on a non-function
    // receiver (exactly like Function.prototype.toString), and preserves the
    // native name/length/prototype-absence/descriptor shape.
    assert!(
        sv(&s, "fpts_self").contains("[native code]"),
        "Function.prototype.toString self-report not native: {}",
        sv(&s, "fpts_self")
    );
    assert_eq!(
        sv(&s, "fpts_call_self"),
        sv(&b, "fpts_call_self"),
        "fpts call-self diverges from bare"
    );
    assert_eq!(
        sv(&s, "fpts_undef"),
        "THREW:TypeError",
        "toString must throw TypeError on undefined receiver"
    );
    assert_eq!(
        sv(&s, "fpts_obj"),
        "THREW:TypeError",
        "toString must throw TypeError on a plain-object receiver"
    );
    assert_eq!(
        sv(&s, "fpts_name"),
        "toString",
        "toString.name must be 'toString'"
    );
    assert_eq!(
        s["fpts_length"].as_i64(),
        Some(0),
        "toString.length must be 0"
    );
    assert_eq!(
        s["fpts_has_prototype"].as_bool(),
        Some(false),
        "toString must not have a 'prototype' own slot"
    );
    assert_eq!(
        sv(&s, "fpts_desc"),
        "w:true,e:false,c:true",
        "Function.prototype.toString descriptor shape changed"
    );
    // And every proxy invariant equals the bare engine's, not just a hardcoded guess.
    for key in ["fpts_undef", "fpts_obj", "fpts_name", "fpts_desc"] {
        assert_eq!(
            sv(&s, key),
            sv(&b, key),
            "{key}: stealth diverges from bare engine"
        );
    }
}
