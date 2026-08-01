//! Live contract: the browser's HTTP request headers must agree with the JS-visible
//! navigator values (the most basic server-side spoof check).
//!
//! A persona sets `general.useragent.override` and `intl.accept_languages` (engine
//! prefs → request headers) AND overrides `navigator.userAgent/language/languages`
//! (JS getters). These are two different construction paths; if they ever diverge,
//! the server sees a `User-Agent` header that contradicts the JS `navigator.userAgent`
//! (or an `Accept-Language` that contradicts `navigator.languages`), a trivial,
//! high-weight bot flag. Firefox additionally must NOT send Chromium client-hint
//! headers (`sec-ch-ua*`). This captures the REAL request headers server-side and
//! asserts they match what the page reports in JS, on a cross-OS persona.
//!
//! Opt-in: `STEALTH_LIVE_BROWSER=1 [STEALTH_FIREFOX=/path]`.
#![cfg(feature = "browser")]

use guise::fingerprint::StealthProfile;
use runtime_foxdriver::FoxBrowserConfig;
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

fn skip() -> bool {
    if std::env::var("STEALTH_LIVE_BROWSER").is_err() {
        eprintln!("skip http_js_header_coherence_live: set STEALTH_LIVE_BROWSER=1");
        return true;
    }
    false
}

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

/// Serve a page and record the raw header block of every request received.
async fn serve_capturing(reqs: Arc<Mutex<Vec<String>>>) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut s, _)) = listener.accept().await {
            let reqs = reqs.clone();
            tokio::spawn(async move {
                let mut buf = vec![0u8; 8192];
                let n = s.read(&mut buf).await.unwrap_or(0);
                let req = String::from_utf8_lossy(&buf[..n]).to_string();
                reqs.lock().unwrap().push(req);
                let body = b"<!doctype html><html><body>hdr</body></html>";
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                let _ = s.write_all(resp.as_bytes()).await;
                let _ = s.write_all(body).await;
                let _ = s.shutdown().await;
            });
        }
    });
    format!("http://{addr}/")
}

/// Case-insensitive single-header value extractor from a raw request block.
fn header(req: &str, name: &str) -> Option<String> {
    let want = name.to_ascii_lowercase();
    for line in req.split("\r\n").skip(1) {
        if let Some((k, v)) = line.split_once(':') {
            if k.trim().to_ascii_lowercase() == want {
                return Some(v.trim().to_string());
            }
        }
    }
    None
}

const NAV_PROBE: &str = r#"JSON.stringify({
  ua: String(navigator.userAgent),
  language: String(navigator.language),
  languages: (navigator.languages||[]).join(',')
})"#;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn request_headers_match_navigator_js() {
    if skip() {
        return;
    }
    let reqs = Arc::new(Mutex::new(Vec::<String>::new()));
    let url = serve_capturing(reqs.clone()).await;

    let page = guise::browser::launch_profiled_firefox(cfg(), &StealthProfile::FirefoxWindows)
        .await
        .expect("launch");
    page.goto(&url).await.expect("nav");
    let nav_raw = page
        .evaluate(NAV_PROBE)
        .await
        .expect("nav eval")
        .into_value::<String>()
        .expect("nav json");
    let _ = page.close().await;

    let nav: serde_json::Value = serde_json::from_str(&nav_raw).expect("parse nav");
    let nav_ua = nav["ua"].as_str().unwrap_or("");
    let nav_lang = nav["language"].as_str().unwrap_or("");
    let nav_langs = nav["languages"].as_str().unwrap_or("");

    // Find the first captured request that carries a User-Agent (the navigation).
    let reqs = reqs.lock().unwrap().clone();
    let nav_req = reqs
        .iter()
        .find(|r| header(r, "user-agent").is_some())
        .cloned()
        .unwrap_or_default();
    let ua_hdr = header(&nav_req, "user-agent").unwrap_or_default();
    let al_hdr = header(&nav_req, "accept-language").unwrap_or_default();
    let sec_ch_ua = header(&nav_req, "sec-ch-ua");
    let sec_ch_plat = header(&nav_req, "sec-ch-ua-platform");

    let report = format!(
        "captured {} request(s)\nUA header : {ua_hdr}\nnav.userAgent: {nav_ua}\nAccept-Language: {al_hdr}\nnav.language: {nav_lang}\nnav.languages: {nav_langs}\nsec-ch-ua: {sec_ch_ua:?}\n",
        reqs.len()
    );
    let _ = std::fs::write("/tmp/guise_http_js_coherence.txt", &report);
    eprint!("{report}");

    // 1. The User-Agent HEADER must EXACTLY equal navigator.userAgent.
    assert_eq!(
        ua_hdr, nav_ua,
        "UA header disagrees with navigator.userAgent, a server-side spoof flag: {report}"
    );
    // The persona must actually be in force (Windows), not the bare host UA.
    assert!(
        ua_hdr.contains("Windows NT") && ua_hdr.contains("Firefox/"),
        "UA header is not the FirefoxWindows persona: {report}"
    );

    // 2. Accept-Language must be present and cohere with navigator: its first tag
    //    equals navigator.language, and navigator.languages[0] matches too.
    assert!(
        !al_hdr.is_empty(),
        "Accept-Language header missing: {report}"
    );
    let al_primary = al_hdr.split([',', ';']).next().unwrap_or("").trim();
    assert_eq!(
        al_primary, nav_lang,
        "Accept-Language primary tag disagrees with navigator.language: {report}"
    );
    assert!(
        nav_langs.split(',').next().map(|s| s.trim()) == Some(nav_lang),
        "navigator.languages[0] != navigator.language: {report}"
    );

    // 3. Firefox must NOT emit Chromium client-hint headers.
    assert!(
        sec_ch_ua.is_none(),
        "Firefox persona emitted a Chromium sec-ch-ua header (instant engine tell): {sec_ch_ua:?}"
    );
    assert!(
        sec_ch_plat.is_none(),
        "Firefox persona emitted sec-ch-ua-platform (Chromium-only): {sec_ch_plat:?}"
    );
}
