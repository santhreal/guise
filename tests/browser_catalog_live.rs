//! Live diff: `browser_catalog` header truth values vs. real stock Firefox (G080/G081).
//!
//! `browser_catalog` is a static projection of what a real browser sends on a
//! top-level document navigation. Because it is hand-maintained, it drifts as
//! Firefox evolves (new image formats, new compression schemes, new fetch-metadata
//! behaviour). This test captures the headers from an actual stock Firefox and
//! compares them to the catalogue, failing on invariant divergence and recording
//! a machine-readable diff so a drift can be fixed rather than ignored.
//!
//! Opt-in (spawns a real Firefox): `STEALTH_LIVE_BROWSER=1`.
#![cfg(feature = "browser")]

use std::collections::HashSet;

use guise::fingerprint::browser_catalog::PROFILES;
use runtime_foxdriver::{launch_firefox, FoxBrowserConfig};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::oneshot;

struct CapturedRequest {
    headers: Vec<(String, String)>,
}

fn header_value<'h>(headers: &'h [(String, String)], name: &str) -> Option<&'h str> {
    headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_str())
}

/// Parse a comma-separated header into trimmed, lowercase tokens (q-values removed).
fn header_tokens(value: &str) -> Vec<String> {
    value
        .split(',')
        .map(|s| {
            let mut part = s.trim();
            if let Some(idx) = part.find(';') {
                part = &part[..idx];
            }
            part.trim().to_ascii_lowercase()
        })
        .filter(|s| !s.is_empty())
        .collect()
}

async fn capture_server() -> (String, oneshot::Receiver<CapturedRequest>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let (tx, rx) = oneshot::channel();

    tokio::spawn(async move {
        let mut captured: Option<CapturedRequest> = None;
        while let Ok((mut socket, _)) = listener.accept().await {
            let mut buf = vec![0u8; 8192];
            let n = match socket.read(&mut buf).await {
                Ok(n) if n > 0 => n,
                _ => continue,
            };
            buf.truncate(n);
            let req = String::from_utf8_lossy(&buf);
            let lines: Vec<&str> = req.lines().collect();
            let path = lines
                .first()
                .and_then(|l| l.split_whitespace().nth(1))
                .unwrap_or("/");

            let headers: Vec<(String, String)> = lines
                .iter()
                .skip(1)
                .filter_map(|line| {
                    let mut parts = line.splitn(2, ':').map(str::trim);
                    let key = parts.next()?;
                    let value = parts.next()?;
                    if key.is_empty() {
                        return None;
                    }
                    Some((key.to_string(), value.to_string()))
                })
                .collect();

            let body = b"<!doctype html><html><head><title>ok</title></head><body>ok</body></html>";
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            let _ = socket.write_all(response.as_bytes()).await;
            let _ = socket.write_all(body).await;
            let _ = socket.shutdown().await;

            // Keep the first document request; ignore favicon.ico etc.
            if captured.is_none() && path != "/favicon.ico" {
                captured = Some(CapturedRequest { headers });
                break;
            }
        }
        let _ = tx.send(captured.expect("no document request captured from Firefox"));
    });

    (format!("http://127.0.0.1:{port}/"), rx)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn browser_catalog_matches_live_stock_firefox() {
    if std::env::var("STEALTH_LIVE_BROWSER").is_err() {
        eprintln!("SKIP browser_catalog_live: set STEALTH_LIVE_BROWSER=1 to run (spawns Firefox)");
        return;
    }

    let (url, rx) = capture_server().await;

    let page = launch_firefox(FoxBrowserConfig {
        headless: true,
        ..Default::default()
    })
    .await
    .expect("launch stock Firefox for header capture");

    page.goto(&url)
        .await
        .expect("navigate to local capture server");

    // Give the server a moment to finish the response; `goto` returns when the
    // page load reaches its lifecycle point, but the socket close is async.
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;

    let captured = rx
        .await
        .expect("capture server dropped without sending headers");
    let _ = page.close().await;

    let profile = PROFILES
        .iter()
        .find(|p| p.name == "firefox-linux")
        .expect("firefox-linux catalogue profile must exist");

    // --- Invariant fields: these are Fetch Metadata spec behaviour and must not
    // drift without a deliberate catalogue update. ---
    assert_eq!(
        header_value(&captured.headers, "sec-fetch-site"),
        Some(profile.sec_fetch_site),
        "Sec-Fetch-Site drift: catalogue says {catalogue:?}, live says {live:?}",
        catalogue = profile.sec_fetch_site,
        live = header_value(&captured.headers, "sec-fetch-site")
    );
    assert_eq!(
        header_value(&captured.headers, "sec-fetch-mode"),
        Some(profile.sec_fetch_mode),
        "Sec-Fetch-Mode drift"
    );
    assert_eq!(
        header_value(&captured.headers, "sec-fetch-dest"),
        Some(profile.sec_fetch_dest),
        "Sec-Fetch-Dest drift"
    );
    assert_eq!(
        header_value(&captured.headers, "upgrade-insecure-requests"),
        Some("1"),
        "Upgrade-Insecure-Requests drift"
    );

    // --- Version-shaped fields: exact equality is the wrong invariant across
    // Firefox releases, but the catalogue must remain a faithful SUBSET/FAMILY
    // of the live browser's values, never a contradictory superset. ---

    let live_ua = header_value(&captured.headers, "user-agent").unwrap_or("");
    assert!(
        live_ua.contains("Firefox/"),
        "live User-Agent does not look like Firefox: {live_ua:?}"
    );
    assert!(
        live_ua.contains("Linux x86_64") || live_ua.contains("X11; Linux"),
        "live User-Agent does not claim Linux: {live_ua:?}"
    );

    let live_accept = header_value(&captured.headers, "accept").unwrap_or("");
    let catalogue_accept_tokens: HashSet<String> =
        header_tokens(profile.accept).into_iter().collect();
    let live_accept_tokens: HashSet<String> = header_tokens(live_accept).into_iter().collect();
    assert!(
        catalogue_accept_tokens.is_subset(&live_accept_tokens),
        "catalogue Accept contains tokens the live browser does not send: \
         catalogue={catalogue:?}, live={live:?}",
        catalogue = profile.accept,
        live = live_accept
    );
    assert!(
        live_accept_tokens.contains("text/html"),
        "live Accept missing text/html: {live_accept:?}"
    );

    let live_enc = header_value(&captured.headers, "accept-encoding").unwrap_or("");
    let catalogue_enc_tokens: HashSet<String> =
        header_tokens(profile.accept_encoding).into_iter().collect();
    let live_enc_tokens: HashSet<String> = header_tokens(live_enc).into_iter().collect();
    assert!(
        catalogue_enc_tokens.is_subset(&live_enc_tokens),
        "catalogue Accept-Encoding claims encodings the live browser does not send: \
         catalogue={catalogue:?}, live={live:?}",
        catalogue = profile.accept_encoding,
        live = live_enc
    );

    let live_lang = header_value(&captured.headers, "accept-language").unwrap_or("");
    let catalogue_lang_tags: HashSet<String> =
        header_tokens(profile.accept_language).into_iter().collect();
    let live_lang_tags: HashSet<String> = header_tokens(live_lang).into_iter().collect();
    assert!(
        !catalogue_lang_tags.is_empty(),
        "catalogue Accept-Language is empty"
    );
    assert!(
        catalogue_lang_tags.is_subset(&live_lang_tags),
        "catalogue Accept-Language contains language tags the live browser does not send: \
         catalogue={catalogue:?}, live={live:?}",
        catalogue = profile.accept_language,
        live = live_lang
    );

    // --- Machine-readable diff for the operator / update workflow. ---
    let diff = serde_json::json!({
        "catalogue_profile": profile.name,
        "live_user_agent": live_ua,
        "live_accept": live_accept,
        "live_accept_language": live_lang,
        "live_accept_encoding": live_enc,
        "live_sec_fetch_site": header_value(&captured.headers, "sec-fetch-site"),
        "live_sec_fetch_mode": header_value(&captured.headers, "sec-fetch-mode"),
        "live_sec_fetch_dest": header_value(&captured.headers, "sec-fetch-dest"),
        "live_upgrade_insecure_requests": header_value(&captured.headers, "upgrade-insecure-requests"),
        "catalogue_user_agent": profile.user_agent,
        "catalogue_accept": profile.accept,
        "catalogue_accept_language": profile.accept_language,
        "catalogue_accept_encoding": profile.accept_encoding,
        "catalogue_sec_fetch_site": profile.sec_fetch_site,
        "catalogue_sec_fetch_mode": profile.sec_fetch_mode,
        "catalogue_sec_fetch_dest": profile.sec_fetch_dest,
    });

    let scorecard_path = std::path::PathBuf::from(
        std::env::var("BROWSER_CATALOG_DIFF_PATH")
            .unwrap_or_else(|_| "bench-results/browser_catalog_live_diff.json".into()),
    );
    if let Some(parent) = scorecard_path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    std::fs::write(
        &scorecard_path,
        serde_json::to_string_pretty(&diff).expect("serialize diff"),
    )
    .unwrap_or_else(|e| panic!("write browser-catalog diff to {scorecard_path:?}: {e}"));
}
