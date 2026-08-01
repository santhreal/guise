//! Live PoC: does a PROXYLESS guise persona leak the host's real LAN IP via a
//! WebRTC `host` ICE candidate?
//!
//! `proxy_prefs` closes the WebRTC leak when a proxy is configured (see
//! foxdriver/tests/webrtc_proxy_leak.rs: `ice.proxy_only` confines ICE). But the
//! DEFAULT, proxyless persona sets NOTHING under `media.peerconnection`, so it
//! relies entirely on Firefox's registered default
//! `media.peerconnection.ice.obfuscate_host_addresses = true` (all.js) to replace
//! the raw LAN address of every `host` candidate with an `<uuid>.local` mDNS name.
//!
//! That obfuscation is real ONLY if the platform mDNS responder registers the
//! `.local` name. In a HEADLESS box with no avahi/mDNS responder running, the
//! common automation deployment, registration can fail, and whether Firefox then
//! (a) emits the candidate as an unresolvable `.local` (safe), (b) drops the host
//! candidate (safe), or (c) falls back to the raw RFC1918 address (LEAK + a
//! deviation from real-FF default, i.e. a tell) is environment-dependent and
//! unverified. guise additionally runs with `privacy.resistFingerprinting=false`,
//! the path that does NOT get RFP's WebRTC hardening, so the default obfuscation
//! is the only thing standing between the operator and a LAN-topology leak.
//!
//! This drives the FULL guise persona launch and asserts the negative with teeth:
//! the host's real primary LAN IP, and any RFC1918 literal, must NEVER appear in a
//! gathered candidate. No STUN is configured, only link-local host candidates are
//! gathered, so the test needs no network egress and runs offline.
//!
//! Opt-in: `STEALTH_LIVE_BROWSER=1 [STEALTH_FIREFOX=/path]`.
#![cfg(feature = "browser")]

use guise::fingerprint::StealthProfile;
use runtime_foxdriver::FoxBrowserConfig;
use std::net::{IpAddr, UdpSocket};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

fn skip() -> bool {
    if std::env::var("STEALTH_LIVE_BROWSER").is_err() {
        eprintln!("skip webrtc_host_candidate_live: set STEALTH_LIVE_BROWSER=1");
        return true;
    }
    false
}

/// The host's primary outbound-interface address, via the connectionless
/// UDP-connect trick (no packet is sent: `connect` only picks the route, then
/// `local_addr` reports the chosen source IP). This is the address a `host` ICE
/// candidate would carry if obfuscation were off, so it is the precise oracle.
fn primary_lan_ip() -> Option<IpAddr> {
    let sock = UdpSocket::bind("0.0.0.0:0").ok()?;
    sock.connect("8.8.8.8:80").ok()?;
    sock.local_addr().ok().map(|a| a.ip())
}

/// True for an RFC1918 IPv4 literal appearing anywhere in `s` (10/8, 172.16/12,
/// 192.168/16) (the LAN ranges a `host` candidate must never expose raw).
fn contains_rfc1918(s: &str) -> bool {
    if s.contains("192.168.") || s.contains("10.") {
        // 10. is broad; restrict to a dotted-quad-looking context to avoid
        // matching e.g. a port or priority. Candidate IPs are space-delimited.
        if s.contains("192.168.") {
            return true;
        }
        for tok in s.split([' ', '\t']) {
            let octs: Vec<&str> = tok.split('.').collect();
            if octs.len() == 4 && octs[0] == "10" && octs.iter().all(|o| o.parse::<u8>().is_ok()) {
                return true;
            }
        }
    }
    // 172.16.0.0 – 172.31.255.255
    for tok in s.split([' ', '\t']) {
        let octs: Vec<&str> = tok.split('.').collect();
        if octs.len() == 4
            && octs[0] == "172"
            && octs.iter().all(|o| o.parse::<u8>().is_ok())
            && matches!(octs[1].parse::<u8>(), Ok(16..=31))
        {
            return true;
        }
    }
    false
}

async fn serve_html(listener: TcpListener, body: String) {
    while let Ok((mut s, _)) = listener.accept().await {
        let body = body.clone();
        tokio::spawn(async move {
            let mut b = [0u8; 2048];
            let _ = s.read(&mut b).await;
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            let _ = s.write_all(resp.as_bytes()).await;
            let _ = s.write_all(body.as_bytes()).await;
            let _ = s.shutdown().await;
        });
    }
}

/// Gather host ICE candidates (no STUN/iceServers → host candidates only) and
/// return (candidate_strings, gathering_completed). `gathering_completed` is true
/// once the null end-of-candidates event fires, so the caller can distinguish
/// "no leak" from "ICE never ran".
const GATHER_JS: &str = r#"(() => {
    window.__cands = [];
    window.__done = false;
    let pc;
    try { pc = new RTCPeerConnection(); }
    catch (e) { window.__err = String(e); return; }
    pc.onicecandidate = (e) => {
        if (e.candidate) window.__cands.push(e.candidate.candidate);
        else window.__done = true;
    };
    pc.createDataChannel('probe');
    pc.createOffer().then((o) => pc.setLocalDescription(o)).catch((e) => { window.__err = String(e); });
})()"#;

fn cfg() -> FoxBrowserConfig {
    // Proxyless by construction: `proxy: None` is the whole point, this exercises
    // the DEFAULT path that relies solely on FF's obfuscation default.
    let mut c = FoxBrowserConfig {
        headless: true,
        ..Default::default()
    };
    if let Ok(p) = std::env::var("STEALTH_FIREFOX") {
        c.executable_path = Some(p);
    }
    c
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn proxyless_webrtc_host_candidate_does_not_leak_lan_ip() {
    if skip() {
        return;
    }
    let lan_ip = primary_lan_ip();
    let lan_ip_str = lan_ip.map(|ip| ip.to_string());

    // A real http origin → a normal content process (FF gates obfuscation on
    // `XRE_IsContentProcess()`), the realistic operator path a detector page runs in.
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().unwrap();
    let url = format!("http://{addr}/");
    tokio::spawn(serve_html(
        listener,
        "<!doctype html><html><body>probe</body></html>".to_string(),
    ));

    let page = guise::browser::launch_profiled_firefox(cfg(), &StealthProfile::FirefoxWindows)
        .await
        .expect("launch");
    page.goto(&url).await.expect("nav");

    let _ = page.evaluate(GATHER_JS).await;

    // Poll until end-of-candidates fires or the budget elapses.
    let mut completed = false;
    for _ in 0..40 {
        tokio::time::sleep(std::time::Duration::from_millis(150)).await;
        completed = page
            .evaluate("window.__done === true")
            .await
            .ok()
            .and_then(|v| v.into_value::<bool>().ok())
            .unwrap_or(false);
        if completed {
            break;
        }
    }

    let cands: Vec<String> = page
        .evaluate("JSON.stringify(window.__cands || [])")
        .await
        .ok()
        .and_then(|v| v.into_value::<String>().ok())
        .and_then(|s| serde_json::from_str::<Vec<String>>(&s).ok())
        .unwrap_or_default();
    let err = page
        .evaluate("String(window.__err || '')")
        .await
        .ok()
        .and_then(|v| v.into_value::<String>().ok())
        .unwrap_or_default();
    let _ = page.close().await;

    let host_local = cands
        .iter()
        .filter(|c| c.contains("typ host") && c.contains(".local"))
        .count();
    let host_total = cands.iter().filter(|c| c.contains("typ host")).count();
    let report = format!(
        "proxyless WebRTC host-candidate probe (FirefoxWindows):\n  host LAN IP: {lan_ip_str:?}\n  \
         gathering_completed: {completed}\n  candidates: {}\n  host candidates: {host_total} ({host_local} mDNS .local)\n  \
         err: {err:?}\n  raw: {cands:?}\n",
        cands.len()
    );
    let _ = std::fs::write("/tmp/guise_webrtc_host_candidate.txt", &report);
    eprint!("{report}");

    // If ICE never produced a terminal signal AND gathered nothing, there is no
    // oracle signal, skip rather than false-pass. (Distinct from "completed with
    // zero host candidates", which IS a valid no-leak observation.)
    if !completed && cands.is_empty() {
        eprintln!(
            "SKIP proxyless_webrtc_host_candidate: ICE produced no candidates and no \
             end-of-candidates event (err={err:?}); environment cannot exercise the oracle."
        );
        return;
    }

    // TEETH 1: the host's real primary LAN IP must never appear in any candidate.
    if let Some(ip) = &lan_ip_str {
        let leaked: Vec<&String> = cands.iter().filter(|c| c.contains(ip.as_str())).collect();
        assert!(
            leaked.is_empty(),
            "proxyless persona LEAKS the host's real LAN IP {ip} via a WebRTC candidate \
             (mDNS obfuscation did not cover it in this environment): {leaked:?}"
        );
    }

    // TEETH 2: no candidate may carry a raw RFC1918 LAN literal (backstop for
    // secondary interfaces the primary-IP probe does not see).
    let rfc1918: Vec<&String> = cands.iter().filter(|c| contains_rfc1918(c)).collect();
    assert!(
        rfc1918.is_empty(),
        "proxyless persona exposes a raw RFC1918 LAN address via WebRTC, a topology \
         leak and a deviation from Firefox's mDNS-obfuscation default: {rfc1918:?}"
    );
}
