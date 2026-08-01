//! Layer-2 transport fingerprint: reynard's **wire** identity vs stock Firefox.
//!
//! The probe oracle proves reynard's *JS surface* matches a real Firefox. This
//! closes the layer below it: the TLS ClientHello (JA3/JA4), the HTTP/2 SETTINGS
//! (Akamai fingerprint), and the TCP/IP stack shape, the layer three independent
//! 2026 benchmarks (incolumitas, Botforensics, techinz) say actually decides bot
//! detection. The categorical bet of an NSS-native engine fork is that reynard is
//! **byte-identical to stock Firefox at the TLS layer for free** (no wreq/boring
//! shim, no proxy rewrite). This test measures whether that bet holds.
//!
//! Method: drive reynard (and, if `STEALTH_FIREFOX` is set, stock FF) to
//! `tls.peet.ws`, fetch `/api/all` same-origin (kicked into a global + polled,
//! since `evaluate` does not await promises), and diff JA3/JA4/Akamai/peetprint.
//! Matching hashes ⇒ the engine's TLS is authentic Firefox. The `tcpip` block is
//! recorded as the Botforensics-layer signal (does the OS guess match the persona?).
//!
//! Opt-in (needs a built reynard binary, a display, and network egress):
//! ```text
//! REYNARD_BIN=/…/dist/bin/camoufox STEALTH_FIREFOX=/tmp/firefox-150/firefox \
//!   DISPLAY=:1 MOZ_DISABLE_CONTENT_SANDBOX=1 \
//!   cargo test -p guise --no-default-features --features browser \
//!   --test tls_fingerprint -- --nocapture
//! ```
// G259: needs `http` too (uses `guise::http`), so a `--features browser`-only
// build compiles it to empty instead of failing on the absent `http` module.
#![cfg(all(feature = "browser", feature = "http"))]

use guise::browser::{firefox_engine_major, launch_reynard};
use guise::fingerprint::cluster::{classify_observed, ObservedFingerprint};
use guise::fingerprint::{infer_initial_ttl, profile_os_network_stack, StealthProfile};
use guise::http::session_coherence::{
    persona_wire_self_probe, H2Profile, WireCapture, WireSelfProbe, FIREFOX_H2,
    FIREFOX_HEADER_ORDER,
};
use runtime_foxdriver::{launch_firefox_self_managed, FoxBrowserConfig, Page};
use std::time::Duration;

const PEET_HOME: &str = "https://tls.peet.ws/";

/// Render the `SETTINGS|WINDOW_UPDATE` prefix of an Akamai HTTP/2 fingerprint
/// from a guise [`H2Profile`] model: `id:value;…|increment`. The live Akamai
/// string additionally carries `|priority|pseudo-header-order` which the model
/// does not encode, so a live capture must START WITH this prefix.
fn model_akamai_settings_window(h2: &H2Profile) -> String {
    let settings = h2
        .settings
        .iter()
        .map(|(id, value)| format!("{id}:{value}"))
        .collect::<Vec<_>>()
        .join(";");
    format!("{settings}|{}", h2.initial_window_increment)
}

/// One browser's Layer-2 wire fingerprint as reported by tls.peet.ws.
#[derive(Debug, Default, Clone)]
struct WireFp {
    ja3_hash: Option<String>,
    ja4: Option<String>,
    peetprint_hash: Option<String>,
    akamai: Option<String>,
    user_agent: Option<String>,
    tcpip: Option<String>,
    /// Observed IP TTL of reynard's egress SYN as seen by peet (past NAT). The
    /// live signal for the Layer-2 TCP-OS coherence check.
    tcp_ttl: Option<u8>,
    /// Ordered, lowercased NON-pseudo request-header names from reynard's HTTP/2
    /// HEADERS frame (peet `http2.sent_frames`). The live signal for the
    /// header-order model differential. Empty when peet reported no h2 HEADERS.
    sent_headers: Vec<String>,
    /// The ordered TLS ClientHello cipher-suite list peet observed (`tls.ciphers`),
    /// verbatim (e.g. `"TLS_AES_128_GCM_SHA256 (0x1301)"`). This is the raw input the
    /// JA3/JA4 cipher hash is computed from, so when those hashes differ vs stock this
    /// list pinpoints the exact suite that drifted (a hash diff alone can't).
    ciphers: Vec<String>,
    /// The ordered TLS ClientHello extension list peet observed (`tls.extensions[].name`).
    /// Captured so an extension-set drift is localized the same way the cipher list does.
    extensions: Vec<String>,
    /// The full JA3 string (not just the hash): `ver,ciphers,exts,curves,points`. Recorded
    /// for diagnostics (its hash is GREASE-unstable run-to-run, so it is NOT asserted).
    ja3_str: Option<String>,
}

/// True for a GREASE value (RFC 8701): the 16 reserved code points `0x0a0a,0x1a1a,…0xfafa`
/// that Firefox/Chrome inject at a RANDOM position each handshake. peet renders them as a
/// `TLS_GREASE`/`GREASE` label or a bare `0x?a?a`. They MUST be filtered before comparing
/// two real-browser fingerprints, otherwise a same-browser diff flaps purely on the random
/// draw (which is exactly why an exact JA3 hash is the wrong cross-launch invariant).
fn is_grease(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    if n.contains("grease") {
        return true;
    }
    // Bare/embedded hex form 0xYaYa where the two nibble-bytes are equal and low-nibble a.
    for hx in [
        "0a0a", "1a1a", "2a2a", "3a3a", "4a4a", "5a5a", "6a6a", "7a7a", "8a8a", "9a9a", "aaaa",
        "baba", "caca", "dada", "eaea", "fafa",
    ] {
        if n.contains(hx) {
            return true;
        }
    }
    false
}

/// A browser's cipher/extension list with GREASE stripped, the GREASE-stable view two
/// real Firefoxes must agree on, and the realistic thing an anti-bot that "knows Firefox"
/// actually compares (it normalizes GREASE; it does not demand a byte-identical JA3).
fn degreased(list: &[String]) -> Vec<&str> {
    list.iter()
        .filter(|c| !is_grease(c))
        .map(String::as_str)
        .collect()
}

impl WireFp {
    fn from_json(v: &serde_json::Value) -> Self {
        let tls = &v["tls"];
        let s = |x: &serde_json::Value| x.as_str().map(|s| s.to_string());
        WireFp {
            ja3_hash: s(&tls["ja3_hash"]),
            ja4: s(&tls["ja4"]),
            peetprint_hash: s(&tls["peetprint_hash"]),
            akamai: s(&v["http2"]["akamai_fingerprint"]),
            user_agent: s(&v["user_agent"]),
            // The TCP/IP block is the Botforensics layer: ttl/window/os hints. Keep
            // the whole block compacted so the scorecard can show what OS our stack
            // presents at the packet layer (Linux build vs the persona's claimed OS).
            tcpip: (!v["tcpip"].is_null()).then(|| v["tcpip"].to_string()),
            // peet reports the egress TTL at tcpip.ip.ttl (as seen past NAT).
            tcp_ttl: v["tcpip"]["ip"]["ttl"]
                .as_u64()
                .and_then(|t| u8::try_from(t).ok()),
            sent_headers: parse_h2_sent_headers(v),
            ciphers: tls["ciphers"]
                .as_array()
                .map(|a| {
                    a.iter()
                        .filter_map(|c| c.as_str().map(str::to_string))
                        .collect()
                })
                .unwrap_or_default(),
            extensions: tls["extensions"]
                .as_array()
                .map(|a| {
                    a.iter()
                        .filter_map(|e| {
                            // peet renders extensions as objects ({name, data}) or bare strings.
                            e.get("name")
                                .and_then(|n| n.as_str())
                                .or_else(|| e.as_str())
                                .map(str::to_string)
                        })
                        .collect()
                })
                .unwrap_or_default(),
            ja3_str: s(&tls["ja3"]),
        }
    }
}

/// The symmetric difference of two ordered cipher lists, formatted for a panic/log:
/// what `a` (reynard) has that `b` (stock) lacks, and vice-versa. Pinpoints the exact
/// suite behind a JA3/JA4 cipher-hash drift instead of leaving it as an opaque hash.
fn cipher_diff(a: &[String], b: &[String]) -> String {
    let only_a: Vec<&str> = a
        .iter()
        .filter(|c| !b.contains(c))
        .map(String::as_str)
        .collect();
    let only_b: Vec<&str> = b
        .iter()
        .filter(|c| !a.contains(c))
        .map(String::as_str)
        .collect();
    format!("reynard-only={only_a:?} stock-only={only_b:?}")
}

/// Extract the ordered, lowercased non-pseudo request-header names from peet's
/// HTTP/2 HEADERS frame (`http2.sent_frames[].frame_type == "HEADERS"`,
/// `.headers` = `"name: value"` / `":pseudo: value"` strings). Pseudo-headers
/// (leading `:`) are dropped, their order is already validated via the Akamai
/// fingerprint's 4th segment; this captures the regular-header order.
fn parse_h2_sent_headers(v: &serde_json::Value) -> Vec<String> {
    let mut out = Vec::new();
    let Some(frames) = v["http2"]["sent_frames"].as_array() else {
        return out;
    };
    for frame in frames {
        if frame["frame_type"].as_str() != Some("HEADERS") {
            continue;
        }
        let Some(headers) = frame["headers"].as_array() else {
            continue;
        };
        for header in headers {
            let Some(line) = header.as_str() else {
                continue;
            };
            if line.starts_with(':') {
                continue; // pseudo-header, covered by the Akamai 4th segment
            }
            if let Some(name) = line.split(':').next() {
                let name = name.trim().to_ascii_lowercase();
                if !name.is_empty() {
                    out.push(name);
                }
            }
        }
    }
    out
}

/// Whether `observed` (already filtered to names the model knows) appears in the
/// `model` slot order as a relative subsequence. Over HTTP/2 a browser sends only
/// a subset of the canonical navigation headers (no `host`/`connection`: those
/// become `:authority` or are h2-forbidden), so the contract is "every header
/// the engine sent that the model knows about is in the model's relative order",
/// not a full-set match. Case-insensitive.
fn is_ordered_subsequence(observed: &[String], model: &[&str]) -> bool {
    let mut cursor = 0usize;
    for name in observed {
        match model[cursor..]
            .iter()
            .position(|slot| slot.eq_ignore_ascii_case(name))
        {
            Some(offset) => cursor += offset + 1,
            None => return false,
        }
    }
    true
}

/// Drive `page` to tls.peet.ws, fetch `/api/all` same-origin (promise kicked into a
/// global, then polled: `evaluate` does not await), and parse the wire fingerprint.
async fn capture_wire(page: &Page) -> anyhow::Result<WireFp> {
    page.goto(PEET_HOME)
        .await
        .map_err(|e| anyhow::anyhow!("nav peet: {e:?}"))?;
    // Kick off the same-origin fetch into a global.
    let _ = page
        .evaluate(
            "(function(){try{window.__peet='pending';\
             fetch('/api/all',{cache:'no-store'}).then(function(r){return r.json();})\
             .then(function(j){window.__peet=j;}).catch(function(e){window.__peet={error:String(e)};});\
             return 'started';}catch(e){return 'err:'+String(e);}})()",
        )
        .await;
    // Poll the global until the fetch resolves (≤25s).
    for _ in 0..25 {
        tokio::time::sleep(Duration::from_millis(1000)).await;
        let got = page
            .evaluate("(function(){if(!window.__peet||window.__peet==='pending')return null;return JSON.stringify(window.__peet);})()")
            .await;
        if let Ok(ev) = got {
            if let Ok(Some(s)) = ev.into_value::<Option<String>>() {
                let v: serde_json::Value = serde_json::from_str(&s)
                    .map_err(|e| anyhow::anyhow!("parse peet json: {e}"))?;
                if v.get("error").is_some() {
                    return Err(anyhow::anyhow!("peet fetch error: {}", v["error"]));
                }
                return Ok(WireFp::from_json(&v));
            }
        }
    }
    Err(anyhow::anyhow!("peet fetch did not resolve in 25s"))
}

/// G066/G014, model ↔ engine differential: guise's `FIREFOX_H2` model must
/// match reynard's REAL emitted HTTP/2 fingerprint on the wire. **in full**,
/// all four Akamai segments (`SETTINGS|WINDOW_UPDATE|PRIORITY|pseudo-headers`).
/// The whole L2 coherence gate trusts `FIREFOX_H2`; this proves it is the truth,
/// not a guess. (This is exactly the check that caught `FIREFOX_H2` omitting
/// `2:0`.) Now that the model encodes the PRIORITY field and pseudo-header order
/// too, the assertion is full-string equality, not a prefix match, so a drift
/// in the third or fourth segment fails here instead of slipping through.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reynard_h2_fingerprint_matches_guise_model() {
    let Ok(reynard_bin) = std::env::var("REYNARD_BIN") else {
        eprintln!("SKIP reynard_h2_model: set REYNARD_BIN to run");
        return;
    };
    if std::env::var("DISPLAY").is_err() {
        eprintln!("SKIP reynard_h2_model: no DISPLAY");
        return;
    }

    let reynard = launch_reynard(&reynard_bin, &StealthProfile::FirefoxLinux, false)
        .await
        .expect("launch reynard");
    let rey = match capture_wire(&reynard).await {
        Ok(fp) => fp,
        Err(e) => {
            eprintln!("SKIP reynard_h2_model: capture failed (network?): {e:?}");
            let _ = reynard.close().await;
            return;
        }
    };
    let _ = reynard.close().await;

    let live = rey
        .akamai
        .expect("tls.peet.ws returned no http2.akamai_fingerprint");
    let prefix = model_akamai_settings_window(&FIREFOX_H2);
    let full = FIREFOX_H2.akamai_fingerprint();
    eprintln!("[h2-model] guise FIREFOX_H2 full model = {full}");
    eprintln!("[h2-model] reynard live akamai         = {live}");

    // First diagnostic: the SETTINGS+WINDOW_UPDATE prefix must match (localizes a
    // settings drift). Then the stronger claim: the FULL four-segment Akamai
    // string is byte-identical, proving the PRIORITY field and pseudo-header
    // order in the model are the wire truth too.
    assert!(
        live.starts_with(&prefix),
        "guise FIREFOX_H2 SETTINGS+WINDOW_UPDATE ({prefix}) does not prefix reynard's \
         live HTTP/2 Akamai ({live}), the L2 model's first two segments drifted"
    );
    assert_eq!(
        live, full,
        "guise FIREFOX_H2 full Akamai model ({full}) != reynard's live wire ({live}). \
         the PRIORITY field or pseudo-header order has drifted from the engine"
    );
}

/// G021/G063, live TCP-OS coherence: reynard's REAL egress TTL (measured by
/// tls.peet.ws past NAT) must de-hop to the FirefoxLinux persona's expected
/// initial TTL (64, Linux). Validates the `os_network` model against the wire
/// with no raw socket, peet does the measurement. This is the live arm of the
/// L2 coherence work; a Windows persona egressing this Linux host would fail it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reynard_egress_tcp_os_matches_persona() {
    let Ok(reynard_bin) = std::env::var("REYNARD_BIN") else {
        eprintln!("SKIP reynard_tcp_os: set REYNARD_BIN to run");
        return;
    };
    if std::env::var("DISPLAY").is_err() {
        eprintln!("SKIP reynard_tcp_os: no DISPLAY");
        return;
    }

    let reynard = launch_reynard(&reynard_bin, &StealthProfile::FirefoxLinux, false)
        .await
        .expect("launch reynard");
    let rey = match capture_wire(&reynard).await {
        Ok(fp) => fp,
        Err(e) => {
            eprintln!("SKIP reynard_tcp_os: capture failed (network?): {e:?}");
            let _ = reynard.close().await;
            return;
        }
    };
    let _ = reynard.close().await;

    let Some(ttl) = rey.tcp_ttl else {
        eprintln!("SKIP reynard_tcp_os: peet did not report tcpip.ip.ttl (endpoint shape?)");
        return;
    };
    let observed_initial = infer_initial_ttl(ttl);
    let expected = profile_os_network_stack(StealthProfile::FirefoxLinux).initial_ttl;
    eprintln!(
        "[tcp-os] reynard egress TTL={ttl} -> initial {observed_initial}; FirefoxLinux expects {expected}"
    );

    assert_eq!(
        observed_initial, expected,
        "reynard's live egress TTL {ttl} de-hops to initial {observed_initial}, but the \
         FirefoxLinux persona's TCP stack expects {expected}, a Layer-2 TCP-OS incoherence \
         (host OS != persona OS, or a TTL-rewriting middlebox)"
    );
}

/// X049, the unified operator self-probe, proven live: feed BOTH observed
/// layers (egress TTL + Akamai H2) from one real reynard capture into
/// `persona_wire_self_probe` and assert the FirefoxLinux persona is coherent.
/// This dogfoods the one-call gate an operator runs to answer "will my egress
/// betray this persona?" against the actual wire, not a hand-assembled check.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reynard_wire_self_probe_is_coherent() {
    let Ok(reynard_bin) = std::env::var("REYNARD_BIN") else {
        eprintln!("SKIP reynard_self_probe: set REYNARD_BIN to run");
        return;
    };
    if std::env::var("DISPLAY").is_err() {
        eprintln!("SKIP reynard_self_probe: no DISPLAY");
        return;
    }

    let reynard = launch_reynard(&reynard_bin, &StealthProfile::FirefoxLinux, false)
        .await
        .expect("launch reynard");
    let rey = match capture_wire(&reynard).await {
        Ok(fp) => fp,
        Err(e) => {
            eprintln!("SKIP reynard_self_probe: capture failed (network?): {e:?}");
            let _ = reynard.close().await;
            return;
        }
    };
    let _ = reynard.close().await;

    let capture = WireCapture {
        observed_ttl: rey.tcp_ttl,
        akamai_fingerprint: rey.akamai.clone(),
        // peet's capture here yields TTL + Akamai but no JA4T; the self-probe
        // compares only the layers present, so this validates TTL+Akamai
        // coherence exactly as it did before the JA4T field was added (X049).
        observed_ja4t: None,
    };
    // The capture must carry at least one layer, or the probe is Unmeasured and
    // proves nothing (surface that as a skip, never a false pass).
    if capture.is_empty() {
        eprintln!("SKIP reynard_self_probe: peet reported neither TTL nor Akamai");
        return;
    }
    let verdict = persona_wire_self_probe(StealthProfile::FirefoxLinux, &capture);
    eprintln!("[self-probe] capture={capture:?} -> {verdict:?}");
    assert_eq!(
        verdict,
        WireSelfProbe::Coherent,
        "reynard's live egress is incoherent with the FirefoxLinux persona at the wire layer"
    );
}

/// G050 (third transport leg), header-order model ↔ engine differential:
/// reynard's REAL HTTP/2 request-header order must agree with guise's
/// `FIREFOX_HEADER_ORDER` model. Completes the transport-validation trilogy
/// (TLS byte-identical + Akamai H2 full-string + header order) against the live
/// engine. Sound contract: over h2 the engine sends only a subset of the
/// canonical navigation headers, so every header reynard sent that the model
/// knows must appear in the model's RELATIVE order (a subsequence), and at least
/// the stable Firefox markers (`user-agent` before `accept` before
/// `accept-language` before `accept-encoding`) must all be present.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reynard_header_order_matches_firefox_model() {
    let Ok(reynard_bin) = std::env::var("REYNARD_BIN") else {
        eprintln!("SKIP reynard_header_order: set REYNARD_BIN to run");
        return;
    };
    if std::env::var("DISPLAY").is_err() {
        eprintln!("SKIP reynard_header_order: no DISPLAY");
        return;
    }

    let reynard = launch_reynard(&reynard_bin, &StealthProfile::FirefoxLinux, false)
        .await
        .expect("launch reynard");
    let rey = match capture_wire(&reynard).await {
        Ok(fp) => fp,
        Err(e) => {
            eprintln!("SKIP reynard_header_order: capture failed (network?): {e:?}");
            let _ = reynard.close().await;
            return;
        }
    };
    let _ = reynard.close().await;

    eprintln!(
        "[hdr-order] reynard sent (non-pseudo) = {:?}",
        rey.sent_headers
    );
    if rey.sent_headers.is_empty() {
        eprintln!("SKIP reynard_header_order: peet reported no http2.sent_frames HEADERS");
        return;
    }

    // Keep only the headers the model knows about, preserving reynard's order.
    let known: Vec<String> = rey
        .sent_headers
        .iter()
        .filter(|name| {
            FIREFOX_HEADER_ORDER
                .slots
                .iter()
                .any(|slot| slot.eq_ignore_ascii_case(name))
        })
        .cloned()
        .collect();
    eprintln!("[hdr-order] model-known subset (in reynard order) = {known:?}");
    assert!(
        !known.is_empty(),
        "reynard sent headers {:?} but none are in the Firefox model, parse or model drift",
        rey.sent_headers
    );

    assert!(
        is_ordered_subsequence(&known, FIREFOX_HEADER_ORDER.slots),
        "reynard's live header order {known:?} is not a subsequence of the Firefox model \
         {:?}, the header-order model has drifted from the engine",
        FIREFOX_HEADER_ORDER.slots
    );

    // The four Accept-family / UA markers are stable across Firefox builds; all
    // must be present (a missing one would mean a parse miss, not a real engine).
    for marker in ["user-agent", "accept", "accept-language", "accept-encoding"] {
        assert!(
            known.iter().any(|h| h == marker),
            "reynard's captured headers {known:?} are missing the stable marker {marker:?}"
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reynard_tls_matches_stock_firefox() {
    let Ok(reynard_bin) = std::env::var("REYNARD_BIN") else {
        eprintln!("SKIP tls_fingerprint: set REYNARD_BIN to run");
        return;
    };
    if std::env::var("DISPLAY").is_err() {
        eprintln!("SKIP tls_fingerprint: no DISPLAY");
        return;
    }

    let reynard = launch_reynard(&reynard_bin, &StealthProfile::FirefoxLinux, false)
        .await
        .expect("launch reynard");
    let rey = match capture_wire(&reynard).await {
        Ok(fp) => fp,
        Err(e) => {
            eprintln!("SKIP tls_fingerprint: reynard capture failed (network?): {e:?}");
            let _ = reynard.close().await;
            return;
        }
    };
    let _ = reynard.close().await;

    eprintln!("\n[tls] reynard JA3={:?}\n[tls] reynard JA4={:?}\n[tls] reynard Akamai(H2)={:?}\n[tls] reynard peetprint={:?}\n[tls] reynard UA={:?}\n[tls] reynard tcpip={:?}",
        rey.ja3_hash, rey.ja4, rey.akamai, rey.peetprint_hash, rey.user_agent, rey.tcpip);

    // Stock reference (optional): drive a real FF to the same endpoint and diff.
    let stock = if let Ok(stock_bin) = std::env::var("STEALTH_FIREFOX") {
        let scfg = FoxBrowserConfig {
            headless: false,
            viewport_width: 1280,
            viewport_height: 720,
            executable_path: Some(stock_bin),
            ..Default::default()
        };
        match launch_firefox_self_managed(scfg).await {
            Ok(p) => {
                let fp = capture_wire(&p).await.ok();
                let _ = p.close().await;
                fp
            }
            Err(e) => {
                eprintln!("[tls] stock launch failed: {e:?}");
                None
            }
        }
    } else {
        eprintln!("[tls] STEALTH_FIREFOX unset, recording reynard only, no stock diff");
        None
    };

    if let Some(stk) = &stock {
        eprintln!("\n[tls] stock  JA3={:?}\n[tls] stock  JA4={:?}\n[tls] stock  Akamai(H2)={:?}\n[tls] stock  peetprint={:?}",
            stk.ja3_hash, stk.ja4, stk.akamai, stk.peetprint_hash);
        let ja3_match = rey.ja3_hash.is_some() && rey.ja3_hash == stk.ja3_hash;
        let ja4_match = rey.ja4.is_some() && rey.ja4 == stk.ja4;
        let akamai_match = rey.akamai.is_some() && rey.akamai == stk.akamai;
        eprintln!(
            "[tls] MATCH vs stock FF. JA3:{} JA4:{} Akamai/H2:{}",
            ja3_match, ja4_match, akamai_match
        );
    }

    // G048–G051 anti-uniqueness self-check: classify reynard's OWN emitted shape
    // against the bundled real-browser catalogue on the STABLE axes only. JA4
    // (GREASE-stripped + sorted by construction) and Akamai-H2 (GREASE-free). JA3
    // and peetprint are deliberately excluded: their raw values carry Firefox's
    // per-handshake GREASE draw, so feeding them would flap membership exactly as
    // an exact-JA3-hash contract does (the very reason this test asserts on
    // degreased sets, not raw hashes). reynard IS Firefox-150, so it must land in
    // the firefox-150-linux cluster, a Distinguishable verdict means the engine
    // drifted off the FF-150 wire shape or the catalogue lost that target.
    let cluster = classify_observed(&ObservedFingerprint {
        ja4: rey.ja4.clone(),
        akamai_h2: rey.akamai.clone(),
        ..Default::default()
    });
    eprintln!(
        "[tls] cluster self-check: in_cluster={} labels={:?}",
        cluster.is_in_cluster(),
        cluster.cluster_labels()
    );

    // Persist for the stack scorecard.
    let dir = std::env::var("STACK_BENCH_DIR").unwrap_or_else(|_| "/tmp/stack-bench".into());
    if std::fs::create_dir_all(&dir).is_ok() {
        let json = serde_json::json!({
            "benchmark": "tls_fingerprint",
            "endpoint": "tls.peet.ws/api/all",
            // Anti-uniqueness: which real-browser cluster reynard's emitted JA4+Akamai
            // collides with (empty => distinguishable from the bundled catalogue).
            "cluster_in_real_browser": cluster.is_in_cluster(),
            "cluster_labels": cluster.cluster_labels(),
            "reynard": {
                "ja3_hash": rey.ja3_hash, "ja3": rey.ja3_str, "ja4": rey.ja4, "akamai_h2": rey.akamai,
                "peetprint_hash": rey.peetprint_hash, "user_agent": rey.user_agent,
                "tcpip": rey.tcpip,
                "degreased_ciphers": degreased(&rey.ciphers), "degreased_extensions": degreased(&rey.extensions),
            },
            "stock": stock.as_ref().map(|s| serde_json::json!({
                "ja3_hash": s.ja3_hash, "ja3": s.ja3_str, "ja4": s.ja4, "akamai_h2": s.akamai,
                "peetprint_hash": s.peetprint_hash,
                "degreased_ciphers": degreased(&s.ciphers), "degreased_extensions": degreased(&s.extensions),
            })),
            // Raw JA3/JA4 hashes vary per-handshake (GREASE), so the AUTHORITATIVE match
            // signal is the GREASE-stripped cipher+extension equality the test asserts on.
            "degreased_ciphers_match_stock": stock.as_ref().map(|s| degreased(&rey.ciphers) == degreased(&s.ciphers)),
            "degreased_extensions_match_stock": stock.as_ref().map(|s| degreased(&rey.extensions) == degreased(&s.extensions)),
            "akamai_matches_stock": stock.as_ref().map(|s| rey.akamai.is_some() && rey.akamai == s.akamai),
            // Kept for humans; NOT the pass signal (GREASE-variant).
            "ja3_hash_matches_stock_this_run": stock.as_ref().map(|s| rey.ja3_hash.is_some() && rey.ja3_hash == s.ja3_hash),
            "ja4_matches_stock_this_run": stock.as_ref().map(|s| rey.ja4.is_some() && rey.ja4 == s.ja4),
        });
        let path = format!("{dir}/tls_fingerprint.json");
        match std::fs::write(&path, serde_json::to_vec_pretty(&json).unwrap()) {
            Ok(()) => eprintln!("[tls] wrote {path}"),
            Err(e) => eprintln!("[tls] WARN could not write {path}: {e}"),
        }
    }

    // We at least need reynard's own wire fingerprint to have been read; a network
    // failure skips loud above. A present-but-empty JA3 means the endpoint changed
    // shape (surface that rather than passing silently).
    assert!(
        rey.ja3_hash.is_some() && rey.ja4.is_some(),
        "tls.peet.ws returned no JA3/JA4 for reynard, endpoint shape changed or capture broke"
    );

    // The anti-uniqueness self-check is unconditional (no stock FF needed): reynard
    // IS Firefox-150, so its GREASE-stable JA4 + Akamai MUST collide with the
    // populated firefox-150-linux cluster. Failure = the emitted L2 shape drifted
    // off real FF-150 (a fresh tell), or the catalogue lost the FF-150 target.
    assert!(
        cluster.is_in_cluster(),
        "reynard's emitted JA4+Akamai matched no bundled real-browser cluster. \
         L2 wire shape drifted off FF-150 or the firefox-150-linux target is missing. \
         verdict={cluster:?}"
    );
    assert!(
        cluster.cluster_labels().contains(&"firefox-150-linux"),
        "reynard must be in the firefox-150-linux cluster specifically; got {:?}",
        cluster.cluster_labels()
    );

    // THE test's namesake claim, now ENFORCED against the RIGHT invariant. Live
    // characterization (2026-06-12) proved exact JA3/JA4 *hash* equality is the WRONG
    // contract: stock FF-150's own JA3 varies launch-to-launch (e.g. 0e76c7e9… → aa335cae…)
    // because Firefox injects a GREASE value (RFC 8701) at a random position in BOTH the
    // cipher and extension lists each handshake, so demanding a byte-identical JA3 would
    // make this test flap ~half the time for a perfectly real browser. What a same-engine,
    // same-version Firefox MUST agree on, and what an anti-bot that "knows Firefox" actually
    // compares, is the GREASE-stripped wire identity: the ordered real-cipher list, the
    // ordered real-extension list, and the (GREASE-free) Akamai HTTP/2 fingerprint. Those
    // are pure network-layer (no JS-persona dependence), so a diff there is the categorical
    // L2 advantage failing, a real tell, while the GREASE draw is not. The raw JA3/JA4
    // hashes are still recorded to the scorecard for humans; they are not asserted.
    // Skips loudly (never a false fail) when STEALTH_FIREFOX is unset.
    if let Some(stk) = &stock {
        // Version guard (Vector 12 robustness): the GREASE-stripped cipher/extension/H2
        // lists are Firefox-VERSION-specific, e.g. FF-151 dropped 0xc009
        // (TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA), 17→16 ciphers. reynard's engine is
        // PINNED (FF-150) while the fleet's stock Firefox auto-updates AHEAD of it, so a
        // blind live-stock equality FALSELY flags a Firefox-version delta as a reynard
        // ClientHello "tell". When the stock's engine major != reynard's, skip the
        // live-stock equality (loudly) and rely on the firefox-150-linux CLUSTER
        // assertion above, which enforces reynard's wire == the wire-measured FF-150
        // catalogue (JA4 cipher-hash + Akamai), the version-correct ground truth. So
        // coherence stays HARD-enforced; only the version-invalid live diff is gated.
        // Unknown major on either side → enforce (don't claim a skew we can't prove, so a
        // genuine same-version drift still fails).
        let rey_major = firefox_engine_major(&reynard_bin);
        let stk_major = std::env::var("STEALTH_FIREFOX")
            .ok()
            .and_then(|b| firefox_engine_major(&b));
        let versions_match = match (rey_major, stk_major) {
            (Some(r), Some(s)) => r == s,
            _ => true,
        };
        if !versions_match {
            eprintln!(
                "[tls] VERSION SKEW, reynard engine major {rey_major:?} != stock {stk_major:?}: \
                 the live-stock cipher/ext/H2 diff is a Firefox-VERSION delta (FF-151 dropped \
                 0xc009 vs FF-150), NOT a reynard tell. Skipping live-stock equality; the \
                 firefox-150-linux cluster assertion above enforces FF-150 wire coherence. For the \
                 live differential too, point STEALTH_FIREFOX at a version-matched stock (FF-{}).",
                rey_major.map_or_else(|| "?".to_string(), |m| m.to_string())
            );
        }
        let rey_cs = degreased(&rey.ciphers);
        let stk_cs = degreased(&stk.ciphers);
        let rey_ex = degreased(&rey.extensions);
        let stk_ex = degreased(&stk.extensions);
        eprintln!(
            "[tls] degreased ciphers   reynard={} stock={}",
            rey_cs.len(),
            stk_cs.len()
        );
        eprintln!(
            "[tls] degreased exts      reynard={} stock={}",
            rey_ex.len(),
            stk_ex.len()
        );
        eprintln!(
            "[tls] JA3 hash (GREASE-variant, not asserted) reynard={:?} stock={:?}",
            rey.ja3_hash, stk.ja3_hash
        );

        // Cipher list, ordered, GREASE-stripped. (This is the contract that caught the real
        // 0xc009 / TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA omission on 2026-06-12.)
        if !stk.ciphers.is_empty() {
            if rey_cs != stk_cs {
                eprintln!(
                    "[tls] CIPHER DIFF: {}",
                    cipher_diff(&rey.ciphers, &stk.ciphers)
                );
            }
            if versions_match {
                assert_eq!(
                    rey_cs, stk_cs,
                    "reynard's TLS cipher list (GREASE-stripped) != stock Firefox, a ClientHello tell. {}",
                    cipher_diff(&rey.ciphers, &stk.ciphers)
                );
            }
        } else {
            eprintln!("[tls] stock ciphers absent, skipping cipher-set equality (stock capture incomplete)");
        }

        // Extension list, ordered, GREASE-stripped. Firefox does not randomize extension
        // order (only the GREASE insertion point), so once degreased this is stable.
        if !stk.extensions.is_empty() {
            if rey_ex != stk_ex {
                eprintln!(
                    "[tls] EXT DIFF: {}",
                    cipher_diff(&rey.extensions, &stk.extensions)
                );
            }
            if versions_match {
                assert_eq!(
                    rey_ex, stk_ex,
                    "reynard's TLS extension list (GREASE-stripped) != stock Firefox, a ClientHello tell. {}",
                    cipher_diff(&rey.extensions, &stk.extensions)
                );
            }
        } else {
            eprintln!("[tls] stock extensions absent, skipping extension-set equality (stock capture incomplete)");
        }

        // Akamai HTTP/2 fingerprint, measured stable across both live runs; assert
        // equality (also version-gated: H2 SETTINGS can shift across major versions).
        if stk.akamai.is_some() {
            if versions_match {
                assert_eq!(
                    rey.akamai, stk.akamai,
                    "reynard Akamai HTTP/2 fingerprint != stock Firefox, a SETTINGS/WINDOW_UPDATE/priority tell"
                );
            }
        } else {
            eprintln!(
                "[tls] stock Akamai/H2 absent, skipping H2 equality (stock capture incomplete)"
            );
        }
    } else {
        eprintln!(
            "[tls] STEALTH_FIREFOX unset, recorded reynard's wire fingerprint only; set \
             STEALTH_FIREFOX=/path/to/stock/firefox to ENFORCE the degreased cipher/ext/H2 == stock claim"
        );
    }
}
