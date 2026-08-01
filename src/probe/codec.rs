//! Media-codec coherence probe, the media-stack analog of the capability- and
//! error-subsystem coherence probes in [`super::redteam`].
//!
//! The supported-codec matrix (`HTMLMediaElement.canPlayType` +
//! `MediaSource.isTypeSupported`) is one of the surfaces FingerprintJS/CreepJS
//! and the commercial anti-bot vendors weight most heavily, precisely because it
//! is hard to fake coherently: every real consumer browser, desktop or mobile,
//! Chrome or Firefox or Safari, decodes the H.264/AAC/MP4 baseline (via the OS
//! decoder, system ffmpeg, or the bundled OpenH264), and exposes Media Source
//! Extensions and the EME entry point. A browser that reports it cannot play
//! H.264 is not a consumer browser: it is a stripped CI image, a `--headless`
//! build without the media stack, or a container with no ffmpeg.
//!
//! The differential gate ([`super::oracle`]) cannot catch this on its own: it
//! diffs two browsers driven through the *same* engine, so a codec matrix that
//! is identically broken on both sides passes silently. This probe asserts the
//! **absolute** consumer baseline, so a stripped media stack is flagged even
//! when the disguise is internally self-consistent.
//!
//! Ground truth (live headless Firefox 151 on a GPU+ffmpeg host, the
//! `headless_tells` diagnostic): `h264 "probably"`, `aac "probably"`,
//! `vp9 "probably"`, `opus "probably"`, `mp3 "maybe"`, `mseH264 true`,
//! `eme "function"`: a healthy matrix. On a codec-less cloud image the same
//! surfaces collapse to `""`/`false`, which is exactly what this probe catches.
//!
//! Every classifier is pure (`fn(&serde_json::Value) -> ProbeOutcome`) and
//! unit-tested below; the JS may return a Promise for async surfaces such as
//! `MediaCapabilities.decodingInfo`, which the BiDi runtime awaits.

use super::{Determinism, Probe, ProbeOutcome, Severity};

/// The supported-codec matrix as a single synchronous object. `canPlayType`
/// returns `""` / `"maybe"` / `"probably"`; `MediaSource.isTypeSupported`
/// returns a bool; `requestMediaKeySystemAccess` is reported by `typeof` (its
/// *presence*, the async availability of a specific CDM is deliberately out of
/// scope for a sync probe, so we never overclaim Widevine provisioning).
const MEDIA_CODEC_COHERENCE_JS: &str = r#"(function(){function v(tag,t){try{return document.createElement(tag).canPlayType(t)||'';}catch(e){return 'ERR';}}function m(t){try{return !!(window.MediaSource&&MediaSource.isTypeSupported(t));}catch(e){return false;}}var n=navigator;function mc(t){if(!n.mediaCapabilities||typeof n.mediaCapabilities.decodingInfo!=='function')return Promise.resolve(false);return n.mediaCapabilities.decodingInfo({type:'file',audio:t}).then(function(r){return !!r&&r.supported===true;}).catch(function(){return false;});}return Promise.all([mc({contentType:'audio/mp4; codecs="mp4a.40.2"'}),mc({contentType:'audio/ogg; codecs="opus"'})]).then(function(mcRes){return {ua:n.userAgent,h264:v('video','video/mp4; codecs="avc1.42E01E"'),aac:v('audio','audio/mp4; codecs="mp4a.40.2"'),mp4:v('video','video/mp4'),vp9:v('video','video/webm; codecs="vp9"'),opus:v('audio','audio/ogg; codecs="opus"'),mp3:v('audio','audio/mpeg'),mseH264:m('video/mp4; codecs="avc1.42E01E"'),eme:(typeof n.requestMediaKeySystemAccess),mcAac:mcRes[0],mcOpus:mcRes[1]};});})()"#;

/// The media-codec coherence probe set. Folded into [`super::catalogue::probes_for`]
/// for every family (the consumer baseline is family-independent).
pub(super) fn codec_probes() -> Vec<Probe> {
    vec![Probe {
        name: "media: supported-codec matrix matches a consumer browser (H.264/AAC/MSE/EME)",
        js: MEDIA_CODEC_COHERENCE_JS,
        severity: Severity::High,
        classifier: classify_media_codec_coherence,
        determinism: Determinism::Deterministic,
    }]
}

/// `canPlayType` reports support as `"maybe"` or `"probably"`; `""` (and our
/// `"ERR"` sentinel) mean unsupported. A real consumer browser never returns
/// `""` for the H.264/AAC/MP4 baseline.
fn can_play(v: &serde_json::Value, key: &str) -> bool {
    matches!(
        v.get(key).and_then(|x| x.as_str()),
        Some("maybe") | Some("probably")
    )
}

fn classify_media_codec_coherence(v: &serde_json::Value) -> ProbeOutcome {
    let Some(_ua) = v.get("ua").and_then(|x| x.as_str()) else {
        return ProbeOutcome::ProbeError("codec probe returned no ua".into());
    };

    let h264 = can_play(v, "h264");
    let aac = can_play(v, "aac");
    let mp4 = can_play(v, "mp4");
    let vp9 = can_play(v, "vp9");
    let opus = can_play(v, "opus");
    let mp3 = can_play(v, "mp3");
    let mse_h264 = v.get("mseH264").and_then(|x| x.as_bool()).unwrap_or(false);
    let eme = v.get("eme").and_then(|x| x.as_str()) == Some("function");
    let mc_aac = v.get("mcAac").and_then(|x| x.as_bool()).unwrap_or(false);
    let mc_opus = v.get("mcOpus").and_then(|x| x.as_bool()).unwrap_or(false);

    // The H.264 / AAC / MP4-container / MSE block is the consumer-web baseline:
    // the single most common video+audio codec pair and the playback path every
    // streaming site uses. No real consumer browser lacks the whole set.
    let h264_stack = [h264, aac, mp4, mse_h264];
    let h264_present = h264_stack.iter().filter(|x| **x).count();

    // VP9 / Opus / MP3 ship in the bundled decoders (ffvpx / libvpx / libopus)
    // of every Firefox and Chrome build, including minimal ones, so missing
    // *these* indicates an even more stripped build than missing H.264.
    let baseline = [vp9, opus, mp3];
    let baseline_present = baseline.iter().filter(|x| **x).count();

    if h264_present == 0 && baseline_present == 0 {
        return ProbeOutcome::Critical(
            "no decodable audio/video codecs (H.264, AAC, VP9, Opus, MP3 all absent). \
             a sandbox-grade / media-less build, not a consumer browser"
                .into(),
        );
    }

    if h264_present == 0 {
        return ProbeOutcome::Critical(
            "the entire H.264/AAC/MP4/MSE stack is unsupported, no consumer browser \
             fails the most common web video+audio codecs; stripped/headless media build"
                .into(),
        );
    }

    // Partial breaks: some of the core present, some missing. Name what is gone.
    let mut missing: Vec<&str> = Vec::new();
    if !h264 {
        missing.push("H.264(canPlayType)");
    }
    if !aac {
        missing.push("AAC");
    }
    if !mse_h264 {
        missing.push("MSE:H.264");
    }
    if !mp4 {
        missing.push("video/mp4");
    }
    if !missing.is_empty() {
        return ProbeOutcome::Drift(format!(
            "consumer codec baseline incomplete, missing {}; a real desktop browser \
             supports all of them",
            missing.join(", ")
        ));
    }

    if baseline_present < baseline.len() {
        let mut bmiss: Vec<&str> = Vec::new();
        if !vp9 {
            bmiss.push("VP9");
        }
        if !opus {
            bmiss.push("Opus");
        }
        if !mp3 {
            bmiss.push("MP3");
        }
        return ProbeOutcome::Drift(format!(
            "bundled-decoder codec(s) missing: {}; every Firefox/Chrome build ships these",
            bmiss.join(", ")
        ));
    }

    if !mc_aac && !mc_opus {
        // MediaCapabilities absent entirely, or decodingInfo rejected both core
        // audio codecs. That is consistent with a very stripped build but not
        // a consumer desktop browser.
        return ProbeOutcome::Drift(
            "MediaCapabilities.decodingInfo absent or denies core audio codecs. \
             missing modern media-stack signal"
                .into(),
        );
    }
    if !mc_aac || !mc_opus {
        let missing = [
            (!mc_aac).then_some("AAC via MediaCapabilities"),
            (!mc_opus).then_some("Opus via MediaCapabilities"),
        ]
        .into_iter()
        .flatten()
        .collect::<Vec<_>>()
        .join(", ");
        return ProbeOutcome::Drift(format!("MediaCapabilities denies a core codec. {missing}"));
    }

    if !eme {
        return ProbeOutcome::Drift(
            "navigator.requestMediaKeySystemAccess absent: EME is present in every \
             consumer browser; its absence is a stripped-build tell"
                .into(),
        );
    }

    ProbeOutcome::Pass
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const FF_UA: &str = "Mozilla/5.0 (X11; Linux x86_64; rv:151.0) Gecko/20100101 Firefox/151.0";
    const CR_UA: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36";

    /// The exact matrix the live `headless_tells` diagnostic dumped from a real
    /// headless Firefox 151 (the probe must call this healthy).
    fn healthy(ua: &str) -> serde_json::Value {
        json!({
            "ua": ua, "h264": "probably", "aac": "probably", "mp4": "maybe",
            "vp9": "probably", "opus": "probably", "mp3": "maybe",
            "mseH264": true, "eme": "function", "mcAac": true, "mcOpus": true
        })
    }

    #[test]
    fn codec_set_is_one_named_probe_with_js() {
        let p = codec_probes();
        assert_eq!(p.len(), 1);
        assert!(!p[0].js.is_empty());
        assert!(p[0].name.contains("codec"));
    }

    #[test]
    fn codec_js_is_balanced_and_await_free() {
        // The BiDi runtime awaits returned Promises; the expression itself must not
        // use the `await` keyword (which is illegal at the top level of a function
        // expression here and would require an async wrapper).
        assert!(!MEDIA_CODEC_COHERENCE_JS.contains("await"));
        let mut depth = 0i32;
        for c in MEDIA_CODEC_COHERENCE_JS.chars() {
            match c {
                '(' | '{' | '[' => depth += 1,
                ')' | '}' | ']' => depth -= 1,
                _ => {}
            }
            assert!(depth >= 0, "unbalanced");
        }
        assert_eq!(depth, 0, "unbalanced brackets in codec JS");
    }

    #[test]
    fn healthy_firefox_matrix_passes() {
        assert_eq!(
            classify_media_codec_coherence(&healthy(FF_UA)),
            ProbeOutcome::Pass
        );
    }

    #[test]
    fn healthy_chrome_matrix_passes() {
        assert_eq!(
            classify_media_codec_coherence(&healthy(CR_UA)),
            ProbeOutcome::Pass
        );
    }

    #[test]
    fn probably_and_maybe_both_count_as_supported() {
        // canPlayType "maybe" is still support (must not be flagged).
        let mut v = healthy(FF_UA);
        v["h264"] = json!("maybe");
        v["aac"] = json!("maybe");
        assert_eq!(classify_media_codec_coherence(&v), ProbeOutcome::Pass);
    }

    #[test]
    fn fully_stripped_media_stack_is_critical() {
        // Codec-less cloud image: every canPlayType "" and MSE false.
        let v = json!({
            "ua": FF_UA, "h264": "", "aac": "", "mp4": "", "vp9": "",
            "opus": "", "mp3": "", "mseH264": false, "eme": "undefined",
            "mcAac": false, "mcOpus": false
        });
        match classify_media_codec_coherence(&v) {
            ProbeOutcome::Critical(m) => {
                assert!(m.contains("sandbox-grade") || m.contains("media-less"))
            }
            o => panic!("expected Critical, got {o:?}"),
        }
    }

    #[test]
    fn h264_stack_gone_but_webm_present_is_critical() {
        // The H.264/AAC/MP4/MSE block fully absent while VP9/Opus survive, a
        // Firefox without system ffmpeg / OpenH264. Still not a consumer browser.
        let v = json!({
            "ua": FF_UA, "h264": "", "aac": "", "mp4": "", "vp9": "probably",
            "opus": "probably", "mp3": "maybe", "mseH264": false, "eme": "function",
            "mcAac": true, "mcOpus": true
        });
        match classify_media_codec_coherence(&v) {
            ProbeOutcome::Critical(m) => assert!(m.contains("H.264")),
            o => panic!("expected Critical, got {o:?}"),
        }
    }

    #[test]
    fn partial_core_break_is_drift() {
        // H.264 plays but MSE/H.264 is off (a partial, suspicious break).
        let mut v = healthy(FF_UA);
        v["mseH264"] = json!(false);
        match classify_media_codec_coherence(&v) {
            ProbeOutcome::Drift(m) => assert!(m.contains("MSE:H.264")),
            o => panic!("expected Drift, got {o:?}"),
        }
    }

    #[test]
    fn missing_aac_only_is_drift() {
        let mut v = healthy(CR_UA);
        v["aac"] = json!("");
        match classify_media_codec_coherence(&v) {
            ProbeOutcome::Drift(m) => assert!(m.contains("AAC")),
            o => panic!("expected Drift, got {o:?}"),
        }
    }

    #[test]
    fn core_ok_but_baseline_decoder_missing_is_drift() {
        // H.264 stack fine, but VP9 absent (an oddly stripped bundled decoder).
        let mut v = healthy(FF_UA);
        v["vp9"] = json!("");
        match classify_media_codec_coherence(&v) {
            ProbeOutcome::Drift(m) => assert!(m.contains("VP9")),
            o => panic!("expected Drift, got {o:?}"),
        }
    }

    #[test]
    fn core_ok_but_eme_absent_is_drift() {
        let mut v = healthy(FF_UA);
        v["eme"] = json!("undefined");
        match classify_media_codec_coherence(&v) {
            ProbeOutcome::Drift(m) => assert!(m.contains("EME")),
            o => panic!("expected Drift, got {o:?}"),
        }
    }

    #[test]
    fn missing_ua_is_probe_error() {
        assert!(matches!(
            classify_media_codec_coherence(&json!({"h264": "probably"})),
            ProbeOutcome::ProbeError(_)
        ));
    }

    #[test]
    fn err_sentinel_counts_as_unsupported() {
        // A throwing canPlayType ("ERR") must not be read as support.
        let v = json!({
            "ua": FF_UA, "h264": "ERR", "aac": "ERR", "mp4": "ERR", "vp9": "ERR",
            "opus": "ERR", "mp3": "ERR", "mseH264": false, "eme": "function",
            "mcAac": false, "mcOpus": false
        });
        assert!(matches!(
            classify_media_codec_coherence(&v),
            ProbeOutcome::Critical(_)
        ));
    }

    #[test]
    fn missing_media_capabilities_is_drift() {
        // Core codecs supported via canPlayType/MSE but MediaCapabilities absent.
        let mut v = healthy(FF_UA);
        v["mcAac"] = json!(false);
        v["mcOpus"] = json!(false);
        match classify_media_codec_coherence(&v) {
            ProbeOutcome::Drift(m) => assert!(m.contains("MediaCapabilities")),
            o => panic!("expected Drift, got {o:?}"),
        }
    }

    #[test]
    fn media_capabilities_denies_opus_is_drift() {
        let mut v = healthy(FF_UA);
        v["mcOpus"] = json!(false);
        match classify_media_codec_coherence(&v) {
            ProbeOutcome::Drift(m) => assert!(m.contains("Opus")),
            o => panic!("expected Drift, got {o:?}"),
        }
    }
}
