//! Unit tests for the Tier-B speech-synthesis voice persona library loader (G099).

use super::*;

/// Path to the shipped Tier-B voice library, relative to the workspace root.
fn shipped_voice_dir() -> std::path::PathBuf {
    let manifest = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest.join("tier_b").join("voices")
}

#[test]
fn shipped_voice_library_loads_all_platforms() {
    let voices = load_voice_directory(&shipped_voice_dir()).expect("shipped library must load");
    assert!(
        voices.len() >= 48,
        "expected at least 48 voices across platforms, got {}",
        voices.len()
    );

    let defaults = voices.iter().filter(|v| v.default).count();
    assert!(
        defaults >= 3,
        "expected at least one default voice per platform, got {defaults}"
    );

    let en_us = voices.iter().filter(|v| v.lang == "en-US").count();
    assert!(en_us >= 3, "expected at least 3 en-US voices, got {en_us}");
}

#[test]
fn every_shipped_platform_has_at_least_sixteen_voices() {
    // The probe catalogue asserts real browsers expose >=16 voices. Each
    // platform file in the library should meet that bar.
    for file in ["linux.toml", "windows.toml", "macos.toml"] {
        let path = shipped_voice_dir().join(file);
        let voices = load_voices_from_toml(&path).unwrap_or_else(|_| panic!("{file} must load"));
        assert!(
            voices.len() >= 16,
            "{file} must provide at least 16 voices (real-browser probe expectation), got {}",
            voices.len()
        );
    }
}

#[test]
fn empty_name_is_rejected() {
    let dir = std::env::temp_dir().join(format!("guise-voice-empty-name-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("bad.toml");
    std::fs::write(&path, "[[voice]]\nname = \"\"\nlang = \"en-US\"\n").unwrap();

    let err = load_voices_from_toml(&path).expect_err("empty name must be rejected");
    assert!(
        format!("{err}").contains("empty name"),
        "expected empty-name error, got {err}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn malformed_lang_is_rejected() {
    let dir = std::env::temp_dir().join(format!("guise-voice-bad-lang-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("bad.toml");
    std::fs::write(&path, "[[voice]]\nname = \"X\"\nlang = \"not a tag\"\n").unwrap();

    let err = load_voices_from_toml(&path).expect_err("malformed lang must be rejected");
    assert!(
        format!("{err}").contains("not a plausible BCP 47 tag"),
        "expected lang error, got {err}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn oversized_file_is_rejected() {
    let dir = std::env::temp_dir().join(format!("guise-voice-oversize-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("huge.toml");
    let payload = format!(
        "# {}\n[[voice]]\nname = \"X\"\nlang = \"en-US\"\n",
        "x".repeat(65 * 1024)
    );
    std::fs::write(&path, payload).unwrap();

    let err = load_voices_from_toml(&path).expect_err("oversize file must be rejected");
    assert!(
        format!("{err}").contains("over the 65536-byte cap"),
        "expected oversize error, got {err}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}
