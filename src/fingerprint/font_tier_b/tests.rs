//! Unit tests for the Tier-B font persona library loader (G096).

use super::*;

/// Path to the shipped Tier-B font library, relative to the workspace root.
fn shipped_font_dir() -> std::path::PathBuf {
    let manifest = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest.join("tier_b").join("fonts")
}

#[test]
fn built_in_font_set_matches_tier_b_file() {
    // G096 contract: the hardcoded Linux standard set is exactly the Tier-B file.
    loader_impl::built_in_matches_file().expect("built-in const must match Tier-B file");
}

#[test]
fn shipped_font_library_loads() {
    let fonts = load_font_directory(&shipped_font_dir()).expect("shipped library must load");
    assert!(
        fonts.len() >= LINUX_STANDARD_FONTS.len(),
        "expected at least {} font personas, got {}",
        LINUX_STANDARD_FONTS.len(),
        fonts.len()
    );
    let deja_vu = fonts.iter().any(|f| f.family == "DejaVu Sans");
    assert!(deja_vu, "shipped library must include DejaVu Sans");
}

#[test]
fn malformed_empty_family_is_rejected() {
    let dir = std::env::temp_dir().join(format!("guise-font-empty-family-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("bad.toml");
    std::fs::write(&path, "[[font]]\nfamily = \"\"\n").unwrap();

    let err = load_fonts_from_toml(&path).expect_err("empty family must be rejected");
    assert!(
        format!("{err}").contains("empty family"),
        "expected empty-family error, got {err}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn oversized_file_is_rejected() {
    let dir = std::env::temp_dir().join(format!("guise-font-oversize-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("huge.toml");
    let payload = format!("# {}\n[[font]]\nfamily = \"X\"\n", "x".repeat(65 * 1024));
    std::fs::write(&path, payload).unwrap();

    let err = load_fonts_from_toml(&path).expect_err("oversize file must be rejected");
    assert!(
        format!("{err}").contains("over the 65536-byte cap"),
        "expected oversize error, got {err}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn empty_font_array_loads_successfully() {
    let dir = std::env::temp_dir().join(format!("guise-font-empty-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("empty.toml");
    std::fs::write(&path, "# no fonts\n").unwrap();

    let fonts = load_fonts_from_toml(&path).expect("empty font array must load");
    assert!(fonts.is_empty());
    let _ = std::fs::remove_dir_all(&dir);
}
