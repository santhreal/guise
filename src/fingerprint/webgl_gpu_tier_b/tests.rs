//! Unit tests for the Tier-B WebGL GPU persona library loader (G095).

use super::*;
use guise_profiles::profile_hardware;

/// Path to the shipped Tier-B WebGL GPU library, relative to the workspace root.
fn shipped_webgl_dir() -> std::path::PathBuf {
    let manifest = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest.join("tier_b").join("webgl")
}

#[test]
fn shipped_webgl_library_loads_all_vendor_files() {
    let gpus = load_webgl_gpu_directory(&shipped_webgl_dir()).expect("shipped library must load");
    // 8 vendor files: intel (4), nvidia (3), amd (1), apple (3), qualcomm (2),
    // mesa (1), brave (1), microsoft (1) = 16 personas.
    assert!(
        gpus.len() >= 16,
        "expected at least the 16 built-in extracted personas, got {}",
        gpus.len()
    );

    let families: std::collections::HashSet<_> = gpus
        .iter()
        .map(|g| webgl_gpu_vendor_family(g.vendor))
        .collect();
    for want in [
        WebGlGpuFamily::Intel,
        WebGlGpuFamily::Nvidia,
        WebGlGpuFamily::Amd,
        WebGlGpuFamily::Apple,
        WebGlGpuFamily::Qualcomm,
        WebGlGpuFamily::Mesa,
        WebGlGpuFamily::Brave,
        WebGlGpuFamily::Microsoft,
    ] {
        assert!(
            families.contains(&want),
            "shipped library must cover {want:?}"
        );
    }
}

#[test]
fn every_shipped_profile_webgl_pair_exists_in_tier_b_library() {
    // G095 contract: the built-in profiles are a subset of the Tier-B library.
    // If a profile's GPU pair is missing from the library, the library is not
    // authoritative.
    let gpus = load_webgl_gpu_directory(&shipped_webgl_dir()).expect("shipped library must load");
    let set: std::collections::HashSet<_> = gpus.iter().map(|g| (g.vendor, g.renderer)).collect();

    for profile in guise_profiles::ALL_PROFILES {
        let hw = profile_hardware(*profile);
        // FirefoxLinux uses native passthrough (empty strings), that is a
        // deliberate "no persona" choice, not a missing library entry.
        if hw.webgl_vendor.is_empty() && hw.webgl_renderer.is_empty() {
            continue;
        }
        assert!(
            set.contains(&(hw.webgl_vendor, hw.webgl_renderer)),
            "{profile:?} WebGL pair ({:?}, {:?}) must be in the Tier-B library",
            hw.webgl_vendor,
            hw.webgl_renderer
        );
    }
}

#[test]
fn malformed_empty_vendor_is_rejected() {
    let dir = std::env::temp_dir().join(format!("guise-webgl-empty-vendor-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("bad.toml");
    std::fs::write(&path, "[[gpu]]\nvendor = \"\"\nrenderer = \"ANGLE\"\n").unwrap();

    let err = load_webgl_gpus_from_toml(&path).expect_err("empty vendor must be rejected");
    assert!(
        format!("{err}").contains("empty vendor"),
        "expected empty-vendor error, got {err}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn malformed_empty_renderer_is_rejected() {
    let dir =
        std::env::temp_dir().join(format!("guise-webgl-empty-renderer-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("bad.toml");
    std::fs::write(&path, "[[gpu]]\nvendor = \"NVIDIA\"\nrenderer = \"\"\n").unwrap();

    let err = load_webgl_gpus_from_toml(&path).expect_err("empty renderer must be rejected");
    assert!(
        format!("{err}").contains("empty renderer"),
        "expected empty-renderer error, got {err}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn oversized_file_is_rejected() {
    let dir = std::env::temp_dir().join(format!("guise-webgl-oversize-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("huge.toml");
    // 65 KiB of comment padding pushes the file past the 64 KiB cap.
    let payload = format!(
        "# {}\n[[gpu]]\nvendor = \"X\"\nrenderer = \"Y\"\n",
        "x".repeat(65 * 1024)
    );
    std::fs::write(&path, payload).unwrap();

    let err = load_webgl_gpus_from_toml(&path).expect_err("oversize file must be rejected");
    assert!(
        format!("{err}").contains("over the 65536-byte cap"),
        "expected oversize error, got {err}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn apple_gpu_family_is_apple_platform_only() {
    assert!(WebGlGpuFamily::Apple.coherent_with_platform("MacIntel"));
    assert!(WebGlGpuFamily::Apple.coherent_with_platform("iPhone"));
    assert!(WebGlGpuFamily::Apple.coherent_with_platform("iPad"));
    assert!(!WebGlGpuFamily::Apple.coherent_with_platform("Win32"));
    assert!(!WebGlGpuFamily::Apple.coherent_with_platform("Linux x86_64"));
}

#[test]
fn non_apple_gpu_families_are_non_apple_platform_only() {
    for family in [
        WebGlGpuFamily::Intel,
        WebGlGpuFamily::Nvidia,
        WebGlGpuFamily::Amd,
        WebGlGpuFamily::Qualcomm,
        WebGlGpuFamily::Mesa,
        WebGlGpuFamily::Brave,
        WebGlGpuFamily::Microsoft,
    ] {
        assert!(
            family.coherent_with_platform("Win32"),
            "{family:?} must be coherent on Windows"
        );
        assert!(
            !family.coherent_with_platform("MacIntel"),
            "{family:?} must be incoherent on macOS"
        );
        assert!(
            !family.coherent_with_platform("iPhone"),
            "{family:?} must be incoherent on iOS"
        );
    }
}

#[test]
fn vendor_family_classification_matches_renderer_content() {
    // The classifier keys primarily on the vendor, but should still catch a
    // renderer-only Apple string because real strings carry the vendor.
    assert_eq!(
        webgl_gpu_vendor_family("Google Inc. (Apple)"),
        WebGlGpuFamily::Apple
    );
    assert_eq!(
        webgl_gpu_vendor_family("Google Inc. (NVIDIA)"),
        WebGlGpuFamily::Nvidia
    );
    assert_eq!(
        webgl_gpu_vendor_family("Unknown Vendor"),
        WebGlGpuFamily::Other
    );
}
