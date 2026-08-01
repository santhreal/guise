//! Unit tests for the Tier-B audio device persona library loader (G098).

use super::*;

/// Path to the shipped Tier-B audio-device library, relative to the workspace root.
fn shipped_audio_dir() -> std::path::PathBuf {
    let manifest = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest.join("tier_b").join("audio_devices")
}

#[test]
fn shipped_audio_device_library_loads_all_platforms() {
    let devices =
        load_audio_device_directory(&shipped_audio_dir()).expect("shipped library must load");
    assert!(
        devices.len() >= 8,
        "expected at least 8 audio devices, got {}",
        devices.len()
    );

    let inputs = devices.iter().filter(|d| d.is_input()).count();
    let outputs = devices.iter().filter(|d| d.is_output()).count();
    assert!(
        inputs >= 3,
        "expected at least 3 input devices, got {inputs}"
    );
    assert!(
        outputs >= 3,
        "expected at least 3 output devices, got {outputs}"
    );
}

#[test]
fn linux_default_devices_present() {
    let path = shipped_audio_dir().join("linux.toml");
    let devices = load_audio_devices_from_toml(&path).expect("linux.toml must load");
    let labels: std::collections::HashSet<_> = devices.iter().map(|d| d.label).collect();
    assert!(labels.contains("Built-in Audio Analog Stereo"));
    assert!(labels.contains("Default"));
}

#[test]
fn invalid_kind_is_rejected() {
    let dir = std::env::temp_dir().join(format!("guise-audio-bad-kind-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("bad.toml");
    std::fs::write(
        &path,
        "[[audio_device]]\nkind = \"videoinput\"\nlabel = \"Camera\"\n",
    )
    .unwrap();

    let err = load_audio_devices_from_toml(&path).expect_err("invalid kind must be rejected");
    assert!(
        format!("{err}").contains("kind `videoinput` is not audioinput/audiooutput"),
        "expected kind error, got {err}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn empty_label_is_rejected() {
    let dir = std::env::temp_dir().join(format!("guise-audio-empty-label-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("bad.toml");
    std::fs::write(
        &path,
        "[[audio_device]]\nkind = \"audioinput\"\nlabel = \"\"\n",
    )
    .unwrap();

    let err = load_audio_devices_from_toml(&path).expect_err("empty label must be rejected");
    assert!(
        format!("{err}").contains("empty label"),
        "expected empty-label error, got {err}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn oversized_file_is_rejected() {
    let dir = std::env::temp_dir().join(format!("guise-audio-oversize-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("huge.toml");
    let payload = format!(
        "# {}\n[[audio_device]]\nkind = \"audioinput\"\nlabel = \"X\"\n",
        "x".repeat(65 * 1024)
    );
    std::fs::write(&path, payload).unwrap();

    let err = load_audio_devices_from_toml(&path).expect_err("oversize file must be rejected");
    assert!(
        format!("{err}").contains("over the 65536-byte cap"),
        "expected oversize error, got {err}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn device_kind_helpers_work() {
    let input = AudioDevicePersona {
        kind: "audioinput",
        label: "Mic",
    };
    assert!(input.is_input());
    assert!(!input.is_output());

    let output = AudioDevicePersona {
        kind: "audiooutput",
        label: "Speakers",
    };
    assert!(!output.is_input());
    assert!(output.is_output());
}
