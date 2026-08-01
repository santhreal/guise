use super::*;
use crate::fingerprint::{profile_os_network_stack, StealthProfile};
use std::path::PathBuf;

/// Write `contents` to a uniquely-named temp file and return its path. The
/// caller removes it; a leak on a failing assert is a harmless temp file.
fn temp_toml(suffix: &str, contents: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!(
        "guise_tcp_tierb_{}_{suffix}.toml",
        std::process::id()
    ));
    std::fs::write(&path, contents).expect("write temp toml");
    path
}

#[test]
fn loads_and_validates_a_labelled_stack_catalogue() {
    let toml = r#"
[[stack]]
label = "windows-11"
os = "windows"
initial_ttl = 128
tcp_mss = 1460
tcp_window_scale = 8
tcp_window = "64240"
tcp_options_layout = "mss,nop,ws,nop,nop,sok"
df = true

[[stack]]
label = "ubuntu-22.04"
os = "linux"
initial_ttl = 64
tcp_mss = 1460
tcp_window_scale = 7
tcp_window = "mss-scaled"
tcp_options_layout = "mss,sok,ts,nop,ws"
df = true
"#;
    let path = temp_toml("ok", toml);
    let stacks = load_tcp_stacks_from_toml(&path).expect("valid catalogue loads");
    std::fs::remove_file(&path).ok();

    assert_eq!(stacks.len(), 2);
    let win = stacks.iter().find(|s| s.label == "windows-11").unwrap();
    assert_eq!(win.stack.os, UserAgentPlatform::Windows);
    // The labelled Tier-B Windows stack renders the FoxIO Windows-11 JA4T, exactly
    // like the built-in Windows FAMILY stack, the data path and the const path
    // agree, so an operator's finer label doesn't drift from the model.
    assert_eq!(win.stack.ja4t().unwrap(), "64240_2-1-3-1-1-4_1460_8");
    assert_eq!(
        win.stack.ja4t().unwrap(),
        profile_os_network_stack(StealthProfile::FirefoxWindows)
            .ja4t()
            .unwrap()
    );

    let linux = stacks.iter().find(|s| s.label == "ubuntu-22.04").unwrap();
    assert_eq!(linux.stack.tcp_window, TcpWindow::MssScaled);
    assert_eq!(linux.stack.ja4t().unwrap(), "*_2-4-8-1-3_1460_7");
    assert_eq!(
        linux.stack.p0f_signature(),
        "64:1460:*,7:mss,sok,ts,nop,ws:df"
    );
}

#[test]
fn absent_stack_array_is_an_empty_load_not_an_error() {
    let path = temp_toml("empty", "# no stacks here\n");
    let stacks = load_tcp_stacks_from_toml(&path).expect("empty file is zero stacks, not an error");
    std::fs::remove_file(&path).ok();
    assert!(stacks.is_empty());
}

#[test]
fn rejects_non_canonical_initial_ttl() {
    // 100 is not one of {64,128,255}; the de-hop self-probe could never recover it.
    let toml = r#"
[[stack]]
label = "weird"
os = "linux"
initial_ttl = 100
tcp_mss = 1460
tcp_window_scale = 7
tcp_window = "mss-scaled"
tcp_options_layout = "mss,sok,ts,nop,ws"
df = true
"#;
    let path = temp_toml("badttl", toml);
    let err = load_tcp_stacks_from_toml(&path).unwrap_err();
    std::fs::remove_file(&path).ok();
    match err {
        TcpStackLoadError::Invalid { label, reason } => {
            assert_eq!(label, "weird");
            assert!(reason.contains("canonical"), "reason: {reason}");
        }
        other => panic!("expected Invalid, got {other:?}"),
    }
}

#[test]
fn rejects_unknown_os_family() {
    let toml = r#"
[[stack]]
label = "haiku"
os = "beos"
initial_ttl = 64
tcp_mss = 1460
tcp_window_scale = 7
tcp_window = "mss-scaled"
tcp_options_layout = "mss,sok,ts,nop,ws"
df = true
"#;
    let path = temp_toml("bados", toml);
    let err = load_tcp_stacks_from_toml(&path).unwrap_err();
    std::fs::remove_file(&path).ok();
    assert!(matches!(err, TcpStackLoadError::Invalid { .. }));
}

#[test]
fn fails_closed_on_unknown_option_token() {
    // Law 10: an options layout the JA4T renderer can't map must reject the stack,
    // never load a stack we cannot faithfully fingerprint.
    let toml = r#"
[[stack]]
label = "frobd"
os = "linux"
initial_ttl = 64
tcp_mss = 1460
tcp_window_scale = 7
tcp_window = "mss-scaled"
tcp_options_layout = "mss,frobnicate,ws"
df = true
"#;
    let path = temp_toml("badopt", toml);
    let err = load_tcp_stacks_from_toml(&path).unwrap_err();
    std::fs::remove_file(&path).ok();
    match err {
        TcpStackLoadError::Invalid { reason, .. } => {
            assert!(reason.contains("JA4T"), "reason: {reason}");
        }
        other => panic!("expected Invalid on bad option, got {other:?}"),
    }
}

#[test]
fn rejects_duplicate_labels() {
    let toml = r#"
[[stack]]
label = "dup"
os = "linux"
initial_ttl = 64
tcp_mss = 1460
tcp_window_scale = 7
tcp_window = "mss-scaled"
tcp_options_layout = "mss,sok,ts,nop,ws"
df = true

[[stack]]
label = "dup"
os = "windows"
initial_ttl = 128
tcp_mss = 1460
tcp_window_scale = 8
tcp_window = "64240"
tcp_options_layout = "mss,nop,ws,nop,nop,sok"
df = true
"#;
    let path = temp_toml("dup", toml);
    let err = load_tcp_stacks_from_toml(&path).unwrap_err();
    std::fs::remove_file(&path).ok();
    match err {
        TcpStackLoadError::DuplicateLabel(label) => assert_eq!(label, "dup"),
        other => panic!("expected DuplicateLabel, got {other:?}"),
    }
}

#[test]
fn rejects_malformed_toml() {
    let path = temp_toml("parse", "this is not = valid = toml [[[");
    let err = load_tcp_stacks_from_toml(&path).unwrap_err();
    std::fs::remove_file(&path).ok();
    assert!(matches!(err, TcpStackLoadError::Parse(_)));
}

#[test]
fn missing_file_is_a_read_error_not_a_silent_empty() {
    let path = std::env::temp_dir().join("guise_tcp_tierb_does_not_exist_zzz.toml");
    let err = load_tcp_stacks_from_toml(&path).unwrap_err();
    assert!(matches!(err, TcpStackLoadError::Read(_)));
}
