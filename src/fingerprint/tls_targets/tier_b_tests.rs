use super::*;

fn tmp(suffix: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!(
        "guise-tier-b-targets-{}-{suffix}.toml",
        std::process::id()
    ))
}

#[test]
fn shipped_example_loads_and_round_trips_to_measured_ff150() {
    // The shipped Tier-B example must load and carry the SAME measured FF-150
    // shape as the built-in `firefox-150-linux` (distinct label, identical
    // fingerprint) (proving the example is real data, not a placeholder).
    let path =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tier_b/fingerprints/example.toml");
    let loaded = load_targets_from_toml(&path).expect("shipped example must load");
    assert_eq!(loaded.len(), 1);
    let ex = &loaded[0];
    assert_eq!(ex.label, "firefox-150-linux-example");
    let builtin = lookup("firefox-150-linux").expect("built-in FF-150 must ship");
    assert_eq!(ex.ja3, builtin.ja3);
    assert_eq!(ex.ja4, builtin.ja4);
    assert_eq!(ex.akamai_h2, builtin.akamai_h2);
    assert_eq!(ex.peet_h2, builtin.peet_h2);
}

#[test]
fn loaded_target_extends_the_cluster_catalogue() {
    // End-to-end: load the example, merge with built-ins, and confirm the
    // cluster check now recognises the example label as its own member.
    use crate::fingerprint::cluster::{classify_against, ObservedFingerprint};
    let path =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tier_b/fingerprints/example.toml");
    let extra = load_targets_from_toml(&path).expect("load example");
    let catalogue = builtin_with(&extra);
    let ex = &extra[0];
    let observed = ObservedFingerprint {
        ja4: Some(ex.ja4.to_string()),
        akamai_h2: Some(ex.akamai_h2.to_string()),
        ..Default::default()
    };
    let labels = classify_against(&observed, &catalogue).cluster_labels();
    // The example shares FF-150's JA4+Akamai, so BOTH labels are in the crowd.
    assert!(
        labels.contains(&"firefox-150-linux-example"),
        "got {labels:?}"
    );
    assert!(labels.contains(&"firefox-150-linux"), "got {labels:?}");
}

#[test]
fn malformed_target_fails_closed_not_skipped() {
    let path = tmp("malformed");
    std::fs::write(
        &path,
        "[[target]]\nlabel=\"bad\"\nja3=\"999,x\"\nja4=\"t13d\"\nakamai_h2=\"a|b|c|d\"\npeet_h2=\"h\"\n",
    )
    .unwrap();
    match load_targets_from_toml(&path) {
        Err(TargetLoadError::Invalid { label, .. }) => assert_eq!(label, "bad"),
        other => panic!("expected Invalid, got {other:?}"),
    }
    let _ = std::fs::remove_file(path);
}

#[test]
fn duplicate_of_builtin_label_is_rejected() {
    let path = tmp("dup");
    // Reuses the built-in `firefox-150-linux` label, must be refused. All
    // other fields are well-formed (parseable Akamai H2; peet_h2 is the real
    // md5(akamai_h2)) so the rejection is unambiguously the duplicate label, not a
    // malformed field.
    std::fs::write(
        &path,
        "[[target]]\nlabel=\"firefox-150-linux\"\nja3=\"771,1\"\nja4=\"t13d1\"\nakamai_h2=\"1:65536|0|0|m,p,a,s\"\npeet_h2=\"c1bb6169cdbf746126ff369c72f0d5b8\"\n",
    )
    .unwrap();
    match load_targets_from_toml(&path) {
        Err(TargetLoadError::DuplicateLabel(label)) => assert_eq!(label, "firefox-150-linux"),
        other => panic!("expected DuplicateLabel, got {other:?}"),
    }
    let _ = std::fs::remove_file(path);
}

#[test]
fn empty_file_loads_zero_targets() {
    let path = tmp("empty");
    std::fs::write(&path, "# no targets here\n").unwrap();
    let loaded = load_targets_from_toml(&path).expect("empty is a valid zero-target load");
    assert!(loaded.is_empty());
    let _ = std::fs::remove_file(path);
}

#[test]
fn missing_file_is_a_read_error() {
    let path = tmp("does-not-exist-xyz");
    let _ = std::fs::remove_file(&path);
    assert!(matches!(
        load_targets_from_toml(&path),
        Err(TargetLoadError::Read(_))
    ));
}

#[test]
fn tier_b_persona_data_tree_has_expected_subdirectories() {
    // G100: the entire persona-data tree lives under one root. This test locks
    // the directory layout so new persona aspects are added here, not duplicated
    // in reynard or guise-profiles.
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tier_b");
    let expected = [
        "audio_devices",
        "fingerprints",
        "fonts",
        "profiles",
        "screen",
        "voices",
        "webgl",
    ];
    for dir in &expected {
        let path = root.join(dir);
        assert!(
            path.is_dir(),
            "Tier-B persona-data tree must contain `{dir}`"
        );
    }

    // README documents the shared-tree contract.
    let readme = root.join("README.md");
    assert!(
        readme.is_file(),
        "Tier-B tree must have a README.md contract"
    );
    let content = std::fs::read_to_string(&readme).expect("README must be readable");
    assert!(
        content.contains("One tree"),
        "README must document the single-tree contract"
    );
}
