use super::*;

// ── default_timezone_for_locale ─────────────────────────────────────────────

#[test]
fn default_timezone_maps_known_locales() {
    assert_eq!(default_timezone_for_locale("en-US"), "America/New_York");
    assert_eq!(default_timezone_for_locale("en-GB"), "Europe/London");
    assert_eq!(default_timezone_for_locale("de-DE"), "Europe/Berlin");
    assert_eq!(default_timezone_for_locale("ja-JP"), "Asia/Tokyo");
    assert_eq!(default_timezone_for_locale("ja"), "Asia/Tokyo");
    assert_eq!(default_timezone_for_locale("fr"), "Europe/Paris");
    assert_eq!(default_timezone_for_locale("en-CA"), "America/Toronto");
}

#[test]
fn default_timezone_is_case_insensitive_and_falls_back_to_en() {
    assert_eq!(default_timezone_for_locale("EN-us"), "America/New_York");
    assert_eq!(default_timezone_for_locale("xx-YY"), "America/New_York");
    assert_eq!(default_timezone_for_locale(""), "America/New_York");
}

#[test]
fn every_derived_default_timezone_is_geo_coherent_with_its_locale() {
    use crate::fingerprint::geo_coherence::timezone_facts;
    let cases = [
        ("en-US", "US"),
        ("en-GB", "GB"),
        ("de-DE", "DE"),
        ("fr-FR", "FR"),
        ("es-ES", "ES"),
        ("nl-NL", "NL"),
        ("ja-JP", "JP"),
        ("zh-CN", "CN"),
        ("en-CA", "CA"),
        ("en-AU", "AU"),
        ("en-IN", "IN"),
    ];
    for (locale, expected_country) in cases {
        let tz = default_timezone_for_locale(locale);
        let facts = timezone_facts(tz)
            .unwrap_or_else(|| panic!("derived tz {tz} for {locale} not in geo catalogue"));
        assert_eq!(
            facts.country, expected_country,
            "derived tz {tz} for {locale}"
        );
    }
}

// ── intl_spoof_js structure ─────────────────────────────────────────────────

#[test]
fn spoof_js_embeds_locale_zone_and_overrides_the_full_consistent_set() {
    let js = intl_spoof_js("de-DE", "Europe/Berlin");
    assert!(js.contains(r#""Europe/Berlin""#), "zone not embedded");
    assert!(js.contains(r#""de-DE""#), "locale not embedded");
    for needle in [
        "Date.prototype.getTimezoneOffset =",
        "Date.prototype.toString =",
        "Number.prototype.toLocaleString =",
        "String.prototype.localeCompare =",
        "Intl.DateTimeFormat = ",
        "['NumberFormat', 'Collator', 'RelativeTimeFormat', 'PluralRules', 'ListFormat']",
    ] {
        assert!(js.contains(needle), "spoof JS missing override: {needle}");
    }
    assert!(
        js.contains("timeZone: __TZ"),
        "must format via ICU for the target zone"
    );
}

#[test]
fn spoof_js_is_embeddable_in_the_profile_iife_seal() {
    let js = intl_spoof_js("ja-JP", "Asia/Tokyo");
    assert!(js.contains("(typeof __seal === 'function') ? __seal"));
}

// ── Node soundness oracle ───────────────────────────────────────────────────

fn run_under_node(label: &str, host_tz: &str, script: &str) -> Option<String> {
    use std::io::Write;
    use std::process::Command;

    if Command::new("node").arg("--version").output().is_err() {
        eprintln!("skip: `node` not found. Intl spoof oracle needs Node + ICU");
        return None;
    }
    // Unique per test (label) AND per process, the oracle tests run in parallel,
    // so a shared path would race (one test's node reading another's script).
    let path = std::env::temp_dir().join(format!(
        "guise_intl_oracle_{}_{label}.js",
        std::process::id()
    ));
    {
        let mut f = std::fs::File::create(&path).expect("create temp oracle script");
        f.write_all(script.as_bytes()).expect("write oracle script");
    }
    let out = Command::new("node")
        .arg(&path)
        .env("TZ", host_tz)
        .output()
        .expect("run node oracle");
    let _ = std::fs::remove_file(&path);
    assert!(
        out.status.success(),
        "node oracle FAILED under TZ={host_tz}:\n{}\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    Some(String::from_utf8_lossy(&out.stdout).to_string())
}

#[test]
fn spoof_overrides_host_timezone_consistently_and_dst_correctly() {
    // Persona zone America/New_York; HOST forced to America/Phoenix (UTC-7, no DST).
    let spoof = intl_spoof_js("en-US", "America/New_York");
    let script = format!(
        r#"{spoof}
const A = (c, m) => {{ if (!c) {{ console.error('ASSERT FAILED: ' + m); process.exit(1); }} }};
A(Intl.DateTimeFormat().resolvedOptions().timeZone === 'America/New_York',
  'default resolvedOptions timeZone = ' + Intl.DateTimeFormat().resolvedOptions().timeZone);
A(Intl.DateTimeFormat('en-US', {{ timeZone: 'UTC' }}).resolvedOptions().timeZone === 'UTC', 'explicit timeZone honoured');
const summer = new Date('2026-06-13T12:00:00Z');
const winter = new Date('2026-01-13T12:00:00Z');
A(summer.getTimezoneOffset() === 240, 'summer offset = ' + summer.getTimezoneOffset() + ' (want 240)');
A(winter.getTimezoneOffset() === 300, 'winter offset = ' + winter.getTimezoneOffset() + ' (want 300)');
const s = summer.toString();
A(s.indexOf('08:00:00') !== -1, 'NY wall clock for 12:00Z must be 08:00:00, got: ' + s);
A(s.indexOf('GMT-0400') !== -1, 'toString must carry GMT-0400, got: ' + s);
A(/Eastern/.test(s), 'toString must carry the Eastern zone name, got: ' + s);
const f = new Intl.DateTimeFormat('en-US', {{ hour: '2-digit', minute: '2-digit', hourCycle: 'h23' }}).format(summer);
A(f.indexOf('08') === 0, 'default format must use persona zone (08:..), got: ' + f);
A(summer.getTimezoneOffset() !== 420, 'host Phoenix offset 420 leaked through');
console.log('ORACLE_OK');
"#,
        spoof = spoof,
    );
    let Some(stdout) = run_under_node("tz", "America/Phoenix", &script) else {
        return;
    };
    assert!(stdout.contains("ORACLE_OK"), "stdout: {stdout}");
}

#[test]
fn spoof_overrides_host_locale_across_intl_number_and_string() {
    // Persona locale de-DE on an en-US host: every locale surface must report de-DE
    // and FORMAT German (decimal comma), proving the locale is genuinely injected,
    // not faked in resolvedOptions.
    let spoof = intl_spoof_js("de-DE", "Europe/Berlin");
    let script = format!(
        r#"{spoof}
const A = (c, m) => {{ if (!c) {{ console.error('ASSERT FAILED: ' + m); process.exit(1); }} }};
// resolvedOptions().locale: assert the LANGUAGE subtag (ICU canonicalises de-DE→de
// per service, e.g. Collator, a real de-DE browser does the same, so matching the
// language subtag is the coherent check, not the exact tag).
A(Intl.DateTimeFormat().resolvedOptions().locale.startsWith('de'), 'DTF locale = ' + Intl.DateTimeFormat().resolvedOptions().locale);
A(Intl.NumberFormat().resolvedOptions().locale.startsWith('de'), 'NumberFormat locale = ' + Intl.NumberFormat().resolvedOptions().locale);
A(Intl.Collator().resolvedOptions().locale.startsWith('de'), 'Collator locale = ' + Intl.Collator().resolvedOptions().locale);
// Explicit locale still honoured (not overridden by the persona default).
A(Intl.NumberFormat('fr-FR').resolvedOptions().locale.startsWith('fr'), 'explicit locale honoured');
// The load-bearing proof: FORMATTING is genuinely German (host is en-US): 1234.5
// → "1.234,5" (dot grouping, decimal comma), not the en-US "1,234.5".
A((1234.5).toLocaleString() === '1.234,5', 'de number format = ' + (1234.5).toLocaleString());
// And the timezone rode along: Berlin summer (CEST, UTC+2) = offset -120.
A(new Date('2026-06-13T12:00:00Z').getTimezoneOffset() === -120,
  'Berlin summer offset = ' + new Date('2026-06-13T12:00:00Z').getTimezoneOffset() + ' (want -120)');
console.log('ORACLE_OK');
"#,
        spoof = spoof,
    );
    let Some(stdout) = run_under_node("locale", "America/New_York", &script) else {
        return;
    };
    assert!(stdout.contains("ORACLE_OK"), "stdout: {stdout}");
}

#[test]
fn spoof_keeps_intl_constructor_identity_native_coherent() {
    // Every wrapped Intl constructor must keep the real-engine invariant
    // `Ctor.prototype.constructor === Ctor` (and the same for an instance). The
    // wrapper replaces Intl.X but shares Orig.prototype, so without repointing the
    // prototype's `constructor` it still pointed at the captured original, a
    // trivial one-line tampering tell. The `constructor` slot must also stay
    // non-enumerable, as in a native engine.
    let spoof = intl_spoof_js("de-DE", "Europe/Berlin");
    let script = format!(
        r#"{spoof}
const A = (c, m) => {{ if (!c) {{ console.error('ASSERT FAILED: ' + m); process.exit(1); }} }};
const ctors = ['DateTimeFormat','NumberFormat','Collator','RelativeTimeFormat','PluralRules','ListFormat'];
for (const name of ctors) {{
  const C = Intl[name];
  A(C.prototype.constructor === C, name + '.prototype.constructor !== Intl.' + name + ' (tampering tell)');
  const d = Object.getOwnPropertyDescriptor(C.prototype, 'constructor');
  A(d && d.enumerable === false, name + '.prototype.constructor became enumerable (tell): ' + JSON.stringify(d));
}}
// Instance-level identity for the constructible ones.
A((new Intl.DateTimeFormat()).constructor === Intl.DateTimeFormat, 'DTF instance.constructor !== Intl.DateTimeFormat');
A((new Intl.NumberFormat()).constructor === Intl.NumberFormat, 'NF instance.constructor !== Intl.NumberFormat');
A((new Intl.Collator()).constructor === Intl.Collator, 'Collator instance.constructor !== Intl.Collator');
// And the wrapper did not break construction / persona injection.
A(Intl.DateTimeFormat().resolvedOptions().timeZone === 'Europe/Berlin', 'persona zone lost after constructor repoint');
console.log('ORACLE_OK');
"#,
        spoof = spoof,
    );
    let Some(stdout) = run_under_node("ctor_identity", "America/Phoenix", &script) else {
        return;
    };
    assert!(stdout.contains("ORACLE_OK"), "stdout: {stdout}");
}

#[test]
fn spoof_is_dst_correct_for_a_southern_hemisphere_zone() {
    let spoof = intl_spoof_js("en-AU", "Australia/Sydney");
    let script = format!(
        r#"{spoof}
const A = (c, m) => {{ if (!c) {{ console.error('ASSERT FAILED: ' + m); process.exit(1); }} }};
A(Intl.DateTimeFormat().resolvedOptions().timeZone === 'Australia/Sydney', 'tz');
const jan = new Date('2026-01-13T12:00:00Z'); // Sydney summer, AEDT UTC+11
const jun = new Date('2026-06-13T12:00:00Z'); // Sydney winter, AEST UTC+10
A(jan.getTimezoneOffset() === -660, 'Jan offset = ' + jan.getTimezoneOffset() + ' (want -660)');
A(jun.getTimezoneOffset() === -600, 'Jun offset = ' + jun.getTimezoneOffset() + ' (want -600)');
console.log('ORACLE_OK');
"#,
        spoof = spoof,
    );
    let Some(stdout) = run_under_node("sydney", "America/Phoenix", &script) else {
        return;
    };
    assert!(stdout.contains("ORACLE_OK"), "stdout: {stdout}");
}
