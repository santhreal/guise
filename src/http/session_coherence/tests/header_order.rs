use super::*;

#[test]
fn chrome_header_order_distinct_from_firefox_and_safari() {
    assert_ne!(CHROME_HEADER_ORDER.slots, FIREFOX_HEADER_ORDER.slots);
    assert_ne!(CHROME_HEADER_ORDER.slots, SAFARI_HEADER_ORDER.slots);
    assert_ne!(FIREFOX_HEADER_ORDER.slots, SAFARI_HEADER_ORDER.slots);
}

#[test]
fn chrome_orders_user_agent_after_sec_ch_ua_block() {
    let slots = CHROME_HEADER_ORDER.slots;
    let sec_ch_pos = slots.iter().position(|s| *s == "sec-ch-ua").unwrap();
    let ua_pos = slots.iter().position(|s| *s == "user-agent").unwrap();
    assert!(sec_ch_pos < ua_pos);
}

#[test]
fn safari_does_not_emit_sec_ch_headers() {
    for slot in SAFARI_HEADER_ORDER.slots {
        assert!(!slot.starts_with("sec-ch-"));
    }
}

#[test]
fn apply_in_order_promotes_canonical_slots_to_the_front() {
    let input = vec![
        ("X-Custom".into(), "junk".into()),
        ("Cookie".into(), "abc=1".into()),
        ("user-agent".into(), "chrome-fake".into()),
        ("Host".into(), "x.com".into()),
    ];
    let out = CHROME_HEADER_ORDER.apply_in_order(input);
    assert_eq!(out[0].0.to_ascii_lowercase(), "host");

    let ua_pos = out
        .iter()
        .position(|(name, _)| name.eq_ignore_ascii_case("user-agent"))
        .unwrap();
    let cookie_pos = out
        .iter()
        .position(|(name, _)| name.eq_ignore_ascii_case("cookie"))
        .unwrap();
    let custom_pos = out.iter().position(|(name, _)| name == "X-Custom").unwrap();
    assert!(ua_pos < cookie_pos);
    assert!(custom_pos > cookie_pos);
}

#[test]
fn apply_in_order_preserves_caller_casing_of_header_names() {
    let input = vec![
        ("User-Agent".into(), "x".into()),
        ("Accept-Language".into(), "en".into()),
    ];
    let out = CHROME_HEADER_ORDER.apply_in_order(input);
    assert!(out.iter().any(|(name, _)| name == "User-Agent"));
    assert!(out.iter().any(|(name, _)| name == "Accept-Language"));
}

#[test]
fn apply_in_order_keeps_duplicate_headers_in_input_order() {
    let input = vec![
        ("Cookie".into(), "first=1".into()),
        ("Cookie".into(), "second=2".into()),
    ];
    let out = CHROME_HEADER_ORDER.apply_in_order(input);
    let cookies: Vec<&str> = out
        .iter()
        .filter(|(name, _)| name.eq_ignore_ascii_case("cookie"))
        .map(|(_, value)| value.as_str())
        .collect();
    assert_eq!(cookies, vec!["first=1", "second=2"]);
}

#[test]
fn header_order_apply_with_every_slot_present() {
    let input: Vec<(String, String)> = CHROME_HEADER_ORDER
        .slots
        .iter()
        .map(|slot| ((*slot).to_string(), format!("v-{slot}")))
        .collect();
    let out = CHROME_HEADER_ORDER.apply_in_order(input);
    assert_eq!(out.len(), CHROME_HEADER_ORDER.slots.len());
    for (i, slot) in CHROME_HEADER_ORDER.slots.iter().enumerate() {
        assert_eq!(out[i].0.to_ascii_lowercase(), **slot);
    }
}

#[test]
fn header_order_apply_with_no_slots_present_preserves_input() {
    let input = vec![
        ("X-Custom-A".into(), "1".into()),
        ("X-Custom-B".into(), "2".into()),
        ("X-Custom-C".into(), "3".into()),
    ];
    let out = CHROME_HEADER_ORDER.apply_in_order(input.clone());
    assert_eq!(out, input);
}

#[test]
fn header_order_apply_is_idempotent() {
    let input = vec![
        ("User-Agent".into(), "chrome".into()),
        ("Host".into(), "x.com".into()),
        ("Cookie".into(), "a=1".into()),
    ];
    let pass1 = CHROME_HEADER_ORDER.apply_in_order(input);
    let pass2 = CHROME_HEADER_ORDER.apply_in_order(pass1.clone());
    assert_eq!(pass1, pass2);
}

#[test]
fn header_order_slots_have_no_duplicates_within_a_family() {
    for (name, slots) in [
        ("chrome", CHROME_HEADER_ORDER.slots),
        ("firefox", FIREFOX_HEADER_ORDER.slots),
        ("safari", SAFARI_HEADER_ORDER.slots),
    ] {
        let mut seen = HashSet::new();
        for slot in slots {
            assert!(seen.insert(*slot), "{name}: duplicate slot `{slot}`");
        }
    }
}
