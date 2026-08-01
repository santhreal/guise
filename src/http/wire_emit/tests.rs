use super::*;
use crate::fingerprint::akamai_h2::{AkamaiH2Fingerprint, H2Priority, H2Setting, PseudoHeader};
use crate::fingerprint::StealthProfile;
use crate::http::session_coherence::{
    persona_wire_self_probe, WireSelfProbe, CHROME_H2, FIREFOX_H2, SAFARI_H2,
};

const AUTHORITY: &str = "example.com";

// Profile -> (a persona that maps to it) for the self-probe direction.
fn families() -> Vec<(&'static H2Profile, StealthProfile)> {
    vec![
        (&CHROME_H2, StealthProfile::ChromeWindowsStable),
        (&FIREFOX_H2, StealthProfile::FirefoxLinux),
        (&SAFARI_H2, StealthProfile::SafariMacStable),
    ]
}

#[test]
fn round_trip_reconstructs_each_familys_exact_akamai_string() {
    // The core proof: the BYTES this module emits parse back (via an independent
    // reader) to the persona's exact canonical Akamai fingerprint, for every
    // shipped family. This is what `h2`/`reqwest` cannot do (SETTINGS + pseudo
    // order are fixed there).
    for (profile, _) in families() {
        let bytes = encode_client_opening_for_profile(profile, AUTHORITY, "/")
            .expect("canonical profile must encode");
        let observed = parse_client_akamai(&bytes).expect("our own emission must parse");
        assert_eq!(
            observed,
            profile.akamai_fingerprint(),
            "{}: emitted wire bytes do not reconstruct the model Akamai string",
            profile.family
        );
    }
}

#[test]
fn pseudo_header_order_segment_on_the_wire_matches_each_family() {
    // Localise the round-trip to the load-bearing discriminator: the 4th Akamai
    // segment (pseudo-header order) reconstructed from the emitted HEADERS frame.
    let expect = [
        (&CHROME_H2, "m,a,s,p"),
        (&FIREFOX_H2, "m,p,a,s"),
        (&SAFARI_H2, "m,s,p,a"),
    ];
    for (profile, want) in expect {
        let bytes = encode_client_opening_for_profile(profile, AUTHORITY, "/").unwrap();
        let observed = parse_client_akamai(&bytes).unwrap();
        let segment = observed.split('|').nth(3).unwrap();
        assert_eq!(
            segment, want,
            "{} pseudo-header order on the wire",
            profile.family
        );
    }
}

#[test]
fn emitted_opening_self_probes_coherent_for_each_persona() {
    // Closes the X049 loop with a REAL produced capture (the module that was
    // missing): feed the emitted-then-parsed Akamai into `persona_wire_self_probe`
    // and it must judge the persona's own egress Coherent.
    for (profile, persona) in families() {
        let bytes = encode_client_opening_for_profile(profile, AUTHORITY, "/").unwrap();
        let capture = capture_client_opening(&bytes).expect("emission parses to a capture");
        assert_eq!(
            persona_wire_self_probe(persona, &capture),
            WireSelfProbe::Coherent,
            "{persona:?}: own emitted H2 opening must self-probe Coherent",
        );
    }
}

#[test]
fn firefox_persona_emitting_chrome_h2_is_caught_incoherent() {
    // Negative twin: a Firefox persona whose transport actually emits CHROME's H2
    // opening (the exact "engine != persona" leak X049 exists to catch) must be
    // reported Incoherent with the Akamai layer named (never a silent pass).
    let chrome_bytes = encode_client_opening_for_profile(&CHROME_H2, AUTHORITY, "/").unwrap();
    let capture = capture_client_opening(&chrome_bytes).unwrap();
    let verdict = persona_wire_self_probe(StealthProfile::FirefoxLinux, &capture);
    match verdict {
        WireSelfProbe::Incoherent(mismatches) => {
            let akamai = mismatches
                .iter()
                .find_map(|m| match m {
                    crate::http::session_coherence::WireLayerMismatch::Akamai {
                        expected,
                        observed,
                    } => Some((expected.clone(), observed.clone())),
                    _ => None,
                })
                .expect("the Akamai layer must be the named mismatch");
            assert_eq!(
                akamai.0,
                FIREFOX_H2.akamai_fingerprint(),
                "expected = persona's Firefox H2"
            );
            assert_eq!(
                akamai.1,
                CHROME_H2.akamai_fingerprint(),
                "observed = the emitted Chrome H2"
            );
        }
        other => panic!("Firefox persona emitting Chrome H2 must be Incoherent, got {other:?}"),
    }
}

#[test]
fn wire_round_trip_over_a_real_loopback_socket() {
    // END-TO-END over a real OS socket: the emitter writes a Firefox opening to a
    // loopback TCP stream; an INDEPENDENT server thread reads the raw bytes off the
    // wire, parses them, and reconstructs the Akamai string, which must equal the
    // Firefox model and self-probe Coherent. Proves the bytes survive a real
    // socket, not just an in-memory buffer.
    use std::io::{Read, Write};
    use std::net::{Shutdown, TcpListener, TcpStream};

    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
    let addr = listener.local_addr().unwrap();
    let server = std::thread::spawn(move || -> Result<String, WireParseError> {
        let (mut sock, _) = listener.accept().expect("accept");
        let mut buf = Vec::new();
        sock.read_to_end(&mut buf).expect("read opening");
        parse_client_akamai(&buf)
    });

    let bytes = encode_client_opening_for_profile(&FIREFOX_H2, AUTHORITY, "/").unwrap();
    let mut client = TcpStream::connect(addr).expect("connect loopback");
    client.write_all(&bytes).expect("write opening");
    client
        .shutdown(Shutdown::Write)
        .expect("half-close so server sees EOF");

    let observed = server
        .join()
        .expect("server thread")
        .expect("server parses opening");
    assert_eq!(observed, FIREFOX_H2.akamai_fingerprint());

    let capture = crate::http::session_coherence::WireCapture {
        akamai_fingerprint: Some(observed),
        ..Default::default()
    };
    assert!(persona_wire_self_probe(StealthProfile::FirefoxLinux, &capture).is_coherent());
}

#[test]
fn synthetic_priority_and_window_round_trip() {
    // Exercise the PRIORITY + WINDOW_UPDATE paths the three current personas don't
    // use (they render `0`): an older-Firefox-style shape with a real PRIORITY
    // frame `3:0:0:201` and a connection window increment must round-trip byte-exact.
    let fp = AkamaiH2Fingerprint {
        settings: vec![
            H2Setting {
                id: 1,
                value: 65_536,
            },
            H2Setting {
                id: 4,
                value: 131_072,
            },
            H2Setting {
                id: 5,
                value: 16_384,
            },
        ],
        window_update: 12_517_377,
        priorities: vec![H2Priority {
            stream_id: 3,
            exclusive: 0,
            dependent: 0,
            weight: 201,
        }],
        pseudo_header_order: vec![
            PseudoHeader::Method,
            PseudoHeader::Path,
            PseudoHeader::Authority,
            PseudoHeader::Scheme,
        ],
    };
    let canonical = fp.to_canonical();
    assert_eq!(
        canonical,
        "1:65536;4:131072;5:16384|12517377|3:0:0:201|m,p,a,s"
    );
    let bytes = encode_client_opening(&fp, AUTHORITY, "/");
    assert_eq!(parse_client_akamai(&bytes).unwrap(), canonical);
}

#[test]
fn non_root_path_round_trips_via_literal_path() {
    // The `:path` literal (non-indexed) branch must also reconstruct the order.
    let bytes = encode_client_opening_for_profile(&CHROME_H2, AUTHORITY, "/search?q=1").unwrap();
    let observed = parse_client_akamai(&bytes).unwrap();
    assert_eq!(observed, CHROME_H2.akamai_fingerprint());
}

#[test]
fn emitted_wire_reconstructs_the_published_catalogue_akamai_for_wire_measured_families() {
    // The full chain proven on real bytes (Vectors 9/10): drive the emitter from a
    // family's H2Profile, then assert the INDEPENDENTLY-parsed wire reconstructs the
    // exact Akamai string the `fingerprint::tls_targets` CATALOGUE publishes for the
    // wire-measured families. So the catalogue value a persona is classified against
    // is the same one we actually put on the wire (not merely an internal model).
    use crate::fingerprint::tls_targets::lookup;
    let cases = [
        (&CHROME_H2, "chrome-146-linux"),
        (&FIREFOX_H2, "firefox-150-linux"),
    ];
    for (profile, label) in cases {
        let bytes = encode_client_opening_for_profile(profile, AUTHORITY, "/").unwrap();
        let observed = parse_client_akamai(&bytes).unwrap();
        assert_eq!(
            observed,
            lookup(label).unwrap().akamai_h2,
            "{}: emitted wire Akamai must equal the published {label} catalogue target",
            profile.family
        );
    }
}

#[test]
fn bad_preface_fails_closed() {
    let err = parse_client_akamai(b"GET / HTTP/1.1\r\n\r\n").unwrap_err();
    assert_eq!(err, WireParseError::BadPreface);
}

#[test]
fn truncated_opening_fails_closed_not_partial() {
    // Chop the last frame mid-payload: the parser must error, never return a
    // partial Akamai string that could read as agreement.
    let bytes = encode_client_opening_for_profile(&CHROME_H2, AUTHORITY, "/").unwrap();
    let truncated = &bytes[..bytes.len() - 3];
    assert!(matches!(
        parse_client_akamai(truncated),
        Err(WireParseError::Truncated | WireParseError::NoHeaders)
    ));
}

#[test]
fn opening_without_headers_fails_closed() {
    // Only the preface + SETTINGS, no HEADERS frame: there is no observed
    // pseudo-header order, so the parser refuses rather than inventing one.
    let mut bytes = Vec::new();
    bytes.extend_from_slice(H2_CLIENT_PREFACE);
    // an empty SETTINGS frame
    super::push_frame(&mut bytes, 0x4, 0, 0, &[]);
    assert_eq!(parse_client_akamai(&bytes), Err(WireParseError::NoHeaders));
}
