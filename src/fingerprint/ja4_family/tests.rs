use crate::fingerprint::ja4_family::{
    compute_ja4l, compute_ja4l_from_tcp_handshake, compute_ja4s, compute_ja4x, light_distance_km,
    light_distance_miles, oid_to_hex, CertificateFields, LatencySample, LatencySide,
    ServerHelloFields, TcpHandshakeRole, TransportProto,
};

// ---------------------------------------------------------------------------
// JA4S
// ---------------------------------------------------------------------------

#[test]
fn ja4s_sliver_vector() {
    // Published FoxIO example: Sliver C2 ServerHello.
    // Corresponds to TLS 1.3, no ALPN, cipher 0x1301, extensions [supported_versions, key_share].
    let fields = ServerHelloFields {
        version: 0x0303,
        supported_versions: vec![0x0304],
        cipher: 0x1301,
        extensions: vec![0x002b, 0x0033],
        alpn: vec![],
        proto: TransportProto::Tcp,
    };
    assert_eq!(compute_ja4s(&fields), "t130200_1301_a56c5b993250");
}

#[test]
fn ja4s_softether_vector() {
    // Published FoxIO example: SoftEther VPN ServerHello, cipher 0x1302.
    let fields = ServerHelloFields {
        version: 0x0303,
        supported_versions: vec![0x0304],
        cipher: 0x1302,
        extensions: vec![0x002b, 0x0033],
        alpn: vec![],
        proto: TransportProto::Tcp,
    };
    assert_eq!(compute_ja4s(&fields), "t130200_1302_a56c5b993250");
}

#[test]
fn ja4s_alpn_is_rendered() {
    let fields = ServerHelloFields {
        version: 0x0303,
        supported_versions: vec![0x0304],
        cipher: 0x1301,
        extensions: vec![0x002b],
        alpn: vec!["h2".to_string()],
        proto: TransportProto::Tcp,
    };
    assert_eq!(compute_ja4s(&fields), "t1301h2_1301_b9a491fefe05");
}

#[test]
fn ja4s_empty_extensions_use_zero_hash() {
    let fields = ServerHelloFields {
        version: 0x0303,
        supported_versions: vec![0x0304],
        cipher: 0x1301,
        extensions: vec![],
        alpn: vec![],
        proto: TransportProto::Tcp,
    };
    assert_eq!(compute_ja4s(&fields), "t130000_1301_000000000000");
}

#[test]
fn ja4s_version_falls_back_to_legacy_when_supported_versions_absent() {
    let fields = ServerHelloFields {
        version: 0x0302,
        supported_versions: vec![],
        cipher: 0xc030,
        extensions: vec![0x002b, 0x0000, 0x0015],
        alpn: vec![],
        proto: TransportProto::Tcp,
    };
    assert!(compute_ja4s(&fields).starts_with("t11"));
}

#[test]
fn ja4s_grease_is_skipped_for_version() {
    let fields = ServerHelloFields {
        version: 0x0303,
        supported_versions: vec![0x0a0a, 0x0304, 0x1a1a],
        cipher: 0x1301,
        extensions: vec![0x002b],
        alpn: vec![],
        proto: TransportProto::Tcp,
    };
    assert!(compute_ja4s(&fields).starts_with("t13"));
}

#[test]
fn ja4s_extension_count_caps_at_99() {
    let fields = ServerHelloFields {
        version: 0x0303,
        supported_versions: vec![0x0304],
        cipher: 0x1301,
        extensions: vec![0x0001; 150],
        alpn: vec![],
        proto: TransportProto::Tcp,
    };
    assert!(compute_ja4s(&fields).contains("99"));
}

#[test]
fn ja4s_quic_prefix() {
    let fields = ServerHelloFields {
        version: 0x0303,
        supported_versions: vec![0x0304],
        cipher: 0x1301,
        extensions: vec![0x002b],
        alpn: vec![],
        proto: TransportProto::Quic,
    };
    assert!(compute_ja4s(&fields).starts_with('q'));
}

// ---------------------------------------------------------------------------
// JA4L
// ---------------------------------------------------------------------------

#[test]
fn ja4l_client_format() {
    let sample = LatencySample {
        side: LatencySide::Client,
        latency_us: 12_345,
        ttl: 64,
    };
    assert_eq!(compute_ja4l(&sample), "JA4L-C=12345_64");
}

#[test]
fn ja4l_server_format() {
    let sample = LatencySample {
        side: LatencySide::Server,
        latency_us: 987_654_321,
        ttl: 128,
    };
    assert_eq!(compute_ja4l(&sample), "JA4L-S=987654321_128");
}

#[test]
fn ja4l_tcp_handshake_roles() {
    assert_eq!(
        compute_ja4l_from_tcp_handshake(TcpHandshakeRole::Syn, 100, 64),
        None
    );
    assert_eq!(
        compute_ja4l_from_tcp_handshake(TcpHandshakeRole::SynAck, 100, 128),
        Some("JA4L-S=100_128".to_string())
    );
    assert_eq!(
        compute_ja4l_from_tcp_handshake(TcpHandshakeRole::Ack, 100, 64),
        Some("JA4L-C=100_64".to_string())
    );
}

#[test]
fn ja4l_distance_estimate_is_non_negative_and_monotonic() {
    let d1 = light_distance_miles(1_000, 1.6);
    let d2 = light_distance_miles(2_000, 1.6);
    assert!(d1 >= 0.0);
    assert!(d2 > d1);

    let km1 = light_distance_km(1_000, 1.6);
    let km2 = light_distance_km(2_000, 1.6);
    assert!(km1 >= 0.0);
    assert!(km2 > km1);
}

// ---------------------------------------------------------------------------
// OID → hex
// ---------------------------------------------------------------------------

#[test]
fn oid_to_hex_common_name() {
    assert_eq!(oid_to_hex("2.5.4.3").unwrap(), "550403");
}

#[test]
fn oid_to_hex_subject_alt_name() {
    assert_eq!(oid_to_hex("2.5.29.17").unwrap(), "551d11");
}

#[test]
fn oid_to_hex_large_component() {
    // 1.2.840.113549 -> PKCS OID; 840 and 113549 need VLQ encoding.
    // 1*40+2 = 0x2a; 840 = 0x86 0x48; 113549 = 0x86 f7 0d
    assert_eq!(oid_to_hex("1.2.840.113549").unwrap(), "2a864886f70d");
}

#[test]
fn oid_to_hex_rejects_invalid() {
    assert!(oid_to_hex("not-an-oid").is_err());
    assert!(oid_to_hex("1").is_err());
    assert!(oid_to_hex("").is_err());
}

// ---------------------------------------------------------------------------
// JA4X
// ---------------------------------------------------------------------------

#[test]
fn ja4x_self_signed_cn_san_vector() {
    // Reproduces the Python ja4plus reference output for a self-signed cert
    // whose issuer/subject each contain only CN (OID 2.5.4.3) and whose only
    // extension is SubjectAltName (OID 2.5.29.17).
    let fields = CertificateFields {
        issuer_rdns: vec!["550403".to_string()],
        subject_rdns: vec!["550403".to_string()],
        extensions: vec!["551d11".to_string()],
    };
    assert_eq!(
        compute_ja4x(&fields),
        "7022c563de38_7022c563de38_6ea8df877ef2"
    );
}

#[test]
fn ja4x_empty_fields_use_sentinel() {
    let fields = CertificateFields::default();
    assert_eq!(
        compute_ja4x(&fields),
        "000000000000_000000000000_000000000000"
    );
}

#[test]
fn ja4x_hashes_change_when_structure_changes() {
    let base = CertificateFields {
        issuer_rdns: vec!["550403".to_string()],
        subject_rdns: vec!["550403".to_string()],
        extensions: vec!["551d11".to_string()],
    };
    let mut different_subject = base.clone();
    different_subject.subject_rdns = vec!["550404".to_string()];

    let base_fp = compute_ja4x(&base);
    let different_fp = compute_ja4x(&different_subject);
    assert_ne!(base_fp, different_fp);
    assert_eq!(
        base_fp.split('_').next(),
        different_fp.split('_').next(),
        "issuer hash must stay identical"
    );
}

#[test]
fn ja4x_issuer_and_subject_independence() {
    let only_issuer = CertificateFields {
        issuer_rdns: vec!["550403".to_string()],
        ..CertificateFields::default()
    };
    let only_subject = CertificateFields {
        subject_rdns: vec!["550403".to_string()],
        ..CertificateFields::default()
    };
    let issuer_fp = compute_ja4x(&only_issuer);
    let subject_fp = compute_ja4x(&only_subject);
    assert_ne!(issuer_fp, subject_fp);
    assert!(issuer_fp.starts_with("7022c563de38_000000000000"));
    assert!(subject_fp.starts_with("000000000000_7022c563de38"));
}
