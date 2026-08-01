//! Offline Layer-2 regression against the local `guise-echo` service (G068).
//!
//! This test removes the third-party flakiness of live reflectors (`tls.peet.ws`)
//! for the subset of the wire fingerprint we can deterministically replay: the TLS
//! ClientHello parsed by guise itself, the negotiated ALPN, and the host TCP/IP
//! diagnostics. It is gated behind the same `fingerprint` + `http` features that
//! power guise-echo's JA3/JA4 computation and ALPN handling.
#![cfg(all(feature = "fingerprint", feature = "http"))]

use std::net::SocketAddr;
use std::sync::Arc;

use rustls::pki_types::ServerName;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

/// A test-only certificate verifier that accepts guise-echo's self-signed cert.
#[derive(Debug)]
struct NoVerifier;

impl rustls::client::danger::ServerCertVerifier for NoVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::ECDSA_NISTP521_SHA512,
            rustls::SignatureScheme::ED25519,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA512,
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA384,
            rustls::SignatureScheme::RSA_PKCS1_SHA512,
        ]
    }
}

#[tokio::test]
async fn local_echo_reports_tls_alpn_and_tcp_diagnostics() {
    // guise-echo uses rustls 0.23; the workspace has both ring and aws-lc-rs in
    // the graph, so an explicit provider selection is required before any config
    // is built. The same call in guise-echo itself handles the server side.
    let _ = rustls::crypto::ring::default_provider().install_default();

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr: SocketAddr = listener.local_addr().unwrap();

    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        guise_echo::accept_one_for_test(stream).await.unwrap()
    });

    let mut config = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoVerifier))
        .with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    let connector = TlsConnector::from(Arc::new(config));

    let stream = TcpStream::connect(addr).await.unwrap();
    let server_name = ServerName::try_from("localhost").unwrap();
    let mut tls_stream = connector.connect(server_name, stream).await.unwrap();

    tls_stream
        .write_all(b"GET /echo HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .await
        .unwrap();

    let mut response = Vec::new();
    tls_stream.read_to_end(&mut response).await.unwrap();

    let body_start = response
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .expect("HTTP response has a body separator");
    let body = &response[body_start + 4..];
    let info: serde_json::Value = serde_json::from_slice(body).expect("response body is JSON");

    let tls = info.get("tls").expect("tls field present");
    let ja4 = tls["ja4"].as_str().expect("ja4 is a string");
    assert!(!ja4.is_empty(), "echoed JA4 must not be empty");
    assert!(
        ja4.starts_with("t13"),
        "TLS 1.3 JA4 must start with t13: {ja4}"
    );

    // Recompute JA4 from the echoed fields to prove the echo service's computation
    // is consistent with guise's own ja3 module (regression lock on the computation
    // path, not just the response shape).
    let echoed_fields = guise::fingerprint::ja3::ClientHelloFields {
        version: tls["legacy_version"].as_u64().unwrap() as u16,
        cipher_suites: serde_json::from_value(tls["cipher_suites"].clone()).unwrap(),
        extensions: serde_json::from_value(tls["extensions"].clone()).unwrap(),
        supported_groups: serde_json::from_value(tls["supported_groups"].clone()).unwrap(),
        ec_point_formats: serde_json::from_value(tls["ec_point_formats"].clone()).unwrap(),
        alpn: serde_json::from_value(tls["alpn"].clone()).unwrap(),
        signature_algorithms: serde_json::from_value(tls["signature_algorithms"].clone()).unwrap(),
        supported_versions: serde_json::from_value(tls["supported_versions"].clone()).unwrap(),
    };
    let recomputed = guise::fingerprint::ja3::compute_ja4(&echoed_fields);
    assert_eq!(
        recomputed, ja4,
        "echo service JA4 must equal guise's recomputed JA4 from the echoed fields"
    );

    assert_eq!(
        tls["alpn"],
        serde_json::json!([[104, 116, 116, 112, 47, 49, 46, 49]]),
        "client advertised http/1.1 as raw ALPN bytes"
    );

    // http/1.1 was negotiated (the H2 reflector must be absent/null).
    assert!(
        info.get("h2").map(|v| v.is_null()).unwrap_or(true),
        "http/1.1 negotiation must not produce H2 frame info"
    );

    let tcp = info.get("tcp").expect("tcp field present");
    if cfg!(target_os = "linux") {
        assert!(
            tcp["host_ttl"].as_u64().is_some_and(|v| v > 0),
            "Linux host TTL must be a positive byte"
        );
        assert!(
            tcp["timestamps_enabled"].is_boolean()
                && tcp["sack_enabled"].is_boolean()
                && tcp["window_scaling_enabled"].is_boolean(),
            "Linux TCP option knobs must be reported as booleans"
        );
    }

    let _info = server.await.unwrap();
}
