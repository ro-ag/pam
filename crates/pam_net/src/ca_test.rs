use super::ca::{CaError, MAX_CERTIFICATES, decode_base64, normalize_pem};

/// A DER-looking body: a SEQUENCE tag, then filler. What matters here is
/// that it decodes and starts with `0x30`.
fn block(label: &str, der: &[u8]) -> String {
    let body = crate::testing::base64(der);
    let mut text = format!("-----BEGIN {label}-----\n");
    for chunk in body.as_bytes().chunks(64) {
        text.push_str(std::str::from_utf8(chunk).unwrap());
        text.push('\n');
    }
    text.push_str("-----END ");
    text.push_str(label);
    text.push_str("-----\n");
    text
}

fn certificate(filler: u8) -> String {
    let mut der = vec![0x30, 0x82, 0x01, 0x00];
    der.extend(std::iter::repeat_n(filler, 200));
    block("CERTIFICATE", &der)
}

#[test]
fn base64_round_trips_the_reference_vectors() {
    for (text, bytes) in [
        ("", None),
        ("Zg==", Some(b"f".to_vec())),
        ("Zm8=", Some(b"fo".to_vec())),
        ("Zm9v", Some(b"foo".to_vec())),
        ("Zm9vYg==", Some(b"foob".to_vec())),
        ("Zm9vYmE=", Some(b"fooba".to_vec())),
        ("Zm9vYmFy", Some(b"foobar".to_vec())),
        ("Zm9vYmF", None),
        ("Zm9v=mFy", None),
        ("Zm9vYmF===", None),
        ("Zm9v YmFy", None),
        ("Zm9v\nYmFy", None),
    ] {
        assert_eq!(decode_base64(text), bytes, "{text:?}");
    }
    let every: Vec<u8> = (0..=255).collect();
    assert_eq!(
        decode_base64(&crate::testing::base64(&every)),
        Some(every.clone())
    );
}

#[test]
fn a_bundle_is_reduced_to_its_certificate_blocks() {
    let source = format!(
        "# Corp roots, distributed by IT\r\n\r\n{}Subject: CN=Other\r\n{}trailing words\n",
        certificate(1).replace('\n', "\r\n"),
        block("TRUSTED CERTIFICATE", &[0x30, 0x03, 1, 2, 3])
    );
    let bundle = normalize_pem(source.as_bytes()).expect("a bundle");
    assert_eq!(bundle.certificates, 1);
    assert_eq!(bundle.pem, certificate(1));
    // The normalized form is a fixed point.
    assert_eq!(normalize_pem(bundle.pem.as_bytes()).unwrap(), bundle);

    let two = format!("{}{}", certificate(1), certificate(2));
    assert_eq!(normalize_pem(two.as_bytes()).unwrap().certificates, 2);
}

#[test]
fn explanatory_headers_inside_a_block_are_dropped() {
    let der = [0x30, 0x05, 9, 8, 7, 6, 5];
    let body = crate::testing::base64(&der);
    let source = format!(
        "-----BEGIN CERTIFICATE-----\nProc-Type: 4,PLAIN\n\n{body}\n-----END CERTIFICATE-----\n"
    );
    let bundle = normalize_pem(source.as_bytes()).unwrap();
    assert_eq!(bundle.pem, block("CERTIFICATE", &der));
}

#[test]
fn every_kind_of_private_key_refuses_the_whole_file() {
    for label in [
        "PRIVATE KEY",
        "RSA PRIVATE KEY",
        "EC PRIVATE KEY",
        "ENCRYPTED PRIVATE KEY",
        "private key",
    ] {
        let source = format!("{}{}", certificate(1), block(label, b"secret"));
        assert_eq!(
            normalize_pem(source.as_bytes()),
            Err(CaError::PrivateKey),
            "{label}"
        );
    }
    assert!(CaError::PrivateKey.to_string().contains("private key"));
}

#[test]
fn files_that_are_not_certificate_bundles_are_refused_by_name() {
    assert_eq!(normalize_pem(b""), Err(CaError::NoCertificate));
    assert_eq!(
        normalize_pem(b"just some text\n"),
        Err(CaError::NoCertificate)
    );
    assert_eq!(
        normalize_pem(block("X509 CRL", &[0x30, 0]).as_bytes()),
        Err(CaError::NoCertificate)
    );
    assert_eq!(normalize_pem(&[0xff, 0xfe, 0x00]), Err(CaError::NotText));
    assert_eq!(
        normalize_pem(b"-----BEGIN CERTIFICATE-----\nMIIB\n"),
        Err(CaError::Unterminated {
            label: "CERTIFICATE".to_owned()
        })
    );
    assert_eq!(
        normalize_pem(b"-----BEGIN CERTIFICATE-----\nMIIB\n-----END TRUSTED CERTIFICATE-----\n"),
        Err(CaError::Unterminated {
            label: "CERTIFICATE".to_owned()
        })
    );
    let nested = "-----BEGIN CERTIFICATE-----\n-----BEGIN CERTIFICATE-----\n";
    assert!(matches!(
        normalize_pem(nested.as_bytes()),
        Err(CaError::Unterminated { .. })
    ));
}

#[test]
fn a_block_that_is_not_der_is_named_by_its_position() {
    let bad_base64 = format!(
        "{}-----BEGIN CERTIFICATE-----\nnot*base64\n-----END CERTIFICATE-----\n",
        certificate(1)
    );
    assert_eq!(
        normalize_pem(bad_base64.as_bytes()),
        Err(CaError::Malformed { index: 2 })
    );
    let not_der = block("CERTIFICATE", b"plain bytes");
    assert_eq!(
        normalize_pem(not_der.as_bytes()),
        Err(CaError::Malformed { index: 1 })
    );
    let empty = "-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----\n";
    assert_eq!(
        normalize_pem(empty.as_bytes()),
        Err(CaError::Malformed { index: 1 })
    );
}

#[test]
fn the_certificate_count_is_bounded() {
    let many: String = (0..=MAX_CERTIFICATES).map(|_| certificate(3)).collect();
    assert_eq!(normalize_pem(many.as_bytes()), Err(CaError::TooMany));
}

#[test]
fn the_committed_test_ca_normalizes_to_one_certificate() {
    let bytes = std::fs::read(crate::testing::test_ca()).expect("the fixture is committed");
    let bundle = normalize_pem(&bytes).expect("the test CA is a bundle");
    assert_eq!(bundle.certificates, 1);
    assert!(bundle.pem.starts_with("-----BEGIN CERTIFICATE-----\n"));
    assert!(bundle.pem.ends_with("-----END CERTIFICATE-----\n"));
}
