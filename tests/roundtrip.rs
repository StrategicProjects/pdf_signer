use pdf_signer::testkit::{
    ca_chain3_p12, ca_signed_p12, sample_pdf, self_signed_p12, self_signed_p256_p12,
    self_signed_p384_p12,
};
use pdf_signer::{
    sign_pdf_bytes, verify_pdf_bytes, verify_pdf_bytes_with_roots, Appearance, PadesLevel,
    SignOptions, TrustStore,
};

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

#[test]
fn sign_then_verify_roundtrip() {
    let pdf = sample_pdf();
    let p12 = self_signed_p12("password");

    let opts = SignOptions {
        reason: Some("Proof of concept".into()),
        name: Some("pdf_signer PoC".into()),
        signing_time: Some("D:20260614120000Z".into()),
        ..Default::default()
    };
    let signed = sign_pdf_bytes(&pdf, &p12, "password", &opts).expect("signing failed");

    assert!(signed.len() > pdf.len(), "signed PDF should grow");
    assert!(
        contains(&signed, b"ETSI.CAdES.detached"),
        "signed PDF must carry the PAdES SubFilter"
    );

    let report = verify_pdf_bytes(&signed).expect("verify failed");
    assert_eq!(report.signatures.len(), 1, "exactly one signature expected");
    let s = &report.signatures[0];
    assert!(s.valid, "signature must verify: {}", s.detail);
    assert!(s.covers_whole_document, "byte range must cover whole doc");
    assert!(report.all_valid());
}

#[test]
fn tampered_document_is_rejected() {
    let pdf = sample_pdf();
    let p12 = self_signed_p12("pw");
    let mut signed =
        sign_pdf_bytes(&pdf, &p12, "pw", &SignOptions::default()).expect("signing failed");

    // Flip a byte inside the signed header region (well before the signature).
    signed[20] ^= 0xff;

    let report = verify_pdf_bytes(&signed).expect("verify failed");
    assert!(
        !report.signatures[0].valid,
        "a modified document must fail verification"
    );
}

#[test]
fn visible_appearance_round_trip() {
    let pdf = sample_pdf();
    let p12 = self_signed_p12("pw");
    let opts = SignOptions {
        reason: Some("Aprovado".into()),
        appearance: Some(Appearance {
            text: "Assinado digitalmente por Fulano.\nValidar em: exemplo.org/validar".into(),
            ..Appearance::default()
        }),
        ..Default::default()
    };
    let signed = sign_pdf_bytes(&pdf, &p12, "pw", &opts).expect("signing failed");

    // The widget now carries an appearance stream and a Form XObject.
    assert!(contains(&signed, b"/AP"), "widget should have an /AP entry");
    assert!(contains(&signed, b"/Subtype /Form") || contains(&signed, b"/Subtype/Form"));
    assert!(contains(&signed, b"/Helv"), "appearance font should be present");

    // And the signature must still verify after adding the appearance.
    let report = verify_pdf_bytes(&signed).expect("verify failed");
    assert!(report.signatures[0].valid, "{}", report.signatures[0].detail);
    assert!(report.signatures[0].covers_whole_document);
}

#[test]
fn incremental_update_preserves_original_bytes() {
    let pdf = sample_pdf();
    let p12 = self_signed_p12("pw");
    let signed = sign_pdf_bytes(&pdf, &p12, "pw", &SignOptions::default()).expect("sign");
    // An incremental update appends; the original is an exact byte prefix.
    assert!(signed.len() > pdf.len());
    assert_eq!(&signed[..pdf.len()], &pdf[..], "original bytes must be intact");
    assert!(contains(&signed, b"/Prev"), "update trailer should chain /Prev");
}

#[test]
fn second_signature_keeps_the_first_valid() {
    let pdf = sample_pdf();
    let p12 = self_signed_p12("pw");

    let first = sign_pdf_bytes(&pdf, &p12, "pw", &SignOptions {
        reason: Some("Primeira".into()),
        ..Default::default()
    })
    .expect("first sign");

    let second = sign_pdf_bytes(&first, &p12, "pw", &SignOptions {
        reason: Some("Segunda".into()),
        ..Default::default()
    })
    .expect("second sign");

    // The first signed file is preserved verbatim as a prefix of the second.
    assert_eq!(&second[..first.len()], &first[..], "first signature bytes intact");

    let report = verify_pdf_bytes(&second).expect("verify");
    assert_eq!(report.signatures.len(), 2, "two signatures expected");
    assert!(report.all_valid(), "both signatures must verify");

    // The earlier signature covers the doc as it was; the later one covers all.
    assert!(!report.signatures[0].covers_whole_document);
    assert!(report.signatures[1].covers_whole_document);
}

#[test]
fn pades_bb_carries_signing_certificate() {
    let pdf = sample_pdf();
    let p12 = self_signed_p12("pw");
    let signed = sign_pdf_bytes(&pdf, &p12, "pw", &SignOptions::default()).expect("sign");

    assert!(contains(&signed, b"ETSI.CAdES.detached"), "PAdES SubFilter");
    // id-aa-signingCertificateV2 OID, hex-encoded inside /Contents.
    assert!(
        contains(&signed, b"060b2a864886f70d010910022f"),
        "CMS must carry signing-certificate-v2 (PAdES-B-B)"
    );
    assert!(verify_pdf_bytes(&signed).expect("verify").all_valid());
}

#[test]
#[ignore = "requires network access to a public RFC 3161 TSA"]
fn pades_bt_embeds_timestamp() {
    let pdf = sample_pdf();
    let p12 = self_signed_p12("pw");
    let opts = SignOptions {
        tsa_url: Some("http://timestamp.digicert.com".into()),
        ..Default::default()
    };
    let signed = sign_pdf_bytes(&pdf, &p12, "pw", &opts).expect("sign + timestamp");

    // id-aa-timeStampToken OID, hex-encoded inside /Contents.
    assert!(
        contains(&signed, b"060b2a864886f70d010910020e"),
        "CMS must carry an RFC 3161 timestamp token (PAdES-B-T)"
    );
    assert!(verify_pdf_bytes(&signed).expect("verify").all_valid());
}

#[test]
#[ignore = "requires network + the `https` feature: cargo test --features https -- --ignored"]
fn pades_bt_over_https_tsa() {
    let pdf = sample_pdf();
    let p12 = self_signed_p12("pw");
    let opts = SignOptions {
        pades_level: PadesLevel::Bt,
        tsa_url: Some("https://freetsa.org/tsr".into()),
        ..Default::default()
    };
    let signed = sign_pdf_bytes(&pdf, &p12, "pw", &opts).expect("B-T over HTTPS TSA");
    assert!(
        contains(&signed, b"060b2a864886f70d010910020e"),
        "timestamp token embedded"
    );
    assert!(verify_pdf_bytes(&signed).expect("verify").all_valid());
}

#[test]
#[ignore = "requires network access (TSA + CRL fetch)"]
fn pades_blta_builds_dss_and_document_timestamp() {
    let pdf = sample_pdf();
    let p12 = self_signed_p12("pw");
    let opts = SignOptions {
        pades_level: PadesLevel::Blta,
        tsa_url: Some("http://timestamp.digicert.com".into()),
        ..Default::default()
    };
    let signed = sign_pdf_bytes(&pdf, &p12, "pw", &opts).expect("B-LTA sign");

    assert!(contains(&signed, b"/DSS"), "Document Security Store");
    assert!(contains(&signed, b"/Certs"), "DSS certificates");
    // The DigiCert TSA chain has AIA, so CRLs + OCSP responses get embedded.
    assert!(contains(&signed, b"/CRLs"), "DSS CRLs");
    assert!(contains(&signed, b"/OCSPs"), "DSS OCSP responses");
    assert!(contains(&signed, b"DocTimeStamp"), "document timestamp");
    assert!(contains(&signed, b"ETSI.RFC3161"), "doc-timestamp SubFilter");

    let report = verify_pdf_bytes(&signed).expect("verify");
    assert_eq!(report.signatures.len(), 2, "signature + document timestamp");
    assert!(report.all_valid(), "both must validate");
    assert!(report.signatures[1].detail.contains("timestamp"));
}

#[test]
fn chain_validates_against_trusted_root() {
    let pdf = sample_pdf();
    let (p12, root_der) = ca_signed_p12("pw");
    let signed = sign_pdf_bytes(&pdf, &p12, "pw", &SignOptions::default()).expect("sign");

    // Trusted: the issuing root is in the store.
    let store = TrustStore::from_ders([root_der]).expect("store");
    let report = verify_pdf_bytes_with_roots(&signed, &store).expect("verify");
    assert!(report.signatures[0].valid);
    assert_eq!(
        report.signatures[0].chain_trusted,
        Some(true),
        "{}",
        report.signatures[0].detail
    );

    // No store -> no chain check performed.
    let none = verify_pdf_bytes(&signed).expect("verify");
    assert_eq!(none.signatures[0].chain_trusted, None);

    // A different (untrusted) root -> chain not trusted, even though the test
    // roots share a subject name (the signature check is what rejects it).
    let (_, other_root) = ca_signed_p12("pw");
    let store2 = TrustStore::from_ders([other_root]).expect("store2");
    let report2 = verify_pdf_bytes_with_roots(&signed, &store2).expect("verify");
    assert_eq!(report2.signatures[0].chain_trusted, Some(false));
}

#[test]
fn chain_validates_through_intermediate_ca() {
    let pdf = sample_pdf();
    let (p12, root_der) = ca_chain3_p12("pw");
    let signed = sign_pdf_bytes(&pdf, &p12, "pw", &SignOptions::default()).expect("sign");

    // The CMS now embeds the full chain, so the path leaf -> intermediate ->
    // root can be built; the intermediate must pass the CA / keyCertSign checks.
    let store = TrustStore::from_ders([root_der]).expect("store");
    let report = verify_pdf_bytes_with_roots(&signed, &store).expect("verify");
    assert!(report.signatures[0].valid);
    assert_eq!(
        report.signatures[0].chain_trusted,
        Some(true),
        "{}",
        report.signatures[0].detail
    );
}

#[test]
fn ecdsa_p256_sign_and_verify() {
    let pdf = sample_pdf();
    let p12 = self_signed_p256_p12("pw");
    let signed = sign_pdf_bytes(&pdf, &p12, "pw", &SignOptions::default()).expect("P-256 sign");
    let report = verify_pdf_bytes(&signed).expect("verify");
    assert!(report.signatures[0].valid, "{}", report.signatures[0].detail);
}

#[test]
fn ecdsa_p384_sign_and_verify() {
    let pdf = sample_pdf();
    let p12 = self_signed_p384_p12("pw");
    let signed = sign_pdf_bytes(&pdf, &p12, "pw", &SignOptions::default()).expect("P-384 sign");
    let report = verify_pdf_bytes(&signed).expect("verify");
    assert!(report.signatures[0].valid, "{}", report.signatures[0].detail);
}

#[test]
fn unsigned_document_reports_no_signatures() {
    let pdf = sample_pdf();
    let report = verify_pdf_bytes(&pdf).expect("verify failed");
    assert!(report.signatures.is_empty());
    assert!(!report.all_valid());
}
