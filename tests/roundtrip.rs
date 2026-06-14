use pdf_signer::testkit::{sample_pdf, self_signed_p12};
use pdf_signer::{sign_pdf_bytes, verify_pdf_bytes, Appearance, SignOptions};

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
        signed.windows(b"adbe.pkcs7.detached".len())
            .any(|w| w == b"adbe.pkcs7.detached"),
        "signed PDF must contain the signature SubFilter"
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
fn unsigned_document_reports_no_signatures() {
    let pdf = sample_pdf();
    let report = verify_pdf_bytes(&pdf).expect("verify failed");
    assert!(report.signatures.is_empty());
    assert!(!report.all_valid());
}
