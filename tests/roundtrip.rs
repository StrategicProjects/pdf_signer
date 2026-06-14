use pdf_signer::testkit::{sample_pdf, self_signed_p12};
use pdf_signer::{sign_pdf_bytes, verify_pdf_bytes, SignOptions};

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
fn unsigned_document_reports_no_signatures() {
    let pdf = sample_pdf();
    let report = verify_pdf_bytes(&pdf).expect("verify failed");
    assert!(report.signatures.is_empty());
    assert!(!report.all_valid());
}
