use pdf_signer::testkit::{
    ca_chain3_p12, ca_chain_policy_mapping_p12, ca_name_constrained_p12, ca_signed_p12,
    ca_with_policy_p12, sample_pdf, sample_pdf_xref_stream, self_signed_ed25519_p12,
    self_signed_p12, self_signed_p256_p12, self_signed_p384_p12, tiny_png,
};
use pdf_signer::{
    sign_pdf_bytes, verify_pdf_bytes, verify_pdf_bytes_with_roots, Appearance, PadesLevel,
    SignOptions, TrustStore,
};

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
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
fn coverage_requires_byterange_to_match_contents() {
    let pdf = sample_pdf();
    let p12 = self_signed_p12("pw");
    let mut signed = sign_pdf_bytes(&pdf, &p12, "pw", &SignOptions::default()).expect("sign");

    // Untampered: the ByteRange gap is exactly the /Contents hex string.
    let report = verify_pdf_bytes(&signed).expect("verify");
    assert!(
        report.signatures[0].covers_whole_document,
        "a normal signature must cover the whole document"
    );

    // Tamper *only* the /ByteRange numbers: shrink the first segment by 4 bytes
    // so the excluded gap now starts before the real `/Contents` `<`, leaving 4
    // bytes outside the signature that are NOT the Contents string. The byte
    // span 0..EOF is still spanned, so this exercises the new binding check
    // (issue #3), not the old start/end check.
    let open = find(&signed, b"/ByteRange").expect("ByteRange");
    let lb = open + find(&signed[open..], b"[").expect("[");
    let rb = lb + find(&signed[lb..], b"]").expect("]");
    let span = rb - lb + 1;
    let nums: Vec<i64> = std::str::from_utf8(&signed[lb + 1..rb])
        .unwrap()
        .split_whitespace()
        .map(|t| t.parse().unwrap())
        .collect();
    assert_eq!(nums.len(), 4);
    let mut repl = format!("[{} {} {} {}]", nums[0], nums[1] - 4, nums[2], nums[3]).into_bytes();
    assert!(repl.len() <= span);
    while repl.len() < span {
        repl.insert(repl.len() - 1, b' ');
    }
    signed[lb..=rb].copy_from_slice(&repl);

    let report2 = verify_pdf_bytes(&signed).expect("verify");
    assert!(
        !report2.signatures[0].covers_whole_document,
        "a ByteRange gap that does not match /Contents must not claim whole-document coverage"
    );
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
fn timestamped_levels_require_a_tsa_url() {
    let pdf = sample_pdf();
    let p12 = self_signed_p12("pw");

    // B-T / B-LT / B-LTA without a TSA must fail loudly, not silently
    // downgrade to B-B (issue #1).
    for level in [PadesLevel::Bt, PadesLevel::Blt, PadesLevel::Blta] {
        let opts = SignOptions {
            pades_level: level,
            tsa_url: None,
            ..Default::default()
        };
        let err = sign_pdf_bytes(&pdf, &p12, "pw", &opts).expect_err("must require a TSA");
        assert!(
            err.to_string().contains("tsa_url"),
            "error should mention the missing tsa_url, got: {err}"
        );
    }

    // B-B needs no TSA and still signs.
    let opts = SignOptions {
        pades_level: PadesLevel::Bb,
        tsa_url: None,
        ..Default::default()
    };
    assert!(sign_pdf_bytes(&pdf, &p12, "pw", &opts).is_ok());
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
fn all_trusted_separates_validity_from_trust() {
    let pdf = sample_pdf();
    let (p12, root_der) = ca_signed_p12("pw");
    let signed = sign_pdf_bytes(&pdf, &p12, "pw", &SignOptions::default()).expect("sign");

    // Trusted root: valid AND trusted.
    let store = TrustStore::from_ders([root_der]).expect("store");
    let report = verify_pdf_bytes_with_roots(&signed, &store).expect("verify");
    assert!(report.all_valid());
    assert!(report.all_trusted(), "{}", report.signatures[0].detail);

    // Untrusted root: cryptographically valid but NOT trusted. This is the
    // regression guard for issue #2 — `all_valid` must not imply `all_trusted`.
    let (_, other_root) = ca_signed_p12("pw");
    let store2 = TrustStore::from_ders([other_root]).expect("store2");
    let report2 = verify_pdf_bytes_with_roots(&signed, &store2).expect("verify");
    assert!(report2.all_valid(), "signature is still crypto-valid");
    assert!(
        !report2.all_trusted(),
        "an untrusted chain must not count as trusted"
    );

    // No trust store: `all_trusted` falls back to validity (no Some(false)).
    let none = verify_pdf_bytes(&signed).expect("verify");
    assert!(none.all_valid());
    assert!(none.all_trusted());
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
fn cross_signed_chain_finds_the_trusted_branch() {
    use pdf_signer::{testkit::cross_signed_scenario, verify_certificate_chain};
    use std::time::SystemTime;

    // The intermediate is cross-certified by an untrusted root A and a trusted
    // root B; the pool lists the untrusted cross-cert first. Path building must
    // backtrack past it and reach root B (issue #9). A first-match-only builder
    // would commit to the A branch and fail.
    let (leaf, pool, trusted_root_b) = cross_signed_scenario();
    let store = TrustStore::from_ders([trusted_root_b]).expect("store");
    assert!(
        verify_certificate_chain(&leaf, &pool, &[], &store, SystemTime::now()),
        "backtracking must find the trusted cross-signed branch"
    );

    // Order-independence: same result with the trusted cross-cert listed first.
    let reversed: Vec<Vec<u8>> = pool.into_iter().rev().collect();
    assert!(verify_certificate_chain(&leaf, &reversed, &[], &store, SystemTime::now()));
}

#[test]
fn crl_revocation_must_be_authenticated() {
    use pdf_signer::{testkit::revocation_scenario, verify_certificate_chain};
    use std::time::SystemTime;

    let s = revocation_scenario();
    let store = TrustStore::from_ders([s.root_der.clone()]).expect("store");
    let now = SystemTime::now();

    // No CRL: revocation is soft-fail, so the leaf still validates.
    assert!(verify_certificate_chain(&s.leaf_der, &[], &[], &store, now));

    // A current CRL signed by the issuing CA revokes the leaf.
    assert!(
        !verify_certificate_chain(&s.leaf_der, &[], std::slice::from_ref(&s.good_crl), &store, now),
        "an authenticated CRL listing the leaf must revoke it"
    );

    // A CRL with a bad signature is ignored (not trusted as evidence).
    assert!(
        verify_certificate_chain(
            &s.leaf_der,
            &[],
            std::slice::from_ref(&s.wrong_key_crl),
            &store,
            now
        ),
        "a CRL not signed by the CA must be ignored"
    );

    // A stale CRL (past nextUpdate) is ignored.
    assert!(
        verify_certificate_chain(
            &s.leaf_der,
            &[],
            std::slice::from_ref(&s.expired_crl),
            &store,
            now
        ),
        "an expired CRL must be ignored"
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
fn name_constraint_permitted_is_trusted() {
    let pdf = sample_pdf();
    let (p12, root_der) = ca_name_constrained_p12("pw", false); // permitted = leaf DN
    let signed = sign_pdf_bytes(&pdf, &p12, "pw", &SignOptions::default()).expect("sign");
    let store = TrustStore::from_ders([root_der]).expect("store");
    let report = verify_pdf_bytes_with_roots(&signed, &store).expect("verify");
    assert_eq!(
        report.signatures[0].chain_trusted,
        Some(true),
        "{}",
        report.signatures[0].detail
    );
}

#[test]
fn name_constraint_excluded_is_rejected() {
    let pdf = sample_pdf();
    let (p12, root_der) = ca_name_constrained_p12("pw", true); // excluded = leaf DN
    let signed = sign_pdf_bytes(&pdf, &p12, "pw", &SignOptions::default()).expect("sign");
    let store = TrustStore::from_ders([root_der]).expect("store");
    let report = verify_pdf_bytes_with_roots(&signed, &store).expect("verify");
    assert_eq!(report.signatures[0].chain_trusted, Some(false));
    assert!(report.signatures[0].detail.contains("excluded"));
}

#[test]
fn required_policy_present_and_absent() {
    let pdf = sample_pdf();
    let (p12, root_der) = ca_with_policy_p12("pw", "1.3.6.1.4.1.99999.1");
    let signed = sign_pdf_bytes(&pdf, &p12, "pw", &SignOptions::default()).expect("sign");

    // The leaf asserts the required policy -> trusted.
    let store = TrustStore::from_ders([root_der.clone()])
        .unwrap()
        .require_policy("1.3.6.1.4.1.99999.1")
        .unwrap();
    assert_eq!(
        verify_pdf_bytes_with_roots(&signed, &store).unwrap().signatures[0].chain_trusted,
        Some(true)
    );

    // A different required policy -> rejected.
    let store2 = TrustStore::from_ders([root_der])
        .unwrap()
        .require_policy("1.3.6.1.4.1.99999.2")
        .unwrap();
    assert_eq!(
        verify_pdf_bytes_with_roots(&signed, &store2).unwrap().signatures[0].chain_trusted,
        Some(false)
    );
}

#[test]
fn ed25519_sign_and_verify() {
    let pdf = sample_pdf();
    let p12 = self_signed_ed25519_p12("pw");
    let signed = sign_pdf_bytes(&pdf, &p12, "pw", &SignOptions::default()).expect("Ed25519 sign");
    let report = verify_pdf_bytes(&signed).expect("verify");
    assert!(report.signatures[0].valid, "{}", report.signatures[0].detail);
}

#[test]
fn xref_stream_source_gets_xref_stream_update() {
    let pdf = sample_pdf_xref_stream();
    let p12 = self_signed_p12("pw");
    let signed = sign_pdf_bytes(&pdf, &p12, "pw", &SignOptions::default()).expect("sign");

    // Original preserved; the appended update is itself a cross-reference stream.
    assert_eq!(&signed[..pdf.len()], &pdf[..], "original bytes intact");
    assert!(
        contains(&signed[pdf.len()..], b"/Type /XRef"),
        "incremental update should use an xref stream to match the source"
    );
    assert!(verify_pdf_bytes(&signed).expect("verify").signatures[0].valid);
}

#[test]
fn policy_mapping_is_honored() {
    let pdf = sample_pdf();
    let a = "1.3.6.1.4.1.99999.10"; // issuer-domain policy
    let b = "1.3.6.1.4.1.99999.20"; // subject-domain policy (leaf asserts this)
    let (p12, root_der) = ca_chain_policy_mapping_p12("pw", a, b);
    let signed = sign_pdf_bytes(&pdf, &p12, "pw", &SignOptions::default()).expect("sign");

    // Requiring A succeeds: the intermediate maps A -> B and the leaf asserts B.
    // (The old per-cert subset would have rejected this.)
    let store = TrustStore::from_ders([root_der.clone()])
        .unwrap()
        .require_policy(a)
        .unwrap();
    let r = verify_pdf_bytes_with_roots(&signed, &store).expect("verify");
    assert_eq!(
        r.signatures[0].chain_trusted,
        Some(true),
        "{}",
        r.signatures[0].detail
    );

    // An unrelated policy is rejected.
    let store2 = TrustStore::from_ders([root_der])
        .unwrap()
        .require_policy("1.3.6.1.4.1.99999.30")
        .unwrap();
    assert_eq!(
        verify_pdf_bytes_with_roots(&signed, &store2).unwrap().signatures[0].chain_trusted,
        Some(false)
    );
}

#[test]
fn appearance_embeds_png_image() {
    let pdf = sample_pdf();
    let p12 = self_signed_p12("pw");
    let opts = SignOptions {
        appearance: Some(Appearance {
            text: "Signed with a logo".into(),
            image: Some(tiny_png()),
            ..Appearance::default()
        }),
        ..Default::default()
    };
    let signed = sign_pdf_bytes(&pdf, &p12, "pw", &opts).expect("sign");

    assert!(contains(&signed, b"/Subtype /Image"), "image XObject present");
    assert!(contains(&signed, b"/SMask"), "RGBA image gets a soft mask");
    assert!(contains(&signed, b"/Img Do"), "image is drawn in the content");
    assert!(verify_pdf_bytes(&signed).expect("verify").signatures[0].valid);
}

#[test]
#[ignore = "reads a macOS system TrueType font"]
fn appearance_embeds_truetype_font() {
    let font = std::fs::read("/System/Library/Fonts/Supplemental/Andale Mono.ttf")
        .expect("system TrueType font");
    let pdf = sample_pdf();
    let p12 = self_signed_p12("pw");
    let opts = SignOptions {
        appearance: Some(Appearance {
            text: "Embedded font".into(),
            font: Some(font),
            ..Appearance::default()
        }),
        ..Default::default()
    };
    let signed = sign_pdf_bytes(&pdf, &p12, "pw", &opts).expect("sign");
    assert!(contains(&signed, b"/FontFile2"), "font program embedded");
    assert!(contains(&signed, b"/TrueType"), "TrueType simple font");
    assert!(verify_pdf_bytes(&signed).expect("verify").signatures[0].valid);
}

#[test]
fn unsigned_document_reports_no_signatures() {
    let pdf = sample_pdf();
    let report = verify_pdf_bytes(&pdf).expect("verify failed");
    assert!(report.signatures.is_empty());
    assert!(!report.all_valid());
}
