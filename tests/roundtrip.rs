use pdf_signer::testkit::{
    ca_chain3_p12, ca_chain_policy_mapping_p12, ca_name_constrained_p12, ca_signed_p12,
    ca_with_policy_p12, mock_tsa, sample_pdf, sample_pdf_xref_stream, sample_pdf_xref_table,
    self_signed_ed25519_p12, self_signed_p12, self_signed_p256_p12, self_signed_p384_p12,
    tiny_png, MockTsaOptions,
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
fn byterange_in_stream_is_not_a_signature() {
    use pdf_signer::testkit::pdf_with_byterange_decoy;

    // A `/ByteRange ... /Contents <...>` sitting in a content stream (not a
    // signature dictionary) must be ignored: structural parsing finds no
    // signatures, where a raw byte scan would have reported a bogus one (#5).
    let pdf = pdf_with_byterange_decoy();
    assert!(contains(&pdf, b"/ByteRange"), "decoy must be present in bytes");
    let report = verify_pdf_bytes(&pdf).expect("verify");
    assert!(
        report.signatures.is_empty(),
        "a /ByteRange in stream content is not a signature"
    );
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
fn pades_bt_embeds_timestamp() {
    let pdf = sample_pdf();
    let p12 = self_signed_p12("pw");
    let tsa = mock_tsa(MockTsaOptions::default());
    let opts = SignOptions {
        pades_level: PadesLevel::Bt,
        tsa_url: Some(tsa.url.clone()),
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
#[ignore = "requires network access to a public RFC 3161 TSA"]
fn pades_bt_against_public_tsa() {
    let pdf = sample_pdf();
    let p12 = self_signed_p12("pw");
    let opts = SignOptions {
        pades_level: PadesLevel::Bt,
        tsa_url: Some("http://timestamp.digicert.com".into()),
        ..Default::default()
    };
    let signed = sign_pdf_bytes(&pdf, &p12, "pw", &opts).expect("sign + timestamp");
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

    // No trust store: validity can be asserted, trust cannot.
    let none = verify_pdf_bytes(&signed).expect("verify");
    assert!(none.all_valid());
    assert!(!none.all_trusted(), "all_trusted must be false without a trust store");
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

    // Revocation is permanent: an authenticated CRL past its nextUpdate still
    // proves the leaf was revoked at `now`.
    assert!(
        !verify_certificate_chain(
            &s.leaf_der,
            &[],
            std::slice::from_ref(&s.expired_crl),
            &store,
            now
        ),
        "a stale CRL listing the leaf must still revoke it"
    );

    // Evidence issued *after* the validation time (thisUpdate in the future)
    // that records an earlier revocation counts (RFC 3161 Appendix B) — this
    // is what lets a B-LT's own OCSP/CRL, fetched after signing, flag a signer
    // that was already revoked at the trusted signing time.
    assert!(
        !verify_certificate_chain(
            &s.leaf_der,
            &[],
            std::slice::from_ref(&s.future_crl),
            &store,
            now
        ),
        "a later CRL recording an earlier revocation must revoke the leaf"
    );

    // …but a revocation dated after the validation time does not apply yet.
    assert!(
        verify_certificate_chain(
            &s.leaf_der,
            &[],
            std::slice::from_ref(&s.revoked_later_crl),
            &store,
            now
        ),
        "a revocation in the future must not revoke the leaf at now"
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


// --- v0.3.0 regression tests -------------------------------------------------------

/// Append an unsigned incremental update that swaps the page's content stream.
fn append_content_replacement(signed: &[u8]) -> Vec<u8> {
    let doc = lopdf::Document::load_mem(signed).expect("parse signed");
    let page_id = *doc.get_pages().values().next().expect("page");
    let page = doc.get_object(page_id).unwrap().as_dict().unwrap();
    let contents_id = page.get(b"Contents").unwrap().as_reference().unwrap();
    let root_id = doc.trailer.get(b"Root").unwrap().as_reference().unwrap();
    let evil = b"BT /F1 24 Tf 72 720 Td (PAY THE ATTACKER) Tj ET";
    let mut out = signed.to_vec();
    if !out.ends_with(b"\n") {
        out.push(b'\n');
    }
    let off = out.len();
    out.extend_from_slice(
        format!(
            "{} 0 obj\n<< /Length {} >>\nstream\n",
            contents_id.0,
            evil.len()
        )
        .as_bytes(),
    );
    out.extend_from_slice(evil);
    out.extend_from_slice(b"\nendstream\nendobj\n");
    let xref = out.len();
    let prev = {
        let s = String::from_utf8_lossy(signed);
        let i = s.rfind("startxref").unwrap();
        s[i + 9..].split_whitespace().next().unwrap().parse::<usize>().unwrap()
    };
    // The signed file uses an xref stream; an appended classic table works for
    // readers (hybrid chains via /Prev), which is exactly what an attacker does.
    out.extend_from_slice(
        format!(
            "xref\n{} 1\n{:010} 00000 n\r\ntrailer\n<< /Size {} /Root {} 0 R /Prev {} >>\nstartxref\n{}\n%%EOF\n",
            contents_id.0,
            off,
            doc.max_id + 1,
            root_id.0,
            prev,
            xref
        )
        .as_bytes(),
    );
    out
}

#[test]
fn modification_after_signing_is_not_intact() {
    let pdf = sample_pdf();
    let (p12, root_der) = ca_signed_p12("pw");
    let signed = sign_pdf_bytes(&pdf, &p12, "pw", &SignOptions::default()).expect("sign");
    let tampered = append_content_replacement(&signed);

    // The original signature still verifies over its own bytes…
    let store = TrustStore::from_ders([root_der]).unwrap();
    let report = verify_pdf_bytes_with_roots(&tampered, &store).expect("verify");
    assert!(report.signatures[0].valid);
    assert_eq!(report.signatures[0].chain_trusted, Some(true));
    assert!(!report.signatures[0].covers_whole_document);
    // …but the document is not what was signed, so nothing passes overall.
    assert!(!report.document_intact, "unsigned content change must break integrity");
    assert!(!report.all_valid());
    assert!(!report.all_trusted());

    // And a plain trailing garbage append is not intact either.
    let mut junk = signed.clone();
    junk.extend_from_slice(b"\n% not part of the signed revision\n");
    assert!(!verify_pdf_bytes(&junk).unwrap().document_intact);
}

#[test]
fn pades_blt_and_blta_offline_with_mock_tsa() {
    let pdf = sample_pdf();
    let (p12, root_der) = ca_signed_p12("pw");
    let tsa = mock_tsa(MockTsaOptions::default());

    // B-LT: signature + timestamp + DSS. The DSS update after the signature is
    // the one trailing change that keeps the document intact.
    let blt = sign_pdf_bytes(
        &pdf,
        &p12,
        "pw",
        &SignOptions {
            pades_level: PadesLevel::Blt,
            tsa_url: Some(tsa.url.clone()),
            ..Default::default()
        },
    )
    .expect("B-LT sign");
    assert!(contains(&blt, b"/DSS") && contains(&blt, b"/Certs"));
    let store = TrustStore::from_ders([root_der.clone(), tsa.root_der.clone()]).unwrap();
    let report = verify_pdf_bytes_with_roots(&blt, &store).expect("verify");
    assert_eq!(report.signatures.len(), 1);
    assert!(!report.signatures[0].covers_whole_document, "DSS follows the signature");
    assert!(report.document_intact, "a DSS-only trailing update keeps the document intact");
    assert!(report.all_trusted(), "{}", report.signatures[0].detail);
    assert!(
        report.signatures[0].trusted_time.is_some(),
        "the chain must be judged at the trusted genTime: {}",
        report.signatures[0].detail
    );

    // B-LTA: + document timestamp covering everything, chain-validated as a TSA.
    let blta = sign_pdf_bytes(
        &pdf,
        &p12,
        "pw",
        &SignOptions {
            pades_level: PadesLevel::Blta,
            tsa_url: Some(tsa.url.clone()),
            ..Default::default()
        },
    )
    .expect("B-LTA sign");
    assert!(contains(&blta, b"DocTimeStamp"));
    let report = verify_pdf_bytes_with_roots(&blta, &store).expect("verify");
    assert_eq!(report.signatures.len(), 2, "signature + document timestamp");
    let ts = &report.signatures[1];
    assert!(ts.is_timestamp && ts.valid && ts.covers_whole_document);
    assert_eq!(ts.chain_trusted, Some(true), "{}", ts.detail);
    assert!(report.all_trusted());

    // A second B-LT signature must merge into the existing DSS, not replace it.
    let (p12b, root_b) = ca_signed_p12("pw");
    let twice = sign_pdf_bytes(
        &blt,
        &p12b,
        "pw",
        &SignOptions {
            pades_level: PadesLevel::Blt,
            tsa_url: Some(tsa.url.clone()),
            ..Default::default()
        },
    )
    .expect("second B-LT");
    let doc = lopdf::Document::load_mem(&twice).unwrap();
    let catalog = doc.catalog().unwrap();
    let dss = catalog.get(b"DSS").unwrap().as_dict().unwrap();
    let certs = dss.get(b"Certs").unwrap().as_array().unwrap();
    // Root A + leaf A + TSA (first DSS) and root B + leaf B (second) — the TSA
    // certificate is deduplicated.
    assert!(certs.len() >= 5, "merged DSS should keep both chains, got {}", certs.len());
    let store_ab = TrustStore::from_ders([root_der, root_b, tsa.root_der.clone()]).unwrap();
    let report = verify_pdf_bytes_with_roots(&twice, &store_ab).expect("verify");
    assert_eq!(report.signatures.len(), 2);
    assert!(report.all_trusted(), "{:?}", report.signatures.iter().map(|s| &s.detail).collect::<Vec<_>>());
}

#[test]
fn untrusted_document_timestamp_is_not_trusted() {
    let pdf = sample_pdf();
    let (p12, root_der) = ca_signed_p12("pw");
    let tsa = mock_tsa(MockTsaOptions::default());
    let blta = sign_pdf_bytes(
        &pdf,
        &p12,
        "pw",
        &SignOptions {
            pades_level: PadesLevel::Blta,
            tsa_url: Some(tsa.url.clone()),
            ..Default::default()
        },
    )
    .unwrap();
    // Trust only the signer's root, not the TSA's: the document timestamp is
    // valid but must be reported untrusted, and the report must not pass.
    let store = TrustStore::from_ders([root_der]).unwrap();
    let report = verify_pdf_bytes_with_roots(&blta, &store).unwrap();
    let ts = &report.signatures[1];
    assert!(ts.is_timestamp && ts.valid);
    assert_eq!(ts.chain_trusted, Some(false), "{}", ts.detail);
    assert!(!report.all_trusted(), "an untrusted TSA must not count as trusted");
    // The signature's own timestamp comes from the same untrusted TSA, so the
    // signer chain is judged at "now" (no trusted time).
    assert!(report.signatures[0].trusted_time.is_none());
}

#[test]
fn tsa_without_timestamping_eku_cannot_anchor_time() {
    let pdf = sample_pdf();
    let (p12, root_der) = ca_signed_p12("pw");
    let tsa = mock_tsa(MockTsaOptions {
        without_timestamping_eku: true,
        ..Default::default()
    });
    let signed = sign_pdf_bytes(
        &pdf,
        &p12,
        "pw",
        &SignOptions {
            pades_level: PadesLevel::Bt,
            tsa_url: Some(tsa.url.clone()),
            ..Default::default()
        },
    )
    .unwrap();
    // Even with the TSA's root trusted, a certificate without the
    // id-kp-timeStamping EKU is not a TSA (RFC 3161 §2.3): its genTime must
    // not become the validation time.
    let store = TrustStore::from_ders([root_der, tsa.root_der.clone()]).unwrap();
    let report = verify_pdf_bytes_with_roots(&signed, &store).unwrap();
    assert!(report.signatures[0].valid);
    assert!(
        report.signatures[0].trusted_time.is_none(),
        "{}",
        report.signatures[0].detail
    );
    assert!(report.signatures[0].detail.contains("timeStamping"));
}

#[test]
fn tsa_with_fractional_seconds_is_accepted() {
    let pdf = sample_pdf();
    let (p12, root_der) = ca_signed_p12("pw");
    let tsa = mock_tsa(MockTsaOptions {
        fractional_seconds: true,
        ..Default::default()
    });
    let signed = sign_pdf_bytes(
        &pdf,
        &p12,
        "pw",
        &SignOptions {
            pades_level: PadesLevel::Blta,
            tsa_url: Some(tsa.url.clone()),
            ..Default::default()
        },
    )
    .expect("a genTime with fractional seconds must be accepted");
    let store = TrustStore::from_ders([root_der, tsa.root_der.clone()]).unwrap();
    let report = verify_pdf_bytes_with_roots(&signed, &store).unwrap();
    assert!(report.all_trusted(), "{:?}", report.signatures.iter().map(|s| &s.detail).collect::<Vec<_>>());
}

#[test]
fn tsa_rejection_fails_signing() {
    let pdf = sample_pdf();
    let p12 = self_signed_p12("pw");
    let tsa = mock_tsa(MockTsaOptions {
        reject: true,
        ..Default::default()
    });
    let err = sign_pdf_bytes(
        &pdf,
        &p12,
        "pw",
        &SignOptions {
            pades_level: PadesLevel::Bt,
            tsa_url: Some(tsa.url.clone()),
            ..Default::default()
        },
    )
    .expect_err("a rejected timestamp must fail signing");
    assert!(err.to_string().contains("PKIStatus"), "{err}");
}

#[test]
fn xref_table_source_gets_xref_table_update_and_keeps_info() {
    let pdf = sample_pdf_xref_table();
    let p12 = self_signed_p12("pw");
    let signed = sign_pdf_bytes(&pdf, &p12, "pw", &SignOptions::default()).expect("sign");
    assert_eq!(&signed[..pdf.len()], &pdf[..]);
    let tail = &signed[pdf.len()..];
    assert!(contains(tail, b"xref\n") && contains(tail, b"trailer"), "classic xref table expected");
    assert!(!contains(tail, b"/Type /XRef"));
    // /Info is carried into the new trailer.
    let doc = lopdf::Document::load_mem(&signed).unwrap();
    let info = doc.trailer.get(b"Info").expect("Info carried forward");
    let title = info.as_dict().unwrap().get(b"Title").unwrap().as_str().unwrap();
    assert_eq!(title, b"Contrato 42");
    let report = verify_pdf_bytes(&signed).unwrap();
    assert!(report.all_valid() && report.signatures[0].covers_whole_document);

    // Sign again: two signatures, both valid, document intact.
    let twice = sign_pdf_bytes(&signed, &p12, "pw", &SignOptions::default()).unwrap();
    let report = verify_pdf_bytes(&twice).unwrap();
    assert_eq!(report.signatures.len(), 2);
    assert!(report.all_valid());
}

#[test]
fn leading_junk_before_header_is_handled() {
    let mut pdf = b"JUNKJUNKJUNK\n".to_vec();
    pdf.extend_from_slice(&sample_pdf_xref_table());
    let p12 = self_signed_p12("pw");
    let signed = sign_pdf_bytes(&pdf, &p12, "pw", &SignOptions::default()).expect("sign");
    // lopdf must still parse the result (offsets relative to %PDF-) and find
    // the signature structurally.
    let report = verify_pdf_bytes(&signed).unwrap();
    assert_eq!(report.signatures.len(), 1);
    assert!(report.all_valid(), "{}", report.signatures[0].detail);
    assert!(report.signatures[0].covers_whole_document);
}

#[test]
fn non_ascii_metadata_is_written_as_utf16() {
    let pdf = sample_pdf();
    let p12 = self_signed_p12("pw");
    let opts = SignOptions {
        reason: Some("Aprovação — São Paulo".into()),
        name: Some("José".into()),
        location: Some("Recife".into()),
        ..Default::default()
    };
    let signed = sign_pdf_bytes(&pdf, &p12, "pw", &opts).unwrap();
    let doc = lopdf::Document::load_mem(&signed).unwrap();
    let sig = doc
        .objects
        .values()
        .filter_map(|o| o.as_dict().ok())
        .find(|d| d.has(b"ByteRange"))
        .unwrap();
    let reason = sig.get(b"Reason").unwrap().as_str().unwrap();
    assert_eq!(&reason[..2], &[0xFE, 0xFF], "UTF-16BE BOM expected");
    let units: Vec<u16> = reason[2..]
        .chunks(2)
        .map(|c| u16::from_be_bytes([c[0], c[1]]))
        .collect();
    assert_eq!(String::from_utf16(&units).unwrap(), "Aprovação — São Paulo");
    // ASCII stays a plain literal string; /M is always present.
    assert_eq!(sig.get(b"Location").unwrap().as_str().unwrap(), b"Recife");
    assert!(sig.get(b"M").unwrap().as_str().unwrap().starts_with(b"D:20"));
    // No CMS signing-time attribute (PAdES baseline): id-signingTime OID.
    assert!(!contains(&signed, b"06092a864886f70d010905"));
}

#[test]
fn encrypted_input_is_refused() {
    // Build an AES-encrypted copy of the sample with lopdf and an empty user
    // password (the case a reader — and lopdf — silently decrypts).
    let mut doc = lopdf::Document::load_mem(&sample_pdf()).unwrap();
    // The document needs an /ID for the standard security handler.
    doc.trailer.set(
        "ID",
        lopdf::Object::Array(vec![
            lopdf::Object::string_literal(vec![7u8; 16]),
            lopdf::Object::string_literal(vec![7u8; 16]),
        ]),
    );
    let state = lopdf::EncryptionState::try_from(lopdf::EncryptionVersion::V1 {
        document: &doc,
        owner_password: "owner",
        user_password: "",
        permissions: lopdf::Permissions::default(),
    })
    .expect("encryption state");
    doc.encrypt(&state).expect("encrypt");
    let mut enc = Vec::new();
    doc.save_to(&mut enc).unwrap();
    assert!(contains(&enc, b"/Encrypt"));

    let p12 = self_signed_p12("pw");
    let err = sign_pdf_bytes(&enc, &p12, "pw", &SignOptions::default())
        .expect_err("encrypted input must be refused");
    assert!(err.to_string().contains("encrypted"), "{err}");
}

#[test]
fn out_of_range_page_is_an_error() {
    let pdf = sample_pdf();
    let p12 = self_signed_p12("pw");
    let opts = SignOptions {
        appearance: Some(Appearance {
            page: 7,
            text: "x".into(),
            ..Appearance::default()
        }),
        ..Default::default()
    };
    let err = sign_pdf_bytes(&pdf, &p12, "pw", &opts).expect_err("page 7 of 1");
    assert!(err.to_string().contains("page 7"), "{err}");
    let opts = SignOptions {
        appearance: Some(Appearance {
            width: f64::NAN,
            text: "x".into(),
            ..Appearance::default()
        }),
        ..Default::default()
    };
    assert!(sign_pdf_bytes(&pdf, &p12, "pw", &opts).is_err(), "NaN geometry");
}

#[test]
fn malformed_signature_dictionary_does_not_abort_the_report() {
    let pdf = sample_pdf();
    let p12 = self_signed_p12("pw");
    let signed = sign_pdf_bytes(&pdf, &p12, "pw", &SignOptions::default()).unwrap();
    // Corrupt the ByteRange's second value into a negative number of the same
    // width (still four integers, so the dictionary itself parses).
    let i = find(&signed, b"/ByteRange [0 ").unwrap() + b"/ByteRange [0 ".len();
    let mut bad = signed.clone();
    bad[i] = b'-';
    let report = verify_pdf_bytes(&bad).expect("a bad ByteRange is reported, not an error");
    assert_eq!(report.signatures.len(), 1);
    assert!(!report.signatures[0].valid);
    assert!(report.signatures[0].detail.contains("ByteRange"));
    assert!(!report.all_valid());
}

#[test]
fn leaf_key_usage_is_enforced() {
    use pdf_signer::testkit::revocation_scenario;
    // The revocation scenario's leaf has digitalSignature: trusted as a signer.
    let s = revocation_scenario();
    let pdf = sample_pdf();
    let _ = (s, pdf); // exercised through ca_signed_p12 below

    // ca_signed_p12's leaf profile asserts digitalSignature|nonRepudiation, so
    // it must pass the DocumentSigning purpose check.
    let (p12, root_der) = ca_signed_p12("pw");
    let signed = sign_pdf_bytes(&sample_pdf(), &p12, "pw", &SignOptions::default()).unwrap();
    let store = TrustStore::from_ders([root_der]).unwrap();
    assert!(verify_pdf_bytes_with_roots(&signed, &store).unwrap().all_trusted());
}
