//! Test/demo helpers: build a minimal sample PDF and a self-signed PKCS#12.
//!
//! These exist so the PoC is fully reproducible without external fixtures.
//! They are not part of the production signing/verification surface.

use lopdf::content::{Content, Operation};
use lopdf::{dictionary, Document, Object, Stream};

use openssl::asn1::Asn1Time;
use openssl::bn::{BigNum, MsbOption};
use openssl::hash::MessageDigest;
use openssl::pkcs12::Pkcs12;
use openssl::pkey::PKey;
use openssl::rsa::Rsa;
use openssl::x509::{X509NameBuilder, X509};

/// Build a minimal, valid one-page PDF with a line of text.
pub fn sample_pdf() -> Vec<u8> {
    let mut doc = Document::with_version("1.5");
    let pages_id = doc.new_object_id();

    let font_id = doc.add_object(dictionary! {
        "Type" => "Font",
        "Subtype" => "Type1",
        "BaseFont" => "Helvetica",
    });
    let resources_id = doc.add_object(dictionary! {
        "Font" => dictionary! { "F1" => font_id },
    });

    let content = Content {
        operations: vec![
            Operation::new("BT", vec![]),
            Operation::new("Tf", vec!["F1".into(), 24.into()]),
            Operation::new("Td", vec![72.into(), 720.into()]),
            Operation::new(
                "Tj",
                vec![Object::string_literal("pdf_signer PoC - sample document")],
            ),
            Operation::new("ET", vec![]),
        ],
    };
    let content_id = doc.add_object(Stream::new(dictionary! {}, content.encode().unwrap()));

    let page_id = doc.add_object(dictionary! {
        "Type" => "Page",
        "Parent" => pages_id,
        "Contents" => content_id,
        "MediaBox" => vec![0.into(), 0.into(), 612.into(), 792.into()],
        "Resources" => resources_id,
    });

    let pages = dictionary! {
        "Type" => "Pages",
        "Kids" => vec![page_id.into()],
        "Count" => 1,
    };
    doc.objects.insert(pages_id, Object::Dictionary(pages));

    let catalog_id = doc.add_object(dictionary! {
        "Type" => "Catalog",
        "Pages" => pages_id,
    });
    doc.trailer.set("Root", catalog_id);

    let mut buf = Vec::new();
    doc.save_to(&mut buf).unwrap();
    buf
}

/// Build a self-signed RSA-2048 certificate and wrap it in a PKCS#12 keystore.
pub fn self_signed_p12(password: &str) -> Vec<u8> {
    let rsa = Rsa::generate(2048).unwrap();
    let pkey = PKey::from_rsa(rsa).unwrap();

    let mut nb = X509NameBuilder::new().unwrap();
    nb.append_entry_by_text("C", "BR").unwrap();
    nb.append_entry_by_text("O", "StrategicProjects").unwrap();
    nb.append_entry_by_text("CN", "pdf_signer PoC").unwrap();
    let name = nb.build();

    let mut b = X509::builder().unwrap();
    b.set_version(2).unwrap();
    let serial = {
        let mut bn = BigNum::new().unwrap();
        bn.rand(159, MsbOption::MAYBE_ZERO, false).unwrap();
        bn.to_asn1_integer().unwrap()
    };
    b.set_serial_number(&serial).unwrap();
    b.set_subject_name(&name).unwrap();
    b.set_issuer_name(&name).unwrap();
    b.set_pubkey(&pkey).unwrap();
    b.set_not_before(&Asn1Time::days_from_now(0).unwrap()).unwrap();
    b.set_not_after(&Asn1Time::days_from_now(365).unwrap()).unwrap();
    b.sign(&pkey, MessageDigest::sha256()).unwrap();
    let cert = b.build();

    let p12 = Pkcs12::builder()
        .name("poc")
        .pkey(&pkey)
        .cert(&cert)
        .build2(password)
        .unwrap();
    p12.to_der().unwrap()
}
