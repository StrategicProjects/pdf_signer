//! Test/demo helpers: build a minimal sample PDF and a self-signed PKCS#12.
//!
//! These exist so the PoC is fully reproducible without external fixtures and
//! without OpenSSL — everything is pure RustCrypto. They are not part of the
//! production signing/verification surface.

use std::str::FromStr;
use std::time::Duration;

use lopdf::content::{Content, Operation};
use lopdf::{dictionary, Document, Object, Stream};

use const_oid::ObjectIdentifier;
use der::Encode;
use p12_keystore::{Certificate as P12Certificate, KeyStore, KeyStoreEntry, PrivateKeyChain};
use rsa::pkcs1v15::{Signature, SigningKey};
use rsa::pkcs8::EncodePrivateKey;
use rsa::RsaPrivateKey;
use sha2::Sha256;
use signature::Keypair;
use x509_cert::builder::{Builder, CertificateBuilder, Profile};
use x509_cert::name::Name;
use x509_cert::serial_number::SerialNumber;
use x509_cert::spki::SubjectPublicKeyInfoOwned;
use x509_cert::time::Validity;

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

/// A valid (unsigned) PDF that contains signature-looking syntax
/// (`/ByteRange ... /Contents <...>`) inside a content stream. Structural
/// verification must not mistake it for a signature.
pub fn pdf_with_byterange_decoy() -> Vec<u8> {
    let mut doc = Document::load_mem(&sample_pdf()).unwrap();
    let decoy = b"/ByteRange [0 10 20 10] /Contents <30820000>".to_vec();
    doc.add_object(Stream::new(dictionary! {}, decoy));
    let mut buf = Vec::new();
    doc.save_to(&mut buf).unwrap();
    buf
}

/// Build a self-signed **ECDSA P-256** certificate and wrap it in a PKCS#12.
pub fn self_signed_p256_p12(password: &str) -> Vec<u8> {
    let mut rng = rand::thread_rng();
    let signing_key = p256::ecdsa::SigningKey::random(&mut rng);
    let subject = Name::from_str("CN=pdf_signer P-256,O=StrategicProjects,C=BR").unwrap();
    let spki = SubjectPublicKeyInfoOwned::from_key(*signing_key.verifying_key()).unwrap();
    let cert = CertificateBuilder::new(
        Profile::Root,
        SerialNumber::from(1u32),
        Validity::from_now(Duration::from_secs(365 * 24 * 3600)).unwrap(),
        subject,
        spki,
        &signing_key,
    )
    .unwrap()
    .build::<p256::ecdsa::DerSignature>()
    .unwrap();
    let key_der = signing_key.to_pkcs8_der().unwrap().as_bytes().to_vec();
    ec_p12(password, &key_der, &cert.to_der().unwrap())
}

/// Build a self-signed **ECDSA P-384** certificate and wrap it in a PKCS#12.
pub fn self_signed_p384_p12(password: &str) -> Vec<u8> {
    let mut rng = rand::thread_rng();
    let signing_key = p384::ecdsa::SigningKey::random(&mut rng);
    let subject = Name::from_str("CN=pdf_signer P-384,O=StrategicProjects,C=BR").unwrap();
    let spki = SubjectPublicKeyInfoOwned::from_key(*signing_key.verifying_key()).unwrap();
    let cert = CertificateBuilder::new(
        Profile::Root,
        SerialNumber::from(1u32),
        Validity::from_now(Duration::from_secs(365 * 24 * 3600)).unwrap(),
        subject,
        spki,
        &signing_key,
    )
    .unwrap()
    .build::<p384::ecdsa::DerSignature>()
    .unwrap();
    let key_der = signing_key.to_pkcs8_der().unwrap().as_bytes().to_vec();
    ec_p12(password, &key_der, &cert.to_der().unwrap())
}

/// Build a self-signed **Ed25519** certificate and wrap it in a PKCS#12.
pub fn self_signed_ed25519_p12(password: &str) -> Vec<u8> {
    use rsa::pkcs8::EncodePrivateKey;
    let mut rng = rand::thread_rng();
    let sk = ed25519_dalek::SigningKey::generate(&mut rng);
    let subject = Name::from_str("CN=pdf_signer Ed25519,O=StrategicProjects,C=BR").unwrap();
    let spki = SubjectPublicKeyInfoOwned::from_key(sk.verifying_key()).unwrap();
    let signer = crate::crypto::Ed25519Signer(sk.clone());
    let cert = CertificateBuilder::new(
        Profile::Root,
        SerialNumber::from(1u32),
        Validity::from_now(Duration::from_secs(365 * 24 * 3600)).unwrap(),
        subject,
        spki,
        &signer,
    )
    .unwrap()
    .build::<crate::crypto::Ed25519Sig>()
    .unwrap();
    let key_der = sk.to_pkcs8_der().unwrap().as_bytes().to_vec();
    ec_p12(password, &key_der, &cert.to_der().unwrap())
}

fn ec_p12(password: &str, key_der: &[u8], cert_der: &[u8]) -> Vec<u8> {
    let chain = PrivateKeyChain::new(
        key_der,
        b"poc",
        vec![P12Certificate::from_der(cert_der).unwrap()],
    );
    let mut ks = KeyStore::new();
    ks.add_entry("poc", KeyStoreEntry::PrivateKeyChain(chain));
    ks.writer(password).write().unwrap()
}

/// A tiny 4×4 RGBA PNG (opaque red), for testing image appearances.
pub fn tiny_png() -> Vec<u8> {
    let (w, h) = (4u32, 4u32);
    let mut pixels = Vec::with_capacity((w * h * 4) as usize);
    for _ in 0..(w * h) {
        pixels.extend_from_slice(&[220, 30, 30, 255]);
    }
    let mut out = Vec::new();
    {
        let mut enc = png::Encoder::new(&mut out, w, h);
        enc.set_color(png::ColorType::Rgba);
        enc.set_depth(png::BitDepth::Eight);
        let mut writer = enc.write_header().unwrap();
        writer.write_image_data(&pixels).unwrap();
    }
    out
}

/// A minimal one-page PDF that uses a **cross-reference stream** (PDF 1.5)
/// instead of a traditional xref table, for testing the xref-stream path.
pub fn sample_pdf_xref_stream() -> Vec<u8> {
    let content: &[u8] = b"BT /F1 24 Tf 72 720 Td (xref-stream sample) Tj ET";
    let mut out = Vec::new();
    let mut off = [0usize; 7];
    out.extend_from_slice(b"%PDF-1.5\n");
    off[1] = out.len();
    out.extend_from_slice(b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n");
    off[2] = out.len();
    out.extend_from_slice(b"2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n");
    off[3] = out.len();
    out.extend_from_slice(
        b"3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] \
          /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>\nendobj\n",
    );
    off[4] = out.len();
    out.extend_from_slice(format!("4 0 obj\n<< /Length {} >>\nstream\n", content.len()).as_bytes());
    out.extend_from_slice(content);
    out.extend_from_slice(b"\nendstream\nendobj\n");
    off[5] = out.len();
    out.extend_from_slice(b"5 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>\nendobj\n");
    off[6] = out.len();

    // Uncompressed cross-reference stream, W = [1, 4, 2], Index [0 7].
    let mut data = vec![0u8, 0, 0, 0, 0, 0xFF, 0xFF]; // object 0: free
    for &o in &off[1..=6] {
        data.push(1);
        data.extend_from_slice(&(o as u32).to_be_bytes());
        data.extend_from_slice(&0u16.to_be_bytes());
    }
    out.extend_from_slice(
        format!(
            "6 0 obj\n<< /Type /XRef /Size 7 /Root 1 0 R /W [1 4 2] /Index [0 7] /Length {} >>\nstream\n",
            data.len()
        )
        .as_bytes(),
    );
    out.extend_from_slice(&data);
    out.extend_from_slice(b"\nendstream\nendobj\n");
    out.extend_from_slice(format!("startxref\n{}\n%%EOF\n", off[6]).as_bytes());
    out
}

/// Build a self-signed RSA-2048 certificate and wrap it in a PKCS#12 keystore.
pub fn self_signed_p12(password: &str) -> Vec<u8> {
    let mut rng = rand::thread_rng();
    let priv_key = RsaPrivateKey::new(&mut rng, 2048).expect("rsa keygen");
    let signing_key = SigningKey::<Sha256>::new(priv_key.clone());

    let subject =
        Name::from_str("CN=pdf_signer PoC,O=StrategicProjects,C=BR").expect("subject name");
    let spki =
        SubjectPublicKeyInfoOwned::from_key(signing_key.verifying_key()).expect("spki from key");

    let builder = CertificateBuilder::new(
        Profile::Root, // self-signed root: issuer == subject
        SerialNumber::from(1u32),
        Validity::from_now(Duration::from_secs(365 * 24 * 3600)).expect("validity"),
        subject,
        spki,
        &signing_key,
    )
    .expect("certificate builder");
    let cert = builder.build::<Signature>().expect("build cert");
    let cert_der = cert.to_der().expect("cert der");

    let key_der = priv_key
        .to_pkcs8_der()
        .expect("pkcs8 der")
        .as_bytes()
        .to_vec();

    let p12_cert = P12Certificate::from_der(&cert_der).expect("p12 cert");
    let chain = PrivateKeyChain::new(&key_der, b"poc", vec![p12_cert]);

    let mut ks = KeyStore::new();
    ks.add_entry("poc", KeyStoreEntry::PrivateKeyChain(chain));
    ks.writer(password).write().expect("write p12")
}

/// Build a tiny PKI — a self-signed root CA and a leaf signed by it — and
/// return `(p12, root_cert_der)`. The p12 holds the leaf key + `[leaf, root]`
/// chain; `root_cert_der` is the trust anchor for chain-validation tests.
pub fn ca_signed_p12(password: &str) -> (Vec<u8>, Vec<u8>) {
    let mut rng = rand::thread_rng();
    let validity = Validity::from_now(Duration::from_secs(365 * 24 * 3600)).expect("validity");

    // Root CA (self-signed).
    let root_key = RsaPrivateKey::new(&mut rng, 2048).expect("root keygen");
    let root_signing = SigningKey::<Sha256>::new(root_key);
    let root_name = Name::from_str("CN=PoC Test Root CA,O=StrategicProjects,C=BR").unwrap();
    let root_spki = SubjectPublicKeyInfoOwned::from_key(root_signing.verifying_key()).unwrap();
    let root_cert = CertificateBuilder::new(
        Profile::Root,
        SerialNumber::from(1u32),
        validity,
        root_name.clone(),
        root_spki,
        &root_signing,
    )
    .expect("root builder")
    .build::<Signature>()
    .expect("build root");
    let root_der = root_cert.to_der().expect("root der");

    // Leaf, signed by the root key.
    let leaf_key = RsaPrivateKey::new(&mut rng, 2048).expect("leaf keygen");
    let leaf_signing = SigningKey::<Sha256>::new(leaf_key.clone());
    let leaf_name = Name::from_str("CN=PoC Signer,O=StrategicProjects,C=BR").unwrap();
    let leaf_spki = SubjectPublicKeyInfoOwned::from_key(leaf_signing.verifying_key()).unwrap();
    let leaf_cert = CertificateBuilder::new(
        Profile::Leaf {
            issuer: root_name,
            enable_key_agreement: false,
            enable_key_encipherment: true,
        },
        SerialNumber::from(2u32),
        validity,
        leaf_name,
        leaf_spki,
        &root_signing, // signed by the ROOT key
    )
    .expect("leaf builder")
    .build::<Signature>()
    .expect("build leaf");
    let leaf_der = leaf_cert.to_der().expect("leaf der");

    let key_der = leaf_key.to_pkcs8_der().expect("pkcs8").as_bytes().to_vec();
    let chain = PrivateKeyChain::new(
        &key_der,
        b"poc",
        vec![
            P12Certificate::from_der(&leaf_der).expect("p12 leaf"),
            P12Certificate::from_der(&root_der).expect("p12 root"),
        ],
    );
    let mut ks = KeyStore::new();
    ks.add_entry("poc", KeyStoreEntry::PrivateKeyChain(chain));
    (ks.writer(password).write().expect("write p12"), root_der)
}

/// Root CA that name-constrains the leaf's exact DN — permitted (`excluded` =
/// false) or excluded (true). Returns `(p12, root_cert_der)`.
pub fn ca_name_constrained_p12(password: &str, excluded: bool) -> (Vec<u8>, Vec<u8>) {
    use x509_cert::ext::pkix::constraints::name::GeneralSubtree;
    use x509_cert::ext::pkix::name::GeneralName;
    use x509_cert::ext::pkix::NameConstraints;

    let mut rng = rand::thread_rng();
    let validity = Validity::from_now(Duration::from_secs(365 * 24 * 3600)).unwrap();
    let root_name = Name::from_str("CN=NC Root,O=StrategicProjects,C=BR").unwrap();
    let leaf_name = Name::from_str("CN=NC Leaf,O=StrategicProjects,C=BR").unwrap();

    let subtree = GeneralSubtree {
        base: GeneralName::DirectoryName(leaf_name.clone()),
        minimum: 0,
        maximum: None,
    };
    let nc = if excluded {
        NameConstraints {
            permitted_subtrees: None,
            excluded_subtrees: Some(vec![subtree]),
        }
    } else {
        NameConstraints {
            permitted_subtrees: Some(vec![subtree]),
            excluded_subtrees: None,
        }
    };

    let root_key = RsaPrivateKey::new(&mut rng, 2048).unwrap();
    let root_signing = SigningKey::<Sha256>::new(root_key);
    let mut root_builder = CertificateBuilder::new(
        Profile::Root,
        SerialNumber::from(1u32),
        validity,
        root_name.clone(),
        SubjectPublicKeyInfoOwned::from_key(root_signing.verifying_key()).unwrap(),
        &root_signing,
    )
    .unwrap();
    root_builder.add_extension(&nc).unwrap();
    let root_cert = root_builder.build::<Signature>().unwrap();
    let root_der = root_cert.to_der().unwrap();

    let leaf_key = RsaPrivateKey::new(&mut rng, 2048).unwrap();
    let leaf_signing = SigningKey::<Sha256>::new(leaf_key.clone());
    let leaf_cert = CertificateBuilder::new(
        leaf_profile(root_name),
        SerialNumber::from(2u32),
        validity,
        leaf_name,
        SubjectPublicKeyInfoOwned::from_key(leaf_signing.verifying_key()).unwrap(),
        &root_signing,
    )
    .unwrap()
    .build::<Signature>()
    .unwrap();
    let p12 = leaf_p12(password, &leaf_key, &leaf_cert.to_der().unwrap(), &root_der);
    (p12, root_der)
}

/// Root CA + leaf where the leaf asserts `policy_oid`. Returns `(p12, root_der)`.
pub fn ca_with_policy_p12(password: &str, policy_oid: &str) -> (Vec<u8>, Vec<u8>) {
    use x509_cert::ext::pkix::certpolicy::PolicyInformation;
    use x509_cert::ext::pkix::CertificatePolicies;

    let mut rng = rand::thread_rng();
    let validity = Validity::from_now(Duration::from_secs(365 * 24 * 3600)).unwrap();
    let root_name = Name::from_str("CN=Policy Root,O=StrategicProjects,C=BR").unwrap();

    let root_key = RsaPrivateKey::new(&mut rng, 2048).unwrap();
    let root_signing = SigningKey::<Sha256>::new(root_key);
    let root_cert = CertificateBuilder::new(
        Profile::Root,
        SerialNumber::from(1u32),
        validity,
        root_name.clone(),
        SubjectPublicKeyInfoOwned::from_key(root_signing.verifying_key()).unwrap(),
        &root_signing,
    )
    .unwrap()
    .build::<Signature>()
    .unwrap();
    let root_der = root_cert.to_der().unwrap();

    let leaf_key = RsaPrivateKey::new(&mut rng, 2048).unwrap();
    let leaf_signing = SigningKey::<Sha256>::new(leaf_key.clone());
    let pols = CertificatePolicies(vec![PolicyInformation {
        policy_identifier: ObjectIdentifier::new(policy_oid).unwrap(),
        policy_qualifiers: None,
    }]);
    let mut leaf_builder = CertificateBuilder::new(
        leaf_profile(root_name),
        SerialNumber::from(2u32),
        validity,
        Name::from_str("CN=Policy Leaf,O=StrategicProjects,C=BR").unwrap(),
        SubjectPublicKeyInfoOwned::from_key(leaf_signing.verifying_key()).unwrap(),
        &root_signing,
    )
    .unwrap();
    leaf_builder.add_extension(&pols).unwrap();
    let leaf_cert = leaf_builder.build::<Signature>().unwrap();
    let p12 = leaf_p12(password, &leaf_key, &leaf_cert.to_der().unwrap(), &root_der);
    (p12, root_der)
}

/// Root → intermediate (asserts `idp`, maps `idp`→`sdp`) → leaf (asserts `sdp`).
/// Exercises RFC 5280 policy mapping. Returns `(p12, root_der)`.
pub fn ca_chain_policy_mapping_p12(password: &str, idp: &str, sdp: &str) -> (Vec<u8>, Vec<u8>) {
    use x509_cert::ext::pkix::certpolicy::PolicyInformation;
    use x509_cert::ext::pkix::{CertificatePolicies, PolicyMapping, PolicyMappings};

    let idp = ObjectIdentifier::new(idp).unwrap();
    let sdp = ObjectIdentifier::new(sdp).unwrap();
    let mut rng = rand::thread_rng();
    let validity = Validity::from_now(Duration::from_secs(365 * 24 * 3600)).unwrap();

    let root_key = RsaPrivateKey::new(&mut rng, 2048).unwrap();
    let root_signing = SigningKey::<Sha256>::new(root_key);
    let root_name = Name::from_str("CN=PM Root,O=StrategicProjects,C=BR").unwrap();
    let root_cert = CertificateBuilder::new(
        Profile::Root,
        SerialNumber::from(1u32),
        validity,
        root_name.clone(),
        SubjectPublicKeyInfoOwned::from_key(root_signing.verifying_key()).unwrap(),
        &root_signing,
    )
    .unwrap()
    .build::<Signature>()
    .unwrap();
    let root_der = root_cert.to_der().unwrap();

    let inter_key = RsaPrivateKey::new(&mut rng, 2048).unwrap();
    let inter_signing = SigningKey::<Sha256>::new(inter_key);
    let inter_name = Name::from_str("CN=PM Intermediate,O=StrategicProjects,C=BR").unwrap();
    let mut inter_builder = CertificateBuilder::new(
        Profile::SubCA {
            issuer: root_name,
            path_len_constraint: Some(0),
        },
        SerialNumber::from(2u32),
        validity,
        inter_name.clone(),
        SubjectPublicKeyInfoOwned::from_key(inter_signing.verifying_key()).unwrap(),
        &root_signing,
    )
    .unwrap();
    inter_builder
        .add_extension(&CertificatePolicies(vec![PolicyInformation {
            policy_identifier: idp,
            policy_qualifiers: None,
        }]))
        .unwrap();
    inter_builder
        .add_extension(&PolicyMappings(vec![PolicyMapping {
            issuer_domain_policy: idp,
            subject_domain_policy: sdp,
        }]))
        .unwrap();
    let inter_cert = inter_builder.build::<Signature>().unwrap();
    let inter_der = inter_cert.to_der().unwrap();

    let leaf_key = RsaPrivateKey::new(&mut rng, 2048).unwrap();
    let leaf_signing = SigningKey::<Sha256>::new(leaf_key.clone());
    let mut leaf_builder = CertificateBuilder::new(
        leaf_profile(inter_name),
        SerialNumber::from(3u32),
        validity,
        Name::from_str("CN=PM Leaf,O=StrategicProjects,C=BR").unwrap(),
        SubjectPublicKeyInfoOwned::from_key(leaf_signing.verifying_key()).unwrap(),
        &inter_signing,
    )
    .unwrap();
    leaf_builder
        .add_extension(&CertificatePolicies(vec![PolicyInformation {
            policy_identifier: sdp,
            policy_qualifiers: None,
        }]))
        .unwrap();
    let leaf_cert = leaf_builder.build::<Signature>().unwrap();

    let key_der = leaf_key.to_pkcs8_der().unwrap().as_bytes().to_vec();
    let chain = PrivateKeyChain::new(
        &key_der,
        b"poc",
        vec![
            P12Certificate::from_der(&leaf_cert.to_der().unwrap()).unwrap(),
            P12Certificate::from_der(&inter_der).unwrap(),
            P12Certificate::from_der(&root_der).unwrap(),
        ],
    );
    let mut ks = KeyStore::new();
    ks.add_entry("poc", KeyStoreEntry::PrivateKeyChain(chain));
    (ks.writer(password).write().unwrap(), root_der)
}

fn leaf_profile(issuer: Name) -> Profile {
    Profile::Leaf {
        issuer,
        enable_key_agreement: false,
        enable_key_encipherment: true,
    }
}

fn leaf_p12(password: &str, leaf_key: &RsaPrivateKey, leaf_der: &[u8], root_der: &[u8]) -> Vec<u8> {
    let key_der = leaf_key.to_pkcs8_der().unwrap().as_bytes().to_vec();
    let chain = PrivateKeyChain::new(
        &key_der,
        b"poc",
        vec![
            P12Certificate::from_der(leaf_der).unwrap(),
            P12Certificate::from_der(root_der).unwrap(),
        ],
    );
    let mut ks = KeyStore::new();
    ks.add_entry("poc", KeyStoreEntry::PrivateKeyChain(chain));
    ks.writer(password).write().unwrap()
}

/// Build a three-level PKI (root CA → intermediate CA → leaf). Returns
/// `(p12, root_cert_der)`; the p12 holds the leaf key + `[leaf, intermediate,
/// root]` chain, exercising path building through an intermediate.
pub fn ca_chain3_p12(password: &str) -> (Vec<u8>, Vec<u8>) {
    let mut rng = rand::thread_rng();
    let validity = Validity::from_now(Duration::from_secs(365 * 24 * 3600)).expect("validity");

    let root_key = RsaPrivateKey::new(&mut rng, 2048).expect("root key");
    let root_signing = SigningKey::<Sha256>::new(root_key);
    let root_name = Name::from_str("CN=PoC Root CA,O=StrategicProjects,C=BR").unwrap();
    let root_cert = CertificateBuilder::new(
        Profile::Root,
        SerialNumber::from(1u32),
        validity,
        root_name.clone(),
        SubjectPublicKeyInfoOwned::from_key(root_signing.verifying_key()).unwrap(),
        &root_signing,
    )
    .expect("root builder")
    .build::<Signature>()
    .expect("root");
    let root_der = root_cert.to_der().unwrap();

    let inter_key = RsaPrivateKey::new(&mut rng, 2048).expect("inter key");
    let inter_signing = SigningKey::<Sha256>::new(inter_key);
    let inter_name = Name::from_str("CN=PoC Intermediate CA,O=StrategicProjects,C=BR").unwrap();
    let inter_cert = CertificateBuilder::new(
        Profile::SubCA {
            issuer: root_name,
            path_len_constraint: Some(0),
        },
        SerialNumber::from(2u32),
        validity,
        inter_name.clone(),
        SubjectPublicKeyInfoOwned::from_key(inter_signing.verifying_key()).unwrap(),
        &root_signing, // signed by root
    )
    .expect("inter builder")
    .build::<Signature>()
    .expect("inter");
    let inter_der = inter_cert.to_der().unwrap();

    let leaf_key = RsaPrivateKey::new(&mut rng, 2048).expect("leaf key");
    let leaf_signing = SigningKey::<Sha256>::new(leaf_key.clone());
    let leaf_name = Name::from_str("CN=PoC Signer,O=StrategicProjects,C=BR").unwrap();
    let leaf_cert = CertificateBuilder::new(
        Profile::Leaf {
            issuer: inter_name,
            enable_key_agreement: false,
            enable_key_encipherment: true,
        },
        SerialNumber::from(3u32),
        validity,
        leaf_name,
        SubjectPublicKeyInfoOwned::from_key(leaf_signing.verifying_key()).unwrap(),
        &inter_signing, // signed by intermediate
    )
    .expect("leaf builder")
    .build::<Signature>()
    .expect("leaf");
    let leaf_der = leaf_cert.to_der().unwrap();

    let key_der = leaf_key.to_pkcs8_der().expect("pkcs8").as_bytes().to_vec();
    let chain = PrivateKeyChain::new(
        &key_der,
        b"poc",
        vec![
            P12Certificate::from_der(&leaf_der).unwrap(),
            P12Certificate::from_der(&inter_der).unwrap(),
            P12Certificate::from_der(&root_der).unwrap(),
        ],
    );
    let mut ks = KeyStore::new();
    ks.add_entry("poc", KeyStoreEntry::PrivateKeyChain(chain));
    (ks.writer(password).write().expect("write p12"), root_der)
}

/// Build a **cross-signing** scenario for path-building tests.
///
/// One intermediate key with subject `CN=Cross Intermediate` is certified twice:
/// once by an *untrusted* root A and once by a *trusted* root B. A leaf is signed
/// by the intermediate key. Returns `(leaf_der, pool, trusted_root_b_der)` where
/// `pool` is `[I_a, I_b]` — the untrusted-chaining cross-cert first, so a
/// non-backtracking path builder commits to the dead end and fails.
pub fn cross_signed_scenario() -> (Vec<u8>, Vec<Vec<u8>>, Vec<u8>) {
    let mut rng = rand::thread_rng();
    let validity = Validity::from_now(Duration::from_secs(365 * 24 * 3600)).unwrap();

    // Two independent roots: A (untrusted) and B (trusted).
    let make_root = |name: &str, rng: &mut rand::rngs::ThreadRng| {
        let key = RsaPrivateKey::new(rng, 2048).unwrap();
        let signing = SigningKey::<Sha256>::new(key);
        let name = Name::from_str(name).unwrap();
        let cert = CertificateBuilder::new(
            Profile::Root,
            SerialNumber::from(1u32),
            validity,
            name.clone(),
            SubjectPublicKeyInfoOwned::from_key(signing.verifying_key()).unwrap(),
            &signing,
        )
        .unwrap()
        .build::<Signature>()
        .unwrap();
        (signing, name, cert.to_der().unwrap())
    };
    let (root_a_signing, root_a_name, _root_a_der) = make_root("CN=Cross Root A,C=BR", &mut rng);
    let (root_b_signing, root_b_name, root_b_der) = make_root("CN=Cross Root B,C=BR", &mut rng);

    // One intermediate key, certified by each root (same subject + key).
    let inter_key = RsaPrivateKey::new(&mut rng, 2048).unwrap();
    let inter_signing = SigningKey::<Sha256>::new(inter_key.clone());
    let inter_name = Name::from_str("CN=Cross Intermediate,C=BR").unwrap();
    let inter_spki = SubjectPublicKeyInfoOwned::from_key(inter_signing.verifying_key()).unwrap();

    let make_inter = |issuer: Name, signer: &SigningKey<Sha256>, spki: &SubjectPublicKeyInfoOwned| {
        CertificateBuilder::new(
            Profile::SubCA {
                issuer,
                path_len_constraint: Some(0),
            },
            SerialNumber::from(2u32),
            validity,
            inter_name.clone(),
            spki.clone(),
            signer,
        )
        .unwrap()
        .build::<Signature>()
        .unwrap()
        .to_der()
        .unwrap()
    };
    let i_a = make_inter(root_a_name, &root_a_signing, &inter_spki);
    let i_b = make_inter(root_b_name, &root_b_signing, &inter_spki);

    // Leaf signed by the intermediate key.
    let leaf_key = RsaPrivateKey::new(&mut rng, 2048).unwrap();
    let leaf_signing = SigningKey::<Sha256>::new(leaf_key);
    let leaf_der = CertificateBuilder::new(
        leaf_profile(inter_name),
        SerialNumber::from(3u32),
        validity,
        Name::from_str("CN=Cross Leaf,C=BR").unwrap(),
        SubjectPublicKeyInfoOwned::from_key(leaf_signing.verifying_key()).unwrap(),
        &inter_signing,
    )
    .unwrap()
    .build::<Signature>()
    .unwrap()
    .to_der()
    .unwrap();

    (leaf_der, vec![i_a, i_b], root_b_der)
}

/// Material for exercising authenticated CRL revocation checks.
pub struct RevocationScenario {
    /// Leaf certificate (serial 2), signed by `root`.
    pub leaf_der: Vec<u8>,
    /// Trusted root CA (serial 1).
    pub root_der: Vec<u8>,
    /// A current CRL, signed by the root, listing the leaf as revoked.
    pub good_crl: Vec<u8>,
    /// Same contents, but signed by a different key (signature must not verify).
    pub wrong_key_crl: Vec<u8>,
    /// Signed by the root and listing the leaf, but already past `nextUpdate`.
    /// Revocation is permanent, so this still revokes the leaf.
    pub expired_crl: Vec<u8>,
    /// Signed by the root, issued (`thisUpdate`) one hour in the **future**,
    /// listing the leaf as revoked one hour **ago**: evidence produced after
    /// the validation time that still proves revocation at that time.
    pub future_crl: Vec<u8>,
    /// Signed by the root and listing the leaf, but with a `revocationDate`
    /// one hour in the future: the leaf is *not yet* revoked at "now".
    pub revoked_later_crl: Vec<u8>,
}

/// Build a root CA, a leaf, and three CRLs (valid / bad-signature / stale) so
/// tests can assert that only an authenticated, current CRL revokes the leaf.
pub fn revocation_scenario() -> RevocationScenario {
    use der::asn1::{BitString, GeneralizedTime};
    use der::DateTime;
    use signature::{SignatureEncoding, Signer};
    use std::time::{SystemTime, UNIX_EPOCH};
    use x509_cert::certificate::Version;
    use x509_cert::crl::{CertificateList, RevokedCert, TbsCertList};
    use x509_cert::spki::AlgorithmIdentifierOwned;

    let mut rng = rand::thread_rng();
    let validity = Validity::from_now(Duration::from_secs(365 * 24 * 3600)).unwrap();

    let root_key = RsaPrivateKey::new(&mut rng, 2048).unwrap();
    let root_signing = SigningKey::<Sha256>::new(root_key);
    let root_name = Name::from_str("CN=Revocation Root,C=BR").unwrap();
    let root_cert = CertificateBuilder::new(
        Profile::Root,
        SerialNumber::from(1u32),
        validity,
        root_name.clone(),
        SubjectPublicKeyInfoOwned::from_key(root_signing.verifying_key()).unwrap(),
        &root_signing,
    )
    .unwrap()
    .build::<Signature>()
    .unwrap();
    let root_der = root_cert.to_der().unwrap();

    let leaf_key = RsaPrivateKey::new(&mut rng, 2048).unwrap();
    let leaf_signing = SigningKey::<Sha256>::new(leaf_key);
    let leaf_serial = SerialNumber::from(2u32);
    let leaf_cert = CertificateBuilder::new(
        leaf_profile(root_name.clone()),
        leaf_serial.clone(),
        validity,
        Name::from_str("CN=Revocation Leaf,C=BR").unwrap(),
        SubjectPublicKeyInfoOwned::from_key(leaf_signing.verifying_key()).unwrap(),
        &root_signing,
    )
    .unwrap()
    .build::<Signature>()
    .unwrap();
    let leaf_der = leaf_cert.to_der().unwrap();

    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
    let time = |secs: u64| {
        x509_cert::time::Time::GeneralTime(GeneralizedTime::from_date_time(
            DateTime::from_unix_duration(Duration::from_secs(secs)).unwrap(),
        ))
    };
    let rsa_sha256 = || AlgorithmIdentifierOwned {
        oid: const_oid::db::rfc5912::SHA_256_WITH_RSA_ENCRYPTION,
        parameters: None,
    };

    // Build a CRL revoking the leaf at `revoked`, signed by `signer`, valid in
    // [this, next].
    let build_crl_at = |signer: &SigningKey<Sha256>, this: u64, next: u64, revoked: u64| -> Vec<u8> {
        let tbs = TbsCertList {
            version: Version::V2,
            signature: rsa_sha256(),
            issuer: root_name.clone(),
            this_update: time(this),
            next_update: Some(time(next)),
            revoked_certificates: Some(vec![RevokedCert {
                serial_number: leaf_serial.clone(),
                revocation_date: time(revoked),
                crl_entry_extensions: None,
            }]),
            crl_extensions: None,
        };
        let tbs_der = tbs.to_der().unwrap();
        let sig = signer.sign(&tbs_der);
        let crl = CertificateList {
            tbs_cert_list: tbs,
            signature_algorithm: rsa_sha256(),
            signature: BitString::from_bytes(&sig.to_vec()).unwrap(),
        };
        crl.to_der().unwrap()
    };

    let build_crl = |signer: &SigningKey<Sha256>, this: u64, next: u64| -> Vec<u8> {
        build_crl_at(signer, this, next, this)
    };
    let wrong_key = SigningKey::<Sha256>::new(RsaPrivateKey::new(&mut rng, 2048).unwrap());

    RevocationScenario {
        leaf_der,
        root_der,
        good_crl: build_crl(&root_signing, now - 3600, now + 3600),
        wrong_key_crl: build_crl(&wrong_key, now - 3600, now + 3600),
        expired_crl: build_crl(&root_signing, now - 7200, now - 3600),
        future_crl: build_crl_at(&root_signing, now + 3600, now + 7200, now - 3600),
        revoked_later_crl: build_crl_at(&root_signing, now - 3600, now + 3600, now + 3600),
    }
}

/// A minimal one-page PDF that uses a **traditional cross-reference table**
/// (as `lopdf` now saves xref streams by default, this keeps the xref-table
/// incremental-update path under test).
pub fn sample_pdf_xref_table() -> Vec<u8> {
    let content: &[u8] = b"BT /F1 24 Tf 72 720 Td (xref-table sample) Tj ET";
    let mut out = Vec::new();
    let mut off = [0usize; 6];
    out.extend_from_slice(b"%PDF-1.4\n");
    off[1] = out.len();
    out.extend_from_slice(b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n");
    off[2] = out.len();
    out.extend_from_slice(b"2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n");
    off[3] = out.len();
    out.extend_from_slice(
        b"3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] \
          /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>\nendobj\n",
    );
    off[4] = out.len();
    out.extend_from_slice(format!("4 0 obj\n<< /Length {} >>\nstream\n", content.len()).as_bytes());
    out.extend_from_slice(content);
    out.extend_from_slice(b"\nendstream\nendobj\n");
    off[5] = out.len();
    out.extend_from_slice(b"5 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>\nendobj\n");
    let xref = out.len();
    out.extend_from_slice(b"xref\n0 6\n0000000000 65535 f\r\n");
    for &o in &off[1..=5] {
        out.extend_from_slice(format!("{:010} 00000 n\r\n", o).as_bytes());
    }
    out.extend_from_slice(b"trailer\n<< /Size 6 /Root 1 0 R /Info << /Title (Contrato 42) >> >>\n");
    out.extend_from_slice(format!("startxref\n{}\n%%EOF\n", xref).as_bytes());
    out
}

// --- in-process RFC 3161 TSA ---------------------------------------------------

/// Knobs for [`mock_tsa`].
#[derive(Debug, Clone, Default)]
pub struct MockTsaOptions {
    /// Omit the `id-kp-timeStamping` EKU from the TSA certificate (a
    /// non-conforming TSA whose tokens must not anchor time).
    pub without_timestamping_eku: bool,
    /// Emit `genTime` with fractional seconds (`…SS.123Z`), as many TSAs do.
    pub fractional_seconds: bool,
    /// Assert this `genTime` (seconds since the Unix epoch) instead of "now".
    pub gen_time: Option<u64>,
    /// Answer with a bogus PKIStatus (rejection) instead of a token.
    pub reject: bool,
}

/// A running in-process TSA: POST `TimeStampReq`s to `url`.
pub struct MockTsa {
    /// `http://127.0.0.1:<port>/tsa`
    pub url: String,
    /// DER of the root CA that issued the TSA certificate (trust it to trust
    /// the TSA).
    pub root_der: Vec<u8>,
    /// DER of the TSA (leaf) certificate.
    pub tsa_der: Vec<u8>,
}

/// Start an RFC 3161 TSA on a loopback port in a background thread. It builds
/// a fresh root CA + TSA certificate (RSA-2048, SHA-256), answers every
/// well-formed request with a `granted` token over the request's imprint and
/// nonce, and embeds the TSA certificate. Lives until the process exits.
pub fn mock_tsa(opts: MockTsaOptions) -> MockTsa {
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use x509_cert::ext::pkix::ExtendedKeyUsage;

    let mut rng = rand::thread_rng();
    let validity = Validity::from_now(Duration::from_secs(365 * 24 * 3600)).unwrap();

    let root_key = RsaPrivateKey::new(&mut rng, 2048).unwrap();
    let root_signing = SigningKey::<Sha256>::new(root_key);
    let root_name = Name::from_str("CN=Mock TSA Root,O=pdf_signer tests,C=BR").unwrap();
    let root_cert = CertificateBuilder::new(
        Profile::Root,
        SerialNumber::from(1u32),
        validity,
        root_name.clone(),
        SubjectPublicKeyInfoOwned::from_key(root_signing.verifying_key()).unwrap(),
        &root_signing,
    )
    .unwrap()
    .build::<Signature>()
    .unwrap();
    let root_der = root_cert.to_der().unwrap();

    let tsa_key = RsaPrivateKey::new(&mut rng, 2048).unwrap();
    let tsa_signing = SigningKey::<Sha256>::new(tsa_key);
    let tsa_name = Name::from_str("CN=Mock TSA,O=pdf_signer tests,C=BR").unwrap();
    let mut builder = CertificateBuilder::new(
        Profile::Leaf {
            issuer: root_name,
            enable_key_agreement: false,
            enable_key_encipherment: false,
        },
        SerialNumber::from(rand::Rng::gen::<u32>(&mut rng) | 1),
        validity,
        tsa_name,
        SubjectPublicKeyInfoOwned::from_key(tsa_signing.verifying_key()).unwrap(),
        &root_signing,
    )
    .unwrap();
    if !opts.without_timestamping_eku {
        builder
            .add_extension(&ExtendedKeyUsage(vec![
                const_oid::db::rfc5280::ID_KP_TIME_STAMPING,
            ]))
            .unwrap();
    }
    let tsa_cert = builder.build::<Signature>().unwrap();
    let tsa_der = tsa_cert.to_der().unwrap();

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}/tsa", listener.local_addr().unwrap());
    let tsa_cert_thread = tsa_cert.clone();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            // Read the HTTP request: headers, then Content-Length body bytes.
            let mut buf = Vec::new();
            let mut chunk = [0u8; 4096];
            let mut body_start: Option<usize> = None;
            while let Ok(n) = stream.read(&mut chunk) {
                if n == 0 {
                    break;
                }
                buf.extend_from_slice(&chunk[..n]);
                if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                    body_start = Some(i + 4);
                    let head = String::from_utf8_lossy(&buf[..i]).to_lowercase();
                    let len: usize = head
                        .lines()
                        .find_map(|l| l.strip_prefix("content-length:"))
                        .and_then(|v| v.trim().parse().ok())
                        .unwrap_or(0);
                    while buf.len() < body_start.unwrap() + len {
                        let Ok(n) = stream.read(&mut chunk) else { break };
                        if n == 0 {
                            break;
                        }
                        buf.extend_from_slice(&chunk[..n]);
                    }
                    break;
                }
            }
            let body = body_start.map(|s| &buf[s..]).unwrap_or(&[]);
            let resp = tsa_response(body, &tsa_signing, &tsa_cert_thread, &opts);
            let _ = stream.write_all(
                format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/timestamp-reply\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    resp.len()
                )
                .as_bytes(),
            );
            let _ = stream.write_all(&resp);
        }
    });

    MockTsa {
        url,
        root_der,
        tsa_der,
    }
}

/// Build the DER `TimeStampResp` for a DER `TimeStampReq`.
fn tsa_response(
    req_der: &[u8],
    signing: &SigningKey<Sha256>,
    tsa_cert: &x509_cert::Certificate,
    opts: &MockTsaOptions,
) -> Vec<u8> {
    use cms::builder::{SignedDataBuilder, SignerInfoBuilder};
    use cms::cert::{CertificateChoices, IssuerAndSerialNumber};
    use cms::signed_data::{EncapsulatedContentInfo, SignerIdentifier};
    use der::asn1::{Int, OctetString, SetOfVec};
    use der::{Any, Decode, Sequence, Tag};
    use spki::AlgorithmIdentifierOwned;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[derive(Sequence)]
    struct MessageImprint {
        hash_algorithm: AlgorithmIdentifierOwned,
        hashed_message: OctetString,
    }
    // TimeStampReq with the optional fields we care about.
    #[derive(Sequence)]
    struct TimeStampReq {
        version: i32,
        message_imprint: MessageImprint,
        #[asn1(optional = "true")]
        req_policy: Option<ObjectIdentifier>,
        #[asn1(optional = "true")]
        nonce: Option<Int>,
        #[asn1(default = "Default::default")]
        cert_req: bool,
    }
    #[derive(Sequence)]
    struct PkiStatusInfo {
        status: i32,
    }
    #[derive(Sequence)]
    struct TimeStampResp {
        status: PkiStatusInfo,
        #[asn1(optional = "true")]
        token: Option<cms::content_info::ContentInfo>,
    }
    // TSTInfo with genTime as a raw GeneralizedTime `Any` (so fractional
    // seconds can be emitted) and an optional nonce.
    #[derive(Sequence)]
    struct TstInfo {
        version: i32,
        policy: ObjectIdentifier,
        message_imprint: MessageImprint,
        serial_number: Int,
        gen_time: Any,
        #[asn1(optional = "true")]
        nonce: Option<Int>,
    }

    let rejected = || {
        TimeStampResp {
            status: PkiStatusInfo { status: 2 },
            token: None,
        }
        .to_der()
        .unwrap()
    };
    let Ok(req) = TimeStampReq::from_der(req_der) else {
        return rejected();
    };
    if opts.reject {
        return rejected();
    }

    let secs = opts.gen_time.unwrap_or_else(|| {
        SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
    });
    let dt = der::DateTime::from_unix_duration(Duration::from_secs(secs)).unwrap();
    let mut gt = format!(
        "{:04}{:02}{:02}{:02}{:02}{:02}",
        dt.year(),
        dt.month(),
        dt.day(),
        dt.hour(),
        dt.minutes(),
        dt.seconds()
    );
    if opts.fractional_seconds {
        gt.push_str(".123");
    }
    gt.push('Z');
    let tst = TstInfo {
        version: 1,
        policy: ObjectIdentifier::new_unwrap("1.3.6.1.4.1.99999.1"),
        message_imprint: req.message_imprint,
        serial_number: Int::new(&[0x01, 0x02, 0x03]).unwrap(),
        gen_time: Any::new(Tag::GeneralizedTime, gt.as_bytes()).unwrap(),
        nonce: req.nonce,
    };
    let tst_der = tst.to_der().unwrap();

    let encap = EncapsulatedContentInfo {
        econtent_type: ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.1.4"),
        econtent: Some(Any::new(Tag::OctetString, tst_der).unwrap()),
    };
    let sid = SignerIdentifier::IssuerAndSerialNumber(IssuerAndSerialNumber {
        issuer: tsa_cert.tbs_certificate.issuer.clone(),
        serial_number: tsa_cert.tbs_certificate.serial_number.clone(),
    });
    let sha256 = AlgorithmIdentifierOwned {
        oid: const_oid::db::rfc5912::ID_SHA_256,
        parameters: None,
    };
    let mut si = SignerInfoBuilder::new(signing, sid, sha256.clone(), &encap, None).unwrap();
    // ESS signing-certificate-v2 over the TSA certificate.
    #[derive(Sequence)]
    struct EssCertIdV2 {
        cert_hash: OctetString,
    }
    #[derive(Sequence)]
    struct SigningCertificateV2 {
        certs: Vec<EssCertIdV2>,
    }
    let scv2 = SigningCertificateV2 {
        certs: vec![EssCertIdV2 {
            cert_hash: OctetString::new(
                <Sha256 as sha2::Digest>::digest(tsa_cert.to_der().unwrap()).to_vec(),
            )
            .unwrap(),
        }],
    };
    let mut values = SetOfVec::new();
    values.insert(Any::encode_from(&scv2).unwrap()).unwrap();
    si.add_signed_attribute(x509_cert::attr::Attribute {
        oid: const_oid::db::rfc5911::ID_AA_SIGNING_CERTIFICATE_V_2,
        values,
    })
    .unwrap();
    let mut builder = SignedDataBuilder::new(&encap);
    builder.add_digest_algorithm(sha256).unwrap();
    builder
        .add_certificate(CertificateChoices::Certificate(tsa_cert.clone()))
        .unwrap();
    let token = builder
        .add_signer_info::<SigningKey<Sha256>, Signature>(si)
        .unwrap()
        .build()
        .unwrap();
    TimeStampResp {
        status: PkiStatusInfo { status: 0 },
        token: Some(token),
    }
    .to_der()
    .unwrap()
}
