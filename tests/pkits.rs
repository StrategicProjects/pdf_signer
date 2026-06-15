//! NIST PKITS conformance harness for the certificate-policy engine.
//!
//! The NIST Public Key Interoperability Test Suite encodes the expected outcome
//! in each end-entity certificate's name (`Valid...` / `Invalid...`). Point
//! `PKITS_DIR` at the extracted PKITS data and run:
//!
//! ```sh
//! PKITS_DIR=/tmp/pkits cargo test --test pkits -- --ignored --nocapture
//! ```

use std::path::{Path, PathBuf};
use std::time::SystemTime;

use pdf_signer::{verify_certificate_chain, TrustStore};

fn pkits_certs_dir() -> Option<PathBuf> {
    let dir = PathBuf::from(std::env::var("PKITS_DIR").ok()?).join("certs");
    dir.is_dir().then_some(dir)
}

#[test]
#[ignore = "set PKITS_DIR to the extracted NIST PKITS data"]
fn pkits_policy_conformance() {
    let Some(certs) = pkits_certs_dir() else {
        eprintln!("PKITS_DIR not set or invalid; skipping");
        return;
    };

    let anchor = std::fs::read(certs.join("TrustAnchorRootCertificate.crt")).unwrap();
    let store = TrustStore::from_ders([anchor]).unwrap();

    // The pool is every certificate except the trust anchor; the validator picks
    // the right issuers by name + signature.
    let mut pool: Vec<Vec<u8>> = Vec::new();
    let mut ee: Vec<(String, Vec<u8>)> = Vec::new();
    for entry in std::fs::read_dir(&certs).unwrap() {
        let path = entry.unwrap().path();
        let name = file_name(&path);
        if !name.ends_with(".crt") || name == "TrustAnchorRootCertificate.crt" {
            continue;
        }
        let der = std::fs::read(&path).unwrap();
        if name.ends_with("EE.crt") {
            ee.push((name, der.clone()));
        }
        pool.push(der);
    }
    ee.sort();

    let at = SystemTime::now();
    let mut all_mismatches = Vec::new();

    // The categories whose features this crate implements. (Revocation/CRL-shape
    // tests need CRLs and features we don't claim, so they aren't asserted here.)
    let categories: &[(&str, &[&str])] = &[
        (
            "policy (§4.8–4.12)",
            &["Policy", "Mapping", "inhibit", "requireExplicit", "anyPolicy"],
        ),
        ("name constraints (§4.13)", &["nameConstraint"]),
    ];

    for (label, keywords) in categories {
        let (mut pass, mut skipped) = (0, 0);
        let mut mismatches = Vec::new();
        for (name, der) in &ee {
            if !keywords.iter().any(|k| name.contains(k)) {
                continue;
            }
            // Only the unambiguously-prefixed tests have a fixed expected result
            // under the default validation inputs.
            let expected = if name.starts_with("Valid") {
                true
            } else if name.starts_with("Invalid") {
                false
            } else {
                skipped += 1;
                continue;
            };
            let got = verify_certificate_chain(der, &pool, &[], &store, at);
            if got == expected {
                pass += 1;
            } else {
                mismatches.push(format!("  {name}: expected {expected}, got {got}"));
            }
        }
        eprintln!(
            "PKITS {label}: {}/{} passed ({skipped} input-dependent skipped)",
            pass,
            pass + mismatches.len()
        );
        for m in &mismatches {
            eprintln!("{m}");
        }
        all_mismatches.extend(mismatches);
    }

    assert!(all_mismatches.is_empty(), "{} mismatches", all_mismatches.len());
}

fn file_name(path: &Path) -> String {
    path.file_name().unwrap().to_string_lossy().into_owned()
}
