//! Certificate-chain validation against a trust store.
//!
//! Builds a path from a leaf certificate up to a trusted root, verifying each
//! link's signature and validity window. Intended for validating a signer
//! certificate against the **ICP-Brasil** roots (load them with
//! [`TrustStore::from_pem`]), but works with any root set.
//!
//! Scope: RSA PKCS#1 v1.5 with SHA-256/384/512 (the ICP-Brasil norm). ECDSA and
//! SHA-1 links are treated as unverifiable. No name-constraint / policy
//! processing and no revocation checking here (CRLs live in the DSS).

use std::time::SystemTime;

use const_oid::db::rfc5912::{
    ECDSA_WITH_SHA_256, ECDSA_WITH_SHA_384, ECDSA_WITH_SHA_512, SHA_256_WITH_RSA_ENCRYPTION,
    SHA_384_WITH_RSA_ENCRYPTION, SHA_512_WITH_RSA_ENCRYPTION,
};
use der::{Decode, Encode};
use rsa::pkcs1v15::{Signature, VerifyingKey};
use rsa::RsaPublicKey;
use sha2::{Sha256, Sha384, Sha512};
use signature::Verifier;
use spki::DecodePublicKey;
use x509_cert::crl::CertificateList;
use x509_cert::ext::pkix::{BasicConstraints, KeyUsage};
use x509_cert::Certificate;

use crate::error::Error;
use crate::Result;

const MAX_DEPTH: usize = 10;

/// A set of trusted root certificates (e.g. the ICP-Brasil AC Raiz set).
#[derive(Clone, Default)]
pub struct TrustStore {
    roots: Vec<Certificate>,
}

impl TrustStore {
    /// An empty store (no chain validation will succeed).
    pub fn new() -> Self {
        Self::default()
    }

    /// Load trusted roots from one or more concatenated PEM certificates.
    pub fn from_pem(pem: &[u8]) -> Result<Self> {
        let roots = Certificate::load_pem_chain(pem).map_err(|e| Error::Crypto(e.to_string()))?;
        Ok(Self { roots })
    }

    /// Load trusted roots from DER certificate blobs.
    pub fn from_ders<I: IntoIterator<Item = Vec<u8>>>(ders: I) -> Result<Self> {
        let mut roots = Vec::new();
        for der in ders {
            roots.push(
                Certificate::from_der(&der).map_err(|e| Error::Crypto(e.to_string()))?,
            );
        }
        Ok(Self { roots })
    }

    pub fn is_empty(&self) -> bool {
        self.roots.is_empty()
    }

    pub fn len(&self) -> usize {
        self.roots.len()
    }
}

/// Outcome of building/validating a certificate path.
#[derive(Debug, Clone)]
pub(crate) struct ChainResult {
    pub trusted: bool,
    pub detail: String,
}

/// Validate that `leaf` chains to a trusted root, using `pool` (e.g. the certs
/// embedded in the CMS) as candidate intermediates, at time `at`. `crls` are
/// the revocation lists available (e.g. from the document's DSS).
///
/// Enforces, per RFC 5280 (practical subset): each link's signature, validity
/// windows, issuer `basicConstraints` CA flag, `pathLenConstraint`,
/// `keyCertSign` key usage, and CRL revocation. Not enforced: name constraints,
/// certificate policies / policy mapping.
pub(crate) fn verify_chain(
    leaf: &Certificate,
    pool: &[Certificate],
    store: &TrustStore,
    crls: &[CertificateList],
    at: SystemTime,
) -> ChainResult {
    let at = at
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);

    let mut current = leaf.clone();
    let mut intermediates = 0usize; // CAs traversed below `current`
    for _ in 0..MAX_DEPTH {
        if !valid_at(&current, at) {
            return fail("a certificate in the path is expired or not yet valid");
        }
        if is_revoked(&current, crls) {
            return fail("a certificate in the path has been revoked");
        }
        // Signer certificate is itself a trusted root.
        if store.roots.iter().any(|r| same_cert(r, &current)) {
            return ok("certificate is a trusted root");
        }
        // Directly issued by a trusted root.
        if let Some(root) = store.roots.iter().find(|r| issued_by(&current, r)) {
            if !valid_at(root, at) {
                return fail("trusted root is expired");
            }
            return ok(&format!("chains to trusted root ({})", dn(root)));
        }
        // Climb one intermediate from the pool. It must be a CA whose
        // pathLenConstraint still permits the certificates below it.
        match pool
            .iter()
            .find(|c| !same_cert(c, &current) && issued_by(&current, c))
        {
            Some(next) => {
                match ca_constraints(next) {
                    Some((true, path_len)) => {
                        if path_len.is_some_and(|n| (n as usize) < intermediates) {
                            return fail("intermediate CA pathLenConstraint exceeded");
                        }
                    }
                    _ => return fail("intermediate is not a CA (basicConstraints)"),
                }
                if !permits_cert_sign(next) {
                    return fail("intermediate CA lacks keyCertSign key usage");
                }
                intermediates += 1;
                current = next.clone();
            }
            None => return fail("could not build a path to a trusted root"),
        }
    }
    fail("certificate path too long")
}

fn ok(detail: &str) -> ChainResult {
    ChainResult {
        trusted: true,
        detail: detail.to_string(),
    }
}

fn fail(detail: &str) -> ChainResult {
    ChainResult {
        trusted: false,
        detail: detail.to_string(),
    }
}

/// `(ca, pathLenConstraint)` from basicConstraints, or `None` if absent.
fn ca_constraints(cert: &Certificate) -> Option<(bool, Option<u8>)> {
    match cert.tbs_certificate.get::<BasicConstraints>() {
        Ok(Some((_, bc))) => Some((bc.ca, bc.path_len_constraint)),
        _ => None,
    }
}

/// True if the cert has no keyUsage or asserts keyCertSign.
fn permits_cert_sign(cert: &Certificate) -> bool {
    match cert.tbs_certificate.get::<KeyUsage>() {
        Ok(Some((_, ku))) => ku.key_cert_sign(),
        _ => true, // absent keyUsage = unrestricted
    }
}

/// True if `cert` appears (by serial, under its own issuer) in any CRL.
fn is_revoked(cert: &Certificate, crls: &[CertificateList]) -> bool {
    let issuer = cert.tbs_certificate.issuer.to_der().ok();
    let serial = cert.tbs_certificate.serial_number.to_der().ok();
    for crl in crls {
        if crl.tbs_cert_list.issuer.to_der().ok() != issuer {
            continue;
        }
        if let Some(revoked) = &crl.tbs_cert_list.revoked_certificates {
            for entry in revoked {
                if entry.serial_number.to_der().ok() == serial {
                    return true;
                }
            }
        }
    }
    false
}

/// `child` is issued by `issuer`: issuer/subject names match and the issuer's
/// public key verifies the child's signature.
fn issued_by(child: &Certificate, issuer: &Certificate) -> bool {
    let child_issuer = child.tbs_certificate.issuer.to_der().ok();
    let issuer_subject = issuer.tbs_certificate.subject.to_der().ok();
    if child_issuer.is_none() || child_issuer != issuer_subject {
        return false;
    }
    verify_cert_signature(child, issuer)
}

fn verify_cert_signature(child: &Certificate, issuer: &Certificate) -> bool {
    let Ok(tbs) = child.tbs_certificate.to_der() else {
        return false;
    };
    let Some(sig) = child.signature.as_bytes() else {
        return false;
    };
    let Ok(spki) = issuer.tbs_certificate.subject_public_key_info.to_der() else {
        return false;
    };
    let oid = child.signature_algorithm.oid;

    if oid == SHA_256_WITH_RSA_ENCRYPTION
        || oid == SHA_384_WITH_RSA_ENCRYPTION
        || oid == SHA_512_WITH_RSA_ENCRYPTION
    {
        let (Ok(pubkey), Ok(signature)) =
            (RsaPublicKey::from_public_key_der(&spki), Signature::try_from(sig))
        else {
            return false;
        };
        if oid == SHA_256_WITH_RSA_ENCRYPTION {
            VerifyingKey::<Sha256>::new(pubkey).verify(&tbs, &signature).is_ok()
        } else if oid == SHA_384_WITH_RSA_ENCRYPTION {
            VerifyingKey::<Sha384>::new(pubkey).verify(&tbs, &signature).is_ok()
        } else {
            VerifyingKey::<Sha512>::new(pubkey).verify(&tbs, &signature).is_ok()
        }
    } else if oid == ECDSA_WITH_SHA_256 || oid == ECDSA_WITH_SHA_384 || oid == ECDSA_WITH_SHA_512 {
        verify_ecdsa(&spki, &tbs, sig)
    } else {
        false // unsupported (e.g. SHA-1, Ed25519)
    }
}

/// Verify an ECDSA certificate signature over P-256 or P-384 (with the curve's
/// standard hash). The DER signature is `ECDSA-Sig-Value`.
fn verify_ecdsa(spki_der: &[u8], tbs: &[u8], sig: &[u8]) -> bool {
    use signature::Verifier as _;
    if let (Ok(vk), Ok(s)) = (
        p256::ecdsa::VerifyingKey::from_public_key_der(spki_der),
        p256::ecdsa::DerSignature::try_from(sig),
    ) {
        return vk.verify(tbs, &s).is_ok();
    }
    if let (Ok(vk), Ok(s)) = (
        p384::ecdsa::VerifyingKey::from_public_key_der(spki_der),
        p384::ecdsa::DerSignature::try_from(sig),
    ) {
        return vk.verify(tbs, &s).is_ok();
    }
    false
}

fn valid_at(cert: &Certificate, at: i64) -> bool {
    let nb = cert
        .tbs_certificate
        .validity
        .not_before
        .to_unix_duration()
        .as_secs() as i64;
    let na = cert
        .tbs_certificate
        .validity
        .not_after
        .to_unix_duration()
        .as_secs() as i64;
    at >= nb && at <= na
}

fn same_cert(a: &Certificate, b: &Certificate) -> bool {
    match (a.to_der(), b.to_der()) {
        (Ok(x), Ok(y)) => x == y,
        _ => false,
    }
}

fn dn(cert: &Certificate) -> String {
    cert.tbs_certificate.subject.to_string()
}
