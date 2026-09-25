//! Certificate-chain validation against a trust store.
//!
//! Builds a path from a leaf certificate up to a trusted root, verifying each
//! link's signature and validity window. Intended for validating a signer
//! certificate against the **ICP-Brasil** roots (load them with
//! [`TrustStore::from_pem`]), but works with any root set.
//!
//! Supported signature algorithms: RSA PKCS#1 v1.5 (SHA-256/384/512), ECDSA
//! (P-256/P-384) and Ed25519; SHA-1 links are treated as unverifiable. The path
//! checks basicConstraints/`keyCertSign`, the validity window, RFC 5280 name
//! constraints (§4.2.1.10) and an optional required-policy OID via the
//! [`policy`](crate::policy) engine.
//!
//! Revocation: CRL and OCSP material (collected into the `/DSS`) is
//! authenticated before it is acted on — a CRL must be in scope and signed by
//! the issuing CA; an OCSP response must be signed by the issuer or a delegated
//! `id-kp-OCSPSigning` responder. An authenticated *revoked* entry counts
//! whenever its revocation date is not after the validation time, even if the
//! evidence itself was produced later (RFC 3161 Appendix B). Revocation is
//! soft-fail (no usable evidence ⇒ not treated as revoked). Not yet covered:
//! IDP / partitioned CRLs and a hard-fail mode.
//!
//! Every certificate below the trust anchor must also pass RFC 5280 §6.1.3
//! extension processing: a critical extension this crate does not understand,
//! or a known extension that fails to decode (including duplicates), fails the
//! path rather than being ignored.

use std::time::SystemTime;

use const_oid::db::rfc5912::{
    ECDSA_WITH_SHA_256, ECDSA_WITH_SHA_384, ECDSA_WITH_SHA_512, ID_KP_OCSP_SIGNING,
    ID_KP_TIME_STAMPING, SHA_256_WITH_RSA_ENCRYPTION, SHA_384_WITH_RSA_ENCRYPTION,
    SHA_512_WITH_RSA_ENCRYPTION,
};
use const_oid::db::rfc8410::ID_ED_25519;
use der::{Decode, Encode};
use rsa::pkcs1v15::{Signature, VerifyingKey};
use rsa::RsaPublicKey;
use sha2::{Sha256, Sha384, Sha512};
use signature::hazmat::PrehashVerifier;
use signature::Verifier;
use spki::DecodePublicKey;
use std::collections::BTreeSet;

use const_oid::db::rfc5280::ANY_POLICY;
use const_oid::db::rfc5912::{
    ID_SHA_1, ID_SHA_256, ID_SHA_384, ID_SHA_512,
};
use const_oid::ObjectIdentifier;
use sha1::{Digest as _, Sha1};
use x509_cert::crl::CertificateList;
use x509_cert::ext::pkix::name::GeneralName;
use x509_cert::ext::pkix::{
    BasicConstraints, ExtendedKeyUsage, KeyUsage, NameConstraints, SubjectAltName,
};
use x509_cert::name::{Name, RelativeDistinguishedName};
use x509_cert::Certificate;
use x509_ocsp::{BasicOcspResponse, CertId, CertStatus, ResponderId};

use crate::error::Error;
use crate::policy::{process_policies, PolicyInput};
use crate::Result;

const MAX_DEPTH: usize = 10;

/// Upper bound on the number of candidate-issuer evaluations (each costing a
/// signature verification) a single path search may perform. The candidate
/// pool comes from the untrusted CMS, and without a budget a handful of
/// same-name CA certificates makes the backtracking search factorial.
const MAX_CANDIDATE_EVALUATIONS: usize = 256;

/// What the end-entity certificate of a path is being used for. Drives the
/// leaf `keyUsage` / `extendedKeyUsage` checks (RFC 5280 §4.2.1.3 / §4.2.1.12).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LeafPurpose {
    /// No purpose-specific leaf checks (e.g. NIST PKITS conformance runs).
    Any,
    /// A document signer: `digitalSignature` or `nonRepudiation` when
    /// `keyUsage` is present.
    DocumentSigning,
    /// An RFC 3161 TSA: the `id-kp-timeStamping` extended key usage is
    /// **required** (RFC 3161 §2.3), plus `digitalSignature`/`nonRepudiation`
    /// when `keyUsage` is present.
    TimeStamping,
}

/// Extensions this validator knows how to process. Any *other* extension that
/// a certificate marks critical fails path validation (RFC 5280 §6.1.3 (b)).
const RECOGNIZED_EXTENSIONS: &[ObjectIdentifier] = &[
    const_oid::db::rfc5280::ID_CE_BASIC_CONSTRAINTS,
    const_oid::db::rfc5280::ID_CE_KEY_USAGE,
    const_oid::db::rfc5280::ID_CE_EXT_KEY_USAGE,
    const_oid::db::rfc5280::ID_CE_NAME_CONSTRAINTS,
    const_oid::db::rfc5280::ID_CE_CERTIFICATE_POLICIES,
    const_oid::db::rfc5280::ID_CE_POLICY_MAPPINGS,
    const_oid::db::rfc5280::ID_CE_POLICY_CONSTRAINTS,
    const_oid::db::rfc5280::ID_CE_INHIBIT_ANY_POLICY,
    const_oid::db::rfc5280::ID_CE_SUBJECT_ALT_NAME,
    const_oid::db::rfc5280::ID_CE_ISSUER_ALT_NAME,
    const_oid::db::rfc5280::ID_CE_SUBJECT_KEY_IDENTIFIER,
    const_oid::db::rfc5280::ID_CE_AUTHORITY_KEY_IDENTIFIER,
    const_oid::db::rfc5280::ID_CE_CRL_DISTRIBUTION_POINTS,
    const_oid::db::rfc5280::ID_CE_FRESHEST_CRL,
    const_oid::db::rfc5280::ID_CE_SUBJECT_DIRECTORY_ATTRIBUTES,
    const_oid::db::rfc5280::ID_PE_AUTHORITY_INFO_ACCESS,
    const_oid::db::rfc5280::ID_PE_SUBJECT_INFO_ACCESS,
    // id-pkix-ocsp-nocheck (RFC 6960 §4.2.2.2.1), seen on OCSP responder certs.
    const_oid::db::rfc6960::ID_PKIX_OCSP_NOCHECK,
];

/// Decode extension `T` of `cert` strictly: `Ok(None)` when absent, `Ok(Some)`
/// when present and well-formed, `Err` when present but undecodable — which
/// includes a duplicated extension (x509-cert reports duplicates as an error).
/// Callers treat `Err` as a validation failure, never as "absent".
fn ext<'a, T: Decode<'a> + const_oid::AssociatedOid>(
    cert: &'a Certificate,
) -> std::result::Result<Option<T>, String> {
    match cert.tbs_certificate.get::<T>() {
        Ok(Some((_, v))) => Ok(Some(v)),
        Ok(None) => Ok(None),
        Err(e) => Err(format!("malformed or duplicated certificate extension: {e}")),
    }
}

/// RFC 5280 §6.1.3 (b)/(c) extension processing for one certificate below the
/// anchor: every known extension must decode, and no unknown extension may be
/// critical.
fn check_extensions(cert: &Certificate) -> std::result::Result<(), String> {
    if let Some(exts) = &cert.tbs_certificate.extensions {
        for e in exts {
            if e.critical && !RECOGNIZED_EXTENSIONS.contains(&e.extn_id) {
                return Err(format!(
                    "unrecognized critical certificate extension {}",
                    e.extn_id
                ));
            }
        }
    }
    ext::<BasicConstraints>(cert)?;
    ext::<KeyUsage>(cert)?;
    ext::<ExtendedKeyUsage>(cert)?;
    ext::<NameConstraints>(cert)?;
    ext::<SubjectAltName>(cert)?;
    ext::<x509_cert::ext::pkix::CertificatePolicies>(cert)?;
    ext::<x509_cert::ext::pkix::PolicyMappings>(cert)?;
    ext::<x509_cert::ext::pkix::PolicyConstraints>(cert)?;
    ext::<x509_cert::ext::pkix::InhibitAnyPolicy>(cert)?;
    Ok(())
}

/// Leaf key-usage checks for `purpose` (RFC 5280 §4.2.1.3, RFC 3161 §2.3).
fn check_leaf_purpose(leaf: &Certificate, purpose: LeafPurpose) -> std::result::Result<(), String> {
    if purpose == LeafPurpose::Any {
        return Ok(());
    }
    if let Some(ku) = ext::<KeyUsage>(leaf)? {
        if !(ku.digital_signature() || ku.non_repudiation()) {
            return Err(
                "signer certificate keyUsage permits neither digitalSignature nor nonRepudiation"
                    .into(),
            );
        }
    }
    if purpose == LeafPurpose::TimeStamping {
        match ext::<ExtendedKeyUsage>(leaf)? {
            Some(eku) if eku.0.contains(&ID_KP_TIME_STAMPING) => {}
            _ => {
                return Err(
                    "TSA certificate lacks the id-kp-timeStamping extended key usage (RFC 3161 §2.3)"
                        .into(),
                )
            }
        }
    }
    Ok(())
}

/// A set of trusted root certificates (e.g. the ICP-Brasil AC Raiz set), plus
/// optional validation parameters.
#[derive(Clone, Default)]
pub struct TrustStore {
    roots: Vec<Certificate>,
    required_policy: Option<ObjectIdentifier>,
}

impl TrustStore {
    /// An empty store (no chain validation will succeed).
    pub fn new() -> Self {
        Self::default()
    }

    /// Load trusted roots from one or more concatenated PEM certificates.
    pub fn from_pem(pem: &[u8]) -> Result<Self> {
        let roots = Certificate::load_pem_chain(pem).map_err(|e| Error::Crypto(e.to_string()))?;
        Ok(Self {
            roots,
            required_policy: None,
        })
    }

    /// Load trusted roots from DER certificate blobs.
    pub fn from_ders<I: IntoIterator<Item = Vec<u8>>>(ders: I) -> Result<Self> {
        let mut roots = Vec::new();
        for der in ders {
            roots.push(Certificate::from_der(&der).map_err(|e| Error::Crypto(e.to_string()))?);
        }
        Ok(Self {
            roots,
            required_policy: None,
        })
    }

    /// Require that the certificate path asserts a given policy OID (e.g. an
    /// ICP-Brasil policy): the OID becomes the `user-initial-policy-set` and
    /// `initial-explicit-policy` is set, so the RFC 5280 §6.1 policy engine
    /// (`valid_policy_tree`, policy mapping, the inhibit/require counters) must
    /// end with that policy valid for the leaf.
    pub fn require_policy(mut self, oid: &str) -> Result<Self> {
        self.required_policy =
            Some(ObjectIdentifier::new(oid).map_err(|e| Error::Crypto(e.to_string()))?);
        Ok(self)
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
/// Enforces, per RFC 5280: each link's signature, validity windows, issuer
/// `basicConstraints` CA flag, `pathLenConstraint` (non-self-issued
/// intermediates), `keyCertSign` key usage, critical-extension processing,
/// CRL + OCSP revocation, **name constraints**, the §6.1 **policy engine**
/// (with an optional required policy), and the leaf's key usage for
/// `purpose`. The search is bounded by [`MAX_CANDIDATE_EVALUATIONS`].
///
/// Revocation is **soft-fail**: a CRL or OCSP response is only acted on once it
/// is authenticated (signed by the issuing CA / an authorized responder) and in
/// scope; when no such evidence is available a certificate is not treated as
/// revoked. This avoids a forged list silently flipping the verdict, while not
/// requiring online revocation material to be present.
pub(crate) fn verify_chain(
    leaf: &Certificate,
    pool: &[Certificate],
    store: &TrustStore,
    crls: &[CertificateList],
    ocsps: &[BasicOcspResponse],
    at: SystemTime,
    purpose: LeafPurpose,
) -> ChainResult {
    let at = at
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);

    // The leaf's own extensions and purpose are checked once, up front (they do
    // not depend on which issuer path is taken).
    if !store.roots.iter().any(|r| same_cert(r, leaf)) {
        if let Err(detail) = check_extensions(leaf) {
            return fail(&detail);
        }
    }
    if let Err(detail) = check_leaf_purpose(leaf, purpose) {
        return fail(&detail);
    }

    // Deduplicate the candidate pool (the CMS may carry the same certificate
    // several times) so identical candidates are not re-evaluated.
    let mut seen: BTreeSet<Vec<u8>> = BTreeSet::new();
    let pool: Vec<&Certificate> = pool
        .iter()
        .filter(|c| c.to_der().map(|d| seen.insert(d)).unwrap_or(false))
        .collect();

    // Build [leaf, intermediate..., root] depth-first, backtracking past any
    // candidate issuer that fails its checks so a valid alternative chain — e.g.
    // under cross-signing, duplicate intermediates, or a candidate that trips a
    // constraint — can still be found rather than abandoned.
    let mut ctx = SearchCtx {
        store,
        pool: &pool,
        crls,
        ocsps,
        at,
        budget: MAX_CANDIDATE_EVALUATIONS,
    };
    let mut path: Vec<Certificate> = vec![leaf.clone()];
    extend_path(&mut path, &mut ctx)
}

/// Shared, read-mostly state of one path search plus its remaining budget.
struct SearchCtx<'a> {
    store: &'a TrustStore,
    pool: &'a [&'a Certificate],
    crls: &'a [CertificateList],
    ocsps: &'a [BasicOcspResponse],
    at: i64,
    /// Remaining candidate-issuer evaluations (see [`MAX_CANDIDATE_EVALUATIONS`]).
    budget: usize,
}

impl SearchCtx<'_> {
    /// Spend one unit of budget; `false` once exhausted.
    fn spend(&mut self) -> bool {
        if self.budget == 0 {
            return false;
        }
        self.budget -= 1;
        true
    }
}

/// Depth-first certificate-path construction with backtracking. `path` ends at
/// the certificate we are trying to chain upward to a trusted root. Returns the
/// first fully validated [`ChainResult`], else a failure. Each candidate issuer
/// is evaluated independently: a rejected candidate is skipped, not fatal, so a
/// later valid issuer still gets its turn. The search stops once the
/// evaluation budget is exhausted (an attacker-supplied pool must not be able to
/// make verification run for hours).
fn extend_path(path: &mut Vec<Certificate>, ctx: &mut SearchCtx<'_>) -> ChainResult {
    let current = path.last().unwrap().clone();
    let at = ctx.at;
    if !valid_at(&current, at) {
        return fail("a certificate in the path is expired or not yet valid");
    }
    // The current certificate is itself a trusted anchor.
    if ctx.store.roots.iter().any(|r| same_cert(r, &current)) {
        return finalize(path, ctx.store);
    }
    // The most informative rejection seen so far (a path that reached a root but
    // failed a path-wide check beats the generic "no path" message).
    let mut pending: Option<ChainResult> = None;

    // Try every trusted root that could have issued `current`.
    for root in ctx.store.roots.iter() {
        if !ctx.spend() {
            return pending.unwrap_or_else(|| fail("certificate path search budget exhausted"));
        }
        if !issued_by(&current, root) {
            continue;
        }
        if !valid_at(root, at) || revoked(&current, root, ctx.crls, ctx.ocsps, at) {
            continue;
        }
        path.push(root.clone());
        let result = finalize(path, ctx.store);
        if result.trusted {
            return result;
        }
        pending.get_or_insert(result);
        path.pop();
    }
    // Intermediates already on the path (everything but the leaf).
    let intermediates = path.len() - 1;
    if intermediates >= MAX_DEPTH {
        return pending.unwrap_or_else(|| fail("certificate path too long"));
    }
    // RFC 5280 §4.2.1.9: pathLenConstraint bounds the number of **non-self-issued**
    // intermediate certificates that may follow the constrained CA.
    let counted_below = path[1..]
        .iter()
        .filter(|c| !crate::policy::is_self_issued(c))
        .count();
    // Try every candidate intermediate that could have issued `current`.
    for &next in ctx.pool.iter() {
        // Skip self and anything already on the path (avoid cycles).
        if same_cert(next, &current) || path.iter().any(|c| same_cert(c, next)) {
            continue;
        }
        if !ctx.spend() {
            return pending.unwrap_or_else(|| fail("certificate path search budget exhausted"));
        }
        if !issued_by(&current, next) {
            continue;
        }
        // RFC 5280 §6.1.3 extension processing, then: must be a CA whose
        // pathLenConstraint still permits the certificates below it, assert
        // keyCertSign, and not be revoked by its issuer.
        if let Err(detail) = check_extensions(next) {
            pending.get_or_insert(fail(&detail));
            continue;
        }
        match ca_constraints(next) {
            Some((true, path_len)) if !path_len.is_some_and(|n| (n as usize) < counted_below) => {}
            _ => continue,
        }
        if !permits_cert_sign(next) || revoked(&current, next, ctx.crls, ctx.ocsps, at) {
            continue;
        }
        path.push(next.clone());
        let result = extend_path(path, ctx);
        if result.trusted {
            return result;
        }
        pending.get_or_insert(result);
        path.pop();
    }
    pending.unwrap_or_else(|| fail("could not build a path to a trusted root"))
}

/// Run the path-wide checks (name constraints, required policy) once a trusted
/// root has been reached. `path` is `[leaf, intermediate..., root]`.
fn finalize(path: &[Certificate], store: &TrustStore) -> ChainResult {
    if let Err(detail) = check_name_constraints(path) {
        return fail(&detail);
    }
    // RFC 5280 §6.1 policy processing over the path (excluding the anchor).
    let certs: Vec<&Certificate> = path[..path.len().saturating_sub(1)].iter().rev().collect();
    let input = PolicyInput {
        initial_policy_set: match store.required_policy {
            Some(p) => BTreeSet::from([p]),
            None => BTreeSet::from([ANY_POLICY]),
        },
        initial_explicit_policy: store.required_policy.is_some(),
    };
    if let Err(detail) = process_policies(&certs, &input) {
        return fail(&detail);
    }
    let anchor = path.last().expect("non-empty path");
    if path.len() == 1 {
        ok("certificate is a trusted root")
    } else {
        ok(&format!("chains to trusted root ({})", dn(anchor)))
    }
}

// --- RFC 5280 name constraints (§4.2.1.10) -----------------------------------

/// Apply name constraints down the path: each certificate must satisfy the
/// constraints imposed by every CA above it. `path` is `[leaf, ..., root]`.
fn check_name_constraints(path: &[Certificate]) -> std::result::Result<(), String> {
    let mut collected: Vec<NameConstraints> = Vec::new();
    // Walk from the root (trust anchor, unchecked) down to the leaf.
    // `path[0]` is the leaf (the "final certificate" in RFC 5280 §6.1 terms).
    for (i, cert) in path.iter().enumerate().rev() {
        let is_anchor = i == path.len() - 1;
        // RFC 5280 §6.1.3 (b)/(c): a self-issued certificate that is not the
        // final certificate in the path is exempt from the subject name-constraint
        // check (its name is an artefact of a key rollover, not a new identity).
        let exempt_self_issued = i != 0 && crate::policy::is_self_issued(cert);
        if !is_anchor && !exempt_self_issued {
            for name in cert_names(cert) {
                for nc in &collected {
                    if name_excluded(&name, nc) {
                        return Err("subject name excluded by a CA name constraint".into());
                    }
                    if !name_permitted(&name, nc) {
                        return Err("subject name outside a CA's permitted name constraints".into());
                    }
                }
            }
        }
        if let Ok(Some((_, nc))) = cert.tbs_certificate.get::<NameConstraints>() {
            collected.push(nc);
        }
    }
    Ok(())
}

/// The PKCS#9 `emailAddress` attribute OID (`1.2.840.113549.1.9.1`). RFC 5280
/// §4.2.1.10 requires `rfc822Name` constraints to also bind a legacy email
/// address carried in this subject-DN attribute.
const EMAIL_ADDRESS_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.1");

/// The constrained names of a certificate: its subject DN (when non-empty), any
/// SANs, and any legacy `emailAddress` attribute in the subject DN promoted to an
/// `rfc822Name` (RFC 5280 §4.2.1.10).
fn cert_names(cert: &Certificate) -> Vec<GeneralName> {
    let mut names = Vec::new();
    if !cert.tbs_certificate.subject.0.is_empty() {
        names.push(GeneralName::DirectoryName(cert.tbs_certificate.subject.clone()));
    }
    for rdn in cert.tbs_certificate.subject.0.iter() {
        for atv in rdn.0.iter() {
            if atv.oid == EMAIL_ADDRESS_OID {
                if let Ok(email) = der::asn1::Ia5String::new(&value_string(atv)) {
                    names.push(GeneralName::Rfc822Name(email));
                }
            }
        }
    }
    if let Ok(Some((_, san))) = cert.tbs_certificate.get::<SubjectAltName>() {
        names.extend(san.0.iter().cloned());
    }
    names
}

/// Best-effort decode of an `AttributeTypeAndValue` value into its string content.
fn value_string(atv: &x509_cert::attr::AttributeTypeAndValue) -> String {
    let bytes = atv.value.value();
    String::from_utf8_lossy(bytes).into_owned()
}

fn name_excluded(name: &GeneralName, nc: &NameConstraints) -> bool {
    nc.excluded_subtrees
        .as_ref()
        .is_some_and(|subs| subs.iter().any(|s| within_subtree(name, &s.base) == Some(true)))
}

fn name_permitted(name: &GeneralName, nc: &NameConstraints) -> bool {
    let Some(subs) = &nc.permitted_subtrees else {
        return true; // no permitted constraint
    };
    // Only subtrees of the same type as `name` constrain it.
    let same_type: Vec<_> = subs
        .iter()
        .filter(|s| within_subtree(name, &s.base).is_some())
        .collect();
    if same_type.is_empty() {
        return true; // this type is unconstrained by permittedSubtrees
    }
    same_type
        .iter()
        .any(|s| within_subtree(name, &s.base) == Some(true))
}

/// `Some(true/false)` when `name` and `base` are the same GeneralName type
/// (matched or not), `None` when the types differ (constraint not applicable).
fn within_subtree(name: &GeneralName, base: &GeneralName) -> Option<bool> {
    match (name, base) {
        (GeneralName::DirectoryName(n), GeneralName::DirectoryName(b)) => Some(dn_within(n, b)),
        (GeneralName::DnsName(n), GeneralName::DnsName(b)) => {
            Some(dns_within(n.as_str(), b.as_str()))
        }
        (GeneralName::Rfc822Name(n), GeneralName::Rfc822Name(b)) => {
            Some(email_within(n.as_str(), b.as_str()))
        }
        (GeneralName::IpAddress(n), GeneralName::IpAddress(b)) => {
            Some(ip_within(n.as_bytes(), b.as_bytes()))
        }
        (GeneralName::UniformResourceIdentifier(n), GeneralName::UniformResourceIdentifier(b)) => {
            Some(host_within(uri_host(n.as_str()), b.as_str()))
        }
        _ => None,
    }
}

/// Host-based matching (URI/email): an exact host unless the base begins with a
/// period, which then matches subdomains only (not the bare domain).
fn host_within(host: &str, base: &str) -> bool {
    let h = host.to_ascii_lowercase();
    let b = base.to_ascii_lowercase();
    match b.strip_prefix('.') {
        Some(domain) => h.ends_with(&format!(".{domain}")),
        None => h == b,
    }
}

/// A DN is within a base subtree if the base RDN sequence is a prefix of it,
/// comparing RDNs case-insensitively and ignoring the DirectoryString encoding
/// (PrintableString vs UTF8String) — a practical subset of RFC 5280 §7.1.
fn dn_within(name: &Name, base: &Name) -> bool {
    if base.0.len() > name.0.len() {
        return false;
    }
    base.0
        .iter()
        .zip(name.0.iter())
        .all(|(b, n)| rdn_key(b) == rdn_key(n))
}

/// Normalize an RDN to a set of `(attribute oid, folded value)` pairs.
fn rdn_key(rdn: &RelativeDistinguishedName) -> BTreeSet<(ObjectIdentifier, String)> {
    rdn.0
        .iter()
        .map(|atv| {
            let folded = String::from_utf8_lossy(atv.value.value())
                .split_whitespace()
                .collect::<Vec<_>>()
                .join(" ")
                .to_lowercase();
            (atv.oid, folded)
        })
        .collect()
}

fn dns_within(name: &str, base: &str) -> bool {
    let n = name.to_ascii_lowercase();
    let b = base.trim_start_matches('.').to_ascii_lowercase();
    if b.is_empty() {
        return true;
    }
    n == b || n.ends_with(&format!(".{b}"))
}

fn email_within(name: &str, base: &str) -> bool {
    let n = name.to_ascii_lowercase();
    let b = base.to_ascii_lowercase();
    if b.contains('@') {
        return n == b; // exact mailbox
    }
    match n.split_once('@') {
        Some((_, host)) => host_within(host, &b),
        None => false,
    }
}

fn ip_within(name: &[u8], base: &[u8]) -> bool {
    // base is address || mask (8 bytes for IPv4, 32 for IPv6).
    if base.len() != name.len() * 2 {
        return false;
    }
    let (net, mask) = base.split_at(name.len());
    name.iter()
        .zip(net)
        .zip(mask)
        .all(|((nb, ab), mb)| (nb & mb) == (ab & mb))
}

fn uri_host(uri: &str) -> &str {
    let after_scheme = uri.split("://").nth(1).unwrap_or(uri);
    let authority = after_scheme.split(['/', '?', '#']).next().unwrap_or("");
    let host = authority.rsplit('@').next().unwrap_or(authority);
    host.split(':').next().unwrap_or(host)
}


/// True if an **authenticated** OCSP response marks `cert` (under `issuer`) as
/// revoked at or before `at`. The response must be signed either by the issuer
/// itself or by a delegated responder it certified (with the `id-kp-OCSPSigning`
/// EKU) that is valid at `at`. Unauthenticated responses are ignored (soft-fail,
/// see [`revoked`]). Revocation is permanent, so a *revoked* single response
/// counts whenever its `revocationTime` is not after `at` — even if the
/// response itself was produced later than `at` (RFC 3161 Appendix B): the
/// OCSP evidence a B-LT signer embeds is necessarily fetched after signing.
fn ocsp_revoked(
    cert: &Certificate,
    issuer: &Certificate,
    ocsps: &[BasicOcspResponse],
    at: i64,
) -> bool {
    for basic in ocsps {
        if !ocsp_authentic(basic, issuer, at) {
            continue;
        }
        for single in basic.tbs_response_data.responses.iter() {
            let CertStatus::Revoked(info) = &single.cert_status else {
                continue;
            };
            // Recompute the CertID under the hash the responder used.
            let Some(want) = cert_id_for(&single.cert_id.hash_algorithm.oid, issuer, cert) else {
                continue;
            };
            if !cert_id_eq(&single.cert_id, &want) {
                continue;
            }
            let revoked_at = info.revocation_time.0.to_unix_duration().as_secs() as i64;
            if revoked_at <= at {
                return true;
            }
        }
    }
    false
}

/// The `CertID` of `cert` under `issuer`, hashed with the algorithm `oid`
/// (SHA-1 / SHA-256 / SHA-384 / SHA-512, as responders use in practice).
fn cert_id_for(oid: &ObjectIdentifier, issuer: &Certificate, cert: &Certificate) -> Option<CertId> {
    let serial = cert.tbs_certificate.serial_number.clone();
    if *oid == ID_SHA_1 {
        CertId::from_issuer::<Sha1>(issuer, serial).ok()
    } else if *oid == ID_SHA_256 {
        CertId::from_issuer::<Sha256>(issuer, serial).ok()
    } else if *oid == ID_SHA_384 {
        CertId::from_issuer::<Sha384>(issuer, serial).ok()
    } else if *oid == ID_SHA_512 {
        CertId::from_issuer::<Sha512>(issuer, serial).ok()
    } else {
        None
    }
}

/// Verify that a `BasicOcspResponse` is signed by an authorized responder for
/// `issuer`: either `issuer` directly, or a delegated responder certificate
/// embedded in the response, issued by `issuer` and bearing the OCSP-signing EKU.
fn ocsp_authentic(basic: &BasicOcspResponse, issuer: &Certificate, at: i64) -> bool {
    let Ok(tbs) = basic.tbs_response_data.to_der() else {
        return false;
    };
    let Some(sig) = basic.signature.as_bytes() else {
        return false;
    };
    let oid = basic.signature_algorithm.oid;
    let rid = &basic.tbs_response_data.responder_id;

    // The issuer signs its own OCSP responses.
    if responder_is(rid, issuer) && verify_with_cert(issuer, &tbs, oid, sig) {
        return true;
    }
    // A delegated responder certified by the issuer.
    if let Some(certs) = &basic.certs {
        for c in certs {
            if responder_is(rid, c)
                && issued_by(c, issuer)
                && has_ocsp_signing_eku(c)
                && valid_at(c, at)
                && check_extensions(c).is_ok()
                && verify_with_cert(c, &tbs, oid, sig)
            {
                return true;
            }
        }
    }
    false
}

/// Verify `sig`/`oid` over `tbs` using `cert`'s public key.
fn verify_with_cert(cert: &Certificate, tbs: &[u8], oid: ObjectIdentifier, sig: &[u8]) -> bool {
    match cert.tbs_certificate.subject_public_key_info.to_der() {
        Ok(spki) => verify_signature(tbs, oid, sig, &spki),
        Err(_) => false,
    }
}

/// True if `rid` identifies `cert` (by subject name or by SHA-1 key hash).
fn responder_is(rid: &ResponderId, cert: &Certificate) -> bool {
    match rid {
        ResponderId::ByName(name) => {
            name.to_der().ok() == cert.tbs_certificate.subject.to_der().ok()
        }
        ResponderId::ByKey(key_hash) => {
            match cert
                .tbs_certificate
                .subject_public_key_info
                .subject_public_key
                .as_bytes()
            {
                Some(pk) => Sha1::digest(pk).as_slice() == key_hash.as_bytes(),
                None => false,
            }
        }
    }
}

/// True if `cert` asserts the `id-kp-OCSPSigning` extended key usage.
fn has_ocsp_signing_eku(cert: &Certificate) -> bool {
    matches!(
        cert.tbs_certificate.get::<ExtendedKeyUsage>(),
        Ok(Some((_, eku))) if eku.0.contains(&ID_KP_OCSP_SIGNING)
    )
}

/// Compare two `CertID`s by name hash, key hash and serial (ignoring the hash
/// algorithm's encoding nuances).
fn cert_id_eq(a: &CertId, b: &CertId) -> bool {
    a.issuer_name_hash.as_bytes() == b.issuer_name_hash.as_bytes()
        && a.issuer_key_hash.as_bytes() == b.issuer_key_hash.as_bytes()
        && a.serial_number.to_der().ok() == b.serial_number.to_der().ok()
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

/// True if `cert` is revoked by `issuer` according to any authenticated CRL or
/// OCSP response. Revocation is soft-fail: when no usable (authenticated, fresh,
/// in-scope) evidence is available the certificate is *not* treated as revoked.
fn revoked(
    cert: &Certificate,
    issuer: &Certificate,
    crls: &[CertificateList],
    ocsps: &[BasicOcspResponse],
    at: i64,
) -> bool {
    crl_revoked(cert, issuer, crls, at) || ocsp_revoked(cert, issuer, ocsps, at)
}

/// True if an **authenticated** CRL from `issuer` lists `cert` as revoked at or
/// before `at`.
///
/// A CRL is only consulted when it is in scope (issued by this CA) and its
/// signature verifies under the CA's key. Revocation is permanent, so an entry
/// whose `revocationDate` is not after `at` counts regardless of the CRL's own
/// `thisUpdate`/`nextUpdate` window: a CRL published *after* a trusted signing
/// time is exactly the evidence that shows the certificate was already revoked
/// at that time (RFC 3161 Appendix B), and a stale CRL does not un-revoke
/// anything. Unauthenticated or out-of-scope CRLs are ignored rather than
/// trusted (revocation is otherwise soft-fail — see [`verify_chain`]).
fn crl_revoked(cert: &Certificate, issuer: &Certificate, crls: &[CertificateList], at: i64) -> bool {
    let serial = cert.tbs_certificate.serial_number.to_der().ok();
    let ca_subject = issuer.tbs_certificate.subject.to_der().ok();
    for crl in crls {
        // Scope: the CRL must be issued by this CA.
        if crl.tbs_cert_list.issuer.to_der().ok() != ca_subject {
            continue;
        }
        // Authenticity: the CRL must be signed by this CA.
        if !verify_crl_signature(crl, issuer) {
            continue;
        }
        if let Some(revoked) = &crl.tbs_cert_list.revoked_certificates {
            if revoked.iter().any(|entry| {
                entry.serial_number.to_der().ok() == serial
                    && time_secs(&entry.revocation_date) <= at
            }) {
                return true;
            }
        }
    }
    false
}

/// Verify a CRL's signature under the issuing CA's public key.
fn verify_crl_signature(crl: &CertificateList, issuer: &Certificate) -> bool {
    let Ok(tbs) = crl.tbs_cert_list.to_der() else {
        return false;
    };
    let Some(sig) = crl.signature.as_bytes() else {
        return false;
    };
    let Ok(spki) = issuer.tbs_certificate.subject_public_key_info.to_der() else {
        return false;
    };
    // RFC 5280 §5.1.1.2: the outer signatureAlgorithm must equal the TBS one.
    if crl.signature_algorithm != crl.tbs_cert_list.signature {
        return false;
    }
    verify_signature(&tbs, crl.signature_algorithm.oid, sig, &spki)
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
    // RFC 5280 §4.1.1.2: the outer signatureAlgorithm must equal the TBS one.
    if child.signature_algorithm != child.tbs_certificate.signature {
        return false;
    }
    verify_signature(&tbs, child.signature_algorithm.oid, sig, &spki)
}

/// Verify `sig` over `tbs` under the algorithm `oid`, using the signer's
/// SubjectPublicKeyInfo DER. Shared by certificate, CRL and OCSP verification.
/// SHA-1-based algorithms are treated as unverifiable.
fn verify_signature(tbs: &[u8], oid: ObjectIdentifier, sig: &[u8], signer_spki_der: &[u8]) -> bool {
    if oid == SHA_256_WITH_RSA_ENCRYPTION
        || oid == SHA_384_WITH_RSA_ENCRYPTION
        || oid == SHA_512_WITH_RSA_ENCRYPTION
    {
        let (Ok(pubkey), Ok(signature)) = (
            RsaPublicKey::from_public_key_der(signer_spki_der),
            Signature::try_from(sig),
        ) else {
            return false;
        };
        if oid == SHA_256_WITH_RSA_ENCRYPTION {
            VerifyingKey::<Sha256>::new(pubkey).verify(tbs, &signature).is_ok()
        } else if oid == SHA_384_WITH_RSA_ENCRYPTION {
            VerifyingKey::<Sha384>::new(pubkey).verify(tbs, &signature).is_ok()
        } else {
            VerifyingKey::<Sha512>::new(pubkey).verify(tbs, &signature).is_ok()
        }
    } else if oid == ECDSA_WITH_SHA_256 {
        verify_ecdsa(signer_spki_der, &Sha256::digest(tbs), sig)
    } else if oid == ECDSA_WITH_SHA_384 {
        verify_ecdsa(signer_spki_der, &Sha384::digest(tbs), sig)
    } else if oid == ECDSA_WITH_SHA_512 {
        verify_ecdsa(signer_spki_der, &Sha512::digest(tbs), sig)
    } else if oid == ID_ED_25519 {
        verify_ed25519(signer_spki_der, tbs, sig)
    } else {
        false // unsupported (e.g. SHA-1)
    }
}

/// Verify an Ed25519 certificate signature.
pub(crate) fn verify_ed25519(spki_der: &[u8], tbs: &[u8], sig: &[u8]) -> bool {
    use signature::Verifier as _;
    use spki::DecodePublicKey as _;
    if let (Ok(vk), Ok(s)) = (
        ed25519_dalek::VerifyingKey::from_public_key_der(spki_der),
        ed25519::Signature::from_slice(sig),
    ) {
        return vk.verify(tbs, &s).is_ok();
    }
    false
}

/// Verify an ECDSA signature (DER `ECDSA-Sig-Value`) over an already computed
/// message digest, on P-256 or P-384 — whichever curve the SPKI names. The
/// digest is the one the algorithm identifier declares (not the curve's
/// "natural" hash), so P-256 with SHA-384/512 and P-384 with SHA-256 verify
/// per RFC 5480 §2.1.1.
pub(crate) fn verify_ecdsa(spki_der: &[u8], prehash: &[u8], sig: &[u8]) -> bool {
    if let Ok(vk) = p256::ecdsa::VerifyingKey::from_public_key_der(spki_der) {
        return p256::ecdsa::Signature::from_der(sig)
            .map(|s| vk.verify_prehash(prehash, &s).is_ok())
            .unwrap_or(false);
    }
    if let Ok(vk) = p384::ecdsa::VerifyingKey::from_public_key_der(spki_der) {
        return p384::ecdsa::Signature::from_der(sig)
            .map(|s| vk.verify_prehash(prehash, &s).is_ok())
            .unwrap_or(false);
    }
    false
}

fn valid_at(cert: &Certificate, at: i64) -> bool {
    let nb = time_secs(&cert.tbs_certificate.validity.not_before);
    let na = time_secs(&cert.tbs_certificate.validity.not_after);
    at >= nb && at <= na
}

/// An X.509 `Time` (UTCTime / GeneralizedTime) as seconds since the Unix epoch.
fn time_secs(t: &x509_cert::time::Time) -> i64 {
    t.to_unix_duration().as_secs() as i64
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
