//! Pure-Rust (RustCrypto) CMS signing and verification.
//!
//! Replaces the OpenSSL backend so the crate can be vendored for a CRAN build
//! with no system OpenSSL dependency. Produces / consumes detached CAdES CMS
//! (`ETSI.CAdES.detached`, PKCS#7 SignedData) over an external byte range, and
//! verifies RFC 3161 timestamp tokens.

use cms::builder::{SignedDataBuilder, SignerInfoBuilder};
use cms::cert::CertificateChoices;
use cms::cert::IssuerAndSerialNumber;
use cms::content_info::ContentInfo;
use cms::signed_data::{EncapsulatedContentInfo, SignedData, SignerInfo, SignerInfos, SignerIdentifier};

use const_oid::db::rfc5911::{
    ID_AA_SIGNING_CERTIFICATE, ID_AA_SIGNING_CERTIFICATE_V_2, ID_CONTENT_TYPE, ID_DATA,
    ID_MESSAGE_DIGEST,
};
use const_oid::db::rfc5912::{
    ECDSA_WITH_SHA_256, ECDSA_WITH_SHA_384, ECDSA_WITH_SHA_512, ID_EC_PUBLIC_KEY, ID_SHA_1,
    ID_SHA_256, ID_SHA_384, ID_SHA_512, RSA_ENCRYPTION, SECP_256_R_1, SECP_384_R_1,
    SHA_256_WITH_RSA_ENCRYPTION, SHA_384_WITH_RSA_ENCRYPTION, SHA_512_WITH_RSA_ENCRYPTION,
};
use const_oid::db::rfc8410::ID_ED_25519;
use const_oid::ObjectIdentifier;

use der::asn1::{BitString, OctetString, SetOfVec};
use der::{Any, DateTime, Decode, Encode, Reader, Sequence, SliceReader, Tag};

use rsa::pkcs8::{DecodePrivateKey, PrivateKeyInfo};
use sha2::{Sha384, Sha512};
use signature::{Keypair, Signer};
use spki::{DynSignatureAlgorithmIdentifier, SignatureBitStringEncoding};

use std::time::{Duration, SystemTime};
use x509_cert::attr::Attribute;

/// id-aa-timeStampToken (RFC 3161), not present in the const-oid database.
const ID_AA_TIME_STAMP_TOKEN: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.2.14");

/// id-ct-TSTInfo (RFC 3161) — the eContentType of a timestamp token.
const ID_CT_TST_INFO: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.1.4");

/// RFC 3161 `MessageImprint` — the hash algorithm and the hash of the stamped
/// data, as echoed back inside `TSTInfo`.
#[derive(Sequence)]
struct MessageImprint {
    hash_algorithm: AlgorithmIdentifierOwned,
    hashed_message: OctetString,
}

/// `ESSCertIDv2` with the SHA-256 default hash algorithm and `issuerSerial`
/// omitted (both optional), leaving just the certificate hash.
#[derive(Sequence)]
struct EssCertIdV2 {
    cert_hash: OctetString,
}

/// `SigningCertificateV2` (RFC 5035) — binds the signer certificate to the
/// signature, the key requirement that turns a basic CMS into CAdES/PAdES.
#[derive(Sequence)]
struct SigningCertificateV2 {
    certs: Vec<EssCertIdV2>,
}

use p12_keystore::KeyStore;

use rsa::pkcs1v15::{Signature, SigningKey, VerifyingKey};
use rsa::RsaPrivateKey;

use sha2::{Digest, Sha256};
use signature::Verifier;
use spki::{AlgorithmIdentifierOwned, DecodePublicKey};
use x509_cert::Certificate;

use crate::error::Error;
use crate::Result;

fn crypto<E: std::fmt::Display>(e: E) -> Error {
    Error::Crypto(e.to_string())
}

/// Outcome of a successful verification.
pub(crate) struct CmsVerification {
    /// Subject Distinguished Name of the signing certificate.
    pub signer_subject: String,
}

fn sha256_alg() -> AlgorithmIdentifierOwned {
    AlgorithmIdentifierOwned {
        oid: ID_SHA_256,
        parameters: None,
    }
}

fn sha384_alg() -> AlgorithmIdentifierOwned {
    AlgorithmIdentifierOwned {
        oid: ID_SHA_384,
        parameters: None,
    }
}

fn sha512_alg() -> AlgorithmIdentifierOwned {
    AlgorithmIdentifierOwned {
        oid: ID_SHA_512,
        parameters: None,
    }
}

/// Adapter so the CMS / X.509 builders (which require
/// `SignatureBitStringEncoding`) can drive an `ed25519-dalek` key.
pub(crate) struct Ed25519Signer(pub(crate) ed25519_dalek::SigningKey);

/// Newtype giving `ed25519::Signature` a `SignatureBitStringEncoding` impl.
pub(crate) struct Ed25519Sig(ed25519::Signature);

impl SignatureBitStringEncoding for Ed25519Sig {
    fn to_bitstring(&self) -> der::Result<BitString> {
        BitString::from_bytes(&self.0.to_bytes())
    }
}
impl Keypair for Ed25519Signer {
    type VerifyingKey = ed25519_dalek::VerifyingKey;
    fn verifying_key(&self) -> Self::VerifyingKey {
        self.0.verifying_key()
    }
}
impl Signer<Ed25519Sig> for Ed25519Signer {
    fn try_sign(&self, msg: &[u8]) -> std::result::Result<Ed25519Sig, signature::Error> {
        Ok(Ed25519Sig(self.0.try_sign(msg)?))
    }
}
impl DynSignatureAlgorithmIdentifier for Ed25519Signer {
    fn signature_algorithm_identifier(&self) -> spki::Result<AlgorithmIdentifierOwned> {
        Ok(AlgorithmIdentifierOwned {
            oid: ID_ED_25519,
            parameters: None,
        })
    }
}

/// Build the `signing-certificate-v2` (ESS) signed attribute over the DER of
/// the signer certificate.
fn signing_certificate_v2_attribute(cert_der: &[u8]) -> Result<Attribute> {
    let hash = Sha256::digest(cert_der);
    let scv2 = SigningCertificateV2 {
        certs: vec![EssCertIdV2 {
            cert_hash: OctetString::new(hash.to_vec()).map_err(crypto)?,
        }],
    };
    let mut values = SetOfVec::new();
    values
        .insert(Any::encode_from(&scv2).map_err(crypto)?)
        .map_err(crypto)?;
    Ok(Attribute {
        oid: ID_AA_SIGNING_CERTIFICATE_V_2,
        values,
    })
}

/// Produce a detached CMS signature over `data` using the PKCS#12 keystore.
///
/// The signature is CAdES/PAdES-B-B (carries a `signing-certificate-v2`
/// attribute). When `tsa_url` is `Some`, an RFC 3161 signature timestamp is
/// fetched and embedded, yielding PAdES-B-T.
pub(crate) fn cms_sign(
    keystore_p12: &[u8],
    password: &str,
    data: &[u8],
    tsa_url: Option<&str>,
) -> Result<Vec<u8>> {
    // 1. Load key + certificate from the keystore.
    let ks = KeyStore::from_pkcs12(keystore_p12, password).map_err(crypto)?;
    let (_, chain) = ks
        .private_key_chain()
        .ok_or_else(|| Error::Crypto("keystore has no private key chain".into()))?;
    let leaf = chain
        .chain()
        .first()
        .ok_or_else(|| Error::Crypto("keystore has no certificate".into()))?;
    let cert_der = leaf.as_der().to_vec();
    let cert = Certificate::from_der(&cert_der).map_err(crypto)?;

    let sid = SignerIdentifier::IssuerAndSerialNumber(IssuerAndSerialNumber {
        issuer: cert.tbs_certificate.issuer.clone(),
        serial_number: cert.tbs_certificate.serial_number.clone(),
    });
    // Embed the whole chain (so intermediates are available for path building).
    let cert_ders: Vec<Vec<u8>> = chain.chain().iter().map(|c| c.as_der().to_vec()).collect();
    let key_der = chain.key();

    // 2. Build the SignedData using the algorithm that matches the key type.
    let content_info = match detect_key_kind(key_der)? {
        KeyKind::Rsa => {
            let sk = SigningKey::<Sha256>::new(RsaPrivateKey::from_pkcs8_der(key_der).map_err(crypto)?);
            build_signed_data::<_, Signature>(
                &sk, sha256_alg(), Sha256::digest(data).as_slice(), sid, &cert_der, &cert_ders,
            )?
        }
        KeyKind::P256 => {
            let sk = p256::ecdsa::SigningKey::from(
                p256::SecretKey::from_pkcs8_der(key_der).map_err(crypto)?,
            );
            build_signed_data::<_, p256::ecdsa::DerSignature>(
                &sk, sha256_alg(), Sha256::digest(data).as_slice(), sid, &cert_der, &cert_ders,
            )?
        }
        KeyKind::P384 => {
            let sk = p384::ecdsa::SigningKey::from(
                p384::SecretKey::from_pkcs8_der(key_der).map_err(crypto)?,
            );
            build_signed_data::<_, p384::ecdsa::DerSignature>(
                &sk, sha384_alg(), Sha384::digest(data).as_slice(), sid, &cert_der, &cert_ders,
            )?
        }
        KeyKind::Ed25519 => {
            let sk = ed25519_dalek::SigningKey::from_pkcs8_der(key_der).map_err(crypto)?;
            // RFC 8419: Ed25519 in CMS uses SHA-512 for the message digest.
            build_signed_data::<_, Ed25519Sig>(
                &Ed25519Signer(sk),
                sha512_alg(),
                Sha512::digest(data).as_slice(),
                sid,
                &cert_der,
                &cert_ders,
            )?
        }
    };

    match tsa_url {
        Some(url) => apply_timestamp(content_info, url),
        None => content_info.to_der().map_err(crypto),
    }
}

/// Supported signer key types.
enum KeyKind {
    Rsa,
    P256,
    P384,
    Ed25519,
}

/// Determine the signing key type from its PKCS#8 algorithm identifier.
fn detect_key_kind(pkcs8_der: &[u8]) -> Result<KeyKind> {
    let pki = PrivateKeyInfo::from_der(pkcs8_der).map_err(crypto)?;
    let oid = pki.algorithm.oid;
    if oid == RSA_ENCRYPTION {
        Ok(KeyKind::Rsa)
    } else if oid == ID_ED_25519 {
        Ok(KeyKind::Ed25519)
    } else if oid == ID_EC_PUBLIC_KEY {
        let curve = pki.algorithm.parameters_oid().map_err(crypto)?;
        if curve == SECP_256_R_1 {
            Ok(KeyKind::P256)
        } else if curve == SECP_384_R_1 {
            Ok(KeyKind::P384)
        } else {
            Err(Error::Crypto(format!("unsupported EC curve: {curve}")))
        }
    } else {
        Err(Error::Crypto(format!("unsupported signing key algorithm: {oid}")))
    }
}

/// Assemble a detached `SignedData` (B-B: with `signing-certificate-v2`, and the
/// mandatory `content-type` + `message-digest` attributes added by the builder)
/// over a pre-computed `data_digest`, generic over the signer and signature types.
fn build_signed_data<S, Sig>(
    signing_key: &S,
    digest_alg: AlgorithmIdentifierOwned,
    data_digest: &[u8],
    sid: SignerIdentifier,
    ess_cert_der: &[u8],
    cert_ders: &[Vec<u8>],
) -> Result<ContentInfo>
where
    S: Keypair + DynSignatureAlgorithmIdentifier + Signer<Sig>,
    Sig: SignatureBitStringEncoding,
{
    let encap = EncapsulatedContentInfo {
        econtent_type: ID_DATA,
        econtent: None,
    };
    let mut signer_info =
        SignerInfoBuilder::new(signing_key, sid, digest_alg.clone(), &encap, Some(data_digest))
            .map_err(crypto)?;
    // PAdES baseline (ETSI EN 319 142-1, table 1) forbids the CMS `signing-time`
    // attribute: the claimed signing time lives in the signature dictionary's
    // `/M` entry instead (see `sign.rs`).
    signer_info
        .add_signed_attribute(signing_certificate_v2_attribute(ess_cert_der)?)
        .map_err(crypto)?;

    let mut builder = SignedDataBuilder::new(&encap);
    builder.add_digest_algorithm(digest_alg).map_err(crypto)?;
    for der in cert_ders {
        let c = Certificate::from_der(der).map_err(crypto)?;
        builder
            .add_certificate(CertificateChoices::Certificate(c))
            .map_err(crypto)?;
    }
    builder
        .add_signer_info::<S, Sig>(signer_info)
        .map_err(crypto)?
        .build()
        .map_err(crypto)
}

/// Fetch an RFC 3161 timestamp over the signature and embed it as the
/// `id-aa-timeStampToken` unsigned attribute (PAdES-B-T).
fn apply_timestamp(ci: ContentInfo, tsa_url: &str) -> Result<Vec<u8>> {
    let mut sd = ci.content.decode_as::<SignedData>().map_err(crypto)?;

    let mut signers: Vec<SignerInfo> = sd.signer_infos.0.iter().cloned().collect();
    let si = signers
        .get_mut(0)
        .ok_or_else(|| Error::Crypto("no SignerInfo to timestamp".into()))?;

    let token = crate::tsa::request_timestamp(tsa_url, si.signature.as_bytes())?;

    let mut ts_values = SetOfVec::new();
    ts_values
        .insert(Any::encode_from(&token).map_err(crypto)?)
        .map_err(crypto)?;
    let ts_attr = Attribute {
        oid: ID_AA_TIME_STAMP_TOKEN,
        values: ts_values,
    };

    let mut unsigned = si.unsigned_attrs.clone().unwrap_or_default();
    unsigned.insert(ts_attr).map_err(crypto)?;
    si.unsigned_attrs = Some(unsigned);

    sd.signer_infos = SignerInfos(SetOfVec::try_from(signers).map_err(crypto)?);

    let new_ci = ContentInfo {
        content_type: ci.content_type,
        content: Any::encode_from(&sd).map_err(crypto)?,
    };
    new_ci.to_der().map_err(crypto)
}

/// Extract the signer certificate (matched by SignerIdentifier) and the full
/// pool of certificates embedded in a signature CMS, for chain validation.
pub(crate) fn signer_certificate_and_pool(
    cms_der: &[u8],
) -> Result<(Certificate, Vec<Certificate>)> {
    let ci = ContentInfo::from_der(cms_der).map_err(crypto)?;
    let sd = ci.content.decode_as::<SignedData>().map_err(crypto)?;
    let si = sd
        .signer_infos
        .0
        .iter()
        .next()
        .ok_or_else(|| Error::Verification("no SignerInfo present".into()))?;
    let signer = find_signer_cert(&sd, si)?.clone();

    let mut pool = Vec::new();
    if let Some(set) = &sd.certificates {
        for choice in set.0.iter() {
            if let CertificateChoices::Certificate(c) = choice {
                pool.push(c.clone());
            }
        }
    }
    Ok((signer, pool))
}

/// A cryptographically verified RFC 3161 timestamp token: the asserted time,
/// what it stamped, and the TSA's own certificates so the caller can anchor the
/// TSA to a trust store (with the `id-kp-timeStamping` purpose) before relying
/// on `gen_time`.
pub(crate) struct VerifiedTimestamp {
    /// The TSA's asserted `genTime`.
    pub gen_time: SystemTime,
    /// The TSA's signing certificate.
    pub tsa_leaf: Certificate,
    /// Certificates embedded in the token (for building the TSA's chain).
    pub tsa_pool: Vec<Certificate>,
    /// `TSTInfo.messageImprint.hashAlgorithm`.
    pub imprint_alg: ObjectIdentifier,
    /// `TSTInfo.messageImprint.hashedMessage`.
    pub imprint: Vec<u8>,
    /// `TSTInfo.nonce`, when present (DER INTEGER content bytes).
    pub nonce: Option<Vec<u8>>,
}

/// Verify an RFC 3161 timestamp token (`token_der`, a CMS `ContentInfo`)
/// **internally**: the encapsulated content is a `TSTInfo`, and the TSA's CMS
/// signature over it (signed attributes, `content-type`, `message-digest`, ESS
/// certificate binding) is valid under the certificate embedded in the token.
/// Whether the TSA is *trusted* is the caller's decision (see
/// [`crate::trust::LeafPurpose::TimeStamping`]).
pub(crate) fn verify_timestamp_token(token_der: &[u8]) -> Result<VerifiedTimestamp> {
    let ci = ContentInfo::from_der(token_der).map_err(crypto)?;
    if ci.content_type != const_oid::db::rfc5911::ID_SIGNED_DATA {
        return Err(Error::Verification("timestamp token is not SignedData".into()));
    }
    let sd = ci.content.decode_as::<SignedData>().map_err(crypto)?;
    let tst_der = tst_info_der(&sd)?;
    let si = single_signer(&sd, "timestamp")?;
    let tsa_leaf = verify_signed_attrs(&sd, si, &tst_der)?.clone();
    let info = parse_tst_info(&tst_der)?;

    let mut tsa_pool = Vec::new();
    if let Some(set) = &sd.certificates {
        for choice in set.0.iter() {
            if let CertificateChoices::Certificate(c) = choice {
                tsa_pool.push(c.clone());
            }
        }
    }
    Ok(VerifiedTimestamp {
        gen_time: info.gen_time,
        tsa_leaf,
        tsa_pool,
        imprint_alg: info.imprint.hash_algorithm.oid,
        imprint: info.imprint.hashed_message.as_bytes().to_vec(),
        nonce: info.nonce,
    })
}

/// Verify a `/DocTimeStamp` token against `data` (the stamped document byte
/// range): the token verifies internally ([`verify_timestamp_token`]) and its
/// `messageImprint` equals `H(data)` under the imprint's own hash algorithm.
pub(crate) fn verify_doc_timestamp(token_der: &[u8], data: &[u8]) -> Result<VerifiedTimestamp> {
    let ts = verify_timestamp_token(token_der)?;
    let want = digest_data(ts.imprint_alg, data)?;
    if ts.imprint != want {
        return Err(Error::Verification(
            "timestamp imprint does not match the document".into(),
        ));
    }
    Ok(ts)
}

/// Verify the embedded RFC 3161 **signature-timestamp** of a document CMS.
///
/// This authenticates the time before it can be used as a validation anchor:
/// the token verifies internally and its `messageImprint` equals the hash of
/// the document signer's signature value (RFC 3161 / CAdES signature-timestamp
/// semantics). It returns the `genTime` together with the TSA's certificates so
/// the caller can require the TSA to chain to a trusted root **as a TSA** —
/// without that anchor a forged token could assert any time. The
/// unauthenticated `signingTime` attribute / `/M` entry is deliberately **not**
/// consulted; it is display-only.
pub(crate) fn verify_embedded_timestamp(cms_der: &[u8]) -> Result<VerifiedTimestamp> {
    let ci = ContentInfo::from_der(cms_der).map_err(crypto)?;
    let sd = ci.content.decode_as::<SignedData>().map_err(crypto)?;
    let si = single_signer(&sd, "signature")?;
    let signature_value = si.signature.as_bytes();

    // Locate the id-aa-timeStampToken unsigned attribute.
    let token_der = si
        .unsigned_attrs
        .as_ref()
        .and_then(|attrs| attrs.iter().find(|a| a.oid == ID_AA_TIME_STAMP_TOKEN))
        .and_then(|a| a.values.iter().next())
        .ok_or_else(|| Error::Verification("no signature timestamp present".into()))?
        .to_der()
        .map_err(crypto)?;

    let ts = verify_timestamp_token(&token_der)?;
    // The timestamp must imprint the document signer's signature value.
    let want = digest_data(ts.imprint_alg, signature_value)?;
    if ts.imprint != want {
        return Err(Error::Verification(
            "signature timestamp does not bind to the signature".into(),
        ));
    }
    Ok(ts)
}

/// Extract the DER of the encapsulated `TSTInfo` from a timestamp token's
/// `SignedData`, validating that the eContentType is `id-ct-TSTInfo`.
fn tst_info_der(sd: &SignedData) -> Result<Vec<u8>> {
    let eci = &sd.encap_content_info;
    if eci.econtent_type != ID_CT_TST_INFO {
        return Err(Error::Verification(
            "timestamp token does not encapsulate a TSTInfo".into(),
        ));
    }
    let econtent = eci
        .econtent
        .as_ref()
        .ok_or_else(|| Error::Verification("timestamp token has no eContent".into()))?;
    let octets = econtent.decode_as::<OctetString>().map_err(crypto)?;
    Ok(octets.as_bytes().to_vec())
}

/// The fields of an RFC 3161 `TSTInfo` that we consume.
struct TstInfo {
    imprint: MessageImprint,
    gen_time: SystemTime,
    nonce: Option<Vec<u8>>,
}

/// Parse a DER-encoded `TSTInfo`: the leading fields up to `genTime`, then the
/// optional trailing fields (`accuracy`, `ordering`, `nonce`, `tsa`,
/// `extensions`) by tag, keeping only `nonce`.
///
/// `genTime` is decoded by hand because RFC 3161 §2.4.2 allows fractional
/// seconds (`YYYYMMDDhhmmss[.fff]Z`), which the strict X.509 `GeneralizedTime`
/// decoder in `der` rejects — and many production TSAs emit them.
fn parse_tst_info(tst_der: &[u8]) -> Result<TstInfo> {
    let mut reader = SliceReader::new(tst_der).map_err(crypto)?;
    reader
        .sequence(|r| {
            let _version: u8 = r.decode()?; // INTEGER v1
            let _policy: ObjectIdentifier = r.decode()?; // TSAPolicyId
            let imprint: MessageImprint = r.decode()?;
            r.tlv_bytes()?; // serialNumber (INTEGER), unused
            let gen_time = parse_generalized_time(r.tlv_bytes()?)?;
            let mut nonce = None;
            while !r.is_finished() {
                let tlv = r.tlv_bytes()?;
                // nonce is a top-level INTEGER (tag 0x02); accuracy is a SEQUENCE,
                // ordering a BOOLEAN, tsa [0] and extensions [1] context-specific.
                if tlv.first() == Some(&0x02) {
                    let int: der::asn1::Int = der::asn1::Int::from_der(tlv)?;
                    nonce = Some(int.as_bytes().to_vec());
                }
            }
            Ok(TstInfo {
                imprint,
                gen_time,
                nonce,
            })
        })
        .map_err(crypto)
}

/// Decode a DER `GeneralizedTime` TLV (`YYYYMMDDhhmmss[.f…]Z`) to a
/// `SystemTime`, truncating any fractional seconds.
fn parse_generalized_time(tlv: &[u8]) -> der::Result<SystemTime> {
    let mut r = SliceReader::new(tlv)?;
    let header = der::Header::decode(&mut r)?;
    if header.tag != Tag::GeneralizedTime {
        return Err(der::Error::new(
            der::ErrorKind::TagUnexpected {
                expected: Some(Tag::GeneralizedTime),
                actual: header.tag,
            },
            r.position(),
        ));
    }
    let body = r.read_slice(header.length)?;
    let invalid = || der::Error::new(der::ErrorKind::DateTime, r.position());
    if body.len() < 15 || *body.last().unwrap() != b'Z' {
        return Err(invalid());
    }
    let digits = &body[..14];
    if !digits.iter().all(u8::is_ascii_digit) {
        return Err(invalid());
    }
    // Anything between the seconds and the trailing 'Z' must be ".digits".
    let frac = &body[14..body.len() - 1];
    if !frac.is_empty() && (frac[0] != b'.' || frac.len() < 2 || !frac[1..].iter().all(u8::is_ascii_digit)) {
        return Err(invalid());
    }
    let num = |from: usize, len: usize| -> u16 {
        std::str::from_utf8(&digits[from..from + len])
            .ok()
            .and_then(|t| t.parse().ok())
            .unwrap_or(u16::MAX)
    };
    let dt = DateTime::new(
        num(0, 4),
        num(4, 2) as u8,
        num(6, 2) as u8,
        num(8, 2) as u8,
        num(10, 2) as u8,
        num(12, 2) as u8,
    )?;
    Ok(SystemTime::UNIX_EPOCH + Duration::from_secs(dt.unix_duration().as_secs()))
}

/// Verify a detached CMS `der` (a ContentInfo) against `data`.
///
/// Checks the CMS structure (SignedData, exactly one SignerInfo), that the
/// `content-type` and `message-digest` signed attributes are present and
/// correct (`message-digest == H(data)`), that the ESS signing-certificate
/// attribute (when present) binds the signer certificate, and that the signer's
/// signature over the signed attributes is valid under the declared algorithm.
/// Does **not** validate the certificate chain / trust (see `trust.rs`).
pub(crate) fn cms_verify(der: &[u8], data: &[u8]) -> Result<CmsVerification> {
    let ci = ContentInfo::from_der(der).map_err(crypto)?;
    if ci.content_type != const_oid::db::rfc5911::ID_SIGNED_DATA {
        return Err(Error::Verification("CMS is not SignedData".into()));
    }
    let sd = ci.content.decode_as::<SignedData>().map_err(crypto)?;
    if sd.encap_content_info.econtent_type != ID_DATA {
        return Err(Error::Verification(
            "document signature eContentType is not id-data".into(),
        ));
    }
    if sd.encap_content_info.econtent.is_some() {
        return Err(Error::Verification(
            "document signature must be detached (no eContent)".into(),
        ));
    }
    let si = single_signer(&sd, "signature")?;
    let cert = verify_signed_attrs(&sd, si, data)?;
    Ok(CmsVerification {
        signer_subject: cert.tbs_certificate.subject.to_string(),
    })
}

/// The one `SignerInfo` of a PAdES/timestamp `SignedData`. ETSI EN 319 142-1
/// permits exactly one signer per signature; more than one is rejected rather
/// than silently verifying only the first.
fn single_signer<'a>(sd: &'a SignedData, what: &str) -> Result<&'a SignerInfo> {
    let mut iter = sd.signer_infos.0.iter();
    let si = iter
        .next()
        .ok_or_else(|| Error::Verification(format!("{what} has no SignerInfo")))?;
    if iter.next().is_some() {
        return Err(Error::Verification(format!(
            "{what} carries more than one SignerInfo"
        )));
    }
    Ok(si)
}

/// The single value of the attribute `oid` among `attrs`: `Ok(None)` when
/// absent, `Err` when the attribute appears more than once or carries a number
/// of values other than one (RFC 5652 §11: `content-type` and `message-digest`
/// are single-valued and must not be repeated).
fn single_attr_value<'a>(
    attrs: &'a x509_cert::attr::Attributes,
    oid: ObjectIdentifier,
    name: &str,
) -> Result<Option<&'a Any>> {
    let mut found: Option<&Attribute> = None;
    for attr in attrs.iter().filter(|a| a.oid == oid) {
        if found.is_some() {
            return Err(Error::Verification(format!("duplicate {name} attribute")));
        }
        found = Some(attr);
    }
    let Some(attr) = found else {
        return Ok(None);
    };
    if attr.values.len() != 1 {
        return Err(Error::Verification(format!(
            "{name} attribute must carry exactly one value"
        )));
    }
    Ok(attr.values.iter().next())
}

/// Verify a `SignerInfo`'s signature over its signed attributes and that its
/// `messageDigest` attribute equals `H(content)`, returning the signer
/// certificate. `content` is whatever the signature commits to: the external
/// byte range for a detached document signature, or the encapsulated `TSTInfo`
/// for a timestamp token. Does **not** validate the certificate chain / trust.
fn verify_signed_attrs<'a>(
    sd: &'a SignedData,
    si: &SignerInfo,
    content: &[u8],
) -> Result<&'a Certificate> {
    let signed_attrs = si
        .signed_attrs
        .as_ref()
        .ok_or_else(|| Error::Verification("signer has no signed attributes".into()))?;

    // 1. content-type (RFC 5652 §11.1): mandatory when signed attributes are
    //    present, and it must name the encapsulated content type.
    let ct = single_attr_value(signed_attrs, ID_CONTENT_TYPE, "content-type")?
        .ok_or_else(|| Error::Verification("no content-type attribute".into()))?;
    let ct: ObjectIdentifier = ct.decode_as().map_err(crypto)?;
    if ct != sd.encap_content_info.econtent_type {
        return Err(Error::Verification(
            "content-type attribute does not match the encapsulated content type".into(),
        ));
    }

    // 2. message-digest (RFC 5652 §11.2) must equal H(content) under the
    //    SignerInfo's digest algorithm.
    let want = digest_data(si.digest_alg.oid, content)?;
    let md = single_attr_value(signed_attrs, ID_MESSAGE_DIGEST, "message-digest")?
        .ok_or_else(|| Error::Verification("no messageDigest attribute".into()))?;
    let octets = md.decode_as::<OctetString>().map_err(crypto)?;
    if octets.as_bytes() != want.as_slice() {
        return Err(Error::Verification("messageDigest mismatch".into()));
    }

    // 3. Locate the signer certificate by issuer + serial.
    let cert = find_signer_cert(sd, si)?;
    let cert_der = cert.to_der().map_err(crypto)?;

    // 4. ESS signing-certificate(-v2) (RFC 5035 / CAdES): when present, its
    //    first certHash must be the hash of the signer certificate, otherwise a
    //    certificate with the same issuer+serial could be substituted.
    check_ess_binding(signed_attrs, &cert_der)?;

    // 5. Verify the signature over the DER of the signed attributes, using the
    //    algorithm of the certificate's public key, and require the declared
    //    signatureAlgorithm to be consistent with it.
    let spki = &cert.tbs_certificate.subject_public_key_info;
    let spki_der = spki.to_der().map_err(crypto)?;
    let signed_attrs_der = signed_attrs.to_der().map_err(crypto)?;
    let sig_bytes = si.signature.as_bytes();
    let sig_alg = si.signature_algorithm.oid;
    let digest_oid = si.digest_alg.oid;

    let ok = if spki.algorithm.oid == RSA_ENCRYPTION {
        let consistent = sig_alg == RSA_ENCRYPTION
            || (sig_alg == SHA_256_WITH_RSA_ENCRYPTION && digest_oid == ID_SHA_256)
            || (sig_alg == SHA_384_WITH_RSA_ENCRYPTION && digest_oid == ID_SHA_384)
            || (sig_alg == SHA_512_WITH_RSA_ENCRYPTION && digest_oid == ID_SHA_512);
        if !consistent {
            return Err(Error::Verification(format!(
                "unsupported or inconsistent RSA signature algorithm {sig_alg} (RSASSA-PSS is not supported)"
            )));
        }
        rsa_verify(&spki_der, &signed_attrs_der, sig_bytes, digest_oid)
    } else if spki.algorithm.oid == ID_EC_PUBLIC_KEY {
        let consistent = (sig_alg == ECDSA_WITH_SHA_256 && digest_oid == ID_SHA_256)
            || (sig_alg == ECDSA_WITH_SHA_384 && digest_oid == ID_SHA_384)
            || (sig_alg == ECDSA_WITH_SHA_512 && digest_oid == ID_SHA_512);
        if !consistent {
            return Err(Error::Verification(format!(
                "unsupported or inconsistent ECDSA signature algorithm {sig_alg}"
            )));
        }
        crate::trust::verify_ecdsa(&spki_der, &want_digest(digest_oid, &signed_attrs_der)?, sig_bytes)
    } else if spki.algorithm.oid == ID_ED_25519 {
        // RFC 8419 §2.3: Ed25519 in CMS uses SHA-512 as the message digest.
        if sig_alg != ID_ED_25519 || digest_oid != ID_SHA_512 {
            return Err(Error::Verification(
                "Ed25519 CMS signatures must use id-Ed25519 with SHA-512 (RFC 8419)".into(),
            ));
        }
        crate::trust::verify_ed25519(&spki_der, &signed_attrs_der, sig_bytes)
    } else {
        return Err(Error::Verification("unsupported signer key algorithm".into()));
    };
    if !ok {
        return Err(Error::Verification("signature invalid".into()));
    }
    Ok(cert)
}

/// `ESSCertIDv2` as parsed for verification: `hashAlgorithm` (DEFAULT SHA-256)
/// and `certHash`; `issuerSerial` is skipped.
struct EssCertId {
    hash_alg: ObjectIdentifier,
    cert_hash: Vec<u8>,
}

/// Parse the first `ESSCertID(v2)` of a `SigningCertificate(V2)` attribute
/// value: `SEQUENCE { certs SEQUENCE OF ESSCertID(v2), policies OPTIONAL }`.
fn first_ess_cert_id(value: &Any, v2: bool) -> Result<EssCertId> {
    let mut reader = SliceReader::new(value.value()).map_err(crypto)?;
    reader
        .sequence(|certs| {
            // The first ESSCertID(v2) SEQUENCE.
            certs.sequence(|c| {
                let mut hash_alg = if v2 { ID_SHA_256 } else { ID_SHA_1 };
                if v2 && c.peek_tag()? == Tag::Sequence {
                    let alg: AlgorithmIdentifierOwned = c.decode()?;
                    hash_alg = alg.oid;
                }
                let hash: OctetString = c.decode()?;
                // issuerSerial (OPTIONAL), ignored.
                while !c.is_finished() {
                    c.tlv_bytes()?;
                }
                Ok(EssCertId {
                    hash_alg,
                    cert_hash: hash.as_bytes().to_vec(),
                })
            })
        })
        .map_err(crypto)
}

/// If a `signing-certificate-v2` (or legacy `signing-certificate`) attribute is
/// present, its first certificate hash must match `cert_der`.
fn check_ess_binding(attrs: &x509_cert::attr::Attributes, cert_der: &[u8]) -> Result<()> {
    if let Some(v) = single_attr_value(attrs, ID_AA_SIGNING_CERTIFICATE_V_2, "signing-certificate-v2")? {
        let id = first_ess_cert_id(v, true)?;
        let want = digest_data(id.hash_alg, cert_der)
            .map_err(|_| Error::Verification("unsupported ESSCertIDv2 hash algorithm".into()))?;
        if id.cert_hash != want {
            return Err(Error::Verification(
                "signing-certificate-v2 does not match the signer certificate".into(),
            ));
        }
    }
    if let Some(v) = single_attr_value(attrs, ID_AA_SIGNING_CERTIFICATE, "signing-certificate")? {
        let id = first_ess_cert_id(v, false)?;
        if id.cert_hash != sha1::Sha1::digest(cert_der).as_slice() {
            return Err(Error::Verification(
                "signing-certificate does not match the signer certificate".into(),
            ));
        }
    }
    Ok(())
}

/// Verify an RSA PKCS#1 v1.5 signature over `msg`, choosing the hash from the
/// SignerInfo's digest algorithm (SHA-256/384/512).
fn rsa_verify(spki_der: &[u8], msg: &[u8], sig: &[u8], digest_oid: ObjectIdentifier) -> bool {
    let (Ok(pub_key), Ok(s)) = (
        rsa::RsaPublicKey::from_public_key_der(spki_der),
        Signature::try_from(sig),
    ) else {
        return false;
    };
    if digest_oid == ID_SHA_256 {
        VerifyingKey::<Sha256>::new(pub_key).verify(msg, &s).is_ok()
    } else if digest_oid == ID_SHA_384 {
        VerifyingKey::<Sha384>::new(pub_key).verify(msg, &s).is_ok()
    } else if digest_oid == ID_SHA_512 {
        VerifyingKey::<Sha512>::new(pub_key).verify(msg, &s).is_ok()
    } else {
        false
    }
}

/// Hash `data` with the digest named by `oid` (SHA-256/384/512).
fn digest_data(oid: ObjectIdentifier, data: &[u8]) -> Result<Vec<u8>> {
    if oid == ID_SHA_256 {
        Ok(Sha256::digest(data).to_vec())
    } else if oid == ID_SHA_384 {
        Ok(Sha384::digest(data).to_vec())
    } else if oid == ID_SHA_512 {
        Ok(Sha512::digest(data).to_vec())
    } else {
        Err(Error::Verification("unsupported digest algorithm".into()))
    }
}

/// Alias of [`digest_data`] used where the digest is the ECDSA prehash.
fn want_digest(oid: ObjectIdentifier, data: &[u8]) -> Result<Vec<u8>> {
    digest_data(oid, data)
}

fn find_signer_cert<'a>(
    sd: &'a SignedData,
    si: &cms::signed_data::SignerInfo,
) -> Result<&'a Certificate> {
    let ias = match &si.sid {
        SignerIdentifier::IssuerAndSerialNumber(ias) => ias,
        SignerIdentifier::SubjectKeyIdentifier(_) => {
            return Err(Error::Verification(
                "SubjectKeyIdentifier signer id not supported".into(),
            ))
        }
    };
    let certs = sd
        .certificates
        .as_ref()
        .ok_or_else(|| Error::Verification("no certificates embedded".into()))?;

    let want_issuer = ias.issuer.to_der().map_err(crypto)?;
    let want_serial = ias.serial_number.to_der().map_err(crypto)?;

    for choice in certs.0.iter() {
        if let CertificateChoices::Certificate(cert) = choice {
            let issuer = cert.tbs_certificate.issuer.to_der().map_err(crypto)?;
            let serial = cert.tbs_certificate.serial_number.to_der().map_err(crypto)?;
            if issuer == want_issuer && serial == want_serial {
                return Ok(cert);
            }
        }
    }
    Err(Error::Verification(
        "signer certificate not found in CMS".into(),
    ))
}

#[cfg(test)]
mod tests {
    use super::{cms_sign, verify_doc_timestamp};
    use crate::testkit::self_signed_p12;
    use sha2::{Digest, Sha256};

    #[test]
    fn doc_timestamp_rejects_a_non_tstinfo_cms() {
        // A detached CMS signature over `data` embeds SHA-256(data) as its
        // messageDigest attribute. The old window-search verifier found those
        // bytes and wrongly accepted it as a document timestamp. It is not an
        // RFC 3161 TSTInfo, so the hardened verifier must reject it (issue #4).
        let data = b"the document byte range";
        let p12 = self_signed_p12("pw");
        let cms = cms_sign(&p12, "pw", data, None).expect("sign");

        // Sanity: the imprint really is present in the DER (what fooled the old
        // check), yet verification now fails for lack of a real TSTInfo.
        let imprint = Sha256::digest(data);
        assert!(cms.windows(imprint.len()).any(|w| w == imprint.as_slice()));
        assert!(verify_doc_timestamp(&cms, data).is_err());
    }

    #[test]
    fn doc_timestamp_rejects_garbage() {
        assert!(verify_doc_timestamp(b"not der at all", b"data").is_err());
    }

    #[test]
    fn embedded_timestamp_required_for_trusted_time() {
        // A B-B signature carries no RFC 3161 signature-timestamp, so there is
        // no authenticated time anchor: the chain must be judged at "now", never
        // at the signer-asserted signingTime (issue #6 / security review). The
        // verifier surfaces this as an error so the caller falls back to now().
        use super::verify_embedded_timestamp;

        let p12 = self_signed_p12("pw");
        let cms = cms_sign(&p12, "pw", b"the byte range", None).expect("sign");
        assert!(
            verify_embedded_timestamp(&cms).is_err(),
            "no embedded timestamp must not yield a trusted time"
        );
    }
}
