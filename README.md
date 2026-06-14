# pdf_signer

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
[![Rust](https://img.shields.io/badge/rust-1.74%2B-orange.svg)](https://www.rust-lang.org)
[![PAdES](https://img.shields.io/badge/PAdES-B--B%20%E2%86%92%20B--LTA-success.svg)](#pades-levels)
![pure Rust](https://img.shields.io/badge/crypto-pure%20RustCrypto-success.svg)

A self-contained Rust library + CLI to **digitally sign** PDF documents with a
PKCS#12 keystore and **verify** their signatures — implementing the **PAdES**
baseline profiles (ETSI EN 319 142) from **B-B all the way to B-LTA**.

The cryptography is **100 % pure Rust** ([RustCrypto](https://github.com/RustCrypto)) —
no OpenSSL, no Java, no system C libraries — so the crate vendors cleanly (it
powers the [`signer`](https://github.com/StrategicProjects/signer) R package on
CRAN). TLS is the only optional, opt-in exception (for HTTPS timestamp/CRL
endpoints).

Every signature this produces is cross-validated by **Poppler's `pdfsig`** and
opens as valid in Adobe Reader.

```console
$ cargo run --example gen_assets        # writes sample.pdf + keystore.p12
$ cargo run -- sign sample.pdf signed.pdf keystore.p12 password "Approved"
$ cargo run -- verify signed.pdf
signature #1:
  valid:                 true
  signer:                CN=pdf_signer PoC,O=StrategicProjects,C=BR
  detail:                valid CMS signature; signer: ...
$ pdfsig signed.pdf
  - Signature Type: ETSI.CAdES.detached
  - Signature Validation: Signature is Valid.
  - Total document signed
```

## Features

- **PAdES B-B → B-LTA** detached CMS signatures (`ETSI.CAdES.detached`).
- **Visible or invisible** signatures — a bordered text box (the signing
  statement + validation link) at any position on any page, with word wrap.
- **True incremental updates** — the original bytes are never rewritten, so
  **multiple signatures** compose and earlier ones stay valid.
- **RFC 3161 timestamps** — signature timestamps (B-T) and document timestamps
  (B-LTA), from any TSA.
- **Long-term validation material** — a `/DSS` with the full certificate chain
  and CRLs fetched from the certificates' distribution points (B-LT).
- **Verification** — re-derives the signed byte range, checks the message
  digest and the signer's signature, and reports each signature *and* document
  timestamp.
- **Certificate-chain validation** against a trust store (e.g. the **ICP-Brasil**
  roots): per-link signature (RSA **and** ECDSA P-256/P-384), validity,
  `basicConstraints` / `pathLenConstraint` / `keyCertSign`, and CRL revocation.
- **Pure Rust**, with an optional `https` feature (rustls) for TLS endpoints.

### PAdES levels

| Level      | What it adds                                       | `pades_level` | Needs a TSA |
|------------|----------------------------------------------------|---------------|-------------|
| **B-B**    | `signing-certificate-v2` (CAdES baseline)          | `Bb`          | no          |
| **B-T**    | + RFC 3161 **signature timestamp**                 | `Bt`          | yes         |
| **B-LT**   | + `/DSS` (certificate chain + CRLs)                | `Blt`         | yes         |
| **B-LTA**  | + `/DocTimeStamp` over the whole file              | `Blta`        | yes         |

## Library usage

```rust
use pdf_signer::{sign_pdf_file, verify_pdf_file_with_roots, Appearance, PadesLevel, SignOptions, TrustStore};

// Sign at PAdES-B-LTA with a visible appearance and a timestamp.
sign_pdf_file("in.pdf", "out.pdf", "keystore.p12", "password", &SignOptions {
    reason: Some("Approved".into()),
    pades_level: PadesLevel::Blta,
    tsa_url: Some("http://timestamp.digicert.com".into()),
    appearance: Some(Appearance {
        page: 1, x: 36.0, y: 36.0, width: 320.0, height: 64.0,
        font_size: 8.0, border: true,
        text: "Digitally signed.\nValidate at: example.org/validate".into(),
    }),
    ..Default::default()
})?;

// Verify and validate the signer chain against trusted roots.
let roots = TrustStore::from_pem(&std::fs::read("icp-brasil-roots.pem")?)?;
let report = verify_pdf_file_with_roots("out.pdf", &roots)?;
for s in &report.signatures {
    println!("valid={} trusted={:?} — {}", s.valid, s.chain_trusted, s.detail);
}
```

The `https` feature enables TLS TSA/CRL endpoints:

```toml
pdf_signer = { version = "0.1", features = ["https"] }
```

## How it works

1. **PDF structure** (`lopdf`) — add an AcroForm signature field and a `/Sig`
   dictionary with `/SubFilter /ETSI.CAdES.detached`, a `/ByteRange` placeholder
   and a zero-filled `/Contents` placeholder.
2. **Incremental update** (`incremental.rs`) — keep the original bytes verbatim;
   append the new objects, a fresh xref table and a `/Prev`-chained trailer.
   Byte surgery (within the appended region) computes the real `/ByteRange` and
   patches it length-preservingly.
3. **CMS** (`cms` + `rsa` + `sha2`) — build a detached SignedData with the
   `contentType`, `messageDigest`, `signingTime` and `signing-certificate-v2`
   signed attributes; optionally fetch and embed an RFC 3161 timestamp.
4. **DSS / DocTimeStamp** (`dss.rs`) — collect the chain + CRLs into a `/DSS`,
   then append a document timestamp over the whole file.
5. **Verify** (`verify.rs` + `trust.rs`) — validate the CMS and, optionally, the
   certificate path against a trust store.

## Scope & limitations

- **Revocation** uses **CRLs only** (no OCSP yet).
- **Path validation** covers the practical RFC 5280 subset (signatures,
  validity, basic constraints, path length, key usage, CRL revocation) — **not**
  name constraints or certificate policies.
- **Signing keys are RSA** (PKCS#1 v1.5 + SHA-256); ECDSA is supported on the
  **verification** side (chain), not yet for the signer key.
- Incremental updates use a **traditional xref table** (chained via `/Prev`),
  accepted by PDF 1.5+ readers; no xref-*stream* output.
- Visible appearances use **standard Helvetica** (WinAnsi); no embedded
  fonts/images, approximate line wrapping.

## Roadmap

- [x] Pure-Rust CMS signing & verification (no OpenSSL/Java)
- [x] Visible appearance, incremental updates, multi-signature
- [x] PAdES B-B / B-T / B-LT / B-LTA (DSS + document timestamp)
- [x] Certificate-chain validation (RSA + ECDSA, CRL revocation, RFC 5280 subset)
- [x] Optional HTTPS (rustls) for TSA / CRL
- [x] [extendr](https://extendr.github.io/) bindings + vendoring for R / CRAN
- [ ] OCSP revocation; ECDSA *signing* keys
- [ ] Full RFC 5280 path processing (name constraints, policies)
- [ ] xref-stream incremental updates; richer appearances (fonts/images)

## License

GPL-3.0-or-later.
