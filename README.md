# pdf_signer

Minimal, self-contained Rust library + CLI to **digitally sign** PDF documents
with a PKCS#12 keystore and **verify** their signatures.

This is a **proof of concept** built to replace the bundled
`BatchPDFSignPortable.jar` (Java / Apache PDFBox, ~13 MB) used by the R package
[`signer`](https://github.com/StrategicProjects/signer). The goal is to drop the
Java runtime dependency and the binary blob, enabling a clean, CRAN-friendly
native backend.

The crypto stack is **100% pure Rust (RustCrypto)** — no OpenSSL, `ring`, or any
system C library — so the crate can be fully vendored for a CRAN build.

Signatures are **PAdES** up to **B-LTA** via `SignOptions::pades_level`:
**B-B** (CAdES `signing-certificate-v2`), **B-T** (RFC 3161 signature
timestamp), **B-LT** (a `/DSS` with the certificate chain + fetched CRLs), and
**B-LTA** (a `/DocTimeStamp` over the whole file). The timestamp / CRL fetching
uses a tiny dependency-free HTTP client (`http://` endpoints only).

## Status: the PoC works end to end

A signed PDF produced here is validated **independently by Poppler's `pdfsig`**:

```
$ cargo run --example gen_assets
$ cargo run --bin pdf_signer -- sign sample.pdf signed.pdf keystore.p12 password "Reason"
$ cargo run --bin pdf_signer -- verify signed.pdf      # our own verifier
$ pdfsig signed.pdf                                     # third-party cross-check
  - Signature Type: adbe.pkcs7.detached
  - Signing Hash Algorithm: SHA-256
  - Total document signed
  - Signature Validation: Signature is Valid.
```

Signatures can be **invisible** or carry a **visible appearance** — a bordered
box with wrapped text (the `signtext` + validation link), placed at any
position on any page:

```rust
use pdf_signer::{sign_pdf_file, Appearance, SignOptions};

sign_pdf_file("in.pdf", "out.pdf", "keystore.p12", "password", &SignOptions {
    reason: Some("Aprovado".into()),
    appearance: Some(Appearance {
        page: 1,
        x: 36.0, y: 36.0, width: 320.0, height: 64.0,
        font_size: 8.0,
        text: "Assinado por Fulano.\nValidar em: exemplo.org/validar".into(),
        border: true,
    }),
    ..Default::default()
})?;
```

Signing uses a true **incremental update**: the original bytes are kept
verbatim and the new objects + xref are appended. This means **multiple
signatures** are supported — signing again does not invalidate earlier
signatures, which keep covering their original (unchanged) byte range:

```text
$ pdf_signer sign  in.pdf   s1.pdf keystore.p12 pw "First"
$ pdf_signer sign  s1.pdf   s2.pdf keystore.p12 pw "Second"   # appends only
$ pdfsig s2.pdf
  Signature #1: Signature is Valid.
  Signature #2: Total document signed — Signature is Valid.
```

`cargo test` covers the round trip, tamper detection, the visible appearance,
incremental-update byte preservation, multi-signature, and the unsigned case.

## How it works

1. **PDF structure** (`lopdf`): add an AcroForm signature field + a `/Sig`
   dictionary with `/SubFilter /adbe.pkcs7.detached`, a `/ByteRange` placeholder
   and a zero-filled `/Contents` hex placeholder.
2. **Incremental update** (`incremental.rs`): the original file is left byte-for-byte
   intact; the signature objects, a fresh xref table and a `/Prev`-chained
   trailer are appended. Then byte surgery locates the placeholder (within the
   appended region), computes the real `/ByteRange` and patches it length-preservingly.
3. **CMS signature** (`cms` + `rsa` + `sha2`, RustCrypto): load the PKCS#12
   (`p12-keystore`), build a detached CMS SignedData with `messageDigest`,
   `contentType` and `signingTime` signed attributes, RSA-sign it, and
   hex-encode the DER into `/Contents`.
4. **Verify**: re-derive the signed byte range, slice the CMS DER out of the
   placeholder, check the `messageDigest` attribute against `SHA-256(data)` and
   verify the signer's RSA signature over the signed attributes.

## API

```rust
use pdf_signer::{sign_pdf_file, verify_pdf_file, SignOptions};

sign_pdf_file("in.pdf", "out.pdf", "keystore.p12", "password", &SignOptions {
    reason: Some("Signed by Org".into()),
    ..Default::default()
})?;

let report = verify_pdf_file("out.pdf")?;
assert!(report.all_valid());
```

## Known limitations (PoC scope — see roadmap)

- **Invisible signature only** — no visual appearance stream yet (the `signtext`
  / rectangle / validation-link box from the R package is not rendered).
- **Basic appearance.** Visible signatures use the standard Helvetica font with
  approximate (character-count) line wrapping and WinAnsi encoding, so glyphs
  outside Latin-1 become `?`. No logo/image support yet.
- **RSA keys only.** The signer assumes RSA (PKCS#1 v1.5 + SHA-256). ECDSA /
  Ed25519 keystores are not handled yet.
- **Incremental update uses a traditional xref table.** It chains via `/Prev`
  to the previous section (table or stream), which 1.5+ readers accept; an
  xref-*stream* output is not produced. Existing referenced `/AcroForm` /
  `/Annots` / `/Fields` objects are handled, but exotic shared structures may
  need more care.
- **No PAdES-LTV / timestamps (RFC 3161)** and no certificate chain / revocation
  checking on verify; the signer DN is reported but trust is not enforced.
- Single signature parsed on verify; AcroForm is overwritten rather than merged.

## Roadmap to replace the JAR in `signer`

1. ~~Swap OpenSSL → RustCrypto~~ ✅ done — pure-Rust `cms`/`rsa`/`p12-keystore`.
2. ~~Visual appearance stream (`signtext` box + validation link)~~ ✅ done.
3. ~~Incremental-update save for multi-signature / re-signing~~ ✅ done.
4. ~~Vendor + expose to R via extendr~~ ✅ done (in the `signer` R package).
5. ~~PAdES-B-B / B-T / B-LT / B-LTA~~ ✅ done (DSS with certs + CRLs, document
   timestamp; the verifier reports doc timestamps).
6. Remaining: OCSP (in addition to CRLs), full TSA-signature + chain validation
   against the ICP-Brasil roots on verify, and HTTPS TSA/CRL support.

## License

GPL-3.0-or-later, matching the `signer` package.
