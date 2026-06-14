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

`cargo test` covers the round trip, tamper detection, and the unsigned case.

## How it works

1. **PDF structure** (`lopdf`): add an AcroForm signature field + a `/Sig`
   dictionary with `/SubFilter /adbe.pkcs7.detached`, a `/ByteRange` placeholder
   and a zero-filled `/Contents` hex placeholder.
2. **Byte surgery**: serialize once, locate the placeholder, compute the real
   `/ByteRange` and patch it length-preservingly.
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
- **Full-rewrite save**, not an incremental update. Fine for a first signature;
  must become an append-only incremental update before multi-signature support.
- **RSA keys only.** The signer assumes RSA (PKCS#1 v1.5 + SHA-256). ECDSA /
  Ed25519 keystores are not handled yet.
- **No PAdES-LTV / timestamps (RFC 3161)** and no certificate chain / revocation
  checking on verify; the signer DN is reported but trust is not enforced.
- Single signature parsed on verify; AcroForm is overwritten rather than merged.

## Roadmap to replace the JAR in `signer`

1. ~~Swap OpenSSL → RustCrypto~~ ✅ done — pure-Rust `cms`/`rsa`/`p12-keystore`.
2. Visual appearance stream (port the `signtext` box + validation link).
3. Incremental-update save for multi-signature / re-signing.
4. Vendor crates for an R package build (`SystemRequirements: Cargo, rustc`).
5. Expose to R: either a thin CLI invoked via `system2`, or a native binding
   (e.g. via `extendr`) compiled into the package.
6. PAdES baseline (B-T) with RFC 3161 timestamps if legal validity requires it,
   plus certificate-chain validation against the ICP-Brasil roots on verify.

## License

GPL-3.0-or-later, matching the `signer` package.
