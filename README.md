# pdf_signer

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
[![Rust](https://img.shields.io/badge/rust-1.74%2B-orange.svg)](https://www.rust-lang.org)
[![PAdES](https://img.shields.io/badge/PAdES-B--B%20%E2%86%92%20B--LTA-success.svg)](#pades-levels)
![pure Rust](https://img.shields.io/badge/crypto-pure%20RustCrypto-success.svg)

**Also available as:**
[![R package: pdfsigner](https://img.shields.io/badge/R-pdfsigner-276DC3?logo=r&logoColor=white)](https://github.com/StrategicProjects/pdfsigner)
[![PyPI: pdfsignerpy](https://img.shields.io/badge/PyPI-pdfsignerpy-3776AB?logo=python&logoColor=white)](https://pypi.org/project/pdfsignerpy/)

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
$ pdf_signer sign sample.pdf signed.pdf keystore.p12 \
      --password password --reason "Approved" --level blta \
      --tsa-url http://timestamp.digicert.com \
      --text "Digitally signed" --image logo.png --font Arial.ttf
$ pdf_signer verify signed.pdf --roots icp-brasil-roots.pem
signature #1:
  valid:                 true
  signer:                CN=...
  chain_trusted:         true
  detail:                valid CMS signature; signer: ...
$ pdfsig signed.pdf
  - Signature Type: ETSI.CAdES.detached
  - Signature Validation: Signature is Valid.
  - Total document signed
```

Run `pdf_signer sign --help` / `verify --help` for all options.

## Features

- **PAdES B-B → B-LTA** detached CMS signatures (`ETSI.CAdES.detached`).
- **Visible or invisible** signatures — a bordered text box (the signing
  statement + validation link) at any position on any page, with word wrap,
  an optional **embedded TrueType font** and a **PNG/JPEG logo**.
- **True incremental updates** — the original bytes are never rewritten, so
  **multiple signatures** compose and earlier ones stay valid.
- **RFC 3161 timestamps** — signature timestamps (B-T) and document timestamps
  (B-LTA), from any TSA.
- **Long-term validation material** — a `/DSS` with the full certificate chain,
  CRLs **and OCSP responses** fetched from the certificates' distribution points
  / responders (B-LT).
- **Verification** — re-derives the signed byte range, checks the message
  digest and the signer's signature, and reports each signature *and* document
  timestamp.
- **Certificate-chain validation** against a trust store (e.g. the **ICP-Brasil**
  roots): per-link signature (RSA, ECDSA P-256/P-384, Ed25519), validity,
  `basicConstraints` / `pathLenConstraint` / `keyCertSign`, **CRL + OCSP**
  revocation, **name constraints** (§4.2.1.10), and the full **policy engine**
  (`valid_policy_tree`, policy mapping) with an optional required-policy set.
- **RSA, ECDSA and Ed25519** signing keys (RSA PKCS#1 v1.5 + SHA-256; ECDSA
  P-256/SHA-256 and P-384/SHA-384; Ed25519 per RFC 8419), detected automatically
  from the keystore.
- **Pure Rust**, with an optional `https` feature (rustls) for TLS endpoints.

### PAdES levels

| Level      | What it adds                                       | `pades_level` | Needs a TSA |
|------------|----------------------------------------------------|---------------|-------------|
| **B-B**    | `signing-certificate-v2` (CAdES baseline)          | `Bb`          | no          |
| **B-T**    | + RFC 3161 **signature timestamp**                 | `Bt`          | yes         |
| **B-LT**   | + `/DSS` (certificate chain + CRLs)                | `Blt`         | yes         |
| **B-LTA**  | + `/DocTimeStamp` over the whole file              | `Blta`        | yes         |

## Command-line interface

The crate ships a `pdf_signer` binary with two subcommands. Install it (or run
it straight from a checkout):

```console
$ cargo install --path .            # puts `pdf_signer` on your PATH
# …or, without installing:
$ cargo run --release -- sign  …    # everything after `--` is forwarded
$ cargo run --release -- verify …
```

### `sign`

```console
$ pdf_signer sign <INPUT> <OUTPUT> <KEYSTORE> --password <PWD> [options]
```

| Argument / flag | Meaning |
| --- | --- |
| `<INPUT>` `<OUTPUT>` `<KEYSTORE>` | input PDF, signed output PDF, PKCS#12 `.p12`/`.pfx` |
| `-p, --password` | keystore password (or set `KEY_PASSWORD` in the environment) |
| `--level <bb\|bt\|blt\|blta>` | PAdES level (default `bb`); `bt`+ need `--tsa-url` |
| `--tsa-url <URL>` | RFC 3161 timestamp authority (`http://`, or `https://` with the `https` feature) |
| `--reason` / `--name` / `--location` | signature dictionary metadata |
| `--text <STR>` | draw a **visible** signature box with this text |
| `--page --x --y --width --height --font-size` | box placement/size, in points |
| `--no-border` | omit the box border |
| `--font <FILE.ttf>` | embed a TrueType/OpenType font in the box |
| `--image <FILE.png\|jpg>` | draw a PNG/JPEG logo in the box |

```console
# Invisible PAdES-B-B signature, password from the environment:
$ KEY_PASSWORD=secret pdf_signer sign in.pdf out.pdf keystore.p12

# Visible box, long-term (B-LTA) with a timestamp and an embedded logo:
$ pdf_signer sign in.pdf out.pdf keystore.p12 \
      --password secret --level blta \
      --tsa-url http://timestamp.digicert.com \
      --reason "Approved" --name "André Leite" \
      --text "Digitally signed" --image logo.png --font Arial.ttf
```

### `verify`

```console
$ pdf_signer verify <INPUT> [--roots <ROOTS.pem>]
```

Without `--roots` it reports cryptographic validity only; pass a PEM bundle of
trusted roots (e.g. ICP-Brasil) to additionally validate each signer's chain.

```console
$ pdf_signer verify out.pdf --roots icp-brasil-roots.pem
signature #1:
  valid:                 true
  signer:                CN=…
  chain_trusted:         true
  covers_whole_document: true
  detail:                valid CMS signature; signer: …
```

The process exits `0` only when at least one signature is present and all found
signatures are valid. Run `pdf_signer sign --help` / `verify --help` for the
full, authoritative list of options.

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

- **Path validation** implements RFC 5280 §6.1 broadly: signatures, validity,
  basic constraints, path length, key usage, CRL + OCSP revocation, name
  constraints, and the **policy engine** (`valid_policy_tree`, policy mapping,
  `requireExplicit­Policy`/`inhibitPolicyMapping`/`inhibitAnyPolicy`).
  The policy engine and name-constraint processing are validated against the
  **NIST PKITS** suite — **42/42 certificate-policy tests (§4.8–4.12)** and
  **38/38 name-constraint tests (§4.13)** pass. Run them with
  `PKITS_DIR=/path/to/pkits cargo test --test pkits -- --ignored` (the
  revocation/CRL-shape PKITS sections rely on features this crate does not
  claim, so they are not asserted).
- **Signing keys**: RSA (SHA-256), ECDSA (P-256/P-384) and Ed25519. Most PDF
  readers (e.g. Adobe) do **not** validate Ed25519 PDF signatures yet — this
  crate's own verifier does.
- Incremental updates match the source: a **traditional xref table** *or* a
  **cross-reference stream** (auto-detected), chained via `/Prev`.
- Visible appearances can **embed a TrueType font** (a *simple* WinAnsi font —
  Latin-1, not Type0/Unicode, so non-Latin-1 glyphs become `?`) and a **PNG or
  JPEG logo**; the default font is standard Helvetica. Line wrapping is
  approximate (character-count).

## Roadmap

- [x] Pure-Rust CMS signing & verification (no OpenSSL/Java)
- [x] Visible appearance, incremental updates, multi-signature
- [x] PAdES B-B / B-T / B-LT / B-LTA (DSS + document timestamp)
- [x] Certificate-chain validation (RSA + ECDSA, CRL + OCSP, RFC 5280 subset)
- [x] Optional HTTPS (rustls) for TSA / CRL / OCSP
- [x] [extendr](https://extendr.github.io/) bindings + vendoring for R / CRAN
- [x] ECDSA signing keys (P-256 / P-384)
- [x] RFC 5280 name constraints + required-policy check
- [x] Ed25519 signing keys; xref-stream incremental updates
- [x] RFC 5280 policy engine (valid_policy_tree, policy mapping) — **NIST PKITS
  validated** (42/42 policy + 38/38 name-constraint tests)
- [x] Richer visible appearances (embedded TrueType fonts + PNG/JPEG images)

## License

GPL-3.0-or-later.
