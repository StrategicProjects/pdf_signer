//! `pdf_signer` command-line interface.

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand, ValueEnum};
use pdf_signer::{
    sign_pdf_file, verify_pdf_file, verify_pdf_file_with_roots, Appearance, PadesLevel,
    SignOptions, TrustStore,
};

/// Sign and verify PDF documents (pure-Rust PAdES).
#[derive(Parser)]
#[command(name = "pdf_signer", version, about)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Sign a PDF with a PKCS#12 keystore.
    Sign(Box<SignArgs>),
    /// Verify the signatures in a PDF.
    Verify(VerifyArgs),
}

#[derive(Clone, Copy, ValueEnum)]
enum Level {
    /// Baseline (signing-certificate-v2).
    Bb,
    /// + RFC 3161 signature timestamp.
    Bt,
    /// + DSS (certificate chain, CRLs, OCSP).
    Blt,
    /// + document timestamp over the whole file.
    Blta,
}

impl From<Level> for PadesLevel {
    fn from(l: Level) -> Self {
        match l {
            Level::Bb => PadesLevel::Bb,
            Level::Bt => PadesLevel::Bt,
            Level::Blt => PadesLevel::Blt,
            Level::Blta => PadesLevel::Blta,
        }
    }
}

#[derive(Parser)]
struct SignArgs {
    /// Input PDF.
    input: PathBuf,
    /// Output (signed) PDF.
    output: PathBuf,
    /// PKCS#12 (.p12/.pfx) keystore.
    keystore: PathBuf,
    /// Keystore password.
    #[arg(short, long, env = "KEY_PASSWORD")]
    password: String,

    /// PAdES level. `bt`+ require `--tsa-url`.
    #[arg(long, value_enum, default_value = "bb")]
    level: Level,
    /// RFC 3161 Time-Stamping Authority URL (http:// or, with the `https`
    /// feature, https://).
    #[arg(long)]
    tsa_url: Option<String>,

    /// `/Reason` for signing.
    #[arg(long)]
    reason: Option<String>,
    /// Signer `/Name`.
    #[arg(long)]
    name: Option<String>,
    /// `/Location`.
    #[arg(long)]
    location: Option<String>,

    /// Draw a visible signature box with this text (enables a visible signature).
    #[arg(long)]
    text: Option<String>,
    /// Page for the visible box (1-based).
    #[arg(long, default_value_t = 1)]
    page: usize,
    /// Visible box geometry, in points.
    #[arg(long, default_value_t = 36.0)]
    x: f64,
    #[arg(long, default_value_t = 36.0)]
    y: f64,
    #[arg(long, default_value_t = 320.0)]
    width: f64,
    #[arg(long, default_value_t = 64.0)]
    height: f64,
    #[arg(long, default_value_t = 8.0)]
    font_size: f64,
    /// Drop the box border.
    #[arg(long)]
    no_border: bool,
    /// TrueType/OpenType font file to embed in the box.
    #[arg(long)]
    font: Option<PathBuf>,
    /// PNG/JPEG logo to draw in the box.
    #[arg(long)]
    image: Option<PathBuf>,
}

#[derive(Parser)]
struct VerifyArgs {
    /// PDF to verify.
    input: PathBuf,
    /// PEM file of trusted roots (e.g. ICP-Brasil). Enables chain validation.
    #[arg(long)]
    roots: Option<PathBuf>,
}

fn main() -> ExitCode {
    match Cli::parse().command {
        Command::Sign(a) => run_sign(*a),
        Command::Verify(a) => run_verify(a),
    }
}

fn run_sign(a: SignArgs) -> ExitCode {
    let appearance = a.text.as_ref().map(|text| {
        Ok::<_, std::io::Error>(Appearance {
            page: a.page,
            x: a.x,
            y: a.y,
            width: a.width,
            height: a.height,
            font_size: a.font_size,
            text: text.clone(),
            border: !a.no_border,
            font: a.font.as_ref().map(std::fs::read).transpose()?,
            image: a.image.as_ref().map(std::fs::read).transpose()?,
            image_rect: None,
        })
    });
    let appearance = match appearance.transpose() {
        Ok(v) => v,
        Err(e) => {
            eprintln!("error: reading font/image: {e}");
            return ExitCode::FAILURE;
        }
    };

    let opts = SignOptions {
        reason: a.reason,
        name: a.name,
        location: a.location,
        tsa_url: a.tsa_url,
        pades_level: a.level.into(),
        appearance,
        ..Default::default()
    };

    match sign_pdf_file(&a.input, &a.output, &a.keystore, &a.password, &opts) {
        Ok(()) => {
            println!("signed: {} -> {}", a.input.display(), a.output.display());
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

fn run_verify(a: VerifyArgs) -> ExitCode {
    // When a trust store is supplied, the chain must be trusted for success;
    // otherwise we can only attest to cryptographic validity.
    let roots_supplied = a.roots.is_some();
    let report = if let Some(roots_path) = &a.roots {
        let pem = match std::fs::read(roots_path) {
            Ok(p) => p,
            Err(e) => {
                eprintln!("error: reading roots: {e}");
                return ExitCode::FAILURE;
            }
        };
        match TrustStore::from_pem(&pem) {
            Ok(store) => verify_pdf_file_with_roots(&a.input, &store),
            Err(e) => {
                eprintln!("error: parsing roots: {e}");
                return ExitCode::FAILURE;
            }
        }
    } else {
        verify_pdf_file(&a.input)
    };

    let report = match report {
        Ok(r) => r,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::FAILURE;
        }
    };

    if report.signatures.is_empty() {
        println!("no signatures found");
        return ExitCode::FAILURE;
    }
    for (i, s) in report.signatures.iter().enumerate() {
        println!("signature #{}:", i + 1);
        println!("  valid:                 {}", s.valid);
        println!("  signer:                {}", s.signer.as_deref().unwrap_or("-"));
        println!(
            "  chain_trusted:         {}",
            s.chain_trusted.map_or("n/a (no roots)".into(), |b| b.to_string())
        );
        println!("  covers_whole_document: {}", s.covers_whole_document);
        println!("  detail:                {}", s.detail);
    }

    if roots_supplied {
        if report.all_trusted() {
            ExitCode::SUCCESS
        } else if report.all_valid() {
            eprintln!(
                "error: signature(s) cryptographically valid but not trusted by the supplied roots"
            );
            ExitCode::FAILURE
        } else {
            ExitCode::FAILURE
        }
    } else if report.all_valid() {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}
