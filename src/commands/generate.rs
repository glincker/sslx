use anyhow::{Context, Result};
use rcgen::{CertificateParams, DistinguishedName, KeyPair, SanType};
use std::path::Path;

use crate::output::colors;
use crate::output::json::JsonGenerateOutput;

pub fn run(
    cn: &str,
    sans: &[String],
    days: u32,
    key_type: &str,
    out_dir: &str,
    json: bool,
    no_color: bool,
) -> Result<i32> {
    let use_color = !no_color && !json && colors::should_color();

    // Build certificate params
    let mut params = CertificateParams::default();

    let mut dn = DistinguishedName::new();
    dn.push(rcgen::DnType::CommonName, cn);
    params.distinguished_name = dn;

    // SANs
    let mut san_types = Vec::new();
    // Always include CN as SAN
    san_types.push(SanType::DnsName(
        cn.try_into().context("Invalid CN for SAN")?,
    ));

    // Add localhost defaults if CN is localhost
    if cn == "localhost" {
        if let Ok(ip) = "127.0.0.1".parse() {
            san_types.push(SanType::IpAddress(ip));
        }
        if let Ok(ip) = "::1".parse() {
            san_types.push(SanType::IpAddress(ip));
        }
    }

    for san in sans {
        if let Ok(ip) = san.parse::<std::net::IpAddr>() {
            san_types.push(SanType::IpAddress(ip));
        } else if let Ok(dns) = san.as_str().try_into() {
            san_types.push(SanType::DnsName(dns));
        }
    }
    params.subject_alt_names = san_types;

    // Validity
    let not_before = time::OffsetDateTime::now_utc();
    let not_after = not_before + time::Duration::days(days as i64);
    params.not_before = not_before;
    params.not_after = not_after;

    // Generate key pair
    let key_pair = match key_type {
        "ec256" | "p256" => KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)?,
        "ec384" | "p384" => KeyPair::generate_for(&rcgen::PKCS_ECDSA_P384_SHA384)?,
        "ed25519" => KeyPair::generate_for(&rcgen::PKCS_ED25519)?,
        other => {
            anyhow::bail!(
                "Unsupported key type: '{}'\n\
                 Supported types: ec256 (default), ec384, ed25519\n\n\
                 Hint: EC keys are recommended over RSA for modern TLS.",
                other
            );
        }
    };

    let cert = params.self_signed(&key_pair)?;

    // Write files
    let out_path = Path::new(out_dir);
    let cert_path = out_path.join("cert.pem");
    let key_path = out_path.join("key.pem");

    std::fs::write(&cert_path, cert.pem())
        .with_context(|| format!("Failed to write {}", cert_path.display()))?;
    std::fs::write(&key_path, key_pair.serialize_pem())
        .with_context(|| format!("Failed to write {}", key_path.display()))?;

    if json {
        let output = JsonGenerateOutput {
            cert_path: cert_path.display().to_string(),
            key_path: key_path.display().to_string(),
            subject: format!("CN={}", cn),
            sans: sans.to_vec(),
            days,
            key_type: key_type.to_string(),
        };
        println!("{}", serde_json::to_string_pretty(&output)?);
    } else {
        let check = crate::output::box_chars::CHECK;

        if use_color {
            println!(
                "\n  {}{} Certificate generated{}\n",
                colors::BOLD_GREEN,
                check,
                colors::RESET
            );
        } else {
            println!("\n  {} Certificate generated\n", check);
        }

        println!("    {}     {} certificate", cert_path.display(), key_type);
        println!("    {}      {} private key", key_path.display(), key_type);
        println!();
        println!("    Subject:  CN={}", cn);

        let all_sans: Vec<String> = std::iter::once(cn.to_string())
            .chain(sans.iter().cloned())
            .collect();
        println!("    SANs:     {}", all_sans.join(", "));
        println!("    Valid:    {} days (until {})", days, not_after.date());
        println!();

        if use_color {
            println!("  {}Usage:{}", colors::DIM, colors::RESET);
        } else {
            println!("  Usage:");
        }
        println!(
            "    nginx:   ssl_certificate {}; ssl_certificate_key {};",
            cert_path.display(),
            key_path.display()
        );
        println!("    node:    https.createServer({{ cert: readFileSync('{}'), key: readFileSync('{}') }})",
            cert_path.display(), key_path.display());
        println!();
    }

    Ok(0)
}
