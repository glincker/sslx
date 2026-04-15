use anyhow::{Context, Result};
use rcgen::{CertificateParams, DistinguishedName, KeyPair, SanType};
use std::path::Path;

use crate::output::util::print_status;
use crate::output::{box_chars, colors};

pub fn run(
    cn: &str,
    sans: &[String],
    key_type: &str,
    out_dir: &str,
    json: bool,
    no_color: bool,
) -> Result<i32> {
    let use_color = !no_color && !json && colors::should_color();

    // Build params (we use CertificateParams and serialize as CSR)
    let mut params = CertificateParams::default();

    let mut dn = DistinguishedName::new();
    dn.push(rcgen::DnType::CommonName, cn);
    params.distinguished_name = dn;

    // SANs
    let mut san_types = Vec::new();
    san_types.push(SanType::DnsName(
        cn.try_into().context("Invalid CN for SAN")?,
    ));
    for san in sans {
        if let Ok(ip) = san.parse::<std::net::IpAddr>() {
            san_types.push(SanType::IpAddress(ip));
        } else if let Ok(dns) = san.as_str().try_into() {
            san_types.push(SanType::DnsName(dns));
        }
    }
    params.subject_alt_names = san_types;

    // Generate key pair
    let key_pair = match key_type {
        "ec256" | "p256" => KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)?,
        "ec384" | "p384" => KeyPair::generate_for(&rcgen::PKCS_ECDSA_P384_SHA384)?,
        "ed25519" => KeyPair::generate_for(&rcgen::PKCS_ED25519)?,
        other => {
            anyhow::bail!(
                "Unsupported key type: '{}'\n\
                 Supported types: ec256 (default), ec384, ed25519",
                other
            );
        }
    };

    // Serialize as CSR
    let csr = params.serialize_request(&key_pair)?;

    // Write files
    let out = Path::new(out_dir);
    let csr_path = out.join("csr.pem");
    let key_path = out.join("key.pem");

    let csr_pem = csr.pem().context("Failed to serialize CSR as PEM")?;
    std::fs::write(&csr_path, csr_pem)
        .with_context(|| format!("Failed to write {}", csr_path.display()))?;
    std::fs::write(&key_path, key_pair.serialize_pem())
        .with_context(|| format!("Failed to write {}", key_path.display()))?;

    let all_sans: Vec<String> = std::iter::once(cn.to_string())
        .chain(sans.iter().cloned())
        .collect();

    if json {
        let output = serde_json::json!({
            "csr_path": csr_path.display().to_string(),
            "key_path": key_path.display().to_string(),
            "subject": format!("CN={}", cn),
            "sans": all_sans,
            "key_type": key_type,
        });
        println!("{}", serde_json::to_string_pretty(&output)?);
    } else {
        print_status(
            box_chars::CHECK,
            "CSR generated",
            colors::BOLD_GREEN,
            use_color,
        );
        println!(
            "    {}      Certificate Signing Request",
            csr_path.display()
        );
        println!("    {}      {} private key", key_path.display(), key_type);
        println!();
        println!("    Subject:  CN={}", cn);
        println!("    SANs:     {}", all_sans.join(", "));
        println!();
        if use_color {
            println!(
                "  {}Next: submit csr.pem to your CA for signing{}",
                colors::DIM,
                colors::RESET
            );
        } else {
            println!("  Next: submit csr.pem to your CA for signing");
        }
        println!();
    }

    Ok(0)
}
