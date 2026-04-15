use anyhow::{Context, Result};

use crate::cert::parser::parse_cert_file;
use crate::output::util::print_status;
use crate::output::{box_chars, colors};

pub fn run(cert_path: &str, key_path: &str, json: bool, no_color: bool) -> Result<i32> {
    let use_color = !no_color && !json && colors::should_color();

    let certs = parse_cert_file(cert_path)?;
    let cert = certs.first().context("No certificate found in file")?;

    let key_data = std::fs::read(key_path)
        .with_context(|| format!("Failed to read key file: {}", key_path))?;

    let cert_pubkey_hash = &cert.public_key_sha256;
    let key_pubkey_hash = extract_pubkey_hash_from_key(&key_data)?;

    let matches = cert_pubkey_hash == &key_pubkey_hash;

    if json {
        let output = serde_json::json!({
            "matches": matches,
            "cert_file": cert_path,
            "key_file": key_path,
            "cert_key_type": cert.key_type.to_string(),
            "cert_key_bits": cert.key_bits,
        });
        println!("{}", serde_json::to_string_pretty(&output)?);
    } else if matches {
        let msg = format!("Certificate and key match ({})", cert.key_description());
        print_status(box_chars::CHECK, &msg, colors::BOLD_GREEN, use_color);
    } else {
        print_status(
            box_chars::CROSS,
            "Certificate and key DO NOT match",
            colors::BOLD_RED,
            use_color,
        );
        println!(
            "    Cert: {} ({})",
            cert.key_description(),
            truncate(&cert.public_key_sha256, 20)
        );
        println!("    Key:  {}", truncate(&key_pubkey_hash, 20));
        println!();
    }

    if matches {
        Ok(0)
    } else {
        Ok(1)
    }
}

/// Verify match by generating a self-signed cert from the key and comparing public keys
fn extract_pubkey_hash_from_key(data: &[u8]) -> Result<String> {
    use crate::cert::parser::sha256_of;

    let text = std::str::from_utf8(data).unwrap_or("");

    // Try to load the key with rcgen and extract the raw public key
    if text.contains("BEGIN") {
        if let Ok(key_pair) = rcgen::KeyPair::from_pem(text) {
            let pub_der = key_pair.public_key_raw();
            return Ok(sha256_of(pub_der));
        }
    }

    // Fallback: hash the raw key data (won't match cert, but provides output)
    Ok(sha256_of(data))
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        format!("{}...", &s[..max])
    }
}
