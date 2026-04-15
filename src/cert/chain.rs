use anyhow::{Context, Result};

use crate::cert::parser::parse_pem_certs;

/// Result of chain verification
pub struct VerifyResult {
    pub valid: bool,
    pub error: Option<String>,
    pub chain_length: usize,
    pub hint: Option<String>,
}

/// Verify a certificate against a CA bundle
pub fn verify_chain(cert_path: &str, ca_path: &str) -> Result<VerifyResult> {
    let cert_data = std::fs::read(cert_path)
        .with_context(|| format!("Failed to read certificate: {}", cert_path))?;
    let ca_data =
        std::fs::read(ca_path).with_context(|| format!("Failed to read CA bundle: {}", ca_path))?;

    let certs = parse_pem_certs(&cert_data)
        .with_context(|| format!("Failed to parse certificate: {}", cert_path))?;
    let ca_certs = parse_pem_certs(&ca_data)
        .with_context(|| format!("Failed to parse CA bundle: {}", ca_path))?;

    if certs.is_empty() {
        return Ok(VerifyResult {
            valid: false,
            error: Some("No certificates found in file".to_string()),
            chain_length: 0,
            hint: Some("Check that the file contains a valid PEM certificate".to_string()),
        });
    }

    let cert = &certs[0];
    let chain_length = certs.len() + ca_certs.len();

    // Check expiry
    if cert.is_expired() {
        let days = -cert.days_remaining();
        return Ok(VerifyResult {
            valid: false,
            error: Some(format!(
                "Certificate has expired ({} on {}, {} days ago)",
                cert.subject, cert.not_after, days
            )),
            chain_length,
            hint: Some(
                "Check if the server's certificate has been renewed.\n\
                 Use `sslx connect <host>` to fetch the current certificate."
                    .to_string(),
            ),
        });
    }

    // Check not yet valid
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;

    if cert.not_before.timestamp > now {
        return Ok(VerifyResult {
            valid: false,
            error: Some(format!(
                "Certificate is not yet valid (starts {})",
                cert.not_before
            )),
            chain_length,
            hint: Some(
                "Check your system clock, or wait until the validity period begins.".to_string(),
            ),
        });
    }

    // Check issuer chain (basic: verify issuer DN matches a CA subject DN)
    let issuer = &cert.issuer;
    let issuer_found = ca_certs.iter().any(|ca| &ca.subject == issuer)
        || certs.iter().skip(1).any(|c| &c.subject == issuer);

    if !issuer_found && cert.subject != cert.issuer {
        return Ok(VerifyResult {
            valid: false,
            error: Some(format!("Issuer '{}' not found in CA bundle", issuer)),
            chain_length,
            hint: Some(format!(
                "The CA bundle at '{}' does not contain the issuer certificate.\n\
                 Try providing the full chain including intermediate CAs.",
                ca_path
            )),
        });
    }

    Ok(VerifyResult {
        valid: true,
        error: None,
        chain_length,
        hint: None,
    })
}
