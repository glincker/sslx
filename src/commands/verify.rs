use anyhow::Result;

use crate::cert::chain::verify_chain;
use crate::cert::parser::parse_cert_file;
use crate::output::colors;
use crate::output::json::{JsonCert, JsonVerifyOutput};
use crate::output::terminal;

pub fn run(cert_path: &str, ca_path: &str, json: bool, no_color: bool) -> Result<i32> {
    let result = verify_chain(cert_path, ca_path)?;
    let certs = parse_cert_file(cert_path)?;
    let use_color = !no_color && !json && colors::should_color();

    if json {
        let output = JsonVerifyOutput {
            valid: result.valid,
            error: result.error.clone(),
            chain_length: result.chain_length,
            certificate: certs
                .first()
                .map(JsonCert::from)
                .unwrap_or_else(|| JsonCert {
                    subject: String::new(),
                    issuer: String::new(),
                    serial: String::new(),
                    not_before: String::new(),
                    not_after: String::new(),
                    days_remaining: 0,
                    is_expired: true,
                    key_type: String::new(),
                    key_bits: 0,
                    sans: vec![],
                    sha256_fingerprint: String::new(),
                    is_ca: false,
                }),
        };
        println!("{}", serde_json::to_string_pretty(&output)?);
    } else {
        let mut details = String::new();

        if result.valid {
            details.push_str(&format!(
                "    Chain:    complete ({} certs)\n",
                result.chain_length
            ));
            if let Some(cert) = certs.first() {
                details.push_str(&format!(
                    "    Expiry:   {} days remaining\n",
                    cert.days_remaining()
                ));
            }
        } else if let Some(err) = &result.error {
            details.push_str(&format!("    Reason:   {}\n", err));
        }

        if let Some(hint) = &result.hint {
            details.push('\n');
            if use_color {
                details.push_str(&format!("  {}Hint: {}{}", colors::DIM, hint, colors::RESET));
            } else {
                details.push_str(&format!("  Hint: {}", hint));
            }
        }

        println!(
            "{}",
            terminal::render_verify_result(result.valid, &details, use_color)
        );
    }

    if result.valid {
        Ok(0)
    } else {
        Ok(3)
    }
}
