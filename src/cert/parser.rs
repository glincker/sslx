use anyhow::{bail, Context, Result};
use x509_parser::prelude::*;
use x509_parser::public_key::PublicKey;

use crate::cert::{CertInfo, CertTime, KeyType};

/// Format bytes as colon-separated hex
fn format_hex(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("{:02X}", b))
        .collect::<Vec<_>>()
        .join(":")
}

pub fn parse_cert_file(path: &str) -> Result<Vec<CertInfo>> {
    let data = std::fs::read(path).with_context(|| format!("can't read {}", path))?;
    parse_cert_data_with_source(&data, path)
}

/// Parse certificate(s) from raw bytes (PEM or DER).
/// Use this when data is already in memory (e.g. read from stdin).
pub fn parse_cert_data(data: &[u8]) -> Result<Vec<CertInfo>> {
    parse_cert_data_with_source(data, "stdin")
}

pub fn parse_cert_data_from(data: &[u8], source: &str) -> Result<Vec<CertInfo>> {
    parse_cert_data_with_source(data, source)
}

fn parse_cert_data_with_source(data: &[u8], source: &str) -> Result<Vec<CertInfo>> {
    if is_pem(data) {
        parse_pem_certs(data)
    } else if is_der(data) {
        parse_der_cert(data).map(|c| vec![c])
    } else {
        bail!(
            "Unrecognized certificate format in '{}'. Expected PEM or DER.\n\
             Hint: PEM files start with '-----BEGIN CERTIFICATE-----'\n\
             Hint: For PKCS12 (.p12/.pfx), use the convert or extract command",
            source
        )
    }
}

pub fn parse_pem_certs(data: &[u8]) -> Result<Vec<CertInfo>> {
    let pem_blocks = parse_pem_blocks(data)?;

    if pem_blocks.is_empty() {
        bail!("No certificates found in PEM data");
    }

    let mut certs = Vec::new();
    for (i, block) in pem_blocks.iter().enumerate() {
        let cert = parse_der_cert(block)
            .with_context(|| format!("certificate {} in bundle is invalid", i + 1))?;
        certs.push(cert);
    }

    Ok(certs)
}

pub fn parse_der_cert(der_data: &[u8]) -> Result<CertInfo> {
    let (_, cert) = X509Certificate::from_der(der_data)
        .map_err(|e| anyhow::anyhow!("bad certificate: {}", e))?;

    let subject = cert.subject().to_string();
    let issuer = cert.issuer().to_string();
    let serial_hex = format_hex(cert.raw_serial());

    let not_before = cert.validity().not_before.timestamp();
    let not_after = cert.validity().not_after.timestamp();

    let (key_type, key_bits) = extract_key_info(&cert);

    let sans = extract_sans(&cert);

    let sha256_fingerprint = sha256_hex(der_data);
    let public_key_sha256 = sha256_hex(&cert.public_key().subject_public_key.data);

    let is_ca = cert
        .basic_constraints()
        .ok()
        .flatten()
        .map(|ext| ext.value.ca)
        .unwrap_or(false);

    Ok(CertInfo {
        subject,
        issuer,
        serial_hex,
        not_before: CertTime::from_timestamp(not_before),
        not_after: CertTime::from_timestamp(not_after),
        key_type,
        key_bits,
        sans,
        sha256_fingerprint,
        public_key_sha256,
        is_ca,
        version: cert.version().0,
    })
}

fn extract_key_info(cert: &X509Certificate<'_>) -> (KeyType, u32) {
    let spki = cert.public_key();
    let algo_oid = spki.algorithm.algorithm.to_string();

    match algo_oid.as_str() {
        // RSA
        "1.2.840.113549.1.1.1" => {
            let bits = spki
                .parsed()
                .ok()
                .map(|pk| match pk {
                    PublicKey::RSA(rsa) => {
                        let size = rsa.key_size() as u32;
                        // key_size() returns bytes, convert to bits
                        // but guard against already-in-bits values
                        if size > 1024 {
                            size
                        } else {
                            size * 8
                        }
                    }
                    _ => 0,
                })
                .unwrap_or(0);
            (KeyType::Rsa, bits)
        }
        // EC (id-ecPublicKey)
        "1.2.840.10045.2.1" => {
            let curve = spki
                .algorithm
                .parameters
                .as_ref()
                .and_then(|p| p.as_oid().ok())
                .map(|oid| match oid.to_string().as_str() {
                    "1.2.840.10045.3.1.7" => ("P-256".to_string(), 256),
                    "1.3.132.0.34" => ("P-384".to_string(), 384),
                    "1.3.132.0.35" => ("P-521".to_string(), 521),
                    _ => (oid.to_string(), 0),
                })
                .unwrap_or_else(|| ("unknown".to_string(), 0));
            (KeyType::Ec(curve.0), curve.1)
        }
        // Ed25519
        "1.3.101.112" => (KeyType::Ed25519, 256),
        _ => (KeyType::Unknown(algo_oid), 0),
    }
}

fn extract_sans(cert: &X509Certificate<'_>) -> Vec<String> {
    cert.subject_alternative_name()
        .ok()
        .flatten()
        .map(|ext| {
            ext.value
                .general_names
                .iter()
                .filter_map(|name| match name {
                    GeneralName::DNSName(dns) => Some(dns.to_string()),
                    GeneralName::IPAddress(ip) => {
                        if ip.len() == 4 {
                            Some(format!("{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3]))
                        } else if ip.len() == 16 {
                            // IPv6: format as standard notation
                            let mut segments = Vec::new();
                            for i in (0..16).step_by(2) {
                                segments
                                    .push(format!("{:x}", u16::from_be_bytes([ip[i], ip[i + 1]])));
                            }
                            Some(segments.join(":"))
                        } else {
                            Some(format!("{:?}", ip))
                        }
                    }
                    _ => None,
                })
                .collect()
        })
        .unwrap_or_default()
}

fn is_pem(data: &[u8]) -> bool {
    data.starts_with(b"-----BEGIN ")
}

// DER files start with ASN.1 SEQUENCE tag (0x30)
fn is_der(data: &[u8]) -> bool {
    !data.is_empty() && data[0] == 0x30
}

fn parse_pem_blocks(data: &[u8]) -> Result<Vec<Vec<u8>>> {
    let text = std::str::from_utf8(data).context("PEM file contains invalid UTF-8")?;

    let mut blocks = Vec::new();
    let mut in_block = false;
    let mut base64_buf = String::new();

    for line in text.lines() {
        let line = line.trim();
        if line.starts_with("-----BEGIN ") {
            in_block = true;
            base64_buf.clear();
        } else if line.starts_with("-----END ") {
            if in_block {
                let decoded = base64_decode(&base64_buf).context("bad base64 in PEM block")?;
                blocks.push(decoded);
            }
            in_block = false;
        } else if in_block && !line.is_empty() {
            base64_buf.push_str(line);
        }
    }

    Ok(blocks)
}

/// Public base64 decoder for other modules
pub fn base64_decode_str(input: &str) -> Result<Vec<u8>> {
    base64_decode(input)
}

/// Public SHA-256 helper for other modules
pub fn sha256_of(data: &[u8]) -> String {
    sha256_hex(data)
}

fn base64_decode(input: &str) -> Result<Vec<u8>> {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD
        .decode(input.trim())
        .context("invalid base64")
}

fn sha256_hex(data: &[u8]) -> String {
    use ring::digest;
    let hash = digest::digest(&digest::SHA256, data);
    hash.as_ref()
        .iter()
        .map(|b| format!("{:02X}", b))
        .collect::<Vec<_>>()
        .join(":")
}

// TODO: support PKCS8 encrypted private keys

#[cfg(test)]
mod tests {
    use super::*;

    // ── helpers ──────────────────────────────────────────────────────────────

    /// Build a minimal self-signed DER certificate using rcgen.
    fn make_self_signed_der(cn: &str, sans: &[&str]) -> Vec<u8> {
        use rcgen::{CertificateParams, DistinguishedName, DnType, SanType};

        let mut params = CertificateParams::default();
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, cn);
        params.distinguished_name = dn;
        params.subject_alt_names = sans
            .iter()
            .map(|s| SanType::DnsName(s.to_string().try_into().unwrap()))
            .collect();

        let kp = rcgen::KeyPair::generate().unwrap();
        let cert = params.self_signed(&kp).unwrap();
        cert.der().to_vec()
    }

    /// Wrap DER bytes in a PEM block.
    fn der_to_pem(der: &[u8]) -> Vec<u8> {
        use base64::Engine;
        let b64 = base64::engine::general_purpose::STANDARD.encode(der);
        let mut pem = String::from("-----BEGIN CERTIFICATE-----\n");
        for chunk in b64.as_bytes().chunks(64) {
            pem.push_str(std::str::from_utf8(chunk).unwrap());
            pem.push('\n');
        }
        pem.push_str("-----END CERTIFICATE-----\n");
        pem.into_bytes()
    }

    // ── parse_pem_certs ───────────────────────────────────────────────────────

    #[test]
    fn test_parse_pem_single_cert() {
        let der = make_self_signed_der("example.com", &["example.com"]);
        let pem = der_to_pem(&der);

        let certs = parse_pem_certs(&pem).unwrap();
        assert_eq!(certs.len(), 1);
        assert!(certs[0].subject.contains("example.com"));
    }

    #[test]
    fn test_parse_pem_bundle_multiple_certs() {
        let der1 = make_self_signed_der("first.example.com", &["first.example.com"]);
        let der2 = make_self_signed_der("second.example.com", &["second.example.com"]);
        let mut bundle = der_to_pem(&der1);
        bundle.extend(der_to_pem(&der2));

        let certs = parse_pem_certs(&bundle).unwrap();
        assert_eq!(certs.len(), 2);
    }

    #[test]
    fn test_parse_pem_empty_returns_error() {
        let result = parse_pem_certs(b"");
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("No certificates"));
    }

    #[test]
    fn test_parse_pem_invalid_base64_returns_error() {
        let bad =
            b"-----BEGIN CERTIFICATE-----\n!!!not-valid-base64!!!\n-----END CERTIFICATE-----\n";
        let result = parse_pem_certs(bad);
        assert!(result.is_err());
    }

    // ── parse_der_cert ────────────────────────────────────────────────────────

    #[test]
    fn test_parse_der_cert_roundtrip() {
        let der = make_self_signed_der("der-test.example.com", &["der-test.example.com"]);
        let cert = parse_der_cert(&der).unwrap();

        assert!(cert.subject.contains("der-test.example.com"));
        assert!(cert.issuer.contains("der-test.example.com")); // self-signed
        assert!(cert.sans.contains(&"der-test.example.com".to_string()));
        assert!(!cert.sha256_fingerprint.is_empty());
    }

    #[test]
    fn test_parse_der_cert_invalid_returns_error() {
        let garbage = b"\x30\x00\x00\x00junk-data-that-is-not-a-cert";
        let result = parse_der_cert(garbage);
        assert!(result.is_err());
    }

    // ── sha256_of ─────────────────────────────────────────────────────────────

    #[test]
    fn test_sha256_of_known_input() {
        // SHA-256("") = e3b0c44298fc1c149afbf4c8996fb924...
        let hash = sha256_of(b"");
        assert!(hash.starts_with("E3:B0:C4:42:98:FC:1C:14"));
    }

    #[test]
    fn test_sha256_of_hello_world() {
        // SHA-256("hello world") starts with b94d27b9...
        let hash = sha256_of(b"hello world");
        assert!(hash.starts_with("B9:4D:27:B9"));
    }

    #[test]
    fn test_sha256_format_is_colon_separated_uppercase_hex() {
        let hash = sha256_of(b"test");
        let parts: Vec<&str> = hash.split(':').collect();
        assert_eq!(parts.len(), 32); // SHA-256 = 32 bytes
        for part in parts {
            assert_eq!(part.len(), 2);
            assert!(part.chars().all(|c| c.is_ascii_hexdigit()));
        }
    }

    // ── base64_decode_str ─────────────────────────────────────────────────────

    #[test]
    fn test_base64_decode_valid() {
        // "hello" in base64
        let decoded = base64_decode_str("aGVsbG8=").unwrap();
        assert_eq!(decoded, b"hello");
    }

    #[test]
    fn test_base64_decode_empty_string() {
        let decoded = base64_decode_str("").unwrap();
        assert!(decoded.is_empty());
    }

    #[test]
    fn test_base64_decode_invalid_returns_error() {
        let result = base64_decode_str("!!!not-valid!!!");
        assert!(result.is_err());
    }

    #[test]
    fn test_base64_decode_with_whitespace_padding() {
        // Leading/trailing whitespace should be trimmed and still parse
        let result = base64_decode_str("  aGVsbG8=  ");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), b"hello");
    }
}
