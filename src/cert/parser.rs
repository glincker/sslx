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

/// Parse certificates from a file (auto-detects PEM vs DER)
pub fn parse_cert_file(path: &str) -> Result<Vec<CertInfo>> {
    let data = std::fs::read(path).with_context(|| format!("Failed to read file: {}", path))?;

    if is_pem(&data) {
        parse_pem_certs(&data)
    } else if is_der(&data) {
        parse_der_cert(&data).map(|c| vec![c])
    } else {
        bail!(
            "Unrecognized certificate format in '{}'. Expected PEM or DER.\n\
             Hint: PEM files start with '-----BEGIN CERTIFICATE-----'\n\
             Hint: For PKCS12 (.p12/.pfx), use --pkcs12 flag",
            path
        )
    }
}

/// Parse PEM-encoded certificates (handles multi-cert bundles)
pub fn parse_pem_certs(data: &[u8]) -> Result<Vec<CertInfo>> {
    let pem_blocks = parse_pem_blocks(data)?;

    if pem_blocks.is_empty() {
        bail!("No certificates found in PEM data");
    }

    let mut certs = Vec::new();
    for (i, block) in pem_blocks.iter().enumerate() {
        let cert = parse_der_cert(block)
            .with_context(|| format!("Failed to parse certificate {} in PEM bundle", i + 1))?;
        certs.push(cert);
    }

    Ok(certs)
}

/// Parse a single DER-encoded certificate
pub fn parse_der_cert(der_data: &[u8]) -> Result<CertInfo> {
    let (_, cert) = X509Certificate::from_der(der_data)
        .map_err(|e| anyhow::anyhow!("Failed to parse DER certificate: {}", e))?;

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

/// Extract key type and bit size from certificate
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

/// Extract Subject Alternative Names
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

/// Check if data looks like PEM
fn is_pem(data: &[u8]) -> bool {
    data.starts_with(b"-----BEGIN ")
}

/// Check if data looks like DER (ASN.1 SEQUENCE tag)
fn is_der(data: &[u8]) -> bool {
    !data.is_empty() && data[0] == 0x30
}

/// Parse PEM blocks into DER byte arrays (no dependency needed)
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
                let decoded =
                    base64_decode(&base64_buf).context("Failed to decode base64 in PEM block")?;
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

/// Simple base64 decoder (avoids base64 crate dependency)
fn base64_decode(input: &str) -> Result<Vec<u8>> {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    let mut lookup = [255u8; 256];
    for (i, &c) in TABLE.iter().enumerate() {
        lookup[c as usize] = i as u8;
    }

    let input: Vec<u8> = input
        .bytes()
        .filter(|&b| b != b'\n' && b != b'\r' && b != b' ')
        .collect();
    let mut output = Vec::with_capacity(input.len() * 3 / 4);

    for chunk in input.chunks(4) {
        let mut buf = [0u8; 4];
        let mut valid = 0;

        for (i, &byte) in chunk.iter().enumerate() {
            if byte == b'=' {
                break;
            }
            let val = lookup[byte as usize];
            if val == 255 {
                bail!("Invalid base64 character: '{}'", byte as char);
            }
            buf[i] = val;
            valid = i + 1;
        }

        if valid >= 2 {
            output.push((buf[0] << 2) | (buf[1] >> 4));
        }
        if valid >= 3 {
            output.push((buf[1] << 4) | (buf[2] >> 2));
        }
        if valid >= 4 {
            output.push((buf[2] << 6) | buf[3]);
        }
    }

    Ok(output)
}

/// Compute SHA-256 fingerprint (built-in, no extra dependency)
fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let hash = hasher.finalize();
    hash.iter()
        .map(|b| format!("{:02X}", b))
        .collect::<Vec<_>>()
        .join(":")
}

/// Minimal SHA-256 implementation (avoids additional dependency)
/// rustls pulls in ring which has SHA-256 but the API isn't always convenient
struct Sha256 {
    data: Vec<u8>,
}

impl Sha256 {
    fn new() -> Self {
        Self { data: Vec::new() }
    }

    fn update(&mut self, data: &[u8]) {
        self.data.extend_from_slice(data);
    }

    fn finalize(&self) -> [u8; 32] {
        // SHA-256 constants
        const K: [u32; 64] = [
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
            0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
            0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
            0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
            0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
            0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
            0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
            0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
            0xc67178f2,
        ];

        let mut h: [u32; 8] = [
            0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
            0x5be0cd19,
        ];

        // Pre-processing: pad message
        let bit_len = (self.data.len() as u64) * 8;
        let mut msg = self.data.clone();
        msg.push(0x80);
        while (msg.len() % 64) != 56 {
            msg.push(0);
        }
        msg.extend_from_slice(&bit_len.to_be_bytes());

        // Process each 512-bit block
        for block in msg.chunks(64) {
            let mut w = [0u32; 64];
            for i in 0..16 {
                w[i] = u32::from_be_bytes([
                    block[i * 4],
                    block[i * 4 + 1],
                    block[i * 4 + 2],
                    block[i * 4 + 3],
                ]);
            }
            for i in 16..64 {
                let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
                let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
                w[i] = w[i - 16]
                    .wrapping_add(s0)
                    .wrapping_add(w[i - 7])
                    .wrapping_add(s1);
            }

            let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh] = h;

            for i in 0..64 {
                let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
                let ch = (e & f) ^ ((!e) & g);
                let temp1 = hh
                    .wrapping_add(s1)
                    .wrapping_add(ch)
                    .wrapping_add(K[i])
                    .wrapping_add(w[i]);
                let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
                let maj = (a & b) ^ (a & c) ^ (b & c);
                let temp2 = s0.wrapping_add(maj);

                hh = g;
                g = f;
                f = e;
                e = d.wrapping_add(temp1);
                d = c;
                c = b;
                b = a;
                a = temp1.wrapping_add(temp2);
            }

            h[0] = h[0].wrapping_add(a);
            h[1] = h[1].wrapping_add(b);
            h[2] = h[2].wrapping_add(c);
            h[3] = h[3].wrapping_add(d);
            h[4] = h[4].wrapping_add(e);
            h[5] = h[5].wrapping_add(f);
            h[6] = h[6].wrapping_add(g);
            h[7] = h[7].wrapping_add(hh);
        }

        let mut result = [0u8; 32];
        for (i, val) in h.iter().enumerate() {
            result[i * 4..i * 4 + 4].copy_from_slice(&val.to_be_bytes());
        }
        result
    }
}
