use crate::cert::CertInfo;
use serde::Serialize;

#[derive(Serialize)]
pub struct JsonCertOutput {
    pub certificates: Vec<JsonCert>,
}

#[derive(Serialize)]
pub struct JsonCert {
    pub subject: String,
    pub issuer: String,
    pub serial: String,
    pub not_before: String,
    pub not_after: String,
    pub days_remaining: i64,
    pub is_expired: bool,
    pub key_type: String,
    pub key_bits: u32,
    pub sans: Vec<String>,
    pub sha256_fingerprint: String,
    pub is_ca: bool,
}

impl From<&CertInfo> for JsonCert {
    fn from(cert: &CertInfo) -> Self {
        Self {
            subject: cert.subject.clone(),
            issuer: cert.issuer.clone(),
            serial: cert.serial_hex.clone(),
            not_before: cert.not_before.format("%Y-%m-%dT%H:%M:%SZ").to_string(),
            not_after: cert.not_after.format("%Y-%m-%dT%H:%M:%SZ").to_string(),
            days_remaining: cert.days_remaining(),
            is_expired: cert.is_expired(),
            key_type: cert.key_type.to_string(),
            key_bits: cert.key_bits,
            sans: cert.sans.clone(),
            sha256_fingerprint: cert.sha256_fingerprint.clone(),
            is_ca: cert.is_ca,
        }
    }
}

#[derive(Serialize)]
pub struct JsonConnectionOutput {
    pub host: String,
    pub port: u16,
    pub tls_version: String,
    pub cipher_suite: String,
    pub alpn: Option<String>,
    pub chain: JsonCertOutput,
}

#[derive(Serialize)]
pub struct JsonVerifyOutput {
    pub valid: bool,
    pub error: Option<String>,
    pub chain_length: usize,
    pub certificate: JsonCert,
}

#[derive(Serialize)]
pub struct JsonGenerateOutput {
    pub cert_path: String,
    pub key_path: String,
    pub subject: String,
    pub sans: Vec<String>,
    pub days: u32,
    pub key_type: String,
}
