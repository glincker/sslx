pub mod chain;
pub mod parser;
pub mod tls;

use serde::Serialize;
use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

/// Parsed certificate information
#[derive(Debug, Clone, Serialize)]
pub struct CertInfo {
    pub subject: String,
    pub issuer: String,
    pub serial_hex: String,
    pub not_before: CertTime,
    pub not_after: CertTime,
    pub key_type: KeyType,
    pub key_bits: u32,
    pub sans: Vec<String>,
    pub sha256_fingerprint: String,
    pub public_key_sha256: String,
    pub is_ca: bool,
    pub version: u32,
}

impl CertInfo {
    /// Days remaining until expiry (negative = expired)
    pub fn days_remaining(&self) -> i64 {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        let expiry = self.not_after.timestamp;
        (expiry - now) / 86400
    }

    /// Whether the certificate is currently expired
    pub fn is_expired(&self) -> bool {
        self.days_remaining() < 0
    }

    /// Human-readable key description
    pub fn key_description(&self) -> String {
        match &self.key_type {
            KeyType::Rsa => format!("RSA {} bit", self.key_bits),
            KeyType::Ec(curve) => format!("ECDSA {} ({} bit)", curve, self.key_bits),
            KeyType::Ed25519 => "Ed25519".to_string(),
            KeyType::Unknown(name) => format!("{} ({} bit)", name, self.key_bits),
        }
    }
}

/// Key algorithm type
#[derive(Debug, Clone, Serialize)]
pub enum KeyType {
    Rsa,
    Ec(String),
    Ed25519,
    Unknown(String),
}

impl fmt::Display for KeyType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            KeyType::Rsa => write!(f, "RSA"),
            KeyType::Ec(curve) => write!(f, "EC {}", curve),
            KeyType::Ed25519 => write!(f, "Ed25519"),
            KeyType::Unknown(name) => write!(f, "{}", name),
        }
    }
}

/// Simple timestamp wrapper (avoids chrono dependency)
#[derive(Debug, Clone, Serialize)]
pub struct CertTime {
    pub timestamp: i64,
    year: i32,
    month: u8,
    day: u8,
    hour: u8,
    min: u8,
    sec: u8,
}

impl CertTime {
    pub fn from_timestamp(ts: i64) -> Self {
        // Convert unix timestamp to date components
        // Simple algorithm — handles dates from 1970 to 2099
        let secs = ts;
        let days = (secs / 86400) as i32;
        let time_of_day = (secs % 86400) as u32;

        let hour = (time_of_day / 3600) as u8;
        let min = ((time_of_day % 3600) / 60) as u8;
        let sec = (time_of_day % 60) as u8;

        // Days since epoch to Y-M-D (simplified Gregorian)
        let (year, month, day) = days_to_ymd(days);

        Self {
            timestamp: ts,
            year,
            month,
            day,
            hour,
            min,
            sec,
        }
    }

    pub fn format(&self, fmt: &str) -> String {
        // Support basic format strings
        fmt.replace("%Y", &format!("{:04}", self.year))
            .replace("%m", &format!("{:02}", self.month))
            .replace("%d", &format!("{:02}", self.day))
            .replace("%H", &format!("{:02}", self.hour))
            .replace("%M", &format!("{:02}", self.min))
            .replace("%S", &format!("{:02}", self.sec))
    }
}

impl fmt::Display for CertTime {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:04}-{:02}-{:02} {:02}:{:02}:{:02}",
            self.year, self.month, self.day, self.hour, self.min, self.sec
        )
    }
}

/// Convert days since Unix epoch to (year, month, day)
fn days_to_ymd(days: i32) -> (i32, u8, u8) {
    // Algorithm from http://howardhinnant.github.io/date_algorithms.html
    let z = days + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = (z - era * 146097) as u32;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe as i32 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u8;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u8;
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}
