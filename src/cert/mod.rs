pub mod chain;
pub mod parser;
pub mod tls;

use serde::Serialize;
use std::collections::HashMap;
use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

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
    pub fn days_remaining(&self) -> i64 {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        let expiry = self.not_after.timestamp;
        (expiry - now) / 86400
    }

    pub fn is_expired(&self) -> bool {
        self.days_remaining() < 0
    }

    pub fn key_description(&self) -> String {
        match &self.key_type {
            KeyType::Rsa => format!("RSA {} bit", self.key_bits),
            KeyType::Ec(curve) => format!("ECDSA {} ({} bit)", curve, self.key_bits),
            KeyType::Ed25519 => "Ed25519".to_string(),
            KeyType::Unknown(name) => format!("{} ({} bit)", name, self.key_bits),
        }
    }
}

pub struct VerboseCert {
    pub base_cert: CertInfo,
    pub extensions: HashMap<String, Vec<(String, String)>>,
}

// This could be implemented using a trait, however this would require some refactoring
impl VerboseCert {
    // Days remaining and key description removed to keep clippy clean

    pub fn is_expired(&self) -> bool {
        self.base_cert.is_expired()
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
        // handles dates from 1970 to 2099
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
pub(crate) fn days_to_ymd(days: i32) -> (i32, u8, u8) {
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

#[cfg(test)]
mod tests {
    use super::*;

    // ── days_to_ymd ───────────────────────────────────────────────────────────

    #[test]
    fn test_days_to_ymd_epoch() {
        // Day 0 = 1970-01-01
        assert_eq!(days_to_ymd(0), (1970, 1, 1));
    }

    #[test]
    fn test_days_to_ymd_known_dates() {
        // 2000-01-01 = 10957 days after epoch
        assert_eq!(days_to_ymd(10957), (2000, 1, 1));
        // 19796 days from epoch = 2024-03-14
        assert_eq!(days_to_ymd(19796), (2024, 3, 14));
    }

    #[test]
    fn test_days_to_ymd_leap_year_feb29() {
        // 2000-02-29 (leap year)
        assert_eq!(days_to_ymd(11016), (2000, 2, 29));
    }

    #[test]
    fn test_days_to_ymd_end_of_year() {
        // 2023-12-31 = 19722 days after epoch
        assert_eq!(days_to_ymd(19722), (2023, 12, 31));
    }

    // ── CertTime::from_timestamp ──────────────────────────────────────────────

    #[test]
    fn test_certtime_from_timestamp_epoch() {
        let t = CertTime::from_timestamp(0);
        assert_eq!(t.timestamp, 0);
        assert_eq!(t.year, 1970);
        assert_eq!(t.month, 1);
        assert_eq!(t.day, 1);
        assert_eq!(t.hour, 0);
        assert_eq!(t.min, 0);
        assert_eq!(t.sec, 0);
    }

    #[test]
    fn test_certtime_from_timestamp_known() {
        // 1710502496 = 2024-03-15 11:34:56 UTC
        let ts = 1710502496_i64;
        let t = CertTime::from_timestamp(ts);
        assert_eq!(t.year, 2024);
        assert_eq!(t.month, 3);
        assert_eq!(t.day, 15);
        assert_eq!(t.hour, 11);
        assert_eq!(t.min, 34);
        assert_eq!(t.sec, 56);
    }

    #[test]
    fn test_certtime_from_timestamp_midnight() {
        // A known midnight: 2020-01-01 00:00:00 = 1577836800
        let t = CertTime::from_timestamp(1577836800);
        assert_eq!(t.year, 2020);
        assert_eq!(t.month, 1);
        assert_eq!(t.day, 1);
        assert_eq!(t.hour, 0);
        assert_eq!(t.min, 0);
        assert_eq!(t.sec, 0);
    }

    // ── CertTime::format ──────────────────────────────────────────────────────

    #[test]
    fn test_certtime_format_iso() {
        let t = CertTime::from_timestamp(0);
        assert_eq!(t.format("%Y-%m-%d"), "1970-01-01");
        assert_eq!(t.format("%H:%M:%S"), "00:00:00");
    }

    #[test]
    fn test_certtime_format_combined() {
        let t = CertTime::from_timestamp(1710502496);
        assert_eq!(t.format("%Y-%m-%d %H:%M:%S"), "2024-03-15 11:34:56");
    }

    #[test]
    fn test_certtime_format_zero_padding() {
        // 946857903 = 2000-01-03 00:05:03 UTC
        let ts = 946_857_903_i64;
        let t = CertTime::from_timestamp(ts);
        let formatted = t.format("%Y-%m-%d %H:%M:%S");
        assert_eq!(&formatted[5..7], "01"); // month
        assert_eq!(&formatted[8..10], "03"); // day
    }

    #[test]
    fn test_certtime_display() {
        let t = CertTime::from_timestamp(0);
        assert_eq!(t.to_string(), "1970-01-01 00:00:00");
    }
}
