use anyhow::{Context, Result};
use rustls::pki_types::ServerName;
use std::io::Write;
use std::net::TcpStream;
use std::sync::Arc;
use std::time::Duration;

use crate::cert::parser::parse_der_cert;
use crate::cert::CertInfo;

/// TLS connection result
pub struct TlsConnectionInfo {
    pub host: String,
    pub port: u16,
    pub tls_version: String,
    pub cipher_suite: String,
    pub alpn: Option<String>,
    pub peer_certs: Vec<CertInfo>,
}

/// Connect to a host via TLS and extract connection + cert info
pub fn connect(
    host: &str,
    port: u16,
    sni: Option<&str>,
    alpn: Option<&[String]>,
    timeout_secs: u64,
    insecure: bool,
) -> Result<TlsConnectionInfo> {
    let sni_name = sni.unwrap_or(host);
    let server_name = ServerName::try_from(sni_name.to_string())
        .map_err(|_| anyhow::anyhow!("Invalid server name: {}", sni_name))?;

    // Build TLS config
    let mut config = if insecure {
        rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerifier))
            .with_no_client_auth()
    } else {
        let root_store =
            rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth()
    };

    // Set ALPN if requested
    if let Some(protos) = alpn {
        config.alpn_protocols = protos.iter().map(|p| p.as_bytes().to_vec()).collect();
    } else {
        // Default: try h2 and http/1.1
        config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    }

    let config = Arc::new(config);

    // TCP connect with timeout
    let addr = format!("{}:{}", host, port);
    let tcp = TcpStream::connect_timeout(
        &addr.parse().or_else(|_| {
            // Try DNS resolution
            use std::net::ToSocketAddrs;
            addr.to_socket_addrs()
                .ok()
                .and_then(|mut addrs| addrs.next())
                .ok_or_else(|| anyhow::anyhow!("DNS resolution failed"))
        })?,
        Duration::from_secs(timeout_secs),
    )
    .with_context(|| format!("Failed to connect to {}:{}", host, port))?;

    tcp.set_read_timeout(Some(Duration::from_secs(timeout_secs)))?;
    tcp.set_write_timeout(Some(Duration::from_secs(timeout_secs)))?;

    // TLS handshake
    let mut conn = rustls::ClientConnection::new(config, server_name)
        .context("Failed to create TLS connection")?;

    let mut tcp_ref = &tcp;
    let mut tls_stream = rustls::Stream::new(&mut conn, &mut tcp_ref);

    // Complete handshake
    tls_stream.flush().ok();
    let _ = tls_stream;

    // Extract TLS info
    let tls_version = conn
        .protocol_version()
        .map(|v| {
            let s = format!("{:?}", v);
            // Convert "TLSv1_3" to "TLS 1.3"
            s.replace("TLSv1_", "TLS 1.")
        })
        .unwrap_or_else(|| "Unknown".to_string());

    let cipher_suite = conn
        .negotiated_cipher_suite()
        .map(|cs| format!("{:?}", cs.suite()))
        .unwrap_or_else(|| "Unknown".to_string());

    let alpn_proto = conn
        .alpn_protocol()
        .map(|p| String::from_utf8_lossy(p).to_string());

    // Extract peer certificates
    let peer_certs: Vec<CertInfo> = conn
        .peer_certificates()
        .unwrap_or(&[])
        .iter()
        .filter_map(|cert| parse_der_cert(cert.as_ref()).ok())
        .collect();

    Ok(TlsConnectionInfo {
        host: host.to_string(),
        port,
        tls_version,
        cipher_suite,
        alpn: alpn_proto,
        peer_certs,
    })
}

/// Certificate verifier that accepts anything (for --insecure)
#[derive(Debug)]
struct NoVerifier;

impl rustls::client::danger::ServerCertVerifier for NoVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA512,
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA384,
            rustls::SignatureScheme::RSA_PKCS1_SHA512,
            rustls::SignatureScheme::ED25519,
        ]
    }
}
