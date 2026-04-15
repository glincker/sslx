use anyhow::Result;

use crate::cert::tls;
use crate::output::colors;
use crate::output::json::{JsonCert, JsonCertOutput, JsonConnectionOutput};
use crate::output::terminal;

pub struct ConnectOptions<'a> {
    pub host: &'a str,
    pub port: u16,
    pub sni: Option<&'a str>,
    pub alpn: Option<&'a [String]>,
    pub timeout: u64,
    pub insecure: bool,
    pub json: bool,
    pub no_color: bool,
}

pub fn run(opts: ConnectOptions<'_>) -> Result<i32> {
    let info = tls::connect(
        opts.host,
        opts.port,
        opts.sni,
        opts.alpn,
        opts.timeout,
        opts.insecure,
    )?;
    let use_color = !opts.no_color && !opts.json && colors::should_color();

    if opts.json {
        let output = JsonConnectionOutput {
            host: info.host.clone(),
            port: info.port,
            tls_version: info.tls_version.clone(),
            cipher_suite: info.cipher_suite.clone(),
            alpn: info.alpn.clone(),
            chain: JsonCertOutput {
                certificates: info.peer_certs.iter().map(JsonCert::from).collect(),
            },
        };
        println!("{}", serde_json::to_string_pretty(&output)?);
    } else {
        println!(
            "{}",
            terminal::render_connection_header(
                &info.host,
                info.port,
                &info.tls_version,
                &info.cipher_suite,
                info.alpn.as_deref(),
                use_color,
            )
        );

        let total = info.peer_certs.len();
        for (i, cert) in info.peer_certs.iter().enumerate() {
            println!("{}", terminal::render_cert(cert, i, total, use_color));
            if i < total - 1 {
                println!("{}", terminal::render_chain_arrow(use_color));
            }
        }
    }

    if info.peer_certs.iter().any(|c| c.is_expired()) {
        Ok(1)
    } else {
        Ok(0)
    }
}
