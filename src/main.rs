use clap::{Parser, Subcommand};
use std::process;

mod cert;
mod commands;
mod output;

#[derive(Parser)]
#[command(
    name = "sslx",
    about = "The modern way to work with certificates and TLS",
    version,
    after_help = "Examples:\n  \
        sslx inspect cert.pem          Read a certificate file\n  \
        sslx connect google.com        Test TLS connection\n  \
        sslx verify cert.pem --ca ca   Validate certificate chain\n  \
        sslx generate --cn localhost   Create a self-signed cert"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// Output as JSON
    #[arg(long, global = true)]
    json: bool,

    /// Disable colored output
    #[arg(long, global = true)]
    no_color: bool,
}

#[derive(Subcommand)]
enum Commands {
    /// Read and display certificate file details
    Inspect {
        /// Path to certificate file (PEM, DER, or PKCS12)
        file: String,
    },

    /// Test TLS connection and show certificate chain
    Connect {
        /// Hostname or host:port to connect to
        host: String,

        /// Override SNI hostname
        #[arg(long)]
        sni: Option<String>,

        /// ALPN protocols (comma-separated)
        #[arg(long)]
        alpn: Option<String>,

        /// Connection timeout in seconds
        #[arg(long, default_value = "10")]
        timeout: u64,

        /// Skip certificate verification (still shows issues)
        #[arg(long)]
        insecure: bool,
    },

    /// Validate certificate against CA bundle
    Verify {
        /// Path to certificate to verify
        cert: String,

        /// Path to CA bundle or certificate
        #[arg(long)]
        ca: String,
    },

    /// Generate a self-signed certificate for local development
    Generate {
        /// Common Name
        #[arg(long, default_value = "localhost")]
        cn: String,

        /// Subject Alternative Names (comma-separated)
        #[arg(long, value_delimiter = ',')]
        san: Vec<String>,

        /// Validity period in days
        #[arg(long, default_value = "365")]
        days: u32,

        /// Key type: ec256 (default), ec384, ed25519
        #[arg(long, default_value = "ec256")]
        key_type: String,

        /// Output directory
        #[arg(short, long, default_value = ".")]
        out: String,
    },
}

fn main() {
    let cli = Cli::parse();

    let exit_code = match run(cli) {
        Ok(code) => code,
        Err(e) => {
            let use_color = output::colors::should_color();
            if use_color {
                eprintln!(
                    "\n  {}{}error:{} {}",
                    output::colors::BOLD_RED,
                    output::box_chars::CROSS,
                    output::colors::RESET,
                    e
                );
            } else {
                eprintln!("\n  error: {}", e);
            }

            // Print cause chain
            let mut source: Option<&dyn std::error::Error> = e.source();
            while let Some(cause) = source {
                if use_color {
                    eprintln!(
                        "    {}{}{}",
                        output::colors::DIM,
                        cause,
                        output::colors::RESET
                    );
                } else {
                    eprintln!("    {}", cause);
                }
                source = cause.source();
            }
            eprintln!();

            10 // usage/general error
        }
    };

    process::exit(exit_code);
}

fn run(cli: Cli) -> anyhow::Result<i32> {
    match cli.command {
        Commands::Inspect { file } => commands::inspect::run(&file, cli.json, cli.no_color),
        Commands::Connect {
            host,
            sni,
            alpn,
            timeout,
            insecure,
        } => {
            let (host, port) = parse_host_port(&host);
            let alpn_protos: Option<Vec<String>> =
                alpn.map(|a| a.split(',').map(|s| s.trim().to_string()).collect());
            commands::connect::run(commands::connect::ConnectOptions {
                host: &host,
                port,
                sni: sni.as_deref(),
                alpn: alpn_protos.as_deref(),
                timeout,
                insecure,
                json: cli.json,
                no_color: cli.no_color,
            })
        }
        Commands::Verify { cert, ca } => commands::verify::run(&cert, &ca, cli.json, cli.no_color),
        Commands::Generate {
            cn,
            san,
            days,
            key_type,
            out,
        } => commands::generate::run(&cn, &san, days, &key_type, &out, cli.json, cli.no_color),
    }
}

/// Parse "host:port" or just "host" (defaults to 443)
fn parse_host_port(input: &str) -> (String, u16) {
    if let Some((host, port_str)) = input.rsplit_once(':') {
        if let Ok(port) = port_str.parse::<u16>() {
            return (host.to_string(), port);
        }
    }
    (input.to_string(), 443)
}
