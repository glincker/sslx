use clap::{CommandFactory, Parser, Subcommand};
use std::process;

mod cert;
mod commands;
mod output;

use output::util::parse_host_port;

#[derive(Parser)]
#[command(
    name = "sslx",
    about = "The modern way to work with certificates and TLS",
    version,
    after_help = "Examples:\n  \
        sslx inspect cert.pem          Read a certificate file\n  \
        sslx inspect -                 Read a certificate from stdin\n  \
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

    /// Verbose output
    #[arg(long, global = true)]
    verbose: bool,

    /// Disable colored output
    #[arg(long, global = true)]
    no_color: bool,
}

#[derive(Subcommand)]
enum Commands {
    /// Read and display certificate file details
    Inspect {
        /// Path to certificate file (PEM or DER), or - to read from stdin
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

    /// Convert between certificate formats (PEM, DER, PKCS12)
    Convert {
        /// Input file path
        input: String,

        /// Target format: pem, der, pkcs12
        #[arg(long)]
        to: String,

        /// Private key file (required for PKCS12 export)
        #[arg(long)]
        key: Option<String>,

        /// Password for PKCS12
        #[arg(long)]
        password: Option<String>,

        /// Output file path (auto-generated if omitted)
        #[arg(short, long)]
        out: Option<String>,
    },

    /// Check if a certificate and private key match
    #[command(name = "match")]
    Match {
        /// Path to certificate file
        cert: String,

        /// Path to private key file
        key: String,
    },

    /// Extract cert, key, and chain from a PKCS12 file
    Extract {
        /// Path to .p12/.pfx file
        input: String,

        /// PKCS12 password
        #[arg(long)]
        password: Option<String>,

        /// Output directory
        #[arg(short, long, default_value = ".")]
        out: String,
    },

    /// Generate a Certificate Signing Request (CSR)
    Csr {
        /// Common Name
        #[arg(long)]
        cn: String,

        /// Subject Alternative Names (comma-separated)
        #[arg(long, value_delimiter = ',')]
        san: Vec<String>,

        /// Key type: ec256 (default), ec384, ed25519
        #[arg(long, default_value = "ec256")]
        key_type: String,

        /// Output directory
        #[arg(short, long, default_value = ".")]
        out: String,
    },

    /// Auto-detect and decode any crypto file (cert, key, CSR, JWT)
    Decode {
        /// File path, inline string (e.g., JWT token), or - to read from stdin
        input: String,
    },

    /// TLS security grade (A+ to F) like SSL Labs
    Grade {
        /// Hostname or host:port
        host: String,
    },

    /// Check certificate expiry across multiple hosts
    Expiry {
        /// One or more hostnames (or host:port)
        hosts: Vec<String>,
    },

    /// Generate shell completions
    #[command(hide = true)]
    Completions {
        /// Shell type: bash, zsh, fish, powershell
        shell: clap_complete::Shell,
    },

    /// Generate man page
    #[command(hide = true)]
    Manpage,
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
        Commands::Inspect { file } => {
            commands::inspect::run(&file, cli.json, cli.verbose, cli.no_color)
        }
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
        Commands::Convert {
            input,
            to,
            key,
            password,
            out,
        } => commands::convert::run(
            &input,
            &to,
            key.as_deref(),
            password.as_deref(),
            out.as_deref(),
            cli.json,
            cli.no_color,
        ),
        Commands::Match { cert, key } => {
            commands::match_cmd::run(&cert, &key, cli.json, cli.no_color)
        }
        Commands::Extract {
            input,
            password,
            out,
        } => commands::extract::run(&input, password.as_deref(), &out, cli.json, cli.no_color),
        Commands::Csr {
            cn,
            san,
            key_type,
            out,
        } => commands::csr::run(&cn, &san, &key_type, &out, cli.json, cli.no_color),
        Commands::Decode { input } => commands::decode::run(&input, cli.json, cli.no_color),
        Commands::Grade { host } => {
            let (host, port) = parse_host_port(&host);
            commands::grade::run(&host, port, cli.json, cli.no_color)
        }
        Commands::Expiry { hosts } => commands::expiry::run(&hosts, cli.json, cli.no_color),
        Commands::Completions { shell } => {
            clap_complete::generate(shell, &mut Cli::command(), "sslx", &mut std::io::stdout());
            Ok(0)
        }
        Commands::Manpage => {
            let cmd = Cli::command();
            let man = clap_mangen::Man::new(cmd);
            man.render(&mut std::io::stdout())?;
            Ok(0)
        }
    }
}
