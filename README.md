# sslx

A command-line tool for inspecting, generating, and verifying TLS certificates and connections.

## Install

```bash
cargo install sslx
```

Homebrew:

```bash
brew install glincker/tap/sslx
```

Binary download (macOS/Linux):

```bash
curl -fsSL https://github.com/glincker/sslx/releases/latest/download/sslx-$(uname -s)-$(uname -m) -o sslx
chmod +x sslx
```

## Usage

### Inspect a certificate file

```bash
sslx inspect cert.pem
```

```
╭─ Certificate 1 of 1 ──────────────────────────────────╮
│  Subject:  CN=*.example.com                             │
│  Issuer:   CN=Let's Encrypt Authority X3                │
│  Serial:   0A:1B:2C:3D...                               │
│                                                         │
│  Valid:    2026-01-15 → 2026-04-15                      │
│  Expires:  ██░░░░░░░░  12 days remaining [!]            │
│                                                         │
│  Key:      ECDSA P-256 (256 bit)                        │
│  SANs:     *.example.com, example.com                   │
│  SHA-256:  AB:CD:EF:12:34...                            │
╰──────────────────────────────────────────────────────────╯
```

### Test a live TLS connection

```bash
sslx connect google.com
```

Shows TLS version, cipher suite, ALPN protocol, and the full certificate chain with expiry status.

### Check expiry across multiple hosts

```bash
sslx expiry google.com github.com cloudflare.com
```

```
  Host                           Expires          Days  Status
  ────────────────────────────────────────────────────────────────
  ✓ google.com:443                 2026-06-15         61  OK
  ✓ github.com:443                 2026-06-03         49  OK
  ✓ cloudflare.com:443             2026-06-10         56  OK
```

### TLS security grade

```bash
sslx grade github.com
```

```
  ╭──────────────────────────────────────────╮
  │  github.com:443                  Grade: A+  │
  ╰──────────────────────────────────────────╯

  ✓ Protocol      TLS 1.3
  ✓ Cipher        TLS13_AES_128_GCM_SHA256 (AEAD)
  ✓ Certificate   Valid, 49 days remaining
  ✓ Key           ECDSA P-256 (256 bit)
  ✓ Hostname      github.com in SANs
  ✓ Chain         Complete (3 certs)
  ✓ ALPN          HTTP/2 supported
```

## Commands

| Command | Description |
|---------|-------------|
| `inspect <file>` | Parse and display a certificate file |
| `connect <host>` | Connect and show TLS handshake details |
| `verify <file>` | Verify a certificate chain |
| `generate` | Generate a self-signed certificate |
| `grade <host>` | Rate the TLS configuration of a host |
| `expiry <host...>` | Check expiry across multiple hosts |
| `convert <file>` | Convert between PEM, DER, and PKCS12 |
| `match <cert> <key>` | Check that a cert and key are a pair |
| `extract <file>` | Extract certs from a PKCS12 bundle |
| `csr` | Generate a certificate signing request |
| `decode <file|token>` | Decode PEM files or JWT tokens |
| `completions <shell>` | Print shell completions |

## JSON output

All commands support `--json` for scripting and CI:

```bash
sslx connect google.com --json | jq '.chain.certificates[0].days_remaining'
```

## Exit codes

| Code | Meaning |
|------|---------|
| 0 | Success / certificate valid |
| 1 | Certificate expired |
| 2 | Certificate not yet valid |
| 3 | Chain incomplete or untrusted |
| 4 | Connection failed |
| 5 | File parse error |

## Benchmarks

Measured on macOS M2, median of 10 runs (hyperfine):

| Operation | sslx | openssl |
|-----------|------|---------|
| Inspect PEM certificate | 2.1ms | 9.4ms |
| Generate self-signed cert | 1.7ms | 4.5ms |
| Startup time | 1.3ms | - |
| Binary size | 3.9MB | ~893KB + libssl |

Built with rustls. No system OpenSSL dependency.

## Shell completions

```bash
sslx completions bash > /etc/bash_completion.d/sslx
sslx completions zsh > ~/.zsh/completions/_sslx
sslx completions fish > ~/.config/fish/completions/sslx.fish
```

## License

MIT
