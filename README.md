# sslx

The modern way to work with certificates and TLS.

A fast, beautiful replacement for common `openssl` commands. Single binary, zero config, pure Rust.

## Why

Every developer googles OpenSSL flags. Every. Single. Time.

```bash
# Before (openssl)
openssl s_client -connect google.com:443 -servername google.com 2>/dev/null | openssl x509 -noout -text | grep -A2 "Validity"

# After (sslx)
sslx connect google.com
```

## Install

```bash
# Homebrew
brew install glincker/tap/sslx

# Cargo
cargo install sslx

# Binary (macOS/Linux/Windows)
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

### Test a TLS connection

```bash
sslx connect google.com
```

Shows TLS version, cipher suite, ALPN protocol, and the full certificate chain with expiry status.

### Verify a certificate chain

```bash
sslx verify cert.pem --ca ca-bundle.pem
```

```
  ✓ Certificate is valid
    Chain:    complete (3 certs)
    Expiry:   328 days remaining
```

### Generate a self-signed certificate

```bash
sslx generate --cn localhost --san "*.local,127.0.0.1"
```

```
  ✓ Certificate generated

    cert.pem     EC P-256 certificate
    key.pem      EC P-256 private key

    Subject:  CN=localhost
    SANs:     localhost, *.local, 127.0.0.1
    Valid:    365 days
```

## JSON output

Every command supports `--json` for scripting and CI:

```bash
sslx connect google.com --json | jq '.chain.certificates[0].days_remaining'
```

## Exit codes

| Code | Meaning |
|------|---------|
| 0 | Certificate valid |
| 1 | Certificate expired |
| 2 | Certificate not yet valid |
| 3 | Chain incomplete or untrusted |
| 4 | Connection failed |
| 5 | File parse error |

## TLS security grade

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

## Multi-host expiry check

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

## More commands

```bash
sslx convert cert.der --to pem         # Format conversion (PEM/DER/PKCS12)
sslx match cert.pem key.pem            # Verify cert and key are a pair
sslx extract bundle.p12                # Extract certs from PKCS12
sslx csr --cn example.com             # Generate a CSR
sslx decode mystery-file.pem          # Auto-detect and decode any crypto file
sslx decode eyJhbGciOi...             # Decode JWT tokens
```

## Comparison

| Task | openssl | sslx |
|------|---------|------|
| Inspect cert | `openssl x509 -in cert.pem -text -noout` | `sslx inspect cert.pem` |
| Test TLS | `openssl s_client -connect host:443 2>/dev/null \| openssl x509 -text` | `sslx connect host` |
| Verify chain | `openssl verify -CAfile ca.pem cert.pem` | `sslx verify cert.pem --ca ca.pem` |
| Generate cert | `openssl req -x509 -newkey ec -pkeyopt...` | `sslx generate --cn localhost` |
| Create CSR | `openssl req -new -newkey ec...` | `sslx csr --cn example.com` |
| Convert format | `openssl x509 -in cert.pem -outform DER...` | `sslx convert cert.pem --to der` |
| Check expiry | `openssl s_client ... \| openssl x509 -enddate` | `sslx expiry host1 host2 host3` |
| TLS grade | *(use SSL Labs website)* | `sslx grade example.com` |
| Match cert+key | `diff <(openssl x509 -modulus...) <(openssl rsa -modulus...)` | `sslx match cert.pem key.pem` |
| Decode JWT | *(use jwt.io website)* | `sslx decode <token>` |

## Benchmarks

Measured on macOS, median of 10 runs:

| Operation | sslx | openssl | Speedup |
|-----------|------|---------|---------|
| Inspect PEM certificate | 2.1ms | 9.4ms | **4.4x faster** |
| Generate self-signed cert | 1.7ms | 4.5ms | **2.7x faster** |
| Startup time | 1.3ms | — | — |
| Binary size | 3.9MB | ~893KB + libssl | — |

Pure Rust (rustls). Zero system OpenSSL dependency. Runs the same everywhere.

## Shell completions

```bash
sslx completions bash > /etc/bash_completion.d/sslx
sslx completions zsh > ~/.zsh/completions/_sslx
sslx completions fish > ~/.config/fish/completions/sslx.fish
```

## License

MIT
