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

## Comparison

| Task | openssl | sslx |
|------|---------|------|
| Inspect cert | `openssl x509 -in cert.pem -text -noout` | `sslx inspect cert.pem` |
| Test TLS | `openssl s_client -connect host:443` | `sslx connect host` |
| Verify chain | `openssl verify -CAfile ca.pem cert.pem` | `sslx verify cert.pem --ca ca.pem` |
| Generate cert | `openssl req -x509 -newkey ec -pkeyopt...` | `sslx generate --cn localhost` |
| Binary size | ~5MB + system dep | 3.3MB standalone |

## License

MIT
