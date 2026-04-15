<p align="center">
  <h1 align="center">sslx</h1>
  <p align="center">Inspect, verify, and manage TLS certificates from the terminal.</p>
</p>

<p align="center">
  <a href="https://crates.io/crates/sslx"><img src="https://img.shields.io/crates/v/sslx.svg" alt="crates.io"></a>
  <a href="https://github.com/glincker/sslx/actions"><img src="https://github.com/glincker/sslx/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://github.com/glincker/sslx/blob/main/LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="License"></a>
  <a href="https://crates.io/crates/sslx"><img src="https://img.shields.io/crates/d/sslx.svg" alt="Downloads"></a>
</p>

---

```
$ sslx grade github.com

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

## Install

```bash
cargo install sslx
```

Or download a prebuilt binary from [releases](https://github.com/glincker/sslx/releases).

Homebrew:
```bash
brew install glincker/tap/sslx
```

## What it does

sslx replaces the OpenSSL commands you keep looking up.

```bash
# instead of: openssl x509 -in cert.pem -text -noout
sslx inspect cert.pem

# instead of: openssl s_client -connect host:443 2>/dev/null | openssl x509 -text
sslx connect example.com

# instead of: openssl verify -CAfile ca.pem cert.pem
sslx verify cert.pem --ca ca.pem

# instead of: openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 ...
sslx generate --cn localhost
```

### Check expiry across multiple hosts

```
$ sslx expiry google.com github.com cloudflare.com

  Host                           Expires          Days  Status
  ────────────────────────────────────────────────────────────────
  ✓ google.com:443                 2026-06-15         61  OK
  ✓ github.com:443                 2026-06-03         49  OK
  ✓ cloudflare.com:443             2026-06-10         56  OK
```

Exit code is 1 if anything is expiring within 7 days, so you can use it in CI or cron.

### Inspect certificates

```
$ sslx inspect cert.pem

╭─ Certificate 1 of 1 ──────────────────────────────────╮
│  Subject:  CN=*.example.com                             │
│  Issuer:   CN=Let's Encrypt Authority X3                │
│                                                         │
│  Valid:    2026-01-15 → 2026-04-15                      │
│  Expires:  ██░░░░░░░░  12 days remaining [!]            │
│                                                         │
│  Key:      ECDSA P-256 (256 bit)                        │
│  SANs:     *.example.com, example.com                   │
╰──────────────────────────────────────────────────────────╯
```

### Decode JWTs

```
$ sslx decode eyJhbGciOiJIUzI1...

  ✓ Detected: JSON Web Token (JWT)

    Header:   {"alg":"HS256","typ":"JWT"}
    Payload:  {"sub":"1234567890","name":"John","iat":1516239022}
```

## All commands

| Command | What it does |
|---------|-------------|
| `inspect <file>` | Parse and display a certificate |
| `connect <host>` | TLS handshake details and cert chain |
| `verify <file>` | Verify a certificate chain |
| `generate` | Generate a self-signed cert for local dev |
| `grade <host>` | TLS security grade (A+ to F) |
| `expiry <hosts...>` | Check expiry across multiple hosts |
| `convert <file>` | Convert between PEM, DER, PKCS12 |
| `match <cert> <key>` | Check that a cert and key are a pair |
| `extract <file>` | Extract certs from a PKCS12 bundle |
| `csr` | Generate a certificate signing request |
| `decode <file\|token>` | Auto-detect PEM, DER, JWT, etc. |

All commands support `--json` for scripting:

```bash
sslx connect example.com --json | jq '.chain.certificates[0].days_remaining'
```

## Benchmarks

Median of 10 runs on macOS M2:

| Operation | sslx | openssl |
|-----------|------|---------|
| Inspect cert | 2.1ms | 9.4ms |
| Generate cert | 1.7ms | 4.5ms |
| Startup | 1.3ms | - |

Built with [rustls](https://github.com/rustls/rustls). No system OpenSSL dependency.

## Shell completions

```bash
sslx completions bash > /etc/bash_completion.d/sslx
sslx completions zsh > ~/.zsh/completions/_sslx
sslx completions fish > ~/.config/fish/completions/sslx.fish
```

## License

MIT
