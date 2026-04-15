<p align="center">
  <h1 align="center">sslx</h1>
  <p align="center">openssl, but you don't have to google the flags</p>
</p>

<p align="center">
  <a href="https://crates.io/crates/sslx"><img src="https://img.shields.io/crates/v/sslx.svg" alt="crates.io"></a>
  <a href="https://github.com/glincker/sslx/actions"><img src="https://github.com/glincker/sslx/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://github.com/glincker/sslx/blob/main/LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="License"></a>
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

Prebuilt binaries on the [releases page](https://github.com/glincker/sslx/releases). Homebrew: `brew install glincker/tap/sslx`

## Examples

The openssl command you can never remember vs sslx:

```bash
# openssl x509 -in cert.pem -text -noout
sslx inspect cert.pem

# openssl s_client -connect host:443 2>/dev/null | openssl x509 -text
sslx connect example.com

# openssl verify -CAfile ca.pem cert.pem
sslx verify cert.pem --ca ca.pem

# openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 ...
sslx generate --cn localhost
```

Check cert expiry on a bunch of hosts at once:

```
$ sslx expiry google.com github.com cloudflare.com

  Host                           Expires          Days  Status
  ────────────────────────────────────────────────────────────────
  ✓ google.com:443                 2026-06-15         61  OK
  ✓ github.com:443                 2026-06-03         49  OK
  ✓ cloudflare.com:443             2026-06-10         56  OK
```

Returns exit code 1 if anything expires within 7 days, so it works in cron/CI.

Look at a cert file:

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

Throw a JWT at it and it figures it out:

```
$ sslx decode eyJhbGciOiJIUzI1...

  ✓ Detected: JSON Web Token (JWT)

    Header:   {"alg":"HS256","typ":"JWT"}
    Payload:  {"sub":"1234567890","name":"John","iat":1516239022}
```

## Commands

| Command | |
|---------|---|
| `inspect <file>` | show cert details |
| `connect <host>` | TLS handshake + cert chain |
| `verify <file>` | check a cert chain |
| `generate` | self-signed cert |
| `grade <host>` | A+ to F TLS grade |
| `expiry <hosts...>` | cert expiry check |
| `convert <file>` | PEM/DER/PKCS12 conversion |
| `match <cert> <key>` | cert+key pair check |
| `extract <file>` | pull certs out of a .p12 |
| `csr` | certificate signing request |
| `decode <file\|token>` | figure out what a file is |

Everything supports `--json`:

```bash
sslx connect example.com --json | jq '.chain.certificates[0].days_remaining'
```

## Speed

| | sslx | openssl |
|---|------|---------|
| inspect cert | 2.1ms | 9.4ms |
| generate cert | 1.7ms | 4.5ms |
| cold start | 1.3ms | |

Uses [rustls](https://github.com/rustls/rustls), not system OpenSSL.

## Shell completions

```bash
sslx completions bash > /etc/bash_completion.d/sslx
sslx completions zsh > ~/.zsh/completions/_sslx
sslx completions fish > ~/.config/fish/completions/sslx.fish
```

## License

MIT
