# sslx

**openssl, but you don't have to google the flags.**

A single binary that handles certs, TLS connections, and all the stuff you normally need three different openssl invocations for. Built with Rust and [rustls](https://github.com/rustls/rustls), no system OpenSSL required.

[![crates.io](https://img.shields.io/crates/v/sslx.svg)](https://crates.io/crates/sslx)
[![CI](https://github.com/glincker/sslx/actions/workflows/ci.yml/badge.svg)](https://github.com/glincker/sslx/actions)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](https://github.com/glincker/sslx/blob/main/LICENSE)

![sslx demo](demo.gif)

## Install

```bash
cargo install sslx
```

Prebuilt binaries on the [releases page](https://github.com/glincker/sslx/releases).

Homebrew:
```bash
brew install glincker/tap/sslx
```

Or download directly:
```bash
# macOS (Apple Silicon)
curl -fsSL https://github.com/glincker/sslx/releases/latest/download/sslx-macos-aarch64 -o sslx && chmod +x sslx

# Linux
curl -fsSL https://github.com/glincker/sslx/releases/latest/download/sslx-linux-x86_64 -o sslx && chmod +x sslx
```

## TLS grade

Rate the TLS setup of any host, like SSL Labs but from your terminal:

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

Checks protocol version, cipher strength, cert validity, key type, hostname matching, chain completeness, and ALPN. Gives you a letter grade from A+ to F.

## Expiry check

Check cert expiry on a bunch of hosts at once:

```
$ sslx expiry google.com github.com cloudflare.com stripe.com

  Host                           Expires          Days  Status
  ────────────────────────────────────────────────────────────────
  ✓ google.com:443                 2026-06-15         61  OK
  ✓ github.com:443                 2026-06-03         49  OK
  ✓ cloudflare.com:443             2026-06-10         56  OK
  ✓ stripe.com:443                 2026-09-01        139  OK
```

Exit code 1 if anything expires within 7 days. Useful in cron jobs or CI pipelines.

## Inspect certificates

Read a PEM or DER cert file with colored output:

```
$ sslx inspect cert.pem

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

Handles multi-cert bundles too. Auto-detects PEM vs DER.

## Connect to a host

See the full TLS handshake details and cert chain for any host:

```
$ sslx connect example.com

Connection to example.com:443

  TLS 1.3 · TLS13_AES_256_GCM_SHA384
  ALPN: h2

  Chain:
  ╭─ Certificate 1 of 3 ─────────────────────────╮
  │  Subject:  CN=*.example.com                    │
  │  Valid:    61 days remaining ✓                 │
  │  Key:      ECDSA P-256 (256 bit)              │
  ╰────────────────────────────────────────────────╯
    ↓ signed by
  ╭─ Certificate 2 of 3 (CA) ────────────────────╮
  │  ...                                          │
  ╰────────────────────────────────────────────────╯
```

## Generate certs

Self-signed cert for local dev in one command:

```bash
sslx generate --cn localhost --san "*.local,127.0.0.1"
```

Creates `cert.pem` and `key.pem` with EC P-256 by default. Also supports `ec384` and `ed25519`.

## Generate a CSR

```bash
sslx csr --cn example.com --san "*.example.com,api.example.com"
```

Creates `csr.pem` and `key.pem`. Submit the CSR to your CA.

## Convert between formats

```bash
sslx convert cert.pem --to der           # PEM to DER
sslx convert cert.der --to pem           # DER to PEM
sslx convert bundle.p12 --to pem         # PKCS12 to PEM
```

Auto-detects input format.

## Check cert+key match

```
$ sslx match cert.pem key.pem

  ✓ Certificate and key match (ECDSA P-256 (256 bit))
```

No more comparing modulus hashes manually.

## Extract from PKCS12

```bash
sslx extract bundle.p12 --password mypass --out ./certs
```

Pulls out the leaf cert, intermediates, and key into separate PEM files.

## Decode anything

Throw a file or a JWT token at it and sslx figures out what it is:

```
$ sslx decode eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...

  ✓ Detected: JSON Web Token (JWT)

    Header:   {"alg":"HS256","typ":"JWT"}
    Payload:  {"sub":"1234567890","name":"John","iat":1516239022}
    Expires:  in 3 hours
```

Also detects PEM certs, DER files, private keys, public keys, and CSRs.

## Verify a chain

```bash
sslx verify cert.pem --ca ca-bundle.pem
```

```
  ✓ Certificate is valid
    Chain:    complete (3 certs)
    Expiry:   328 days remaining
```

Tells you exactly what's wrong if it fails, with hints on how to fix it.

## openssl vs sslx

| What you're doing | openssl | sslx |
|---|---|---|
| Look at a cert | `openssl x509 -in cert.pem -text -noout` | `sslx inspect cert.pem` |
| TLS handshake | `openssl s_client -connect host:443 2>/dev/null \| openssl x509 -text` | `sslx connect host` |
| Verify chain | `openssl verify -CAfile ca.pem cert.pem` | `sslx verify cert.pem --ca ca.pem` |
| Self-signed cert | `openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -keyout key.pem -out cert.pem -days 365 -nodes -batch -subj "/CN=localhost"` | `sslx generate --cn localhost` |
| Create CSR | `openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -keyout key.pem -out csr.pem -batch -subj "/CN=example.com"` | `sslx csr --cn example.com` |
| PEM to DER | `openssl x509 -in cert.pem -outform DER -out cert.der` | `sslx convert cert.pem --to der` |
| Check expiry | `echo \| openssl s_client -connect host:443 2>/dev/null \| openssl x509 -noout -enddate` | `sslx expiry host` |
| Cert+key match | `diff <(openssl x509 -noout -modulus -in cert.pem) <(openssl rsa -noout -modulus -in key.pem)` | `sslx match cert.pem key.pem` |
| TLS grade | (go to ssllabs.com) | `sslx grade host` |
| Decode JWT | (go to jwt.io) | `sslx decode <token>` |

## JSON output

Every command supports `--json` for scripting and CI:

```bash
# check days until expiry
sslx connect example.com --json | jq '.chain.certificates[0].days_remaining'

# get the grade
sslx grade example.com --json | jq '.grade'

# list all SANs
sslx inspect cert.pem --json | jq '.certificates[0].sans'
```

## Exit codes

| Code | Meaning |
|---|---|
| 0 | ok |
| 1 | cert expired or expiring |
| 3 | chain untrusted |
| 4 | connection failed |
| 5 | bad file |

## Benchmarks

Median of 10 runs on macOS M2:

| | sslx | openssl |
|---|---|---|
| inspect cert | 2.1ms | 9.4ms |
| generate cert | 1.7ms | 4.5ms |
| startup | 1.3ms | |

## Shell completions

```bash
sslx completions bash > /etc/bash_completion.d/sslx
sslx completions zsh > ~/.zsh/completions/_sslx
sslx completions fish > ~/.config/fish/completions/sslx.fish
```

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Bugs and feature requests go in [issues](https://github.com/glincker/sslx/issues).

## License

MIT
