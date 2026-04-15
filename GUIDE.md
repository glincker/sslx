# User Guide

This covers the main workflows. Run `sslx --help` or `sslx <command> --help` for full flag details.

## Checking a live server

### Quick look

```bash
sslx connect example.com
```

Shows the TLS version, cipher suite, ALPN protocol, and the full certificate chain. Default port is 443. Use `host:port` for other ports:

```bash
sslx connect mail.example.com:587
```

### TLS grade

```bash
sslx grade example.com
```

Checks protocol version, cipher strength, certificate validity, key type, hostname matching, chain completeness, and ALPN. Scores from A+ to F.

Use `--json` to get the grade programmatically:

```bash
sslx grade example.com --json | jq '.grade'
```

### Expiry monitoring

Check multiple hosts at once:

```bash
sslx expiry host1.example.com host2.example.com host3.example.com
```

Exit code is 1 if any cert expires within 7 days. Put this in a cron job:

```bash
# check every morning at 8am
0 8 * * * /usr/local/bin/sslx expiry prod.example.com api.example.com || notify-send "cert expiring"
```

## Working with cert files

### Inspect a cert

```bash
sslx inspect cert.pem
```

Handles PEM and DER. If the file has multiple certs (like a bundle), all are shown with chain arrows between them.

### Verify a cert chain

```bash
sslx verify cert.pem --ca ca-bundle.pem
```

Checks that the cert is signed by the CA, not expired, and the chain is complete. If something is wrong, the error message tells you what to fix.

### Check if cert and key match

```bash
sslx match cert.pem key.pem
```

Compares the public key in the cert with the public key derived from the private key. Useful after copying certs between servers.

## Generating certs

### Self-signed cert for local dev

```bash
sslx generate --cn localhost
```

Creates `cert.pem` and `key.pem` in the current directory. EC P-256 by default.

Add SANs:

```bash
sslx generate --cn myapp.local --san "*.myapp.local,192.168.1.100"
```

Change key type:

```bash
sslx generate --cn localhost --key-type ed25519
```

Available types: `ec256` (default), `ec384`, `ed25519`.

### Create a CSR

```bash
sslx csr --cn example.com --san "*.example.com,api.example.com"
```

Creates `csr.pem` and `key.pem`. Submit the CSR to your certificate authority.

## Format conversion

### PEM to DER

```bash
sslx convert cert.pem --to der
```

### DER to PEM

```bash
sslx convert cert.der --to pem
```

### Extract certs from PKCS12

```bash
sslx extract bundle.p12 --password mypass --out ./certs
```

Writes the leaf cert, intermediates (if any), and notes if a private key was found.

### Convert PKCS12 to PEM

```bash
sslx convert bundle.p12 --to pem --password mypass
```

## Decoding unknown files

Don't know what a file is? Throw it at decode:

```bash
sslx decode mystery-file.pem
```

It auto-detects: PEM certificates, DER certificates, private keys (RSA, EC, PKCS8), public keys, CSRs, and JWT tokens.

### JWT tokens

Paste a JWT directly:

```bash
sslx decode eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyMTIzIn0.signature
```

Shows the header, payload, and expiry time if present.

## JSON output

Every command supports `--json`. Some examples:

```bash
# days until cert expires
sslx inspect cert.pem --json | jq '.certificates[0].days_remaining'

# all SANs on a host
sslx connect example.com --json | jq '.chain.certificates[0].sans'

# is the cert expired?
sslx inspect cert.pem --json | jq '.certificates[0].is_expired'

# TLS grade as a string
sslx grade example.com --json | jq -r '.grade'
```

## Exit codes

| Code | Meaning |
|------|---------|
| 0 | ok |
| 1 | cert expired or expiring soon |
| 3 | chain untrusted or incomplete |
| 4 | connection failed |
| 5 | file format error |
| 10 | bad arguments |

These work with set -e in shell scripts and CI pipelines.

## Shell completions

Generate completions for your shell:

```bash
# bash
sslx completions bash > /etc/bash_completion.d/sslx

# zsh
sslx completions zsh > ~/.zsh/completions/_sslx

# fish
sslx completions fish > ~/.config/fish/completions/sslx.fish
```
