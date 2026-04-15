# FAQ

## How is sslx different from openssl?

openssl is a cryptographic library with a CLI bolted on. It does everything (TLS, symmetric crypto, PKCS, ASN.1, etc) but the CLI syntax is inconsistent and hard to remember.

sslx only does certificate and TLS operations. It's a single binary with consistent flags, colored output, and commands you can actually remember.

sslx also does things openssl can't do from the CLI, like TLS grading (A+ to F), multi-host expiry checks, and JWT decoding.

## How is sslx different from step-cli?

step-cli is a full PKI toolkit with an ACME server, SSH certificates, OIDC token handling, and more. It's 80MB+ and has a lot of features most people don't need.

sslx is smaller (4MB), focused on the common tasks, and doesn't require any setup. If you need a CA server or SSH certificates, use step. If you just want to check a cert or grade a TLS connection, sslx is faster to reach for.

## How is sslx different from mkcert?

mkcert does one thing: generate locally-trusted certificates for development. It's great at that.

sslx generates self-signed certs too (sslx generate), but it also inspects, connects, grades, converts, and checks expiry. If you need mkcert's trust store integration (installing a root CA into your browser), use mkcert. sslx might add that in a future version.

## Does sslx use OpenSSL?

No. sslx is built with rustls, a TLS library written in Rust. There's no dependency on system OpenSSL at all. The binary is fully static and works the same everywhere.

## Can I use sslx in CI/CD?

Yes. Every command returns meaningful exit codes (0 for ok, 1 for expired, etc) and supports --json for machine-readable output.

```bash
# fail the build if any cert expires within 7 days
sslx expiry staging.example.com prod.example.com

# get structured data
sslx grade example.com --json | jq '.grade'
```

## What cert formats does sslx support?

PEM, DER, and PKCS12 (.p12/.pfx) for reading. PEM and DER for writing. Auto-detection works for all three, or you can force a format with flags.

## Is sslx safe to use with production certificates?

sslx reads certificates, it doesn't modify them. Private keys are only handled during generation (sslx generate, sslx csr) and are written to local files. sslx never sends your keys or certs anywhere.
