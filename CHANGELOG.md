# Changelog

## 0.4.0
- Stdin support for inspect and decode (`cat cert.pem | sslx inspect -`)
- 40 unit tests for parser, grade scoring, and date logic
- 11 new integration tests
- Security audit (cargo-audit) in CI pipeline
- Bumped x509-parser, rcgen, clap_mangen, webpki-roots

## 0.3.1
- Published to crates.io
- Added benchmarks and shell completions

## 0.3.0
- Added `grade` and `expiry` commands

## 0.2.0
- Added `convert`, `match`, `extract`, `csr`, `decode` commands

## 0.1.0
- Initial release: `inspect`, `connect`, `verify`, `generate`
