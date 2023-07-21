# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

<!-- next-header -->
## [Unreleased] - ReleaseDate

### Added

- Added `Serialize` and `Default` traits to `AdvisoryStatus` and `Advisories`
- Added `Deserialize` trait to `Advisories`
- Added `Ord` trait to `AdvisoryStatus`
- Added `MbedTlsCertificateChainVerifier` which can be used to verify X509 certificate chains. This is behind the `mbedtls` feature.

### Changed

- `x509` feature has been renamed to `mbedtls`
- `UnverifiedCertChain` is no no longer public. One should use the `MbedTlsCertificateChainVerifier` instead.
- `CertificateREvocationList` is no longer public. One should use the `MbedTlsCertificateChainVerifier` instead.
- `EvidenceVerifier` will now also verify the signature of the `Quote3`
- `Quote3Verifier::new()` now takes an `Option<VerifyingKey>`, instead of a `VerifyingKey`.

### Removed

- `VerifiedCertChain` has been removed. One should sue the `MbedTlsCertificateChainVerifier` instead.

## [0.1.0] - 2023-07-13

- Initial release of attestation verifier crate

<!-- next-url -->
[Unreleased]: https://github.com/mobilecoinfoundation/attestation/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/mobilecoinfoundation/sgx/compare/v0.1.0
