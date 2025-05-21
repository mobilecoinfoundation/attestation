# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

<!-- next-header -->
## [Unreleased] - ReleaseDate

### Changed

- Updated SGX crates to `0.12.0`.

## [0.4.3] - 2024-04-05

### Changed

- Updated SGX crates to `0.11.0`.

## [0.4.2] - 2023-12-05

### Changed

- Updated SGX crates to `0.10.0`.

## [0.4.1] - 2023-10-20

### Changed

- Updated SGX crates to `0.9.0`.

## [0.4.0] - 2023-09-21

### Added

- `Clone`, `PartialEq`, `Serialize`, and `Deserialize` to `Error`.

### Changed

- `Error::Der` and `Error::Serde` variants now contain an inner `String`. This
  allows the `Error` type to be serializable, cloneable, and compared for
equivalence.
- Time-based certificate validation is now optional. `DateTime` parameters have been replaced with `Into<Option<DateTime>>`. If a `None` value is provided to the APIs, time validation will be skipped.
- Updated SGX crates to `0.8.0`.

## [0.3.1] - 2023-08-16

### Added

- Export constructs to assist in using custom `Verifier`s with
  the `VerificationTreeDisplay`:
  - `MESSAGE_INDENT`
  - `choice_to_status_message()`
  - `VerificationMessage`

## [0.3.0] - 2023-08-14

### Added

- `EvidenceValue` is exposed as a public type.

### Changed

- `EvidenceVerifier` now takes ownership of the provided `CertificateChainVerifier`.

## [0.2.0] - 2023-07-21

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
[Unreleased]: https://github.com/mobilecoinfoundation/attestation/compare/v0.4.3...HEAD
[0.4.3]: https://github.com/mobilecoinfoundation/attestation/compare/v0.4.2...v0.4.3
[0.4.2]: https://github.com/mobilecoinfoundation/attestation/compare/v0.4.1...v0.4.2
[0.4.1]: https://github.com/mobilecoinfoundation/attestation/compare/v0.4.0...v0.4.1
[0.4.0]: https://github.com/mobilecoinfoundation/attestation/compare/v0.3.1...v0.4.0
[0.3.1]: https://github.com/mobilecoinfoundation/attestation/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/mobilecoinfoundation/attestation/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/mobilecoinfoundation/attestation/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/mobilecoinfoundation/sgx/compare/v0.1.0
