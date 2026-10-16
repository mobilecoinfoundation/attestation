# MobileCoin: SGX Enclave Attestation Report Verification

[![Project Chat][chat-image]][chat-link]<!--
-->![License][license-image]<!--
-->![Architecture: any][arch-image]<!--
-->[![Crates.io][crate-image]][crate-link]<!--
-->[![Docs Status][docs-image]][docs-link]<!--
-->[![Dependency Status][deps-image]][deps-link]

SGX Enclave Attestation Report Verification

## Certificate verification backends

The crate has no default certificate backend. Implement `CertificateChainVerifier`
or enable a backend explicitly:

- `webpki`: `WebPkiCertificateChainVerifier`, using upstream WebPKI with a
  RustCrypto P-256/SHA-256 signature adapter. Supports `no_std + alloc` and does
  not enable WebPKI's ring or aws-lc signature providers.
- `mbedtls`: the existing `MbedTlsCertificateChainVerifier` and `TrustAnchor` API.

Enable the `webpki` feature on a release of `mc-attestation-verifier` that includes it.

Construct `WebPkiCertificateChainVerifier::from_pem(root_pem)` with an explicitly
trusted attestation root and pass it to `EvidenceVerifier::new`.
The first certificate is the leaf; the remaining certificates form an unordered
issuer pool. Signing checks apply only to certificates on the validated path.
The backend supports ECDSA P-256/SHA-256 certificate and CRL signatures, as used
by the Intel DCAP certificates tested here. Leaf and intermediate certificates
may omit EKU; if present, it must include `anyExtendedKeyUsage`. Certificates
restricted to TLS or code signing are rejected.

The WebPKI backend requires an explicit validation time and CRLs covering every
certificate below the trust anchor. It checks certificate validity, signing key
usage, CA/path constraints, signatures, and revocation. Missing time, missing or
unknown revocation status, and CRLs outside their `thisUpdate`/`nextUpdate`
intervals fail verification. These checks are stricter than the existing mbedTLS
backend, whose clock behavior depends on its build configuration.

Missing time, future CRLs, expired CRLs, and unknown revocation status have
separate error variants, so the verification tree reports the validation cause.
The backend checks CRL `thisUpdate` after WebPKI authenticates the selected path
and its revocation data, so an invalid CRL signature is reported before its
future issuance time.

CA certificates on the validated path, including the pinned root, must carry
KeyUsage authorizing both certificate and CRL signing. The pinned root must also
have BasicConstraints with `ca = true`. If a leaf has KeyUsage, it must authorize
digital signatures.

Supply at most one CRL per issuer on the validated path. Duplicate issuers on
that path are rejected after WebPKI's path and revocation checks succeed; a
signature, expiry, or revocation error from its first matching CRL takes
precedence. CRLs whose issuers match no supplied certificate are dropped before
parsing. For remaining CRLs, duplicate-issuer and `thisUpdate` checks apply only
to issuers on the validated path. WebPKI checks the `nextUpdate` of CRLs it uses.

Supply the same validation time to `EvidenceVerifier` so its certificate, TCB,
and QE identity checks are consistent. A host-supplied timestamp is untrusted;
acceptance at that timestamp does not establish current freshness against a
malicious host.

[chat-image]: https://img.shields.io/discord/844353360348971068?style=flat-square
[chat-link]: https://discord.gg/mobilecoin
[license-image]: https://img.shields.io/crates/l/mc-attestation-verifier?style=flat-square
[arch-image]: https://img.shields.io/badge/arch-any-brightgreen?style=flat-square
[crate-image]: https://img.shields.io/crates/v/mc-attestation-verifier.svg?style=flat-square
[crate-link]: https://crates.io/crates/mc-attestation-verifier
[docs-image]: https://img.shields.io/docsrs/mc-attestation-verifier?style=flat-square
[docs-link]: https://docs.rs/crate/mc-attestation-verifier
[deps-image]: https://deps.rs/crate/mc-attestation-verifier/0.5.0/status.svg?style=flat-square
[deps-link]: https://deps.rs/crate/mc-attestation-verifier/0.5.0
