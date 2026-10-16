# Test data for `mc-attestation-verifier`

* `root_ca.pem` - Root CA of a certificate chain. This is a copy of an Intel
  root CA which was in an actual hardware quote.
* `processor_ca.pem` - Processor CA in a certificate chain. This is a copy
  of an Intel intermediate CA which was in an actual hardware quote. There are
  two types of certificate chains: "processor" and "platform". "Platform" isn't
  currently used by Intel.
* `leaf_cert.pem` - Leaf of a certificate chain. This is a copy of an Intel
  leaf certificate which was in an actual hardware quote.
* `root_crl.der` - CRL for the root CA of a certificate chain. This was
  retrieved via the CRL Distribution Points URI in the root CA,
  <https://certificates.trustedservices.intel.com/IntelSGXRootCA.der>
* `root_crl.pem` - CRL for the root CA of a certificate chain in PEM format. This was created by
  converting the DER version to PEM via openssl

  ```console
  openssl crl -in verifier/data/tests/root_crl.der -out verifier/data/tests/root_crl.pem -outform PEM
  ```

* `processor_crl.pem` - CRL for the processor CA in a certificate chain. This
  was retrieved from
  <https://api.trustedservices.intel.com/sgx/certification/v4/pckcrl?ca=processor>.
* `processor_crl.der` - CRL for the processor CA of a certificate chain in DER format. This was created by
  converting the PEM version to DER via openssl

  ```console
  openssl crl -in verifier/data/tests/processor_crl.pem -out verifier/data/tests/processor_crl.der -outform DEr
  ```

* `fmspc_00906ED50000_2023_07_12.json` - JSON file containing the result of a
  TCB request from
  <https://api.trustedservices.intel.com/sgx/certification/v4/tcb?fmspc=00906ED50000>.
  This was captured on 2023-07-12.
* `example_tcb.json` - JSON file containing the example TCB response from
  <https://api.portal.trustedservices.intel.com/documentation#pcs-tcb-info-v4>.
* `tcb_signer.pem` - The signer certificate for TCB data from
  <https://api.trustedservices.intel.com/sgx/certification/v4/tcb?fmspc={}>.
  This was retrieved by looking at the header using `curl --include ...`.
* `example_qe_identity.json` - JSON file containing the example QE identity response from
  <https://api.portal.trustedservices.intel.com/documentation#pcs-enclave-identity-v4>.
* `qe_identity.json` - A QE identity file from
  <https://api.trustedservices.intel.com/sgx/certification/v4/qe/identity?update=standard>.
* `hw_quote.dat` - A quote from an Intel SGX enclave on hardware.

## Current Intel collateral

The `current_*` files were captured directly from Intel PCS on October 16,
2026. They are unchanged response bodies (DER CRLs/JSON), with signing leaf
certificates decoded from the percent-encoded issuer-chain HTTP headers:

* <https://api.trustedservices.intel.com/sgx/certification/v4/tcb?fmspc=00906ED50000>
* <https://api.trustedservices.intel.com/sgx/certification/v4/qe/identity>
* <https://api.trustedservices.intel.com/sgx/certification/v4/pckcrl?ca=processor&encoding=der>
* <https://certificates.trustedservices.intel.com/IntelSGXRootCA.der>

The fixed test time is October 16, 2026 at 21:00 UTC, within all signed validity
intervals. Tests require no network access.

With this collateral, the historical `hw_quote.dat` platform has TCB status
`OutOfDate`. Its certificate chains and signatures verify, but the evidence
verifier rejects its identity under the existing policy with either backend.
The positive end-to-end WebPKI test uses an explicitly synthetic signing
hierarchy and re-signed quote/collateral; these generated values stay in memory.

## Mainnet Fog capture

The `mainnet_fog/` fixture was retrieved on October 19, 2026 from the public
mainnet Fog report endpoint over verified HTTPS:
<https://fog.prod.mobilecoinww.com/report.ReportAPI/GetReports>.
The empty `report.ReportRequest` was sent as an uncompressed gRPC frame
(five zero bytes) with `content-type: application/grpc` and `te: trailers`.
The response returned HTTP 200 and gRPC status 0, containing one DCAP report.

* `quote.dat` contains the unchanged quote bytes from that response.
* `collateral.json` contains the same report's collateral. Certificate chains
  are represented as PEM and DER CRLs as hex. The signed TCB and QE JSON
  strings are preserved unchanged. No collateral was replaced or re-signed.
* `capture.json` records the endpoint, fixed verification time, quote and
  protobuf response SHA-256 digests, report ID, public-key expiry, report-data
  contents, and captured enclave measurements.

`mainnet_fog_evidence_verifies_at_capture_time` verifies the full evidence
against the pinned Intel root at `2026-10-19T20:00:36Z` with either backend,
checks the report-data binding, and pins the captured MRENCLAVE. It allows
only the same three hardening advisories listed in MobileCoin's Fog ingest
measurement crate: `INTEL-SA-00334`, `INTEL-SA-00615`, and `INTEL-SA-00657`.
The test also checks rejection by WebPKI for missing time, a time before the
collateral was issued, and a time after it expired. It performs no network I/O.
This is a captured attestation fixture, not a check of the live Fog authority
signature, current production release measurements, or Fog key block expiry.
