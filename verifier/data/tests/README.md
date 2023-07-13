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
