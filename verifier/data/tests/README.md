# Test data for `mc-attestation-verifier`

* `root_ca.pem` - Root CA of a certificate chain. This is a copy of an Intel
  root CA which was in an actual hardware quote.
* `processor_ca.pem` - Processor CA in a certificate chain. This is a copy
  of an Intel intermediate CA which was in an actual hardware quote. There are
  two types of certificate chains: "processor" and "platform". "Platform" isn't
  currently used by Intel.
* `leaf_cert.pem` - Leaf of a certificate chain. This is a copy of an Intel
  leaf certificate which was in an actual hardware quote.
* `root_crl.pem` - CRL for the root CA of a certificate chain. This was
  retrieved via the CRL Distribution Points URI in the root CA,
  <https://certificates.trustedservices.intel.com/IntelSGXRootCA.der>
* `processor_crl.pem` - CRL for the processor CA in a certificate chain. This
  was retrieved from
  <https://api.trustedservices.intel.com/sgx/certification/v4/pckcrl?ca=processor>.
* `fmspc_00906ED50000_2023_05_10.json` - JSON file containing the result of a
  TCB request from
  <https://api.trustedservices.intel.com/sgx/certification/v4/tcb?fmspc=00906ED50000>.
  This was captured on 2023-05-10.
* `example_tcb.json` - JSON file containing the example TCB response from
  <https://api.portal.trustedservices.intel.com/documentation#pcs-tcb-info-v4>.
* `tcb_signer.pem` - The signer certificate for TCB data from
  <https://api.trustedservices.intel.com/sgx/certification/v4/tcb?fmspc={}>.
  This was retrieved by looking at the header using `curl --include ...`.
