# PKITS Test Vectors

Test vectors from the NIST PKITS test suite. See
<https://csrc.nist.gov/projects/pki-testing> for more information.

To view the contents of the certificates or CRLs one can use the following
command:

```console
openssl x509 -in <file> -text -noout
```

> The `-noout` option is to suppress the display of the PEM format at the end
> of the output.
