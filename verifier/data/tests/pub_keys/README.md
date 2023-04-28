# Public Keys For Testing

Public keys created with openssl. The private keys are not included to avoid
being flagged by security scans.

The ecdsa public keys were created using OpenSSL and the following command
lines:

```console
openssl ecparam -name prime256v1 -genkey -noout -out <private_key_file>.pem
openssl ec -in <private_key_file>.pem -pubout -out <public_key_file>.pem
```

For the RSA keys, the following command lines were used:

```console
openssl genrsa -out <private_key_file>.pem 3072
openssl rsa -in <private_key_file>.pem -pubout -out <public_key_file>.pem
```
