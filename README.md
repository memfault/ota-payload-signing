# ECDSA Signature Verification with OpenSSL

This is a simple example of how to sign a payload with ECDSA (SHA256 hash
function and Secp256k1 ECC curve), and verify it with OpenSSL.

## Example Usage

> [!NOTE]
>
> This example provides a pre-generated key pair for signing and verifying. Do
> not use in production!

```bash
# Sign the payload
$ echo 'Hello, World!' > payload.txt
$ ./sign.py private.pem payload.txt payload.txt.signed
# Build the verify program with gcc
$ gcc verify.c -o verify -lssl -lcrypto
# Verify the signature
$ ./verify public.pem payload.txt.signed
Signature: de3865d02a99d4a9ac21d86a2f607720709e813778fc3e45f8742fedb138ce97bfa0c1260670815303a928a8c96cead87c7d7df9f29b89bb69ae8a74a4822516
Signature verification successful!
```

Note: if your compiler supports these options, you can build the `verify`
program with additional flags:

```bash
$ gcc -g -o verify verify.c \
  -Wall \
  -Werror \
  -Wno-deprecated-declarations \
  -fsanitize=leak \
  -fsanitize=address \
  -fsanitize=undefined \
  -fno-sanitize-recover=all \
  -lssl \
  -lcrypto
```
