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

## Gzipped Payload

Also provided is an example gzipped payload, which was generated like so:

```bash
$ echo 'Hello, World!' | gzip > payload.txt.gz
$ ./sign.py private.pem payload.txt.gz payload.txt.gz.signed
```

The signed file is now the gzipped payload with the signature appended to the
end. It can be unzipped as normal- gzip will ignore the trailing signature data:

```bash
# note the --suffix argument to support the .gz.signed extension
$ gunzip --keep --suffix .gz.signed payload.txt.gz.signed
gzip: payload.txt.gz.signed: decompression OK, trailing garbage ignored
$ cat payload.txt
Hello, World!
```

Use `gzip --quiet` to suppress the warning about the trailing garbage.

You can verify the gzipped payload just like the plaintext payload:

```bash
$ ./verify public.pem payload.txt.gz.signed
Signature: 533ad8724802ebb5a92dba5b41841501e3146aa855a208fc6b7ce24db87b09088880e1b372f7b6f076817f8c5cbab3bcc10866320439cb03fde626b09445fb6e
Signature verification successful!
```
