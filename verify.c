//! @file
//!
//! Simple example program that verifies a file containing a signature using a
//! public key.
//!
//! The file has the signature appended at the end of the file.
//!
//! To compile and run:
//!
//!    gcc -o verify verify.c -lssl -lcrypto
//!    ./verify <signed file> <public key>
//!
//! Note: this program uses functions that are deprecated (but still available)
//! in OpenSSL 3.0.0. It should be compatible with OpenSSL 1.1.1 and 3+, but has
//! only been tested with 3.0.13

#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/obj_mac.h>
#include <openssl/pem.h>
#include <openssl/sha.h>
#include <stdio.h>
#include <stdlib.h>

int verify_signature(const char* filename, const char* pub_key_filename) {
  FILE* file = fopen(filename, "rb");
  if (file == NULL) {
    perror("Error opening file");
    return -1;
  }

  // Read the file contents into memory
  fseek(file, 0, SEEK_END);
  long file_size = ftell(file);
  fseek(file, 0, SEEK_SET);
  unsigned char* file_data = (unsigned char*)malloc(file_size);
  if (file_data == NULL) {
    perror("Error allocating memory");
    fclose(file);
    return -1;
  }
  fread(file_data, 1, file_size, file);

  // Extract the signature from the file. The signature is P1363 encoded (the
  // 32 byte r + s values concatenated), which we convert to DER for OpenSSL.
  // The signature is appended to the file when it is signed, so it's the last
  // 64 bytes of the file.
  const size_t sig_size = 64;
  unsigned char signature[sig_size];
  memcpy(signature, file_data + file_size - sig_size, sig_size);

  // Calculate the hash of the file data
  unsigned char hash[SHA256_DIGEST_LENGTH];
  SHA256(file_data, file_size - sig_size, hash);
  free(file_data);
  fclose(file);

  // Print the signature
  printf("Signature: ");
  for (int i = 0; i < sig_size; i++) {
    printf("%02x", signature[i]);
  }
  printf("\n");

  // Convert the signature to DER format
  ECDSA_SIG* ecdsa_sig = ECDSA_SIG_new();
  if (ecdsa_sig == NULL) {
    perror("Error creating ECDSA_SIG");
    return -1;
  }

  BIGNUM* r = BN_bin2bn(signature, sig_size / 2, NULL);
  BIGNUM* s = BN_bin2bn(signature + sig_size / 2, sig_size / 2, NULL);
  if (r == NULL || s == NULL) {
    perror("Error converting signature to BIGNUM");
    ECDSA_SIG_free(ecdsa_sig);
    return -1;
  }
  ECDSA_SIG_set0(ecdsa_sig, r, s);

  // now encode into DER
  unsigned char* der_sig = NULL;
  int der_sig_len = i2d_ECDSA_SIG(ecdsa_sig, &der_sig);
  if (der_sig_len <= 0) {
    perror("Error encoding signature to DER");
    ECDSA_SIG_free(ecdsa_sig);
    return -1;
  }
ECDSA_SIG_free(ecdsa_sig);

  // Load the public key
  FILE* pub_key_file = fopen(pub_key_filename, "r");
  if (pub_key_file == NULL) {
    perror("Error opening public key file");
    return -1;
  }

  EC_KEY* ec_key = PEM_read_EC_PUBKEY(pub_key_file, NULL, NULL, NULL);
  if (ec_key == NULL) {
    perror("Error reading public key");
    fclose(pub_key_file);
    return -1;
  }
  fclose(pub_key_file);

  // Verify the signature
  int result =
      ECDSA_verify(0, hash, SHA256_DIGEST_LENGTH, der_sig, der_sig_len, ec_key);

  // Cleanup
  EC_KEY_free(ec_key);
  free(der_sig);

  return result;
}

int main(int argc, char** argv) {
  // takes 2 arguments: the file to verify and the public key
  if (argc != 3) {
    printf("Usage: %s <public-key.pem> <filename>\n", argv[0]);
    return 1;
  }

  const char* pub_key_filename = argv[1];
  const char* filename = argv[2];

  int result = verify_signature(filename, pub_key_filename);

  if (result == 1) {
    printf("Signature verification successful!\n");
  } else if (result == 0) {
    printf("Signature verification failed!\n");
  } else {
    printf("Error verifying signature!\n");
  }

  return 0;
}