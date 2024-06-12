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
//!    ./verify <public key> <signed file>
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

// Get the SHA256 hash and signature from the file. Processes the file
// incrementally to avoid allocating a file-sized buffer in memory.
static int prv_get_sha256_and_signature_from_file(const char* filename,
                                                  unsigned char* hash,
                                                  unsigned char* signature,
                                                  size_t sig_size) {
  FILE* file = fopen(filename, "rb");
  if (file == NULL) {
    fprintf(stderr, "Error opening file %s\n", filename);
    return -1;
  }

  // Get the file size
  fseek(file, 0, SEEK_END);
  long file_size = ftell(file);
  fseek(file, 0, SEEK_SET);

// Define the chunk size
#define CHUNK_SIZE 16384

  // Initialize the SHA256 context
  SHA256_CTX sha256;
  SHA256_Init(&sha256);

  // Read the file contents into memory in chunks
  unsigned char* buffer = (unsigned char*)malloc(CHUNK_SIZE);
  if (buffer == NULL) {
    perror("Error allocating memory");
    fclose(file);
    return -1;
  }

  size_t total_bytes_read = 0;
  size_t bytes_to_read = file_size - sig_size;

  while (total_bytes_read < bytes_to_read) {
    // Read the chunk, truncated to the remaining bytes
    #define MIN(a, b) ((a) < (b) ? (a) : (b))
    const size_t chunk_size = MIN(CHUNK_SIZE, bytes_to_read - total_bytes_read);
    size_t bytes_read = fread(buffer, 1, chunk_size,
                       file);
    // Update the hash with the chunk data
    SHA256_Update(&sha256, buffer, bytes_read);
    total_bytes_read += bytes_read;
  }

  // Finalize the hash
  SHA256_Final(hash, &sha256);

  // Read the signature from the end of the file
  fseek(file, -sig_size, SEEK_END);
  fread(signature, 1, sig_size, file);

  free(buffer);
  fclose(file);

  return 0;
}

int verify_signature(const char* filename, const char* pub_key_filename) {
  // The signature is P1363 encoded (the 32 byte r + s values concatenated),
  // which we convert to DER for OpenSSL. The signature is appended to the file
  // when it is signed, so it's the last 64 bytes of the file.
  const size_t sig_size = 64;
  unsigned char signature[sig_size];
  unsigned char hash[SHA256_DIGEST_LENGTH];
  int rv = prv_get_sha256_and_signature_from_file(filename, hash, signature,
                                                  sig_size);
  if (rv != 0) {
    perror("Error getting hash and signature from file");
    return rv;
  }

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