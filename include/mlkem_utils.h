#ifndef MLKEM_UTILS_H
#define MLKEM_UTILS_H

#include <arpa/inet.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

void hexdump(const char *label, const unsigned char *buf, size_t len);
EVP_PKEY *generate_keys(const char *type);
EVP_PKEY *create_pkey_from_pubkey(const unsigned char *pubkey,
                                  size_t pubkey_len, const char *type);

int encapsulate_keys(EVP_PKEY *pkey, const char *mode, unsigned char **out,
                     size_t *outlen, unsigned char **secret, size_t *secretlen);

int decapsulate_keys(EVP_PKEY *pkey, const char *mode, const unsigned char *in,
                     size_t inlen, unsigned char **secret, size_t *secretlen);

// Secured network functions
void send_data(int sock, const unsigned char *buf, uint32_t len);
unsigned char *recv_data(int sock, size_t *out_len);

int derive_hybrid_key(const unsigned char *s1, size_t s1_len,
                      const unsigned char *s2, size_t s2_len,
                      unsigned char *derived_key);

int aes_encrypt(const unsigned char *plaintext, int plaintext_len,
                const unsigned char *key, unsigned char *ciphertext,
                unsigned char *tag);

int aes_decrypt(const unsigned char *ciphertext, int ciphertext_len,
                const unsigned char *tag, const unsigned char *key,
                unsigned char *plaintext);
#endif