#include "mlkem_utils.h"

void hexdump(const char *label, const unsigned char *buf, size_t len) {
  printf("%s (%zu bytes): ", label, len);
  for (size_t i = 0; i < len; i++) {
    printf("%02X", buf[i]);
  }
  printf("\n");
}

EVP_PKEY *generate_keys(const char *type) {
  EVP_PKEY *pkey = NULL;
  EVP_PKEY_CTX *kctx = EVP_PKEY_CTX_new_from_name(NULL, type, NULL);
  if (!kctx)
    return NULL;

  EVP_PKEY_keygen_init(kctx);
  EVP_PKEY_keygen(kctx, &pkey);
  EVP_PKEY_CTX_free(kctx);

  return pkey;
}

EVP_PKEY *create_pkey_from_pubkey(const unsigned char *pubkey,
                                  size_t pubkey_len, const char *type) {
  EVP_PKEY *pkey = NULL;
  EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(NULL, type, NULL);
  if (!ctx)
    return NULL;

  EVP_PKEY_fromdata_init(ctx);
  OSSL_PARAM params[] = {OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PUB_KEY,
                                                 (void *)pubkey, pubkey_len),
                         OSSL_PARAM_END};

  EVP_PKEY_fromdata(ctx, &pkey, EVP_PKEY_PUBLIC_KEY, params);
  EVP_PKEY_CTX_free(ctx);
  return pkey;
}

int encapsulate_keys(EVP_PKEY *pkey, const char *mode, unsigned char **out,
                     size_t *outlen, unsigned char **secret,
                     size_t *secretlen) {
  EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_pkey(NULL, pkey, NULL);
  if (!ctx)
    return 0;

  if (EVP_PKEY_encapsulate_init(ctx, NULL) <= 0)
    return 0;
  if (mode && EVP_PKEY_CTX_set_kem_op(ctx, mode) <= 0)
    return 0;

  if (EVP_PKEY_encapsulate(ctx, NULL, outlen, NULL, secretlen) <= 0)
    return 0;

  *out = OPENSSL_malloc(*outlen);
  *secret = OPENSSL_malloc(*secretlen);

  if (EVP_PKEY_encapsulate(ctx, *out, outlen, *secret, secretlen) <= 0)
    return 0;

  EVP_PKEY_CTX_free(ctx);
  return 1;
}

int decapsulate_keys(EVP_PKEY *pkey, const char *mode, const unsigned char *in,
                     size_t inlen, unsigned char **secret, size_t *secretlen) {
  EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_pkey(NULL, pkey, NULL);
  if (!ctx)
    return 0;

  if (EVP_PKEY_decapsulate_init(ctx, NULL) <= 0)
    return 0;
  if (mode && EVP_PKEY_CTX_set_kem_op(ctx, mode) <= 0)
    return 0;

  if (EVP_PKEY_decapsulate(ctx, NULL, secretlen, in, inlen) <= 0)
    return 0;

  *secret = OPENSSL_malloc(*secretlen);

  if (EVP_PKEY_decapsulate(ctx, *secret, secretlen, in, inlen) <= 0)
    return 0;

  EVP_PKEY_CTX_free(ctx);
  return 1;
}

void send_data(int sock, const unsigned char *buf, uint32_t len) {
  uint32_t net_len = htonl(len);
  send(sock, &net_len, sizeof(net_len), 0);
  send(sock, buf, len, 0);
}

unsigned char *recv_data(int sock, size_t *out_len) {
  uint32_t net_len;
  if (recv(sock, &net_len, sizeof(net_len), 0) <= 0)
    return NULL;

  uint32_t len = ntohl(net_len);
  unsigned char *buf = malloc(len);

  size_t total_read = 0;
  while (total_read < len) {
    ssize_t r = recv(sock, buf + total_read, len - total_read, 0);
    if (r <= 0)
      break;
    total_read += r;
  }

  *out_len = total_read;
  return buf;
}

// Combine both secrets using HKDF-SHA256
int derive_hybrid_key(const unsigned char *s1, size_t s1_len,
                      const unsigned char *s2, size_t s2_len,
                      unsigned char *derived_key) {
  EVP_KDF *kdf = EVP_KDF_fetch(NULL, "HKDF", NULL);
  EVP_KDF_CTX *kctx = EVP_KDF_CTX_new(kdf);

  // Concatenate both secrets
  size_t combined_len = s1_len + s2_len;
  unsigned char *combined_secret = malloc(combined_len);
  memcpy(combined_secret, s1, s1_len);
  memcpy(combined_secret + s1_len, s2, s2_len);

  OSSL_PARAM params[4];
  params[0] =
      OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, SN_sha256, strlen(SN_sha256));

  params[1] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY,
                                                combined_secret, combined_len);
                                                
  params[2] =
      OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO, "label", (size_t)5);
      
  params[3] = OSSL_PARAM_construct_end();

  int res = EVP_KDF_derive(kctx, derived_key, 32, params); // Generate 256 bits

  free(combined_secret);
  EVP_KDF_CTX_free(kctx);
  EVP_KDF_free(kdf);
  return res > 0;
}

int aes_encrypt(const unsigned char *plaintext, int plaintext_len,
                const unsigned char *key, unsigned char *ciphertext,
                unsigned char *tag) {
  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  int len, ciphertext_len;
  unsigned char iv[12] = {0}; // In production, use one random iv

  EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, iv);
  EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len);
  ciphertext_len = len;
  EVP_EncryptFinal_ex(ctx, ciphertext + len, &len);
  ciphertext_len += len;
  EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag);

  EVP_CIPHER_CTX_free(ctx);
  return ciphertext_len;
}

int aes_decrypt(const unsigned char *ciphertext, int ciphertext_len,
                const unsigned char *tag, const unsigned char *key,
                unsigned char *plaintext) {
  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  int len, plaintext_len;
  unsigned char iv[12] = {0};

  EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, iv);
  EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len);
  plaintext_len = len;
  EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, (void *)tag);

  int ret = EVP_DecryptFinal_ex(ctx, plaintext + len, &len);
  EVP_CIPHER_CTX_free(ctx);
  return (ret > 0) ? (plaintext_len + len) : -1;
}