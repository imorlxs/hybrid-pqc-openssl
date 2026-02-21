#include "mlkem_utils.h"

int main(int argc, char const *argv[]) {
  int sockD = socket(AF_INET, SOCK_STREAM, 0);

  struct sockaddr_in servAddr;
  servAddr.sin_family = AF_INET;
  servAddr.sin_port = htons(9001);
  servAddr.sin_addr.s_addr = INADDR_ANY;

  if (connect(sockD, (struct sockaddr *)&servAddr, sizeof(servAddr)) == -1) {
    perror("Connection Error");
    return EXIT_FAILURE;
  }
  printf("Connected to the server.\n");

  const char *classicAlgo = "X25519";
  const char *mlkemAlgo = "ML-KEM-768";

  // 1. Receive Public Keys from server
  size_t pubClassicLen = 0, pubMlkemLen = 0;
  unsigned char *pubClassic = recv_data(sockD, &pubClassicLen);
  unsigned char *pubMlkem = recv_data(sockD, &pubMlkemLen);

  // 2. Reconstruct EVP_PKEY from received keys
  EVP_PKEY *peerClassic =
      create_pkey_from_pubkey(pubClassic, pubClassicLen, classicAlgo);
  EVP_PKEY *peerMlkem =
      create_pkey_from_pubkey(pubMlkem, pubMlkemLen, mlkemAlgo);

  // 3. Encapsulate (Generate secret and cyphertext)
  unsigned char *ctClassic = NULL, *secretClassic = NULL;
  unsigned char *ctMlkem = NULL, *secretMlkem = NULL;
  size_t ctClassicLen = 0, secretClassicLen = 0;
  size_t ctMlkemLen = 0, secretMlkemLen = 0;

  encapsulate_keys(peerClassic, NULL, &ctClassic, &ctClassicLen, &secretClassic,
                   &secretClassicLen);
  encapsulate_keys(peerMlkem, NULL, &ctMlkem, &ctMlkemLen, &secretMlkem,
                   &secretMlkemLen);

  printf("\n--- Shared Secrets (Client) ---\n");
  hexdump(classicAlgo, secretClassic, secretClassicLen);
  hexdump(mlkemAlgo, secretMlkem, secretMlkemLen);

  // 4. Send cypher texts
  send_data(sockD, ctClassic, ctClassicLen);
  send_data(sockD, ctMlkem, ctMlkemLen);
  printf("\nCypher texts sent to the server .\n");

  // 5. Derive AES key
  unsigned char finalKey[32];
  derive_hybrid_key(secretClassic, secretClassicLen, secretMlkem,
                    secretMlkemLen, finalKey);
  hexdump("Final AES key", finalKey, 32);

  // 6. Send encrypted message
  unsigned char *msg = (unsigned char *)"Hello world!";
  unsigned char ciphertext[128], tag[16];
  int ct_len =
      aes_encrypt(msg, strlen((char *)msg) + 1, finalKey, ciphertext, tag);

  send_data(sockD, ciphertext, ct_len);
  send_data(sockD, tag, 16);
  printf("Encrypted message sent.\n");

  // Cleaning
  EVP_PKEY_free(peerClassic);
  EVP_PKEY_free(peerMlkem);
  free(pubClassic);
  free(pubMlkem);
  OPENSSL_free(ctClassic);
  OPENSSL_free(secretClassic);
  OPENSSL_free(ctMlkem);
  OPENSSL_free(secretMlkem);
  close(sockD);

  return 0;
}