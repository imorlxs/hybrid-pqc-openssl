#include "mlkem_utils.h"

int main(int argc, char const *argv[]) {
  int servSockD = socket(AF_INET, SOCK_STREAM, 0);

  struct sockaddr_in servAddr;
  servAddr.sin_family = AF_INET;
  servAddr.sin_port = htons(9001);
  servAddr.sin_addr.s_addr = INADDR_ANY;

  int opt = 1;
  setsockopt(servSockD, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

  bind(servSockD, (struct sockaddr *)&servAddr, sizeof(servAddr));
  listen(servSockD, 1);

  printf("Waiting connections in port 9001...\n");
  int clientSocket = accept(servSockD, NULL, NULL);
  printf("Client connected.\n");

  const char *classicAlgo = "X25519";
  const char *mlkemAlgo = "ML-KEM-768";

  // 1. Generate key pairs
  EVP_PKEY *pkeyClassic = generate_keys(classicAlgo);
  EVP_PKEY *pkeyMlkem = generate_keys(mlkemAlgo);

  // 2. Extract and send public keys
  size_t pubClassicLen = 0, pubMlkemLen = 0;

  EVP_PKEY_get_octet_string_param(pkeyClassic, OSSL_PKEY_PARAM_PUB_KEY, NULL, 0,
                                  &pubClassicLen);
  unsigned char *pubClassic = malloc(pubClassicLen);
  EVP_PKEY_get_octet_string_param(pkeyClassic, OSSL_PKEY_PARAM_PUB_KEY,
                                  pubClassic, pubClassicLen, &pubClassicLen);
  send_data(clientSocket, pubClassic, pubClassicLen);

  EVP_PKEY_get_octet_string_param(pkeyMlkem, OSSL_PKEY_PARAM_PUB_KEY, NULL, 0,
                                  &pubMlkemLen);
  unsigned char *pubMlkem = malloc(pubMlkemLen);
  EVP_PKEY_get_octet_string_param(pkeyMlkem, OSSL_PKEY_PARAM_PUB_KEY, pubMlkem,
                                  pubMlkemLen, &pubMlkemLen);
  send_data(clientSocket, pubMlkem, pubMlkemLen);

  printf("Public keys sent.\n");

  // 3. Receive CypherText from the client
  size_t ctClassicLen = 0, ctMlkemLen = 0;
  unsigned char *ctClassic = recv_data(clientSocket, &ctClassicLen);
  unsigned char *ctMlkem = recv_data(clientSocket, &ctMlkemLen);

  // 4. Decapsulate to obtain the secrets
  unsigned char *secretClassic = NULL, *secretMlkem = NULL;
  size_t secretClassicLen = 0, secretMlkemLen = 0;

  decapsulate_keys(pkeyClassic, NULL, ctClassic, ctClassicLen, &secretClassic,
                   &secretClassicLen);
  decapsulate_keys(pkeyMlkem, NULL, ctMlkem, ctMlkemLen, &secretMlkem,
                   &secretMlkemLen);

  printf("\n--- Shared Secrets (Server) ---\n");
  hexdump(classicAlgo, secretClassic, secretClassicLen);
  hexdump(mlkemAlgo, secretMlkem, secretMlkemLen);

  // 5. Derive AES key
  unsigned char finalKey[32];
  derive_hybrid_key(secretClassic, secretClassicLen, secretMlkem,
                    secretMlkemLen, finalKey);
  hexdump("Final AES key", finalKey, 32);

  size_t ct_len = 0, tag_len = 0;
  unsigned char *ciphertext = recv_data(clientSocket, &ct_len);
  unsigned char *tag = recv_data(clientSocket, &tag_len);

  unsigned char decrypted[128];
  int pt_len = aes_decrypt(ciphertext, ct_len, tag, finalKey, decrypted);

  if (pt_len > 0) {
    printf("Decrypted message: %s\n", decrypted);
  } else {
    printf("Decryption error.\n");
  }

  // Cleaning
  EVP_PKEY_free(pkeyClassic);
  EVP_PKEY_free(pkeyMlkem);
  free(pubClassic);
  free(pubMlkem);
  free(ctClassic);
  free(ctMlkem);
  OPENSSL_free(secretClassic);
  OPENSSL_free(secretMlkem);
  close(clientSocket);
  close(servSockD);

  return 0;
}