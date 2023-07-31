//
// Created by vontroy on 2023/6/25.
//

#include "symmetric_encryption/aes.hpp"

void aes_encrypt(const unsigned char *plaintext,
                 int plaintext_len,
                 const unsigned char *key,
                 const unsigned char *iv,
                 unsigned char *ciphertext) {
  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);
  EVP_EncryptUpdate(ctx, ciphertext, &plaintext_len, plaintext, plaintext_len);
  EVP_EncryptFinal_ex(ctx, ciphertext + plaintext_len, &plaintext_len);
  EVP_CIPHER_CTX_free(ctx);
}

void aes_decrypt(const unsigned char *ciphertext,
                 int ciphertext_len,
                 const unsigned char *key,
                 const unsigned char *iv,
                 unsigned char *plaintext) {
  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);
  EVP_DecryptUpdate(ctx, plaintext, &ciphertext_len, ciphertext, ciphertext_len);
  EVP_DecryptFinal_ex(ctx, plaintext + ciphertext_len, &ciphertext_len);
  EVP_CIPHER_CTX_free(ctx);
}

//int main() {
//  // Initialize OpenSSL library
//  OpenSSL_add_all_algorithms();
//
//  const int KEY_SIZE = 256; // Key size in bits
//  const int BLOCK_SIZE = AES_BLOCK_SIZE; // Block size in bytes
////  unsigned char key[KEY_SIZE / 8]; // Key buffer
////  unsigned char iv[BLOCK_SIZE]; // Initialization vector (IV) buffer
//
//  // Set your key and IV values here (make sure they are of the correct sizes)
//  // Example:
//  unsigned char key[] = "0123456789abcdef0123456789abcdef";
//  unsigned char iv[] = "0123456789abcdef";
//
//  const char *plaintext = "This is the plaintext to encrypt.";
//  int plaintext_len = strlen(plaintext);
//
//  unsigned char ciphertext[plaintext_len + BLOCK_SIZE]; // Buffer for ciphertext
//  unsigned char decryptedtext[plaintext_len]; // Buffer for decrypted plaintext
//
//  // Perform encryption
//  aes_encrypt(reinterpret_cast<const unsigned char *>(plaintext), plaintext_len, key, iv, ciphertext);
//
//  // Print the encrypted ciphertext
//  std::cout << "Ciphertext: ";
//  for (int i = 0; i < plaintext_len + BLOCK_SIZE; ++i) {
//    printf("%02x", ciphertext[i]);
//  }
//  std::cout << std::endl;
//
//  // Perform decryption
//  aes_decrypt(ciphertext, plaintext_len, key, iv, decryptedtext);
//  decryptedtext[plaintext_len] = '\0';
//
//  // Print the decrypted plaintext
//  std::cout << "Decrypted Text: " << decryptedtext << std::endl;
//
//  return 0;
//}

