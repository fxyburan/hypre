//
// Created by vontroy on 2023/6/25.
//

#include "symmetric_encryption/aes.hpp"

// Function to print the hexadecimal representation of a buffer
void PrintHex(const unsigned char *buffer, size_t length) {
  for (size_t i = 0; i < length; ++i) {
    std::cout << std::setw(2) << std::setfill('0') << std::hex << static_cast<int>(buffer[i]);
  }
  std::cout << std::dec << std::endl;
}

// Function to perform AES encryption
std::string AESEncrypt(const unsigned char *plaintext, size_t plaintext_length, const unsigned char *key) {
  // Generate a random IV
  unsigned char iv[AES_BLOCK_SIZE];
  RAND_bytes(iv, AES_BLOCK_SIZE);

  // Set up the encryption context
  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key, iv);

  // Perform the encryption
  int ciphertext_length = plaintext_length + AES_BLOCK_SIZE;
  auto *ciphertext = new unsigned char[ciphertext_length];
  int len;
  EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_length);
  ciphertext_length = len;
  EVP_EncryptFinal_ex(ctx, ciphertext + len, &len);
  ciphertext_length += len;

  // Combine the IV and ciphertext
  auto *fullCiphertext = new unsigned char[AES_BLOCK_SIZE + ciphertext_length];
  std::memcpy(fullCiphertext, iv, AES_BLOCK_SIZE);
  std::memcpy(fullCiphertext + AES_BLOCK_SIZE, ciphertext, ciphertext_length);

  // Clean up
  EVP_CIPHER_CTX_free(ctx);
  delete[] ciphertext;

  // Convert the result to a string (base64 encoding)
  std::string result(reinterpret_cast<char *>(fullCiphertext), AES_BLOCK_SIZE + ciphertext_length);
  delete[] fullCiphertext;

  return result;
}

// Function to perform AES decryption
std::string AESDecrypt(const std::string &ciphertext, const unsigned char *key) {
  // Extract the IV from the ciphertext
  unsigned char iv[AES_BLOCK_SIZE];
  std::memcpy(iv, ciphertext.c_str(), AES_BLOCK_SIZE);

  // Set up the decryption context
  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key, iv);

  // Perform the decryption
  int plaintext_length = ciphertext.size() - AES_BLOCK_SIZE;
  auto *plaintext = new unsigned char[plaintext_length];
  int len;
  EVP_DecryptUpdate(ctx,
                    plaintext,
                    &len,
                    reinterpret_cast<const unsigned char *>(ciphertext.c_str()) + AES_BLOCK_SIZE,
                    plaintext_length);
  plaintext_length = len;
  EVP_DecryptFinal_ex(ctx, plaintext + len, &len);
  plaintext_length += len;

  // Clean up
  EVP_CIPHER_CTX_free(ctx);

  // Convert the result to a string
  std::string result(reinterpret_cast<char *>(plaintext), plaintext_length);
  delete[] plaintext;

  return result;
}

