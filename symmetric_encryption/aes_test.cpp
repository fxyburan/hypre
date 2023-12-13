//
// Created by Xinyu Feng on 2023/12/13.
//
#include "symmetric_encryption/aes.hpp"

int main() {
  // AES key (256 bits = 32 bytes)
  const unsigned char key[] = "your-32-byte-key-here";

  // Message to be encrypted
  const char *message = "This is a secret message.........ddd";

  // Encrypt the message
  std::string ciphertext = AESEncrypt(reinterpret_cast<const unsigned char *>(message), std::strlen(message), key);
  std::cout << "Encrypted: ";
  PrintHex(reinterpret_cast<const unsigned char *>(ciphertext.c_str()), ciphertext.size());

  // Decrypt the message
  std::string decryptedMessage = AESDecrypt(ciphertext, key);
  std::cout << "Decrypted: " << decryptedMessage << std::endl;

  return 0;
}
