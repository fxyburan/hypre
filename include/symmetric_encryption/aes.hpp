//
// Created by vontroy on 2023/6/25.
//

#ifndef ABE_SYMMETRIC_ENCRYPTION_AES_HPP_
#define ABE_SYMMETRIC_ENCRYPTION_AES_HPP_

#include <iostream>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <cstring>
#include <iomanip>

std::string AESEncrypt(const unsigned char *plaintext, size_t plaintext_length, const unsigned char *key);

std::string AESDecrypt(const std::string &ciphertext, const unsigned char *key);

void PrintHex(const unsigned char *buffer, size_t length);

#endif //ABE_SYMMETRIC_ENCRYPTION_AES_HPP_
