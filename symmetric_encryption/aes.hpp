//
// Created by vontroy on 2023/6/25.
//

#ifndef ABE_SYMMETRIC_ENCRYPTION_AES_HPP_
#define ABE_SYMMETRIC_ENCRYPTION_AES_HPP_

#include <iostream>
#include <cstring>
#include <openssl/evp.h>
#include <openssl/aes.h>

void aes_encrypt(const unsigned char *plaintext,
                 int plaintext_len,
                 const unsigned char *key,
                 const unsigned char *iv,
                 unsigned char *ciphertext);

void aes_decrypt(const unsigned char *ciphertext,
                 int ciphertext_len,
                 const unsigned char *key,
                 const unsigned char *iv,
                 unsigned char *plaintext);

#endif //ABE_SYMMETRIC_ENCRYPTION_AES_HPP_
