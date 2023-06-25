#include <iostream>
#include <chrono>
#include <random>
#include <cassert>
#include "abe.h"
#include "symmetric_encryption/aes.hpp"
#include "schemes/hypre/hypre_impl.hpp"

#define current_time std::chrono::high_resolution_clock::now()
#define duration_time(start_time, end_time) std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time).count()

void gen_bytes(unsigned char *randomBytes, size_t length) {
  std::random_device rd;
  std::mt19937 gen(rd()); // Mersenne Twister random number engine
  std::uniform_int_distribution<int> distribution(0, 255); // Range for random byte (0 to 255)

  // Generate random bytes
  for (int i = 0; i < length; ++i) {
    *(randomBytes + i) = static_cast<unsigned char>(distribution(gen));
  }
}

unsigned char *message;
unsigned char *ciphertext;
unsigned char *decryptedtext;
static size_t plaintext_len;

void test() {
  std::cout << "Plaintext size: " << plaintext_len << "(Bytes).\n";
  HyPRE_Impl habpreks;
  auto keys = habpreks.setUp();
  auto *attributes = new vector<string>(0);
  std::string policyStr;
  for (int attrIdx = 0; attrIdx < 5; ++attrIdx) {
    attributes->push_back(to_string(attrIdx));
    if (attrIdx) {
      policyStr.append("&");
    }
    policyStr.append(to_string(attrIdx));
  }
  string identity = "1801110674";
  auto *attrID = new vector<string>{identity};

  std::cout << policyStr << "\n";
  auto keygen_s_start = current_time;
  auto *sk_S = habpreks.keyGen(keys->at(1), keys->at(0), attributes);
  auto keygen_s_end = current_time;
  auto keygen_s_duration = duration_time(keygen_s_start, keygen_s_end);
  std::cout << "Key generation for S: " << keygen_s_duration << "(us)\n";

  auto keygen_id_start = current_time;
  auto *sk_ID = habpreks.keyGen(keys->at(1), keys->at(0), identity);
  auto keygen_id_end = current_time;
  auto keygen_id_duration = duration_time(keygen_id_start, keygen_id_end);
  std::cout << "Key generation for id: " << keygen_id_duration << "(us)\n";

  element_t key_ele;
  element_init_GT(key_ele, reinterpret_cast<pairing_s *>(habpreks.getPairing()));
  element_random(key_ele);

  auto *aes_key = new unsigned char[1024];
  element_to_bytes(aes_key, key_ele);

  // Initialize OpenSSL library
  OpenSSL_add_all_algorithms();

  const int BLOCK_SIZE = AES_BLOCK_SIZE; // Block size in bytes
  unsigned char iv[] = "0123456789abcdef";

  message = new unsigned char[plaintext_len];
  gen_bytes(message, plaintext_len);

  ciphertext = new unsigned char[plaintext_len + BLOCK_SIZE]; // Buffer for ciphertext

  auto enc_st = current_time;
  // Perform encryption
  aes_encrypt(message, plaintext_len, aes_key, iv, ciphertext);
  auto ibe_ciphertext = habpreks.encrypt(key_ele, identity, keys->at(1));
  auto enc_ed = current_time;
  std::cout << "Encryption time: " << duration_time(enc_st, enc_ed) << "(us)\n";
  std::cout << "IBE CT len: " << ibe_ciphertext->getCiphertextLen() << "(Bytes).\n";
  std::cout << "AES CT len: " << plaintext_len + BLOCK_SIZE << "(Bytes).\n";

  auto rk = habpreks.rkGen(keys->at(1), sk_ID, policyStr);
  auto reEncryptedCT = habpreks.reEnc(keys->at(1), rk, ibe_ciphertext);
  std::cout << "Re-encrypted CT len: " << reEncryptedCT->getCiphertextLen() << "(Bytes).\n";

  auto dec_1_st = current_time;
  auto ibe_plaintext = habpreks.decrypt(ibe_ciphertext, sk_ID, attrID, "identity");
  auto dec_1_ed = current_time;
  auto plaintext2 = habpreks.decrypt(reEncryptedCT, sk_S, attributes, "attributes");
  auto dec_2_ed = current_time;

  auto *aes_dec_key = new unsigned char[1024];
  element_to_bytes(aes_dec_key, plaintext2);
  // Perform decryption
  decryptedtext = new unsigned char[plaintext_len]; // Buffer for decrypted plaintext
  aes_decrypt(ciphertext, plaintext_len, aes_dec_key, iv, decryptedtext);
  auto aes_dec_ed = current_time;
  std::cout << "IBE decryption time: " << duration_time(dec_1_st, dec_1_ed) << "(us)\n";
  std::cout << "Total IBE decryption time: " << duration_time(dec_1_st, dec_1_ed) + duration_time(dec_2_ed, aes_dec_ed)
            << "(us)\n";

  std::cout << "Re-encrypted CT decryption time: " << duration_time(dec_1_ed, dec_2_ed) << "(us)\n";
  std::cout << "Total Re-encrypted CT decryption time: "
            << duration_time(dec_1_ed, dec_2_ed) + duration_time(dec_2_ed, aes_dec_ed) << "(us)\n";

  std::cout << "AES decryption time: " << duration_time(dec_2_ed, aes_dec_ed) << "(us)\n";

  std::cout << "len: " << plaintext_len << "\n";
  for (int i = 0; i < plaintext_len - 19; ++i) {
    if (message[i] != decryptedtext[i]) {
      std::cout << "Decryption failed at index " << i << ".\n";
      exit(255);
    }
  }
  std::cout << "Decryption correct.\n";
  std::cout << "-------------------------Test finished-------------------------\n";

  delete[] message;
  delete[] ciphertext;
  delete[] decryptedtext;
}

int main() {
  for (int i = 16; i <= 30; i += 2) {
    plaintext_len = 1 << i;
    test();
  }
}