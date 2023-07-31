//
// Created by Xinyu Feng on 2023/7/18.
//

#include <iostream>
#include <chrono>
#include <random>
#include <cassert>
#include "abe.h"
#include "schemes/hypre/hypre_impl.hpp"

#define current_time std::chrono::high_resolution_clock::now()
#define duration_time(start_time, end_time) std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time).count()

unsigned char *message;
unsigned char *ciphertext;
unsigned char *decryptedtext;
static size_t plaintext_len;

const int iter_times = 1;

void test() {
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
  Key *sk_S;
  for (int i = 0; i < iter_times; ++i) {
    sk_S = habpreks.keyGen(keys->at(1), keys->at(0), attributes);
  }
  auto keygen_s_end = current_time;
  auto keygen_s_duration = duration_time(keygen_s_start, keygen_s_end);
  std::cout << "Key generation for S: " << (double) keygen_s_duration / iter_times << "(us)\n";

  Key *sk_ID;
  auto keygen_id_start = current_time;
  for (int i = 0; i < iter_times; ++i) {
    sk_ID = habpreks.keyGen(keys->at(1), keys->at(0), identity);
  }
  auto keygen_id_end = current_time;
  auto keygen_id_duration = duration_time(keygen_id_start, keygen_id_end);
  std::cout << "Key generation for id: " << (double) keygen_id_duration / iter_times << "(us)\n";

  element_t key_ele;
  element_init_GT(key_ele, reinterpret_cast<pairing_s *>(habpreks.getPairing()));
  element_random(key_ele);

  auto ibe_ciphertext = habpreks.encrypt(key_ele, identity, keys->at(1));
  auto enc_ed = current_time;

  auto rkgen_st = current_time;
  Ciphertext *rk, *reEncryptedCT;
  for (int i = 0; i < iter_times; ++i) {
    rk = habpreks.rkGen(keys->at(1), sk_ID, policyStr);
  }

  auto rkgen_ed = current_time;
  for (int i = 0; i < iter_times; ++i) {
    reEncryptedCT = habpreks.reEnc(keys->at(1), rk, ibe_ciphertext);
  }
  auto reenc_ed = current_time;
  std::cout << "RKGen time: " << (double) duration_time(rkgen_st, rkgen_ed) / iter_times << "(us)\n";
  std::cout << "ReEncrypt time: " << (double) duration_time(rkgen_ed, reenc_ed) / iter_times << "(us)\n";
  std::cout << "Re-encrypted CT len: " << reEncryptedCT->getCiphertextLen() << "(Bytes).\n";

  element_s *ibe_plaintext, *plaintext2;
  auto dec_1_st = current_time;
  for (int i = 0; i < iter_times; ++i) {
    ibe_plaintext = habpreks.decrypt(ibe_ciphertext, sk_ID, attrID, "identity");
  }

  auto dec_1_ed = current_time;
  plaintext2 = habpreks.decrypt(reEncryptedCT, sk_S, attributes, "attributes");
  auto dec_2_ed = current_time;

  std::cout << "IBE decryption time: " << (double) duration_time(dec_1_st, dec_1_ed) / iter_times << "(us)\n";

  std::cout << "Re-encrypted CT decryption time: " << (double) duration_time(dec_1_ed, dec_2_ed) / iter_times
            << "(us)\n";

  std::cout << "-------------------------Test finished-------------------------\n";

  delete[] message;
  delete[] ciphertext;
  delete[] decryptedtext;
}

int main() {
  test();
}
