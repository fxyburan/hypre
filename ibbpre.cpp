//
// Created by vontroy on 2022/5/6.
//

#include <iostream>
#include <chrono>
#include "abe.h"

#define cur_time std::chrono::high_resolution_clock::now()
#define duration_time(end, start) std::chrono::duration_cast<std::chrono::microseconds>(end - start).count()

void test(int n_times, int attr_num) {
  IBBPRE_IMPL ibbpre;
  auto keys = ibbpre.setUp();

  auto keygen_st = cur_time;
  std::string identity = "1801110674";
  Key *sk;
  for (int i = 0; i < n_times; ++i) {
    sk = ibbpre.keyGen(keys->at(1), keys->at(0), identity);
  }
  auto keygen_ed = cur_time;

  element_t m;
  element_init_GT(m, reinterpret_cast<pairing_s *>(ibbpre.getPairing()));
  element_random(m);
  string keyword = "kwwww";
  auto enc_st = cur_time;
  Ciphertext *ciphertext;
  for (int i = 0; i < n_times; ++i) {
    ciphertext = ibbpre.encrypt(m, identity, keys->at(1));
  }
  auto enc_ed = cur_time;

  std::vector<std::string> id_set;
  id_set.reserve(attr_num);
  for (int i = 0; i < attr_num; ++i) {
    id_set.emplace_back("id-" + std::to_string(i));
  }

  auto rkgen_st = cur_time;
  Ciphertext *rk;
  for (int i = 0; i < n_times; ++i) {
    rk = ibbpre.rkGen(keys->at(1), sk, identity, id_set, attr_num);
  }
  auto rkgen_ed = cur_time;
  auto renc_st = cur_time;
  Ciphertext *re_encrypted_ct;
  for (int i = 0; i < n_times; ++i) { re_encrypted_ct = ibbpre.reEnc(keys->at(1), rk, ciphertext); }
  auto renc_ed = cur_time;
  auto dec_ori_st = cur_time;
  for (int i = 0; i < n_times; ++i) {
    auto plaintext = ibbpre.decrypt(ciphertext, sk, &id_set, "identity");
  }
  auto dec_ori_ed = cur_time;
  auto dec_re_st = cur_time;
  for (int i = 0; i < n_times; ++i) {
    auto plaintext2 = ibbpre.decrypt(ciphertext, sk, &id_set, "attributes");
  }
  auto dec_re_ed = cur_time;

  std::cout << "/*************************** Test Results ***************************/\n";
  std::cout << "Keygen time: " << duration_time(keygen_ed, keygen_st) / n_times << " (us)\n";
  std::cout << "Encrypt time: " << duration_time(enc_ed, enc_st) / n_times << " (us)\n";
  std::cout << "RKGen time: " << duration_time(rkgen_ed, rkgen_st) / n_times << " (us)\n";
  std::cout << "ReEncrypt time: " << duration_time(renc_ed, renc_st) / n_times << " (us)\n";
  std::cout << "DecryptOri time: " << duration_time(dec_ori_ed, dec_ori_st) / n_times << " (us)\n";
  std::cout << "DecryptRe time: " << duration_time(dec_re_ed, dec_re_st) / n_times << " (us)\n";
}

int main() {
  for (int i = 5; i <= 30; i += 5) {
    std::cout << "Attribute number: " << i << std::endl;
    test(50, i);
  }
  return 0;
}
