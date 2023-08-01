#include <iostream>
#include <chrono>
#include <random>
#include <cassert>
#include "abe.h"
#include "symmetric_encryption/aes.hpp"
#include "schemes/hypre/hypre_impl.hpp"

#define cur_time std::chrono::high_resolution_clock::now()
#define duration_time(end, start) std::chrono::duration_cast<std::chrono::microseconds>(end - start).count()

const std::vector<std::string> U{"a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l", "m",
                                 "n", "o", "p", "q", "r", "s", "t", "u", "v", "w", "x", "y", "z",
                                 "aa", "bb", "cc", "dd", "ee", "ff", "gg", "hh", "ii", "jj", "kk",
                                 "ll", "mm", "nn", "oo", "pp", "qq", "rr", "ss", "tt", "uu", "vv",
                                 "ww", "xx", "yy", "zz", "aaa", "bbb", "ccc", "ddd", "eee", "fff",
                                 "ggg", "hhh", "iii", "jjj", "kkk", "lll", "mmm", "nnn", "ooo", "ppp",
                                 "qqq", "rrr", "sss", "ttt", "uuu", "vvv", "www", "xxx", "yyy", "zzz"};

void test(int iter_times, int attribute_num) {
  std::cout << "Attribute numbers: " << attribute_num << std::endl;
  HyPRE_Impl habpreks;
  auto keys = habpreks.setUp();

  std::vector<std::string> attributes;
  for (int i = 0; i < attribute_num; ++i) {
    attributes.emplace_back(U[i]);
  }

  std::string policy;
  for (int i = 0; i < attribute_num; ++i) {
    if (i != 0) {
      policy.append("|");
    }
    policy.append(U[i]);
  }
  std::cout << "policy: " << policy << "\n";

  string identity = "1801110674";
  auto *attrID = new vector<string>{identity};

  Key *sk_S;
  auto keygen_s_start = cur_time;
  for (int i = 0; i < iter_times; ++i) {
    sk_S = habpreks.keyGen(keys->at(1), keys->at(0), &attributes);
  }
  auto keygen_s_end = cur_time;

  Key *sk_ID;
  auto keygen_id_start = cur_time;
  for (int i = 0; i < iter_times; ++i) {
    sk_ID = habpreks.keyGen(keys->at(1), keys->at(0), identity);
  }
  auto keygen_id_end = cur_time;

  element_t key_ele;
  element_init_GT(key_ele, reinterpret_cast<pairing_s *>(habpreks.getPairing()));
  element_random(key_ele);

  auto enc_st = cur_time;
  auto ibe_ciphertext = habpreks.encrypt(key_ele, identity, keys->at(1));
  auto enc_ed = cur_time;

  Ciphertext *rk, *reEncryptedCT;
  auto rkgen_st = cur_time;
  for (int i = 0; i < iter_times; ++i) {
    rk = habpreks.rkGen(keys->at(1), sk_ID, policy);
  }
  auto rkgen_ed = cur_time;
  auto renc_st = cur_time;
  for (int i = 0; i < iter_times; ++i) {
    reEncryptedCT = habpreks.reEnc(keys->at(1), rk, ibe_ciphertext);
  }
  auto renc_ed = cur_time;

  element_s *ibe_plaintext, *plaintext2;
  auto dec_ori_st = cur_time;
  for (int i = 0; i < iter_times; ++i) {
    ibe_plaintext = habpreks.decrypt(ibe_ciphertext, sk_ID, attrID, "identity");
  }
  auto dec_ori_ed = cur_time;

  auto dec_re_st = cur_time;
  plaintext2 = habpreks.decrypt(reEncryptedCT, sk_S, &attributes, "attributes");
  auto dec_re_ed = cur_time;

  std::cout << "/*************************** Test Results ***************************/\n";
  std::cout << "Keygen for id time: " << duration_time(keygen_id_end, keygen_id_start) / iter_times << " (us)\n";
  std::cout << "Keygen for attrs time: " << duration_time(keygen_s_end, keygen_s_start) / iter_times << " (us)\n";
  std::cout << "Encrypt time: " << duration_time(enc_ed, enc_st) / iter_times << " (us)\n";
  std::cout << "RKGen time: " << duration_time(rkgen_ed, rkgen_st) / iter_times << " (us)\n";
  std::cout << "ReEncrypt time: " << duration_time(renc_ed, renc_st) / iter_times << " (us)\n";
  std::cout << "DecryptOri time: " << duration_time(dec_ori_ed, dec_ori_st) / iter_times << " (us)\n";
  std::cout << "DecryptRe time: " << duration_time(dec_re_ed, dec_re_st) / iter_times << " (us)\n";
}

int main() {
  for (int i = 5; i <= 30; i += 5) {
    test(50, i);
  }
}
