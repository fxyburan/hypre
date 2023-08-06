//
// Created by Xinyu Feng on 2023/7/27.
//
#include <cassert>
#include <chrono>
#include "schemes/abpre/abpre_impl_cpa.hpp"

#define cur_time std::chrono::high_resolution_clock::now()
#define duration_time(end, start) std::chrono::duration_cast<std::chrono::microseconds>(end - start).count()

const std::vector<std::string> U{"a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l", "m",
                                 "n", "o", "p", "q", "r", "s", "t", "u", "v", "w", "x", "y", "z",
                                 "aa", "bb", "cc", "dd", "ee", "ff", "gg", "hh", "ii", "jj", "kk",
                                 "ll", "mm", "nn", "oo", "pp", "qq", "rr", "ss", "tt", "uu", "vv",
                                 "ww", "xx", "yy", "zz", "aaa", "bbb", "ccc", "ddd", "eee", "fff",
                                 "ggg", "hhh", "iii", "jjj", "kkk", "lll", "mmm", "nnn", "ooo", "ppp",
                                 "qqq", "rrr", "sss", "ttt", "uuu", "vvv", "www", "xxx", "yyy", "zzz"};

void benchmark(int attribute_num, int iteration_time) {
  assert (attribute_num < U.size());
  std::cout << "Attribute numbers: " << attribute_num << std::endl;
  ABPRE_Impl abpre_cpa;
  auto setup_st = cur_time;
  auto keys = abpre_cpa.setUp();
  auto setup_ed = cur_time;
  std::vector<std::string> attributes;
  for (int i = 0; i < attribute_num; ++i) {
    attributes.emplace_back(U[i]);
  }

  auto keygen_st = cur_time;
  Key *private_key;
  for (int i = 0; i < iteration_time; ++i) {
    private_key = abpre_cpa.keyGen(keys->at(1), keys->at(0), &attributes);
  }
  auto keygen_ed = cur_time;

  std::string policy;
  for (int i = 0; i < attribute_num; ++i) {
    if (i != 0) {
      policy.append("|");
    }
    policy.append(U[i]);
  }
  std::cout << "policy: " << policy << "\n";

  element_t m;
  element_init_G1(m, reinterpret_cast<struct pairing_s *>(abpre_cpa.getPairing()));
  element_random(m);

  auto enc_st = cur_time;
  Ciphertext *ciphertext;
  for (int i = 0; i < iteration_time; ++i) {
    ciphertext = abpre_cpa.encrypt(m, policy, keys->at(1));
  }
  auto enc_ed = cur_time;

  std::string policy2 = policy;
  auto rkgen_st = cur_time;
  Ciphertext *rk;
  for (int i = 0; i < iteration_time; ++i) {
    rk = abpre_cpa.rkGen(keys->at(1), private_key, policy2);
  }
  auto rkgen_ed = cur_time;

  auto renc_st = cur_time;
  Ciphertext *re_encrypted_ct;
  for (int i = 0; i < iteration_time; ++i) {
    re_encrypted_ct = abpre_cpa.reEnc(keys->at(0), rk, ciphertext);
  }
  auto renc_ed = cur_time;

  element_s *plaintext, *plaintext2;
  auto dec_ori_st = cur_time;
  for (int i = 0; i < iteration_time; ++i) {
    plaintext = abpre_cpa.decrypt(ciphertext, private_key, &attributes, "ori");
  }
  auto dec_ori_ed = cur_time;
  auto dec_re_st = cur_time;
  for (int i = 0; i < iteration_time; ++i) {
    plaintext2 = abpre_cpa.decrypt(re_encrypted_ct, private_key, &attributes, "renc");
  }
  auto dec_re_ed = cur_time;

  std::cout << "/*************************** Test Results ***************************/\n";
  std::cout << "Keygen time: " << duration_time(keygen_ed, keygen_st) / iteration_time << " (us)\n";
  std::cout << "Encrypt time: " << duration_time(enc_ed, enc_st) / iteration_time << " (us)\n";
  std::cout << "RKGen time: " << duration_time(rkgen_ed, rkgen_st) / iteration_time << " (us)\n";
  std::cout << "ReEncrypt time: " << duration_time(renc_ed, renc_st) / iteration_time << " (us)\n";
  std::cout << "DecryptOri time: " << duration_time(dec_ori_ed, dec_ori_st) / iteration_time << " (us)\n";
  std::cout << "DecryptRe time: " << duration_time(dec_re_ed, dec_re_st) / iteration_time << " (us)\n";
}

int main() {
  benchmark(1, 50);
  return 0;
}