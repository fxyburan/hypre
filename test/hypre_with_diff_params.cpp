//
// Created by Xinyu Feng on 2023/7/18.
//

#include <iostream>
#include <chrono>
#include <random>
#include <cassert>
#include "abe.h"
#include "schemes/hypre/hypre_impl.hpp"
#include <unordered_map>
#include <vector>

#define current_time std::chrono::high_resolution_clock::now()
#define duration_time(end_time, start_time) std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time).count()

const std::vector<std::string> U{"a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l", "m",
                                 "n", "o", "p", "q", "r", "s", "t", "u", "v", "w", "x", "y", "z",
                                 "aa", "bb", "cc", "dd", "ee", "ff", "gg", "hh", "ii", "jj", "kk",
                                 "ll", "mm", "nn", "oo", "pp", "qq", "rr", "ss", "tt", "uu", "vv",
                                 "ww", "xx", "yy", "zz", "aaa", "bbb", "ccc", "ddd", "eee", "fff",
                                 "ggg", "hhh", "iii", "jjj", "kkk", "lll", "mmm", "nnn", "ooo", "ppp",
                                 "qqq", "rrr", "sss", "ttt", "uuu", "vvv", "www", "xxx", "yyy", "zzz"};

std::unordered_map<int, std::vector<double>> setup_data;
std::unordered_map<int, std::vector<double>> keygen_id_data;
std::unordered_map<int, std::vector<double>> keygen_s_data;
std::unordered_map<int, std::vector<double>> enc_data;
std::unordered_map<int, std::vector<double>> rkgen_data;
std::unordered_map<int, std::vector<double>> re_enc_data;
std::unordered_map<int, std::vector<double>> dec_ori_data;
std::unordered_map<int, std::vector<double>> dec_re_data;

void test(int iter_times, int attribute_num, int lambda) {
  std::cout << "Lambda: " << lambda << " | Attribute number: " << attribute_num << "\n";
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

  HyPRE_Impl habpreks(lambda);
  auto setup_st = current_time;
  std::vector<Key *> *keys;
  for (int i = 0; i < iter_times; ++i) {
    keys = habpreks.setUp();
  }
  auto setup_ed = current_time;

  string identity = "1801110674";
  auto *attrID = new vector<string>{identity};

  Key *sk_S;
  auto keygen_s_start = current_time;
  for (int i = 0; i < iter_times; ++i) {
    sk_S = habpreks.keyGen(keys->at(1), keys->at(0), &attributes);
  }
  auto keygen_s_end = current_time;

  Key *sk_ID;
  auto keygen_id_start = current_time;
  for (int i = 0; i < iter_times; ++i) {
    sk_ID = habpreks.keyGen(keys->at(1), keys->at(0), identity);
  }
  auto keygen_id_end = current_time;

  element_t key_ele;
  element_init_GT(key_ele, reinterpret_cast<pairing_s *>(habpreks.getPairing()));
  element_random(key_ele);
  auto enc_st = current_time;
  Ciphertext *ibe_ciphertext;
  for (int i = 0; i < iter_times; ++i) {
    ibe_ciphertext = habpreks.encrypt(key_ele, identity, keys->at(1));
  }
  auto enc_ed = current_time;

  auto rkgen_st = current_time;
  Ciphertext *rk, *reEncryptedCT;
  for (int i = 0; i < iter_times; ++i) {
    rk = habpreks.rkGen(keys->at(1), sk_ID, policy);
  }
  auto rkgen_ed = current_time;

  auto reenc_st = current_time;
  for (int i = 0; i < iter_times; ++i) {
    reEncryptedCT = habpreks.reEnc(keys->at(1), rk, ibe_ciphertext);
  }
  auto reenc_ed = current_time;

  element_s *ibe_plaintext, *plaintext2;
  auto dec_1_st = current_time;
  for (int i = 0; i < iter_times; ++i) {
    ibe_plaintext = habpreks.decrypt(ibe_ciphertext, sk_ID, attrID, "identity");
  }
  auto dec_1_ed = current_time;

  auto dec_2_st = current_time;
  for (int i = 0; i < iter_times; ++i) {
    plaintext2 = habpreks.decrypt(reEncryptedCT, sk_S, &attributes, "attributes");
  }
  auto dec_2_ed = current_time;

  setup_data[lambda].emplace_back((double) duration_time(setup_ed, setup_st) / iter_times / 100.0);
  keygen_id_data[lambda].emplace_back((double) duration_time(keygen_id_end, keygen_id_start) / iter_times / 100.0);
  keygen_s_data[lambda].emplace_back((double) duration_time(keygen_s_end, keygen_s_start) / iter_times / 100.0);
  enc_data[lambda].emplace_back((double) duration_time(enc_ed, enc_st) / iter_times / 100.0);
  rkgen_data[lambda].emplace_back((double) duration_time(rkgen_ed, rkgen_st) / iter_times / 100.0);
  re_enc_data[lambda].emplace_back((double) duration_time(reenc_ed, reenc_st) / iter_times / 100.0);
  dec_ori_data[lambda].emplace_back((double) duration_time(dec_1_ed, dec_1_st) / iter_times / 100.0);
  dec_re_data[lambda].emplace_back((double) duration_time(dec_2_ed, dec_2_st) / iter_times / 100.0);

  std::cout << "/*************************** Test Results ***************************/\n";
  std::cout << "Keygen for id time: " << duration_time(keygen_id_end, keygen_id_start) / iter_times << " (us)\n";
  std::cout << "Keygen for attrs time: " << duration_time(keygen_s_end, keygen_s_start) / iter_times << " (us)\n";
  std::cout << "Encrypt time: " << duration_time(enc_ed, enc_st) / iter_times << " (us)\n";
  std::cout << "RKGen time: " << duration_time(rkgen_ed, rkgen_st) / iter_times << " (us)\n";
  std::cout << "ReEncrypt time: " << duration_time(reenc_ed, reenc_st) / iter_times << " (us)\n";
  std::cout << "DecryptOri time: " << duration_time(dec_1_ed, dec_1_st) / iter_times << " (us)\n";
  std::cout << "DecryptRe time: " << duration_time(dec_2_ed, dec_2_st) / iter_times << " (us)\n";
  std::cout << "---------------------------------------------\n";
}

void PrintVector(const std::vector<double> &vec) {
  std::cout << "[";
  for (int i = 0; i < vec.size(); ++i) {
    if (i) { std::cout << ", "; }
    std::cout << vec[i];
  }
  std::cout << "]\n";
}

std::vector<int> params = {192, 224, 256, 384, 521};

int main() {
  for (auto &param : params) {
    for (int i = 5; i <= 30; i += 5) {
      test(5, i, param);
    }
  }
  for (auto &param : params) {
    std::cout << "setup_" << param << "=";
    PrintVector(setup_data[param]);
//    std::cout << "keygen_id_" << param << "=";
//    PrintVector(keygen_id_data[param]);
//    std::cout << "keygen_s_" << param << "=";
//    PrintVector(keygen_s_data[param]);
//    std::cout << "enc_" << param << "=";
//    PrintVector(enc_data[param]);
//    std::cout << "rkgen_" << param << "=";
//    PrintVector(rkgen_data[param]);
//    std::cout << "reenc_" << param << "=";
//    PrintVector(re_enc_data[param]);
//    std::cout << "dec_ori_" << param << "=";
//    PrintVector(dec_ori_data[param]);
//    std::cout << "dec_re_" << param << "=";
//    PrintVector(dec_re_data[param]);
  }

  return 0;
}
