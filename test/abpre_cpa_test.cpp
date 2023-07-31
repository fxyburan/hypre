//
// Created by Xinyu Feng on 2023/7/27.
//
#include "schemes/abpre/abpre_impl_cpa.hpp"
int main() {
  ABPRE_Impl abpre_cpa;
  auto keys = abpre_cpa.setUp();

  auto attributes = new std::vector<std::string>{"a", "b", "c"};

  auto private_key = abpre_cpa.keyGen(keys->at(1), keys->at(0), attributes);

  std::string policy = "a&b";
  element_t m;
  element_init_G1(m, reinterpret_cast<struct pairing_s *>(abpre_cpa.getPairing()));
  element_random(m);

  auto ciphertext = abpre_cpa.encrypt(m, policy, keys->at(1));

  std::string policy2 = "a&c";
  auto rk = abpre_cpa.rkGen(keys->at(1), private_key, policy2);

  auto re_encrypted_ct = abpre_cpa.reEnc(keys->at(0), rk, ciphertext);

  auto plaintext = abpre_cpa.decrypt(ciphertext, private_key, attributes, "ori");

  auto plaintext2 = abpre_cpa.decrypt(re_encrypted_ct, private_key, attributes, "renc");

  return 0;
}