//
// Created by fengxinyu on 2021-05-07.
//

#ifndef ABE_HABPREKS_HPP
#define ABE_HABPREKS_HPP

#include "basis.h"
#include "scheme_structure/scheme_structure.h"
#include "extend_math_operation/extend_math_operation.h"
#include "curves/curve_param.h"
#include "utils/utils.h"
#include "hypre.hpp"

class HyPRE_Impl : public HyPRE
{
private:
  element_s *decryptID(Ciphertext *ciphertext, Key *secret_key, vector<string> *attributes);

  element_s *decryptS(Ciphertext *ciphertext, Key *secret_key, vector<string> *attributes);

public:
  HyPRE_Impl();

  vector<Key *> *setUp() override;

  Key *keyGen(Key *public_key, Key *master_key, string identity) override;

  Key *keyGen(Key *public_key, Key *master_key, vector<string> *attributes) override;

  Ciphertext *encrypt(element_s *m, string policy, Key *public_key) override;

  element_s *decrypt(Ciphertext *ciphertext, Key *secret_key, vector<string> *attributes, string type) override;

  Ciphertext *rkGen(Key *public_key, Key *secret_key, string policy) override;

  Ciphertext *reEnc(Key *public_key, Ciphertext *reEncryptionKey, Ciphertext *ciphertext) override;
};

#endif //ABE_HABPREKS_HPP
