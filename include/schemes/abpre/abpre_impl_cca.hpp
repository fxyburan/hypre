//
// Created by Xinyu Feng on 2023/7/27.
//

#ifndef HYPRE_INCLUDE_SCHEMES_ABPRE_ABPRE_IMPL_H_
#define HYPRE_INCLUDE_SCHEMES_ABPRE_ABPRE_IMPL_H_

#include "basis.h"
#include "scheme_structure/scheme_structure.h"
#include "extend_math_operation/extend_math_operation.h"
#include "curves/curve_param.h"
#include "utils/utils.h"
#include "abpre.hpp"

class ABPRE_Impl : public ABPRE {
 private:
  element_s *decryptID(Ciphertext *ciphertext, Key *secret_key, vector<string> *attributes);

  element_s *decryptS(Ciphertext *ciphertext, Key *secret_key, vector<string> *attributes);

 public:
  ABPRE_Impl();

  vector<Key *> *setUp() override;

  Key *keyGen(Key *public_key, Key *master_key, vector<string> *attributes) override;

  Ciphertext *encrypt(element_s *m, const string &policy, Key *public_key) override;

  element_s *decrypt(Ciphertext *ciphertext, Key *secret_key, vector<string> *attributes, const string &type) override;

  Ciphertext *rkGen(Key *public_key, Key *secret_key, const string &policy) override;

  Ciphertext *reEnc(Key *public_key, Ciphertext *reEncryptionKey, Ciphertext *ciphertext) override;
};

#endif //HYPRE_INCLUDE_SCHEMES_ABPRE_ABPRE_IMPL_H_
