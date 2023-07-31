//
// Created by Xinyu Feng on 2023/7/27.
//

#ifndef HYPRE_INCLUDE_SCHEMES_ABPRE_ABPRE_H_
#define HYPRE_INCLUDE_SCHEMES_ABPRE_ABPRE_H_

#include "basis.h"
#include "scheme_structure/scheme_structure.h"

class ABPRE {
 protected:
  pairing_t pairing{};
 public:
  pairing_t *getPairing();

  virtual vector<Key *> *setUp() = 0;

  virtual Key *keyGen(Key *public_key, Key *master_key, vector<string> *attributes) = 0;

  virtual Ciphertext *encrypt(element_s *m, const string &policy, Key *public_key) = 0;

  virtual Ciphertext *rkGen(Key *public_key, Key *secret_key, const string &policy) = 0;

  virtual Ciphertext *reEnc(Key *public_key, Ciphertext *reEncryptionKey, Ciphertext *ciphertext) = 0;

  virtual element_s *decrypt(Ciphertext *ciphertext,
                             Key *secret_key,
                             vector<string> *attributes,
                             const string &type) = 0;
};

#endif //HYPRE_INCLUDE_SCHEMES_ABPRE_ABPRE_H_
