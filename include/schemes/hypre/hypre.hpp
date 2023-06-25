//
// Created by fengxinyu on 2021-05-07.
//

#ifndef ABE_HAB_PRE_KS_HPP
#define ABE_HAB_PRE_KS_HPP

#include "../../basis.h"
#include "../../scheme_structure/scheme_structure.h"

class HyPRE
{
protected:
  pairing_t pairing{};
public:
  pairing_t *getPairing();

  virtual vector<Key *> *setUp() = 0;

  virtual Key *keyGen(Key *public_key, Key *master_key, vector<string> *attributes) = 0;

  virtual Key *keyGen(Key *public_key, Key *master_key, string identity) = 0;

  virtual Ciphertext *encrypt(element_s *m, string policy, Key *public_key) = 0;

  virtual element_s *decrypt(Ciphertext *ciphertext, Key *secret_key, vector<string> *attributes, string type) = 0;

  virtual Ciphertext *rkGen(Key *public_key, Key *secret_key, string policy) = 0;

  virtual Ciphertext *reEnc(Key *public_key, Ciphertext *reEncryptionKey, Ciphertext *ciphertext) = 0;
};

#endif //ABE_HAB_PRE_KS_HPP
