//
// Created by alan on 19-4-26.
//

#ifndef ABELIB_CIPHERTEXT_H
#define ABELIB_CIPHERTEXT_H

#include "../basis.h"
#include "../data_structure/data_structure.h"
#include "../policy_resolution/policy_resolution.h"
#include "../policy_generation/policy_generation.h"

class Ciphertext
{
private:
  string policy;
  access_structure *A{};

  map<string, element_s *> *g1_components;
  map<string, element_s *> *g2_components;
  map<string, element_s *> *gt_components;
  map<string, element_s *> *zr_components;
public:
  Ciphertext();

  explicit Ciphertext(string policy);

  explicit Ciphertext(access_structure *A);

  Ciphertext(element_t_matrix *M, map<signed long int, string> *rho);

  access_structure *getAccessStructure();

  void setPolicy(string policyStr);

  string getPolicy();

  element_s *getComponent(const string &s, const string &group);

  void insertComponent(const string &s, const string &group, element_s *component);

  map<string, element_s *> *getComponents(const string &group);

  element_s *getComponent(const string &s);

  void printCiphertext();
};

#endif //ABELIB_CIPHERTEXT_H
