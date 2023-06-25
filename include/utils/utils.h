//
// Created by alan on 19-4-26.
//

#ifndef ABELIB_UTILS_H
#define ABELIB_UTILS_H

#include "../basis.h"
#include "../data_structure/data_structure.h"
#include "../scheme_structure/scheme_structure.h"

class utils
{
public:
  static element_s *stringToElementT(const string &str, const string &group, pairing_t *pairing);

  static map<signed long int, signed long int> *
  attributesMatching(vector<string> *attributes, map<signed long int, string> *rho);

  static element_t_matrix *getAttributesMatrix(element_t_matrix *M, map<signed long int, signed long int> *rho);

  static element_t_matrix *inverse(element_t_matrix *M);

  static element_t_vector *getCoordinateAxisUnitVector(element_t_matrix *M);

  static map<signed long int, signed long int> *
  xToAttributes(element_t_matrix *M, map<signed long int, signed long int> *rho);

  // for SAR
//    sar_tree* generateEmptySarTreeFromOneSarTree(sar_tree *tree);
  static void expandSarTree(sar_tree *tree);

  static map<sar_tree_node *, bool> *sarKUNodes(sar_tree *tree);

  static void sarRevock(string user_id, sar_kgc *kgc);

  static void sarRevock(string user_id, string attribute, sar_kgc *kgc);
};

#endif //ABELIB_UTILS_H
