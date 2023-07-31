//
// Created by fengxinyu on 2021-05-07.
//

#include <cstring>
#include <cstdio>
#include "schemes/abpre/abpre_impl_cca.hpp"

ABPRE_Impl::ABPRE_Impl() {
  // init pairing
  pbc_param_t par;
  curve_param curves;
  pbc_param_init_set_str(par, curve_param::d224_param.c_str());
//    pbc_param_init_a_gen(par, 3, 3);
  pairing_init_pbc_param(pairing, par);
}

vector<Key *> *ABPRE_Impl::setUp() {
  element_t g, g2, u, h, f, w, v;
  element_t alpha;
  element_t e_gg, e_gg_alpha;

  element_init_G1(g, pairing);
  element_init_G2(g2, pairing);
  element_init_G2(u, pairing);
  element_init_G2(h, pairing);
  element_init_G2(w, pairing);
  element_init_G2(v, pairing);
  element_init_G2(f, pairing);

  element_init_Zr(alpha, pairing);

  element_init_GT(e_gg, pairing);
  element_init_GT(e_gg_alpha, pairing);

  element_random(g);
  element_random(g2);
  element_random(u);
  element_random(h);
  element_random(w);
  element_random(v);
  element_random(f);
  element_random(alpha);
  element_pairing(e_gg, g, g2);
  element_pow_zn(e_gg_alpha, e_gg, alpha);

  Key *master_key = new Key(Key::MASTER);
  Key *public_key = new Key(Key::PUBLIC);

  master_key->insertComponent("alpha", "ZR", alpha);

  public_key->insertComponent("g", "G1", g);
  public_key->insertComponent("g2", "G2", g2);
  public_key->insertComponent("u", "G2", u);
  public_key->insertComponent("h", "G2", h);
  public_key->insertComponent("w", "G2", w);
  public_key->insertComponent("v", "G2", v);
  public_key->insertComponent("f", "G2", f);
  public_key->insertComponent("e_gg_alpha", "GT", e_gg_alpha);

  auto *res = new vector<Key *>(2);
  (*res)[0] = master_key;
  (*res)[1] = public_key;
  return res;
}

Key *ABPRE_Impl::keyGen(Key *public_key, Key *master_key, std::vector<std::string> *attributes) {
  Key *res = new Key();

  return res;
}

Ciphertext *ABPRE_Impl::encrypt(element_s *m, const string &policy, Key *public_key) {
  element_t sample_element;
  element_init_Zr(sample_element, pairing);
  auto *res = new Ciphertext(policy);

  policy_resolution pr;
  policy_generation pg;
  utils util;
  vector<string> *postfix_expression = pr.infixToPostfix(policy);
  binary_tree *binary_tree_expression = pr.postfixToBinaryTree(postfix_expression, sample_element);
  pg.generatePolicyInMatrixForm(binary_tree_expression);
  element_t_matrix *M = pg.getPolicyInMatrixFormFromTree(binary_tree_expression);
  map<signed long int, string> *rho = pg.getRhoFromTree(binary_tree_expression);

  // obtain public parameters
  element_t g, u, h, w, f;
  element_init_same_as(g, public_key->getComponent("g"));
  element_set(g, public_key->getComponent("g"));
  element_init_same_as(u, public_key->getComponent("u"));
  element_set(u, public_key->getComponent("u"));
  element_init_same_as(h, public_key->getComponent("h"));
  element_set(h, public_key->getComponent("h"));
  element_init_same_as(w, public_key->getComponent("w"));
  element_set(w, public_key->getComponent("w"));
  element_init_same_as(f, public_key->getComponent("f"));
  element_set(f, public_key->getComponent("f"));

  return res;
}

Ciphertext *ABPRE_Impl::rkGen(Key *public_key, Key *secret_key, const string &policy) {
  element_t sample_element;
  element_init_Zr(sample_element, pairing);
  auto *res = new Ciphertext(policy);

  policy_resolution pr;
  policy_generation pg;
  utils util;
  vector<string> *postfix_expression = pr.infixToPostfix(policy);
  binary_tree *binary_tree_expression = pr.postfixToBinaryTree(postfix_expression, sample_element);
  pg.generatePolicyInMatrixForm(binary_tree_expression);
  element_t_matrix *M = pg.getPolicyInMatrixFormFromTree(binary_tree_expression);
  map<signed long int, string> *rho = pg.getRhoFromTree(binary_tree_expression);

  // generate sprime
  element_t sprime;
  element_init_Zr(sprime, pairing);
  element_random(sprime);

  // generate vector y
  auto *y = new element_t_vector(M->col(), sample_element);
  element_set(y->getElement(0), sprime);
  for (signed long int i = 1; i < y->length(); ++i) {
    element_random(y->getElement(i));
  }

  // compute shares
  extend_math_operation emo;
  element_t_vector *shares = emo.multiply(M, y);

  element_t g, u, h, w, v, f;
  element_t K0, K1, K2;
  element_init_same_as(g, public_key->getComponent("g"));
  element_set(g, public_key->getComponent("g"));
  element_init_same_as(u, public_key->getComponent("u"));
  element_set(u, public_key->getComponent("u"));
  element_init_same_as(h, public_key->getComponent("h"));
  element_set(h, public_key->getComponent("h"));
  element_init_same_as(w, public_key->getComponent("w"));
  element_set(w, public_key->getComponent("w"));
  element_init_same_as(v, public_key->getComponent("v"));
  element_set(v, public_key->getComponent("v"));
  element_init_same_as(f, public_key->getComponent("f"));
  element_set(f, public_key->getComponent("f"));

  element_init_G2(K0, pairing);
  element_init_G2(K1, pairing);
  element_init_G1(K2, pairing);
  element_set(K0, secret_key->getComponent("K0", "G2"));
  element_set(K1, secret_key->getComponent("K1", "G2"));
  element_set(K2, secret_key->getComponent("K2", "G1"));

  element_t e_gg_alpha;
  element_init_GT(e_gg_alpha, pairing);
  element_set(e_gg_alpha, public_key->getComponent("e_gg_alpha"));

  element_t d0, d1, d2, d6, d7;
  element_init_G2(d0, pairing);
  element_init_G2(d1, pairing);
  element_init_G1(d2, pairing);
  element_init_G1(d6, pairing);
  element_init_G1(d7, pairing);

  // generate tprime dprime
  element_t tprime, dprime;
  element_init_Zr(tprime, pairing);
  element_init_Zr(dprime, pairing);
  element_random(tprime);
  element_random(dprime);
  element_t f_tprime;
  element_init_G2(f_tprime, pairing);
  element_pow_zn(f_tprime, f, tprime);
  element_mul(d0, K0, f_tprime);
  element_set(d1, K1);
  element_set(d2, K2);

  //d6
  element_t e_gg_alpha_sprime;
  element_init_GT(e_gg_alpha_sprime, pairing);
  element_pow_zn(e_gg_alpha_sprime, e_gg_alpha, sprime);
  element_t g_tprime;
  element_init_G1(g_tprime, pairing);
  element_pow_zn(g_tprime, g, tprime);
  //GT to G1
  int e_gg_alpha_sprime_len = element_length_in_bytes(e_gg_alpha_sprime);
  auto *e_gg_alpha_sprime_str = (unsigned char *) malloc(e_gg_alpha_sprime_len);
  element_to_bytes(e_gg_alpha_sprime_str, e_gg_alpha_sprime);
  element_t F_e_gg_alpha_sprime, e_gg_alpha_sprime_zr;
  element_init_G1(F_e_gg_alpha_sprime, pairing);
  unsigned char F_hash_str_byte[SHA256_DIGEST_LENGTH];
  SHA256_CTX F_sha256;
  SHA256_Init(&F_sha256);
  SHA256_Update(&F_sha256, e_gg_alpha_sprime_str, e_gg_alpha_sprime_len);
  SHA256_Final(F_hash_str_byte, &F_sha256);
  element_from_hash(F_e_gg_alpha_sprime, F_hash_str_byte, SHA256_DIGEST_LENGTH);

  element_mul(d6, F_e_gg_alpha_sprime, g_tprime);

  //d7
  element_pow_zn(d7, g, sprime);

  res->insertComponent("d0", "G2", d0);
  res->insertComponent("d1", "G2", d1);
  res->insertComponent("d2", "G1", d2);
  res->insertComponent("d6", "G1", d6);
  res->insertComponent("d7", "G1", d7);

  for (signed long int i = 0; i < M->row(); ++i) {
    // get tiprime
    element_t tiprime;
    element_init_Zr(tiprime, pairing);
    element_random(tiprime);

    // get rhoiprime
    element_t rhoi;
    element_init_Zr(rhoi, pairing);
    auto it = rho->find(i);
    string attr = it->second;
    element_set(rhoi, utils::stringToElementT(attr, "ZR", &pairing));

    // compute di3, di4, ei3
    element_t di3, di4, di5;
    element_init_G2(di3, pairing);
    element_init_G2(di4, pairing);
    element_init_G1(di5, pairing);
    element_t w_lambdaiprime, v_tiprime;
    element_init_G2(w_lambdaiprime, pairing);
    element_init_G2(v_tiprime, pairing);
    element_pow_zn(w_lambdaiprime, w, shares->getElement(i));
    element_pow_zn(v_tiprime, v, tiprime);
    element_mul(di3, w_lambdaiprime, v_tiprime);

    element_t neg_tiprime, neg_sprime;
    element_t u_rhoi, u_rhoi_h;
    element_init_Zr(neg_tiprime, pairing);
    element_init_Zr(neg_sprime, pairing);
    element_init_G2(u_rhoi, pairing);
    element_init_G2(u_rhoi_h, pairing);
    element_neg(neg_tiprime, tiprime);
    element_neg(neg_sprime, sprime);
    element_pow_zn(u_rhoi, u, rhoi);
    element_mul(u_rhoi_h, u_rhoi, h);
    element_pow_zn(di4, u_rhoi_h, neg_tiprime);
    element_pow_zn(di5, g, tiprime);

    res->insertComponent("d" + attr + "3", "G2", di3);
    res->insertComponent("d" + attr + "4", "G2", di4);
    res->insertComponent("d" + attr + "5", "G1", di5);
  }

  return res;
}

Ciphertext *ABPRE_Impl::reEnc(Key *public_key, Ciphertext *reEncryptionKey, Ciphertext *ciphertext) {
  auto *res = new Ciphertext(reEncryptionKey->getPolicy());

  element_t d0, d1, d2, d6, d7;
  element_init_G2(d0, pairing);
  element_init_G2(d1, pairing);
  element_init_G1(d2, pairing);
  element_init_G1(d6, pairing);
  element_init_G1(d7, pairing);
  element_set(d0, reEncryptionKey->getComponent("d0", "G2"));
  element_set(d1, reEncryptionKey->getComponent("d1", "G2"));
  element_set(d2, reEncryptionKey->getComponent("d2", "G1"));

  element_t C, C0, C1, C2, B;
  element_init_GT(C, pairing);
  element_init_GT(B, pairing);
  element_init_G1(C0, pairing);
  element_init_G1(C1, pairing);
  element_init_G2(C2, pairing);
  element_set(C, ciphertext->getComponent("C", "GT"));
  element_set(C0, ciphertext->getComponent("C0", "G1"));
  element_set(C1, ciphertext->getComponent("C1", "G1"));
  element_set(C2, ciphertext->getComponent("C2", "G2"));

  element_t e_d0_C0, e_d1_C1, e_d2_C2, e_d0_C0_e_d1_C1;
  element_init_GT(e_d0_C0, pairing);
  element_pairing(e_d0_C0, C0, d0);
  element_init_GT(e_d1_C1, pairing);
  element_pairing(e_d1_C1, C1, d1);
  element_init_GT(e_d2_C2, pairing);
  element_pairing(e_d2_C2, d2, C2);
  element_init_GT(e_d0_C0_e_d1_C1, pairing);
  element_mul(e_d0_C0_e_d1_C1, e_d0_C0, e_d1_C1);
  element_mul(B, e_d0_C0_e_d1_C1, e_d2_C2);

  element_t CPrime, C0Prime, C4Prime, C5Prime;
  element_init_GT(CPrime, pairing);
  element_init_G1(C0Prime, pairing);
  element_init_G2(C4Prime, pairing);
  element_init_G1(C5Prime, pairing);
  element_div(CPrime, C, B);

  res->insertComponent("CPrime", "GT", CPrime);
  res->insertComponent("C0Prime", "G1", reEncryptionKey->getComponent("d6", "G1"));
  res->insertComponent("C4Prime", "G2", ciphertext->getComponent("C3", "G2"));
  res->insertComponent("C5Prime", "G1", reEncryptionKey->getComponent("d7", "G1"));

  // get M and rho
  element_t sample_element;
  element_init_Zr(sample_element, pairing);
  policy_resolution pr;
  policy_generation pg;
  vector<string> *postfix_expression = pr.infixToPostfix(reEncryptionKey->getPolicy());
  binary_tree *binary_tree_expression = pr.postfixToBinaryTree(postfix_expression, sample_element);
  pg.generatePolicyInMatrixForm(binary_tree_expression);
  element_t_matrix *M = pg.getPolicyInMatrixFormFromTree(binary_tree_expression);
  map<signed long int, string> *rho = pg.getRhoFromTree(binary_tree_expression);

  map<signed long, string>::iterator rho_it;
  for (rho_it = rho->begin(); rho_it != rho->end(); ++rho_it) {
    res->insertComponent("C" + rho_it->second + "1Prime", "G2",
                         reEncryptionKey->getComponent("d" + rho_it->second + "3", "G2"));
    res->insertComponent("C" + rho_it->second + "2Prime", "G2",
                         reEncryptionKey->getComponent("d" + rho_it->second + "4", "G2"));
    res->insertComponent("C" + rho_it->second + "3Prime", "G1",
                         reEncryptionKey->getComponent("d" + rho_it->second + "5", "G1"));
  }

  return res;
}

element_s *ABPRE_Impl::decryptID(Ciphertext *ciphertext, Key *secret_key, vector<string> *attributes) {
  element_t C, C0, C1, C2, B;
  element_init_GT(C, pairing);
  element_init_GT(B, pairing);
  element_init_G1(C0, pairing);
  element_init_G1(C1, pairing);
  element_init_G2(C2, pairing);
  element_set(C, ciphertext->getComponent("C", "GT"));
  element_set(C0, ciphertext->getComponent("C0", "G1"));
  element_set(C1, ciphertext->getComponent("C1", "G1"));
  element_set(C2, ciphertext->getComponent("C2", "G2"));

  element_t K0, K1, K2;
  element_init_G2(K0, pairing);
  element_init_G2(K1, pairing);
  element_init_G1(K2, pairing);
  element_set(K0, secret_key->getComponent("K0", "G2"));
  element_set(K1, secret_key->getComponent("K1", "G2"));
  element_set(K2, secret_key->getComponent("K2", "G1"));
  element_t e_K0_C0, e_K1_C1, e_K2_C2, e_K0_C0_K1_C1;
  element_init_GT(e_K0_C0, pairing);
  element_init_GT(e_K1_C1, pairing);
  element_init_GT(e_K2_C2, pairing);
  element_init_GT(e_K0_C0_K1_C1, pairing);
  element_pairing(e_K0_C0, C0, K0);
  element_pairing(e_K1_C1, C1, K1);
  element_pairing(e_K2_C2, K2, C2);
  element_mul(e_K0_C0_K1_C1, e_K0_C0, e_K1_C1);
  element_mul(B, e_K0_C0_K1_C1, e_K2_C2);

  auto *res = new element_t[1];
  element_init_GT(*res, pairing);
  element_div(*res, C, B);

  return *res;
}

element_s *ABPRE_Impl::decryptS(Ciphertext *ciphertext, Key *secret_key, vector<string> *attributes) {
  // get M and rho
  element_t sample_element;
  element_init_Zr(sample_element, pairing);
  policy_resolution pr;
  policy_generation pg;
  vector<string> *postfix_expression = pr.infixToPostfix(ciphertext->getPolicy());
  binary_tree *binary_tree_expression = pr.postfixToBinaryTree(postfix_expression, sample_element);
  pg.generatePolicyInMatrixForm(binary_tree_expression);
  element_t_matrix *M = pg.getPolicyInMatrixFormFromTree(binary_tree_expression);
  map<signed long int, string> *rho = pg.getRhoFromTree(binary_tree_expression);

  // compute e_C5Prime_K0
  element_t e_C5Prime_K0;
  element_init_GT(e_C5Prime_K0, pairing);
  element_pairing(e_C5Prime_K0, ciphertext->getComponent("C5Prime", "G1"), secret_key->getComponent("K0", "G2"));

  // compute wi
  utils util;
  map<signed long int, signed long int> *matchedAttributes = util.attributesMatching(attributes, rho);
  element_t_matrix *attributesMatrix = util.getAttributesMatrix(M, matchedAttributes);
  map<signed long int, signed long int> *x_to_attributes = util.xToAttributes(M, matchedAttributes);
  element_t_matrix *inverse_M = util.inverse(attributesMatrix);
  element_t_vector *unit = util.getCoordinateAxisUnitVector(inverse_M);
  auto *x = new element_t_vector(inverse_M->col(), inverse_M->getElement(0, 0));
  extend_math_operation emo;
  signed long int type = emo.gaussElimination(x, inverse_M, unit);
  if (-1 == type) {
    return nullptr;
  }

  element_t denominator;
  element_init_GT(denominator, pairing);

  map<signed long int, signed long int>::iterator it;
  for (it = matchedAttributes->begin(); it != matchedAttributes->end(); ++it) {
    // get attribute
    string attr = (*attributes)[it->second];

    // get Ci1, K1, Ci2, Ktau2, Ci3, Ktau3
    element_t Ci1Prime, Ci2Prime, Ci3Prime, K1, Kj2, Kj3;
    element_init_G2(Ci1Prime, pairing);
    element_init_G1(K1, pairing);
    element_init_G2(Ci2Prime, pairing);
    element_init_G1(Kj2, pairing);
    element_init_G1(Ci3Prime, pairing);
    element_init_G2(Kj3, pairing);
    element_set(Ci1Prime, ciphertext->getComponent("C" + attr + "1Prime"));
    element_set(K1, secret_key->getComponent("K1"));
    element_set(Ci2Prime, ciphertext->getComponent("C" + attr + "2Prime"));
    element_set(Kj2, secret_key->getComponent("K" + attr + "2"));
    element_set(Ci3Prime, ciphertext->getComponent("C" + attr + "3Prime"));
    element_set(Kj3, secret_key->getComponent("K" + attr + "3"));

    // compute e_Ci1_K1, e_Ci2_Ktau2, e_Ci3_Ktau3
    element_t e_Ci1Prime_K1, e_Ci2Prime_Kj2, e_Ci3Prime_Kj3;
    element_init_GT(e_Ci1Prime_K1, pairing);
    element_init_GT(e_Ci2Prime_Kj2, pairing);
    element_init_GT(e_Ci3Prime_Kj3, pairing);
    element_pairing(e_Ci1Prime_K1, K1, Ci1Prime);
    element_pairing(e_Ci2Prime_Kj2, Kj2, Ci2Prime);
    element_pairing(e_Ci3Prime_Kj3, Ci3Prime, Kj3);

    // compute factor_denominator
    element_t e_e, e_e_e, factor_denominator;
    element_init_GT(e_e, pairing);
    element_init_GT(e_e_e, pairing);
    element_init_GT(factor_denominator, pairing);
    element_mul(e_e, e_Ci1Prime_K1, e_Ci2Prime_Kj2);
    element_mul(e_e_e, e_e, e_Ci3Prime_Kj3);
    // get wi
    signed long int attribute_index = it->second;
    auto itt = x_to_attributes->find(attribute_index);
    signed long int x_index = itt->second;
    element_pow_zn(factor_denominator, e_e_e, x->getElement(x_index));

    if (it == matchedAttributes->begin()) {
      element_set(denominator, factor_denominator);
    } else {
      element_mul(denominator, denominator, factor_denominator);
    }
  }

  element_t e_gg_alpha_sprime;
  element_init_GT(e_gg_alpha_sprime, pairing);
  element_div(e_gg_alpha_sprime, e_C5Prime_K0, denominator);

  // get C0Prime
  element_t C0Prime;
  element_init_G1(C0Prime, pairing);
  element_set(C0Prime, ciphertext->getComponent("C0Prime"));

  //GT to G1
  int e_gg_alpha_sprime_len = element_length_in_bytes(e_gg_alpha_sprime);
  auto *e_gg_alpha_sprime_str = (unsigned char *) malloc(e_gg_alpha_sprime_len);
  element_to_bytes(e_gg_alpha_sprime_str, e_gg_alpha_sprime);
  element_t F_e_gg_alpha_sprime, e_gg_alpha_sprime_zr;
  element_init_G1(F_e_gg_alpha_sprime, pairing);
  unsigned char F_hash_str_byte[SHA256_DIGEST_LENGTH];
  SHA256_CTX F_sha256;
  SHA256_Init(&F_sha256);
  SHA256_Update(&F_sha256, e_gg_alpha_sprime_str, e_gg_alpha_sprime_len);
  SHA256_Final(F_hash_str_byte, &F_sha256);
  element_from_hash(F_e_gg_alpha_sprime, F_hash_str_byte, SHA256_DIGEST_LENGTH);

  element_t g_tPrime, CPrime, e_gtPrime_C4Prime;
  element_init_G1(g_tPrime, pairing);
  element_init_GT(CPrime, pairing);
  element_init_GT(e_gtPrime_C4Prime, pairing);
  element_div(g_tPrime, C0Prime, F_e_gg_alpha_sprime);
  element_pairing(e_gtPrime_C4Prime, g_tPrime, ciphertext->getComponent("C4Prime", "G2"));
  element_set(CPrime, ciphertext->getComponent("CPrime", "GT"));

  auto *res = new element_t[1];
  element_init_GT(*res, pairing);
  element_mul(*res, CPrime, e_gtPrime_C4Prime);

  return *res;
}

element_s *ABPRE_Impl::decrypt(Ciphertext *ciphertext,
                               Key *secret_key,
                               vector<string> *attributes,
                               const string &type) {
  if ("identity" == type) {
    return this->decryptID(ciphertext, secret_key, attributes);
  } else if ("attributes" == type) {
    return this->decryptS(ciphertext, secret_key, attributes);
  }
  return nullptr;
}