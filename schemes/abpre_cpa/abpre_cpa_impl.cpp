//
// Created by fengxinyu on 2021-05-07.
//

#include <cstring>
#include <cstdio>
#include "schemes/abpre/abpre_impl_cpa.hpp"

#define print_line_num printf("Line: %d\n", __LINE__)

ABPRE_Impl::ABPRE_Impl() {
  // init pairing
  pbc_param_t par;
  curve_param curves;
  pbc_param_init_set_str(par, curve_param::a_param.c_str());
//    pbc_param_init_a_gen(par, 3, 3);
  pairing_init_pbc_param(pairing, par);
}

vector<Key *> *ABPRE_Impl::setUp() {
  std::vector<std::string> U
      {"a", "b", "c", "d", "e", "f",
       "g", "h", "i", "j", "k", "l",
       "m", "n", "o", "p", "q", "r",
       "s", "t", "u", "v", "w", "x", "y", "y", "z"};

  element_t g, phi, var_phi, Q;
  element_t alpha, a;
  element_t e_gg, e_gg_alpha;

  element_init_G1(g, pairing);
  element_init_G1(phi, pairing);
  element_init_G1(var_phi, pairing);
  element_init_G1(Q, pairing);

  element_init_Zr(alpha, pairing);
  element_init_Zr(a, pairing);

  element_init_GT(e_gg, pairing);
  element_init_GT(e_gg_alpha, pairing);

  element_random(g);
  element_random(phi);
  element_random(var_phi);
  element_random(Q);

  element_random(a);
  element_random(alpha);

  element_pairing(e_gg, g, g);

  element_pow_zn(e_gg_alpha, e_gg, alpha);

  element_t g_a, g_alpha;
  element_init_G1(g_a, pairing);
  element_pow_zn(g_a, g, a);

  element_init_G1(g_alpha, pairing);
  element_pow_zn(g_alpha, g, alpha);

  Key *master_key = new Key(Key::MASTER);
  Key *public_key = new Key(Key::PUBLIC);

  for (auto &x : U) {
    element_t f_x;
    element_init_G1(f_x, pairing);
    element_random(f_x);
    public_key->insertComponent("f_" + x, "G1", f_x);
  }

  public_key->insertComponent("g", "G1", g);
  public_key->insertComponent("phi", "G1", phi);
  public_key->insertComponent("var_phi", "G1", var_phi);
  public_key->insertComponent("Q", "G1", Q);
  public_key->insertComponent("g_a", "G1", g_a);
  public_key->insertComponent("e_gg_alpha", "GT", e_gg_alpha);

  master_key->insertComponent("g_alpha", "G1", g_alpha);

  auto *res = new vector<Key *>(2);
  (*res)[0] = master_key;
  (*res)[1] = public_key;
  return res;
}

Key *ABPRE_Impl::keyGen(Key *public_key, Key *master_key, std::vector<std::string> *attributes) {
  Key *res = new Key();
  res->setType(Key::SECRET);

  element_t g, g_alpha, g_a;
  element_init_same_as(g, public_key->getComponent("g"));
  element_set(g, public_key->getComponent("g"));
  element_init_same_as(g_alpha, master_key->getComponent("g_alpha"));
  element_set(g_alpha, master_key->getComponent("g_alpha"));
  element_init_same_as(g_a, public_key->getComponent("g_a"));
  element_set(g_a, public_key->getComponent("g_a"));

  element_t s;
  element_init_Zr(s, pairing);
  element_random(s);

  //K1
  element_t g_as;
  element_init_G1(g_as, pairing);
  element_pow_zn(g_as, g_a, s);
  element_t K1;
  element_init_G1(K1, pairing);
  element_mul(K1, g_as, g_alpha);
  res->insertComponent("K_1", "G1", K1);

  //K2
  element_t g_s;
  element_init_G1(g_s, pairing);
  element_pow_zn(g_s, g, s);
  res->insertComponent("K_2", "G1", g_s);

  for (auto &x : *attributes) {
    element_t f_x;
    element_init_same_as(f_x, public_key->getComponent("f_" + x));
    element_set(f_x, public_key->getComponent("f_" + x));

    element_t f_x_s;
    element_init_G1(f_x_s, pairing);
    element_pow_zn(f_x_s, f_x, s);
    res->insertComponent("K_" + x, "G1", f_x_s);
  }

  res->SetAttributes(*attributes);

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
  element_t g, phi, var_phi, Q, g_a, e_gg_alpha;
  element_init_same_as(g_a, public_key->getComponent("g_a"));
  element_set(g_a, public_key->getComponent("g_a"));
  element_init_same_as(g, public_key->getComponent("g"));
  element_set(g, public_key->getComponent("g"));
  element_init_same_as(phi, public_key->getComponent("phi"));
  element_set(phi, public_key->getComponent("phi"));
  element_init_same_as(var_phi, public_key->getComponent("var_phi"));
  element_set(var_phi, public_key->getComponent("var_phi"));
  element_init_same_as(Q, public_key->getComponent("Q"));
  element_set(Q, public_key->getComponent("Q"));
  element_init_same_as(e_gg_alpha, public_key->getComponent("e_gg_alpha"));
  element_set(e_gg_alpha, public_key->getComponent("e_gg_alpha"));

  element_t r;
  element_init_Zr(r, pairing);
  element_random(r);

  // generate vector y
  auto *y = new element_t_vector(M->col(), sample_element);
  element_set(y->getElement(0), r);
  for (signed long int i = 1; i < y->length(); ++i) {
    element_random(y->getElement(i));
  }

  // compute shares
  extend_math_operation emo;
  element_t_vector *shares = emo.multiply(M, y);

  element_t R;
  element_init_Zr(R, pairing);
  element_random(R);

  //C
  element_t C;
  element_init_G1(C, pairing);
  element_mul(C, m, R);
  element_t e_gg_alpha_r;
  element_init_GT(e_gg_alpha_r, pairing);
  element_pow_zn(e_gg_alpha_r, e_gg_alpha, r);

  auto *e_gg_alpha_r_str = new unsigned char[1024];
  element_to_bytes(e_gg_alpha_r_str, e_gg_alpha_r);
  auto h_e_gg_alpha_r = util.stringToElementT(reinterpret_cast<char *>(e_gg_alpha_r_str), "G1", &pairing);
  element_mul(C, C, h_e_gg_alpha_r);
  res->insertComponent("C", "G1", C);

  //C1 = g^r
  element_t C1;
  element_init_G1(C1, pairing);
  element_pow_zn(C1, g, r);
  res->insertComponent("C1", "G1", C1);

  //C2 = Q^r
  element_t C2;
  element_init_G1(C2, pairing);
  element_pow_zn(C2, Q, r);
  res->insertComponent("C2", "G1", C2);

  //C3 = g^{a\lambda_j}f_{\rho(j)}^{-r_j}
  for (unsigned int j = 0; j < M->row(); ++j) {
    element_t C3j;
    element_init_G1(C3j, pairing);
    element_pow_zn(C3j, g_a, shares->getElement(j));

    // get rj
    auto it = rho->find(j);
    string attr = it->second;
    element_t f_x;
    element_init_same_as(f_x, public_key->getComponent("f_" + attr));
    element_set(f_x, public_key->getComponent("f_" + attr));
    element_t r_j, r_j_inv;
    element_init_Zr(r_j, pairing);
    element_random(r_j);
    element_init_Zr(r_j_inv, pairing);
    element_invert(r_j_inv, r_j);

    element_pow_zn(f_x, f_x, r_j_inv);
    element_mul(C3j, C3j, f_x);
    res->insertComponent("C_3_" + std::to_string(j), "G1", C3j);

    element_t C4j;
    element_init_G1(C4j, pairing);
    element_pow_zn(C4j, g, r_j);
    res->insertComponent("C_4_" + std::to_string(j), "G1", C4j);
  }

  //C\bar = \phi^{H_2(m)}\var_phi^{H_2(R)}
  element_t C_bar;
  element_init_G1(C_bar, pairing);
  element_pow_zn(C_bar, phi, m);
  element_pow_zn(var_phi, var_phi, R);
  element_mul(C_bar, C_bar, var_phi);
  res->insertComponent("C_bar", "G1", C_bar);
  res->setPolicy(policy);

  return res;
}

Ciphertext *ABPRE_Impl::rkGen(Key *public_key, Key *secret_key, const string &policy) {
  element_t sample_element;
  element_init_Zr(sample_element, pairing);
  auto *res = new Ciphertext(policy);
  res->SetAttributes(secret_key->GetAttributes());

  policy_resolution pr;
  policy_generation pg;
  utils util;
  vector<string> *postfix_expression = pr.infixToPostfix(policy);
  binary_tree *binary_tree_expression = pr.postfixToBinaryTree(postfix_expression, sample_element);
  pg.generatePolicyInMatrixForm(binary_tree_expression);
  element_t_matrix *M = pg.getPolicyInMatrixFormFromTree(binary_tree_expression);
  map<signed long int, string> *rho = pg.getRhoFromTree(binary_tree_expression);

  // generate sprime
  element_t rtilde;
  element_init_Zr(rtilde, pairing);
  element_random(rtilde);

  // generate vector y
  auto *y = new element_t_vector(M->col(), sample_element);
  element_set(y->getElement(0), rtilde);
  for (signed long int i = 1; i < y->length(); ++i) {
    element_random(y->getElement(i));
  }

  // compute shares
  extend_math_operation emo;
  element_t_vector *shares = emo.multiply(M, y);

  element_t K1, K2;
  element_t g, phi, var_phi, Q, g_a, e_gg_alpha;
  element_init_same_as(g_a, public_key->getComponent("g_a"));
  element_set(g_a, public_key->getComponent("g_a"));
  element_init_same_as(g, public_key->getComponent("g"));
  element_set(g, public_key->getComponent("g"));
  element_init_same_as(phi, public_key->getComponent("phi"));
  element_set(phi, public_key->getComponent("phi"));
  element_init_same_as(var_phi, public_key->getComponent("var_phi"));
  element_set(var_phi, public_key->getComponent("var_phi"));
  element_init_same_as(Q, public_key->getComponent("Q"));
  element_set(Q, public_key->getComponent("Q"));
  element_init_same_as(e_gg_alpha, public_key->getComponent("e_gg_alpha"));
  element_set(e_gg_alpha, public_key->getComponent("e_gg_alpha"));

  element_init_G1(K1, pairing);
  element_init_G1(K2, pairing);
  element_set(K1, secret_key->getComponent("K_1", "G1"));
  element_set(K2, secret_key->getComponent("K_2", "G1"));

  element_t X;
  element_init_GT(X, pairing);
  element_random(X);
  auto H2X = util.Elem2Elem(X, "ZR", &pairing);

  //rk0
  element_t rk0;
  element_init_GT(rk0, pairing);
  element_pow_zn(rk0, e_gg_alpha, H2X);
  res->insertComponent("rk_0", "GT", rk0);

  //rk1
  element_t rk1;
  element_init_G1(rk1, pairing);
  element_pow_zn(rk1, K1, H2X);
  element_t delta;
  element_init_Zr(delta, pairing);
  element_random(delta);
  element_t Q_delta;
  element_init_G1(Q_delta, pairing);
  element_pow_zn(Q_delta, Q, delta);
  element_mul(rk1, rk1, Q_delta);
  res->insertComponent("rk_1", "G1", rk1);

  //rk2
  element_t rk2;
  element_init_G1(rk2, pairing);
  element_pow_zn(rk2, g, delta);
  res->insertComponent("rk_2", "G1", rk2);

  //rk3
  element_t rk3;
  element_init_G1(rk3, pairing);
  element_pow_zn(rk3, K2, H2X);
  res->insertComponent("rk_3", "G1", rk3);

  //rk4x
  auto attributes_in_sk = secret_key->GetAttributes();
  for (auto &x : attributes_in_sk) {
    element_t Kx;
    element_init_G1(Kx, pairing);
    element_set(Kx, secret_key->getComponent("K_" + x));
    element_t rk4x;
    element_init_G1(rk4x, pairing);
    element_pow_zn(rk4x, Kx, H2X);
    res->insertComponent("rk_4_" + x, "G1", rk4x);
  }

  //rk5
  element_t rk5;
  element_init_GT(rk5, pairing);
  element_t e_gg_alpha_r_tilde;
  element_init_GT(e_gg_alpha_r_tilde, pairing);
  element_pow_zn(e_gg_alpha_r_tilde, e_gg_alpha, rtilde);
  element_mul(rk5, X, e_gg_alpha_r_tilde);
  res->insertComponent("rk_5", "GT", rk5);

  //rk6
  element_t rk6;
  element_init_G1(rk6, pairing);
  element_pow_zn(rk6, g, rtilde);
  res->insertComponent("rk_6", "G1", rk6);

  for (unsigned int j = 0; j < M->row(); ++j) {
    element_t rk7j;
    element_init_G1(rk7j, pairing);
    element_pow_zn(rk7j, g_a, shares->getElement(j));

    auto it = rho->find(j);
    string attr = it->second;
    element_t f_x;
    element_init_same_as(f_x, public_key->getComponent("f_" + attr));
    element_set(f_x, public_key->getComponent("f_" + attr));
    element_t r_j_tilde, r_j_tilde_inv;
    element_init_Zr(r_j_tilde, pairing);
    element_random(r_j_tilde);
    element_init_Zr(r_j_tilde_inv, pairing);
    element_invert(r_j_tilde_inv, r_j_tilde);

    element_pow_zn(f_x, f_x, r_j_tilde_inv);
    element_mul(rk7j, rk7j, f_x);
    res->insertComponent("rk_7_" + std::to_string(j), "G1", rk7j);

    element_t rk8j;
    element_init_G1(rk8j, pairing);
    element_pow_zn(rk8j, g, r_j_tilde);
    res->insertComponent("rk_8_" + std::to_string(j), "G1", rk8j);
  }
  res->setPolicy(policy);

  return res;
}

Ciphertext *ABPRE_Impl::reEnc(Key *public_key, Ciphertext *reEncryptionKey, Ciphertext *ciphertext) {
  auto *res = new Ciphertext(reEncryptionKey->getPolicy());
  auto attributes = reEncryptionKey->GetAttributes();

  element_t C, C1, C2, C_bar;
  element_init_same_as(C, ciphertext->getComponent("C", "G1"));
  element_set(C, ciphertext->getComponent("C", "G1"));
  res->insertComponent("C_prime", "G1", C);

  element_init_same_as(C1, ciphertext->getComponent("C1", "G1"));
  element_set(C1, ciphertext->getComponent("C1", "G1"));

  element_init_same_as(C2, ciphertext->getComponent("C2", "G1"));
  element_set(C2, ciphertext->getComponent("C2", "G1"));

  element_init_same_as(C_bar, ciphertext->getComponent("C_bar", "G1"));
  element_set(C_bar, ciphertext->getComponent("C_bar", "G1"));
  res->insertComponent("C_bar_prime", "G1", C_bar);

  element_t rk0, rk1, rk2, rk3, rk5, rk6;
  element_init_same_as(rk0, reEncryptionKey->getComponent("rk_0", "GT"));
  element_set(rk0, reEncryptionKey->getComponent("rk_0", "GT"));
  res->insertComponent("C_5_prime", "G1", rk0);
  element_init_same_as(rk1, reEncryptionKey->getComponent("rk_1", "G1"));
  element_set(rk1, reEncryptionKey->getComponent("rk_1", "G1"));
  element_init_same_as(rk2, reEncryptionKey->getComponent("rk_2", "G1"));
  element_set(rk2, reEncryptionKey->getComponent("rk_2", "G1"));
  element_init_same_as(rk3, reEncryptionKey->getComponent("rk_3", "G1"));
  element_set(rk3, reEncryptionKey->getComponent("rk_3", "G1"));
  element_init_same_as(rk5, reEncryptionKey->getComponent("rk_5", "GT"));
  element_set(rk5, reEncryptionKey->getComponent("rk_5", "GT"));
  res->insertComponent("C_1_prime", "GT", rk5);
  element_init_same_as(rk6, reEncryptionKey->getComponent("rk_6", "G1"));
  element_set(rk6, reEncryptionKey->getComponent("rk_6", "G1"));
  res->insertComponent("C_2_prime", "G1", rk6);

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

  // compute wi
  utils util;
  map<signed long int, signed long int> *matchedAttributes = util.attributesMatching(&attributes, rho);
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

  element_t e_e_prod;
  element_init_GT(e_e_prod, pairing);
  element_set1(e_e_prod);
  for (unsigned int j = 0; j < M->row(); ++j) {
    element_t C3j;
    element_init_G1(C3j, pairing);
    element_set(C3j, ciphertext->getComponent("C_3_" + std::to_string(j), "G1"));

    element_t C4j;
    element_init_G1(C4j, pairing);
    element_set(C4j, ciphertext->getComponent("C_4_" + std::to_string(j), "G1"));

    auto it = rho->find(j);
    string attr = it->second;
    element_t rk_4_x;
    element_init_same_as(rk_4_x, reEncryptionKey->getComponent("rk_4_" + attr));
    element_set(rk_4_x, reEncryptionKey->getComponent("rk_4_" + attr));

    res->insertComponent("C_3_" + std::to_string(j) + "_prime",
                         "G1",
                         reEncryptionKey->getComponent("rk_7_" + std::to_string(j)));
    res->insertComponent("C_4_" + std::to_string(j) + "_prime",
                         "G1",
                         reEncryptionKey->getComponent("rk_8_" + std::to_string(j)));

    auto theta_j = x->getElement(j);
    element_t e_rk3_c3j, e_rk4x_c4j, e_e;
    element_init_GT(e_e, pairing);
    element_init_GT(e_rk3_c3j, pairing);
    element_init_GT(e_rk4x_c4j, pairing);
    element_pairing(e_rk3_c3j, rk3, C4j);
    element_pairing(e_rk4x_c4j, rk_4_x, C4j);
    element_mul(e_e, e_rk3_c3j, e_rk4x_c4j);
    element_pow_zn(e_e, e_e, theta_j);
    element_mul(e_e_prod, e_e_prod, e_e);
  }

  element_t e_rk1_c1, e_rk2_c2;
  element_init_GT(e_rk1_c1, pairing);
  element_init_GT(e_rk2_c2, pairing);
  element_pairing(e_rk1_c1, rk1, C1);
  element_pairing(e_rk2_c2, rk2, C2);
  element_t C_0_Prime;
  element_init_GT(C_0_Prime, pairing);
  element_set(C_0_Prime, e_rk1_c1);
  element_div(C_0_Prime, C_0_Prime, e_rk2_c2);
  element_div(C_0_Prime, C_0_Prime, e_e_prod);
  res->insertComponent("C_0_prime", "GT", C_0_Prime);

  return res;
}

element_s *ABPRE_Impl::decryptOri(Ciphertext *ciphertext, Key *secret_key, vector<string> *attributes) {
  element_t K1, K2;
  element_init_same_as(K1, secret_key->getComponent("K_1"));
  element_set(K1, secret_key->getComponent("K_1"));
  element_init_same_as(K2, secret_key->getComponent("K_2"));
  element_set(K2, secret_key->getComponent("K_2"));

  element_t C, C1, C2, C_bar;
  element_init_same_as(C, ciphertext->getComponent("C"));
  element_set(C, ciphertext->getComponent("C"));
  element_init_same_as(C1, ciphertext->getComponent("C1"));
  element_set(C1, ciphertext->getComponent("C1"));
  element_init_same_as(C2, ciphertext->getComponent("C2"));
  element_set(C2, ciphertext->getComponent("C2"));
  element_init_same_as(C_bar, ciphertext->getComponent("C_bar"));
  element_set(C_bar, ciphertext->getComponent("C_bar"));

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

  element_t e_e_prod;
  element_init_GT(e_e_prod, pairing);
  element_set1(e_e_prod);
  for (unsigned int j = 0; j < M->row(); ++j) {
    element_t C3j;
    element_init_G1(C3j, pairing);
    element_set(C3j, ciphertext->getComponent("C_3_" + std::to_string(j), "G1"));

    element_t C4j;
    element_init_G1(C4j, pairing);
    element_set(C4j, ciphertext->getComponent("C_4_" + std::to_string(j), "G1"));

    auto it = rho->find(j);
    string attr = it->second;
    element_t Kx;
    element_init_same_as(Kx, secret_key->getComponent("K_" + attr));
    element_set(Kx, secret_key->getComponent("K_" + attr));

    auto theta_j = x->getElement(j);

    element_t e_K2_C3j, e_Kx_C4j, e_e;
    element_init_GT(e_K2_C3j, pairing);
    element_init_GT(e_Kx_C4j, pairing);
    element_init_GT(e_e, pairing);
    element_pairing(e_K2_C3j, K2, C3j);
    element_pairing(e_Kx_C4j, Kx, C4j);
    element_mul(e_e, e_K2_C3j, e_Kx_C4j);
    element_pow_zn(e_e, e_e, theta_j);
    element_mul(e_e_prod, e_e_prod, e_e);
  }

  element_t Theta, mR;
  element_init_G1(mR, pairing);
  element_init_GT(Theta, pairing);
  element_pairing(Theta, K1, C1);

  auto *e_gg_alpha_r_str = new unsigned char[1024];
  element_to_bytes(e_gg_alpha_r_str, Theta);
  auto h_Theta = util.stringToElementT(reinterpret_cast<char *>(e_gg_alpha_r_str), "G1", &pairing);

  element_div(mR, C, h_Theta);

  auto *res = new element_t[1];
  element_init_G1(*res, pairing);
  element_set(*res, mR);

  return *res;
}

element_s *ABPRE_Impl::decryptRenc(Ciphertext *ciphertext, Key *secret_key, vector<string> *attributes) {
  element_t C_prime, C_bar_prime, C_0_prime, C_1_prime, C_2_prime, C_5_prime;
  element_init_same_as(C_prime, ciphertext->getComponent("C_prime"));
  element_set(C_prime, ciphertext->getComponent("C_prime"));
  element_init_same_as(C_bar_prime, ciphertext->getComponent("C_bar_prime"));
  element_set(C_bar_prime, ciphertext->getComponent("C_bar_prime"));
  element_init_same_as(C_0_prime, ciphertext->getComponent("C_0_prime"));
  element_set(C_0_prime, ciphertext->getComponent("C_0_prime"));
  element_init_same_as(C_1_prime, ciphertext->getComponent("C_1_prime"));
  element_set(C_1_prime, ciphertext->getComponent("C_1_prime"));
  element_init_same_as(C_2_prime, ciphertext->getComponent("C_2_prime"));
  element_set(C_2_prime, ciphertext->getComponent("C_2_prime"));
  element_init_same_as(C_5_prime, ciphertext->getComponent("C_5_prime"));
  element_set(C_5_prime, ciphertext->getComponent("C_5_prime"));

  element_t K1, K2;
  element_init_same_as(K1, secret_key->getComponent("K_1"));
  element_set(K1, secret_key->getComponent("K_1"));
  element_init_same_as(K2, secret_key->getComponent("K_2"));
  element_set(K2, secret_key->getComponent("K_2"));

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

  element_t e_e_prod;
  element_init_GT(e_e_prod, pairing);
  element_set1(e_e_prod);
  for (unsigned int j = 0; j < M->row(); ++j) {
    element_t C3j_prime;
    element_init_G1(C3j_prime, pairing);
    element_set(C3j_prime, ciphertext->getComponent("C_3_" + std::to_string(j) + "_prime", "G1"));

    element_t C4j_prime;
    element_init_G1(C4j_prime, pairing);
    element_set(C4j_prime, ciphertext->getComponent("C_4_" + std::to_string(j) + "_prime", "G1"));

    auto it = rho->find(j);
    string attr = it->second;
    element_t Kx;
    element_init_same_as(Kx, secret_key->getComponent("K_" + attr));
    element_set(Kx, secret_key->getComponent("K_" + attr));

    auto theta_j = x->getElement(j);

    element_t e_K2_C3j_prime, e_Kx_C4j_prime, e_e;
    element_init_GT(e_e, pairing);
    element_init_GT(e_K2_C3j_prime, pairing);
    element_init_GT(e_Kx_C4j_prime, pairing);
    element_pairing(e_K2_C3j_prime, K2, C3j_prime);
    element_pairing(e_Kx_C4j_prime, Kx, C4j_prime);
    element_mul(e_e, e_K2_C3j_prime, e_Kx_C4j_prime);
    element_pow_zn(e_e, e_e, theta_j);
    element_mul(e_e_prod, e_e_prod, e_e);
  }
  element_t X;
  element_init_GT(X, pairing);
  element_mul(X, C_1_prime, e_e_prod);
  element_t e_K1_C2_prime;
  element_init_GT(e_K1_C2_prime, pairing);
  element_pairing(e_K1_C2_prime, K1, C_2_prime);
  element_div(X, X, e_K1_C2_prime);
  auto H2X = util.Elem2Elem(X, "ZR", &pairing);
  element_t reci_H2X;
  element_init_Zr(reci_H2X, pairing);
  element_set1(reci_H2X);
  element_div(reci_H2X, reci_H2X, H2X);
  element_t C0_prime_reci_H2X;
  element_init_same_as(C0_prime_reci_H2X, C_0_prime);
  element_pow_zn(C0_prime_reci_H2X, C_0_prime, reci_H2X);

  auto *C0_prime_reci_H2X_bytes = new unsigned char[1024];
  element_to_bytes(C0_prime_reci_H2X_bytes, C0_prime_reci_H2X);
  auto h_C0_prime_reci_H2X = util.stringToElementT(reinterpret_cast<char *>(C0_prime_reci_H2X_bytes), "G1", &pairing);
  element_t mR;
  element_init_G1(mR, pairing);
  element_mul(mR, C_prime, h_C0_prime_reci_H2X);

  auto *res = new element_t[1];
  element_init_G1(*res, pairing);
  element_set(*res, mR);

  return *res;
}

element_s *ABPRE_Impl::decrypt(Ciphertext *ciphertext,
                               Key *secret_key,
                               vector<string> *attributes,
                               const string &type) {
  if ("ori" == type) {
    return this->decryptOri(ciphertext, secret_key, attributes);
  } else if ("renc" == type) {
    return this->decryptRenc(ciphertext, secret_key, attributes);
  }
  return nullptr;
}