//
// Created by fengxinyu on 2021-05-07.
//

#include <cstring>
#include <cstdio>
#include "hypre_impl.hpp"

HyPRE_Impl::HyPRE_Impl() {
  // init pairing
  pbc_param_t par;
  curve_param curves;
  pbc_param_init_set_str(par, curve_param::a_param.c_str());
//    pbc_param_init_a_gen(par, 3, 3);
  pairing_init_pbc_param(pairing, par);
}

vector<Key *> *HyPRE_Impl::setUp() {
  element_t g, g_a, g_b, g_c, u, h, f, w, v;
  element_t alpha, a, b, c;
  element_t e_gg, e_gg_alpha;

  element_init_G1(g, pairing);
  element_init_G1(u, pairing);
  element_init_G1(h, pairing);
  element_init_G1(w, pairing);
  element_init_G1(v, pairing);
  element_init_G1(f, pairing);
  element_init_G1(g_a, pairing);
  element_init_G1(g_b, pairing);
  element_init_G1(g_c, pairing);

  element_init_Zr(alpha, pairing);
  element_init_Zr(a, pairing);
  element_init_Zr(b, pairing);
  element_init_Zr(c, pairing);

  element_init_GT(e_gg, pairing);
  element_init_GT(e_gg_alpha, pairing);

  element_random(g);
  element_random(u);
  element_random(h);
  element_random(w);
  element_random(v);
  element_random(f);
  element_random(alpha);
  element_random(a);
  element_random(b);
  element_random(c);
  element_pow_zn(g_a, g, a);
  element_pow_zn(g_b, g, b);
  element_pow_zn(g_c, g, c);
  element_pairing(e_gg, g, g);
  element_pow_zn(e_gg_alpha, e_gg, alpha);

  Key *master_key = new Key(Key::MASTER);
  Key *public_key = new Key(Key::PUBLIC);

  master_key->insertComponent("alpha", "ZR", alpha);
  master_key->insertComponent("a", "ZR", a);
  master_key->insertComponent("b", "ZR", b);

  public_key->insertComponent("g", "G1", g);
  public_key->insertComponent("u", "G1", u);
  public_key->insertComponent("h", "G1", h);
  public_key->insertComponent("w", "G1", w);
  public_key->insertComponent("v", "G1", v);
  public_key->insertComponent("f", "G1", f);
  public_key->insertComponent("g_a", "G1", g_a);
  public_key->insertComponent("g_b", "G1", g_b);
  public_key->insertComponent("g_c", "G1", g_c);
  public_key->insertComponent("e_gg_alpha", "GT", e_gg_alpha);

  auto *res = new vector<Key *>(2);
  (*res)[0] = master_key;
  (*res)[1] = public_key;

  return res;
}

Key *HyPRE_Impl::keyGen(Key *public_key, Key *master_key, string identity) {
  Key *res = new Key();

  // obtain public parameters
  element_t g, u, h, w, f, g_c;
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
  element_init_same_as(g_c, public_key->getComponent("g_c"));
  element_set(g_c, public_key->getComponent("g_c"));

  // obtain master key
  element_t alpha, a, b;
  element_init_same_as(alpha, master_key->getComponent("alpha"));
  element_set(alpha, master_key->getComponent("alpha"));
  element_init_same_as(a, master_key->getComponent("a"));
  element_set(a, master_key->getComponent("a"));
  element_init_same_as(b, master_key->getComponent("b"));
  element_set(b, master_key->getComponent("b"));

  // generate r and -r
  element_t r;
  element_init_Zr(r, pairing);
  element_random(r);
  element_t neg_r;
  element_init_Zr(neg_r, pairing);
  element_neg(neg_r, r);

  // compute K0, K1
  element_t K0, K1, K2, V, Z;
  element_t g_alpha, w_r;
  element_init_G1(K0, pairing);
  element_init_G1(K1, pairing);
  element_init_G1(K2, pairing);
  element_init_G1(V, pairing);
  element_init_G1(Z, pairing);
  element_init_G1(g_alpha, pairing);
  element_init_G1(w_r, pairing);
  element_pow_zn(g_alpha, g, alpha);
  element_pow_zn(w_r, w, r);
  element_mul(K0, g_alpha, w_r);
  element_pow_zn(K2, g, r);
  element_pow_zn(Z, f, r);

  res->insertComponent("K0", "G1", K0);
  res->insertComponent("K2", "G1", K2);
  res->insertComponent("Z", "G1", Z);

  //g^(ac/b)
  element_t a_b;
  element_init_Zr(a_b, pairing);
  element_div(a_b, a, b);
  element_t g_ac_b;
  element_init_G1(g_ac_b, pairing);
  element_pow_zn(g_ac_b, g_c, a_b);

  //g^(-r/b)
  element_t neg_r_b;
  element_init_Zr(neg_r_b, pairing);
  element_div(neg_r_b, neg_r, b);
  element_t g_neg_r_b;
  element_init_G1(g_neg_r_b, pairing);
  element_pow_zn(g_neg_r_b, g, neg_r_b);

  //g^(ac/b) / g^(r/b)
  element_mul(V, g_ac_b, g_neg_r_b);
  res->insertComponent("V", "G1", V);

  element_t ID;
  element_init_Zr(ID, pairing);

  // compute ID
  unsigned char hash_str_byte[SHA256_DIGEST_LENGTH];
  SHA256_CTX sha256;
  SHA256_Init(&sha256);
  SHA256_Update(&sha256, identity.c_str(), identity.size());
  SHA256_Final(hash_str_byte, &sha256);
  element_from_hash(ID, hash_str_byte, SHA256_DIGEST_LENGTH);

  // compute K1
  element_t u_ID, u_ID_h;
  element_init_G1(u_ID, pairing);
  element_init_G1(u_ID_h, pairing);
  element_pow_zn(u_ID, u, ID);
  element_mul(u_ID_h, u_ID, h);
  element_pow_zn(K1, u_ID_h, neg_r);
  res->insertComponent("K1", "G1", K1);

  return res;
}

Key *HyPRE_Impl::keyGen(Key *public_key, Key *master_key, vector<string> *attributes) {
  Key *res = new Key();

  // obtain public parameters
  element_t g, u, h, w, v, f, g_c;
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
  element_init_same_as(g_c, public_key->getComponent("g_c"));
  element_set(g_c, public_key->getComponent("g_c"));

  // obtain master key
  element_t alpha, a, b;
  element_init_same_as(alpha, master_key->getComponent("alpha"));
  element_set(alpha, master_key->getComponent("alpha"));
  element_init_same_as(a, master_key->getComponent("a"));
  element_set(a, master_key->getComponent("a"));
  element_init_same_as(b, master_key->getComponent("b"));
  element_set(b, master_key->getComponent("b"));

  // generate r and -r
  element_t r, rtilde;
  element_init_Zr(r, pairing);
  element_init_Zr(rtilde, pairing);
  element_random(r);
  element_random(rtilde);

  element_t neg_r, neg_rtilde;
  element_init_Zr(neg_r, pairing);
  element_init_Zr(neg_rtilde, pairing);
  element_neg(neg_r, r);
  element_neg(neg_rtilde, rtilde);

  // compute K0, K1
  element_t K0, K1, V, Y1, Z;
  element_t g_alpha, w_r;
  element_init_G1(K0, pairing);
  element_init_G1(K1, pairing);
  element_init_G1(V, pairing);
  element_init_G1(Y1, pairing);
  element_init_G1(Z, pairing);
  element_init_G1(g_alpha, pairing);
  element_init_G1(w_r, pairing);
  element_pow_zn(g_alpha, g, alpha);
  element_pow_zn(w_r, w, r);
  element_mul(K0, g_alpha, w_r);
  element_pow_zn(K1, g, r);

  // V
  element_t a_b, neg_rtilde_b;
  element_init_Zr(a_b, pairing);
  element_init_Zr(neg_rtilde_b, pairing);
  element_div(a_b, a, b);
  element_div(neg_rtilde_b, neg_rtilde, b);
  element_t g_ac_b, g_neg_rtilde_b;
  element_init_G1(g_ac_b, pairing);
  element_init_G1(g_neg_rtilde_b, pairing);
  element_pow_zn(g_ac_b, g_c, a_b);
  element_pow_zn(g_neg_rtilde_b, g, neg_rtilde_b);
  element_mul(V, g_ac_b, g_neg_rtilde_b);

  element_pow_zn(Y1, g, rtilde);

  element_pow_zn(Z, f, rtilde);

  res->insertComponent("K0", "G1", K0);
  res->insertComponent("K1", "G1", K1);
  res->insertComponent("V", "G1", V);
  res->insertComponent("Y1", "G1", Y1);
  res->insertComponent("Z", "G1", Z);

  //-----------------------debug-----------------------
  res->insertComponent("rtilde", "ZR", rtilde);
  //-----------------------debug-----------------------


  element_t neg_rtildetau_b;
  element_init_Zr(neg_rtildetau_b, pairing);

  element_t g_neg_rtildetau_b;
  element_init_G1(g_neg_rtildetau_b, pairing);

  for (auto &attribute: *attributes) {
    element_t rtau;
    element_init_Zr(rtau, pairing);
    element_t Ktau2, Ktau3;
    element_init_G1(Ktau2, pairing);
    element_init_G1(Ktau3, pairing);
    element_t Atau;
    element_init_Zr(Atau, pairing);
    element_t u_Atau, u_Atau_h, u_Atau_h_rtau;
    element_t v_neg_r;
    element_init_G1(u_Atau, pairing);
    element_init_G1(u_Atau_h, pairing);
    element_init_G1(u_Atau_h_rtau, pairing);
    element_init_G1(v_neg_r, pairing);

    // generate random r tau
    element_random(rtau);

    // compute Ktau2
    element_pow_zn(Ktau2, g, rtau);

    // compute Atau
    unsigned char hash_str_byte[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, attribute.c_str(), attribute.size());
    SHA256_Final(hash_str_byte, &sha256);
    element_from_hash(Atau, hash_str_byte, SHA256_DIGEST_LENGTH);

    // compute Ktau3
    element_pow_zn(u_Atau, u, Atau);
    element_mul(u_Atau_h, u_Atau, h);
    element_pow_zn(u_Atau_h_rtau, u_Atau_h, rtau);
    element_pow_zn(v_neg_r, v, neg_r);
    element_mul(Ktau3, u_Atau_h_rtau, v_neg_r);

    // compute Ytau2
    element_t Ytau2;
    element_init_G1(Ytau2, pairing);
    element_pow_zn(Ytau2, u_Atau_h, rtilde);

    res->insertComponent("K" + attribute + "2", "G1", Ktau2);
    res->insertComponent("K" + attribute + "3", "G1", Ktau3);
    res->insertComponent("Y" + attribute + "2", "G1", Ytau2);
  }

  return res;
}

Ciphertext *HyPRE_Impl::encrypt(element_s *m, string identity, Key *public_key) {
  element_t sample_element;
  element_init_Zr(sample_element, pairing);
  auto *res = new Ciphertext(identity);

  policy_resolution pr;
  policy_generation pg;
  utils util;
  vector<string> *postfix_expression = pr.infixToPostfix(identity);
  binary_tree *binary_tree_expression = pr.postfixToBinaryTree(postfix_expression, sample_element);
  pg.generatePolicyInMatrixForm(binary_tree_expression);
  element_t_matrix *M = pg.getPolicyInMatrixFormFromTree(binary_tree_expression);
  map<signed long int, string> *rho = pg.getRhoFromTree(binary_tree_expression);

  // obtain public parameters
  element_t g, u, h, w, f, g_a, g_b, g_c;
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
  element_init_same_as(g_a, public_key->getComponent("g_a"));
  element_set(g_a, public_key->getComponent("g_a"));
  element_init_same_as(g_b, public_key->getComponent("g_b"));
  element_set(g_b, public_key->getComponent("g_b"));
  element_init_same_as(g_c, public_key->getComponent("g_c"));
  element_set(g_c, public_key->getComponent("g_c"));

  // generate s, t
  element_t s, t;
  element_init_Zr(s, pairing);
  element_init_Zr(t, pairing);
  element_random(s);
  element_random(t);

  // compute C
  element_t e_gg_alpha;
  element_init_GT(e_gg_alpha, pairing);
  element_set(e_gg_alpha, public_key->getComponent("e_gg_alpha"));
  element_t e_gg_alpha_s;
  element_init_GT(e_gg_alpha_s, pairing);
  element_pow_zn(e_gg_alpha_s, e_gg_alpha, s);
  element_t C;
  element_init_GT(C, pairing);
  element_mul(C, m, e_gg_alpha_s);

  // compute C0
  element_t C0;
  element_init_G1(C0, pairing);
  element_pow_zn(C0, g, s);

  //compute C1
  element_t C1;
  element_init_G1(C1, pairing);
  element_pow_zn(C1, g, t);

  //compute C2
  element_t C2;
  element_init_G1(C2, pairing);
  // compute ID
  element_t ID;
  element_init_Zr(ID, pairing);
  unsigned char hash_str_byte[SHA256_DIGEST_LENGTH];
  SHA256_CTX sha256;
  SHA256_Init(&sha256);
  SHA256_Update(&sha256, identity.c_str(), identity.size());
  SHA256_Final(hash_str_byte, &sha256);
  element_from_hash(ID, hash_str_byte, SHA256_DIGEST_LENGTH);

  element_t u_ID, u_ID_h, u_ID_h_t;
  element_init_G1(u_ID, pairing);
  element_init_G1(u_ID_h, pairing);
  element_init_G1(u_ID_h_t, pairing);
  element_pow_zn(u_ID, u, ID);
  element_mul(u_ID_h, u_ID, h);
  element_pow_zn(u_ID_h_t, u_ID_h, t);

  element_t neg_s;
  element_init_Zr(neg_s, pairing);
  element_neg(neg_s, s);
  element_t w_neg_s;
  element_init_G1(w_neg_s, pairing);
  element_pow_zn(w_neg_s, w, neg_s);
  element_mul(C2, u_ID_h_t, w_neg_s);

  //compute C3
  element_t C3;
  element_init_G1(C3, pairing);
  element_pow_zn(C3, f, s);

  res->insertComponent("C", "GT", C);
  res->insertComponent("C0", "G1", C0);
  res->insertComponent("C1", "G1", C1);
  res->insertComponent("C2", "G1", C2);
  res->insertComponent("C3", "G1", C3);

  return res;
}

Ciphertext *HyPRE_Impl::rkGen(Key *public_key, Key *secret_key, string policy) {
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

  element_init_G1(K0, pairing);
  element_init_G1(K1, pairing);
  element_init_G1(K2, pairing);
  element_set(K0, secret_key->getComponent("K0", "G1"));
  element_set(K1, secret_key->getComponent("K1", "G1"));
  element_set(K2, secret_key->getComponent("K2", "G1"));

  element_t e_gg_alpha;
  element_init_GT(e_gg_alpha, pairing);
  element_set(e_gg_alpha, public_key->getComponent("e_gg_alpha"));

  element_t d0, d1, d2, d6, d7;
  element_init_G1(d0, pairing);
  element_init_G1(d1, pairing);
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
  element_init_G1(f_tprime, pairing);
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

  res->insertComponent("d0", "G1", d0);
  res->insertComponent("d1", "G1", d1);
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
    element_t di3, di4, di5, ei3;
    element_init_G1(di3, pairing);
    element_init_G1(di4, pairing);
    element_init_G1(di5, pairing);
    element_init_G1(ei3, pairing);
    element_t w_lambdaiprime, v_tiprime;
    element_init_G1(w_lambdaiprime, pairing);
    element_init_G1(v_tiprime, pairing);
    element_pow_zn(w_lambdaiprime, w, shares->getElement(i));
    element_pow_zn(v_tiprime, v, tiprime);
    element_mul(di3, w_lambdaiprime, v_tiprime);

    element_t neg_tiprime, neg_sprime;
    element_t u_rhoi, u_rhoi_h;
    element_init_Zr(neg_tiprime, pairing);
    element_init_Zr(neg_sprime, pairing);
    element_init_G1(u_rhoi, pairing);
    element_init_G1(u_rhoi_h, pairing);
    element_neg(neg_tiprime, tiprime);
    element_neg(neg_sprime, sprime);
    element_pow_zn(u_rhoi, u, rhoi);
    element_mul(u_rhoi_h, u_rhoi, h);
    element_pow_zn(di4, u_rhoi_h, neg_tiprime);
    element_pow_zn(di5, g, tiprime);

    res->insertComponent("d" + attr + "3", "G1", di3);
    res->insertComponent("d" + attr + "4", "G1", di4);
    res->insertComponent("d" + attr + "5", "G1", di5);
  }

  return res;
}

Ciphertext *HyPRE_Impl::reEnc(Key *public_key, Ciphertext *reEncryptionKey, Ciphertext *ciphertext) {
  auto *res = new Ciphertext(reEncryptionKey->getPolicy());

  element_t d0, d1, d2, d6, d7;
  element_init_G1(d0, pairing);
  element_init_G1(d1, pairing);
  element_init_G1(d2, pairing);
  element_init_G1(d6, pairing);
  element_init_G1(d7, pairing);
  element_set(d0, reEncryptionKey->getComponent("d0", "G1"));
  element_set(d1, reEncryptionKey->getComponent("d1", "G1"));
  element_set(d2, reEncryptionKey->getComponent("d2", "G1"));

  element_t C, C0, C1, C2, B;
  element_init_GT(C, pairing);
  element_init_GT(B, pairing);
  element_init_G1(C0, pairing);
  element_init_G1(C1, pairing);
  element_init_G1(C2, pairing);
  element_set(C, ciphertext->getComponent("C", "GT"));
  element_set(C0, ciphertext->getComponent("C0", "G1"));
  element_set(C1, ciphertext->getComponent("C1", "G1"));
  element_set(C2, ciphertext->getComponent("C2", "G1"));

  element_t e_d0_C0, e_d1_C1, e_d2_C2, e_d0_C0_e_d1_C1;
  element_init_GT(e_d0_C0, pairing);
  element_pairing(e_d0_C0, d0, C0);
  element_init_GT(e_d1_C1, pairing);
  element_pairing(e_d1_C1, d1, C1);
  element_init_GT(e_d2_C2, pairing);
  element_pairing(e_d2_C2, d2, C2);
  element_init_GT(e_d0_C0_e_d1_C1, pairing);
  element_mul(e_d0_C0_e_d1_C1, e_d0_C0, e_d1_C1);
  element_mul(B, e_d0_C0_e_d1_C1, e_d2_C2);
  element_t CPrime, C0Prime, C4Prime, C5Prime, W0Prime, W1Prime, W2Prime;
  element_init_GT(CPrime, pairing);
  element_init_G1(C0Prime, pairing);
  element_init_G1(C4Prime, pairing);
  element_init_G1(C5Prime, pairing);
  element_init_G1(W0Prime, pairing);
  element_init_G1(W1Prime, pairing);
  element_init_G1(W2Prime, pairing);
  element_div(CPrime, C, B);

  res->insertComponent("CPrime", "GT", CPrime);
  res->insertComponent("C0Prime", "G1", reEncryptionKey->getComponent("d6", "G1"));
  res->insertComponent("C4Prime", "G1", ciphertext->getComponent("C3", "G1"));
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
    res->insertComponent("C" + rho_it->second + "1Prime", "G1",
                         reEncryptionKey->getComponent("d" + rho_it->second + "3", "G1"));
    res->insertComponent("C" + rho_it->second + "2Prime", "G1",
                         reEncryptionKey->getComponent("d" + rho_it->second + "4", "G1"));
    res->insertComponent("C" + rho_it->second + "3Prime", "G1",
                         reEncryptionKey->getComponent("d" + rho_it->second + "5", "G1"));
  }

  return res;
}

element_s *HyPRE_Impl::decryptID(Ciphertext *ciphertext, Key *secret_key, vector<string> *attributes) {
  element_t C, C0, C1, C2, B;
  element_init_GT(C, pairing);
  element_init_GT(B, pairing);
  element_init_G1(C0, pairing);
  element_init_G1(C1, pairing);
  element_init_G1(C2, pairing);
  element_set(C, ciphertext->getComponent("C", "GT"));
  element_set(C0, ciphertext->getComponent("C0", "G1"));
  element_set(C1, ciphertext->getComponent("C1", "G1"));
  element_set(C2, ciphertext->getComponent("C2", "G1"));

  element_t K0, K1, K2;
  element_init_G1(K0, pairing);
  element_init_G1(K1, pairing);
  element_init_G1(K2, pairing);
  element_set(K0, secret_key->getComponent("K0", "G1"));
  element_set(K1, secret_key->getComponent("K1", "G1"));
  element_set(K2, secret_key->getComponent("K2", "G1"));
  element_t e_K0_C0, e_K1_C1, e_K2_C2, e_K0_C0_K1_C1;
  element_init_GT(e_K0_C0, pairing);
  element_init_GT(e_K1_C1, pairing);
  element_init_GT(e_K2_C2, pairing);
  element_init_GT(e_K0_C0_K1_C1, pairing);
  element_pairing(e_K0_C0, K0, C0);
  element_pairing(e_K1_C1, K1, C1);
  element_pairing(e_K2_C2, K2, C2);
  element_mul(e_K0_C0_K1_C1, e_K0_C0, e_K1_C1);
  element_mul(B, e_K0_C0_K1_C1, e_K2_C2);

  auto *res = new element_t[1];
  element_init_GT(*res, pairing);
  element_div(*res, C, B);

  return *res;
}

element_s *HyPRE_Impl::decryptS(Ciphertext *ciphertext, Key *secret_key, vector<string> *attributes) {
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
  element_pairing(e_C5Prime_K0, ciphertext->getComponent("C5Prime", "G1"), secret_key->getComponent("K0", "G1"));

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
    element_init_G1(Ci1Prime, pairing);
    element_init_G1(K1, pairing);
    element_init_G1(Ci2Prime, pairing);
    element_init_G1(Kj2, pairing);
    element_init_G1(Ci3Prime, pairing);
    element_init_G1(Kj3, pairing);
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
    element_pairing(e_Ci1Prime_K1, Ci1Prime, K1);
    element_pairing(e_Ci2Prime_Kj2, Ci2Prime, Kj2);
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
  element_pairing(e_gtPrime_C4Prime, g_tPrime, ciphertext->getComponent("C4Prime", "G1"));
  element_set(CPrime, ciphertext->getComponent("CPrime", "GT"));

  auto *res = new element_t[1];
  element_init_GT(*res, pairing);
  element_mul(*res, CPrime, e_gtPrime_C4Prime);

  return *res;
}

element_s *HyPRE_Impl::decrypt(Ciphertext *ciphertext, Key *secret_key, vector<string> *attributes, string type) {
  if ("identity" == type) {
    return this->decryptID(ciphertext, secret_key, attributes);
  } else if ("attributes" == type) {
    return this->decryptS(ciphertext, secret_key, attributes);
  }
  return nullptr;
}