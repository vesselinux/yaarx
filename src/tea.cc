/*
 *    Copyright (c) 2012-2013 Luxembourg University,
 *    Laboratory of Algorithmics, Cryptology and Security (LACS).
 *
 *    This file is part of the YAARX toolkit. YAARX stands for
 *    Yet Another ARX toolkit for analysis of ARX cryptographic algorithms.
 *
 *    YAARX is free software: you can redistribute it and/or modify
 *    it under the terms of the GNU General Public License as published by
 *    the Free Software Foundation, either version 3 of the License, or
 *    (at your option) any later version.
 *
 *    YAARX is distributed in the hope that it will be useful,
 *    but WITHOUT ANY WARRANTY; without even the implied warranty of
 *    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *    GNU General Public License for more details.
 *
 *    You should have received a copy of the GNU General Public License
 *    along with YAARX.  If not, see <http://www.gnu.org/licenses/>.
 */
/**
 * \file  tea.cc
 * \author V.Velichkov, vesselin.velichkov@uni.lu
 * \brief Common functions used in the analysis of TEA.
 */ 
#ifndef COMMON_H
#include "common.hh"
#endif
#ifndef TEA_H
#include "tea.hh"
#endif

/**
 * Round-reduced version of block cipher TEA. Reference: https://en.wikipedia.org/wiki/Tiny_Encryption_Algorithm.
 *
 * \param v plaintext.
 * \param k secret key.
 * \param nrounds number of rounds (1 \f$\le\f$ \p nrounds \f$\le\f$ 64).
 *
 */
void tea_encrypt(uint32_t* v, uint32_t* k, int nrounds)
{
  uint32_t v0=v[0], v1=v[1], sum=0, i;           /* set up */
  uint32_t delta = DELTA_INIT;                     /* a key schedule constant = DELTA_INIT*/
  uint32_t k0=k[0], k1=k[1], k2=k[2], k3=k[3];   /* cache key */
  uint32_t R = nrounds - 1;							 // counts from 0 !!
  for (i=0; i < 32; i++) {                       /* basic cycle start */	 
	 sum = ADD(sum, delta);//			 sum += delta;
	 //			 v0 += ((v1<<4) + k0) ^ (v1 + sum) ^ ((v1>>5) + k1);
	 uint32_t lv1 = LSH(v1, TEA_LSH_CONST);
	 uint32_t rv1 = RSH(v1, TEA_RSH_CONST);
	 uint32_t new_v0 = ADD(lv1, k0) ^ ADD(v1, sum) ^ ADD(rv1, k1);
	 v0 = ADD(v0, new_v0);

	 if(R == (2*i)) {
		break;
	 }
	 //			 v1 += ((v0<<4) + k2) ^ (v0 + sum) ^ ((v0>>5) + k3);  
	 uint32_t lv0 = LSH(v0, TEA_LSH_CONST);
	 uint32_t rv0 = RSH(v0, TEA_RSH_CONST);
	 uint32_t new_v1 = ADD(lv0, k2) ^ ADD(v0, sum) ^ ADD(rv0, k3);
	 v1 = ADD(v1, new_v1);
	 if(R == (2*i + 1)) {
		break;
	 }
  }                                              /* end cycle */
  v[0]=v0; v[1]=v1;
}

// the F-function of TEA
// 
//               __ k0
//              /
//       db <--[+]- << 4 <---
//        |      __          |
//        |     /  delta     |
// dd <- xor --[+]-----------<--- da 
//        |      __ k1       |
//        |     /            |
//       dc <--[+]-- >> 5 <--
// 
// 
/**
 * The F-function of block cipher TEA:
 * \f$ F(x) = ((x \ll 4) + k_0) \oplus (x + \delta) \oplus ((x \gg 5) + k_1)\f$.
 *
 * \param x input to  \f$F\f$.
 * \param k0 first round key.
 * \param k1 second round key.
 * \param delta round constant.
 * \param lsh_const LSH constant (default is 4).
 * \param rsh_const RSH constant (default is 5).
 * \return \f$F(x)\f$
 */ 
uint32_t tea_f(uint32_t x, uint32_t k0, uint32_t k1, uint32_t delta, uint32_t lsh_const, uint32_t rsh_const)
{
  uint32_t x_lsh = LSH(x, lsh_const);
  uint32_t x_rsh = RSH(x, rsh_const);
  uint32_t y = ADD(x_lsh, k0) ^ ADD(x, delta) ^ ADD(x_rsh, k1);

  return y;
}

/**
 * The F-function of block cipher TEA (\ref tea_f) computed on
 * the first \p i least-significant (LS) bits.
 *
 * \param mask_i \p i bit LSB mask.
 * \param k0 first round key.
 * \param k1 second round key.
 * \param delta round constant.
 * \param lsh_const LSH constant (default is 4).
 * \param rsh_const RSH constant (default is 5).
 * \param x_in input to  \f$F\f$.
 * \return \f$F(x)~ \mathrm{mod}~ 2^i\f$
 *
 * \attention the initial value \p x_in must be minimum 
 *            (\p rsh_const + 1) bits long so that it can be shifted 
 *            right by \p rsh_const positions.
 *
 * \see xtea_f()
 */ 
uint32_t tea_f_i(const uint32_t mask_i, 
					  const uint32_t k0, const uint32_t k1, const uint32_t delta,
					  const uint32_t lsh_const, const uint32_t rsh_const, const uint32_t x_in)
{
  uint32_t x = x_in;
  uint32_t x_lsh = LSH(x, lsh_const) & mask_i;
  uint32_t x_rsh = RSH(x, rsh_const) & mask_i;

  x_lsh = ADD(x_lsh, k0) & mask_i;
  x_rsh = ADD(x_rsh, k1) & mask_i;
  x = ADD(x, delta) & mask_i;

  uint32_t y = (x_lsh ^ x ^ x_rsh) & mask_i;

  return y;
}

/**
 * Compute all round constants of block cipher TEA.
 *
 * \param D all round constants \f$\delta\f$ of TEA.
 */
void tea_compute_delta_const(uint32_t D[TEA_NCYCLES])
{
  uint32_t sum = 0;
  uint32_t delta = DELTA_INIT;                     /* a key schedule constant */
  for(int i = 0; i < TEA_NCYCLES; i++) {              /* basic cycle start */
#if SINGLE_DELTA
	 sum = delta;					  // one delta equal to the initial value
#else
	 sum += delta;					  // different delta-s (original versoin)
	 //	 assert(1 == 0);
#endif
#if 0									  // DEBUG
	 printf("delta[%2d] %8X\n", i, sum);
#endif
	 D[i] = sum & MASK;
	 //	 D[i] = sum;
  }                                                /* end cycle */
}

/**
 * Experimentally adjust the probability of a differential for one
 * round of TEA to a fixed key over a number of chosen plaintexts.
 *
 * \param npairs number of chosen plaintext pairs (\ref NPAIRS).
 * \param round_idx index of the round.
 * \param da input difference to the TEA F function.
 * \param db output difference from the TEA F function.
 * \param key cryptographic key of TEA.
 */
#if 1
double tea_add_diff_adjust_to_key(const uint64_t npairs, const int round_idx, 
											 const uint32_t da, const uint32_t db, 
											 const  uint32_t key[4])
{
  uint64_t cnt  = 0;
  uint32_t k0 = 0;
  uint32_t k1 = 0;

  // get the round key
  if(is_even(round_idx)) {
	 k0 = key[0];
	 k1 = key[1];
  } else {
	 k0 = key[2];
	 k1 = key[3];
  }
  
  uint32_t delta = 0;
  int i = 0;
  while(i <= round_idx) {
	 if(is_even(i)) {				  // update delta every 2-nd round
		delta = ADD(delta, DELTA_INIT); // delta += DELTA_INIT;
	 }
	 i++;
  }
  //  delta = DELTA_INIT;			  // !!!
#if 0									  // DEBUG
  printf("[%s:%d] R%2d key %8X %8X delta %8X\n", __FILE__, __LINE__, round_idx + 1, k0, k1, delta);
#endif
  // Encrypt many chosen plaintext pairs {a1, a2}
  for(uint64_t j = 0; j < npairs; j++) {
	 uint32_t a1 = xrandom() & MASK;
	 uint32_t a2 = ADD(a1, da);
	 uint32_t v1, lv1, rv1, new_v0;

	 // encrypt a1
	 v1 = a1;
	 lv1 = LSH(v1, TEA_LSH_CONST);
	 rv1 = RSH(v1, TEA_RSH_CONST);
	 new_v0 = ADD(lv1, k0) ^ ADD(v1, delta) ^ ADD(rv1, k1);
	 uint32_t b1 = new_v0;;

	 // encrypt a2
	 v1 = a2;
	 lv1 = LSH(v1, TEA_LSH_CONST);
	 rv1 = RSH(v1, TEA_RSH_CONST);
	 new_v0 = ADD(lv1, k0) ^ ADD(v1, delta) ^ ADD(rv1, k1);
	 uint32_t b2 = new_v0;

	 // output difference
	 uint32_t dx = SUB(b2, b1);

	 if(dx == db) {
		cnt++;
	 }
  }
  double p = (double)cnt / (double)(npairs);
  return p;
}
#else	 // Raiden
double tea_add_diff_adjust_to_key(const uint64_t npairs, const int round_idx, 
											 const uint32_t da, const uint32_t db, 
											 const uint32_t key_in[4])
{
  uint64_t cnt  = 0;
  uint32_t k0 = 0;
  uint32_t k1 = 0;

#if 0									  // DEBUG
  printf("[%s:%d] R%2d key %8X %8X delta %8X\n", __FILE__, __LINE__, round_idx + 1, k0, k1, delta);
#endif

  uint32_t key[16] = {0};
  key[0] = key_in[0];
  key[1] = key_in[1];
  key[2] = key_in[2];
  key[3] = key_in[3];

  //  k0 = k1 = ((key[0] + key[1]) + ((key[2] + key[3]) ^ (key[0] << key[2])));

  //  for(uint32_t i = 0; i < 16; i++) {
  for(uint32_t i = 0; i < 16; i++) {
	 key[i%4] = ((key[0] + key[1]) + ((key[2] + key[3]) ^ (key[0] << key[2])));
	 //	 printf("p[%s:%d] %d %d\n", __FILE__, __LINE__, i, i / 2);
  }
  //  printf("p[%s:%d] %d %d\n", __FILE__, __LINE__, round_idx, round_idx / 2);
  assert((round_idx / 2) < 16);
  k0 = k1 = key[round_idx / 2];

  //  printf("p[%s:%d] KEY[%d] %8X\n", __FILE__, __LINE__, round_idx / 2, k0);

  // Encrypt many chosen plaintext pairs {a1, a2}
  for(uint64_t j = 0; j < npairs; j++) {
	 uint32_t a1 = xrandom() & MASK;
	 uint32_t a2 = ADD(a1, da);
	 uint32_t v1, lv1, rv1, new_v0;

	 // encrypt a1
	 v1 = a1;
	 //	 lv1 = LSH(v1, TEA_LSH_CONST);
	 //	 rv1 = RSH(v1, TEA_RSH_CONST);
	 //	 new_v0 = ADD(lv1, k0) ^ ADD(v1, delta) ^ ADD(rv1, k1);
	 lv1 = LSH(ADD(v1, k0), TEA_LSH_CONST);
	 rv1 = RSH(ADD(v1, k1), TEA_RSH_CONST);
	 new_v0 = lv1 ^ SUB(v1, k0) ^ rv1;
	 uint32_t b1 = new_v0;;

	 // encrypt a2
	 v1 = a2;
	 //	 lv1 = LSH(v1, TEA_LSH_CONST);
	 //	 rv1 = RSH(v1, TEA_RSH_CONST);
	 //	 new_v0 = ADD(lv1, k0) ^ ADD(v1, delta) ^ ADD(rv1, k1);
	 lv1 = LSH(ADD(v1, k0), TEA_LSH_CONST);
	 rv1 = RSH(ADD(v1, k1), TEA_RSH_CONST);
	 new_v0 = lv1 ^ SUB(v1, k0) ^ rv1;
	 uint32_t b2 = new_v0;

	 // output difference
	 uint32_t dx = SUB(b2, b1);

	 if(dx == db) {
		cnt++;
	 }
  }
  double p = (double)cnt / (double)(npairs);
  return p;
}
#endif  // Raiden

/**
 * Experimentally verify the probability of an \p r round differential
 * for TEA, for a fixed key, over a number of chosen plaintexts.
 *
 * \param npairs number of chosen plaintext pairs (\ref NPAIRS).
 * \param r number of rounds (1 \f$\le\f$ \p nrounds \f$\le\f$ 64).
 * \param da input state to round \p 1.
 * \param db output state after round \p r.
 * \param key cryptographic key of TEA.
 */
double tea_differential_thres_exper_fk(uint64_t npairs, int r, uint32_t key[4], uint32_t da[2], uint32_t db[2])
{
  uint64_t cnt  = 0;

  if((r % 2) == 1) { 	 // ! swapped for odd rounds
	 uint32_t temp = db[0];
	 db[0] = db[1];
	 db[1] = temp;
  }

  for(uint64_t j = 0; j < npairs; j++) {
    uint32_t a1[2] = {xrandom() & (WORD_T)MASK, xrandom() & (WORD_T)MASK};
	 uint32_t a2[2] = {ADD(a1[0], da[0]), ADD(a1[1], da[1])};

	 // Encrypt the pair {a1, a2}
	 tea_encrypt(a1, key, r);
	 tea_encrypt(a2, key, r);

	 uint32_t b1[2] = {a1[0], a1[1]};
	 uint32_t b2[2] = {a2[0], a2[1]};
	 // output difference
	 uint32_t dx[2] = {SUB(b2[0], b1[0]), SUB(b2[1], b1[1])};

	 if((dx[0] == db[0]) && (dx[1] == db[1])) {
		cnt++;
	 }
  }
  double p = (double)cnt / (double)(npairs);
  return p;
}

/**
 * Experimentally verify the probability of all 1-round differentials
 * from which an N round ADD trail for TEA is composed.
 *
 * \param nrounds number of rounds covered by the trail (\ref NROUNDS).
 * \param npairs number of chosen plaintext pairs (\ref NPAIRS).
 * \param key cryptographic key of TEA.
 * \param trail differential trail for \p nrounds.
 */
uint32_t tea_add_verify_trail(uint32_t nrounds, uint32_t npairs, uint32_t key[4], differential_t trail[NROUNDS]) 
{
  uint32_t warn_cnt = 0;
  printf("[%s:%d] Verify P for one round (2^%f CPs)... ", __FILE__, __LINE__, log2(npairs));
  for(uint32_t i = 0; i < nrounds; i++) {

	 double p_exp = tea_add_diff_adjust_to_key(npairs, i, trail[i].dx, trail[i].dy, key);
#if 1									  // DEBUG
	 printf("THE %2d: %f (2^%f) %8X <- %8X\n", i, trail[i].p, log2(trail[i].p), trail[i].dy, trail[i].dx);
	 printf("EXP %2d: %f (2^%f) %8X <- %8X\n\n", i, p_exp, log2(p_exp), trail[i].dy, trail[i].dx);
#endif
	 if((p_exp == 0.0) && (trail[i].p != 0.0)) {
		warn_cnt++;
	 }
  }
  printf("OK\n");
  return warn_cnt;
}

/**
 * 
 * Given an ADD trail for \f$N\f$ rounds of TEA, experimentally verify
 * the probabilities of the corresponding \f$N\f$ differentials:
 *
 *       - Differential for 1 round: round 0. 
 *       - Differential for 2 rounds: rounds \f$0,1\f$. 
 *       - Differential for 3 rounds: rounds \f$0,1,2\f$. 
 *       - \f$\ldots\f$
 *       - Differential for \f$N\f$ rounds: rounds \f$0,1,2,\ldots,(N-1)\f$. 
 * 
 * \param nrounds number of rounds covered by the trail (\ref NROUNDS).
 * \param npairs number of chosen plaintext pairs (\ref NPAIRS).
 * \param key cryptographic key of TEA.
 * \param trail differential trail for \p nrounds.
 */
uint32_t tea_add_verify_differential(uint32_t nrounds, uint32_t npairs, uint32_t key[4], differential_t trail[NROUNDS]) 
{
  uint32_t warn_cnt = 0;
  printf("[%s:%d] Verify P of differential (2^%f CPs)...", __FILE__, __LINE__, log2(npairs));
  double p1 = 1.0;
  for(uint32_t i = 0; i < nrounds; i++) {

	 uint32_t da[2], db[2];

	 da[1] = trail[0].dx;
	 if(i == 0) {
		da[0] = 0;
	 } else {
		da[0] = SUB(trail[1].dx, trail[0].dy);
	 }
	 if(i == 0) {
		db[1] = trail[i].dy;
	 } else {
		db[1] = ADD(trail[i].dy, trail[i-1].dx);
	 }
	 db[0] = trail[i].dx;

	 p1 *= trail[i].p;

	 int r = i + 1;				  // number of rounds
	 double p2 = tea_differential_thres_exper_fk(npairs, r, key, da, db);
#if 1									  // DEBUG
	 printf("THE %2d: %f (2^%f)\n", i, p1, log2(p1));
	 printf("EXP %2d: %f (2^%f) (%8X, %8X) <- (%8X, %8X)\n\n", i, p2, log2(p2), db[0], db[1], da[0], da[1]);
#endif
	 if((p2 == 0.0) && (p1 != 0.0)) {
		warn_cnt++;
	 }
  }
  printf("OK\n");
  return warn_cnt;
}

/**
 * Print a differential trail in LaTeX-formatted style, suitable to 
 * add in a LaTeX document.
 *
 * \param fp FILE pointer for writing; opened and closed by the calling function.
 * \param nrounds number of rounds covered by the trail (\ref NROUNDS).
 * \param keys cryptographic key of TEA.
 * \param trail differential trail for \p nrounds.
 */
void print_trail_latex(FILE* fp, uint32_t nrounds, uint32_t keys[4], differential_t trail[NROUNDS])
{
  //  assert(NKEYS == 1);
  double p_tot = 1.0;
  fprintf(fp, "\n%%------------------------\n");
  fprintf(fp, "\\texttt{key} & \\texttt{%8X} & & \\texttt{%8X} & \\texttt{%8X} & \\texttt{%8X} \\\\\n", keys[0], keys[1], keys[2], keys[3]);
  fprintf(fp, "\\toprule\n");
  fprintf(fp, "$r$ & $\\Delta y$ & & $\\Delta x$ & $p$ & $\\mathrm{log}_2 p$\\\\\n");
  fprintf(fp, "\\midrule\n");
  for(uint32_t i = 0; i < nrounds; i++) {
	 fprintf(fp, "$%2d$ & \\texttt{%8X} & $\\leftarrow$ & \\texttt{%8X} & $%f$ & $2^{%3.2f}$ \\\\\n", i + 1, trail[i].dy, trail[i].dx, trail[i].p, log2(trail[i].p));
	 //	 printf("%2d: %8X <- %8X (%f)\n", i, trail[i].dy, trail[i].dx, trail[i].p);
	 p_tot *= trail[i].p;
  }
  fprintf(fp, "\\midrule\n");
  fprintf(fp, " $\\prod_{r}$ & & & & & $2^{%3.2f}$ \\\\\n", log2(p_tot));
  fprintf(fp, "\\bottomrule\n");
  fprintf(fp, "%% TEA_ADD_P_THRES = %f, TEA_ADD_MAX_PDDT_SIZE = 2^%f, NROUNDS = %d\n", TEA_ADD_P_THRES, log2(TEA_ADD_MAX_PDDT_SIZE), NROUNDS);
}
