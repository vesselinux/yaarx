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
 * \file  speck-xor-threshold-search.cc 
 * \author V.Velichkov, vesselin.velichkov@uni.lu
 * \date 2012-2013
 * \brief Tests for automatic search for XOR differentials in block cipher Speck .
 */ 
#ifndef COMMON_H
#include "common.hh"
#endif
#ifndef ADP_XOR_H
#include "xdp-add.hh"
#endif
#ifndef MAX_XDP_ADD_H
#include "max-xdp-add.hh"
#endif
#ifndef SPECK_H
#include "speck.hh"
#endif
#ifndef XDP_ADD_PDDT_H
#include "xdp-add-pddt.hh"
#endif
#ifndef XDP_ADD_DIFF_SET_H
#include "xdp-add-diff-set.hh"
#endif

void speck_print_round_diffs_latex(FILE* fp, uint32_t nrounds, uint32_t keys[4], differential_t trail[NROUNDS + 1])
{
  //  assert(NKEYS == 1);
  double p_tot = 1.0;
  fprintf(fp, "\n%%------------------------\n");
  //  fprintf(fp, "\\texttt{key} & \\texttt{%8X} & & \\texttt{%8X} & \\texttt{%8X} & \\texttt{%8X} \\\\\n", keys[0], keys[1], keys[2], keys[3]);
  fprintf(fp, "\\toprule\n");
  //  fprintf(fp, "$r$ & $\\Delta y$ & & $\\Delta x$ & $p$ & $\\mathrm{log}_2 p$\\\\\n");
  fprintf(fp, "$r$ & $\\Delta X_{\\mathrm{L}}$ & $\\Delta X_{\\mathrm{R}}$ & $\\mathrm{log}_2 p$\\\\\n");
  fprintf(fp, "\\midrule\n");
  for(uint32_t i = 0; i < nrounds; i++) {
	 //	 fprintf(fp, "$%2d$ & \\texttt{%8X} & $\\rightarrow$ & \\texttt{%8X} & $%f$ & $2^{%3.2f}$ \\\\\n", i, trail[i].dx, trail[i].dy, trail[i].p, log2(trail[i].p));
	 //	 printf("%2d: %8X <- %8X (%f)\n", i, trail[i].dy, trail[i].dx, trail[i].p);
	 if(trail[i].p != 1.0) {
		fprintf(fp, "$%2d$ & \\texttt{%16llX} & \\texttt{%16llX} & $%3.2f$ \\\\\n", i, (WORD_MAX_T)trail[i].dx, (WORD_MAX_T)trail[i].dy, log2(trail[i].p));
	 } else {
		fprintf(fp, "$%2d$ & \\texttt{%16llX} & \\texttt{%16llX} & $-%3.2f$ \\\\\n", i, (WORD_MAX_T)trail[i].dx, (WORD_MAX_T)trail[i].dy, log2(trail[i].p));
	 }
	 p_tot *= trail[i].p;
  }
  uint32_t right_rot_const = SPECK_RIGHT_ROT_CONST; 
  uint32_t left_rot_const = SPECK_LEFT_ROT_CONST;
  if(WORD_SIZE == 16) {
	 right_rot_const = SPECK_RIGHT_ROT_CONST_16BITS; 
	 left_rot_const = SPECK_LEFT_ROT_CONST_16BITS;
  }
  fprintf(fp, "\\midrule\n");
  fprintf(fp, " $\\sum_{r}\\mathrm{log}_2 p_r$ & & & $%3.2f$ \\\\\n", log2(p_tot));
  //  fprintf(fp, " $\\prod_{r}$ & & & & & $2^{%3.2f}$ \\\\\n", log2(p_tot));
  fprintf(fp, " $\\mathrm{log}_2 (p_{\\mathrm{thres}})$ & & & $%3.2f$ \\\\\n", log2(SPECK_P_THRES));
  fprintf(fp, " $\\#{\\mathrm{hways}}$ & & & $%lld$ \\\\\n", SPECK_MAX_DIFF_CNT);
  fprintf(fp, " Time: & & & $0.0$ min.\\\\\n");
  fprintf(fp, "\\bottomrule\n");
  fprintf(fp, "%% WORD_SIZE = %d, SPECK_P_THRES = %f, SPECK_MAX_DIFF_CNT = 2^%f, RIGHT_ROT_CONST = %d, LEFT_ROT_CONST = %d, NROUNDS = %d\n", WORD_SIZE, SPECK_P_THRES, log2(SPECK_MAX_DIFF_CNT), right_rot_const, left_rot_const, NROUNDS);
}

/** 
  * Given an XOR trail for \f$N\f$ rounds, experimentally verify
  * the probabilities of the corresponding \f$N\f$ differentials:
  *
  *       - Differential for 1 round: round 0. 
  *       - Differential for 2 rounds: rounds \f$0,1\f$. 
  *       - Differential for 3 rounds: rounds \f$0,1,2\f$. 
  *       - \f$\ldots\f$
  *       - Differential for \f$N\f$ rounds: rounds \f$0,1,2,\ldots,(N-1)\f$. 
  */
uint32_t speck_verify_xor_differential(uint32_t nrounds, uint32_t npairs, 
													WORD_T key_in[SPECK_MAX_NROUNDS], differential_t trail[NROUNDS],
													const WORD_T dx_init, const WORD_T dy_init,
													uint32_t right_rot_const, uint32_t left_rot_const)
{
  if(WORD_SIZE == 16) {
	 assert(right_rot_const == SPECK_RIGHT_ROT_CONST_16BITS); 
	 assert(left_rot_const == SPECK_LEFT_ROT_CONST_16BITS);
  } else {
	 assert(right_rot_const == SPECK_RIGHT_ROT_CONST); 
	 assert(left_rot_const == SPECK_LEFT_ROT_CONST);
  }

  WORD_T key[SPECK_MAX_NROUNDS] = {0};
  for(uint32_t i = 0; i < SPECK_MAX_NROUNDS; i++) {
	 key[i] = key_in[i];
  }

  uint32_t word_size = WORD_SIZE;
  uint32_t key_size = speck_get_keysize(word_size);
  uint32_t nkey_words = speck_compute_nkeywords(word_size, key_size);
  speck_key_expansion(key, nrounds, nkey_words, right_rot_const, left_rot_const);

  uint32_t warn_cnt = 0;
  printf("[%s:%d] Verify P of differentials (2^%f CPs)...\n", __FILE__, __LINE__, log2(npairs));

  WORD_T dx_in = dx_init;
  WORD_T dy_in = dy_init;

  printf("Input differences: %16llX %16llX\n\n", (WORD_MAX_T)dx_in, (WORD_MAX_T)dy_in);

  double p_the = 1.0;
  for(uint32_t i = 0; i < nrounds; i++) {

	 uint32_t enc_nrounds = i+1;

	 uint32_t cnt = 0;

	 WORD_T dx_out = trail[i].dx;
	 WORD_T dy_out = trail[i].dy;
	 p_the *= trail[i].p;

	 for(uint64_t j = 0; j < npairs; j++) {
		WORD_T x1 = xrandom() & MASK;
		WORD_T x2 = XOR(x1, dx_in);

		WORD_T y1 = xrandom() & MASK;
		WORD_T y2 = XOR(y1, dy_in);

		speck_encrypt(key, enc_nrounds, right_rot_const, left_rot_const, &x1, &y1);
		speck_encrypt(key, enc_nrounds, right_rot_const, left_rot_const, &x2, &y2);

		WORD_T dx_ctext = XOR(x1, x2);
		WORD_T dy_ctext = XOR(y1, y2);

		if((dx_ctext == dx_out) && (dy_ctext == dy_out)) {
		  cnt++;
		}
	 }
	 double p_exp = (double)cnt / (double)npairs;;

#if (WORD_SIZE <= 32)									  // DEBUG
	 printf("R#%2d Output differences: %8X %8X\n", i, dx_out, dy_out);
	 printf("THE %2d: %f (2^%f) %8X -> %8X\n", i+1,   p_the, log2(p_the), trail[i].dx, trail[i].dy);
	 printf("EXP %2d: %f (2^%f) %8X -> %8X\n\n", i+1, p_exp, log2(p_exp), trail[i].dx, trail[i].dy);
#endif
#if (WORD_SIZE > 32)									  // DEBUG
	 printf("R#%2d Output differences: %16llX %16llX\n", i, (WORD_MAX_T)dx_out, (WORD_MAX_T)dy_out);
	 printf("THE %2d: %f (2^%f) %16llX -> %16llX\n", i+1,   p_the, log2(p_the), (WORD_MAX_T)trail[i].dx, (WORD_MAX_T)trail[i].dy);
	 printf("EXP %2d: %f (2^%f) %16llX -> %16llX\n\n", i+1, p_exp, log2(p_exp), (WORD_MAX_T)trail[i].dx, (WORD_MAX_T)trail[i].dy);
#endif

	 if((p_exp == 0.0) && (trail[i].p != 0.0)) {
		warn_cnt++;
	 }
  }
  //  printf("OK\n");
  return warn_cnt;
}

uint32_t speck_verify_xor_differential_decrypt(uint32_t nrounds, uint32_t npairs, 
															  WORD_T key_in[SPECK_MAX_NROUNDS], differential_t trail[NROUNDS],
															  const WORD_T dx_init, const WORD_T dy_init,
															  uint32_t right_rot_const, uint32_t left_rot_const)
{
  if(WORD_SIZE == 16) {
	 assert(right_rot_const == SPECK_RIGHT_ROT_CONST_16BITS); 
	 assert(left_rot_const == SPECK_LEFT_ROT_CONST_16BITS);
  } else {
	 assert(right_rot_const == SPECK_RIGHT_ROT_CONST); 
	 assert(left_rot_const == SPECK_LEFT_ROT_CONST);
  }

  WORD_T key[SPECK_MAX_NROUNDS] = {0};
  for(uint32_t i = 0; i < SPECK_MAX_NROUNDS; i++) {
	 key[i] = key_in[i];
  }

  uint32_t word_size = WORD_SIZE;
  uint32_t key_size = speck_get_keysize(word_size);
  uint32_t nkey_words = speck_compute_nkeywords(word_size, key_size);
  speck_key_expansion(key, nrounds, nkey_words, right_rot_const, left_rot_const);

  uint32_t warn_cnt = 0;
  printf("[%s:%d] Verify P of differentials (2^%f CPs)...\n", __FILE__, __LINE__, log2(npairs));

  WORD_T dx_in = dx_init;
  WORD_T dy_in = dy_init;

  printf("Input differences: %16llX %16llX\n\n", (WORD_MAX_T)dx_in, (WORD_MAX_T)dy_in);

  double p_the = 1.0;
  for(uint32_t i = 0; i < nrounds; i++) {

	 uint32_t enc_nrounds = i+1;

	 uint32_t cnt = 0;

	 WORD_T dx_out = trail[i].dx;
	 WORD_T dy_out = trail[i].dy;
	 p_the *= trail[i].p;

	 for(uint64_t j = 0; j < npairs; j++) {
		WORD_T x1 = xrandom() & MASK;
		WORD_T x2 = XOR(x1, dx_in);

		WORD_T y1 = xrandom() & MASK;
		WORD_T y2 = XOR(y1, dy_in);

		speck_decrypt(key, enc_nrounds, right_rot_const, left_rot_const, &x1, &y1);
		speck_decrypt(key, enc_nrounds, right_rot_const, left_rot_const, &x2, &y2);

		WORD_T dx_ctext = XOR(x1, x2);
		WORD_T dy_ctext = XOR(y1, y2);

		if((dx_ctext == dx_out) && (dy_ctext == dy_out)) {
		  cnt++;
		}
	 }
	 double p_exp = (double)cnt / (double)npairs;;

#if (WORD_SIZE <= 32)									  // DEBUG
	 printf("R#%2d Output differences: %8X %8X\n", i, dx_out, dy_out);
	 printf("THE %2d: %f (2^%f) %8X -> %8X\n", i+1,   p_the, log2(p_the), trail[i].dx, trail[i].dy);
	 printf("EXP %2d: %f (2^%f) %8X -> %8X\n\n", i+1, p_exp, log2(p_exp), trail[i].dx, trail[i].dy);
#endif
#if (WORD_SIZE > 32)									  // DEBUG
	 printf("R#%2d Output differences: %16llX %16llX\n", i, (WORD_MAX_T)dx_out, (WORD_MAX_T)dy_out);
	 printf("THE %2d: %f (2^%f) %16llX -> %16llX\n", i+1,   p_the, log2(p_the), (WORD_MAX_T)trail[i].dx, (WORD_MAX_T)trail[i].dy);
	 printf("EXP %2d: %f (2^%f) %16llX -> %16llX\n\n", i+1, p_exp, log2(p_exp), (WORD_MAX_T)trail[i].dx, (WORD_MAX_T)trail[i].dy);
#endif

	 if((p_exp == 0.0) && (trail[i].p != 0.0)) {
		warn_cnt++;
	 }
  }
  printf("OK\n");
  return warn_cnt;
}

/**
 * Experimentally verify the probability of all 1-round differentials
 * from which an N round trail is composed.
 */
uint32_t speck_verify_xor_trail(uint32_t nrounds, uint32_t npairs, 
										  WORD_T key_in[SPECK_MAX_NROUNDS], differential_t trail[NROUNDS],
										  const WORD_T dx_init, const WORD_T dy_init,
										  uint32_t right_rot_const, uint32_t left_rot_const)
{
  if(WORD_SIZE == 16) {
	 assert(right_rot_const == SPECK_RIGHT_ROT_CONST_16BITS); 
	 assert(left_rot_const == SPECK_LEFT_ROT_CONST_16BITS);
  } else {
	 assert(right_rot_const == SPECK_RIGHT_ROT_CONST); 
	 assert(left_rot_const == SPECK_LEFT_ROT_CONST);
  }

  WORD_T key[SPECK_MAX_NROUNDS] = {0};
  for(uint32_t i = 0; i < SPECK_MAX_NROUNDS; i++) {
	 key[i] = key_in[i];
  }

  uint32_t word_size = WORD_SIZE;
  uint32_t key_size = speck_get_keysize(word_size);
  uint32_t nkey_words = speck_compute_nkeywords(word_size, key_size);
  //  uint32_t nrounds_tot = speck_compute_nrounds(word_size, nkey_words);
  //  speck_compute_nrounds(word_size, nkey_words);

  speck_key_expansion(key, nrounds, nkey_words, right_rot_const, left_rot_const);

  uint32_t one_round = 1;
  uint32_t warn_cnt = 0;
  printf("[%s:%d] Verify P for one round (2^%f CPs)...\n", __FILE__, __LINE__, log2(npairs));
  for(uint32_t i = 0; i < nrounds; i++) {

	 uint32_t cnt = 0;

	 WORD_T dx_in = dx_init;
	 WORD_T dy_in = dy_init;
	 if(i > 0) {
		dx_in = trail[i-1].dx;
		dy_in = trail[i-1].dy;
	 } 
	 WORD_T dx_out = trail[i].dx;
	 WORD_T dy_out = trail[i].dy;

#if 1									  // DEBUG
	 printf("R#%2d  Input differences: %16llX %16llX\n", i, (WORD_MAX_T)dx_in, (WORD_MAX_T)dy_in);
	 printf("R#%2d Output differences: %16llX %16llX\n", i, (WORD_MAX_T)dx_out, (WORD_MAX_T)dy_out);
#endif

	 for(uint64_t j = 0; j < npairs; j++) {
		WORD_T x1 = xrandom() & MASK;
		WORD_T x2 = XOR(x1, dx_in);

		WORD_T y1 = xrandom() & MASK;
		WORD_T y2 = XOR(y1, dy_in);

		speck_encrypt(key, one_round, right_rot_const, left_rot_const, &x1, &y1);
		speck_encrypt(key, one_round, right_rot_const, left_rot_const, &x2, &y2);

		WORD_T dx_ctext = XOR(x1, x2);
		WORD_T dy_ctext = XOR(y1, y2);

		if((dx_ctext == dx_out) && (dy_ctext == dy_out)) {
		  cnt++;
		}

	 }
	 double p_exp = (double)cnt / (double)npairs;;

#if 1									  // DEBUG
	 printf("THE %2d: %f (2^%f)\n", i, trail[i].p, log2(trail[i].p));
	 printf("EXP %2d: %f (2^%f)\n\n", i, p_exp, log2(p_exp));
#endif

	 if((p_exp == 0.0) && (trail[i].p != 0.0)) {
		warn_cnt++;
	 }
  }
  printf("OK\n");
  return warn_cnt;
}

/**
 * Experimentally verify the probability of all 1-round differentials
 * from which an N round trail is composed in DECRYPT mode.
 */
uint32_t speck_verify_xor_trail_decrypt(uint32_t nrounds, uint32_t npairs, 
													 WORD_T key_in[SPECK_MAX_NROUNDS], differential_t trail[NROUNDS],
													 const WORD_T dx_init, const WORD_T dy_init,
													 uint32_t right_rot_const, uint32_t left_rot_const)
{
  if(WORD_SIZE == 16) {
	 assert(right_rot_const == SPECK_RIGHT_ROT_CONST_16BITS); 
	 assert(left_rot_const == SPECK_LEFT_ROT_CONST_16BITS);
  } else {
	 assert(right_rot_const == SPECK_RIGHT_ROT_CONST); 
	 assert(left_rot_const == SPECK_LEFT_ROT_CONST);
  }

  WORD_T key[SPECK_MAX_NROUNDS] = {0};
  for(uint32_t i = 0; i < SPECK_MAX_NROUNDS; i++) {
	 key[i] = key_in[i];
  }

  uint32_t word_size = WORD_SIZE;
  uint32_t key_size = speck_get_keysize(word_size);
  uint32_t nkey_words = speck_compute_nkeywords(word_size, key_size);
  //  uint32_t nrounds_tot = speck_compute_nrounds(word_size, nkey_words);
  //  speck_compute_nrounds(word_size, nkey_words);

  speck_key_expansion(key, nrounds, nkey_words, right_rot_const, left_rot_const);

  uint32_t one_round = 1;
  uint32_t warn_cnt = 0;
  printf("[%s:%d] Verify P for one round (2^%f CPs)...\n", __FILE__, __LINE__, log2(npairs));
  for(uint32_t i = 0; i < nrounds; i++) {

	 uint32_t cnt = 0;

	 WORD_T dx_in = dx_init;
	 WORD_T dy_in = dy_init;
	 if(i > 0) {
		dx_in = trail[i-1].dx;
		dy_in = trail[i-1].dy;
	 } 
	 WORD_T dx_out = trail[i].dx;
	 WORD_T dy_out = trail[i].dy;

#if 1									  // DEBUG
	 printf("R#%2d  Input differences: %16llX %16llX\n", i, (WORD_MAX_T)dx_in, (WORD_MAX_T)dy_in);
	 printf("R#%2d Output differences: %16llX %16llX\n", i, (WORD_MAX_T)dx_out, (WORD_MAX_T)dy_out);
#endif

	 for(uint64_t j = 0; j < npairs; j++) {
		WORD_T x1 = xrandom() & MASK;
		WORD_T x2 = XOR(x1, dx_in);

		WORD_T y1 = xrandom() & MASK;
		WORD_T y2 = XOR(y1, dy_in);

		speck_decrypt(key, one_round, right_rot_const, left_rot_const, &x1, &y1);
		speck_decrypt(key, one_round, right_rot_const, left_rot_const, &x2, &y2);

		WORD_T dx_ctext = XOR(x1, x2);
		WORD_T dy_ctext = XOR(y1, y2);

		if((dx_ctext == dx_out) && (dy_ctext == dy_out)) {
		  cnt++;
		}

	 }
	 double p_exp = (double)cnt / (double)npairs;;

#if 1									  // DEBUG
	 printf("THE %2d: %f (2^%f)\n", i, trail[i].p, log2(trail[i].p));
	 printf("EXP %2d: %f (2^%f)\n\n", i, p_exp, log2(p_exp));
#endif

	 if((p_exp == 0.0) && (trail[i].p != 0.0)) {
		warn_cnt++;
	 }
  }
  printf("OK\n");
  return warn_cnt;
}

/**
 * SPECK: For given input differences dx,dy, check if in the
 * list of differentials set_dx_dy_dz exists an entry (dx,dy->dz)
 *
 * \see xdp_add_is_dz_in_set_dx_dy_dz
 */
bool speck_xdp_add_is_dz_in_set_dx_dy_dz(uint32_t dx, uint32_t dy,
													  std::set<differential_3d_t, struct_comp_diff_3d_dx_dy_dz> diff_set_dx_dy_dz)
{
  assert(diff_set_dx_dy_dz.size() != 0);
  bool b_is_inset = false;
  std::set<differential_3d_t, struct_comp_diff_3d_dx_dy_dz>::iterator set_iter = diff_set_dx_dy_dz.begin();;
  while((set_iter != diff_set_dx_dy_dz.end()) && (!b_is_inset)) {
	 b_is_inset = ((dx == set_iter->dx) && (dy == set_iter->dy));
#if 0									  // DEBUG
	 if(b_is_inset) {
		printf("[%s:%d] Found in HW: dx dy dz %8X %8X %8X 2^%f\n", __FILE__, __LINE__, set_iter->dx, set_iter->dy, set_iter->dz, log2(set_iter->p));
	 } 
#endif
	 set_iter++;
  }
  assert(diff_set_dx_dy_dz.size() != 0);
#if 0									  // DEBUG
  if(!b_is_inset) {
	 printf("[%s:%d] NOT found in HW: dx dy %8X %8X\n", __FILE__, __LINE__, set_iter->dx, set_iter->dy);
  }
#endif
  return b_is_inset;
}

/*
 * Generate all dx, dy below certian Hamming weight and also the max dz.
 */
void speck_xdp_add_pddt_dx_dy_max_dz_i(const uint32_t k, const uint32_t n, 
													const uint32_t hw_thres, const double p_thres,
													WORD_T* da, WORD_T* db,
													differential_3d_t full_diff_set[SPECK_MAX_DIFF_CNT], const uint64_t max_len,
													uint64_t* len)
{
  if(k == n) {
	 WORD_T dc_max = 0;
	 double p_max = max_xdp_add_lm(*da, *db, &dc_max);
	 bool b_low_hw = (hamming_weight(*da) <= hw_thres) && (hamming_weight(*db) <= hw_thres);
	 assert(b_low_hw);

	 if(((*len) < max_len) && (p_max >= p_thres))  {
      // store the difference
		differential_3d_t i_diff;
		i_diff.dx = *da;
		i_diff.dy = *db;
		i_diff.dz = dc_max;
		i_diff.p = p_max;
		full_diff_set[*len] = i_diff;
		assert(p_max >= SPECK_P_THRES);
		(*len)++;
#if 0									  // DEBUG
		printf("\r[%s:%d] %10lld / %10lld | Add %8X %8X -> %8X : %f 2^%4.2f", __FILE__, __LINE__, len, len, *da, *db, dc_max, p_max, log2(p_max));
		fflush(stdout);
#endif
#if 0									  // DEBUG
		// find the smallest LSB that is active
		WORD_T t = *da | *db;
		WORD_T i = 0;
		WORD_T bit = (t >> i) & 1;
		while((!bit) && (i != (WORD_SIZE - 1))) {
		  i++;
		  bit = (t >> i) & 1;
		}
		printf("\r#bit %2d %d", i, bit);
		fflush(stdout);
#endif
#if 0									  // DEBUG
		if((*da == RROT(0x480901, SPECK_RIGHT_ROT_CONST)) && (*db == 0x94009)) { printf("\n-> ! Found 0:\n"); sleep(0);}
		if((*da == 0x400052) && (*db == 0x504200)) {printf("\n->! Found 1:\n"); sleep(0);}
		if((*da == 0x820200) && (*db == 0x1202)) {printf("\n->! Found 2:\n"); sleep(0);}
#endif
	 }
	 return;
  }

  if((*len) == max_len) {
	 return;
  }


  for(WORD_T x = 0; x < 2; x++) {
	 for(WORD_T y = 0; y < 2; y++) {

		WORD_T new_da = *da | (x << k);
		WORD_T new_db = *db | (y << k);
		bool b_low_hw = (hamming_weight(new_da) <= hw_thres) && (hamming_weight(new_db) <= hw_thres);
		if(b_low_hw) {
		  speck_xdp_add_pddt_dx_dy_max_dz_i(k+1, n, hw_thres, p_thres, &new_da, &new_db, full_diff_set, max_len, len);
		}
	 }
  }
}

void speck_xdp_add_pddt_dx_dy_max_dz(uint32_t n, const double p_thres, uint32_t hw_thres, 
												 differential_3d_t* full_diff_set, uint64_t* full_diff_set_len)
{
  assert(p_thres == SPECK_P_THRES);
  uint32_t k = 0;

  // init A
  gsl_matrix* A[2][2][2];
  xdp_add_alloc_matrices(A);
  xdp_add_sf(A);
  xdp_add_normalize_matrices(A);

  // init C
  gsl_vector* C = gsl_vector_calloc(XDP_ADD_MSIZE);
  gsl_vector_set(C, XDP_ADD_ISTATE, 1.0);

  WORD_T da = 0;
  WORD_T db = 0;
  uint64_t len = 0;

  assert(p_thres == SPECK_P_THRES);

  speck_xdp_add_pddt_dx_dy_max_dz_i(k, n, hw_thres, p_thres, &da, &db, full_diff_set, *full_diff_set_len, &len);

  //  printf("[%s:%d] Lengths full %lld len %lld\n", __FILE__, __LINE__, *full_diff_set_len, len);
  if(len < *full_diff_set_len) {
	 printf("[%s:%d] Update length %lld -> %lld\n", __FILE__, __LINE__, (WORD_MAX_T)*full_diff_set_len, (WORD_MAX_T)len);
	 //	 printf("[%s:%d] Update length %ld -> %ld\n", __FILE__, __LINE__, *full_diff_set_len, len);
	 *full_diff_set_len = len;
  }
#if 1									  // DEBUG
  printf("[%s:%d] INIT table: p_thres = %f (2^%f), hw_thres = %d, n = %d, #diffs = %lld 2^%4.2f\n", __FILE__, __LINE__, 
			p_thres, log2(p_thres), hw_thres, WORD_SIZE, (WORD_MAX_T)len, log2(len));
  //  printf("[%s:%d] INIT table: p_thres = %f (2^%f), hw_thres = %d, n = %d, #diffs = %ld 2^%4.2f\n", __FILE__, __LINE__, 
  //			p_thres, log2(p_thres), hw_thres, WORD_SIZE, len, log2(len));
#endif

  gsl_vector_free(C);
  xdp_add_free_matrices(A);
}

/**
 * Compute a pDDT for SPECK.
 * \sa xdp_add_pddt_i
 */
void speck_xdp_add_pddt_i(const uint32_t k, const uint32_t n, const double p_thres, const uint32_t hw_thres, 
								  gsl_matrix* A[2][2][2], gsl_vector* C, 
								  WORD_T* da, WORD_T* db, WORD_T* dc, double* p, 
								  std::set<differential_3d_t, struct_comp_diff_3d_dx_dy_dz>* diff_set_dx_dy_dz,
								  std::multiset<differential_3d_t, struct_comp_diff_3d_p>* diff_mset_p,
								  uint64_t max_size)
{
  if(k == n) {
	 double p_the = xdp_add(A, *da, *db, *dc);
#if 0									  // DEBUG
	 printf("[%s:%d] XDP_ADD_THE[(%8X,%8X)->%8X] = %6.5f\n", 
			  __FILE__, __LINE__, *da, *db, *dc, p_the);
	 printf("[%s:%d] XDP_ADD_REC[(%8X,%8X)->%8X] = %6.5f\n", 
			  __FILE__, __LINE__, *da, *db, *dc, *p);
#endif
	 if(p_thres > 0.0) {
		assert(*p > 0.0);
	 }
	 assert(*p == p_the);
	 assert(*p >= p_thres);
	 uint64_t len = diff_set_dx_dy_dz->size();
	 bool b_low_hw = (hamming_weight(*da) <= hw_thres) && (hamming_weight(*db) <= hw_thres) && (hamming_weight(*dc) <= hw_thres);
	 assert(b_low_hw);
	 if((*p >= p_thres) && (len < max_size)) {
#if 1									  // store the difference
		differential_3d_t i_diff;
		i_diff.dx = *da;
		i_diff.dy = *db;
		i_diff.dz = *dc;
		i_diff.p = *p;
		diff_set_dx_dy_dz->insert(i_diff);
		diff_mset_p->insert(i_diff);
#endif  // #if 0									  // do not store the difference

#if 0									  // DEBUG
		//		printf("\r[%s:%d] %10ld / %10ld | Add %8X %8X -> %8X : %f 2^%4.2f | 2^%4.2f", __FILE__, __LINE__, len, max_size, *da, *db, *dc, *p, log2(*p), log2(p_thres));
		//		fflush(stdout);
		printf("[%s:%d] %10ld / %10ld | Add %8X %8X -> %8X : %f 2^%4.2f | 2^%4.2f\n", __FILE__, __LINE__, len, max_size, *da, *db, *dc, *p, log2(*p), log2(p_thres));
#endif
#if 0									  // DEBUG
		// find the smallest LSB that is active
		WORD_T t = *da | *db;
		WORD_T i = 0;
		WORD_T bit = (t >> i) & 1;
		while((!bit) && (i != (WORD_SIZE - 1))) {
		  i++;
		  bit = (t >> i) & 1;
		}
		printf("\r#bit %2d %d", i, bit);
		fflush(stdout);
#endif
#if 0									  // DEBUG
		if((*da == RROT(0x480901, SPECK_RIGHT_ROT_CONST)) && (*db == 0x94009)) { printf("\n->! Found 0:\n"); sleep(0);}
		if((*da == 0x80802) && (*db == 0x42084A)) {printf("\n->! Found 1:\n"); sleep(0);}
		if((*da == 0x400052) && (*db == 0x504200)) {printf("\n->! Found 2:\n"); sleep(0);}
		if((*da == 0x820200) && (*db == 0x1202)) {printf("\n->! Found 3:\n"); sleep(0);}
#endif
	 }
	 return;
  }

  if(diff_set_dx_dy_dz->size() == max_size)
	 return;

  // init L
  gsl_vector* L = gsl_vector_calloc(XDP_ADD_MSIZE);
  gsl_vector_set_all(L, 1.0);

  for(WORD_T x = 0; x < 2; x++) {
	 for(WORD_T y = 0; y < 2; y++) {
		for(WORD_T z = 0; z < 2; z++) {

		  // temp
		  gsl_vector* R = gsl_vector_calloc(XDP_ADD_MSIZE);
		  double new_p = 0.0;

		  // L A C
		  gsl_blas_dgemv(CblasNoTrans, 1.0, A[x][y][z], C, 0.0, R);
		  gsl_blas_ddot(L, R, &new_p);

		  //			 if(new_p != 0.0) {
		  if(new_p >= p_thres) {
			 WORD_T new_da = *da | (x << k);
			 WORD_T new_db = *db | (y << k);
			 WORD_T new_dc = *dc | (z << k);
			 bool b_low_hw = (hamming_weight(new_da) <= hw_thres) && (hamming_weight(new_db) <= hw_thres) && (hamming_weight(new_dc) <= hw_thres);
			 if(b_low_hw) {
				speck_xdp_add_pddt_i(k+1, n, p_thres, hw_thres, A, R, &new_da, &new_db, &new_dc, &new_p, diff_set_dx_dy_dz, diff_mset_p, max_size);
			 }
		  }
		  gsl_vector_free(R);
		}
	 }
  }
  gsl_vector_free(L);
}

/** 
 * For Speck: compute a partial DDT for \f$\mathrm{xdp}^{+}\f$: wrapper function
 * of \ref xdp_add_pddt_i.
 *
 * \see xdp_add_pddt speck_xdp_add_pddt_i
 */
void speck_xdp_add_pddt(uint32_t n, double p_thres, uint32_t hw_thres, const uint64_t max_size,
								std::set<differential_3d_t, struct_comp_diff_3d_dx_dy_dz>* diff_set_dx_dy_dz,
								std::multiset<differential_3d_t, struct_comp_diff_3d_p>* diff_mset_p)
{
  //  uint32_t n = WORD_SIZE;
  //  double p_thres = P_THRES;
  uint32_t k = 0;

  // init A
  gsl_matrix* A[2][2][2];
  xdp_add_alloc_matrices(A);
  xdp_add_sf(A);
  xdp_add_normalize_matrices(A);

  // init C
  gsl_vector* C = gsl_vector_calloc(XDP_ADD_MSIZE);
  gsl_vector_set(C, XDP_ADD_ISTATE, 1.0);

  WORD_T da = 0;
  WORD_T db = 0;

  double p = 0.0;
  WORD_T dc = 0;
  speck_xdp_add_pddt_i(k, n, p_thres, hw_thres, A, C, &da, &db, &dc, &p, diff_set_dx_dy_dz, diff_mset_p, max_size);
  assert(diff_set_dx_dy_dz->size() == diff_mset_p->size());

#if 1									  // DEBUG
  //  printf("[%s:%d] HWay table: p_thres = %f (2^%f), hw_thres = %d, n = %d, #diffs = %d 2^%4.2f\n", __FILE__, __LINE__, 
  //			p_thres, log2(p_thres), hw_thres, WORD_SIZE, (uint64_t)diff_mset_p->size(), log2((uint64_t)diff_mset_p->size()));
  printf("[%s:%d] HWay table: p_thres = %f (2^%f), hw_thres = %d, n = %d, #diffs = %lld 2^%4.2f\n", __FILE__, __LINE__, 
			p_thres, log2(p_thres), hw_thres, WORD_SIZE, (WORD_MAX_T)diff_mset_p->size(), log2(diff_mset_p->size()));
#endif

  gsl_vector_free(C);
  xdp_add_free_matrices(A);
}

/**
 * For given input XOR differences da,db to ADD compute a pDDT of
 * differentials (da,db->dc) with probability above a fixed threshold
 * p_thres.
 * 
 * \see speck_xdp_add_dx_dy_pddt
 */
void speck_xdp_add_dx_dy_pddt_i(const WORD_T k, const WORD_T n, gsl_matrix* A[2][2][2], gsl_vector* C, 
										  const WORD_T da, const WORD_T db, WORD_T* dc, double* p, 
										  std::set<differential_3d_t, struct_comp_diff_3d_dx_dy_dz>* hways_diff_set_dx_dy_dz,
										  std::multiset<differential_3d_t, struct_comp_diff_3d_p>* hways_diff_mset_p,
										  std::set<differential_3d_t, struct_comp_diff_3d_dx_dy_dz>* croads_diff_set_dx_dy_dz,
										  std::multiset<differential_3d_t, struct_comp_diff_3d_p>* croads_diff_mset_p,
										  uint32_t right_rot_const, uint32_t left_rot_const,
										  const double p_thres, uint32_t max_size, bool b_speck_cluster_trails)
{
  if(k == n) {
	 double p_the = xdp_add(A, da, db, *dc);
#if 0									  // DEBUG
	 printf("[%s:%d] XDP_ADD_THE[(%8X,%8X)->%8X] = %6.5f\n", 
			  __FILE__, __LINE__, da, db, *dc, p_the);
	 printf("[%s:%d] XDP_ADD_REC[(%8X,%8X)->%8X] = %6.5f\n", 
			  __FILE__, __LINE__, da, db, *dc, *p);
#endif
	 if(p_thres > 0.0) {
		assert(*p > 0.0);
	 }
	 assert(*p == p_the);
	 assert(*p >= p_thres);
	 //	 bool b_low_hw = (hamming_weight(*dc) <= SPECK_MAX_HW);
	 //	 assert(b_low_hw);
	 uint32_t len = croads_diff_set_dx_dy_dz->size();
	 if((*p >= p_thres) && (len < max_size) && (*p != 0.0)) {

		assert(*p != 0.0);

		differential_3d_t i_diff;
		i_diff.dx = da;
		i_diff.dy = db;
		i_diff.dz = *dc;
		i_diff.p = *p;

		WORD_T dx_next = RROT(i_diff.dz, right_rot_const); // ! the left input to the next round will be rotated before entering the ADD op
		WORD_T dy_next = LROT(i_diff.dy, left_rot_const) ^ i_diff.dz;
		bool b_low_hw = true;//

		if(!b_speck_cluster_trails) {
		  b_low_hw = (hamming_weight(dx_next) <= SPECK_MAX_HW) && (hamming_weight(dy_next) <= SPECK_MAX_HW);
		} else {
		  b_low_hw = (hamming_weight(dx_next) <= SPECK_CLUSTER_MAX_HW) && (hamming_weight(dy_next) <= SPECK_CLUSTER_MAX_HW);
		}

		if(b_low_hw) {
 		  //		  bool b_is_hway_next = true;
#if SPECK_BACK_TO_HWAY			  // explore only the fixed list of highways
		  bool b_is_hway_next = speck_xdp_add_is_dz_in_set_dx_dy_dz(dx_next, dy_next, *hways_diff_set_dx_dy_dz);
		  assert(0 == 1);
#else	 // compute new highways on-demand; explore them, but don't store
		  double p_max = 0.0;
		  WORD_T dz_next_max = 0;
		  p_max = max_xdp_add_lm(dx_next, dy_next, &dz_next_max);
		  bool b_is_hway_next = (p_max >= SPECK_P_THRES) && (hamming_weight(dz_next_max) <= SPECK_MAX_HW);
		  //		  assert(hamming_weight(dz_next_max) <= SPECK_MAX_HW);
#endif  // #if SPECK_BACK_TO_HWAY

		  if(b_speck_cluster_trails) { // if clustering, consider also non-highways
			 b_is_hway_next = true;  // accept all
		  }

		  if(b_is_hway_next) {
			 if(b_speck_cluster_trails) {
#if 0
				printf("\n[%s:%d] XDP_ADD_THE[(%8X,%8X)->%8X] = %6.5f\n", 
						 __FILE__, __LINE__, da, db, *dc, p_the);
				printf("[%s:%d] Added CR: dx dy next: %8X %8X\n", __FILE__, __LINE__, dx_next, dy_next);
#endif
			 }
#if 0									  // update hways
			 uint32_t num_hways = croads_diff_set_dx_dy_dz->size();
			 hways_diff_set_dx_dy_dz->insert(i_diff);
			 if(num_hways < hways_diff_set_dx_dy_dz->size()) { // if a new croad was added, add it also in the other list
				hways_diff_mset_p->insert(i_diff);
			 }
#endif
			 uint32_t num_croads = croads_diff_set_dx_dy_dz->size();
			 croads_diff_set_dx_dy_dz->insert(i_diff);
			 if(num_croads < croads_diff_set_dx_dy_dz->size()) { // if a new croad was added, add it also in the other list
				croads_diff_mset_p->insert(i_diff);
				if(b_speck_cluster_trails) {
#if 0
				  printf("\r[%s:%d] %10d / %10d | Add %8X %8X -> %8X : %f 2^%4.2f | 2^%4.2f", __FILE__, __LINE__, len, max_size, da, db, *dc, *p, log2(*p), log2(p_thres));
				  fflush(stdout);
				  //			 printf("[%s:%d] %10d / %10d | Add %8X %8X -> %8X : %f 2^%4.2f | 2^%4.2f\n", __FILE__, __LINE__, len, max_size, da, db, *dc, *p, log2(*p), log2(p_thres));
#endif
				}
			 }
		  }
		}
	 }
	 return;
  }

  if(croads_diff_set_dx_dy_dz->size() == max_size)
	 return;

  // init L
  gsl_vector* L = gsl_vector_calloc(XDP_ADD_MSIZE);
  gsl_vector_set_all(L, 1.0);

  WORD_T x = (da >> k) & 1;
  WORD_T y = (db >> k) & 1;

  for(WORD_T z = 0; z < 2; z++) {

	 // temp
	 gsl_vector* R = gsl_vector_calloc(XDP_ADD_MSIZE);
	 double new_p = 0.0;

	 // L A C
	 gsl_blas_dgemv(CblasNoTrans, 1.0, A[x][y][z], C, 0.0, R);
	 gsl_blas_ddot(L, R, &new_p);

	 if(new_p >= p_thres) {
		WORD_T new_dc = (*dc) | (z << k);
		//		bool b_low_hw = (hamming_weight(new_dc) <= SPECK_MAX_HW);
		bool b_low_hw = true;
		if(!b_speck_cluster_trails) {
		  b_low_hw = (hamming_weight(da) <= SPECK_MAX_HW) && (hamming_weight(db) <= SPECK_MAX_HW) && (hamming_weight(new_dc) <= SPECK_MAX_HW);
		} else {
		  b_low_hw = (hamming_weight(da) <= SPECK_CLUSTER_MAX_HW) && (hamming_weight(db) <= SPECK_CLUSTER_MAX_HW) && (hamming_weight(new_dc) <= SPECK_CLUSTER_MAX_HW);
		}
		if(b_low_hw) {
		  speck_xdp_add_dx_dy_pddt_i(k+1, n, A, R, da, db, &new_dc, &new_p, hways_diff_set_dx_dy_dz, hways_diff_mset_p, croads_diff_set_dx_dy_dz, croads_diff_mset_p, right_rot_const, left_rot_const, p_thres, max_size, b_speck_cluster_trails);
		}
	 }
	 gsl_vector_free(R);
  }
  gsl_vector_free(L);
}

/** 
 * For given input XOR differences da,db to ADD compute a pDDT of
 * differentials (da,db->dc) with probability above a fixed threshold
 * p_thres. Wrapper for \p speck_xdp_add_dx_dy_pddt_i .
 * 
 * right_rot_const and left_rot_const are the rotation constants of
 * block cipher Speck \ref speck.cc . 
 *
 * \see xdp_add_dx_dy_pddt
 */ 
WORD_T speck_xdp_add_dx_dy_pddt(WORD_T da, WORD_T db, 
											 std::set<differential_3d_t, struct_comp_diff_3d_dx_dy_dz>* hways_diff_set_dx_dy_dz,
											 std::multiset<differential_3d_t, struct_comp_diff_3d_p>* hways_diff_mset_p,
											 std::set<differential_3d_t, struct_comp_diff_3d_dx_dy_dz>* croads_diff_set_dx_dy_dz,
											 std::multiset<differential_3d_t, struct_comp_diff_3d_p>* croads_diff_mset_p,
											 uint32_t right_rot_const, uint32_t left_rot_const,
											 double p_thres, WORD_T max_size, bool b_speck_cluster_trails)
{
  uint32_t n = WORD_SIZE;
  uint32_t k = 0;
  double p = 0.0;

  // init A
  gsl_matrix* A[2][2][2];
  xdp_add_alloc_matrices(A);
  xdp_add_sf(A);
  xdp_add_normalize_matrices(A);

  // init C
  gsl_vector* C = gsl_vector_calloc(XDP_ADD_MSIZE);
  gsl_vector_set(C, XDP_ADD_ISTATE, 1.0);

  WORD_T dc = 0;

  uint32_t old_size = croads_diff_set_dx_dy_dz->size();
  uint32_t old_size_hways = hways_diff_set_dx_dy_dz->size();

  //  xdp_add_pddt_i(k, n, p_thres, A, C, &da, &db, &dc, &p, diff_set_dx_dy_dz, diff_mset_p, max_size);
  speck_xdp_add_dx_dy_pddt_i(k, n, A, C, da, db, &dc, &p, hways_diff_set_dx_dy_dz, hways_diff_mset_p, croads_diff_set_dx_dy_dz, croads_diff_mset_p, right_rot_const, left_rot_const, p_thres, max_size, b_speck_cluster_trails);

  assert(croads_diff_set_dx_dy_dz->size() == croads_diff_mset_p->size());
  uint32_t new_size = croads_diff_set_dx_dy_dz->size();
  uint32_t new_size_hways = hways_diff_set_dx_dy_dz->size();

  assert(old_size_hways == new_size_hways);

#if 0									  // DEBUG
  printf("[%s:%d] p_thres = %f (2^%f), n = %d, #diffs = %d\n", __FILE__, __LINE__, 
			p_thres, log2(p_thres), WORD_SIZE, croads_diff_mset_p->size());
#endif
  assert(croads_diff_set_dx_dy_dz->size() == croads_diff_mset_p->size());

  gsl_vector_free(C);
  xdp_add_free_matrices(A);

  return (new_size - old_size);
}

/**
 * Simplified version of \p speck_xdp_add_dx_dy_pddt_i
 * \see xdp_add_dx_dy_pddt , speck_xdp_add_dx_dy_pddt_simple
 */
void speck_xdp_add_dx_dy_pddt_simple_i(const uint32_t k, const uint32_t n, gsl_matrix* A[2][2][2], gsl_vector* C, 
													const WORD_T da, const WORD_T db, WORD_T* dc, double* p, 
													std::set<differential_3d_t, struct_comp_diff_3d_dx_dy_dz>* croads_diff_set_dx_dy_dz,
													std::multiset<differential_3d_t, struct_comp_diff_3d_p>* croads_diff_mset_p,
													const double p_thres, const uint32_t dc_max_hw, uint32_t max_size)
{
  if(k == n) {
	 double p_the = xdp_add_lm(da, db, *dc);
	 if(p_thres > 0.0) {
		assert(*p > 0.0);
	 }
	 assert(*p == p_the);
	 assert(*p >= p_thres);
	 uint32_t len = croads_diff_set_dx_dy_dz->size();
	 if((*p >= p_thres) && (len < max_size) && (*p != 0.0)) {

		assert(*p != 0.0);

		differential_3d_t i_diff;
		i_diff.dx = da;
		i_diff.dy = db;
		i_diff.dz = *dc;
		i_diff.p = *p;

		uint32_t num_croads = croads_diff_set_dx_dy_dz->size();
		croads_diff_set_dx_dy_dz->insert(i_diff);
		if(num_croads < croads_diff_set_dx_dy_dz->size()) { // if a new croad was added, add it also in the other list
		  croads_diff_mset_p->insert(i_diff);
#if 0									  // DEBUG
		  uint32_t hway_size = croads_diff_set_dx_dy_dz->size();
		  printf("\r[%s:%d] Add %8X %8X -> %8X : %f 2^%4.2f | 2^%4.2f  HW size 2^%f", __FILE__, __LINE__, da, db, *dc, *p, log2(*p), log2(p_thres), log2(hway_size));
		  fflush(stdout);
		  //		  printf("[%s:%d] Add %8X %8X -> %8X : %f 2^%4.2f | 2^%4.2f  HW size 2^%f\n", __FILE__, __LINE__, da, db, *dc, *p, log2(*p), log2(p_thres), log2(hway_size));
#endif
		}
	 }
	 return;
  }

  if(croads_diff_set_dx_dy_dz->size() == max_size)
	 return;

  // init L
  gsl_vector* L = gsl_vector_calloc(XDP_ADD_MSIZE);
  gsl_vector_set_all(L, 1.0);

  WORD_T x = (da >> k) & 1;
  WORD_T y = (db >> k) & 1;

  for(WORD_T z = 0; z < 2; z++) {

	 // temp
	 gsl_vector* R = gsl_vector_calloc(XDP_ADD_MSIZE);
	 double new_p = 0.0;

	 // L A C
	 gsl_blas_dgemv(CblasNoTrans, 1.0, A[x][y][z], C, 0.0, R);
	 gsl_blas_ddot(L, R, &new_p);

	 if(new_p >= p_thres) {
		WORD_T new_dc = (*dc) | (z << k);
#if 0
		//		WORD_T mask_k = (0xffffffff >> (WORD_SIZE - k - 1));
		WORD_MAX_T mask_k = (~0ULL >> (64 - word_size)); // masks word_size LS bits
		WORD_T db_next = (LROT(db, SPECK_LEFT_ROT_CONST) ^ new_dc) & mask_k;
		//		printf("k %2d mask_k %8X\n", k, mask_k);
		bool b_low_hw = (hamming_weight(new_dc) <= SPECK_MAX_HW) && (hamming_weight(db_next) <= SPECK_MAX_HW);
#else
		bool b_low_hw = (hamming_weight(new_dc) <= dc_max_hw);
		//		bool b_low_hw = (hamming_weight(new_dc) <= SPECK_MAX_HW);
#endif
		if(b_low_hw) {
		  speck_xdp_add_dx_dy_pddt_simple_i(k+1, n, A, R, da, db, &new_dc, &new_p, croads_diff_set_dx_dy_dz, croads_diff_mset_p, p_thres, dc_max_hw, max_size);
		}
	 }
	 gsl_vector_free(R);
  }
  gsl_vector_free(L);
}

/** 
 * Simplified version of \p xdp_add_dx_dy_pddt :
 * for given input XOR differences da,db to ADD compute a pDDT of
 * differentials (da,db->dc) with probability above a fixed threshold
 * p_thres. Wrapper for speck_xdp_add_dx_dy_pddt_simple_i .
 * 
 * right_rot_const and left_rot_const are the rotation constants of
 * block cipher Speck \ref speck.cc . 
 *
 * \see xdp_add_dx_dy_pddt
 */ 
WORD_T speck_xdp_add_dx_dy_pddt_simple(WORD_T da, WORD_T db, 
													  std::set<differential_3d_t, struct_comp_diff_3d_dx_dy_dz>* croads_diff_set_dx_dy_dz,
													  std::multiset<differential_3d_t, struct_comp_diff_3d_p>* croads_diff_mset_p,
													  double p_thres, uint32_t hw_thres, uint32_t max_size)
{
  uint32_t n = WORD_SIZE;
  uint32_t k = 0;
  double p = 0.0;

  // init A
  gsl_matrix* A[2][2][2];
  xdp_add_alloc_matrices(A);
  xdp_add_sf(A);
  xdp_add_normalize_matrices(A);

  // init C
  gsl_vector* C = gsl_vector_calloc(XDP_ADD_MSIZE);
  gsl_vector_set(C, XDP_ADD_ISTATE, 1.0);

  WORD_T dc = 0;

  uint32_t old_size = croads_diff_set_dx_dy_dz->size();
  speck_xdp_add_dx_dy_pddt_simple_i(k, n, A, C, da, db, &dc, &p, croads_diff_set_dx_dy_dz, croads_diff_mset_p, p_thres, hw_thres, max_size);
  uint32_t new_size = croads_diff_set_dx_dy_dz->size();
  assert(croads_diff_set_dx_dy_dz->size() == croads_diff_mset_p->size());

  gsl_vector_free(C);
  xdp_add_free_matrices(A);

  return (new_size - old_size);
}

void speck_xdp_add_pddt_rand(WORD_T n, const double p_thres, const uint32_t hw_thres, const uint64_t max_size,
									  std::set<differential_3d_t, struct_comp_diff_3d_dx_dy_dz>* diff_set_dx_dy_dz,
									  std::multiset<differential_3d_t, struct_comp_diff_3d_p>* diff_mset_p)
{
  //  uint32_t n = WORD_SIZE;
  //  double p_thres = P_THRES;
  uint32_t k = 0;
  double p = 0.0;

  // init A
  gsl_matrix* A[2][2][2];
  xdp_add_alloc_matrices(A);
  xdp_add_sf(A);
  xdp_add_normalize_matrices(A);

  uint64_t ntrials = (1ULL << 32);
  uint32_t cnt = 0;
  while((cnt < ntrials) && (diff_set_dx_dy_dz->size() < SPECK_MAX_DIFF_CNT)) {

	 WORD_T da = gen_sparse(hw_thres, WORD_SIZE);
	 WORD_T db = gen_sparse(hw_thres, WORD_SIZE);
	 WORD_T dc = 0;

	 // search in HWays
	 differential_3d_t diff_dz = {da, db, dc};
	 std::set<differential_3d_t, struct_comp_diff_3d_dx_dy_dz>::iterator hway_iter = diff_set_dx_dy_dz->lower_bound(diff_dz);
 	 bool b_found_in_hways = (hway_iter != diff_set_dx_dy_dz->end()) && (hway_iter->dx == db) && (hway_iter->dy == db);
	 if(b_found_in_hways) {
		cnt++;
		continue;
	 }
#if 1									  // DEBUG
	 //if((da == (RROT(0x480901, SPECK_RIGHT_ROT_CONST)) && (db == 0x94009)) { printf("-> ! Found 0: %llX %llX\n", (WORD_MAX_T)da, (WORD_MAX_T)db);}
	 if((da == 0x80802) && (db == 0x42084A)) {printf("->! Found 1: %llX %llX\n", (WORD_MAX_T)da, (WORD_MAX_T)db);}
	 if((da == 0x400052) && (db == 0x504200)) {printf("->! Found 2: %llX %llX\n", (WORD_MAX_T)da, (WORD_MAX_T)db);}
	 if((da == 0x820200) && (db == 0x1202)) {printf("->! Found 3: %llX %llX\n", (WORD_MAX_T)da, (WORD_MAX_T)db);}
#endif

	 // init C
	 gsl_vector* C = gsl_vector_calloc(XDP_ADD_MSIZE);
	 gsl_vector_set(C, XDP_ADD_ISTATE, 1.0);

	 //  speck_xdp_add_pddt_i(k, n, p_thres, A, C, &da, &db, &dc, &p, diff_set_dx_dy_dz, diff_mset_p, max_size);
	 speck_xdp_add_dx_dy_pddt_simple_i(k, n, A, C, da, db, &dc, &p, diff_set_dx_dy_dz, diff_mset_p, p_thres, hw_thres, max_size);
#if 0									  // DEBUG
	 printf("[%s:%d] p_thres = %f (2^%f), n = %d, #diffs = %d 2^%4.2f\n", __FILE__, __LINE__, 
			  p_thres, log2(p_thres), WORD_SIZE, (uint32_t)diff_mset_p->size(), log2(diff_mset_p->size()));
#endif
	 assert(diff_set_dx_dy_dz->size() == diff_mset_p->size());

	 gsl_vector_free(C);
	 cnt++;
  }
  xdp_add_free_matrices(A);
}


// {------- DECRYPT ---------------

/*
 * Search for a trail in decryption mode i.e. bottom to top as opposed to encryption that is top to bottom
 * Note: has a possibility to start from a single fixed input difference
 * so that it can be easily concatenated to a top to bottom trail
 */
void speck_xor_threshold_search_decrypt(const int n, const int nrounds, gsl_matrix* A[2][2][2], double B[NROUNDS], double* Bn,
													 const differential_t diff_in[NROUNDS], const WORD_T dx_init_in, const WORD_T dy_init_in, 
													 differential_t trail[NROUNDS], WORD_T* dx_init, WORD_T* dy_init,
													 uint32_t right_rot_const, uint32_t left_rot_const,
													 std::multiset<differential_3d_t, struct_comp_diff_3d_p>* diff_mset_p, // highways
													 std::set<differential_3d_t, struct_comp_diff_3d_dx_dy_dz>* diff_set_dx_dy_dz,
													 std::multiset<differential_3d_t, struct_comp_diff_3d_p>* croads_diff_mset_p, // country roads
													 std::set<differential_3d_t, struct_comp_diff_3d_dx_dy_dz>* croads_diff_set_dx_dy_dz,
													 double p_thres, bool b_speck_cluster_trails)
{
  double pn = 0.0;

  // make a local copy of the input diff trail
  differential_t diff[NROUNDS] = {{0, 0, 0, 0.0}};
  for(int i = 0; i < n; i++) {
	 diff[i].dx = diff_in[i].dx;
	 diff[i].dy = diff_in[i].dy;
	 diff[i].p = diff_in[i].p;
  }

  if((n == 0) && (nrounds == 1)) {						  // Only one round
	 WORD_T dx = dx_init_in;
	 WORD_T dy = RROT((dx_init_in ^ dy_init_in), left_rot_const);
	 WORD_T dz_max = 0;
	 double p_max = max_xdp_add_lm(dx, dy, &dz_max);

	 //	 WORD_T dz = mset_iter->dz;
	 pn = p_max;

	 WORD_T dxx = LROT(dz_max, right_rot_const); // x_{i-1}
	 WORD_T dyy = dy; // y_{i-1}

	 //	 if((pn >= *Bn) && (pn != 0.0)) {
	 trail[n].dx = dxx;		  // dx_{i-1}
	 trail[n].dy = dyy;		  // dy_{i-1} 
	 trail[n].p = pn;
	 *Bn = pn;
	 B[n] = pn;
		//	 } 
  }

  // Greedy !!!
#if SPECK_GREEDY_SEARCH
  if((n >= 0) && (n != (nrounds - 1))) { // Round-i and not last round
  //  if(0) {

	 // n == 0
	 WORD_T dx = dx_init_in;
	 WORD_T dy = RROT((dx_init_in ^ dy_init_in), left_rot_const);

	 // n > 0
	 if(n > 0) {
		dx = diff[n - 1].dx;
		dy = RROT((dx ^ diff[n - 1].dy), left_rot_const);
	 } 

	 WORD_T dz_max = 0;
	 double p_max = max_xdp_add_lm(dx, dy, &dz_max);

	 pn = p_max;

	 WORD_T dxx = LROT(dz_max, right_rot_const); // x_{i-1}
	 WORD_T dyy = dy; // y_{i-1}

	 double p = 1.0;
	 for(int i = 0; i < n; i++) {
		p *= diff[i].p;
	 }
	 p = p * pn * B[nrounds - 1 - (n + 1)];

	 //	 if((p >= *Bn) && (p != 0.0)) {
	 diff[n].dx = dxx;		  // dx_{i-1}
	 diff[n].dy = dyy;		  // dy_{i-1} 
	 diff[n].p = pn;
	 speck_xor_threshold_search_decrypt(n+1, nrounds, A, B, Bn, diff, dx_init_in, dy_init_in, trail, dx_init, dy_init, right_rot_const, left_rot_const, diff_mset_p, diff_set_dx_dy_dz, croads_diff_mset_p, croads_diff_set_dx_dy_dz, p_thres, b_speck_cluster_trails);
		//	 } 
  }
#else	 // Threshold search
  if((n >= 0) && (n != (nrounds - 1))) { // Round-i and not last round

	 // n == 0
	 WORD_T dx = dx_init_in;
	 WORD_T dy = RROT((dx_init_in ^ dy_init_in), left_rot_const);

	 // n > 0
	 if(n > 0) {
		dx = diff[n - 1].dx;
		dy = RROT((dx ^ diff[n - 1].dy), left_rot_const);
	 } 

#if 0	  // VERIFY
	 if(nrounds >= 1) {
		//			 WORD_T dyy_test = RROT((diff[n - 1].dx ^ diff[n - 1].dy), left_rot_const);
		WORD_T dyy_test_1 = RROT((diff[n - 1].dx ^ diff[n - 1].dy), left_rot_const);
		WORD_T dyy_test_2 = RROT((dx_init_in ^ dy_init_in), left_rot_const);
		assert((dyy_test_1 == dy) || (dyy_test_2 == dy));
	 }
#endif  // #if 1	  // VERIFY

	 differential_3d_t diff_dz;
	 diff_dz.dx = dx;  			  // alpha
	 diff_dz.dy = dy;
	 diff_dz.dz = 0;
	 diff_dz.p = 0.0;

	 // check if the differential is not already in the set
	 std::set<differential_3d_t, struct_comp_diff_3d_dx_dy_dz>::iterator hway_iter = diff_set_dx_dy_dz->lower_bound(diff_dz);
 	 bool b_found_in_hways = (hway_iter != diff_set_dx_dy_dz->end()) && (hway_iter->dx == dx) && (hway_iter->dy == dy);

#define CLEAR_CROADS 1
#if CLEAR_CROADS								  // !!!
	 croads_diff_set_dx_dy_dz->clear();
	 croads_diff_mset_p->clear();
#endif

	 std::set<differential_3d_t, struct_comp_diff_3d_dx_dy_dz>::iterator croad_iter = croads_diff_set_dx_dy_dz->lower_bound(diff_dz);
	 bool b_found_in_croads = (croad_iter != croads_diff_set_dx_dy_dz->end()) && (croad_iter->dx == dx) && (croad_iter->dy == dy);

#if CLEAR_CROADS
	 assert(b_found_in_croads == false);
#endif

	 // p_i >= p_min = Bn / p1 * p2 ... * p{i-1} * B{n-i} 
	 double p_min = 0.0;
	 p_min = 1.0;
	 for(int i = 0; i < n; i++) { // p[0] * p[1] * p[n-1]
		p_min *= diff[i].p;
	 }
	 p_min = p_min * 1.0 * B[nrounds - 1 - (n + 1)]; 
	 p_min = *Bn / p_min;
	 assert(p_min <= 1.0);

	 assert(diff_set_dx_dy_dz->size() != 0);

	 const WORD_T max_cnt = (1ULL << (WORD_SIZE - 1));//SPECK_MAX_DIFF_CNT; 

#if 0								  // DEBUG
	 printf("\n ----------------------------------------------------------------------------------------\n");
	 printf("[%s:%d] Find in CR or HW (dx_rrot dy) = (%8X %8X)\n", __FILE__, __LINE__, dx, dy);
#endif

	 //	 printf("[%s:%d] CHECKPOINT!\n", __FILE__, __LINE__);

	 WORD_T cnt_new = speck_xdp_add_dx_dy_pddt(dx, dy, diff_set_dx_dy_dz, diff_mset_p, croads_diff_set_dx_dy_dz, croads_diff_mset_p, right_rot_const, left_rot_const, p_min, max_cnt, b_speck_cluster_trails);

	 if(cnt_new != 0) {
#if 0									  // DEBUG
		printf("[%s:%d] [%2d / %2d]: Added %d new CR dx dy %8X %8X: p_min = %f (2^%f). New sizes: Dxy %d, Dp %d.\n", __FILE__, __LINE__, n, NROUNDS, cnt_new, dx, dy, p_min, log2(p_min), croads_diff_set_dx_dy_dz->size(), croads_diff_mset_p->size());
#endif
		croad_iter = croads_diff_set_dx_dy_dz->lower_bound(diff_dz);
		b_found_in_croads = (croad_iter != croads_diff_set_dx_dy_dz->end()) && (croad_iter->dx == dx) && (croad_iter->dy == dy);
	 } else {
#if 0									  // DEBUG
		//		printf("\r[%s:%d] [%2d / %2d]: No new country roads found: p_min = %f (2^%f).", __FILE__, __LINE__, n, NROUNDS, p_min, log2(p_min));
		//		fflush(stdout);
		printf("[%s:%d] [%2d / %2d]: No new country roads found: p_min = %f (2^%f).\n", __FILE__, __LINE__, n, NROUNDS, p_min, log2(p_min));
#endif
	 }


	 //	 std::set<differential_t, struct_comp_diff_dx_dy>* diff_set_dx_dy_dz;
	 std::multiset<differential_3d_t, struct_comp_diff_3d_p> found_mset_p;

	 if(b_found_in_hways) {
		//		while((hway_iter->dx == dx) && (hway_iter->p >= p_min)) {
		while((hway_iter->dx == dx)  && (hway_iter->dy == dy)) {
#if 0									  // DEBUG
		  bool b_low_hw = (hamming_weight(hway_iter->dx) <= SPECK_MAX_HW) &&  (hamming_weight(hway_iter->dy) <= SPECK_MAX_HW) && (hamming_weight(hway_iter->dz) <= SPECK_MAX_HW);
		  bool b_is_hway = (hway_iter->p >= SPECK_P_THRES) && b_low_hw;
		  if(!b_is_hway) {
			 printf("[%s:%d] CHECKPOINT! %8X %8X 2^%f\n", __FILE__, __LINE__, dx, dy, log2(hway_iter->p));
		  }
		  assert(b_is_hway);
#endif
		  found_mset_p.insert(*hway_iter);
		  hway_iter++;
		}
	 }

	 //	 b_found_in_croads = false;
	 if(b_found_in_croads) {
		//		printf("[%s:%d] CHECKPOINT!\n", __FILE__, __LINE__);
#if CLEAR_CROADS
		assert(croad_iter->p >= p_min);
#endif
		//		while((croad_iter->dx == dx) && (croad_iter->dy == dy) && (croad_iter->p >= p_min)) {
		while((croad_iter->dx == dx) && (croad_iter->dy == dy) && (croad_iter->p >= p_min) && (croad_iter != croads_diff_set_dx_dy_dz->end())) {

#if CLEAR_CROADS

		  dx = croad_iter->dx;
		  dy = croad_iter->dy;
		  //		  uint32_t dz = croad_iter->dz;

#if 0	  // VERIFY
		  if(nrounds >= 1) {
			 //			 uint32_t dyy_test = RROT((diff[n - 1].dx ^ diff[n - 1].dy), left_rot_const);
			 WORD_T dyy_test_1 = RROT((diff[n - 1].dx ^ diff[n - 1].dy), left_rot_const);
			 WORD_T dyy_test_2 = RROT((dx_init_in ^ dy_init_in), left_rot_const);
			 assert((dyy_test_1 == croad_iter->dy) || (dyy_test_2 == croad_iter->dy));
		  }
#endif  // #if 1	  // VERIFY
		  //		  uint32_t dx_next = LROT(dz, right_rot_const); // x_{i-1}
		  //		  uint32_t dy_next = dy;

		  //		  uint32_t dx_next_rrot = RROT(dx_next, right_rot_const); // ! the left input to the next round will be rotated before entering the ADD op

#if SPECK_BACK_TO_HWAY
		  // empty
#endif  // #if SPECK_BACK_TO_HWAY

		  //		  assert(b_is_hway_next);
		  //		  if(b_is_hway_next) {
			 found_mset_p.insert(*croad_iter);
			 //		  }
#else	 // #if CLEAR_CROADS
		  found_mset_p.insert(*croad_iter);
#endif  // #if CLEAR_CROADS
		  croad_iter++;
		}
	 }

#if 1									  // add the max
	 double p_max = 0.0;
	 WORD_T dz_max = 0;
	 p_max = max_xdp_add_lm(dx, dy, &dz_max);

	 //	 assert((hamming_weight(diff_dz.dx) <= SPECK_MAX_HW) && (hamming_weight(diff_dz.dy) <= SPECK_MAX_HW));
	 bool b_low_hw = (hamming_weight(dx) <= SPECK_MAX_HW) && (hamming_weight(dy) <= SPECK_MAX_HW) && (hamming_weight(dz_max) <= SPECK_MAX_HW);
	 if((p_max >= SPECK_P_THRES) && (b_low_hw)) {
#if 0									  // DEBUG
		printf("[%s:%d] Add (%X %X %X) 2^%f\n", __FILE__, __LINE__, dx, dy, dz_max, log2(p_max));
#endif  // #if 0									  // DEBUG
		differential_3d_t new_diff = {dx, dy, dz_max, p_max};
		found_mset_p.insert(new_diff);
		b_found_in_hways = true;
	 }
#endif

	 std::multiset<differential_3d_t, struct_comp_diff_3d_p>::iterator find_iter = found_mset_p.begin();

#if 0									  // DEBUG
	 printf("[%s:%d] %2d: Temp set size %d\n", __FILE__, __LINE__, n, found_mset_p.size());
#endif

	 //	 printf("[%s:%d] CHECKPOINT!\n", __FILE__, __LINE__);

	 //		while((find_iter->dx < (dx + 1)) && (find_iter != diff_set_dx_dy_dz->end())) {
	 if((find_iter->dx == dx) && (find_iter->dy == dy)) {
		while((find_iter->dx == dx) && (find_iter->dy == dy) && (find_iter != found_mset_p.end())) {
		  assert((find_iter->dx == dx));
		  assert((find_iter->dy == dy));
		  diff_dz = *find_iter;

		  dx = diff_dz.dx;
		  dy = diff_dz.dy;
		  WORD_T dz = diff_dz.dz;
		  pn = diff_dz.p;
#if 0								  // DEBUG
		  printf("[%s:%d] List: (%X %X %X) 2^%f | b_found_in_hways %d\n", __FILE__, __LINE__, dx, dy, dz, log2(pn), b_found_in_hways);
#endif  // #if 0									  // DEBUG
		  double p = 1.0;
		  for(int i = 0; i < n; i++) { // p[0] * p[1] * p[n-1]
			 p *= diff[i].p;
		  }
		  p = p * pn * B[nrounds - 1 - (n + 1)]; 

		  //		  WORD_T dxx = dz;
		  //		  WORD_T dyy = LROT(dy, left_rot_const) ^ dz; // y_{i+1}
		  WORD_T dxx = LROT(dz, right_rot_const); // x_{i-1}
		  WORD_T dyy = dy; // y_{i-1}

#if 0																	// DEBUG
		  // ! the left input to the next round will be rotated before entering the ADD op
		  bool b_low_hw = (hamming_weight(diff_dz.dx) <= SPECK_MAX_HW) &&  (hamming_weight(diff_dz.dy) <= SPECK_MAX_HW) && (hamming_weight(diff_dz.dz) <= SPECK_MAX_HW);
		  WORD_T dxx_rrot = RROT(dz, right_rot_const); 		                     // x_{i+1}
		  //		  bool b_is_hway = false;
#if SPECK_BACK_TO_HWAY
		  //		  std::set<differential_3d_t, struct_comp_diff_3d_dx_dy_dz>::iterator hway_iter = diff_set_dx_dy_dz->lower_bound(diff_dz);
		  //		  b_is_hway = (hway_iter != diff_set_dx_dy_dz->end()) && (hway_iter->dx == dx) && (hway_iter->dy == dy);
		  //		  assert(b_found_in_hways == b_is_hway);
#else	 // #if SPECK_BACK_TO_HWAY
		  //		  b_is_hway = (diff_dz.p >= SPECK_P_THRES) && b_low_hw;
#if 0									  // DEBUG
		  printf("[%s:%d] b_found_in_hways = %d b_is_hway %d |  (%X %X %X) 2^%f\n", __FILE__, __LINE__, b_found_in_hways, b_is_hway, diff_dz.dx, diff_dz.dy, diff_dz.dz, log2(diff_dz.p));
#endif  // #if 0									  // DEBUG
#endif  // #if SPECK_BACK_TO_HWAY
		  assert(b_low_hw);

		  bool b_is_hway_next = false;
		  if(!b_found_in_hways) {
#if SPECK_BACK_TO_HWAY
			 b_is_hway_next = speck_xdp_add_is_dz_in_set_dx_dy_dz(dxx_rrot, dyy, *diff_set_dx_dy_dz);
#else	 // #if SPECK_BACK_TO_HWAY
			 WORD_T dz_max_next = 0;
			 //			 double p_max_next = 0.0;
			 //			 p_max_next = 
			 max_xdp_add_lm(dxx_rrot, dyy, &dz_max_next);
			 //			 bool b_low_hw_next = (hamming_weight(dxx_rrot) <= SPECK_MAX_HW) &&  (hamming_weight(dyy) <= SPECK_MAX_HW) && (hamming_weight(dz_max_next) <= SPECK_MAX_HW);
			 //			 b_is_hway_next = (p_max_next >= SPECK_P_THRES) && b_low_hw_next;
			 //			 assert(b_low_hw_next);
#endif  // #if SPECK_BACK_TO_HWAY
			 //			 printf("[%s:%d] CHECK is HW: dxx_rrot dyy %8X %8X\n\n", __FILE__, __LINE__, dxx_rrot, dyy);
			 assert(b_is_hway_next);
		  }
		  assert(b_found_in_hways || b_is_hway_next);
		  assert(0 == 1);
#endif  // DEBUG

		  if((p >= *Bn) && (p != 0.0)) {
			 diff[n].dx = dxx;		  // dx_{i+1}
			 diff[n].dy = dyy;		  // dy_{i+1} 
			 diff[n].p = pn;

#if 0	  // VERIFY
			 if(nrounds >= 1) {
				//			 WORD_T dyy_test = RROT((diff[n - 1].dx ^ diff[n - 1].dy), left_rot_const);
				WORD_T dyy_test_1 = RROT((diff[n - 1].dx ^ diff[n - 1].dy), left_rot_const);
				WORD_T dyy_test_2 = RROT((dx_init_in ^ dy_init_in), left_rot_const);
				assert((dyy_test_1 == dyy) || (dyy_test_2 == dyy));
			 }
#endif  // #if 1	  // VERIFY

			 speck_xor_threshold_search_decrypt(n+1, nrounds, A, B, Bn, diff, dx_init_in, dy_init_in, trail, dx_init, dy_init, right_rot_const, left_rot_const, diff_mset_p, diff_set_dx_dy_dz, croads_diff_mset_p, croads_diff_set_dx_dy_dz, p_thres, b_speck_cluster_trails);

		  }
		  find_iter++;
		}	// while
	 }		// if
  }
#endif  // #if SPECK_GREEDY_SEARCH

  if((n == (nrounds - 1)) && (nrounds > 1)) {		  // Last round

	 // n == 0
	 WORD_T dx = dx_init_in;
	 WORD_T dy = RROT((dx_init_in ^ dy_init_in), left_rot_const);

	 // n > 0
	 if(n > 0) {
		dx = diff[n - 1].dx;
		dy = RROT((dx ^ diff[n - 1].dy), left_rot_const);
	 } 

	 WORD_T dz = 0;

	 pn = max_xdp_add_lm(dx, dy, &dz);

	 WORD_T dxx = LROT(dz, right_rot_const); // x_{i-1}
	 WORD_T dyy = dy; // y_{i-1}

	 double p = 1.0;
	 for(int i = 0; i < n; i++) {
		p *= diff[i].p;
	 }
	 p *= pn;

	 bool b_low_hw = true;//(hamming_weight(dxx) <= SPECK_MAX_HW) && (hamming_weight(dyy) <= SPECK_MAX_HW);
	 if((b_low_hw) && (p >= *Bn) && (p != 1.0) && (p != 0.0)) { // skip the 0-diff trail (p = 1.0)
#if 1									  // DEBUG
		if (p > *Bn) {
		  printf("\n[%s:%d] %d | Update best found Bn: 2^%f -> 2^%f\n", __FILE__, __LINE__, n, log2(*Bn), log2(p));
		}
#endif
		diff[n].dx = dxx;
		diff[n].dy = dyy;
		diff[n].p = pn;
		*Bn = p;
		B[n] = p;
		for(int i = 0; i < nrounds; i++) {
		  //		  *dx_init = dx_init_in;
		  //		  *dy_init = dy_init_in;
		  trail[i].dx = diff[i].dx;
		  trail[i].dy = diff[i].dy;
		  trail[i].p = diff[i].p;
#if 1	  // VERIFY
			 if(i >= 1) {
				//			 uint32_t dyy_test = RROT((diff[n - 1].dx ^ diff[n - 1].dy), left_rot_const);
				WORD_T dyy_test_1 = RROT((diff[i - 1].dx ^ diff[i - 1].dy), left_rot_const);
				WORD_T dyy_test_2 = RROT((dx_init_in ^ dy_init_in), left_rot_const);
				assert((dyy_test_1 == diff[i].dy) || (dyy_test_2 == diff[i].dy));
			 }
#endif  // #if 1	  // VERIFY
		}
	 }
  }
}

// ------- DECRYPT ---------------}

// {-------------- ENCRYPT ---------

/*
 * Search for a trail in encryption mode for fixed input difference
 */
void speck_xor_threshold_search_encrypt(const int n, const int nrounds, gsl_matrix* A[2][2][2], double B[NROUNDS], double* Bn,
													 const differential_t diff_in[NROUNDS], const WORD_T dx_init_in, const WORD_T dy_init_in, 
													 differential_t trail[NROUNDS], WORD_T* dx_init, WORD_T* dy_init,
													 uint32_t right_rot_const, uint32_t left_rot_const,
													 std::multiset<differential_3d_t, struct_comp_diff_3d_p>* diff_mset_p, // highways
													 std::set<differential_3d_t, struct_comp_diff_3d_dx_dy_dz>* diff_set_dx_dy_dz,
													 std::multiset<differential_3d_t, struct_comp_diff_3d_p>* croads_diff_mset_p, // country roads
													 std::set<differential_3d_t, struct_comp_diff_3d_dx_dy_dz>* croads_diff_set_dx_dy_dz,
													 double p_thres, bool b_speck_cluster_trails)
{
  double pn = 0.0;

  // make a local copy of the input diff trail
  differential_t diff[NROUNDS] = {{0, 0, 0, 0.0}};
  for(int i = 0; i < n; i++) {
	 diff[i].dx = diff_in[i].dx;
	 diff[i].dy = diff_in[i].dy;
	 diff[i].p = diff_in[i].p;
  }

  if((n == 0) && (nrounds == 1)) {						  // Only one round
	 WORD_T dx = RROT(dx_init_in, right_rot_const); // the x input to ADD
	 WORD_T dy = dy_init_in; // the y input to ADD
	 WORD_T dz = 0;
	 double p_max = max_xdp_add_lm(dx, dy, &dz);

	 //	 WORD_T dz = mset_iter->dz;
	 pn = p_max;

	 WORD_T dxx = dz;		                     // x_{i+1}
	 WORD_T dyy = LROT(dy, left_rot_const) ^ dz; // y_{i+1}

	 trail[n].dx = dxx;		  // dx_{i-1}
	 trail[n].dy = dyy;		  // dy_{i-1} 
	 trail[n].p = pn;
	 *Bn = pn;
	 B[n] = pn;
  }


  // Greedy !!!
#if SPECK_GREEDY_SEARCH
  if((n >= 0) && (n != (nrounds - 1))) { // Round-i and not last round
  //  if(0) {

	 WORD_T dx = RROT(dx_init_in, right_rot_const); // the x input to ADD
	 WORD_T dy = dy_init_in; // the y input to ADD

	 if(n > 0) {
		dx = RROT(diff[n - 1].dx, right_rot_const); // the x input to ADD
		dy = diff[n - 1].dy; // the y input to ADD
	 }

	 WORD_T dz = 0;

	 pn = max_xdp_add_lm(dx, dy, &dz);

	 WORD_T dxx = dz;		                     // x_{i+1}
	 WORD_T dyy = LROT(dy, left_rot_const) ^ dz; // y_{i+1}

	 double p = 1.0;
	 for(int i = 0; i < n; i++) {
		p *= diff[i].p;
	 }
	 p = p * pn * B[nrounds - 1 - (n + 1)];

	 if((p >= *Bn) && (p != 0.0)) {
		diff[n].dx = dxx;		  // dx_{i+1}
		diff[n].dy = dyy;		  // dy_{i+1} 
		diff[n].p = pn;
		speck_xor_threshold_search_encrypt(n+1, nrounds, A, B, Bn, diff, dx_init_in, dy_init_in, trail, dx_init, dy_init, right_rot_const, left_rot_const, diff_mset_p, diff_set_dx_dy_dz, croads_diff_mset_p, croads_diff_set_dx_dy_dz, p_thres, b_speck_cluster_trails);
	 } 
  }
#else	 // Threshold search
  //  if(0) {							  // !!!
  if((n >= 0) && (n != (nrounds - 1))) { // Round-i and not last round

	 WORD_T dx = RROT(dx_init_in, right_rot_const); // the x input to ADD
	 WORD_T dy = dy_init_in; // the y input to ADD

	 if(n > 0) {
		dx = RROT(diff[n - 1].dx, right_rot_const); // the x input to ADD
		dy = diff[n - 1].dy; // the y input to ADD
	 }

	 differential_3d_t diff_dz;
	 diff_dz.dx = dx;  			  // alpha
	 diff_dz.dy = dy;
	 diff_dz.dz = 0;
	 diff_dz.p = 0.0;

	 // check if the differential is not already in the set
	 std::set<differential_3d_t, struct_comp_diff_3d_dx_dy_dz>::iterator hway_iter = diff_set_dx_dy_dz->lower_bound(diff_dz);
 	 bool b_found_in_hways = (hway_iter != diff_set_dx_dy_dz->end()) && (hway_iter->dx == dx) && (hway_iter->dy == dy);

#define CLEAR_CROADS 1
#if CLEAR_CROADS								  // !!!
	 croads_diff_set_dx_dy_dz->clear();
	 croads_diff_mset_p->clear();
#endif

	 std::set<differential_3d_t, struct_comp_diff_3d_dx_dy_dz>::iterator croad_iter = croads_diff_set_dx_dy_dz->lower_bound(diff_dz);
	 bool b_found_in_croads = (croad_iter != croads_diff_set_dx_dy_dz->end()) && (croad_iter->dx == dx) && (croad_iter->dy == dy);

#if CLEAR_CROADS
	 assert(b_found_in_croads == false);
#endif

	 // p_i >= p_min = Bn / p1 * p2 ... * p{i-1} * B{n-i} 
	 double p_min = 0.0;
	 p_min = 1.0;
	 for(int i = 0; i < n; i++) { // p[0] * p[1] * p[n-1]
		p_min *= diff[i].p;
	 }
	 p_min = p_min * 1.0 * B[nrounds - 1 - (n + 1)]; 
	 p_min = *Bn / p_min;
	 assert(p_min <= 1.0);

	 assert(diff_set_dx_dy_dz->size() != 0);

	 const WORD_T max_cnt = (1ULL << (WORD_SIZE - 1));//SPECK_MAX_DIFF_CNT; 

#if 0								  // DEBUG
	 printf("\n ----------------------------------------------------------------------------------------\n");
	 printf("[%s:%d] Find in CR or HW (dx_rrot dy) = (%8X %8X)\n", __FILE__, __LINE__, dx, dy);
#endif

	 //	 printf("[%s:%d] CHECKPOINT!\n", __FILE__, __LINE__);

	 WORD_T cnt_new = speck_xdp_add_dx_dy_pddt(dx, dy, diff_set_dx_dy_dz, diff_mset_p, croads_diff_set_dx_dy_dz, croads_diff_mset_p, right_rot_const, left_rot_const, p_min, max_cnt, b_speck_cluster_trails);

	 if(cnt_new != 0) {
#if 0									  // DEBUG
		printf("[%s:%d] [%2d / %2d]: Added %d new CR dx dy %8X %8X: p_min = %f (2^%f). New sizes: Dxy %d, Dp %d.\n", __FILE__, __LINE__, n, NROUNDS, cnt_new, dx, dy, p_min, log2(p_min), croads_diff_set_dx_dy_dz->size(), croads_diff_mset_p->size());
#endif
		croad_iter = croads_diff_set_dx_dy_dz->lower_bound(diff_dz);
		b_found_in_croads = (croad_iter != croads_diff_set_dx_dy_dz->end()) && (croad_iter->dx == dx) && (croad_iter->dy == dy);
	 } else {
#if 0									  // DEBUG
		//		printf("\r[%s:%d] [%2d / %2d]: No new country roads found: p_min = %f (2^%f).", __FILE__, __LINE__, n, NROUNDS, p_min, log2(p_min));
		//		fflush(stdout);
		printf("[%s:%d] [%2d / %2d]: No new country roads found: p_min = %f (2^%f).\n", __FILE__, __LINE__, n, NROUNDS, p_min, log2(p_min));
#endif
	 }

	 //	 std::set<differential_t, struct_comp_diff_dx_dy>* diff_set_dx_dy_dz;
	 std::multiset<differential_3d_t, struct_comp_diff_3d_p> found_mset_p;

	 if(b_found_in_hways) {
		//		while((hway_iter->dx == dx) && (hway_iter->p >= p_min)) {
		while((hway_iter->dx == dx)  && (hway_iter->dy == dy)) {
#if 1									  // DEBUG
		  bool b_low_hw = (hamming_weight(hway_iter->dx) <= SPECK_MAX_HW) &&  (hamming_weight(hway_iter->dy) <= SPECK_MAX_HW) && (hamming_weight(hway_iter->dz) <= SPECK_MAX_HW);
		  bool b_is_hway = (hway_iter->p >= SPECK_P_THRES) && b_low_hw;
		  if(!b_is_hway) {
			 printf("[%s:%d] CHECKPOINT! %llX %llX 2^%f\n", __FILE__, __LINE__, (WORD_MAX_T)dx, (WORD_MAX_T)dy, log2(hway_iter->p));
		  }
		  assert(b_is_hway);
#endif
		  found_mset_p.insert(*hway_iter);
		  hway_iter++;
		}
	 }

	 if(b_found_in_croads) {
		//		printf("[%s:%d] CHECKPOINT!\n", __FILE__, __LINE__);
#if CLEAR_CROADS
		assert(croad_iter->p >= p_min);
#endif
		while((croad_iter->dx == dx) && (croad_iter->dy == dy) && (croad_iter->p >= p_min) && (croad_iter != croads_diff_set_dx_dy_dz->end())) {

		  //		printf("[%s:%d] CHECKPOINT!\n", __FILE__, __LINE__);
#if CLEAR_CROADS

		  dx = croad_iter->dx;
		  dy = croad_iter->dy;
		  WORD_T dz = croad_iter->dz;

		  WORD_T dx_next = dz;
		  WORD_T dy_next = LROT(dy, left_rot_const) ^ dx_next;
		  WORD_T dx_next_rrot = RROT(dx_next, right_rot_const); // ! the left input to the next round will be rotated before entering the ADD op

#if SPECK_BACK_TO_HWAY

		  bool b_is_hway_next = speck_xdp_add_is_dz_in_set_dx_dy_dz(dx_next_rrot, dy_next, *diff_set_dx_dy_dz);
		  assert(0 == 1);
#else	 // #if SPECK_BACK_TO_HWAY

		  WORD_T dz_max_next = 0;
		  double p_max_next = 0.0;
		  p_max_next = max_xdp_add_lm(dx_next_rrot, dy_next, &dz_max_next);

		  bool b_low_hw = (hamming_weight(dx) <= SPECK_MAX_HW) &&  (hamming_weight(dy) <= SPECK_MAX_HW) && (hamming_weight(dz) <= SPECK_MAX_HW);
		  bool b_low_hw_next = (hamming_weight(dx_next_rrot) <= SPECK_MAX_HW) &&  (hamming_weight(dy_next) <= SPECK_MAX_HW) && (hamming_weight(dz_max_next) <= SPECK_MAX_HW);
		  bool b_is_hway_next = (p_max_next >= SPECK_P_THRES) && b_low_hw && b_low_hw_next;
#endif  // #if SPECK_BACK_TO_HWAY

		  //		  assert(b_is_hway_next);
		  if(b_is_hway_next) {
			 found_mset_p.insert(*croad_iter);
		  }
#else	 // #if CLEAR_CROADS
		  found_mset_p.insert(*croad_iter);
#endif  // #if CLEAR_CROADS
		  croad_iter++;
		}
	 }

#if 1									  // add the max
	 double p_max = 0.0;
	 WORD_T dz_max = 0;
#if((WORD_SIZE == 16) || (WORD_SIZE == 32))
	 p_max = max_xdp_add_lm(dx, dy, &dz_max);
#else
	 //	 p_max = max_xdp_add(A, dx, dy, &dz_max);
	 p_max = max_xdp_add_lm(dx, dy, &dz_max);
#endif
	 //	 assert((hamming_weight(diff_dz.dx) <= SPECK_MAX_HW) && (hamming_weight(diff_dz.dy) <= SPECK_MAX_HW));
	 bool b_low_hw = (hamming_weight(dx) <= SPECK_MAX_HW) && (hamming_weight(dy) <= SPECK_MAX_HW) && (hamming_weight(dz_max) <= SPECK_MAX_HW);
	 if((p_max >= SPECK_P_THRES) && (b_low_hw)) {
#if 0									  // DEBUG
		printf("[%s:%d] Add (%X %X %X) 2^%f\n", __FILE__, __LINE__, dx, dy, dz_max, log2(p_max));
#endif  // #if 0									  // DEBUG
		differential_3d_t new_diff = {dx, dy, dz_max, p_max};
		found_mset_p.insert(new_diff);
		b_found_in_hways = true;
	 }
#endif

	 std::multiset<differential_3d_t, struct_comp_diff_3d_p>::iterator find_iter = found_mset_p.begin();

#if 0									  // DEBUG
	 printf("[%s:%d] %2d: Temp set size %d\n", __FILE__, __LINE__, n, found_mset_p.size());
#endif

	 //	 printf("[%s:%d] CHECKPOINT!\n", __FILE__, __LINE__);

	 //		while((find_iter->dx < (dx + 1)) && (find_iter != diff_set_dx_dy_dz->end())) {
	 if((find_iter->dx == dx) && (find_iter->dy == dy)) {
		while((find_iter->dx == dx) && (find_iter->dy == dy) && (find_iter != found_mset_p.end())) {
		  assert((find_iter->dx == dx));
		  assert((find_iter->dy == dy));
		  diff_dz = *find_iter;

		  dx = diff_dz.dx;
		  dy = diff_dz.dy;
		  WORD_T dz = diff_dz.dz;
		  pn = diff_dz.p;
#if 0									  // DEBUG
		  printf("[%s:%d] List: (%X %X %X) 2^%f | b_found_in_hways %d\n", __FILE__, __LINE__, dx, dy, dz, log2(pn), b_found_in_hways);
#endif  // #if 0									  // DEBUG
		  double p = 1.0;
		  for(int i = 0; i < n; i++) { // p[0] * p[1] * p[n-1]
			 p *= diff[i].p;
		  }
		  p = p * pn * B[nrounds - 1 - (n + 1)]; 

		  WORD_T dxx = dz;
		  WORD_T dyy = LROT(dy, left_rot_const) ^ dz; // y_{i+1}
#if 1																	// DEBUG
		  // ! the left input to the next round will be rotated before entering the ADD op
		  bool b_low_hw = (hamming_weight(diff_dz.dx) <= SPECK_MAX_HW) &&  (hamming_weight(diff_dz.dy) <= SPECK_MAX_HW) && (hamming_weight(diff_dz.dz) <= SPECK_MAX_HW);
		  WORD_T dxx_rrot = RROT(dz, right_rot_const); 		                     // x_{i+1}
		  //		  bool b_is_hway = false;
#if SPECK_BACK_TO_HWAY
		  //		  std::set<differential_3d_t, struct_comp_diff_3d_dx_dy_dz>::iterator hway_iter = diff_set_dx_dy_dz->lower_bound(diff_dz);
		  //		  b_is_hway = (hway_iter != diff_set_dx_dy_dz->end()) && (hway_iter->dx == dx) && (hway_iter->dy == dy);
		  //		  assert(b_found_in_hways == b_is_hway);
#else	 // #if SPECK_BACK_TO_HWAY
		  //		  b_is_hway = (diff_dz.p >= SPECK_P_THRES) && b_low_hw;
#if 0									  // DEBUG
		  printf("[%s:%d] b_found_in_hways = %d b_is_hway %d |  (%X %X %X) 2^%f\n", __FILE__, __LINE__, b_found_in_hways, b_is_hway, diff_dz.dx, diff_dz.dy, diff_dz.dz, log2(diff_dz.p));
#endif  // #if 0									  // DEBUG
#endif  // #if SPECK_BACK_TO_HWAY
		  assert(b_low_hw);

		  bool b_is_hway_next = false;
		  if(!b_found_in_hways) {
#if SPECK_BACK_TO_HWAY
			 b_is_hway_next = speck_xdp_add_is_dz_in_set_dx_dy_dz(dxx_rrot, dyy, *diff_set_dx_dy_dz);
#else	 // #if SPECK_BACK_TO_HWAY
			 WORD_T dz_max_next = 0;
			 double p_max_next = 0.0;
#if((WORD_SIZE == 16) || (WORD_SIZE == 32))
			 p_max_next = max_xdp_add_lm(dxx_rrot, dyy, &dz_max_next);
#else	 // #if((WORD_SIZE == 16) || (WORD_SIZE == 32))
			 //			 p_max_next = max_xdp_add(A, dxx_rrot, dyy, &dz_max_next);
			 p_max_next = max_xdp_add_lm(dxx_rrot, dyy, &dz_max_next);
#endif  // #if((WORD_SIZE == 16) || (WORD_SIZE == 32))
			 bool b_low_hw_next = (hamming_weight(dxx_rrot) <= SPECK_MAX_HW) &&  (hamming_weight(dyy) <= SPECK_MAX_HW) && (hamming_weight(dz_max_next) <= SPECK_MAX_HW);
			 b_is_hway_next = (p_max_next >= SPECK_P_THRES) && b_low_hw_next;
			 assert(b_low_hw_next);
#endif  // #if SPECK_BACK_TO_HWAY
			 //			 printf("[%s:%d] CHECK is HW: dxx_rrot dyy %8X %8X\n\n", __FILE__, __LINE__, dxx_rrot, dyy);
			 assert(b_is_hway_next);
		  }
		  assert(b_found_in_hways || b_is_hway_next);
#endif  // DEBUG
		  if((p >= *Bn) && (p != 0.0)) {
			 diff[n].dx = dxx;		  // dx_{i+1}
			 diff[n].dy = dyy;		  // dy_{i+1} 
			 diff[n].p = pn;
			 speck_xor_threshold_search_encrypt(n+1, nrounds, A, B, Bn, diff, dx_init_in, dy_init_in, trail, dx_init, dy_init, right_rot_const, left_rot_const, diff_mset_p, diff_set_dx_dy_dz, croads_diff_mset_p, croads_diff_set_dx_dy_dz, p_thres, b_speck_cluster_trails);

		  }
		  find_iter++;
		}	// while
	 }		// if
  }
#endif  // #if SPECK_GREEDY_SEARCH

  if((n == (nrounds - 1)) && (nrounds > 1)) {		  // Last round

	 WORD_T dx = RROT(dx_init_in, right_rot_const); // the x input to ADD
	 WORD_T dy = dy_init_in; // the y input to ADD

	 if(n > 0) {
		dx = RROT(diff[n - 1].dx, right_rot_const); // the x input to ADD
		dy = diff[n - 1].dy; // the y input to ADD
	 }

	 WORD_T dz = 0;

	 pn = max_xdp_add_lm(dx, dy, &dz);
	 WORD_T dxx = dz;		                     // x_{i+1}
	 WORD_T dyy = LROT(dy, left_rot_const) ^ dz; // y_{i+1}

	 double p = 1.0;
	 for(int i = 0; i < n; i++) {
		p *= diff[i].p;
	 }
	 p *= pn;

	 bool b_low_hw = true;//(hamming_weight(dxx) <= SPECK_MAX_HW) && (hamming_weight(dyy) <= SPECK_MAX_HW);
	 if((b_low_hw) && (p >= *Bn) && (p != 1.0) && (p != 0.0)) { // skip the 0-diff trail (p = 1.0)
#if 1									  // DEBUG
		if (p > *Bn) {
		  printf("\n[%s:%d] %d | Update best found Bn: 2^%f -> 2^%f\n", __FILE__, __LINE__, n, log2(*Bn), log2(p));
		}
#endif
		diff[n].dx = dxx;
		diff[n].dy = dyy;
		diff[n].p = pn;
		*Bn = p;
		B[n] = p;
		for(int i = 0; i < nrounds; i++) {
		  //		  *dx_init = dx_init_in;
		  //		  *dy_init = dy_init_in;
		  trail[i].dx = diff[i].dx;
		  trail[i].dy = diff[i].dy;
		  trail[i].p = diff[i].p;
		}
	 }
  }
}

// --------------- ENCRYPT --------}

// {------  SPECK THRESHOLD SEARCH SIMPLE ---

/**
 * Do not apply the back-to-the-highway heuristic. Limit only by Hamming weight.
 */
void speck_xor_threshold_search_simple(const int n, const int nrounds, gsl_matrix* A[2][2][2], double B[NROUNDS], double* Bn,
													const differential_t diff_in[NROUNDS], WORD_T dx_init_in, WORD_T dy_init_in, 
													differential_t trail[NROUNDS], WORD_T* dx_init, WORD_T* dy_init,
													uint32_t right_rot_const, uint32_t left_rot_const,
													std::multiset<differential_3d_t, struct_comp_diff_3d_p>* diff_mset_p, // highways
													std::set<differential_3d_t, struct_comp_diff_3d_dx_dy_dz>* diff_set_dx_dy_dz,
													double p_thres, bool b_speck_cluster_trails)
{
  double pn = 0.0;

  // make a local copy of the input diff trail
  differential_t diff[NROUNDS] = {{0, 0, 0, 0.0}};
  for(int i = 0; i < n; i++) {
	 diff[i].dx = diff_in[i].dx;
	 diff[i].dy = diff_in[i].dy;
	 diff[i].p = diff_in[i].p;
  }

  if((n == 0) && (nrounds == 1)) {						  // Only one round
	 bool b_end = false;
	 std::multiset<differential_3d_t, struct_comp_diff_3d_p>::iterator mset_iter = diff_mset_p->begin();
	 uint32_t cnt = 0;
	 while((mset_iter != diff_mset_p->end()) && (!b_end)) {
		WORD_T dx = mset_iter->dx;
		WORD_T dy = mset_iter->dy;
		WORD_T dz = mset_iter->dz;
		pn = mset_iter->p;
		WORD_T dxx = dz;		                     // x_{i+1}
		WORD_T dyy = LROT(dy, left_rot_const) ^ dz; // y_{i+1}
		bool b_is_low_hw = (hamming_weight(dxx) <= SPECK_MAX_HW) && (hamming_weight(dyy) <= SPECK_MAX_HW);
#if 0									  // DEBUG
		printf("\r[%s:%d] %2d: [%2d / %2d] %8X -> %8X, 2^%f, 2^%f", __FILE__, __LINE__, n, cnt, diff_mset_p->size(), dx, dy, log2(pn), log2(*Bn));
		fflush(stdout);
#endif
		if((pn >= *Bn) && (pn != 0.0) && (b_is_low_hw)) {
		  dx_init_in = LROT(dx, right_rot_const);
		  dy_init_in = dy;
		  trail[n].dx = dxx;		  // dx_{i+1}
		  trail[n].dy = dyy;		  // dy_{i+1} 
		  trail[n].p = pn;
		  *Bn = pn;
		  B[n] = pn;
		} else {
		  b_end = true;
		}
		mset_iter++;
		cnt++;
	 }	// while()
  }

  if((n == 0) && (nrounds > 1)) {						  // Round-0 and not last round
	 bool b_end = false;
	 std::multiset<differential_3d_t, struct_comp_diff_3d_p>::iterator mset_iter = diff_mset_p->begin();
	 uint32_t cnt = 0;
	 while((mset_iter != diff_mset_p->end()) && (!b_end)) {
		WORD_T dx = mset_iter->dx; // alpha
		WORD_T dy = mset_iter->dy; // gamma
		WORD_T dz = mset_iter->dz;
		pn = mset_iter->p;
		WORD_T dxx = dz;		                     // x_{i+1}
		WORD_T dyy = LROT(dy, left_rot_const) ^ dz; // y_{i+1}
		double p = pn * B[nrounds - 1 - (n + 1)];
		assert(B[nrounds - 1 - (n + 1)] != 0.0);
		std::multiset<differential_3d_t, struct_comp_diff_3d_p>::iterator begin_iter = diff_mset_p->begin();
		bool b_is_low_hw = (hamming_weight(dxx) <= SPECK_MAX_HW) && (hamming_weight(dyy) <= SPECK_MAX_HW);
#if 0									  // DEBUG
		printf("\r[%s:%d] %2d: [%2d / %2d] %8X -> %8X, 2^%f, 2^%f", __FILE__, __LINE__, n, cnt, diff_mset_p->size(), dx, dy, log2(pn), log2(*Bn));
		fflush(stdout);
#endif
		if((p >= *Bn) && (pn != 0.0) && (b_is_low_hw)) {
		  dx_init_in = LROT(dx, right_rot_const);
		  dy_init_in = dy;
		  diff[n].dx = dxx;		  // dx_{i+1}
		  diff[n].dy = dyy;		  // dy_{i+1} 
		  diff[n].p = pn;
		  speck_xor_threshold_search_simple(n+1, nrounds, A, B, Bn, diff, dx_init_in, dy_init_in, trail, dx_init, dy_init, right_rot_const, left_rot_const, diff_mset_p, diff_set_dx_dy_dz, p_thres, b_speck_cluster_trails);
		} else {
		  b_end = true;
		}
		if(begin_iter != diff_mset_p->begin()) { // if the root was updated, start from beginning
		  mset_iter = diff_mset_p->begin();
		  printf("[%s:%d] Return to beginning\n", __FILE__, __LINE__);
		  cnt = 0;
		  assert(0 == 1);
		} else {
		  mset_iter++;
		  cnt++;
		}
	 }
  }

  if((n >= 1) && (n != (nrounds - 1))) { // Round-i and not last round
	 WORD_T dx = RROT(diff[n - 1].dx, right_rot_const); // the x input to ADD
	 WORD_T dy = diff[n - 1].dy; // the y input to ADD

	 differential_3d_t diff_dz;
	 diff_dz.dx = dx;  			  // alpha
	 diff_dz.dy = dy;
	 diff_dz.dz = 0;
	 diff_dz.p = 0.0;

	 // p_i >= p_min = Bn / p1 * p2 ... * p{i-1} * B{n-i} 
	 double p_min = 0.0;
	 p_min = 1.0;
	 for(int i = 0; i < n; i++) { // p[0] * p[1] * p[n-1]
		p_min *= diff[i].p;
	 }
	 p_min = p_min * 1.0 * B[nrounds - 1 - (n + 1)]; 
	 p_min = *Bn / p_min;
	 assert(p_min <= 1.0);

#if !SPECK_48
	 assert(diff_set_dx_dy_dz->size() != 0);
#endif  // #if SPECK_48

	 // stores both highways and countryroads
	 std::multiset<differential_3d_t, struct_comp_diff_3d_p> found_mset_p;
	 std::set<differential_3d_t, struct_comp_diff_3d_dx_dy_dz> found_set_dx_dy_dz;

	 // search in HWays
	 std::set<differential_3d_t, struct_comp_diff_3d_dx_dy_dz>::iterator hway_iter = diff_set_dx_dy_dz->lower_bound(diff_dz);

	 uint32_t hway_cnt = 0;
	 while((hway_iter->dx == dx) && (hway_iter->dy == dy) && (hway_iter != diff_set_dx_dy_dz->end())) {
		if(hway_iter->p >= p_min) {
		  uint32_t old_size = found_set_dx_dy_dz.size();
		  found_set_dx_dy_dz.insert(*hway_iter);
		  // store element only of not already there
		  if(old_size != found_set_dx_dy_dz.size()) {
			 found_mset_p.insert(*hway_iter);
			 assert(hway_iter->dx == dx);
			 assert(hway_iter->dy == dy);
#if 0									  // DEBUG
			 printf("[%s:%d] Found HWay (%8X %8X) (%8X %8X %8X) 2^%f\n", __FILE__, __LINE__, dx, dy, hway_iter->dx, hway_iter->dy, hway_iter->dz, log2(hway_iter->p));
#endif  // DEBUG
			 hway_cnt++;
		  }
		}
		hway_iter++;
	 }
#if 0									  // DEBUG
	 if(hway_cnt > 0) {
		printf("[%s:%d] %2d: Found #HWays %d\n", __FILE__, __LINE__, n, hway_cnt);
	 }
#endif  // DEBUG

#if 1 // search in CRoads
	 WORD_T max_size = (1UL << (WORD_SIZE - 1));
	 uint32_t hw_thres = SPECK_MAX_HW;
	 //	 uint32_t cnt_new =
	 speck_xdp_add_dx_dy_pddt_simple(dx, dy, &found_set_dx_dy_dz, &found_mset_p, p_min, hw_thres, max_size);
#endif
#if 0									  // DEBUG
	 if(cnt_new != 0) {
		printf("\r[%s:%d] [%2d / %2d]: Added %d new CR dx dy %8X %8X: p_min = %f (2^%f). New sizes: Dxy %d, Dp %d.", __FILE__, __LINE__, n, NROUNDS, cnt_new, dx, dy, p_min, log2(p_min), (uint32_t)found_set_dx_dy_dz.size(), (uint32_t)found_mset_p.size());
		fflush(stdout);
	 }
#endif

    // add also the MAX: even if nothing else is found then always the greedy choice is an option
	 double p_max = 0.0;
	 WORD_T dz_max = 0;
	 p_max = max_xdp_add_lm(dx, dy, &dz_max);
	 if(p_max >= p_min) {
		differential_3d_t new_diff = {dx, dy, dz_max, p_max};
		uint32_t old_size = found_set_dx_dy_dz.size();
		found_set_dx_dy_dz.insert(new_diff);
		// store element only of not already there
		if(old_size != found_set_dx_dy_dz.size()) {
		  found_mset_p.insert(new_diff);
		}
	 }

	 //	 printf("[%s:%d] CHECKPOINT!\n", __FILE__, __LINE__);
	 assert(found_set_dx_dy_dz.size() == found_mset_p.size());

	 std::multiset<differential_3d_t, struct_comp_diff_3d_p>::iterator find_iter = found_mset_p.begin();

	 if(!((find_iter->dx == dx) && (find_iter->dy == dy) && (find_iter != found_mset_p.end()))) {
#if 0									  // DEBUG
		printf("[%s:%d] No transition found for  R#%2d | %8X %8X -> ? . p_min 2^%f . Exiting...\n", __FILE__, __LINE__, n, dx, dy, log2(p_min));
		//		exit(EXIT_FAILURE);
#endif
		return;
	 }

	 while((find_iter->dx == dx) && (find_iter->dy == dy) && (find_iter != found_mset_p.end())) {
		assert((find_iter->dx == dx));
		assert((find_iter->dy == dy));
		diff_dz = *find_iter;

		dx = diff_dz.dx;
		dy = diff_dz.dy;
		WORD_T dz = diff_dz.dz;
		pn = diff_dz.p;
#if 0									  // DEBUG
		printf("[%s:%d] List: (%X %X %X) 2^%f | b_found_in_hways %d\n", __FILE__, __LINE__, dx, dy, dz, log2(pn), b_found_in_hways);
#endif  // #if 0									  // DEBUG

		double p = 1.0;
		for(int i = 0; i < n; i++) { // p[0] * p[1] * p[n-1]
		  p *= diff[i].p;
		}
		p = p * pn * B[nrounds - 1 - (n + 1)]; 

		WORD_T dxx = dz;
		WORD_T dyy = LROT(dy, left_rot_const) ^ dz; // y_{i+1}
		bool b_is_low_hw = (hamming_weight(dxx) <= SPECK_MAX_HW) && (hamming_weight(dyy) <= SPECK_MAX_HW);

		//		  if((p >= *Bn) && (p != 0.0)) {
		if((p >= *Bn) && (pn != 0.0) && (b_is_low_hw)) {
		  diff[n].dx = dxx;		  // dx_{i+1}
		  diff[n].dy = dyy;		  // dy_{i+1} 
		  diff[n].p = pn;
		  speck_xor_threshold_search_simple(n+1, nrounds, A, B, Bn, diff, dx_init_in, dy_init_in, trail, dx_init, dy_init, right_rot_const, left_rot_const, diff_mset_p, diff_set_dx_dy_dz, p_thres, b_speck_cluster_trails);

		}
		find_iter++;
	 }	// while
		//	 }		// if
  }

  if((n == (nrounds - 1)) && (nrounds > 1)) {		  // Last round

	 WORD_T dx = RROT(diff[n - 1].dx, right_rot_const); // the x input to ADD
	 WORD_T dy = diff[n - 1].dy; // the y input to ADD
	 WORD_T dz = 0;

	 pn = max_xdp_add_lm(dx, dy, &dz);

	 WORD_T dxx = dz;		                     // x_{i+1}
	 WORD_T dyy = LROT(dy, left_rot_const) ^ dz; // y_{i+1}

	 double p = 1.0;
	 for(int i = 0; i < n; i++) {
		p *= diff[i].p;
	 }
	 p *= pn;

	 bool b_is_low_hw = (hamming_weight(dxx) <= SPECK_MAX_HW) && (hamming_weight(dyy) <= SPECK_MAX_HW);
	 if((b_is_low_hw) && (p >= *Bn) && (p != 1.0) && (p != 0.0)) { // skip the 0-diff trail (p = 1.0)
#if 1									  // DEBUG
		if (p > *Bn) {
		  printf("\n[%s:%d] %d | Update best found Bn: 2^%f -> 2^%f\n", __FILE__, __LINE__, n, log2(*Bn), log2(p));
		}
#endif
		diff[n].dx = dxx;
		diff[n].dy = dyy;
		diff[n].p = pn;
		*Bn = p;
		B[n] = p;
		for(int i = 0; i < nrounds; i++) {
		  *dx_init = dx_init_in;
		  *dy_init = dy_init_in;
		  trail[i].dx = diff[i].dx;
		  trail[i].dy = diff[i].dy;
		  trail[i].p = diff[i].p;
		}
	 }
  }
}

// -------  SPECK THRESHOLD SEARCH SIMPLE ---}

// {-------- SPECK48 ---------

void speck_xor_threshold_search_48(const int n, const int nrounds, gsl_matrix* A[2][2][2], double B[NROUNDS], double* Bn,
											  const differential_t diff_in[NROUNDS], WORD_T dx_init_in, WORD_T dy_init_in, 
											  differential_t trail[NROUNDS], WORD_T* dx_init, WORD_T* dy_init,
											  uint32_t right_rot_const, uint32_t left_rot_const,
											  std::multiset<differential_3d_t, struct_comp_diff_3d_p>* diff_mset_p, // highways
											  std::set<differential_3d_t, struct_comp_diff_3d_dx_dy_dz>* diff_set_dx_dy_dz,
											  differential_3d_t* full_diff_set, const uint64_t full_diff_set_len,
											  double p_thres, bool b_speck_cluster_trails)
{
  double pn = 0.0;

  // make a local copy of the input diff trail
  differential_t diff[NROUNDS] = {{0, 0, 0, 0.0}};
  for(int i = 0; i < n; i++) {
	 diff[i].dx = diff_in[i].dx;
	 diff[i].dy = diff_in[i].dy;
	 diff[i].p = diff_in[i].p;
  }

  if((n == 0) && (nrounds == 1)) {						  // Only one round
	 uint64_t cnt = 0;										  // skip the tricial differential 0, 0 -> 0
 	 while((cnt < full_diff_set_len) && (full_diff_set[cnt].p >= *Bn)) {
	 // 	 while((cnt < full_diff_set_len)) {
		differential_3d_t diff_i = full_diff_set[cnt];
		WORD_T dx = diff_i.dx;
		WORD_T dy = diff_i.dy;
		WORD_T dz = diff_i.dz;
		pn = diff_i.p;
		WORD_T dxx = dz;		                     // x_{i+1}
		WORD_T dyy = LROT(dy, left_rot_const) ^ dz; // y_{i+1}
		bool b_is_low_hw = (hamming_weight(dxx) <= SPECK_MAX_HW) && (hamming_weight(dyy) <= SPECK_MAX_HW);
#if 0									  // DEBUG
		printf("\r[%s:%d] %2d: [%2lld / %2lld] %8X -> %8X, 2^%f, 2^%f", __FILE__, __LINE__, n, cnt, full_diff_set_len, dx, dy, log2(pn), log2(*Bn));
		//		printf("\r[%s:%d] %2d: [%2ld / %2ld] %8X -> %8X, 2^%f, 2^%f", __FILE__, __LINE__, n, cnt, full_diff_set_len, dx, dy, log2(pn), log2(*Bn));
		fflush(stdout);
#endif
		dx_init_in = LROT(dx, right_rot_const);
		dy_init_in = dy;
		//		if((pn >= *Bn) && (pn != 0.0) && (b_is_low_hw)) {
		if((pn >= *Bn) && (pn != 0.0) && (b_is_low_hw) && (dx_init_in != 0) && (dy_init_in != 0)) {
		  trail[n].dx = dxx;		  // dx_{i+1}
		  trail[n].dy = dyy;		  // dy_{i+1} 
		  trail[n].p = pn;
		  *Bn = pn;
		  B[n] = pn;
		}
		cnt++;
	 }	// while()
  }

  if((n == 0) && (nrounds > 1)) {						  // Round-0 and not last round
	 double p_min = 1.0;
	 for(int i = 0; i < n; i++) { // p[0] * p[1] * p[n-1]
		p_min *= diff[i].p;
	 }
	 p_min = p_min * 1.0 * B[nrounds - 1 - (n + 1)]; 
	 assert(p_min != 0.0);
	 p_min = *Bn / p_min;
	 assert(p_min <= 1.0);
	 double Bn_prev = *Bn;
	 printf("[%s:%d] %d: Init p_min 2^%f\n", __FILE__, __LINE__, n, log2(p_min));

	 uint64_t cnt = 0;
 	 while((cnt < full_diff_set_len) && (full_diff_set[cnt].p >= p_min)) {
		differential_3d_t diff_i = full_diff_set[cnt];
		WORD_T dx = diff_i.dx; // alpha
		WORD_T dy = diff_i.dy; // gamma
		WORD_T dz_max = diff_i.dz;
		double p_max = diff_i.p;

#if 0									  // DEBUG
		printf("\r[%s:%d] %2d: [%2lld / %2lld] %8X -> %8X, 2^%f, 2^%f", __FILE__, __LINE__, n, cnt, full_diff_set_len, dx, dy, log2(p_max), log2(p_min));
		//		printf("\r[%s:%d] %2d: [%2ld / %2ld] %8X -> %8X, 2^%f, 2^%f", __FILE__, __LINE__, n, cnt, full_diff_set_len, dx, dy, log2(p_max), log2(p_min));
		fflush(stdout);
#endif
		// stores both highways and countryroads
		std::multiset<differential_3d_t, struct_comp_diff_3d_p> found_mset_p;
		std::set<differential_3d_t, struct_comp_diff_3d_dx_dy_dz> found_set_dx_dy_dz;

		// add the max
		differential_3d_t diff_max;
		diff_max.dx = dx;  			  // alpha
		diff_max.dy = dy;
		diff_max.dz = dz_max;
		diff_max.p = p_max;

		found_mset_p.insert(diff_max);
		found_set_dx_dy_dz.insert(diff_max);

#if 1 // search in CRoads
		uint32_t max_size = 10;//(1UL << (WORD_SIZE - 1));
		uint32_t hw_thres = SPECK_MAX_HW;
		//		uint32_t cnt_new =
		  speck_xdp_add_dx_dy_pddt_simple(dx, dy, &found_set_dx_dy_dz, &found_mset_p, p_min, hw_thres, max_size);
#endif
#if 0									  // DEBUG
		if(cnt_new != 0) {
		  printf("\r[%s:%d] [%2d / %2d]: Added %d new CR dx dy %8X %8X: p_min = %f (2^%f). New sizes: Dxy %d, Dp %d.", __FILE__, __LINE__, n, NROUNDS, cnt_new, dx, dy, p_min, log2(p_min), (uint32_t)found_set_dx_dy_dz.size(), (uint32_t)found_mset_p.size());
		  fflush(stdout);
		}
#endif

		//	 printf("[%s:%d] CHECKPOINT!\n", __FILE__, __LINE__);
		assert(found_set_dx_dy_dz.size() == found_mset_p.size());

		std::multiset<differential_3d_t, struct_comp_diff_3d_p>::iterator find_iter = found_mset_p.begin();

		if(!((find_iter->dx == dx) && (find_iter->dy == dy) && (find_iter != found_mset_p.end()))) {
#if 0									  // DEBUG
		  printf("[%s:%d] No transition found for  R#%2d | %8X %8X -> ? . p_min 2^%f . Exiting...\n", __FILE__, __LINE__, n, dx, dy, log2(p_min));
		  //		exit(EXIT_FAILURE);
#endif
		  return;
		}

		// {--- inner while() over dz ----
		while((find_iter->dx == dx) && (find_iter->dy == dy) && (find_iter != found_mset_p.end())) {
		  assert((find_iter->dx == dx));
		  assert((find_iter->dy == dy));
		  differential_3d_t diff_dz = *find_iter;

		  dx = diff_dz.dx;
		  dy = diff_dz.dy;
		  WORD_T dz = diff_dz.dz;
		  pn = diff_dz.p;

		  //		  pn = mset_iter->p;
		  WORD_T dxx = dz;		                     // x_{i+1}
		  WORD_T dyy = LROT(dy, left_rot_const) ^ dz; // y_{i+1}
		  double p = pn * B[nrounds - 1 - (n + 1)];
		  assert(B[nrounds - 1 - (n + 1)] != 0.0);
		  //		  std::multiset<differential_3d_t, struct_comp_diff_3d_p>::iterator begin_iter = diff_mset_p->begin();
		  bool b_is_low_hw = (hamming_weight(dxx) <= SPECK_MAX_HW) && (hamming_weight(dyy) <= SPECK_MAX_HW);
#if 0									  // DEBUG
		  printf("\r[%s:%d] %2d: [%2d / %2d] %8X -> %8X, 2^%f, 2^%f", __FILE__, __LINE__, n, cnt, diff_mset_p->size(), dx, dy, log2(pn), log2(*Bn));
		  fflush(stdout);
#endif
		  if((p >= *Bn) && (pn != 0.0) && (b_is_low_hw)) {
			 dx_init_in = LROT(dx, right_rot_const);
			 dy_init_in = dy;
			 diff[n].dx = dxx;		  // dx_{i+1}
			 diff[n].dy = dyy;		  // dy_{i+1} 
			 diff[n].p = pn;
			 speck_xor_threshold_search_48(n+1, nrounds, A, B, Bn, diff, dx_init_in, dy_init_in, trail, dx_init, dy_init, right_rot_const, left_rot_const, diff_mset_p, diff_set_dx_dy_dz, full_diff_set, full_diff_set_len, p_thres, b_speck_cluster_trails);
		// update min
			 if(*Bn != Bn_prev) {
				assert(*Bn > Bn_prev);
				double p_min_old = p_min;
				p_min = 1.0;
				for(int i = 0; i < n; i++) { // p[0] * p[1] * p[n-1]
				  p_min *= diff[i].p;
				}
				p_min = p_min * 1.0 * B[nrounds - 1 - (n + 1)]; 
				assert(p_min != 0.0);
				p_min = *Bn / p_min;
				assert(p_min < 1.0);
				Bn_prev = *Bn;
				printf("[%s:%d] Update p_min 2^%f -> 2^%f\n", __FILE__, __LINE__, log2(p_min_old), log2(p_min));
				assert(p_min_old <= p_min);
			 }
		  }
		  cnt++;
		  find_iter++;
		}
		// inner while() ----}
		cnt++;
	 }	// outer while()
  }

  if((n >= 1) && (n != (nrounds - 1))) { // Round-i and not last round

	 WORD_T dx = RROT(diff[n - 1].dx, right_rot_const); // the x input to ADD
	 WORD_T dy = diff[n - 1].dy; // the y input to ADD

	 differential_3d_t diff_dz;
	 diff_dz.dx = dx;  			  // alpha
	 diff_dz.dy = dy;
	 diff_dz.dz = 0;
	 diff_dz.p = 0.0;

	 // p_i >= p_min = Bn / p1 * p2 ... * p{i-1} * B{n-i} 
	 double p_min = 0.0;
	 p_min = 1.0;
	 for(int i = 0; i < n; i++) { // p[0] * p[1] * p[n-1]
		p_min *= diff[i].p;
	 }
	 p_min = p_min * 1.0 * B[nrounds - 1 - (n + 1)]; 
	 p_min = *Bn / p_min;
	 assert(p_min <= 1.0);

	 assert(diff_set_dx_dy_dz->size() != 0);

	 // stores both highways and countryroads
	 std::multiset<differential_3d_t, struct_comp_diff_3d_p> found_mset_p;
	 std::set<differential_3d_t, struct_comp_diff_3d_dx_dy_dz> found_set_dx_dy_dz;

	 // search in HWays
	 std::set<differential_3d_t, struct_comp_diff_3d_dx_dy_dz>::iterator hway_iter = diff_set_dx_dy_dz->lower_bound(diff_dz);

	 //	 assert(diff_set_dx_dy_dz->size() != 0);
	 //	 assert(diff_mset_p->size() != 0);

	 uint32_t hway_cnt = 0;
	 while((hway_iter->dx == dx) && (hway_iter->dy == dy) && (hway_iter != diff_set_dx_dy_dz->end())) {
		if(hway_iter->p >= p_min) {
		  uint32_t old_size = found_set_dx_dy_dz.size();
		  found_set_dx_dy_dz.insert(*hway_iter);
		  // store element only of not already there
		  if(old_size != found_set_dx_dy_dz.size()) {
			 found_mset_p.insert(*hway_iter);
			 assert(hway_iter->dx == dx);
			 assert(hway_iter->dy == dy);
#if 0									  // DEBUG
			 printf("[%s:%d] Found HWay (%8X %8X) (%8X %8X %8X) 2^%f\n", __FILE__, __LINE__, dx, dy, hway_iter->dx, hway_iter->dy, hway_iter->dz, log2(hway_iter->p));
#endif  // DEBUG
			 hway_cnt++;
		  }
		}
		hway_iter++;
	 }
#if 0									  // DEBUG
	 if(hway_cnt > 0) {
		printf("[%s:%d] %2d: Found #HWays %d\n", __FILE__, __LINE__, n, hway_cnt);
	 }
#endif  // DEBUG

#if 1 // search in CRoads
	 WORD_T max_size = (1UL << (WORD_SIZE - 1));
	 uint32_t hw_thres = SPECK_MAX_HW;
	 //	 uint32_t cnt_new =
	 speck_xdp_add_dx_dy_pddt_simple(dx, dy, &found_set_dx_dy_dz, &found_mset_p, p_min, hw_thres, max_size);
#endif
#if 0									  // DEBUG
	 if(cnt_new != 0) {
		printf("\r[%s:%d] [%2d / %2d]: Added %d new CR dx dy %8X %8X: p_min = %f (2^%f). New sizes: Dxy %d, Dp %d.", __FILE__, __LINE__, n, NROUNDS, cnt_new, dx, dy, p_min, log2(p_min), (uint32_t)found_set_dx_dy_dz.size(), (uint32_t)found_mset_p.size());
		fflush(stdout);
	 }
#endif

    // add also the MAX: even if nothing else is found then always the greedy choice is an option
	 double p_max = 0.0;
	 WORD_T dz_max = 0;
	 p_max = max_xdp_add_lm(dx, dy, &dz_max);
	 if(p_max >= p_min) {
		differential_3d_t new_diff = {dx, dy, dz_max, p_max};
		uint32_t old_size = found_set_dx_dy_dz.size();
		found_set_dx_dy_dz.insert(new_diff);
		// store element only of not already there
		if(old_size != found_set_dx_dy_dz.size()) {
		  found_mset_p.insert(new_diff);
		}
	 }

	 //	 printf("[%s:%d] CHECKPOINT!\n", __FILE__, __LINE__);
	 assert(found_set_dx_dy_dz.size() == found_mset_p.size());

	 std::multiset<differential_3d_t, struct_comp_diff_3d_p>::iterator find_iter = found_mset_p.begin();

	 if(!((find_iter->dx == dx) && (find_iter->dy == dy) && (find_iter != found_mset_p.end()))) {
#if 0									  // DEBUG
		printf("[%s:%d] No transition found for  R#%2d | %8X %8X -> ? . p_min 2^%f . Exiting...\n", __FILE__, __LINE__, n, dx, dy, log2(p_min));
		//		exit(EXIT_FAILURE);
#endif
		return;
	 }

	 while((find_iter->dx == dx) && (find_iter->dy == dy) && (find_iter != found_mset_p.end())) {
		assert((find_iter->dx == dx));
		assert((find_iter->dy == dy));
		diff_dz = *find_iter;

		dx = diff_dz.dx;
		dy = diff_dz.dy;
		WORD_T dz = diff_dz.dz;
		pn = diff_dz.p;
#if 0									  // DEBUG
		printf("[%s:%d] List: (%X %X %X) 2^%f | b_found_in_hways %d\n", __FILE__, __LINE__, dx, dy, dz, log2(pn), b_found_in_hways);
#endif  // #if 0									  // DEBUG

		double p = 1.0;
		for(int i = 0; i < n; i++) { // p[0] * p[1] * p[n-1]
		  p *= diff[i].p;
		}
		p = p * pn * B[nrounds - 1 - (n + 1)]; 

		WORD_T dxx = dz;
		WORD_T dyy = LROT(dy, left_rot_const) ^ dz; // y_{i+1}
		bool b_is_low_hw = (hamming_weight(dxx) <= SPECK_MAX_HW) && (hamming_weight(dyy) <= SPECK_MAX_HW);

		//		  if((p >= *Bn) && (p != 0.0)) {
		if((p >= *Bn) && (pn != 0.0) && (b_is_low_hw)) {
		  diff[n].dx = dxx;		  // dx_{i+1}
		  diff[n].dy = dyy;		  // dy_{i+1} 
		  diff[n].p = pn;
		  speck_xor_threshold_search_48(n+1, nrounds, A, B, Bn, diff, dx_init_in, dy_init_in, trail, dx_init, dy_init, right_rot_const, left_rot_const, diff_mset_p, diff_set_dx_dy_dz, full_diff_set, full_diff_set_len, p_thres, b_speck_cluster_trails);

		}
		find_iter++;
	 }	// while
		//	 }		// if
  }

  if((n == (nrounds - 1)) && (nrounds > 1)) {		  // Last round

	 WORD_T dx = RROT(diff[n - 1].dx, right_rot_const); // the x input to ADD
	 WORD_T dy = diff[n - 1].dy; // the y input to ADD
	 WORD_T dz = 0;

	 pn = max_xdp_add_lm(dx, dy, &dz);

	 WORD_T dxx = dz;		                     // x_{i+1}
	 WORD_T dyy = LROT(dy, left_rot_const) ^ dz; // y_{i+1}

	 double p = 1.0;
	 for(int i = 0; i < n; i++) {
		p *= diff[i].p;
	 }
	 p *= pn;

	 bool b_is_low_hw = (hamming_weight(dxx) <= SPECK_MAX_HW) && (hamming_weight(dyy) <= SPECK_MAX_HW);
	 if((b_is_low_hw) && (p >= *Bn) && (p != 1.0) && (p != 0.0)) { // skip the 0-diff trail (p = 1.0)
#if 1									  // DEBUG
		if (p > *Bn) {
		  printf("\n[%s:%d] %d | Update best found Bn: 2^%f -> 2^%f\n", __FILE__, __LINE__, n, log2(*Bn), log2(p));
		}
#endif
		diff[n].dx = dxx;
		diff[n].dy = dyy;
		diff[n].p = pn;
		*Bn = p;
		B[n] = p;
		for(int i = 0; i < nrounds; i++) {
		  *dx_init = dx_init_in;
		  *dy_init = dy_init_in;
		  trail[i].dx = diff[i].dx;
		  trail[i].dy = diff[i].dy;
		  trail[i].p = diff[i].p;
		}
	 }
  }
}

// -------- SPECK48 ----------}

void speck_boost_print_hash_table(boost::unordered_map<std::array<differential_t, NROUNDS>, uint32_t, speck_trail_hash, speck_trail_equal_to> trails_hash_map, uint32_t trail_len, uint32_t dx_input, uint32_t dy_input)
{
  FILE* fp = fopen(SPECK_LOG_FILE, "a");
  //  printf("[%s:%d] CHECKPOINT! Enter %s() trail_len %d hmap_size %d\n", __FILE__, __LINE__, __FUNCTION__, trail_len, (uint32_t)trails_hash_map.size());
#if 0//(WORD_SIZE <= 16)
  uint32_t key[SPECK_MAX_NROUNDS] = {0};
  key[0] = xrandom() & MASK;
  key[1] = xrandom() & MASK;
  key[2] = xrandom() & MASK;
  key[3] = xrandom() & MASK;
#endif

  boost::unordered_map<std::array<differential_t, NROUNDS>, uint32_t, speck_trail_hash, speck_trail_equal_to>::iterator hash_map_iter 
	 = trails_hash_map.begin();

  //  uint32_t dx_in = hash_map_iter->first[0].dx;
  //  uint32_t dy_in = hash_map_iter->first[1].dy;
  uint32_t dx_in = dx_input;
  uint32_t dy_in = dy_input;

  uint32_t dx_out = hash_map_iter->first[trail_len - 1].dx;
  uint32_t dy_out = hash_map_iter->first[trail_len - 1].dy;

  uint32_t trail_cnt = 0;
  double p_tot = 0.0;

#define PRINT_TRAIL 0
#define PRINT_TRAIL_FILE 0
#if PRINT_TRAIL									  // print trail
  printf("[%s:%d] Found %d trails:\n", __FILE__, __LINE__, (uint32_t)trails_hash_map.size());
#endif
#if PRINT_TRAIL_FILE
  fprintf(fp, "[%s:%d] Found %d trails:\n", __FILE__, __LINE__, (uint32_t)trails_hash_map.size());
#endif  // #if PRINT_TRAIL_FILE
  while(hash_map_iter != trails_hash_map.end()) {
	 trail_cnt++;
	 double p = 1.0;

#if PRINT_TRAIL									  // print trail
	 printf("[%5d] ", trail_cnt);
	 printf("%X %X ", dx_in, dy_in);
#endif
#if PRINT_TRAIL_FILE
	 fprintf(fp, "[%5d] ", trail_cnt);
	 fprintf(fp, "%X %X ", dx_in, dy_in);
#endif  // #if PRINT_TRAIL_FILE
	 for(uint32_t i = 0; i < trail_len; i++) {
#if PRINT_TRAIL									  // print trail
		printf("%X %X ", hash_map_iter->first[i].dx, hash_map_iter->first[i].dy);
#endif
#if PRINT_TRAIL_FILE
		fprintf(fp, "%X %X ", hash_map_iter->first[i].dx, hash_map_iter->first[i].dy);
#endif  // #if PRINT_TRAIL_FILE
		p *= hash_map_iter->first[i].p;
	 }
	 p_tot += p;
#if PRINT_TRAIL									  // print trail
	 printf(" | 2^%f ", log2(p));
#endif
#if PRINT_TRAIL_FILE
	 fprintf(fp, " | 2^%f ", log2(p));
#endif  // #if PRINT_TRAIL_FILE
#if PRINT_TRAIL									  // print trail
	 printf("\n");
#endif
#if PRINT_TRAIL_FILE
	 fprintf(fp, "\n");
#endif  // #if PRINT_TRAIL_FILE
	 hash_map_iter++;
  }

#if 1//PRINT_TRAIL
  //  printf("Probability of differential: 2^%f\n", log2(p_tot));
  //  printf("[%s:%d] %2d R (%8X %8X) -> (%8X %8X) : [%10d trails]  2^%f\n", __FILE__, __LINE__, trail_len, dx_in, dy_in, dx_out, dy_out, (uint32_t)trails_hash_map.size(), log2(p_tot));
  printf("\r[%s:%d] %2d R (%8X %8X) -> (%8X %8X) : [%10d trails]  2^%12.10f", __FILE__, __LINE__, trail_len, dx_in, dy_in, dx_out, dy_out, (uint32_t)trails_hash_map.size(), log2(p_tot));
  fflush(stdout);

  //  fprintf(fp, "Probability of differential: 2^%f\n", log2(p_tot));
  fprintf(fp, "[%s:%d] %2d R (%8X %8X) -> (%8X %8X) : [%10d trails]  2^%12.10f\n", __FILE__, __LINE__, trail_len, dx_in, dy_in, dx_out, dy_out, (uint32_t)trails_hash_map.size(), log2(p_tot));
#else

  printf("\r[%s:%d] %2d R (%8X %8X) -> (%8X %8X) : [%10d trails]  2^%f", __FILE__, __LINE__, trail_len, dx_in, dy_in, dx_out, dy_out, (uint32_t)trails_hash_map.size(), log2(p_tot));
  fflush(stdout);
#endif

  fclose(fp);
}


//#define SPECK_CLUSTER_TRAILS 1

/**
 * \see simon_xor_cluster_trails_boost
 */
void speck_xor_cluster_trails_boost(const int n, const int nrounds, gsl_matrix* A[2][2][2], double B[NROUNDS], //double* Bn,
												const differential_t diff_in[NROUNDS], differential_t trail[NROUNDS], 
												boost::unordered_map<std::array<differential_t, NROUNDS>, uint32_t, speck_trail_hash, speck_trail_equal_to>* trails_hash_map,
												const differential_t input_diff, const differential_t output_diff, 
												uint32_t right_rot_const, uint32_t left_rot_const,
												std::multiset<differential_3d_t, struct_comp_diff_3d_p>* diff_mset_p, // highways
												std::set<differential_3d_t, struct_comp_diff_3d_dx_dy_dz>* diff_set_dx_dy_dz,
												std::multiset<differential_3d_t, struct_comp_diff_3d_p>* croads_diff_mset_p, // country roads
												std::set<differential_3d_t, struct_comp_diff_3d_dx_dy_dz>* croads_diff_set_dx_dy_dz,
												double eps)
{
  //  printf("[%s:%d] CHECKPOINT!\n", __FILE__, __LINE__);

  double pn = 0.0;

  // make a local copy of the input diff trail
  differential_t diff[NROUNDS] = {{0, 0, 0, 0.0}};
  for(int i = 0; i < n; i++) {
	 diff[i].dx = diff_in[i].dx;
	 diff[i].dy = diff_in[i].dy;
	 diff[i].p = diff_in[i].p;
  }

  if((n >= 0) && (n < (nrounds - 1))) { // Round-i and not last round

#if 0									  // DEBUG
	 printf("[%s:%d] CHECKPOINT! n = %d\n", __FILE__, __LINE__, n);
#endif

	 WORD_T dx = RROT(diff[n - 1].dx, right_rot_const); // the x input to ADD
	 WORD_T dy = diff[n - 1].dy; // the y input to ADD

	 if(n == 0) {
		dx = RROT(input_diff.dx, right_rot_const);
		dy = input_diff.dy;
	 }

	 differential_3d_t diff_dz;
	 diff_dz.dx = dx;  			  // alpha
	 diff_dz.dy = dy;
	 diff_dz.dz = 0;
	 diff_dz.p = 0.0;

	 std::multiset<differential_3d_t, struct_comp_diff_3d_p> found_mset_p;

	 // p_i >= p_min = Bn / p1 * p2 ... * p{i-1} * B{n-i} 
	 double p_min = 1.0;
	 for(int i = 0; i < n; i++) { // p[0] * p[1] * p[n-1]
		p_min *= diff[i].p;
	 }
	 p_min = p_min * 1.0 * B[nrounds - 1 - (n + 1)]; 
	 p_min = (B[nrounds - 1] * eps) / p_min;
	 // if the prob. so far is already lower than than the maximum allowed prob
    // the set the maximum allowed probability to 1.0
	 if(p_min > 1.0) {
		p_min = 1.0;
	 }

#if 1									  // DEBUG
	 if(p_min > 1.0) {
		double p_min_temp = 1.0;
		printf("[%s:%d] 2^%f\n", __FILE__, __LINE__, log2(p_min_temp));
		for(int i = 0; i < n; i++) { // p[0] * p[1] * p[n-1]
		  p_min_temp *= diff[i].p;
		  printf("diff[%d] 2^%f\n", i, log2(diff[i].p));
		}
		printf("[%s:%d] p_min_temp 2^%f\n", __FILE__, __LINE__, log2(p_min_temp));
		p_min_temp = p_min_temp * 1.0 * B[nrounds - 1 - (n + 1)]; 
		printf("[%s:%d] n %d  B[%d] 2^%f\n", __FILE__, __LINE__, n, nrounds - 1 - (n + 1), log2(B[nrounds - 1 - (n + 1)]));
		printf("[%s:%d] p_min_temp 2^%f\n", __FILE__, __LINE__, log2(p_min_temp));
		printf("[%s:%d] n %d  B[%d] 2^%f\n", __FILE__, __LINE__, n, nrounds - 1, log2(B[nrounds - 1]));
		double p_min_temp_final = (B[nrounds - 1] * eps) / p_min_temp;
		printf("[%s:%d] p_min_temp = (2^%f * 2^%f) / 2^%f = 2^%f\n", __FILE__, __LINE__, 
				 log2(B[nrounds - 1]), log2(eps), log2(p_min_temp), log2(p_min_temp_final));

	 }
#endif
	 assert(p_min <= 1.0);

	 assert(diff_set_dx_dy_dz->size() != 0);


	 // check if the differential is not already in the set
	 std::set<differential_3d_t, struct_comp_diff_3d_dx_dy_dz>::iterator hway_iter = diff_set_dx_dy_dz->lower_bound(diff_dz);
 	 bool b_found_in_hways = (hway_iter != diff_set_dx_dy_dz->end()) && (hway_iter->dx == dx) && (hway_iter->dy == dy);
	 bool b_found_in_croads = false;
	 if(b_found_in_hways) {
		while((hway_iter->dx == dx)  && (hway_iter->dy == dy)) {
		  found_mset_p.insert(*hway_iter);
		  hway_iter++;
		}
	 }

#if 0									  // add the max
	 double p_max = 0.0;
	 WORD_T dz_max = 0;
#if((WORD_SIZE == 16) || (WORD_SIZE == 32))
	 p_max = max_xdp_add_lm(dx, dy, &dz_max);
#else
	 //	 p_max = max_xdp_add(A, dx, dy, &dz_max);
	 p_max = max_xdp_add_lm(dx, dy, &dz_max);
#endif
	 assert(p_max != 0.0);
	 if(true) {
#if 0									  // DEBUG
		printf("[%s:%d] Add (%X %X %X) 2^%f\n", __FILE__, __LINE__, dx, dy, dz_max, log2(p_max));
#endif  // #if 0									  // DEBUG
		differential_3d_t new_diff = {dx, dy, dz_max, p_max};
		found_mset_p.insert(new_diff);
		b_found_in_hways = true;
	 }
#endif

	 croads_diff_set_dx_dy_dz->clear();
	 croads_diff_mset_p->clear();
	 std::set<differential_3d_t, struct_comp_diff_3d_dx_dy_dz>::iterator croad_iter = croads_diff_set_dx_dy_dz->lower_bound(diff_dz);
	 b_found_in_croads = (croad_iter != croads_diff_set_dx_dy_dz->end()) && (croad_iter->dx == dx) && (croad_iter->dy == dy);
	 assert(b_found_in_croads == false);

	 const uint32_t max_cnt = (1ULL << 25);//SPECK_MAX_DIFF_CNT; 
	 bool b_speck_cluster_trails = true;
	 uint32_t cnt_new = speck_xdp_add_dx_dy_pddt(dx, dy, diff_set_dx_dy_dz, diff_mset_p, croads_diff_set_dx_dy_dz, croads_diff_mset_p, right_rot_const, left_rot_const, p_min, max_cnt, b_speck_cluster_trails);

	 if(cnt_new != 0) {
#if 0									  // DEBUG
		printf("\r[%s:%d] [%2d / %2d]: Added %d new CR dx dy %8X %8X: p_min = %f (2^%f). New sizes: Dxy %d, Dp %d.", __FILE__, __LINE__, n, NROUNDS, cnt_new, dx, dy, p_min, log2(p_min), croads_diff_set_dx_dy_dz->size(), croads_diff_mset_p->size());
		fflush(stdout);
#endif
		croad_iter = croads_diff_set_dx_dy_dz->lower_bound(diff_dz);
		b_found_in_croads = (croad_iter != croads_diff_set_dx_dy_dz->end()) && (croad_iter->dx == dx) && (croad_iter->dy == dy);
	 } else {
#if 0									  // DEBUG
		printf("[%s:%d] [%2d / %2d]: No new country roads found: p_min = %f (2^%f).\n", __FILE__, __LINE__, n, NROUNDS, p_min, log2(p_min));
#endif
	 }

	 if(b_found_in_croads) {
		//		printf("[%s:%d] CHECKPOINT!\n", __FILE__, __LINE__);

		assert(croad_iter->p >= p_min);
		while((croad_iter->dx == dx) && (croad_iter->dy == dy) && (croad_iter->p >= p_min)) {

		  dx = croad_iter->dx;
		  dy = croad_iter->dy;
		  WORD_T dz = croad_iter->dz;

		  WORD_T dx_next = dz;
		  WORD_T dy_next = LROT(dy, left_rot_const) ^ dx_next;
		  WORD_T dx_next_rrot = RROT(dx_next, right_rot_const); // ! the left input to the next round will be rotated before entering the ADD op

		  bool b_low_hw = (hamming_weight(dx) <= SPECK_CLUSTER_MAX_HW) &&  (hamming_weight(dy) <= SPECK_CLUSTER_MAX_HW) && (hamming_weight(dz) <= SPECK_CLUSTER_MAX_HW);
		  bool b_low_hw_next = (hamming_weight(dx_next_rrot) <= SPECK_CLUSTER_MAX_HW) &&  (hamming_weight(dy_next) <= SPECK_CLUSTER_MAX_HW);

		  if(b_low_hw && b_low_hw_next) {
#if 0	  // DEBUG
			 printf("[%s:%d] List of CR: dx dy dz %8X %8X %8X 2^%f\n\n", __FILE__, __LINE__, dx, dy, dz, log2(croad_iter->p));
			 printf("[%s:%d] CHECK is HW: dx_next_rrot dy_next %8X %8X\n\n", __FILE__, __LINE__, dx_next_rrot, dy_next);
#endif
			 found_mset_p.insert(*croad_iter);
		  }
		  croad_iter++;
		}
	 }

	 //	 assert(found_mset_p.size() != 0);
	 //	 printf("[%s:%d] CHECKPOINT!\n", __FILE__, __LINE__);
	 std::multiset<differential_3d_t, struct_comp_diff_3d_p>::iterator find_iter = found_mset_p.begin();

#if 0									  // DEBUG
	 printf("[%s:%d] %2d: found_mset size %d\n", __FILE__, __LINE__, n, found_mset_p.size());
#endif

	 if((find_iter->dx == dx) && (find_iter->dy == dy)) {
		while((find_iter->dx == dx) && (find_iter->dy == dy) && (find_iter != found_mset_p.end())) {
		  assert((find_iter->dx == dx));
		  assert((find_iter->dy == dy));
		  diff_dz = *find_iter;

		  dx = diff_dz.dx;
		  dy = diff_dz.dy;
		  WORD_T dz = diff_dz.dz;
		  pn = diff_dz.p;
		  assert(pn != 0.0);
#if 0									  // DEBUG
		  printf("[%s:%d] List: (%X %X %X) 2^%f\n", __FILE__, __LINE__, dx, dy, dz, log2(pn));
#endif  // #if 0									  // DEBUG

#if 0
		  double p = 1.0;
		  for(int i = 0; i < n; i++) { // p[0] * p[1] * p[n-1]
			 p *= diff[i].p;
		  }
		  p = p * pn * B[nrounds - 1 - (n + 1)] * eps; // <--- ?
#endif

		  WORD_T dxx = dz;
		  WORD_T dyy = LROT(dy, left_rot_const) ^ dz; // y_{i+1}

		  //		  if((p >= *Bn) && (p != 0.0)) {
		  diff[n].dx = dxx;		  // dx_{i+1}
		  diff[n].dy = dyy;		  // dy_{i+1} 
		  diff[n].p = pn;
			 //		  }

		  //		  if(n < (nrounds - 1) || ((nrounds == 1))) {
		  speck_xor_cluster_trails_boost(n+1, nrounds, A, B, diff, trail, trails_hash_map, input_diff, output_diff, right_rot_const, left_rot_const, diff_mset_p, diff_set_dx_dy_dz, croads_diff_mset_p, croads_diff_set_dx_dy_dz, eps);

		  find_iter++;
		}	// while
	 }	else {
		//		assert(0 == 1);
	 }	// if
  }

  if((n == (nrounds - 1)) && (nrounds > 1)) {		  // Last round

	 WORD_T dx = RROT(diff[n - 1].dx, right_rot_const); // the x input to ADD
	 WORD_T dy = diff[n - 1].dy; // the y input to ADD
	 WORD_T dz = 0;

#if((WORD_SIZE == 16) || (WORD_SIZE == 32))
	 pn = max_xdp_add_lm(dx, dy, &dz);
#else
	 //	 pn = max_xdp_add(A, dx, dy, &dz);
	 pn = max_xdp_add_lm(dx, dy, &dz);
#endif
	 WORD_T dxx = dz;		                     // x_{i+1}
	 WORD_T dyy = LROT(dy, left_rot_const) ^ dz; // y_{i+1}

	 double p = 1.0;
	 for(int i = 0; i < n; i++) {
		p *= diff[i].p;
	 }
	 p *= pn;						  // * eps?
#if 0
	 printf("[%s:%d] Final prob 2^%f\n", __FILE__, __LINE__, log2(p));
#endif
	 if((p != 1.0) && (p != 0.0)) { // skip the 0-diff trail (p = 1.0)

		diff[n].dx = dxx;
		diff[n].dy = dyy;
		diff[n].p = pn;

		if((diff[n].dx == output_diff.dx) && (diff[n].dy == output_diff.dy)) {

		  uint32_t trail_len = nrounds;
		  differential_t trail[NROUNDS] = {{0,0,0,0.0}};


		  for(int i = 0; i < nrounds; i++) {
			 trail[i].dx = diff[i].dx;
			 trail[i].dy = diff[i].dy;
			 trail[i].p = diff[i].p;
		  }

		  speck_trail_hash trail_hash;  // trails hash function

		  std::array<differential_t, NROUNDS> trail_array;
		  for(uint32_t i = 0; i < NROUNDS; i++) {
			 trail_array[i].dx = trail[i].dx;
			 trail_array[i].dy = trail[i].dy;
			 trail_array[i].npairs = trail[i].npairs;
			 trail_array[i].p = trail[i].p;
		  }

		  boost::unordered_map<std::array<differential_t, NROUNDS>, uint32_t, speck_trail_hash, speck_trail_equal_to>::iterator trail_iter 
			 = trails_hash_map->find(trail_array);

		  if(trail_iter == trails_hash_map->end()) { // trail is not in the trail table
#if 0									  // DEBUG
			 printf("[%s:%d] Add new trail: 2^%f | %d\n", __FILE__, __LINE__, log2(p), (uint32_t)trails_hash_map->size());
			 FILE* fp = fopen(SPECK_LOG_FILE, "a");
			 fprintf(fp, "[%s:%d] Add new trail: 2^%f | %d\n", __FILE__, __LINE__, log2(p), (uint32_t)trails_hash_map->size());
			 fclose(fp);
			 //			 assert(0 == 1);
#endif
			 uint32_t trail_hash_val = trail_hash(trail_array);
			 std::pair<std::array<differential_t, NROUNDS>, uint32_t> new_pair (trail_array, trail_hash_val);
			 trails_hash_map->insert(new_pair);

			 speck_boost_print_hash_table(*trails_hash_map, trail_len, input_diff.dx, input_diff.dy);
		  }

#if 0									  // DEBUG
		  for(int i = 0; i < nrounds; i++) {
			 printf("[%s:%d] %8X %8X 2^%f\n", __FILE__, __LINE__, trail[i].dx, trail[i].dy, log2(trail[i].p));
		  }
		  printf("\n");
#endif
		} else {
#if 0
		  printf("\r[%s:%d] Does not match output diffs: (%8X,%8X) vs. (%8X,%8X)", __FILE__, __LINE__, 
					diff[n].dx, diff[n].dy, output_diff.dx, output_diff.dy);
		  fflush(stdout);
#endif
#if 1									  // DEBUG
		  //		  printf("[%s:%d] Does not match output diffs: (%8X,%8X) vs. (%8X,%8X)\n", __FILE__, __LINE__, 
		  //					diff[n].dx, diff[n].dy, output_diff.dx, output_diff.dy);
		  double p_this = 1.0;
		  double p_best = 1.0;
		  for(int i = 0; i < nrounds; i++) {
			 p_this *= diff[i].p;
			 p_best *= trail[i].p;
		  }
		  printf("\r[%s:%d] this: 2^%f (best: 2^%f)", __FILE__, __LINE__, log2(p_this), log2(p_best));
		  fflush(stdout);
		  if(p_this > p_best) {
			 //			 printf("[%s:%d] IN: %8X %8X %f\n", __FILE__, __LINE__, input_diff.dx, input_diff.dy, 1.0);
			 printf("\n{0x%llX, 0x%llX, 0, %f},\n", (WORD_MAX_T)input_diff.dx, (WORD_MAX_T)input_diff.dy, 1.0);
			 for(int i = 0; i < nrounds; i++) {
				//			 printf("[%s:%d] %8X %8X 2^%f\n", __FILE__, __LINE__, trail[i].dx, trail[i].dy, log2(trail[i].p));
				//				printf("[%s:%d] [%2d] %8X %8X 2^%f\n", __FILE__, __LINE__, i, diff[i].dx, diff[i].dy, log2(diff[i].p));
				printf("{0x%llX, 0x%llX, 0, (1.0 / (double)(1ULL <<  %1.0f))},\n", (WORD_MAX_T)diff[i].dx, (WORD_MAX_T)diff[i].dy, log2(diff[i].p));
			 }
			 printf(" | %f 2^%f (best: %f 2^%f)\n", p_this, log2(p_this), p_best, log2(p_best));
			 printf("[%s:%d] Better found. Exiting...\n", __FILE__, __LINE__);
			 exit(1);
		  } 
#endif
		}
	 }
  }
}

void speck_trail_cluster_search_boost(boost::unordered_map<std::array<differential_t, NROUNDS>, uint32_t, speck_trail_hash, speck_trail_equal_to>* trails_hash_map,
												  std::multiset<differential_3d_t, struct_comp_diff_3d_p>* diff_mset_p, // highways
												  std::set<differential_3d_t, struct_comp_diff_3d_dx_dy_dz>* diff_set_dx_dy_dz,
												  uint32_t dx_input, uint32_t dy_input,  
												  double B[NROUNDS], differential_t trail_in[NROUNDS], uint32_t trail_len)
{
  //  assert(trail_len >= NROUNDS);
  assert(trail_len == NROUNDS);
  printf("[%s:%d] trail_len %d\n", __FILE__, __LINE__, trail_len);

  // init A
  gsl_matrix* A[2][2][2];
  xdp_add_alloc_matrices(A);
  xdp_add_sf(A);
  xdp_add_normalize_matrices(A);

  // init C
  gsl_vector* C = gsl_vector_calloc(XDP_ADD_MSIZE);
  gsl_vector_set(C, XDP_ADD_ISTATE, 1.0);

  uint32_t right_rot_const = SPECK_RIGHT_ROT_CONST; 
  uint32_t left_rot_const = SPECK_LEFT_ROT_CONST;

  //  uint32_t dx_init_in = dx_input;
  //  uint32_t dy_init_in = dy_input;

  //	 uint32_t dyy_init = 0;
  differential_t diff[NROUNDS] = {{0,0,0,0.0}};
  differential_t trail[NROUNDS] = {{0, 0, 0, 0.0}}; 
  for(uint32_t i = 0; i < NROUNDS; i++) {
	 trail[i] = {trail_in[i].dx, trail_in[i].dy, trail_in[i].npairs, trail_in[i].p};
  }

  //  std::set<differential_3d_t, struct_comp_diff_3d_dx_dy_dz> diff_set_dx_dy_dz; // Dxy
  //  std::multiset<differential_3d_t, struct_comp_diff_3d_p> diff_mset_p;	 // Dp
  std::set<differential_3d_t, struct_comp_diff_3d_dx_dy_dz> croads_diff_set_dx_dy_dz; // Dxy
  std::multiset<differential_3d_t, struct_comp_diff_3d_p> croads_diff_mset_p;	 // Dp

  //  double p_thres = SPECK_P_THRES;
  //  uint64_t max_cnt = SPECK_MAX_DIFF_CNT;
  //  speck_xdp_add_pddt(WORD_SIZE, p_thres, max_cnt, &diff_set_dx_dy_dz, &diff_mset_p);

  uint32_t init_round = 0;

  uint32_t dx_in = dx_input;
  uint32_t dy_in = dy_input;
  differential_t input_diff = {dx_in, dy_in};

  uint32_t dx_out = trail[trail_len - 1].dx;
  uint32_t dy_out = trail[trail_len - 1].dy;
  differential_t output_diff = {dx_out, dy_out};

  double eps = SPECK_EPS;//1.0 / (double)(1UL << 10);//0.125;//SPECK_EPS

  double p = 1.0;
  speck_trail_hash trail_hash;  // trails hash function
  std::array<differential_t, NROUNDS> trail_array;
  for(uint32_t i = 0; i < NROUNDS; i++) {
	 trail_array[i].dx = trail[i].dx;
	 trail_array[i].dy = trail[i].dy;
	 trail_array[i].npairs = trail[i].npairs;
	 trail_array[i].p = trail[i].p;
	 p *= trail[i].p;
  }
  printf("[%s:%d] Add initial trail: 2^%f | %d\n", __FILE__, __LINE__, log2(p), (uint32_t)trails_hash_map->size());
  uint32_t trail_hash_val = trail_hash(trail_array);
  std::pair<std::array<differential_t, NROUNDS>, uint32_t> new_pair (trail_array, trail_hash_val);
  trails_hash_map->insert(new_pair);

  printf("[%s:%d] Initial trail: %2d R (%8X %8X) -> (%8X %8X) : [%10d trails]  2^%f\n", __FILE__, __LINE__, trail_len, dx_in, dy_in, dx_out, dy_out, (uint32_t)trails_hash_map->size(), log2(p));

  speck_boost_print_hash_table(*trails_hash_map, trail_len, dx_input, dy_input);

  //  speck_xor_cluster_trails_boost(init_round, trail_len, A, B, diff, dx_init_in, dy_init_in, trail, trails_hash_map, input_diff, output_diff, right_rot_const, left_rot_const, &diff_mset_p, &diff_set_dx_dy_dz, &croads_diff_mset_p, &croads_diff_set_dx_dy_dz, eps);
  speck_xor_cluster_trails_boost(init_round, trail_len, A, B, diff, trail, trails_hash_map, input_diff, output_diff, right_rot_const, left_rot_const, diff_mset_p, diff_set_dx_dy_dz, &croads_diff_mset_p, &croads_diff_set_dx_dy_dz, eps);

  gsl_vector_free(C);
  xdp_add_free_matrices(A);
}

void speck_array_differential_3d_alloc(differential_3d_t** T, const uint64_t len)
{
  (*T) = (differential_3d_t *)calloc(len, sizeof(differential_3d_t));
}

void speck_array_differential_3d_free(differential_3d_t* T, const uint64_t len)
{
  free(T);
}


uint32_t speck_xor_trail_search(uint32_t key[SPECK_MAX_NROUNDS], double B[NROUNDS],
										  WORD_T* dx_input, WORD_T* dy_input, 
										  differential_t best_trail[NROUNDS], uint32_t num_rounds)
{
  double p_thres = SPECK_P_THRES;
  uint64_t max_cnt = SPECK_MAX_DIFF_CNT;
  differential_t diff[NROUNDS];	  // arrey of differences
  differential_t trail[NROUNDS] = {{0, 0, 0, 0.0}};
  uint32_t right_rot_const = SPECK_RIGHT_ROT_CONST; 
  uint32_t left_rot_const = SPECK_LEFT_ROT_CONST;
  if(WORD_SIZE == 16) {
	 right_rot_const = SPECK_RIGHT_ROT_CONST_16BITS; 
	 left_rot_const = SPECK_LEFT_ROT_CONST_16BITS;
  }

  // init A
  gsl_matrix* A[2][2][2];
  xdp_add_alloc_matrices(A);
  xdp_add_sf(A);
  xdp_add_normalize_matrices(A);

  // init C
  gsl_vector* C = gsl_vector_calloc(XDP_ADD_MSIZE);
  gsl_vector_set(C, XDP_ADD_ISTATE, 1.0);

  // init bounds
  for(int i = 0; i < NROUNDS; i++) {
	 B[i] = 0.0;
  }

  std::set<differential_3d_t, struct_comp_diff_3d_dx_dy_dz> diff_set_dx_dy_dz; // Dxy
  std::multiset<differential_3d_t, struct_comp_diff_3d_p> diff_mset_p;	 // Dp
  std::set<differential_3d_t, struct_comp_diff_3d_dx_dy_dz> croads_diff_set_dx_dy_dz; // Dxy
  std::multiset<differential_3d_t, struct_comp_diff_3d_p> croads_diff_mset_p;	 // Dp

  uint32_t word_size = WORD_SIZE;

  // compute tsandard pDDT
#if 1 // standard pddt
  uint32_t hw_thres = SPECK_MAX_HW;// = 7
  speck_xdp_add_pddt(word_size, p_thres, hw_thres, max_cnt, &diff_set_dx_dy_dz, &diff_mset_p);
#else  // random entries
  uint32_t hw_thres = 6;
  speck_xdp_add_pddt_rand(word_size, p_thres, hw_thres, max_cnt, &diff_set_dx_dy_dz, &diff_mset_p);
#endif
  assert(diff_set_dx_dy_dz.size() == diff_mset_p.size());

  // compute a list of max prob. diffs to start with
#if SPECK_48
  assert(SPECK_P_THRES == (1.0 / (double)(1UL << 7)));
  //  uint32_t hw_thres = 5;//SPECK_MAX_HW;//5;
  uint32_t full_hw_thres = 5;//7
  uint64_t full_diff_set_len = (1ULL << 32);//(1ULL << 32);
  differential_3d_t* full_diff_set;
  speck_array_differential_3d_alloc(&full_diff_set, full_diff_set_len);
  speck_xdp_add_pddt_dx_dy_max_dz(word_size, p_thres, full_hw_thres, full_diff_set, &full_diff_set_len);

  std::sort(full_diff_set, full_diff_set + full_diff_set_len, sort_comp_diff_3d_p);
#if 0	  // DEBUG
  for(uint32_t i = 0; i < full_diff_set_len; i++) {
	 differential_3d_t diff = full_diff_set[i];
	 //	 printf("[%s:%d] %8X %8X %8X 2^%f \n", __FILE__, __LINE__, diff.dx, diff.dy, diff.dz, log2(diff.p));
	 assert(diff.p >= SPECK_P_THRES);
  }
#endif  // #if 1

  double speck48_ibounds[11] = {
	 //  1.0,								  // 0: input diff
	 (1.0 / (double)(1ULL <<  0)), // 1
	 (1.0 / (double)(1ULL <<  1)), // 2
	 (1.0 / (double)(1ULL <<  3)), // 3
	 (1.0 / (double)(1ULL <<  6)), // 4
	 (1.0 / (double)(1ULL << 10)), // 5
	 (1.0 / (double)(1ULL << 14)), // 6
	 (1.0 / (double)(1ULL << 19)), // 7
	 (1.0 / (double)(1ULL << 26)), // 8 : 24,25 can not
	 (1.0 / (double)(1ULL << 31)), // 9
	 (1.0 / (double)(1ULL << 36)),  // 10
	 (1.0 / (double)(1ULL << 40))  // 11
  };

 for(uint32_t i = 0; i < 11; i++) {
	printf("[%s:%d] speck48_ibounds[%d] %f 2^%f\n", __FILE__, __LINE__, i, speck48_ibounds[i], log2(speck48_ibounds[i]));
 }

#endif  // #if SPECK_48

#if 0									  // DEBUG
  std::set<differential_3d_t, struct_comp_diff_3d_dx_dy_dz>::iterator set_iter = diff_set_dx_dy_dz.begin();
  for(set_iter = diff_set_dx_dy_dz.begin(); set_iter != diff_set_dx_dy_dz.end(); set_iter++) {
	 printf("[%s:%d] %8X %8X %8X 2^%f \n", __FILE__, __LINE__, set_iter->dx, set_iter->dy, set_iter->dz, log2(set_iter->p));
	 assert(set_iter->p >= SPECK_P_THRES);
  }
  std::multiset<differential_3d_t, struct_comp_diff_3d_p>::iterator mset_iter = diff_mset_p.begin();
  for(mset_iter = diff_mset_p.begin(); mset_iter != diff_mset_p.end(); mset_iter++) {
	 printf("[%s:%d] %8X %8X %8X 2^%f \n", __FILE__, __LINE__, mset_iter->dx, mset_iter->dy, mset_iter->dz, log2(mset_iter->p));
	 assert(mset_iter->p >= SPECK_P_THRES);
  }
#endif

#if 0									  // DEBUG
  printf("[%s:%d] p_thres = %f (2^%f), n = %d, #diffs = %d %d\n", __FILE__, __LINE__, 
			p_thres, log2(p_thres), WORD_SIZE, diff_set_dx_dy_dz.size(), diff_mset_p.size());
#endif

#if 0									  // DEBUG
  uint32_t cnt = 0;
  std::multiset<differential_3d_t, struct_comp_diff_3d_p>::iterator set_iter;
  for(set_iter = diff_mset_p.begin(); set_iter != diff_mset_p.end(); set_iter++) {
	 differential_3d_t i_diff = *set_iter;
	 double p_the = xdp_add(A, i_diff.dx, i_diff.dy, i_diff.dz);
	 assert(p_the == i_diff.p);
	 cnt++;
  }
#endif

  bool b_speck_cluster_trails = false;

  double Bn_init = 0.0;
  uint32_t nrounds = 0;

  WORD_T dx_init = 0;
  WORD_T dy_init = 0;

  do {

	 WORD_T dx_init_in = 0;
	 WORD_T dy_init_in = 0;

	 nrounds++;

	 FILE* fp = fopen(SPECK_LOG_FILE, "a");

	 double Bn = Bn_init;
	 int r = 0;						  // initial round
	 B[nrounds - 1] = Bn_init;

	 printf("[%s:%d] nrounds = %d, Bn_init = 2^%f : key %8X %8X %8X %8X\n", __FILE__, __LINE__, nrounds, log2(Bn_init), key[0], key[1], key[2], key[3]);
	 fprintf(fp, "[%s:%d] nrounds = %d, Bn_init = 2^%f : key %8X %8X %8X %8X\n", __FILE__, __LINE__, nrounds, log2(Bn_init), key[0], key[1], key[2], key[3]);

	 // init diffs
	 for(int i = 0; i < NROUNDS; i++) {
		diff[i].dx = 0;
		diff[i].dy = 0;
		diff[i].p = 0.0;
	 }

#if 0 // original
	 speck_xor_threshold_search(r, nrounds, A, B, &Bn, diff, dx_init_in, dy_init_in, trail, &dx_init, &dy_init, right_rot_const, left_rot_const, &diff_mset_p, &diff_set_dx_dy_dz, &croads_diff_mset_p, &croads_diff_set_dx_dy_dz, p_thres, b_speck_cluster_trails);
#else	 // simplified
#if SPECK_48
	 speck_xor_threshold_search_48(r, nrounds, A, B, &Bn, diff, dx_init_in, dy_init_in, trail, &dx_init, &dy_init, right_rot_const, left_rot_const, &diff_mset_p, &diff_set_dx_dy_dz, full_diff_set, full_diff_set_len, p_thres, b_speck_cluster_trails);
#else
	 speck_xor_threshold_search_simple(r, nrounds, A, B, &Bn, diff, dx_init_in, dy_init_in, trail, &dx_init, &dy_init, right_rot_const, left_rot_const, &diff_mset_p, &diff_set_dx_dy_dz, p_thres, b_speck_cluster_trails);
#endif  // #if SPECK_48
#endif  // #if 0 // original

#if 1									  // DEBUG
	 printf("\n");
	 fprintf(fp, "\n");
	 for(uint32_t i = 0; i < nrounds; i++) {
		printf("B[%2d] = 2^%f", i, log2(B[i]));
		fprintf(fp, "B[%2d] = 2^%f", i, log2(B[i]));
		if(i > 0) {
		  if(B[i-1] < B[i]) {
			 printf(" <-");
		  }
		}
		printf("\n");
		fprintf(fp, "\n");
	 }
#endif
	 assert(B[nrounds - 1] == Bn);

	 if((trail[nrounds-1].dx == 0) && (trail[nrounds-1].dy == 0) && (trail[nrounds-1].p == 0.0)) {
		//printf("[%s:%d] R#%d could not satisfy the bound B[%d] = 2^%f 2^%f\n", __FILE__, __LINE__, nrounds, nrounds-1, log2(Bn_init), log2(B[nrounds - 1]));
		printf("[%s:%d] R#%d could not satisfy the bound B[%d] = 2^%f\n", __FILE__, __LINE__, nrounds, nrounds-1, log2(B[nrounds - 1]));
		printf("Exiting...\n");
#if SPECK_48
		speck_array_differential_3d_free(full_diff_set, full_diff_set_len);
#endif
		gsl_vector_free(C);
		xdp_add_free_matrices(A);
		exit(EXIT_FAILURE);
	 }

#if 1									  // DEBUG
	 double p_tot = 1.0;
	 for(uint32_t i = 0; i < nrounds; i++) {
		printf("%2d: %llX -> %llX %f (2^%f)\n", i, (WORD_MAX_T)trail[i].dx, (WORD_MAX_T)trail[i].dy, trail[i].p, log2(trail[i].p));
		fprintf(fp, "%2d: %llX -> %llX %f (2^%f)\n", i, (WORD_MAX_T)trail[i].dx, (WORD_MAX_T)trail[i].dy, trail[i].p, log2(trail[i].p));
		p_tot *= trail[i].p;
	 }
	 printf("p_tot = %16.15f = 2^%f, Bn = %f = 2^%f\n", p_tot, log2(p_tot), Bn, log2(Bn));
	 fprintf(fp, "p_tot = %16.15f = 2^%f, Bn = %f = 2^%f\n", p_tot, log2(p_tot), Bn, log2(Bn));
#endif  // #if 0									  // DEBUG

	 fclose(fp);

#if 1	  // VERIFY
	 if(nrounds >= 1) {
		for(uint32_t i = (nrounds - 1); i >= 1; i--) {
		  WORD_T dyy = LROT(trail[i-1].dy, left_rot_const) ^ trail[i].dx;
		  assert(trail[i].dy == dyy);
		}
	 }
#endif  // #if 1	  // VERIFY

	 // Compute an initial bound for the next round
	 //	 if(0) {

	 uint32_t next_round = nrounds;
#if SPECK_USE_PRECOMPUTED_BOUNDS
	 assert(WORD_SIZE == 24);
	 assert(next_round <= 10);
	 Bn_init = speck48_ibounds[next_round];
	 B[next_round] = Bn_init;
	 //printf("[%s:%d] Init bound for round %d: B[%d] = 2^%f 2^%f 2^%f\n", __FILE__, __LINE__, next_round, next_round-1, log2(B[next_round]), log2(Bn_init), log2(speck48_ibounds[next_round]));
	 printf("[%s:%d] Init bound for round %d: B[%d] = 2^%f\n", __FILE__, __LINE__, next_round, next_round-1, log2(B[next_round]));
#else
	 if((next_round >= 1) && (next_round < NROUNDS)) {

		WORD_T dx = RROT(trail[next_round - 1].dx, right_rot_const); // the x input to ADD
		WORD_T dy = trail[next_round - 1].dy; // the y input to ADD
		WORD_T dz = 0;

		//#if((WORD_SIZE == 16) || (WORD_SIZE == 32))
#if (WORD_SIZE <= 32)
		double p = max_xdp_add_lm(dx, dy, &dz);
#else
		double p = max_xdp_add(A, dx, dy, &dz);
		//		double p = max_xdp_add_lm(dx, dy, &dz);
#endif
		assert(p != 0.0);

		WORD_T dxx = dz;		                     // x_{i+1}
		WORD_T dyy = LROT(dy, left_rot_const) ^ dz; // y_{i+1}

		//	bool b_low_hw = true;//(hamming_weight(dxx) <= SPECK_MAX_HW) && (hamming_weight(dyy) <= SPECK_MAX_HW);
		bool b_low_hw = true;//(p >= SPECK_P_THRES);//(hamming_weight(dxx) <= SPECK_MAX_HW) && (hamming_weight(dyy) <= SPECK_MAX_HW);
		if(b_low_hw) {

		  Bn_init = B[next_round - 1] * p;
		  B[next_round] = Bn_init;

		  //		printf("[%s:%d] Set B[%d] = 2^%f\n", __FILE__, __LINE__, next_round, log2(Bn_init));
		  trail[next_round].dx = dxx;
		  trail[next_round].dy = dyy;
		  trail[next_round].p = p;

		  //		assert(trail[next_round].dx == trail[next_round-1].dy);
		  dyy = LROT(trail[next_round-1].dy, left_rot_const) ^ trail[next_round].dx;
		  assert(trail[next_round].dy == dyy);
#if 0									  // do not modifu the original Hway table
		  differential_3d_t diff;
		  diff.dx = dx;
		  diff.dy = dy;
		  diff.dz = dz;
		  diff.p = p;
		  uint32_t set_size = diff_set_dx_dy_dz.size();
		  diff_set_dx_dy_dz.insert(diff);
		  if(set_size < diff_set_dx_dy_dz.size()) {
			 diff_mset_p.insert(diff);
		  }
#endif
		} else {
		  Bn_init = 0.0;
		}
	 } else {
		Bn_init = 0.0;
	 }
#endif  // #if SPECK_USE_PRECOMPUTED_BOUNDS

	 // avoid the trivial diferential 0, 0 -> 0
	 //	 if(Bn_init == 1.0) {
	 //		Bn_init = 0.0;
	 //	 }

	 // If the bound for i rounds is better than the bound for (i - 1) rounds -- start the search again from round 1
	 uint32_t i = nrounds - 1;
	 if(i > 0) {
		if(B[i-1] < B[i]) {
		  assert(0 == 1);
		  nrounds = 0;
		  Bn_init = 0.0;
		  for(int j = 0; j < NROUNDS; j++) {
			 B[j] = 0.0;
		  }
		  printf("[%s:%d] Start again from round 1\n", __FILE__, __LINE__);
		}
		assert(B[i-1] >= B[i]);
	 }
  } while(nrounds < NROUNDS);
  //	 } while((nrounds < NROUNDS) && (log2(B[nrounds - 1]) > SPECK_BEST_TRAIL_LOG2P));

  assert(nrounds == NROUNDS);

  num_rounds = nrounds;
  for(uint32_t i = 0; i < nrounds; i++) {
	 best_trail[i].dx = trail[i].dx;
	 best_trail[i].dy = trail[i].dy;
	 best_trail[i].p = trail[i].p;
  }

  *dx_input = dx_init;
  *dy_input = dy_init;

  assert(nrounds <= NROUNDS);

#if 0
  uint32_t npairs = SPECK_NPAIRS;
  uint32_t trail_len = NROUNDS;
  speck_verify_xor_trail(num_rounds, npairs, key, trail, dx_init, dy_init, right_rot_const, left_rot_const);
  speck_verify_xor_differential(num_rounds, npairs, key, trail, dx_init, dy_init, right_rot_const, left_rot_const);

  boost::unordered_map<std::array<differential_t, NROUNDS>, uint32_t, speck_trail_hash, speck_trail_equal_to> trails_hash_map;
  speck_trail_cluster_search_boost(&trails_hash_map, &diff_mset_p, &diff_set_dx_dy_dz, *dx_input, *dy_input, B, best_trail, trail_len);
#endif

#if SPECK_48
  speck_array_differential_3d_free(full_diff_set, full_diff_set_len);
#endif
  gsl_vector_free(C);
  xdp_add_free_matrices(A);
  return num_rounds;
}

/**
 * Apply threshold search starting from a fixed differences in the middle
 * end rpoceeding in the encryption direction.
 */ 
uint32_t speck_xor_trail_search_encrypt ( uint32_t key[SPECK_MAX_NROUNDS], double B[NROUNDS], 
														const WORD_T dx_input, const WORD_T dy_input, 
														differential_t best_trail[NROUNDS], const uint32_t num_rounds,
														std::set<differential_3d_t, struct_comp_diff_3d_dx_dy_dz>* diff_set_dx_dy_dz,
														std::multiset<differential_3d_t, struct_comp_diff_3d_p>* diff_mset_p,
														gsl_matrix* A[2][2][2])
{
  assert(num_rounds <= NROUNDS); // !

  double p_thres = SPECK_P_THRES;
  differential_t diff[NROUNDS];	  // arrey of differences
  differential_t trail[NROUNDS] = {{0, 0, 0, 0.0}};
  uint32_t right_rot_const = SPECK_RIGHT_ROT_CONST; 
  uint32_t left_rot_const = SPECK_LEFT_ROT_CONST;
  if(WORD_SIZE == 16) {
	 right_rot_const = SPECK_RIGHT_ROT_CONST_16BITS; 
	 left_rot_const = SPECK_LEFT_ROT_CONST_16BITS;
  }

  // init bounds
  for(int i = 0; i < NROUNDS; i++) {
	 B[i] = 0.0;
  }

  std::set<differential_3d_t, struct_comp_diff_3d_dx_dy_dz> croads_diff_set_dx_dy_dz; // Dxy
  std::multiset<differential_3d_t, struct_comp_diff_3d_p> croads_diff_mset_p;	 // Dp

  assert(diff_set_dx_dy_dz->size() == diff_mset_p->size());

#if 0									  // DEBUG
  std::set<differential_3d_t, struct_comp_diff_3d_dx_dy_dz>::iterator set_iter = diff_set_dx_dy_dz.begin();
  for(set_iter = diff_set_dx_dy_dz.begin(); set_iter != diff_set_dx_dy_dz.end(); set_iter++) {
	 printf("[%s:%d] %8X %8X %8X 2^%f \n", __FILE__, __LINE__, set_iter->dx, set_iter->dy, set_iter->dz, log2(set_iter->p));
	 assert(set_iter->p >= SPECK_P_THRES);
  }
  std::multiset<differential_3d_t, struct_comp_diff_3d_p>::iterator mset_iter = diff_mset_p.begin();
  for(mset_iter = diff_mset_p.begin(); mset_iter != diff_mset_p.end(); mset_iter++) {
	 printf("[%s:%d] %8X %8X %8X 2^%f \n", __FILE__, __LINE__, mset_iter->dx, mset_iter->dy, mset_iter->dz, log2(mset_iter->p));
	 assert(mset_iter->p >= SPECK_P_THRES);
  }
#endif

#if 0									  // DEBUG
  printf("[%s:%d] p_thres = %f (2^%f), n = %d, #diffs = %d %d\n", __FILE__, __LINE__, 
			p_thres, log2(p_thres), WORD_SIZE, diff_set_dx_dy_dz.size(), diff_mset_p.size());
#endif

#if 0									  // DEBUG
  uint32_t cnt = 0;

  std::multiset<differential_3d_t, struct_comp_diff_3d_p>::iterator set_iter;
  for(set_iter = diff_mset_p.begin(); set_iter != diff_mset_p.end(); set_iter++) {
	 differential_3d_t i_diff = *set_iter;
	 double p_the = xdp_add(A, i_diff.dx, i_diff.dy, i_diff.dz);
#if 1
	 WORD_T tmp_dx = 0x10000090;
	 WORD_T tmp_dy = 0x10000010;
	 if((tmp_dx == i_diff.dx) && (tmp_dy == i_diff.dy)) {
		printf("[%s:%d] %4d: XDP_ADD_THRES[(%8X,%8X)->%8X] = %6.5f\n", 
				 __FILE__, __LINE__, cnt, i_diff.dx, i_diff.dy, i_diff.dz, i_diff.p);
		//		assert(0 == 1);
	 }
#endif
	 assert(p_the == i_diff.p);
	 cnt++;
  }
#endif

  bool b_speck_cluster_trails = false;

  double Bn_init = 0.0;
  uint32_t nrounds = 0;

  WORD_T dx_init = 0;
  WORD_T dy_init = 0;

  const WORD_T dx_init_in = dx_input;
  const WORD_T dy_init_in = dy_input;

  do {

	 nrounds++;
	 printf("[%s:%d] nrounds = %d, Bn_init = 2^%f : key %8X %8X %8X %8X\n", __FILE__, __LINE__, nrounds, log2(Bn_init), key[0], key[1], key[2], key[3]);

	 FILE* fp = fopen(SPECK_LOG_FILE, "a");

	 fprintf(fp, "[%s:%d] nrounds = %d, Bn_init = 2^%f : key %8X %8X %8X %8X\n", __FILE__, __LINE__, nrounds, log2(Bn_init), key[0], key[1], key[2], key[3]);

	 double Bn = Bn_init;
	 B[nrounds - 1] = Bn_init;
	 int r = 0;						  // initial round

	 // init diffs
	 for(int i = 0; i < NROUNDS; i++) {
		diff[i].dx = 0;
		diff[i].dy = 0;
		diff[i].p = 0.0;
	 }

	 speck_xor_threshold_search_encrypt(r, nrounds, A, B, &Bn, diff, dx_init_in, dy_init_in, trail, &dx_init, &dy_init, right_rot_const, left_rot_const, diff_mset_p, diff_set_dx_dy_dz, &croads_diff_mset_p, &croads_diff_set_dx_dy_dz, p_thres, b_speck_cluster_trails);

#if 1									  // DEBUG
	 printf("\n");
	 fprintf(fp, "\n");
	 for(uint32_t i = 0; i < nrounds; i++) {
		printf("B[%2d] = 2^%f", i, log2(B[i]));
		fprintf(fp, "B[%2d] = 2^%f", i, log2(B[i]));
		if(i > 0) {
		  if(B[i-1] < B[i]) {
			 printf(" <-");
		  }
		}
		printf("\n");
		fprintf(fp, "\n");
	 }
#endif
	 assert(B[nrounds - 1] == Bn);

#if 1									  // DEBUG
	 double p_tot = 1.0;
	 for(uint32_t i = 0; i < nrounds; i++) {
		printf("%2d: %llX -> %llX %f (2^%f)\n", i, (WORD_MAX_T)trail[i].dx, (WORD_MAX_T)trail[i].dy, trail[i].p, log2(trail[i].p));
		fprintf(fp, "%2d: %llX -> %llX %f (2^%f)\n", i, (WORD_MAX_T)trail[i].dx, (WORD_MAX_T)trail[i].dy, trail[i].p, log2(trail[i].p));
		p_tot *= trail[i].p;
	 }
	 printf("p_tot = %16.15f = 2^%f, Bn = %f = 2^%f\n", p_tot, log2(p_tot), Bn, log2(Bn));
	 fprintf(fp, "p_tot = %16.15f = 2^%f, Bn = %f = 2^%f\n", p_tot, log2(p_tot), Bn, log2(Bn));
#endif  // #if 0									  // DEBUG

	 fclose(fp);

#if 1	  // VERIFY
	 if(nrounds >= 1) {
		for(uint32_t i = (nrounds - 1); i >= 1; i--) {
		  WORD_T dyy = LROT(trail[i-1].dy, left_rot_const) ^ trail[i].dx;
		  assert(trail[i].dy == dyy);
		}
	 }
#endif  // #if 1	  // VERIFY

	 // Compute an initial bound for the next round
	 //	 if(0) {
	 uint32_t next_round = nrounds;
	 if((next_round >= 1) && (next_round < NROUNDS)) {

		WORD_T dx = RROT(trail[next_round - 1].dx, right_rot_const); // the x input to ADD
		WORD_T dy = trail[next_round - 1].dy; // the y input to ADD
		WORD_T dz = 0;

#if((WORD_SIZE == 16) || (WORD_SIZE == 32))
		double p = max_xdp_add_lm(dx, dy, &dz);
#else
		//		double p = max_xdp_add(A, dx, dy, &dz);
		double p = max_xdp_add_lm(dx, dy, &dz);
#endif
		assert(p != 0.0);

		WORD_T dxx = dz;		                     // x_{i+1}
		WORD_T dyy = LROT(dy, left_rot_const) ^ dz; // y_{i+1}

		//	bool b_low_hw = true;//(hamming_weight(dxx) <= SPECK_MAX_HW) && (hamming_weight(dyy) <= SPECK_MAX_HW);
		bool b_low_hw = true;//(p >= SPECK_P_THRES);//(hamming_weight(dxx) <= SPECK_MAX_HW) && (hamming_weight(dyy) <= SPECK_MAX_HW);
		if(b_low_hw) {

		  Bn_init = B[next_round - 1] * p;
		  B[next_round] = Bn_init;

		  //		printf("[%s:%d] Set B[%d] = 2^%f\n", __FILE__, __LINE__, next_round, log2(Bn_init));
		  trail[next_round].dx = dxx;
		  trail[next_round].dy = dyy;
		  trail[next_round].p = p;

		  //		assert(trail[next_round].dx == trail[next_round-1].dy);
		  dyy = LROT(trail[next_round-1].dy, left_rot_const) ^ trail[next_round].dx;
		  assert(trail[next_round].dy == dyy);
#if 0									  // do not modifu the original Hway table
		  differential_3d_t diff;
		  diff.dx = dx;
		  diff.dy = dy;
		  diff.dz = dz;
		  diff.p = p;
		  uint32_t set_size = diff_set_dx_dy_dz->size();
		  diff_set_dx_dy_dz->insert(diff);
		  if(set_size < diff_set_dx_dy_dz->size()) {
			 diff_mset_p->insert(diff);
		  }
#endif
		} else {
		  Bn_init = 0.0;
		}
	 } else {
		Bn_init = 0.0;
	 }

	 // If the bound for i rounds is better than the bound for (i - 1) rounds -- start the search again from round 1
	 uint32_t i = nrounds - 1;
	 if(i > 0) {
		if(B[i-1] < B[i]) {
		  assert(0 == 1);
		  nrounds = 0;
		  Bn_init = 0.0;
		  for(int j = 0; j < NROUNDS; j++) {
			 B[j] = 0.0;
		  }
		  printf("[%s:%d] Start again from round 1\n", __FILE__, __LINE__);
		}
		assert(B[i-1] >= B[i]);
	 }
	 //  } while(nrounds < NROUNDS);
  } while(nrounds < num_rounds);

  //  assert(nrounds == NROUNDS);
  //  num_rounds = nrounds;

  for(uint32_t i = 0; i < nrounds; i++) {
	 best_trail[i].dx = trail[i].dx;
	 best_trail[i].dy = trail[i].dy;
	 best_trail[i].p = trail[i].p;
  }

  //  *dx_input = dx_init;
  //  *dy_input = dy_init;

  printf("[%s:%d] nrounds = %d\n", __FILE__, __LINE__, nrounds);
  assert(nrounds <= NROUNDS);

#if 0
  uint32_t npairs = SPECK_NPAIRS;
  speck_verify_xor_trail(num_rounds, npairs, key, trail, dx_init_in, dy_init_in, right_rot_const, left_rot_const);
  printf("[%s:%d] ---- ENCRYPT ---\n", __FILE__, __LINE__);
  speck_verify_xor_differential(num_rounds, npairs, key, trail, dx_init_in, dy_init_in, right_rot_const, left_rot_const);
#endif  

  return num_rounds;
}


/**
 * Apply threshold search starting from a fixed differences in the middle
 * and proceeding in the decryption direction.
 */ 
uint32_t speck_xor_trail_search_decrypt ( uint32_t key[SPECK_MAX_NROUNDS], double B[NROUNDS], 
														const WORD_T dx_input, const WORD_T dy_input, 
														differential_t best_trail[NROUNDS], const uint32_t num_rounds,
														std::set<differential_3d_t, struct_comp_diff_3d_dx_dy_dz>* diff_set_dx_dy_dz,
														std::multiset<differential_3d_t, struct_comp_diff_3d_p>* diff_mset_p,
														gsl_matrix* A[2][2][2])
{
  assert(num_rounds <= NROUNDS); // !

  double p_thres = SPECK_P_THRES;
  differential_t diff[NROUNDS];	  // arrey of differences
  differential_t trail[NROUNDS] = {{0, 0, 0, 0.0}};
  uint32_t right_rot_const = SPECK_RIGHT_ROT_CONST; 
  uint32_t left_rot_const = SPECK_LEFT_ROT_CONST;
  if(WORD_SIZE == 16) {
	 right_rot_const = SPECK_RIGHT_ROT_CONST_16BITS; 
	 left_rot_const = SPECK_LEFT_ROT_CONST_16BITS;
  }

  // init bounds
  for(int i = 0; i < NROUNDS; i++) {
	 B[i] = 0.0;
  }

  std::set<differential_3d_t, struct_comp_diff_3d_dx_dy_dz> croads_diff_set_dx_dy_dz; // Dxy
  std::multiset<differential_3d_t, struct_comp_diff_3d_p> croads_diff_mset_p;	 // Dp

  assert(diff_set_dx_dy_dz->size() == diff_mset_p->size());

  bool b_speck_cluster_trails = false;

  double Bn_init = 0.0;
  uint32_t nrounds = 0;

  WORD_T dx_init = 0;
  WORD_T dy_init = 0;
  const WORD_T dx_init_in = dx_input;
  const WORD_T dy_init_in = dy_input;

  do {

	 nrounds++;
	 printf("[%s:%d] nrounds = %d, Bn_init = 2^%f : key %8X %8X %8X %8X\n", __FILE__, __LINE__, nrounds, log2(Bn_init), key[0], key[1], key[2], key[3]);

	 FILE* fp = fopen(SPECK_LOG_FILE, "a");

	 fprintf(fp, "[%s:%d] nrounds = %d, Bn_init = 2^%f : key %8X %8X %8X %8X\n", __FILE__, __LINE__, nrounds, log2(Bn_init), key[0], key[1], key[2], key[3]);

	 double Bn = Bn_init;
	 B[nrounds - 1] = Bn_init;
	 int r = 0;						  // initial round

	 // init diffs
	 for(int i = 0; i < NROUNDS; i++) {
		diff[i].dx = 0;
		diff[i].dy = 0;
		diff[i].p = 0.0;
	 }

	 speck_xor_threshold_search_decrypt(r, nrounds, A, B, &Bn, diff, dx_init_in, dy_init_in, trail, &dx_init, &dy_init, right_rot_const, left_rot_const, diff_mset_p, diff_set_dx_dy_dz, &croads_diff_mset_p, &croads_diff_set_dx_dy_dz, p_thres, b_speck_cluster_trails);

#if 1									  // DEBUG
	 printf("\n");
	 fprintf(fp, "\n");
	 for(uint32_t i = 0; i < nrounds; i++) {
		printf("B[%2d] = 2^%f", i, log2(B[i]));
		fprintf(fp, "B[%2d] = 2^%f", i, log2(B[i]));
		if(i > 0) {
		  if(B[i-1] < B[i]) {
			 printf(" <-");
		  }
		}
		printf("\n");
		fprintf(fp, "\n");
	 }
#endif
	 assert(B[nrounds - 1] == Bn);

#if 1									  // DEBUG
	 double p_tot = 1.0;
	 for(uint32_t i = 0; i < nrounds; i++) {
		printf("%2d: %llX -> %llX %f (2^%f)\n", i, (WORD_MAX_T)trail[i].dx, (WORD_MAX_T)trail[i].dy, trail[i].p, log2(trail[i].p));
		fprintf(fp, "%2d: %llX -> %llX %f (2^%f)\n", i, (WORD_MAX_T)trail[i].dx, (WORD_MAX_T)trail[i].dy, trail[i].p, log2(trail[i].p));
		p_tot *= trail[i].p;
	 }
	 printf("p_tot = %16.15f = 2^%f, Bn = %f = 2^%f\n", p_tot, log2(p_tot), Bn, log2(Bn));
	 fprintf(fp, "p_tot = %16.15f = 2^%f, Bn = %f = 2^%f\n", p_tot, log2(p_tot), Bn, log2(Bn));
#endif  // #if 0									  // DEBUG

	 fclose(fp);

#if 1	  // VERIFY
	 if(nrounds >= 1) {
		for(uint32_t i = (nrounds - 1); i >= 1; i--) {
		  //		  uint32_t dyy = LROT(trail[i-1].dy, left_rot_const) ^ trail[i].dx;
		  uint32_t dyy = RROT((trail[i - 1].dx ^ trail[i - 1].dy), left_rot_const);
		  assert(trail[i].dy == dyy);
		}
	 }
#endif  // #if 1	  // VERIFY

	 // Compute an initial bound for the next round
	 //	 if(0) {
	 uint32_t next_round = nrounds;
	 if((next_round >= 1) && (next_round < NROUNDS)) {

		//		WORD_T dx = RROT(trail[next_round - 1].dx, right_rot_const); // the x input to ADD
		//		WORD_T dy = trail[next_round - 1].dy; // the y input to ADD
		WORD_T dx = trail[next_round - 1].dx;
		WORD_T dy = RROT((dx ^ trail[next_round - 1].dy), left_rot_const);
		WORD_T dz = 0;

		double p = max_xdp_add_lm(dx, dy, &dz);
		assert(p != 0.0);

		//		WORD_T dxx = dz;		                     // x_{i+1}
		//		WORD_T dyy = LROT(dy, left_rot_const) ^ dz; // y_{i+1}
		WORD_T dxx = LROT(dz, right_rot_const); // x_{i-1}
		WORD_T dyy = dy; // y_{i-1}

		//	bool b_low_hw = true;//(hamming_weight(dxx) <= SPECK_MAX_HW) && (hamming_weight(dyy) <= SPECK_MAX_HW);
		bool b_low_hw = true;//(p >= SPECK_P_THRES);//(hamming_weight(dxx) <= SPECK_MAX_HW) && (hamming_weight(dyy) <= SPECK_MAX_HW);
		if(b_low_hw) {

		  Bn_init = B[next_round - 1] * p;
		  B[next_round] = Bn_init;

		  //		printf("[%s:%d] Set B[%d] = 2^%f\n", __FILE__, __LINE__, next_round, log2(Bn_init));
		  trail[next_round].dx = dxx;
		  trail[next_round].dy = dyy;
		  trail[next_round].p = p;

		  //		assert(trail[next_round].dx == trail[next_round-1].dy);
		  //		  dyy = LROT(trail[next_round-1].dy, left_rot_const) ^ trail[next_round].dx;
		  dyy = RROT((dx ^ trail[next_round - 1].dy), left_rot_const);
		  assert(trail[next_round].dy == dyy);
#if 0									  // do not modifu the original Hway table
		  differential_3d_t diff;
		  diff.dx = dx;
		  diff.dy = dy;
		  diff.dz = dz;
		  diff.p = p;
		  uint32_t set_size = diff_set_dx_dy_dz->size();
		  diff_set_dx_dy_dz->insert(diff);
		  if(set_size < diff_set_dx_dy_dz->size()) {
			 diff_mset_p->insert(diff);
		  }
#endif
		} else {
		  Bn_init = 0.0;
		}
	 } else {
		Bn_init = 0.0;
	 }

	 // If the bound for i rounds is better than the bound for (i - 1) rounds -- start the search again from round 1
	 uint32_t i = nrounds - 1;
	 if(i > 0) {
		if(B[i-1] < B[i]) {
		  assert(0 == 1);
		  nrounds = 0;
		  Bn_init = 0.0;
		  for(int j = 0; j < NROUNDS; j++) {
			 B[j] = 0.0;
		  }
		  printf("[%s:%d] Start again from round 1\n", __FILE__, __LINE__);
		}
		assert(B[i-1] >= B[i]);
	 }
	 //  } while(nrounds < NROUNDS);
  } while(nrounds < num_rounds);

  //  assert(nrounds == NROUNDS);
  //  num_rounds = nrounds;
  for(uint32_t i = 0; i < nrounds; i++) {
	 best_trail[i].dx = trail[i].dx;
	 best_trail[i].dy = trail[i].dy;
	 best_trail[i].p = trail[i].p;
  }

  //  *dx_input = dx_init;
  //  *dy_input = dy_init;

  printf("[%s:%d] nrounds = %d\n", __FILE__, __LINE__, nrounds);
  assert(nrounds <= NROUNDS);

#if 0
  uint32_t npairs = SPECK_NPAIRS;
  speck_verify_xor_trail_decrypt(num_rounds, npairs, key, trail, dx_init_in, dy_init_in, right_rot_const, left_rot_const);
  printf("[%s:%d] ---- DECRYPT ---\n", __FILE__, __LINE__);
  speck_verify_xor_differential_decrypt(num_rounds, npairs, key, trail, dx_init_in, dy_init_in, right_rot_const, left_rot_const);
#endif

  //  boost::unordered_map<std::array<differential_t, NROUNDS>, uint32_t, speck_trail_hash, speck_trail_equal_to> trails_hash_map;

  return num_rounds;
}

