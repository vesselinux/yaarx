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
 * \file  tea-f-add-pddt-tests.cc
 * \author V.Velichkov, vesselin.velichkov@uni.lu
 * \brief Tests for tea-f-add-pddt.cc.
 *
 * Testing the computation of pDDT for the TEA F-function
 *
 */ 
#ifndef COMMON_H
#include "common.hh"
#endif
#ifndef ADP_XOR3_H
#include "adp-xor3.hh"
#endif
#ifndef ADP_SHIFT_H
#include "adp-shift.hh"
#endif
#ifndef TEA_H
#include "tea.hh"
#endif
#ifndef EADP_TEA_F_H
#include "eadp-tea-f.hh"
#endif
#ifndef ADP_TEA_F_FK_H
#include "adp-tea-f-fk.hh"
#endif
#ifndef TEA_F_ADD_PDDT_H
#include "tea-f-add-pddt.hh"
#endif

void test_rsh_condition()
{
  for(uint32_t da = 0; da < ALL_WORDS; da++) {
	 uint32_t dx[4] = {0, 0, 0, 0};
	 adp_rsh_odiffs(dx, da, TEA_RSH_CONST);

	 for(uint32_t k = TEA_RSH_CONST; k < WORD_SIZE; k++) {
		uint32_t mask_k = ~(0xffffffff << k);
		uint32_t da_k = da & mask_k;
		for(int i = 0; i < 4; i++) {
		  uint32_t dx_k = dx[i] & mask_k;
		  bool b_con = rsh_condition_is_sat(k, da_k, dx_k);
		  if(!b_con) {
			 //		  printf("[%s:%d] %8X | %8X %8X %8X %8X\n", da, dx[0]);
			 printf("[%s:%d] k=%d i=%d | %8X %8X | %8X %8X\n", __FILE__, __LINE__, k, i, da, dx[i], da_k, dx_k);
		  }
		}

	 }
  }
}

// 
// Compare the incomplete pDDT for F used in the search
// to the full pDDT obtained experimentally. Two cases are co nsidered:
//    1) the pDDT averaged over all keys and delta
//    2) the pDDT for a fixed key and delta
// 
void test_tea_f_add_pddt_vs_full_ddt()
{
  uint32_t lsh_const = TEA_LSH_CONST; 
  uint32_t rsh_const = TEA_RSH_CONST;
  double p_thres = 0.05;
  uint32_t word_size = WORD_SIZE;
  uint32_t npairs = NPAIRS;
  uint32_t num_rounds = 1;

  // init A
  gsl_matrix* A[2][2][2][2];
  adp_xor3_alloc_matrices(A);
  adp_xor3_sf(A);
  adp_xor3_normalize_matrices(A);

  uint32_t key[4];
  key[0] = random32() & MASK;
  key[1] = random32() & MASK;
  key[2] = random32() & MASK;
  key[3] = random32() & MASK;

  uint32_t k0 = 0;
  uint32_t k1 = 0;

  // get the round key
  if(is_even(num_rounds)) {
	 k0 = key[0];
	 k1 = key[1];
  } else {
	 k0 = key[2];
	 k1 = key[3];
  }

  // compute delta
  uint32_t delta = 0;
  uint32_t i = 0;
  while(i <= num_rounds) {
	 if(is_even(i)) {				  // update delta every 2-nd round
		delta = ADD(delta, DELTA_INIT); // delta += DELTA_INIT;
	 }
	 i++;
  }

  std::set<differential_t, struct_comp_diff_dx_dy> diff_set_dx_dy; // Dxy
  std::multiset<differential_t, struct_comp_diff_p> diff_mset_p;	 // Dp
  std::multiset<differential_t, struct_comp_diff_p> diff_mset_p_exper;	 // Dp

  // pDDT the
  tea_f_add_pddt(word_size, p_thres, lsh_const, rsh_const, &diff_set_dx_dy);
  tea_f_add_pddt_dxy_to_dp(&diff_mset_p, diff_set_dx_dy);

  // pDDT exper
  tea_f_add_pddt_exper(A, word_size, p_thres, lsh_const, rsh_const, &diff_mset_p_exper);

  uint32_t pddt_size_the = diff_mset_p.size();
  uint32_t pddt_size_exp = diff_mset_p_exper.size();
  printf("[%s:%d]     pDDT size | exp %d, the %d\n ", __FILE__, __LINE__, pddt_size_exp, pddt_size_the);

  diff_mset_p.clear();
  diff_mset_p_exper.clear();

  // pDDT fk the
  tea_f_add_pddt_adjust_to_key(num_rounds, npairs, key, p_thres, &diff_set_dx_dy);
  tea_f_add_pddt_dxy_to_dp(&diff_mset_p, diff_set_dx_dy);

  // pDDT fk exper
  tea_f_add_pddt_fk_exper(word_size, p_thres, delta, k0, k1, lsh_const, rsh_const, &diff_mset_p_exper);

  uint32_t pddt_fk_size_the = diff_mset_p.size();
  uint32_t pddt_fk_size_exp = diff_mset_p_exper.size();
  printf("[%s:%d] FK pDDT size | exp %d, the %d\n ", __FILE__, __LINE__, pddt_fk_size_exp, pddt_fk_size_the);

  adp_xor3_free_matrices(A);
}

int main()
{
  printf("[%s:%d] Tests, WORD_SIZE  = %d, MASK = %8X\n", __FILE__, __LINE__, WORD_SIZE, MASK);
  srandom(time(NULL));
  test_tea_f_add_pddt_vs_full_ddt();
  return 0;
}
