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
 * \file  adp-tea-f-fk-noshift-tests.cc
 * \author V.Velichkov, vesselin.velichkov@uni.lu
 * \date 2012-2013
 * \brief Tests for adp-tea-f-fk-noshift.cc
 */ 
#ifndef COMMON_H
#include "common.hh"
#endif
#ifndef TEA_H
#include "tea.hh"
#endif
#ifndef ADP_TEA_F_FK_NOSHIFT_H
#include "adp-tea-f-fk-noshift.hh"
#endif

void test_adp_f_op_noshift()
{
  printf("[%s:%d] Running test %s() ...\n", __FILE__, __LINE__, __FUNCTION__);
  gsl_matrix* A[NSPOS][2][2][2][2][2];
  adp_f_op_noshift_alloc_matrices(A);
  adp_f_op_noshift_sf(A);
  adp_f_op_noshift_normalize_matrices(A);
  uint32_t k0 = random() & MASK;
  uint32_t k1 = random() & MASK;
  uint32_t delta = random() & MASK;
  uint32_t da = random() & MASK;
  uint32_t db = random() & MASK;
  for(da = 0; da < ALL_WORDS; da++) {
	 double p_the = adp_f_op_noshift(A, k0, k1, delta, da, db);
	 double p_exp = adp_f_op_noshift_exper(k0, k1, delta, da, db);
	 assert((p_the >= 0.0) && (p_the <= 1.0));
#if 0									  // DEBUG
	 printf("[%s:%d] ADP_F_OP_NOSHIFT_THE[%8X,%8X,%8X | %8X->%8X] = %6.5f\n", 
			  __FILE__, __LINE__, k0, k1, delta, da, db, p_the);
	 printf("[%s:%d] ADP_F_OP_NOSHIFT_EXP[%8X,%8X,%8X | %8X->%8X] = %6.5f\n", 
			  __FILE__, __LINE__, k0, k1, delta, da, db, p_exp);
#endif
	 assert(p_the == p_exp);
  }
  adp_f_op_noshift_free_matrices(A);
  printf("[%s:%d] WORD_SIZE = %d. Test %s() OK.\n", __FILE__, __LINE__, WORD_SIZE, __FUNCTION__);
}

void test_adp_f_op_noshift_vs_exper_all()
{
  printf("[%s:%d] Running test %s() ...\n", __FILE__, __LINE__, __FUNCTION__);
  gsl_matrix* A[NSPOS][2][2][2][2][2];
  adp_f_op_noshift_alloc_matrices(A);
  adp_f_op_noshift_sf(A);
  adp_f_op_noshift_normalize_matrices(A);
  uint64_t all = ALL_WORDS * ALL_WORDS * ALL_WORDS * ALL_WORDS * ALL_WORDS;
  for(uint64_t i = 0; i < all; i++) {
	 uint64_t temp = i;
	 uint32_t db = temp & MASK;
	 temp /= ALL_WORDS; 
	 uint32_t da = temp & MASK;
	 temp /= ALL_WORDS; 
	 uint32_t delta = temp & MASK;
	 temp /= ALL_WORDS; 
	 uint32_t k1 = temp & MASK;
	 temp /= ALL_WORDS; 
	 uint32_t k0 = temp & MASK;
	 temp /= ALL_WORDS; 
	 double p_the = adp_f_op_noshift(A, k0, k1, delta, da, db);
	 assert((p_the >= 0.0) && (p_the <= 1.0));
	 double p_exp = adp_f_op_noshift_exper(k0, k1, delta, da, db);
#if 0									  // DEBUG
	 if(p_the) {
		printf("[%s:%d] ADP_F_OP_NOSHIFT_THE[%2d,%2d,%2d | %2d->%2d] = %6.5f\n", 
				 __FILE__, __LINE__, k0, k1, delta, da, db, p_the);
		printf("[%s:%d] ADP_F_OP_NOSHIFT_EXP[%2d,%2d,%2d | %2d->%2d] = %6.5f\n", 
				 __FILE__, __LINE__, k0, k1, delta, da, db, p_exp);
	 }
#endif
	 assert(p_the == p_exp);
  }
  adp_f_op_noshift_free_matrices(A);
  printf("[%s:%d] WORD_SIZE = %d. Test %s() OK.\n", __FILE__, __LINE__, WORD_SIZE, __FUNCTION__);
}

void test_adp_f_op_noshift_sf()
{
  printf("[%s:%d] Running test %s() ...\n", __FILE__, __LINE__, __FUNCTION__);
  gsl_matrix* A[NSPOS][2][2][2][2][2];
  adp_f_op_noshift_alloc_matrices(A);
  adp_f_op_noshift_sf(A);
  adp_f_op_noshift_normalize_matrices(A);
#if 0
  adp_f_op_noshift_print_matrices(A);
#endif
  adp_f_op_noshift_free_matrices(A);
  printf("[%s:%d] WORD_SIZE = %d. Test %s() OK.\n", __FILE__, __LINE__, WORD_SIZE, __FUNCTION__);
}

void test_adp_f_op_noshift_exper()
{
  printf("[%s:%d] Running test %s() ...\n", __FILE__, __LINE__, __FUNCTION__);
  uint32_t lsh_const = 0;//TEA_LSH_CONST; 
  uint32_t rsh_const = 0;//TEA_RSH_CONST;

  uint32_t k0 = xrandom() & MASK;
  uint32_t k1 = xrandom() & MASK;
  uint32_t delta = xrandom() & MASK;

  for(uint32_t dx = 0; dx < ALL_WORDS; dx++) {
		for(uint32_t dy = 0; dy < ALL_WORDS; dy++) {
		uint32_t cnt_pairs = 0;
		for(uint32_t x1 = 0; x1 < ALL_WORDS; x1++) {
		  uint32_t x2 = ADD(x1, dx);
		  uint32_t y1 = tea_f(x1, k0, k1, delta, lsh_const, rsh_const);
		  uint32_t y2 = tea_f(x2, k0, k1, delta, lsh_const, rsh_const);
		  uint32_t y_sub = SUB(y2, y1);
		  if(y_sub == dy) {
			 cnt_pairs++;
		  }
		}
		double p = (double)cnt_pairs / (double)ALL_WORDS;
		printf("%8X %8X %8X | %8X -> %8X     %f", k0, k1, delta, dx, dy, p);
		if(cnt_pairs == 0) {
		  printf(" <- ");
		}
		printf("\n");
	 }
  }
  printf("[%s:%d] WORD_SIZE = %d. Test %s() OK.\n", __FILE__, __LINE__, WORD_SIZE, __FUNCTION__);
}

int main()
{
  printf("[%s:%d] Tests, WORD_SIZE  = %d, MASK = %llX ", __FILE__, __LINE__, WORD_SIZE, (WORD_MAX_T)MASK);
  printf("TEA_LSH_CONST = %d, TEA_RSH_CONST = %d\n", TEA_LSH_CONST, TEA_RSH_CONST);
  srandom(time(NULL));

  test_adp_f_op_noshift_sf();
  test_adp_f_op_noshift();
  if(WORD_SIZE < 5) {
	 test_adp_f_op_noshift_vs_exper_all();
  }
  //  test_adp_f_op_noshift_exper();

  return 0;
}


