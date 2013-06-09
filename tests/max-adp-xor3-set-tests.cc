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
 * \file  max-adp-xor3-set-tests.cc
 * \author V.Velichkov, vesselin.velichkov@uni.lu
 * \date 2012-2013
 * \brief Tests for max-adp-xor3-set.cc.
 */ 
#ifndef COMMON_H
#include "common.hh"
#endif
#ifndef ADP_XOR3_H
#include "adp-xor3.hh"
#endif
#ifndef MAX_ADP_XOR3_SET_H
#include "max-adp-xor3-set.hh"
#endif

void test_max_adp_xor3_set()
{
  printf("[%s:%d] Running test %s() ...\n", __FILE__, __LINE__, __FUNCTION__);
  // init A
  gsl_matrix* A[2][2][2][2];
  adp_xor3_alloc_matrices(A);
  adp_xor3_sf(A);
  adp_xor3_normalize_matrices(A);

  uint32_t da = random32() & MASK;
  uint32_t db = random32() & MASK;
  uint32_t dc[ADP_XOR3_SET_SIZE] = {0};
  for(uint32_t j = 0; j < ADP_XOR3_SET_SIZE; j++) {
	 dc[j] = random32() & MASK;
  }
  double p_dc[ADP_XOR3_SET_SIZE];
  for(uint32_t j = 0; j < ADP_XOR3_SET_SIZE; j++) {
	 p_dc[j] = 1.0;
  }

  uint32_t dd_the = 0;
  double p_the = max_adp_xor3_set(A, da, db, dc, p_dc, &dd_the);
  uint32_t dd_exper = 0;
  double p_exper = max_adp_xor3_set_exper(A, da, db, dc, p_dc, &dd_exper);
#if DEBUG_MAX_ADP_XOR3_SET_TESTS
  printf("[%s:%d] MAX_ADP_XOR3_SET_THE[(%8X,%8X,{", __FILE__, __LINE__, da, db);
  for(uint32_t j = 0; j < ADP_XOR3_SET_SIZE; j++) {
	 printf("%8X,", dc[j]);
  }
  printf("})->%8X] = %6.5f = 2^%f\n", dd_the, p_the, log2(p_the));
  printf("[%s:%d] MAX_ADP_XOR3_SET_THE[(%8X,%8X,{", __FILE__, __LINE__, da, db);
  for(uint32_t j = 0; j < ADP_XOR3_SET_SIZE; j++) {
	 printf("%8X,", dc[j]);
  }
  printf("})->%8X] = %6.5f = 2^%f\n", dd_the, p_exper, log2(p_exper));
#endif  // #if DEBUG_MAX_ADP_XOR3_SET_TESTS
  assert(p_the == p_exper);
  adp_xor3_free_matrices(A);
  printf("[%s:%d] WORD_SIZE = %d, ADP_XOR3_SET_SIZE = %d. Test %s() OK.\n", __FILE__, __LINE__, WORD_SIZE, ADP_XOR3_SET_SIZE, __FUNCTION__);
}

void test_max_adp_xor3_set_is_max_all()
{
  printf("[%s:%d] Running test %s() ...\n", __FILE__, __LINE__, __FUNCTION__);
  assert(WORD_SIZE < 8);

  // init A
  gsl_matrix* A[2][2][2][2];
  adp_xor3_alloc_matrices(A);
  adp_xor3_sf(A);
  adp_xor3_normalize_matrices(A);

  for(uint32_t da = 0; da < ALL_WORDS; da++) {
	 for(uint32_t db = 0; db < ALL_WORDS; db++) {
		for(uint32_t dx = 0; dx < ALL_WORDS; dx++) {
		  for(uint32_t dy = 0; dy < ALL_WORDS; dy++) {

			 uint32_t dc[ADP_XOR3_SET_SIZE] = {0};
			 for(uint32_t j = 0; j < ADP_XOR3_SET_SIZE; j++) {
				dc[j] = random32() & MASK;
			 }
			 dc[0] = dx;
			 dc[1] = dy;
			 double p_dc[ADP_XOR3_SET_SIZE];
			 for(uint32_t j = 0; j < ADP_XOR3_SET_SIZE; j++) {
				p_dc[j] = 1.0;
            // generate non 1.0 probabilities
#if 0
				p_dc[j] = (double)(random() % 101) / (double)100;
				assert((p_dc[j] >= 0) && (p_dc[j] <= 1.0));
#endif
			 }
			 uint32_t dd_the = 0;
			 double p_the = max_adp_xor3_set(A, da, db, dc, p_dc, &dd_the);
			 uint32_t dd_exper = 0;
			 double p_exper = max_adp_xor3_set_exper(A, da, db, dc, p_dc, &dd_exper);
#if DEBUG_MAX_ADP_XOR3_SET_TESTS
			 printf("[%s:%d] MAX_ADP_XOR3_SET_THE[(%8X,%8X,{", __FILE__, __LINE__, da, db);
			 for(uint32_t j = 0; j < ADP_XOR3_SET_SIZE; j++) {
				printf("%8X,", dc[j]);
			 }
			 printf("})->%8X] = %6.5f = 2^%f\n", dd_the, p_the, log2(p_the));
			 printf("[%s:%d] MAX_ADP_XOR3_SET_THE[(%8X,%8X,{", __FILE__, __LINE__, da, db);
			 for(uint32_t j = 0; j < ADP_XOR3_SET_SIZE; j++) {
				printf("%8X,", dc[j]);
			 }
			 printf("})->%8X] = %6.5f = 2^%f\n", dd_the, p_exper, log2(p_exper));
#endif  // #if DEBUG_MAX_ADP_XOR3_SET_TESTS
			 if(p_exper != p_the) {
				printf("[%s:%d] WARNING: p_the != p_exp\n", __FILE__, __LINE__);
				printf("p_the = %41.40f = 2^%f\n", p_the, log2(p_the));
				printf("p_exp = %41.40f = 2^%f\n", p_exper, log2(p_exper));
			 }
			 assert(p_the == p_exper);
		  }
		}
	 }
  }
  adp_xor3_free_matrices(A);
  printf("[%s:%d] WORD_SIZE = %d, ADP_XOR3_SET_SIZE = %d. Test %s() OK.\n", __FILE__, __LINE__, WORD_SIZE, ADP_XOR3_SET_SIZE, __FUNCTION__);
}

// 
// Random inputs
// 
void test_max_adp_xor3_set_is_max_rand()
{
  printf("[%s:%d] Running test %s() ...\n", __FILE__, __LINE__, __FUNCTION__);
  uint32_t N = (1UL << 12);

  // init A
  gsl_matrix* A[2][2][2][2];
  adp_xor3_alloc_matrices(A);
  adp_xor3_sf(A);
  adp_xor3_normalize_matrices(A);

  for(uint32_t i = 0; i < N; i++) {

	 uint32_t da = random32() & MASK;
	 uint32_t db = random32() & MASK;
	 uint32_t dc[ADP_XOR3_SET_SIZE] = {0};
	 for(uint32_t j = 0; j < ADP_XOR3_SET_SIZE; j++) {
		dc[j] = random32() & MASK;
	 }
	 double p_dc[ADP_XOR3_SET_SIZE];
	 for(uint32_t j = 0; j < ADP_XOR3_SET_SIZE; j++) {
		p_dc[j] = 1.0;
		// generate non 1.0 probabilities
#if 0
		p_dc[j] = (double)(random() % 101) / (double)100;
		assert((p_dc[j] >= 0) && (p_dc[j] <= 1.0));
#endif
	 }
	 uint32_t dd_the = 0;
	 double p_the = max_adp_xor3_set(A, da, db, dc, p_dc, &dd_the);
	 uint32_t dd_exper = 0;
	 double p_exper = max_adp_xor3_set_exper(A, da, db, dc, p_dc, &dd_exper);
#if DEBUG_MAX_ADP_XOR3_SET_TESTS
	 printf("[%s:%d] MAX_ADP_XOR3_SET_THE[(%8X,%8X,{", __FILE__, __LINE__, da, db);
	 for(uint32_t j = 0; j < ADP_XOR3_SET_SIZE; j++) {
		printf("%8X,", dc[j]);
	 }
	 printf("})->%8X] = %6.5f = 2^%f\n", dd_the, p_the, log2(p_the));
	 printf("[%s:%d] MAX_ADP_XOR3_SET_THE[(%8X,%8X,{", __FILE__, __LINE__, da, db);
	 for(uint32_t j = 0; j < ADP_XOR3_SET_SIZE; j++) {
		printf("%8X,", dc[j]);
	 }
	 printf("})->%8X] = %6.5f = 2^%f\n", dd_the, p_exper, log2(p_exper));
#endif  // #if DEBUG_MAX_ADP_XOR3_SET_TESTS
	 if(p_exper != p_the) {
		printf("[%s:%d] WARNING: p_the != p_exp\n", __FILE__, __LINE__);
		printf("p_the = %41.40f = 2^%f\n", p_the, log2(p_the));
		printf("p_exp = %41.40f = 2^%f\n", p_exper, log2(p_exper));
	 }
	 assert(p_the == p_exper);
  }
  adp_xor3_free_matrices(A);
  printf("[%s:%d] WORD_SIZE = %d, ADP_XOR3_SET_SIZE = %d. Test %s() OK.\n", __FILE__, __LINE__, WORD_SIZE, ADP_XOR3_SET_SIZE, __FUNCTION__);
}

int main()
{
  printf("[%s:%d] Tests, WORD_SIZE  = %d, MASK = %8X, ADP_XOR3_SET_SIZE = %d\n", __FILE__, __LINE__, WORD_SIZE, MASK, ADP_XOR3_SET_SIZE);
  test_max_adp_xor3_set();
  if((WORD_SIZE <= 4) && (ADP_XOR3_SET_SIZE == 2)) {
	 test_max_adp_xor3_set_is_max_all();
  } else {
	 test_max_adp_xor3_set_is_max_rand();
  }
  return 0;
}
